#!/usr/bin/env python3
"""Shared, non-policy helpers for YNAB post-sign inspection."""

from __future__ import annotations

import datetime as dt
import hashlib
import pathlib
import plistlib
import struct
import subprocess
import zipfile
from typing import Any


MH_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
FAT_MAGIC_BE = b"\xca\xfe\xba\xbe"
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
DYLIB_COMMANDS = {0xC, 0xD, 0x20, 0x80000018, 0x8000001F, 0x80000023}


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def archive_index(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members = archive.infolist()
    names = [member.filename for member in members]
    if len(names) != len(set(names)):
        fail("archive contains duplicate ZIP entries")
    for name in names:
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            fail(f"unsafe ZIP entry: {name}")
    return {member.filename: member for member in members}


def parse_thin(data: bytes | bytearray, label: str) -> dict[str, Any]:
    if len(data) < 32 or bytes(data[:4]) != MH_MAGIC_64_LE:
        fail(f"not a thin little-endian Mach-O 64 image: {label}")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    offset = 32
    commands = []
    segments = []
    signature = None
    uuid = None
    dylibs = []
    for _ in range(ncmds):
        if offset + 8 > len(data):
            fail(f"truncated load-command table: {label}")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > len(data):
            fail(f"invalid load command at {offset:#x}: {label}")
        commands.append({"offset": offset, "command": command, "size": size})
        if command == LC_SEGMENT_64:
            name = bytes(data[offset + 8 : offset + 24]).split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", data, offset + 24
            )
            segments.append(
                {
                    "name": name,
                    "offset": offset,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                }
            )
        elif command == LC_UUID:
            uuid = bytes(data[offset + 8 : offset + 24]).hex()
        elif command == LC_CODE_SIGNATURE:
            if signature is not None:
                fail(f"multiple LC_CODE_SIGNATURE commands: {label}")
            dataoff, datasize = struct.unpack_from("<II", data, offset + 8)
            signature = {
                "offset": offset,
                "size": size,
                "dataoff": dataoff,
                "datasize": datasize,
            }
        elif command in DYLIB_COMMANDS:
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if name_offset >= size:
                fail(f"invalid dylib name offset: {label}")
            raw = bytes(data[offset + name_offset : offset + size]).split(b"\0", 1)[0]
            dylibs.append((command, raw.decode("utf-8")))
        offset += size
    if offset != 32 + sizeofcmds:
        fail(f"load-command size mismatch: {label}")
    return {
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "commands": commands,
        "segments": segments,
        "signature": signature,
        "uuid": uuid,
        "dylibs": dylibs,
    }


def parse_container(data: bytes, label: str) -> tuple[list[dict], list[bytes], str]:
    if data[:4] == MH_MAGIC_64_LE:
        return ([{"cpu": None, "subtype": None, "align": None}], [data], "thin")
    if data[:4] != FAT_MAGIC_BE or len(data) < 8:
        fail(f"unsupported Mach-O container: {label}")
    count = struct.unpack_from(">I", data, 4)[0]
    if count <= 0 or 8 + count * 20 > len(data):
        fail(f"invalid fat Mach-O header: {label}")
    arches = []
    images = []
    previous_end = 0
    for index in range(count):
        cpu, subtype, offset, size, align = struct.unpack_from(
            ">iiIII", data, 8 + index * 20
        )
        if offset % (1 << align) or offset < previous_end or offset + size > len(data):
            fail(f"invalid fat Mach-O slice {index}: {label}")
        arches.append({"cpu": cpu, "subtype": subtype, "align": align})
        images.append(data[offset : offset + size])
        previous_end = offset + size
    return arches, images, "fat32"


def compare_signed_slice(candidate: bytes, signed: bytes, label: str) -> dict[str, Any]:
    before = parse_thin(candidate, f"{label}[resign-required]")
    after = parse_thin(signed, f"{label}[signed]")
    signature = after["signature"]
    if signature is None or signature["datasize"] <= 0:
        fail(f"signed Mach-O has no signature payload: {label}")
    if signature["dataoff"] + signature["datasize"] != len(signed):
        fail(f"signed Mach-O signature is not an EOF payload: {label}")
    if signature["dataoff"] < len(candidate):
        fail(f"signed Mach-O signature overlaps candidate runtime bytes: {label}")
    if any(signed[len(candidate) : signature["dataoff"]]):
        fail(f"signed Mach-O has nonzero pre-signature padding: {label}")
    if before["uuid"] != after["uuid"] or before["dylibs"] != after["dylibs"]:
        fail(f"signing changed UUID or dylib dependencies: {label}")

    candidate_signature = before["signature"]
    normalized = bytearray(signed[: len(candidate)])
    normalized[16:24] = candidate[16:24]
    if candidate_signature is None:
        if (
            after["ncmds"] != before["ncmds"] + 1
            or after["sizeofcmds"] != before["sizeofcmds"] + 16
            or signature["size"] != 16
            or signature["offset"] != 32 + before["sizeofcmds"]
        ):
            fail(f"signer added an unexpected signature command: {label}")
        end = signature["offset"] + signature["size"]
        if end > len(candidate) or any(candidate[signature["offset"] : end]):
            fail(f"signature command does not occupy candidate header slack: {label}")
        normalized[signature["offset"] : end] = candidate[signature["offset"] : end]
    else:
        if (
            candidate_signature["datasize"] != 0
            or after["ncmds"] != before["ncmds"]
            or after["sizeofcmds"] != before["sizeofcmds"]
            or signature["offset"] != candidate_signature["offset"]
            or signature["size"] != candidate_signature["size"]
        ):
            fail(f"signer changed the existing signature-command layout: {label}")
        start = candidate_signature["offset"]
        normalized[start : start + candidate_signature["size"]] = candidate[
            start : start + candidate_signature["size"]
        ]

    before_segments = {segment["name"]: segment for segment in before["segments"]}
    after_segments = {segment["name"]: segment for segment in after["segments"]}
    if set(before_segments) != set(after_segments):
        fail(f"signing changed the Mach-O segment graph: {label}")
    for name, segment in before_segments.items():
        signed_segment = after_segments[name]
        if (
            segment["offset"] != signed_segment["offset"]
            or segment["vmaddr"] != signed_segment["vmaddr"]
            or segment["fileoff"] != signed_segment["fileoff"]
        ):
            fail(f"signing moved Mach-O segment {name}: {label}")
        if name == "__LINKEDIT":
            for relative, size in ((32, 8), (48, 8)):
                start = segment["offset"] + relative
                normalized[start : start + size] = candidate[start : start + size]
        elif (
            segment["vmsize"] != signed_segment["vmsize"]
            or segment["filesize"] != signed_segment["filesize"]
        ):
            fail(f"signing resized non-LINKEDIT segment {name}: {label}")

    if bytes(normalized) != candidate:
        fail(f"signing changed runtime bytes outside signature metadata: {label}")
    return {
        "unsignedSha256": sha256_bytes(candidate),
        "signedSha256": sha256_bytes(signed),
        "unsignedSize": len(candidate),
        "signedSize": len(signed),
        "signatureOffset": signature["dataoff"],
        "signatureSize": signature["datasize"],
        "runtimeBytesPreserved": True,
    }


def compare_signed_container(candidate: bytes, signed: bytes, label: str) -> dict[str, Any]:
    before_arches, before_images, before_kind = parse_container(candidate, label)
    after_arches, after_images, after_kind = parse_container(signed, label)
    if before_kind != after_kind or before_arches != after_arches:
        fail(f"signing changed the Mach-O architecture set: {label}")
    slices = [
        compare_signed_slice(before, after, f"{label}[{index}]")
        for index, (before, after) in enumerate(zip(before_images, after_images))
    ]
    return {
        "path": label,
        "container": before_kind,
        "sliceCount": len(slices),
        "slices": slices,
    }


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, capture_output=True, check=False)
    if check and result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        fail(f"command failed ({result.returncode}): {command[0]}: {detail}")
    return result


def decode_entitlements(bundle: pathlib.Path) -> dict[str, Any]:
    result = run(["codesign", "-d", "--entitlements", ":-", str(bundle)])
    try:
        value = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise RuntimeError(f"codesign emitted invalid entitlements: {bundle}") from error
    if not isinstance(value, dict):
        fail(f"codesign entitlements are not a dictionary: {bundle}")
    return value


def signature_metadata(bundle: pathlib.Path) -> dict[str, Any]:
    result = run(["codesign", "-d", "--verbose=4", str(bundle)])
    fields: dict[str, list[str]] = {}
    for line in result.stderr.decode("utf-8", "replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields.setdefault(key, []).append(value)
    return {
        "identifier": (fields.get("Identifier") or [None])[0],
        "teamIdentifier": (fields.get("TeamIdentifier") or [None])[0],
        "cdhash": (fields.get("CDHash") or [None])[0],
        "authorities": fields.get("Authority", []),
    }


def decode_profile(path: pathlib.Path) -> dict[str, Any]:
    result = run(["security", "cms", "-D", "-i", str(path)])
    try:
        profile = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise RuntimeError(f"embedded provisioning profile is invalid: {path}") from error
    entitlements = profile.get("Entitlements")
    if not isinstance(profile, dict) or not isinstance(entitlements, dict):
        fail(f"embedded profile has no entitlement dictionary: {path}")
    expiration = profile.get("ExpirationDate")
    return {
        "name": profile.get("Name"),
        "uuid": profile.get("UUID"),
        "teamIdentifier": (profile.get("TeamIdentifier") or [None])[0]
        if isinstance(profile.get("TeamIdentifier"), list)
        else profile.get("TeamIdentifier"),
        "expiration": expiration.isoformat() if isinstance(expiration, dt.datetime) else None,
        "provisionedDeviceCount": len(profile.get("ProvisionedDevices", [])),
        "entitlements": entitlements,
    }


def entitlement_authorized(effective: Any, authorized: Any) -> bool:
    if effective == authorized:
        return True
    if isinstance(effective, str) and isinstance(authorized, str):
        return authorized == "*" or (
            authorized.endswith("*")
            and effective.startswith(authorized[:-1])
        )
    if isinstance(effective, list) and isinstance(authorized, list):
        return all(
            any(entitlement_authorized(item, grant) for grant in authorized)
            for item in effective
        )
    return False


def usable_string_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item) for item in value)
    )


def signing_metadata_member(name: str) -> bool:
    path = pathlib.PurePosixPath(name)
    return "_CodeSignature" in path.parts or path.name == "embedded.mobileprovision"
