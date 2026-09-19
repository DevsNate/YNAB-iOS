#!/usr/bin/env python3
"""Build a version-admitted YNAB signer-neutral carrier.

This is intentionally narrower than a functional private-server build. It
patches only the three proven stock App Group owners so they resolve the
current signer's entitlement, then removes stale signing state using the
admitted signature-clean packaging contract.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile


PAGE_SIZE = 0x4000

MH_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
FAT_MAGIC_BE = b"\xca\xfe\xba\xbe"
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

VERSION_ID = ""
EXPECTED_INPUT_SHA256 = ""
EXPECTED_CARRIER_SHA256: str | None = ""
EXPECTED_BUNDLE_ID = ""
EXPECTED_VERSION = ""
EXPECTED_BUILD = ""
EXPECTED_MACHO_CONTAINER_COUNT = 0
EXPECTED_MACHO_SLICE_COUNT = 0
EXPECTED_RESOLVER_SIZE = 0
EXPECTED_BRANCH_OFFSETS: list[int] = []
RESOLVER_SOURCE = pathlib.Path()
TARGETS: tuple[dict, ...] = ()


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def validate_carrier_hash(value: object, derive_carrier_hash: bool) -> str | None:
    if derive_carrier_hash:
        if value is not None:
            fail("carrier-hash derivation requires expectedCarrierSha256 to be null")
        return None
    if not isinstance(value, str) or len(value) != 64:
        fail("signer-neutral profile is not sealed with a carrier SHA-256")
    try:
        bytes.fromhex(value)
    except ValueError:
        fail("signer-neutral carrier SHA-256 is not hexadecimal")
    return value


def load_version(version_id: str, derive_carrier_hash: bool = False) -> None:
    global VERSION_ID
    global EXPECTED_INPUT_SHA256, EXPECTED_CARRIER_SHA256
    global EXPECTED_BUNDLE_ID, EXPECTED_VERSION, EXPECTED_BUILD
    global EXPECTED_MACHO_CONTAINER_COUNT, EXPECTED_MACHO_SLICE_COUNT
    global EXPECTED_RESOLVER_SIZE, EXPECTED_BRANCH_OFFSETS
    global RESOLVER_SOURCE, TARGETS

    version_root = PROJECT_ROOT / "versions" / version_id
    stock_path = version_root / "stock.json"
    neutral_path = version_root / "signer-neutral.json"
    if not stock_path.is_file() or not neutral_path.is_file():
        fail(f"version is not admitted: {version_id}")
    stock = json.loads(stock_path.read_text(encoding="utf-8"))
    neutral = json.loads(neutral_path.read_text(encoding="utf-8"))
    if stock.get("schema") != "ynab-ios-stock/v1":
        fail(f"unsupported stock specification: {stock.get('schema')}")
    if neutral.get("schema") != "ynab-ios-signer-neutral/v1":
        fail(f"unsupported neutral specification: {neutral.get('schema')}")
    if stock.get("versionId") != version_id or neutral.get("versionId") != version_id:
        fail("version specification identity mismatch")

    component = neutral["component"]
    resolver_source = (PROJECT_ROOT / component["source"]).resolve()
    if not resolver_source.is_relative_to(PROJECT_ROOT) or not resolver_source.is_file():
        fail("resolver component path is invalid")
    if sha256_path(resolver_source) != component["sourceSha256"]:
        fail("resolver component source hash mismatch")

    targets = []
    for item in neutral["targets"]:
        targets.append(
            {
                "name": item["name"],
                "path": item["path"],
                "sha256": item["sha256"],
                "uuid": item["uuid"],
                "patch_vm": int(item["patchVm"], 0),
                "patch_bytes": bytes.fromhex(item["patchBytes"]),
                "resolver_vm": int(item["resolverVm"], 0),
                "dlopen_vm": int(item["dlopenVm"], 0),
                "dlsym_vm": int(item["dlsymVm"], 0),
            }
        )

    VERSION_ID = version_id
    EXPECTED_INPUT_SHA256 = stock["input"]["sha256"]
    EXPECTED_CARRIER_SHA256 = validate_carrier_hash(
        neutral.get("expectedCarrierSha256"), derive_carrier_hash
    )
    EXPECTED_BUNDLE_ID = stock["bundleIdentifier"]
    EXPECTED_VERSION = stock["marketingVersion"]
    EXPECTED_BUILD = stock["build"]
    EXPECTED_MACHO_CONTAINER_COUNT = stock["inventory"]["machoContainers"]
    EXPECTED_MACHO_SLICE_COUNT = stock["inventory"]["machoSlices"]
    EXPECTED_RESOLVER_SIZE = component["payloadSize"]
    EXPECTED_BRANCH_OFFSETS = component["branchInstructionOffsets"]
    RESOLVER_SOURCE = resolver_source
    TARGETS = tuple(targets)


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_macho(data: bytes | bytearray, label: str) -> dict:
    if len(data) < 32 or bytes(data[:4]) != MH_MAGIC_64_LE:
        fail(f"not a thin little-endian Mach-O 64 image: {label}")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    segments = []
    code_signature = None
    uuid = None
    for _ in range(ncmds):
        if offset + 8 > len(data):
            fail(f"truncated load-command table: {label}")
        command, command_size = struct.unpack_from("<II", data, offset)
        if command_size < 8 or offset + command_size > len(data):
            fail(f"invalid load command at {offset:#x}: {label}")
        if command == LC_SEGMENT_64:
            if command_size < 72:
                fail(f"short LC_SEGMENT_64: {label}")
            segment_name = (
                struct.unpack_from("<16s", data, offset + 8)[0]
                .split(b"\0", 1)[0]
                .decode("ascii")
            )
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", data, offset + 24
            )
            maxprot, initprot = struct.unpack_from("<ii", data, offset + 56)
            segments.append(
                {
                    "name": segment_name,
                    "command_offset": offset,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                    "maxprot": maxprot,
                    "initprot": initprot,
                }
            )
        elif command == LC_CODE_SIGNATURE:
            if code_signature is not None:
                fail(f"multiple LC_CODE_SIGNATURE commands: {label}")
            dataoff, datasize = struct.unpack_from("<II", data, offset + 8)
            code_signature = {
                "command_offset": offset,
                "dataoff": dataoff,
                "datasize": datasize,
            }
        elif command == LC_UUID:
            uuid = bytes(data[offset + 8 : offset + 24]).hex()
        offset += command_size
    return {
        "segments": segments,
        "code_signature": code_signature,
        "uuid": uuid,
    }


def vm_to_file(parsed: dict, vmaddr: int, size: int, label: str) -> tuple[int, dict]:
    for segment in parsed["segments"]:
        start = segment["vmaddr"]
        if start <= vmaddr and vmaddr + size <= start + segment["filesize"]:
            return segment["fileoff"] + vmaddr - start, segment
    fail(f"VM range {vmaddr:#x}+{size:#x} is not file-backed: {label}")


def encode_branch(pc: int, target: int, link: bool) -> bytes:
    delta = target - pc
    if delta % 4:
        fail(f"unaligned branch {pc:#x} -> {target:#x}")
    immediate = delta // 4
    if not -(1 << 25) <= immediate < (1 << 25):
        fail(f"branch out of range {pc:#x} -> {target:#x}")
    opcode = 0x94000000 if link else 0x14000000
    return struct.pack("<I", opcode | (immediate & 0x03FFFFFF))


def extract_text_section(object_path: pathlib.Path) -> bytes:
    data = object_path.read_bytes()
    parsed = parse_macho(data, str(object_path))
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    matches = []
    for _ in range(ncmds):
        command, command_size = struct.unpack_from("<II", data, offset)
        if command == LC_SEGMENT_64:
            section_count = struct.unpack_from("<I", data, offset + 64)[0]
            section_offset = offset + 72
            for _ in range(section_count):
                section_name = (
                    struct.unpack_from("<16s", data, section_offset)[0]
                    .split(b"\0", 1)[0]
                    .decode("ascii")
                )
                segment_name = (
                    struct.unpack_from("<16s", data, section_offset + 16)[0]
                    .split(b"\0", 1)[0]
                    .decode("ascii")
                )
                section_size = struct.unpack_from("<Q", data, section_offset + 40)[0]
                file_offset = struct.unpack_from("<I", data, section_offset + 48)[0]
                relocation_offset, relocation_count = struct.unpack_from(
                    "<II", data, section_offset + 56
                )
                if segment_name == "__TEXT" and section_name == "__text":
                    if relocation_count != 0 or relocation_offset != 0:
                        fail("resolver object unexpectedly contains relocations")
                    matches.append(bytes(data[file_offset : file_offset + section_size]))
                section_offset += 80
        offset += command_size
    if len(matches) != 1:
        fail(f"expected one resolver __TEXT,__text section, found {len(matches)}")
    if parsed["uuid"] is not None:
        fail("resolver object unexpectedly contains LC_UUID")
    return matches[0]


def compile_resolver(work_dir: pathlib.Path) -> bytes:
    if not RESOLVER_SOURCE.is_file():
        fail(f"missing resolver source: {RESOLVER_SOURCE}")
    object_path = work_dir / "YNABAppGroupResolver.o"
    command = [
        "xcrun",
        "--sdk",
        "iphoneos",
        "clang",
        "-arch",
        "arm64",
        "-c",
        "-x",
        "assembler-with-cpp",
        str(RESOLVER_SOURCE),
        "-o",
        str(object_path),
    ]
    subprocess.run(command, check=True)
    payload = extract_text_section(object_path)
    if len(payload) != EXPECTED_RESOLVER_SIZE:
        fail(
            f"resolver size mismatch: expected={EXPECTED_RESOLVER_SIZE} actual={len(payload)}"
        )
    markers = [struct.pack("<I", 0xFEED3000 + index) for index in range(1, 10)]
    if any(payload.count(marker) != 1 for marker in markers):
        fail("resolver branch-marker occurrence mismatch")
    return payload


def patch_resolver(payload: bytes, target: dict) -> tuple[bytes, dict]:
    patched = bytearray(payload)
    branch_offsets = []
    for index in range(1, 10):
        marker = struct.pack("<I", 0xFEED3000 + index)
        marker_offset = patched.find(marker)
        if marker_offset < 0 or patched.find(marker, marker_offset + 4) >= 0:
            fail(f"resolver marker {index} occurrence mismatch")
        branch_offsets.append(marker_offset)
        target_vm = target["dlopen_vm"] if index == 1 else target["dlsym_vm"]
        patched[marker_offset : marker_offset + 4] = encode_branch(
            target["resolver_vm"] + marker_offset, target_vm, True
        )
    if branch_offsets != EXPECTED_BRANCH_OFFSETS:
        fail(f"unexpected resolver branch-marker layout: {branch_offsets}")
    if any(
        struct.pack("<I", 0xFEED3000 + index) in patched
        for index in range(1, 10)
    ):
        fail("unreplaced branch marker remains in resolver")
    return bytes(patched), {
        "payload_size": len(patched),
        "payload_sha256": sha256_bytes(patched),
        "branch_instruction_offsets": branch_offsets,
    }


def patch_target(app: pathlib.Path, target: dict, resolver: bytes) -> dict:
    path = app / target["path"]
    if not path.is_file():
        fail(f"missing patch target: {path}")
    data = bytearray(path.read_bytes())
    before_hash = sha256_bytes(data)
    if before_hash != target["sha256"]:
        fail(
            f"stock hash mismatch for {target['name']}: "
            f"expected={target['sha256']} actual={before_hash}"
        )
    parsed = parse_macho(data, str(path))
    if parsed["uuid"] != target["uuid"]:
        fail(
            f"UUID mismatch for {target['name']}: "
            f"expected={target['uuid']} actual={parsed['uuid']}"
        )
    patch_offset, patch_segment = vm_to_file(
        parsed, target["patch_vm"], len(target["patch_bytes"]), target["name"]
    )
    cave_offset, cave_segment = vm_to_file(
        parsed, target["resolver_vm"], len(resolver), target["name"]
    )
    if (
        bytes(data[patch_offset : patch_offset + len(target["patch_bytes"])])
        != target["patch_bytes"]
    ):
        fail(f"stock patch-site bytes mismatch for {target['name']}")
    if any(data[cave_offset : cave_offset + len(resolver)]):
        fail(f"resolver cave is not zero-filled for {target['name']}")
    if not (cave_segment["initprot"] & 0x4):
        fail(f"resolver cave is not executable for {target['name']}")

    patched_resolver, resolver_report = patch_resolver(resolver, target)
    data[cave_offset : cave_offset + len(patched_resolver)] = patched_resolver
    call_patch = encode_branch(target["patch_vm"], target["resolver_vm"], True)
    call_patch += struct.pack("<I", 0xD503201F) * 5
    data[patch_offset : patch_offset + len(call_patch)] = call_patch
    path.write_bytes(data)
    return {
        "name": target["name"],
        "path": str(path.relative_to(app.parent.parent)),
        "uuid": target["uuid"],
        "before_sha256": before_hash,
        "after_runtime_patch_sha256": sha256_bytes(data),
        "patch_vm": f"0x{target['patch_vm']:x}",
        "patch_file_offset": f"0x{patch_offset:x}",
        "stock_patch_bytes": target["patch_bytes"].hex(),
        "patched_call_bytes": call_patch.hex(),
        "resolver_vm": f"0x{target['resolver_vm']:x}",
        "resolver_file_offset": f"0x{cave_offset:x}",
        "dlopen_vm": f"0x{target['dlopen_vm']:x}",
        "dlsym_vm": f"0x{target['dlsym_vm']:x}",
        "patch_segment": patch_segment["name"],
        "resolver_segment": cave_segment["name"],
        **resolver_report,
    }


def strip_signature_bytes(data: bytes, relative_path: str) -> tuple[bytes, dict]:
    data = bytearray(data)
    parsed = parse_macho(data, relative_path)
    code_signature = parsed["code_signature"]
    if code_signature is None:
        fail(f"Mach-O lacks LC_CODE_SIGNATURE: {relative_path}")
    linkedit_matches = [
        segment for segment in parsed["segments"] if segment["name"] == "__LINKEDIT"
    ]
    if len(linkedit_matches) != 1:
        fail(f"expected one __LINKEDIT segment: {relative_path}")
    linkedit = linkedit_matches[0]
    dataoff = code_signature["dataoff"]
    datasize = code_signature["datasize"]
    if datasize <= 0 or dataoff + datasize != len(data):
        fail(
            f"signature is not a non-empty EOF payload: {relative_path} "
            f"off={dataoff} size={datasize} file={len(data)}"
        )
    if not (
        linkedit["fileoff"]
        <= dataoff
        <= linkedit["fileoff"] + linkedit["filesize"]
    ):
        fail(f"signature lies outside __LINKEDIT: {relative_path}")
    before_hash = sha256_bytes(data)
    before_size = len(data)
    new_filesize = dataoff - linkedit["fileoff"]
    new_vmsize = (new_filesize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    struct.pack_into(
        "<II",
        data,
        code_signature["command_offset"] + 8,
        dataoff,
        0,
    )
    struct.pack_into(
        "<QQQQ",
        data,
        linkedit["command_offset"] + 24,
        linkedit["vmaddr"],
        new_vmsize,
        linkedit["fileoff"],
        new_filesize,
    )
    data = data[:dataoff]
    report = {
        "path": relative_path,
        "before_strip_sha256": before_hash,
        "after_strip_sha256": sha256_bytes(data),
        "old_file_size": before_size,
        "new_file_size": len(data),
        "signature_dataoff": dataoff,
        "removed_signature_bytes": datasize,
        "lc_code_signature_datasize_after": 0,
        "linkedit_fileoff": linkedit["fileoff"],
        "linkedit_filesize_before": linkedit["filesize"],
        "linkedit_filesize_after": new_filesize,
        "linkedit_vmsize_before": linkedit["vmsize"],
        "linkedit_vmsize_after": new_vmsize,
    }
    return bytes(data), report


def strip_macho_file(path: pathlib.Path, relative_path: str) -> tuple[dict, int]:
    original = path.read_bytes()
    if original[:4] == MH_MAGIC_64_LE:
        stripped, report = strip_signature_bytes(original, relative_path)
        path.write_bytes(stripped)
        return {"container": "thin", "slices": [report]}, 1
    if original[:4] != FAT_MAGIC_BE:
        fail(f"unsupported Mach-O container: {relative_path}")
    if len(original) < 8:
        fail(f"truncated fat header: {relative_path}")
    slice_count = struct.unpack_from(">I", original, 4)[0]
    if slice_count <= 0 or 8 + 20 * slice_count > len(original):
        fail(f"invalid fat architecture table: {relative_path}")
    result = bytearray(original)
    reports = []
    final_size = 8 + 20 * slice_count
    previous_end = 0
    for index in range(slice_count):
        arch_offset = 8 + 20 * index
        cpu_type, cpu_subtype, offset, size, align_power = struct.unpack_from(
            ">iiIII", original, arch_offset
        )
        alignment = 1 << align_power
        if offset % alignment or offset < previous_end or offset + size > len(original):
            fail(f"invalid fat slice {index}: {relative_path}")
        slice_label = f"{relative_path}[slice={index},cpu={cpu_type}:{cpu_subtype}]"
        stripped, report = strip_signature_bytes(
            original[offset : offset + size], slice_label
        )
        result[offset : offset + size] = b"\0" * size
        result[offset : offset + len(stripped)] = stripped
        struct.pack_into(">I", result, arch_offset + 12, len(stripped))
        report.update(
            {
                "slice_index": index,
                "cpu_type": cpu_type,
                "cpu_subtype": cpu_subtype,
                "fat_offset": offset,
                "fat_alignment_power": align_power,
            }
        )
        reports.append(report)
        previous_end = offset + size
        final_size = max(final_size, offset + len(stripped))
    result = result[:final_size]
    path.write_bytes(result)
    return {"container": "fat32", "slices": reports}, slice_count


def excluded_from_output(name: str) -> bool:
    parts = pathlib.PurePosixPath(name).parts
    return "_CodeSignature" in parts or (
        parts and parts[-1] == "embedded.mobileprovision"
    )


def write_preserving_archive(
    source_ipa: pathlib.Path, extracted_root: pathlib.Path, output_ipa: pathlib.Path
) -> None:
    with zipfile.ZipFile(source_ipa, "r") as source, zipfile.ZipFile(
        output_ipa, "x"
    ) as output:
        for source_info in source.infolist():
            if excluded_from_output(source_info.filename):
                continue
            info = copy.copy(source_info)
            if source_info.is_dir():
                payload = b""
            else:
                payload = (extracted_root / source_info.filename).read_bytes()
            output.writestr(
                info,
                payload,
                compress_type=source_info.compress_type,
                compresslevel=9,
            )


def ensure_external_new_path(path: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if resolved == PROJECT_ROOT or resolved.is_relative_to(PROJECT_ROOT):
        fail(f"{label} must be outside the repository: {resolved}")
    if resolved.exists():
        fail(f"refusing to overwrite existing {label}: {resolved}")
    return resolved


def build(
    input_ipa: pathlib.Path,
    output_ipa: pathlib.Path,
    derive_carrier_hash: bool = False,
) -> dict:
    input_ipa = input_ipa.expanduser().resolve()
    if not input_ipa.is_file():
        fail(f"input IPA not found: {input_ipa}")
    input_hash = sha256_path(input_ipa)
    if input_hash != EXPECTED_INPUT_SHA256:
        fail(
            "refusing unsealed input IPA: "
            f"expected={EXPECTED_INPUT_SHA256} actual={input_hash}"
        )
    output_ipa = ensure_external_new_path(output_ipa, "output IPA")
    receipt_path = ensure_external_new_path(
        pathlib.Path(str(output_ipa) + ".neutral.json"), "receipt"
    )
    output_ipa.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ynab-ios-v10-") as temporary:
        work_dir = pathlib.Path(temporary)
        with zipfile.ZipFile(input_ipa, "r") as source:
            source.extractall(work_dir)
            source_file_entries = sorted(
                info.filename for info in source.infolist() if not info.is_dir()
            )
        apps = list((work_dir / "Payload").glob("*.app"))
        if len(apps) != 1:
            fail(f"expected one Payload/*.app, found {len(apps)}")
        app = apps[0]
        info = plistlib.loads((app / "Info.plist").read_bytes())
        identity = {
            "bundle_id": info.get("CFBundleIdentifier"),
            "version": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
        }
        expected_identity = {
            "bundle_id": EXPECTED_BUNDLE_ID,
            "version": EXPECTED_VERSION,
            "build": EXPECTED_BUILD,
        }
        if identity != expected_identity:
            fail(f"stock identity mismatch: expected={expected_identity} actual={identity}")

        resolver = compile_resolver(work_dir)
        patch_reports = [patch_target(app, target, resolver) for target in TARGETS]

        removed_signature_dirs = []
        for directory in sorted(
            (item for item in app.rglob("_CodeSignature") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            removed_signature_dirs.append(str(directory.relative_to(work_dir)))
            shutil.rmtree(directory)
        removed_profiles = []
        for profile in app.rglob("embedded.mobileprovision"):
            removed_profiles.append(str(profile.relative_to(work_dir)))
            profile.unlink()

        macho_paths = []
        for path in app.rglob("*"):
            if not path.is_file():
                continue
            with path.open("rb") as stream:
                magic = stream.read(4)
            if magic in (MH_MAGIC_64_LE, FAT_MAGIC_BE):
                macho_paths.append(path)
        macho_paths.sort()
        if len(macho_paths) != EXPECTED_MACHO_CONTAINER_COUNT:
            fail(
                "Mach-O container count mismatch: "
                f"expected={EXPECTED_MACHO_CONTAINER_COUNT} "
                f"actual={len(macho_paths)}"
            )
        macho_reports = []
        macho_slice_count = 0
        for path in macho_paths:
            report, slice_count = strip_macho_file(
                path, str(path.relative_to(work_dir))
            )
            report["path"] = str(path.relative_to(work_dir))
            macho_reports.append(report)
            macho_slice_count += slice_count
        if macho_slice_count != EXPECTED_MACHO_SLICE_COUNT:
            fail(
                f"Mach-O slice count mismatch: expected={EXPECTED_MACHO_SLICE_COUNT} "
                f"actual={macho_slice_count}"
            )

        expected_file_entries = sorted(
            name for name in source_file_entries if not excluded_from_output(name)
        )
        actual_file_entries = sorted(
            str(path.relative_to(work_dir))
            for path in work_dir.rglob("*")
            if path.is_file() and path.name != "YNABAppGroupResolver.o"
        )
        if actual_file_entries != expected_file_entries:
            fail("extracted output file surface differs beyond signing resources")

        write_preserving_archive(input_ipa, work_dir, output_ipa)

    output_hash = sha256_path(output_ipa)
    if not derive_carrier_hash and output_hash != EXPECTED_CARRIER_SHA256:
        fail(
            "carrier hash mismatch: "
            f"expected={EXPECTED_CARRIER_SHA256} actual={output_hash}"
        )
    with zipfile.ZipFile(output_ipa, "r") as result:
        output_files = sorted(
            info.filename for info in result.infolist() if not info.is_dir()
        )
    report = {
        "schema": "ynab-ios-signer-neutral-receipt/v1",
        "version_id": VERSION_ID,
        "artifact": output_ipa.name,
        "purpose": (
            "Resign-required carrier with only signer App Group "
            "neutrality patches; no private-server feature layer"
        ),
        "source": {
            "artifact": input_ipa.name,
            "sha256": input_hash,
            "expected_sha256": EXPECTED_INPUT_SHA256,
        },
        "output": {
            "sha256": output_hash,
            "profile_sealed": not derive_carrier_hash,
            **identity,
            "requires_final_signing": True,
            "runtime_signer_neutrality": True,
            "private_server_feature": False,
        },
        "runtime_patches": patch_reports,
        "neutralization": {
            "method": (
                "remove _CodeSignature resources and embedded profiles; truncate "
                "each EOF Mach-O signature payload; retain LC_CODE_SIGNATURE with "
                "datasize zero; update __LINKEDIT filesize and page-aligned vmsize"
            ),
            "code_signature_directories_removed": len(removed_signature_dirs),
            "embedded_profiles_removed": len(removed_profiles),
            "macho_container_count": len(macho_reports),
            "macho_slice_count": macho_slice_count,
            "macho_signatures_stripped": macho_slice_count,
        },
        "stock_preservation": {
            "source_file_count": len(source_file_entries),
            "output_file_count": len(output_files),
            "file_delta_limited_to_signing_resources": True,
            "runtime_patched_macho_count": len(patch_reports),
            "all_other_payload_files_preserved": True,
        },
        "removed_code_signature_dirs": removed_signature_dirs,
        "removed_profiles": removed_profiles,
        "macho_signature_report": macho_reports,
        "notes": [
            "This is unsigned and must fail codesign verification until final signing.",
            "No server URL UI, endpoint rewrite, offline widget, or login bypass is present.",
            "The final signing entitlements must make the same usable App Group sort first in the main app and both widget extensions.",
            *(
                [
                    "Authoring-only output: copy this carrier SHA-256 into the profile, then rebuild normally and independently verify."
                ]
                if derive_carrier_hash
                else []
            ),
        ],
    }
    receipt_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return {
        "input_sha256": input_hash,
        "output": str(output_ipa),
        "output_sha256": output_hash,
        "receipt": str(receipt_path),
        "runtime_patches": len(patch_reports),
        "macho_containers_stripped": len(macho_reports),
        "macho_slices_stripped": macho_slice_count,
        "signature_dirs_removed": len(removed_signature_dirs),
        "profile_sealed": not derive_carrier_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, dest="version_id")
    parser.add_argument(
        "--derive-carrier-hash",
        action="store_true",
        help="authoring only: require a null carrier hash and report the derived value",
    )
    parser.add_argument("input_ipa", type=pathlib.Path)
    parser.add_argument("output_ipa", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        load_version(arguments.version_id, arguments.derive_carrier_hash)
        result = build(
            arguments.input_ipa,
            arguments.output_ipa,
            arguments.derive_carrier_hash,
        )
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        zipfile.BadZipFile,
        json.JSONDecodeError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
