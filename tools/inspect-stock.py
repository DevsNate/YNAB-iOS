#!/usr/bin/env python3
"""Inspect a decrypted stock YNAB IPA before artifact-profile admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import struct
import sys
import zipfile


MH_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
FAT_MAGIC_BE = b"\xca\xfe\xba\xbe"
LC_UUID = 0x1B

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_member_name(name: str) -> None:
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        fail(f"unsafe ZIP member path: {name}")


def thin_uuid(data: bytes, label: str) -> str:
    if len(data) < 32 or data[:4] != MH_MAGIC_64_LE:
        fail(f"not a thin little-endian Mach-O 64 image: {label}")
    command_count = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    uuid = None
    for _ in range(command_count):
        if offset + 8 > len(data):
            fail(f"truncated load-command table: {label}")
        command, command_size = struct.unpack_from("<II", data, offset)
        if command_size < 8 or offset + command_size > len(data):
            fail(f"invalid load command at {offset:#x}: {label}")
        if command == LC_UUID:
            if command_size < 24 or uuid is not None:
                fail(f"invalid LC_UUID command: {label}")
            uuid = data[offset + 8 : offset + 24].hex()
        offset += command_size
    if uuid is None:
        fail(f"Mach-O lacks LC_UUID: {label}")
    return uuid


def inspect_macho(data: bytes, label: str) -> dict:
    if data[:4] == MH_MAGIC_64_LE:
        return {
            "container": "thin",
            "sliceCount": 1,
            "uuids": [thin_uuid(data, label)],
        }
    if data[:4] != FAT_MAGIC_BE or len(data) < 8:
        fail(f"unsupported Mach-O container: {label}")
    slice_count = struct.unpack_from(">I", data, 4)[0]
    if slice_count <= 0 or 8 + 20 * slice_count > len(data):
        fail(f"invalid fat architecture table: {label}")
    uuids = []
    previous_end = 0
    for index in range(slice_count):
        entry = 8 + 20 * index
        _, _, offset, size, align_power = struct.unpack_from(">iiIII", data, entry)
        alignment = 1 << align_power
        if offset % alignment or offset < previous_end or offset + size > len(data):
            fail(f"invalid fat slice {index}: {label}")
        uuids.append(thin_uuid(data[offset : offset + size], f"{label}[{index}]"))
        previous_end = offset + size
    return {"container": "fat32", "sliceCount": slice_count, "uuids": uuids}


def load_reference(version_id: str | None) -> tuple[dict, dict] | None:
    if version_id is None:
        return None
    version_root = PROJECT_ROOT / "versions" / version_id
    stock_path = version_root / "stock.json"
    neutral_path = version_root / "signer-neutral.json"
    if not stock_path.is_file() or not neutral_path.is_file():
        fail(f"reference version is not admitted: {version_id}")
    stock = json.loads(stock_path.read_text(encoding="utf-8"))
    neutral = json.loads(neutral_path.read_text(encoding="utf-8"))
    if stock.get("versionId") != version_id or neutral.get("versionId") != version_id:
        fail("reference profile identity mismatch")
    return stock, neutral


def classify_reference(
    exact_input: bool,
    same_version_id: bool,
    identity_match: bool,
    requires_mapping: bool,
) -> tuple[str, str]:
    if exact_input:
        return (
            "already-admitted",
            "Use the existing admitted profile; do not create a duplicate.",
        )
    if same_version_id:
        return (
            "provenance-conflict",
            "Stop: different bytes claim the same version and build as the reference.",
        )
    if not identity_match:
        return (
            "incompatible-product",
            "Stop: the bundle identity does not match the reference product.",
        )
    if requires_mapping:
        return (
            "requires-target-mapping",
            "Resolve only changed or missing signer-neutral targets before authoring a profile.",
        )
    return (
        "target-compatible",
        "Reuse unchanged target bindings and author a new immutable profile.",
    )


def inspect_stock(input_ipa: pathlib.Path, reference_version: str | None) -> dict:
    input_ipa = input_ipa.expanduser().resolve()
    if not input_ipa.is_file():
        fail(f"input IPA not found: {input_ipa}")
    reference = load_reference(reference_version)
    with zipfile.ZipFile(input_ipa, "r") as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if len(names) != len(set(names)):
            fail("duplicate ZIP entry detected")
        for name in names:
            validate_member_name(name)
        files = [item.filename for item in members if not item.is_dir()]
        info_paths = []
        for name in files:
            parts = pathlib.PurePosixPath(name).parts
            if (
                len(parts) == 3
                and parts[0] == "Payload"
                and parts[1].endswith(".app")
                and parts[2] == "Info.plist"
            ):
                info_paths.append(name)
        if len(info_paths) != 1:
            fail(f"expected one Payload/*.app/Info.plist, found {len(info_paths)}")
        info_path = info_paths[0]
        main_app_path = str(pathlib.PurePosixPath(info_path).parent)
        info = plistlib.loads(archive.read(info_path))
        identity = {
            "product": pathlib.PurePosixPath(main_app_path).stem,
            "bundleIdentifier": info.get("CFBundleIdentifier"),
            "marketingVersion": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
        }
        if not all(isinstance(value, str) and value for value in identity.values()):
            fail(f"incomplete main-app identity: {identity}")
        version_id = f"{identity['marketingVersion']}-{identity['build']}"
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version_id) is None:
            fail(f"unsafe version/build identity: {version_id}")

        app_prefix = main_app_path + "/"
        macho = []
        macho_data = {}
        for name in files:
            if not name.startswith(app_prefix):
                continue
            data = archive.read(name)
            if data[:4] not in (MH_MAGIC_64_LE, FAT_MAGIC_BE):
                continue
            relative = name[len(app_prefix) :]
            shape = inspect_macho(data, name)
            record = {
                "path": relative,
                "sha256": sha256_bytes(data),
                **shape,
            }
            macho.append(record)
            macho_data[relative] = record
        macho.sort(key=lambda item: item["path"])

        signature_directories = set()
        embedded_profiles = []
        for name in files:
            parts = pathlib.PurePosixPath(name).parts
            if "_CodeSignature" in parts:
                index = parts.index("_CodeSignature")
                signature_directories.add("/".join(parts[: index + 1]))
            if parts and parts[-1] == "embedded.mobileprovision":
                embedded_profiles.append(name)

        extensions = []
        plugin_prefix = app_prefix + "PlugIns/"
        for name in files:
            path = pathlib.PurePosixPath(name)
            if not name.startswith(plugin_prefix) or path.name != "Info.plist":
                continue
            if len(path.parts) != len(pathlib.PurePosixPath(main_app_path).parts) + 3:
                continue
            if not path.parent.name.endswith(".appex"):
                continue
            extension_info = plistlib.loads(archive.read(name))
            extensions.append(
                {
                    "path": str(path.parent.relative_to(main_app_path)),
                    "bundleIdentifier": extension_info.get("CFBundleIdentifier"),
                    "executable": extension_info.get("CFBundleExecutable"),
                }
            )
        extensions.sort(key=lambda item: item["path"])

        report = {
            "schema": "ynab-ios-stock-inspection/v1",
            "versionId": version_id,
            "artifact": {
                "filename": input_ipa.name,
                "sha256": sha256_path(input_ipa),
                "size": input_ipa.stat().st_size,
            },
            "identity": identity,
            "mainAppPath": main_app_path,
            "inventory": {
                "regularFiles": len(files),
                "machoContainers": len(macho),
                "machoSlices": sum(item["sliceCount"] for item in macho),
                "signatureDirectories": len(signature_directories),
                "embeddedProfiles": len(embedded_profiles),
                "extensions": len(extensions),
            },
            "extensions": extensions,
            "macho": macho,
        }

        if reference is not None:
            reference_stock, reference_neutral = reference
            comparisons = []
            for target in reference_neutral["targets"]:
                current = macho_data.get(target["path"])
                status = "missing"
                if current is not None:
                    status = (
                        "unchanged"
                        if current["sha256"] == target["sha256"]
                        else "changed"
                    )
                comparisons.append(
                    {
                        "name": target["name"],
                        "path": target["path"],
                        "status": status,
                        "referenceSha256": target["sha256"],
                        "currentSha256": current["sha256"] if current else None,
                        "currentUuids": current["uuids"] if current else [],
                    }
                )
            exact_input = report["artifact"]["sha256"] == reference_stock["input"]["sha256"]
            identity_match = identity["bundleIdentifier"] == reference_stock["bundleIdentifier"]
            requires_mapping = any(item["status"] != "unchanged" for item in comparisons)
            inventory_comparison = {}
            for key in ("regularFiles", "machoContainers", "machoSlices"):
                reference_value = reference_stock["inventory"][key]
                current_value = report["inventory"][key]
                inventory_comparison[key] = {
                    "reference": reference_value,
                    "current": current_value,
                    "status": "unchanged" if current_value == reference_value else "changed",
                }
            same_version_id = version_id == reference_version
            classification, next_action = classify_reference(
                exact_input,
                same_version_id,
                identity_match,
                requires_mapping,
            )
            report["reference"] = {
                "versionId": reference_version,
                "exactInputMatch": exact_input,
                "versionIdMatch": same_version_id,
                "bundleIdentityMatch": identity_match,
                "mainAppPathMatch": main_app_path == reference_stock["mainAppPath"],
                "inventoryComparison": inventory_comparison,
                "targetComparison": comparisons,
                "classification": classification,
                "nextAction": next_action,
            }
        return report


def write_external_report(report: dict, output_path: pathlib.Path) -> pathlib.Path:
    resolved = output_path.expanduser().resolve()
    if resolved == PROJECT_ROOT or resolved.is_relative_to(PROJECT_ROOT):
        fail(f"inspection report must be outside the repository: {resolved}")
    if resolved.exists():
        fail(f"refusing to overwrite inspection report: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-version")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("input_ipa", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        report = inspect_stock(arguments.input_ipa, arguments.reference_version)
        if arguments.output is not None:
            write_external_report(report, arguments.output)
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
