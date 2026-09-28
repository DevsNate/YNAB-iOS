#!/usr/bin/env python3
"""Build the complete signer-neutral, private-server-ready YNAB IPA."""

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


MH_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_DYLIB = 0xC
DYLIB_COMMANDS = {0xC, 0xD, 0x20, 0x80000018, 0x8000001F, 0x80000023}

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
INSTALL_NAME = "@rpath/YNABServerOrigin.dylib"


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


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_external_new_path(path: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if resolved == PROJECT_ROOT or resolved.is_relative_to(PROJECT_ROOT):
        fail(f"{label} must be outside the repository: {resolved}")
    if resolved.exists():
        fail(f"refusing to overwrite existing {label}: {resolved}")
    return resolved


def parse_macho(data: bytes | bytearray, label: str) -> dict:
    if len(data) < 32 or bytes(data[:4]) != MH_MAGIC_64_LE:
        fail(f"not a thin little-endian Mach-O 64 image: {label}")
    command_count, command_bytes = struct.unpack_from("<II", data, 16)
    offset = 32
    commands = []
    sections = []
    uuid = None
    dylibs = []
    code_signature = None
    for _ in range(command_count):
        if offset + 8 > len(data):
            fail(f"truncated load-command table: {label}")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > len(data):
            fail(f"invalid load command at {offset:#x}: {label}")
        commands.append((offset, command, size))
        if command == LC_SEGMENT_64:
            section_count = struct.unpack_from("<I", data, offset + 64)[0]
            for index in range(section_count):
                section = offset + 72 + index * 80
                section_size = struct.unpack_from("<Q", data, section + 40)[0]
                file_offset = struct.unpack_from("<I", data, section + 48)[0]
                if section_size and file_offset:
                    sections.append((file_offset, section_size))
        elif command == LC_UUID:
            uuid = bytes(data[offset + 8 : offset + 24]).hex()
        elif command == LC_CODE_SIGNATURE:
            code_signature = struct.unpack_from("<II", data, offset + 8)
        elif command in DYLIB_COMMANDS:
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if name_offset >= size:
                fail(f"invalid dylib name offset: {label}")
            raw = bytes(data[offset + name_offset : offset + size]).split(b"\0", 1)[0]
            dylibs.append(raw.decode("utf-8"))
        offset += size
    if offset != 32 + command_bytes:
        fail(f"load-command size mismatch: {label}")
    return {
        "command_count": command_count,
        "command_bytes": command_bytes,
        "command_end": offset,
        "commands": commands,
        "sections": sections,
        "uuid": uuid,
        "dylibs": dylibs,
        "code_signature": code_signature,
    }


def add_load_command(path: pathlib.Path, target: dict) -> dict:
    data = bytearray(path.read_bytes())
    before_hash = sha256_bytes(data)
    if before_hash != target["neutralSha256"]:
        fail(
            f"neutral target hash mismatch for {target['name']}: "
            f"expected={target['neutralSha256']} actual={before_hash}"
        )
    parsed = parse_macho(data, str(path))
    if parsed["uuid"] != target["uuid"]:
        fail(f"Mach-O UUID mismatch for {target['name']}")
    if parsed["code_signature"] is None or parsed["code_signature"][1] != 0:
        fail(f"target is not signer-neutral: {target['name']}")
    if INSTALL_NAME in parsed["dylibs"]:
        fail(f"private-server load command already exists: {target['name']}")

    name = INSTALL_NAME.encode("utf-8") + b"\0"
    command_size = (24 + len(name) + 7) & ~7
    first_section = min((offset for offset, _ in parsed["sections"]), default=None)
    command_end = parsed["command_end"]
    if first_section is None or command_end + command_size > first_section:
        fail(f"insufficient load-command slack: {target['name']}")
    if any(data[command_end : command_end + command_size]):
        fail(f"load-command insertion area is not zero-filled: {target['name']}")

    blob = bytearray(command_size)
    struct.pack_into(
        "<IIIIII", blob, 0, LC_LOAD_DYLIB, command_size, 24, 2, 0x10000, 0x10000
    )
    blob[24 : 24 + len(name)] = name
    data[command_end : command_end + command_size] = blob
    struct.pack_into("<I", data, 16, parsed["command_count"] + 1)
    struct.pack_into("<I", data, 20, parsed["command_bytes"] + command_size)
    path.write_bytes(data)
    after = parse_macho(data, str(path))
    if after["dylibs"].count(INSTALL_NAME) != 1:
        fail(f"load-command insertion verification failed: {target['name']}")
    return {
        "name": target["name"],
        "path": target["path"],
        "uuid": target["uuid"],
        "beforeSha256": before_hash,
        "afterSha256": sha256_bytes(data),
        "installName": INSTALL_NAME,
        "commandSize": command_size,
        "headerSlackBefore": first_section - command_end,
        "headerSlackAfter": first_section - command_end - command_size,
    }


def apply_source_binding(path: pathlib.Path, binding: dict) -> dict:
    data = bytearray(path.read_bytes())
    offset = int(binding["fileOffset"], 0)
    before = bytes.fromhex(binding["beforeHex"])
    after = bytes.fromhex(binding["afterHex"])
    if not before or len(before) != len(after):
        fail(f"invalid source binding length: {binding['id']}")
    if offset < 0 or offset + len(before) > len(data):
        fail(f"source binding is outside target: {binding['id']}")
    if bytes(data[offset : offset + len(before)]) != before:
        fail(f"source binding preimage mismatch: {binding['id']}")
    before_hash = sha256_bytes(data)
    data[offset : offset + len(after)] = after
    path.write_bytes(data)
    return {
        "id": binding["id"],
        "targetPath": binding["targetPath"],
        "fileOffset": binding["fileOffset"],
        "vmAddress": binding["vmAddress"],
        "beforeHex": binding["beforeHex"],
        "afterHex": binding["afterHex"],
        "beforeSha256": before_hash,
        "afterSha256": sha256_bytes(data),
    }


def compile_component(profile: dict, work_dir: pathlib.Path) -> pathlib.Path:
    component = profile["component"]
    binding = profile["nativeTextActionBinding"]
    source = (PROJECT_ROOT / component["source"]).resolve()
    if not source.is_relative_to(PROJECT_ROOT) or not source.is_file():
        fail("server-origin component source path is invalid")
    if sha256_path(source) != component["sourceSha256"]:
        fail("server-origin component source hash mismatch")

    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True
    ).strip()
    output = work_dir / "YNABServerOrigin.dylib"
    subprocess.run(
        [
            "xcrun",
            "--sdk",
            "iphoneos",
            "clang",
            "-dynamiclib",
            "-fobjc-arc",
            "-fblocks",
            "-arch",
            "arm64",
            "-miphoneos-version-min=18.0",
            "-isysroot",
            sdk,
            f"-DYN_BUTTON_TEMPLATE_VM_ADDRESS={binding['factoryVmAddress']}ULL",
            f"-DYN_FORGOT_TITLE_COUNT_AND_FLAGS={binding['sourceTitleCountAndFlags']}ULL",
            f"-DYN_FORGOT_TITLE_OBJECT_VM_ADDRESS={binding['sourceTitleObjectVmAddress']}ULL",
            f"-DYN_FORGOT_ACCESSIBILITY_COUNT_AND_FLAGS={binding['sourceAccessibilityCountAndFlags']}ULL",
            f"-DYN_FORGOT_ACCESSIBILITY_OBJECT_VM_ADDRESS={binding['sourceAccessibilityObjectVmAddress']}ULL",
            "-DYN_NATIVE_TEXT_ACTION_CLASS_SUFFIX=\""
            + binding["expectedClassSuffix"]
            + "\"",
            "-framework",
            "Foundation",
            "-framework",
            "UIKit",
            f"-Wl,-install_name,{INSTALL_NAME}",
            "-Wl,-no_adhoc_codesign",
            str(source),
            "-o",
            str(output),
        ],
        check=True,
    )
    if output.stat().st_size != component["compiledDylibSize"]:
        fail("compiled server-origin dylib size mismatch")
    if sha256_path(output) != component["compiledDylibSha256"]:
        fail("compiled server-origin dylib hash mismatch")
    parsed = parse_macho(output.read_bytes(), str(output))
    if parsed["uuid"] != component["compiledDylibUuid"]:
        fail("compiled server-origin dylib UUID mismatch")
    if parsed["code_signature"] is not None:
        fail("compiled server-origin dylib is unexpectedly signed")
    return output


def update_transport_policy(info_path: pathlib.Path) -> dict:
    data = info_path.read_bytes()
    info = plistlib.loads(data)
    transport = dict(info.get("NSAppTransportSecurity", {}))
    previous = transport.get("NSAllowsLocalNetworking")
    transport["NSAllowsLocalNetworking"] = True
    info["NSAppTransportSecurity"] = transport
    format_ = plistlib.FMT_BINARY if data.startswith(b"bplist") else plistlib.FMT_XML
    info_path.write_bytes(plistlib.dumps(info, fmt=format_, sort_keys=False))
    return {
        "key": "NSAppTransportSecurity.NSAllowsLocalNetworking",
        "previous": previous,
        "current": True,
    }


def safe_extract(archive: zipfile.ZipFile, root: pathlib.Path) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    names = [member.filename for member in members]
    if len(names) != len(set(names)):
        fail("neutral carrier contains duplicate ZIP entries")
    for name in names:
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            fail(f"unsafe ZIP entry: {name}")
    archive.extractall(root, members)
    return members


def write_archive(
    source_ipa: pathlib.Path,
    extracted_root: pathlib.Path,
    output_ipa: pathlib.Path,
    added_relative_path: str,
) -> None:
    with zipfile.ZipFile(source_ipa, "r") as source, zipfile.ZipFile(
        output_ipa, "x"
    ) as output:
        members = source.infolist()
        for source_info in members:
            info = copy.copy(source_info)
            payload = b"" if source_info.is_dir() else (
                extracted_root / source_info.filename
            ).read_bytes()
            output.writestr(
                info,
                payload,
                compress_type=source_info.compress_type,
                compresslevel=9,
            )
        added = zipfile.ZipInfo(added_relative_path, (1980, 1, 1, 0, 0, 0))
        added.compress_type = zipfile.ZIP_DEFLATED
        added.external_attr = 0o100755 << 16
        added.create_system = 3
        output.writestr(
            added,
            (extracted_root / added_relative_path).read_bytes(),
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )


def validate_profile(version_id: str, derive_carrier_hash: bool) -> tuple[dict, dict, dict]:
    version_root = PROJECT_ROOT / "versions" / version_id
    stock = read_json(version_root / "stock.json")
    neutral = read_json(version_root / "signer-neutral.json")
    private = read_json(version_root / "private-server.json")
    if stock.get("schema") != "ynab-ios-stock/v1":
        fail("unsupported stock profile")
    if neutral.get("schema") != "ynab-ios-signer-neutral/v1":
        fail("unsupported signer-neutral profile")
    if private.get("schema") != "ynab-ios-private-server/v1":
        fail("unsupported private-server profile")
    if any(item.get("versionId") != version_id for item in (stock, neutral, private)):
        fail("version profile identity mismatch")
    if private.get("artifactRole") != "product-carrier":
        fail("private-server profile has an invalid artifact role")
    expected = private.get("expectedCarrierSha256")
    if derive_carrier_hash:
        if expected is not None:
            fail("carrier-hash derivation requires a null expected carrier hash")
    elif not isinstance(expected, str) or len(expected) != 64:
        fail("private-server profile is not sealed with a carrier SHA-256")
    if private["component"]["installName"] != INSTALL_NAME:
        fail("private-server install-name mismatch")
    text_action = private.get("nativeTextActionBinding")
    if not isinstance(text_action, dict):
        fail("native text-action binding is missing")
    for key in (
        "factoryVmAddress",
        "sourceTitleCountAndFlags",
        "sourceTitleObjectVmAddress",
        "sourceAccessibilityCountAndFlags",
        "sourceAccessibilityObjectVmAddress",
    ):
        value = text_action.get(key)
        try:
            parsed = int(value, 0)
        except (TypeError, ValueError):
            fail(f"native text-action binding is invalid: {key}")
        if parsed <= 0 or parsed > 0xFFFFFFFFFFFFFFFF:
            fail(f"native text-action binding is out of range: {key}")
    suffix = text_action.get("expectedClassSuffix")
    if not isinstance(suffix, str) or not suffix or not suffix.isidentifier():
        fail("native text-action class suffix is invalid")
    if text_action.get("invocationBoundary") != (
        "controller lifecycle or one-shot owned-stack mutation on main thread"
    ):
        fail("native text-action invocation boundary is invalid")
    target_paths = {target["path"] for target in private["targets"]}
    for binding in private.get("sourceBindings", []):
        if binding.get("targetPath") not in target_paths:
            fail("source binding target is not a declared load target")
    return stock, neutral, private


def build(
    version_id: str,
    input_ipa: pathlib.Path,
    output_ipa: pathlib.Path,
    derive_carrier_hash: bool,
) -> dict:
    stock, neutral_profile, private = validate_profile(version_id, derive_carrier_hash)
    input_ipa = input_ipa.expanduser().resolve()
    if not input_ipa.is_file() or sha256_path(input_ipa) != stock["input"]["sha256"]:
        fail(f"input does not match the sealed {version_id} stock artifact")
    output_ipa = ensure_external_new_path(output_ipa, "output IPA")
    receipt_path = ensure_external_new_path(
        pathlib.Path(str(output_ipa) + ".private-server.json"), "receipt"
    )
    output_ipa.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f"ynab-{version_id}-private-server-") as temp:
        temporary = pathlib.Path(temp)
        neutral_ipa = temporary / "internal-signer-neutral.ipa"
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "build-signer-neutral.py"),
                "--version",
                version_id,
                str(input_ipa),
                str(neutral_ipa),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        neutral_receipt_path = pathlib.Path(str(neutral_ipa) + ".neutral.json")
        neutral_receipt = read_json(neutral_receipt_path)
        if neutral_receipt["output"]["sha256"] != neutral_profile["expectedCarrierSha256"]:
            fail("internal signer-neutral component did not reproduce its sealed hash")

        extracted = temporary / "package"
        extracted.mkdir()
        with zipfile.ZipFile(neutral_ipa, "r") as archive:
            neutral_members = safe_extract(archive, extracted)
        app = extracted / stock["mainAppPath"]
        if not app.is_dir():
            fail("neutral carrier main app is missing")

        component = compile_component(private, temporary)
        embedded = app / private["component"]["packagePath"]
        if embedded.exists():
            fail("server-origin dylib package path already exists")
        embedded.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(component, embedded)

        load_reports = [
            add_load_command(app / target["path"], target)
            for target in private["targets"]
        ]
        binding_reports = [
            apply_source_binding(app / binding["targetPath"], binding)
            for binding in private.get("sourceBindings", [])
        ]
        transport_report = update_transport_policy(app / "Info.plist")
        added_relative = str(embedded.relative_to(extracted))
        write_archive(neutral_ipa, extracted, output_ipa, added_relative)

        expected_files = private["outputInventory"]["regularFiles"]
        with zipfile.ZipFile(output_ipa, "r") as result:
            files = [item for item in result.infolist() if not item.is_dir()]
        if len(files) != expected_files:
            fail(f"final regular-file count mismatch: expected={expected_files} actual={len(files)}")
        if len(files) != sum(not item.is_dir() for item in neutral_members) + 1:
            fail("final file delta is not limited to the runtime dylib")

    output_hash = sha256_path(output_ipa)
    expected_hash = private.get("expectedCarrierSha256")
    if not derive_carrier_hash and output_hash != expected_hash:
        output_ipa.unlink(missing_ok=True)
        fail(f"carrier hash mismatch: expected={expected_hash} actual={output_hash}")

    receipt = {
        "schema": "ynab-ios-private-server-receipt/v1",
        "versionId": version_id,
        "source": {
            "artifact": input_ipa.name,
            "sha256": stock["input"]["sha256"],
        },
        "output": {
            "artifact": output_ipa.name,
            "sha256": output_hash,
            "profileSealed": not derive_carrier_hash,
            "productAdmitted": False,
            "requiresFinalSigning": True,
        },
        "transformations": {
            "signerNeutral": {
                "componentCarrierSha256": neutral_profile["expectedCarrierSha256"],
                "runtimePatches": len(neutral_receipt["runtime_patches"]),
                "signatureDirectoriesRemoved": neutral_receipt["neutralization"][
                    "code_signature_directories_removed"
                ],
            },
            "serverOrigin": {
                "componentId": private["component"]["id"],
                "sourceSha256": private["component"]["sourceSha256"],
                "compiledDylibSha256": private["component"]["compiledDylibSha256"],
                "packagePath": private["component"]["packagePath"],
                "defaultsKey": private["component"]["defaultsKey"],
                "ownedHosts": private["component"]["ownedHosts"],
                "loadCommands": load_reports,
                "sourceBindings": binding_reports,
                "transportPolicy": transport_report,
            },
        },
        "invariants": {
            "stockAuthenticationPreserved": True,
            "stockEndpointPathsPreserved": True,
            "unrelatedTrafficPreserved": True,
            "allStockExtensionsPreserved": True,
            "intermediateCarrierPublished": False,
        },
        "verification": {"status": "pending", "deviceTested": False},
    }
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    if not derive_carrier_hash:
        try:
            verified = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "verify-private-server.py"),
                    "--version",
                    version_id,
                    str(input_ipa),
                    str(output_ipa),
                    "--receipt",
                    str(receipt_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            receipt["verification"] = {
                "status": "passed",
                **json.loads(verified.stdout),
            }
            receipt_path.write_text(
                json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
            )
        except Exception:
            output_ipa.unlink(missing_ok=True)
            receipt_path.unlink(missing_ok=True)
            raise
    return {
        "output": str(output_ipa),
        "outputSha256": output_hash,
        "receipt": str(receipt_path),
        "profileSealed": not derive_carrier_hash,
        "loadCommandsAdded": len(load_reports),
        "verification": receipt["verification"]["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, dest="version_id")
    parser.add_argument("--derive-carrier-hash", action="store_true")
    parser.add_argument("input_ipa", type=pathlib.Path)
    parser.add_argument("output_ipa", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        result = build(
            arguments.version_id,
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
