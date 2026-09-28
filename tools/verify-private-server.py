#!/usr/bin/env python3
"""Independently verify a complete YNAB private-server carrier."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import plistlib
import struct
import subprocess
import sys
import tempfile
import zipfile


MH_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
FAT_MAGIC_BE = b"\xca\xfe\xba\xbe"
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


def safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    names = [member.filename for member in members]
    if len(names) != len(set(names)):
        fail("candidate contains duplicate ZIP entries")
    for name in names:
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            fail(f"unsafe ZIP entry: {name}")
    return members


def parse_thin(data: bytes | bytearray, label: str) -> dict:
    if len(data) < 32 or bytes(data[:4]) != MH_MAGIC_64_LE:
        fail(f"not a thin arm64 Mach-O: {label}")
    command_count, command_bytes = struct.unpack_from("<II", data, 16)
    offset = 32
    commands = []
    uuid = None
    signatures = []
    dylibs = []
    for _ in range(command_count):
        if offset + 8 > len(data):
            fail(f"truncated load-command table: {label}")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > len(data):
            fail(f"invalid load command at {offset:#x}: {label}")
        commands.append((offset, command, size))
        if command == LC_UUID:
            uuid = bytes(data[offset + 8 : offset + 24]).hex()
        elif command == LC_CODE_SIGNATURE:
            signatures.append(struct.unpack_from("<II", data, offset + 8))
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
        "commandCount": command_count,
        "commandBytes": command_bytes,
        "commands": commands,
        "uuid": uuid,
        "signatures": signatures,
        "dylibs": dylibs,
    }


def slices(data: bytes, label: str) -> list[bytes]:
    if data[:4] == MH_MAGIC_64_LE:
        return [data]
    if data[:4] != FAT_MAGIC_BE or len(data) < 8:
        return []
    count = struct.unpack_from(">I", data, 4)[0]
    if count <= 0 or 8 + 20 * count > len(data):
        fail(f"invalid fat Mach-O: {label}")
    result = []
    previous_end = 0
    for index in range(count):
        _, _, offset, size, alignment_power = struct.unpack_from(
            ">iiIII", data, 8 + index * 20
        )
        if offset % (1 << alignment_power) or offset < previous_end or offset + size > len(data):
            fail(f"invalid fat slice {index}: {label}")
        result.append(data[offset : offset + size])
        previous_end = offset + size
    return result


def remove_private_load(
    data: bytes, target: dict, bindings: list[dict] | None = None
) -> bytes:
    result = bytearray(data)
    parsed = parse_thin(result, target["name"])
    if parsed["uuid"] != target["uuid"]:
        fail(f"final target UUID mismatch: {target['name']}")
    matches = []
    for offset, command, size in parsed["commands"]:
        if command != LC_LOAD_DYLIB:
            continue
        name_offset = struct.unpack_from("<I", result, offset + 8)[0]
        raw = bytes(result[offset + name_offset : offset + size]).split(b"\0", 1)[0]
        if raw.decode("utf-8") == INSTALL_NAME:
            matches.append((offset, size))
    if len(matches) != 1:
        fail(f"expected exactly one private load command: {target['name']}")
    offset, size = matches[0]
    if offset + size != 32 + parsed["commandBytes"]:
        fail(f"private load command is not the final command: {target['name']}")
    result[offset : offset + size] = b"\0" * size
    struct.pack_into("<I", result, 16, parsed["commandCount"] - 1)
    struct.pack_into("<I", result, 20, parsed["commandBytes"] - size)
    for binding in bindings or []:
        patch_offset = int(binding["fileOffset"], 0)
        before = bytes.fromhex(binding["beforeHex"])
        after = bytes.fromhex(binding["afterHex"])
        if not before or len(before) != len(after):
            fail(f"invalid source binding length: {binding['id']}")
        if bytes(result[patch_offset : patch_offset + len(after)]) != after:
            fail(f"source binding output mismatch: {binding['id']}")
        result[patch_offset : patch_offset + len(before)] = before
    if sha256_bytes(result) != target["neutralSha256"]:
        fail(f"target differs beyond declared private changes: {target['name']}")
    return bytes(result)


def project_neutral(
    stock_ipa: pathlib.Path,
    candidate_ipa: pathlib.Path,
    output: pathlib.Path,
    stock: dict,
    private: dict,
) -> None:
    main_info = f"{stock['mainAppPath']}/Info.plist"
    dylib = f"{stock['mainAppPath']}/{private['component']['packagePath']}"
    targets = {
        f"{stock['mainAppPath']}/{target['path']}": target
        for target in private["targets"]
    }
    bindings_by_path: dict[str, list[dict]] = {}
    for binding in private.get("sourceBindings", []):
        full_path = f"{stock['mainAppPath']}/{binding['targetPath']}"
        bindings_by_path.setdefault(full_path, []).append(binding)
    with zipfile.ZipFile(stock_ipa, "r") as stock_archive:
        stock_info = stock_archive.read(main_info)
    with zipfile.ZipFile(candidate_ipa, "r") as candidate, zipfile.ZipFile(
        output, "x"
    ) as projected:
        for member in safe_members(candidate):
            if member.filename == dylib:
                continue
            info = copy.copy(member)
            if member.is_dir():
                payload = b""
            elif member.filename == main_info:
                payload = stock_info
            elif member.filename in targets:
                payload = remove_private_load(
                    candidate.read(member),
                    targets[member.filename],
                    bindings_by_path.get(member.filename),
                )
            else:
                payload = candidate.read(member)
            projected.writestr(
                info,
                payload,
                compress_type=member.compress_type,
                compresslevel=9,
            )


def verify(
    version_id: str,
    stock_ipa: pathlib.Path,
    candidate_ipa: pathlib.Path,
    receipt_path: pathlib.Path,
) -> dict:
    version_root = PROJECT_ROOT / "versions" / version_id
    stock = read_json(version_root / "stock.json")
    neutral = read_json(version_root / "signer-neutral.json")
    private = read_json(version_root / "private-server.json")
    if private.get("schema") != "ynab-ios-private-server/v1":
        fail("private-server profile schema mismatch")
    if private.get("artifactRole") != "product-carrier":
        fail("private-server profile role mismatch")
    if private.get("versionId") != version_id:
        fail("private-server profile identity mismatch")
    if sha256_path(stock_ipa) != stock["input"]["sha256"]:
        fail("stock IPA hash mismatch")
    candidate_hash = sha256_path(candidate_ipa)
    if candidate_hash != private["expectedCarrierSha256"]:
        fail("candidate does not match the sealed private-server carrier hash")

    receipt = read_json(receipt_path)
    if receipt.get("schema") != "ynab-ios-private-server-receipt/v1":
        fail("combined receipt schema mismatch")
    if receipt.get("versionId") != version_id:
        fail("combined receipt version mismatch")
    if receipt.get("output", {}).get("sha256") != candidate_hash:
        fail("combined receipt output hash mismatch")
    if receipt.get("output", {}).get("profileSealed") is not True:
        fail("combined receipt does not represent a sealed build")
    if receipt.get("output", {}).get("productAdmitted") is not False:
        fail("static build receipt must not claim product admission")

    source = PROJECT_ROOT / private["component"]["source"]
    if sha256_path(source) != private["component"]["sourceSha256"]:
        fail("maintained server-origin source hash mismatch")

    with tempfile.TemporaryDirectory(prefix=f"ynab-{version_id}-verify-") as temp:
        temporary = pathlib.Path(temp)
        neutral_projection = temporary / "neutral-projection.ipa"
        project_neutral(stock_ipa, candidate_ipa, neutral_projection, stock, private)
        if sha256_path(neutral_projection) != neutral["expectedCarrierSha256"]:
            fail("removing the private-server layer does not reproduce signer neutrality")
        neutral_verification = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "verify-signer-neutral.py"),
                "--version",
                version_id,
                str(stock_ipa),
                str(neutral_projection),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        neutral_result = json.loads(neutral_verification.stdout)
        if neutral_result.get("result") != "VALID":
            fail("independent signer-neutral verification did not return VALID")

        extracted = temporary / "package"
        extracted.mkdir()
        with zipfile.ZipFile(candidate_ipa, "r") as archive:
            members = safe_members(archive)
            archive.extractall(extracted, members)
        app = extracted / stock["mainAppPath"]
        info = plistlib.loads((app / "Info.plist").read_bytes())
        identity = (
            info.get("CFBundleIdentifier"),
            info.get("CFBundleShortVersionString"),
            str(info.get("CFBundleVersion")),
        )
        expected_identity = (
            stock["bundleIdentifier"],
            stock["marketingVersion"],
            stock["build"],
        )
        if identity != expected_identity:
            fail("final application identity differs from stock")
        transport = info.get("NSAppTransportSecurity", {})
        if transport.get("NSAllowsLocalNetworking") is not True:
            fail("local-network transport policy is missing")
        if transport.get("NSAllowsArbitraryLoads") is True:
            fail("final carrier enables arbitrary insecure transport")

        if list(app.rglob("_CodeSignature")) or list(app.rglob("embedded.mobileprovision")):
            fail("stale signing resources remain")
        extension_count = len(list(app.rglob("*.appex")))
        if extension_count != 2:
            fail(f"stock extension count changed: {extension_count}")

        regular_files = [path for path in app.rglob("*") if path.is_file()]
        if len(regular_files) != private["outputInventory"]["regularFiles"]:
            fail("final regular-file inventory mismatch")
        macho_containers = 0
        macho_slices = 0
        private_loads = []
        for path in regular_files:
            data = path.read_bytes()
            images = slices(data, str(path))
            if not images:
                continue
            macho_containers += 1
            macho_slices += len(images)
            for image in images:
                parsed = parse_thin(image, str(path.relative_to(app)))
                if any(size != 0 for _, size in parsed["signatures"]):
                    fail(f"non-empty code signature remains: {path.relative_to(app)}")
                if (
                    INSTALL_NAME in parsed["dylibs"]
                    and str(path.relative_to(app)) != private["component"]["packagePath"]
                ):
                    private_loads.append(str(path.relative_to(app)))
        if macho_containers != private["outputInventory"]["machoContainers"]:
            fail("final Mach-O container inventory mismatch")
        if macho_slices != private["outputInventory"]["machoSlices"]:
            fail("final Mach-O slice inventory mismatch")
        expected_loads = sorted(target["path"] for target in private["targets"])
        if sorted(private_loads) != expected_loads:
            fail("private dylib is not loaded by exactly the three declared processes")

        for binding in private.get("sourceBindings", []):
            target_data = (app / binding["targetPath"]).read_bytes()
            offset = int(binding["fileOffset"], 0)
            expected = bytes.fromhex(binding["afterHex"])
            if target_data[offset : offset + len(expected)] != expected:
                fail(f"source binding is not present: {binding['id']}")

        dylib = app / private["component"]["packagePath"]
        if not dylib.is_file() or sha256_path(dylib) != private["component"]["compiledDylibSha256"]:
            fail("packaged server-origin component hash mismatch")
        if dylib.stat().st_size != private["component"]["compiledDylibSize"]:
            fail("packaged server-origin component size mismatch")
        dylib_data = dylib.read_bytes()
        required_markers = [
            private["component"]["defaultsKey"],
            *private["component"]["ownedHosts"],
            "YB_APP_SERVER",
            "ynab-private-server-unconfigured",
            "Server URL",
            "YNAB_Evergreen.SignInViewController",
            "YNAB_Evergreen.CreateAccountViewController",
            "$__lazy_storage_$_stackView",
            "$__lazy_storage_$_forgotPasswordButton",
            "$__lazy_storage_$_createAccountButton",
            "$__lazy_storage_$_signUpButton",
            private["subscriptionFlowBinding"]["class"],
            private["subscriptionFlowBinding"]["selector"],
            private["nativeTextActionBinding"]["expectedClassSuffix"],
            private["localNetworkAdmission"]["request"]["path"],
            "Can't Reach Private Server",
            *private["localNetworkAdmission"]["failureActions"],
            "YNABPrivateServerInstallToken",
            "YNABPrivateServerOriginInstallToken",
        ]
        for marker in required_markers:
            if marker.encode("utf-8") not in dylib_data:
                fail(f"server-origin component is missing marker: {marker}")
        parsed_dylib = parse_thin(dylib_data, "server-origin dylib")
        if parsed_dylib["uuid"] != private["component"]["compiledDylibUuid"]:
            fail("server-origin dylib UUID mismatch")
        if parsed_dylib["signatures"]:
            fail("server-origin dylib contains an embedded code signature")

        signing = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(app)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if signing.returncode == 0:
            fail("candidate unexpectedly verifies as signed")

    return {
        "result": "VALID",
        "candidateSha256": candidate_hash,
        "signerNeutralProjectionSha256": neutral["expectedCarrierSha256"],
        "signerNeutralRuntimePatches": neutral_result["runtime_patches"],
        "privateLoadCommands": len(private_loads),
        "stockExtensions": extension_count,
        "machoContainers": macho_containers,
        "machoSlices": macho_slices,
        "serverOriginDylibSha256": private["component"]["compiledDylibSha256"],
        "codesignVerify": "expected failure: resign-required",
        "deviceTested": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, dest="version_id")
    parser.add_argument("stock_ipa", type=pathlib.Path)
    parser.add_argument("candidate_ipa", type=pathlib.Path)
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    try:
        result = verify(
            arguments.version_id,
            arguments.stock_ipa.resolve(),
            arguments.candidate_ipa.resolve(),
            arguments.receipt.resolve(),
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
