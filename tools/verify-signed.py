#!/usr/bin/env python3
"""Independently verify a signed YNAB IPA against its sealed carrier."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import zipfile
from typing import Any

import signing_common


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_external_new_path(path: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if resolved == PROJECT_ROOT or resolved.is_relative_to(PROJECT_ROOT):
        signing_common.fail(f"{label} must be outside the repository: {resolved}")
    if resolved.exists():
        signing_common.fail(f"refusing to overwrite existing {label}: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def run_carrier_verifier(
    version_id: str,
    stock_ipa: pathlib.Path,
    carrier_ipa: pathlib.Path,
    receipt_path: pathlib.Path,
) -> dict[str, Any]:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_DIR / "verify-private-server.py"),
            "--version",
            version_id,
            str(stock_ipa),
            str(carrier_ipa),
            "--receipt",
            str(receipt_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        signing_common.fail(f"sealed carrier verification failed: {detail}")
    report = json.loads(result.stdout)
    if report.get("result") != "VALID":
        signing_common.fail("sealed carrier verifier did not return VALID")
    return report


def expected_bundle_root(main_app_path: str, relative: str) -> str:
    return main_app_path if relative == "." else f"{main_app_path}/{relative}"


def verify_entitlement_authority(
    effective: dict[str, Any], authorized: dict[str, Any], label: str
) -> None:
    for key, value in effective.items():
        if key not in authorized or not signing_common.entitlement_authorized(
            value, authorized[key]
        ):
            signing_common.fail(
                f"effective entitlement is not authorized by the embedded profile: {label}: {key}"
            )


def verify(
    version_id: str,
    stock_ipa: pathlib.Path,
    carrier_ipa: pathlib.Path,
    signed_ipa: pathlib.Path,
    receipt_path: pathlib.Path,
) -> dict[str, Any]:
    version_root = PROJECT_ROOT / "versions" / version_id
    stock = read_json(version_root / "stock.json")
    private = read_json(version_root / "private-server.json")
    policy = read_json(version_root / "signing.json")
    if policy.get("schema") != "ynab-ios-signing-policy/v1":
        signing_common.fail("signing policy schema mismatch")
    if policy.get("versionId") != version_id:
        signing_common.fail("signing policy version mismatch")
    if policy.get("artifactRole") != "post-sign-policy":
        signing_common.fail("signing policy role mismatch")
    carrier_report = run_carrier_verifier(
        version_id, stock_ipa, carrier_ipa, receipt_path
    )
    if not signed_ipa.is_file() or signed_ipa.resolve() == carrier_ipa.resolve():
        signing_common.fail("signed IPA is missing or overlaps the sealed carrier")

    with zipfile.ZipFile(carrier_ipa, "r") as candidate_zip, zipfile.ZipFile(
        signed_ipa, "r"
    ) as signed_zip:
        candidate_index = signing_common.archive_index(candidate_zip)
        signed_index = signing_common.archive_index(signed_zip)
        if candidate_zip.testzip() is not None or signed_zip.testzip() is not None:
            signing_common.fail("carrier or signed IPA ZIP integrity failed")
        candidate_files = {
            name for name, member in candidate_index.items() if not member.is_dir()
        }
        signed_files = {
            name for name, member in signed_index.items() if not member.is_dir()
        }
        removed = sorted(candidate_files - signed_files)
        if removed:
            signing_common.fail(f"signer removed packaged files: {removed[:5]}")
        added = sorted(signed_files - candidate_files)
        unexpected = [
            name for name in added if not signing_common.signing_metadata_member(name)
        ]
        if unexpected:
            signing_common.fail(
                f"signer added non-signing resources: {unexpected[:5]}"
            )

        candidate_machos = {
            name
            for name in candidate_files
            if candidate_zip.read(name)[:4]
            in (signing_common.MH_MAGIC_64_LE, signing_common.FAT_MAGIC_BE)
        }
        signed_machos = {
            name
            for name in candidate_machos
            if signed_zip.read(name)[:4]
            in (signing_common.MH_MAGIC_64_LE, signing_common.FAT_MAGIC_BE)
        }
        if candidate_machos != signed_machos:
            signing_common.fail("signer changed the Mach-O member graph")
        macho_reports = [
            signing_common.compare_signed_container(
                candidate_zip.read(name), signed_zip.read(name), name
            )
            for name in sorted(candidate_machos)
        ]
        slice_count = sum(item["sliceCount"] for item in macho_reports)
        closure = policy["codeClosure"]
        if len(macho_reports) != closure["machoContainers"]:
            signing_common.fail("signed Mach-O container count mismatch")
        if slice_count != closure["machoSlices"]:
            signing_common.fail("signed Mach-O slice count mismatch")

        for name in sorted(candidate_files - candidate_machos):
            if signing_common.signing_metadata_member(name):
                continue
            if candidate_zip.read(name) != signed_zip.read(name):
                signing_common.fail(f"signer changed ordinary packaged resource: {name}")

        expected_profile_members = {
            f"{expected_bundle_root(stock['mainAppPath'], item['path'])}/embedded.mobileprovision"
            for item in closure["entitlementBundles"]
        }
        profile_members = {
            name for name in signed_files if name.endswith("embedded.mobileprovision")
        }
        main_profile_member = f"{stock['mainAppPath']}/embedded.mobileprovision"
        if main_profile_member not in profile_members:
            signing_common.fail("signed main app has no embedded provisioning profile")
        if not profile_members <= expected_profile_members:
            signing_common.fail("signed IPA has a provisioning profile in an unexpected bundle")

        with tempfile.TemporaryDirectory(prefix=f"ynab-{version_id}-signed-") as temporary:
            extracted = pathlib.Path(temporary)
            signed_zip.extractall(extracted)
            app = extracted / stock["mainAppPath"]
            strict = subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", "--verbose=4", str(app)],
                capture_output=True,
                text=True,
                check=False,
            )
            if strict.returncode:
                detail = (strict.stderr or strict.stdout).strip()
                signing_common.fail(f"strict nested signature verification failed: {detail}")
            signature_directories = list(app.rglob("_CodeSignature"))
            if len(signature_directories) != closure["signatureDirectories"]:
                signing_common.fail("signed code-signature directory count mismatch")
            signed_bundle_paths = {
                "."
                if directory.parent == app
                else directory.parent.relative_to(app).as_posix()
                for directory in signature_directories
            }
            expected_bundle_paths = {
                item["path"] for item in closure["signedCodeBundles"]
            }
            if signed_bundle_paths != expected_bundle_paths:
                signing_common.fail(
                    "signed nested-code bundle graph does not match policy"
                )

            code_bundle_reports = []
            for item in closure["signedCodeBundles"]:
                relative = item["path"]
                bundle = app if relative == "." else app / relative
                info = plistlib.loads((bundle / "Info.plist").read_bytes())
                if info.get("CFBundleIdentifier") != item["bundleIdentifier"]:
                    signing_common.fail(
                        f"signer changed bundle identifier: {relative}"
                    )
                signature = signing_common.signature_metadata(bundle)
                if signature.get("identifier") != item["bundleIdentifier"]:
                    signing_common.fail(
                        f"signer changed code-signing identifier: {relative}"
                    )
                code_bundle_reports.append(
                    {
                        "path": relative,
                        "bundleIdentifier": item["bundleIdentifier"],
                        "signature": signature,
                    }
                )

            root_profile = signing_common.decode_profile(
                extracted / main_profile_member
            )
            for item in code_bundle_reports:
                if (
                    item["signature"].get("teamIdentifier")
                    != root_profile.get("teamIdentifier")
                ):
                    signing_common.fail(
                        "nested code object uses a different signing Team ID: "
                        + item["path"]
                    )
            expiration = root_profile.get("expiration")
            if expiration is not None:
                expires = dt.datetime.fromisoformat(expiration)
                now = dt.datetime.now(expires.tzinfo) if expires.tzinfo else dt.datetime.now()
                if expires <= now:
                    signing_common.fail("embedded provisioning profile is expired")

            bundle_reports = []
            selected_groups: dict[str, str] = {}
            warnings = []
            profile_uuids = {root_profile.get("uuid")}
            for item in closure["entitlementBundles"]:
                relative = item["path"]
                bundle = app if relative == "." else app / relative
                info = plistlib.loads((bundle / "Info.plist").read_bytes())
                if info.get("CFBundleIdentifier") != item["bundleIdentifier"]:
                    signing_common.fail(
                        f"signer changed bundle identifier for role {item['role']}"
                    )
                effective = signing_common.decode_entitlements(bundle)
                signature = signing_common.signature_metadata(bundle)
                local_profile_path = bundle / "embedded.mobileprovision"
                authority = (
                    signing_common.decode_profile(local_profile_path)
                    if local_profile_path.is_file()
                    else root_profile
                )
                profile_uuids.add(authority.get("uuid"))
                authorized = authority["entitlements"]
                verify_entitlement_authority(
                    effective, authorized, item["bundleIdentifier"]
                )
                missing = [key for key in item["requiredEntitlements"] if key not in effective]
                if missing:
                    signing_common.fail(
                        f"required entitlements are missing for {item['role']}: {missing}"
                    )
                if (
                    "keychain-access-groups" in item["requiredEntitlements"]
                    and not signing_common.usable_string_list(
                        effective.get("keychain-access-groups")
                    )
                ):
                    signing_common.fail(
                        f"no usable Keychain access group for {item['role']}"
                    )
                team = effective.get("com.apple.developer.team-identifier")
                if (
                    not isinstance(team, str)
                    or signature.get("teamIdentifier") != team
                    or authority.get("teamIdentifier") != team
                ):
                    signing_common.fail(
                        f"signature, effective entitlement and profile Team IDs disagree: {item['role']}"
                    )
                if signature.get("identifier") != item["bundleIdentifier"]:
                    signing_common.fail(
                        f"code-signing identifier changed: {item['role']}"
                    )
                application_identifier = effective.get("application-identifier")
                expected_application_identifier = f"{team}.{item['bundleIdentifier']}"
                if application_identifier != expected_application_identifier:
                    warnings.append(
                        {
                            "role": item["role"],
                            "code": "signer-application-identifier-not-bundle-scoped",
                            "value": application_identifier,
                        }
                    )
                groups = effective.get("com.apple.security.application-groups")
                if not isinstance(groups, list) or not groups or not all(
                    isinstance(group, str) and group.startswith("group.")
                    for group in groups
                ):
                    signing_common.fail(
                        f"no usable App Group entitlement for {item['role']}"
                    )
                selected_groups[item["role"]] = sorted(set(groups))[0]
                apple_policy = policy["appleServicePolicy"]
                for key in apple_policy["concreteContainerEntitlementsMustBeEmpty"]:
                    value = effective.get(key)
                    if value not in (None, []):
                        signing_common.fail(
                            f"signed bundle gained a concrete Apple container: {item['role']}: {key}"
                        )
                broad = sorted(
                    key
                    for key in apple_policy["broadUnusedAuthorityWarnings"]
                    if key in authorized
                )
                if broad:
                    warnings.append(
                        {
                            "role": item["role"],
                            "code": "broad-unused-profile-authority",
                            "entitlements": broad,
                        }
                    )
                bundle_reports.append(
                    {
                        "role": item["role"],
                        "path": relative,
                        "bundleIdentifier": item["bundleIdentifier"],
                        "signature": signature,
                        "effectiveEntitlementKeys": sorted(effective),
                        "selectedAppGroup": selected_groups[item["role"]],
                        "embeddedProfile": local_profile_path.is_file(),
                        "profileUuid": authority.get("uuid"),
                    }
                )
            if len(set(selected_groups.values())) != 1:
                signing_common.fail(
                    "main app and widget processes do not converge on one App Group"
                )

    return {
        "schema": "ynab-ios-signed-output-verification/v1",
        "result": "VALID",
        "versionId": version_id,
        "carrier": {
            "sha256": carrier_report["candidateSha256"],
            "verification": carrier_report["result"],
        },
        "signed": {
            "sha256": signing_common.sha256_path(signed_ipa),
            "strictNestedSignature": True,
            "machoContainers": len(macho_reports),
            "machoSlices": slice_count,
            "runtimeBytesPreserved": True,
            "ordinaryResourcesPreserved": True,
        },
        "provisioning": {
            "name": root_profile.get("name"),
            "uuid": root_profile.get("uuid"),
            "teamIdentifier": root_profile.get("teamIdentifier"),
            "expiration": root_profile.get("expiration"),
            "provisionedDeviceCount": root_profile.get("provisionedDeviceCount"),
            "profilePlacements": sorted(profile_members),
            "profileUuids": sorted(item for item in profile_uuids if item),
        },
        "namespaces": {
            "selectedByRole": selected_groups,
            "convergedAppGroup": next(iter(selected_groups.values())),
        },
        "codeBundles": code_bundle_reports,
        "bundles": bundle_reports,
        "warnings": warnings,
        "deviceTested": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, dest="version_id")
    parser.add_argument("stock_ipa", type=pathlib.Path)
    parser.add_argument("carrier_ipa", type=pathlib.Path)
    parser.add_argument("signed_ipa", type=pathlib.Path)
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    try:
        report_path = ensure_external_new_path(arguments.report, "signed report")
        report = verify(
            arguments.version_id,
            arguments.stock_ipa.expanduser().resolve(),
            arguments.carrier_ipa.expanduser().resolve(),
            arguments.signed_ipa.expanduser().resolve(),
            arguments.receipt.expanduser().resolve(),
        )
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        zipfile.BadZipFile,
        json.JSONDecodeError,
        plistlib.InvalidFileException,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result": report["result"],
                "signedSha256": report["signed"]["sha256"],
                "warningCount": len(report["warnings"]),
                "report": str(report_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
