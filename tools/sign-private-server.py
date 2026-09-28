#!/usr/bin/env python3
"""Sign one sealed YNAB carrier with an explicit external zsign identity."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import signing_common


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent


def ensure_external_new_path(path: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if resolved == PROJECT_ROOT or resolved.is_relative_to(PROJECT_ROOT):
        signing_common.fail(f"{label} must be outside the repository: {resolved}")
    if resolved.exists():
        signing_common.fail(f"refusing to overwrite existing {label}: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def publish_no_clobber(staged: pathlib.Path, destination: pathlib.Path) -> None:
    """Atomically publish a staged file without replacing an existing path."""
    os.link(staged, destination)


def signing_password(environment_name: str | None) -> str:
    if environment_name:
        value = os.environ.get(environment_name)
        if value is None:
            signing_common.fail(
                f"signing password environment variable is unset: {environment_name}"
            )
        return value
    if not sys.stdin.isatty():
        signing_common.fail(
            "interactive signing requires a terminal; otherwise pass --password-env"
        )
    return getpass.getpass("PKCS#12 password: ")


def sign(
    version_id: str,
    stock_ipa: pathlib.Path,
    carrier_ipa: pathlib.Path,
    receipt_path: pathlib.Path,
    p12_path: pathlib.Path,
    provision_path: pathlib.Path,
    signed_ipa: pathlib.Path,
    report_path: pathlib.Path,
    password_environment: str | None,
) -> dict:
    for path, label in (
        (stock_ipa, "stock IPA"),
        (carrier_ipa, "sealed carrier"),
        (receipt_path, "carrier receipt"),
        (p12_path, "PKCS#12 identity"),
        (provision_path, "provisioning profile"),
    ):
        if not path.is_file():
            signing_common.fail(f"{label} is missing: {path}")
    if p12_path == PROJECT_ROOT or p12_path.is_relative_to(PROJECT_ROOT):
        signing_common.fail("PKCS#12 identity must remain outside the repository")
    if provision_path == PROJECT_ROOT or provision_path.is_relative_to(PROJECT_ROOT):
        signing_common.fail("provisioning profile must remain outside the repository")
    signed_ipa = ensure_external_new_path(signed_ipa, "signed IPA")
    report_path = ensure_external_new_path(report_path, "signed verification report")

    verifier = subprocess.run(
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
    if verifier.returncode:
        signing_common.fail(
            f"refusing to sign an invalid carrier: {(verifier.stderr or verifier.stdout).strip()}"
        )
    profile = signing_common.decode_profile(provision_path)
    zsign = shutil.which("zsign")
    if zsign is None:
        signing_common.fail("zsign is unavailable")
    password = signing_password(password_environment)
    with tempfile.TemporaryDirectory(
        prefix=f".ynab-{version_id}-sign-", dir=signed_ipa.parent
    ) as signed_temporary, tempfile.TemporaryDirectory(
        prefix=f".ynab-{version_id}-report-", dir=report_path.parent
    ) as report_temporary:
        staged_signed = pathlib.Path(signed_temporary) / "signed.ipa"
        staged_report = pathlib.Path(report_temporary) / "verification.json"
        result = subprocess.run(
            [
                zsign,
                "-f",
                "-k",
                str(p12_path),
                "-m",
                str(provision_path),
                "-p",
                password,
                "-t",
                signed_temporary,
                "-o",
                str(staged_signed),
                str(carrier_ipa),
            ],
            cwd=signed_temporary,
            capture_output=True,
            text=True,
            check=False,
        )
        password = ""
        if result.returncode:
            signing_common.fail(
                f"zsign failed ({result.returncode}): "
                + (result.stderr or result.stdout).strip()
            )
        post_sign = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "verify-signed.py"),
                "--version",
                version_id,
                str(stock_ipa),
                str(carrier_ipa),
                str(staged_signed),
                "--receipt",
                str(receipt_path),
                "--report",
                str(staged_report),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if post_sign.returncode:
            signing_common.fail(
                "signed output failed independent verification: "
                + (post_sign.stderr or post_sign.stdout).strip()
            )
        signed_report = json.loads(staged_report.read_text(encoding="utf-8"))
        publish_no_clobber(staged_signed, signed_ipa)
        try:
            publish_no_clobber(staged_report, report_path)
        except OSError:
            signed_ipa.unlink(missing_ok=True)
            raise
    return {
        "result": "VALID",
        "signedIpa": str(signed_ipa),
        "signedSha256": signed_report["signed"]["sha256"],
        "report": str(report_path),
        "profile": {
            "name": profile.get("name"),
            "uuid": profile.get("uuid"),
            "teamIdentifier": profile.get("teamIdentifier"),
            "expiration": profile.get("expiration"),
        },
        "warningCount": len(signed_report["warnings"]),
        "deviceTested": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, dest="version_id")
    parser.add_argument("stock_ipa", type=pathlib.Path)
    parser.add_argument("carrier_ipa", type=pathlib.Path)
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    parser.add_argument("--p12", type=pathlib.Path, required=True)
    parser.add_argument("--provision", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument(
        "--password-env",
        help="read the PKCS#12 password from this environment variable instead of prompting",
    )
    arguments = parser.parse_args()
    try:
        report = sign(
            arguments.version_id,
            arguments.stock_ipa.expanduser().resolve(),
            arguments.carrier_ipa.expanduser().resolve(),
            arguments.receipt.expanduser().resolve(),
            arguments.p12.expanduser().resolve(),
            arguments.provision.expanduser().resolve(),
            arguments.output,
            arguments.report,
            arguments.password_env,
        )
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
