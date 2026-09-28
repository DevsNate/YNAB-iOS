#!/usr/bin/env python3
"""Run the YNAB stock-IPA grinder through a verified carrier or signed IPA."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = PROJECT_ROOT / "tools"


def run_json(command: list[str], label: str) -> dict:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{label} failed: {detail}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} returned invalid JSON") from error


def build_carrier(arguments: argparse.Namespace) -> tuple[dict, pathlib.Path]:
    carrier = arguments.carrier.expanduser().resolve()
    receipt = pathlib.Path(str(carrier) + ".private-server.json")
    if carrier == PROJECT_ROOT or carrier.is_relative_to(PROJECT_ROOT):
        raise RuntimeError(f"carrier must be outside the repository: {carrier}")
    if carrier.exists() or receipt.exists():
        if not carrier.is_file() or not receipt.is_file():
            raise RuntimeError("existing carrier boundary is incomplete")
        if arguments.mode != "signed":
            raise RuntimeError("refusing to overwrite the carrier or its receipt")
        verified = run_json(
            [
                sys.executable,
                str(TOOLS / "verify-private-server.py"),
                "--version",
                arguments.version_id,
                str(arguments.stock.expanduser().resolve()),
                str(carrier),
                "--receipt",
                str(receipt),
            ],
            "existing carrier verification",
        )
        if verified.get("result") != "VALID":
            raise RuntimeError("existing carrier verifier did not return VALID")
        return (
            {
                "output": str(carrier),
                "outputSha256": verified["candidateSha256"],
                "receipt": str(receipt),
                "profileSealed": True,
                "loadCommandsAdded": verified["privateLoadCommands"],
                "verification": "passed",
                "reused": True,
            },
            receipt,
        )
    carrier.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".ynab-{arguments.version_id}-carrier-", dir=carrier.parent
    ) as temporary:
        staged = pathlib.Path(temporary) / carrier.name
        staged_receipt = pathlib.Path(str(staged) + ".private-server.json")
        report = run_json(
            [
                sys.executable,
                str(TOOLS / "build-private-server.py"),
                "--version",
                arguments.version_id,
                str(arguments.stock.expanduser().resolve()),
                str(staged),
            ],
            "carrier build",
        )
        if report.get("verification") != "passed":
            raise RuntimeError(
                "carrier build did not complete independent verification"
            )
        os.link(staged, carrier)
        try:
            os.link(staged_receipt, receipt)
        except OSError:
            carrier.unlink(missing_ok=True)
            raise
    report["output"] = str(carrier)
    report["receipt"] = str(receipt)
    report["reused"] = False
    return report, receipt


def grind(arguments: argparse.Namespace) -> dict:
    carrier_report, receipt = build_carrier(arguments)
    result = {
        "schema": "ynab-ios-grinder-result/v1",
        "versionId": arguments.version_id,
        "state": "verified-carrier",
        "carrier": carrier_report,
        "signed": None,
        "deviceTested": False,
    }
    if arguments.mode == "signed":
        signed = arguments.signed.expanduser().resolve()
        signed_report = arguments.report or pathlib.Path(str(signed) + ".signed.json")
        command = [
            sys.executable,
            str(TOOLS / "sign-private-server.py"),
            "--version",
            arguments.version_id,
            str(arguments.stock.expanduser().resolve()),
            str(arguments.carrier.expanduser().resolve()),
            "--receipt",
            str(receipt),
            "--p12",
            str(arguments.p12.expanduser().resolve()),
            "--provision",
            str(arguments.provision.expanduser().resolve()),
            "--output",
            str(signed),
            "--report",
            str(signed_report.expanduser().resolve()),
        ]
        if arguments.password_env:
            command.extend(["--password-env", arguments.password_env])
        result["signed"] = run_json(command, "signing and post-sign verification")
        result["state"] = "verified-signed"
    return result


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--version", required=True, dest="version_id")
    parser.add_argument("--stock", required=True, type=pathlib.Path)
    parser.add_argument("--carrier", required=True, type=pathlib.Path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    carrier = commands.add_parser(
        "carrier",
        help="produce an independently verified resign-required carrier",
    )
    add_common(carrier)
    signed = commands.add_parser(
        "signed",
        help="produce and independently verify a signer-specific IPA",
    )
    add_common(signed)
    signed.add_argument("--signed", required=True, type=pathlib.Path)
    signed.add_argument("--p12", required=True, type=pathlib.Path)
    signed.add_argument("--provision", required=True, type=pathlib.Path)
    signed.add_argument("--report", type=pathlib.Path)
    signed.add_argument("--password-env")
    arguments = parser.parse_args()
    try:
        result = grind(arguments)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
