import importlib.util
import plistlib
import pathlib
import struct
import tempfile
import unittest
import warnings
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load tool: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = load_tool("build-signer-neutral")
VERIFIER = load_tool("verify-signer-neutral")
INSPECTOR = load_tool("inspect-stock")


class BranchEncodingTests(unittest.TestCase):
    def test_builder_and_verifier_encode_known_forward_bl(self):
        expected = bytes.fromhex("40000094")
        self.assertEqual(BUILDER.encode_branch(0x1000, 0x1100, True), expected)
        self.assertEqual(VERIFIER.encode_bl(0x1000, 0x1100), expected)

    def test_builder_encodes_non_linking_branch_independently(self):
        self.assertEqual(
            BUILDER.encode_branch(0x1000, 0x1100, False),
            bytes.fromhex("40000014"),
        )

    def test_branch_encoders_reject_unaligned_targets(self):
        with self.assertRaises(RuntimeError):
            BUILDER.encode_branch(0x1000, 0x1101, True)
        with self.assertRaises(RuntimeError):
            VERIFIER.encode_bl(0x1000, 0x1101)


class ProfileAuthoringTests(unittest.TestCase):
    def test_normal_build_requires_sealed_hash(self):
        sealed = "ab" * 32
        self.assertEqual(BUILDER.validate_carrier_hash(sealed, False), sealed)
        with self.assertRaises(RuntimeError):
            BUILDER.validate_carrier_hash(None, False)

    def test_derivation_requires_unsealed_hash(self):
        self.assertIsNone(BUILDER.validate_carrier_hash(None, True))
        with self.assertRaises(RuntimeError):
            BUILDER.validate_carrier_hash("ab" * 32, True)

    def test_sealed_hash_must_be_hexadecimal(self):
        with self.assertRaises(RuntimeError):
            BUILDER.validate_carrier_hash("z" * 64, False)


def synthetic_macho(uuid: bytes) -> bytes:
    header = bytearray(32)
    header[:4] = INSPECTOR.MH_MAGIC_64_LE
    struct.pack_into("<I", header, 16, 1)
    struct.pack_into("<I", header, 20, 24)
    command = struct.pack("<II", INSPECTOR.LC_UUID, 24) + uuid
    return bytes(header) + command


class StockInspectionTests(unittest.TestCase):
    def make_ipa(self, path: pathlib.Path, duplicate: bool = False) -> None:
        info = plistlib.dumps(
            {
                "CFBundleIdentifier": "com.youneedabudget.evergreen.YNAB-Evergreen",
                "CFBundleShortVersionString": "99.1",
                "CFBundleVersion": "1001",
            }
        )
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/YNAB Evergreen.app/Info.plist", info)
            archive.writestr(
                "Payload/YNAB Evergreen.app/YNAB Evergreen",
                synthetic_macho(bytes.fromhex("00112233445566778899aabbccddeeff")),
            )
            archive.writestr(
                "Payload/YNAB Evergreen.app/_CodeSignature/CodeResources", b"signature"
            )
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr("Payload/YNAB Evergreen.app/Info.plist", info)

    def test_inspection_reports_identity_inventory_and_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            ipa = pathlib.Path(temporary) / "stock.ipa"
            self.make_ipa(ipa)
            report = INSPECTOR.inspect_stock(ipa, None)
        self.assertEqual(report["versionId"], "99.1-1001")
        self.assertEqual(report["inventory"]["regularFiles"], 3)
        self.assertEqual(report["inventory"]["machoContainers"], 1)
        self.assertEqual(report["inventory"]["machoSlices"], 1)
        self.assertEqual(report["inventory"]["signatureDirectories"], 1)
        self.assertEqual(
            report["macho"][0]["uuids"],
            ["00112233445566778899aabbccddeeff"],
        )

    def test_inspection_rejects_duplicate_zip_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            ipa = pathlib.Path(temporary) / "duplicate.ipa"
            self.make_ipa(ipa, duplicate=True)
            with self.assertRaises(RuntimeError):
                INSPECTOR.inspect_stock(ipa, None)

    def test_reference_classification_stops_same_version_conflicts(self):
        classification, _ = INSPECTOR.classify_reference(
            exact_input=False,
            same_version_id=True,
            identity_match=True,
            requires_mapping=False,
        )
        self.assertEqual(classification, "provenance-conflict")

    def test_reference_classification_routes_changed_targets(self):
        classification, _ = INSPECTOR.classify_reference(
            exact_input=False,
            same_version_id=False,
            identity_match=True,
            requires_mapping=True,
        )
        self.assertEqual(classification, "requires-target-mapping")


if __name__ == "__main__":
    unittest.main()
