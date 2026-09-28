import importlib.util
import hashlib
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
PRIVATE_BUILDER = load_tool("build-private-server")
PRIVATE_VERIFIER = load_tool("verify-private-server")


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

    def test_private_profile_is_sealed_for_normal_build(self):
        stock, neutral, private = PRIVATE_BUILDER.validate_profile(
            "26.35-744", False
        )
        self.assertEqual(stock["versionId"], "26.35-744")
        self.assertEqual(neutral["artifactRole"], "internal-component-reference")
        self.assertEqual(private["artifactRole"], "product-carrier")

    def test_private_derivation_rejects_sealed_profile(self):
        with self.assertRaises(RuntimeError):
            PRIVATE_BUILDER.validate_profile("26.35-744", True)


class PrivateServerStructureTests(unittest.TestCase):
    def test_server_origin_uses_the_profile_bound_native_text_action_factory(self):
        source = (
            ROOT / "components/server-origin/v1/YNABServerOrigin.m"
        ).read_text(encoding="utf-8")
        self.assertIn("YNButtonTemplateFactory", source)
        self.assertIn("header->filetype == MH_EXECUTE", source)
        self.assertIn("_dyld_get_image_vmaddr_slide(index)", source)
        self.assertNotIn("_dyld_get_image_vmaddr_slide(0)", source)
        self.assertIn("YNRuntimeAddress(YN_BUTTON_TEMPLATE_VM_ADDRESS)", source)
        self.assertIn("YN_FORGOT_TITLE_COUNT_AND_FLAGS", source)
        self.assertIn("YN_FORGOT_TITLE_OBJECT_VM_ADDRESS", source)
        self.assertIn("YN_FORGOT_ACCESSIBILITY_COUNT_AND_FLAGS", source)
        self.assertIn("YN_FORGOT_ACCESSIBILITY_OBJECT_VM_ADDRESS", source)
        self.assertIn("YN_NATIVE_TEXT_ACTION_CLASS_SUFFIX", source)
        self.assertIn('configuration.title = @"Server URL"', source)
        self.assertIn(
            "[stack insertArrangedSubview:button atIndex:anchorIndex + 1]", source
        )
        self.assertIn("[stack removeArrangedSubview:button]", source)
        self.assertIn("[button removeFromSuperview]", source)
        self.assertIn(
            "CGFloat customSpacing = [stack customSpacingAfterView:precedingView]",
            source,
        )
        self.assertIn(
            "[stack setCustomSpacing:useZeroSpacing ? 0.0 : precedingSpacing",
            source,
        )
        self.assertNotIn("YNLoginServerActionBottomContentInset", source)
        self.assertNotIn("setCustomSpacing:8", source)
        self.assertIn(
            "[button setContentHuggingPriority:UILayoutPriorityDefaultHigh - 1.0f",
            source,
        )
        self.assertIn("forAxis:UILayoutConstraintAxisHorizontal", source)
        self.assertNotIn(
            "[button.centerXAnchor constraintEqualToAnchor:positionAnchor.centerXAnchor]",
            source,
        )
        self.assertIn(
            "[button.widthAnchor constraintEqualToAnchor:stack.widthAnchor]",
            source,
        )
        self.assertIn(
            "[button.centerXAnchor constraintEqualToAnchor:stack.centerXAnchor]",
            source,
        )
        self.assertIn("if (!hasArrangedPositionAnchor) return nil", source)
        self.assertIn("YNArmServerButtonPlacement", source)
        self.assertIn("YNAddArrangedSubview", source)
        self.assertIn("YNArrangedSubviewObserver", source)
        self.assertIn("@selector(addArrangedSubview:)", source)
        self.assertIn(
            "objc_setAssociatedObject(ownedStack, YNArrangedSubviewObserverKey, nil",
            source,
        )
        self.assertNotIn("dispatch_after", source)
        self.assertNotIn("[stack addArrangedSubview:button]", source)
        self.assertIn("YNInstallSignInServerButton(self)", source)
        self.assertIn(
            'controller, YNSignInButtonKey,\n'
            '      "$__lazy_storage_$_forgotPasswordButton", NO, YES',
            source,
        )
        self.assertIn(
            'YNInstallServerButton(strongController, YNSignInButtonKey,\n'
            '                          "$__lazy_storage_$_createAccountButton", NO, YES)',
            source,
        )
        self.assertIn(
            'YNArmServerButtonPlacement(self, YNCreateAccountButtonKey,\n'
            '                             "$__lazy_storage_$_signUpButton", YES, NO)',
            source,
        )
        self.assertNotIn("alreadyHaveAccountButton", source)
        self.assertIn("YNPatchedShouldSkipSubscribeFlow", source)
        self.assertIn("@selector(shouldSkipSubscribeFlow)", source)
        self.assertIn("if (YNStoredOrigin()) return YES", source)
        self.assertIn(
            "YNOriginalShouldSkipSubscribeFlow(self, selector)", source
        )
        self.assertNotIn('actionWithTitle:@"Use YNAB"', source)

    def test_local_network_admission_preflights_without_replaying_authentication(self):
        source = (
            ROOT / "components/server-origin/v1/YNABServerOrigin.m"
        ).read_text(encoding="utf-8")
        self.assertIn('components.path = @"/health"', source)
        self.assertIn("YNBeginOriginPreflight(weakController, YES)", source)
        self.assertIn("YNBeginOriginPreflight(self, YES)", source)
        self.assertEqual(source.count("YNBeginOriginPreflight(self, YES)"), 2)
        self.assertIn("!YNIsPrivateDevelopmentHost(components.host)", source)
        self.assertIn("timeoutInterval:8.0", source)
        self.assertIn("YNBeginOriginPreflight(strongController, NO)", source)
        self.assertIn('actionWithTitle:@"Retry"', source)
        self.assertIn('actionWithTitle:@"Server URL"', source)
        self.assertIn('actionWithTitle:@"Settings"', source)
        self.assertNotIn("signInButtonTapped", source)
        self.assertNotIn("signUpButtonTapped", source)

    def test_server_origin_is_owned_by_the_current_app_installation(self):
        source = (
            ROOT / "components/server-origin/v1/YNABServerOrigin.m"
        ).read_text(encoding="utf-8")
        self.assertIn('YNInstallTokenDefaultsKey', source)
        self.assertIn('YNOriginInstallTokenDefaultsKey', source)
        self.assertIn("YNReconcileOriginOwnership();", source)
        self.assertIn("[shared removeObjectForKey:YNOriginDefaultsKey]", source)
        self.assertIn(
            "[shared setObject:installToken forKey:YNOriginInstallTokenDefaultsKey]",
            source,
        )

    def test_component_compile_flags_come_from_the_artifact_profile(self):
        source = (ROOT / "tools/build-private-server.py").read_text(
            encoding="utf-8"
        )
        for marker in (
            "-DYN_BUTTON_TEMPLATE_VM_ADDRESS=",
            "-DYN_FORGOT_TITLE_COUNT_AND_FLAGS=",
            "-DYN_FORGOT_TITLE_OBJECT_VM_ADDRESS=",
            "-DYN_FORGOT_ACCESSIBILITY_COUNT_AND_FLAGS=",
            "-DYN_FORGOT_ACCESSIBILITY_OBJECT_VM_ADDRESS=",
            "-DYN_NATIVE_TEXT_ACTION_CLASS_SUFFIX=",
        ):
            self.assertIn(marker, source)

    def test_authoritative_server_configuration_blocks_stock_without_an_origin(self):
        source = (
            ROOT / "components/server-origin/v1/YNABServerOrigin.m"
        ).read_text(encoding="utf-8")
        self.assertIn('YNStockServerInfoKey = @"YB_APP_SERVER"', source)
        self.assertIn("YNInstallAuthoritativeConfigurationHook();", source)
        self.assertIn('YNUnconfiguredScheme =', source)
        self.assertIn('@"ynab-private-server-unconfigured"', source)
        self.assertIn("if (!originString) return YNBlockedOwnedURL(stockURL)", source)
        self.assertNotIn("127.0.0.1:1", source)
        self.assertNotIn("YNFailClosedOrigin", source)

    def test_source_binding_applies_exact_preimage(self):
        original = bytes(range(64))
        binding = {
            "id": "synthetic",
            "targetPath": "synthetic",
            "fileOffset": "0x10",
            "vmAddress": "0x100000010",
            "beforeHex": original[16:24].hex(),
            "afterHex": bytes(reversed(original[16:24])).hex(),
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "target"
            path.write_bytes(original)
            PRIVATE_BUILDER.apply_source_binding(path, binding)
            patched = path.read_bytes()
        self.assertEqual(patched[16:24], bytes.fromhex(binding["afterHex"]))

    def test_private_load_command_round_trip(self):
        uuid = bytes.fromhex("00112233445566778899aabbccddeeff")
        header = bytearray(0x400)
        header[:4] = PRIVATE_BUILDER.MH_MAGIC_64_LE
        struct.pack_into("<I", header, 16, 3)
        segment = bytearray(152)
        struct.pack_into("<II", segment, 0, PRIVATE_BUILDER.LC_SEGMENT_64, 152)
        struct.pack_into("<I", segment, 64, 1)
        struct.pack_into("<Q", segment, 72 + 40, 16)
        struct.pack_into("<I", segment, 72 + 48, 0x300)
        uuid_command = struct.pack("<II", PRIVATE_BUILDER.LC_UUID, 24) + uuid
        signature = struct.pack("<IIII", PRIVATE_BUILDER.LC_CODE_SIGNATURE, 16, 0, 0)
        commands = bytes(segment) + uuid_command + signature
        struct.pack_into("<I", header, 20, len(commands))
        header[32 : 32 + len(commands)] = commands

        target = {
            "name": "synthetic",
            "path": "synthetic",
            "neutralSha256": hashlib.sha256(header).hexdigest(),
            "uuid": uuid.hex(),
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "target"
            path.write_bytes(header)
            PRIVATE_BUILDER.add_load_command(path, target)
            final = path.read_bytes()
        self.assertEqual(
            PRIVATE_VERIFIER.remove_private_load(final, target), bytes(header)
        )


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

    def test_exact_component_reference_does_not_claim_product_admission(self):
        classification, next_action = INSPECTOR.classify_reference(
            exact_input=True,
            same_version_id=True,
            identity_match=True,
            requires_mapping=False,
        )
        self.assertEqual(classification, "already-profiled-input")
        self.assertIn("combined profile", next_action)

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
