import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILES = tuple(
    path
    for path in sorted((ROOT / "versions").iterdir())
    if path.is_dir()
)


def read_profile(path: pathlib.Path) -> tuple[dict, dict, dict, dict]:
    return (
        json.loads((path / "stock.json").read_text()),
        json.loads((path / "signer-neutral.json").read_text()),
        json.loads((path / "private-server.json").read_text()),
        json.loads((path / "signing.json").read_text()),
    )


class ArtifactProfileTests(unittest.TestCase):
    def test_at_least_one_component_profile_exists(self):
        self.assertTrue(PROFILES)

    def test_every_profile_directory_is_complete(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                self.assertTrue((profile / "stock.json").is_file())
                self.assertTrue((profile / "signer-neutral.json").is_file())
                self.assertTrue((profile / "private-server.json").is_file())
                self.assertTrue((profile / "signing.json").is_file())

    def test_profile_ids_match_directory(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                stock, neutral, private, signing = read_profile(profile)
                self.assertEqual(stock["versionId"], profile.name)
                self.assertEqual(neutral["versionId"], profile.name)
                self.assertEqual(private["versionId"], profile.name)
                self.assertEqual(signing["versionId"], profile.name)
                self.assertEqual(
                    neutral["artifactRole"], "internal-component-reference"
                )
                self.assertEqual(private["artifactRole"], "product-carrier")
                self.assertEqual(signing["artifactRole"], "post-sign-policy")

    def test_component_source_is_sealed(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, neutral, private, _ = read_profile(profile)
                for document in (neutral, private):
                    component = document["component"]
                    source = ROOT / component["source"]
                    self.assertTrue(source.is_file())
                    self.assertEqual(
                        hashlib.sha256(source.read_bytes()).hexdigest(),
                        component["sourceSha256"],
                    )

    def test_committed_profiles_are_sealed(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                stock, neutral, private, _ = read_profile(profile)
                self.assertEqual(len(stock["input"]["sha256"]), 64)
                self.assertEqual(len(neutral["expectedCarrierSha256"]), 64)
                self.assertEqual(len(private["expectedCarrierSha256"]), 64)
                self.assertEqual(len(private["component"]["compiledDylibSha256"]), 64)
                self.assertEqual(len(private["component"]["compiledDylibUuid"]), 32)

    def test_targets_are_distinct_and_well_formed(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, neutral, _, _ = read_profile(profile)
                targets = neutral["targets"]
                self.assertEqual(
                    len(targets), neutral["outputInventory"]["runtimePatches"]
                )
                self.assertEqual(len({item["path"] for item in targets}), len(targets))
                for target in targets:
                    self.assertEqual(len(bytes.fromhex(target["patchBytes"])), 24)
                    self.assertEqual(len(target["sha256"]), 64)
                    self.assertEqual(len(target["uuid"]), 32)
                    for key in ("patchVm", "resolverVm", "dlopenVm", "dlsymVm"):
                        self.assertGreater(int(target[key], 0), 0)

    def test_private_source_bindings_are_exact_and_non_overlapping(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, _, private, _ = read_profile(profile)
                occupied = set()
                target_paths = {item["path"] for item in private["targets"]}
                for binding in private.get("sourceBindings", []):
                    self.assertIn(binding["targetPath"], target_paths)
                    before = bytes.fromhex(binding["beforeHex"])
                    after = bytes.fromhex(binding["afterHex"])
                    self.assertTrue(before)
                    self.assertEqual(len(before), len(after))
                    offset = int(binding["fileOffset"], 0)
                    for position in range(offset, offset + len(before)):
                        key = (binding["targetPath"], position)
                        self.assertNotIn(key, occupied)
                        occupied.add(key)

    def test_private_ui_bindings_keep_stock_controls_and_place_server_links(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, _, private, _ = read_profile(profile)
                bindings = {
                    item["class"]: item for item in private["uiBindings"]
                }
                self.assertEqual(
                    bindings["YNAB_Evergreen.SignInViewController"],
                    {
                        "class": "YNAB_Evergreen.SignInViewController",
                        "lifecycle": "viewDidLoad plus optional one-shot asynchronous relocation",
                        "stackIvar": "$__lazy_storage_$_stackView",
                        "initialPositionAnchorIvar": "$__lazy_storage_$_forgotPasswordButton",
                        "optionalFinalPositionAnchorIvar": "$__lazy_storage_$_createAccountButton",
                        "relocationEvent": "exact final-anchor insertion in controller-owned stack",
                        "nativeTextAction": "forgot-password-button-template",
                        "horizontalLayout": "stack-fill",
                        "spacingAfterAnchor": "zero-matching-stock-preceding-action",
                    },
                )
                self.assertEqual(
                    bindings["YNAB_Evergreen.CreateAccountViewController"],
                    {
                        "class": "YNAB_Evergreen.CreateAccountViewController",
                        "lifecycle": "viewDidLoad",
                        "stackIvar": "$__lazy_storage_$_stackView",
                        "positionAnchorIvar": "$__lazy_storage_$_signUpButton",
                        "nativeTextAction": "forgot-password-button-template",
                        "horizontalLayout": "stock-anchor-width-and-center-x",
                        "spacingAfterAnchor": "inherit-preceding",
                    },
                )

    def test_private_native_text_action_binding_is_complete(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, _, private, _ = read_profile(profile)
                binding = private["nativeTextActionBinding"]
                for key in (
                    "factoryVmAddress",
                    "sourceTitleCountAndFlags",
                    "sourceTitleObjectVmAddress",
                    "sourceAccessibilityCountAndFlags",
                    "sourceAccessibilityObjectVmAddress",
                ):
                    self.assertGreater(int(binding[key], 0), 0)
                self.assertEqual(
                    binding["expectedClassSuffix"], "InsettableContentButton"
                )
                self.assertEqual(
                    binding["invocationBoundary"],
                    "controller lifecycle or one-shot owned-stack mutation on main thread",
                )

    def test_private_subscription_flow_binding_is_origin_gated(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, _, private, _ = read_profile(profile)
                self.assertEqual(
                    private["subscriptionFlowBinding"],
                    {
                        "class": "YBAppStatus",
                        "selector": "shouldSkipSubscribeFlow",
                        "hookType": "instance-method",
                        "condition": "valid-normalized-private-origin-stored",
                        "privateOriginResult": True,
                        "otherwise": "preserve-stock-result",
                    },
                )

    def test_private_routing_blocks_owned_stock_requests_without_an_origin(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, _, private, _ = read_profile(profile)
                self.assertEqual(
                    private["routingContract"]["rewriteSources"],
                    ["owned-stock-hosts"],
                )
                self.assertEqual(
                    private["routingContract"]["unconfiguredBehavior"],
                    "owned-requests-fail-locally-through-unsupported-non-network-scheme",
                )

    def test_private_local_network_admission_is_bounded(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, _, private, _ = read_profile(profile)
                self.assertEqual(
                    private["localNetworkAdmission"],
                    {
                        "scope": "stored-normalized-private-development-origin-only",
                        "triggers": [
                            "server-origin-save",
                            "sign-in-viewDidLoad",
                            "create-account-viewDidLoad",
                        ],
                        "request": {
                            "method": "GET",
                            "path": "/health",
                            "timeoutSeconds": 8,
                            "cachePolicy": "reload-ignoring-local-cache",
                        },
                        "retry": {"count": 1, "scope": "health-probe-only"},
                        "neverAutoRetry": ["authentication", "account-creation"],
                        "failureActions": ["Retry", "Server URL", "Settings"],
                        "originPersistence": {
                            "sharedValueOwner": "main-app-install-token",
                            "upgrade": "preserve",
                            "uninstallReinstall": "reject-orphaned-shared-origin",
                        },
                    },
                )

    def test_no_private_paths(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                combined = json.dumps(read_profile(profile))
                self.assertNotIn("/Users/", combined)
                self.assertNotIn("/tmp/", combined)

    def test_signing_policy_covers_the_complete_runtime_namespace(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, _, private, signing = read_profile(profile)
                closure = signing["codeClosure"]
                self.assertEqual(
                    closure["machoContainers"],
                    private["outputInventory"]["machoContainers"],
                )
                self.assertEqual(
                    closure["machoSlices"],
                    private["outputInventory"]["machoSlices"],
                )
                code_bundles = closure["signedCodeBundles"]
                self.assertEqual(
                    len(code_bundles), closure["signatureDirectories"]
                )
                self.assertEqual(
                    len({item["path"] for item in code_bundles}),
                    len(code_bundles),
                )
                self.assertEqual(
                    len({item["bundleIdentifier"] for item in code_bundles}),
                    len(code_bundles),
                )
                roles = {item["role"] for item in closure["entitlementBundles"]}
                self.assertEqual(roles, {"main", "widget", "widget-intent"})
                code_paths = {item["path"] for item in code_bundles}
                code_identifiers = {
                    item["path"]: item["bundleIdentifier"]
                    for item in code_bundles
                }
                for item in closure["entitlementBundles"]:
                    self.assertIn(item["path"], code_paths)
                    self.assertEqual(
                        item["bundleIdentifier"],
                        code_identifiers[item["path"]],
                    )
                    self.assertIn(
                        "com.apple.security.application-groups",
                        item["requiredEntitlements"],
                    )
                    if item["role"] == "main":
                        self.assertIn(
                            "keychain-access-groups",
                            item["requiredEntitlements"],
                        )
                self.assertTrue(
                    signing["namespacePolicy"][
                        "allEntitlementBundlesMustConverge"
                    ]
                )


if __name__ == "__main__":
    unittest.main()
