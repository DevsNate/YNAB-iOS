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


def read_profile(path: pathlib.Path) -> tuple[dict, dict]:
    return (
        json.loads((path / "stock.json").read_text()),
        json.loads((path / "signer-neutral.json").read_text()),
    )


class ArtifactProfileTests(unittest.TestCase):
    def test_at_least_one_profile_is_admitted(self):
        self.assertTrue(PROFILES)

    def test_every_profile_directory_is_complete(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                self.assertTrue((profile / "stock.json").is_file())
                self.assertTrue((profile / "signer-neutral.json").is_file())

    def test_profile_ids_match_directory(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                stock, neutral = read_profile(profile)
                self.assertEqual(stock["versionId"], profile.name)
                self.assertEqual(neutral["versionId"], profile.name)

    def test_component_source_is_sealed(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, neutral = read_profile(profile)
                component = neutral["component"]
                source = ROOT / component["source"]
                self.assertTrue(source.is_file())
                self.assertEqual(
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                    component["sourceSha256"],
                )

    def test_committed_profiles_are_sealed(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                stock, neutral = read_profile(profile)
                self.assertEqual(len(stock["input"]["sha256"]), 64)
                self.assertEqual(len(neutral["expectedCarrierSha256"]), 64)

    def test_targets_are_distinct_and_well_formed(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                _, neutral = read_profile(profile)
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

    def test_no_private_paths(self):
        for profile in PROFILES:
            with self.subTest(profile=profile.name):
                combined = json.dumps(read_profile(profile))
                self.assertNotIn("/Users/", combined)
                self.assertNotIn("/tmp/", combined)


if __name__ == "__main__":
    unittest.main()
