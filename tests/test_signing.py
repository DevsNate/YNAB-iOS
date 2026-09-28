from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load tool: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SIGNING = load_tool("signing_common")


class SigningPolicyHelperTests(unittest.TestCase):
    def test_profile_wildcards_authorize_narrower_effective_values(self):
        self.assertTrue(SIGNING.entitlement_authorized("example", "*"))
        self.assertTrue(
            SIGNING.entitlement_authorized(
                "TEAM.com.example.application", "TEAM.*"
            )
        )
        self.assertTrue(
            SIGNING.entitlement_authorized(
                ["TEAM.com.example.application"], ["TEAM.*"]
            )
        )
        self.assertFalse(
            SIGNING.entitlement_authorized("OTHER.application", "TEAM.*")
        )

    def test_profile_lists_reject_ungranted_values(self):
        self.assertTrue(SIGNING.entitlement_authorized(["one"], ["one", "two"]))
        self.assertFalse(SIGNING.entitlement_authorized(["three"], ["one", "two"]))

    def test_usable_string_lists_require_nonempty_values(self):
        self.assertTrue(SIGNING.usable_string_list(["TEAM.application"]))
        self.assertFalse(SIGNING.usable_string_list([]))
        self.assertFalse(SIGNING.usable_string_list([""]))
        self.assertFalse(SIGNING.usable_string_list("TEAM.application"))

    def test_signing_tools_do_not_embed_private_material(self):
        sources = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "cli/grind.py",
                "tools/sign-private-server.py",
                "tools/verify-signed.py",
            )
        )
        self.assertNotIn("/Users/", sources)
        self.assertNotIn(".p12\"", sources)
        self.assertNotIn(
            ".mobileprovision",
            sources.replace("embedded.mobileprovision", ""),
        )
        self.assertIn("--password-env", sources)


if __name__ == "__main__":
    unittest.main()
