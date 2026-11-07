"""Run with `python3 -I -B -m unittest discover -s scripts` from rust/ (`just scripts-test`)."""

import unittest

from changed import affected, owner, touches_manifests

PACKAGES = [
    {"name": "ti-types", "dir": "ti-types", "deps": set()},
    {"name": "ti-pki", "dir": "ti-pki", "deps": {"ti-types"}},
    {"name": "ti-tls", "dir": "ti-tls", "deps": {"ti-pki"}},
    {"name": "ti-cli", "dir": "ti-cli", "deps": {"ti-tls", "ti-pkcs12"}},
    {"name": "ti-pkcs12", "dir": "ti-pkcs12", "deps": set()},
    {"name": "unsafe-audit", "dir": "unsafe-audit", "deps": set()},
]


class Affected(unittest.TestCase):
    def test_a_change_reaches_every_dependent(self):
        self.assertEqual(
            affected(["ti-types/src/time.rs"], PACKAGES),
            ["ti-cli", "ti-pki", "ti-tls", "ti-types"],
        )

    def test_a_leaf_change_stays_with_its_crate_and_dependents(self):
        self.assertEqual(affected(["ti-pkcs12/tests/decode.rs"], PACKAGES), ["ti-cli", "ti-pkcs12"])

    def test_a_file_outside_every_crate_affects_none(self):
        self.assertEqual(affected(["docs/design.md", "Justfile"], PACKAGES), [])

    def test_a_file_belongs_to_the_closest_crate(self):
        nested = PACKAGES + [{"name": "ti-cli-fuzz", "dir": "ti-cli/fuzz", "deps": set()}]
        self.assertEqual(owner("ti-cli/fuzz/src/lib.rs", nested), "ti-cli-fuzz")
        self.assertEqual(owner("ti-cli/src/main.rs", nested), "ti-cli")


class Manifests(unittest.TestCase):
    def test_manifests_lock_and_policy_count(self):
        for path in ["Cargo.lock", "Cargo.toml", "ti-pki/Cargo.toml", "supply-chain/config.toml",
                     "deny.toml", "docs/unsafe-exceptions.md"]:
            self.assertTrue(touches_manifests([path]), path)

    def test_sources_do_not(self):
        self.assertFalse(touches_manifests(["ti-pki/src/lib.rs", "docs/design.md"]))


if __name__ == "__main__":
    unittest.main()
