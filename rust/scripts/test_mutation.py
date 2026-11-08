"""Run with `python3 -I -B -m unittest discover -s scripts` from rust/ (`just scripts-test`)."""

import unittest

from mutation import counts, judge, score, without_package_version


class Score(unittest.TestCase):
    def test_a_timeout_counts_once_as_noticed(self):
        # jwz's run of 2026-11-06: 565 caught, 34 missed, 45 timeouts.
        self.assertEqual(score(565, 34, 45), round(610 / 644, 4))

    def test_without_viable_mutants_there_is_no_score(self):
        self.assertIsNone(score(0, 0, 0))

    def test_only_missed_mutants_score_zero(self):
        self.assertEqual(score(0, 3, 0), 0.0)


class Code(unittest.TestCase):
    """What can change a crate's mutation score, and so needs a new one."""

    def test_sources_tests_and_data_count(self):
        for path in ["src/jwk.rs", "tests/jws.rs", "tests/data/x.json", "build.rs", "benches/b.rs"]:
            self.assertTrue(counts(path, set()), path)

    def test_readme_licence_stamps_fuzz_and_plain_documents_do_not(self):
        for path in ["README.md", "LICENSE", "docs/adr/0001-jwz.md", "verification/stamps/kani.toml",
                     "fuzz/fuzz_targets/jws.rs", "docs/traceability.md"]:
            self.assertFalse(counts(path, set()), path)

    def test_a_document_compiled_into_the_crate_counts(self):
        # jwz's guide is its `guide` module's documentation, and its examples run as doctests.
        self.assertTrue(counts("docs/guide.md", {"docs/guide.md"}))

    def test_only_the_package_version_line_is_left_out(self):
        old = '[package]\nname = "jwz"\nversion = "0.2.0"\n\n[dependencies]\nserde = "1"\n'
        bumped = old.replace('version = "0.2.0"', 'version = "0.2.1"')
        self.assertEqual(without_package_version(old), without_package_version(bumped))
        dependency = old.replace('serde = "1"', 'serde = "2"')
        self.assertNotEqual(without_package_version(old), without_package_version(dependency))
        table = '[package]\nname = "a"\n\n[dependencies.b]\nversion = "1"\n'
        self.assertIn('version = "1"', without_package_version(table))


class Gate(unittest.TestCase):
    """Only a crate with a threshold, one that makes a security decision, is held to a score."""

    SCORE = {"commit": "abc12345", "caught": 90, "missed": 10, "timeout": 0}

    def test_a_crate_without_a_threshold_is_not_gated(self):
        self.assertEqual(judge("ti-cli", None, None, []), (True, "ti-cli: no threshold, not gated"))

    def test_a_crate_with_a_threshold_needs_a_score(self):
        self.assertFalse(judge("ti-pki", None, 0.8, [])[0])

    def test_its_score_must_be_of_its_current_code(self):
        self.assertFalse(judge("ti-pki", self.SCORE, 0.8, ["src/lib.rs"])[0])

    def test_and_reach_the_threshold(self):
        self.assertTrue(judge("ti-pki", self.SCORE, 0.8, [])[0])
        self.assertFalse(judge("ti-pki", self.SCORE, 0.95, [])[0])


if __name__ == "__main__":
    unittest.main()
