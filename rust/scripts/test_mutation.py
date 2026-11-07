"""Run with `python3 -I -B -m unittest discover -s scripts` from rust/ (`just scripts-test`)."""

import unittest

from mutation import score


class Score(unittest.TestCase):
    def test_a_timeout_counts_once_as_noticed(self):
        # jwz's run of 2026-11-06: 565 caught, 34 missed, 45 timeouts.
        self.assertEqual(score(565, 34, 45), round(610 / 644, 4))

    def test_without_viable_mutants_there_is_no_score(self):
        self.assertIsNone(score(0, 0, 0))

    def test_only_missed_mutants_score_zero(self):
        self.assertEqual(score(0, 3, 0), 0.0)


if __name__ == "__main__":
    unittest.main()
