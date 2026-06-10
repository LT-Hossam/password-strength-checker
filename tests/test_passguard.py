"""Tests for PassGuard. All offline — the breach logic is tested against a
synthetic API response, so no network is required.

Run with:  python -m pytest -q     (or)     python tests/test_passguard.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from passguard import strength
from passguard.breach import hash_password, parse_range_response


class TestStrength(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        report = strength.analyze("password")
        self.assertEqual(report["rating"], "Very Weak")
        self.assertTrue(any("common" in w for w in report["warnings"]))

    def test_all_digits_flagged(self):
        report = strength.analyze("8462013957")
        self.assertTrue(any("digits" in w for w in report["warnings"]))

    def test_keyboard_pattern_detected(self):
        self.assertTrue(any("keyboard" in w for w in strength.detect_patterns("qwerty12")))

    def test_sequential_run_detected(self):
        self.assertTrue(any("sequential" in w for w in strength.detect_patterns("abcd9921")))

    def test_repeated_run_detected(self):
        self.assertTrue(any("repeated" in w for w in strength.detect_patterns("aaaa1234")))

    def test_strong_passphrase_scores_high(self):
        report = strength.analyze("Tr0ub4dor&3-Xk9!qZ")
        self.assertGreaterEqual(report["score"], 60)
        self.assertIn(report["rating"], ("Strong", "Very Strong"))

    def test_longer_password_has_more_entropy(self):
        short = strength.analyze("Ab1!xY")["raw_entropy_bits"]
        longer = strength.analyze("Ab1!xY" * 3)["raw_entropy_bits"]
        self.assertGreater(longer, short)

    def test_empty_password_does_not_crash(self):
        report = strength.analyze("")
        self.assertEqual(report["length"], 0)
        self.assertEqual(report["score"], 0)


class TestBreachKAnonymity(unittest.TestCase):
    def test_hash_split_sends_only_prefix(self):
        prefix, suffix = hash_password("password")
        # k-anonymity: prefix is exactly 5 chars; suffix completes the digest.
        self.assertEqual(len(prefix), 5)
        self.assertEqual(len(prefix) + len(suffix), 40)  # SHA-1 hex length
        # The full hash must never equal just the prefix that goes to the API.
        self.assertNotIn(suffix, prefix)

    def test_parser_finds_matching_suffix(self):
        # Build a synthetic API response that includes our real suffix.
        _, suffix = hash_password("password")
        body = "\r\n".join([
            "00000000000000000000000000000000000:5",
            f"{suffix}:99999",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3",
        ])
        self.assertEqual(parse_range_response(body, suffix), 99999)

    def test_parser_returns_zero_when_absent(self):
        _, suffix = hash_password("a-unique-passphrase-not-in-list-9281")
        body = "0123456789ABCDEF0123456789ABCDEF012:7"
        self.assertEqual(parse_range_response(body, suffix), 0)

    def test_parser_is_case_insensitive(self):
        _, suffix = hash_password("password")
        body = f"{suffix.lower()}:42"
        self.assertEqual(parse_range_response(body, suffix), 42)


if __name__ == "__main__":
    unittest.main(verbosity=2)
