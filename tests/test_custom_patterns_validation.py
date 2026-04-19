"""v0.6.3 G6 — Python `custom_patterns` name validation parity with JS.

The JS H9 commit added name validation for ShieldConfig.customPatterns
(reject __proto__/constructor/prototype + non-uppercase names). The
Python equivalent in ShieldConfig.__post_init__ was missed at the time;
G6 closes the parity gap.

Without this, a caller passing
    ShieldConfig(custom_patterns=[("__proto__", r"...")])
created a category name that flowed into downstream dict-key writes
(category counter, audit serialization). Python dicts don't have the
JS-style __proto__ setter — the prototype-pollution surface is smaller
than JS — but the invariant "category names are uppercase identifiers"
matters in both SDKs for cross-SDK hash-equality and audit-log shape.
"""

from __future__ import annotations

import unittest

import pytest

from cloakllm import ShieldConfig


class TestCustomPatternsNameValidation(unittest.TestCase):

    def test_valid_uppercase_name_accepted(self):
        cfg = ShieldConfig(custom_patterns=[("MY_THING", r"\d+")])
        self.assertEqual(cfg.custom_patterns, [("MY_THING", r"\d+")])

    def test_proto_pollution_name_rejected(self):
        for bad in ("__proto__", "constructor", "prototype"):
            with self.assertRaises(ValueError) as cm:
                ShieldConfig(custom_patterns=[(bad, r"\d+")])
            self.assertIn("Invalid custom pattern name", str(cm.exception))

    def test_lowercase_name_rejected(self):
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(custom_patterns=[("my_thing", r"\d+")])
        self.assertIn("^[A-Z]", str(cm.exception))

    def test_starts_with_digit_rejected(self):
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(custom_patterns=[("9LIVES", r"\d+")])
        self.assertIn("Invalid", str(cm.exception))

    def test_special_chars_rejected(self):
        with self.assertRaises(ValueError):
            ShieldConfig(custom_patterns=[("MY-THING", r"\d+")])
        with self.assertRaises(ValueError):
            ShieldConfig(custom_patterns=[("MY THING", r"\d+")])

    def test_non_string_name_rejected(self):
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(custom_patterns=[(None, r"\d+")])
        self.assertIn("Must be a string", str(cm.exception))

    def test_collision_with_builtin_rejected(self):
        # EMAIL is a built-in regex category — custom_patterns can't shadow it.
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(custom_patterns=[("EMAIL", r".+")])
        self.assertIn("conflicts with built-in", str(cm.exception))

    def test_malformed_entry_rejected(self):
        # custom_patterns expects (name, regex) tuples — bare strings
        # or single-element lists must error clearly.
        with self.assertRaises(ValueError):
            ShieldConfig(custom_patterns=["just_a_string"])
        with self.assertRaises(ValueError):
            ShieldConfig(custom_patterns=[("only_name",)])

    def test_empty_list_accepted(self):
        # Default — no patterns is fine.
        cfg = ShieldConfig(custom_patterns=[])
        self.assertEqual(cfg.custom_patterns, [])


if __name__ == "__main__":
    unittest.main()
