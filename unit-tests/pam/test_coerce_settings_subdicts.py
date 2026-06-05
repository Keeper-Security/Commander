"""
Unit tests for ``_coerce_settings_subdicts`` — the guard that protects pamSettings /
pamRemoteBrowserSettings sub-field writes from KeyError/TypeError.

Discovery and the Web Vault may publish ``connection`` / ``portForward`` as an empty
string (``""``) or omit them entirely (e.g. ``{"portForward": ""}`` with no
``connection``). The command code then indexes ``entry["connection"][...]`` /
``entry["portForward"][...]``, which would raise without this coercion. Covers the
"pam connection edit" (bug #1), "pam tunnel edit" portForward, and "pam rbi edit"
connection guards.
"""
import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

skip_tests = False
skip_reason = ""
try:
    # Pre-warm the circular-import chain (same pattern as the other pam tests).
    importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')
    from keepercommander.commands.tunnel_and_connections import _coerce_settings_subdicts
except ImportError as e:  # pragma: no cover
    skip_tests = True
    skip_reason = f"Cannot import tunnel_and_connections: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestCoerceSettingsSubdicts(unittest.TestCase):

    def test_missing_key_is_created_as_dict(self):
        entry = {"portForward": {}}  # discovery published no "connection"
        changed = _coerce_settings_subdicts(entry, "connection", "portForward")
        self.assertEqual(entry["connection"], {})
        self.assertEqual(entry["portForward"], {})
        self.assertTrue(changed)

    def test_empty_string_value_is_coerced_to_dict(self):
        entry = {"connection": {"port": 3389}, "portForward": ""}  # real dump shape
        changed = _coerce_settings_subdicts(entry, "connection", "portForward")
        self.assertEqual(entry["portForward"], {})
        # existing connection dict is preserved untouched
        self.assertEqual(entry["connection"], {"port": 3389})
        self.assertTrue(changed)

    def test_none_value_is_coerced_to_dict(self):
        entry = {"connection": None}
        changed = _coerce_settings_subdicts(entry, "connection")
        self.assertEqual(entry["connection"], {})
        self.assertTrue(changed)

    def test_existing_dicts_are_left_unchanged_and_returns_false(self):
        entry = {"connection": {"protocol": "rdp"}, "portForward": {"port": "10389"}}
        changed = _coerce_settings_subdicts(entry, "connection", "portForward")
        self.assertEqual(entry["connection"], {"protocol": "rdp"})
        self.assertEqual(entry["portForward"], {"port": "10389"})
        self.assertFalse(changed)

    def test_single_key_only_touches_that_key(self):
        entry = {"connection": "", "portForward": ""}
        changed = _coerce_settings_subdicts(entry, "connection")  # RBI: connection only
        self.assertEqual(entry["connection"], {})
        self.assertEqual(entry["portForward"], "")  # untouched
        self.assertTrue(changed)

    def test_non_dict_entry_is_a_noop(self):
        # Caller is responsible for ensuring entry is a dict; helper must not raise.
        self.assertFalse(_coerce_settings_subdicts("", "connection"))
        self.assertFalse(_coerce_settings_subdicts(None, "connection"))

    def test_indexing_after_coercion_does_not_raise(self):
        # Reproduces the bug-#1 / tunnel-edit crash shape, then confirms the write lands.
        entry = {"portForward": ""}
        _coerce_settings_subdicts(entry, "connection", "portForward")
        entry["connection"]["port"] = 3389          # would KeyError pre-fix
        entry["portForward"]["port"] = "10389"       # would TypeError pre-fix (str)
        self.assertEqual(entry["connection"]["port"], 3389)
        self.assertEqual(entry["portForward"]["port"], "10389")


if __name__ == '__main__':
    unittest.main()
