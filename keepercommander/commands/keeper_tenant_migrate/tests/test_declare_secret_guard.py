"""Tests for keepercommander.commands.keeper_tenant_migrate.declare.secret_guard."""
import unittest

from keepercommander.commands.keeper_tenant_migrate.declare.secret_guard import find_secret_fields


class SecretGuardTests(unittest.TestCase):
    def test_clean_manifest_no_findings(self):
        d = {"schema": "tenant-overlay.v1", "name": "x", "base": "/p",
             "edits": {"roles": {"rename": {"Admin": "Administrator"}}}}
        self.assertEqual(find_secret_fields(d), [])

    def test_password_at_top_level(self):
        self.assertIn("password", find_secret_fields({"password": "hunter2"}))

    def test_nested_password(self):
        d = {"a": {"b": {"password": "x"}}}
        f = find_secret_fields(d)
        self.assertEqual(f, ["a.b.password"])

    def test_api_key_with_underscore_or_concat(self):
        for name in ("api_key", "apikey", "API_KEY"):
            self.assertEqual(find_secret_fields({name: "x"}), [name])

    def test_private_key(self):
        self.assertIn("private_key", find_secret_fields({"private_key": "x"}))

    def test_totp_and_otp_seed(self):
        self.assertEqual(find_secret_fields({"totp": "x"}), ["totp"])
        self.assertEqual(find_secret_fields({"otp_seed": "x"}), ["otp_seed"])

    def test_inside_lists(self):
        d = {"items": [{"id": 1}, {"secret": "y"}]}
        f = find_secret_fields(d)
        self.assertEqual(f, ["items[1].secret"])

    def test_case_insensitive(self):
        self.assertEqual(find_secret_fields({"Password": "x"}), ["Password"])
        self.assertEqual(find_secret_fields({"PWD": "x"}), ["PWD"])

    def test_substring_match_does_not_false_positive_on_innocuous(self):
        # `node` and `not_secret_at_all` should NOT trigger
        self.assertEqual(find_secret_fields({"node": "Acme"}), [])
        self.assertEqual(find_secret_fields({"name": "x"}), [])

    def test_substring_match_does_match_compound(self):
        # boundary is \b, so this hits — the field name contains 'secret'
        self.assertEqual(find_secret_fields({"my_secret_value": "x"}),
                         ["my_secret_value"])


if __name__ == "__main__":
    unittest.main()
