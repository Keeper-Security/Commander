#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Unit tests for PAMProjectExportCommand.

Uses real vault.TypedRecord / vault.TypedField objects (no network access)
so isinstance() checks in the production code pass correctly.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from keepercommander import vault

# ── record builders ────────────────────────────────────────────────────────

def _make_typed_field(field_type, value, label=None):
    """Create a real vault.TypedField."""
    tf = vault.TypedField.new_field(field_type, value, field_label=label)
    return tf


def _make_config_record(uid, title="Test Project", record_type="pamNetworkConfiguration",
                        resource_uids=None):
    """Real vault.TypedRecord v6 for a PAM configuration."""
    resource_uids = resource_uids or ["res-machine-1", "res-db-1"]

    rec = vault.TypedRecord(version=6)
    rec.type_name = record_type
    rec.title = title
    rec.record_uid = uid

    pam_res_value = [{
        "controllerUid": "gw-uid-abc",
        "folderUid": "sf-uid-abc",
        "resourceRef": list(resource_uids),
    }]
    rec.fields.append(_make_typed_field("pamResources", pam_res_value))
    return rec


def _make_resource_record(uid, title, record_type, user_uids=None):
    """Real vault.TypedRecord v3 for a PAM resource."""
    user_uids = user_uids or []
    rec = vault.TypedRecord(version=3)
    rec.type_name = record_type
    rec.title = title
    rec.record_uid = uid

    pam_settings_value = [{
        "connection": {"userRecords": list(user_uids), "protocol": "ssh"},
    }]
    rec.fields.append(_make_typed_field("pamSettings", pam_settings_value))
    return rec


def _make_user_record(uid, title, login):
    """Real vault.TypedRecord v3 for a pamUser."""
    rec = vault.TypedRecord(version=3)
    rec.type_name = "pamUser"
    rec.title = title
    rec.record_uid = uid
    rec.fields.append(_make_typed_field("login", [login]))
    return rec


# ── fixtures ───────────────────────────────────────────────────────────────

CONFIG_UID = "cfg-uid-001"
MACHINE_UID = "res-machine-1"
DB_UID = "res-db-1"
USER1_UID = "usr-uid-001"
USER2_UID = "usr-uid-002"

_RECORDS = {
    CONFIG_UID: _make_config_record(CONFIG_UID, "Test Project",
                                    resource_uids=[MACHINE_UID, DB_UID]),
    MACHINE_UID: _make_resource_record(MACHINE_UID, "Linux Server", "pamMachine",
                                       user_uids=[USER1_UID]),
    DB_UID: _make_resource_record(DB_UID, "Postgres DB", "pamDatabase",
                                  user_uids=[USER1_UID, USER2_UID]),
    USER1_UID: _make_user_record(USER1_UID, "Admin User", "root"),
    USER2_UID: _make_user_record(USER2_UID, "DB User", "dbuser"),
}


def _fake_load(_params, uid):
    """Replacement for vault.KeeperRecord.load in tests."""
    return _RECORDS.get(uid)


_DEFAULT_ALLOWED = {
    "connections": "on", "rotation": "on", "tunneling": "on",
    "remote_browser_isolation": "on", "graphical_session_recording": "off",
    "text_session_recording": "off", "ai_threat_detection": "off",
    "ai_terminate_session_on_detection": "off",
}

# ── tests ──────────────────────────────────────────────────────────────────

if sys.version_info >= (3, 8):

    from unittest.mock import MagicMock

    class TestPAMProjectExportCommand(unittest.TestCase):

        def setUp(self):
            from keepercommander.commands.pam_import.export import PAMProjectExportCommand
            self.cmd = PAMProjectExportCommand()
            self.params = MagicMock()
            self.params.record_cache = {uid: {} for uid in _RECORDS}

        def _execute(self, project_uid=CONFIG_UID, output=None):
            """Run execute() with vault.KeeperRecord.load mocked."""
            with patch("keepercommander.vault.KeeperRecord.load", side_effect=_fake_load):
                with patch.object(self.cmd, "_get_allowed_settings",
                                  return_value=dict(_DEFAULT_ALLOWED)):
                    kwargs = {"project_uid": project_uid}
                    if output:
                        kwargs["output"] = output
                    return self.cmd.execute(self.params, **kwargs)

        # ── basic output ──────────────────────────────────────────────

        def test_returns_string(self):
            result = self._execute()
            self.assertIsInstance(result, str,
                                  "execute() should return a JSON string when --output is not set")

        def test_valid_json(self):
            parsed = json.loads(self._execute())
            self.assertIsInstance(parsed, dict)

        # ── required top-level keys ───────────────────────────────────

        def test_has_project_key(self):
            parsed = json.loads(self._execute())
            self.assertIn("project", parsed)
            self.assertEqual(parsed["project"], "Test Project")

        def test_has_pam_configuration_key(self):
            parsed = json.loads(self._execute())
            self.assertIn("pam_configuration", parsed)

        def test_has_pam_data_key(self):
            parsed = json.loads(self._execute())
            self.assertIn("pam_data", parsed)
            self.assertIn("resources", parsed["pam_data"])
            self.assertIn("users", parsed["pam_data"])

        def test_has_tool_version(self):
            parsed = json.loads(self._execute())
            self.assertIn("tool_version", parsed)
            self.assertEqual(parsed["tool_version"], "commander-export-1.0")

        # ── pam_configuration fields ──────────────────────────────────

        def test_pam_configuration_environment(self):
            parsed = json.loads(self._execute())
            self.assertEqual(parsed["pam_configuration"]["environment"], "local")

        def test_pam_configuration_on_off_values(self):
            parsed = json.loads(self._execute())
            cfg = parsed["pam_configuration"]
            for key in ("connections", "rotation", "tunneling", "remote_browser_isolation"):
                self.assertIn(cfg[key], ("on", "off"), f"{key} must be 'on' or 'off'")

        # ── resources ────────────────────────────────────────────────

        def test_resources_count(self):
            parsed = json.loads(self._execute())
            self.assertEqual(len(parsed["pam_data"]["resources"]), 2)

        def test_resource_has_required_keys(self):
            parsed = json.loads(self._execute())
            for res in parsed["pam_data"]["resources"]:
                for key in ("uid", "type", "title", "users"):
                    self.assertIn(key, res, f"resource missing key: {key}")

        def test_resource_uids_are_unique(self):
            parsed = json.loads(self._execute())
            uids = [r["uid"] for r in parsed["pam_data"]["resources"]]
            self.assertEqual(len(uids), len(set(uids)), "resource UIDs must be unique")

        def test_resource_types(self):
            parsed = json.loads(self._execute())
            types = {r["type"] for r in parsed["pam_data"]["resources"]}
            self.assertIn("pamMachine", types)
            self.assertIn("pamDatabase", types)

        # ── users ────────────────────────────────────────────────────

        def test_top_level_users_deduplication(self):
            # USER1 appears in both machine and database resources;
            # must only appear once in pam_data.users
            parsed = json.loads(self._execute())
            top_uids = [u["uid"] for u in parsed["pam_data"]["users"]]
            self.assertEqual(len(top_uids), len(set(top_uids)),
                             "top-level user UIDs must be unique (de-duplicated)")

        def test_top_level_users_count(self):
            # USER1 shared across both resources, USER2 only in DB → 2 unique users
            parsed = json.loads(self._execute())
            self.assertEqual(len(parsed["pam_data"]["users"]), 2)

        def test_user_has_required_keys(self):
            parsed = json.loads(self._execute())
            for usr in parsed["pam_data"]["users"]:
                for key in ("uid", "type", "title", "login"):
                    self.assertIn(key, usr, f"user missing key: {key}")

        # ── --output flag ────────────────────────────────────────────

        def test_output_flag_writes_file(self):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
                tmp_path = tmp.name
            try:
                result = self._execute(output=tmp_path)
                # When --output is set, execute() should return None
                self.assertIsNone(result)
                self.assertTrue(os.path.exists(tmp_path))
                with open(tmp_path, encoding="utf-8") as fh:
                    content = fh.read()
                parsed = json.loads(content)
                self.assertIn("project", parsed)
                self.assertIn("tool_version", parsed)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

        # ── error handling ───────────────────────────────────────────

        def test_missing_project_uid_returns_none(self):
            with patch("keepercommander.vault.KeeperRecord.load", side_effect=_fake_load):
                result = self.cmd.execute(self.params, project_uid="", output=None)
            self.assertIsNone(result)

        def test_unknown_uid_returns_none(self):
            with patch("keepercommander.vault.KeeperRecord.load", return_value=None):
                result = self.cmd.execute(self.params, project_uid="unknown-uid", output=None)
            self.assertIsNone(result)

        def test_non_v6_record_returns_none(self):
            v3_rec = vault.TypedRecord(version=3)
            v3_rec.type_name = "pamMachine"
            v3_rec.title = "some"
            v3_rec.record_uid = "some-uid"
            with patch("keepercommander.vault.KeeperRecord.load", return_value=v3_rec):
                result = self.cmd.execute(self.params, project_uid="some-uid", output=None)
            self.assertIsNone(result)

        # ── round-trip / determinism ─────────────────────────────────

        def test_sort_keys_determinism(self):
            result1 = self._execute()
            result2 = self._execute()
            self.assertEqual(result1, result2, "Output must be deterministic across calls")

        def test_output_is_sorted(self):
            result = self._execute()
            parsed = json.loads(result)
            keys = list(parsed.keys())
            self.assertEqual(keys, sorted(keys),
                             "Top-level keys should be sorted (sort_keys=True)")


else:
    class TestPAMProjectExportCommand(unittest.TestCase):
        def test_skip(self):
            self.skipTest("Requires Python 3.8+")


if __name__ == "__main__":
    unittest.main()
