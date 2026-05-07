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


# ────────────────────────────────────────────────────────────────────
# KCM-import compatibility (PR #1942)
# ────────────────────────────────────────────────────────────────────

class TestKCMImportRoundTrip(unittest.TestCase):
    """KCM-imported records (PR #1942) reference users by *title* in
    ``pam_settings.connection.launch_credentials`` rather than by UID
    in ``userRecords[]``. Export must resolve these title references
    so the exported JSON re-imports with the user link intact.
    """

    KCM_CFG = "kcm-cfg-1"
    KCM_RES = "kcm-res-prod-db"
    KCM_USR = "kcm-usr-prod-db"

    def _make_kcm_records(self):
        """Build the KCM-shaped vault state (PR #1942 import output)."""
        cfg = vault.TypedRecord(version=6)
        cfg.type_name = "pamNetworkConfiguration"
        cfg.title = "KCM Migration"
        cfg.record_uid = self.KCM_CFG
        cfg.fields.append(_make_typed_field("pamResources", [{
            "controllerUid": "gw-uid",
            "folderUid": "sf-uid",
            "resourceRef": [self.KCM_RES],
        }]))

        res = vault.TypedRecord(version=3)
        res.type_name = "pamMachine"
        res.title = "KCM Resource - prod-db"
        res.record_uid = self.KCM_RES
        res.fields.append(_make_typed_field("pamSettings", [{
            "connection": {
                "protocol": "ssh",
                "port": "22",
                "launch_credentials": "KCM User - prod-db",
            },
            "options": {"connections": "on", "rotation": "off"},
        }]))

        usr = vault.TypedRecord(version=3)
        usr.type_name = "pamUser"
        usr.title = "KCM User - prod-db"
        usr.record_uid = self.KCM_USR
        usr.fields.append(_make_typed_field("login", ["root"]))

        return {self.KCM_CFG: cfg, self.KCM_RES: res, self.KCM_USR: usr}

    def setUp(self):
        from keepercommander.commands.pam_import.export import PAMProjectExportCommand
        from unittest.mock import MagicMock
        self.cmd = PAMProjectExportCommand()
        self.records = self._make_kcm_records()
        self.params = MagicMock()
        self.params.record_cache = {uid: {} for uid in self.records}

    def _execute(self):
        def _load(_p, uid):
            return self.records.get(uid)
        with patch("keepercommander.vault.KeeperRecord.load", side_effect=_load):
            with patch.object(self.cmd, "_get_allowed_settings",
                              return_value=dict(_DEFAULT_ALLOWED)):
                return self.cmd.execute(self.params, project_uid=self.KCM_CFG)

    def test_title_based_user_link_resolved(self):
        """KCM resource → export must include the user via title resolution."""
        parsed = json.loads(self._execute())
        resources = parsed["pam_data"]["resources"]
        self.assertEqual(len(resources), 1, "expected one KCM resource")
        res = resources[0]
        self.assertEqual(len(res["users"]), 1,
                         "KCM resource must export 1 user (resolved by title)")
        self.assertEqual(res["users"][0]["uid"], self.KCM_USR)
        self.assertEqual(res["users"][0]["title"], "KCM User - prod-db")

    def test_top_level_users_includes_resolved_user(self):
        parsed = json.loads(self._execute())
        top_users = parsed["pam_data"]["users"]
        self.assertEqual(len(top_users), 1)
        self.assertEqual(top_users[0]["uid"], self.KCM_USR)

    def test_pam_settings_preserved_for_round_trip(self):
        """Round-trip safety: KCM-specific pam_settings keys preserved verbatim."""
        parsed = json.loads(self._execute())
        res = parsed["pam_data"]["resources"][0]
        conn = res["pam_settings"]["connection"]
        self.assertEqual(conn["protocol"], "ssh")
        self.assertEqual(conn["port"], "22")
        self.assertEqual(conn["launch_credentials"], "KCM User - prod-db")

    def test_uid_in_launch_credentials_accepted(self):
        """If launch_credentials already holds a 22-char UID (non-KCM path), keep it as-is."""
        uid_22 = "AAAAAAAAAAAAAAAAAAAAAA"  # 22 chars, no slash, no space
        usr = vault.TypedRecord(version=3)
        usr.type_name = "pamUser"
        usr.title = "Direct UID User"
        usr.record_uid = uid_22
        usr.fields.append(_make_typed_field("login", ["alice"]))
        self.records[uid_22] = usr
        self.params.record_cache[uid_22] = {}

        res = self.records[self.KCM_RES]
        ps = res.get_typed_field("pamSettings").value[0]
        ps["connection"]["launch_credentials"] = uid_22
        parsed = json.loads(self._execute())
        users = parsed["pam_data"]["resources"][0]["users"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["uid"], uid_22)


if __name__ == "__main__":
    unittest.main()
