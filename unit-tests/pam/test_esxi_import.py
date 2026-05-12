#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Smoke tests for pam_import.esxi_import.

Focus: the new pieces unique to this PR — the in-process record
creator, the rollback path with audit-tag handling, the kv-style
parsers, the structured report builder. Field-schema / DAG-wiring
parity with the source-of-truth tool (jlima8900/esxi-pam-rotation)
is covered by its 1079-test suite upstream of this port; these
tests cover the Commander-integration shim.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from keepercommander.commands.pam_import.esxi_import import (
    PAMProjectESXiImportCommand,
    _create_record_in_process,
    execute_rollback_in_process,
    parse_user_map,
    parse_vm_record_type,
    build_import_report,
    _record_type_for_protocol,
    _extract_uid,
)


class TestParsers(unittest.TestCase):
    """The kv-style parsers (operator-typed argv values)."""

    def test_user_map_basic(self):
        out = parse_user_map("alice=alice@x.com,bob=bob@y.com")
        self.assertEqual(out, {"alice": "alice@x.com", "bob": "bob@y.com"})

    def test_user_map_empty(self):
        self.assertEqual(parse_user_map(None), {})
        self.assertEqual(parse_user_map(""), {})

    def test_user_map_malformed_raises(self):
        with self.assertRaises(RuntimeError):
            parse_user_map("alice-without-equals")
        with self.assertRaises(RuntimeError):
            parse_user_map("alice=")

    def test_vm_record_type_basic(self):
        out = parse_vm_record_type("v1=pamDatabase,v2=pamDirectory")
        self.assertEqual(out, {"v1": "pamDatabase", "v2": "pamDirectory"})

    def test_vm_record_type_malformed_raises(self):
        with self.assertRaises(RuntimeError):
            parse_vm_record_type("noequals")


class TestProtocolRouting(unittest.TestCase):
    """Upstream PROTOCOL_TYPE_MAP routing."""

    def test_default_is_pamMachine(self):
        self.assertEqual(_record_type_for_protocol("ssh"), "pamMachine")
        self.assertEqual(_record_type_for_protocol("rdp"), "pamMachine")

    def test_http_routes_to_rbi(self):
        self.assertEqual(_record_type_for_protocol("http"), "pamRemoteBrowser")

    def test_db_protocols_route_to_pamDatabase(self):
        self.assertEqual(_record_type_for_protocol("mysql"), "pamDatabase")
        self.assertEqual(_record_type_for_protocol("postgres"), "pamDatabase")

    def test_unknown_falls_back(self):
        self.assertEqual(_record_type_for_protocol("xyz"), "pamMachine")


class TestExtractUid(unittest.TestCase):
    """Phase 8.24 D7 anchored UID scan — strict line-only match."""

    def test_finds_uid_on_own_line(self):
        out = "created successfully\nAaBbCcDdEeFfGgHhIiJjKk\n"
        self.assertEqual(_extract_uid(out), "AaBbCcDdEeFfGgHhIiJjKk")

    def test_rejects_uid_embedded_in_line(self):
        # Adversarial VM name happens to be 22 url-safe chars; must NOT match.
        out = "creating record: AaBbCcDdEeFfGgHhIiJjKk for X"
        self.assertIsNone(_extract_uid(out))

    def test_rejects_too_short(self):
        out = "shortuid\n"
        self.assertIsNone(_extract_uid(out))


class TestInProcessRecordCreator(unittest.TestCase):
    """_create_record_in_process — builds vault.TypedRecord from row dict."""

    def _make_params(self):
        params = MagicMock()
        params.folder_cache = {}
        params.shared_folder_cache = {}
        params.data_key = b"\x00" * 32
        return params

    @patch("keepercommander.record_management.add_record_to_folder")
    def test_creates_pamuser_record(self, mock_add):
        params = self._make_params()
        # mock generates a UID
        def _side_effect(p, rec, folder_uid=None):
            rec.record_uid = "U" * 22
            return None
        mock_add.side_effect = _side_effect

        row = {
            "type": "pamUser",
            "title": "host :: alice",
            "fields": {
                "login": "alice",
                "password": "",
                "notes": "phase6:demo ; imported",
            },
        }
        rc, stdout, stderr = _create_record_in_process(params, row, None)
        self.assertEqual(rc, 0)
        self.assertEqual(stderr, "")
        self.assertIn("U" * 22, stdout)
        mock_add.assert_called_once()
        # Confirm the record passed in had the right shape
        called_record = mock_add.call_args.args[1]
        self.assertEqual(called_record.type_name, "pamUser")
        self.assertEqual(called_record.title, "host :: alice")
        self.assertEqual(called_record.notes, "phase6:demo ; imported")

    @patch("keepercommander.record_management.add_record_to_folder")
    def test_parses_json_prefix(self, mock_add):
        params = self._make_params()
        def _se(p, rec, folder_uid=None):
            rec.record_uid = "V" * 22
        mock_add.side_effect = _se

        host_json = json.dumps({"hostName": "esxi-01", "port": "22"})
        row = {
            "type": "pamMachine",
            "title": "esxi-01",
            "fields": {
                "pamHostname": f"$JSON:{host_json}",
                "notes": "",
            },
        }
        rc, _, _ = _create_record_in_process(params, row, None)
        self.assertEqual(rc, 0)
        called_record = mock_add.call_args.args[1]
        # The pamHostname field's value should be the parsed dict, not the string
        hostname_field = next(
            (f for f in called_record.fields if f.type == "pamHostname"), None,
        )
        self.assertIsNotNone(hostname_field)
        self.assertEqual(hostname_field.value[0]["hostName"], "esxi-01")

    @patch("keepercommander.record_management.add_record_to_folder")
    def test_c_text_routes_to_custom(self, mock_add):
        params = self._make_params()
        def _se(p, rec, folder_uid=None):
            rec.record_uid = "W" * 22
        mock_add.side_effect = _se

        row = {
            "type": "pamMachine",
            "title": "esxi-01",
            "fields": {
                "notes": "",
                "c.text.ESXi Version": "8.0.3",
                "c.text.Hardware": "Dell PowerEdge",
            },
        }
        rc, _, _ = _create_record_in_process(params, row, None)
        self.assertEqual(rc, 0)
        called_record = mock_add.call_args.args[1]
        labels = {f.label: f.value[0] for f in called_record.custom}
        self.assertEqual(labels, {"ESXi Version": "8.0.3", "Hardware": "Dell PowerEdge"})

    @patch("keepercommander.record_management.add_record_to_folder")
    def test_add_failure_propagates(self, mock_add):
        params = self._make_params()
        mock_add.side_effect = RuntimeError("vault error")
        row = {"type": "pamUser", "title": "t", "fields": {"login": "u"}}
        rc, _, stderr = _create_record_in_process(params, row, None)
        self.assertEqual(rc, 1)
        self.assertIn("vault error", stderr)


class TestExecuteRollbackInProcess(unittest.TestCase):
    """Rollback path — audit-tag check + in-process delete."""

    def test_refuses_without_audit_tag(self):
        state = {"pam_import": {"execution": {"rows": [
            {"result": "ok", "uid": "U" * 22, "title": "x"},
        ]}}}
        out = execute_rollback_in_process(
            MagicMock(), state, yes=True,
            audit_tag_override=None,
            skip_audit_check=False,
        )
        self.assertTrue(out.get("refused_no_audit_tag"))

    def test_refuses_without_yes(self):
        state = {"pam_import": {"execution": {"rows": [
            {"result": "ok", "uid": "U" * 22, "title": "x"},
        ]}, "plan": {"target": "demo"}}}
        out = execute_rollback_in_process(
            MagicMock(), state, yes=False,
        )
        self.assertTrue(out.get("refused_no_yes"))

    def test_not_run_when_no_pam_import_section(self):
        out = execute_rollback_in_process(
            MagicMock(), {}, yes=True, skip_audit_check=True,
        )
        self.assertTrue(out.get("not_run"))

    @patch("keepercommander.api.sync_down")
    @patch("keepercommander.api.delete_record")
    def test_skip_audit_check_deletes_all(self, mock_delete, mock_sync):
        params = MagicMock()
        state = {"pam_import": {"execution": {"rows": [
            {"result": "ok", "uid": "U" * 22, "title": "a"},
            {"result": "ok", "uid": "V" * 22, "title": "b"},
            {"result": "failed", "uid": "X" * 22, "title": "c"},  # skip non-ok
        ]}}}
        out = execute_rollback_in_process(
            params, state, yes=True, skip_audit_check=True,
        )
        self.assertEqual(out["rolled_back"], 2)
        self.assertEqual(out["failed"], 0)
        self.assertEqual(mock_delete.call_count, 2)


class TestCommandParser(unittest.TestCase):
    """Argparse surface — all flags present + help renders."""

    def test_help_renders(self):
        import io
        buf = io.StringIO()
        PAMProjectESXiImportCommand.parser.print_help(buf)
        body = buf.getvalue()
        self.assertGreater(len(body), 2000)
        # All 7 new operator flags present
        for flag in (
            "--host-record-type", "--vm-record-type", "--share-scope",
            "--minimum-role", "--include-host-share", "--vm-primary-user",
            "--folder-from",
        ):
            self.assertIn(flag, body)
        # Examples in epilog
        self.assertIn("pam project esxi-import", body)
        self.assertIn("--dry-run", body)


class TestBuildImportReport(unittest.TestCase):
    """The kcm-import-style structured report."""

    def test_smoke(self):
        plan = {"host": "esxi-01", "rbi_mode": "none", "target": "demo",
                "rows": [], "warnings": ["test warning"], "summary": {}}
        execution = {"rows": [
            {"type": "pamMachine", "title": "host", "result": "ok"},
            {"type": "pamUser", "title": "alice", "result": "failed",
             "stderr": "boom"},
        ]}
        report = build_import_report(plan, execution, pam_config_uid="P" * 22)
        self.assertIn("IMPORT RESULTS", report)
        self.assertIn("RECORD BREAKDOWN", report)
        self.assertIn("FAILED RECORDS", report)
        self.assertIn("boom", report)  # Phase 8.24 B1: failed-row reads stderr
        self.assertIn("WARNINGS", report)
        self.assertIn("test warning", report)
        self.assertIn("WHAT TO DO NEXT", report)
        self.assertIn("P" * 22, report)


if __name__ == "__main__":
    unittest.main()
