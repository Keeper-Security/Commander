"""
Tests for pam_settings.port_forward in `pam project import/extend`:
Keeper proxy gates (SSH/RDP/DB), use_specified_local_port/local_port, the pre-flight
validation that runs before any vault write, and `pam tunnel edit` writing the DB
gate to portForward only (never to the legacy connection section).
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from keepercommander import vault
from keepercommander.commands.pam_import.base import PamPortForwardSettings, PamSettingsFieldData
from keepercommander.commands.pam_import.port_forward_validation import (
    preflight_port_forward, validate_port_forward_data, validate_resource_port_forward,
)


def _res(rtype="pamMachine", protocol="rdp", port_forward=None, connection=None, options=None, **ps):
    conn = {"protocol": protocol, "launch_credentials": "launch-user"}
    conn.update(connection or {})
    pam_settings = {"connection": conn, "port_forward": port_forward or {}}
    if options:
        pam_settings["options"] = options
    pam_settings.update(ps)
    return {"type": rtype, "title": "R1", "pam_settings": pam_settings}


class TestPortForwardLoad(unittest.TestCase):
    def test_load_and_record_dict_all_keys(self):
        pf = PamPortForwardSettings.load({
            "port": "2222", "reuse_port": True, "use_specified_local_port": True, "local_port": 5555,
            "allow_keeper_db_proxy": True, "allow_keeper_rdp_proxy": "true", "allow_keeper_ssh_proxy": False,
        })
        self.assertEqual(pf.to_record_dict(), {
            "port": "2222", "reusePort": True, "useSpecifiedLocalPort": True, "localPort": "5555",
            "allowKeeperDBProxy": True, "allowKeeperRDPProxy": True, "allowKeeperSSHProxy": False,
        })

    def test_empty_load_has_no_keys(self):
        self.assertEqual(PamPortForwardSettings.load({}).to_record_dict(), {})

    def test_settings_field_data_keeps_gates_in_port_forward(self):
        fd = PamSettingsFieldData.load({
            "port_forward": {"allow_keeper_ssh_proxy": True},
            "connection": {"protocol": "ssh"},
        })
        self.assertTrue(fd.portForward.allowKeeperSSHProxy)
        self.assertIsNone(fd.portForward.allowKeeperDBProxy)


class TestPortForwardValidation(unittest.TestCase):
    def errors(self, res):
        return validate_resource_port_forward(res)[0]

    def test_valid_gates(self):
        for rtype, proto, key in (
            ("pamMachine", "rdp", "allow_keeper_rdp_proxy"),
            ("pamMachine", "ssh", "allow_keeper_ssh_proxy"),
            ("pamDatabase", "mysql", "allow_keeper_db_proxy"),
            ("pamDatabase", "mariadb", "allow_keeper_db_proxy"),
            ("pamDatabase", "postgresql", "allow_keeper_db_proxy"),
            ("pamDatabase", "sql-server", "allow_keeper_db_proxy"),
            ("pamDatabase", "oracle", "allow_keeper_db_proxy"),
            ("pamDatabase", "dynamodb", "allow_keeper_db_proxy"),
        ):
            self.assertEqual(self.errors(_res(rtype, proto, {key: True})), [], (proto, key))

    def test_gate_off_never_errors(self):
        self.assertEqual(self.errors(_res("pamMachine", "vnc", {"allow_keeper_rdp_proxy": False},
                                          connection={"launch_credentials": ""})), [])

    def test_gate_on_unsupported_protocol(self):
        self.assertEqual(len(self.errors(_res("pamMachine", "ssh", {"allow_keeper_rdp_proxy": True}))), 1)
        self.assertEqual(len(self.errors(_res("pamMachine", "rdp", {"allow_keeper_ssh_proxy": True}))), 1)
        self.assertEqual(len(self.errors(_res("pamMachine", "rdp", {"allow_keeper_db_proxy": True}))), 1)
        # MongoDB is not in the Web Vault KeeperDB Proxy list
        self.assertEqual(len(self.errors(_res("pamDatabase", "mongodb", {"allow_keeper_db_proxy": True}))), 1)
        self.assertEqual(len(self.errors(_res("pamDatabase", "redis", {"allow_keeper_db_proxy": True}))), 1)

    def test_gate_without_protocol(self):
        res = _res("pamDatabase", "", {"allow_keeper_db_proxy": True})
        self.assertIn("requires pam_settings.connection.protocol", self.errors(res)[0])

    def test_launch_credential_required(self):
        res = _res("pamMachine", "rdp", {"allow_keeper_rdp_proxy": True}, connection={"launch_credentials": ""})
        errs = self.errors(res)
        self.assertEqual(len(errs), 1)
        self.assertIn("launch credential", errs[0])

    def test_launch_credential_satisfied_by(self):
        pf = {"allow_keeper_rdp_proxy": True}
        base = {"launch_credentials": ""}
        self.assertEqual(self.errors(_res(port_forward=pf, connection={"launch_credentials": ["u1"]})), [])
        self.assertEqual(self.errors(_res(port_forward=pf, connection={**base, "allow_supply_user": True})), [])
        self.assertEqual(self.errors(_res(port_forward=pf, connection=base, allow_supply_host=True)), [])
        self.assertEqual(self.errors(_res(port_forward=pf, connection=base,
                                          options={"jit_settings": {"create_ephemeral": True}})), [])

    def test_dynamodb_ephemeral_does_not_satisfy_credential(self):
        res = _res("pamDatabase", "dynamodb", {"allow_keeper_db_proxy": True}, connection={"launch_credentials": ""},
                   options={"jit_settings": {"create_ephemeral": True}})
        self.assertEqual(len(self.errors(res)), 1)

    def test_local_port_rules(self):
        self.assertEqual(len(self.errors(_res(port_forward={"use_specified_local_port": True}))), 1)
        self.assertEqual(self.errors(_res(port_forward={"use_specified_local_port": True, "local_port": "8080"})), [])
        self.assertEqual(self.errors(_res(port_forward={"use_specified_local_port": True, "local_port": 8080})), [])
        for bad in ("0", "65536", "abc", "-1", "80.5"):
            self.assertEqual(len(self.errors(_res(port_forward={"local_port": bad}))), 1, bad)
        # use_specified_local_port off: the (valid) port is just stored
        self.assertEqual(self.errors(_res(port_forward={"use_specified_local_port": False, "local_port": "9"})), [])

    def test_legacy_db_gate_in_connection_rejected(self):
        for key in ("allow_keeper_db_proxy", "allowKeeperDBProxy"):
            res = _res("pamDatabase", "mysql", connection={key: True})
            errs = self.errors(res)
            self.assertEqual(len(errs), 1, key)
            self.assertIn("port_forward.allow_keeper_db_proxy", errs[0])

    def test_tunneling_off_is_warning_only(self):
        res = _res(port_forward={"reuse_port": True}, options={"tunneling": "off"})
        errs, warns = validate_resource_port_forward(res)
        self.assertEqual(errs, [])
        self.assertEqual(len(warns), 1)
        # no port_forward settings -> nothing to warn about
        self.assertEqual(validate_resource_port_forward(_res(options={"tunneling": "off"})), ([], []))

    def test_tunneling_off_with_gate_still_checks_errors(self):
        res = _res("pamMachine", "ssh", {"allow_keeper_rdp_proxy": True}, options={"tunneling": "off"})
        errs, warns = validate_resource_port_forward(res)
        self.assertEqual(len(errs), 1)
        self.assertEqual(len(warns), 1)

    def test_all_errors_collected_across_resources(self):
        data = {"resources": [
            _res("pamMachine", "ssh", {"allow_keeper_rdp_proxy": True}),
            _res("pamDatabase", "mysql", {"allow_keeper_db_proxy": True}),  # ok
            _res("pamMachine", "rdp", {"use_specified_local_port": True}),
            {"type": "pamRemoteBrowser", "title": "rbi"},  # ignored
        ]}
        errs, _ = validate_port_forward_data(data)
        self.assertEqual(len(errs), 2)
        self.assertIn("resources[0]", errs[0])
        self.assertIn("resources[2]", errs[1])

    def test_non_dict_data_is_ignored(self):
        self.assertEqual(validate_port_forward_data(None), ([], []))
        self.assertEqual(validate_port_forward_data({"resources": "x"}), ([], []))
        self.assertEqual(validate_port_forward_data({"resources": [None, 1]}), ([], []))

    def test_preflight_return_value(self):
        self.assertTrue(preflight_port_forward({"resources": [_res()]}))
        bad = {"resources": [_res("pamMachine", "ssh", {"allow_keeper_rdp_proxy": True})]}
        with mock.patch("builtins.print") as p:
            self.assertFalse(preflight_port_forward(bad))
        self.assertTrue(any("No changes made to vault" in str(c) for c in p.call_args_list))


class TestPreflightRunsBeforeVaultWrites(unittest.TestCase):
    BAD = {"project": "P1", "pam_data": {"resources": [_res("pamMachine", "ssh", {"allow_keeper_rdp_proxy": True})]}}

    def test_import_aborts_before_any_vault_access(self):
        from keepercommander.commands.pam_import import edit
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.BAD, f)
            cmd = edit.PAMProjectImportCommand()
            with mock.patch.object(edit.api, "sync_down") as sync, \
                    mock.patch.object(cmd, "process_folders") as folders, \
                    mock.patch.object(cmd, "process_ksm_app") as app, \
                    mock.patch("builtins.print"):
                cmd.execute(mock.MagicMock(), file_name=path, project_name="", dry_run=False)
        sync.assert_not_called()
        folders.assert_not_called()
        app.assert_not_called()

    def test_import_dry_run_also_validates(self):
        from keepercommander.commands.pam_import import edit
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.BAD, f)
            cmd = edit.PAMProjectImportCommand()
            with mock.patch.object(edit.api, "sync_down") as sync, mock.patch("builtins.print"):
                cmd.execute(mock.MagicMock(), file_name=path, project_name="", dry_run=True)
        sync.assert_not_called()

    def test_extend_aborts_before_gateway_and_folders(self):
        from keepercommander.commands.pam_import import extend
        cfg = vault.TypedRecord(version=6)
        cfg.record_uid = "cfguid"
        cmd = extend.PAMProjectExtendCommand()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"pam_data": self.BAD["pam_data"]}, f)
            with mock.patch.object(extend.api, "sync_down"), \
                    mock.patch.object(extend, "find_pam_configuration", return_value=cfg), \
                    mock.patch.object(extend, "configuration_controller_get") as ctrl, \
                    mock.patch.object(cmd, "process_folders") as folders, \
                    mock.patch("builtins.print"):
                cmd.execute(mock.MagicMock(), file_name=path, config="cfg", dry_run=False)
        ctrl.assert_not_called()
        folders.assert_not_called()


class TestTunnelEditDbGateLocation(unittest.TestCase):
    """`pam tunnel edit --keeper-db-proxy / --keeper-proxy` write the DB gate to portForward only."""

    def _run(self, pam_settings_value, **opts):
        from keepercommander.commands import tunnel_and_connections as tc
        record = vault.TypedRecord(version=3)
        record.record_uid = "recuid"
        record.type_name = "pamDatabase"
        record.fields.append(vault.TypedField.new_field("trafficEncryptionSeed", "seed", ""))
        record.custom.append(vault.TypedField.new_field("pamSettings", pam_settings_value, ""))
        dag = mock.MagicMock()
        dag.linking_dag.has_graph = True
        dag.check_tunneling_enabled_config.return_value = True
        dag.check_if_resource_has_launch_credential.return_value = True
        cmd = tc.PAMTunnelEditCommand()
        cfg = mock.MagicMock()
        cfg.record_uid = "cfguid"
        with mock.patch.object(tc.RecordMixin, "resolve_single_record", side_effect=[record, cfg]), \
                mock.patch.object(tc, "get_keeper_tokens", return_value=(b"a", b"b", b"c")), \
                mock.patch.object(tc, "get_config_uid", return_value="cfguid"), \
                mock.patch.object(tc, "TunnelDAG", return_value=dag), \
                mock.patch.object(tc, "update_pam_record", return_value=False) as upd, \
                mock.patch.object(tc, "reload_pam_record_if_nsf_updated", side_effect=lambda p, r, u, w: r), \
                mock.patch.object(tc, "sync_down_preserving_nsf_keys"), \
                mock.patch.object(tc, "get_resource_jit_settings", return_value={}), \
                mock.patch("builtins.print"):
            kwargs = dict(record="recuid", config="cfguid", silent=True)
            kwargs.update(opts)
            try:
                cmd.execute(mock.MagicMock(), **kwargs)
            except Exception:  # pylint: disable=broad-except
                raise
        return record.get_typed_field("pamSettings").value[0], upd

    def test_keeper_db_proxy_on_writes_port_forward_only(self):
        legacy = {"connection": {"protocol": "mysql", "allowKeeperDBProxy": False}, "portForward": {}}
        ps, upd = self._run(legacy, keeper_db_proxy="on")
        self.assertIs(ps["portForward"]["allowKeeperDBProxy"], True)
        self.assertIs(ps["connection"]["allowKeeperDBProxy"], False)  # legacy untouched
        upd.assert_called()

    def test_keeper_proxy_on_writes_port_forward_only(self):
        ps, _ = self._run({"connection": {"protocol": "postgresql"}, "portForward": {}}, keeper_proxy="on")
        self.assertIs(ps["portForward"]["allowKeeperDBProxy"], True)
        self.assertNotIn("allowKeeperDBProxy", ps["connection"])

    def test_keeper_proxy_default_removes_port_forward_key_only(self):
        ps, _ = self._run({"connection": {"protocol": "mysql", "allowKeeperDBProxy": True},
                           "portForward": {"allowKeeperDBProxy": True}}, keeper_proxy="default")
        self.assertNotIn("allowKeeperDBProxy", ps["portForward"])
        self.assertIs(ps["connection"]["allowKeeperDBProxy"], True)  # legacy untouched


if __name__ == "__main__":
    unittest.main()
