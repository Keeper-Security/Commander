"""
Unit tests for PAM Connection Edit `--ignore-server-cert` and `--security-mode` flags.

Covers argument parsing and the up-front validation that runs before any DAG /
record mutation: allowed record types (pamMachine, pamDatabase, pamDirectory),
allowed protocols per flag (rdp/kubernetes for cert, rdp-only for security mode),
and the record mutation itself (connection.ignoreCert / connection.security).
"""

import unittest
from unittest import mock

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.tunnel_and_connections import PAMConnectionEditCommand
    from keepercommander.error import CommandError
    from keepercommander import vault
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import tunnel_and_connections: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditSecurityArgs(unittest.TestCase):
    def setUp(self):
        self.parser = PAMConnectionEditCommand.parser

    def test_ignore_server_cert_on(self):
        args = self.parser.parse_args(['rec', '--ignore-server-cert', 'on'])
        self.assertEqual(args.ignore_server_cert, 'on')

    def test_ignore_server_cert_off(self):
        args = self.parser.parse_args(['rec', '--ignore-server-cert', 'off'])
        self.assertEqual(args.ignore_server_cert, 'off')

    def test_ignore_server_cert_default(self):
        args = self.parser.parse_args(['rec', '--ignore-server-cert', 'default'])
        self.assertEqual(args.ignore_server_cert, 'default')

    def test_ignore_server_cert_short_alias(self):
        args = self.parser.parse_args(['rec', '-isc', 'on'])
        self.assertEqual(args.ignore_server_cert, 'on')

    def test_ignore_server_cert_invalid_choice_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(['rec', '--ignore-server-cert', 'bogus'])

    def test_ignore_server_cert_not_provided(self):
        args = self.parser.parse_args(['rec'])
        self.assertIsNone(args.ignore_server_cert)

    def test_security_mode_choices(self):
        for mode in ('any', 'nla', 'tls', 'vmconnect', 'rdp', 'default'):
            with self.subTest(mode=mode):
                args = self.parser.parse_args(['rec', '--security-mode', mode])
                self.assertEqual(args.security_mode, mode)

    def test_security_mode_short_alias(self):
        args = self.parser.parse_args(['rec', '-sm', 'nla'])
        self.assertEqual(args.security_mode, 'nla')

    def test_security_mode_invalid_choice_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(['rec', '--security-mode', 'bogus'])

    def test_security_mode_not_provided(self):
        args = self.parser.parse_args(['rec'])
        self.assertIsNone(args.security_mode)

    def test_help_includes_new_flags(self):
        help_text = self.parser.format_help()
        self.assertIn('--ignore-server-cert', help_text)
        self.assertIn('-isc', help_text)
        self.assertIn('--security-mode', help_text)
        self.assertIn('-sm', help_text)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditSecurityValidation(unittest.TestCase):
    """Validation runs before DAG / token operations, so we can drive execute()
    with mocks that only need to satisfy resolve_single_record + the typed-field
    accessor for pamSettings."""

    def _mock_record(self, record_type, protocol):
        rec = mock.MagicMock(spec=vault.TypedRecord)
        rec.record_uid = 'rec-uid'
        rec.record_type = record_type
        rec.version = 3
        ps_field = mock.MagicMock()
        if protocol is None:
            ps_field.value = []
        else:
            ps_field.value = [{'connection': {'protocol': protocol}}]
        rec.get_typed_field.side_effect = lambda name: ps_field if name == 'pamSettings' else None
        return rec

    def _execute(self, record, **kwargs):
        cmd = PAMConnectionEditCommand()
        params = mock.MagicMock()
        with mock.patch(
            'keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record',
            return_value=record,
        ):
            cmd.execute(params, record='rec', **kwargs)

    # --ignore-server-cert: record-type gating

    def test_ignore_server_cert_pam_remote_browser_rejected(self):
        rec = self._mock_record('pamRemoteBrowser', 'http')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, ignore_server_cert='on')
        msg = str(ctx.exception)
        self.assertIn('--ignore-server-cert is only supported for pamMachine, pamDatabase, and pamDirectory', msg)
        self.assertIn('pam rbi edit', msg)

    def test_ignore_server_cert_pam_network_configuration_rejected(self):
        rec = self._mock_record('pamNetworkConfiguration', None)
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, ignore_server_cert='on')
        self.assertIn('--ignore-server-cert is only supported for pamMachine, pamDatabase, and pamDirectory',
                      str(ctx.exception))

    # --ignore-server-cert: protocol gating

    def test_ignore_server_cert_ssh_rejected(self):
        rec = self._mock_record('pamMachine', 'ssh')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, ignore_server_cert='on')
        msg = str(ctx.exception)
        self.assertIn('not supported for protocol "ssh"', msg)
        self.assertIn('kubernetes, rdp', msg)

    def test_ignore_server_cert_no_protocol_rejected(self):
        rec = self._mock_record('pamMachine', None)
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, ignore_server_cert='on')
        self.assertIn('not supported for protocol "(unset)"', str(ctx.exception))

    def test_ignore_server_cert_rdp_accepted(self):
        rec = self._mock_record('pamMachine', 'rdp')
        try:
            self._execute(rec, ignore_server_cert='on')
        except CommandError as e:
            self.assertNotIn('--ignore-server-cert is', str(e))
        except Exception:
            pass  # downstream failures not under test

    def test_ignore_server_cert_kubernetes_accepted(self):
        rec = self._mock_record('pamDirectory', 'kubernetes')
        try:
            self._execute(rec, ignore_server_cert='on')
        except CommandError as e:
            self.assertNotIn('--ignore-server-cert is', str(e))
        except Exception:
            pass  # downstream failures not under test

    # --security-mode: record-type gating

    def test_security_mode_pam_remote_browser_rejected(self):
        rec = self._mock_record('pamRemoteBrowser', 'http')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, security_mode='nla')
        self.assertIn('--security-mode is only supported for pamMachine, pamDatabase, and pamDirectory',
                      str(ctx.exception))

    # --security-mode: protocol gating

    def test_security_mode_kubernetes_rejected(self):
        rec = self._mock_record('pamMachine', 'kubernetes')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, security_mode='nla')
        msg = str(ctx.exception)
        self.assertIn('not supported for protocol "kubernetes"', msg)

    def test_security_mode_no_protocol_rejected(self):
        rec = self._mock_record('pamMachine', None)
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, security_mode='nla')
        self.assertIn('not supported for protocol "(unset)"', str(ctx.exception))

    def test_security_mode_rdp_accepted(self):
        rec = self._mock_record('pamMachine', 'rdp')
        try:
            self._execute(rec, security_mode='nla')
        except CommandError as e:
            self.assertNotIn('--security-mode is', str(e))
        except Exception:
            pass  # downstream failures not under test

    def test_protocol_change_in_same_command_validated_against_new(self):
        """When --connections=on and --protocol=ssh are passed alongside --security-mode,
        validation uses the new (post-mutation) protocol -> ssh -> reject."""
        rec = self._mock_record('pamMachine', 'rdp')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, security_mode='nla', connections='on', protocol='ssh')
        self.assertIn('not supported for protocol "ssh"', str(ctx.exception))


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditSecurityMutation(unittest.TestCase):
    """Verifies the actual JSON keys written to pamSettings.connection."""

    def _mock_record(self, record_type='pamMachine', protocol='rdp', existing_connection=None):
        rec = mock.MagicMock(spec=vault.TypedRecord)
        rec.record_uid = 'rec-uid'
        rec.record_type = record_type
        rec.version = 3
        rec.fields = []
        rec.custom = []
        connection = {'protocol': protocol}
        if existing_connection:
            connection.update(existing_connection)
        pam_settings_value = [{'connection': connection, 'portForward': {}}]
        ps_field = mock.MagicMock()
        ps_field.value = pam_settings_value
        rec.get_typed_field.side_effect = lambda name: ps_field if name == 'pamSettings' else (
            mock.MagicMock(value=['seed']) if name == 'trafficEncryptionSeed' else None
        )
        return rec, ps_field

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_ignore_server_cert_on_writes_true(self, mock_tdag, mock_get_config_uid,
                                                mock_tokens, mock_sync, mock_update, mock_resolve):
        rec, ps_field = self._mock_record(protocol='rdp')
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', ignore_server_cert='on')
        self.assertEqual(ps_field.value[0]['connection'].get('ignoreCert'), True)
        mock_update.assert_called_once()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_ignore_server_cert_off_writes_false(self, mock_tdag, mock_get_config_uid,
                                                  mock_tokens, mock_sync, mock_update, mock_resolve):
        rec, ps_field = self._mock_record(protocol='kubernetes', existing_connection={'ignoreCert': True})
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', ignore_server_cert='off')
        self.assertEqual(ps_field.value[0]['connection'].get('ignoreCert'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_ignore_server_cert_default_removes_key(self, mock_tdag, mock_get_config_uid,
                                                     mock_tokens, mock_sync, mock_update, mock_resolve):
        rec, ps_field = self._mock_record(protocol='rdp', existing_connection={'ignoreCert': True})
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', ignore_server_cert='default')
        self.assertNotIn('ignoreCert', ps_field.value[0]['connection'])

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_security_mode_writes_lowercase_value(self, mock_tdag, mock_get_config_uid,
                                                   mock_tokens, mock_sync, mock_update, mock_resolve):
        rec, ps_field = self._mock_record(protocol='rdp')
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', security_mode='NLA'.lower())
        self.assertEqual(ps_field.value[0]['connection'].get('security'), 'nla')

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_security_mode_default_removes_key(self, mock_tdag, mock_get_config_uid,
                                                mock_tokens, mock_sync, mock_update, mock_resolve):
        rec, ps_field = self._mock_record(protocol='rdp', existing_connection={'security': 'tls'})
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', security_mode='default')
        self.assertNotIn('security', ps_field.value[0]['connection'])

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    def test_no_change_does_not_mark_dirty(self, mock_get_config_uid,
                                            mock_tokens, mock_sync, mock_update, mock_resolve):
        """Setting a value that already matches the current one should not trigger update_record.

        TunnelDAG is deliberately left unmocked here (unlike the other tests in this file):
        mocking the whole class also mocks its `_convert_allowed_setting` staticmethod, turning
        `_connections`/`_recording`/`_typescript_recording` into truthy MagicMocks regardless of
        input and forcing a spurious dirty=True. Since neither flag under test touches the DAG
        path, the real staticmethod (called unconditionally near the top of execute()) is safe
        to leave in place.
        """
        rec, ps_field = self._mock_record(protocol='rdp', existing_connection={'ignoreCert': True, 'security': 'nla'})
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', ignore_server_cert='on', security_mode='nla')
        mock_update.assert_not_called()


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditSecurityEarlyReturn(unittest.TestCase):
    """--ignore-server-cert / --security-mode are record-only edits; passing them alone
    should not touch the DAG/config lookup, mirroring the --scrollback early-return."""

    def _mock_record(self, record_type='pamMachine', protocol='rdp'):
        rec = mock.MagicMock(spec=vault.TypedRecord)
        rec.record_uid = 'rec-uid'
        rec.record_type = record_type
        rec.version = 3
        rec.fields = []
        rec.custom = []
        ps_field = mock.MagicMock()
        ps_field.value = [{'connection': {'protocol': protocol}}]
        rec.get_typed_field.side_effect = lambda name: ps_field if name == 'pamSettings' else (
            mock.MagicMock(value=['seed']) if name == 'trafficEncryptionSeed' else None
        )
        return rec

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_ignore_server_cert_alone_skips_dag(self, mock_tdag, mock_get_config_uid,
                                                 mock_tokens, mock_sync, mock_update, mock_resolve):
        rec = self._mock_record()
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', ignore_server_cert='on')
        mock_get_config_uid.assert_not_called()
        mock_tdag.assert_not_called()
        mock_update.assert_called_once()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_security_mode_alone_skips_dag(self, mock_tdag, mock_get_config_uid,
                                            mock_tokens, mock_sync, mock_update, mock_resolve):
        rec = self._mock_record()
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', security_mode='tls')
        mock_get_config_uid.assert_not_called()
        mock_tdag.assert_not_called()
        mock_update.assert_called_once()


if __name__ == '__main__':
    unittest.main()
