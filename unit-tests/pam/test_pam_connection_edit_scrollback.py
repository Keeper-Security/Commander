"""
Unit tests for PAM Connection Edit `--scrollback` flag.

Covers argument parsing and the up-front validation that runs before any DAG /
record mutation: allowed record types (pamDatabase, pamMachine, pamDirectory),
allowed protocols per type, and value parsing (int / empty string / invalid).
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
class TestPamConnectionEditScrollbackArgs(unittest.TestCase):
    def setUp(self):
        self.parser = PAMConnectionEditCommand.parser

    def test_scrollback_int(self):
        args = self.parser.parse_args(['rec', '--scrollback', '1234'])
        self.assertEqual(args.scrollback, '1234')

    def test_scrollback_empty_string(self):
        args = self.parser.parse_args(['rec', '--scrollback', ''])
        self.assertEqual(args.scrollback, '')

    def test_scrollback_short_alias(self):
        args = self.parser.parse_args(['rec', '-sb', '5000'])
        self.assertEqual(args.scrollback, '5000')

    def test_scrollback_not_provided(self):
        args = self.parser.parse_args(['rec'])
        self.assertIsNone(args.scrollback)

    def test_help_includes_scrollback(self):
        help_text = self.parser.format_help()
        self.assertIn('--scrollback', help_text)
        self.assertIn('-sb', help_text)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditProtocolChoices(unittest.TestCase):
    """--protocol choices: the full DB protocol set is now accepted, and the choices
    list is composed from the db_protocols / non_db_protocols source-of-truth lists."""

    NEW_DB_PROTOCOLS = ['mariadb', 'oracle', 'mongodb', 'redis',
                        'elasticsearch', 'clickhouse', 'dynamodb']

    def setUp(self):
        self.parser = PAMConnectionEditCommand.parser

    def test_new_db_protocols_accepted(self):
        for proto in self.NEW_DB_PROTOCOLS:
            with self.subTest(protocol=proto):
                args = self.parser.parse_args(['rec', '--protocol', proto])
                self.assertEqual(args.protocol, proto)

    def test_mariadb_and_oracle_accepted(self):
        # The two protocols this change was specifically about.
        self.assertEqual(self.parser.parse_args(['rec', '-p', 'mariadb']).protocol, 'mariadb')
        self.assertEqual(self.parser.parse_args(['rec', '-p', 'oracle']).protocol, 'oracle')

    def test_existing_protocols_still_accepted(self):
        for proto in ['', 'http', 'kubernetes', 'mysql', 'postgresql', 'rdp', 'sql-server', 'ssh', 'telnet', 'vnc']:
            with self.subTest(protocol=proto):
                self.assertEqual(self.parser.parse_args(['rec', '--protocol', proto]).protocol, proto)

    def test_invalid_protocol_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(['rec', '--protocol', 'bogus'])

    def test_choices_composed_from_source_lists(self):
        # protocols is the single source of truth: '' + sorted(non_db + db), no duplicates.
        expected = [''] + sorted(PAMConnectionEditCommand.non_db_protocols
                                  + PAMConnectionEditCommand.db_protocols)
        self.assertEqual(PAMConnectionEditCommand.protocols, expected)
        self.assertEqual(len(PAMConnectionEditCommand.protocols),
                         len(set(PAMConnectionEditCommand.protocols)))

    def test_all_db_protocols_present_in_choices(self):
        for proto in PAMConnectionEditCommand.db_protocols:
            self.assertIn(proto, PAMConnectionEditCommand.protocols)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditScrollbackValidation(unittest.TestCase):
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

    def test_pam_remote_browser_rejected(self):
        rec = self._mock_record('pamRemoteBrowser', 'http')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100')
        self.assertIn('--scrollback is only supported for pamDatabase, pamMachine, and pamDirectory',
                      str(ctx.exception))

    def test_pam_user_rejected(self):
        rec = self._mock_record('pamUser', None)
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100')
        # pamUser fails the outer record-type check before scrollback validation runs
        self.assertIn("type is not supported for connections", str(ctx.exception))

    def test_pam_network_configuration_rejected(self):
        rec = self._mock_record('pamNetworkConfiguration', None)
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100')
        self.assertIn('--scrollback is only supported for pamDatabase, pamMachine, and pamDirectory',
                      str(ctx.exception))

    def test_pam_machine_rdp_rejected(self):
        rec = self._mock_record('pamMachine', 'rdp')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100')
        msg = str(ctx.exception)
        self.assertIn('not supported for protocol "rdp"', msg)
        self.assertIn('pamMachine', msg)

    def test_pam_machine_vnc_rejected(self):
        rec = self._mock_record('pamMachine', 'vnc')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100')
        self.assertIn('not supported for protocol "vnc"', str(ctx.exception))

    def test_pam_machine_no_protocol_rejected(self):
        rec = self._mock_record('pamMachine', None)
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100')
        self.assertIn('not supported for protocol "(unset)"', str(ctx.exception))

    def test_pam_directory_http_rejected(self):
        rec = self._mock_record('pamDirectory', 'http')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100')
        self.assertIn('not supported for protocol "http"', str(ctx.exception))

    def test_non_numeric_rejected(self):
        rec = self._mock_record('pamMachine', 'ssh')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='not-a-number')
        self.assertIn('--scrollback must be a non-negative integer', str(ctx.exception))

    def test_float_rejected(self):
        rec = self._mock_record('pamMachine', 'ssh')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='1.5')
        self.assertIn('--scrollback must be a non-negative integer', str(ctx.exception))

    def test_negative_integer_rejected(self):
        rec = self._mock_record('pamMachine', 'ssh')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='-100')
        self.assertIn('--scrollback must be a non-negative integer', str(ctx.exception))

    def test_negative_one_rejected(self):
        rec = self._mock_record('pamMachine', 'ssh')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='-1')
        self.assertIn('--scrollback must be a non-negative integer', str(ctx.exception))

    def test_zero_accepted(self):
        """Zero is a non-negative integer and should pass validation."""
        rec = self._mock_record('pamMachine', 'ssh')
        try:
            self._execute(rec, scrollback='0')
        except CommandError as e:
            self.assertNotIn('--scrollback must be', str(e))
        except Exception:
            pass  # downstream DAG failure expected; only validation is under test

    def test_protocol_change_in_same_command_validated_against_new(self):
        """When --connections=on and --protocol=rdp are passed alongside --scrollback,
        validation uses the new (post-mutation) protocol — rdp -> reject."""
        rec = self._mock_record('pamMachine', 'ssh')
        with self.assertRaises(CommandError) as ctx:
            self._execute(rec, scrollback='100', connections='on', protocol='rdp')
        self.assertIn('not supported for protocol "rdp"', str(ctx.exception))

    def test_protocol_change_without_connections_uses_existing(self):
        """--protocol is only honored alongside --connections=on; without it,
        validation uses the existing record protocol."""
        rec = self._mock_record('pamMachine', 'ssh')
        # Without --connections=on, the bogus --protocol is ignored, existing
        # 'ssh' wins. Validation should not raise (it gets past the protocol
        # check); we expect it to proceed to the DAG layer and fail there.
        # We just assert the error is NOT the scrollback-protocol error.
        with self.assertRaises(Exception) as ctx:
            self._execute(rec, scrollback='100', protocol='rdp')
        self.assertNotIn('not supported for protocol', str(ctx.exception))


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditScrollbackAllowedCombinations(unittest.TestCase):
    """For each allowed (record_type, protocol) pair, validation must not raise
    a scrollback-related error. We don't run the full execute path (which would
    require mocking the entire DAG layer), only verify validation passes."""

    DB_PROTOCOLS = ['mysql', 'postgresql', 'sql-server', 'mariadb', 'oracle',
                    'mongodb', 'redis', 'elasticsearch', 'clickhouse', 'dynamodb']
    TERMINAL_PROTOCOLS = ['ssh', 'telnet', 'kubernetes']

    def _assert_validation_passes(self, record_type, protocol):
        rec = mock.MagicMock(spec=vault.TypedRecord)
        rec.record_uid = 'rec-uid'
        rec.record_type = record_type
        rec.version = 3
        ps_field = mock.MagicMock()
        ps_field.value = [{'connection': {'protocol': protocol}}]
        rec.get_typed_field.side_effect = lambda name: ps_field if name == 'pamSettings' else None

        cmd = PAMConnectionEditCommand()
        params = mock.MagicMock()
        with mock.patch(
            'keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record',
            return_value=rec,
        ):
            try:
                cmd.execute(params, record='rec', scrollback='100')
            except CommandError as e:
                self.assertNotIn('--scrollback is only supported', str(e))
                self.assertNotIn('--scrollback is not supported for protocol', str(e))
                self.assertNotIn('--scrollback must be an integer', str(e))
            except Exception:
                pass  # downstream DAG/token failures are not what we're testing

    def test_pam_database_all_db_protocols(self):
        for proto in self.DB_PROTOCOLS:
            with self.subTest(protocol=proto):
                self._assert_validation_passes('pamDatabase', proto)

    def test_pam_machine_terminal_protocols(self):
        for proto in self.TERMINAL_PROTOCOLS:
            with self.subTest(protocol=proto):
                self._assert_validation_passes('pamMachine', proto)

    def test_pam_directory_terminal_protocols(self):
        for proto in self.TERMINAL_PROTOCOLS:
            with self.subTest(protocol=proto):
                self._assert_validation_passes('pamDirectory', proto)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamConnectionEditScrollbackEarlyReturn(unittest.TestCase):
    """When only record-level args (scrollback, key-events, protocol alone) are passed,
    the command should return after the record update without touching the DAG. Locks in
    the fix for the misleading 'No PAM Configuration UID set' error when --scrollback is
    used on a resource that isn't linked to a config."""

    def _mock_record(self, record_type='pamMachine', protocol='ssh'):
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
    def test_scrollback_alone_skips_dag(self, mock_tdag, mock_get_config_uid,
                                         mock_tokens, mock_sync, mock_update, mock_resolve):
        """Running with only --scrollback should NOT invoke get_config_uid or TunnelDAG."""
        rec = self._mock_record()
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', scrollback='1234')
        mock_get_config_uid.assert_not_called()
        mock_tdag.assert_not_called()
        # The record update IS expected to run (scrollback was written)
        mock_update.assert_called_once()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    def test_key_events_alone_skips_dag(self, mock_tdag, mock_get_config_uid,
                                         mock_tokens, mock_sync, mock_update, mock_resolve):
        """Same early-return applies to --key-events alone."""
        rec = self._mock_record()
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='rec', key_events='on')
        mock_get_config_uid.assert_not_called()
        mock_tdag.assert_not_called()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid',
                return_value=None)
    def test_scrollback_with_connections_still_runs_dag(self, mock_get_config_uid,
                                                        mock_tokens, mock_sync, mock_update, mock_resolve):
        """When --connections is passed alongside --scrollback, the DAG block must still run
        (and is expected to surface its own errors). We just verify get_config_uid is reached."""
        rec = self._mock_record()
        mock_resolve.return_value = rec
        cmd = PAMConnectionEditCommand()
        try:
            cmd.execute(mock.MagicMock(), record='rec', scrollback='1234', connections='on')
        except Exception:
            pass  # downstream TunnelDAG instantiation will fail; not under test here
        mock_get_config_uid.assert_called_once()


if __name__ == '__main__':
    unittest.main()
