"""
Unit tests for PAM RBI Edit `--url` and PAM Connection Edit `--allow-copy`, `--allow-paste`, and `--sftp` flags.
"""

import unittest
from unittest import mock

from keepercommander import vault
from keepercommander.commands.tunnel_and_connections import PAMConnectionEditCommand, PAMRbiEditCommand
from keepercommander.error import CommandError


def mock_sync_decorator(cls):
    original_setup = cls.setUp if hasattr(cls, 'setUp') else None
    original_teardown = cls.tearDown if hasattr(cls, 'tearDown') else None

    def new_setup(self):
        if original_setup:
            original_setup(self)
        self.sync_patcher = mock.patch('keepercommander.commands.tunnel_and_connections.sync_down_preserving_nsf_keys')
        self.sync_patcher.start()
        self.load_patcher = mock.patch('keepercommander.commands.pam_import.record_loader.load_pam_record')
        self.load_patcher.start()

    def new_teardown(self):
        self.sync_patcher.stop()
        self.load_patcher.stop()
        if original_teardown:
            original_teardown(self)

    cls.setUp = new_setup
    cls.tearDown = new_teardown
    return cls


@mock_sync_decorator
class TestPamRbiEditUrlFlag(unittest.TestCase):
    def _mock_rbi_record(self, existing_url='https://old.example.com'):
        rec = mock.MagicMock(spec=vault.TypedRecord)
        rec.record_uid = 'rbi-uid-1'
        rec.record_type = 'pamRemoteBrowser'
        rec.version = 3
        rec.fields = []
        rec.custom = []

        seed_field = mock.MagicMock(spec=vault.TypedField)
        seed_field.value = ['seed-123']

        rbs_field = mock.MagicMock(spec=vault.TypedField)
        rbs_field.value = [{'connection': {'protocol': 'http', 'httpCredentialsUid': ''}}]

        url_field = None
        if existing_url is not None:
            url_field = mock.MagicMock(spec=vault.TypedField)
            url_field.value = [existing_url] if existing_url else []

        def _get_field(name):
            if name == 'trafficEncryptionSeed':
                return seed_field
            if name == 'pamRemoteBrowserSettings':
                return rbs_field
            if name == 'rbiUrl':
                return url_field
            return None

        rec.get_typed_field.side_effect = _get_field
        return rec, url_field

    def test_parser_accepts_url_flag(self):
        parser = PAMRbiEditCommand.parser
        args = parser.parse_args(['-r', 'rbi-uid-1', '--url', 'https://portal.example.com'])
        self.assertEqual(args.url, 'https://portal.example.com')

        args_short = parser.parse_args(['-r', 'rbi-uid-1', '-u', 'https://short.example.com'])
        self.assertEqual(args_short.url, 'https://short.example.com')

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.update_pam_record', return_value=False)
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    def test_rbi_edit_url_updates_existing_field_and_skips_dag(self, mock_get_cfg, mock_update, mock_resolve):
        rec, url_field = self._mock_rbi_record('https://old.example.com')
        mock_resolve.return_value = rec

        PAMRbiEditCommand().execute(mock.MagicMock(), record='rbi-uid-1', url='https://new.example.com')

        self.assertEqual(url_field.value, ['https://new.example.com'])
        mock_update.assert_called_once()
        mock_get_cfg.assert_not_called()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.update_pam_record', return_value=False)
    def test_rbi_edit_url_creates_field_when_missing(self, mock_update, mock_resolve):
        rec, _ = self._mock_rbi_record(existing_url=None)
        mock_resolve.return_value = rec

        PAMRbiEditCommand().execute(mock.MagicMock(), record='rbi-uid-1', url='https://created.example.com')

        self.assertEqual(len(rec.fields), 1)
        self.assertEqual(rec.fields[0].type, 'rbiUrl')
        self.assertEqual(rec.fields[0].value, ['https://created.example.com'])
        mock_update.assert_called_once()


@mock_sync_decorator
class TestPamConnectionEditClipboardAndSftpFlags(unittest.TestCase):
    def _mock_machine_record(self, protocol='ssh', existing_connection=None):
        rec = mock.MagicMock(spec=vault.TypedRecord)
        rec.record_uid = 'mach-uid-1'
        rec.record_type = 'pamMachine'
        rec.version = 3
        rec.fields = []
        rec.custom = []

        seed_field = mock.MagicMock(spec=vault.TypedField)
        seed_field.value = ['seed-123']

        conn = {'protocol': protocol} if protocol else {}
        if existing_connection:
            conn.update(existing_connection)

        ps_field = mock.MagicMock(spec=vault.TypedField)
        ps_field.value = [{'connection': conn, 'portForward': {}}]

        def _get_field(name):
            if name == 'trafficEncryptionSeed':
                return seed_field
            if name == 'pamSettings':
                return ps_field
            return None

        rec.get_typed_field.side_effect = _get_field
        return rec, ps_field

    def test_parser_accepts_clipboard_and_sftp_flags(self):
        parser = PAMConnectionEditCommand.parser
        args = parser.parse_args([
            'mach-uid-1',
            '--allow-copy', 'off',
            '--allow-paste', 'on',
            '--sftp', 'on',
        ])
        self.assertEqual(args.allow_copy, 'off')
        self.assertEqual(args.allow_paste, 'on')
        self.assertEqual(args.sftp, 'on')

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.update_pam_record', return_value=False)
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens', return_value=(b'st', b'tk', b'tr'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_config_uid')
    def test_allow_copy_paste_and_sftp_apply_and_clear(self, mock_get_cfg, _mock_tokens, mock_update, mock_resolve):
        rec, ps_field = self._mock_machine_record(protocol='ssh')
        mock_resolve.return_value = rec

        cmd = PAMConnectionEditCommand()
        cmd.execute(mock.MagicMock(), record='mach-uid-1', allow_copy='off', allow_paste='on', sftp='on')

        conn = ps_field.value[0]['connection']
        self.assertEqual(conn.get('disableCopy'), True)
        self.assertEqual(conn.get('disablePaste'), False)
        self.assertEqual(conn.get('sftp'), {'enableSftp': True})
        mock_update.assert_called_once()
        mock_get_cfg.assert_not_called()

        # Reset to default removes keys cleanly
        cmd.execute(mock.MagicMock(), record='mach-uid-1', allow_copy='default', allow_paste='default', sftp='default')
        self.assertNotIn('disableCopy', conn)
        self.assertNotIn('disablePaste', conn)
        self.assertNotIn('sftp', conn)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    def test_sftp_rejects_unsupported_protocol(self, mock_resolve):
        rec, _ = self._mock_machine_record(protocol='telnet')
        mock_resolve.return_value = rec

        with self.assertRaises(CommandError) as ctx:
            PAMConnectionEditCommand().execute(mock.MagicMock(), record='mach-uid-1', sftp='on')
        self.assertIn('--sftp is not supported for protocol "telnet"', str(ctx.exception))

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    def test_allow_copy_rejects_kubernetes_protocol(self, mock_resolve):
        rec, _ = self._mock_machine_record(protocol='kubernetes')
        mock_resolve.return_value = rec

        with self.assertRaises(CommandError) as ctx:
            PAMConnectionEditCommand().execute(mock.MagicMock(), record='mach-uid-1', allow_copy='on')
        self.assertIn('--allow-copy is not supported for protocol "kubernetes"', str(ctx.exception))
