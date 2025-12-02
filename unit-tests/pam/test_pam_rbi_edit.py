"""
Unit tests for PAM RBI Edit command - KC-1034 Feature Parity

Tests the new CLI arguments added to expose RBI settings:
- Browser Settings: --allow-url-navigation, --ignore-server-cert (on/off/default)
- URL Filtering: --allowed-urls, --allowed-resource-urls (multi-value)
- Autofill: --autofill-targets (multi-value)
- Clipboard: --allow-copy, --allow-paste (on/off/default)
- Audio: --disable-audio (on/off/default), --audio-channels, --audio-bit-depth, --audio-sample-rate

Note: Tests require Python 3.8+ due to pydantic dependency in tunnel_and_connections imports.
"""

import sys
import unittest
from unittest import mock

# Try to import the module - skip tests if it fails (Python < 3.8 or missing pydantic)
skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.tunnel_and_connections import PAMRbiEditCommand
    from keepercommander.error import CommandError
    from keepercommander import vault
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import tunnel_and_connections: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestPamRbiEditArguments(unittest.TestCase):
    """Tests for PAMRbiEditCommand argument parsing."""

    def setUp(self):
        """Set up parser for testing."""
        self.parser = PAMRbiEditCommand.parser

    def test_allow_url_navigation_on(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'on'])
        self.assertEqual(args.allow_url_navigation, 'on')

    def test_allow_url_navigation_off(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'off'])
        self.assertEqual(args.allow_url_navigation, 'off')

    def test_allow_url_navigation_default(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'default'])
        self.assertEqual(args.allow_url_navigation, 'default')

    def test_allow_url_navigation_invalid(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'invalid'])

    def test_allow_url_navigation_not_provided(self):
        args = self.parser.parse_args(['--record', 'test-record', '--key-events', 'on'])
        self.assertIsNone(args.allow_url_navigation)

    def test_ignore_server_cert_on(self):
        args = self.parser.parse_args(['--record', 'test-record', '--ignore-server-cert', 'on'])
        self.assertEqual(args.ignore_server_cert, 'on')

    def test_ignore_server_cert_off(self):
        args = self.parser.parse_args(['--record', 'test-record', '--ignore-server-cert', 'off'])
        self.assertEqual(args.ignore_server_cert, 'off')

    def test_ignore_server_cert_default(self):
        args = self.parser.parse_args(['--record', 'test-record', '--ignore-server-cert', 'default'])
        self.assertEqual(args.ignore_server_cert, 'default')

    def test_allowed_urls_single(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allowed-urls', '*.example.com'])
        self.assertEqual(args.allowed_urls, ['*.example.com'])

    def test_allowed_urls_multiple(self):
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--allowed-urls', '*.example.com',
            '--allowed-urls', '*.test.com',
            '--allowed-urls', '*.dev.com'
        ])
        self.assertEqual(args.allowed_urls, ['*.example.com', '*.test.com', '*.dev.com'])

    def test_allowed_urls_not_provided(self):
        args = self.parser.parse_args(['--record', 'test-record', '--key-events', 'on'])
        self.assertIsNone(args.allowed_urls)

    def test_allowed_resource_urls_single(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allowed-resource-urls', '*.cdn.example.com'])
        self.assertEqual(args.allowed_resource_urls, ['*.cdn.example.com'])

    def test_allowed_resource_urls_multiple(self):
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--allowed-resource-urls', '*.cdn.example.com',
            '--allowed-resource-urls', '*.static.test.com'
        ])
        self.assertEqual(args.allowed_resource_urls, ['*.cdn.example.com', '*.static.test.com'])

    def test_autofill_targets_single(self):
        args = self.parser.parse_args(['--record', 'test-record', '--autofill-targets', '#username'])
        self.assertEqual(args.autofill_targets, ['#username'])

    def test_autofill_targets_multiple(self):
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--autofill-targets', '#username',
            '--autofill-targets', '#password',
            '--autofill-targets', 'input[name=email]'
        ])
        self.assertEqual(args.autofill_targets, ['#username', '#password', 'input[name=email]'])

    def test_allow_copy_on(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-copy', 'on'])
        self.assertEqual(args.allow_copy, 'on')

    def test_allow_copy_off(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-copy', 'off'])
        self.assertEqual(args.allow_copy, 'off')

    def test_allow_copy_default(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-copy', 'default'])
        self.assertEqual(args.allow_copy, 'default')

    def test_allow_paste_on(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-paste', 'on'])
        self.assertEqual(args.allow_paste, 'on')

    def test_allow_paste_off(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-paste', 'off'])
        self.assertEqual(args.allow_paste, 'off')

    def test_allow_paste_default(self):
        args = self.parser.parse_args(['--record', 'test-record', '--allow-paste', 'default'])
        self.assertEqual(args.allow_paste, 'default')

    def test_combine_multiple_new_args(self):
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--allow-url-navigation', 'on',
            '--ignore-server-cert', 'off',
            '--allowed-urls', '*.example.com',
            '--allow-copy', 'on',
            '--allow-paste', 'off'
        ])
        self.assertEqual(args.allow_url_navigation, 'on')
        self.assertEqual(args.ignore_server_cert, 'off')
        self.assertEqual(args.allowed_urls, ['*.example.com'])
        self.assertEqual(args.allow_copy, 'on')
        self.assertEqual(args.allow_paste, 'off')

    def test_combine_new_args_with_existing(self):
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--key-events', 'on',
            '--allow-url-navigation', 'on',
            '--allowed-urls', '*.example.com'
        ])
        self.assertEqual(args.key_events, 'on')
        self.assertEqual(args.allow_url_navigation, 'on')
        self.assertEqual(args.allowed_urls, ['*.example.com'])


@unittest.skipIf(skip_tests, skip_reason)
class TestPamRbiEditExecute(unittest.TestCase):
    """Tests for PAMRbiEditCommand.execute() method."""

    def setUp(self):
        self.command = PAMRbiEditCommand()
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'
        self.pam_settings = {'connection': {'protocol': 'http', 'httpCredentialsUid': ''}}
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field
        self.mock_params = mock.MagicMock()
        self.mock_params.record_cache = {'test-record-uid': self.mock_record}

    def test_no_param_raises_error_with_new_settings_check(self):
        with self.assertRaises(CommandError) as context:
            self.command.execute(self.mock_params, record='test-record')
        self.assertIn('At least one parameter is required', str(context.exception))

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_url_navigation_on_sets_true(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='on')
        self.assertEqual(self.pam_settings['connection'].get('allowUrlManipulation'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_url_navigation_off_sets_false(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='off')
        self.assertEqual(self.pam_settings['connection'].get('allowUrlManipulation'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_url_navigation_default_removes_field(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.pam_settings['connection']['allowUrlManipulation'] = True
        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='default')
        self.assertNotIn('allowUrlManipulation', self.pam_settings['connection'])

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_ignore_server_cert_on_sets_true(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', ignore_server_cert='on')
        self.assertEqual(self.pam_settings['connection'].get('ignoreInitialSslCert'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allowed_urls_joins_with_newlines(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allowed_urls=['*.example.com', '*.test.com'])
        self.assertEqual(self.pam_settings['connection'].get('allowedUrlPatterns'), '*.example.com\n*.test.com')

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allowed_resource_urls_joins_with_newlines(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allowed_resource_urls=['*.cdn.example.com'])
        self.assertEqual(self.pam_settings['connection'].get('allowedResourceUrlPatterns'), '*.cdn.example.com')

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_autofill_targets_joins_with_newlines(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', autofill_targets=['#username', '#password'])
        self.assertEqual(self.pam_settings['connection'].get('autofillConfiguration'), '#username\n#password')


@unittest.skipIf(skip_tests, skip_reason)
class TestPamRbiEditClipboardInversion(unittest.TestCase):
    """Tests for clipboard inversion logic."""

    def setUp(self):
        self.command = PAMRbiEditCommand()
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'
        self.pam_settings = {'connection': {'protocol': 'http', 'httpCredentialsUid': ''}}
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field
        self.mock_params = mock.MagicMock()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_copy_on_sets_disable_copy_false(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_copy='on')
        self.assertEqual(self.pam_settings['connection'].get('disableCopy'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_copy_off_sets_disable_copy_true(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_copy='off')
        self.assertEqual(self.pam_settings['connection'].get('disableCopy'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_copy_default_removes_field(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.pam_settings['connection']['disableCopy'] = True
        self.command.execute(self.mock_params, record='test-record', allow_copy='default')
        self.assertNotIn('disableCopy', self.pam_settings['connection'])

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_paste_on_sets_disable_paste_false(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_paste='on')
        self.assertEqual(self.pam_settings['connection'].get('disablePaste'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_paste_off_sets_disable_paste_true(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_paste='off')
        self.assertEqual(self.pam_settings['connection'].get('disablePaste'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_clipboard_both_on(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_copy='on', allow_paste='on')
        self.assertEqual(self.pam_settings['connection'].get('disableCopy'), False)
        self.assertEqual(self.pam_settings['connection'].get('disablePaste'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_clipboard_both_off(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_copy='off', allow_paste='off')
        self.assertEqual(self.pam_settings['connection'].get('disableCopy'), True)
        self.assertEqual(self.pam_settings['connection'].get('disablePaste'), True)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamRbiEditRecordUpdate(unittest.TestCase):
    """Tests for record update behavior."""

    def setUp(self):
        self.command = PAMRbiEditCommand()
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'
        self.pam_settings = {'connection': {'protocol': 'http', 'httpCredentialsUid': ''}}
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field
        self.mock_params = mock.MagicMock()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_record_update_called_when_field_changes(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='on')
        mock_update.assert_called_once()
        mock_sync.assert_called_once()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_multiple_fields_single_update(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='on',
                           ignore_server_cert='off', allow_copy='on', allowed_urls=['*.example.com'])
        mock_update.assert_called_once()


@unittest.skipIf(skip_tests, skip_reason)
class TestPamRbiEditHelp(unittest.TestCase):
    """Test that help text is correct for new arguments."""

    def test_help_includes_new_arguments(self):
        help_text = PAMRbiEditCommand.parser.format_help()
        self.assertIn('--allow-url-navigation', help_text)
        self.assertIn('--ignore-server-cert', help_text)
        self.assertIn('--allowed-urls', help_text)
        self.assertIn('--allowed-resource-urls', help_text)
        self.assertIn('--autofill-targets', help_text)
        self.assertIn('--allow-copy', help_text)
        self.assertIn('--allow-paste', help_text)
        self.assertIn('--disable-audio', help_text)
        self.assertIn('--audio-channels', help_text)
        self.assertIn('--audio-bit-depth', help_text)
        self.assertIn('--audio-sample-rate', help_text)

    def test_help_shows_choices(self):
        help_text = PAMRbiEditCommand.parser.format_help()
        self.assertIn('on/off/default', help_text.lower().replace('{', '').replace('}', '').replace(',', '/'))


@unittest.skipIf(skip_tests, skip_reason)
class TestPamRbiEditAliases(unittest.TestCase):
    """Tests for short alias arguments."""

    def setUp(self):
        self.parser = PAMRbiEditCommand.parser

    def test_alias_nav(self):
        args = self.parser.parse_args(['--record', 'test-record', '-nav', 'on'])
        self.assertEqual(args.allow_url_navigation, 'on')

    def test_alias_isc(self):
        args = self.parser.parse_args(['--record', 'test-record', '-isc', 'on'])
        self.assertEqual(args.ignore_server_cert, 'on')

    def test_alias_au(self):
        args = self.parser.parse_args(['--record', 'test-record', '-au', '*.example.com'])
        self.assertEqual(args.allowed_urls, ['*.example.com'])

    def test_alias_aru(self):
        args = self.parser.parse_args(['--record', 'test-record', '-aru', '*.cdn.example.com'])
        self.assertEqual(args.allowed_resource_urls, ['*.cdn.example.com'])

    def test_alias_at(self):
        args = self.parser.parse_args(['--record', 'test-record', '-at', '#username'])
        self.assertEqual(args.autofill_targets, ['#username'])

    def test_alias_cpy(self):
        args = self.parser.parse_args(['--record', 'test-record', '-cpy', 'on'])
        self.assertEqual(args.allow_copy, 'on')

    def test_alias_p(self):
        args = self.parser.parse_args(['--record', 'test-record', '-p', 'on'])
        self.assertEqual(args.allow_paste, 'on')

    def test_alias_da(self):
        args = self.parser.parse_args(['--record', 'test-record', '-da', 'on'])
        self.assertEqual(args.disable_audio, 'on')

    def test_alias_ac(self):
        args = self.parser.parse_args(['--record', 'test-record', '-ac', '2'])
        self.assertEqual(args.audio_channels, 2)

    def test_alias_bd(self):
        args = self.parser.parse_args(['--record', 'test-record', '-bd', '16'])
        self.assertEqual(args.audio_bit_depth, 16)

    def test_alias_sr(self):
        args = self.parser.parse_args(['--record', 'test-record', '-sr', '44100'])
        self.assertEqual(args.audio_sample_rate, 44100)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamRbiEditAudioSettings(unittest.TestCase):
    """Tests for audio settings."""

    def setUp(self):
        self.parser = PAMRbiEditCommand.parser
        self.command = PAMRbiEditCommand()
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'
        self.pam_settings = {'connection': {'protocol': 'http', 'httpCredentialsUid': ''}}
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field
        self.mock_params = mock.MagicMock()

    def test_disable_audio_on(self):
        args = self.parser.parse_args(['--record', 'test-record', '--disable-audio', 'on'])
        self.assertEqual(args.disable_audio, 'on')

    def test_disable_audio_off(self):
        args = self.parser.parse_args(['--record', 'test-record', '--disable-audio', 'off'])
        self.assertEqual(args.disable_audio, 'off')

    def test_disable_audio_default(self):
        args = self.parser.parse_args(['--record', 'test-record', '--disable-audio', 'default'])
        self.assertEqual(args.disable_audio, 'default')

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_disable_audio_on_sets_true(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', disable_audio='on')
        self.assertEqual(self.pam_settings['connection'].get('disableAudio'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_disable_audio_off_sets_false(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', disable_audio='off')
        self.assertEqual(self.pam_settings['connection'].get('disableAudio'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_disable_audio_default_removes_field(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.pam_settings['connection']['disableAudio'] = True
        self.command.execute(self.mock_params, record='test-record', disable_audio='default')
        self.assertNotIn('disableAudio', self.pam_settings['connection'])

    def test_audio_channels_argument(self):
        args = self.parser.parse_args(['--record', 'test-record', '--audio-channels', '2'])
        self.assertEqual(args.audio_channels, 2)

    def test_audio_channels_mono(self):
        args = self.parser.parse_args(['--record', 'test-record', '--audio-channels', '1'])
        self.assertEqual(args.audio_channels, 1)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_audio_channels_sets_field(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', audio_channels=2)
        self.assertEqual(self.pam_settings['connection'].get('audioChannels'), 2)

    def test_audio_bit_depth_8(self):
        args = self.parser.parse_args(['--record', 'test-record', '--audio-bit-depth', '8'])
        self.assertEqual(args.audio_bit_depth, 8)

    def test_audio_bit_depth_16(self):
        args = self.parser.parse_args(['--record', 'test-record', '--audio-bit-depth', '16'])
        self.assertEqual(args.audio_bit_depth, 16)

    def test_audio_bit_depth_invalid(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(['--record', 'test-record', '--audio-bit-depth', '24'])

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_audio_bit_depth_sets_field(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', audio_bit_depth=16)
        self.assertEqual(self.pam_settings['connection'].get('audioBps'), 16)

    def test_audio_sample_rate_44100(self):
        args = self.parser.parse_args(['--record', 'test-record', '--audio-sample-rate', '44100'])
        self.assertEqual(args.audio_sample_rate, 44100)

    def test_audio_sample_rate_48000(self):
        args = self.parser.parse_args(['--record', 'test-record', '--audio-sample-rate', '48000'])
        self.assertEqual(args.audio_sample_rate, 48000)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_audio_sample_rate_sets_field(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', audio_sample_rate=48000)
        self.assertEqual(self.pam_settings['connection'].get('audioSampleRate'), 48000)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_all_audio_settings_combined(self, mock_sync, mock_update, mock_resolve):
        mock_resolve.return_value = self.mock_record
        self.command.execute(self.mock_params, record='test-record', disable_audio='off',
                           audio_channels=2, audio_bit_depth=16, audio_sample_rate=44100)
        self.assertEqual(self.pam_settings['connection'].get('disableAudio'), False)
        self.assertEqual(self.pam_settings['connection'].get('audioChannels'), 2)
        self.assertEqual(self.pam_settings['connection'].get('audioBps'), 16)
        self.assertEqual(self.pam_settings['connection'].get('audioSampleRate'), 44100)


if __name__ == '__main__':
    unittest.main()
