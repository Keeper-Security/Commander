"""
Unit tests for PAM RBI Edit command - KC-1034 Feature Parity

Tests the new CLI arguments added to expose RBI settings:
- Browser Settings: --allow-url-navigation, --ignore-server-cert (on/off/default)
- URL Filtering: --allowed-urls, --allowed-resource-urls (multi-value)
- Autofill: --autofill-targets (multi-value)
- Clipboard: --allow-copy, --allow-paste (on/off/default)
- Audio: --disable-audio (on/off/default), --audio-channels, --audio-bit-depth, --audio-sample-rate
"""

import sys
import unittest
from unittest import mock

from keepercommander.commands.tunnel_and_connections import PAMRbiEditCommand
from keepercommander.error import CommandError
from keepercommander import vault


class TestPamRbiEditArguments(unittest.TestCase):
    """Tests for PAMRbiEditCommand argument parsing."""

    def setUp(self):
        """Set up parser for testing."""
        self.parser = PAMRbiEditCommand.parser

    # Browser Settings - --allow-url-navigation (on/off/default)
    def test_allow_url_navigation_on(self):
        """--allow-url-navigation on sets value to 'on'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'on'])
        self.assertEqual(args.allow_url_navigation, 'on')

    def test_allow_url_navigation_off(self):
        """--allow-url-navigation off sets value to 'off'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'off'])
        self.assertEqual(args.allow_url_navigation, 'off')

    def test_allow_url_navigation_default(self):
        """--allow-url-navigation default sets value to 'default'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'default'])
        self.assertEqual(args.allow_url_navigation, 'default')

    def test_allow_url_navigation_invalid(self):
        """--allow-url-navigation with invalid value raises error"""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(['--record', 'test-record', '--allow-url-navigation', 'invalid'])

    def test_allow_url_navigation_not_provided(self):
        """Without flag, allow_url_navigation is None"""
        args = self.parser.parse_args(['--record', 'test-record', '--key-events', 'on'])
        self.assertIsNone(args.allow_url_navigation)

    # Browser Settings - --ignore-server-cert (on/off/default)
    def test_ignore_server_cert_on(self):
        """--ignore-server-cert on sets value to 'on'"""
        args = self.parser.parse_args(['--record', 'test-record', '--ignore-server-cert', 'on'])
        self.assertEqual(args.ignore_server_cert, 'on')

    def test_ignore_server_cert_off(self):
        """--ignore-server-cert off sets value to 'off'"""
        args = self.parser.parse_args(['--record', 'test-record', '--ignore-server-cert', 'off'])
        self.assertEqual(args.ignore_server_cert, 'off')

    def test_ignore_server_cert_default(self):
        """--ignore-server-cert default sets value to 'default'"""
        args = self.parser.parse_args(['--record', 'test-record', '--ignore-server-cert', 'default'])
        self.assertEqual(args.ignore_server_cert, 'default')

    # URL Filtering - --allowed-urls (multi-value)
    def test_allowed_urls_single(self):
        """--allowed-urls with single value creates list"""
        args = self.parser.parse_args(['--record', 'test-record', '--allowed-urls', '*.example.com'])
        self.assertEqual(args.allowed_urls, ['*.example.com'])

    def test_allowed_urls_multiple(self):
        """Multiple --allowed-urls flags create list with all values"""
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--allowed-urls', '*.example.com',
            '--allowed-urls', '*.test.com',
            '--allowed-urls', '*.dev.com'
        ])
        self.assertEqual(args.allowed_urls, ['*.example.com', '*.test.com', '*.dev.com'])

    def test_allowed_urls_not_provided(self):
        """Without flag, allowed_urls is None"""
        args = self.parser.parse_args(['--record', 'test-record', '--key-events', 'on'])
        self.assertIsNone(args.allowed_urls)

    # URL Filtering - --allowed-resource-urls (multi-value)
    def test_allowed_resource_urls_single(self):
        """--allowed-resource-urls with single value creates list"""
        args = self.parser.parse_args(['--record', 'test-record', '--allowed-resource-urls', '*.cdn.example.com'])
        self.assertEqual(args.allowed_resource_urls, ['*.cdn.example.com'])

    def test_allowed_resource_urls_multiple(self):
        """Multiple --allowed-resource-urls flags create list"""
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--allowed-resource-urls', '*.cdn.example.com',
            '--allowed-resource-urls', '*.static.test.com'
        ])
        self.assertEqual(args.allowed_resource_urls, ['*.cdn.example.com', '*.static.test.com'])

    # Autofill Targets - --autofill-targets (multi-value)
    def test_autofill_targets_single(self):
        """--autofill-targets with single value creates list"""
        args = self.parser.parse_args(['--record', 'test-record', '--autofill-targets', '#username'])
        self.assertEqual(args.autofill_targets, ['#username'])

    def test_autofill_targets_multiple(self):
        """Multiple --autofill-targets flags create list"""
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--autofill-targets', '#username',
            '--autofill-targets', '#password',
            '--autofill-targets', 'input[name=email]'
        ])
        self.assertEqual(args.autofill_targets, ['#username', '#password', 'input[name=email]'])

    # Clipboard Settings - --allow-copy (on/off/default)
    def test_allow_copy_on(self):
        """--allow-copy on sets value to 'on'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-copy', 'on'])
        self.assertEqual(args.allow_copy, 'on')

    def test_allow_copy_off(self):
        """--allow-copy off sets value to 'off'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-copy', 'off'])
        self.assertEqual(args.allow_copy, 'off')

    def test_allow_copy_default(self):
        """--allow-copy default sets value to 'default'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-copy', 'default'])
        self.assertEqual(args.allow_copy, 'default')

    # Clipboard Settings - --allow-paste (on/off/default)
    def test_allow_paste_on(self):
        """--allow-paste on sets value to 'on'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-paste', 'on'])
        self.assertEqual(args.allow_paste, 'on')

    def test_allow_paste_off(self):
        """--allow-paste off sets value to 'off'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-paste', 'off'])
        self.assertEqual(args.allow_paste, 'off')

    def test_allow_paste_default(self):
        """--allow-paste default sets value to 'default'"""
        args = self.parser.parse_args(['--record', 'test-record', '--allow-paste', 'default'])
        self.assertEqual(args.allow_paste, 'default')

    # Combined arguments
    def test_combine_multiple_new_args(self):
        """Can combine multiple new arguments in one command"""
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
        """New arguments work alongside existing arguments"""
        args = self.parser.parse_args([
            '--record', 'test-record',
            '--key-events', 'on',
            '--allow-url-navigation', 'on',
            '--allowed-urls', '*.example.com'
        ])
        self.assertEqual(args.key_events, 'on')
        self.assertEqual(args.allow_url_navigation, 'on')
        self.assertEqual(args.allowed_urls, ['*.example.com'])


class TestPamRbiEditExecute(unittest.TestCase):
    """Tests for PAMRbiEditCommand.execute() method."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = PAMRbiEditCommand()

        # Create a mock PAM RBI record
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'

        # Mock pamRemoteBrowserSettings field
        self.pam_settings = {
            'connection': {
                'protocol': 'http',
                'httpCredentialsUid': ''
            }
        }
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field

        # Mock params
        self.mock_params = mock.MagicMock()
        self.mock_params.record_cache = {'test-record-uid': self.mock_record}

    def test_no_param_raises_error_with_new_settings_check(self):
        """At least one parameter is required - checks new settings too"""
        with self.assertRaises(CommandError) as context:
            self.command.execute(self.mock_params, record='test-record')

        self.assertIn('At least one parameter is required', str(context.exception))

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_url_navigation_on_sets_true(self, mock_sync, mock_update, mock_resolve):
        """--allow-url-navigation on sets allowUrlManipulation=True"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='on')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('allowUrlManipulation'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_url_navigation_off_sets_false(self, mock_sync, mock_update, mock_resolve):
        """--allow-url-navigation off sets allowUrlManipulation=False"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='off')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('allowUrlManipulation'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_url_navigation_default_removes_field(self, mock_sync, mock_update, mock_resolve):
        """--allow-url-navigation default removes allowUrlManipulation field"""
        mock_resolve.return_value = self.mock_record
        # Pre-set the field
        self.pam_settings['connection']['allowUrlManipulation'] = True

        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='default')

        connection = self.pam_settings['connection']
        self.assertNotIn('allowUrlManipulation', connection)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_ignore_server_cert_on_sets_true(self, mock_sync, mock_update, mock_resolve):
        """--ignore-server-cert on sets ignoreInitialSslCert=True"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', ignore_server_cert='on')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('ignoreInitialSslCert'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allowed_urls_joins_with_newlines(self, mock_sync, mock_update, mock_resolve):
        """Multiple URLs joined with newlines"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(
            self.mock_params,
            record='test-record',
            allowed_urls=['*.example.com', '*.test.com', '*.dev.com']
        )

        connection = self.pam_settings['connection']
        self.assertEqual(
            connection.get('allowedUrlPatterns'),
            '*.example.com\n*.test.com\n*.dev.com'
        )

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allowed_resource_urls_joins_with_newlines(self, mock_sync, mock_update, mock_resolve):
        """Multiple resource URLs joined with newlines"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(
            self.mock_params,
            record='test-record',
            allowed_resource_urls=['*.cdn.example.com', '*.static.test.com']
        )

        connection = self.pam_settings['connection']
        self.assertEqual(
            connection.get('allowedResourceUrlPatterns'),
            '*.cdn.example.com\n*.static.test.com'
        )

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_autofill_targets_joins_with_newlines(self, mock_sync, mock_update, mock_resolve):
        """Multiple autofill targets joined with newlines"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(
            self.mock_params,
            record='test-record',
            autofill_targets=['#username', '#password', 'input[name=email]']
        )

        connection = self.pam_settings['connection']
        self.assertEqual(
            connection.get('autofillConfiguration'),
            '#username\n#password\ninput[name=email]'
        )


class TestPamRbiEditClipboardInversion(unittest.TestCase):
    """Tests for clipboard inversion logic (allow_copy on -> disableCopy=False)"""

    def setUp(self):
        """Set up test fixtures."""
        self.command = PAMRbiEditCommand()

        # Create a mock PAM RBI record
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'

        # Mock pamRemoteBrowserSettings field
        self.pam_settings = {
            'connection': {
                'protocol': 'http',
                'httpCredentialsUid': ''
            }
        }
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field

        # Mock params
        self.mock_params = mock.MagicMock()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_copy_on_sets_disable_copy_false(self, mock_sync, mock_update, mock_resolve):
        """--allow-copy on sets disableCopy=False (inverted logic)"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', allow_copy='on')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disableCopy'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_copy_off_sets_disable_copy_true(self, mock_sync, mock_update, mock_resolve):
        """--allow-copy off sets disableCopy=True (inverted logic)"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', allow_copy='off')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disableCopy'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_copy_default_removes_field(self, mock_sync, mock_update, mock_resolve):
        """--allow-copy default removes disableCopy field"""
        mock_resolve.return_value = self.mock_record
        # Pre-set the field
        self.pam_settings['connection']['disableCopy'] = True

        self.command.execute(self.mock_params, record='test-record', allow_copy='default')

        connection = self.pam_settings['connection']
        self.assertNotIn('disableCopy', connection)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_paste_on_sets_disable_paste_false(self, mock_sync, mock_update, mock_resolve):
        """--allow-paste on sets disablePaste=False (inverted logic)"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', allow_paste='on')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disablePaste'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_allow_paste_off_sets_disable_paste_true(self, mock_sync, mock_update, mock_resolve):
        """--allow-paste off sets disablePaste=True (inverted logic)"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', allow_paste='off')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disablePaste'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_clipboard_both_on(self, mock_sync, mock_update, mock_resolve):
        """Setting both --allow-copy on and --allow-paste on works correctly"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(
            self.mock_params,
            record='test-record',
            allow_copy='on',
            allow_paste='on'
        )

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disableCopy'), False)
        self.assertEqual(connection.get('disablePaste'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_clipboard_both_off(self, mock_sync, mock_update, mock_resolve):
        """Setting both --allow-copy off and --allow-paste off works correctly"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(
            self.mock_params,
            record='test-record',
            allow_copy='off',
            allow_paste='off'
        )

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disableCopy'), True)
        self.assertEqual(connection.get('disablePaste'), True)


class TestPamRbiEditRecordUpdate(unittest.TestCase):
    """Tests for record update behavior."""

    def setUp(self):
        """Set up test fixtures."""
        self.command = PAMRbiEditCommand()

        # Create a mock PAM RBI record
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'

        # Mock pamRemoteBrowserSettings field
        self.pam_settings = {
            'connection': {
                'protocol': 'http',
                'httpCredentialsUid': ''
            }
        }
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field

        # Mock params
        self.mock_params = mock.MagicMock()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_record_update_called_when_field_changes(self, mock_sync, mock_update, mock_resolve):
        """record_management.update_record is called when fields change"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', allow_url_navigation='on')

        mock_update.assert_called_once()
        mock_sync.assert_called_once()

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_multiple_fields_single_update(self, mock_sync, mock_update, mock_resolve):
        """Multiple field changes result in single update call"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(
            self.mock_params,
            record='test-record',
            allow_url_navigation='on',
            ignore_server_cert='off',
            allow_copy='on',
            allow_paste='on',
            allowed_urls=['*.example.com']
        )

        # Should only update once, not once per field
        mock_update.assert_called_once()


class TestPamRbiEditHelp(unittest.TestCase):
    """Test that help text is correct for new arguments."""

    def test_help_includes_new_arguments(self):
        """Help text includes all new arguments"""
        help_text = PAMRbiEditCommand.parser.format_help()

        # Browser settings (on/off/default)
        self.assertIn('--allow-url-navigation', help_text)
        self.assertIn('--ignore-server-cert', help_text)

        # URL filtering
        self.assertIn('--allowed-urls', help_text)
        self.assertIn('--allowed-resource-urls', help_text)

        # Autofill
        self.assertIn('--autofill-targets', help_text)

        # Clipboard (on/off/default)
        self.assertIn('--allow-copy', help_text)
        self.assertIn('--allow-paste', help_text)

        # Audio settings
        self.assertIn('--disable-audio', help_text)
        self.assertIn('--audio-channels', help_text)
        self.assertIn('--audio-bit-depth', help_text)
        self.assertIn('--audio-sample-rate', help_text)

    def test_help_shows_choices(self):
        """Help text shows on/off/default choices"""
        help_text = PAMRbiEditCommand.parser.format_help()

        # Verify choices are shown
        self.assertIn('on/off/default', help_text.lower().replace('{', '').replace('}', '').replace(',', '/'))


class TestPamRbiEditAliases(unittest.TestCase):
    """Tests for short alias arguments."""

    def setUp(self):
        """Set up parser for testing."""
        self.parser = PAMRbiEditCommand.parser

    def test_alias_nav(self):
        """-nav alias works for --allow-url-navigation"""
        args = self.parser.parse_args(['--record', 'test-record', '-nav', 'on'])
        self.assertEqual(args.allow_url_navigation, 'on')

    def test_alias_isc(self):
        """-isc alias works for --ignore-server-cert"""
        args = self.parser.parse_args(['--record', 'test-record', '-isc', 'on'])
        self.assertEqual(args.ignore_server_cert, 'on')

    def test_alias_au(self):
        """-au alias works for --allowed-urls"""
        args = self.parser.parse_args(['--record', 'test-record', '-au', '*.example.com'])
        self.assertEqual(args.allowed_urls, ['*.example.com'])

    def test_alias_aru(self):
        """-aru alias works for --allowed-resource-urls"""
        args = self.parser.parse_args(['--record', 'test-record', '-aru', '*.cdn.example.com'])
        self.assertEqual(args.allowed_resource_urls, ['*.cdn.example.com'])

    def test_alias_at(self):
        """-at alias works for --autofill-targets"""
        args = self.parser.parse_args(['--record', 'test-record', '-at', '#username'])
        self.assertEqual(args.autofill_targets, ['#username'])

    def test_alias_cpy(self):
        """-cpy alias works for --allow-copy"""
        args = self.parser.parse_args(['--record', 'test-record', '-cpy', 'on'])
        self.assertEqual(args.allow_copy, 'on')

    def test_alias_p(self):
        """-p alias works for --allow-paste"""
        args = self.parser.parse_args(['--record', 'test-record', '-p', 'on'])
        self.assertEqual(args.allow_paste, 'on')

    def test_alias_da(self):
        """-da alias works for --disable-audio"""
        args = self.parser.parse_args(['--record', 'test-record', '-da', 'on'])
        self.assertEqual(args.disable_audio, 'on')

    def test_alias_ac(self):
        """-ac alias works for --audio-channels"""
        args = self.parser.parse_args(['--record', 'test-record', '-ac', '2'])
        self.assertEqual(args.audio_channels, 2)

    def test_alias_bd(self):
        """-bd alias works for --audio-bit-depth"""
        args = self.parser.parse_args(['--record', 'test-record', '-bd', '16'])
        self.assertEqual(args.audio_bit_depth, 16)

    def test_alias_sr(self):
        """-sr alias works for --audio-sample-rate"""
        args = self.parser.parse_args(['--record', 'test-record', '-sr', '44100'])
        self.assertEqual(args.audio_sample_rate, 44100)


class TestPamRbiEditAudioSettings(unittest.TestCase):
    """Tests for --disable-audio setting."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = PAMRbiEditCommand.parser
        self.command = PAMRbiEditCommand()

        # Create a mock PAM RBI record
        self.mock_record = mock.MagicMock(spec=vault.TypedRecord)
        self.mock_record.record_uid = 'test-record-uid'
        self.mock_record.record_type = 'pamRemoteBrowser'

        # Mock pamRemoteBrowserSettings field
        self.pam_settings = {
            'connection': {
                'protocol': 'http',
                'httpCredentialsUid': ''
            }
        }
        self.mock_field = mock.MagicMock()
        self.mock_field.value = [self.pam_settings]
        self.mock_record.get_typed_field.return_value = self.mock_field

        # Mock params
        self.mock_params = mock.MagicMock()

    def test_disable_audio_on(self):
        """--disable-audio on sets value to 'on'"""
        args = self.parser.parse_args(['--record', 'test-record', '--disable-audio', 'on'])
        self.assertEqual(args.disable_audio, 'on')

    def test_disable_audio_off(self):
        """--disable-audio off sets value to 'off'"""
        args = self.parser.parse_args(['--record', 'test-record', '--disable-audio', 'off'])
        self.assertEqual(args.disable_audio, 'off')

    def test_disable_audio_default(self):
        """--disable-audio default sets value to 'default'"""
        args = self.parser.parse_args(['--record', 'test-record', '--disable-audio', 'default'])
        self.assertEqual(args.disable_audio, 'default')

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_disable_audio_on_sets_true(self, mock_sync, mock_update, mock_resolve):
        """--disable-audio on sets disableAudio=True"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', disable_audio='on')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disableAudio'), True)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_disable_audio_off_sets_false(self, mock_sync, mock_update, mock_resolve):
        """--disable-audio off sets disableAudio=False"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', disable_audio='off')

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disableAudio'), False)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_disable_audio_default_removes_field(self, mock_sync, mock_update, mock_resolve):
        """--disable-audio default removes disableAudio field"""
        mock_resolve.return_value = self.mock_record
        # Pre-set the field
        self.pam_settings['connection']['disableAudio'] = True

        self.command.execute(self.mock_params, record='test-record', disable_audio='default')

        connection = self.pam_settings['connection']
        self.assertNotIn('disableAudio', connection)

    # Audio channels tests
    def test_audio_channels_argument(self):
        """--audio-channels accepts integer value"""
        args = self.parser.parse_args(['--record', 'test-record', '--audio-channels', '2'])
        self.assertEqual(args.audio_channels, 2)

    def test_audio_channels_mono(self):
        """--audio-channels 1 for mono"""
        args = self.parser.parse_args(['--record', 'test-record', '--audio-channels', '1'])
        self.assertEqual(args.audio_channels, 1)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_audio_channels_sets_field(self, mock_sync, mock_update, mock_resolve):
        """--audio-channels sets audioChannels field"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', audio_channels=2)

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('audioChannels'), 2)

    # Audio bit depth tests
    def test_audio_bit_depth_8(self):
        """--audio-bit-depth 8 is accepted"""
        args = self.parser.parse_args(['--record', 'test-record', '--audio-bit-depth', '8'])
        self.assertEqual(args.audio_bit_depth, 8)

    def test_audio_bit_depth_16(self):
        """--audio-bit-depth 16 is accepted"""
        args = self.parser.parse_args(['--record', 'test-record', '--audio-bit-depth', '16'])
        self.assertEqual(args.audio_bit_depth, 16)

    def test_audio_bit_depth_invalid(self):
        """--audio-bit-depth with invalid value raises error"""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(['--record', 'test-record', '--audio-bit-depth', '24'])

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_audio_bit_depth_sets_field(self, mock_sync, mock_update, mock_resolve):
        """--audio-bit-depth sets audioBps field"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', audio_bit_depth=16)

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('audioBps'), 16)

    # Audio sample rate tests
    def test_audio_sample_rate_44100(self):
        """--audio-sample-rate 44100 is accepted"""
        args = self.parser.parse_args(['--record', 'test-record', '--audio-sample-rate', '44100'])
        self.assertEqual(args.audio_sample_rate, 44100)

    def test_audio_sample_rate_48000(self):
        """--audio-sample-rate 48000 is accepted"""
        args = self.parser.parse_args(['--record', 'test-record', '--audio-sample-rate', '48000'])
        self.assertEqual(args.audio_sample_rate, 48000)

    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_audio_sample_rate_sets_field(self, mock_sync, mock_update, mock_resolve):
        """--audio-sample-rate sets audioSampleRate field"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(self.mock_params, record='test-record', audio_sample_rate=48000)

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('audioSampleRate'), 48000)

    # Combined audio settings test
    @mock.patch('keepercommander.commands.tunnel_and_connections.RecordMixin.resolve_single_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    def test_all_audio_settings_combined(self, mock_sync, mock_update, mock_resolve):
        """All audio settings can be set together"""
        mock_resolve.return_value = self.mock_record

        self.command.execute(
            self.mock_params,
            record='test-record',
            disable_audio='off',
            audio_channels=2,
            audio_bit_depth=16,
            audio_sample_rate=44100
        )

        connection = self.pam_settings['connection']
        self.assertEqual(connection.get('disableAudio'), False)
        self.assertEqual(connection.get('audioChannels'), 2)
        self.assertEqual(connection.get('audioBps'), 16)
        self.assertEqual(connection.get('audioSampleRate'), 44100)


if __name__ == '__main__':
    unittest.main()
