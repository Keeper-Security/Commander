import unittest
from unittest.mock import MagicMock, patch

from keepercommander.error import CommandError
from keepercommander.params import KeeperParams, RecordOwner


class TestFindEmailConfigRecordOwnership(unittest.TestCase):
    """Email config records must be owned by the current account."""

    TITLE = 'default'

    def _make_typed_record(self, uid, title=None):
        from keepercommander import vault

        record = MagicMock(spec=vault.TypedRecord)
        record.record_uid = uid
        record.title = title or self.TITLE
        record.record_type = 'login'
        return record

    def _email_config_data(self):
        return {
            'custom': [
                {'type': 'text', 'label': '__email_config__', 'value': ['true']},
            ]
        }

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_skips_non_owned_record(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        shared = self._make_typed_record('SHARED_UID')
        owned = self._make_typed_record('OWNED_UID')

        def load_side_effect(_params, uid):
            return {'SHARED_UID': shared, 'OWNED_UID': owned}[uid]

        mock_load.side_effect = load_side_effect
        mock_extract.return_value = self._email_config_data()

        params = MagicMock(spec=KeeperParams)
        params.record_cache = {'SHARED_UID': {}, 'OWNED_UID': {}}
        params.record_owner_cache = {
            'SHARED_UID': RecordOwner(False, 'attacker'),
            'OWNED_UID': RecordOwner(True, 'operator'),
        }

        self.assertEqual(find_email_config_record(params, self.TITLE), 'OWNED_UID')

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_returns_none_when_only_shared_match(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('SHARED_UID')
        mock_extract.return_value = self._email_config_data()

        params = MagicMock(spec=KeeperParams)
        params.record_cache = {'SHARED_UID': {}}
        params.record_owner_cache = {
            'SHARED_UID': RecordOwner(False, 'attacker'),
        }

        self.assertIsNone(find_email_config_record(params, self.TITLE))

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_returns_none_when_owner_cache_missing(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('UNKNOWN_UID')
        mock_extract.return_value = self._email_config_data()

        params = MagicMock(spec=KeeperParams)
        params.record_cache = {'UNKNOWN_UID': {}}
        params.record_owner_cache = {}

        self.assertIsNone(find_email_config_record(params, self.TITLE))

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_returns_owned_record(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('OWNED_UID')
        mock_extract.return_value = self._email_config_data()

        params = MagicMock(spec=KeeperParams)
        params.record_cache = {'OWNED_UID': {}}
        params.record_owner_cache = {
            'OWNED_UID': RecordOwner(True, 'operator'),
        }

        self.assertEqual(find_email_config_record(params, self.TITLE), 'OWNED_UID')


class TestEmailConfigListOwnership(unittest.TestCase):
    """email-config list must only show owned configurations."""

    def _make_typed_record(self, uid, title):
        from keepercommander import vault

        record = MagicMock(spec=vault.TypedRecord)
        record.record_uid = uid
        record.title = title
        record.record_type = 'login'
        return record

    def _email_config_data(self, provider='smtp', from_address='it@corp.example'):
        return {
            'custom': [
                {'type': 'text', 'label': '__email_config__', 'value': ['true']},
                {'type': 'text', 'label': 'provider', 'value': [provider]},
                {'type': 'text', 'label': 'from_address', 'value': [from_address]},
            ]
        }

    @patch('keepercommander.commands.email_commands.dump_report_data')
    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_list_skips_shared_in_config(self, mock_load, mock_extract, mock_dump):
        from keepercommander.commands.email_commands import EmailConfigListCommand

        shared = self._make_typed_record('SHARED_UID', 'default')
        owned = self._make_typed_record('OWNED_UID', 'corp-smtp')

        def load_side_effect(_params, uid):
            return {'SHARED_UID': shared, 'OWNED_UID': owned}[uid]

        mock_load.side_effect = load_side_effect
        mock_extract.return_value = self._email_config_data()

        params = MagicMock(spec=KeeperParams)
        params.record_cache = {'SHARED_UID': {}, 'OWNED_UID': {}}
        params.record_owner_cache = {
            'SHARED_UID': RecordOwner(False, 'attacker'),
            'OWNED_UID': RecordOwner(True, 'operator'),
        }

        EmailConfigListCommand().execute(params, format='table')

        mock_dump.assert_called_once()
        table = mock_dump.call_args[0][0]
        self.assertEqual(len(table), 1)
        self.assertEqual(table[0][0], 'corp-smtp')
        self.assertEqual(table[0][3], 'OWNED_UID')


class TestSendEmailValidationOwnership(unittest.TestCase):
    """Patched validation paths must raise when only a shared-in config matches."""

    @patch('keepercommander.commands.email_commands.find_email_config_record', return_value=None)
    def test_record_add_raises_when_only_shared_config(self, _mock_find):
        from keepercommander.commands.record_edit import RecordAddCommand

        params = MagicMock(spec=KeeperParams)
        with self.assertRaises(CommandError) as ctx:
            RecordAddCommand().execute(
                params,
                send_email='newhire@corp.example',
                email_config='default',
            )
        self.assertIn('Email configuration "default" not found', str(ctx.exception))

    @patch('keepercommander.commands.discoveryrotation._is_rotation_allowed_by_enforcement',
           return_value=True)
    @patch('keepercommander.commands.discoveryrotation.find_email_config_record', return_value=None)
    def test_pam_rotate_raises_when_only_shared_config(self, _mock_find, _mock_allowed):
        from keepercommander.commands.discoveryrotation import PAMGatewayActionRotateCommand

        params = MagicMock(spec=KeeperParams)
        with self.assertRaises(CommandError) as ctx:
            PAMGatewayActionRotateCommand().execute(
                params,
                record_uid='REC_UID',
                send_email='newhire@corp.example',
                email_config='default',
            )
        self.assertIn('Email configuration "default" not found', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
