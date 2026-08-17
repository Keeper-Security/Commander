import unittest
from unittest.mock import MagicMock, patch

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


if __name__ == '__main__':
    unittest.main()
