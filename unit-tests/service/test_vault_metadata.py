import unittest
from unittest.mock import Mock, patch

from keepercommander.params import KeeperParams
from keepercommander.service.commands.integrations.vault_metadata import (
    API_KEY_FIELD,
    SERVICE_URL_FIELD,
    VAULT_METADATA_MAX_ATTEMPTS,
    get_existing_api_key,
    write_service_metadata,
)


def _make_field(label, value):
    field = Mock()
    field.label = label
    field.get_default_value.return_value = value
    return field


def _make_typed_record(custom_fields):
    from keepercommander import vault
    record = Mock(spec=vault.TypedRecord)
    record.custom = list(custom_fields)
    return record


class TestGetExistingApiKey(unittest.TestCase):
    RECORD_UID = 'abc123uid'

    def setUp(self):
        self.params = Mock(spec=KeeperParams)

    @patch('keepercommander.vault.KeeperRecord.load')
    def test_returns_api_key_when_present(self, mock_load):
        mock_load.return_value = _make_typed_record([
            _make_field(SERVICE_URL_FIELD, 'https://example.com'),
            _make_field(API_KEY_FIELD, 'prev-key-123'),
        ])
        self.assertEqual(get_existing_api_key(self.params, self.RECORD_UID), 'prev-key-123')
        mock_load.assert_called_once_with(self.params, self.RECORD_UID)

    @patch('keepercommander.vault.KeeperRecord.load')
    def test_returns_none_when_api_key_field_missing(self, mock_load):
        mock_load.return_value = _make_typed_record([_make_field(SERVICE_URL_FIELD, 'https://example.com')])
        self.assertIsNone(get_existing_api_key(self.params, self.RECORD_UID))

    @patch('keepercommander.vault.KeeperRecord.load')
    def test_returns_none_when_api_key_value_empty(self, mock_load):
        mock_load.return_value = _make_typed_record([_make_field(API_KEY_FIELD, '')])
        self.assertIsNone(get_existing_api_key(self.params, self.RECORD_UID))

    @patch('keepercommander.vault.KeeperRecord.load')
    def test_returns_none_when_custom_is_empty(self, mock_load):
        mock_load.return_value = _make_typed_record([])
        self.assertIsNone(get_existing_api_key(self.params, self.RECORD_UID))

    @patch('keepercommander.vault.KeeperRecord.load')
    def test_returns_none_when_record_is_not_typed(self, mock_load):
        non_typed = Mock()
        non_typed.custom = [_make_field(API_KEY_FIELD, 'should-not-be-used')]
        mock_load.return_value = non_typed
        self.assertIsNone(get_existing_api_key(self.params, self.RECORD_UID))

    @patch('keepercommander.vault.KeeperRecord.load')
    def test_returns_none_when_load_raises(self, mock_load):
        mock_load.side_effect = RuntimeError("boom")
        self.assertIsNone(get_existing_api_key(self.params, self.RECORD_UID))


class TestWriteServiceMetadata(unittest.TestCase):
    RECORD_UID = 'rec-uid-xyz'
    SERVICE_URL = 'http://localhost:8900/api/v2'
    API_KEY = 'fresh-api-key'

    def setUp(self):
        self.params = Mock(spec=KeeperParams)

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.record_management.update_record')
    @patch('keepercommander.vault.KeeperRecord.load')
    def test_success_on_first_attempt(self, mock_load, mock_update, mock_sync):
        existing = Mock()
        existing.label = 'unrelated'
        record = _make_typed_record([existing])
        mock_load.return_value = record

        write_service_metadata(self.params, self.RECORD_UID, self.SERVICE_URL, self.API_KEY)

        mock_update.assert_called_once_with(self.params, record)
        self.assertEqual(mock_sync.call_count, 2)
        labels = {f.label for f in record.custom}
        self.assertIn(SERVICE_URL_FIELD, labels)
        self.assertIn(API_KEY_FIELD, labels)
        self.assertIn('unrelated', labels)

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.record_management.update_record')
    @patch('keepercommander.vault.KeeperRecord.load')
    def test_retries_on_stale_revision_then_succeeds(self, mock_load, mock_update, mock_sync):
        mock_load.return_value = _make_typed_record([])
        mock_update.side_effect = [Exception("RS_OUT_OF_SYNC: This object no longer exists."), None]

        write_service_metadata(self.params, self.RECORD_UID, self.SERVICE_URL, self.API_KEY)

        self.assertEqual(mock_update.call_count, 2)

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.record_management.update_record')
    @patch('keepercommander.vault.KeeperRecord.load')
    def test_does_not_retry_on_non_stale_error(self, mock_load, mock_update, mock_sync):
        mock_load.return_value = _make_typed_record([])
        mock_update.side_effect = Exception("Permission denied")

        write_service_metadata(self.params, self.RECORD_UID, self.SERVICE_URL, self.API_KEY)

        self.assertEqual(mock_update.call_count, 1)

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.record_management.update_record')
    @patch('keepercommander.vault.KeeperRecord.load')
    def test_gives_up_after_max_attempts(self, mock_load, mock_update, mock_sync):
        mock_load.return_value = _make_typed_record([])
        mock_update.side_effect = Exception("RS_OUT_OF_SYNC")

        write_service_metadata(self.params, self.RECORD_UID, self.SERVICE_URL, self.API_KEY)

        self.assertEqual(mock_update.call_count, VAULT_METADATA_MAX_ATTEMPTS)

    @patch('keepercommander.api.sync_down')
    @patch('keepercommander.record_management.update_record')
    @patch('keepercommander.vault.KeeperRecord.load')
    def test_does_not_update_when_record_missing(self, mock_load, mock_update, mock_sync):
        mock_load.return_value = None

        write_service_metadata(self.params, self.RECORD_UID, self.SERVICE_URL, self.API_KEY)

        mock_update.assert_not_called()


if __name__ == '__main__':
    unittest.main()
