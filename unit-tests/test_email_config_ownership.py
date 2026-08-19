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

    def _email_config_data(self, extra_fields=None):
        custom = [
            {'type': 'text', 'label': '__email_config__', 'value': ['true']},
        ]
        if extra_fields:
            custom.extend(extra_fields)
        return {'custom': custom}

    def _params(self, record_cache, record_owner_cache, account_uid_bytes=None, meta_data_cache=None):
        params = MagicMock(spec=KeeperParams)
        params.account_uid_bytes = account_uid_bytes
        params.record_cache = record_cache
        params.record_owner_cache = record_owner_cache
        params.meta_data_cache = meta_data_cache or {}
        return params

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

        params = self._params(
            {'SHARED_UID': {}, 'OWNED_UID': {}},
            {
                'SHARED_UID': RecordOwner(False, 'attacker'),
                'OWNED_UID': RecordOwner(True, 'operator'),
            },
        )

        self.assertEqual(find_email_config_record(params, self.TITLE), 'OWNED_UID')

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_returns_none_when_only_shared_match(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('SHARED_UID')
        mock_extract.return_value = self._email_config_data()

        params = self._params(
            {'SHARED_UID': {}},
            {'SHARED_UID': RecordOwner(False, 'attacker')},
        )

        self.assertIsNone(find_email_config_record(params, self.TITLE))

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_returns_none_when_owner_cache_missing(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('UNKNOWN_UID')
        mock_extract.return_value = self._email_config_data()

        params = self._params({'UNKNOWN_UID': {}}, {})

        self.assertIsNone(find_email_config_record(params, self.TITLE))

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_returns_owned_record(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('OWNED_UID')
        mock_extract.return_value = self._email_config_data()

        params = self._params(
            {'OWNED_UID': {}},
            {'OWNED_UID': RecordOwner(True, 'operator')},
        )

        self.assertEqual(find_email_config_record(params, self.TITLE), 'OWNED_UID')

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_accepts_owned_record_when_owner_flag_overwritten(self, mock_load, mock_extract):
        from keepercommander import utils
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('OWNED_UID')
        mock_extract.return_value = self._email_config_data()

        account_uid_bytes = b'current-account'
        current_uid = utils.base64_url_encode(account_uid_bytes)
        params = self._params(
            {'OWNED_UID': {}},
            {'OWNED_UID': RecordOwner(False, current_uid)},
            account_uid_bytes=account_uid_bytes,
        )

        self.assertEqual(find_email_config_record(params, self.TITLE), 'OWNED_UID')

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_accepts_owned_record_from_metadata_when_owner_cache_wrong(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('OWNED_UID')
        mock_extract.return_value = self._email_config_data()

        params = self._params(
            {'OWNED_UID': {}},
            {'OWNED_UID': RecordOwner(False, 'attacker')},
            meta_data_cache={'OWNED_UID': {'owner': True}},
        )

        self.assertEqual(find_email_config_record(params, self.TITLE), 'OWNED_UID')

    @patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data')
    @patch('keepercommander.commands.email_commands.vault.KeeperRecord.load')
    def test_matches_when_marker_is_not_last_custom_field(self, mock_load, mock_extract):
        from keepercommander.commands.email_commands import find_email_config_record

        mock_load.return_value = self._make_typed_record('OWNED_UID')
        mock_extract.return_value = self._email_config_data(
            extra_fields=[
                {'type': 'text', 'label': 'smtp_host', 'value': ['smtp.example.com']},
            ]
        )
        params = self._params(
            {'OWNED_UID': {}},
            {'OWNED_UID': RecordOwner(True, 'operator')},
        )

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
        params.account_uid_bytes = None
        params.record_cache = {'SHARED_UID': {}, 'OWNED_UID': {}}
        params.record_owner_cache = {
            'SHARED_UID': RecordOwner(False, 'attacker'),
            'OWNED_UID': RecordOwner(True, 'operator'),
        }
        params.meta_data_cache = {}

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
