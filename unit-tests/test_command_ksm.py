"""Unit tests for secrets-manager (KSM) CLI commands."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.ksm import KSMCommand


class TestKSMSecretResolution(unittest.TestCase):

    def _make_params(self):
        params = MagicMock()
        params.record_cache = {}
        params.shared_folder_cache = {}
        params.nested_share_records = {}
        params.nested_share_folders = {}
        params.nested_share_record_data = {}
        params.folder_cache = {}
        return params

    def test_resolve_secret_uid_from_nsf_record_cache(self):
        params = self._make_params()
        record_uid = 'OYNvVgpPPJBrVfYOIRtdag'
        params.nested_share_records = {record_uid: {'record_key_unencrypted': b'key'}}
        self.assertEqual(KSMCommand.resolve_secret_uid(params, record_uid), record_uid)

    def test_resolve_secret_uid_from_nsf_folder_cache(self):
        params = self._make_params()
        folder_uid = 'bU2LVM6LjX_hmCoSMDA7vg'
        params.nested_share_folders = {folder_uid: {'name': 'Project Folder'}}
        with patch('keepercommander.commands.ksm.is_nested_share_folder', return_value=True):
            self.assertEqual(KSMCommand.resolve_secret_uid(params, folder_uid), folder_uid)

    @patch('keepercommander.commands.ksm.resolve_nested_share_record_uid')
    def test_resolve_secret_uid_by_record_title(self, mock_resolve_record):
        params = self._make_params()
        mock_resolve_record.return_value = 'resolved_record_uid'
        self.assertEqual(KSMCommand.resolve_secret_uid(params, 'My Record'), 'resolved_record_uid')

    @patch('keepercommander.commands.ksm.resolve_folder_uid')
    @patch('keepercommander.commands.ksm.resolve_nested_share_record_uid', return_value=None)
    def test_resolve_secret_uid_by_folder_path(self, _mock_resolve_record, mock_resolve_folder):
        params = self._make_params()
        mock_resolve_folder.return_value = 'resolved_folder_uid'
        with patch('keepercommander.commands.ksm.is_nested_share_folder',
                   side_effect=lambda _params, uid: uid == 'resolved_folder_uid'):
            with patch('keepercommander.commands.ksm.api.is_shared_folder', return_value=False):
                self.assertEqual(KSMCommand.resolve_secret_uid(params, 'NSF/Folder'), 'resolved_folder_uid')

    def test_classify_secret_nsf_record(self):
        params = self._make_params()
        record_uid = 'OYNvVgpPPJBrVfYOIRtdag'
        params.nested_share_records = {record_uid: {'record_key_unencrypted': b'record_key'}}
        with patch('keepercommander.commands.ksm.is_nested_share_record', return_value=True):
            secret = KSMCommand.classify_secret(params, record_uid)
        self.assertIsNotNone(secret)
        self.assertEqual(secret['share_type'], 'SHARE_TYPE_RECORD')
        self.assertEqual(secret['share_key'], b'record_key')

    def test_classify_secret_nsf_folder(self):
        params = self._make_params()
        folder_uid = 'bU2LVM6LjX_hmCoSMDA7vg'
        with patch('keepercommander.commands.ksm.is_nested_share_folder', return_value=True):
            with patch('keepercommander.commands.ksm.api.is_shared_folder', return_value=False):
                with patch('keepercommander.commands.ksm.get_folder_key', return_value=b'folder_key'):
                    secret = KSMCommand.classify_secret(params, folder_uid)
        self.assertIsNotNone(secret)
        self.assertEqual(secret['share_type'], 'SHARE_TYPE_FOLDER')
        self.assertEqual(secret['share_key'], b'folder_key')

    @patch('keepercommander.commands.ksm.KSMCommand.update_secrets_user_permissions')
    @patch('keepercommander.commands.ksm.api.sync_down')
    @patch('keepercommander.commands.ksm.api.communicate_rest')
    @patch('keepercommander.commands.ksm.KSMCommand.get_app_record')
    def test_share_secret_adds_nsf_record(self, mock_get_app_record, mock_communicate_rest,
                                          _mock_sync_down, _mock_update_perms):
        params = self._make_params()
        record_uid = 'OYNvVgpPPJBrVfYOIRtdag'
        params.nested_share_records = {record_uid: {'record_key_unencrypted': b'record_key'}}
        mock_get_app_record.return_value = {
            'record_uid': 'app_uid___________',
            'record_key_unencrypted': b'a' * 32,
        }
        with patch('keepercommander.commands.ksm.is_nested_share_record', return_value=True):
            KSMCommand.add_app_share(params, [record_uid], 'MyApp', False)
        mock_communicate_rest.assert_called_once()
        self.assertEqual(mock_communicate_rest.call_args[0][2], 'vault/app_share_add')


class TestKSMAppRecordResolution(unittest.TestCase):

    def _make_params(self):
        params = MagicMock()
        params.record_cache = {}
        params.nested_share_records = {}
        params.nested_share_record_data = {}
        return params

    def test_get_app_record_from_nsf_cache(self):
        params = self._make_params()
        app_uid = 'appUid00000000000001'
        params.nested_share_records = {
            app_uid: {'version': 5, 'record_key_unencrypted': b'app_key', 'revision': 1}
        }
        params.nested_share_record_data = {
            app_uid: {'data_json': {'title': 'NSF App', 'type': 'app'}}
        }
        with patch('keepercommander.commands.ksm.is_nested_share_record', return_value=True):
            rec = KSMCommand.get_app_record(params, app_uid)
        self.assertIsNotNone(rec)
        self.assertEqual(rec['record_uid'], app_uid)
        self.assertEqual(rec['record_key_unencrypted'], b'app_key')

    @patch('keepercommander.commands.ksm.resolve_nested_share_record_uid')
    def test_get_app_record_by_nsf_path(self, mock_resolve):
        params = self._make_params()
        app_uid = 'appUid00000000000001'
        mock_resolve.return_value = app_uid
        params.nested_share_records = {
            app_uid: {'version': 5, 'record_key_unencrypted': b'app_key', 'revision': 1}
        }
        params.nested_share_record_data = {
            app_uid: {'data_json': {'title': 'NSF App', 'type': 'app'}}
        }
        rec = KSMCommand.get_app_record(params, 'NSF/NSF App')
        self.assertIsNotNone(rec)
        self.assertEqual(rec['record_uid'], app_uid)

    def test_get_ksm_app_display_info_from_nsf_metadata(self):
        params = self._make_params()
        app_uid = 'appUid00000000000001'
        with patch('keepercommander.commands.ksm.KSMCommand.get_app_record', return_value=None):
            with patch('keepercommander.commands.ksm.KSMCommand.get_app_title', return_value='NSF App'):
                title, accessible, info = KSMCommand.get_ksm_app_display_info(params, app_uid)
        self.assertEqual(title, 'NSF App')
        self.assertFalse(accessible)
        self.assertIn('NSF App', info)


class TestKSMTokenAdd(unittest.TestCase):
    """secrets-manager token add <app-uid> → calls add_client."""

    def _make_params(self, record_uid='test-app-uid'):
        params = MagicMock()
        params.record_cache = {}
        return params

    @patch('keepercommander.commands.ksm.KSMCommand.add_client')
    def test_token_add_calls_add_client(self, mock_add_client):
        mock_add_client.return_value = [{'oneTimeToken': 'US:abc123', 'deviceToken': 'dt1'}]
        params = self._make_params()
        cmd = KSMCommand()
        result = cmd.execute(params, command=['token', 'add', 'MyApp'],
                             count=1, unlockIp=False, firstAccessExpiresIn=None,
                             accessExpireInMin=None, name=None, config_init=None,
                             returnTokens=False, format='table')
        mock_add_client.assert_called_once()
        call_args = mock_add_client.call_args
        assert call_args[0][1] == 'MyApp', f"Expected 'MyApp', got {call_args[0][1]}"

    @patch('keepercommander.commands.ksm.KSMCommand.add_client')
    def test_token_add_return_tokens(self, mock_add_client):
        mock_add_client.return_value = [{'oneTimeToken': 'US:tok1'}, {'oneTimeToken': 'US:tok2'}]
        params = self._make_params()
        cmd = KSMCommand()
        result = cmd.execute(params, command=['token', 'add', 'MyApp'],
                             count=2, unlockIp=False, firstAccessExpiresIn=None,
                             accessExpireInMin=None, name=None, config_init=None,
                             returnTokens=True, format='table')
        assert result == 'US:tok1, US:tok2', f"Expected 'US:tok1, US:tok2', got {result!r}"

    def test_token_add_missing_app_prints_help(self):
        params = self._make_params()
        cmd = KSMCommand()
        # Should print help and return None without calling add_client
        with patch('keepercommander.commands.ksm.KSMCommand.add_client') as mock_ac:
            result = cmd.execute(params, command=['token', 'add'],
                                 count=1, unlockIp=False, firstAccessExpiresIn=None,
                                 accessExpireInMin=None, name=None, config_init=None,
                                 returnTokens=False, format='table')
            mock_ac.assert_not_called()
            assert result is None, f"Expected None, got {result!r}"


if __name__ == '__main__':
    unittest.main()
