import unittest
from unittest import mock

import keepercommander.commands.record  # noqa: F401
from keepercommander import vault
from keepercommander.commands.credential_provision import CredentialProvisionCommand
from keepercommander.commands.pam.vault_target import (
    create_record_in_folder, resolve_access_user_save_folder, resolve_provision_target_folder)
from keepercommander.commands.pam_cloud.pam_privileged_access import PAMAccessUserProvisionCommand
from keepercommander.error import CommandError
from keepercommander.subfolder import NestedShareFolderNode, RootFolderNode, SharedFolderNode


def _make_params():
    params = mock.MagicMock()
    params.folder_cache = {}
    params.shared_folder_cache = {}
    params.nested_share_folders = {}
    params.nested_share_folder_records = {}
    params.subfolder_record_cache = {}
    params.current_folder = ''
    params.root_folder = RootFolderNode()
    params.environment_variables = {}
    params.sync_data = False
    params.record_cache = {}
    return params


class TestPamProvisionNsf(unittest.TestCase):

    @mock.patch('keepercommander.commands.pam.vault_target.PamConfigurationRecordFacade')
    @mock.patch('keepercommander.commands.pam.vault_target.vault.KeeperRecord.load')
    def test_resolve_access_user_save_folder_uses_users_subfolder(self, mock_load, mock_facade_cls):
        params = _make_params()
        params.nested_share_folders = {
            'users_uid': {'name': 'Project 1 - Users', 'parent_uid': 'app_uid'},
        }
        params.folder_cache['app_uid'] = NestedShareFolderNode()
        params.folder_cache['app_uid'].uid = 'app_uid'

        facade = mock_facade_cls.return_value
        facade.folder_uid = 'app_uid'

        folder_uid = resolve_access_user_save_folder(params, 'config_uid')
        self.assertEqual(folder_uid, 'users_uid')

    @mock.patch('keepercommander.commands.pam_cloud.pam_privileged_access.create_record_in_folder')
    @mock.patch('keepercommander.commands.pam_cloud.pam_privileged_access.resolve_access_user_save_folder',
                return_value='nsf_users_uid')
    def test_access_user_provision_save_record_uses_create_record_in_folder(self, _resolve, mock_create):
        params = _make_params()
        cmd = PAMAccessUserProvisionCommand()

        with mock.patch('keepercommander.commands.pam_cloud.pam_privileged_access.resolve_pam_idp_config',
                        return_value='idp_uid'), \
                mock.patch('keepercommander.commands.pam_cloud.pam_privileged_access._get_record_key',
                           return_value=b'0' * 32), \
                mock.patch('keepercommander.commands.pam_cloud.pam_privileged_access._dispatch_idp_action',
                           return_value={'data': {'username': 'user@example.com', 'password': 'secret'}}):
            cmd.execute(
                params,
                config_uid='config_uid',
                username='user@example.com',
                save_record=True,
            )

        mock_create.assert_called_once()
        self.assertEqual(mock_create.call_args.args[2], 'nsf_users_uid')
        self.assertEqual(mock_create.call_args.kwargs['command'], 'pam-access-user-provision')

    @mock.patch('keepercommander.commands.pam.vault_target.ensure_pam_folder_path', return_value='target_uid')
    @mock.patch('keepercommander.commands.pam.vault_target.resolve_pam_application_folder',
                return_value=('app_uid', 'Project 1'))
    def test_resolve_provision_target_folder_uses_nsf_path_for_relative_folder(self, _app, mock_ensure):
        params = _make_params()
        params.nested_share_folders['app_uid'] = {'name': 'Project 1', 'parent_uid': None}
        params.folder_cache['app_uid'] = NestedShareFolderNode()
        params.folder_cache['app_uid'].uid = 'app_uid'

        folder_uid = resolve_provision_target_folder(
            params, 'config_uid', folder_spec='Onboarding/Team A', command='credential-provision')
        self.assertEqual(folder_uid, 'target_uid')
        mock_ensure.assert_called_once_with(
            params, 'app_uid', 'Onboarding/Team A', command='credential-provision')

    @mock.patch('keepercommander.commands.credential_provision.api.sync_down')
    @mock.patch('keepercommander.commands.credential_provision.create_record_in_folder')
    @mock.patch.object(CredentialProvisionCommand, '_resolve_pam_user_folder_uid', return_value='nsf_users_uid')
    def test_credential_provision_create_pam_user_uses_create_record_in_folder(self, _resolve, mock_create, _sync):
        params = _make_params()
        cmd = CredentialProvisionCommand()
        config = {
            'account': {'username': 'svc-user', 'pam_config_uid': 'config_uid'},
            'user': {'first_name': 'Svc', 'last_name': 'User', 'department': 'Eng'},
        }

        def _assign_uid(params, record, folder_uid, command='credential-provision'):
            record.record_uid = 'new_uid'

        mock_create.side_effect = _assign_uid
        uid = cmd._create_pam_user(config, 'password123', params)
        self.assertEqual(uid, 'new_uid')
        mock_create.assert_called_once()
        self.assertEqual(mock_create.call_args.args[2], 'nsf_users_uid')
        self.assertEqual(mock_create.call_args.kwargs['command'], 'credential-provision')

    @mock.patch('keepercommander.commands.pam.vault_target.record_management.add_record_to_folder')
    def test_create_record_in_folder_for_access_user_provision_nsf(self, mock_add):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder
        record = vault.TypedRecord()
        record.record_uid = 'record_uid'

        with mock.patch('keepercommander.commands.pam.vault_target.place_record_in_folder') as mock_place:
            create_record_in_folder(params, record, folder.uid, command='pam-access-user-provision')
            mock_add.assert_called_once_with(params, record)
            mock_place.assert_called_once_with(
                params, 'record_uid', 'nsf_folder', command='pam-access-user-provision')

    def test_resolve_access_user_save_folder_rejects_unknown_folder(self):
        params = _make_params()
        with self.assertRaises(CommandError):
            resolve_access_user_save_folder(params, 'config_uid', folder_spec='missing-folder')


if __name__ == '__main__':
    unittest.main()
