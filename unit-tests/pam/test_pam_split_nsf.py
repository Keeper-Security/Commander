import unittest
from unittest import mock

import keepercommander.commands.record  # noqa: F401
from keepercommander import vault
from keepercommander.commands.tunnel_and_connections import PAMSplitCommand
from keepercommander.params import LAST_RECORD_UID
from keepercommander.subfolder import NestedShareFolderNode, RootFolderNode


def _make_params():
    params = mock.MagicMock()
    params.folder_cache = {}
    params.subfolder_record_cache = {}
    params.shared_folder_cache = {}
    params.nested_share_folders = {}
    params.root_folder = RootFolderNode()
    params.current_folder = ''
    params.environment_variables = {}
    params.sync_data = False
    return params


def _make_pam_machine():
    record = vault.TypedRecord()
    record.record_uid = 'machine_uid'
    record.type_name = 'pamMachine'
    record.title = 'Machine'
    record.fields.append(vault.TypedField.new_field('login', 'admin'))
    record.fields.append(vault.TypedField.new_field('password', 'password'))
    return record


def _make_pam_user():
    record = vault.TypedRecord()
    record.record_uid = 'user_uid'
    record.type_name = 'pamUser'
    record.fields.append(vault.TypedField.new_field('login', ''))
    record.fields.append(vault.TypedField.new_field('password', ''))
    record.fields.append(vault.TypedField.new_field('secret', ''))
    return record


class TestPamSplitNsfPlacement(unittest.TestCase):

    @mock.patch('builtins.print')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'encrypted_session', b'encrypted_key', b'transmission_key'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.pam.vault_target.create_record_in_folder')
    @mock.patch('keepercommander.commands.pam.vault_target.resolve_pam_folder_uid',
                return_value='nsf_folder')
    @mock.patch('keepercommander.commands.tunnel_and_connections.vault.KeeperRecord.create')
    @mock.patch('keepercommander.commands.tunnel_and_connections.vault.KeeperRecord.load')
    @mock.patch('keepercommander.commands.tunnel_and_connections.resolve_pam_config',
                return_value='config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.resolve_record',
                return_value='machine_uid')
    def test_split_resolves_explicit_nsf_folder_name(
            self, mock_resolve_record, mock_resolve_config, mock_load, mock_create,
            mock_resolve_folder, mock_create_record, mock_update_record,
            mock_sync_down, mock_tokens, mock_dag, mock_print):
        params = _make_params()
        params.environment_variables[LAST_RECORD_UID] = 'user_uid'
        mock_load.return_value = _make_pam_machine()
        mock_create.return_value = _make_pam_user()

        PAMSplitCommand().execute(
            params, pam_machine_record='machine_uid',
            pam_config='config_uid', pam_user_folder='testpam')

        mock_resolve_folder.assert_called_once_with(
            params, 'testpam', allow_legacy_user=True)
        user_record = mock_create_record.call_args.args[1]
        self.assertEqual(user_record.type_name, 'pamUser')
        mock_create_record.assert_called_once_with(
            params, user_record, 'nsf_folder', command='pam-split')

    @mock.patch('builtins.print')
    @mock.patch('keepercommander.commands.tunnel_and_connections.TunnelDAG')
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_keeper_tokens',
                return_value=(b'encrypted_session', b'encrypted_key', b'transmission_key'))
    @mock.patch('keepercommander.commands.tunnel_and_connections.api.sync_down')
    @mock.patch('keepercommander.commands.tunnel_and_connections.record_management.update_record')
    @mock.patch('keepercommander.commands.pam.vault_target.create_record_in_folder')
    @mock.patch('keepercommander.commands.tunnel_and_connections.vault.KeeperRecord.create')
    @mock.patch('keepercommander.commands.tunnel_and_connections.vault.KeeperRecord.load')
    @mock.patch('keepercommander.commands.tunnel_and_connections.resolve_pam_config',
                return_value='config_uid')
    @mock.patch('keepercommander.commands.tunnel_and_connections.resolve_record',
                return_value='machine_uid')
    def test_split_defaults_to_machine_nsf_folder(
            self, mock_resolve_record, mock_resolve_config, mock_load, mock_create,
            mock_create_record, mock_update_record, mock_sync_down,
            mock_tokens, mock_dag, mock_print):
        params = _make_params()
        params.environment_variables[LAST_RECORD_UID] = 'user_uid'
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder
        params.subfolder_record_cache = {'nsf_folder': {'machine_uid'}}
        mock_load.return_value = _make_pam_machine()
        mock_create.return_value = _make_pam_user()

        PAMSplitCommand().execute(
            params, pam_machine_record='machine_uid',
            pam_config='config_uid', pam_user_folder='')

        user_record = mock_create_record.call_args.args[1]
        mock_create_record.assert_called_once_with(
            params, user_record, 'nsf_folder', command='pam-split')


if __name__ == '__main__':
    unittest.main()
