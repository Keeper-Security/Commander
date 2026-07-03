import unittest
from unittest import mock

import keepercommander.commands.record  # noqa: F401
from keepercommander import vault
from keepercommander.commands.discoveryrotation import PAMConfigurationEditCommand, PAMConfigurationNewCommand
from keepercommander.commands.pam.vault_target import (
    create_record_in_folder, place_record_in_folder, resolve_pam_folder_uid)
from keepercommander.error import CommandError
from keepercommander.subfolder import NestedShareFolderNode, RootFolderNode, SharedFolderNode


def _make_params():
    params = mock.MagicMock()
    params.folder_cache = {}
    params.shared_folder_cache = {}
    params.nested_share_folders = {}
    params.current_folder = ''
    params.root_folder = RootFolderNode()
    params.environment_variables = {}
    params.sync_data = False
    return params


class TestPamVaultTarget(unittest.TestCase):

    @mock.patch('keepercommander.commands.pam.vault_target.api.sync_down')
    @mock.patch('keepercommander.commands.pam.vault_target.move_record_v3')
    @mock.patch('keepercommander.commands.pam.vault_target.FolderMoveCommand')
    def test_place_record_uses_legacy_move_for_legacy_folder(self, mock_move_command, mock_nsf_move, mock_sync):
        params = _make_params()
        folder = SharedFolderNode()
        folder.uid = 'legacy_folder'
        params.folder_cache[folder.uid] = folder

        place_record_in_folder(params, 'record_uid', folder.uid, command='pam-config-new')

        mock_move_command.return_value.execute.assert_called_once_with(
            params, src='record_uid', dst='legacy_folder', force=True)
        mock_nsf_move.assert_not_called()
        mock_sync.assert_not_called()

    @mock.patch('keepercommander.commands.pam.vault_target.api.sync_down')
    @mock.patch('keepercommander.commands.pam.vault_target.move_record_v3')
    @mock.patch('keepercommander.commands.pam.vault_target.FolderMoveCommand')
    def test_place_record_uses_nsf_move_for_nsf_folder(self, mock_move_command, mock_nsf_move, mock_sync):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder

        place_record_in_folder(params, 'record_uid', folder.uid, command='pam-config-new')

        mock_nsf_move.assert_called_once_with(params, 'record_uid', to_folder_uid='nsf_folder')
        mock_sync.assert_called_once_with(params)
        mock_move_command.assert_not_called()

    @mock.patch('keepercommander.commands.pam.vault_target.api.sync_down')
    @mock.patch('keepercommander.commands.pam.vault_target.move_record_v3',
                return_value={'success': False, 'message': 'denied'})
    def test_place_record_raises_when_nsf_move_fails(self, mock_nsf_move, mock_sync):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder

        with self.assertRaises(CommandError):
            place_record_in_folder(params, 'record_uid', folder.uid, command='pam-config-new')
        mock_sync.assert_not_called()

    def test_place_record_rejects_missing_folder(self):
        params = _make_params()

        with self.assertRaises(CommandError):
            place_record_in_folder(params, 'record_uid', 'missing_folder', command='pam-config-new')

    @mock.patch('keepercommander.commands.pam.vault_target.record_management.add_record_to_folder')
    def test_create_record_in_folder_uses_legacy_add_for_legacy_folder(self, mock_add_record):
        params = _make_params()
        folder = SharedFolderNode()
        folder.uid = 'legacy_folder'
        params.folder_cache[folder.uid] = folder
        record = vault.TypedRecord()

        create_record_in_folder(params, record, folder.uid, command='pam-access-user-provision')

        mock_add_record.assert_called_once_with(params, record, 'legacy_folder')

    @mock.patch('keepercommander.commands.pam.vault_target.api.sync_down')
    @mock.patch('keepercommander.nested_share_folder.record_api.create_record_v3',
                return_value={'success': True, 'record_uid': 'nsf_record_uid'})
    @mock.patch('keepercommander.vault_extensions.extract_typed_record_data',
                return_value={'type': 'pamUser', 'title': 'Test', 'fields': [], 'custom': []})
    def test_create_record_in_folder_uses_v3_add_for_nsf_folder(self, _extract, mock_create, _sync):
        params = _make_params()
        params.nested_share_folders['nsf_folder'] = {
            'name': 'Project - Users',
            'parent_uid': 'app_uid',
            'folder_key_unencrypted': b'0' * 32,
        }
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder
        record = vault.TypedRecord()

        create_record_in_folder(params, record, folder.uid, command='pam-access-user-provision')

        mock_create.assert_called_once()
        self.assertEqual(mock_create.call_args.kwargs['folder_uid'], 'nsf_folder')
        self.assertEqual(record.record_uid, 'nsf_record_uid')
        _sync.assert_called_once_with(params)

    def test_resolve_pam_folder_uid_finds_root_nsf_folder_by_name(self):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        folder.name = 'testpam'
        params.folder_cache[folder.uid] = folder
        params.root_folder.subfolders.append(folder.uid)

        self.assertEqual(resolve_pam_folder_uid(params, 'testpam'), 'nsf_folder')

    def test_resolve_pam_folder_uid_finds_nsf_cache_folder_by_name(self):
        params = _make_params()
        params.nested_share_folders['nsf_folder'] = {'name': 'testpam'}

        self.assertEqual(resolve_pam_folder_uid(params, 'testpam'), 'nsf_folder')


class TestPamConfigNewNsfPlacement(unittest.TestCase):

    def test_parse_pam_configuration_accepts_nsf_folder_uid(self):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder

        record = vault.TypedRecord(version=6)
        command = PAMConfigurationNewCommand()
        command.parse_pam_configuration(params, record, shared_folder_uid='nsf_folder')

        field = record.get_typed_field('pamResources')
        self.assertEqual(field.value[0]['folderUid'], 'nsf_folder')

    def test_parse_pam_configuration_accepts_nsf_folder_name(self):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        folder.name = 'testpam'
        params.folder_cache[folder.uid] = folder
        params.root_folder.subfolders.append(folder.uid)

        record = vault.TypedRecord(version=6)
        command = PAMConfigurationNewCommand()
        command.parse_pam_configuration(params, record, shared_folder_uid='testpam')

        field = record.get_typed_field('pamResources')
        self.assertEqual(field.value[0]['folderUid'], 'nsf_folder')

    @mock.patch('keepercommander.commands.discoveryrotation.place_record_in_folder')
    @mock.patch('keepercommander.commands.discoveryrotation.api.sync_down')
    @mock.patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @mock.patch('keepercommander.commands.discoveryrotation.get_keeper_tokens',
                return_value=(b'encrypted_session', b'encrypted_key', b'transmission_key'))
    @mock.patch('keepercommander.commands.discoveryrotation.pam_configuration_create_record_v6')
    @mock.patch('keepercommander.commands.discoveryrotation.RecordEditMixin.get_record_type_fields',
                return_value=[])
    def test_execute_places_new_config_with_backend_aware_helper(
            self, mock_record_fields, mock_create_config, mock_tokens, mock_dag, mock_sync, mock_place):
        params = _make_params()
        command = PAMConfigurationNewCommand()

        def parse_properties(_, record, **kwargs):
            record.fields.append(vault.TypedField.new_field(
                'pamResources', {'folderUid': 'nsf_folder'}))

        def create_config(_, record, folder_uid):
            record.record_uid = 'config_uid'

        mock_create_config.side_effect = create_config
        with mock.patch.object(command, 'parse_properties', side_effect=parse_properties), \
                mock.patch.object(command, 'verify_required'):
            result = command.execute(params, config_type='local', title='Config')

        self.assertEqual(result, 'config_uid')
        mock_place.assert_called_once_with(
            params, 'config_uid', 'nsf_folder', command='pam-config-new')


class TestPamConfigEditNsfPlacement(unittest.TestCase):

    @mock.patch('keepercommander.commands.discoveryrotation.place_record_in_folder')
    @mock.patch('keepercommander.commands.discoveryrotation.record_management.update_record')
    @mock.patch('keepercommander.commands.discoveryrotation.RecordEditMixin.get_record_type_fields',
                return_value=[])
    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_execute_places_edited_config_with_backend_aware_helper(
            self, mock_load, mock_record_fields, mock_update_record, mock_place):
        params = _make_params()
        params.record_cache = {'config_uid': {}}
        command = PAMConfigurationEditCommand()

        configuration = vault.TypedRecord(version=6)
        configuration.record_uid = 'config_uid'
        configuration.type_name = 'pamNetworkConfiguration'
        configuration.fields.append(vault.TypedField.new_field(
            'pamResources', {'folderUid': 'legacy_folder'}))
        mock_load.return_value = configuration

        def parse_properties(_, record, **kwargs):
            field = record.get_typed_field('pamResources')
            field.value[0]['folderUid'] = 'nsf_folder'

        with mock.patch.object(command, 'parse_properties', side_effect=parse_properties), \
                mock.patch.object(command, 'verify_required'):
            command.execute(params, uid='config_uid')

        mock_update_record.assert_called_once_with(params, configuration)
        mock_place.assert_called_once_with(
            params, 'config_uid', 'nsf_folder', command='pam-config-edit')
