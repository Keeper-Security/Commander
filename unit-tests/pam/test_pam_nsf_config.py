import unittest
from unittest import mock

import keepercommander.commands.record  # noqa: F401
from keepercommander import vault
from keepercommander.proto import record_pb2
from keepercommander.commands.discoveryrotation import PAMConfigurationEditCommand, PAMConfigurationNewCommand
from keepercommander.commands.pam.vault_target import (
    create_record_in_folder, place_record_in_folder, place_pam_configuration_in_folder,
    resolve_pam_folder_uid)
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

    @mock.patch('keepercommander.commands.pam.vault_target.FolderMoveCommand')
    def test_place_record_uses_legacy_move_for_legacy_folder(self, mock_move_command):
        params = _make_params()
        folder = SharedFolderNode()
        folder.uid = 'legacy_folder'
        params.folder_cache[folder.uid] = folder

        place_record_in_folder(params, 'record_uid', folder.uid, command='pam-config-new')

        mock_move_command.return_value.execute.assert_called_once_with(
            params, src='record_uid', dst='legacy_folder', force=True)

    @mock.patch('keepercommander.commands.pam.vault_target.FolderMoveCommand')
    def test_place_record_rejects_nsf_move(self, mock_move_command):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder

        with self.assertRaises(CommandError):
            place_record_in_folder(params, 'record_uid', folder.uid, command='pam-config-new')

        mock_move_command.assert_not_called()

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

    @mock.patch('keepercommander.commands.pam.vault_target._create_typed_record_in_nsf', return_value='record_uid')
    def test_create_record_in_folder_creates_directly_in_nsf(self, mock_create_nsf):
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

        uid = create_record_in_folder(params, record, folder.uid, command='pam-access-user-provision')

        self.assertEqual(uid, 'record_uid')
        mock_create_nsf.assert_called_once_with(
            params, record, 'nsf_folder', command='pam-access-user-provision')

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


class TestPamConfigPlacement(unittest.TestCase):

    @mock.patch('keepercommander.commands.pam.vault_target.api.sync_down')
    @mock.patch('keepercommander.commands.pam.vault_target.FolderMoveCommand')
    def test_place_pam_config_skips_nsf_record_update(self, mock_move_command, mock_sync):
        params = _make_params()
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder

        place_pam_configuration_in_folder(params, 'config_uid', folder.uid, command='pam-config-new')

        mock_move_command.assert_not_called()
        mock_sync.assert_called_once_with(params)

    @mock.patch('keepercommander.commands.pam.vault_target.FolderMoveCommand')
    def test_place_pam_config_uses_legacy_move_for_shared_folder(self, mock_move_command):
        params = _make_params()
        folder = SharedFolderNode()
        folder.uid = 'legacy_folder'
        params.folder_cache[folder.uid] = folder

        place_pam_configuration_in_folder(params, 'config_uid', folder.uid, command='pam-config-new')

        mock_move_command.return_value.execute.assert_called_once_with(
            params, src='config_uid', dst='legacy_folder', force=True)


class TestPamConfigurationCreateNsf(unittest.TestCase):

    @mock.patch('keepercommander.commands.pam.config_helper.api.sync_down')
    @mock.patch('keepercommander.nested_share_folder.record_api.pam_configuration_add_v3')
    @mock.patch('keepercommander.nested_share_folder.record_api.create_record_data_v3')
    @mock.patch('keepercommander.nested_share_folder.common.get_folder_key', return_value=b'folder_key')
    @mock.patch('keepercommander.commands.pam.config_helper.is_nested_share_folder', return_value=True)
    def test_create_uses_add_pam_configuration_for_nsf(
            self, mock_is_nsf, mock_get_folder_key, mock_create_record_data,
            mock_add_pam_configuration, mock_sync):
        from keepercommander.commands.pam.config_helper import pam_configuration_create_record_v6

        params = _make_params()
        params.nested_share_folders = {'nsf_folder': {'name': 'Config'}}
        record = vault.TypedRecord(version=6)
        record.type_name = 'pamNetworkConfiguration'
        record.title = 'Config'
        mock_create_record_data.return_value = mock.MagicMock()

        status = mock.MagicMock()
        status.status = record_pb2.RS_SUCCESS
        status.message = ''
        response = mock.MagicMock()
        response.records = [status]
        mock_add_pam_configuration.return_value = response

        pam_configuration_create_record_v6(params, record, 'nsf_folder')

        mock_add_pam_configuration.assert_called_once()
        mock_sync.assert_called_once_with(params)
        self.assertTrue(record.record_uid)
        self.assertTrue(record.record_key)

    @mock.patch('keepercommander.commands.pam.config_helper.api.communicate_rest')
    @mock.patch('keepercommander.commands.pam.config_helper.is_nested_share_folder', return_value=False)
    def test_create_uses_legacy_endpoint_for_shared_folder(
            self, mock_is_nsf, mock_communicate):
        from keepercommander.commands.pam.config_helper import pam_configuration_create_record_v6

        params = _make_params()
        params.data_key = b'0' * 32
        record = vault.TypedRecord(version=6)
        record.type_name = 'pamNetworkConfiguration'
        record.title = 'Config'

        pam_configuration_create_record_v6(params, record, 'legacy_folder')

        mock_communicate.assert_called_once()
        self.assertEqual(mock_communicate.call_args[0][2], 'pam/add_configuration_record')


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

    @mock.patch('keepercommander.commands.pam.vault_target.place_pam_configuration_in_folder')
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

    @mock.patch('keepercommander.commands.pam.vault_target.place_pam_configuration_in_folder')
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
