import unittest
from unittest import mock

import keepercommander.commands.record  # noqa: F401
from keepercommander import vault
from keepercommander.commands.discoveryrotation import (
    PAMConfigurationEditCommand, PAMConfigurationNewCommand, PAMConfigurationRemoveCommand,
    PAMCreateRecordRotationCommand)
from keepercommander.commands.pam.vault_target import (
    create_pam_configuration_in_folder, create_record_in_folder, place_record_in_folder,
    resolve_pam_folder_uid, records_in_folder)
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

    @mock.patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down')
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

    def test_records_in_folder_merges_legacy_and_nsf_membership(self):
        params = _make_params()
        params.subfolder_record_cache = {'nsf_folder': {'legacy_rec_uid'}}
        params.nested_share_folder_records = {'nsf_folder': {'nsf_rec_uid'}}

        self.assertEqual(
            records_in_folder(params, 'nsf_folder'),
            {'legacy_rec_uid', 'nsf_rec_uid'},
        )

    @mock.patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down')
    @mock.patch('keepercommander.commands.pam.config_helper.pam_configuration_create_record_nsf')
    def test_create_pam_configuration_in_folder_uses_add_pam_configuration_for_nsf(
            self, mock_create_nsf, mock_sync):
        params = _make_params()
        params.nested_share_folders['nsf_folder'] = {'name': 'Project - Users'}
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder
        record = vault.TypedRecord(version=6)

        create_pam_configuration_in_folder(params, record, 'nsf_folder', command='pam-config-new')

        mock_create_nsf.assert_called_once_with(params, record, 'nsf_folder')
        mock_sync.assert_called_once_with(params)

    @mock.patch('keepercommander.commands.pam.vault_target.place_record_in_folder')
    @mock.patch('keepercommander.commands.pam.vault_target.api.sync_down')
    @mock.patch('keepercommander.commands.pam.config_helper.pam_configuration_create_record_v6')
    def test_create_pam_configuration_in_folder_uses_classic_api_for_legacy(
            self, mock_create_v6, mock_sync, mock_place):
        params = _make_params()
        folder = SharedFolderNode()
        folder.uid = 'legacy_folder'
        params.folder_cache[folder.uid] = folder
        record = vault.TypedRecord(version=6)
        record.record_uid = 'config_uid'

        create_pam_configuration_in_folder(params, record, 'legacy_folder', command='pam-config-new')

        mock_create_v6.assert_called_once_with(params, record, 'legacy_folder')
        mock_sync.assert_called_once_with(params)
        mock_place.assert_called_once_with(
            params, 'config_uid', 'legacy_folder', command='pam-config-new')


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

    @mock.patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @mock.patch('keepercommander.commands.discoveryrotation.get_keeper_tokens',
                return_value=(b'encrypted_session', b'encrypted_key', b'transmission_key'))
    @mock.patch('keepercommander.commands.discoveryrotation.create_pam_configuration_in_folder')
    @mock.patch('keepercommander.commands.discoveryrotation.RecordEditMixin.get_record_type_fields',
                return_value=[])
    def test_execute_creates_new_config_in_nsf_folder(
            self, mock_record_fields, mock_create_config, mock_tokens, mock_dag):
        params = _make_params()
        params.nested_share_folders['nsf_folder'] = {
            'name': 'Project - Users',
            'parent_uid': 'app_uid',
            'folder_key_unencrypted': b'0' * 32,
        }
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder
        command = PAMConfigurationNewCommand()

        def parse_properties(_, record, **kwargs):
            record.fields.append(vault.TypedField.new_field(
                'pamResources', {'folderUid': 'nsf_folder'}))

        def create_config(_, record, folder_uid, command='pam-config-new'):
            record.record_uid = 'config_uid'

        mock_create_config.side_effect = create_config
        with mock.patch.object(command, 'parse_properties', side_effect=parse_properties), \
                mock.patch.object(command, 'verify_required'):
            result = command.execute(params, config_type='local', title='Config')

        self.assertEqual(result, 'config_uid')
        mock_create_config.assert_called_once_with(
            params, mock.ANY, 'nsf_folder', command='pam-config-new')

    @mock.patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @mock.patch('keepercommander.commands.discoveryrotation.get_keeper_tokens',
                return_value=(b'encrypted_session', b'encrypted_key', b'transmission_key'))
    @mock.patch('keepercommander.commands.discoveryrotation.create_pam_configuration_in_folder')
    @mock.patch('keepercommander.commands.discoveryrotation.RecordEditMixin.get_record_type_fields',
                return_value=[])
    def test_execute_creates_new_config_in_legacy_folder(
            self, mock_record_fields, mock_create_config, mock_tokens, mock_dag):
        params = _make_params()
        folder = SharedFolderNode()
        folder.uid = 'legacy_folder'
        params.folder_cache[folder.uid] = folder
        command = PAMConfigurationNewCommand()

        def parse_properties(_, record, **kwargs):
            record.fields.append(vault.TypedField.new_field(
                'pamResources', {'folderUid': 'legacy_folder'}))

        def create_config(_, record, folder_uid, command='pam-config-new'):
            record.record_uid = 'config_uid'

        mock_create_config.side_effect = create_config
        with mock.patch.object(command, 'parse_properties', side_effect=parse_properties), \
                mock.patch.object(command, 'verify_required'):
            result = command.execute(params, config_type='local', title='Config')

        self.assertEqual(result, 'config_uid')
        mock_create_config.assert_called_once_with(
            params, mock.ANY, 'legacy_folder', command='pam-config-new')


class TestPamConfigEditNsfPlacement(unittest.TestCase):

    @mock.patch('keepercommander.commands.discoveryrotation.place_record_in_folder')
    @mock.patch('keepercommander.commands.discoveryrotation.update_pam_record')
    @mock.patch('keepercommander.commands.discoveryrotation.RecordEditMixin.get_record_type_fields',
                return_value=[])
    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_execute_updates_and_places_edited_config_in_nsf_folder(
            self, mock_load, mock_record_fields, mock_update_record, mock_place):
        params = _make_params()
        params.nested_share_folders['nsf_folder'] = {
            'name': 'Project - Users',
            'parent_uid': 'app_uid',
            'folder_key_unencrypted': b'0' * 32,
        }
        folder = NestedShareFolderNode()
        folder.uid = 'nsf_folder'
        params.folder_cache[folder.uid] = folder
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

        mock_update_record.assert_called_once_with(params, configuration, command='pam-config-edit')
        mock_place.assert_called_once_with(
            params, 'config_uid', 'nsf_folder', command='pam-config-edit')

    @mock.patch('keepercommander.commands.discoveryrotation.place_record_in_folder')
    @mock.patch('keepercommander.commands.discoveryrotation.update_pam_record')
    @mock.patch('keepercommander.commands.discoveryrotation.RecordEditMixin.get_record_type_fields',
                return_value=[])
    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_execute_places_edited_config_with_backend_aware_helper(
            self, mock_load, mock_record_fields, mock_update_record, mock_place):
        params = _make_params()
        folder = SharedFolderNode()
        folder.uid = 'legacy_folder'
        params.folder_cache[folder.uid] = folder
        params.record_cache = {'config_uid': {}}
        command = PAMConfigurationEditCommand()

        configuration = vault.TypedRecord(version=6)
        configuration.record_uid = 'config_uid'
        configuration.type_name = 'pamNetworkConfiguration'
        configuration.fields.append(vault.TypedField.new_field(
            'pamResources', {'folderUid': 'nsf_folder'}))
        mock_load.return_value = configuration

        def parse_properties(_, record, **kwargs):
            field = record.get_typed_field('pamResources')
            field.value[0]['folderUid'] = 'legacy_folder'

        with mock.patch.object(command, 'parse_properties', side_effect=parse_properties), \
                mock.patch.object(command, 'verify_required'):
            command.execute(params, uid='config_uid')

        mock_update_record.assert_called_once_with(params, configuration, command='pam-config-edit')
        mock_place.assert_called_once_with(
            params, 'config_uid', 'legacy_folder', command='pam-config-edit')


class TestPamConfigRemoveNsf(unittest.TestCase):

    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_resolve_pam_config_uid_finds_nsf_record_by_uid(self, mock_load):
        params = _make_params()
        params.record_cache = {}
        params.nested_share_records = {
            'config_uid': {'record_uid': 'config_uid', 'version': 6},
        }

        configuration = vault.TypedRecord(version=6)
        configuration.record_uid = 'config_uid'
        configuration.type_name = 'pamNetworkConfiguration'
        mock_load.return_value = configuration

        uid = PAMConfigurationRemoveCommand._resolve_pam_config_uid(params, 'config_uid')
        self.assertEqual(uid, 'config_uid')

    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_resolve_pam_config_uid_finds_nsf_record_by_title(self, mock_load):
        params = _make_params()
        params.record_cache = {}
        params.nested_share_records = {
            'config_uid': {'record_uid': 'config_uid', 'version': 6},
        }
        params.nested_share_record_data = {
            'config_uid': {
                'data_json': {
                    'title': 'PAM NSF Test Configuration',
                    'type': 'pamNetworkConfiguration',
                },
            },
        }

        configuration = vault.TypedRecord(version=6)
        configuration.record_uid = 'config_uid'
        configuration.type_name = 'pamNetworkConfiguration'
        configuration.title = 'PAM NSF Test Configuration'
        mock_load.return_value = configuration

        uid = PAMConfigurationRemoveCommand._resolve_pam_config_uid(
            params, 'PAM NSF Test Configuration')
        self.assertEqual(uid, 'config_uid')

    @mock.patch('keepercommander.commands.pam.config_helper.RecordRemoveCommand')
    @mock.patch('keepercommander.commands.nested_share_folder.helpers.is_nested_share_record',
                  return_value=False)
    def test_pam_configuration_remove_uses_legacy_remove_for_non_nsf_record(
            self, _mock_is_nsf, mock_remove_cmd):
        from keepercommander.commands.pam.config_helper import pam_configuration_remove

        params = _make_params()
        params.record_cache = {'config_uid': {}}
        params.nested_share_records = {}

        pam_configuration_remove(params, 'config_uid')

        mock_remove_cmd.return_value.execute.assert_called_once_with(
            params, record='config_uid', force=True)
        self.assertNotIn('config_uid', params.record_cache)

    @mock.patch('keepercommander.nested_share_folder.remove_record_v3',
                return_value={'confirmed': True})
    @mock.patch('keepercommander.subfolder.find_folders', return_value=['nsf_folder'])
    @mock.patch('keepercommander.commands.nested_share_folder.helpers.is_nested_share_record',
                  return_value=True)
    def test_pam_configuration_remove_uses_nsf_remove_for_nsf_record(
            self, _mock_is_nsf, mock_find_folders, mock_remove_v3):
        from keepercommander.commands.pam.config_helper import pam_configuration_remove

        params = _make_params()
        params.record_cache = {'config_uid': {}}
        params.nested_share_records = {'config_uid': {'record_uid': 'config_uid', 'version': 6}}

        pam_configuration_remove(params, 'config_uid')

        mock_remove_v3.assert_called_once_with(params, [{
            'record_uid': 'config_uid',
            'folder_uid': 'nsf_folder',
            'operation_type': 'owner-trash',
        }], dry_run=False)
        self.assertNotIn('config_uid', params.record_cache)
        self.assertNotIn('config_uid', params.nested_share_records)

    @mock.patch('keepercommander.commands.discoveryrotation.pam_configuration_remove')
    @mock.patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @mock.patch('keepercommander.commands.discoveryrotation.get_keeper_tokens',
                return_value=(b'encrypted_session', b'encrypted_key', b'transmission_key'))
    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_execute_removes_nsf_config(
            self, mock_load, mock_tokens, mock_dag, mock_remove):
        params = _make_params()
        params.record_cache = {}
        params.nested_share_records = {
            'config_uid': {'record_uid': 'config_uid', 'version': 6},
        }
        command = PAMConfigurationRemoveCommand()

        configuration = vault.TypedRecord(version=6)
        configuration.record_uid = 'config_uid'
        configuration.type_name = 'pamNetworkConfiguration'
        mock_load.return_value = configuration
        mock_dag.return_value.linking_dag.has_graph = False

        command.execute(params, uid='config_uid')

        mock_remove.assert_called_once_with(params, 'config_uid')
        self.assertTrue(params.sync_data)


class TestPamRotationNsfFolder(unittest.TestCase):

    @mock.patch('keepercommander.commands.discoveryrotation.router_set_record_rotation_information')
    @mock.patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @mock.patch('keepercommander.commands.discoveryrotation.get_keeper_tokens',
                return_value=(b'encrypted_session', b'encrypted_key', b'transmission_key'))
    @mock.patch('keepercommander.commands.discoveryrotation.collect_pam_folder_uids',
                return_value={'nsf_folder'})
    @mock.patch('keepercommander.commands.discoveryrotation.records_in_folder',
                return_value={'nsf_pam_user_uid'})
    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_execute_with_nsf_folder_collects_nsf_records(
            self, mock_load, mock_records_in_folder, mock_collect_folders,
            mock_tokens, mock_dag, _mock_router_set):
        from cryptography.hazmat.primitives.asymmetric import ec

        params = _make_params()
        params.rest_context.server_key_id = 8
        params.session_token = 'base64_encoded_session_token'
        params.record_rotation_cache = {}
        params.subfolder_record_cache = {}
        params.nested_share_folder_records = {'nsf_folder': {'nsf_pam_user_uid'}}

        pam_user = vault.TypedRecord(version=3)
        pam_user.record_uid = 'nsf_pam_user_uid'
        pam_user.type_name = 'pamMachine'
        pam_user.title = 'PAM NSF Test Machine'
        pam_user.record_key = b'\x00' * 32
        mock_load.return_value = pam_user

        mock_dag_instance = mock_dag.return_value
        mock_dag_instance.linking_dag.has_graph = True
        mock_dag_instance.resource_belongs_to_config.return_value = True
        mock_dag_instance.record.record_uid = 'config_uid'

        config_record = vault.TypedRecord(version=6)
        config_record.record_uid = 'config_uid'
        config_record.type_name = 'pamNetworkConfiguration'

        command = PAMCreateRecordRotationCommand()
        with mock.patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS',
                        {8: ec.generate_private_key(ec.SECP256R1()).public_key()}), \
                mock.patch('keepercommander.vault_extensions.find_records', return_value=[config_record]), \
                mock.patch('keepercommander.commands.discoveryrotation.resolve_pam_record',
                           side_effect=lambda _p, ident, rec_type=None: config_record if ident == 'config_uid' else pam_user), \
                mock.patch('keepercommander.commands.discoveryrotation.router_set_record_rotation_information'):
            command.execute(params, folder_name='M_SR5x7Q4cu9O0-RiLDN4A', force=True, on_demand=True,
                            config='config_uid')

        mock_collect_folders.assert_called_once_with(params, 'M_SR5x7Q4cu9O0-RiLDN4A')
        mock_records_in_folder.assert_called_once_with(params, 'nsf_folder')
        mock_load.assert_any_call(params, 'nsf_pam_user_uid')
