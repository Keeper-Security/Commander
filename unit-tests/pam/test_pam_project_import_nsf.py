from types import SimpleNamespace
from unittest.mock import patch

import keepercommander.commands.record  # noqa: F401

from keepercommander.commands.pam.vault_target import (
    execute_record_add_in_folder, execute_record_v3_add_in_folder, grant_pam_folder_permissions, is_nested_share_folder)
from keepercommander.commands.pam_import.base import PamUserObject
from keepercommander.commands.pam_import.edit import PAMProjectImportCommand
from keepercommander.subfolder import BaseFolderNode


def _params():
    return SimpleNamespace(
        data_key=b'1' * 32,
        root_folder=SimpleNamespace(type=BaseFolderNode.RootFolderType),
        folder_cache={},
        shared_folder_cache={},
        subfolder_cache={},
        nested_share_folders={
            'root_nsf': {
                'name': PAMProjectImportCommand.PAM_ROOT_FOLDER_NAME,
                'parent_uid': None,
            }
        },
        environment_variables={},
        enterprise={'users': []},
        available_team_cache=[],
    )


def test_record_add_helper_creates_natively_in_nsf_folder():
    params = _params()
    args = {
        'force': True,
        'folder': 'root_nsf',
        'record_type': 'pamUser',
        'title': 'Admin',
    }

    with patch('keepercommander.commands.nested_share_folder.record_commands.NestedShareRecordAddCommand') as nsf_add, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down') as sync_down:
        nsf_add.return_value.execute.return_value = 'record_uid'

        uid = execute_record_add_in_folder(params, args, 'root_nsf', command='pam-project-import')

    assert uid == 'record_uid'
    nsf_add.return_value.execute.assert_called_once()
    sync_down.assert_called_once_with(params)
    call_kwargs = nsf_add.return_value.execute.call_args.kwargs
    assert call_kwargs['folder_uid'] == 'root_nsf'
    assert call_kwargs['record_type'] == 'pamUser'
    assert 'folder' not in call_kwargs


def test_record_v3_add_helper_creates_natively_in_nsf_folder():
    params = _params()
    args = {
        'folder': 'root_nsf',
        'data': '{"type":"pamUser","title":"Admin","fields":[]}',
    }

    with patch('keepercommander.nested_share_folder.record_api.create_record_v3',
               return_value={'success': True, 'record_uid': 'record_uid'}) as create_record, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'):
        uid = execute_record_v3_add_in_folder(params, args, 'root_nsf', command='pam-project-import')

    assert uid == 'record_uid'
    create_record.assert_called_once()
    assert create_record.call_args.kwargs['folder_uid'] == 'root_nsf'
    assert create_record.call_args.kwargs['record_data']['type'] == 'pamUser'


def test_is_nested_share_folder_detects_reconstructed_subfolder_cache():
    params = _params()
    params.nested_share_folders = {}
    params.subfolder_cache['root_nsf'] = {
        'folder_uid': 'root_nsf',
        'type': 'user_folder',
        'source': 'nested_share_folder',
    }

    assert is_nested_share_folder(params, 'root_nsf') is True


def test_import_record_objects_use_nsf_aware_record_add_helper():
    params = _params()
    user = PamUserObject.load({'type': 'pamUser', 'title': 'Admin', 'login': 'admin', 'password': 'password'})

    with patch('keepercommander.commands.pam_import.base.execute_record_add_in_folder',
               return_value='record_uid') as add_record:
        uid = user.create_record(params, 'root_nsf')

    assert uid == 'record_uid'
    add_record.assert_called_once()
    assert add_record.call_args.args[2] == 'root_nsf'
    assert add_record.call_args.kwargs == {'command': 'pam-project-import'}


def test_process_folders_uses_existing_nsf_root_and_creates_nsf_children():
    params = _params()
    project = {
        'options': {
            'project_name': 'Project 1',
            'dry_run': False,
            'use_nsf': True,
        },
        'data': {},
    }
    created = []

    def create_folder(params_arg, folder_name, parent_uid=None):
        uid = f'nsf_{len(created) + 1}'
        created.append((folder_name, parent_uid, uid))
        params_arg.nested_share_folders[uid] = {
            'name': folder_name,
            'parent_uid': parent_uid,
            'folder_key_unencrypted': b'k' * 32,
        }
        return {
            'success': True,
            'folder_uid': uid,
            'folder_key_unencrypted': b'k' * 32,
        }

    with patch('keepercommander.nested_share_folder.folder_api.create_folder_v3',
               side_effect=create_folder) as create_folder_v3, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'), \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        result = PAMProjectImportCommand().process_folders(params, project)

    assert result['root_folder_uid'] == 'root_nsf'
    assert result['project_folder_uid'] == 'nsf_1'
    assert result['resources_folder_uid'] == 'nsf_2'
    assert result['users_folder_uid'] == 'nsf_3'
    assert create_folder_v3.call_count == 3
    assert created == [
        ('Project 1', 'root_nsf', 'nsf_1'),
        ('Project 1 - Resources', 'nsf_1', 'nsf_2'),
        ('Project 1 - Users', 'nsf_1', 'nsf_3'),
    ]
    assert params.nested_share_folders['nsf_3']['folder_key_unencrypted'] == b'k' * 32


def test_process_folders_with_nsf_flag_ignores_legacy_root_folder():
    params = _params()
    params.nested_share_folders = {}
    params.folder_cache['legacy_root'] = SimpleNamespace(
        uid='legacy_root',
        parent_uid=None,
        name=PAMProjectImportCommand.PAM_ROOT_FOLDER_NAME,
        type=BaseFolderNode.UserFolderType,
        UserFolderType=BaseFolderNode.UserFolderType,
        SharedFolderType=BaseFolderNode.SharedFolderType,
    )
    project = {
        'options': {
            'project_name': 'Project 1',
            'dry_run': False,
            'use_nsf': True,
        },
        'data': {},
    }
    created = []

    def create_folder(params_arg, folder_name, parent_uid=None):
        uid = f'nsf_{len(created) + 1}'
        created.append((folder_name, parent_uid, uid))
        params_arg.nested_share_folders[uid] = {
            'name': folder_name,
            'parent_uid': parent_uid,
            'folder_key_unencrypted': b'k' * 32,
        }
        return {
            'success': True,
            'folder_uid': uid,
            'folder_key_unencrypted': b'k' * 32,
        }

    with patch('keepercommander.nested_share_folder.folder_api.create_folder_v3',
               side_effect=create_folder), \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'), \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        result = PAMProjectImportCommand().process_folders(params, project)

    assert result['root_folder_uid'] == 'nsf_1'
    assert result['project_folder_uid'] == 'nsf_2'
    assert result['resources_folder_uid'] == 'nsf_3'
    assert result['users_folder_uid'] == 'nsf_4'
    assert created[0] == (PAMProjectImportCommand.PAM_ROOT_FOLDER_NAME, None, 'nsf_1')
    assert result['root_folder_uid'] != 'legacy_root'


def test_nsf_folder_permissions_route_to_grant_folder_access():
    params = _params()
    params.nested_share_folders['child_nsf'] = {'name': 'Users', 'parent_uid': 'root_nsf'}

    with patch('keepercommander.commands.nested_share_folder.helpers.classify_share_recipient',
               return_value=('user', 'user@example.com')), \
            patch('keepercommander.nested_share_folder.folder_api.grant_folder_access_v3',
                  return_value={'success': True}) as grant:
        grant_pam_folder_permissions(
            params,
            'child_nsf',
            [{'name': 'user@example.com', 'manage_users': True, 'manage_records': True}],
            command='pam-project-import',
        )

    grant.assert_called_once_with(
        params,
        'child_nsf',
        'user@example.com',
        role='full-manager',
        as_team=False,
    )


def test_create_subfolder_seeds_folder_key_and_survives_sync_wipe():
    params = _params()
    folder_key = b'f' * 32

    def create_folder(_params, folder_name, parent_uid=None):
        return {
            'success': True,
            'folder_uid': 'new_nsf',
            'folder_key_unencrypted': folder_key,
        }

    def wipe_nsf(_params):
        _params.nested_share_folders.clear()

    with patch('keepercommander.nested_share_folder.folder_api.create_folder_v3',
               side_effect=create_folder), \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down',
                  side_effect=wipe_nsf):
        uid = PAMProjectImportCommand().create_subfolder(
            params, 'Child', parent_uid='root_nsf', use_nsf=True)

    assert uid == 'new_nsf'
    assert params.nested_share_folders['new_nsf']['folder_key_unencrypted'] == folder_key
    assert params.nested_share_folders['new_nsf']['parent_uid'] == 'root_nsf'
    assert params.subfolder_cache['new_nsf']['source'] == 'nested_share_folder'


def test_process_pam_config_uses_nsf_create_endpoint_for_nsf_users_folder():
    params = _params()
    params.nested_share_folders['users_nsf'] = {
        'name': 'Project - Users',
        'parent_uid': 'root_nsf',
        'folder_key_unencrypted': b'k' * 32,
    }
    params.nested_share_records = {}
    params.nested_share_record_data = {}
    project = {
        'options': {
            'project_name': 'NSF Config Project',
            'dry_run': False,
            'use_nsf': True,
            'sample_data': False,
            'output': 'base64',
        },
        'data': {
            'pam_configuration': {
                'environment': 'local',
                'title': 'NSF Config Project Configuration',
                'connections': 'on',
                'rotation': 'on',
                'tunneling': 'on',
                'remote_browser_isolation': 'on',
                'graphical_session_recording': 'off',
                'text_session_recording': 'off',
                'ai_threat_detection': 'off',
                'ai_terminate_session_on_detection': 'off',
            }
        },
        'folders': {'users_folder_uid': 'users_nsf'},
        'gateway': {'gateway_uid': 'gw-uid'},
        'ksm_app': {'app_uid': 'app-uid'},
    }

    with patch('keepercommander.commands.pam_import.edit.pam_configurations_get_all',
               return_value=[]), \
            patch('keepercommander.commands.discoveryrotation.PAMConfigurationNewCommand') as new_cmd, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'), \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        new_cmd.return_value.execute.return_value = 'cfg-uid'
        result = PAMProjectImportCommand().process_pam_config(params, project)

    assert result['pam_config_uid'] == 'cfg-uid'
    kwargs = new_cmd.return_value.execute.call_args.kwargs
    assert kwargs['shared_folder_uid'] == 'users_nsf'


def test_process_ksm_app_shares_nsf_folders_and_restores_keys():
    from unittest.mock import MagicMock

    params = _params()
    params.nested_share_folders['res_nsf'] = {
        'name': 'Res', 'parent_uid': 'root_nsf', 'folder_key_unencrypted': b'k' * 32,
    }
    params.nested_share_folders['usr_nsf'] = {
        'name': 'Users', 'parent_uid': 'root_nsf', 'folder_key_unencrypted': b'k' * 32,
    }
    project = {
        'options': {'project_name': 'NSF App', 'dry_run': False, 'use_nsf': True},
        'data': {},
        'folders': {
            'resources_folder_uid': 'res_nsf',
            'users_folder_uid': 'usr_nsf',
        },
    }

    def wipe_then_return(_params, _name):
        _params.nested_share_folders.clear()
        return 'app_uid'

    with patch('keepercommander.commands.pam_import.edit.api.communicate_rest') as communicate, \
            patch.object(PAMProjectImportCommand, 'create_ksm_app', side_effect=wipe_then_return), \
            patch('keepercommander.commands.pam_import.edit.KSMCommand') as ksm_cmd, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'), \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        communicate.return_value = MagicMock(applicationSummary=[])
        result = PAMProjectImportCommand().process_ksm_app(params, project)

    assert result['app_uid'] == 'app_uid'
    assert ksm_cmd.return_value.execute.call_count == 2
    shared = [c.kwargs.get('secret') for c in ksm_cmd.return_value.execute.call_args_list]
    assert ['res_nsf'] in shared
    assert ['usr_nsf'] in shared
    assert params.nested_share_folders['res_nsf']['folder_key_unencrypted'] == b'k' * 32
