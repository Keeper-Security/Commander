from types import SimpleNamespace
from unittest.mock import patch

import keepercommander.commands.record  # noqa: F401

from keepercommander import vault
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


def test_record_add_helper_creates_directly_in_nsf_folder():
    params = _params()
    args = {
        'force': True,
        'folder': 'root_nsf',
        'record_type': 'pamUser',
        'title': 'Admin',
        'fields': ['f.login=admin', 'f.password=secret'],
    }
    record = vault.TypedRecord()
    record.record_uid = 'record_uid'
    record.type_name = 'pamUser'
    record.title = 'Admin'

    with patch('keepercommander.commands.pam.vault_target._build_typed_record_from_add_args',
               return_value=(record, [], object())) as build_record, \
            patch('keepercommander.commands.pam.vault_target._create_typed_record_in_nsf',
                  return_value='record_uid') as create_nsf:
        uid = execute_record_add_in_folder(params, args, 'root_nsf', command='pam-project-import')

    assert uid == 'record_uid'
    build_record.assert_called_once()
    create_nsf.assert_called_once_with(
        params, record, 'root_nsf', command='pam-project-import')


def test_record_v3_add_helper_creates_directly_in_nsf_folder():
    params = _params()
    args = {
        'folder': 'root_nsf',
        'data': '{"type":"pamUser","title":"Admin","fields":[]}',
    }

    with patch('keepercommander.commands.pam.vault_target._add_record_data_to_nsf',
               return_value='record_uid') as create_nsf:
        uid = execute_record_v3_add_in_folder(params, args, 'root_nsf', command='pam-project-import')

    assert uid == 'record_uid'
    create_nsf.assert_called_once()
    call = create_nsf.call_args
    assert call.args[2] == 'root_nsf' or call.kwargs.get('folder_uid') == 'root_nsf'


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
        }
        return {'success': True, 'folder_uid': uid}

    with patch('keepercommander.nested_share_folder.folder_api.create_folder_v3',
               side_effect=create_folder) as create_folder_v3, \
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
        }
        return {'success': True, 'folder_uid': uid}

    with patch('keepercommander.nested_share_folder.folder_api.create_folder_v3',
               side_effect=create_folder), \
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
