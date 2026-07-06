from types import SimpleNamespace
from unittest.mock import patch

import keepercommander.commands.record  # noqa: F401

from keepercommander.commands.pam_import.extend import PAMProjectExtendCommand
from keepercommander.subfolder import BaseFolderNode, NestedShareFolderNode, RootFolderNode


def _folder(uid, name, parent_uid=None):
    folder = NestedShareFolderNode()
    folder.uid = uid
    folder.name = name
    folder.parent_uid = parent_uid
    folder.subfolders = []
    return folder


def _params():
    project = _folder('project_nsf', 'NSF Project')
    users = _folder('users_nsf', 'NSF Project - Users', 'project_nsf')
    resources = _folder('resources_nsf', 'NSF Project - Resources', 'project_nsf')
    project.subfolders = ['users_nsf', 'resources_nsf']
    return SimpleNamespace(
        data_key=b'1' * 32,
        root_folder=RootFolderNode(),
        folder_cache={
            'project_nsf': project,
            'users_nsf': users,
            'resources_nsf': resources,
        },
        subfolder_cache={},
        subfolder_record_cache={'users_nsf': {'config_uid'}},
        shared_folder_cache={},
        nested_share_folders={
            'project_nsf': {'name': 'NSF Project', 'parent_uid': None},
            'users_nsf': {'name': 'NSF Project - Users', 'parent_uid': 'project_nsf'},
            'resources_nsf': {'name': 'NSF Project - Resources', 'parent_uid': 'project_nsf'},
        },
        environment_variables={},
    )


def test_get_nsf_project_folders_from_config_folder_siblings():
    params = _params()

    folders = PAMProjectExtendCommand.get_nsf_project_folders(params, 'config_uid')

    assert {x['uid'] for x in folders} == {'users_nsf', 'resources_nsf'}
    assert all(x['source'] == 'nested_share_folder' for x in folders)


def test_get_app_shared_folders_falls_back_to_nsf_project_folders():
    params = _params()

    with patch('keepercommander.commands.ksm.KSMCommand.get_app_info',
               return_value=[]):
        folders = PAMProjectExtendCommand().get_app_shared_folders(params, 'ksm_uid', 'config_uid')

    assert {x['uid'] for x in folders} == {'users_nsf', 'resources_nsf'}


def test_create_subfolder_uses_nsf_api_under_nsf_parent():
    params = _params()

    with patch('keepercommander.nested_share_folder.folder_api.create_folder_v3',
               return_value={'success': True, 'folder_uid': 'child_nsf'}) as create_folder, \
            patch('keepercommander.commands.pam_import.extend.api.sync_down'):
        uid = PAMProjectExtendCommand().create_subfolder(params, 'Child', 'users_nsf')

    assert uid == 'child_nsf'
    create_folder.assert_called_once_with(params, 'Child', parent_uid='users_nsf')


def test_create_subfolder_uses_pre_generated_uid_for_nsf():
    params = _params()

    with patch('keepercommander.commands.pam_import.extend.create_nsf_subfolder',
               return_value='pre_generated') as create_sub:
        uid = PAMProjectExtendCommand().create_subfolder(
            params, 'Child', 'users_nsf', folder_uid='pre_generated')

    assert uid == 'pre_generated'
    create_sub.assert_called_once_with(params, 'Child', 'users_nsf', folder_uid='pre_generated')


def test_process_folders_creates_new_nsf_folder_paths():
    params = _params()
    project = {
        'data': {
            'pam_data': {
                'users': [{'type': 'pamUser', 'title': 'Admin', 'login': 'admin', 'folder_path': 'NSF Project - Users/Admins'}],
                'resources': [],
            }
        },
        'options': {'dry_run': False},
        'ksm_shared_folders': [
            {'uid': 'users_nsf', 'name': 'NSF Project - Users', 'folder_tree': {}},
            {'uid': 'resources_nsf', 'name': 'NSF Project - Resources', 'folder_tree': {}},
        ],
        'folders': {},
        'error_count': 0,
    }

    with patch('keepercommander.commands.pam_import.extend.create_nsf_subfolder',
               return_value='admins_nsf') as create_sub, \
            patch('keepercommander.commands.pam_import.extend.api.sync_down'):
        folders = PAMProjectExtendCommand().process_folders(params, project)

    create_sub.assert_called_once()
    assert folders['path_to_folder_uid']['NSF Project - Users/Admins'] == 'admins_nsf'
    assert project['error_count'] == 0
