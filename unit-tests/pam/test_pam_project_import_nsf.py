from types import SimpleNamespace
from unittest.mock import patch

import keepercommander.commands.record  # noqa: F401

from keepercommander.commands.pam.vault_target import (
    execute_record_add_in_folder, execute_record_v3_add_in_folder, grant_pam_folder_permissions, is_nested_share_folder)
from keepercommander.commands.pam_import.base import PamUserObject
from keepercommander.commands.nested_share_folder.helpers import ROOT_FOLDER_UID as NSF_ROOT_FOLDER_UID
from keepercommander.commands.pam_import.edit import PAMProjectImportCommand
from keepercommander.subfolder import BaseFolderNode, NestedShareFolderNode


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
    assert add_record.call_args.kwargs == {
        'command': 'pam-project-import',
        'sync_after': False,
    }


ROOT_NAME = PAMProjectImportCommand.PAM_ROOT_FOLDER_NAME


def _synced_root_params(root_parent_uid):
    """Vault state after sync: nested_share_folders keeps the raw parent from the server,
    while prepare_folder_tree clears it on the folder_cache node for root-level NSF."""
    params = _params()
    params.nested_share_folders = {
        'wv_root': {'name': ROOT_NAME, 'parent_uid': root_parent_uid},
    }
    node = NestedShareFolderNode()
    node.uid = 'wv_root'
    node.name = ROOT_NAME
    node.parent_uid = None      # prepare_folder_tree normalized it
    node.subfolders = []
    params.folder_cache = {'wv_root': node}
    params.subfolder_cache = {
        'wv_root': {'folder_uid': 'wv_root', 'type': 'user_folder', 'name': ROOT_NAME,
                    'parent_uid': root_parent_uid, 'source': 'nested_share_folder'},
    }
    return params


def test_find_folders_matches_root_nsf_reported_with_drive_root_sentinel():
    # The server reports root-level NSF folders with the drive-root sentinel UID, which
    # is not a vault folder. Such a root must still be found - otherwise --nsf creates a
    # duplicate "PAM Environments" on every import.
    params = _synced_root_params(NSF_ROOT_FOLDER_UID)

    found = PAMProjectImportCommand().find_folders(params, '', ROOT_NAME, False)

    assert [f.uid for f in found] == ['wv_root']
    assert found[0].parent_uid is None


def test_find_folders_matches_root_nsf_when_sentinel_is_a_listed_folder():
    # Defensive: the sentinel is recognized by value, so a root is still matched even if
    # the drive root ever shows up as a real entry in the NSF caches.
    params = _synced_root_params(NSF_ROOT_FOLDER_UID)
    params.nested_share_folders[NSF_ROOT_FOLDER_UID] = {'name': 'Drive Root', 'parent_uid': None}

    found = PAMProjectImportCommand().find_folders(params, '', ROOT_NAME, False)

    assert [f.uid for f in found] == ['wv_root']


def test_find_folders_matches_root_nsf_normalized_to_root_string():
    params = _synced_root_params('root')

    found = PAMProjectImportCommand().find_folders(params, '', ROOT_NAME, False)

    assert [f.uid for f in found] == ['wv_root']


def test_find_folders_matches_root_nsf_whose_synced_parent_is_not_a_folder():
    # Any parent that resolves to no known folder is also treated as root level.
    params = _synced_root_params('SomeUnknownParentUid__')

    found = PAMProjectImportCommand().find_folders(params, '', ROOT_NAME, False)

    assert [f.uid for f in found] == ['wv_root']


def test_find_folders_matches_root_nsf_created_by_commander():
    # Commander omits parentUid on create, so the same root can also come back as None.
    params = _synced_root_params(None)

    found = PAMProjectImportCommand().find_folders(params, '', ROOT_NAME, False)

    assert [f.uid for f in found] == ['wv_root']


def test_find_folders_returns_both_root_shapes_first_wins():
    params = _synced_root_params(NSF_ROOT_FOLDER_UID)
    params.nested_share_folders['kc_root'] = {'name': ROOT_NAME, 'parent_uid': None}

    found = PAMProjectImportCommand().find_folders(params, '', ROOT_NAME, False)

    assert [f.uid for f in found] == ['wv_root', 'kc_root']


def test_find_folders_does_not_promote_a_real_nested_child_to_root():
    params = _synced_root_params(None)
    params.nested_share_folders['child'] = {'name': 'Project', 'parent_uid': 'wv_root'}

    assert PAMProjectImportCommand().find_folders(params, '', 'Project', False) == []
    child = PAMProjectImportCommand().find_folders(params, 'wv_root', 'Project', False)
    assert [f.uid for f in child] == ['child']


def test_find_folders_does_not_duplicate_a_uid_present_in_both_caches():
    params = _synced_root_params(NSF_ROOT_FOLDER_UID)
    # A user_folder node with the same UID must not yield two results.
    plain = BaseFolderNode(BaseFolderNode.UserFolderType)
    plain.uid = 'wv_root'
    plain.name = ROOT_NAME
    plain.parent_uid = None
    plain.subfolders = []
    params.folder_cache['wv_root'] = plain

    found = PAMProjectImportCommand().find_folders(params, '', ROOT_NAME, False)

    assert [f.uid for f in found] == ['wv_root']


def test_process_folders_reuses_synced_nsf_root_instead_of_creating_duplicate():
    params = _synced_root_params(NSF_ROOT_FOLDER_UID)
    project = {
        'options': {'project_name': 'BatchSmokeS', 'dry_run': False, 'use_nsf': True},
        'data': {},
        'folders': {},
    }
    created = []

    def create_folder(_params, folder_name, parent_uid=None, permissions=None, use_nsf=False):
        uid = f'new_{len(created)}'
        created.append((folder_name, parent_uid))
        _params.nested_share_folders[uid] = {'name': folder_name, 'parent_uid': parent_uid}
        return uid

    with patch.object(PAMProjectImportCommand, 'create_subfolder', side_effect=create_folder), \
            patch.object(PAMProjectImportCommand, 'get_folder_permissions', return_value=({}, [])), \
            patch.object(PAMProjectImportCommand, 'verify_users_and_teams'), \
            patch.object(PAMProjectImportCommand, 'add_folder_permissions'), \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'):
        res = PAMProjectImportCommand().process_folders(params, project)

    assert res['root_folder_uid'] == 'wv_root'
    # Only the project folder and its two leaves are created - no second PAM root.
    assert [name for name, _ in created] == [
        'BatchSmokeS', 'BatchSmokeS - Resources', 'BatchSmokeS - Users']
    assert ROOT_NAME not in [name for name, _ in created]


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

    def create_folders_batch(_params, folder_specs):
        results = []
        for spec in folder_specs:
            uid = f'nsf_{len(created) + 1}'
            created.append((spec['name'], spec.get('parent_uid'), uid))
            results.append({
                'success': True,
                'folder_uid': uid,
                'folder_key_unencrypted': b'k' * 32,
                'name': spec['name'],
            })
        return results

    with patch('keepercommander.nested_share_folder.folder_api.create_folders_batch_v3',
               side_effect=create_folders_batch) as create_batch, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'), \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        result = PAMProjectImportCommand().process_folders(params, project)

    assert result['root_folder_uid'] == 'root_nsf'
    assert result['project_folder_uid'] == 'nsf_1'
    assert result['resources_folder_uid'] == 'nsf_2'
    assert result['users_folder_uid'] == 'nsf_3'
    assert create_batch.call_count == 3
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

    def create_folders_batch(_params, folder_specs):
        results = []
        for spec in folder_specs:
            uid = f'nsf_{len(created) + 1}'
            created.append((spec['name'], spec.get('parent_uid'), uid))
            results.append({
                'success': True,
                'folder_uid': uid,
                'folder_key_unencrypted': b'k' * 32,
                'name': spec['name'],
            })
        return results

    with patch('keepercommander.nested_share_folder.folder_api.create_folders_batch_v3',
               side_effect=create_folders_batch), \
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

    def create_folders_batch(_params, folder_specs):
        return [{
            'success': True,
            'folder_uid': 'new_nsf',
            'folder_key_unencrypted': folder_key,
            'name': folder_specs[0]['name'],
        }]

    def wipe_nsf(_params):
        _params.nested_share_folders.clear()

    with patch('keepercommander.nested_share_folder.folder_api.create_folders_batch_v3',
               side_effect=create_folders_batch), \
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
            patch('keepercommander.commands.ksm.KSMCommand') as ksm_cmd, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'), \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        communicate.return_value = MagicMock(applicationSummary=[])
        result = PAMProjectImportCommand().process_ksm_app(params, project)

    assert result['app_uid'] == 'app_uid'
    # Without a project_folder_uid the legacy resources/users fallback applies,
    # batched into a single share call.
    assert ksm_cmd.return_value.execute.call_count == 1
    assert ksm_cmd.return_value.execute.call_args.kwargs['secret'] == ['res_nsf', 'usr_nsf']
    assert params.nested_share_folders['res_nsf']['folder_key_unencrypted'] == b'k' * 32


def _nsf_project_params():
    """NSF project tree: root > project > {Resources, Users, Safe > {Safe-Res, Safe-Usr}}."""
    params = _params()
    tree = {
        'proj_nsf': ('Project', 'root_nsf'),
        'res_nsf': ('Project - Resources', 'proj_nsf'),
        'usr_nsf': ('Project - Users', 'proj_nsf'),
        'safe_nsf': ('Safe A', 'proj_nsf'),
        'safe_res_nsf': ('Safe A - Resources', 'safe_nsf'),
        'safe_usr_nsf': ('Safe A - Users', 'safe_nsf'),
    }
    for uid, (name, parent) in tree.items():
        params.nested_share_folders[uid] = {
            'name': name, 'parent_uid': parent, 'folder_key_unencrypted': b'k' * 32,
        }
    return params


def test_collect_nsf_subtree_uids_walks_descendants_breadth_first():
    from keepercommander.commands.pam_import.nsf_helpers import collect_nsf_subtree_uids

    params = _nsf_project_params()
    uids = collect_nsf_subtree_uids(params, 'proj_nsf')

    assert uids[0] == 'proj_nsf'
    assert set(uids) == {'proj_nsf', 'res_nsf', 'usr_nsf', 'safe_nsf',
                         'safe_res_nsf', 'safe_usr_nsf'}
    # The global PAM root is a parent, never a descendant.
    assert 'root_nsf' not in uids
    # Parents are granted before their children.
    assert uids.index('safe_nsf') < uids.index('safe_res_nsf')


def test_collect_nsf_subtree_uids_survives_parent_cycle():
    from keepercommander.commands.pam_import.nsf_helpers import collect_nsf_subtree_uids

    params = _params()
    params.nested_share_folders['a'] = {'name': 'A', 'parent_uid': 'b'}
    params.nested_share_folders['b'] = {'name': 'B', 'parent_uid': 'a'}

    assert collect_nsf_subtree_uids(params, 'a') == ['a', 'b']
    assert collect_nsf_subtree_uids(params, '') == []


def test_process_ksm_app_nsf_grants_whole_project_subtree():
    from unittest.mock import MagicMock

    params = _nsf_project_params()
    project = {
        'options': {'project_name': 'NSF App', 'dry_run': False, 'use_nsf': True},
        'data': {},
        'folders': {
            'project_folder_uid': 'proj_nsf',
            'resources_folder_uid': 'res_nsf',
            'users_folder_uid': 'usr_nsf',
            'safe_folders': [{
                'name': 'Safe A',
                'uid': 'safe_nsf',
                'resources_subfolder_uid': 'safe_res_nsf',
                'users_subfolder_uid': 'safe_usr_nsf',
            }],
        },
    }

    with patch('keepercommander.commands.pam_import.edit.api.communicate_rest') as communicate, \
            patch.object(PAMProjectImportCommand, 'create_ksm_app', return_value='app_uid'), \
            patch('keepercommander.commands.ksm.KSMCommand') as ksm_cmd, \
            patch('keepercommander.commands.pam_import.nsf_helpers.api.sync_down'), \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        communicate.return_value = MagicMock(applicationSummary=[])
        PAMProjectImportCommand().process_ksm_app(params, project)

    assert ksm_cmd.return_value.execute.call_count == 1
    kwargs = ksm_cmd.return_value.execute.call_args.kwargs
    assert kwargs['app'] == 'app_uid'
    assert kwargs['editable'] is True
    # Project wrapper + both leaves + the safe folder and its two record subfolders.
    assert set(kwargs['secret']) == {'proj_nsf', 'res_nsf', 'usr_nsf', 'safe_nsf',
                                     'safe_res_nsf', 'safe_usr_nsf'}
    assert 'root_nsf' not in kwargs['secret']


def test_process_ksm_app_classic_grant_list_unchanged():
    from unittest.mock import MagicMock

    params = _params()
    project = {
        'options': {'project_name': 'Classic App', 'dry_run': False, 'use_nsf': False},
        'data': {},
        'folders': {
            'project_folder_uid': 'proj_sf',
            'resources_folder_uid': 'res_sf',
            'users_folder_uid': 'usr_sf',
            'safe_folders': [{
                'name': 'Safe A',
                'uid': 'safe_sf',
                'resources_subfolder_uid': 'safe_res_sf',
                'users_subfolder_uid': 'safe_usr_sf',
            }],
        },
    }

    with patch('keepercommander.commands.pam_import.edit.api.communicate_rest') as communicate, \
            patch.object(PAMProjectImportCommand, 'create_ksm_app', return_value='app_uid'), \
            patch('keepercommander.commands.pam_import.edit.KSMCommand') as ksm_cmd, \
            patch('keepercommander.commands.pam_import.edit.api.sync_down'):
        communicate.return_value = MagicMock(applicationSummary=[])
        PAMProjectImportCommand().process_ksm_app(params, project)

    # One call per UID, no project wrapper, no shared_folder_folder children.
    shared = [c.kwargs.get('secret') for c in ksm_cmd.return_value.execute.call_args_list]
    assert shared == [['res_sf'], ['usr_sf'], ['safe_sf']]


def test_grant_nsf_folders_falls_back_to_single_uid_calls():
    from keepercommander.commands.pam_import.nsf_helpers import grant_nsf_folders_to_ksm_app

    params = _nsf_project_params()
    calls = []

    class FakeKSM:
        def execute(self, _params, **kwargs):
            secret = kwargs.get('secret')
            calls.append(list(secret))
            if len(secret) > 1:
                raise Exception('batch rejected')
            if secret == ['usr_nsf']:
                raise Exception('already shared')
            return None

    with patch('keepercommander.commands.ksm.KSMCommand', FakeKSM):
        granted = grant_nsf_folders_to_ksm_app(params, 'app_uid', ['res_nsf', 'usr_nsf', 'safe_nsf'])

    assert calls[0] == ['res_nsf', 'usr_nsf', 'safe_nsf']
    assert calls[1:] == [['res_nsf'], ['usr_nsf'], ['safe_nsf']]
    # The one folder that failed is reported as not granted; the rest still land.
    assert granted == ['res_nsf', 'safe_nsf']
    # Folder keys survive the sync_down inside each share call.
    assert params.nested_share_folders['res_nsf']['folder_key_unencrypted'] == b'k' * 32


def test_grant_nsf_folders_dedups_and_ignores_empty():
    from keepercommander.commands.pam_import.nsf_helpers import grant_nsf_folders_to_ksm_app

    params = _nsf_project_params()
    calls = []

    class FakeKSM:
        def execute(self, _params, **kwargs):
            calls.append(list(kwargs.get('secret')))

    with patch('keepercommander.commands.ksm.KSMCommand', FakeKSM):
        granted = grant_nsf_folders_to_ksm_app(params, 'app_uid', ['res_nsf', '', 'res_nsf', None, 'usr_nsf'])
        assert grant_nsf_folders_to_ksm_app(params, '', ['res_nsf']) == []
        assert grant_nsf_folders_to_ksm_app(params, 'app_uid', []) == []

    assert calls == [['res_nsf', 'usr_nsf']]
    assert granted == ['res_nsf', 'usr_nsf']
