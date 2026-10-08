from types import SimpleNamespace
from unittest.mock import patch

import keepercommander.commands.record  # noqa: F401

from keepercommander.commands.pam_import.extend import (
    PAMProjectExtendCommand,
    _drop_folder_paths,
    _resolve_folder_option,
)
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


def _extend_project(dry_run=False, ksm_app_uid='ksm_app_uid', folder_path='NSF Project - Users/Admins',
                    shared_folders=None):
    return {
        'data': {
            'pam_data': {
                'users': [{'type': 'pamUser', 'title': 'Admin', 'login': 'admin',
                           'folder_path': folder_path}],
                'resources': [],
            }
        },
        'options': {'dry_run': dry_run},
        'ksm_app_uid': ksm_app_uid,
        'ksm_shared_folders': shared_folders if shared_folders is not None else [
            {'uid': 'users_nsf', 'name': 'NSF Project - Users', 'folder_tree': {}},
            {'uid': 'resources_nsf', 'name': 'NSF Project - Resources', 'folder_tree': {}},
        ],
        'folders': {},
        'error_count': 0,
    }


def _seeding_nsf_create(params, new_uid, parent_uid):
    """Stand-in for create_nsf_subfolder that also seeds the NSF cache, as the real one does."""
    def _create(_params, name, _parent_uid='', folder_uid=None):
        uid = folder_uid or new_uid
        params.nested_share_folders[uid] = {
            'name': name, 'parent_uid': parent_uid, 'folder_key_unencrypted': b'k' * 32,
        }
        return uid
    return _create


def test_process_folders_registers_new_nsf_child_on_ksm_app(capsys):
    params = _params()
    project = _extend_project()

    with patch('keepercommander.commands.pam_import.extend.create_nsf_subfolder',
               side_effect=_seeding_nsf_create(params, 'admins_nsf', 'users_nsf')), \
            patch('keepercommander.commands.pam_import.extend.grant_nsf_folders_to_ksm_app',
                  side_effect=lambda _p, _a, uids, **_kw: list(uids)) as grant, \
            patch('keepercommander.commands.pam_import.extend.sync_down_preserving_nsf_keys') as nsf_sync, \
            patch('keepercommander.commands.pam_import.extend.api.sync_down') as plain_sync:
        folders = PAMProjectExtendCommand().process_folders(params, project)

    # The folder UID is pre-generated before creation, so grant the UID that was used.
    new_uid = folders['path_to_folder_uid']['NSF Project - Users/Admins']
    grant.assert_called_once()
    args, kwargs = grant.call_args
    assert args[1] == 'ksm_app_uid'
    assert args[2] == [new_uid]
    assert kwargs['editable'] is True
    # NSF keys must survive the post-create sync so the grant can use them.
    nsf_sync.assert_called_once_with(params)
    plain_sync.assert_not_called()
    assert 'Registered 1 of 1 new Nested Share Folder(s)' in capsys.readouterr().out


def test_process_folders_warns_when_a_folder_could_not_be_registered(capsys):
    params = _params()
    project = _extend_project()

    with patch('keepercommander.commands.pam_import.extend.create_nsf_subfolder',
               side_effect=_seeding_nsf_create(params, 'admins_nsf', 'users_nsf')), \
            patch('keepercommander.commands.pam_import.extend.grant_nsf_folders_to_ksm_app',
                  return_value=[]), \
            patch('keepercommander.commands.pam_import.extend.sync_down_preserving_nsf_keys'), \
            patch('keepercommander.commands.pam_import.extend.api.sync_down'), \
            patch('keepercommander.commands.pam_import.extend.logging.warning') as warn:
        PAMProjectExtendCommand().process_folders(params, project)

    assert 'Registered 0 of 1 new Nested Share Folder(s)' in capsys.readouterr().out
    assert any('not be visible to the Gateway' in str(c.args[0]) for c in warn.call_args_list)


def test_process_folders_classic_child_is_not_registered():
    params = _params()
    # Classic shared folder root - children inherit the folder key, nothing to grant.
    params.folder_cache['classic_sf'] = _folder('classic_sf', 'Classic Project')
    params.folder_cache['classic_sf'].type = BaseFolderNode.SharedFolderType
    params.shared_folder_cache['classic_sf'] = {'name_unencrypted': 'Classic Project'}
    project = _extend_project(folder_path='Classic Project/Admins',
                              shared_folders=[{'uid': 'classic_sf', 'name': 'Classic Project',
                                               'folder_tree': {}}])

    with patch.object(PAMProjectExtendCommand, 'create_subfolder', return_value='admins_sf'), \
            patch('keepercommander.commands.pam_import.extend.grant_nsf_folders_to_ksm_app') as grant, \
            patch('keepercommander.commands.pam_import.extend.sync_down_preserving_nsf_keys') as nsf_sync, \
            patch('keepercommander.commands.pam_import.extend.api.sync_down') as plain_sync:
        PAMProjectExtendCommand().process_folders(params, project)

    grant.assert_not_called()
    nsf_sync.assert_not_called()
    plain_sync.assert_called_once_with(params)


def test_process_folders_warns_when_ksm_app_uid_missing():
    params = _params()
    project = _extend_project(ksm_app_uid='')

    with patch('keepercommander.commands.pam_import.extend.create_nsf_subfolder',
               side_effect=_seeding_nsf_create(params, 'admins_nsf', 'users_nsf')), \
            patch('keepercommander.commands.pam_import.extend.grant_nsf_folders_to_ksm_app') as grant, \
            patch('keepercommander.commands.pam_import.extend.sync_down_preserving_nsf_keys'), \
            patch('keepercommander.commands.pam_import.extend.api.sync_down'), \
            patch('keepercommander.commands.pam_import.extend.logging.warning') as warn:
        PAMProjectExtendCommand().process_folders(params, project)

    grant.assert_not_called()
    assert any('not registered' in str(c.args[0]) for c in warn.call_args_list)


def test_process_folders_dry_run_reports_nsf_registration_without_calling_api(capsys):
    params = _params()
    project = _extend_project(dry_run=True)

    with patch('keepercommander.commands.pam_import.extend.create_nsf_subfolder') as create_sub, \
            patch('keepercommander.commands.pam_import.extend.grant_nsf_folders_to_ksm_app') as grant, \
            patch('keepercommander.commands.pam_import.extend.api.sync_down'):
        PAMProjectExtendCommand().process_folders(params, project)

    create_sub.assert_not_called()
    grant.assert_not_called()
    out = capsys.readouterr().out
    assert 'would be registered on KSM Application ksm_app_uid' in out
    assert 'NSF Project - Users/Admins' in out


def test_nsf_paths_to_be_created_classifies_nested_new_paths():
    params = _params()
    new_nodes = [
        ('NSF Project - Users/Admins/Tier2', 'NSF Project - Users/Admins', 'Tier2', {'uid': 'b'}),
        ('NSF Project - Users/Admins', 'NSF Project - Users', 'Admins', {'uid': 'a'}),
        ('Classic Project/Ops', 'Classic Project', 'Ops', {'uid': 'c'}),
    ]
    path_to_uid = {
        'NSF Project - Users': 'users_nsf',
        'NSF Project - Users/Admins': 'a',
        'NSF Project - Users/Admins/Tier2': 'b',
        'Classic Project': 'classic_sf',
    }
    shared_folders = [{'uid': 'users_nsf', 'name': 'NSF Project - Users'},
                      {'uid': 'classic_sf', 'name': 'Classic Project'}]

    paths = PAMProjectExtendCommand._nsf_paths_to_be_created(
        params, new_nodes, path_to_uid, shared_folders)

    # A new child of a new NSF folder is still NSF even though its UID does not exist yet.
    assert paths == ['NSF Project - Users/Admins', 'NSF Project - Users/Admins/Tier2']


# --- autodetect_folders (KC-1491) ---

def _shf(uid, name, folder_tree=None):
    return {'uid': uid, 'name': name, 'folder_tree': folder_tree or {}}


def _new_project(shared_folders, resources=1, users=1, folders=None):
    mapped_resources = [SimpleNamespace(type='pamDatabase', title=f'DB{i}', folder_path='',
                                        _extend_tag='new', users=[]) for i in range(resources)]
    mapped_users = [SimpleNamespace(type='pamUser', title=f'U{i}', folder_path='',
                                    _extend_tag='new') for i in range(users)]
    return {
        'ksm_shared_folders': shared_folders,
        'mapped_resources': mapped_resources,
        'mapped_users': mapped_users,
        'folders': folders if folders is not None else {},
        'error_count': 0,
    }


def _autodetect(project, types_by_folder):
    """Run autodetect_folders with records faked as (uid, title, type, login) 4-tuples per folder uid."""
    def fake_records(_params, folder_uid):
        return [(f'{folder_uid}-{i}', 'title', rtype, '') for i, rtype in enumerate(types_by_folder.get(folder_uid, []))]

    with patch('keepercommander.commands.pam_import.extend._get_records_in_folder', side_effect=fake_records):
        return PAMProjectExtendCommand().autodetect_folders(SimpleNamespace(), project)


def test_autodetect_uses_resources_and_users_folder_names():
    project = _new_project([_shf('u', 'Proj - Users'), _shf('r', 'Proj - Resources')])

    assert _autodetect(project, {}) == []
    assert project['folders'] == {'resources_folder_uid': 'r', 'users_folder_uid': 'u'}


def test_autodetect_finds_folders_from_existing_records():
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta')])

    assert _autodetect(project, {'a': ['pamMachine'], 'b': ['pamUser']}) == []
    assert project['folders'] == {'resources_folder_uid': 'a', 'users_folder_uid': 'b'}


def test_autodetect_looks_into_subfolders_of_shared_folder():
    tree = {'Prod': {'uid': 'a_prod', 'name': 'Prod', 'subfolders': {}}}
    project = _new_project([_shf('a', 'Alpha', tree), _shf('b', 'Beta')])

    assert _autodetect(project, {'a_prod': ['pamDirectory'], 'b': ['login']}) == []
    assert project['folders'] == {'resources_folder_uid': 'a', 'users_folder_uid': 'b'}


def test_autodetect_does_not_put_resources_into_the_only_non_empty_users_folder(capsys):
    # KC-1491: Resources folder is empty, Users folder holds the admin pamUser.
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta')], users=0)

    errors = _autodetect(project, {'b': ['pamUser']})

    assert len(errors) == 1
    assert 'resources folder' in errors[0] and '--resources-folder' in errors[0]
    assert project['folders'] == {}
    assert project['error_count'] == 1
    assert 'Total: 1 errors' in capsys.readouterr().out


def test_autodetect_errors_on_single_shared_folder_without_resource_records():
    project = _new_project([_shf('u', 'Only Users')], users=0)

    assert len(_autodetect(project, {'u': ['pamUser']})) == 1
    assert project['folders'] == {}


def test_autodetect_errors_when_resources_live_in_several_folders():
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta'), _shf('c', 'Gamma')], users=0)

    errors = _autodetect(project, {'a': ['pamMachine'], 'b': ['pamDatabase']})

    assert len(errors) == 1
    assert 'multiple folders' in errors[0] and '"Alpha"' in errors[0] and '"Beta"' in errors[0]
    assert project['folders'] == {}


def test_autodetect_reports_both_roles_when_both_are_unknown():
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta'), _shf('c', 'Gamma')])

    assert len(_autodetect(project, {})) == 2
    assert project['error_count'] == 2


def test_autodetect_keeps_roles_already_set_by_command_line():
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta'), _shf('c', 'Gamma')],
                           folders={'resources_folder_uid': 'a', 'users_folder_uid': 'b'})

    assert _autodetect(project, {}) == []
    assert project['folders'] == {'resources_folder_uid': 'a', 'users_folder_uid': 'b'}


def test_autodetect_only_detects_the_missing_role():
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta'), _shf('c', 'Gamma')],
                           folders={'resources_folder_uid': 'a'})

    assert _autodetect(project, {'c': ['pamUser']}) == []
    assert project['folders'] == {'resources_folder_uid': 'a', 'users_folder_uid': 'c'}


def test_autodetect_ignores_roles_with_no_new_records():
    # Only resources are new, so an undetectable users folder is not an error.
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta'), _shf('c', 'Gamma')], users=0)

    assert _autodetect(project, {'a': ['pamMachine']}) == []
    assert project['folders'] == {'resources_folder_uid': 'a'}


def test_autodetect_skips_records_with_folder_path_and_existing_records():
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta'), _shf('c', 'Gamma')])
    for o in project['mapped_resources']:
        o.folder_path = 'Alpha/Sub'
    for o in project['mapped_users']:
        o._extend_tag = 'existing'

    assert _autodetect(project, {}) == []
    assert project['folders'] == {}


def test_autodetect_nested_new_users_need_users_folder():
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta'), _shf('c', 'Gamma')], users=0)
    project['mapped_resources'][0].users = [SimpleNamespace(type='pamUser', title='N', folder_path='',
                                                            _extend_tag='new')]

    assert _autodetect(project, {'a': ['pamMachine'], 'b': ['pamUser']}) == []
    assert project['folders'] == {'resources_folder_uid': 'a', 'users_folder_uid': 'b'}


def test_autodetect_warns_when_both_roles_share_one_folder(capsys):
    project = _new_project([_shf('a', 'Alpha'), _shf('b', 'Beta')])

    assert _autodetect(project, {'a': ['pamMachine', 'pamUser']}) == []
    assert project['folders'] == {'resources_folder_uid': 'a', 'users_folder_uid': 'a'}
    assert 'same folder "Alpha"' in capsys.readouterr().out


# --- --resources-folder / --users-folder (KC-1491) ---

def test_resolve_folder_option_accepts_uid_and_path():
    tree = {'Prod': {'uid': 'prod_uid', 'name': 'Prod', 'subfolders': {
        'Db': {'uid': 'db_uid', 'name': 'Db', 'subfolders': {}}}}}
    shared = [_shf('root_uid', 'Proj - Resources', tree)]

    assert _resolve_folder_option('root_uid', shared) == 'root_uid'
    assert _resolve_folder_option('prod_uid', shared) == 'prod_uid'
    assert _resolve_folder_option('Proj - Resources', shared) == 'root_uid'
    assert _resolve_folder_option('Proj - Resources/Prod/Db', shared) == 'db_uid'
    assert _resolve_folder_option('  Proj - Resources/Prod  ', shared) == 'prod_uid'


def test_resolve_folder_option_rejects_unknown_or_empty():
    shared = [_shf('root_uid', 'Proj - Resources')]

    assert _resolve_folder_option('', shared) == ''
    assert _resolve_folder_option('nope', shared) == ''
    assert _resolve_folder_option('Proj - Resources/New', shared) == ''


def _pam_data():
    return {
        'resources': [
            {'title': 'R1', 'folder_path': 'A/res',
             'users': [{'title': 'N1', 'folder_path': 'A/usr'}, {'title': 'N2'}]},
            {'title': 'R2'},
        ],
        'users': [{'title': 'U1', 'folder_path': 'A/usr'}, {'title': 'U2'}],
    }


def test_drop_folder_paths_resources_only():
    pam_data = _pam_data()

    assert _drop_folder_paths(pam_data, True, False) == 1
    assert 'folder_path' not in pam_data['resources'][0]
    assert pam_data['resources'][0]['users'][0]['folder_path'] == 'A/usr'
    assert pam_data['users'][0]['folder_path'] == 'A/usr'


def test_drop_folder_paths_users_only_covers_nested_users():
    pam_data = _pam_data()

    assert _drop_folder_paths(pam_data, False, True) == 2
    assert pam_data['resources'][0]['folder_path'] == 'A/res'
    assert 'folder_path' not in pam_data['resources'][0]['users'][0]
    assert 'folder_path' not in pam_data['users'][0]


def test_extend_parser_accepts_folder_overrides():
    args = PAMProjectExtendCommand.parser.parse_args(
        ['--config', 'c', '--filename', 'f', '--resources-folder', 'R', '--users-folder', 'U'])

    assert (args.resources_folder, args.users_folder) == ('R', 'U')
    assert PAMProjectExtendCommand.parser.parse_args(['-c', 'c', '-f', 'f']).resources_folder == ''
