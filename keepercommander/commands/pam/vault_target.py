from ..folder import FolderMoveCommand
from ... import api, record_management, vault
from ...error import CommandError
from ...nested_share_folder.folder_record_api import move_record_v3
from ...subfolder import BaseFolderNode, get_folder_path, try_resolve_path
from .config_facades import PamConfigurationRecordFacade


def is_nested_share_folder(params, folder_uid):
    if not folder_uid:
        return False

    if folder_uid in getattr(params, 'nested_share_folders', {}):
        return True

    subfolder = getattr(params, 'subfolder_cache', {}).get(folder_uid)
    if isinstance(subfolder, dict) and subfolder.get('source') == 'nested_share_folder':
        return True

    folder = getattr(params, 'folder_cache', {}).get(folder_uid)
    return bool(folder and getattr(folder, 'type', None) == BaseFolderNode.NestedShareFolderType)


def resolve_pam_folder_uid(params, folder_name, allow_legacy_user=False):
    if not folder_name:
        return None

    if folder_name in getattr(params, 'shared_folder_cache', {}):
        return folder_name

    if is_nested_share_folder(params, folder_name):
        return folder_name

    rs = try_resolve_path(params, folder_name)
    if rs:
        folder, remainder = rs
        if folder and not remainder and folder.uid:
            if (folder.type == BaseFolderNode.SharedFolderType
                    or (allow_legacy_user and folder.uid in getattr(params, 'folder_cache', {}))
                    or is_nested_share_folder(params, folder.uid)):
                return folder.uid

    nsf_matches = [
        uid for uid, folder in getattr(params, 'nested_share_folders', {}).items()
        if str(folder.get('name', '')).casefold() == str(folder_name).casefold()
    ]
    if len(nsf_matches) == 1:
        return nsf_matches[0]

    return None


def pam_folder_exists(params, folder_uid):
    if not folder_uid:
        return False
    if folder_uid in getattr(params, 'folder_cache', {}):
        return True
    if folder_uid in getattr(params, 'nested_share_folders', {}):
        return True
    subfolder = getattr(params, 'subfolder_cache', {}).get(folder_uid)
    return isinstance(subfolder, dict) and subfolder.get('source') == 'nested_share_folder'


def get_pam_folder_path(params, folder_uid, delimiter='/'):
    if not folder_uid:
        return ''

    parts = []
    uid = folder_uid
    seen = set()
    while uid and uid not in seen:
        seen.add(uid)
        folder = getattr(params, 'folder_cache', {}).get(uid)
        if folder is not None:
            name = str(folder.name or '').replace(delimiter, delimiter * 2)
            parts.insert(0, name)
            uid = folder.parent_uid
            continue

        nsf = getattr(params, 'nested_share_folders', {}).get(uid)
        if nsf:
            name = str(nsf.get('name', '')).replace(delimiter, delimiter * 2)
            parts.insert(0, name)
            uid = nsf.get('parent_uid')
            continue
        break

    if parts:
        return delimiter.join(parts)
    return get_folder_path(params, folder_uid, delimiter=delimiter)


def resolve_pam_application_folder(params, pam_config_uid, command='pam'):
    pam_config_record = vault.KeeperRecord.load(params, pam_config_uid)
    if not pam_config_record:
        raise CommandError(command, f'PAM Configuration not found: {pam_config_uid}')

    facade = PamConfigurationRecordFacade()
    facade.record = pam_config_record
    facade.load_typed_fields()
    folder_uid = facade.folder_uid
    if not folder_uid:
        raise CommandError(
            command,
            f"PAM Configuration '{pam_config_record.title}' has no application folder configured.\n"
            f'Please configure the application folder in the PAM Configuration record.')

    if not pam_folder_exists(params, folder_uid):
        raise CommandError(
            command,
            f'Application folder (UID: {folder_uid}) not found in vault.\n'
            f'Ensure the folder is shared with you.')

    return folder_uid, get_pam_folder_path(params, folder_uid)


def find_nsf_users_subfolder(params, parent_uid):
    if not parent_uid:
        return None

    for uid, folder in getattr(params, 'nested_share_folders', {}).items():
        if folder.get('parent_uid') == parent_uid and str(folder.get('name', '')).endswith(' - Users'):
            return uid

    for uid, folder in getattr(params, 'folder_cache', {}).items():
        if folder.parent_uid == parent_uid and str(folder.name or '').endswith(' - Users'):
            return uid

    return None


def records_in_folder(params, folder_uid):
    records = set(getattr(params, 'subfolder_record_cache', {}).get(folder_uid, set()) or set())
    nsf_records = getattr(params, 'nested_share_folder_records', {})
    if folder_uid in nsf_records:
        records.update(nsf_records[folder_uid])
    return records


def resolve_provision_target_folder(params, pam_config_uid, folder_spec=None, department='Default',
                                      command='pam'):
    app_uid, app_path = resolve_pam_application_folder(params, pam_config_uid, command=command)

    if folder_spec:
        folder_spec = str(folder_spec).strip()
        resolved = resolve_pam_folder_uid(params, folder_spec, allow_legacy_user=True)
        if resolved:
            return resolved
        if folder_spec in getattr(params, 'shared_folder_cache', {}):
            return folder_spec
        relative = folder_spec.strip('/')
        if is_nested_share_folder(params, app_uid):
            return ensure_pam_folder_path(params, app_uid, relative, command=command)
        if app_path:
            return _ensure_legacy_folder_path(params, f'{app_path}/{relative}', command=command)
        return _ensure_legacy_folder_path(params, relative, command=command)

    if is_nested_share_folder(params, app_uid):
        users_uid = find_nsf_users_subfolder(params, app_uid)
        if users_uid:
            return users_uid
        return ensure_pam_folder_path(params, app_uid, f'PAM Users/{department}', command=command)

    target_path = f'{app_path}/PAM Users/{department}' if app_path else f'PAM Users/{department}'
    return _ensure_legacy_folder_path(params, target_path, command=command)


def resolve_access_user_save_folder(params, config_uid, folder_spec=None, command='pam-access-user-provision'):
    if folder_spec:
        folder_uid = resolve_pam_folder_uid(params, folder_spec, allow_legacy_user=True)
        if not folder_uid:
            raise CommandError(command, f'Folder not found: {folder_spec}')
        return folder_uid

    app_uid, _ = resolve_pam_application_folder(params, config_uid, command=command)
    if is_nested_share_folder(params, app_uid):
        return find_nsf_users_subfolder(params, app_uid) or app_uid
    return app_uid


def _ensure_legacy_folder_path(params, folder_path, command='pam'):
    folder_uid = None
    rs = try_resolve_path(params, folder_path)
    if rs:
        folder_node, remainder = rs
        if folder_node and not remainder:
            folder_uid = folder_node.uid

    if folder_uid:
        return folder_uid

    from ..folder import FolderMakeCommand
    components = [x.strip() for x in str(folder_path or '').replace('\\', '/').split('/') if x.strip()]
    current_path = ''
    for i, component in enumerate(components):
        current_path = f'{current_path}/{component}' if current_path else component
        rs = try_resolve_path(params, current_path)
        if rs and rs[0] and not rs[1]:
            continue
        FolderMakeCommand().execute(
            params,
            folder=current_path,
            shared_folder=(i == 0),
            user_folder=(i != 0),
        )
        api.sync_down(params)

    rs = try_resolve_path(params, folder_path)
    if rs and rs[0] and not rs[1]:
        return rs[0].uid
    raise CommandError(command, f'Folder path creation succeeded but final UID not found: {folder_path}')


def _find_child_folder_uid(params, parent_uid, name):
    parent_uid = parent_uid or None
    for uid, folder in getattr(params, 'folder_cache', {}).items():
        if folder.parent_uid == parent_uid and folder.name == name:
            return uid

    for uid, folder in getattr(params, 'nested_share_folders', {}).items():
        if folder.get('parent_uid') == parent_uid and folder.get('name') == name:
            return uid

    return None


def ensure_pam_folder_path(params, base_folder_uid, relative_path, command='pam'):
    if not base_folder_uid:
        raise CommandError(command, 'Base folder UID is required')

    if base_folder_uid not in getattr(params, 'folder_cache', {}) \
            and base_folder_uid not in getattr(params, 'nested_share_folders', {}):
        raise CommandError(command, f'Base folder "{base_folder_uid}" not found')

    components = [x.strip() for x in str(relative_path or '').replace('\\', '/').split('/') if x.strip()]
    current_uid = base_folder_uid
    if not components:
        return current_uid

    for component in components:
        child_uid = _find_child_folder_uid(params, current_uid, component)
        if child_uid:
            current_uid = child_uid
            continue

        if is_nested_share_folder(params, current_uid):
            from ...nested_share_folder.folder_api import create_folder_v3
            result = create_folder_v3(params, component, parent_uid=current_uid)
            if isinstance(result, dict) and result.get('success') is False:
                raise CommandError(command, result.get('message') or 'Failed to create Nested Share Folder')
            current_uid = result.get('folder_uid') if isinstance(result, dict) else None
            api.sync_down(params)
        else:
            from ..folder import FolderMakeCommand
            parent_path = get_folder_path(params, current_uid)
            folder_path = f'{parent_path}{component}' if parent_path else component
            FolderMakeCommand().execute(params, folder=folder_path, user_folder=True)
            api.sync_down(params)
            current_uid = _find_child_folder_uid(params, current_uid, component)

        if not current_uid:
            raise CommandError(command, f'Folder creation succeeded but UID not found: {component}')

    return current_uid


def place_record_in_folder(params, record_uid, folder_uid, command='pam'):
    if not folder_uid:
        raise CommandError(command, 'Target folder UID is required')

    folder_cache = getattr(params, 'folder_cache', {})
    nsf_cache = getattr(params, 'nested_share_folders', {})
    if folder_uid not in folder_cache and folder_uid not in nsf_cache:
        raise CommandError(command, f'Folder "{folder_uid}" not found')

    if is_nested_share_folder(params, folder_uid):
        result = move_record_v3(params, record_uid, to_folder_uid=folder_uid)
        if isinstance(result, dict) and result.get('success') is False:
            raise CommandError(command, result.get('message') or 'Failed to place record in Nested Share Folder')
        api.sync_down(params)
    else:
        FolderMoveCommand().execute(params, src=record_uid, dst=folder_uid, force=True)


def create_record_in_folder(params, record, folder_uid=None, command='pam'):
    if folder_uid and is_nested_share_folder(params, folder_uid):
        record_management.add_record_to_folder(params, record)
        place_record_in_folder(params, record.record_uid, folder_uid, command=command)
    else:
        record_management.add_record_to_folder(params, record, folder_uid)


def execute_record_add_in_folder(params, args, folder_uid, command='pam'):
    from ..record_edit import RecordAddCommand

    record_args = dict(args or {})
    if folder_uid and is_nested_share_folder(params, folder_uid):
        record_args.pop('folder', None)
        uid = RecordAddCommand().execute(params, **record_args)
        if uid and isinstance(uid, str):
            place_record_in_folder(params, uid, folder_uid, command=command)
        return uid

    record_args['folder'] = folder_uid
    return RecordAddCommand().execute(params, **record_args)


def execute_record_v3_add_in_folder(params, args, folder_uid, command='pam'):
    from ..recordv3 import RecordAddCommand

    record_args = dict(args or {})
    if folder_uid and is_nested_share_folder(params, folder_uid):
        record_args.pop('folder', None)
        uid = RecordAddCommand().execute(params, **record_args)
        if not uid:
            raise CommandError(command, 'Record creation failed for Nested Share Folder target')
        place_record_in_folder(params, uid, folder_uid, command=command)
        return uid

    record_args['folder'] = folder_uid
    return RecordAddCommand().execute(params, **record_args)


def grant_pam_folder_permissions(params, folder_uid, permissions, command='pam'):
    if not permissions:
        return
    if not is_nested_share_folder(params, folder_uid):
        return

    from ..nested_share_folder.helpers import classify_share_recipient
    from ...nested_share_folder.folder_api import grant_folder_access_v3

    for perm in permissions:
        if not any(map(lambda x: x is not None, perm.values())):
            continue
        recipient = perm.get('name') or perm.get('uid')
        if not recipient:
            continue

        classified = classify_share_recipient(params, recipient)
        if not classified:
            continue

        kind, identifier = classified
        manage_users = bool(perm.get('manage_users'))
        manage_records = bool(perm.get('manage_records'))
        if manage_users and manage_records:
            role = 'full-manager'
        elif manage_records:
            role = 'content-manager'
        elif manage_users:
            role = 'share-manager'
        else:
            role = 'viewer'

        result = grant_folder_access_v3(
            params,
            folder_uid,
            identifier,
            role=role,
            as_team=kind == 'team',
        )
        if isinstance(result, dict) and result.get('success') is False:
            raise CommandError(command, result.get('message') or 'Failed to grant Nested Share Folder access')
