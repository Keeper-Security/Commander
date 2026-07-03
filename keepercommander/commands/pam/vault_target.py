import json
import os

from ..folder import FolderMoveCommand
from ... import api, record_management, utils, vault, vault_extensions
from ...error import CommandError
from ...proto import record_pb2
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

    if allow_legacy_user and folder_name in getattr(params, 'folder_cache', {}):
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
    return is_nested_share_folder(params, folder_uid)


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


def _find_child_folder(params, parent_uid, name=None, name_suffix=None):
    if not parent_uid:
        return None

    parent_uid = parent_uid or None
    for uid, folder in getattr(params, 'folder_cache', {}).items():
        if folder.parent_uid != parent_uid:
            continue
        folder_name = str(folder.name or '')
        if name is not None and folder_name == name:
            return uid
        if name_suffix is not None and folder_name.endswith(name_suffix):
            return uid

    for uid, folder in getattr(params, 'nested_share_folders', {}).items():
        if folder.get('parent_uid') != parent_uid:
            continue
        folder_name = str(folder.get('name', ''))
        if name is not None and folder_name == name:
            return uid
        if name_suffix is not None and folder_name.endswith(name_suffix):
            return uid

    return None


def find_nsf_users_subfolder(params, parent_uid):
    return _find_child_folder(params, parent_uid, name_suffix=' - Users')


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


def get_pam_folder_info(params, folder_uid):
    # type: (...) -> Optional[dict]
    """Return folder name, uid, and type for a PAM configuration target folder."""
    if not folder_uid:
        return None
    if folder_uid in getattr(params, 'shared_folder_cache', {}):
        sf = api.get_shared_folder(params, folder_uid)
        return {
            'uid': folder_uid,
            'name': sf.name if sf else folder_uid,
            'type': 'shared_folder',
        }
    if is_nested_share_folder(params, folder_uid):
        nsf = getattr(params, 'nested_share_folders', {}).get(folder_uid, {})
        return {
            'uid': folder_uid,
            'name': nsf.get('name', folder_uid),
            'type': 'nested_share_folder',
        }
    folder = getattr(params, 'folder_cache', {}).get(folder_uid)
    if folder:
        return {
            'uid': folder_uid,
            'name': folder.name,
            'type': 'user_folder',
        }
    return {'uid': folder_uid, 'name': folder_uid, 'type': 'unknown'}


def format_pam_folder_display(folder_info):
    # type: (Optional[dict]) -> str
    if not folder_info:
        return ''
    suffix = ' [NSF]' if folder_info.get('type') == 'nested_share_folder' else ''
    return f'{folder_info["name"]} ({folder_info["uid"]}){suffix}'


def resolve_pam_config_folder_info(params, facade, record_uid):
    # type: (...) -> Optional[dict]
    from ...subfolder import find_parent_top_folder

    folder_info = get_pam_folder_info(params, facade.folder_uid)
    if folder_info and folder_info.get('type') != 'unknown':
        return folder_info
    shared_folder_parents = find_parent_top_folder(params, record_uid)
    if shared_folder_parents:
        sf = shared_folder_parents[0]
        return {'uid': sf.uid, 'name': sf.name, 'type': 'shared_folder'}
    return folder_info


def pam_folder_json_payload(folder_info):
    # type: (Optional[dict]) -> dict
    payload = {}
    if not folder_info:
        return payload
    payload['folder'] = folder_info
    if folder_info.get('type') == 'shared_folder':
        payload['shared_folder'] = {
            'name': folder_info.get('name'),
            'uid': folder_info.get('uid'),
        }
    return payload


def record_exists_in_vault(params, record_uid):
    # type: (...) -> bool
    from ..nested_share_folder.helpers import is_nested_share_record

    if not record_uid:
        return False
    return (record_uid in getattr(params, 'record_cache', {})
            or is_nested_share_record(params, record_uid))


def resolve_pam_record(params, identifier, rec_type=None):
    # type: (...) -> Optional[vault.KeeperRecord]
    """Resolve a record by UID, folder path, or title including Nested Share Records."""
    if not identifier:
        return None

    if identifier in getattr(params, 'record_cache', {}):
        rec = vault.KeeperRecord.load(params, identifier)
        if rec and (not rec_type or rec.record_type == rec_type):
            return rec

    from ...nested_share_folder import removal_api as _nsf
    resolved_uid = _nsf.resolve_nested_share_record_uid(params, identifier)
    if resolved_uid:
        rec = vault.KeeperRecord.load(params, resolved_uid)
        if rec and (not rec_type or rec.record_type == rec_type):
            return rec

    rs = try_resolve_path(params, identifier)
    if rs is not None:
        folder, record_title = rs
        if folder is not None and record_title is not None:
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    record = vault.KeeperRecord.load(params, uid)
                    if record and record.title.casefold() == record_title.casefold():
                        if not rec_type or record.record_type == rec_type:
                            return record

    l_name = identifier.casefold()
    matches = []
    for record_uid in getattr(params, 'record_cache', {}):
        record = vault.KeeperRecord.load(params, record_uid)
        if record and record.title.casefold() == l_name:
            if not rec_type or record.record_type == rec_type:
                matches.append(record)
                if len(matches) > 1:
                    break
    if len(matches) == 1:
        return matches[0]
    return None


def get_vault_record_title_type(params, record_uid):
    # type: (...) -> tuple
    rec = vault.KeeperRecord.load(params, record_uid)
    if rec:
        return rec.title, rec.record_type
    nsf_data = getattr(params, 'nested_share_record_data', {}).get(record_uid, {})
    data_json = nsf_data.get('data_json', {}) if isinstance(nsf_data, dict) else {}
    if isinstance(data_json, dict) and data_json:
        return (data_json.get('title', '[record inaccessible]'),
                data_json.get('type', '[record inaccessible]'))
    return '[record inaccessible]', '[record inaccessible]'


def traverse_pam_folder_subtree(params, root_folder_uid, callback):
    # type: (...) -> None
    seen = set()
    queue = [root_folder_uid]
    while queue:
        f_uid = queue.pop(0)
        if not f_uid or f_uid in seen:
            continue
        seen.add(f_uid)
        callback(f_uid)
        folder = getattr(params, 'folder_cache', {}).get(f_uid)
        if folder and folder.subfolders:
            for child_uid in folder.subfolders:
                if child_uid not in seen:
                    queue.append(child_uid)
        for uid, nsf in getattr(params, 'nested_share_folders', {}).items():
            if nsf.get('parent_uid') == f_uid and uid not in seen:
                queue.append(uid)


def collect_pam_folder_uids(params, folder_name):
    # type: (...) -> set
    folder_uids = set()
    if not folder_name:
        return folder_uids

    resolved = resolve_pam_folder_uid(params, folder_name, allow_legacy_user=True)
    if resolved:
        traverse_pam_folder_subtree(params, resolved, folder_uids.add)
        return folder_uids

    rs = try_resolve_path(params, folder_name, find_all_matches=True)
    if rs is not None:
        folder, record_title = rs
        if not record_title:
            folders = folder if isinstance(folder, list) else [folder]
            for f in folders:
                if isinstance(f, BaseFolderNode) and f.uid:
                    traverse_pam_folder_subtree(params, f.uid, folder_uids.add)

    return folder_uids


def find_pam_records_by_search(params, search_str, record_version=3, record_types=None):
    # type: (...) -> list
    types = tuple(record_types) if record_types else None
    records = list(vault_extensions.find_records(
        params, search_str=search_str, record_version=record_version, record_type=types))
    if search_str and len(records) == 0:
        rec = resolve_pam_record(params, search_str)
        if isinstance(rec, vault.TypedRecord):
            if rec.version == record_version and (not types or rec.record_type in types):
                records = [rec]
    return [r for r in records if isinstance(r, vault.TypedRecord)]


def _find_child_folder_uid(params, parent_uid, name):
    return _find_child_folder(params, parent_uid, name=name)


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


def _add_record_data_to_nsf(params, data: dict, folder_uid: str,
                            record_uid: str = '', command: str = 'pam') -> str:
    """Create a Keeper Drive record directly inside a Nested Share Folder."""
    from ...nested_share_folder.common import get_folder_key
    from ...nested_share_folder.record_api import create_record_data_v3, record_add_v3

    if not folder_uid:
        raise CommandError(command, 'Nested Share Folder UID is required')

    uid = record_uid or utils.generate_uid()
    record_key = os.urandom(32)
    folder_key = get_folder_key(params, folder_uid, raise_on_missing=True)
    record_add = create_record_data_v3(
        record_uid=uid,
        record_key=record_key,
        data=data,
        folder_uid=folder_uid,
        folder_key=folder_key,
        client_modified_time=utils.current_milli_time(),
    )
    response = record_add_v3(params, [record_add])
    if not response.records:
        raise CommandError(command, 'No response from vault/records/v3/add')

    status = response.records[0]
    if status.status != record_pb2.RS_SUCCESS:
        raise CommandError(
            command,
            status.message or 'Failed to create record in Nested Share Folder',
        )

    api.sync_down(params)
    return uid


def _build_typed_record_from_add_args(params, kwargs: dict, command: str = 'pam'):
    """Build a TypedRecord from record-add style kwargs without persisting it."""
    from ..record_edit import RecordAddCommand, RecordEditMixin, RecordTypeEnforcer
    from ...recordv3 import RecordV3

    cmd = RecordAddCommand()
    title = kwargs.get('title')
    record_type = kwargs.get('record_type')
    if not title or not record_type:
        raise CommandError(command, 'Title and record type are required')

    RecordTypeEnforcer.enforce(params, record_type, command)

    fields = [field.strip() for field in kwargs.get('fields', []) if field and str(field).strip()]
    record_fields = []
    add_attachments = []
    rm_attachments = []
    for field in fields:
        parsed_field = RecordEditMixin.parse_field(field)
        if parsed_field.type == 'file':
            (add_attachments if parsed_field.value else rm_attachments).append(parsed_field)
        else:
            record_fields.append(parsed_field)

    rt_fields = cmd.get_record_type_fields(params, record_type)
    if not rt_fields:
        raise CommandError(command, f'Record type "{record_type}" cannot be found.')

    record = vault.TypedRecord()
    record.type_name = record_type
    omit_labels = (kwargs.get('labels') or 'on').lower() == 'off'
    for rf in rt_fields:
        ref = rf.get('$ref')
        if not ref:
            continue
        label = rf.get('label') or ('' if omit_labels else ref)
        required = rf.get('required', False)
        default_value = rf.get('appFillerData') if ref == 'appFiller' and 'appFillerData' in rf else None
        field = vault.TypedField.new_field(ref, default_value, label)
        if required is True:
            field.required = True
        record.fields.append(field)
    cmd.assign_typed_fields(record, record_fields)

    record_uid = str(kwargs.get('record_uid', '') or '')
    if RecordV3.is_valid_ref_uid(record_uid):
        record.record_uid = record_uid
    else:
        record.record_uid = utils.generate_uid()
    record.record_key = utils.generate_aes_key()
    record.title = title
    record.notes = cmd.validate_notes(kwargs.get('notes') or '')
    return record, add_attachments, cmd


def _create_typed_record_in_nsf(params, record, folder_uid: str, command: str = 'pam') -> str:
    data = vault_extensions.extract_typed_record_data(record)
    return _add_record_data_to_nsf(
        params, data, folder_uid,
        record_uid=record.record_uid or '',
        command=command,
    )


def place_record_in_folder(params, record_uid, folder_uid, command='pam'):
    if not folder_uid:
        raise CommandError(command, 'Target folder UID is required')

    folder_cache = getattr(params, 'folder_cache', {})
    nsf_cache = getattr(params, 'nested_share_folders', {})
    if folder_uid not in folder_cache and folder_uid not in nsf_cache:
        raise CommandError(command, f'Folder "{folder_uid}" not found')

    if is_nested_share_folder(params, folder_uid):
        raise CommandError(
            command,
            'Nested Share Folder records cannot be moved after creation — '
            'create the record directly in the target folder instead.',
        )

    FolderMoveCommand().execute(params, src=record_uid, dst=folder_uid, force=True)


def place_pam_configuration_in_folder(params, record_uid, folder_uid, command='pam'):
    """Place a PAM Configuration v6 record into *folder_uid*.

    NSF targets are created directly in-folder via
    ``vault/records/v3/add_pam_configuration`` (see
    ``pam_configuration_create_record_v6``), so no post-create move is needed.
    Legacy shared folders still use ``FolderMoveCommand``.
    """
    if not folder_uid:
        raise CommandError(command, 'Target folder UID is required')

    folder_cache = getattr(params, 'folder_cache', {})
    nsf_cache = getattr(params, 'nested_share_folders', {})
    if folder_uid not in folder_cache and folder_uid not in nsf_cache:
        raise CommandError(command, f'Folder "{folder_uid}" not found')

    if is_nested_share_folder(params, folder_uid):
        api.sync_down(params)
        return

    FolderMoveCommand().execute(params, src=record_uid, dst=folder_uid, force=True)


def create_record_in_folder(params, record, folder_uid=None, command='pam'):
    if folder_uid and is_nested_share_folder(params, folder_uid):
        return _create_typed_record_in_nsf(params, record, folder_uid, command=command)

    record_management.add_record_to_folder(params, record, folder_uid)


def execute_record_add_in_folder(params, args, folder_uid, command='pam'):
    from ..record_edit import RecordAddCommand

    record_args = dict(args or {})
    if folder_uid and is_nested_share_folder(params, folder_uid):
        record_args.pop('folder', None)
        record, add_attachments, cmd = _build_typed_record_from_add_args(
            params, record_args, command=command,
        )
        uid = _create_typed_record_in_nsf(params, record, folder_uid, command=command)
        if add_attachments:
            api.sync_down(params)
            loaded = vault.KeeperRecord.load(params, uid)
            if isinstance(loaded, vault.TypedRecord):
                cmd.upload_attachments(params, loaded, add_attachments, True)
        return uid

    record_args['folder'] = folder_uid
    return RecordAddCommand().execute(params, **record_args)


def execute_record_v3_add_in_folder(params, args, folder_uid, command='pam'):
    from ..recordv3 import RecordAddCommand

    record_args = dict(args or {})
    if folder_uid and is_nested_share_folder(params, folder_uid):
        record_args.pop('folder', None)
        data_str = record_args.get('data')
        if not data_str:
            raise CommandError(command, 'Record data is required for Nested Share Folder import')

        data = json.loads(data_str)
        record_uid = str(record_args.get('record_uid') or data.get('uid') or '')
        uid = _add_record_data_to_nsf(
            params, data, folder_uid,
            record_uid=record_uid,
            command=command,
        )
        if not uid:
            raise CommandError(command, 'Record creation failed for Nested Share Folder target')
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
