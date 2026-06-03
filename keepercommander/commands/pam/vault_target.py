import json
import os

from ..folder import FolderMoveCommand
from ... import api, record_management, utils, vault, vault_extensions
from ...error import CommandError
from ...proto import record_pb2
from ...subfolder import BaseFolderNode, get_folder_path, try_resolve_path


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
