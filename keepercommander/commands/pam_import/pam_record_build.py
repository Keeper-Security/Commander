"""Build vault.TypedRecord / RecordAdd protobuf from PAM import objects (batch Step 1a)."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Set, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .deferred_refs import DeferredChannelAUpdate, DeferredRefUpdate

from ... import vault, utils
from ...recordv3 import RecordV3
from ..record_edit import RecordAddCommand as RecordEditAddCommand
from .base import (
    append_custom_text_fields,
    LoginUserObject,
    PamCloudResourceObject,
    PamAttachmentObject,
    PamAttachmentsObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamRemoteBrowserSettings,
    PamSettingsFieldData,
    PamUserObject,
)

PamObject = Union[
    LoginUserObject,
    PamUserObject,
    PamMachineObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamRemoteBrowserObject,
]

_EMBEDDED_REF_PATHS = (
    ('userRecords',),
    ('sftp', 'sftpResourceUid'),
    ('sftp', 'sftpUserUid'),
    ('httpCredentialsUid',),
)


def build_record_add_kwargs(obj: PamObject, folder_uid: str) -> Dict[str, Any]:
    """Build RecordEditAddCommand kwargs mirroring Pam*Object.create_record()."""
    if isinstance(obj, PamUserObject):
        return _pam_user_kwargs(obj, folder_uid)
    if isinstance(obj, LoginUserObject):
        return _login_user_kwargs(obj, folder_uid)
    if isinstance(obj, PamRemoteBrowserObject):
        return _rbi_kwargs(obj, folder_uid)
    if isinstance(obj, (PamMachineObject, PamDatabaseObject, PamDirectoryObject)):
        return _machine_kwargs(obj, folder_uid)
    raise TypeError(f'Unsupported PAM object type: {type(obj).__name__}')


def _base_kwargs(obj: PamObject, folder_uid: str, record_type: str) -> Dict[str, Any]:
    args: Dict[str, Any] = {
        'force': True,
        'folder': folder_uid,
        'record_type': record_type,
    }
    if obj.uid:
        args['record_uid'] = obj.uid
    if getattr(obj, 'title', None):
        args['title'] = obj.title
    if getattr(obj, 'notes', None):
        args['notes'] = obj.notes
    return args


def _attachment_fields(obj: PamObject) -> List[str]:
    fields: List[str] = []
    attachments = getattr(obj, 'attachments', None)
    files = attachments.attachments if attachments and isinstance(attachments, PamAttachmentsObject) else []
    if files and isinstance(files, list):
        for item in files:
            if item and isinstance(item, PamAttachmentObject) and item.file:
                fields.append(f'file=@{item.file}')
    return fields


def _pam_settings_json(
    obj: PamObject,
    *,
    inserted_uids: Set[str],
    deferred_out: Optional[List['DeferredRefUpdate']] = None,
) -> Optional[str]:
    from .deferred_refs import collect_connection_deferrals

    ps = getattr(obj, 'pam_settings', None)
    if not ps or not isinstance(ps, PamSettingsFieldData):
        return None
    allow_supply = True if ps.allowSupplyHost is True else False
    port_forward = ps.portForward.to_record_dict() if ps.portForward else {}
    connection = ps.connection.to_record_dict() if ps.connection else {}
    if deferred_out is not None and obj.uid:
        connection = collect_connection_deferrals(
            obj.uid, 'pamSettings', connection, inserted_uids, deferred_out,
        )
    else:
        connection, port_forward = _strip_connection_embedded_refs(
            connection, port_forward, inserted_uids,
        )
    if not (port_forward or connection or allow_supply):
        return None
    val = json.dumps({
        'allowSupplyHost': allow_supply,
        'portForward': port_forward or {},
        'connection': connection or {},
    })
    return f'c.pamSettings=$JSON:{val}'


def _rbi_settings_json(
    obj: PamRemoteBrowserObject,
    *,
    inserted_uids: Set[str],
    deferred_out: Optional[List['DeferredRefUpdate']] = None,
) -> Optional[str]:
    from .deferred_refs import collect_connection_deferrals

    connection: dict = {}
    if obj.rbi_settings and isinstance(obj.rbi_settings, PamRemoteBrowserSettings):
        if obj.rbi_settings.connection:
            connection = dict(obj.rbi_settings.connection.to_record_dict() or {})
    if deferred_out is not None and obj.uid:
        connection = collect_connection_deferrals(
            obj.uid, 'pamRemoteBrowserSettings', connection, inserted_uids, deferred_out,
        )
    else:
        connection, _ = _strip_connection_embedded_refs(connection, {}, inserted_uids)
    if not connection:
        return None
    val = json.dumps({'connection': connection})
    return f'pamRemoteBrowserSettings=$JSON:{val}'


def _strip_connection_embedded_refs(
    connection: dict,
    port_forward: dict,
    inserted_uids: Set[str],
) -> tuple:
    connection = dict(connection or {})
    port_forward = dict(port_forward or {})
    if 'userRecords' in connection:
        refs = connection.get('userRecords') or []
        if refs and not all(r in inserted_uids for r in refs):
            connection.pop('userRecords', None)
    sftp = connection.get('sftp')
    if isinstance(sftp, dict):
        sftp = dict(sftp)
        for key in ('sftpResourceUid', 'sftpUserUid'):
            uid = sftp.get(key)
            if uid and uid not in inserted_uids:
                sftp.pop(key, None)
        if sftp:
            connection['sftp'] = sftp
        elif 'sftp' in connection:
            connection.pop('sftp', None)
    hc = connection.get('httpCredentialsUid')
    if hc:
        hc_uids = hc if isinstance(hc, list) else [hc]
        if any(
            isinstance(u, str) and u and u not in inserted_uids
            for u in hc_uids
        ):
            connection.pop('httpCredentialsUid', None)
    return connection, port_forward


def _pam_user_kwargs(obj: PamUserObject, folder_uid: str) -> Dict[str, Any]:
    args = _base_kwargs(obj, folder_uid, obj.type)
    fields: List[str] = []
    if obj.login:
        fields.append(f'f.login={obj.login}')
    if obj.password:
        fields.append(f'f.password={obj.password}')
    if obj.privatePEMKey:
        fields.append(f'f.secret.privatePEMKey={obj.privatePEMKey}')
    if obj.distinguishedName:
        fields.append(f'f.text.distinguishedName={obj.distinguishedName}')
    if obj.connectDatabase:
        fields.append(f'f.text.connectDatabase={obj.connectDatabase}')
    managed = utils.value_to_boolean(obj.managed)
    if managed is not None:
        fields.append(f'f.checkbox.managed={str(managed).lower()}')
    if obj.oneTimeCode:
        fields.append(f'f.oneTimeCode={obj.oneTimeCode}')
    fields.extend(_attachment_fields(obj))
    if fields:
        args['fields'] = fields
    return args


def _login_user_kwargs(obj: LoginUserObject, folder_uid: str) -> Dict[str, Any]:
    args = _base_kwargs(obj, folder_uid, obj.type)
    fields: List[str] = []
    if obj.login:
        fields.append(f'f.login={obj.login}')
    if obj.password:
        fields.append(f'f.password={obj.password}')
    if obj.url:
        fields.append(f'f.url={obj.url}')
    if obj.oneTimeCode:
        fields.append(f'f.oneTimeCode={obj.oneTimeCode}')
    # custom fields: a legacy login SaaS configuration ("SaaS Type") or a saasConfiguration record
    append_custom_text_fields(fields, getattr(obj, 'custom', None))
    fields.extend(_attachment_fields(obj))
    if fields:
        args['fields'] = fields
    return args


def _machine_kwargs(obj: PamObject, folder_uid: str) -> Dict[str, Any]:
    args = _base_kwargs(obj, folder_uid, obj.type)
    fields: List[str] = []
    hostname = obj.host.strip() if isinstance(getattr(obj, 'host', None), str) and obj.host.strip() else ''
    port = obj.port.strip() if isinstance(getattr(obj, 'port', None), str) and obj.port.strip() else ''
    if hostname or port:
        val = json.dumps({'hostName': hostname, 'port': port})
        fields.append(f'f.pamHostname=$JSON:{val}')
    sslv = utils.value_to_boolean(getattr(obj, 'sslVerification', None))
    if sslv is not None:
        fields.append(f'f.checkbox.sslVerification={str(sslv).lower()}')
    for attr, field_name in (
        ('operatingSystem', 'f.text.operatingSystem'),
        ('instanceName', 'f.text.instanceName'),
        ('instanceId', 'f.text.instanceId'),
        ('providerGroup', 'f.text.providerGroup'),
        ('providerRegion', 'f.text.providerRegion'),
        ('databaseId', 'f.text.databaseId'),
        # Enum field types (not text+label) — must match PamDatabase/DirectoryObject.create_record
        # or gateway/KSM never sees openldap/mysql/… and OpenLDAP rotation fails with
        # "Could not find the user's distinguished name in the directory."
        ('databaseType', 'f.databaseType'),
        ('domainName', 'f.text.domainName'),
        ('alternativeIPs', 'f.multiline.alternativeIPs'),
        ('directoryId', 'f.text.directoryId'),
        ('directoryType', 'f.directoryType'),
        ('userMatch', 'f.text.userMatch'),
    ):
        val = getattr(obj, attr, None)
        if val:
            fields.append(f'{field_name}={val}')
    use_ssl = utils.value_to_boolean(getattr(obj, 'useSSL', None))
    if use_ssl is not None:
        fields.append(f'f.checkbox.useSSL={str(use_ssl).lower()}')
    if getattr(obj, 'oneTimeCode', None):
        fields.append(f'f.oneTimeCode={obj.oneTimeCode}')
    fields.extend(_attachment_fields(obj))
    if fields:
        args['fields'] = fields
    return args


def _rbi_kwargs(obj: PamRemoteBrowserObject, folder_uid: str) -> Dict[str, Any]:
    args = _base_kwargs(obj, folder_uid, obj.type)
    fields: List[str] = []
    if obj.rbiUrl:
        fields.append(f'rbiUrl={obj.rbiUrl}')
    if obj.oneTimeCode:
        fields.append(f'oneTimeCode={obj.oneTimeCode}')
    if isinstance(obj, PamCloudResourceObject) and obj.accountIdentifier:
        # standard typed field accountNumber (text) whose template label is pamCloudResourceAccountIdentifier;
        # the Gateway reads it by field type
        fields.append(f'f.accountNumber.pamCloudResourceAccountIdentifier={obj.accountIdentifier}')
    fields.extend(_attachment_fields(obj))
    if fields:
        args['fields'] = fields
    return args


def _apply_pam_settings_fields(
    args: Dict[str, Any],
    obj: PamObject,
    *,
    inserted_uids: Set[str],
    deferred_out: Optional[List['DeferredRefUpdate']] = None,
) -> None:
    if isinstance(obj, PamRemoteBrowserObject):
        rbi_field = _rbi_settings_json(obj, inserted_uids=inserted_uids, deferred_out=deferred_out)
        if rbi_field:
            args.setdefault('fields', []).append(rbi_field)
        return
    if isinstance(obj, (PamMachineObject, PamDatabaseObject, PamDirectoryObject)):
        pam_field = _pam_settings_json(obj, inserted_uids=inserted_uids, deferred_out=deferred_out)
        if pam_field:
            args.setdefault('fields', []).append(pam_field)


def pam_object_to_typed_record(
    params,
    obj: PamObject,
    folder_uid: str,
    *,
    record_key: Optional[bytes] = None,
    linked_keys: Optional[Dict[str, bytes]] = None,
    inserted_uids: Optional[Set[str]] = None,
    deferred_out: Optional[List['DeferredRefUpdate']] = None,
    deferred_links_out: Optional[List['DeferredChannelAUpdate']] = None,
) -> vault.TypedRecord:
    """Build TypedRecord from PAM object without vault write."""
    inserted = inserted_uids or set()
    kwargs = build_record_add_kwargs(obj, folder_uid)
    _apply_pam_settings_fields(
        kwargs, obj,
        inserted_uids=inserted,
        deferred_out=deferred_out,
    )
    cmd = RecordEditAddCommand()
    cmd.warnings = []

    record_type = kwargs['record_type']
    rt_fields = cmd.get_record_type_fields(params, record_type)
    if not rt_fields:
        raise ValueError(f'Record type "{record_type}" cannot be found.')

    fields = kwargs.get('fields', [])
    record_fields = []
    for field in fields:
        parsed = cmd.parse_field(field.strip())
        if parsed.type != 'file':
            record_fields.append(parsed)

    record = vault.TypedRecord()
    record.type_name = record_type
    for rf in rt_fields:
        ref = rf.get('$ref')
        if not ref:
            continue
        label = rf.get('label') or ref
        default_value = rf.get('appFillerData') if ref == 'appFiller' else None
        field = vault.TypedField.new_field(ref, default_value, label)
        if rf.get('required'):
            field.required = True
        record.fields.append(field)
    cmd.assign_typed_fields(record, record_fields)

    record_uid = str(kwargs.get('record_uid', ''))
    if RecordV3.is_valid_ref_uid(record_uid):
        record.record_uid = record_uid
    record.title = kwargs.get('title') or ''
    record.notes = cmd.validate_notes(kwargs.get('notes') or '')

    from .tunnel_setup import (
        ensure_traffic_encryption_seed_on_typed_record,
        merge_initial_pam_settings_on_record,
    )

    ensure_traffic_encryption_seed_on_typed_record(record)
    merge_initial_pam_settings_on_record(record, obj)

    if record_key:
        record.record_key = record_key
    if linked_keys:
        record.linked_keys = dict(linked_keys)

    if deferred_links_out is not None and record.record_uid:
        from .deferred_refs import collect_channel_a_deferrals

        collect_channel_a_deferrals(record, record.record_uid, inserted, deferred_links_out)

    return record
