"""
KeeperDrive — folder CRUD, access/sharing, and retrieval.

Every folder-related API call lives here; shared primitives come from
``common`` and ``permissions``.
"""

import json
import logging
import os
from typing import Optional, List, Dict, Any

from .. import utils, crypto, api
from ..params import KeeperParams
from ..proto import folder_pb2
from ..error import KeeperApiError
from ..subfolder import try_resolve_path

from .common import (
    get_folder_key, get_user_public_key, resolve_user_uid_bytes,
    resolve_uid_email, encrypt_for_recipient, load_user_public_key,
    parse_folder_access_result,
)
from .permissions import (
    FolderUsageType, SetBooleanValue, resolve_role_name, ROLE_NAME_MAP,
    get_folder_permissions_for_role,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════
# Low-level protobuf builders
# ══════════════════════════════════════════════════════════════════════════

def create_folder_data(
    folder_uid, folder_name, encryption_key,
    parent_uid=None, folder_type=None,
    inherit_permissions=None, color=None,
    owner_username=None, owner_account_uid=None
):
    fd = folder_pb2.FolderData()
    fd.folderUid = utils.base64_url_decode(folder_uid)

    data_dict = {'name': folder_name}
    if color and color != 'none':
        data_dict['color'] = color
    fd.data = crypto.encrypt_aes_v2(json.dumps(data_dict).encode(), encryption_key)

    if parent_uid:
        fd.parentUid = utils.base64_url_decode(parent_uid)
    if folder_type is not None:
        fd.type = folder_type
    if inherit_permissions is not None:
        fd.inheritUserPermissions = inherit_permissions
    if owner_username or owner_account_uid:
        oi = folder_pb2.UserInfo()
        if owner_username:
            oi.username = owner_username
        if owner_account_uid:
            oi.accountUid = utils.base64_url_decode(owner_account_uid)
        fd.ownerInfo.CopyFrom(oi)
    return fd


def encrypt_folder_key(folder_key, parent_key, use_gcm=True):
    if use_gcm:
        return crypto.encrypt_aes_v2(folder_key, parent_key)
    return crypto.encrypt_aes_v1(folder_key, parent_key)


# ══════════════════════════════════════════════════════════════════════════
# Internal: prepare folder data for creation (DRY for single + batch)
# ══════════════════════════════════════════════════════════════════════════

def _prepare_folder_for_creation(params, folder_uid, folder_name, parent_uid,
                                  color, inherit_permissions):
    folder_key = os.urandom(32)
    enc_key = params.data_key
    if parent_uid:
        parent_key = get_folder_key(params, parent_uid, raise_on_missing=False)
        if parent_key:
            enc_key = parent_key
        else:
            logging.warning("Parent folder key not found for %s, using user data key", parent_uid)

    encrypted_fk = encrypt_folder_key(folder_key, enc_key, use_gcm=True)
    fd = create_folder_data(
        folder_uid=folder_uid, folder_name=folder_name, encryption_key=folder_key,
        parent_uid=parent_uid, folder_type=FolderUsageType.NORMAL,
        inherit_permissions=(SetBooleanValue.BOOLEAN_TRUE if inherit_permissions
                             else SetBooleanValue.BOOLEAN_FALSE),
        color=color)
    fd.folderKey = encrypted_fk
    return fd


# ══════════════════════════════════════════════════════════════════════════
# Transport: folder_add_v3 / folder_update_v3 / folder_access_update_v3
# ══════════════════════════════════════════════════════════════════════════

def folder_add_v3(params, folders):
    if not folders or len(folders) > 100:
        raise ValueError("Provide 1..100 folders")
    rq = folder_pb2.FolderAddRequest()
    rq.folderData.extend(folders)
    return api.communicate_rest(params, rq, 'vault/folders/v3/add',
                                rs_type=folder_pb2.FolderAddResponse)


def folder_update_v3(params, folders):
    if not folders or len(folders) > 100:
        raise ValueError("Provide 1..100 folders")
    rq = folder_pb2.FolderUpdateRequest()
    rq.folderData.extend(folders)
    return api.communicate_rest(params, rq, 'vault/folders/v3/update',
                                rs_type=folder_pb2.FolderUpdateResponse)


def folder_access_update_v3(params, folder_access_adds=None,
                             folder_access_updates=None,
                             folder_access_removes=None):
    for label, lst in [('adds', folder_access_adds), ('updates', folder_access_updates),
                       ('removes', folder_access_removes)]:
        if lst and len(lst) > 500:
            raise ValueError(f"Maximum 500 {label}")
    if not any([folder_access_adds, folder_access_updates, folder_access_removes]):
        raise ValueError("At least one access operation required")
    rq = folder_pb2.FolderAccessRequest()
    if folder_access_adds:
        rq.folderAccessAdds.extend(folder_access_adds)
    if folder_access_updates:
        rq.folderAccessUpdates.extend(folder_access_updates)
    if folder_access_removes:
        rq.folderAccessRemoves.extend(folder_access_removes)
    return api.communicate_rest(params, rq, 'vault/folders/v3/access_update',
                                rs_type=folder_pb2.FolderAccessResponse)


# ══════════════════════════════════════════════════════════════════════════
# Resolution
# ══════════════════════════════════════════════════════════════════════════

def resolve_folder_identifier(params, folder_identifier):
    if folder_identifier in getattr(params, 'keeper_drive_folders', {}):
        return folder_identifier
    if folder_identifier in getattr(params, 'subfolder_cache', {}):
        return folder_identifier
    if folder_identifier in getattr(params, 'folder_cache', {}):
        return folder_identifier

    matching = [uid for uid, obj in getattr(params, 'keeper_drive_folders', {}).items()
                if obj.get('name', '').lower() == folder_identifier.lower()]
    if len(matching) == 1:
        return matching[0]
    if len(matching) > 1:
        logging.warning("Multiple folders match '%s'. Use UID instead.", folder_identifier)
        return None

    rs = try_resolve_path(params, folder_identifier)
    if rs is not None:
        folder, pattern = rs
        if folder and not pattern:
            return folder.uid
    return None


# ══════════════════════════════════════════════════════════════════════════
# High-level: create / create_batch
# ══════════════════════════════════════════════════════════════════════════

def create_folder_v3(params, folder_name, parent_uid=None, color=None,
                     inherit_permissions=True):
    uid = utils.generate_uid()
    fd = _prepare_folder_for_creation(params, uid, folder_name, parent_uid,
                                       color, inherit_permissions)
    response = folder_add_v3(params, [fd])
    if response.folderAddResults:
        r = response.folderAddResults[0]
        return {
            'folder_uid': uid,
            'status': folder_pb2.FolderModifyStatus.Name(r.status),
            'message': r.message,
            'success': r.status == folder_pb2.SUCCESS,
        }
    raise KeeperApiError('no_results', 'No results from folder creation')


def create_folders_batch_v3(params, folder_specs):
    if len(folder_specs) > 100:
        raise ValueError("Maximum 100 folders at a time")
    fd_list, uid_map = [], {}
    for idx, spec in enumerate(folder_specs):
        uid = utils.generate_uid()
        uid_map[idx] = uid
        name = spec.get('name')
        if not name:
            raise ValueError(f"Spec at index {idx} missing 'name'")
        fd = _prepare_folder_for_creation(
            params, uid, name, spec.get('parent_uid'),
            spec.get('color'), spec.get('inherit_permissions', True))
        fd_list.append(fd)
    response = folder_add_v3(params, fd_list)
    return [{
        'folder_uid': uid_map.get(i, utils.base64_url_encode(r.folderUid)),
        'name': folder_specs[i].get('name'),
        'status': folder_pb2.FolderModifyStatus.Name(r.status),
        'message': r.message,
        'success': r.status == folder_pb2.SUCCESS,
    } for i, r in enumerate(response.folderAddResults)]


# ══════════════════════════════════════════════════════════════════════════
# High-level: update / update_batch
# ══════════════════════════════════════════════════════════════════════════

def _build_update_data(params, folder_uid, folder_name, color, inherit_permissions):
    """Build FolderData for an update, preserving existing name/color."""
    fk = get_folder_key(params, folder_uid)
    fd = folder_pb2.FolderData()
    fd.folderUid = utils.base64_url_decode(folder_uid)

    obj = (getattr(params, 'keeper_drive_folders', {}).get(folder_uid) or
           getattr(params, 'subfolder_cache', {}).get(folder_uid) or {})
    dd = {}
    dd['name'] = folder_name if folder_name is not None else obj.get('name', '')
    if color is not None:
        if color not in ('none', ''):
            dd['color'] = color
    elif obj.get('color') and obj['color'] != 'none':
        dd['color'] = obj['color']

    fd.data = crypto.encrypt_aes_v2(json.dumps(dd).encode(), fk)
    if inherit_permissions is not None:
        fd.inheritUserPermissions = (SetBooleanValue.BOOLEAN_TRUE if inherit_permissions
                                     else SetBooleanValue.BOOLEAN_FALSE)
    return fd


def update_folder_v3(params, folder_uid, folder_name=None, color=None,
                     inherit_permissions=None):
    if folder_name is None and color is None and inherit_permissions is None:
        raise ValueError("At least one update field required")
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    fd = _build_update_data(params, resolved, folder_name, color, inherit_permissions)
    response = folder_update_v3(params, [fd])
    if response.folderUpdateResults:
        r = response.folderUpdateResults[0]
        return {
            'folder_uid': resolved,
            'status': folder_pb2.FolderModifyStatus.Name(r.status),
            'message': r.message,
            'success': r.status == folder_pb2.SUCCESS,
        }
    raise KeeperApiError('no_results', 'No results from folder update')


def update_folders_batch_v3(params, folder_updates):
    if len(folder_updates) > 100:
        raise ValueError("Maximum 100 folders at a time")
    fd_list = []
    for idx, spec in enumerate(folder_updates):
        fi = spec.get('folder_uid')
        if not fi:
            raise ValueError(f"Spec at index {idx} missing 'folder_uid'")
        name, color, inh = spec.get('name'), spec.get('color'), spec.get('inherit_permissions')
        if name is None and color is None and inh is None:
            raise ValueError(f"Spec at index {idx} must update at least one field")
        resolved = resolve_folder_identifier(params, fi)
        if not resolved:
            raise ValueError(f"Folder '{fi}' at index {idx} not found")
        fd_list.append(_build_update_data(params, resolved, name, color, inh))
    response = folder_update_v3(params, fd_list)
    return [{
        'folder_uid': folder_updates[i].get('folder_uid'),
        'status': folder_pb2.FolderModifyStatus.Name(r.status),
        'message': r.message,
        'success': r.status == folder_pb2.SUCCESS,
    } for i, r in enumerate(response.folderUpdateResults)]


# ══════════════════════════════════════════════════════════════════════════
# High-level: folder access grant / update / revoke
# ══════════════════════════════════════════════════════════════════════════

def grant_folder_access_v3(params, folder_uid, user_uid, role='viewer',
                           share_folder_key=True, expiration_timestamp=None):
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    is_email = '@' in user_uid
    user_email = user_uid if is_email else None
    actual_uid_bytes = None
    user_public_key = None
    use_ecc = False

    if is_email:
        try:
            user_public_key, use_ecc, actual_uid_bytes, _inv = get_user_public_key(params, user_email)
        except Exception as e:
            raise ValueError(f"User '{user_email}' not found or has no public key. {e}")
    else:
        actual_uid_bytes, user_email = resolve_uid_email(params, user_uid)
        if not actual_uid_bytes:
            raise ValueError(f"Invalid user UID: {user_uid}")

    access_role = resolve_role_name(role)
    target_role_name = folder_pb2.AccessRoleType.Name(access_role)

    if actual_uid_bytes:
        existing = _check_existing_access(params, folder_uid, actual_uid_bytes, target_role_name)
        if existing is not None:
            if existing == target_role_name:
                return {'folder_uid': folder_uid, 'user_uid': user_uid,
                        'status': 'SUCCESS', 'message': f"User already has {role} access",
                        'success': True, 'action_taken': 'already_had_access'}
            result = update_folder_access_v3(params, folder_uid, user_uid, role=role)
            result['action_taken'] = 'updated'
            return result

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = actual_uid_bytes
    ad.accessType = folder_pb2.AT_USER
    ad.accessRoleType = access_role
    ad.permissions.CopyFrom(get_folder_permissions_for_role(access_role))

    if expiration_timestamp:
        ad.tlaProperties.expiration = expiration_timestamp

    if share_folder_key:
        fk = get_folder_key(params, folder_uid)
        if not user_public_key:
            user_public_key, use_ecc = load_user_public_key(params, user_email)
        efk = encrypt_for_recipient(fk, user_public_key, use_ecc)
        ek = folder_pb2.EncryptedDataKey()
        ek.encryptedKey = efk
        ek.encryptedKeyType = (folder_pb2.encrypted_by_public_key_ecc if use_ecc
                               else folder_pb2.encrypted_by_public_key)
        ad.folderKey.CopyFrom(ek)

    response = folder_access_update_v3(params, folder_access_adds=[ad])
    result = parse_folder_access_result(response, folder_uid, user_uid,
                                        'Access granted successfully')
    result.setdefault('action_taken', 'granted' if result['success'] else 'grant_failed')
    return result


def _check_existing_access(params, folder_uid, uid_bytes, target_role_name):
    """Return existing role name or None."""
    try:
        uid_encoded = utils.base64_url_encode(uid_bytes)
        info = get_folder_access_v3(params, [folder_uid])
        if info.get('results'):
            for a in info['results'][0].get('accessors', []):
                if a.get('access_type') == 'AT_USER' and a.get('accessor_uid') == uid_encoded:
                    return a.get('role')
    except Exception:
        pass
    return None


def update_folder_access_v3(params, folder_uid, user_uid, role=None, hidden=None):
    if role is None and hidden is None:
        raise ValueError("At least one field (role or hidden) required")
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    if '@' in user_uid:
        _, _, actual_uid_bytes, _ = get_user_public_key(params, user_uid)
    else:
        actual_uid_bytes = resolve_user_uid_bytes(params, user_uid)
    if not actual_uid_bytes:
        raise ValueError(f"User '{user_uid}' not found")

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = actual_uid_bytes
    ad.accessType = folder_pb2.AT_USER
    if role:
        resolved_role = resolve_role_name(role)
        ad.accessRoleType = resolved_role
        ad.permissions.CopyFrom(get_folder_permissions_for_role(resolved_role))
    if hidden is not None:
        ad.hidden = hidden

    response = folder_access_update_v3(params, folder_access_updates=[ad])
    return parse_folder_access_result(response, folder_uid, user_uid,
                                      'Access updated successfully')


def revoke_folder_access_v3(params, folder_uid, user_uid):
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    if '@' in user_uid:
        _, _, actual_uid_bytes, _ = get_user_public_key(params, user_uid)
    else:
        actual_uid_bytes = resolve_user_uid_bytes(params, user_uid)
    if not actual_uid_bytes:
        raise ValueError(f"User '{user_uid}' not found")

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = actual_uid_bytes
    ad.accessType = folder_pb2.AT_USER

    response = folder_access_update_v3(params, folder_access_removes=[ad])
    return parse_folder_access_result(response, folder_uid, user_uid,
                                      'Access revoked successfully')


def manage_folder_access_batch_v3(params, access_grants=None,
                                   access_updates=None, access_revokes=None):
    adds, updates, removes = [], [], []
    tracking = []

    for spec in (access_grants or []):
        fuid = resolve_folder_identifier(params, spec['folder_uid'])
        if not fuid:
            raise ValueError(f"Folder '{spec['folder_uid']}' not found")
        uid_bytes, email = resolve_uid_email(params, spec['user_uid'])
        if not uid_bytes:
            raise ValueError(f"User '{spec['user_uid']}' not found")
        role = spec.get('role', 'viewer')
        fk = get_folder_key(params, fuid)
        pk, use_ecc = load_user_public_key(params, email)
        efk = encrypt_for_recipient(fk, pk, use_ecc)

        ad = folder_pb2.FolderAccessData()
        ad.folderUid = utils.base64_url_decode(fuid)
        ad.accessTypeUid = uid_bytes
        ad.accessType = folder_pb2.AT_USER
        ad.accessRoleType = resolve_role_name(role)
        ek = folder_pb2.EncryptedDataKey()
        ek.encryptedKey = efk
        ek.encryptedKeyType = (folder_pb2.encrypted_by_public_key_ecc if use_ecc
                               else folder_pb2.encrypted_by_public_key)
        ad.folderKey.CopyFrom(ek)
        adds.append(ad)
        tracking.append(('grant', fuid, spec['user_uid'], spec))

    for spec in (access_updates or []):
        fuid = resolve_folder_identifier(params, spec['folder_uid'])
        if not fuid:
            raise ValueError(f"Folder '{spec['folder_uid']}' not found")
        uid_bytes = resolve_user_uid_bytes(params, spec['user_uid'])
        if not uid_bytes:
            raise ValueError(f"User '{spec['user_uid']}' not found")
        ad = folder_pb2.FolderAccessData()
        ad.folderUid = utils.base64_url_decode(fuid)
        ad.accessTypeUid = uid_bytes
        ad.accessType = folder_pb2.AT_USER
        if spec.get('role'):
            ad.accessRoleType = resolve_role_name(spec['role'])
        if spec.get('hidden') is not None:
            ad.hidden = spec['hidden']
        updates.append(ad)
        tracking.append(('update', fuid, spec['user_uid'], spec))

    for spec in (access_revokes or []):
        fuid = resolve_folder_identifier(params, spec['folder_uid'])
        if not fuid:
            raise ValueError(f"Folder '{spec['folder_uid']}' not found")
        uid_bytes = resolve_user_uid_bytes(params, spec['user_uid'])
        if not uid_bytes:
            raise ValueError(f"User '{spec['user_uid']}' not found")
        ad = folder_pb2.FolderAccessData()
        ad.folderUid = utils.base64_url_decode(fuid)
        ad.accessTypeUid = uid_bytes
        ad.accessType = folder_pb2.AT_USER
        removes.append(ad)
        tracking.append(('revoke', fuid, spec['user_uid'], spec))

    response = folder_access_update_v3(
        params,
        folder_access_adds=adds or None,
        folder_access_updates=updates or None,
        folder_access_removes=removes or None)

    results = [{'operation': op, 'folder_uid': f, 'user_uid': u,
                'status': 'SUCCESS', 'message': f'{op.capitalize()} completed', 'success': True}
               for op, f, u, _ in tracking]

    if response.folderAccessResults:
        for r in response.folderAccessResults:
            f = utils.base64_url_encode(r.folderUid)
            u = utils.base64_url_encode(r.accessUid) if r.accessUid else 'unknown'
            for i, (op, tf, tu, _) in enumerate(tracking):
                if tf == f and tu == u:
                    results[i] = {
                        'operation': op, 'folder_uid': f, 'user_uid': u,
                        'status': folder_pb2.FolderModifyStatus.Name(r.status),
                        'message': r.message, 'success': False}
                    break
    return results


# ══════════════════════════════════════════════════════════════════════════
# High-level: get_folder_access_v3
# ══════════════════════════════════════════════════════════════════════════

def get_folder_access_v3(params, folder_uids, continuation_token=None, page_size=None):
    if not folder_uids or len(folder_uids) > 100:
        raise ValueError("Provide 1..100 folder UIDs")
    from ..proto import folder_access_pb2

    rq = folder_access_pb2.GetFolderAccessRequest()
    for fi in folder_uids:
        resolved = resolve_folder_identifier(params, fi)
        if not resolved:
            raise ValueError(f"Folder '{fi}' not found")
        rq.folderUid.append(utils.base64_url_decode(resolved))
    if continuation_token is not None:
        tok = folder_access_pb2.ContinuationToken()
        tok.lastModified = continuation_token
        rq.continuationToken.CopyFrom(tok)
    if page_size is not None:
        if page_size > 1000:
            raise ValueError("Maximum page size is 1000")
        rq.pageSize = page_size

    rs = api.communicate_rest(params, rq, 'vault/folders/v3/access',
                              rs_type=folder_access_pb2.GetFolderAccessResponse)
    results = []
    for fr in rs.folderAccessResults:
        fuid = utils.base64_url_encode(fr.folderUid)
        if fr.HasField('error'):
            err = fr.error
            results.append({
                'folder_uid': fuid,
                'error': {'status': folder_pb2.FolderModifyStatus.Name(err.status),
                          'message': err.message},
                'success': False})
        else:
            accessors = []
            for a in fr.accessors:
                auid = utils.base64_url_encode(a.accessTypeUid)
                at = folder_pb2.AccessType.Name(a.accessType)
                rt = folder_pb2.AccessRoleType.Name(a.accessRoleType)
                username = None
                if at == 'AT_USER':
                    username = getattr(params, 'user_cache', {}).get(auid)
                    if not username and hasattr(params, 'enterprise') and params.enterprise:
                        for u in params.enterprise.get('users', []):
                            if u.get('user_account_uid') == auid:
                                username = u.get('username')
                                break
                ai = {
                    'accessor_uid': auid, 'access_type': at, 'role': rt,
                    'inherited': bool(a.inherited), 'hidden': bool(a.hidden),
                    'username': username,
                    'date_created': a.dateCreated or None,
                    'last_modified': a.lastModified or None,
                }
                if a.HasField('permissions'):
                    p = a.permissions
                    ai['permissions'] = {
                        'can_add': bool(p.canAdd), 'can_remove': bool(p.canRemove),
                        'can_delete': bool(p.canDelete),
                        'can_list_access': bool(p.canListAccess),
                        'can_update_access': bool(p.canUpdateAccess),
                        'can_change_ownership': bool(p.canChangeOwnership),
                        'can_edit_records': bool(p.canEditRecords),
                        'can_view_records': bool(p.canViewRecords),
                        'can_approve_access': bool(p.canApproveAccess),
                        'can_request_access': bool(p.canRequestAccess),
                        'can_update_setting': bool(p.canUpdateSetting),
                        'can_list_records': bool(p.canListRecords),
                        'can_list_folders': bool(p.canListFolders),
                    }
                accessors.append(ai)
            results.append({'folder_uid': fuid, 'accessors': accessors, 'success': True})

    rd = {'results': results, 'has_more': bool(rs.hasMore)}
    if rs.HasField('continuationToken'):
        rd['continuation_token'] = rs.continuationToken.lastModified
    return rd
