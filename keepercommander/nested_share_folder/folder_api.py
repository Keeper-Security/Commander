"""
Nested Share Folder — folder CRUD, access/sharing, and retrieval.

Every folder-related API call lives here; shared primitives come from
``common`` and ``permissions``.
"""

import json
import logging
import os
from typing import Optional, List, Dict, Any

from .. import utils, crypto, api
from ..params import KeeperParams
from ..proto import folder_pb2, tla_pb2
from ..error import KeeperApiError
from ..subfolder import try_resolve_path

from .common import (
    get_folder_key, get_user_public_key, resolve_user_uid_bytes,
    resolve_uid_email, encrypt_for_recipient, load_user_public_key,
    parse_folder_access_result,
    resolve_team_identifier, get_team_keys, encrypt_for_team,
    handle_share_invite,
)
from .permissions import (
    FolderUsageType, SetBooleanValue, resolve_role_name, ROLE_NAME_MAP,
    get_folder_permissions_for_role,
)
from .sync import (
    plan_folder_access_change, folder_access_state_from_accessors,
    get_folder_access_state,
    FOLDER_ACCESS_NONE, FOLDER_ACCESS_INHERITED, FOLDER_ACCESS_DIRECT,
    FOLDER_ACCESS_DENIED,
    FOLDER_ACCESS_ADD, FOLDER_ACCESS_UPDATE, FOLDER_ACCESS_REMOVE,
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
    return fd, folder_key


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
    if folder_identifier in getattr(params, 'nested_share_folders', {}):
        return folder_identifier
    if folder_identifier in getattr(params, 'subfolder_cache', {}):
        return folder_identifier
    if folder_identifier in getattr(params, 'folder_cache', {}):
        return folder_identifier

    matching = [uid for uid, obj in getattr(params, 'nested_share_folders', {}).items()
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
    fd, folder_key = _prepare_folder_for_creation(
        params, uid, folder_name, parent_uid, color, inherit_permissions)
    response = folder_add_v3(params, [fd])
    if response.folderAddResults:
        r = response.folderAddResults[0]
        return {
            'folder_uid': uid,
            'folder_key_unencrypted': folder_key,
            'status': folder_pb2.FolderModifyStatus.Name(r.status),
            'message': r.message,
            'success': r.status == folder_pb2.SUCCESS,
        }
    raise KeeperApiError('no_results', 'No results from folder creation')


def create_folders_batch_v3(params, folder_specs):
    if len(folder_specs) > 100:
        raise ValueError("Maximum 100 folders at a time")
    fd_list, uid_map, key_map = [], {}, {}
    for idx, spec in enumerate(folder_specs):
        uid = utils.generate_uid()
        uid_map[idx] = uid
        name = spec.get('name')
        if not name:
            raise ValueError(f"Spec at index {idx} missing 'name'")
        fd, folder_key = _prepare_folder_for_creation(
            params, uid, name, spec.get('parent_uid'),
            spec.get('color'), spec.get('inherit_permissions', True))
        fd_list.append(fd)
        key_map[idx] = folder_key
    response = folder_add_v3(params, fd_list)
    return [{
        'folder_uid': uid_map.get(i, utils.base64_url_encode(r.folderUid)),
        'folder_key_unencrypted': key_map.get(i),
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

    obj = (getattr(params, 'nested_share_folders', {}).get(folder_uid) or
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

def _resolve_accessor(params, accessor_uid, as_team):
    """Resolve a user/team identifier to (uid_bytes, label, access_type_enum).
    """
    if as_team:
        resolved = resolve_team_identifier(params, accessor_uid)
        if not resolved:
            raise ValueError(f"Team '{accessor_uid}' not found")
        team_uid_b64, team_uid_bytes = resolved
        return team_uid_bytes, team_uid_b64, folder_pb2.AT_TEAM

    is_email = '@' in accessor_uid
    if is_email:
        _, _, uid_bytes, _ = get_user_public_key(params, accessor_uid)
        return uid_bytes, accessor_uid, folder_pb2.AT_USER

    uid_bytes = resolve_user_uid_bytes(params, accessor_uid)
    return uid_bytes, accessor_uid, folder_pb2.AT_USER


def _apply_folder_expiration_tla(tla_props, expiration_timestamp,
                                  rotate_on_expiration=False):
    """Set expiration / ROE fields on folder-access TLAProperties."""
    if expiration_timestamp is None:
        return
    tla_props.expiration = expiration_timestamp
    if rotate_on_expiration and expiration_timestamp > 0:
        tla_props.timerNotificationType = tla_pb2.NOTIFY_OWNER
        tla_props.rotateOnExpiration = True


# ── Access-state aware request planning ───────────────────────────────────
#
# A child folder's accessor can be:
#   * direct    - its own access row (and folder-key edge) on this folder
#   * inherited - access flowing from a parent folder; no folder-key edge here
#   * denied    - an inherited access explicitly denied on this folder
#   * none      - no access
#
# The backend refuses to change a folder key on another user's existing access
# row, so turning inherited access into an explicit role must be an *add* with
# the recipient-encrypted folder key, not an update. Otherwise the child loses
# its only key edge when the parent grant is revoked and disappears on sync.
# ``plan_folder_access_change`` (sync.py) owns the transition rules.

_STEP_MESSAGES = {
    FOLDER_ACCESS_ADD: 'Access granted successfully',
    FOLDER_ACCESS_UPDATE: 'Access updated successfully',
    FOLDER_ACCESS_REMOVE: 'Access revoked successfully',
}


def _lookup_folder_accessors(params, folder_uid, accessor_uid_b64,
                             access_type_label=None):
    """Return every server accessor row for one actor on *folder_uid*.

    Rows matching *access_type_label* are preferred; otherwise all rows for
    the UID are returned. Lookup failures return an empty list.
    """
    try:
        info = get_folder_access_v3(params, [folder_uid], resolve_usernames=False)
    except Exception as exc:
        logger.debug('Folder accessor lookup failed for %s: %s', folder_uid, exc)
        return []
    rows = []
    for fr in info.get('results', []):
        if not fr.get('success'):
            continue
        rows.extend(a for a in fr.get('accessors', [])
                    if a.get('accessor_uid') == accessor_uid_b64)
    if access_type_label:
        typed = [a for a in rows if a.get('access_type') == access_type_label]
        if typed:
            return typed
    return rows


def _folder_access_state(params, folder_uid, accessor_uid_b64, accessors):
    """Classify an accessor, preferring server rows over the sync cache.

    The sync cache only carries the caller's own row (plus denials seen in
    sync), so it is a fallback for when the server returned nothing.
    """
    if accessors:
        return folder_access_state_from_accessors(accessors)
    try:
        return get_folder_access_state(params, folder_uid, accessor_uid_b64)
    except Exception as exc:
        logger.debug('Cached folder access state unavailable for %s: %s', folder_uid, exc)
        return FOLDER_ACCESS_NONE


def _current_role_name(accessors):
    """Role of the most specific accessor row (direct over inherited)."""
    for a in sorted(accessors or [], key=lambda r: bool(r.get('inherited'))):
        if a.get('role'):
            return a['role']
    return None


def _encrypted_folder_key_for(params, folder_uid, accessor_uid_b64, as_team,
                              user_email=None, user_public_key=None,
                              use_ecc=False, team_keys=None):
    """Encrypt *folder_uid*'s key for a user (public key) or team."""
    fk = get_folder_key(params, folder_uid)
    ek = folder_pb2.EncryptedDataKey()
    if as_team:
        if team_keys is None:
            team_keys = get_team_keys(params, accessor_uid_b64)
        efk, key_type = encrypt_for_team(
            fk, team_keys, prefer_aes=False,
            forbid_rsa=getattr(params, 'forbid_rsa', False))
    else:
        if not user_public_key:
            if not user_email or '@' not in user_email:
                _, user_email = resolve_uid_email(params, user_email or accessor_uid_b64)
            user_public_key, use_ecc = load_user_public_key(params, user_email)
        efk = encrypt_for_recipient(fk, user_public_key, use_ecc)
        key_type = (folder_pb2.encrypted_by_public_key_ecc if use_ecc
                    else folder_pb2.encrypted_by_public_key)
    ek.encryptedKey = efk
    ek.encryptedKeyType = key_type
    return ek


def _build_access_step_data(folder_uid, uid_bytes, access_type_enum, step,
                            role=None, hidden=None, expiration_timestamp=None,
                            rotate_on_expiration=False, folder_key=None):
    """Build the FolderAccessData for one planned step."""
    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = uid_bytes
    ad.accessType = access_type_enum
    if step['request'] == FOLDER_ACCESS_REMOVE:
        return ad
    if step['denied_access']:
        # A denial is not a direct grant: no role change and never a folder key.
        ad.deniedAccess = True
        return ad
    if role:
        access_role = resolve_role_name(role)
        ad.accessRoleType = access_role
        ad.permissions.CopyFrom(get_folder_permissions_for_role(access_role))
    if hidden is not None:
        ad.hidden = hidden
    _apply_folder_expiration_tla(ad.tlaProperties, expiration_timestamp,
                                 rotate_on_expiration)
    if step['include_folder_key']:
        if folder_key is None:
            raise ValueError('Folder key is required to create direct folder access')
        ad.folderKey.CopyFrom(folder_key)
    return ad


def _send_access_step(params, step, ad):
    if step['request'] == FOLDER_ACCESS_ADD:
        return folder_access_update_v3(params, folder_access_adds=[ad])
    if step['request'] == FOLDER_ACCESS_UPDATE:
        return folder_access_update_v3(params, folder_access_updates=[ad])
    return folder_access_update_v3(params, folder_access_removes=[ad])


def _execute_access_plan(params, folder_uid, identifier_label, uid_bytes,
                         access_type_enum, plan, folder_key_factory=None,
                         messages=None, **fields):
    """Send *plan* steps sequentially, stopping at the first failure.

    Used for the two-step re-add of a denied accessor: the add is only sent
    once the denial removal succeeded, so no add races an existing denied row.
    """
    messages = dict(_STEP_MESSAGES, **(messages or {}))
    result = None
    for idx, step in enumerate(plan):
        folder_key = folder_key_factory() if step['include_folder_key'] else None
        ad = _build_access_step_data(folder_uid, uid_bytes, access_type_enum, step,
                                     folder_key=folder_key, **fields)
        message = ('Access denied successfully' if step['denied_access']
                   else messages[step['request']])
        response = _send_access_step(params, step, ad)
        result = parse_folder_access_result(response, folder_uid, identifier_label, message)
        result['request'] = step['request']
        if not result.get('success'):
            if idx < len(plan) - 1:
                result['message'] = (f"{result.get('message')} "
                                     f"(step {idx + 1} of {len(plan)}; remaining steps skipped)")
            break
    return result


def grant_folder_access_v3(params, folder_uid, user_uid, role='viewer',
                           share_folder_key=True, expiration_timestamp=None,
                           as_team=False, rotate_on_expiration=False):
    """Grant a user *or team* access to a Nested Share Folder.

    The request depends on the accessor's current state on this folder:
    existing direct access is updated (no new key); inherited access becomes a
    direct grant via ``folderAccessAdds`` with the recipient-encrypted folder
    key; a denied accessor has the denial removed first, then is added.
    """
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    actual_uid_bytes = None
    user_email = None
    user_public_key = None
    use_ecc = False
    team_keys = None

    if as_team:
        resolved_team = resolve_team_identifier(params, user_uid)
        if not resolved_team:
            raise ValueError(f"Team '{user_uid}' not found")
        team_uid_b64, actual_uid_bytes = resolved_team
        if share_folder_key:
            team_keys = get_team_keys(params, team_uid_b64)
        access_type_enum = folder_pb2.AT_TEAM
        access_type_label = 'AT_TEAM'
        identifier_label = team_uid_b64
    else:
        is_email = '@' in user_uid
        user_email = user_uid if is_email else None
        if is_email:
            try:
                user_public_key, use_ecc, actual_uid_bytes, needs_invite = \
                    get_user_public_key(params, user_email)
            except Exception as e:
                raise ValueError(f"User '{user_email}' not found or has no public key. {e}")
            if not user_public_key:
                handle_share_invite(params, user_email, needs_invite)
                raise ValueError(f"User '{user_email}' has no public key")
            if not actual_uid_bytes:
                raise ValueError(f"User '{user_email}' not found")
        else:
            actual_uid_bytes, user_email = resolve_uid_email(params, user_uid)
            if not actual_uid_bytes:
                raise ValueError(f"Invalid user UID: {user_uid}")
        access_type_enum = folder_pb2.AT_USER
        access_type_label = 'AT_USER'
        identifier_label = user_uid

    access_role = resolve_role_name(role)
    target_role_name = folder_pb2.AccessRoleType.Name(access_role)
    accessor_uid_b64 = utils.base64_url_encode(actual_uid_bytes)

    accessors = _lookup_folder_accessors(params, folder_uid, accessor_uid_b64,
                                         access_type_label)
    state = _folder_access_state(params, folder_uid, accessor_uid_b64, accessors)

    if state == FOLDER_ACCESS_DIRECT:
        if _current_role_name(accessors) == target_role_name and expiration_timestamp is None:
            return {'folder_uid': folder_uid, 'user_uid': identifier_label,
                    'access_type': access_type_label,
                    'status': 'SUCCESS',
                    'message': f"{'Team' if as_team else 'User'} already has {role} access",
                    'success': True, 'action_taken': 'already_had_access'}
        result = update_folder_access_v3(params, folder_uid, identifier_label,
                                         role=role, as_team=as_team,
                                         expiration_timestamp=expiration_timestamp,
                                         rotate_on_expiration=rotate_on_expiration,
                                         known_state=FOLDER_ACCESS_DIRECT)
        result['action_taken'] = 'updated'
        return result

    plan = plan_folder_access_change(params, folder_uid, accessor_uid_b64, 'grant',
                                     state=state)
    if not share_folder_key:
        if state in (FOLDER_ACCESS_INHERITED, FOLDER_ACCESS_DENIED):
            raise ValueError('A folder key is required to give direct access on a '
                             'folder where the accessor has inherited or denied access')
        plan = [dict(step, include_folder_key=False) for step in plan]

    def folder_key_factory():
        return _encrypted_folder_key_for(
            params, folder_uid, accessor_uid_b64, as_team,
            user_email=user_email, user_public_key=user_public_key,
            use_ecc=use_ecc, team_keys=team_keys)

    result = _execute_access_plan(
        params, folder_uid, identifier_label, actual_uid_bytes, access_type_enum,
        plan, folder_key_factory=folder_key_factory,
        role=role, expiration_timestamp=expiration_timestamp,
        rotate_on_expiration=rotate_on_expiration)
    result['access_type'] = access_type_label
    result['previous_access_state'] = state
    if result['success']:
        result.setdefault('action_taken', 'granted')
    else:
        result.setdefault('action_taken', 'grant_failed')
    return result


def _check_existing_access(params, folder_uid, uid_bytes, target_role_name,
                            access_type_label='AT_USER'):
    """Return existing role name (for the matching access_type) or None."""
    try:
        uid_encoded = utils.base64_url_encode(uid_bytes)
        info = get_folder_access_v3(params, [folder_uid], resolve_usernames=False)
        if info.get('results'):
            for a in info['results'][0].get('accessors', []):
                if (a.get('access_type') == access_type_label
                        and a.get('accessor_uid') == uid_encoded):
                    return a.get('role')
    except Exception:
        pass
    return None


def update_folder_access_v3(params, folder_uid, user_uid, role=None, hidden=None,
                            expiration_timestamp=None, as_team=False,
                            rotate_on_expiration=False, known_state=None):
    """Change an accessor's role / hidden flag / expiration on a folder.

    Direct access is changed with ``folderAccessUpdates`` and keeps its
    existing folder key. Inherited (or denied) access is turned into a direct
    grant with ``folderAccessAdds`` plus the recipient-encrypted folder key,
    so the child keeps its own key edge if parent access is later revoked.
    """
    if role is None and hidden is None and expiration_timestamp is None:
        raise ValueError("At least one field (role, hidden, or expiration) required")
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    actual_uid_bytes, identifier_label, access_type_enum = _resolve_accessor(
        params, user_uid, as_team)
    if not actual_uid_bytes:
        raise ValueError(f"{'Team' if as_team else 'User'} '{user_uid}' not found")
    accessor_uid_b64 = utils.base64_url_encode(actual_uid_bytes)

    accessors = []
    state = known_state
    if state is None:
        accessors = _lookup_folder_accessors(
            params, folder_uid, accessor_uid_b64,
            folder_pb2.AccessType.Name(access_type_enum))
        state = _folder_access_state(params, folder_uid, accessor_uid_b64, accessors)

    if state in (FOLDER_ACCESS_DIRECT, FOLDER_ACCESS_NONE):
        # NONE: nothing known to convert; let the server validate the update.
        plan = [{'request': FOLDER_ACCESS_UPDATE, 'include_folder_key': False,
                 'denied_access': False}]
    else:
        plan = plan_folder_access_change(params, folder_uid, accessor_uid_b64,
                                         'grant', state=state)
        if role is None:
            # An add needs a role; keep the one currently in effect.
            current = (_current_role_name(accessors) or '').lower()
            if current not in ROLE_NAME_MAP:
                raise ValueError(
                    'A role is required to change inherited or denied access on '
                    'this folder (it becomes a direct grant)')
            role = current

    def folder_key_factory():
        return _encrypted_folder_key_for(
            params, folder_uid, accessor_uid_b64, as_team,
            user_email=user_uid if '@' in (user_uid or '') else None)

    result = _execute_access_plan(
        params, folder_uid, identifier_label, actual_uid_bytes, access_type_enum,
        plan, folder_key_factory=folder_key_factory,
        messages={FOLDER_ACCESS_ADD: 'Access updated successfully'},
        role=role, hidden=hidden, expiration_timestamp=expiration_timestamp,
        rotate_on_expiration=rotate_on_expiration)
    result['access_type'] = 'AT_TEAM' if as_team else 'AT_USER'
    result['previous_access_state'] = state
    return result


def _folder_inherits_parent_permissions(params, folder_uid):
    """Return True when *folder_uid* has a parent and still inherits its access list."""
    nsf_folders = getattr(params, 'nested_share_folders', {})
    folder_obj = nsf_folders.get(folder_uid)
    if not folder_obj:
        return False
    parent_uid = folder_obj.get('parent_uid')
    if not parent_uid:
        return False
    inherit = folder_obj.get('inherit_user_permissions', 0) or 0
    return inherit != folder_pb2.BOOLEAN_FALSE


def _ensure_folder_direct_permissions(params, folder_uid):
    """Disable parent permission inheritance so folder access changes apply locally.
    """
    if not _folder_inherits_parent_permissions(params, folder_uid):
        return False
    return True


def _evict_folder_accessor_cache(params, folder_uid, accessor_uid_b64):
    """Drop a cached folder-access row after a successful revoke."""
    accesses = getattr(params, 'nested_share_folder_accesses', {}).get(folder_uid)
    if not accesses:
        return
    params.nested_share_folder_accesses[folder_uid] = [
        fa for fa in accesses
        if fa.get('access_type_uid') != accessor_uid_b64
    ]


def _application_folder_role(is_editable):
    return 'content-manager' if is_editable else 'viewer'


def grant_folder_access_to_application_v3(params, folder_uid, app_uid, app_key,
                                          is_editable=False):
    """Grant a Secrets Manager application access to an NSF folder.

    Uses ``vault/folders/v3/access_update`` with ``AT_APPLICATION``, matching
    the vault UI ``folderAccessAdds`` payload.
    """
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved
    if not app_uid or not app_key:
        raise ValueError('Application UID and key are required')

    role = _application_folder_role(is_editable)
    access_role = resolve_role_name(role)
    target_role_name = folder_pb2.AccessRoleType.Name(access_role)
    app_uid_bytes = utils.base64_url_decode(app_uid)

    existing = _check_existing_access(
        params, folder_uid, app_uid_bytes, target_role_name, 'AT_APPLICATION')
    if existing is not None:
        if existing == target_role_name:
            return {
                'folder_uid': folder_uid,
                'user_uid': app_uid,
                'access_type': 'AT_APPLICATION',
                'status': 'SUCCESS',
                'message': f'Application already has {role} access',
                'success': True,
                'action_taken': 'already_had_access',
            }
        return update_folder_access_to_application_v3(
            params, folder_uid, app_uid, is_editable=is_editable)

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = app_uid_bytes
    ad.accessType = folder_pb2.AT_APPLICATION
    ad.accessRoleType = access_role
    ad.permissions.CopyFrom(get_folder_permissions_for_role(access_role))

    folder_key = get_folder_key(params, folder_uid)
    ek = folder_pb2.EncryptedDataKey()
    ek.encryptedKey = crypto.encrypt_aes_v2(folder_key, app_key)
    ek.encryptedKeyType = folder_pb2.encrypted_by_data_key_gcm
    ad.folderKey.CopyFrom(ek)

    response = folder_access_update_v3(params, folder_access_adds=[ad])
    result = parse_folder_access_result(
        response, folder_uid, app_uid, 'Application access granted successfully')
    result['access_type'] = 'AT_APPLICATION'
    result.setdefault('action_taken', 'granted' if result['success'] else 'grant_failed')
    return result


def update_folder_access_to_application_v3(params, folder_uid, app_uid,
                                            is_editable=False):
    """Update an application's NSF folder role (viewer / content-manager)."""
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    role = _application_folder_role(is_editable)
    access_role = resolve_role_name(role)

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = utils.base64_url_decode(app_uid)
    ad.accessType = folder_pb2.AT_APPLICATION
    ad.accessRoleType = access_role
    ad.permissions.CopyFrom(get_folder_permissions_for_role(access_role))

    response = folder_access_update_v3(params, folder_access_updates=[ad])
    result = parse_folder_access_result(
        response, folder_uid, app_uid, 'Application access updated successfully')
    result['access_type'] = 'AT_APPLICATION'
    return result


def revoke_folder_access_from_application_v3(params, folder_uid, app_uid):
    """Revoke a Secrets Manager application's access to an NSF folder."""
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = utils.base64_url_decode(app_uid)
    ad.accessType = folder_pb2.AT_APPLICATION

    response = folder_access_update_v3(params, folder_access_removes=[ad])
    result = parse_folder_access_result(
        response, folder_uid, app_uid, 'Application access revoked successfully')
    result['access_type'] = 'AT_APPLICATION'
    if result.get('success'):
        params.sync_data = True
    return result


def revoke_folder_access_v3(params, folder_uid, user_uid, as_team=False):
    """Revoke user or team access to an NSF folder.

    Looks up the accessor via ``get_folder_access_v3`` so sub-folders use the
    server-reported UID and access type (including inherited accessors).

    * Direct access is removed with ``folderAccessRemoves``.
    * Inherited access cannot be removed on the child (it comes from the
      parent), so it is denied with ``folderAccessUpdates`` +
      ``deniedAccess=True`` and no folder key.
    * Already-denied access needs no request.

    On success, evicts the local access cache and sets ``params.sync_data``.
    """
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved

    _ensure_folder_direct_permissions(params, folder_uid)

    actual_uid_bytes, identifier_label, access_type_enum = _resolve_accessor(
        params, user_uid, as_team)
    if not actual_uid_bytes:
        raise ValueError(f"{'Team' if as_team else 'User'} '{user_uid}' not found")

    accessor_uid_b64 = utils.base64_url_encode(actual_uid_bytes)
    access_type_label = folder_pb2.AccessType.Name(access_type_enum)
    accessors = _lookup_folder_accessors(
        params, folder_uid, accessor_uid_b64, access_type_label)
    if accessors:
        accessor = accessors[0]
        server_uid = accessor.get('accessor_uid')
        if server_uid:
            actual_uid_bytes = utils.base64_url_decode(server_uid)
            accessor_uid_b64 = server_uid
        server_type = accessor.get('access_type')
        if server_type:
            access_type_label = server_type
            try:
                access_type_enum = folder_pb2.AccessType.Value(server_type)
            except ValueError:
                raise ValueError(
                    f"Unrecognised access type '{server_type}' returned by server "
                    f"for folder '{folder_uid}'")

    state = _folder_access_state(params, folder_uid, accessor_uid_b64, accessors)
    action = 'deny' if state == FOLDER_ACCESS_INHERITED else 'remove'
    plan = plan_folder_access_change(params, folder_uid, accessor_uid_b64, action,
                                     state=state)
    if not plan:
        return {'folder_uid': folder_uid, 'user_uid': identifier_label,
                'access_type': access_type_label, 'status': 'SUCCESS',
                'message': 'Access is already denied on this folder',
                'success': True, 'action_taken': 'already_denied',
                'previous_access_state': state}

    result = _execute_access_plan(
        params, folder_uid, identifier_label, actual_uid_bytes, access_type_enum, plan)
    result['access_type'] = access_type_label
    result['previous_access_state'] = state
    if result.get('success'):
        if action == 'deny':
            result['action_taken'] = 'denied'
        _evict_folder_accessor_cache(params, folder_uid, accessor_uid_b64)
        params.sync_data = True
    return result


def _batch_accessor_index(params, folder_uids):
    """Map (folder_uid, accessor_uid_b64) -> server accessor rows for a batch."""
    index = {}
    uids = sorted(set(folder_uids))
    for i in range(0, len(uids), 100):
        try:
            info = get_folder_access_v3(params, uids[i:i + 100], resolve_usernames=False)
        except Exception as exc:
            logger.debug('Batch folder accessor lookup failed: %s', exc)
            continue
        for fr in info.get('results', []):
            if not fr.get('success'):
                continue
            for a in fr.get('accessors', []):
                index.setdefault((fr['folder_uid'], a.get('accessor_uid')), []).append(a)
    return index


def _batch_resolve_accessor(params, spec):
    as_team = bool(spec.get('as_team'))
    if as_team:
        resolved_team = resolve_team_identifier(params, spec['user_uid'])
        if not resolved_team:
            raise ValueError(f"Team '{spec['user_uid']}' not found")
        _, uid_bytes = resolved_team
        return uid_bytes, folder_pb2.AT_TEAM, as_team
    uid_bytes = resolve_user_uid_bytes(params, spec['user_uid'])
    if not uid_bytes:
        raise ValueError(f"User '{spec['user_uid']}' not found")
    return uid_bytes, folder_pb2.AT_USER, as_team


def manage_folder_access_batch_v3(params, access_grants=None,
                                   access_updates=None, access_revokes=None):
    """Apply a batch of folder access grants/updates/revokes.

    Each operation is planned from the accessor's current state (see
    ``plan_folder_access_change``):

    * grant/update of inherited access -> ``folderAccessAdds`` + folder key
    * grant/update of denied access    -> denial removed in a first request,
      then ``folderAccessAdds`` + folder key in the main request (only for
      denials that were removed successfully)
    * grant/update of direct access    -> ``folderAccessUpdates`` (no key)
    * revoke of inherited access       -> ``folderAccessUpdates`` + deniedAccess
    * revoke of direct access          -> ``folderAccessRemoves``
    """
    ops = []
    for op, specs in (('grant', access_grants), ('update', access_updates),
                      ('revoke', access_revokes)):
        for spec in (specs or []):
            fuid = resolve_folder_identifier(params, spec['folder_uid'])
            if not fuid:
                raise ValueError(f"Folder '{spec['folder_uid']}' not found")
            uid_bytes, access_type_enum, as_team = _batch_resolve_accessor(params, spec)
            ops.append({'op': op, 'folder_uid': fuid, 'spec': spec,
                        'uid_bytes': uid_bytes,
                        'uid_b64': utils.base64_url_encode(uid_bytes),
                        'access_type_enum': access_type_enum, 'as_team': as_team})

    index = _batch_accessor_index(params, [o['folder_uid'] for o in ops])

    pre_removes, adds, updates, removes = [], [], [], []
    for o in ops:
        spec, fuid, uid_b64 = o['spec'], o['folder_uid'], o['uid_b64']
        rows = index.get((fuid, uid_b64), [])
        state = _folder_access_state(params, fuid, uid_b64, rows)
        o['state'] = state
        role = spec.get('role')

        if o['op'] == 'revoke':
            action = 'deny' if state == FOLDER_ACCESS_INHERITED else 'remove'
            plan = plan_folder_access_change(params, fuid, uid_b64, action, state=state)
        elif o['op'] == 'update' and state in (FOLDER_ACCESS_DIRECT, FOLDER_ACCESS_NONE):
            plan = [{'request': FOLDER_ACCESS_UPDATE, 'include_folder_key': False,
                     'denied_access': False}]
        else:
            plan = plan_folder_access_change(params, fuid, uid_b64, 'grant', state=state)
            if o['op'] == 'grant':
                role = role or 'viewer'
            if plan[-1]['request'] == FOLDER_ACCESS_ADD and not role:
                current = (_current_role_name(rows) or '').lower()
                if current not in ROLE_NAME_MAP:
                    raise ValueError(
                        f"A role is required to change inherited or denied access for "
                        f"'{spec['user_uid']}' on folder '{fuid}'")
                role = current

        o['steps'] = plan
        for idx, step in enumerate(plan):
            folder_key = None
            if step['include_folder_key']:
                folder_key = _encrypted_folder_key_for(
                    params, fuid, uid_b64, o['as_team'],
                    user_email=spec['user_uid'] if not o['as_team'] else None)
            ad = _build_access_step_data(
                fuid, o['uid_bytes'], o['access_type_enum'], step,
                role=role, hidden=spec.get('hidden'), folder_key=folder_key)
            if idx < len(plan) - 1:
                pre_removes.append((o, ad))   # denial removal before the add
            elif step['request'] == FOLDER_ACCESS_ADD:
                adds.append((o, ad))
            elif step['request'] == FOLDER_ACCESS_UPDATE:
                updates.append((o, ad))
            else:
                removes.append((o, ad))

    def _failures(response):
        failed = {}
        for r in (response.folderAccessResults or []):
            if r.status == folder_pb2.SUCCESS:
                continue
            key = (utils.base64_url_encode(r.folderUid),
                   utils.base64_url_encode(r.accessUid) if r.accessUid else None)
            failed[key] = (folder_pb2.FolderModifyStatus.Name(r.status), r.message)
        return failed

    failed = {}
    if pre_removes:
        failed.update(_failures(folder_access_update_v3(
            params, folder_access_removes=[ad for _, ad in pre_removes])))
        # Only add accessors whose denial was actually removed.
        adds = [(o, ad) for o, ad in adds
                if (o['folder_uid'], o['uid_b64']) not in failed]

    if adds or updates or removes:
        failed.update(_failures(folder_access_update_v3(
            params,
            folder_access_adds=[ad for _, ad in adds] or None,
            folder_access_updates=[ad for _, ad in updates] or None,
            folder_access_removes=[ad for _, ad in removes] or None)))

    results = []
    for o in ops:
        res = {'operation': o['op'], 'folder_uid': o['folder_uid'],
               'user_uid': o['spec']['user_uid'],
               'access_type': 'AT_TEAM' if o['as_team'] else 'AT_USER',
               'previous_access_state': o['state'],
               'status': 'SUCCESS', 'success': True,
               'message': (f"{o['op'].capitalize()} completed" if o['steps']
                           else 'Access is already denied on this folder')}
        err = failed.get((o['folder_uid'], o['uid_b64']))
        if err:
            res.update(status=err[0], message=err[1], success=False)
        results.append(res)
    return results


# ══════════════════════════════════════════════════════════════════════════
# Internal UID → username resolver
# ══════════════════════════════════════════════════════════════════════════

def _resolve_uid_to_username(params, uid_b64: str) -> Optional[str]:
    """Try to resolve a base64-url accessor UID to a username.

    Checks the share-objects cache (``vault/get_share_objects``), which
    includes every user the vault owner has ever interacted with and
    carries both ``username`` and ``userAccountUid`` fields.  The result
    is a cached API call so repeated lookups are free.
    """
    try:
        from ..proto.record_pb2 import GetShareObjectsRequest, GetShareObjectsResponse
        rq = GetShareObjectsRequest()
        rs = api.communicate_rest(params, rq, 'vault/get_share_objects',
                                  rs_type=GetShareObjectsResponse)
        for user_list in (rs.shareRelationships, rs.shareFamilyUsers,
                          rs.shareEnterpriseUsers, rs.shareMCEnterpriseUsers):
            for su in user_list:
                if su.userAccountUid:
                    su_uid = utils.base64_url_encode(su.userAccountUid)
                    if su_uid == uid_b64:
                        return su.username
    except Exception:
        pass
    return None


def _resolve_uid_to_team_name(params, uid_b64: str) -> Optional[str]:
    """Try to resolve a base64-url team UID to a human-readable team name."""
    team_cache = getattr(params, 'team_cache', None) or {}
    team = team_cache.get(uid_b64)
    if isinstance(team, dict):
        name = team.get('name')
        if name:
            return name

    enterprise = getattr(params, 'enterprise', None)
    if enterprise:
        for t in enterprise.get('teams', []):
            if t.get('team_uid') == uid_b64 and t.get('name'):
                return t['name']

    try:
        teams = api.get_share_objects(params).get('teams', {}) or {}
        team_info = teams.get(uid_b64)
        if isinstance(team_info, dict):
            name = team_info.get('name')
            if name:
                return name
    except Exception:
        pass

    for t in (getattr(params, 'available_team_cache', None) or []):
        if t.get('team_uid') == uid_b64:
            name = t.get('team_name')
            if name:
                return name

    return None


# ══════════════════════════════════════════════════════════════════════════
# High-level: get_folder_access_v3
# ══════════════════════════════════════════════════════════════════════════

def get_folder_access_v3(params, folder_uids, continuation_token=None,
                         page_size=None, resolve_usernames=True):
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
                if resolve_usernames:
                    if at == 'AT_USER':
                        username = getattr(params, 'user_cache', {}).get(auid)
                        if not username and hasattr(params, 'enterprise') and params.enterprise:
                            for u in params.enterprise.get('users', []):
                                if u.get('user_account_uid') == auid:
                                    username = u.get('username')
                                    break
                        if not username:
                            username = _resolve_uid_to_username(params, auid)
                            if username:
                                if not hasattr(params, 'user_cache'):
                                    params.user_cache = {}
                                params.user_cache[auid] = username
                    elif at == 'AT_TEAM':
                        username = _resolve_uid_to_team_name(params, auid)
                ai = {
                    'accessor_uid': auid, 'access_type': at, 'role': rt,
                    'inherited': bool(a.inherited), 'hidden': bool(a.hidden),
                    'denied_access': bool(getattr(a, 'deniedAccess', False)),
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
