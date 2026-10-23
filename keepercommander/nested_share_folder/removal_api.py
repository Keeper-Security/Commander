"""
Nested Share Folder — record and folder removal (preview/confirm pattern).

The preview → confirm two-step is shared via ``_execute_removal``.
"""

import logging
from typing import Optional, List, Dict, Any

from .. import utils, api
from ..proto import remove_pb2

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════
# Operation type mappings
# ══════════════════════════════════════════════════════════════════════════

_RECORD_OP_MAP = {
    'unlink':       remove_pb2.UNLINK_FROM_FOLDER,
    'folder-trash': remove_pb2.MOVE_TO_FOLDER_TRASH,
    'owner-trash':  remove_pb2.MOVE_TO_OWNER_TRASH,
}

_FOLDER_OP_MAP = {
    'folder-trash':     remove_pb2.FOLDER_MOVE_TO_FOLDER_TRASH,
    'delete-permanent': remove_pb2.FOLDER_DELETE_PERMANENT,
}


# ══════════════════════════════════════════════════════════════════════════
# Shared preview/confirm engine  (DRY — used by both record & folder)
# ══════════════════════════════════════════════════════════════════════════

def _parse_impact(res):
    """Parse a RemoveResult's impact field into a dict — shared logic."""
    if not res.HasField('impact'):
        return None
    imp = res.impact
    return {
        'folders_count':        imp.folders_count,
        'records_count':        imp.records_count,
        'affected_users_count': imp.affected_users_count,
        'affected_teams_count': imp.affected_teams_count,
        'record_info': [{'record_uid': utils.base64_url_encode(ri.record_uid),
                         'locations_count': ri.locations_count}
                        for ri in imp.record_info],
        'warnings': list(imp.warnings),
    }


def _parse_error(res):
    if not res.HasField('error'):
        return None
    return {
        'code':    remove_pb2.RemoveErrorCode.Name(res.error.code),
        'message': res.error.message,
    }


def _build_preview_results(preview_rs, uid_field='item_uid'):
    """Parse preview results — works for both record and folder removal."""
    results = []
    for res in preview_rs.results:
        item_uid = utils.base64_url_encode(getattr(res, uid_field, b''))
        entry = {
            'status': remove_pb2.RemoveStatus.Name(res.status),
            'impact': _parse_impact(res),
            'error':  _parse_error(res),
        }
        if hasattr(res, 'folder_uid') and res.folder_uid:
            entry['folder_uid'] = utils.base64_url_encode(res.folder_uid)
        else:
            entry['folder_uid'] = ''
        entry['record_uid'] = item_uid
        entry['folder_uid'] = entry.get('folder_uid', '')
        results.append(entry)
    return results


# ══════════════════════════════════════════════════════════════════════════
# Resolution helpers
# ══════════════════════════════════════════════════════════════════════════

def find_nested_share_folders_for_record(params, record_uid):
    """Return Nested Share Folder UIDs that contain *record_uid*."""
    folders = []
    nsf_fr = getattr(params, 'nested_share_folder_records', {})
    for fuid, rec_set in nsf_fr.items():
        if record_uid in rec_set:
            folders.append(fuid)
    return folders


def resolve_nested_share_record_uid(params, identifier):
    """Resolve a record identifier (UID, title, or name) to a record UID.

    Lookup order:
      1. Direct UID match in nested_share_records
      2. Direct UID match in record_cache (vault records)
      3. Title match from decrypted nested_share_record_data
      4. Title match from record_cache (data_unencrypted)

    When a title has exactly one accessible match and no owned match, the
    shared-in record is retained for compatibility with existing shared-record
    workflows. Callers that require an owned record should use an explicit UID
    or apply an owner-only check before mutating it.
    """
    import json

    if not isinstance(identifier, str):
        return None

    nsf = getattr(params, 'nested_share_records', {})
    if identifier in nsf:
        return identifier

    rc = getattr(params, 'record_cache', {})
    if identifier in rc:
        return identifier

    lower = identifier.casefold()

    nsf_data = getattr(params, 'nested_share_record_data', {})
    nsf_matches = []
    for uid in nsf:
        rd = nsf_data.get(uid, {})
        dj = rd.get('data_json', {})
        if isinstance(dj, dict):
            t = dj.get('title', '')
            if isinstance(t, str) and t.casefold() == lower:
                nsf_matches.append(uid)

    classic_matches = []
    for uid, rec in rc.items():
        if uid in nsf:
            continue
        data = rec.get('data_unencrypted')
        if data:
            try:
                dj = json.loads(data.decode('utf-8') if isinstance(data, bytes) else data)
                t = dj.get('title', '')
                if isinstance(t, str) and t.casefold() == lower:
                    classic_matches.append(uid)
            except Exception:
                pass

    matches = nsf_matches + classic_matches
    if not matches:
        return None

    owned_matches = [
        uid for uid in matches
        if _is_current_account_record_owner(
            params, uid,
            nsf_data.get(uid, {}) if uid in nsf else rc.get(uid, {}),
            rc.get(uid, {}),
        )
    ]
    if len(owned_matches) == 1:
        return owned_matches[0]
    if len(owned_matches) > 1:
        logging.warning("Multiple owned records match '%s'. Use UID instead.", identifier)
        return None
    if len(matches) == 1:
        return matches[0]

    logging.warning("Multiple records match '%s'. Use UID instead.", identifier)
    return None


def _is_current_account_record_owner(params, record_uid, nsf_data, record_obj):
    """Return whether cached ownership identifies the current account."""
    current_username = getattr(params, 'user', None)
    current_account_uid = ''
    account_uid_bytes = getattr(params, 'account_uid_bytes', None)
    if account_uid_bytes:
        try:
            from .. import utils
            current_account_uid = utils.base64_url_encode(account_uid_bytes)
        except Exception:
            pass

    for obj in (nsf_data or {}, record_obj or {},
                getattr(params, 'meta_data_cache', {}).get(record_uid, {})):
        owner_username = obj.get('user_username') or obj.get('owner_username')
        if (isinstance(owner_username, str) and owner_username and
                isinstance(current_username, str) and current_username and
                owner_username.casefold() == current_username.casefold()):
            return True

        owner_uid = obj.get('user_account_uid') or obj.get('owner_account_uid')
        if owner_uid and current_account_uid and owner_uid == current_account_uid:
            return True

    owner_info = getattr(params, 'record_owner_cache', {}).get(record_uid)
    if owner_info and owner_info.owner is True:
        return True
    return False


def resolve_nested_share_folder_uid(params, identifier):
    """Resolve a folder identifier (UID or name) to a Nested Share Folder UID."""
    # Keep all NSF folder lookups behind the ownership-aware resolver. This
    # helper is used by commands outside the main folder API, so an independent
    # name scan here would reintroduce the shared-in shadowing vulnerability.
    from .folder_api import resolve_folder_identifier
    return resolve_folder_identifier(params, identifier)


# ══════════════════════════════════════════════════════════════════════════
# Record removal
# ══════════════════════════════════════════════════════════════════════════

def remove_record_v3(params, removals, dry_run=False):
    if not removals:
        raise ValueError("At least one record required")
    if len(removals) > 500:
        raise ValueError("Maximum 500 records per request")

    preview_rq = remove_pb2.RemoveRecordRequest()
    preview_rq.action = remove_pb2.REMOVE_ACTION_PREVIEW
    for item in removals:
        op = item.get('operation_type', 'owner-trash')
        if op not in _RECORD_OP_MAP:
            raise ValueError(f"Invalid operation_type '{op}'. Use: {', '.join(_RECORD_OP_MAP)}")
        rr = remove_pb2.RecordRemoval()
        rr.record_uid = utils.base64_url_decode(item['record_uid'])
        fuid = item.get('folder_uid')
        rr.folder_uid = utils.base64_url_decode(fuid) if fuid else b''
        rr.operation_type = _RECORD_OP_MAP[op]
        preview_rq.records.append(rr)

    preview_rs = api.communicate_rest(params, preview_rq,
                                      'vault/folders/v3/remove_record',
                                      rs_type=remove_pb2.RemoveResponse)

    preview_results = _build_preview_results(preview_rs)
    token_expires = preview_rs.token_expires_at or None

    if dry_run or not preview_rs.confirmation_token:
        return {'preview_results': preview_results, 'confirmed': False,
                'confirmation_token_expires_at': token_expires}

    confirm_rq = remove_pb2.RemoveRecordRequest()
    confirm_rq.action = remove_pb2.REMOVE_ACTION_CONFIRM
    confirm_rq.confirmation_token = preview_rs.confirmation_token
    confirm_rq.records.extend(preview_rq.records)
    api.communicate_rest(params, confirm_rq,
                         'vault/folders/v3/remove_record',
                         rs_type=remove_pb2.RemoveResponse)
    return {'preview_results': preview_results, 'confirmed': True,
            'confirmation_token_expires_at': token_expires}


# ══════════════════════════════════════════════════════════════════════════
# Folder removal
# ══════════════════════════════════════════════════════════════════════════

def remove_folder_v3(params, removals, dry_run=False):
    if not removals:
        raise ValueError("At least one folder required")
    if len(removals) > 100:
        raise ValueError("Maximum 100 folders per request")

    preview_rq = remove_pb2.RemoveFolderRequest()
    preview_rq.action = remove_pb2.REMOVE_ACTION_PREVIEW
    for item in removals:
        op = item.get('operation_type', 'folder-trash')
        if op not in _FOLDER_OP_MAP:
            raise ValueError(f"Invalid operation_type '{op}'. Use: {', '.join(_FOLDER_OP_MAP)}")
        fr = remove_pb2.FolderRemoval()
        fr.folder_uid = utils.base64_url_decode(item['folder_uid'])
        fr.operation_type = _FOLDER_OP_MAP[op]
        preview_rq.folders.append(fr)

    preview_rs = api.communicate_rest(params, preview_rq,
                                      'vault/folders/v3/remove_folder',
                                      rs_type=remove_pb2.RemoveResponse)

    preview_results = []
    for res in preview_rs.results:
        preview_results.append({
            'folder_uid': utils.base64_url_encode(res.item_uid),
            'status': remove_pb2.RemoveStatus.Name(res.status),
            'impact': _parse_impact(res),
            'error':  _parse_error(res),
        })
    token_expires = preview_rs.token_expires_at or None

    if dry_run or not preview_rs.confirmation_token:
        return {'preview_results': preview_results, 'confirmed': False,
                'confirmation_token_expires_at': token_expires}

    confirm_rq = remove_pb2.RemoveFolderRequest()
    confirm_rq.action = remove_pb2.REMOVE_ACTION_CONFIRM
    confirm_rq.confirmation_token = preview_rs.confirmation_token
    confirm_rq.folders.extend(preview_rq.folders)
    api.communicate_rest(params, confirm_rq,
                         'vault/folders/v3/remove_folder',
                         rs_type=remove_pb2.RemoveResponse)
    return {'preview_results': preview_results, 'confirmed': True,
            'confirmation_token_expires_at': token_expires}
