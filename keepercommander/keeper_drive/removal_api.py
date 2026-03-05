"""
KeeperDrive — record and folder removal (preview/confirm pattern).

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

def find_kd_folders_for_record(params, record_uid):
    """Return KeeperDrive folder UIDs that contain *record_uid*."""
    folders = []
    kd_fr = getattr(params, 'keeper_drive_folder_records', {})
    for fuid, rec_set in kd_fr.items():
        if record_uid in rec_set:
            folders.append(fuid)
    return folders


def resolve_kd_record_uid(params, identifier):
    """Resolve a record identifier (UID or title) to a KeeperDrive record UID."""
    kd = getattr(params, 'keeper_drive_records', {})
    if identifier in kd:
        return identifier
    lower = identifier.casefold()
    for uid, rec in kd.items():
        title = rec.get('title', '')
        if isinstance(title, str) and title.casefold() == lower:
            return uid
    return None


def resolve_kd_folder_uid(params, identifier):
    """Resolve a folder identifier (UID or name) to a KeeperDrive folder UID."""
    kd = getattr(params, 'keeper_drive_folders', {})
    if identifier in kd:
        return identifier
    fc = getattr(params, 'folder_cache', {})
    if identifier in fc:
        return identifier
    lower = identifier.casefold()
    for uid, f in kd.items():
        name = f.get('name', '')
        if isinstance(name, str) and name.casefold() == lower:
            return uid
    for uid, f in getattr(params, 'subfolder_cache', {}).items():
        name = f.get('name', '')
        if isinstance(name, str) and name.casefold() == lower:
            return uid
    return None


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
