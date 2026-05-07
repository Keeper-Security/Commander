"""
KeeperDrive — folder-record linking, moving, and batch operations.
"""

import logging
from typing import Optional, List, Dict, Any

from .. import utils, api
from ..proto import folder_pb2

from .common import (
    get_folder_key, get_record_key, get_record_key_type,
    encrypt_record_key_for_folder,
)
from .folder_api import resolve_folder_identifier

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════
# Transport
# ══════════════════════════════════════════════════════════════════════════

def folder_record_update_v3(params, folder_uid, add_records=None,
                             update_records=None, remove_records=None):
    for label, lst in [('add', add_records), ('update', update_records),
                       ('remove', remove_records)]:
        if lst and len(lst) > 500:
            raise ValueError(f"Maximum 500 records to {label}")
    if not any([add_records, update_records, remove_records]):
        raise ValueError("At least one operation required")
    rq = folder_pb2.FolderRecordUpdateRequest()
    rq.folderUid = utils.base64_url_decode(folder_uid)
    if add_records:
        rq.addRecords.extend(add_records)
    if update_records:
        rq.updateRecords.extend(update_records)
    if remove_records:
        rq.removeRecords.extend(remove_records)
    return api.communicate_rest(params, rq, 'vault/folders/v3/record_update',
                                rs_type=folder_pb2.FolderRecordUpdateResponse)


# ══════════════════════════════════════════════════════════════════════════
# Internal builders (DRY for add/update/move/batch)
# ══════════════════════════════════════════════════════════════════════════

def _build_record_metadata(params, folder_uid, record_uid,
                            expiration_timestamp=None):
    """Build RecordMetadata with encrypted record key and optional TLA."""
    fk = get_folder_key(params, folder_uid)
    rk = get_record_key(params, record_uid)
    rkt = get_record_key_type(params, record_uid)
    enc_rk, enc_rkt = encrypt_record_key_for_folder(rk, fk, rkt)

    rm = folder_pb2.RecordMetadata()
    rm.recordUid = utils.base64_url_decode(record_uid)
    rm.encryptedRecordKey = enc_rk
    rm.encryptedRecordKeyType = enc_rkt
    if expiration_timestamp is not None:
        rm.tlaProperties.expiration = expiration_timestamp
    return rm


def _build_removal_metadata(record_uid):
    """Build minimal RecordMetadata for removal (only UID needed)."""
    rm = folder_pb2.RecordMetadata()
    rm.recordUid = utils.base64_url_decode(record_uid)
    rm.encryptedRecordKey = b''
    rm.encryptedRecordKeyType = folder_pb2.no_key
    return rm


def _parse_folder_record_response(response, folder_uid, record_uid, success_msg):
    if response.folderRecordUpdateResult:
        r = response.folderRecordUpdateResult[0]
        return {
            'folder_uid': folder_uid, 'record_uid': record_uid,
            'status': folder_pb2.FolderModifyStatus.Name(r.status),
            'message': r.message, 'success': r.status == folder_pb2.SUCCESS,
        }
    return {
        'folder_uid': folder_uid, 'record_uid': record_uid,
        'status': 'SUCCESS', 'message': success_msg, 'success': True,
    }


# ══════════════════════════════════════════════════════════════════════════
# High-level: add / update / remove record in folder
# ══════════════════════════════════════════════════════════════════════════

def add_record_to_folder_v3(params, folder_uid, record_uid,
                             expiration_timestamp=None):
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    rm = _build_record_metadata(params, resolved, record_uid, expiration_timestamp)
    rs = folder_record_update_v3(params, resolved, add_records=[rm])
    return _parse_folder_record_response(rs, resolved, record_uid,
                                          'Record added to folder successfully')


def update_record_in_folder_v3(params, folder_uid, record_uid,
                                expiration_timestamp=None):
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    rm = _build_record_metadata(params, resolved, record_uid, expiration_timestamp)
    rs = folder_record_update_v3(params, resolved, update_records=[rm])
    return _parse_folder_record_response(rs, resolved, record_uid,
                                          'Record updated in folder successfully')


def remove_record_from_folder_v3(params, folder_uid, record_uid):
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    rm = _build_removal_metadata(record_uid)
    rs = folder_record_update_v3(params, resolved, remove_records=[rm])
    return _parse_folder_record_response(rs, resolved, record_uid,
                                          'Record removed from folder successfully')


# ══════════════════════════════════════════════════════════════════════════
# High-level: move record between folders
# ══════════════════════════════════════════════════════════════════════════

def move_record_v3(params, record_uid, from_folder_uid=None, to_folder_uid=None):
    from .. import sync_down
    sync_down.sync_down(params)

    if not from_folder_uid and not to_folder_uid:
        raise ValueError("Cannot move from root to root")

    if from_folder_uid:
        resolved_from = resolve_folder_identifier(params, from_folder_uid)
        if not resolved_from:
            raise ValueError(f"Source folder '{from_folder_uid}' not found")
        from_folder_uid = resolved_from
        try:
            rm_meta = _build_removal_metadata(record_uid)
            rs = folder_record_update_v3(params, from_folder_uid, remove_records=[rm_meta])
            if rs.folderRecordUpdateResult:
                r = rs.folderRecordUpdateResult[0]
                if r.status != folder_pb2.SUCCESS:
                    return _move_failure(record_uid, from_folder_uid, to_folder_uid,
                                         f"Remove failed: {r.message}")
        except Exception as e:
            return _move_failure(record_uid, from_folder_uid, to_folder_uid,
                                 f"Remove error: {e}")

    rk = get_record_key(params, record_uid)
    rkt = get_record_key_type(params, record_uid)

    if to_folder_uid:
        resolved_to = resolve_folder_identifier(params, to_folder_uid)
        if not resolved_to:
            raise ValueError(f"Destination folder '{to_folder_uid}' not found")
        to_folder_uid = resolved_to
        fk = get_folder_key(params, to_folder_uid)
        enc_rk, enc_rkt = encrypt_record_key_for_folder(rk, fk, rkt)
        target_uid = to_folder_uid
    else:
        enc_rk, enc_rkt = encrypt_record_key_for_folder(rk, params.data_key, rkt)
        target_uid = ''

    add_meta = folder_pb2.RecordMetadata()
    add_meta.recordUid = utils.base64_url_decode(record_uid)
    add_meta.encryptedRecordKey = enc_rk
    add_meta.encryptedRecordKeyType = enc_rkt

    try:
        rs = folder_record_update_v3(params, target_uid, add_records=[add_meta])
        if rs.folderRecordUpdateResult:
            r = rs.folderRecordUpdateResult[0]
            if r.status != folder_pb2.SUCCESS:
                return _move_failure(record_uid, from_folder_uid, to_folder_uid,
                                     f"Add failed: {r.message}")
    except Exception as e:
        return _move_failure(record_uid, from_folder_uid, to_folder_uid,
                             f"Add error: {e}")

    return {
        'record_uid': record_uid,
        'from_folder': from_folder_uid or 'root',
        'to_folder': to_folder_uid or 'root',
        'success': True, 'message': 'Record moved successfully',
    }


def _move_failure(record_uid, from_folder, to_folder, msg):
    return {
        'record_uid': record_uid,
        'from_folder': from_folder or 'root',
        'to_folder': to_folder or 'root',
        'success': False, 'message': msg,
    }


# ══════════════════════════════════════════════════════════════════════════
# High-level: batch add/remove records
# ══════════════════════════════════════════════════════════════════════════

def manage_folder_records_batch_v3(params, folder_uid, records_to_add=None,
                                    records_to_remove=None):
    resolved = resolve_folder_identifier(params, folder_uid)
    if not resolved:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved
    fk = get_folder_key(params, folder_uid)

    adds, removes, tracking = [], [], []

    for ruid in (records_to_add or []):
        rk = get_record_key(params, ruid)
        rkt = get_record_key_type(params, ruid)
        enc_rk, enc_rkt = encrypt_record_key_for_folder(rk, fk, rkt)
        rm = folder_pb2.RecordMetadata()
        rm.recordUid = utils.base64_url_decode(ruid)
        rm.encryptedRecordKey = enc_rk
        rm.encryptedRecordKeyType = enc_rkt
        adds.append(rm)
        tracking.append(('add', ruid))

    for ruid in (records_to_remove or []):
        removes.append(_build_removal_metadata(ruid))
        tracking.append(('remove', ruid))

    rs = folder_record_update_v3(
        params, folder_uid,
        add_records=adds or None, remove_records=removes or None)

    results = [{'operation': op, 'folder_uid': folder_uid, 'record_uid': ruid,
                'status': 'SUCCESS', 'message': f'{op.capitalize()} completed',
                'success': True} for op, ruid in tracking]

    if rs.folderRecordUpdateResult:
        for r in rs.folderRecordUpdateResult:
            ruid = utils.base64_url_encode(r.recordUid)
            for i, (op, tracked) in enumerate(tracking):
                if tracked == ruid:
                    results[i] = {
                        'operation': op, 'folder_uid': folder_uid,
                        'record_uid': ruid,
                        'status': folder_pb2.FolderModifyStatus.Name(r.status),
                        'message': r.message,
                        'success': r.status == folder_pb2.SUCCESS,
                    }
                    break
    return results
