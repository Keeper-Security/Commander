"""
Nested Share Folder — folder and record move operations (Keeper Drive move API).
"""

import logging

from .. import utils, api
from ..proto import folder_pb2, keeperdrive_move_pb2

from .common import (
    get_folder_key, get_record_key, get_record_key_type,
    encrypt_record_key_for_folder,
)
from .folder_api import resolve_folder_identifier, encrypt_folder_key

logger = logging.getLogger(__name__)

_SUCCESSFUL_MOVE_RESULTS = (
    keeperdrive_move_pb2.MOVED,
    keeperdrive_move_pb2.TARGET_ALREADY_PRESENT_SOURCE_REMOVED,
)


# ══════════════════════════════════════════════════════════════════════════
# Folder move
# ══════════════════════════════════════════════════════════════════════════

def folder_move_v3(params, moves):
    """Reparent one or more folders. Each *moves* entry is a dict with keys
    ``folder_uid`` and ``target_parent_uid`` (``None``/falsy means root).
    """
    if not moves:
        raise ValueError("Provide at least one folder move")

    rq = keeperdrive_move_pb2.FolderMoveRequest()
    for spec in moves:
        folder_uid = resolve_folder_identifier(params, spec['folder_uid'])
        if not folder_uid:
            raise ValueError(f"Folder '{spec['folder_uid']}' not found")

        folder_key = get_folder_key(params, folder_uid)
        target_parent_uid = spec.get('target_parent_uid')
        if target_parent_uid:
            resolved_parent = resolve_folder_identifier(params, target_parent_uid)
            if not resolved_parent:
                raise ValueError(f"Target folder '{target_parent_uid}' not found")
            parent_key = get_folder_key(params, resolved_parent, raise_on_missing=False)
            if not parent_key:
                parent_key = params.data_key
            target_bytes = utils.base64_url_decode(resolved_parent)
        else:
            parent_key = params.data_key
            target_bytes = b''

        mv = keeperdrive_move_pb2.FolderMove()
        mv.folder_uid = utils.base64_url_decode(folder_uid)
        mv.target_parent_uid = target_bytes
        mv.encrypted_folder_key = encrypt_folder_key(folder_key, parent_key, use_gcm=True)
        rq.moves.append(mv)

    rs = api.communicate_rest(params, rq, 'vault/folders/v3/folder_move',
                              rs_type=keeperdrive_move_pb2.FolderMoveResponse)
    return [_parse_folder_move_result(r) for r in rs.results]


def _parse_folder_move_result(r):
    move_status = keeperdrive_move_pb2.MoveResultStatus.Name(r.move_result_status)
    return {
        'folder_uid': utils.base64_url_encode(r.folder_uid),
        'target_parent_uid': (utils.base64_url_encode(r.target_parent_uid)
                              if r.target_parent_uid else ''),
        'status': folder_pb2.FolderModifyStatus.Name(r.status),
        'message': r.message,
        'move_result_status': move_status,
        'success': (r.status == folder_pb2.SUCCESS
                   and r.move_result_status in _SUCCESSFUL_MOVE_RESULTS),
    }


def move_folder_v3(params, folder_uid, target_parent_uid=None):
    """Move a single folder under *target_parent_uid* (``None`` = root)."""
    results = folder_move_v3(params, [{
        'folder_uid': folder_uid, 'target_parent_uid': target_parent_uid,
    }])
    if not results:
        raise ValueError("No results from folder move")
    return results[0]


# ══════════════════════════════════════════════════════════════════════════
# Record move
# ══════════════════════════════════════════════════════════════════════════

def folder_record_move_v3(params, moves):
    """Move one or more records between folders. Each *moves* entry is a dict
    with keys ``record_uid``, ``source_folder_uid`` and ``target_folder_uid``
    (``None``/falsy for either folder means root).
    """
    if not moves:
        raise ValueError("Provide at least one record move")

    rq = keeperdrive_move_pb2.FolderRecordMoveRequest()
    for spec in moves:
        record_uid = spec['record_uid']
        record_key = get_record_key(params, record_uid)
        record_key_type = get_record_key_type(params, record_uid)

        target_folder_uid = spec.get('target_folder_uid')
        if target_folder_uid:
            resolved_target = resolve_folder_identifier(params, target_folder_uid)
            if not resolved_target:
                raise ValueError(f"Target folder '{target_folder_uid}' not found")
            target_key = get_folder_key(params, resolved_target)
            target_bytes = utils.base64_url_decode(resolved_target)
        else:
            target_key = params.data_key
            target_bytes = b''

        source_folder_uid = spec.get('source_folder_uid')
        if source_folder_uid:
            resolved_source = resolve_folder_identifier(params, source_folder_uid)
            source_bytes = utils.base64_url_decode(resolved_source or source_folder_uid)
        else:
            source_bytes = b''

        encrypted_record_key, _ = encrypt_record_key_for_folder(
            record_key, target_key, record_key_type)

        mv = keeperdrive_move_pb2.FolderRecordMove()
        mv.source_folder_uid = source_bytes
        mv.target_folder_uid = target_bytes
        mv.record_uid = utils.base64_url_decode(record_uid)
        mv.encrypted_record_key = encrypted_record_key
        rq.moves.append(mv)

    rs = api.communicate_rest(params, rq, 'vault/folders/v3/record_move',
                              rs_type=keeperdrive_move_pb2.FolderRecordMoveResponse)
    return [_parse_record_move_result(r) for r in rs.results]


def _parse_record_move_result(r):
    move_status = keeperdrive_move_pb2.MoveResultStatus.Name(r.move_result_status)
    return {
        'record_uid': utils.base64_url_encode(r.record_uid),
        'source_folder_uid': (utils.base64_url_encode(r.source_folder_uid)
                              if r.source_folder_uid else ''),
        'target_folder_uid': (utils.base64_url_encode(r.target_folder_uid)
                              if r.target_folder_uid else ''),
        'status': folder_pb2.FolderModifyStatus.Name(r.status),
        'message': r.message,
        'move_result_status': move_status,
        'success': (r.status == folder_pb2.SUCCESS
                   and r.move_result_status in _SUCCESSFUL_MOVE_RESULTS),
    }


def move_folder_record_v3(params, record_uid, source_folder_uid=None,
                          target_folder_uid=None):
    """Move a single record from *source_folder_uid* to *target_folder_uid*
    (``None`` = root for either).
    """
    results = folder_record_move_v3(params, [{
        'record_uid': record_uid,
        'source_folder_uid': source_folder_uid,
        'target_folder_uid': target_folder_uid,
    }])
    if not results:
        raise ValueError("No results from record move")
    return results[0]
