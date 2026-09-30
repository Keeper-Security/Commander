"""
Classic-to-Nested Share Record conversion API.

The server performs the migration of Classic database rows to Nested Share
data rows. The client supplies the record key wrapped for the destination folder
and for the owner's key history.
"""

from typing import Optional

from .. import api, crypto, utils
from ..proto import keeperdrive_convert_pb2

from .common import get_folder_key, get_record_key, is_keeper_uid
from .folder_api import resolve_folder_identifier

MAX_CONVERT_RECORDS = 100


def _decode_uid(uid: str, field_name: str) -> bytes:
    """Decode a canonical Keeper UID and enforce its 16-byte wire form."""
    if not isinstance(uid, str) or not is_keeper_uid(uid):
        raise ValueError(f"{field_name} must be a valid Keeper UID")
    decoded = utils.base64_url_decode(uid)
    if len(decoded) != 16:
        raise ValueError(f"{field_name} must decode to 16 bytes")
    return decoded


def _resolve_target_folder(params, folder_uid: Optional[str]):
    """Return (UID bytes, unencrypted key) for a Nested Share Folder or root."""
    if not folder_uid:
        # Per the endpoint contract, an empty UID is the caller's root folder.
        return b'', params.data_key

    resolved_uid = resolve_folder_identifier(params, folder_uid)
    if not resolved_uid:
        raise ValueError(f"Nested Share Folder '{folder_uid}' was not found")

    # resolve_folder_identifier also understands Classic folders. Conversion
    # only accepts an existing Nested Share Folder as a non-root destination.
    if resolved_uid not in (getattr(params, 'nested_share_folders', {}) or {}):
        raise ValueError(f"'{folder_uid}' is not a Nested Share Folder")

    folder_key = get_folder_key(params, resolved_uid, raise_on_missing=True)
    return _decode_uid(resolved_uid, "folder_uid"), folder_key


def build_convert_records_request(params, record_uids, folder_uid=None):
    """Build and locally validate a Classic-to-Nested Share request.

    ``folder_uid`` may be omitted/empty to target the caller's root folder.
    All records in this helper call share one destination folder.
    """
    if isinstance(record_uids, str):
        record_uids = [record_uids]
    else:
        record_uids = list(record_uids or [])

    if not record_uids:
        raise ValueError("Provide at least one Classic record to convert")
    if len(record_uids) > MAX_CONVERT_RECORDS:
        raise ValueError(f"Convert at most {MAX_CONVERT_RECORDS} records per request")

    if not getattr(params, 'data_key', None):
        raise ValueError("User data key is not available; run sync-down and log in again")

    folder_uid_bytes, folder_key = _resolve_target_folder(params, folder_uid)
    rq = keeperdrive_convert_pb2.ConvertRecordRequest()
    seen = set()

    for record_uid in record_uids:
        if record_uid in seen:
            raise ValueError(f"Duplicate record UID in conversion request: {record_uid}")
        seen.add(record_uid)
        record_uid_bytes = _decode_uid(record_uid, "record_uid")

        record_key = get_record_key(params, record_uid, raise_on_missing=True)
        if not isinstance(record_key, bytes) or len(record_key) != 32:
            raise ValueError(
                f"Record key for {record_uid} is unavailable or has an invalid length")

        item = rq.records.add()
        item.record_uid = record_uid_bytes
        item.folder_uid = folder_uid_bytes
        item.record_key_encrypted_by_folder_key = crypto.encrypt_aes_v2(
            record_key, folder_key)
        item.record_key_encrypted_by_owner_key = crypto.encrypt_aes_v2(
            record_key, params.data_key)

    return rq


def convert_records_v3(params, record_uids, folder_uid=None):
    """Convert Classic records to Nested Share Records and return results.

    The endpoint returns a mixed result bag with no ordering guarantee, so
    callers should associate each result with its UID.
    """
    rq = build_convert_records_request(params, record_uids, folder_uid)
    rs = api.communicate_rest(
        params, rq, 'vault/records/v3/convert',
        rs_type=keeperdrive_convert_pb2.ConvertRecordResponse)
    if rs is None:
        raise ValueError("No response received from the record conversion endpoint")

    results = []
    for result in rs.results:
        try:
            status = keeperdrive_convert_pb2.ConvertRecordStatus.Name(result.status)
        except ValueError:
            status = f"UNKNOWN_STATUS_{int(result.status)}"
        results.append({
            'record_uid': utils.base64_url_encode(result.record_uid),
            'status': status,
            'success': result.status == keeperdrive_convert_pb2.OK,
        })
    return results
