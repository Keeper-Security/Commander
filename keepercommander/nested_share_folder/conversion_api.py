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
AES_KEY_LENGTH = 32


def _validate_aes_key(key: bytes, key_name: str) -> None:
    if not isinstance(key, bytes) or len(key) != AES_KEY_LENGTH:
        raise ValueError(f"{key_name} must be a {AES_KEY_LENGTH}-byte key")


def _decode_uid(uid: str, field_name: str) -> bytes:
    """Decode a canonical Keeper UID and enforce its 16-byte wire form."""
    if not isinstance(uid, str) or not is_keeper_uid(uid):
        raise ValueError(f"{field_name} must be a valid Keeper UID")
    decoded = utils.base64_url_decode(uid)
    if len(decoded) != 16:
        raise ValueError(f"{field_name} must decode to 16 bytes")
    if utils.base64_url_encode(decoded) != uid:
        raise ValueError(f"{field_name} must use canonical Keeper UID encoding")
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

    data_key = getattr(params, 'data_key', None)
    if not data_key:
        raise ValueError("User data key is not available; run sync-down and log in again")
    _validate_aes_key(data_key, "User data key")

    folder_uid_bytes, folder_key = _resolve_target_folder(params, folder_uid)
    _validate_aes_key(folder_key, "Destination folder key")
    rq = keeperdrive_convert_pb2.ConvertRecordRequest()
    seen = set()
    nested_share_records = getattr(params, 'nested_share_records', {}) or {}
    record_cache = getattr(params, 'record_cache', {}) or {}
    record_owner_cache = getattr(params, 'record_owner_cache', {}) or {}

    for record_uid in record_uids:
        record_uid_bytes = _decode_uid(record_uid, "record_uid")
        if record_uid_bytes in seen:
            raise ValueError(f"Duplicate record UID in conversion request: {record_uid}")
        seen.add(record_uid_bytes)

        record = record_cache.get(record_uid)
        if record_uid in nested_share_records or (
                record is not None and record.get('source') == 'nested_share_folder'):
            raise ValueError(f"Record {record_uid} is already a Nested Share Record")
        if record_uid not in record_cache:
            raise ValueError(f"Classic record {record_uid} was not found in the record cache")

        owner_info = record_owner_cache.get(record_uid)
        # Missing ownership metadata is inconclusive; the endpoint remains authoritative.
        if owner_info is not None and owner_info.owner is False:
            raise ValueError(f"Record {record_uid} is not owned by the caller")

        record_key = get_record_key(params, record_uid, raise_on_missing=True)
        _validate_aes_key(record_key, f"Record key for {record_uid}")

        item = rq.records.add()
        item.record_uid = record_uid_bytes
        item.folder_uid = folder_uid_bytes
        item.record_key_encrypted_by_folder_key = crypto.encrypt_aes_v2(
            record_key, folder_key)
        item.record_key_encrypted_by_owner_key = crypto.encrypt_aes_v2(
            record_key, data_key)

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
