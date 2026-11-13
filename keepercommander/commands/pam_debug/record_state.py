"""Record-level state that lives outside the graph and outside the record JSON.

Shared by `pam action debug dump` and the `pam project update` reader:

* ``rotation_info``: the rotation settings of a record (schedule, disabled, resource, complexity ...) as the vault
  cache holds them (``params.record_rotation_cache``). They are NOT in the graph, only the ACL ``rotation_settings``
  flags are.
* ``file_record_info``: name, size and time of the file record behind a ``fileRef`` (attachments, scripts).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Optional

from ... import crypto, utils, vault
from ...nested_share_folder.common import get_record_key
from ..pam_import.record_loader import load_pam_record

if TYPE_CHECKING:
    from ...params import KeeperParams


def record_json(params: 'KeeperParams', record_uid: str) -> tuple:
    """The record as ``get --format=json`` shows it (classic and NSF), plus a list of errors.

    Returns ``(data, errors)``. Moved out of the dump so that the dump and the `pam project update` reader read a
    record the same way. ``data`` has ``notes`` when the record has any.
    """
    from ... import vault_extensions
    from ...nested_share_folder.common import get_record_from_cache

    data: dict = {}
    errors: list = []
    loaded = None
    rec = get_record_from_cache(params, record_uid) or {}
    try:
        raw = rec.get('data_unencrypted')
        if raw:
            data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
        else:
            nsf_data = getattr(params, 'nested_share_record_data', {}).get(record_uid) or {}
            data = dict(nsf_data.get('data_json') or {})
        if not data:
            loaded = load_pam_record(params, record_uid)
            if loaded is not None:
                if isinstance(loaded, vault.TypedRecord):
                    data = vault_extensions.extract_typed_record_data(loaded)
                notes = getattr(loaded, 'notes', None)
                if notes:
                    data['notes'] = notes
        else:
            loaded = load_pam_record(params, record_uid)
            notes = getattr(loaded, 'notes', None) if loaded else None
            if notes:
                data['notes'] = notes
        if not data and loaded is None:
            errors.append({
                'stage': 'record_data',
                'message': 'Record data could not be loaded.',
            })
    except Exception as err:
        logging.warning('Could not build data for record %s: %s', record_uid, err)
        errors.append({
            'stage': 'record_data',
            'message': 'Record data could not be built.',
        })
    return data, errors


def file_refs(data: dict) -> list:
    """UIDs of the file records a record refers to: ``fileRef`` fields and the files of ``script`` fields."""
    uids: list = []
    for field in (data.get('fields') or []) + (data.get('custom') or []):
        if not isinstance(field, dict):
            continue
        for value in field.get('value') or []:
            if field.get('type') == 'fileRef' and isinstance(value, str):
                uids.append(value)
            elif field.get('type') == 'script' and isinstance(value, dict) and value.get('fileRef'):
                uids.append(value['fileRef'])
    return list(dict.fromkeys(uids))


def _decrypt_complexity(encrypted: str, params: 'KeeperParams', record_uid: str) -> Optional[dict]:
    """The password complexity rules of a rotation, or None when there are none or they cannot be decrypted."""
    if not encrypted:
        return None
    try:
        data = utils.base64_url_decode(encrypted)
        if not data:
            return None
        key = get_record_key(params, record_uid, raise_on_missing=False)
        if not key:
            return None
        return json.loads(crypto.decrypt_aes_v2(data, key).decode())
    except Exception:
        return None


def rotation_info(params: 'KeeperParams', record_uid: str) -> Optional[dict]:
    """The rotation settings of *record_uid* from the vault cache, or None when it has no rotation.

    ``schedule`` is the parsed schedule (a list of dicts as the server stores it) when it is JSON, else the raw text.
    ``pwd_complexity`` is the decrypted rules or None. The values are returned as they are; comparing them with
    the JSON of an import is the job of the diff, not of this reader.
    """
    entry = (getattr(params, 'record_rotation_cache', None) or {}).get(record_uid)
    if not entry:
        return None
    schedule = entry.get('schedule')
    if isinstance(schedule, (str, bytes)) and schedule:
        try:
            schedule = json.loads(schedule)
        except Exception:
            pass
    return {
        'record_uid': record_uid,
        'configuration_uid': entry.get('configuration_uid') or '',
        'resource_uid': entry.get('resource_uid') or '',
        'schedule': schedule,
        'disabled': bool(entry.get('disabled')),
        'pwd_complexity': _decrypt_complexity(entry.get('pwd_complexity') or '', params, record_uid),
        'last_rotation': entry.get('last_rotation'),
        'last_rotation_status': entry.get('last_rotation_status'),
        'revision': entry.get('revision'),
    }


def file_record_info(params: 'KeeperParams', file_uid: str) -> Optional[dict]:
    """Name, size, mime type and last-modified time (ms) of a file record, or None when it cannot be loaded.

    The vault keeps no content hash of a file, so these are all there is to compare.
    """
    try:
        record = load_pam_record(params, file_uid)
    except Exception:
        return None
    if not isinstance(record, vault.FileRecord):
        return None
    return {
        'record_uid': file_uid,
        'name': record.name or '',
        'size': record.size,
        'mime_type': record.mime_type or '',
        'last_modified': record.last_modified,
    }
