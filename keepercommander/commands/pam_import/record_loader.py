#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from __future__ import annotations

from typing import Iterator, Optional

from ... import vault
from ...nested_share_folder.common import get_record_from_cache


def iter_accessible_record_uids(params) -> Iterator[str]:
    """Yield record UIDs from classic and Nested Shared Folder caches."""
    seen = set()
    for attr in ('record_cache', 'nested_share_records'):
        cache = getattr(params, attr, None)
        if not isinstance(cache, dict):
            continue
        for uid in cache:
            if uid not in seen:
                seen.add(uid)
                yield uid

    nsf_record_data = getattr(params, 'nested_share_record_data', None)
    if isinstance(nsf_record_data, dict):
        for uid in nsf_record_data:
            if uid not in seen:
                seen.add(uid)
                yield uid


def load_pam_record(params, record_uid: str) -> Optional[vault.KeeperRecord]:
    """Load a vault record from classic cache, NSF cache, or NSF record data."""
    record_uid = (record_uid or '').strip()
    if not record_uid:
        return None

    cached = get_record_from_cache(params, record_uid)
    if cached and cached.get('data_unencrypted'):
        rec = vault.KeeperRecord.load(params, cached)
        if rec:
            return rec

    rec = vault.KeeperRecord.load(params, record_uid)
    if rec:
        return rec

    nsf_record_data = getattr(params, 'nested_share_record_data', None) or {}
    nsf_records = getattr(params, 'nested_share_records', None) or {}
    rd = nsf_record_data.get(record_uid) or {}
    if 'data_json' not in rd:
        return None

    dj = rd['data_json']
    version = nsf_records.get(record_uid, {}).get('version', 3)
    if version not in (3, 6):
        return None

    keeper_record = vault.TypedRecord(version=version)
    keeper_record.record_uid = record_uid
    keeper_record.load_record_data(dj, None)
    return keeper_record
