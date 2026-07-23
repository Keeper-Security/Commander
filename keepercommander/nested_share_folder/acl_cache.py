#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""Session ACL caches for NSF (and helpers to warm classic record shares).

Sync-down only stores the current user's NSF access rows plus sharing-state
flags. Full accessor lists require ``get_folder_access_v3`` /
``get_record_accesses_v3``. This module batch-fetches those once and keeps
them in dedicated in-memory caches so ``tree -s`` (and other callers) can
read without re-hitting the ACL APIs.

These caches are intentionally separate from ``nested_share_folder_accesses`` /
``nested_share_record_accesses`` so permission checks and key decrypt that
rely on sync-shaped self rows are not overwritten.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Optional, Sequence, Set

from .. import api

_FOLDER_BATCH = 100
_RECORD_BATCH = 10
_RECORD_BATCH_MIN = 1

_FOLDER_SHARE_CACHE = 'nested_share_folder_share_cache'
_RECORD_SHARE_CACHE = 'nested_share_record_share_cache'


def ensure_share_caches(params) -> None:
    if not hasattr(params, _FOLDER_SHARE_CACHE) or getattr(params, _FOLDER_SHARE_CACHE) is None:
        setattr(params, _FOLDER_SHARE_CACHE, {})
    if not hasattr(params, _RECORD_SHARE_CACHE) or getattr(params, _RECORD_SHARE_CACHE) is None:
        setattr(params, _RECORD_SHARE_CACHE, {})


def clear_share_caches(params) -> None:
    if hasattr(params, _FOLDER_SHARE_CACHE) and isinstance(getattr(params, _FOLDER_SHARE_CACHE), dict):
        getattr(params, _FOLDER_SHARE_CACHE).clear()
    if hasattr(params, _RECORD_SHARE_CACHE) and isinstance(getattr(params, _RECORD_SHARE_CACHE), dict):
        getattr(params, _RECORD_SHARE_CACHE).clear()


def _chunked(items: Sequence[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield list(items[i:i + size])


def _warm_nsf_folder_chunk(params, cache, chunk: List[str]) -> None:
    """Fetch one folder-UID chunk, following pagination; leave failures uncached."""
    from .folder_api import get_folder_access_v3

    accumulated: dict = {}
    failed: Set[str] = set()
    token = None
    for _ in range(50):
        info = get_folder_access_v3(
            params, chunk, continuation_token=token, resolve_usernames=True)
        for fr in info.get('results') or []:
            fuid = fr.get('folder_uid')
            if not fuid:
                continue
            if fr.get('success'):
                accumulated.setdefault(fuid, []).extend(fr.get('accessors') or [])
            else:
                failed.add(fuid)
                logging.debug('NSF folder ACL warm error for %s: %s', fuid, fr.get('error'))
        if not info.get('has_more'):
            break
        token = info.get('continuation_token')
        if token is None:
            break

    for fuid, accessors in accumulated.items():
        cache[fuid] = accessors
    for fuid in failed:
        if fuid not in accumulated:
            cache[fuid] = []


def warm_nsf_folder_share_cache(params, folder_uids: Iterable[str], *, force: bool = False) -> None:
    """Batch-load full NSF folder accessors into ``nested_share_folder_share_cache``.

    On transport/API exception the UIDs are left uncached so a later warm can
    retry (same as record ACL warm). ``success: false`` results cache as [].
    """
    ensure_share_caches(params)
    cache = getattr(params, _FOLDER_SHARE_CACHE)
    needed = []
    seen: Set[str] = set()
    for uid in folder_uids:
        if not uid or uid in seen:
            continue
        seen.add(uid)
        if force or uid not in cache:
            needed.append(uid)
    if not needed:
        return

    for chunk in _chunked(needed, _FOLDER_BATCH):
        try:
            _warm_nsf_folder_chunk(params, cache, chunk)
        except Exception as exc:
            logging.debug('NSF folder ACL warm failed for %s: %s', chunk, exc)

def _store_nsf_record_accesses(cache, record_uids: Sequence[str], info: dict) -> None:
    by_uid: dict = {}
    for access in info.get('record_accesses', []) or []:
        ruid = access.get('record_uid')
        if not ruid:
            continue
        by_uid.setdefault(ruid, []).append(access)
    forbidden = set(info.get('forbidden_records') or [])
    for uid in record_uids:
        if uid in forbidden:
            cache[uid] = []
        elif uid in by_uid:
            cache[uid] = by_uid[uid]
        else:
            # Successful response with no rows for this UID — real empty ACL.
            cache[uid] = []


def _is_throttle_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return 'throttl' in text or 'too many' in text or 'rate limit' in text


def _warm_nsf_record_chunk(params, cache, chunk: List[str], *, force: bool) -> bool:
    """Warm one chunk. Returns False if further warming should stop (throttled)."""
    from .record_api import get_record_accesses_v3

    pending = [u for u in chunk if force or u not in cache]
    if not pending:
        return True

    try:
        info = get_record_accesses_v3(params, pending)
        _store_nsf_record_accesses(cache, pending, info)
        return True
    except Exception as exc:
        if _is_throttle_error(exc):
            logging.warning(
                'NSF record ACL warm throttled — stopping further record ACL fetches. '
                'Records without a cached ACL will show parent-folder shares. (%s)',
                exc)
            return False

        # Binary-split once instead of N individual calls (avoids hammering / throttle).
        if len(pending) > _RECORD_BATCH_MIN:
            mid = len(pending) // 2
            logging.debug(
                'NSF record ACL warm failed for batch of %d; splitting: %s',
                len(pending), exc)
            if not _warm_nsf_record_chunk(params, cache, pending[:mid], force=force):
                return False
            return _warm_nsf_record_chunk(params, cache, pending[mid:], force=force)

        logging.warning('NSF record ACL warm failed for %s: %s', pending[0], exc)
        # Leave uncached so folder-ACL fallback can still apply.
        return True


def warm_nsf_record_share_cache(params, record_uids: Iterable[str], *, force: bool = False) -> None:
    """Batch-load full NSF record accessors into ``nested_share_record_share_cache``.

    On failure, splits the batch rather than retrying every UID individually
    (that pattern caused API floods / throttling). Throttle aborts the rest of
    the warm for this call; uncached records fall back to parent folder ACL.
    """
    ensure_share_caches(params)
    cache = getattr(params, _RECORD_SHARE_CACHE)
    needed = []
    seen: Set[str] = set()
    for uid in record_uids:
        if not uid or uid in seen:
            continue
        seen.add(uid)
        if force or uid not in cache:
            needed.append(uid)
    if not needed:
        return

    for chunk in _chunked(needed, _RECORD_BATCH):
        if not _warm_nsf_record_chunk(params, cache, chunk, force=force):
            break


def warm_classic_record_shares(params, record_uids: Iterable[str]) -> None:
    """Ensure classic ``record_cache[uid]['shares']`` is populated (batched API)."""
    uids = [u for u in dict.fromkeys(record_uids) if u and u in (params.record_cache or {})]
    if not uids:
        return
    try:
        api.get_record_shares(params, uids)
    except Exception as exc:
        logging.debug('Classic record share warm failed: %s', exc)


def warm_for_tree(params,
                  nsf_folder_uids: Optional[Iterable[str]] = None,
                  classic_record_uids: Optional[Iterable[str]] = None,
                  nsf_record_uids: Optional[Iterable[str]] = None) -> None:
    """Warm all ACL caches needed for ``tree -s`` / ``tree -s -r``."""
    if nsf_folder_uids:
        warm_nsf_folder_share_cache(params, nsf_folder_uids)
    if nsf_record_uids:
        warm_nsf_record_share_cache(params, nsf_record_uids)
    if classic_record_uids:
        warm_classic_record_shares(params, classic_record_uids)


def get_nsf_folder_share_accessors(params, folder_uid: str) -> List[dict]:
    ensure_share_caches(params)
    return list(getattr(params, _FOLDER_SHARE_CACHE).get(folder_uid) or [])


def get_nsf_record_share_accessors(params, record_uid: str) -> List[dict]:
    ensure_share_caches(params)
    return list(getattr(params, _RECORD_SHARE_CACHE).get(record_uid) or [])
