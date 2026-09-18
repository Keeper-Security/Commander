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

"""Identify Service Mode's own config records so they can be hidden from commands."""

from __future__ import annotations

import contextlib
import os
from collections import UserDict
from typing import Dict, FrozenSet, Iterable, Tuple

# Docker mode passes the config record's UID here regardless of what title --record-name gave it at setup time.
_DOCKER_RECORD_UID_ENV = 'COMMANDER_RECORD'

# uid-keyed caches resolve_single_record/load_pam_record fall back to when a UID isn't in record_cache.
_GUARDED_CACHE_ATTRS = ('record_cache', 'nested_share_records', 'nested_share_record_data')


def _protected_titles() -> Tuple[str, ...]:
    """The literal titles of Service Mode's own config records; imported lazily to avoid a circular import through verified_command."""
    from ..config.file_handler import SERVICE_CONFIG_RECORD_TITLES
    from ..docker.models import DockerSetupConstants
    return (*SERVICE_CONFIG_RECORD_TITLES, DockerSetupConstants.DEFAULT_RECORD_NAME)


def get_protected_record_title_set() -> FrozenSet[str]:
    """Lower-cased titles of Service Mode's own config records, for literal matching."""
    return frozenset(t.lower() for t in _protected_titles())


def get_protected_record_uids(params) -> Dict[str, str]:
    """Resolve current UIDs of Service Mode's own config records ({uid: title}), matching by title plus the Docker record's UID from COMMANDER_RECORD; not cached, since a stale result on this security check is worse than the cost of a full-vault scan."""
    found: Dict[str, str] = {}

    docker_uid = (os.environ.get(_DOCKER_RECORD_UID_ENV) or '').strip()
    if docker_uid:
        found[docker_uid] = '<Docker config record>'

    if params is None or not isinstance(getattr(params, 'record_cache', None), dict) or not params.record_cache:
        return found

    from ... import vault
    from ..decorators.logging import logger

    protected_titles = get_protected_record_title_set()
    for uid in params.record_cache:
        try:
            record = vault.KeeperRecord.load(params, uid)
        except Exception as e:
            logger.debug(f'protected_records: could not load record {uid} ({type(e).__name__}); skipping')
            continue
        if record and record.title.lower() in protected_titles:
            found[uid] = record.title
    return found


class _GuardedRecordCache(UserDict):
    """A uid-keyed cache view that can never hold the given protected UIDs; UserDict (not dict) so every mutation reliably routes through __setitem__, even C-level ones like setdefault/|=."""

    def __init__(self, source, protected_uids: Iterable[str]):
        self._protected_uids = frozenset(protected_uids)
        super().__init__({k: v for k, v in source.items() if k not in self._protected_uids})

    def __setitem__(self, key, value):
        if key in self._protected_uids:
            return
        super().__setitem__(key, value)


@contextlib.contextmanager
def hide_from_record_cache(params, protected_uids: Dict[str, str]):
    """For the with-block, guards record_cache/nested_share_records/nested_share_record_data against reintroduction (not just a one-time pop) and strips protected UIDs from subfolder_record_cache, restoring everything on exit; relies on Service Mode commands running one at a time (same assumption capture_output_and_logs already makes) and may leave record_cache stale until the next sync if one lands mid-command."""
    if params is None or not protected_uids:
        yield
        return

    protected_uid_set = frozenset(protected_uids)

    original_caches = {}
    saved_entries = {}
    for attr in _GUARDED_CACHE_ATTRS:
        source = getattr(params, attr, None)
        if not isinstance(source, dict):
            continue
        original_caches[attr] = source
        saved_entries[attr] = {uid: source[uid] for uid in protected_uid_set if uid in source}
        setattr(params, attr, _GuardedRecordCache(source, protected_uid_set))

    subfolder_cache = getattr(params, 'subfolder_record_cache', None)
    removed_from_folders: Dict[str, set] = {}
    if isinstance(subfolder_cache, dict):
        for folder_uid, uids in subfolder_cache.items():
            if not isinstance(uids, set):
                continue
            hit = uids & protected_uid_set
            if hit:
                removed_from_folders[folder_uid] = hit
                uids -= hit

    try:
        yield
    finally:
        from ..decorators.logging import logger

        for attr in original_caches:
            try:
                restored = dict(getattr(params, attr, None) or {})
                restored.update(saved_entries[attr])
                setattr(params, attr, restored)
            except Exception as e:
                logger.debug(f'hide_from_record_cache: failed to restore {attr} ({type(e).__name__}); restoring protected entries only')
                try:
                    setattr(params, attr, dict(saved_entries[attr]))
                except Exception:
                    pass

        if isinstance(subfolder_cache, dict):
            for folder_uid, hit in removed_from_folders.items():
                try:
                    uids = subfolder_cache.get(folder_uid)
                    if isinstance(uids, set):
                        uids |= hit
                except Exception as e:
                    logger.debug(f'hide_from_record_cache: failed to restore subfolder {folder_uid} ({type(e).__name__})')
