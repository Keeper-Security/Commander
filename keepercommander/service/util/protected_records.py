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

# Docker mode passes the config record's UID to the container regardless of what
# title it was set up with (--record-name can override the default title), so this
# is the only reliable way to identify that record when a custom title was chosen.
_DOCKER_RECORD_UID_ENV = 'COMMANDER_RECORD'


def _protected_titles() -> Tuple[str, ...]:
    """The literal titles of Service Mode's own config records; imported lazily to avoid a circular import through verified_command."""
    from ..config.file_handler import SERVICE_CONFIG_RECORD_TITLES
    from ..docker.models import DockerSetupConstants
    return (*SERVICE_CONFIG_RECORD_TITLES, DockerSetupConstants.DEFAULT_RECORD_NAME)


def get_protected_record_title_set() -> FrozenSet[str]:
    """Lower-cased titles of Service Mode's own config records, for literal matching."""
    return frozenset(t.lower() for t in _protected_titles())


def get_protected_record_uids(params) -> Dict[str, str]:
    """Resolve current UIDs of Service Mode's own config records ({uid: title}).

    Matches by title (not ownership), plus the Docker config record's UID from
    COMMANDER_RECORD -- title alone would miss it if --record-name gave it a
    custom title at setup time. A record that fails to decrypt/parse is skipped
    (logged, not raised) rather than breaking every other Service Mode command.
    """
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
    """A record_cache view that can never hold the given protected UIDs.

    Subclassing dict directly isn't reliable here: CPython's C-level dict methods
    (setdefault, |=, etc.) don't reliably call an overridden __setitem__ on a dict
    subclass. UserDict routes every mutation through __setitem__, so this holds even
    if something (e.g. a forced sync-down triggered mid-command) tries to write the
    protected UID back in while the wrapped command is still running.
    """

    def __init__(self, source, protected_uids: Iterable[str]):
        self._protected_uids = frozenset(protected_uids)
        super().__init__({k: v for k, v in source.items() if k not in self._protected_uids})

    def __setitem__(self, key, value):
        if key in self._protected_uids:
            return
        super().__setitem__(key, value)


@contextlib.contextmanager
def hide_from_record_cache(params, protected_uids: Dict[str, str]):
    """Make params.record_cache unable to hold protected_uids for the duration of the with-block.

    Guards against reintroduction during execution (not just a one-time pop before
    dispatch), then restores the original entries and a plain dict container on
    exit, however the block exits -- so nothing outside this call (including
    Service Mode's own internal config-record maintenance, which shares the same
    params singleton) is ever left permanently unable to see these records.
    """
    if params is None or not protected_uids:
        yield
        return

    original = params.record_cache
    saved_entries = {uid: original[uid] for uid in protected_uids if uid in original}
    params.record_cache = _GuardedRecordCache(original, protected_uids)
    try:
        yield
    finally:
        restored = dict(params.record_cache)
        restored.update(saved_entries)
        params.record_cache = restored
