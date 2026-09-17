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

from typing import Dict, FrozenSet, Tuple


def _protected_titles() -> Tuple[str, ...]:
    """The literal titles of Service Mode's own config records; imported lazily to avoid a circular import through verified_command."""
    from ..config.file_handler import SERVICE_CONFIG_RECORD_TITLES
    from ..docker.models import DockerSetupConstants
    return (*SERVICE_CONFIG_RECORD_TITLES, DockerSetupConstants.DEFAULT_RECORD_NAME)


def get_protected_record_title_set() -> FrozenSet[str]:
    """Lower-cased titles of Service Mode's own config records, for literal matching."""
    return frozenset(t.lower() for t in _protected_titles())


def get_protected_record_uids(params) -> Dict[str, str]:
    """Resolve current UIDs of Service Mode's own config records ({uid: title}), matching by title only, not ownership."""
    if params is None or not isinstance(getattr(params, 'record_cache', None), dict) or not params.record_cache:
        return {}

    from ... import vault

    protected_titles = get_protected_record_title_set()
    found: Dict[str, str] = {}
    for uid in params.record_cache:
        record = vault.KeeperRecord.load(params, uid)
        if record and record.title.lower() in protected_titles:
            found[uid] = record.title
    return found
