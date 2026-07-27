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

"""Read SailPoint config fields from the dedicated vault record."""

from __future__ import annotations

from typing import Tuple

from .....params import KeeperParams
from .constants import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    ENTITLEMENT_SCOPE_FIELD,
    POLL_INTERVAL_FIELD,
    SCOPE_BOTH,
)

_VALID_SCOPES = frozenset({'folders', 'records', 'both'})
_MIN_POLL_INTERVAL = 15


def read_scope_and_interval(params: KeeperParams, record_uid: str) -> Tuple[str, int]:
    from ..... import vault

    scope = SCOPE_BOTH
    interval = DEFAULT_POLL_INTERVAL_SECONDS
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord) or not record.custom:
        return scope, interval

    for field in record.custom:
        if field.label == ENTITLEMENT_SCOPE_FIELD:
            value = (field.get_default_value() or SCOPE_BOTH).strip().lower()
            if value in _VALID_SCOPES:
                scope = value
        elif field.label == POLL_INTERVAL_FIELD:
            try:
                interval = max(_MIN_POLL_INTERVAL, int(field.get_default_value() or interval))
            except (TypeError, ValueError):
                pass
    return scope, interval


def read_entitlement_scope(params: KeeperParams, record_uid: str) -> str:
    scope, _ = read_scope_and_interval(params, record_uid)
    return scope
