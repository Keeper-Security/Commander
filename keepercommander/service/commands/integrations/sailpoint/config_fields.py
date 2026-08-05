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

from dataclasses import dataclass
from typing import Optional

from .....params import KeeperParams
from .constants import (
    ALLOW_FOLDERS_FIELD,
    ALLOW_RECORDS_FIELD,
    ALLOW_ROLES_FIELD,
    ALLOW_TEAMS_FIELD,
    DEFAULT_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    POLL_INTERVAL_FIELD,
    TRANSFER_TARGET_EMAIL_FIELD,
)

_TRUE_VALUES = frozenset({'true', '1', 'yes', 'y', 'on'})
_FALSE_VALUES = frozenset({'false', '0', 'no', 'n', 'off'})


@dataclass(frozen=True)
class SailPointCapabilities:
    """Runtime SailPoint config: entitlement gates plus transfer target."""

    allow_folders: bool = True
    allow_records: bool = True
    allow_roles: bool = True
    allow_teams: bool = True
    transfer_target_email: str = ''
    poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS


def parse_bool(raw, default: bool = True) -> bool:
    """Parse common truthy/falsey config strings; empty/unknown → default."""
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if not text:
        return default
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    return default


def _custom_field_value(by_label: dict, label: str) -> Optional[str]:
    field = by_label.get(label)
    if not field:
        return None
    value = field.get_default_value()
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def read_capabilities(params: KeeperParams, record_uid: str) -> SailPointCapabilities:
    from ..... import vault

    caps = SailPointCapabilities()
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord) or not record.custom:
        return caps

    by_label = {field.label: field for field in record.custom if field.label}

    def _bool_field(label: str) -> bool:
        return parse_bool(_custom_field_value(by_label, label), default=True)

    interval = DEFAULT_POLL_INTERVAL_SECONDS
    raw_interval = _custom_field_value(by_label, POLL_INTERVAL_FIELD)
    if raw_interval:
        try:
            interval = max(MIN_POLL_INTERVAL_SECONDS, int(raw_interval))
        except (TypeError, ValueError):
            pass

    return SailPointCapabilities(
        allow_folders=_bool_field(ALLOW_FOLDERS_FIELD),
        allow_records=_bool_field(ALLOW_RECORDS_FIELD),
        allow_roles=_bool_field(ALLOW_ROLES_FIELD),
        allow_teams=_bool_field(ALLOW_TEAMS_FIELD),
        transfer_target_email=_custom_field_value(by_label, TRANSFER_TARGET_EMAIL_FIELD) or '',
        poll_interval_seconds=interval,
    )
