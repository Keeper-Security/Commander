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

"""Pending entitlement JSON store on the SailPoint vault config record."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from ..... import api, record_management, vault
from .....params import KeeperParams
from ....decorators.logging import logger
from .constants import PENDING_ENTITLEMENTS_FIELD

_STALE_HINTS = ('out_of_sync', 'no longer exists')
_MAX_ATTEMPTS = 3


class SailPointPendingStore:
    """Load / merge / save pending entitlement JSON on the SailPoint config record."""

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

    @classmethod
    def empty_entry(cls) -> Dict[str, Any]:
        return {
            'created_at': cls._utc_now(),
            'last_error': None,
            'roles': [],
            'teams': [],
            'folders': [],
            'records': [],
        }

    @classmethod
    def load(cls, params: KeeperParams, record_uid: str) -> Dict[str, Any]:
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord) or not record.custom:
            return {}
        field = next(
            (f for f in record.custom if f.label == PENDING_ENTITLEMENTS_FIELD),
            None,
        )
        if not field:
            return {}
        raw = field.get_default_value()
        if not raw:
            return {}
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            logger.warning(f'Invalid pending_entitlements JSON on record {record_uid}')
            return {}
        return data if isinstance(data, dict) else {}

    @classmethod
    def _write(cls, params: KeeperParams, record_uid: str, pending: Dict[str, Any]) -> None:
        payload = json.dumps(pending, indent=2, sort_keys=True)
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            raise RuntimeError(f'SailPoint config record {record_uid} missing or not typed')

        preserved = [
            f for f in (record.custom or [])
            if f.label != PENDING_ENTITLEMENTS_FIELD
        ]
        record.custom = preserved + [
            vault.TypedField.new_field('text', payload, PENDING_ENTITLEMENTS_FIELD),
        ]
        record_management.update_record(params, record)
        params.sync_data = True
        api.sync_down(params)

    @classmethod
    def update(
        cls,
        params: KeeperParams,
        record_uid: str,
        updater: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Sync, load, apply updater, write. Retries on stale revision so concurrent
        writers merge against the latest remote state instead of overwriting it.
        """
        last_error: Optional[Exception] = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                params.sync_data = True
                api.sync_down(params)
                current = cls.load(params, record_uid)
                next_state = updater(deepcopy(current))
                if next_state is None:
                    next_state = {}
                if not isinstance(next_state, dict):
                    raise TypeError('pending entitlements updater must return a dict')
                if json.dumps(next_state, sort_keys=True) == json.dumps(current, sort_keys=True):
                    return current
                cls._write(params, record_uid, next_state)
                return next_state
            except Exception as e:
                last_error = e
                stale = any(h in str(e).lower() for h in _STALE_HINTS)
                if not stale or attempt == _MAX_ATTEMPTS:
                    raise RuntimeError(f'Failed to save pending entitlements: {last_error}') from e
                logger.warning(
                    f'Stale revision updating pending entitlements; retrying ({attempt}/{_MAX_ATTEMPTS})'
                )

        raise RuntimeError(f'Failed to save pending entitlements: {last_error}')

    @staticmethod
    def _merge_share_list(
        existing: List[Dict[str, Any]], items: List[Dict[str, Any]], uid_key: str
    ) -> List[Dict[str, Any]]:
        by_uid = {str(x.get(uid_key)): dict(x) for x in existing if x.get(uid_key)}
        for item in (x for x in items if x.get(uid_key)):
            key = str(item[uid_key])
            if key in by_uid:
                by_uid[key].update(item)
            else:
                by_uid[key] = dict(item)
        return list(by_uid.values())

    @classmethod
    def merge_entry(
        cls,
        pending: Dict[str, Any],
        email: str,
        *,
        roles: Optional[List[str]] = None,
        teams: Optional[List[str]] = None,
        folders: Optional[List[Dict[str, Any]]] = None,
        records: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        result = deepcopy(pending)
        key = email.strip().lower()
        entry = result.get(key) or cls.empty_entry()
        if 'created_at' not in entry:
            entry['created_at'] = cls._utc_now()

        if roles:
            entry['roles'] = sorted(set(entry.get('roles') or []) | set(roles))
        if teams:
            entry['teams'] = sorted(set(entry.get('teams') or []) | set(teams))
        if folders:
            entry['folders'] = cls._merge_share_list(entry.get('folders') or [], folders, 'uid')
        if records:
            entry['records'] = cls._merge_share_list(entry.get('records') or [], records, 'uid')

        entry['last_error'] = None
        result[key] = entry
        return result

    @staticmethod
    def entry_is_empty(entry: Dict[str, Any]) -> bool:
        return not (
            entry.get('roles')
            or entry.get('teams')
            or entry.get('folders')
            or entry.get('records')
        )

    @staticmethod
    def summarize_entry(entry: Dict[str, Any]) -> str:
        """Human-readable pending payload for INFO logs (counts only for shares)."""
        parts: List[str] = []
        roles = list(entry.get('roles') or [])
        teams = list(entry.get('teams') or [])
        folders = entry.get('folders') or []
        records = entry.get('records') or []
        if roles:
            parts.append(f'roles={roles}')
        if teams:
            parts.append(f'teams={teams}')
        if folders:
            parts.append(f'folders={len(folders)}')
        if records:
            parts.append(f'records={len(records)}')
        return ' '.join(parts)
