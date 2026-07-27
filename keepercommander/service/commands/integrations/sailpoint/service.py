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

"""Facade for SailPoint Service Mode integration."""

from __future__ import annotations

import os
from typing import Any, Optional, Tuple

from .....params import KeeperParams
from ....decorators.logging import logger
from .command_hook import SailPointCommandHook
from .command_policy import SailPointCommandPolicy
from .constants import PARAMS_ATTR, SAILPOINT_MARKER_FIELD, SAILPOINT_RECORD_ENV


class SailPointService:
    """
    Entry point for SailPoint Service Mode.

    Pending entitlements and SailPoint settings live on a dedicated vault
    config record (``Commander Service Mode SailPoint Config``). Runtime
    resolves that UID from ``SAILPOINT_RECORD`` (compose env) or
    ``params.sailpoint_record_uid``. Docker config stays on ``COMMANDER_RECORD``.
    """

    PARAMS_ATTR = PARAMS_ATTR

    @classmethod
    def record_has_marker(cls, params: KeeperParams, record_uid: str) -> bool:
        from ..... import vault
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord) or not record.custom:
            return False
        for field in record.custom:
            if field.label == SAILPOINT_MARKER_FIELD:
                value = str(field.get_default_value() or '').strip().lower()
                return value in ('true', '1', 'yes', 'y')
        return False

    @classmethod
    def record_uid(cls, params: Optional[KeeperParams] = None) -> Optional[str]:
        if params is not None:
            uid = getattr(params, cls.PARAMS_ATTR, None)
            if uid:
                return str(uid).strip() or None
        env_uid = (os.environ.get(SAILPOINT_RECORD_ENV) or '').strip()
        return env_uid or None

    @classmethod
    def bind_params(cls, params: KeeperParams, record_uid: Optional[str] = None) -> KeeperParams:
        uid = (record_uid or cls.record_uid(params) or '').strip()
        if uid:
            setattr(params, cls.PARAMS_ATTR, uid)
        return params

    @classmethod
    def maybe_enable(cls, params: KeeperParams, args) -> None:
        """
        If ``SAILPOINT_RECORD`` is set and the record has the SailPoint marker,
        bind params and sanitize the Service Mode command allowlist.
        """
        uid = (os.environ.get(SAILPOINT_RECORD_ENV) or '').strip()
        if not uid:
            return
        try:
            if not cls.record_has_marker(params, uid):
                logger.warning(
                    f'{SAILPOINT_RECORD_ENV}={uid} is set but record is missing '
                    f'{SAILPOINT_MARKER_FIELD}; SailPoint mode not enabled'
                )
                return
        except Exception as e:
            logger.warning(f'SailPoint marker check failed; mode not enabled: {e}')
            return

        cls.bind_params(params, uid)
        if args.commands:
            cleaned = SailPointCommandPolicy.sanitize(args.commands)
            if cleaned != args.commands:
                print(
                    'SailPoint mode: removed disallowed/sensitive commands from allowlist '
                    f'before service-create.\n  Was: {args.commands}\n  Now: {cleaned}'
                )
            args.commands = cleaned

    @classmethod
    def start_background_services(cls) -> None:
        from ....core.globals import get_current_params
        params = get_current_params()
        uid = cls.record_uid(params)
        if not uid:
            return
        if not params:
            logger.warning('SailPoint poller not started: Keeper params not loaded')
            return
        try:
            if not cls.record_has_marker(params, uid):
                logger.warning(
                    f'SailPoint poller not started: record {uid} missing {SAILPOINT_MARKER_FIELD}'
                )
                return
        except Exception as e:
            logger.warning(f'SailPoint poller not started: marker check failed: {e}')
            return
        cls.bind_params(params, uid)
        try:
            from .poller import SailPointEntitlementPoller
            SailPointEntitlementPoller.start(uid)
        except Exception as e:
            logger.warning(f'SailPoint poller not started: {e}')

    @classmethod
    def handle_command(cls, params: KeeperParams, command: str) -> Optional[Tuple[Any, int]]:
        cls.bind_params(params)
        uid = cls.record_uid(params)
        if not uid:
            return None
        if not cls.record_has_marker(params, uid):
            return None
        return SailPointCommandHook(uid).before_command(params, command)

    @classmethod
    def after_command(cls, params: KeeperParams, command: str, success: bool = True) -> None:
        cls.bind_params(params)
        uid = cls.record_uid(params)
        if not uid or not cls.record_has_marker(params, uid):
            return
        SailPointCommandHook(uid).after_command(params, command, success)
