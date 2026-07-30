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
from .config_fields import parse_bool
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
        if not record_uid:
            return False
        from ..... import vault
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord) or not record.custom:
            return False
        return any(
            field.label == SAILPOINT_MARKER_FIELD
            and parse_bool(field.get_default_value(), default=False)
            for field in record.custom
        )

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
        Bind params and sanitize the Service Mode command allowlist when the
        SailPoint config record has the integration marker.

        Callers must gate on ``SAILPOINT_RECORD`` before invoking this.
        """
        uid = cls.record_uid(params)
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
        """
        Start the entitlement poller when SailPoint is enabled.

        Callers must gate on ``SAILPOINT_RECORD`` before invoking this.
        """
        from ....core.globals import get_current_params
        params = get_current_params()
        if not params:
            logger.warning('SailPoint poller not started: Keeper params not loaded')
            return
        uid = cls.record_uid(params)
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
        """Callers must gate on ``SAILPOINT_RECORD`` before invoking this."""
        cls.bind_params(params)
        uid = cls.record_uid(params)
        if not cls.record_has_marker(params, uid):
            return None
        return SailPointCommandHook(uid).before_command(params, command)

    @classmethod
    def after_command(cls, params: KeeperParams, command: str, success: bool = True) -> None:
        """Callers must gate on ``SAILPOINT_RECORD`` before invoking this."""
        cls.bind_params(params)
        uid = cls.record_uid(params)
        if not cls.record_has_marker(params, uid):
            return
        SailPointCommandHook(uid).after_command(params, command, success)
