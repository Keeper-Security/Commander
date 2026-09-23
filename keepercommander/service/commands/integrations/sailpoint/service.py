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
    """Entry point for SailPoint Service Mode; settings/pending entitlements live on the record pinned by SAILPOINT_RECORD."""

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
    def _record_has_marker_safe(cls, params: KeeperParams, uid: str) -> bool:
        """record_has_marker, but never raises; startup-only -- handle_command/after_command
        must call record_has_marker directly so a check failure denies the request instead of silently skipping it."""
        try:
            return cls.record_has_marker(params, uid)
        except Exception as e:
            logger.warning(f'SailPoint: marker check failed for record {uid}: {e}')
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
        """Bind params and sanitize the allowlist when the config record has the marker; callers must gate on SAILPOINT_RECORD first."""
        uid = cls.record_uid(params)
        if not cls._record_has_marker_safe(params, uid):
            logger.warning(
                f'{SAILPOINT_RECORD_ENV}={uid} is set but record is missing '
                f'{SAILPOINT_MARKER_FIELD}; SailPoint mode not enabled'
            )
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
        """Start the entitlement poller; callers must gate on SAILPOINT_RECORD before invoking this."""
        from ....core.globals import get_current_params
        params = get_current_params()
        if not params:
            logger.warning('SailPoint poller not started: Keeper params not loaded')
            return
        uid = cls.record_uid(params)
        if not cls._record_has_marker_safe(params, uid):
            logger.warning(
                f'SailPoint poller not started: record {uid} missing {SAILPOINT_MARKER_FIELD}'
            )
            return
        cls.bind_params(params, uid)
        try:
            from .poller import SailPointEntitlementPoller
            SailPointEntitlementPoller.start(uid)
        except Exception as e:
            logger.warning(f'SailPoint poller not started: {e}')

    @classmethod
    def handle_command(
        cls, params: KeeperParams, command: str
    ) -> Tuple[str, Optional[Tuple[Any, int]]]:
        """Prepare a SailPoint command, returning (command_to_run, short_circuit); callers must gate on SAILPOINT_RECORD first."""
        cls.bind_params(params)
        uid = cls.record_uid(params)
        # Not swallowed here -- a check failure must deny the request, not silently skip gating.
        if not cls.record_has_marker(params, uid):
            logger.debug(f'SailPoint: record {uid} has no active marker; skipping all command gating for this request')
            return command, None
        return SailPointCommandHook(uid).before_command(params, command)

    @classmethod
    def after_command(cls, params: KeeperParams, command: str, success: bool = True) -> None:
        """Callers must gate on ``SAILPOINT_RECORD`` before invoking this."""
        cls.bind_params(params)
        uid = cls.record_uid(params)
        # Not swallowed here either -- callers turn a raised exception into an explicit 500.
        if not cls.record_has_marker(params, uid):
            logger.debug(f'SailPoint: record {uid} has no active marker; skipping pending-entitlement queue for this request')
            return
        SailPointCommandHook(uid).after_command(params, command, success)
