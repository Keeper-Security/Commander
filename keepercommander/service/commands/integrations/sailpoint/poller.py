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

"""Background poller that applies SailPoint pending entitlements after activation."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List

from ..... import api
from .....params import KeeperParams
from ....decorators.logging import logger
from .apply_entitlements import SailPointEntitlementApplier
from .config_fields import read_capabilities
from .constants import DEFAULT_POLL_INTERVAL_SECONDS
from .pending_store import SailPointPendingStore


class SailPointEntitlementPoller:
    """Periodically reconcile pending entitlements for Active users."""

    _started = False
    _lock = threading.Lock()

    def __init__(self, record_uid: str):
        self.record_uid = record_uid

    def reconcile(self, params: KeeperParams) -> None:
        """
        Apply entitlements outside the pending-store write path so stale-revision
        retries do not re-run share/role commands.
        """
        caps = read_capabilities(params, self.record_uid)
        pending = SailPointPendingStore.load(params, self.record_uid)
        if not pending:
            return

        api.query_enterprise(params)
        remaining_by_email: Dict[str, Dict[str, Any]] = {}
        cleared: List[str] = []

        for email, entry in list(pending.items()):
            if not SailPointEntitlementApplier.user_is_active(params, email):
                continue
            logger.info(
                f'SailPoint: user {email} is Active; applying pending entitlements'
            )
            remaining, dropped = SailPointEntitlementApplier.apply_for_user(
                params,
                email,
                entry,
                allow_roles=caps.allow_roles,
                allow_teams=caps.allow_teams,
                allow_folders=caps.allow_folders,
                allow_records=caps.allow_records,
            )
            for msg in dropped:
                logger.warning(f'SailPoint pending: {msg}')
            if remaining and not SailPointPendingStore.entry_is_empty(remaining):
                remaining_by_email[email] = remaining
            else:
                cleared.append(email)
                logger.info(f'SailPoint: pending entitlements cleared for {email}')

        if not remaining_by_email and not cleared:
            return

        def updater(current: Dict[str, Any]) -> Dict[str, Any]:
            for email, remaining in remaining_by_email.items():
                if email in current:
                    current[email] = remaining
            for email in cleared:
                current.pop(email, None)
            return current

        SailPointPendingStore.update(params, self.record_uid, updater)

    def _loop(self) -> None:
        from ....core.globals import ensure_params_loaded

        logger.info('SailPoint: entitlement poller started')
        while True:
            interval = DEFAULT_POLL_INTERVAL_SECONDS
            try:
                params = ensure_params_loaded()
                if params:
                    params.service_mode = True
                    from .service import SailPointService
                    SailPointService.bind_params(params, self.record_uid)
                    interval = read_capabilities(params, self.record_uid).poll_interval_seconds
                    self.reconcile(params)
            except Exception as e:
                logger.error(f'SailPoint poller cycle failed: {e}')
            time.sleep(interval)

    @classmethod
    def start(cls, record_uid: str) -> None:
        if not record_uid:
            return
        with cls._lock:
            if cls._started:
                return
            poller = cls(record_uid)
            thread = threading.Thread(
                target=poller._loop, name='sailpoint-entitlement-poller', daemon=True
            )
            thread.start()
            cls._started = True
