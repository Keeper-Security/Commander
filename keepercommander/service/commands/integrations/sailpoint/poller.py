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
from typing import Any, Dict

from ..... import api
from .....params import KeeperParams
from ....decorators.logging import logger
from .apply_entitlements import SailPointEntitlementApplier
from .config_fields import read_scope_and_interval
from .constants import DEFAULT_POLL_INTERVAL_SECONDS
from .pending_store import SailPointPendingStore


class SailPointEntitlementPoller:
    """Periodically reconcile pending entitlements for Active users."""

    _started = False
    _lock = threading.Lock()

    def __init__(self, record_uid: str):
        self.record_uid = record_uid

    def reconcile(self, params: KeeperParams) -> None:
        scope, _ = read_scope_and_interval(params, self.record_uid)

        def updater(pending: Dict[str, Any]) -> Dict[str, Any]:
            if not pending:
                return pending

            api.query_enterprise(params)
            for email in list(pending.keys()):
                if not SailPointEntitlementApplier.user_is_active(params, email):
                    continue
                remaining, dropped = SailPointEntitlementApplier.apply_for_user(
                    params, email, pending[email], entitlement_scope=scope
                )
                for msg in dropped:
                    logger.warning(f'SailPoint pending: {msg}')
                if remaining and not SailPointPendingStore.entry_is_empty(remaining):
                    pending[email] = remaining
                else:
                    del pending[email]
                    logger.info(f'SailPoint pending entitlements completed for {email}')
            return pending

        SailPointPendingStore.update(params, self.record_uid, updater)

    def _loop(self) -> None:
        from ....core.globals import ensure_params_loaded

        logger.info(f'SailPoint entitlement poller started (record={self.record_uid})')
        while True:
            interval = DEFAULT_POLL_INTERVAL_SECONDS
            try:
                params = ensure_params_loaded()
                if params:
                    params.service_mode = True
                    from .service import SailPointService
                    SailPointService.bind_params(params, self.record_uid)
                    _, interval = read_scope_and_interval(params, self.record_uid)
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
