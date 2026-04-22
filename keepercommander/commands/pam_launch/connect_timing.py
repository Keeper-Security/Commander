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
# Keeper Commander — PAM launch / WebRTC connect phase timing (debug + env tunable).

from __future__ import annotations

import logging
import os
import time
from typing import Optional

_LOG = logging.getLogger(__name__)

# Log connect checkpoints at INFO when set (e.g. PAM_CONNECT_TIMING=1), else only at DEBUG.
_TIMING_FORCE_ENV = 'PAM_CONNECT_TIMING'


def connect_timing_log_enabled() -> bool:
    """True when PAM_CONNECT_TIMING=1 or the module logger is at DEBUG."""
    if os.environ.get(_TIMING_FORCE_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on'):
        return True
    return _LOG.isEnabledFor(logging.DEBUG)


class PamConnectTiming:
    """Monotonic checkpoints for ``pam launch`` / tunnel open (debug or PAM_CONNECT_TIMING=1).

    Usage:
        tc = PamConnectTiming('pam-launch:webrtc-tunnel')
        tc.checkpoint('enter')
        ...
        tc.checkpoint('relay_creds_ok')
        ...
        tc.summary('done')
    """

    __slots__ = ('_label', '_t0', '_last')

    def __init__(self, label: str = 'pam-launch') -> None:
        self._label = label
        self._t0 = time.perf_counter()
        self._last = self._t0

    def checkpoint(self, phase: str, *, log: Optional[bool] = None) -> None:
        do_log = connect_timing_log_enabled() if log is None else log
        now = time.perf_counter()
        step_ms = (now - self._last) * 1000.0
        total_ms = (now - self._t0) * 1000.0
        self._last = now
        if not do_log:
            return
        force = os.environ.get(_TIMING_FORCE_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on')
        level = logging.INFO if force else logging.DEBUG
        _LOG.log(
            level,
            '%s | %-44s | +%.1f ms (step) | %.1f ms (total)',
            self._label,
            phase,
            step_ms,
            total_ms,
        )

    def summary(self, phase: str = 'done') -> None:
        """Log one line with total elapsed (e.g. at end of tunnel open or command)."""
        if not connect_timing_log_enabled():
            return
        total_ms = (time.perf_counter() - self._t0) * 1000.0
        force = os.environ.get(_TIMING_FORCE_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on')
        level = logging.INFO if force else logging.DEBUG
        _LOG.log(level, '%s | %-44s | TOTAL %.1f ms', self._label, phase, total_ms)
