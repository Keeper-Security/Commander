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


# --- Connect-phase delay helpers -------------------------------------------
#
# The pam launch flow has several historically fixed sleeps whose durations
# only matter in the first-launch / slow-network case. Defaults here are tuned
# for the fast path; each env var below lets operators restore the legacy
# (conservative) values without a code roll.

_WEBSOCKET_BACKEND_DELAY_ENV = 'WEBSOCKET_BACKEND_DELAY'
_WEBSOCKET_BACKEND_DELAY_FAST_DEFAULT = 0.30   # seconds — fast path default
_WEBSOCKET_BACKEND_DELAY_LEGACY_ENV = 'WEBSOCKET_BACKEND_DELAY_LEGACY'
_WEBSOCKET_BACKEND_DELAY_LEGACY_DEFAULT = 2.0  # seconds — adaptive fallback cap

_PAM_PRE_OFFER_SEC_ENV = 'PAM_PRE_OFFER_SEC'
_PAM_PRE_OFFER_FAST_DEFAULT = 0.0              # seconds — merged into backend_delay
_PAM_PRE_OFFER_LEGACY_ENV = 'PAM_PRE_OFFER_LEGACY'  # 1/true/yes → force legacy 1.0s

_PAM_OFFER_RETRY_EXTRA_SEC_ENV = 'PAM_OFFER_RETRY_EXTRA_SEC'
_PAM_OFFER_RETRY_EXTRA_DEFAULT = 1.25          # seconds — retry backoff

_PAM_OPEN_CONNECTION_DELAY_ENV = 'PAM_OPEN_CONNECTION_DELAY'
_PAM_OPEN_CONNECTION_DELAY_FAST_DEFAULT = 0.05  # seconds — safety margin
                                                # (retry loop handles slow DataChannel)

_PAM_WEBRTC_POLL_MS_ENV = 'PAM_WEBRTC_POLL_MS'
_PAM_WEBRTC_POLL_MS_DEFAULT = 25                # milliseconds — poll granularity


def _env_float(name: str, default: float) -> float:
    """Read a float env var; return ``default`` when unset, empty, or unparseable."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    raw = str(raw).strip()
    if raw == '':
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, '').strip().lower() in ('1', 'true', 'yes', 'on')


def websocket_backend_delay_sec() -> float:
    """Sleep after WebSocket connects and before POSTing the offer (router/backend
    registration window).

    Set ``WEBSOCKET_BACKEND_DELAY`` to override. Default is 0.30s for the fast
    path; the legacy value was 2.0s. Combined with the retry path, a single
    unlucky launch still caps at the legacy total (see
    ``websocket_backend_delay_legacy_sec``).
    """
    return _env_float(_WEBSOCKET_BACKEND_DELAY_ENV, _WEBSOCKET_BACKEND_DELAY_FAST_DEFAULT)


def websocket_backend_delay_legacy_sec() -> float:
    """Upper bound for the adaptive backend-delay catch-up on a first-attempt
    offer failure. On retry the code sleeps up to
    ``max(0, legacy - fast_default)`` more so the cumulative wait matches the
    pre-change 2.0s behavior for the unlucky cold-router case.
    """
    return _env_float(_WEBSOCKET_BACKEND_DELAY_LEGACY_ENV, _WEBSOCKET_BACKEND_DELAY_LEGACY_DEFAULT)


def pre_offer_delay_sec() -> float:
    """Extra sleep between the backend-delay wait and the offer HTTP POST.

    Default 0.0 (the previous hardcoded 1.0s sleep was redundant — the
    backend-delay wait already serves the same purpose). Set
    ``PAM_PRE_OFFER_LEGACY=1`` to force the legacy 1.0s, or ``PAM_PRE_OFFER_SEC``
    for a custom value.
    """
    if _env_truthy(_PAM_PRE_OFFER_LEGACY_ENV):
        return max(1.0, _env_float(_PAM_PRE_OFFER_SEC_ENV, 1.0))
    return _env_float(_PAM_PRE_OFFER_SEC_ENV, _PAM_PRE_OFFER_FAST_DEFAULT)


def offer_retry_extra_delay_sec() -> float:
    """Base delay before a retry of the gateway offer HTTP POST."""
    return _env_float(_PAM_OFFER_RETRY_EXTRA_SEC_ENV, _PAM_OFFER_RETRY_EXTRA_DEFAULT)


def open_connection_delay_sec() -> float:
    """Sleep between ``webrtc_data_plane_connected`` and sending ``OpenConnection``.

    Historically 0.2s; reduced to 0.05s because the caller's retry loop with
    exponential backoff already handles the "DataChannel not yet open" case.
    Set ``PAM_OPEN_CONNECTION_DELAY`` to restore a larger safety margin.
    """
    return _env_float(_PAM_OPEN_CONNECTION_DELAY_ENV, _PAM_OPEN_CONNECTION_DELAY_FAST_DEFAULT)


def webrtc_connection_poll_sec() -> float:
    """Poll tick (seconds) for the ``tube_registry.get_connection_state`` loop
    that waits for the WebRTC data plane to reach ``connected``.

    Default 25ms (previously 100ms). Set ``PAM_WEBRTC_POLL_MS`` to override.
    """
    ms = _env_float(_PAM_WEBRTC_POLL_MS_ENV, _PAM_WEBRTC_POLL_MS_DEFAULT)
    return max(0.001, ms / 1000.0)


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
        # Always emit at DEBUG. Commander's ``debug --file`` handler installs an
        # explicit ``record.levelno != INFO`` filter (cli.py::setup_file_logging)
        # to keep user-facing INFO prints out of the debug log — which ate our
        # timing lines when PAM_CONNECT_TIMING=1 previously bumped them to INFO.
        # DEBUG passes that filter and surfaces cleanly whenever debug mode is on.
        _LOG.log(
            logging.DEBUG,
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
        _LOG.log(logging.DEBUG, '%s | %-44s | TOTAL %.1f ms', self._label, phase, total_ms)
