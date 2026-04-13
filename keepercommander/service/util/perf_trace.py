#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Performance tracing for Service Mode.

Wraps key Keeper API functions (communicate_rest, sync_down) so that every
call made while service mode is active gets timed and logged.  The trace is
collected per-command and emitted as a structured summary when the command
finishes.

The instrumentation is activated by calling ``install()`` once at startup
and is safe to leave in place — it only emits logs when ``params.service_mode``
is truthy.
"""

import time
import threading
import logging
from functools import wraps

from ..decorators.logging import logger

_thread_local = threading.local()
_installed = False
_SYNC_DOWN_ENDPOINT = 'vault/sync_down'


class PerfTrace:
    """Accumulates per-call timing entries for a single command execution."""

    def __init__(self, command):
        self.command = command
        self.start_time = time.perf_counter()
        self.entries = []          # list of (endpoint, elapsed_ms)
        self.sync_down_count = 0

    def record(self, endpoint, elapsed_ms):
        self.entries.append((endpoint, elapsed_ms))
        if endpoint == 'vault/sync_down':
            self.sync_down_count += 1

    def finish(self):
        total_ms = (time.perf_counter() - self.start_time) * 1000
        return total_ms

    def summary_lines(self):
        total_ms = self.finish()
        lines = []
        lines.append(f"[PERF] Command: {self.command}")
        lines.append(f"[PERF]   Total wall time : {total_ms:>10.1f} ms")
        lines.append(f"[PERF]   API calls       : {len(self.entries)}")
        lines.append(f"[PERF]   sync_down calls : {self.sync_down_count}")

        api_total = sum(ms for _, ms in self.entries)
        lines.append(f"[PERF]   API time total  : {api_total:>10.1f} ms")
        lines.append(f"[PERF]   Local time      : {total_ms - api_total:>10.1f} ms")
        lines.append(f"[PERF]   ---- breakdown ----")
        for endpoint, ms in self.entries:
            lines.append(f"[PERF]     {endpoint:<45s} {ms:>10.1f} ms")
        lines.append(f"[PERF]   ---- end ----")
        return lines


def begin_trace(command):
    """Start collecting a performance trace for the current thread."""
    _thread_local.trace = PerfTrace(command)


def end_trace():
    """Finish the trace and log a summary.  Returns the PerfTrace or None."""
    trace = getattr(_thread_local, 'trace', None)
    if trace is None:
        return None
    _thread_local.trace = None
    for line in trace.summary_lines():
        logger.info(line)
    return trace


def current_trace():
    """Return the in-flight PerfTrace for this thread, or None."""
    return getattr(_thread_local, 'trace', None)


def _record_call(endpoint, elapsed_ms):
    trace = getattr(_thread_local, 'trace', None)
    if trace is not None:
        trace.record(endpoint, elapsed_ms)


# ---------------------------------------------------------------------------
# Monkey-patching helpers
# ---------------------------------------------------------------------------

def install():
    """Wrap ``api.communicate_rest`` and ``sync_down.sync_down`` with timing.

    Safe to call multiple times — only installs once.
    """
    global _installed
    if _installed:
        return
    _installed = True

    from ... import api as _api
    from ... import sync_down as _sync_mod

    _orig_communicate_rest = _api.communicate_rest

    @wraps(_orig_communicate_rest)
    def timed_communicate_rest(params, request, endpoint, **kwargs):
        trace = current_trace()
        if trace is None:
            return _orig_communicate_rest(params, request, endpoint, **kwargs)
        # Skip recording vault/sync_down here — it's captured by the
        # outer timed_sync_down wrapper which includes local processing time.
        in_sync = getattr(_thread_local, '_in_sync_down', False)
        start = time.perf_counter()
        try:
            return _orig_communicate_rest(params, request, endpoint, **kwargs)
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if not (in_sync and endpoint == _SYNC_DOWN_ENDPOINT):
                _record_call(endpoint, elapsed_ms)
                logger.info(f"[PERF]   >> {endpoint}: {elapsed_ms:.1f} ms")

    _api.communicate_rest = timed_communicate_rest

    _orig_sync_down = _sync_mod.sync_down

    @wraps(_orig_sync_down)
    def timed_sync_down(params, record_types=False):
        trace = current_trace()
        if trace is None:
            return _orig_sync_down(params, record_types=record_types)
        _thread_local._in_sync_down = True
        start = time.perf_counter()
        try:
            return _orig_sync_down(params, record_types=record_types)
        finally:
            _thread_local._in_sync_down = False
            elapsed_ms = (time.perf_counter() - start) * 1000
            _record_call(_SYNC_DOWN_ENDPOINT, elapsed_ms)
            logger.info(f"[PERF]   >> sync_down (full): {elapsed_ms:.1f} ms")

    _sync_mod.sync_down = timed_sync_down
    _api.sync_down = timed_sync_down

    logger.info("[PERF] Service mode performance tracing installed")
