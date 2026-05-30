"""
Rust/webrtc log filtering for pam launch terminal session only.

Downgrades Rust/webrtc/turn log messages to DEBUG so they only appear when --debug is on,
and only while the pam launch CLI terminal session is active.
"""

import logging
import threading


# Patterns for known leak messages from turn-0.11.0's relay-conn task.
# The webrtc-rs ICE agent does not synchronously cancel its TURN refresh task
# on PeerConnection.close(); the task survives indefinitely and re-fires every
# few minutes (TURN permission lifetime ~5 min, refresh at ~3/4 of that). Each
# iteration logs:
#   "fail to refresh permissions: CreatePermission error response (error 400: Bad Request)"
#   "refresh permissions failed"
# from turn-0.11.0/src/client/relay_conn.rs:528 / :618.
#
# Until the upstream leak is fixed, suppress these messages permanently — they
# are post-close stragglers from a deallocated TURN allocation and have no
# diagnostic value to the user.
_TURN_REFRESH_LEAK_PATTERNS = (
    'fail to refresh permissions',
    'refresh permissions failed',
)


class _PermanentTurnLeakFilter(logging.Filter):
    """Always drop the known turn-rs refresh-permission leak messages.

    Installed once at module import time on the root logger, never removed.
    Independent of the session-scoped _RustWebrtcToDebugFilter — that one
    flips with --debug; this one is an upstream-bug workaround that should
    fire regardless of debug state.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        for needle in _TURN_REFRESH_LEAK_PATTERNS:
            if needle in msg:
                return False
        return True


# Loggers known to emit the leak. Both dot- and colon-separated names cover
# the Rust→Python bridge formats. ``turn`` and ``turn.client`` cover any
# parent that records may originate from depending on rust-log target style.
_TURN_LEAK_LOGGER_NAMES = (
    'turn',
    'turn.client',
    'turn.client.relay_conn',
    'turn::client::relay_conn',
)

_PERMANENT_TURN_FILTER = _PermanentTurnLeakFilter()


def _install_permanent_turn_filter():
    """Attach the content filter to the known leaky loggers AND root.

    Python's logger filters fire only at the originating logger (filters do
    NOT re-check during propagation up the hierarchy via callHandlers), so we
    must attach to the actual emitting logger names rather than relying on
    root.addFilter alone. Idempotent — safe to call again.
    """
    for name in _TURN_LEAK_LOGGER_NAMES:
        log = logging.getLogger(name)
        if _PERMANENT_TURN_FILTER not in log.filters:
            log.addFilter(_PERMANENT_TURN_FILTER)
    # Also attach to root in case the Rust→Python bridge ever logs directly to
    # root (cheap belt-and-braces).
    root = logging.getLogger()
    if _PERMANENT_TURN_FILTER not in root.filters:
        root.addFilter(_PERMANENT_TURN_FILTER)


_install_permanent_turn_filter()


def _rust_webrtc_logger_name(name: str) -> bool:
    """True if logger name is from Rust/webrtc/turn so we treat its messages as DEBUG-only."""
    if not name:
        return False
    # Normalize so we match both '.' and '::' (Rust may use either when passed to Python)
    n = (name or '').replace('::', '.')
    return (
        n.startswith('keeper_pam_webrtc_rs')
        or n.startswith('webrtc')
        or n.startswith('turn')
        or n.startswith('stun')
        or 'relay_conn' in n  # turn crate submodule
    )


class _RustWebrtcToDebugFilter(logging.Filter):
    """
    Filter for Rust/webrtc/turn log records.
    When not in debug mode: suppress entirely (return False) so no handler can emit them.
    When in debug mode: allow (return True); downgrading to DEBUG is redundant but harmless.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not _rust_webrtc_logger_name(record.name):
            return True
        # Only show these messages when debug is enabled (root or effective level is DEBUG)
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            return True
        return False  # suppress when not in debug


class _RustAwareLogger(logging.Logger):
    """
    Logger that forces Rust/webrtc/turn loggers to have no handlers and propagate to root,
    and applies the downgrade filter at the logger so messages are DEBUG-only.
    Used so loggers created *after* enter_ (e.g. by turn crate on first use) are still suppressed.
    """

    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        if _rust_webrtc_logger_name(name):
            self.setLevel(logging.DEBUG)
            self.propagate = True
            self.handlers.clear()
            self.addFilter(_RustWebrtcToDebugFilter())


_WEBRTC_CRATE_NAMES = [
    'webrtc', 'webrtc_ice', 'webrtc_mdns', 'webrtc_dtls',
    'webrtc_sctp', 'turn', 'stun', 'webrtc_ice.agent.agent_internal',
    'webrtc_ice.agent.agent_gather', 'webrtc_ice.mdns',
    'webrtc_mdns.conn', 'webrtc.peer_connection', 'turn.client',
    'turn.client.relay_conn',  # turn crate submodule that emits "fail to refresh permissions..."
]


def enter_pam_launch_terminal_rust_logging():
    """
    Apply Rust/webrtc log filtering only during pam launch terminal session.
    Downgrades Rust/webrtc/turn messages to DEBUG so they only show with --debug.
    Returns a token to pass to exit_pam_launch_terminal_rust_logging() on exit.
    """
    global _ACTIVE_SESSION_COUNT
    with _ACTIVE_SESSION_LOCK:
        _ACTIVE_SESSION_COUNT += 1

    root = logging.getLogger()
    flt = _RustWebrtcToDebugFilter()
    root.addFilter(flt)

    # Use custom Logger class so any Rust/webrtc logger created later (e.g. turn crate)
    # gets no handlers and propagates to root, where our filter downgrades to DEBUG.
    _original_logger_class = logging.getLoggerClass()
    logging.setLoggerClass(_RustAwareLogger)

    saved = []
    downgrade_filter = _RustWebrtcToDebugFilter()
    for name in list(logging.Logger.manager.loggerDict.keys()):
        if not isinstance(name, str) or not _rust_webrtc_logger_name(name):
            continue
        log = logging.getLogger(name)
        # Only save if it's a real Logger with state we can restore (not our custom class yet)
        if not isinstance(log, _RustAwareLogger):
            saved.append((name, log.level, log.propagate, list(log.handlers)))
        log.setLevel(logging.DEBUG)
        log.propagate = True
        log.handlers.clear()
        if downgrade_filter not in log.filters:
            log.addFilter(downgrade_filter)
    for crate_name in _WEBRTC_CRATE_NAMES:
        log = logging.getLogger(crate_name)
        if not isinstance(log, _RustAwareLogger):
            saved.append((crate_name, log.level, log.propagate, list(log.handlers)))
        log.setLevel(logging.DEBUG)
        log.propagate = True
        log.handlers.clear()
        if downgrade_filter not in log.filters:
            log.addFilter(downgrade_filter)

    return (flt, saved, _original_logger_class)


# Grace period (seconds) between pam-launch session exit and actually removing
# the Rust/webrtc log filter. The Rust tube shutdown runs on its own runtime
# threads and can emit a final log record AFTER Python's session-exit path has
# returned control to the REPL — e.g. ``webrtc-sctp stream N not found`` when
# the channel is torn down, or TURN ``fail to refresh permissions`` warnings
# from the relay-conn task as it observes the deallocated allocation.
#
# The window must outlive both the tube close + teardown cascade (~3 s) and a
# brief TURN refresh-task latency after the PeerConnection drop cascade.
_DEFAULT_RUST_LOG_FILTER_GRACE_SEC = 4

# Refcount of active pam-launch sessions that have rust-log filtering installed.
# Incremented in enter_*, decremented at the END of the grace timer in
# _do_exit_rust_logging. The restore work (removing class-level filters,
# restoring pre-session logger state) is only performed when this drops to 0,
# so a second `pam launch` started during the grace window of a prior one is
# not silently de-filtered when the prior session's timer fires.
_ACTIVE_SESSION_COUNT = 0
_ACTIVE_SESSION_LOCK = threading.Lock()


def _do_exit_rust_logging(token):
    """Actual restoration — runs on the grace-period timer thread."""
    if not token:
        return
    flt, saved = token[0], token[1]
    original_logger_class = token[2] if len(token) > 2 else logging.Logger

    # Always remove THIS session's filter instance from root so per-token
    # filters don't pile up. The bulk class-based cleanup below only runs when
    # we are the last active session.
    root = logging.getLogger()
    try:
        root.removeFilter(flt)
    except Exception:
        pass

    global _ACTIVE_SESSION_COUNT
    with _ACTIVE_SESSION_LOCK:
        _ACTIVE_SESSION_COUNT = max(0, _ACTIVE_SESSION_COUNT - 1)
        last_session = _ACTIVE_SESSION_COUNT == 0
    if not last_session:
        # Another pam launch session is still active (or in its own grace
        # window); leave the class-level filter and saved state alone so its
        # filtering keeps working. We already removed our specific instance
        # from root above.
        logging.debug(
            "rust_log_filter: skipping restore, %d session(s) still active",
            _ACTIVE_SESSION_COUNT,
        )
        return

    logging.setLoggerClass(original_logger_class)
    # Remove downgrade filter from all Rust/webrtc loggers (we may have added the shared
    # filter to existing loggers, and _RustAwareLogger instances have their own filter)
    for name in list(logging.Logger.manager.loggerDict.keys()):
        if not isinstance(name, str) or not _rust_webrtc_logger_name(name):
            continue
        log = logging.getLogger(name)
        for f in list(log.filters):
            if isinstance(f, _RustWebrtcToDebugFilter):
                try:
                    log.removeFilter(f)
                except ValueError:
                    pass
    for crate_name in _WEBRTC_CRATE_NAMES:
        log = logging.getLogger(crate_name)
        for f in list(log.filters):
            if isinstance(f, _RustWebrtcToDebugFilter):
                try:
                    log.removeFilter(f)
                except ValueError:
                    pass
    for name, level, propagate, handlers in saved:
        log = logging.getLogger(name)
        log.setLevel(level)
        log.propagate = propagate
        for h in handlers:
            log.addHandler(h)


def exit_pam_launch_terminal_rust_logging(token, grace_sec=_DEFAULT_RUST_LOG_FILTER_GRACE_SEC):
    """Restore Rust/webrtc logger state after pam launch terminal session.

    The filter is removed after ``grace_sec`` seconds (default
    ``_DEFAULT_RUST_LOG_FILTER_GRACE_SEC``) so that
    late records from the Rust runtime (e.g. ``webrtc-sctp`` stream teardown
    messages that arrive just after session exit) are still caught by the
    filter and do not leak to the console in front of the subsequent
    ``My Vault>`` prompt. Pass ``grace_sec=0`` to restore immediately.
    """
    if not token:
        return
    if grace_sec <= 0:
        _do_exit_rust_logging(token)
        return
    # Daemon thread so Commander can exit cleanly even during grace.
    timer = threading.Timer(grace_sec, _do_exit_rust_logging, args=(token,))
    timer.daemon = True
    timer.name = 'pam-launch-rust-log-filter-release'
    timer.start()
