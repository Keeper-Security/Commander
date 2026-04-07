"""
Rust/webrtc log filtering for pam launch terminal session only.

Downgrades Rust/webrtc/turn log messages to DEBUG so they only appear when --debug is on,
and only while the pam launch CLI terminal session is active.
"""

import logging


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


def exit_pam_launch_terminal_rust_logging(token):
    """Restore Rust/webrtc logger state after pam launch terminal session. Pass token from enter_pam_launch_terminal_rust_logging()."""
    if not token:
        return
    flt, saved = token[0], token[1]
    original_logger_class = token[2] if len(token) > 2 else logging.Logger
    logging.setLoggerClass(original_logger_class)
    root = logging.getLogger()
    root.removeFilter(flt)
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
