"""
SuperShell debug logging utilities

Shared debug logging infrastructure for SuperShell components.
Set DEBUG_EVENTS to True to log events to /tmp/supershell_debug.log.

Usage:
    from .debug import debug_log, DEBUG_EVENTS

    debug_log("Key pressed: j")

To watch events in real-time:
    tail -f /tmp/supershell_debug.log
"""

# Set to True to log all mouse/keyboard events to /tmp/supershell_debug.log
DEBUG_EVENTS = False

_debug_log_file = None


def debug_log(msg: str) -> None:
    """Log debug message to /tmp/supershell_debug.log if DEBUG_EVENTS is True.

    Args:
        msg: The message to log. Will be prefixed with timestamp.
    """
    if not DEBUG_EVENTS:
        return
    global _debug_log_file
    try:
        if _debug_log_file is None:
            _debug_log_file = open('/tmp/supershell_debug.log', 'a')
        import datetime
        timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        _debug_log_file.write(f"[{timestamp}] {msg}\n")
        _debug_log_file.flush()
    except Exception:
        pass  # Silently fail if logging fails


def close_debug_log() -> None:
    """Close the debug log file if open.

    Call this when the application exits to ensure clean shutdown.
    """
    global _debug_log_file
    if _debug_log_file is not None:
        try:
            _debug_log_file.close()
        except Exception:
            pass
        _debug_log_file = None
