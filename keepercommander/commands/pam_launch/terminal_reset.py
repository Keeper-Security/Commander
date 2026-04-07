#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
#

"""
Restore local TTY / console state after a pam launch terminal session ends.

Plain remote shell output usually leaves the local terminal fine after we
restore raw/cooked mode. The bad case is **fullscreen TUIs on the remote**
(nano, mcedit, vim alternate screen): double Ctrl+C or abrupt exit can leave
alternate-screen mode, hidden cursor, or **queued input** in the local driver.
Then the Commander prompt looks wrong and the first key can be lost.

- **ANSI** sequences (alternate screen off, scroll region reset, origin mode,
  mouse off, cursor visible, SGR reset): all platforms with a VT-capable stdout.
- **Blank lines** after reset: ``pam launch`` prints ``terminal_height`` newlines
  before the session. At exit we **re-query** ``shutil.get_terminal_size().lines``
  and take ``max(current, session_start_rows)`` when the caller passes the
  session-start row count — so shrink-after-start still pads enough to match the
  initial scroll push, and grow-after-start matches the larger viewport.
- **Windows**: after emitting ANSI, optionally move the console **viewport**
  (``SetConsoleWindowInfo``) so the cursor is visible — ConPTY/Terminal can leave
  the window showing the top of the buffer while new output is written below.
- **Discard queued stdin**: POSIX uses ``termios.tcflush``; Windows uses
  ``FlushConsoleInputBuffer`` — there is no ``stty`` on Windows.
- **``stty sane``**: Unix/macOS only (line discipline); not applicable on Windows.

**Partial vs full reset:** The default path emits ANSI mode cleanup plus newline padding
(see :func:`_ansi_terminal_reset_string` and :func:`_post_reset_newlines`). An optional
full viewport clear :func:`_post_reset_clear_viewport` is available but commented out
in :func:`reset_local_terminal_after_pam_session` because it erases scrollback.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys

# Fallback if get_terminal_size fails (matches launch.py pre-session clear).
_FALLBACK_TERMINAL_ROWS = 24


def _post_reset_line_count() -> int:
    """Fresh terminal row count at call time (handles resize since session start)."""
    try:
        if sys.stdout.isatty():
            return max(1, shutil.get_terminal_size().lines)
    except Exception as exc:
        logging.debug('post-reset line count: %s', exc)
    return _FALLBACK_TERMINAL_ROWS


def _padding_line_count(session_start_rows: int | None) -> int:
    """
    Rows of newline padding: max(current size, session start size).

    Session start printed ``session_start_rows`` newlines; if the user shrinks the
    window before exit, ``current`` alone would under-pad; ``max`` fixes that.
    If the window grew, ``current`` is larger and dominates.
    """
    current = _post_reset_line_count()
    if session_start_rows is None:
        return current
    return max(current, max(1, int(session_start_rows)))


def _ansi_terminal_reset_string() -> str:
    """VT sequences to undo common fullscreen TUI state (nano, vim, etc.)."""
    return (
        '\x1b[?1049l'  # rmcup — exit alternate screen
        '\x1b[?47l'    # old secondary screen off (no-op on modern terminals)
        '\x1b[r'       # reset scroll region / margins (DECSTBM full screen)
        '\x1b[?6l'     # origin mode off — cursor addressing to full screen
        # xterm mouse / SGR mouse (nano may enable)
        '\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l'
        '\x1b[?2004l'  # bracketed paste off
        '\x1b[?25h'    # show cursor
        '\x1b[0m'      # SGR reset
        '\x1b[?1l'     # DECCKM off — normal cursor keys
        '\x1b[?7h'     # autowrap on
    )


def _post_reset_newlines(session_start_rows: int | None = None) -> str:
    """Padding newlines: see ``_padding_line_count`` and launch.py pre-session clear."""
    n = _padding_line_count(session_start_rows)
    if sys.platform == 'win32':
        return '\r\n' * n
    return '\n' * n


def _post_reset_clear_viewport() -> str:
    """
    Full terminal reset via viewport clear.

    CSI 3 J + 2 J + H clears scrollback and the visible screen. That strips
    remote TUI residue aggressively but loses all buffered scrollback in the
    emulator — enable in :func:`reset_local_terminal_after_pam_session` only if
    that trade-off is acceptable.
    """
    return '\x1b[3J\x1b[2J\x1b[H'


def _windows_scroll_viewport_to_cursor() -> None:
    """
    If the cursor row is outside the visible window, scroll the window so the
    cursor is on-screen (typically at the bottom). Fixes ConPTY/Windows
    Terminal leaving the viewport at the top while output continues below.
    """
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        STD_OUTPUT_HANDLE = -11
        h = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        if not h or h == wintypes.HANDLE(-1).value:
            return

        class COORD(ctypes.Structure):
            _fields_ = [('X', wintypes.SHORT), ('Y', wintypes.SHORT)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [
                ('Left', wintypes.SHORT),
                ('Top', wintypes.SHORT),
                ('Right', wintypes.SHORT),
                ('Bottom', wintypes.SHORT),
            ]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ('dwSize', COORD),
                ('dwCursorPosition', COORD),
                ('wAttributes', wintypes.WORD),
                ('srWindow', SMALL_RECT),
                ('dwMaximumWindowSize', COORD),
            ]

        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not kernel32.GetConsoleScreenBufferInfo(h, ctypes.byref(info)):
            return

        cy = int(info.dwCursorPosition.Y)
        top = int(info.srWindow.Top)
        bottom = int(info.srWindow.Bottom)
        win_h = bottom - top + 1
        buf_rows = int(info.dwSize.Y)
        if win_h <= 0 or buf_rows <= 0:
            return

        # Put the cursor on the bottom row of the viewport (normal shell UX).
        # ConPTY sometimes leaves the window pinned while the cursor moves down.
        max_top = max(0, buf_rows - win_h)
        new_top = cy - win_h + 1
        if new_top < 0:
            new_top = 0
        elif new_top > max_top:
            new_top = max_top

        new_bottom = new_top + win_h - 1
        if new_bottom >= buf_rows:
            new_bottom = buf_rows - 1
            new_top = max(0, new_bottom - win_h + 1)

        if new_top == top and new_bottom == bottom:
            return

        sr = SMALL_RECT()
        sr.Left = info.srWindow.Left
        sr.Right = info.srWindow.Right
        sr.Top = wintypes.SHORT(new_top)
        sr.Bottom = wintypes.SHORT(new_bottom)

        if not kernel32.SetConsoleWindowInfo(h, True, ctypes.byref(sr)):
            logging.debug(
                'SetConsoleWindowInfo failed: %s', kernel32.GetLastError()
            )
    except Exception as exc:
        logging.debug('Windows viewport scroll after pam session: %s', exc)


def _flush_stdin_queue_posix() -> None:
    try:
        if not sys.stdin.isatty():
            return
        import termios

        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception as exc:
        logging.debug('tcflush stdin after pam session: %s', exc)


def _flush_stdin_queue_windows() -> None:
    """Clear the console input queue (parity with POSIX tcflush TCIFLUSH)."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        STD_INPUT_HANDLE = -10
        h = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        # INVALID_HANDLE_VALUE (-1) is truthy in Python; still call Flush and rely on return.
        if h == 0:
            return
        if not kernel32.FlushConsoleInputBuffer(h):
            logging.debug('FlushConsoleInputBuffer failed: %s', kernel32.GetLastError())
    except Exception as exc:
        logging.debug('FlushConsoleInputBuffer after pam session: %s', exc)


def _stty_sane_posix() -> None:
    try:
        if not sys.stdin.isatty():
            return
        subprocess.run(
            ['stty', 'sane'],
            stdin=sys.stdin,
            check=False,
            timeout=3,
            capture_output=True,
        )
    except Exception as exc:
        logging.debug('stty sane after pam session: %s', exc)


def reset_local_terminal_after_pam_session(
    session_start_rows: int | None = None,
) -> None:
    """
    Best-effort reset of the interactive terminal after pam launch CLI mode.

    Call only after InputHandler/StdinHandler.stop() has restored raw mode /
    Windows console mode so stdin matches the outer shell again.

    Args:
        session_start_rows: Row count used at session start for the pre-session
            newline clear (``launch.py``). When set, padding uses
            ``max(fresh get_terminal_size().lines, session_start_rows)``.
    """
    if not sys.stdout.isatty():
        return

    try:
        sys.stdout.write(_ansi_terminal_reset_string())

        # Optional full clear (scrollback loss)
        sys.stdout.write(_post_reset_clear_viewport())

        sys.stdout.write(_post_reset_newlines(session_start_rows=session_start_rows))
        sys.stdout.flush()
    except Exception as exc:
        logging.debug('Terminal ANSI reset: %s', exc)

    # Queued input: POSIX tcflush; Windows FlushConsoleInputBuffer (before stty on Unix).
    if sys.platform == 'win32':
        _windows_scroll_viewport_to_cursor()
        _flush_stdin_queue_windows()
    else:
        _flush_stdin_queue_posix()
        _stty_sane_posix()
