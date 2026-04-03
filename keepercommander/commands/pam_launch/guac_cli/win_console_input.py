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
Windows console: deliver Ctrl+C as ordinary input so pam launch can implement
double-tap exit without SIGINT (see CtrlCCoordinator).

When ENABLE_PROCESSED_INPUT is set, the system handles Ctrl+C and raises SIGINT
instead of placing 0x03 in the console input queue. Clearing that flag matches
Unix tty.setraw(ISIG off) behavior for the interactive session. Line input and
echo are also cleared so local console echo does not duplicate remote SSH echo.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

# https://learn.microsoft.com/en-us/windows/console/setconsolemode
_ENABLE_PROCESSED_INPUT = 0x0001
_ENABLE_LINE_INPUT = 0x0002
_ENABLE_ECHO_INPUT = 0x0004
_STD_INPUT_HANDLE = -10

# Flags to clear when entering raw mode for ReadConsoleInputW.
# Mirrors what tty.setraw() does on Unix (clears ICANON + ECHO + ISIG):
#   ENABLE_PROCESSED_INPUT — deliver Ctrl+C as 0x03 (not SIGINT)
#   ENABLE_LINE_INPUT      — disable line-editing / cooked-mode buffer
#   ENABLE_ECHO_INPUT      — disable console host visual echo
#
# Without clearing ENABLE_LINE_INPUT + ENABLE_ECHO_INPUT, the Windows console
# host (conhost.exe / PowerShell window) visually echoes each typed character
# to the screen the moment it enters the input queue — before ReadConsoleInputW
# consumes it.  Combined with the SSH server's remote echo (which arrives via
# the guacd STDOUT blob), the user sees every character twice.  Windows Terminal
# (ConPTY) suppresses the visual echo on its own, which is why the duplicate is
# intermittent rather than universal.
_RAW_MODE_CLEAR = _ENABLE_PROCESSED_INPUT | _ENABLE_LINE_INPUT | _ENABLE_ECHO_INPUT


def win_stdin_disable_ctrl_c_process_input() -> Optional[int]:
    """
    Set stdin console handle to raw mode for ReadConsoleInputW:
      - Clear ENABLE_PROCESSED_INPUT so Ctrl+C is read as 0x03, not SIGINT.
      - Clear ENABLE_LINE_INPUT + ENABLE_ECHO_INPUT to suppress the console
        host's visual echo, preventing duplicate characters when the remote
        SSH session also echoes typed input.

    Returns the previous mode for win_stdin_restore_console_mode, or None if not
    Windows, not a console, or the API failed.
    """
    if sys.platform != 'win32':
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(_STD_INPUT_HANDLE)
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return None
        old = int(mode.value)
        new = old & ~_RAW_MODE_CLEAR
        if new == old:
            return old
        if not kernel32.SetConsoleMode(h, new):
            logging.debug('SetConsoleMode(raw mode) failed')
            return None
        return old
    except Exception as exc:
        logging.debug('win_stdin_disable_ctrl_c_process_input: %s', exc)
        return None


def win_stdin_restore_console_mode(old_mode: Optional[int]) -> None:
    """Restore stdin console mode from win_stdin_disable_ctrl_c_process_input."""
    if old_mode is None or sys.platform != 'win32':
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(_STD_INPUT_HANDLE)
        if not kernel32.SetConsoleMode(h, old_mode):
            logging.debug('SetConsoleMode(restore) failed')
    except Exception as exc:
        logging.debug('win_stdin_restore_console_mode: %s', exc)
