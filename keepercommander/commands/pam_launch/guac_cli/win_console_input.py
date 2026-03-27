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
Unix tty.setraw(ISIG off) behavior for the interactive session.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

# https://learn.microsoft.com/en-us/windows/console/setconsolemode
_ENABLE_PROCESSED_INPUT = 0x0001
_STD_INPUT_HANDLE = -10


def win_stdin_disable_ctrl_c_process_input() -> Optional[int]:
    """
    Clear ENABLE_PROCESSED_INPUT on the stdin console handle so Ctrl+C is read
    as character 0x03 (ReadConsoleInput / msvcrt) instead of raising SIGINT.

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
        new = old & ~_ENABLE_PROCESSED_INPUT
        if new == old:
            return old
        if not kernel32.SetConsoleMode(h, new):
            logging.debug('SetConsoleMode(clear ENABLE_PROCESSED_INPUT) failed')
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
