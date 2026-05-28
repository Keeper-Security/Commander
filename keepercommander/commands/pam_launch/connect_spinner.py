#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.

"""
Animated spinner for the ``pam launch`` connect phase.

This is a copy of ``keepercommander.display.Spinner`` kept local to ``pam_launch``
so connect UX can move to another implementation (Rich, plain ASCII, etc.) without
touching global ``display`` helpers.
"""

from __future__ import annotations

import logging
import sys
import threading
import time

from colorama import Fore

__all__ = ['PamLaunchSpinner']


class PamLaunchSpinner:
    """Animated spinner for long-running ``pam launch`` operations."""

    FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def __init__(self, message: str = '') -> None:
        self.message = message
        self.running = False
        self.thread: threading.Thread | None = None
        self._last_visible_len = 0

    def _animate(self) -> None:
        idx = 0
        while self.running:
            try:
                frame = self.FRAMES[idx % len(self.FRAMES)]
                message = self.message or ''
                visible_len = len(message) + 2
                pad = max(0, self._last_visible_len - visible_len)
                sys.stdout.write(f'\r{Fore.CYAN}{frame}{Fore.RESET} {message}' + (' ' * pad))
                sys.stdout.flush()
                self._last_visible_len = visible_len + pad
                idx += 1
            except Exception:
                logging.getLogger(__name__).debug('PamLaunchSpinner frame skipped', exc_info=True)
            time.sleep(0.08)
        clear_len = max(self._last_visible_len, len(self.message or '') + 2)
        sys.stdout.write('\r' + ' ' * clear_len + '\r')
        sys.stdout.flush()
        self._last_visible_len = 0

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
