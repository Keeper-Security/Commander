#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Shared input coordination for both InputHandler (key-event mode) and
StdinHandler (--stdin / pipe mode).

CtrlCCoordinator
    Implements the double-tap Ctrl+C protocol (fixed 400 ms window):
      • First tap  → forward interrupt to the remote session only.
      • Second tap within the window → tear down the local session.
      • Tap outside the window → treated as a fresh first tap.

PasteOrchestrator
    Reads the OS clipboard with pyperclip and sends it to the remote using
    the Web Vault-equivalent Guacamole clipboard stream protocol:
        clipboard,<stream_id>,text/plain;
        blob,<stream_id>,<base64>;
        end,<stream_id>;
    Never falls back to send_stdin for paste.  If disablePaste is set the
    chord is silently ignored (early warning is printed at session start).
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

# Fixed Ctrl+C double-tap window (plan: 400 ms, within the 300–500 ms band).
CTRL_C_WINDOW: float = 0.4


class CtrlCCoordinator:
    """
    Double-tap Ctrl+C coordinator shared by InputHandler and StdinHandler.

    Args:
        remote_interrupt_fn: Called on the *first* tap (or any tap outside the
            window) to forward the interrupt to the remote session.
            • Key mode  : send_key(keysym=3, pressed) x 2  (press + release)
            • Pipe mode : send_stdin(b'\\x03')
        local_exit_fn: Called on the *second* tap inside the window to end the
            local pam-launch session (sets shutdown_requested=True).
    """

    def __init__(
        self,
        remote_interrupt_fn: Callable[[], None],
        local_exit_fn: Callable[[], None],
    ) -> None:
        self._remote_interrupt = remote_interrupt_fn
        self._local_exit = local_exit_fn
        self._last_ctrl_c: Optional[float] = None

    def handle(self) -> None:
        """Call whenever Ctrl+C (byte 0x03) is detected in the input stream."""
        now = time.monotonic()
        if (
            self._last_ctrl_c is not None
            and (now - self._last_ctrl_c) <= CTRL_C_WINDOW
        ):
            # Second tap inside window → local exit
            self._last_ctrl_c = None
            print('\r\nExiting session...', flush=True)
            self._local_exit()
        else:
            # First tap (or outside window) → remote interrupt only
            self._last_ctrl_c = now
            self._remote_interrupt()


class PasteOrchestrator:
    """
    OS-clipboard → remote Guacamole clipboard stream.

    GuacamoleClipboard.setRemoteClipboard:
        client.createClipboardStream(mimetype)   →  clipboard instruction
        writer.sendText(data)                    →  blob instruction
        writer.sendEnd()                         →  end instruction

    Args:
        send_clipboard_fn: Callable(text: str) that formats and sends the
            three-instruction clipboard stream to the gateway.  Should be
            GuacamoleHandler.send_clipboard_stream.
        disable_paste: When True the chord is a silent no-op (warning already
            printed at session start by launch.py execute()).
    """

    def __init__(
        self,
        send_clipboard_fn: Callable[[str], None],
        disable_paste: bool = False,
    ) -> None:
        self._send_clipboard = send_clipboard_fn
        self._disable_paste = disable_paste

    def paste(self) -> None:
        """Trigger a clipboard paste to the remote session."""
        if self._disable_paste:
            return

        try:
            import pyperclip  # type: ignore[import]
            text = pyperclip.paste()
        except ImportError:
            msg = (
                'Paste unavailable: pyperclip is not installed. '
                'Run: pip install pyperclip'
            )
            logging.warning(msg)
            print(f'\r\n{msg}', flush=True)
            return
        except Exception as exc:
            msg = f'Could not read clipboard: {exc}'
            logging.warning(msg)
            print(f'\r\n{msg}', flush=True)
            return

        if not text:
            return

        try:
            self._send_clipboard(text)
            logging.debug('Paste: %d chars sent via Guacamole clipboard stream', len(text))
        except Exception as exc:
            msg = f'Failed to send clipboard to remote: {exc}'
            logging.warning(msg)
            print(f'\r\n{msg}', flush=True)
