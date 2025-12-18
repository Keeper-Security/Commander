#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Stdin handler for Guacamole CLI mode using pipe/blob/end pattern.

Reads raw stdin and sends to server via the pipe/blob/end Guacamole protocol.
This is for plaintext SSH/TTY streams (NOT graphical protocols).

The pipe/blob/end pattern (from kcm-cli):
- pipe,0,text/plain,STDIN  - Open STDIN pipe on stream 0
- blob,0,<base64_data>     - Send base64-encoded keyboard input
- end,0                    - Close the stream

Each chunk of stdin input is sent as a complete pipe/blob/end sequence.

Platform support:
- Unix/Linux: Uses termios for raw mode, select for non-blocking reads
- macOS: Uses same approach as Unix (termios + select)
- Windows: Uses msvcrt for console input
"""

from __future__ import annotations
import logging
import sys
import threading
from typing import Callable, Optional


class StdinHandler:
    """
    Handles stdin input for plaintext SSH/TTY sessions.

    Reads raw stdin in non-buffered mode and sends data via callback.
    Uses pipe/blob/end pattern matching kcm-cli implementation.
    """

    def __init__(self, stdin_callback: Callable[[bytes], None]):
        """
        Initialize the stdin handler.

        Args:
            stdin_callback: Callback function(data: bytes) to send stdin data.
                           Should call GuacamoleHandler.send_stdin()
        """
        self.stdin_callback = stdin_callback
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.raw_mode_active = False

        # Platform-specific stdin reader
        self._stdin_reader = self._get_stdin_reader()

    def _get_stdin_reader(self):
        """Get platform-specific stdin reader."""
        if sys.platform == 'win32':
            return _WindowsStdinReader()
        elif sys.platform == 'darwin':
            return _MacOSStdinReader()
        else:
            return _UnixStdinReader()

    def start(self):
        """Start reading stdin in a background thread."""
        if self.running:
            return

        self.running = True
        self._stdin_reader.set_raw_mode()
        self.raw_mode_active = True

        self.thread = threading.Thread(target=self._input_loop, daemon=True)
        self.thread.start()
        logging.debug("StdinHandler started")

    def stop(self):
        """Stop reading stdin and restore terminal."""
        self.running = False
        if self.raw_mode_active:
            self._stdin_reader.restore()
            self.raw_mode_active = False
        if self.thread:
            # Don't wait too long - stdin.read() might be blocking
            self.thread.join(timeout=0.5)
        logging.debug("StdinHandler stopped")

    def _input_loop(self):
        """Main stdin reading loop."""
        while self.running:
            try:
                # Read available data (non-blocking with short timeout)
                data = self._stdin_reader.read(timeout=0.1)
                if data:
                    self.stdin_callback(data)
            except Exception as e:
                if self.running:  # Only log if not shutting down
                    logging.error(f"Error in stdin loop: {e}")
                break


class _UnixStdinReader:
    """Unix/Linux stdin reader with raw mode support using termios."""

    def __init__(self):
        self.old_settings = None

    def set_raw_mode(self):
        """Set terminal to raw mode (non-buffered, non-echoing)."""
        try:
            import termios
            import tty
            self.old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
        except Exception as e:
            logging.warning(f"Failed to set raw mode: {e}")

    def restore(self):
        """Restore terminal to normal mode."""
        if self.old_settings:
            try:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self.old_settings)
            except Exception as e:
                logging.warning(f"Failed to restore terminal: {e}")
            self.old_settings = None

    def read(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Read available data from stdin.

        Args:
            timeout: Read timeout in seconds (None = blocking)

        Returns:
            Bytes data or None if timeout/no data
        """
        import select

        if timeout:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None

        try:
            # Read what's available (up to 4KB)
            data = sys.stdin.buffer.read1(4096)
            return data if data else None
        except Exception:
            return None


class _MacOSStdinReader:
    """
    macOS stdin reader with raw mode support.

    macOS uses the same POSIX termios approach as Linux, but may have
    slight differences in terminal handling. This class provides
    macOS-specific optimizations if needed.
    """

    def __init__(self):
        self.old_settings = None

    def set_raw_mode(self):
        """Set terminal to raw mode (non-buffered, non-echoing)."""
        try:
            import termios
            import tty
            self.old_settings = termios.tcgetattr(sys.stdin.fileno())
            # Use setraw for macOS - same as Linux
            tty.setraw(sys.stdin.fileno())
        except Exception as e:
            logging.warning(f"Failed to set raw mode on macOS: {e}")

    def restore(self):
        """Restore terminal to normal mode."""
        if self.old_settings:
            try:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self.old_settings)
            except Exception as e:
                logging.warning(f"Failed to restore terminal on macOS: {e}")
            self.old_settings = None

    def read(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Read available data from stdin on macOS.

        Args:
            timeout: Read timeout in seconds (None = blocking)

        Returns:
            Bytes data or None if timeout/no data
        """
        import select

        if timeout:
            # Use select for non-blocking check
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None

        try:
            # Read what's available (up to 4KB)
            # Note: On macOS, read1() may not be available on all Python versions,
            # so we use os.read() as fallback
            import os
            fd = sys.stdin.fileno()
            data = os.read(fd, 4096)
            return data if data else None
        except Exception:
            return None


class _WindowsStdinReader:
    """Windows stdin reader using msvcrt for console input."""

    def __init__(self):
        self.old_mode = None

    def set_raw_mode(self):
        """Set console to raw mode on Windows."""
        # Windows console is already suitable for getch-style reading
        # No explicit raw mode needed for msvcrt
        pass

    def restore(self):
        """Restore console mode."""
        # Nothing to restore for basic msvcrt usage
        pass

    def read(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Read available data from stdin on Windows.

        Args:
            timeout: Read timeout in seconds (None = blocking)

        Returns:
            Bytes data or None if timeout/no data
        """
        try:
            import msvcrt
            import time

            result = b''
            start = time.time()

            # Collect all available characters
            while True:
                if timeout and (time.time() - start >= timeout):
                    break

                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    result += ch
                    # Continue collecting if more chars available immediately
                    continue
                elif result:
                    # Have data, return it
                    break
                else:
                    # No data yet, brief sleep to avoid busy-wait
                    time.sleep(0.01)

            return result if result else None

        except Exception as e:
            logging.error(f"Error reading from stdin on Windows: {e}")
            return None
