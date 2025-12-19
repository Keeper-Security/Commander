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
Input handler for Guacamole CLI mode.

Maps stdin keystrokes to Guacamole key instructions using X11 keysyms.
Handles control keys, special keys, and character input.
"""

from __future__ import annotations
import sys
import logging
import threading
from typing import Optional, Callable
from .decoder import X11Keysym


class InputHandler:
    """
    Handles stdin input and converts it to Guacamole key events.

    Reads from stdin in raw mode (non-buffered, non-echoing) and maps
    keys to X11 keysyms for transmission via Guacamole protocol.
    """

    def __init__(self, key_callback: Callable[[int, bool], None]):
        """
        Initialize the input handler.

        Args:
            key_callback: Callback function(keysym, pressed) to send key events
        """
        self.key_callback = key_callback
        self.running = False
        self.thread = None
        self.raw_mode_active = False

        # Platform-specific stdin handler
        self.stdin_reader = self._get_stdin_reader()

    def _get_stdin_reader(self):
        """Get platform-specific stdin reader"""
        if sys.platform == 'win32':
            return WindowsStdinReader()
        else:
            return UnixStdinReader()

    def start(self):
        """Start reading input in a background thread"""
        if self.running:
            return

        self.running = True
        self.stdin_reader.set_raw_mode()
        self.raw_mode_active = True

        self.thread = threading.Thread(target=self._input_loop, daemon=True)
        self.thread.start()
        logging.debug("Input handler started")

    def stop(self):
        """Stop reading input and restore terminal"""
        self.running = False
        if self.raw_mode_active:
            self.stdin_reader.restore()
            self.raw_mode_active = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logging.debug("Input handler stopped")

    def _input_loop(self):
        """Main input reading loop"""
        while self.running:
            try:
                ch = self.stdin_reader.read_char()
                if ch:
                    self._process_input(ch)
            except Exception as e:
                logging.error(f"Error in input loop: {e}")
                break

    def _process_input(self, ch: str):
        """
        Process a character from stdin and generate key events.

        Args:
            ch: Character or escape sequence from stdin
        """
        # Handle escape sequences for special keys
        if ch == '\x1b':  # ESC
            # Try to read escape sequence
            seq = self._read_escape_sequence()
            if seq:
                keysym = self._escape_to_keysym(seq)
                if keysym:
                    self._send_key(keysym)
            else:
                # Just ESC key
                self._send_key(X11Keysym.ESCAPE)

        # Handle control characters
        elif ord(ch) < 32:
            keysym = self._control_char_to_keysym(ch)
            if keysym:
                self._send_key(keysym)

        # Handle DEL (127)
        elif ord(ch) == 127:
            self._send_key(X11Keysym.BACKSPACE)

        # Handle regular printable characters
        else:
            # For printable ASCII, keysym is just the character code
            keysym = ord(ch)
            self._send_key(keysym)

    def _read_escape_sequence(self) -> Optional[str]:
        """
        Read an ANSI escape sequence from stdin.

        Returns:
            Escape sequence string (without ESC prefix) or None
        """
        seq = ""
        for _ in range(5):  # Read up to 5 characters
            ch = self.stdin_reader.read_char(timeout=0.05)
            if ch:
                seq += ch
                # Common sequences end with a letter
                if ch.isalpha() or ch == '~':
                    break
            else:
                break

        return seq if seq else None

    def _escape_to_keysym(self, seq: str) -> Optional[int]:
        """
        Map an ANSI escape sequence to X11 keysym.

        Args:
            seq: Escape sequence (without ESC prefix)

        Returns:
            X11 keysym or None
        """
        # Common escape sequences
        mappings = {
            '[A': X11Keysym.UP,
            '[B': X11Keysym.DOWN,
            '[C': X11Keysym.RIGHT,
            '[D': X11Keysym.LEFT,
            '[H': X11Keysym.HOME,
            '[F': X11Keysym.END,
            '[1~': X11Keysym.HOME,
            '[2~': 0xFFFF,  # Insert
            '[3~': X11Keysym.DELETE,
            '[4~': X11Keysym.END,
            '[5~': X11Keysym.PAGE_UP,
            '[6~': X11Keysym.PAGE_DOWN,
            'OP': X11Keysym.F1,
            'OQ': X11Keysym.F2,
            'OR': X11Keysym.F3,
            'OS': X11Keysym.F4,
            '[15~': X11Keysym.F5,
            '[17~': X11Keysym.F6,
            '[18~': X11Keysym.F7,
            '[19~': X11Keysym.F8,
            '[20~': X11Keysym.F9,
            '[21~': X11Keysym.F10,
            '[23~': X11Keysym.F11,
            '[24~': X11Keysym.F12,
        }

        return mappings.get(seq)

    def _control_char_to_keysym(self, ch: str) -> Optional[int]:
        """
        Map control character to X11 keysym.

        Args:
            ch: Control character

        Returns:
            X11 keysym or None
        """
        code = ord(ch)

        # Common control characters
        if code == 8:    # Backspace (Ctrl+H)
            return X11Keysym.BACKSPACE
        elif code == 9:  # Tab
            return X11Keysym.TAB
        elif code == 10: # Line feed (Enter on Unix)
            return X11Keysym.RETURN
        elif code == 13: # Carriage return (Enter on Windows)
            return X11Keysym.RETURN
        elif code == 27: # ESC
            return X11Keysym.ESCAPE
        else:
            # Ctrl+letter combinations (Ctrl+A = 1, Ctrl+B = 2, etc.)
            # Send as lowercase letter with Ctrl modifier
            # For simplicity, just send the control character as-is
            # Guacamole can interpret it
            return code

    def _send_key(self, keysym: int):
        """
        Send a key press and release event.

        Args:
            keysym: X11 keysym value
        """
        # Send key press
        self.key_callback(keysym, True)

        # Send key release
        self.key_callback(keysym, False)


class UnixStdinReader:
    """Unix/Linux stdin reader with raw mode support"""

    def __init__(self):
        self.old_settings = None

    def set_raw_mode(self):
        """Set terminal to raw mode (non-buffered, non-echoing)"""
        try:
            import termios
            import tty
            self.old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
        except Exception as e:
            logging.warning(f"Failed to set raw mode: {e}")

    def restore(self):
        """Restore terminal to normal mode"""
        if self.old_settings:
            try:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self.old_settings)
            except Exception as e:
                logging.warning(f"Failed to restore terminal: {e}")
            self.old_settings = None

    def read_char(self, timeout: Optional[float] = None) -> Optional[str]:
        """
        Read a single character from stdin.

        Args:
            timeout: Read timeout in seconds (None = blocking)

        Returns:
            Character or None if timeout
        """
        if timeout:
            import select
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None

        try:
            return sys.stdin.read(1)
        except:
            return None


class WindowsStdinReader:
    """Windows stdin reader with raw mode support"""

    def __init__(self):
        self.old_mode = None

    def set_raw_mode(self):
        """Set console to raw mode on Windows"""
        try:
            import msvcrt
            # Windows console is already non-buffered for getch
            pass
        except:
            pass

    def restore(self):
        """Restore console mode"""
        pass

    def read_char(self, timeout: Optional[float] = None) -> Optional[str]:
        """
        Read a single character from stdin on Windows.

        Args:
            timeout: Read timeout in seconds (None = blocking)

        Returns:
            Character or None if timeout
        """
        try:
            import msvcrt

            if timeout:
                # Poll for input with timeout
                import time
                start = time.time()
                while time.time() - start < timeout:
                    if msvcrt.kbhit():
                        ch = msvcrt.getch()
                        return ch.decode('utf-8', errors='ignore')
                    time.sleep(0.01)
                return None
            else:
                # Blocking read
                ch = msvcrt.getch()
                return ch.decode('utf-8', errors='ignore')
        except Exception as e:
            logging.error(f"Error reading from stdin on Windows: {e}")
            return None

