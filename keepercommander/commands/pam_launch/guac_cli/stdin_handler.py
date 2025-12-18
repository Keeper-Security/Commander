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

    Enhanced to detect escape sequences (arrow keys, function keys) and
    send them as X11 key events instead of raw bytes.
    """

    def __init__(self, stdin_callback: Callable[[bytes], None],
                 key_callback: Optional[Callable[[int, bool], None]] = None):
        """
        Initialize the stdin handler.

        Args:
            stdin_callback: Callback function(data: bytes) to send stdin data.
                           Should call GuacamoleHandler.send_stdin()
            key_callback: Optional callback function(keysym: int, pressed: bool)
                         to send key events. Should call GuacamoleHandler.send_key()
                         If provided, escape sequences will be converted to key events.
        """
        self.stdin_callback = stdin_callback
        self.key_callback = key_callback
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.raw_mode_active = False
        self._escape_buffer = b''  # Buffer for escape sequences

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
        # Flush any pending escape sequence
        if self._escape_buffer:
            # If we have just ESC (0x1B) with no following bytes, treat as standalone ESC key
            if len(self._escape_buffer) == 1 and self._escape_buffer[0] == 0x1B:
                if self.key_callback:
                    self._send_key(0xFF1B)  # X11Keysym.ESCAPE
                else:
                    self.stdin_callback(self._escape_buffer)
            else:
                # Incomplete escape sequence - send as regular data
                logging.debug(f"Flushing incomplete escape sequence: {self._escape_buffer}")
                self.stdin_callback(self._escape_buffer)
            self._escape_buffer = b''
        if self.raw_mode_active:
            self._stdin_reader.restore()
            self.raw_mode_active = False
        if self.thread:
            # Don't wait too long - stdin.read() might be blocking
            self.thread.join(timeout=0.5)
        logging.debug("StdinHandler stopped")

    def _input_loop(self):
        """Main stdin reading loop."""
        import time
        last_escape_time = None

        while self.running:
            try:
                # Read available data (non-blocking with short timeout)
                data = self._stdin_reader.read(timeout=0.1)
                if data:
                    self._process_input(data)
                    # Reset escape timer if we got data
                    last_escape_time = None
                elif self._escape_buffer and len(self._escape_buffer) == 1 and self._escape_buffer[0] == 0x1B:
                    # We have a standalone ESC in buffer with no more data
                    # Wait a short time to see if more bytes arrive (escape sequence)
                    if last_escape_time is None:
                        last_escape_time = time.time()
                    elif time.time() - last_escape_time > 0.05:  # 50ms timeout
                        # No more bytes after 50ms - treat as standalone ESC key
                        logging.debug("Standalone ESC key (timeout)")
                        self._send_key(0xFF1B)  # X11Keysym.ESCAPE
                        self._escape_buffer = b''
                        last_escape_time = None
            except Exception as e:
                if self.running:  # Only log if not shutting down
                    logging.error(f"Error in stdin loop: {e}")
                break

    def _process_input(self, data: bytes):
        """
        Process input data, detecting escape sequences and converting them to key events.

        Args:
            data: Raw bytes from stdin
        """
        if not self.key_callback:
            # No key callback - send everything as stdin (original behavior)
            self.stdin_callback(data)
            return

        # Combine any pending escape buffer with new data
        if self._escape_buffer:
            data = self._escape_buffer + data
            self._escape_buffer = b''

        # Process data byte by byte to detect escape sequences
        i = 0
        while i < len(data):
            byte = data[i]

            # Check if we're in an escape sequence
            if self._escape_buffer:
                self._escape_buffer += bytes([byte])
                keysym = self._detect_escape_sequence()
                if keysym is not None:
                    # Found a complete escape sequence - send as key event
                    logging.debug(f"Detected escape sequence: {self._escape_buffer.hex()} -> keysym 0x{keysym:04X}")
                    self._send_key(keysym)
                    self._escape_buffer = b''
                    i += 1
                    continue
                elif len(self._escape_buffer) > 10:
                    # Escape sequence too long - treat as regular data
                    logging.warning(f"Invalid escape sequence (too long): {self._escape_buffer.hex()}")
                    self.stdin_callback(self._escape_buffer)
                    self._escape_buffer = b''
                    i += 1
                    continue
                else:
                    # Still waiting for more bytes in escape sequence
                    # Check if we've reached the end of current data
                    if i == len(data) - 1:
                        # Last byte, might need more - keep in buffer for next read
                        # But if we only have ESC (0x1B) and no more data, treat as standalone ESC
                        if len(self._escape_buffer) == 1 and self._escape_buffer[0] == 0x1B:
                            logging.debug("Standalone ESC key (no more data available)")
                            self._send_key(0xFF1B)  # X11Keysym.ESCAPE
                            self._escape_buffer = b''
                            i += 1
                            continue
                        break
                    i += 1
                    continue

            # Check for start of escape sequence
            # Unix/Linux/macOS: ESC = 0x1B
            # Windows: Extended key = 0xE0 or 0x00
            if byte == 0x1B:
                # Start of potential Unix-style escape sequence
                # Check if there are more bytes immediately available
                if i < len(data) - 1:
                    # More bytes available - might be an escape sequence
                    self._escape_buffer = bytes([byte])
                    i += 1
                    # Continue processing to see if sequence completes in this read
                    continue
                else:
                    # This is the last byte - could be standalone ESC or start of sequence
                    # For now, treat as standalone ESC key (user can press ESC twice if needed)
                    # If it's part of a sequence, the next read will handle it
                    logging.debug("Standalone ESC key detected")
                    self._send_key(0xFF1B)  # X11Keysym.ESCAPE
                    i += 1
                    continue
            elif byte == 0xE0 or byte == 0x00:
                # Windows extended key sequence (0xE0 or 0x00 followed by scan code)
                self._escape_buffer = bytes([byte])
                i += 1
                # Check if we can read more bytes immediately
                if i < len(data):
                    # Continue processing to see if sequence completes in this read
                    continue
                else:
                    # End of data, wait for next read
                    break

            # Regular character - send as stdin
            # But first check if it's a control character that might be part of an escape sequence
            if byte < 32 and byte != 0x1B:  # Control char but not ESC
                # Send control characters as-is (they might be Ctrl+key combinations)
                self.stdin_callback(bytes([byte]))
            elif byte >= 32:  # Printable character
                self.stdin_callback(bytes([byte]))
            else:
                # Shouldn't reach here, but send anyway
                self.stdin_callback(bytes([byte]))
            i += 1

    def _detect_escape_sequence(self) -> Optional[int]:
        """
        Detect if the escape buffer contains a known escape sequence.

        Returns:
            X11 keysym if sequence is recognized and complete, None if incomplete or unknown
        """
        if not self._escape_buffer or len(self._escape_buffer) < 2:
            return None

        # Check for Windows extended key sequences (0xE0 or 0x00 prefix)
        if len(self._escape_buffer) == 2 and (self._escape_buffer[0] == 0xE0 or self._escape_buffer[0] == 0x00):
            # Windows console extended key code
            scan_code = self._escape_buffer[1]

            # Windows scan codes for arrow keys
            if scan_code == 0x48:  # 'H' = Up arrow
                return 0xFF52  # UP
            elif scan_code == 0x50:  # 'P' = Down arrow
                return 0xFF54  # DOWN
            elif scan_code == 0x4D:  # 'M' = Right arrow
                return 0xFF53  # RIGHT
            elif scan_code == 0x4B:  # 'K' = Left arrow
                return 0xFF51  # LEFT
            elif scan_code == 0x47:  # Home
                return 0xFF50  # HOME
            elif scan_code == 0x4F:  # End
                return 0xFF57  # END
            elif scan_code == 0x49:  # Page Up
                return 0xFF55  # PAGE_UP
            elif scan_code == 0x51:  # Page Down
                return 0xFF56  # PAGE_DOWN
            elif scan_code == 0x52:  # Insert
                return 0xFF63  # INSERT
            elif scan_code == 0x53:  # Delete
                return 0xFFFF  # DELETE
            # Function keys F1-F10 (Windows scan codes)
            elif scan_code == 0x3B:  # F1
                return 0xFFBE  # F1
            elif scan_code == 0x3C:  # F2
                return 0xFFBF  # F2
            elif scan_code == 0x3D:  # F3
                return 0xFFC0  # F3
            elif scan_code == 0x3E:  # F4
                return 0xFFC1  # F4
            elif scan_code == 0x3F:  # F5
                return 0xFFC2  # F5
            elif scan_code == 0x40:  # F6
                return 0xFFC3  # F6
            elif scan_code == 0x41:  # F7
                return 0xFFC4  # F7
            elif scan_code == 0x42:  # F8
                return 0xFFC5  # F8
            elif scan_code == 0x43:  # F9
                return 0xFFC6  # F9
            elif scan_code == 0x44:  # F10
                return 0xFFC7  # F10
            elif scan_code == 0x85:  # F11
                return 0xFFC8  # F11
            elif scan_code == 0x86:  # F12
                return 0xFFC9  # F12
            else:
                return None

        # Unix/Linux/macOS VT100/xterm escape sequences
        # Convert to string for pattern matching
        try:
            seq = self._escape_buffer[1:].decode('ascii', errors='ignore')
        except Exception:
            return None

        # Arrow keys and navigation (VT100/xterm style - universal on Linux/macOS)
        # These sequences are standard across all Unix-like terminals
        if seq == '[A':
            return 0xFF52  # UP
        elif seq == '[B':
            return 0xFF54  # DOWN
        elif seq == '[C':
            return 0xFF53  # RIGHT
        elif seq == '[D':
            return 0xFF51  # LEFT
        elif seq == '[H':
            return 0xFF50  # HOME
        elif seq == '[F':
            return 0xFF57  # END
        # Some terminals send arrow keys with modifiers (e.g., [1;2A for Shift+Up, [1;5A for Ctrl+Up)
        # We ignore the modifier part and just use the base key
        elif seq.startswith('[1;') and len(seq) >= 4:
            # Extract the final character (A, B, C, D for arrows)
            final_char = seq[-1]
            if final_char == 'A':
                return 0xFF52  # UP
            elif final_char == 'B':
                return 0xFF54  # DOWN
            elif final_char == 'C':
                return 0xFF53  # RIGHT
            elif final_char == 'D':
                return 0xFF51  # LEFT

        # Function keys (VT100/xterm style - single character after ESC)
        elif seq == 'OP':
            return 0xFFBE  # F1
        elif seq == 'OQ':
            return 0xFFBF  # F2
        elif seq == 'OR':
            return 0xFFC0  # F3
        elif seq == 'OS':
            return 0xFFC1  # F4

        # Function keys (xterm style - with tilde)
        elif seq == '[11~':
            return 0xFFBE  # F1
        elif seq == '[12~':
            return 0xFFBF  # F2
        elif seq == '[13~':
            return 0xFFC0  # F3
        elif seq == '[14~':
            return 0xFFC1  # F4
        elif seq == '[15~':
            return 0xFFC2  # F5
        elif seq == '[17~':
            return 0xFFC3  # F6
        elif seq == '[18~':
            return 0xFFC4  # F7
        elif seq == '[19~':
            return 0xFFC5  # F8
        elif seq == '[20~':
            return 0xFFC6  # F9
        elif seq == '[21~':
            return 0xFFC7  # F10
        elif seq == '[23~':
            return 0xFFC8  # F11
        elif seq == '[24~':
            return 0xFFC9  # F12

        # Other special keys
        elif seq == '[1~':
            return 0xFF50  # HOME
        elif seq == '[2~':
            return 0xFF63  # INSERT
        elif seq == '[3~':
            return 0xFFFF  # DELETE
        elif seq == '[4~':
            return 0xFF57  # END
        elif seq == '[5~':
            return 0xFF55  # PAGE_UP
        elif seq == '[6~':
            return 0xFF56  # PAGE_DOWN

        # Check if sequence might be incomplete (common patterns that need more bytes)
        # If it starts with '[' and doesn't end with '~' or a letter, might need more
        if seq.startswith('[') and len(seq) >= 2:
            # Check if it looks like it might be complete (ends with letter or ~)
            if seq[-1].isalpha() or seq[-1] == '~':
                # Might be complete but not recognized - return None to continue waiting
                # This handles edge cases where we might have partial sequences
                pass

        # Not a recognized sequence yet - might need more bytes
        return None

    def _send_key(self, keysym: int):
        """
        Send a key press and release event.

        Args:
            keysym: X11 keysym value
        """
        if self.key_callback:
            # Send key press
            self.key_callback(keysym, True)
            # Send key release
            self.key_callback(keysym, False)


class _UnixStdinReader:
    """Unix/Linux stdin reader with raw mode support using termios."""

    def __init__(self):
        self.old_settings = None

    def set_raw_mode(self):
        """Set terminal to raw mode (non-buffered, non-echoing)."""
        try:
            import termios
            import tty
            import time

            # Flush stdout before changing terminal attributes to ensure all output is complete
            sys.stdout.flush()
            sys.stderr.flush()

            self.old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())

            # Small delay to allow terminal to process the attribute change
            # This helps prevent visual glitches where lines appear to be deleted
            time.sleep(0.01)  # 10ms delay

            # Flush again after setting raw mode
            sys.stdout.flush()
            sys.stderr.flush()
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
            import time

            # Flush stdout before changing terminal attributes to ensure all output is complete
            sys.stdout.flush()
            sys.stderr.flush()

            self.old_settings = termios.tcgetattr(sys.stdin.fileno())
            # Use setraw for macOS - same as Linux
            tty.setraw(sys.stdin.fileno())

            # Small delay to allow terminal to process the attribute change
            # This helps prevent visual glitches where lines appear to be deleted
            time.sleep(0.01)  # 10ms delay

            # Flush again after setting raw mode
            sys.stdout.flush()
            sys.stderr.flush()
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
        try:
            import time

            # Flush stdout before changing console mode to ensure all output is complete
            sys.stdout.flush()
            sys.stderr.flush()

            # Windows console is already suitable for getch-style reading
            # No explicit raw mode needed for msvcrt, but we still flush and delay
            # to prevent visual glitches when entering CLI mode

            # Small delay to allow console to process any pending output
            # This helps prevent visual glitches where lines appear to be deleted
            time.sleep(0.01)  # 10ms delay

            # Flush again after the delay
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception as e:
            logging.warning(f"Failed to set raw mode on Windows: {e}")

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
