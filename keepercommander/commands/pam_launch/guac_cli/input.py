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
Input handler for Guacamole CLI key-event mode.

Maps stdin keystrokes to Guacamole `key` instructions (X11 keysyms) —
the default input path for `pam launch`, matching Web Vault behaviour where
Guacamole.Keyboard forwards every keystroke as sendKeyEvent().

Paste and Ctrl+C double-tap are handled via shared helpers from session_input:
    • Ctrl+V / Shift+Insert  → PasteOrchestrator → Vault clipboard stream
    • Ctrl+C (single)        → CtrlCCoordinator  → remote interrupt via send_key
    • Ctrl+C (double, 400ms) → CtrlCCoordinator  → local session exit

Windows extended keys (arrows, F-keys, Home/End …) are handled through a
ReadConsoleInput-based reader that emits standard VT100 escape sequences so
the existing _escape_to_keysym mapping works unchanged.  Shift+Insert and
Ctrl+Shift+V are detected with modifier state and mapped to paste.
"""

from __future__ import annotations

import collections
import sys
import logging
import threading
from typing import Optional, Callable

from .decoder import X11Keysym
from .session_input import CtrlCCoordinator, PasteOrchestrator
from .win_console_input import (
    win_stdin_disable_ctrl_c_process_input,
    win_stdin_restore_console_mode,
)

# Paste-chord sentinels (InputHandler internal)
# Ctrl+V (Unix raw + Windows uChar): 0x16
_PASTE_BYTE = '\x16'
# Windows ReadConsoleInput distinguishes these from Ctrl+V:
_CHORD_CTRL_SHIFT_V = '\x17'
_CHORD_SHIFT_INSERT = '\x18'
_CHORD_CTRL_INSERT = '\x19'


class InputHandler:
    """
    Handles stdin input and converts every keystroke to a Guacamole `key`
    instruction (press + release) via key_callback.

    Paste chords are routed through PasteOrchestrator (local OS → Guacamole
    clipboard) unless ``disable_paste`` is set; then they are sent as key
    events so the remote uses its own clipboard.
    Ctrl+C is routed through CtrlCCoordinator for double-tap exit logic.
    """

    def __init__(
        self,
        key_callback: Callable[[int, bool], None],
        ctrl_c_coordinator: Optional[CtrlCCoordinator] = None,
        paste_orchestrator: Optional[PasteOrchestrator] = None,
        *,
        disable_paste: bool = False,
    ):
        """
        Args:
            key_callback: function(keysym: int, pressed: bool) — sends key events.
            ctrl_c_coordinator: Shared double-tap Ctrl+C coordinator.  When None,
                Ctrl+C is forwarded as keysym 3 (ETX) like any other control char.
            paste_orchestrator: Shared paste handler.  When None, Ctrl+V and
                Shift+Insert are forwarded as key events unchanged.
            disable_paste: When True (PAM disablePaste), paste chords send Guacamole
                key events (Ctrl+V, etc.) so the remote uses its own clipboard, not
                the local OS clipboard stream.
        """
        self.key_callback = key_callback
        self.ctrl_c_coordinator = ctrl_c_coordinator
        self.paste_orchestrator = paste_orchestrator
        self.disable_paste = disable_paste
        self.running = False
        self.thread = None
        self.raw_mode_active = False

        self.stdin_reader = self._get_stdin_reader()

    def _get_stdin_reader(self):
        if sys.platform == 'win32':
            return WindowsStdinReader()
        return UnixStdinReader()

    def start(self):
        """Start reading input in a background thread."""
        if self.running:
            return
        self.running = True
        self.stdin_reader.set_raw_mode()
        self.raw_mode_active = True
        self.thread = threading.Thread(target=self._input_loop, daemon=True)
        self.thread.start()
        logging.debug('InputHandler started (key-event mode)')

    def stop(self):
        """Stop reading input and restore terminal."""
        self.running = False
        if self.raw_mode_active:
            self.stdin_reader.restore()
            self.raw_mode_active = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logging.debug('InputHandler stopped')

    def _input_loop(self):
        while self.running:
            try:
                ch = self.stdin_reader.read_char()
                if ch:
                    self._process_input(ch)
            except Exception as exc:
                logging.error(f'Error in input loop: {exc}')
                break

    # Input processing

    def _process_input(self, ch: str):
        """
        Process a single character (or the first character of a buffered
        sequence) from stdin and emit the appropriate key event(s).
        """
        if not ch:
            return

        code = ord(ch) if len(ch) == 1 else -1

        # ESC / ANSI escape sequences
        if ch == '\x1b':
            seq = self._read_escape_sequence()
            if seq:
                # Shift+Insert → ESC[2~ on Unix (Windows uses _CHORD_SHIFT_INSERT).
                if seq == '[2~':
                    if self.disable_paste:
                        self._send_shift_insert_chord()
                        return
                    if self.paste_orchestrator:
                        self.paste_orchestrator.paste()
                        return
                keysym = self._escape_to_keysym(seq)
                if keysym:
                    self._send_key(keysym)
            else:
                self._send_key(X11Keysym.ESCAPE)
            return

        # Ctrl+C double-tap
        if code == 0x03 and self.ctrl_c_coordinator:
            self.ctrl_c_coordinator.handle()
            return

        # Paste chords: local clipboard stream vs key events (disablePaste)
        if ch in (
            _PASTE_BYTE,
            _CHORD_CTRL_SHIFT_V,
            _CHORD_SHIFT_INSERT,
            _CHORD_CTRL_INSERT,
        ):
            if self.disable_paste:
                if ch == _PASTE_BYTE:
                    self._send_ctrl_v_chord()
                elif ch == _CHORD_CTRL_SHIFT_V:
                    self._send_ctrl_shift_v_chord()
                elif ch == _CHORD_SHIFT_INSERT:
                    self._send_shift_insert_chord()
                else:
                    self._send_ctrl_insert_chord()
                return
            if self.paste_orchestrator:
                self.paste_orchestrator.paste()
                return

        # Other control characters
        if 0 < code < 32:
            keysym = self._control_char_to_keysym(ch)
            if keysym:
                self._send_key(keysym)
            return

        # DEL
        if code == 127:
            self._send_key(X11Keysym.BACKSPACE)
            return

        # Printable / Unicode
        if code > 0:
            self._send_key(X11Keysym.keysym_from_unicode_codepoint(code))

    def _read_escape_sequence(self) -> Optional[str]:
        """Read an ANSI escape sequence from stdin after the leading ESC."""
        seq = ''
        for _ in range(8):
            ch = self.stdin_reader.read_char(timeout=0.05)
            if not ch:
                break
            seq += ch
            if ch.isalpha() or ch == '~':
                break
        return seq if seq else None

    def _escape_to_keysym(self, seq: str) -> Optional[int]:
        """Map an ANSI escape sequence (without leading ESC) to an X11 keysym."""
        mappings = {
            '[A':   X11Keysym.UP,
            '[B':   X11Keysym.DOWN,
            '[C':   X11Keysym.RIGHT,
            '[D':   X11Keysym.LEFT,
            '[H':   X11Keysym.HOME,
            '[F':   X11Keysym.END,
            '[1~':  X11Keysym.HOME,
            '[2~':  X11Keysym.INSERT,
            '[3~':  X11Keysym.DELETE,
            '[4~':  X11Keysym.END,
            '[5~':  X11Keysym.PAGE_UP,
            '[6~':  X11Keysym.PAGE_DOWN,
            'OP':   X11Keysym.F1,
            'OQ':   X11Keysym.F2,
            'OR':   X11Keysym.F3,
            'OS':   X11Keysym.F4,
            '[15~': X11Keysym.F5,
            '[17~': X11Keysym.F6,
            '[18~': X11Keysym.F7,
            '[19~': X11Keysym.F8,
            '[20~': X11Keysym.F9,
            '[21~': X11Keysym.F10,
            '[23~': X11Keysym.F11,
            '[24~': X11Keysym.F12,
        }
        # Strip modifier suffix (e.g. [1;5A → [A)
        if seq.startswith('[1;') and len(seq) >= 4:
            final = seq[-1]
            base = {'A': '[A', 'B': '[B', 'C': '[C', 'D': '[D'}.get(final)
            if base:
                return mappings.get(base)
        return mappings.get(seq)

    def _control_char_to_keysym(self, ch: str) -> Optional[int]:
        """Map a control character (code < 32) to an X11 keysym."""
        code = ord(ch)
        if code == 8:    return X11Keysym.BACKSPACE
        if code == 9:    return X11Keysym.TAB
        if code == 10:   return X11Keysym.RETURN
        if code == 13:   return X11Keysym.RETURN
        if code == 27:   return X11Keysym.ESCAPE
        # Ctrl+A … Ctrl+Z and other control codes: send as the raw code value.
        # guacd maps ETX (3), EOT (4), etc. correctly for SSH/terminal use.
        return code

    def _send_key(self, keysym: int):
        """Emit a key press followed by a key release."""
        self.key_callback(keysym, True)
        self.key_callback(keysym, False)

    def _send_modifier_chord(self, modifiers: list[int], main_keysym: int) -> None:
        """Press modifiers, press+release main key, release modifiers (remote TTY paste)."""
        for m in modifiers:
            self.key_callback(m, True)
        self.key_callback(main_keysym, True)
        self.key_callback(main_keysym, False)
        for m in reversed(modifiers):
            self.key_callback(m, False)

    def _send_ctrl_v_chord(self) -> None:
        self._send_modifier_chord([X11Keysym.CONTROL_L], ord('v'))

    def _send_ctrl_shift_v_chord(self) -> None:
        self._send_modifier_chord([X11Keysym.CONTROL_L, X11Keysym.SHIFT_L], ord('v'))

    def _send_shift_insert_chord(self) -> None:
        self._send_modifier_chord([X11Keysym.SHIFT_L], X11Keysym.INSERT)

    def _send_ctrl_insert_chord(self) -> None:
        self._send_modifier_chord([X11Keysym.CONTROL_L], X11Keysym.INSERT)


# Unix/macOS stdin reader

class UnixStdinReader:
    """Unix/macOS stdin reader with raw mode via termios."""

    def __init__(self):
        self.old_settings = None

    def set_raw_mode(self):
        try:
            import termios, tty, time
            sys.stdout.flush()
            sys.stderr.flush()
            self.old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
            time.sleep(0.01)
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception as exc:
            logging.warning(f'Failed to set raw mode: {exc}')

    def restore(self):
        if self.old_settings:
            try:
                import termios
                termios.tcsetattr(
                    sys.stdin.fileno(), termios.TCSADRAIN, self.old_settings
                )
            except Exception as exc:
                logging.warning(f'Failed to restore terminal: {exc}')
            self.old_settings = None

    def read_char(self, timeout: Optional[float] = None) -> Optional[str]:
        if timeout is not None:
            import select
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None
        try:
            return sys.stdin.read(1)
        except Exception:
            return None


# Windows stdin reader (ReadConsoleInput-based)

# VT100 / xterm escape sequences for Windows VK codes.
# These are queued as individual chars so the existing _escape_to_keysym
# mapping in InputHandler works unchanged.
_VK_TO_ESC_SEQ: dict = {
    0x26: '\x1b[A',    # VK_UP
    0x28: '\x1b[B',    # VK_DOWN
    0x27: '\x1b[C',    # VK_RIGHT
    0x25: '\x1b[D',    # VK_LEFT
    0x24: '\x1b[H',    # VK_HOME
    0x23: '\x1b[F',    # VK_END
    0x2D: '\x1b[2~',   # VK_INSERT
    0x2E: '\x1b[3~',   # VK_DELETE
    0x21: '\x1b[5~',   # VK_PRIOR  (Page Up)
    0x22: '\x1b[6~',   # VK_NEXT   (Page Down)
    0x70: '\x1bOP',    # VK_F1
    0x71: '\x1bOQ',    # VK_F2
    0x72: '\x1bOR',    # VK_F3
    0x73: '\x1bOS',    # VK_F4
    0x74: '\x1b[15~',  # VK_F5
    0x75: '\x1b[17~',  # VK_F6
    0x76: '\x1b[18~',  # VK_F7
    0x77: '\x1b[19~',  # VK_F8
    0x78: '\x1b[20~',  # VK_F9
    0x79: '\x1b[21~',  # VK_F10
    0x7A: '\x1b[23~',  # VK_F11
    0x7B: '\x1b[24~',  # VK_F12
}

_VK_INSERT       = 0x2D
_VK_V            = 0x56
_SHIFT_PRESSED   = 0x0010
_LEFT_CTRL       = 0x0008
_RIGHT_CTRL      = 0x0004
_CTRL_PRESSED    = _LEFT_CTRL | _RIGHT_CTRL
_KEY_EVENT       = 0x0001
_STD_INPUT_HANDLE = -10


class WindowsStdinReader:
    """
    Windows console reader using ReadConsoleInputW for full modifier awareness.

    Paste chords are translated to sentinels so _process_input can route to
    PasteOrchestrator or, when PAM disablePaste, to key chords (Ctrl+V, etc.).

    Navigation / function keys are translated to VT100 escape sequences and
    queued one character at a time; InputHandler._read_escape_sequence drains
    the queue transparently.
    """

    def __init__(self):
        self._queue: collections.deque = collections.deque()
        self._hstdin = None
        self._input_record_type = None
        self._ready = False
        self._init_win32()

    def _init_win32(self):
        """Set up ctypes structures for ReadConsoleInputW."""
        try:
            import ctypes
            from ctypes import wintypes

            class _KeyEventRecord(ctypes.Structure):
                _fields_ = [
                    ('bKeyDown',          wintypes.BOOL),
                    ('wRepeatCount',      wintypes.WORD),
                    ('wVirtualKeyCode',   wintypes.WORD),
                    ('wVirtualScanCode',  wintypes.WORD),
                    ('uChar',             wintypes.WCHAR),
                    ('dwControlKeyState', wintypes.DWORD),
                ]

            class _EventUnion(ctypes.Union):
                _fields_ = [
                    ('KeyEvent', _KeyEventRecord),
                    ('_pad',     ctypes.c_byte * 20),
                ]

            class _InputRecord(ctypes.Structure):
                _fields_ = [
                    ('EventType', wintypes.WORD),
                    ('Event',     _EventUnion),
                ]

            self._InputRecord = _InputRecord
            self._wintypes = wintypes
            self._ctypes = ctypes
            kernel32 = ctypes.windll.kernel32
            self._hstdin = kernel32.GetStdHandle(_STD_INPUT_HANDLE)
            self._ReadConsoleInputW = kernel32.ReadConsoleInputW
            self._WaitForSingleObject = kernel32.WaitForSingleObject
            self._ready = True
        except Exception as exc:
            logging.warning(f'WindowsStdinReader: Win32 init failed, falling back to msvcrt: {exc}')
            self._ready = False

    def set_raw_mode(self):
        import time
        sys.stdout.flush()
        sys.stderr.flush()
        time.sleep(0.01)
        sys.stdout.flush()
        sys.stderr.flush()
        # Ctrl+C as input (not SIGINT) so CtrlCCoordinator can handle double-tap.
        self._win_saved_console_mode = win_stdin_disable_ctrl_c_process_input()

    def restore(self):
        win_stdin_restore_console_mode(self._win_saved_console_mode)
        self._win_saved_console_mode = None

    def read_char(self, timeout: Optional[float] = None) -> Optional[str]:
        # Drain queued chars first (from previously decoded escape sequences).
        if self._queue:
            return self._queue.popleft()

        if self._ready:
            return self._read_via_console_input(timeout)
        return self._read_via_msvcrt(timeout)

    def _read_via_console_input(self, timeout: Optional[float]) -> Optional[str]:
        """Read one logical key event, emitting VT100 sequences for nav keys."""
        ctypes = self._ctypes
        wintypes = self._wintypes

        while True:
            if timeout is not None:
                wait_ms = int(timeout * 1000)
                result = self._WaitForSingleObject(self._hstdin, wait_ms)
                if result != 0:       # WAIT_OBJECT_0 = 0
                    return None

            record = self._InputRecord()
            n_read = wintypes.DWORD(0)
            ok = self._ReadConsoleInputW(
                self._hstdin,
                ctypes.byref(record),
                1,
                ctypes.byref(n_read),
            )
            if not ok or n_read.value == 0:
                return None

            if record.EventType != _KEY_EVENT:
                continue

            key = record.Event.KeyEvent
            if not key.bKeyDown:
                continue       # ignore key-up events

            vk    = key.wVirtualKeyCode
            ctrl  = key.dwControlKeyState & _CTRL_PRESSED
            shift = key.dwControlKeyState & _SHIFT_PRESSED

            # Ctrl+Shift+V
            if vk == _VK_V and ctrl and shift:
                return _CHORD_CTRL_SHIFT_V

            # Ctrl+V (plain) — some consoles omit uChar; match before uChar path
            if vk == _VK_V and ctrl and not shift:
                return _PASTE_BYTE

            # Shift+Insert
            if vk == _VK_INSERT and shift and not ctrl:
                return _CHORD_SHIFT_INSERT

            # Ctrl+Insert (some terminals)
            if vk == _VK_INSERT and ctrl and not shift:
                return _CHORD_CTRL_INSERT

            # Navigation / function keys → VT100 ESC sequence (queued)
            if vk in _VK_TO_ESC_SEQ:
                seq = _VK_TO_ESC_SEQ[vk]
                for c in seq[1:]:
                    self._queue.append(c)
                return seq[0]   # '\x1b' — rest drained by _read_escape_sequence

            # Regular character from uChar (includes Ctrl+letter control codes)
            ch = key.uChar
            if ch and ord(ch) > 0:
                return ch

            # Modifier-only or unhandled VK — loop for next event

    def _read_via_msvcrt(self, timeout: Optional[float]) -> Optional[str]:
        """Fallback when ReadConsoleInput init failed."""
        try:
            import msvcrt, time
            start = time.time()
            while True:
                if timeout is not None and (time.time() - start) >= timeout:
                    return None
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    # Extended key prefix — read second byte immediately
                    if ch in (b'\xe0', b'\x00'):
                        scan = msvcrt.getch()
                        seq = self._win_scan_to_esc(scan[0] if scan else 0)
                        if seq:
                            for c in seq[1:]:
                                self._queue.append(c)
                            return seq[0]
                        return None
                    return ch.decode('utf-8', errors='replace')
                time.sleep(0.01)
        except Exception as exc:
            logging.error(f'msvcrt read error: {exc}')
            return None

    @staticmethod
    def _win_scan_to_esc(scan: int) -> Optional[str]:
        """Map a Windows extended-key scan code to a VT100 escape sequence."""
        table = {
            0x48: '\x1b[A',    # Up
            0x50: '\x1b[B',    # Down
            0x4D: '\x1b[C',    # Right
            0x4B: '\x1b[D',    # Left
            0x47: '\x1b[H',    # Home
            0x4F: '\x1b[F',    # End
            0x52: '\x1b[2~',   # Insert
            0x53: '\x1b[3~',   # Delete
            0x49: '\x1b[5~',   # Page Up
            0x51: '\x1b[6~',   # Page Down
            0x3B: '\x1bOP',    # F1
            0x3C: '\x1bOQ',    # F2
            0x3D: '\x1bOR',    # F3
            0x3E: '\x1bOS',    # F4
            0x3F: '\x1b[15~',  # F5
            0x40: '\x1b[17~',  # F6
            0x41: '\x1b[18~',  # F7
            0x42: '\x1b[19~',  # F8
            0x43: '\x1b[20~',  # F9
            0x44: '\x1b[21~',  # F10
            0x85: '\x1b[23~',  # F11
            0x86: '\x1b[24~',  # F12
        }
        return table.get(scan)
