#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Terminal size helpers for PAM Launch.

Provides get_terminal_size_pixels() which returns terminal dimensions in pixels
and DPI for use in Guacamole 'size' instructions.

Also defines the screen-size constants and _build_screen_info() fallback that
were previously in terminal_connection.py; terminal_connection.py imports them
from here to avoid a circular dependency (terminal_connection imports
get_terminal_size_pixels; terminal_size needs _build_screen_info as fallback).
"""

from __future__ import annotations

import logging
import shutil
import struct
import sys
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Constants (previously defined in terminal_connection.py)
# ---------------------------------------------------------------------------

# Default terminal metrics used to translate local console dimensions into the
# pixel-based values that Guacamole expects.
DEFAULT_TERMINAL_COLUMNS = 80
DEFAULT_TERMINAL_ROWS = 24
DEFAULT_CELL_WIDTH_PX = 10
DEFAULT_CELL_HEIGHT_PX = 19
DEFAULT_SCREEN_DPI = 96


# ---------------------------------------------------------------------------
# Fallback helper (previously defined in terminal_connection.py)
# ---------------------------------------------------------------------------

def _build_screen_info(columns: int, rows: int) -> Dict[str, int]:
    """Convert character columns/rows into pixel measurements for the Gateway."""
    col_value = columns if isinstance(columns, int) and columns > 0 else DEFAULT_TERMINAL_COLUMNS
    row_value = rows if isinstance(rows, int) and rows > 0 else DEFAULT_TERMINAL_ROWS
    return {
        "columns": col_value,
        "rows": row_value,
        "pixel_width": col_value * DEFAULT_CELL_WIDTH_PX,
        "pixel_height": row_value * DEFAULT_CELL_HEIGHT_PX,
        "dpi": DEFAULT_SCREEN_DPI,
    }


# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

# DPI is cached for the lifetime of the process. Display DPI rarely changes
# during a session - it would only change if the user moves the console window
# to a different-DPI monitor, which is not worth the overhead of re-querying
# on every resize event.
_dpi: Optional[int] = None

# TIOCGWINSZ pixel support: None = untested, True = returns non-zero pixels,
# False = permanently disabled (returned all-zero pixel fields). When False,
# _get_pixels_unix() returns (0, 0) immediately without retrying the ioctl.
_tiocgwinsz_works: Optional[bool] = None

# Interactive TTY flag, cached after first call.
_is_tty: Optional[bool] = None


# ---------------------------------------------------------------------------
# TTY detection
# ---------------------------------------------------------------------------

def is_interactive_tty() -> bool:
    """Return True if both stdin and stdout are connected to a real TTY.

    Cached after the first call. When running in a non-interactive environment
    (piped I/O, CI, scripted launch) resize polling should be skipped entirely
    to avoid spurious or meaningless size-change events.
    """
    global _is_tty
    if _is_tty is None:
        try:
            _is_tty = sys.stdin.isatty() and sys.stdout.isatty()
        except Exception:
            _is_tty = False
    return _is_tty


# ---------------------------------------------------------------------------
# Platform DPI helpers
# ---------------------------------------------------------------------------

def _get_dpi_windows() -> int:
    """Return display DPI on Windows via ctypes, cached for the session.

    Tries GetDpiForSystem (shcore.dll, Windows 8.1+) first, then falls back
    to GetDeviceCaps(LOGPIXELSX). Returns DEFAULT_SCREEN_DPI (96) on failure.
    """
    global _dpi
    if _dpi is not None:
        return _dpi
    try:
        import ctypes
        # GetDpiForSystem - available on Windows 8.1+ via shcore.dll
        try:
            dpi = ctypes.windll.shcore.GetDpiForSystem()
            if dpi and dpi > 0:
                _dpi = int(dpi)
                return _dpi
        except Exception:
            pass
        # Fallback: GDI GetDeviceCaps(LOGPIXELSX)
        LOGPIXELSX = 88
        hdc = ctypes.windll.user32.GetDC(0)
        if hdc:
            try:
                dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, LOGPIXELSX)
                if dpi and dpi > 0:
                    _dpi = int(dpi)
                    return _dpi
            finally:
                ctypes.windll.user32.ReleaseDC(0, hdc)
    except Exception as e:
        logging.debug(f"Could not query Windows DPI: {e}")
    _dpi = DEFAULT_SCREEN_DPI
    return _dpi


def _get_dpi_unix() -> int:
    """Return display DPI on Unix/macOS, cached for the session.

    There is no portable, connection-independent way to query DPI from a
    terminal process on Unix without a display-server connection. Standard
    Guacamole sessions use 96 DPI as the baseline, so we return that.
    """
    global _dpi
    if _dpi is None:
        _dpi = DEFAULT_SCREEN_DPI
    return _dpi


# ---------------------------------------------------------------------------
# Platform pixel-dimension helpers
# ---------------------------------------------------------------------------

def _get_pixels_windows(columns: int, rows: int):
    """Return (pixel_width, pixel_height) on Windows via GetCurrentConsoleFontEx.

    Retrieves the console font glyph size in pixels (dwFontSize.X / .Y) and
    multiplies by columns/rows to get the total terminal window pixel size.
    Returns (0, 0) on any failure so the caller can fall back gracefully.
    """
    try:
        import ctypes
        import ctypes.wintypes

        STD_OUTPUT_HANDLE = -11
        handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        if not handle or handle == ctypes.wintypes.HANDLE(-1).value:
            return 0, 0

        class COORD(ctypes.Structure):
            _fields_ = [('X', ctypes.c_short), ('Y', ctypes.c_short)]

        class CONSOLE_FONT_INFOEX(ctypes.Structure):
            _fields_ = [
                ('cbSize', ctypes.c_ulong),
                ('nFont', ctypes.c_ulong),
                ('dwFontSize', COORD),
                ('FontFamily', ctypes.c_uint),
                ('FontWeight', ctypes.c_uint),
                ('FaceName', ctypes.c_wchar * 32),
            ]

        font_info = CONSOLE_FONT_INFOEX()
        font_info.cbSize = ctypes.sizeof(CONSOLE_FONT_INFOEX)

        if ctypes.windll.kernel32.GetCurrentConsoleFontEx(handle, False, ctypes.byref(font_info)):
            fw = font_info.dwFontSize.X
            fh = font_info.dwFontSize.Y
            if fw > 0 and fh > 0:
                return columns * fw, rows * fh

        return 0, 0
    except Exception as e:
        logging.debug(f"GetCurrentConsoleFontEx failed: {e}")
        return 0, 0


def _get_pixels_unix(columns: int, rows: int):
    """Return (pixel_width, pixel_height) on Unix/macOS via TIOCGWINSZ.

    The kernel struct winsize includes ws_xpixel and ws_ypixel holding the
    total terminal pixel dimensions. If those fields are zero on the first
    attempt, the failure is cached permanently (_tiocgwinsz_works = False)
    and subsequent calls return (0, 0) without retrying the ioctl.
    """
    global _tiocgwinsz_works
    if _tiocgwinsz_works is False:
        return 0, 0
    try:
        import fcntl
        import termios

        buf = struct.pack('HHHH', 0, 0, 0, 0)
        result = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, buf)
        # struct winsize layout: ws_row, ws_col, ws_xpixel, ws_ypixel
        _ws_row, _ws_col, ws_xpixel, ws_ypixel = struct.unpack('HHHH', result)
        if ws_xpixel > 0 and ws_ypixel > 0:
            _tiocgwinsz_works = True
            return ws_xpixel, ws_ypixel
        # Pixel fields are zero - terminal emulator does not populate them.
        _tiocgwinsz_works = False
        return 0, 0
    except Exception as e:
        logging.debug(f"TIOCGWINSZ failed: {e}")
        _tiocgwinsz_works = False
        return 0, 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_terminal_size_pixels(
    columns: Optional[int] = None,
    rows: Optional[int] = None,
) -> Dict[str, int]:
    """Return terminal size in pixels and DPI for a Guacamole 'size' instruction.

    Always re-queries the terminal size internally via shutil.get_terminal_size
    for maximum accuracy. The optional *columns* and *rows* arguments serve as
    a fallback used only when the internal query fails.

    Platform behaviour
    ------------------
    Windows
        Uses GetCurrentConsoleFontEx to obtain the console font glyph size in
        pixels, then multiplies columns × rows for exact pixel dimensions.
        DPI is obtained via GetDpiForSystem (or GetDeviceCaps as fallback).
        Both are cached for the session.

    Unix / macOS
        Tries TIOCGWINSZ ws_xpixel / ws_ypixel for pixel dimensions. If those
        fields are zero (common - many terminal emulators do not fill them in),
        the failure is cached permanently and the cell-size fallback is used on
        every subsequent call without retrying the ioctl.

    Fallback
        When platform-specific pixel APIs return (0, 0), falls back to
        _build_screen_info(columns, rows) which uses DEFAULT_CELL_WIDTH_PX /
        DEFAULT_CELL_HEIGHT_PX to estimate pixel dimensions from char cells.

    Returns
    -------
    dict with keys: columns, rows, pixel_width, pixel_height, dpi
    (same structure as _build_screen_info - drop-in compatible)
    """
    # Resolve caller-supplied hints as fallback values
    fallback_cols = columns if (isinstance(columns, int) and columns > 0) else DEFAULT_TERMINAL_COLUMNS
    fallback_rows = rows if (isinstance(rows, int) and rows > 0) else DEFAULT_TERMINAL_ROWS

    # Always re-query for maximum accuracy; use hints only if query fails
    try:
        ts = shutil.get_terminal_size(fallback=(fallback_cols, fallback_rows))
        actual_cols = ts.columns
        actual_rows = ts.lines
    except Exception:
        actual_cols = fallback_cols
        actual_rows = fallback_rows

    # Platform-specific pixel dimensions
    if sys.platform == 'win32':
        pixel_w, pixel_h = _get_pixels_windows(actual_cols, actual_rows)
        dpi = _get_dpi_windows()
    else:
        pixel_w, pixel_h = _get_pixels_unix(actual_cols, actual_rows)
        dpi = _get_dpi_unix()

    # Fallback: platform API returned (0, 0) - use fixed cell-size estimate
    if pixel_w <= 0 or pixel_h <= 0:
        return _build_screen_info(actual_cols, actual_rows)

    return {
        "columns": actual_cols,
        "rows": actual_rows,
        "pixel_width": pixel_w,
        "pixel_height": pixel_h,
        "dpi": dpi,
    }
