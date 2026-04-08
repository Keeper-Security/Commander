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

DPI for text terminals
----------------------
For plaintext SSH/Telnet sessions, OS display DPI is **irrelevant** to the
remote terminal geometry.  guacd uses handshake DPI only for Cairo font
rasterisation (glyph pixel size); runtime ``size`` instructions carry only
width and height — no DPI.  The remote PTY rows/cols are derived purely from
pixel dimensions divided by the font cell size (which is set once at session
start from handshake DPI + ``font-size``).

The ``dpi`` key in screen-info dicts follows the active **pixel mode**
(:data:`DEFAULT_PIXEL_MODE` and ``KEEPER_GUAC_PIXEL_MODE``): ``_KCM_DPI`` (192)
for ``kcm`` or ``_GUACD_DPI`` (96) for ``guacd``, matching the cell-size
formula used for ``pixel_width`` / ``pixel_height``. The platform DPI helpers
(_get_dpi_windows, etc.) are retained for possible future use but are **not
called** on the primary text-terminal code path.

Also defines the screen-size constants and _build_screen_info() fallback that
were previously in terminal_connection.py; terminal_connection.py imports them
from here to avoid a circular dependency (terminal_connection imports
get_terminal_size_pixels; terminal_size needs _build_screen_info as fallback).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import ctypes.util
import logging
import os
import shutil
import struct
import subprocess
import sys
import time
from typing import Dict, Optional, Tuple

if sys.platform != 'win32':
    import fcntl
    import termios
else:
    fcntl = None  # type: ignore[assignment]
    termios = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants (previously defined in terminal_connection.py)
# ---------------------------------------------------------------------------

# Default terminal metrics used to translate local console dimensions into the
# pixel-based values that Guacamole expects.
DEFAULT_TERMINAL_COLUMNS = 80
DEFAULT_TERMINAL_ROWS = 24
DEFAULT_SCREEN_DPI = 192

# ---------------------------------------------------------------------------
# Pixel-mode selection
# ---------------------------------------------------------------------------

# Two pixel modes are supported, selectable via KEEPER_GUAC_PIXEL_MODE env var
# or the pixel_mode parameter on get_terminal_size_pixels / _build_screen_info:
#
#   'kcm'   — matches kcm-cli/src/tty.js (default).
#             DPI 192, char 19×38 px, plus canvas margins and scrollbar.
#             Requires guacd to receive DPI=192 in the handshake 'size'
#             instruction so its Pango font metrics yield char_width=19.
#
#   'guacd' — matches guacd's own defaults (terminal.h / display.c).
#             DPI 96, char 10×20 px, scrollbar only (no canvas margin).
#             Formula: cols = (width - SCROLLBAR_WIDTH) / char_width
#                      rows = height / char_height
#             Guacd uses this when no DPI is supplied or DPI=96 is sent.
#
PIXEL_MODE_KCM = 'kcm'
PIXEL_MODE_GUACD = 'guacd'
DEFAULT_PIXEL_MODE = PIXEL_MODE_GUACD
# TODO: Switch to KCM mode once the fix is included in gateway builds.

# ---------------------------------------------------------------------------
# kcm-cli pixel constants
# Source: kcm-cli/src/tty.js — calibrated for KCM's canvas renderer at DPI 192.
#   columnsToPixels(c) = c * CHAR_WIDTH + TERM_MARGIN * 2 + SCROLLBAR_WIDTH
#   rowsToPixels(r)    = r * CHAR_HEIGHT + TERM_MARGIN * 2
# Sanity check 80×24: width = 80*19 + 30 + 16 = 1566, height = 24*38 + 30 = 942.
# ---------------------------------------------------------------------------
_KCM_DPI = 192          # tty.js: export const DPI = 192
_KCM_CHAR_WIDTH = 19    # tty.js: const CHAR_WIDTH = 19
_KCM_CHAR_HEIGHT = 38   # tty.js: const CHAR_HEIGHT = 38
# tty.js: const TERM_MARGIN = Math.floor(2 * DPI / 25.4)
# = 2 mm × DPI px/inch ÷ 25.4 mm/inch  →  15 px at DPI 192
_KCM_TERM_MARGIN = int(2 * _KCM_DPI / 25.4)
_KCM_SCROLLBAR_WIDTH = 16  # tty.js: const SCROLLBAR_WIDTH = 16

# ---------------------------------------------------------------------------
# guacd default pixel constants
# Source: guacamole-server terminal.h (GUAC_TERMINAL_DEFAULT_FONT_SIZE=12,
#         GUAC_TERMINAL_SCROLLBAR_WIDTH=16) and display.c (Pango metrics).
# At DPI=96 with monospace 12pt, Pango yields char_width≈10, char_height≈20.
# guacd has NO canvas margin — the PTY formula is simply:
#   cols = (width - SCROLLBAR_WIDTH) / char_width
#   rows = height / char_height
# Sanity check 80×24: width = 80*10 + 16 = 816, height = 24*20 = 480.
# ---------------------------------------------------------------------------
_GUACD_DPI = 96
_GUACD_CHAR_WIDTH = 10   # Pango approximate digit width, monospace 12pt @ 96 dpi
_GUACD_CHAR_HEIGHT = 20  # Pango ascent + descent,       monospace 12pt @ 96 dpi
# Same formula: 2 mm × DPI px/inch ÷ 25.4 mm/inch  →  7 px at DPI 96
_GUACD_TERM_MARGIN = int(2 * _GUACD_DPI / 25.4)
_GUACD_SCROLLBAR_WIDTH = 16  # GUAC_TERMINAL_SCROLLBAR_WIDTH (scrollbar.h)

# Re-query DPI after this interval so scaling / display changes can be picked up
# without re-running Commander. Individual API calls are cheap; this bounds work.
DPI_CACHE_TTL_SEC = 1.0


# ---------------------------------------------------------------------------
# kcm-cli pixel approximation (primary path — strict KCM parity)
# ---------------------------------------------------------------------------

def kcm_cli_approximate_pixels(columns: int, rows: int):
    """Return (pixel_width, pixel_height) using kcm-cli tty.js formulas.

    Mirrors ``columnsToPixels`` / ``rowsToPixels`` from kcm-cli/src/tty.js so
    Commander sends identical Guacamole ``size`` values for the same grid.
    All arithmetic is integer (matches JS ``Math.floor`` semantics for the
    TERM_MARGIN constant; the multiplications produce exact integers).
    """
    pixel_width = columns * _KCM_CHAR_WIDTH + _KCM_TERM_MARGIN * 2 + _KCM_SCROLLBAR_WIDTH
    pixel_height = rows * _KCM_CHAR_HEIGHT + _KCM_TERM_MARGIN * 2
    return pixel_width, pixel_height


def guacd_default_approximate_pixels(columns: int, rows: int):
    """Return (pixel_width, pixel_height) using guacd's own default metrics.

    Mirrors guacd's PTY calculation (terminal.c):
        cols = (width - GUAC_TERMINAL_SCROLLBAR_WIDTH) / char_width
        rows = height / char_height
    where char_width/char_height come from Pango metrics for monospace 12pt at
    DPI 96 (≈10 × 20 px).  There is no canvas margin — guacd subtracts only
    the scrollbar from the total pixel width before dividing.
    """
    pixel_width = columns * _GUACD_CHAR_WIDTH + _GUACD_TERM_MARGIN * 2 + _GUACD_SCROLLBAR_WIDTH
    pixel_height = rows * _GUACD_CHAR_HEIGHT + _GUACD_TERM_MARGIN * 2
    return pixel_width, pixel_height


def scale_screen_info(columns: int, rows: int, scale_pct: int) -> Dict[str, int]:
    """Return screen_info using guacd-96 base metrics scaled by *scale_pct* percent.

    Uses :func:`guacd_default_approximate_pixels` (DPI 96, 10×20 px chars) as
    the base, then multiplies pixel_width and pixel_height by ``scale_pct / 100``.
    Canonical ``pam launch --scale`` path: local console columns/rows with
    ``dpi`` 96 aligned to guacd's default PTY pixel model.

    Example: scale_pct=80  → multiply base pixels by 0.80 (shrink)
             scale_pct=120 → multiply base pixels by 1.20 (enlarge)
    """
    base_w, base_h = guacd_default_approximate_pixels(columns, rows)
    factor = scale_pct / 100.0
    return {
        "columns": columns,
        "rows": rows,
        "pixel_width": max(1, int(base_w * factor)),
        "pixel_height": max(1, int(base_h * factor)),
        "dpi": _GUACD_DPI,
    }


def _coerce_pixel_mode(mode_value: str) -> str:
    """Normalize *mode_value* to ``kcm`` or ``guacd``; unknown/empty → :data:`DEFAULT_PIXEL_MODE`."""
    m = (mode_value or "").strip().lower()
    if not m:
        m = DEFAULT_PIXEL_MODE.strip().lower()
    if m in (PIXEL_MODE_KCM, PIXEL_MODE_GUACD):
        return m
    return DEFAULT_PIXEL_MODE.strip().lower()


def approximate_pixels(columns: int, rows: int, pixel_mode: str = DEFAULT_PIXEL_MODE):
    """Return (pixel_width, pixel_height) for the given pixel mode.

    Parameters
    ----------
    pixel_mode:
        ``'kcm'``   — kcm-cli/tty.js formula (DPI 192, char 19×38, with margin).
        ``'guacd'`` — guacd defaults (DPI 96, char 10×20, scrollbar only).
        Other values are treated as :data:`DEFAULT_PIXEL_MODE` (see :func:`_coerce_pixel_mode`).
    """
    mode = _coerce_pixel_mode(pixel_mode)
    if mode == PIXEL_MODE_GUACD:
        return guacd_default_approximate_pixels(columns, rows)
    return kcm_cli_approximate_pixels(columns, rows)


# ---------------------------------------------------------------------------
# Fallback helper (previously defined in terminal_connection.py)
# ---------------------------------------------------------------------------

def _dpi_for_cell_fallback() -> int:
    """DPI to embed when pixel dimensions come from cell estimates (same as Guacamole resize)."""
    if sys.platform == 'win32':
        return _get_dpi_windows()
    if sys.platform == 'darwin':
        return _get_dpi_macos()
    return DEFAULT_SCREEN_DPI

def _resolve_pixel_mode(pixel_mode: Optional[str] = None) -> str:
    """Return the effective pixel mode, consulting env when *pixel_mode* is None.

    Unknown strings (including env typos) become :data:`DEFAULT_PIXEL_MODE`.
    """
    if pixel_mode is not None:
        return _coerce_pixel_mode(pixel_mode)
    raw = os.environ.get("KEEPER_GUAC_PIXEL_MODE", DEFAULT_PIXEL_MODE)
    return _coerce_pixel_mode(raw)


def _dpi_for_mode(pixel_mode: str) -> int:
    """Return Guacamole handshake DPI for *pixel_mode*.

    Must stay aligned with :func:`approximate_pixels` cell metrics:

    - ``guacd`` → :data:`_GUACD_DPI` (96)
    - ``kcm`` → :data:`_KCM_DPI` (192)
    - Any other value → DPI for :data:`DEFAULT_PIXEL_MODE` (via :func:`_coerce_pixel_mode`).
    """
    mode = _coerce_pixel_mode(pixel_mode)
    if mode == PIXEL_MODE_GUACD:
        return _GUACD_DPI
    return _KCM_DPI


def default_handshake_dpi() -> int:
    """DPI for Guacamole text-terminal handshake (matches ``screen_info['dpi']`` when mode is unset).

    Resolved from ``KEEPER_GUAC_PIXEL_MODE`` and :data:`DEFAULT_PIXEL_MODE` via
    :func:`_dpi_for_mode`: **192** for ``kcm``, **96** for ``guacd``.
    """
    return _dpi_for_mode(_resolve_pixel_mode(None))


# Default for imports and ``settings.get('dpi', …)`` fallbacks; set at import time.
GUACAMOLE_HANDSHAKE_DPI = default_handshake_dpi()


def _build_screen_info(columns: int, rows: int, pixel_mode: Optional[str] = None) -> Dict[str, int]:
    """Convert character columns/rows into pixel measurements for the Gateway.

    Uses the pixel mode to select the DPI and pixel formula:
    - ``'kcm'``   — DPI 192, kcm-cli tty.js formula.
    - ``'guacd'`` — DPI 96, guacd-native formula (no canvas margin).

    The active mode is resolved from the *pixel_mode* argument first, then the
    ``KEEPER_GUAC_PIXEL_MODE`` environment variable, then :data:`DEFAULT_PIXEL_MODE`.
    """
    mode = _resolve_pixel_mode(pixel_mode)
    col_value = columns if isinstance(columns, int) and columns > 0 else DEFAULT_TERMINAL_COLUMNS
    row_value = rows if isinstance(rows, int) and rows > 0 else DEFAULT_TERMINAL_ROWS
    pixel_w, pixel_h = approximate_pixels(col_value, row_value, mode)
    return {
        "columns": col_value,
        "rows": row_value,
        "pixel_width": pixel_w,
        "pixel_height": pixel_h,
        "dpi": _dpi_for_mode(mode),
    }


# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

# DPI cache: refreshed at most once per :data:`DPI_CACHE_TTL_SEC` when
# :func:`get_terminal_size_pixels` / resize runs need a DPI value. Not tied to
# "current window screen" on all platforms yet — see platform DPI helpers.
_dpi: Optional[int] = None
_dpi_cache_mono: Optional[float] = None  # time.monotonic() when *_dpi* was stored

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
    return bool(_is_tty)


# ---------------------------------------------------------------------------
# Platform DPI helpers
# ---------------------------------------------------------------------------

def _invalidate_dpi_cache_if_stale() -> None:
    """Clear module DPI cache when the TTL has expired."""
    global _dpi, _dpi_cache_mono
    if _dpi is None:
        return
    if _dpi_cache_mono is None:
        _dpi = None
        return
    if time.monotonic() - _dpi_cache_mono >= DPI_CACHE_TTL_SEC:
        _dpi = None
        _dpi_cache_mono = None


def _store_dpi(value: int) -> int:
    """Store DPI and refresh cache timestamp."""
    global _dpi, _dpi_cache_mono
    _dpi = int(value)
    _dpi_cache_mono = time.monotonic()
    return _dpi


def _get_dpi_windows() -> int:
    """Return display DPI on Windows via ctypes, cached for the session.

    Tries GetDpiForSystem (shcore.dll, Windows 8.1+) first, then falls back
    to GetDeviceCaps(LOGPIXELSX). Returns :data:`DEFAULT_SCREEN_DPI` on failure.
    """
    _invalidate_dpi_cache_if_stale()
    if _dpi is not None:
        return _dpi
    try:
        # GetDpiForSystem - available on Windows 8.1+ via shcore.dll
        try:
            dpi = ctypes.windll.shcore.GetDpiForSystem()
            if dpi and dpi > 0:
                return _store_dpi(int(dpi))
        except Exception:
            pass
        # Fallback: GDI GetDeviceCaps(LOGPIXELSX)
        LOGPIXELSX = 88
        hdc = ctypes.windll.user32.GetDC(0)
        if hdc:
            try:
                dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, LOGPIXELSX)
                if dpi and dpi > 0:
                    return _store_dpi(int(dpi))
            finally:
                ctypes.windll.user32.ReleaseDC(0, hdc)
    except Exception as e:
        logging.debug(f"Could not query Windows DPI: {e}")
    return _store_dpi(DEFAULT_SCREEN_DPI)


def _get_dpi_macos() -> int:
    """Return approximate main-display DPI on macOS via CoreGraphics.

    Uses ``CGDisplayScreenSize`` (physical size in mm) and ``CGDisplayPixelsWide`` /
    ``CGDisplayPixelsHigh`` to compute horizontal/vertical DPI and averages them.
    This uses ``CGMainDisplayID()`` (system menu-bar display), not the screen that
    holds the terminal window. Falls back to :data:`DEFAULT_SCREEN_DPI` on failure.

    Cached for :data:`DPI_CACHE_TTL_SEC` (then refreshed on next query).
    """
    _invalidate_dpi_cache_if_stale()
    if _dpi is not None:
        return _dpi
    try:
        path = ctypes.util.find_library('CoreGraphics')
        if not path:
            return _store_dpi(DEFAULT_SCREEN_DPI)
        cg = ctypes.CDLL(path)
        CGDirectDisplayID = ctypes.c_uint32

        cg.CGMainDisplayID.restype = CGDirectDisplayID
        cg.CGMainDisplayID.argtypes = []

        class CGSize(ctypes.Structure):
            _fields_ = [('width', ctypes.c_double), ('height', ctypes.c_double)]

        cg.CGDisplayScreenSize.argtypes = [CGDirectDisplayID]
        cg.CGDisplayScreenSize.restype = CGSize

        cg.CGDisplayPixelsWide.argtypes = [CGDirectDisplayID]
        cg.CGDisplayPixelsWide.restype = ctypes.c_size_t
        cg.CGDisplayPixelsHigh.argtypes = [CGDirectDisplayID]
        cg.CGDisplayPixelsHigh.restype = ctypes.c_size_t

        main = cg.CGMainDisplayID()
        size_mm = cg.CGDisplayScreenSize(main)
        pw = float(cg.CGDisplayPixelsWide(main))
        ph = float(cg.CGDisplayPixelsHigh(main))

        if size_mm.width > 0 and size_mm.height > 0 and pw > 0 and ph > 0:
            dpi_x = pw / (size_mm.width / 25.4)
            dpi_y = ph / (size_mm.height / 25.4)
            dpi = int(round((dpi_x + dpi_y) / 2.0))
            if 72 <= dpi <= 600:
                return _store_dpi(dpi)
    except Exception as e:
        logging.debug(f"Could not query macOS DPI: {e}")
    return _store_dpi(DEFAULT_SCREEN_DPI)


def _try_linux_x11_xft_dpi() -> Optional[int]:
    """Read Xft.dpi from the X11 resource database (``XGetDefault``).

    Works on X11 sessions and often under XWayland when ``DISPLAY`` is set.
    Returns None if libX11 is unavailable, the display cannot be opened, or
    Xft.dpi is unset.
    """
    try:
        lib_path = ctypes.util.find_library('X11')
        if not lib_path:
            return None
        x11 = ctypes.CDLL(lib_path)
        XOpenDisplay = x11.XOpenDisplay
        XOpenDisplay.argtypes = [ctypes.c_char_p]
        XOpenDisplay.restype = ctypes.c_void_p
        XCloseDisplay = x11.XCloseDisplay
        XCloseDisplay.argtypes = [ctypes.c_void_p]
        XCloseDisplay.restype = ctypes.c_int
        XGetDefault = x11.XGetDefault
        XGetDefault.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        XGetDefault.restype = ctypes.c_char_p

        dpy = XOpenDisplay(None)
        if not dpy:
            return None
        try:
            raw = XGetDefault(dpy, b'Xft', b'dpi')
            if not raw:
                return None
            val = raw.decode('utf-8', errors='ignore').strip()
            dpi_f = float(val)
            dpi = int(round(dpi_f))
            if 72 <= dpi <= 600:
                return dpi
        finally:
            XCloseDisplay(dpy)
    except Exception as e:
        logging.debug(f"Linux X11 Xft.dpi query failed: {e}")
    return None


def _try_linux_gnome_text_scaling_dpi() -> Optional[int]:
    """GNOME (and many Wayland) sessions: ``text-scaling-factor`` × :data:`DEFAULT_SCREEN_DPI`."""
    try:
        if not shutil.which('gsettings'):
            return None
        r = subprocess.run(
            [
                'gsettings',
                'get',
                'org.gnome.desktop.interface',
                'text-scaling-factor',
            ],
            capture_output=True,
            text=True,
            timeout=0.5,
            check=False,
        )
        if r.returncode != 0 or not (r.stdout or '').strip():
            return None
        line = (r.stdout or '').strip().strip("'\"")
        factor = float(line)
        if factor <= 0:
            return None
        dpi = int(round(DEFAULT_SCREEN_DPI * factor))
        if 72 <= dpi <= 600:
            return dpi
    except Exception as e:
        logging.debug(f"Linux gsettings text-scaling query failed: {e}")
    return None


def _try_linux_env_scale_dpi() -> Optional[int]:
    """Derive effective DPI from common toolkit / Qt environment variables."""
    gdk = os.environ.get('GDK_SCALE')
    if gdk:
        try:
            factor = float(gdk)
            if factor > 0:
                dpi = int(round(DEFAULT_SCREEN_DPI * factor))
                if 72 <= dpi <= 600:
                    return dpi
        except ValueError:
            pass
    qt = os.environ.get('QT_SCALE_FACTOR') or os.environ.get('QT_SCREEN_SCALE_FACTORS')
    if qt:
        first = qt.split(';')[0].strip().split(',')[0].strip()
        try:
            factor = float(first)
            if factor > 0:
                dpi = int(round(DEFAULT_SCREEN_DPI * factor))
                if 72 <= dpi <= 600:
                    return dpi
        except ValueError:
            pass
    return None


def _get_dpi_linux() -> int:
    """Return display DPI on Linux without extra Python dependencies.

    Tries in order:

    1. **X11** — ``Xft.dpi`` from the X resource database (``libX11``).
    2. **GNOME** — ``gsettings`` ``text-scaling-factor`` × :data:`DEFAULT_SCREEN_DPI`.
    3. **Environment** — ``GDK_SCALE`` or ``QT_SCALE_FACTOR`` / ``QT_SCREEN_SCALE_FACTORS``
       multiplied by :data:`DEFAULT_SCREEN_DPI`.

    Falls back to :data:`DEFAULT_SCREEN_DPI` when nothing applies (e.g. SSH
    with no display, minimal containers, or non-GNOME Wayland without Xft).
    """
    _invalidate_dpi_cache_if_stale()
    if _dpi is not None:
        return _dpi
    for probe in (
        _try_linux_x11_xft_dpi,
        _try_linux_gnome_text_scaling_dpi,
        _try_linux_env_scale_dpi,
    ):
        found = probe()
        if found is not None:
            return _store_dpi(found)
    return _store_dpi(DEFAULT_SCREEN_DPI)


def _get_dpi_unix() -> int:
    """Return display DPI on Unix.

    On **macOS**, uses CoreGraphics physical screen size + pixel dimensions
    (see :func:`_get_dpi_macos`). On **Linux**, uses :func:`_get_dpi_linux`.
    Other Unix systems use :data:`DEFAULT_SCREEN_DPI`.

    Cached for :data:`DPI_CACHE_TTL_SEC` (then refreshed).
    """
    _invalidate_dpi_cache_if_stale()
    if _dpi is not None:
        return _dpi
    if sys.platform == 'darwin':
        return _get_dpi_macos()
    if sys.platform.startswith('linux'):
        return _get_dpi_linux()
    return _store_dpi(DEFAULT_SCREEN_DPI)


# ---------------------------------------------------------------------------
# Platform pixel-dimension helpers
# ---------------------------------------------------------------------------

def _windows_console_font_cell() -> Optional[Tuple[int, int]]:
    """Return console font cell (dwFontSize.X, dwFontSize.Y), or None if unavailable."""
    if sys.platform != 'win32':
        return None
    try:
        STD_OUTPUT_HANDLE = -11
        handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        if not handle or handle == ctypes.wintypes.HANDLE(-1).value:
            return None

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
            fw = int(font_info.dwFontSize.X)
            fh = int(font_info.dwFontSize.Y)
            if fw > 0 and fh > 0:
                return fw, fh
    except Exception as e:
        logging.debug(f"GetCurrentConsoleFontEx failed: {e}")
    return None


def _get_pixels_windows(columns: int, rows: int):
    """Return (pixel_width, pixel_height) on Windows via GetCurrentConsoleFontEx.

    Retrieves the console font glyph size in pixels (dwFontSize.X / .Y) and
    multiplies by columns/rows to get the total terminal window pixel size.
    Returns (0, 0) on any failure so the caller can fall back gracefully.
    """
    cell = _windows_console_font_cell()
    if not cell:
        return 0, 0
    fw, fh = cell
    return columns * fw, rows * fh


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
    if fcntl is None or termios is None:
        return 0, 0
    try:
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
    pixel_mode: Optional[str] = None,
) -> Dict[str, int]:
    """Return terminal size in pixels and DPI for a Guacamole 'size' instruction.

    Always re-queries the terminal size internally via shutil.get_terminal_size
    for maximum accuracy. The optional *columns* and *rows* arguments serve as
    a fallback used only when the internal query fails.

    Parameters
    ----------
    pixel_mode:
        ``'kcm'``   — kcm-cli/tty.js formula, DPI 192, char 19×38 + margin.
        ``'guacd'`` — guacd-native formula, DPI 96, char 10×20, scrollbar only.
        ``None``    — resolved from ``KEEPER_GUAC_PIXEL_MODE`` env var, then
                      :data:`DEFAULT_PIXEL_MODE`.

    Returns
    -------
    dict with keys: columns, rows, pixel_width, pixel_height, dpi
    (same structure as _build_screen_info — drop-in compatible)
    """
    mode = _resolve_pixel_mode(pixel_mode)

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

    pixel_w, pixel_h = approximate_pixels(actual_cols, actual_rows, mode)
    return {
        "columns": actual_cols,
        "rows": actual_rows,
        "pixel_width": pixel_w,
        "pixel_height": pixel_h,
        "dpi": _dpi_for_mode(mode),
    }
