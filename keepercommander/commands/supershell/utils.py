"""
SuperShell utility functions

Helper functions for preferences, text processing, and other utilities.
"""

import json
import logging
import re
from pathlib import Path

# Preferences file path
PREFS_FILE = Path.home() / '.keeper' / 'supershell_prefs.json'


def load_preferences() -> dict:
    """Load preferences from file, return defaults if not found"""
    defaults = {'color_theme': 'green'}
    try:
        if PREFS_FILE.exists():
            with open(PREFS_FILE, 'r') as f:
                prefs = json.load(f)
                # Merge with defaults
                return {**defaults, **prefs}
    except Exception as e:
        logging.debug(f"Error loading preferences: {e}")
    return defaults


def save_preferences(prefs: dict):
    """Save preferences to file"""
    try:
        PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PREFS_FILE, 'w') as f:
            json.dump(prefs, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving preferences: {e}")


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)


def escape_rich_markup(text: str) -> str:
    """Escape text for use in Rich markup.

    This prevents special characters like [ and ] from being
    interpreted as Rich markup tags.
    """
    from rich.markup import escape as rich_escape
    return rich_escape(text)
