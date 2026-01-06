"""
Keeper SuperShell - A full-screen terminal UI for Keeper vault

This package provides a modern TUI interface with vim-style navigation
for browsing and managing Keeper vault records.

During refactoring, the main implementation is in _supershell_impl.py.
This will be gradually migrated into this package structure.
"""

# Re-export from implementation file for backward compatibility
from .._supershell_impl import SuperShellCommand, SuperShellApp

# Export theme and utility modules
from .themes import COLOR_THEMES
from .screens import PreferencesScreen, HelpScreen
from .utils import load_preferences, save_preferences, strip_ansi_codes
from .widgets import ClickableDetailLine, ClickableField, ClickableRecordUID
from .state import VaultData, UIState, ThemeState, SelectionState
from .renderers import (
    is_sensitive_field,
    mask_passwords_in_json,
    strip_field_type_prefix,
    is_section_header,
    JsonRenderer,
    FolderJsonRenderer,
)
from .handlers import (
    KeyHandler,
    KeyboardDispatcher,
    keyboard_dispatcher,
)

__all__ = [
    # Main classes
    'SuperShellCommand',
    'SuperShellApp',
    # Themes
    'COLOR_THEMES',
    # Screens
    'PreferencesScreen',
    'HelpScreen',
    # Utils
    'load_preferences',
    'save_preferences',
    'strip_ansi_codes',
    # Widgets
    'ClickableDetailLine',
    'ClickableField',
    'ClickableRecordUID',
    # State
    'VaultData',
    'UIState',
    'ThemeState',
    'SelectionState',
    # Renderers
    'is_sensitive_field',
    'mask_passwords_in_json',
    'strip_field_type_prefix',
    'is_section_header',
    'JsonRenderer',
    'FolderJsonRenderer',
    # Handlers
    'KeyHandler',
    'KeyboardDispatcher',
    'keyboard_dispatcher',
]
