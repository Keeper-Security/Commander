"""
SuperShell state management

Dataclasses for managing application state.
"""

from .vault_data import VaultData
from .ui_state import UIState, ThemeState
from .selection import SelectionState

__all__ = [
    'VaultData',
    'UIState',
    'ThemeState',
    'SelectionState',
]
