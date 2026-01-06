"""
SuperShell custom widgets

Reusable Textual widgets for the SuperShell TUI.
"""

from .clickable_line import ClickableDetailLine
from .clickable_field import ClickableField
from .clickable_uid import ClickableRecordUID

__all__ = [
    'ClickableDetailLine',
    'ClickableField',
    'ClickableRecordUID',
]
