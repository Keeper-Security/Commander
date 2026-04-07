"""
SuperShell custom widgets

Reusable Textual widgets for the SuperShell TUI.
"""

from .clickable_line import ClickableDetailLine
from .clickable_field import ClickableField
from .clickable_uid import ClickableRecordUID
from .auto_copy_textarea import AutoCopyTextArea, safe_copy_to_clipboard
from .shell_input_textarea import ShellInputTextArea

__all__ = [
    'ClickableDetailLine',
    'ClickableField',
    'ClickableRecordUID',
    'AutoCopyTextArea',
    'safe_copy_to_clipboard',
    'ShellInputTextArea',
]
