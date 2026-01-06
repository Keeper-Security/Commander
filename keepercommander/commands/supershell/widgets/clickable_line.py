"""
ClickableDetailLine widget

A single line in the detail view that highlights on hover and copies on click.
"""

import pyperclip
from textual.widgets import Static
from textual.events import MouseDown


class ClickableDetailLine(Static):
    """A single line in the detail view that highlights on hover and copies on click"""

    DEFAULT_CSS = """
    ClickableDetailLine {
        width: 100%;
        height: auto;
        padding: 0 1;
    }

    ClickableDetailLine:hover {
        background: #1a1a2e;
    }

    ClickableDetailLine.has-value {
        /* Clickable lines get a subtle left border indicator */
    }

    ClickableDetailLine.has-value:hover {
        background: #16213e;
        text-style: bold;
        border-left: thick #00ff00;
    }
    """

    def __init__(self, content: str, copy_value: str = None, record_uid: str = None,
                 is_password: bool = False, *args, **kwargs):
        """
        Create a clickable detail line.

        Args:
            content: Rich markup content to display
            copy_value: Value to copy on click (None = not copyable)
            record_uid: Record UID for password audit events
            is_password: If True, use ClipboardCommand for audit event
        """
        self.copy_value = copy_value
        self.record_uid = record_uid
        self.is_password = is_password
        classes = "has-value" if copy_value else ""
        super().__init__(content, classes=classes, *args, **kwargs)

    def on_mouse_down(self, event: MouseDown) -> None:
        """Handle mouse down to copy value - fires immediately without waiting for focus"""
        if self.copy_value:
            try:
                if self.is_password and self.record_uid:
                    # Use ClipboardCommand to generate audit event for password copy
                    from ...record import ClipboardCommand
                    cc = ClipboardCommand()
                    cc.execute(self.app.params, record=self.record_uid, output='clipboard',
                               username=None, copy_uid=False, login=False, totp=False,
                               field=None, revision=None)
                    self.app.notify("Password copied to clipboard!", severity="information")
                else:
                    # Regular copy for non-password fields
                    pyperclip.copy(self.copy_value)
                    truncated = self.copy_value[:50] + ('...' if len(self.copy_value) > 50 else '')
                    self.app.notify(f"Copied: {truncated}", severity="information")
            except Exception as e:
                self.app.notify(f"Copy failed: {e}", severity="error")
