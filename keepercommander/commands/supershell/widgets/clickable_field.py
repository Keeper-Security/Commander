"""
ClickableField widget

A clickable field that copies value to clipboard on click.
"""

import pyperclip
from textual.widgets import Static
from textual.events import MouseDown


class ClickableField(Static):
    """A clickable field that copies value to clipboard on click"""

    DEFAULT_CSS = """
    ClickableField {
        width: 100%;
        height: auto;
        padding: 0 1;
    }

    ClickableField:hover {
        background: #333333;
    }

    ClickableField.clickable-value:hover {
        background: #444444;
        text-style: bold;
    }
    """

    def __init__(self, label: str, value: str, copy_value: str = None,
                 label_color: str = "#aaaaaa", value_color: str = "#00ff00",
                 is_header: bool = False, indent: int = 0, *args, **kwargs):
        """
        Create a clickable field.

        Args:
            label: The field label (e.g., "Username:")
            value: The display value
            copy_value: The value to copy (defaults to value)
            label_color: Color for label
            value_color: Color for value
            is_header: If True, style as section header
            indent: Indentation level (spaces)
        """
        self.copy_value = copy_value if copy_value is not None else value

        # Build content before calling super().__init__
        indent_str = "  " * indent
        # Escape brackets for Rich markup
        safe_value = value.replace('[', '\\[').replace(']', '\\]') if value else ''
        safe_label = label.replace('[', '\\[').replace(']', '\\]') if label else ''

        if is_header:
            content = f"[bold {value_color}]{indent_str}{safe_label}[/bold {value_color}]"
        elif label:
            content = f"{indent_str}[{label_color}]{safe_label}[/{label_color}] [{value_color}]{safe_value}[/{value_color}]"
        else:
            content = f"{indent_str}[{value_color}]{safe_value}[/{value_color}]"

        # Set classes for hover effect
        classes = "clickable-value" if self.copy_value else ""

        super().__init__(content, classes=classes, *args, **kwargs)

    def on_mouse_down(self, event: MouseDown) -> None:
        """Handle mouse down to copy value - fires immediately without waiting for focus"""
        if self.copy_value:
            try:
                pyperclip.copy(self.copy_value)
                self.app.notify(f"Copied to clipboard", severity="information")
            except Exception as e:
                self.app.notify(f"Copy failed: {e}", severity="error")
