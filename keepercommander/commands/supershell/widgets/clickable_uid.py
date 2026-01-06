"""
ClickableRecordUID widget

A clickable record UID that navigates to the record when clicked.
"""

import pyperclip
from textual.widgets import Static, Tree
from textual.events import MouseDown


class ClickableRecordUID(Static):
    """A clickable record UID that navigates to the record when clicked"""

    DEFAULT_CSS = """
    ClickableRecordUID {
        width: 100%;
        height: auto;
        padding: 0 1;
    }

    ClickableRecordUID:hover {
        background: #333344;
        text-style: bold underline;
    }
    """

    def __init__(self, label: str, record_uid: str, record_title: str = None,
                 label_color: str = "#aaaaaa", value_color: str = "#ffff00",
                 indent: int = 0, *args, **kwargs):
        """
        Create a clickable record UID that navigates to the record.

        Args:
            label: The field label (e.g., "Record UID:")
            record_uid: The UID of the record to navigate to
            record_title: Optional title to display instead of UID
            label_color: Color for label
            value_color: Color for value
            indent: Indentation level
        """
        self.record_uid = record_uid

        # Build content before calling super().__init__
        indent_str = "  " * indent
        display_value = record_title or record_uid
        safe_value = display_value.replace('[', '\\[').replace(']', '\\]')
        safe_label = label.replace('[', '\\[').replace(']', '\\]') if label else ''

        if label:
            content = f"{indent_str}[{label_color}]{safe_label}[/{label_color}] [{value_color}]{safe_value} ->[/{value_color}]"
        else:
            content = f"{indent_str}[{value_color}]{safe_value} ->[/{value_color}]"

        super().__init__(content, *args, **kwargs)

    def on_mouse_down(self, event: MouseDown) -> None:
        """Handle mouse down to navigate to record - fires immediately without waiting for focus"""
        # Find the app and trigger record selection
        app = self.app
        if hasattr(app, 'records') and self.record_uid in app.records:
            # Navigate to the record in the tree
            app.selected_record = self.record_uid
            app.selected_folder = None
            app._display_record_detail(self.record_uid)

            # Try to select the node in the tree
            tree = app.query_one("#folder_tree", Tree)
            app._select_record_in_tree(tree, self.record_uid)

            app.notify(f"Navigated to record", severity="information")
        else:
            # Just copy the UID if record not found
            pyperclip.copy(self.record_uid)
            app.notify(f"Record not in vault. UID copied.", severity="warning")
