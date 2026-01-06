"""
Folder rendering utilities for SuperShell

Functions for formatting folder data for display with syntax highlighting.
"""

import json
from typing import Any, Dict, List, Optional, Callable

from rich.markup import escape as rich_escape


# Section headers in folder detail output
FOLDER_SECTION_HEADERS = {
    'Record Permissions', 'User Permissions',
    'Team Permissions', 'Share Administrators'
}


def is_folder_section_header(key: str) -> bool:
    """Check if key is a folder section header.

    Args:
        key: Field name

    Returns:
        True if this is a section header
    """
    return key in FOLDER_SECTION_HEADERS


def format_folder_uid_line(key: str, value: str, theme_colors: dict) -> str:
    """Format a folder UID field line.

    Args:
        key: Field name (e.g., 'Shared Folder UID', 'Folder UID')
        value: UID value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]"


def format_folder_name_line(value: str, theme_colors: dict) -> str:
    """Format a folder name line (bold).

    Args:
        value: Folder name
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]"


def format_folder_type_line(key: str, value: str, theme_colors: dict) -> str:
    """Format a folder type line.

    Args:
        key: Field name (usually 'Type' or 'Folder Type')
        value: Type value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[{t['text_dim']}]Type:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]"


def format_folder_section_header(
    name: str,
    theme_colors: dict,
    count: Optional[int] = None
) -> str:
    """Format a folder section header line.

    Args:
        name: Section name
        theme_colors: Theme color dict
        count: Optional count to display

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    if count is not None and count > 0:
        return f"[bold {t['primary_bright']}]{name}:[/bold {t['primary_bright']}] [{t['text_dim']}]({count} users)[/{t['text_dim']}]"
    return f"[bold {t['primary_bright']}]{name}:[/bold {t['primary_bright']}]"


def format_folder_boolean_field(
    key: str,
    value: str,
    theme_colors: dict,
    in_section: bool = False
) -> str:
    """Format a boolean field line in folder display.

    Args:
        key: Field name
        value: Boolean value as string ('true' or 'false')
        theme_colors: Theme color dict
        in_section: Whether this is inside a section (adds indent)

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    color = t['primary'] if value.lower() == 'true' else t['primary_dim']
    indent = "  " if in_section else ""
    return f"{indent}[{t['secondary']}]{rich_escape(str(key))}:[/{t['secondary']}] [{color}]{rich_escape(str(value))}[/{color}]"


def format_folder_field_line(
    key: str,
    value: str,
    theme_colors: dict,
    in_section: bool = False
) -> str:
    """Format a general folder field line.

    Args:
        key: Field name
        value: Field value
        theme_colors: Theme color dict
        in_section: Whether this is inside a section (adds indent)

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    indent = "  " if in_section else ""
    return f"{indent}[{t['secondary']}]{rich_escape(str(key))}:[/{t['secondary']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]"


def format_record_permission_line(
    title: str,
    uid: str,
    theme_colors: dict
) -> tuple:
    """Format record permission lines (returns two lines).

    Args:
        title: Record title
        uid: Record UID
        theme_colors: Theme color dict

    Returns:
        Tuple of (title_line, uid_line) with Rich markup
    """
    t = theme_colors
    title_line = f"  [{t['text_dim']}]Record:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(title))}[/{t['primary']}]"
    uid_line = f"    [{t['text_dim']}]UID:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(uid))}[/{t['primary']}]"
    return title_line, uid_line


def count_share_admins(output: str) -> int:
    """Count share admins in folder output.

    Args:
        output: Raw folder detail output

    Returns:
        Number of share admin users
    """
    count = 0
    in_share_admins = False

    for line in output.split('\n'):
        stripped = line.strip()
        if ':' in stripped:
            key = stripped.split(':', 1)[0].strip()
            if key == 'Share Administrators':
                in_share_admins = True
            elif key in FOLDER_SECTION_HEADERS and key != 'Share Administrators':
                in_share_admins = False
            elif in_share_admins and key == 'User':
                count += 1

    return count


class FolderJsonRenderer:
    """Renders folder JSON with syntax highlighting and clickable values.

    This class provides methods to render folder JSON as a series of lines
    suitable for display in a TUI with copy-on-click functionality.
    """

    def __init__(self, theme_colors: dict):
        """Initialize the folder JSON renderer.

        Args:
            theme_colors: Theme color dictionary
        """
        self.theme_colors = theme_colors

    def render_lines(
        self,
        json_obj: Any,
        on_line: Callable[[str, Optional[str]], None]
    ):
        """Render a JSON object as a series of lines.

        Args:
            json_obj: JSON object to render
            on_line: Callback for each line: (content, copy_value)
        """
        self._render_value(json_obj, on_line, indent=0)

    def _render_value(
        self,
        obj: Any,
        on_line: Callable,
        indent: int
    ):
        """Recursively render a JSON value."""
        t = self.theme_colors

        if isinstance(obj, dict):
            # Opening brace - copyable with entire object
            on_line(f"{'  ' * indent}{{", json.dumps(obj, indent=2))
            items = list(obj.items())
            for i, (key, value) in enumerate(items):
                comma = "," if i < len(items) - 1 else ""
                self._render_key_value(key, value, on_line, indent + 1, comma)
            on_line(f"{'  ' * indent}}}", None)

        elif isinstance(obj, list):
            # Opening bracket - copyable with entire array
            on_line(f"{'  ' * indent}[", json.dumps(obj, indent=2))
            for i, item in enumerate(obj):
                comma = "," if i < len(obj) - 1 else ""
                self._render_list_item(item, on_line, indent + 1, comma)
            on_line(f"{'  ' * indent}]", None)

    def _render_key_value(
        self,
        key: str,
        value: Any,
        on_line: Callable,
        indent: int,
        comma: str
    ):
        """Render a key-value pair."""
        t = self.theme_colors
        prefix = "  " * indent

        if isinstance(value, str):
            escaped_value = rich_escape(value)
            on_line(
                f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: "
                f"[{t['primary']}]\"{escaped_value}\"[/{t['primary']}]{comma}",
                value
            )
        elif isinstance(value, bool):
            bool_str = "true" if value else "false"
            on_line(
                f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: "
                f"[{t['primary_bright']}]{bool_str}[/{t['primary_bright']}]{comma}",
                str(value)
            )
        elif isinstance(value, (int, float)):
            on_line(
                f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: "
                f"[{t['primary_bright']}]{value}[/{t['primary_bright']}]{comma}",
                str(value)
            )
        elif value is None:
            on_line(
                f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: "
                f"[{t['text_dim']}]null[/{t['text_dim']}]{comma}",
                None
            )
        elif isinstance(value, dict):
            on_line(
                f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: {{",
                json.dumps(value, indent=2)
            )
            items = list(value.items())
            for i, (k, v) in enumerate(items):
                item_comma = "," if i < len(items) - 1 else ""
                self._render_key_value(k, v, on_line, indent + 1, item_comma)
            on_line(f"{prefix}}}{comma}", None)
        elif isinstance(value, list):
            on_line(
                f"{prefix}[{t['secondary']}]\"{rich_escape(key)}\"[/{t['secondary']}]: [",
                json.dumps(value, indent=2)
            )
            for i, item in enumerate(value):
                item_comma = "," if i < len(value) - 1 else ""
                self._render_list_item(item, on_line, indent + 1, item_comma)
            on_line(f"{prefix}]{comma}", None)

    def _render_list_item(
        self,
        item: Any,
        on_line: Callable,
        indent: int,
        comma: str
    ):
        """Render a single list item."""
        t = self.theme_colors
        prefix = "  " * indent

        if isinstance(item, str):
            escaped_item = rich_escape(item)
            on_line(f"{prefix}[{t['primary']}]\"{escaped_item}\"[/{t['primary']}]{comma}", item)
        elif isinstance(item, dict):
            on_line(f"{prefix}{{", json.dumps(item, indent=2))
            items = list(item.items())
            for i, (k, v) in enumerate(items):
                item_comma = "," if i < len(items) - 1 else ""
                self._render_key_value(k, v, on_line, indent + 1, item_comma)
            on_line(f"{prefix}}}{comma}", None)
        elif isinstance(item, list):
            on_line(f"{prefix}[", json.dumps(item, indent=2))
            for i, sub_item in enumerate(item):
                item_comma = "," if i < len(item) - 1 else ""
                self._render_list_item(sub_item, on_line, indent + 1, item_comma)
            on_line(f"{prefix}]{comma}", None)
        else:
            on_line(f"{prefix}[{t['primary_bright']}]{item}[/{t['primary_bright']}]{comma}", str(item))
