"""
Record rendering utilities for SuperShell

Functions for formatting record data for display with syntax highlighting.
"""

import json
from typing import Any, Dict, List, Optional, Callable, TYPE_CHECKING

from rich.markup import escape as rich_escape

from .json_syntax import (
    is_sensitive_field,
    mask_passwords_in_json,
    get_json_value_for_copy,
)

if TYPE_CHECKING:
    pass


# Field type prefixes to strip from display
FIELD_TYPE_PREFIXES = (
    'text:', 'multiline:', 'url:', 'phone:', 'email:',
    'secret:', 'date:', 'name:', 'host:', 'address:'
)

# Friendly names for field type prefixes when label is empty
TYPE_FRIENDLY_NAMES = {
    'text:': 'Text',
    'multiline:': 'Note',
    'url:': 'URL',
    'phone:': 'Phone',
    'email:': 'Email',
    'secret:': 'Secret',
    'date:': 'Date',
    'name:': 'Name',
    'host:': 'Host',
    'address:': 'Address',
}

# Section headers in record detail output
RECORD_SECTION_HEADERS = {
    'Custom Fields', 'Attachments', 'User Permissions',
    'Shared Folder Permissions', 'Share Admins', 'One-Time Share URL'
}


def strip_field_type_prefix(key: str) -> str:
    """Strip type prefix from field name (e.g., 'text:Label' -> 'Label').

    Args:
        key: Field name potentially with type prefix

    Returns:
        Display name without type prefix
    """
    for prefix in FIELD_TYPE_PREFIXES:
        if key.lower().startswith(prefix):
            display_key = key[len(prefix):]
            if not display_key:
                # Use friendly name based on type
                display_key = TYPE_FRIENDLY_NAMES.get(prefix, prefix.rstrip(':').title())
            return display_key
    return key


def is_section_header(key: str, value: str) -> bool:
    """Check if key is a section header (only when value is empty).

    Args:
        key: Field name
        value: Field value

    Returns:
        True if this is a section header
    """
    if value:  # If there's a value, not a section header
        return False
    if key in RECORD_SECTION_HEADERS:
        return True
    # Handle cases like "Share Admins (64, showing first 10)"
    for header in RECORD_SECTION_HEADERS:
        if key.startswith(header):
            return True
    return False


def format_uid_line(key: str, value: str, theme_colors: dict) -> str:
    """Format a UID field line.

    Args:
        key: Field name (e.g., 'UID', 'Record UID')
        value: UID value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]"


def format_title_line(key: str, value: str, theme_colors: dict) -> str:
    """Format a title field line (bold).

    Args:
        key: Field name (e.g., 'Title', 'Name')
        value: Title value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [bold {t['primary']}]{rich_escape(str(value))}[/bold {t['primary']}]"


def format_type_line(key: str, value: str, theme_colors: dict) -> str:
    """Format a type field line.

    Args:
        key: Field name (e.g., 'Type')
        value: Type value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary_dim']}]{rich_escape(str(value))}[/{t['primary_dim']}]"


def format_password_line(
    key: str,
    display_value: str,
    theme_colors: dict
) -> str:
    """Format a password field line.

    Args:
        key: Field name (e.g., 'Password')
        display_value: Value to display (masked or unmasked)
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[{t['text_dim']}]{key}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(display_value))}[/{t['primary']}]"


def format_field_line(
    key: str,
    value: str,
    theme_colors: dict,
    in_section: bool = False
) -> str:
    """Format a general field line.

    Args:
        key: Field name
        value: Field value
        theme_colors: Theme color dict
        in_section: Whether this field is inside a section (adds indent)

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    indent = "  " if in_section else ""
    return f"{indent}[{t['text_dim']}]{rich_escape(str(key))}:[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(value))}[/{t['primary']}]"


def format_section_header(name: str, theme_colors: dict) -> str:
    """Format a section header line.

    Args:
        name: Section name
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return f"[bold {t['secondary']}]{name}:[/bold {t['secondary']}]"


def format_totp_display(
    code: str,
    seconds_remaining: int,
    theme_colors: dict
) -> str:
    """Format TOTP code display.

    Args:
        code: TOTP code
        seconds_remaining: Seconds until expiry
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    return (
        f"  [{t['text_dim']}]Code:[/{t['text_dim']}] "
        f"[bold {t['primary']}]{code}[/bold {t['primary']}]    "
        f"[{t['text_dim']}]valid for[/{t['text_dim']}] "
        f"[bold {t['secondary']}]{seconds_remaining} sec[/bold {t['secondary']}]"
    )


def format_attachment_line(
    title: str,
    uid: str,
    theme_colors: dict,
    is_linked: bool = False
) -> str:
    """Format an attachment or linked record line.

    Args:
        title: Attachment/record title
        uid: UID for copying
        theme_colors: Theme color dict
        is_linked: True for linked records (uses arrow), False for files (uses +)

    Returns:
        Rich markup formatted line
    """
    t = theme_colors
    symbol = '→' if is_linked else '+'
    return f"  [{t['text_dim']}]{symbol}[/{t['text_dim']}] [{t['primary']}]{rich_escape(str(title))}[/{t['primary']}]"


def format_rotation_status(status: str, theme_colors: dict) -> str:
    """Format rotation status with appropriate color.

    Args:
        status: Status string (Enabled, Disabled, etc.)
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted status
    """
    t = theme_colors
    if status == 'Enabled':
        color = '#00ff00'
    elif status == 'Disabled':
        color = '#ff6600'
    else:
        color = t['text_dim']
    return f"[{color}]{status}[/{color}]"


def format_rotation_last_status(status: str) -> str:
    """Format rotation last status with appropriate color.

    Args:
        status: Status string (Success, Failure, etc.)

    Returns:
        Rich markup formatted status
    """
    if status == 'Success':
        color = '#00ff00'
    elif status == 'Failure':
        color = '#ff0000'
    else:
        color = '#ffff00'
    return f"[{color}]{status}[/{color}]"


class JsonRenderer:
    """Renders JSON objects with syntax highlighting and clickable values.

    This class provides methods to render JSON as a series of lines
    suitable for display in a TUI with copy-on-click functionality.
    """

    def __init__(self, theme_colors: dict, unmask_secrets: bool = False):
        """Initialize the JSON renderer.

        Args:
            theme_colors: Theme color dictionary
            unmask_secrets: If True, don't mask sensitive values
        """
        self.theme_colors = theme_colors
        self.unmask_secrets = unmask_secrets
        # Colors for JSON syntax
        self.key_color = "#88ccff"      # Light blue for keys
        self.string_color = theme_colors.get('primary', '#00ff00')
        self.number_color = "#ffcc66"   # Orange for numbers
        self.bool_color = "#ff99cc"     # Pink for booleans
        self.null_color = "#999999"     # Gray for null
        self.bracket_color = theme_colors.get('text_dim', '#888888')

    def render_lines(
        self,
        json_obj: Any,
        on_line: Callable[[str, Optional[str], bool], None],
        record_uid: Optional[str] = None
    ):
        """Render a JSON object as a series of lines.

        Args:
            json_obj: JSON object to render
            on_line: Callback for each line: (content, copy_value, is_password)
            record_uid: Optional record UID for password copying
        """
        # Create masked version for display
        display_obj = mask_passwords_in_json(json_obj, unmask=self.unmask_secrets)
        unmasked_obj = json_obj

        self._render_value(display_obj, unmasked_obj, on_line, record_uid, indent=0)

    def _render_value(
        self,
        display_obj: Any,
        unmasked_obj: Any,
        on_line: Callable,
        record_uid: Optional[str],
        indent: int
    ):
        """Recursively render a JSON value."""
        if isinstance(display_obj, dict):
            self._render_dict(display_obj, unmasked_obj, on_line, record_uid, indent)
        elif isinstance(display_obj, list):
            self._render_list(display_obj, unmasked_obj, on_line, record_uid, indent)
        else:
            # Primitive value at top level
            self._render_primitive(display_obj, unmasked_obj, on_line, record_uid, indent, "")

    def _render_dict(
        self,
        display_dict: dict,
        unmasked_dict: Any,
        on_line: Callable,
        record_uid: Optional[str],
        indent: int
    ):
        """Render a dictionary."""
        indent_str = "  " * indent
        t = self.theme_colors

        # Opening brace - copyable with entire object
        on_line(
            f"{indent_str}[{self.bracket_color}]{{[/{self.bracket_color}]",
            json.dumps(unmasked_dict, indent=2) if isinstance(unmasked_dict, dict) else None,
            False
        )

        items = list(display_dict.items())
        for i, (key, value) in enumerate(items):
            comma = "," if i < len(items) - 1 else ""
            unmasked_value = (
                unmasked_dict.get(key, value)
                if isinstance(unmasked_dict, dict)
                else value
            )

            if isinstance(value, (dict, list)):
                self._render_complex_field(
                    key, value, unmasked_value, on_line, record_uid, indent + 1, comma
                )
            else:
                self._render_primitive_field(
                    key, value, unmasked_value, on_line, record_uid, indent + 1, comma
                )

        # Closing brace
        on_line(f"{indent_str}[{self.bracket_color}]}}[/{self.bracket_color}]", None, False)

    def _render_list(
        self,
        display_list: list,
        unmasked_list: Any,
        on_line: Callable,
        record_uid: Optional[str],
        indent: int
    ):
        """Render a list."""
        indent_str = "  " * indent

        # Opening bracket - copyable with entire array
        on_line(
            f"{indent_str}[{self.bracket_color}]\\[[/{self.bracket_color}]",
            json.dumps(unmasked_list, indent=2) if isinstance(unmasked_list, list) else None,
            False
        )

        for i, value in enumerate(display_list):
            comma = "," if i < len(display_list) - 1 else ""
            unmasked_value = (
                unmasked_list[i]
                if isinstance(unmasked_list, list) and i < len(unmasked_list)
                else value
            )

            self._render_list_item(value, unmasked_value, on_line, record_uid, indent + 1, comma)

        # Closing bracket
        on_line(f"{indent_str}[{self.bracket_color}]][/{self.bracket_color}]", None, False)

    def _render_primitive_field(
        self,
        key: str,
        value: Any,
        unmasked_value: Any,
        on_line: Callable,
        record_uid: Optional[str],
        indent: int,
        comma: str
    ):
        """Render a primitive key-value pair."""
        indent_str = "  " * indent

        if isinstance(value, str):
            display_val = value.replace("[", "\\[")
            is_password = (value == "************")
            copy_val = unmasked_value if isinstance(unmasked_value, str) else str(unmasked_value)
            on_line(
                f"{indent_str}[{self.key_color}]\"{key}\"[/{self.key_color}]: "
                f"[{self.string_color}]\"{display_val}\"[/{self.string_color}]{comma}",
                copy_val,
                is_password
            )
        elif isinstance(value, bool):
            bool_str = "true" if value else "false"
            on_line(
                f"{indent_str}[{self.key_color}]\"{key}\"[/{self.key_color}]: "
                f"[{self.bool_color}]{bool_str}[/{self.bool_color}]{comma}",
                str(value),
                False
            )
        elif isinstance(value, (int, float)):
            on_line(
                f"{indent_str}[{self.key_color}]\"{key}\"[/{self.key_color}]: "
                f"[{self.number_color}]{value}[/{self.number_color}]{comma}",
                str(value),
                False
            )
        elif value is None:
            on_line(
                f"{indent_str}[{self.key_color}]\"{key}\"[/{self.key_color}]: "
                f"[{self.null_color}]null[/{self.null_color}]{comma}",
                None,
                False
            )

    def _render_complex_field(
        self,
        key: str,
        value: Any,
        unmasked_value: Any,
        on_line: Callable,
        record_uid: Optional[str],
        indent: int,
        comma: str
    ):
        """Render a complex (dict/list) key-value pair."""
        indent_str = "  " * indent

        if isinstance(value, list):
            unmasked_list = unmasked_value if isinstance(unmasked_value, list) else value
            on_line(
                f"{indent_str}[{self.key_color}]\"{key}\"[/{self.key_color}]: "
                f"[{self.bracket_color}]\\[[/{self.bracket_color}]",
                json.dumps(unmasked_list, indent=2),
                False
            )
            for i, item in enumerate(value):
                item_comma = "," if i < len(value) - 1 else ""
                unmasked_item = (
                    unmasked_list[i]
                    if isinstance(unmasked_list, list) and i < len(unmasked_list)
                    else item
                )
                self._render_list_item(item, unmasked_item, on_line, record_uid, indent + 1, item_comma)
            on_line(f"{indent_str}[{self.bracket_color}]][/{self.bracket_color}]{comma}", None, False)

        elif isinstance(value, dict):
            unmasked_dict = unmasked_value if isinstance(unmasked_value, dict) else value
            on_line(
                f"{indent_str}[{self.key_color}]\"{key}\"[/{self.key_color}]: "
                f"[{self.bracket_color}]{{[/{self.bracket_color}]",
                json.dumps(unmasked_dict, indent=2),
                False
            )
            items = list(value.items())
            for i, (k, v) in enumerate(items):
                item_comma = "," if i < len(items) - 1 else ""
                unmasked_v = unmasked_dict.get(k, v) if isinstance(unmasked_dict, dict) else v
                if isinstance(v, (dict, list)):
                    self._render_complex_field(k, v, unmasked_v, on_line, record_uid, indent + 1, item_comma)
                else:
                    self._render_primitive_field(k, v, unmasked_v, on_line, record_uid, indent + 1, item_comma)
            on_line(f"{indent_str}[{self.bracket_color}]}}[/{self.bracket_color}]{comma}", None, False)

    def _render_list_item(
        self,
        value: Any,
        unmasked_value: Any,
        on_line: Callable,
        record_uid: Optional[str],
        indent: int,
        comma: str
    ):
        """Render a single list item."""
        indent_str = "  " * indent

        if isinstance(value, str):
            display_val = value.replace("[", "\\[")
            is_password = (value == "************")
            copy_val = unmasked_value if isinstance(unmasked_value, str) else str(unmasked_value)
            on_line(
                f"{indent_str}[{self.string_color}]\"{display_val}\"[/{self.string_color}]{comma}",
                copy_val,
                is_password
            )
        elif isinstance(value, bool):
            bool_str = "true" if value else "false"
            on_line(
                f"{indent_str}[{self.bool_color}]{bool_str}[/{self.bool_color}]{comma}",
                str(value),
                False
            )
        elif isinstance(value, (int, float)):
            on_line(
                f"{indent_str}[{self.number_color}]{value}[/{self.number_color}]{comma}",
                str(value),
                False
            )
        elif value is None:
            on_line(f"{indent_str}[{self.null_color}]null[/{self.null_color}]{comma}", None, False)
        elif isinstance(value, dict):
            unmasked_dict = unmasked_value if isinstance(unmasked_value, dict) else value
            on_line(
                f"{indent_str}[{self.bracket_color}]{{[/{self.bracket_color}]",
                json.dumps(unmasked_dict, indent=2),
                False
            )
            items = list(value.items())
            for i, (k, v) in enumerate(items):
                item_comma = "," if i < len(items) - 1 else ""
                unmasked_v = unmasked_dict.get(k, v) if isinstance(unmasked_dict, dict) else v
                if isinstance(v, (dict, list)):
                    self._render_complex_field(k, v, unmasked_v, on_line, record_uid, indent + 1, item_comma)
                else:
                    self._render_primitive_field(k, v, unmasked_v, on_line, record_uid, indent + 1, item_comma)
            on_line(f"{indent_str}[{self.bracket_color}]}}[/{self.bracket_color}]{comma}", None, False)
        elif isinstance(value, list):
            unmasked_list = unmasked_value if isinstance(unmasked_value, list) else value
            on_line(
                f"{indent_str}[{self.bracket_color}]\\[[/{self.bracket_color}]",
                json.dumps(unmasked_list, indent=2),
                False
            )
            for i, item in enumerate(value):
                item_comma = "," if i < len(value) - 1 else ""
                unmasked_item = (
                    unmasked_list[i]
                    if isinstance(unmasked_list, list) and i < len(unmasked_list)
                    else item
                )
                self._render_list_item(item, unmasked_item, on_line, record_uid, indent + 1, item_comma)
            on_line(f"{indent_str}[{self.bracket_color}]][/{self.bracket_color}]{comma}", None, False)

    def _render_primitive(
        self,
        value: Any,
        unmasked_value: Any,
        on_line: Callable,
        record_uid: Optional[str],
        indent: int,
        comma: str
    ):
        """Render a primitive value (string, number, bool, null)."""
        indent_str = "  " * indent

        if isinstance(value, str):
            display_val = value.replace("[", "\\[")
            is_password = (value == "************")
            copy_val = unmasked_value if isinstance(unmasked_value, str) else str(unmasked_value)
            on_line(
                f"{indent_str}[{self.string_color}]\"{display_val}\"[/{self.string_color}]{comma}",
                copy_val,
                is_password
            )
        elif isinstance(value, bool):
            bool_str = "true" if value else "false"
            on_line(
                f"{indent_str}[{self.bool_color}]{bool_str}[/{self.bool_color}]{comma}",
                str(value),
                False
            )
        elif isinstance(value, (int, float)):
            on_line(
                f"{indent_str}[{self.number_color}]{value}[/{self.number_color}]{comma}",
                str(value),
                False
            )
        elif value is None:
            on_line(f"{indent_str}[{self.null_color}]null[/{self.null_color}]{comma}", None, False)
