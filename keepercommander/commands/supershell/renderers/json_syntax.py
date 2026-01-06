"""
JSON syntax highlighting and masking utilities

Functions for rendering JSON with syntax highlighting and password masking.
"""

from typing import Any, Dict, List, Optional, Set

# Fields that should be masked when displaying
SENSITIVE_FIELD_NAMES: Set[str] = {
    'password', 'secret', 'passphrase', 'pin', 'token', 'key',
    'apikey', 'api_key', 'privatekey', 'private_key', 'secret2',
    'pincode', 'onetimecode', 'totp'
}


def is_sensitive_field(field_name: str) -> bool:
    """Check if a field name indicates it contains sensitive data.

    Args:
        field_name: Name of the field to check

    Returns:
        True if the field appears to contain sensitive data
    """
    if not field_name:
        return False
    name_lower = field_name.lower()
    return any(term in name_lower for term in ('secret', 'password', 'passphrase'))


def mask_passwords_in_json(obj: Any, unmask: bool = False, parent_key: str = None) -> Any:
    """Recursively mask password/secret/passphrase values in JSON object for display.

    Args:
        obj: JSON object (dict, list, or primitive)
        unmask: If True, return object unchanged (don't mask)
        parent_key: Parent key name for context

    Returns:
        Object with sensitive values masked as '************'
    """
    if unmask:
        return obj  # Don't mask if unmask mode is enabled

    if isinstance(obj, dict):
        # Check if this dict is a password field (has type: "password")
        if obj.get('type') == 'password':
            masked = dict(obj)
            if 'value' in masked and isinstance(masked['value'], list) and len(masked['value']) > 0:
                masked['value'] = ['************']
            return masked

        # Check if this dict has a label that indicates sensitive data
        label = obj.get('label', '')
        if is_sensitive_field(label):
            masked = dict(obj)
            if 'value' in masked and isinstance(masked['value'], list) and len(masked['value']) > 0:
                masked['value'] = ['************']
            return masked

        # Otherwise recurse into dict values
        result = {}
        for key, value in obj.items():
            # Check if key itself indicates sensitive data
            if is_sensitive_field(key) and isinstance(value, str) and value:
                result[key] = '************'
            else:
                result[key] = mask_passwords_in_json(value, unmask=unmask, parent_key=key)
        return result

    elif isinstance(obj, list):
        return [mask_passwords_in_json(item, unmask=unmask, parent_key=parent_key) for item in obj]

    else:
        return obj


def format_json_key(key: str, theme_colors: dict) -> str:
    """Format a JSON key with theme colors.

    Args:
        key: The JSON key
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted key
    """
    primary = theme_colors.get('primary', '#00ff00')
    return f'[{primary}]"{key}"[/{primary}]'


def format_json_string(value: str, theme_colors: dict) -> str:
    """Format a JSON string value with theme colors.

    Args:
        value: The string value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted string
    """
    secondary = theme_colors.get('secondary', '#88ff88')
    # Escape Rich markup characters
    safe_value = value.replace('[', '\\[').replace(']', '\\]')
    return f'[{secondary}]"{safe_value}"[/{secondary}]'


def format_json_number(value: Any, theme_colors: dict) -> str:
    """Format a JSON number with theme colors.

    Args:
        value: The numeric value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted number
    """
    text_dim = theme_colors.get('text_dim', '#aaaaaa')
    return f'[{text_dim}]{value}[/{text_dim}]'


def format_json_boolean(value: bool, theme_colors: dict) -> str:
    """Format a JSON boolean with theme colors.

    Args:
        value: The boolean value
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted boolean
    """
    text_dim = theme_colors.get('text_dim', '#aaaaaa')
    return f'[{text_dim}]{str(value).lower()}[/{text_dim}]'


def format_json_null(theme_colors: dict) -> str:
    """Format JSON null with theme colors.

    Args:
        theme_colors: Theme color dict

    Returns:
        Rich markup formatted null
    """
    text_dim = theme_colors.get('text_dim', '#aaaaaa')
    return f'[{text_dim}]null[/{text_dim}]'


def get_json_value_for_copy(value: Any) -> Optional[str]:
    """Get the copyable string value from a JSON value.

    Args:
        value: JSON value (string, number, bool, etc.)

    Returns:
        String to copy, or None if not copyable
    """
    if isinstance(value, str):
        return value
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, bool):
        return str(value).lower()
    elif value is None:
        return None
    else:
        return None
