"""
SuperShell display renderers

Functions and classes for formatting records, folders, and JSON for display
with syntax highlighting and copy-on-click functionality.
"""

from .json_syntax import (
    SENSITIVE_FIELD_NAMES,
    is_sensitive_field,
    mask_passwords_in_json,
    format_json_key,
    format_json_string,
    format_json_number,
    format_json_boolean,
    format_json_null,
    get_json_value_for_copy,
)

from .record import (
    FIELD_TYPE_PREFIXES,
    TYPE_FRIENDLY_NAMES,
    RECORD_SECTION_HEADERS,
    strip_field_type_prefix,
    is_section_header,
    format_uid_line,
    format_title_line,
    format_type_line,
    format_password_line,
    format_field_line,
    format_section_header,
    format_totp_display,
    format_attachment_line,
    format_rotation_status,
    format_rotation_last_status,
    JsonRenderer,
)

from .folder import (
    FOLDER_SECTION_HEADERS,
    is_folder_section_header,
    format_folder_uid_line,
    format_folder_name_line,
    format_folder_type_line,
    format_folder_section_header,
    format_folder_boolean_field,
    format_folder_field_line,
    format_record_permission_line,
    count_share_admins,
    FolderJsonRenderer,
)

__all__ = [
    # JSON syntax helpers
    'SENSITIVE_FIELD_NAMES',
    'is_sensitive_field',
    'mask_passwords_in_json',
    'format_json_key',
    'format_json_string',
    'format_json_number',
    'format_json_boolean',
    'format_json_null',
    'get_json_value_for_copy',
    # Record rendering
    'FIELD_TYPE_PREFIXES',
    'TYPE_FRIENDLY_NAMES',
    'RECORD_SECTION_HEADERS',
    'strip_field_type_prefix',
    'is_section_header',
    'format_uid_line',
    'format_title_line',
    'format_type_line',
    'format_password_line',
    'format_field_line',
    'format_section_header',
    'format_totp_display',
    'format_attachment_line',
    'format_rotation_status',
    'format_rotation_last_status',
    'JsonRenderer',
    # Folder rendering
    'FOLDER_SECTION_HEADERS',
    'is_folder_section_header',
    'format_folder_uid_line',
    'format_folder_name_line',
    'format_folder_type_line',
    'format_folder_section_header',
    'format_folder_boolean_field',
    'format_folder_field_line',
    'format_record_permission_line',
    'count_share_admins',
    'FolderJsonRenderer',
]
