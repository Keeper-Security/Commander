#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander - Slack Integration
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Utility functions for Keeper Slack Integration."""

import re
import uuid
from datetime import datetime
from typing import Tuple, Optional


def generate_approval_id() -> str:
    """
    Generate a unique approval request ID.
    """
    date_part = datetime.now().strftime('%Y%m%d')
    random_part = str(uuid.uuid4())[:5]
    return f"APR-{date_part}-{random_part}"


def is_valid_uid(identifier: str) -> bool:
    """
    Check if a string is a valid Keeper UID format.
    """
    # Remove Slack markdown formatting that might have been applied
    cleaned = identifier.strip('*_~`')
    
    # If cleaning changed the string, log it (helps debug formatting issues)
    if cleaned != identifier:
        print(f"[INFO] Stripped Slack formatting from UID: '{identifier}' → '{cleaned}'")
    
    # Keeper UIDs are typically 22 chars, but allow 20-24 for flexibility
    # Valid characters: letters, numbers, -, _
    uid_pattern = r'^[A-Za-z0-9_-]{20,24}$'
    return bool(re.match(uid_pattern, cleaned))


def parse_command_text(text: str) -> Tuple[str, str]:
    """
    Parse slash command text into identifier and justification.
    """
    text = text.strip()
    
    if not text:
        return "", ""
    
    # Check for quoted identifier
    if text.startswith('"'):
        # Find closing quote
        end_quote = text.find('"', 1)
        if end_quote != -1:
            identifier = text[1:end_quote]
            justification = text[end_quote + 1:].strip()
            return identifier, justification
    
    # No quotes - split on first whitespace
    parts = text.split(None, 1)
    identifier = parts[0] if parts else ""
    justification = parts[1] if len(parts) > 1 else ""
    
    # Clean Slack markdown formatting from identifier (*, _, ~, `)
    # This prevents issues where Slack auto-formats UIDs
    if identifier:
        cleaned_identifier = identifier.strip('*_~`')
        if cleaned_identifier != identifier:
            print(f"[INFO] Cleaned identifier: '{identifier}' → '{cleaned_identifier}'")
            identifier = cleaned_identifier
    
    return identifier, justification


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format a datetime for display in Slack.
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def truncate_text(text: str, max_length: int = 100) -> str:
    """
    Truncate text to maximum length with ellipsis.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def sanitize_slack_text(text: str) -> str:
    """
    Sanitize text for safe display in Slack.
    """
    # Escape special Slack characters
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
    }
    
    for char, escape in replacements.items():
        text = text.replace(char, escape)
    
    return text


def format_permission_name(permission: str) -> str:
    """
    Format permission level for display.
    """
    mappings = {
        # Record permissions
        'view_only': 'View Only',
        'can_edit': 'Can Edit',
        'can_share': 'Can Share',
        'edit_and_share': 'Edit and Share',
        'change_owner': 'Change Owner',
        # Folder permissions
        'no_permissions': 'No User Permissions',
        'manage_users': 'Can Manage Users',
        'manage_records': 'Can Manage Records',
        'manage_all': 'Can Manage Records and Users'
    }
    return mappings.get(permission, permission.replace('_', ' ').title())


def parse_duration_to_seconds(duration_str: str) -> Optional[int]:
    """
    Convert duration string to seconds.
    """
    if duration_str == "permanent":
        return None
    
    mapping = {
        '1h': 3600,          
        '4h': 14400,          
        '8h': 28800,          
        '24h': 86400,         
        '7d': 604800,        
        '30d': 2592000       
    }
    return mapping.get(duration_str, 86400)  # Default: 24 hours


def format_duration(duration_str: str) -> str:
    """
    Format duration string for display.
    """
    mapping = {
        '1h': '1 hour',
        '4h': '4 hours',
        '8h': '8 hours',
        '24h': '24 hours',
        '7d': '7 days',
        '30d': '30 days',
        'permanent': 'Permanent'
    }
    return mapping.get(duration_str, '24 hours')


def get_duration_options() -> list:
    """
    Get standard duration options for Slack dropdown.
    """
    return [
        {
            "text": {"type": "plain_text", "text": "1 hour"},
            "value": "1h"
        },
        {
            "text": {"type": "plain_text", "text": "4 hours"},
            "value": "4h"
        },
        {
            "text": {"type": "plain_text", "text": "8 hours"},
            "value": "8h"
        },
        {
            "text": {"type": "plain_text", "text": "24 hours"},
            "value": "24h"
        },
        {
            "text": {"type": "plain_text", "text": "7 days"},
            "value": "7d"
        },
        {
            "text": {"type": "plain_text", "text": "30 days"},
            "value": "30d"
        },
        {
            "text": {"type": "plain_text", "text": "Permanent"},
            "value": "permanent"
        }
    ]


def get_user_email_from_slack(client, user_id: str) -> str:
    """
    Get the user's email from Slack API.
    Falls back to placeholder format if email cannot be retrieved.
    
    Args:
        client: Slack WebClient instance
        user_id: Slack user ID (e.g., U09SC2S46GN)
        
    Returns:
        User's email address or placeholder format
    """
    try:
        user_info = client.users_info(user=user_id)
        if user_info.get('ok') and user_info.get('user'):
            email = user_info['user'].get('profile', {}).get('email')
            if email:
                print(f"[INFO] Resolved Slack user {user_id} to email: {email}")
                return email
        print(f"[WARN] Could not get email for Slack user {user_id}, using placeholder")
        return f"{user_id}@slack.user"
    except Exception as e:
        print(f"[ERROR] Error fetching user email from Slack: {e}")
        return f"{user_id}@slack.user"


def send_dm(client, user_id: str, text: str, blocks: Optional[list] = None) -> bool:
    """
    Send a direct message to a Slack user.
    
    Args:
        client: Slack WebClient instance
        user_id: Slack user ID
        text: Message text (fallback if blocks fail)
        blocks: Optional Block Kit blocks for rich formatting
        
    Returns:
        True if message sent successfully, False otherwise
    """
    try:
        dm_response = client.conversations_open(users=[user_id])
        dm_channel_id = dm_response["channel"]["id"]
        
        if blocks:
            client.chat_postMessage(
                channel=dm_channel_id,
                text=text,
                blocks=blocks
            )
        else:
            client.chat_postMessage(
                channel=dm_channel_id,
                text=text
            )
        
        print(f"[INFO] DM sent to user {user_id}")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to send DM to {user_id}: {e}")
        return False


def send_error_dm(client, user_id: str, title: str, message: str) -> bool:
    """
    Send an error message DM with standardized formatting.
    
    Args:
        client: Slack WebClient instance
        user_id: Slack user ID
        title: Error title (e.g., "Record Not Found")
        message: Detailed error message
        
    Returns:
        True if sent successfully, False otherwise
    """
    formatted_text = f"*{title}*\n\n{message}"
    return send_dm(client, user_id, formatted_text)


def send_success_dm(client, user_id: str, title: str, message: str, **kwargs) -> bool:
    """
    Send a success message DM with standardized formatting.
    
    Args:
        client: Slack WebClient instance
        user_id: Slack user ID
        title: Success title (e.g., "Access Granted")
        message: Success details
        **kwargs: Additional fields to display (e.g., record_title="My Record")
        
    Returns:
        True if sent successfully, False otherwise
    """
    formatted_text = f"*{title}*\n\n{message}"
    
    # Add any additional fields
    if kwargs:
        formatted_text += "\n\n"
        for key, value in kwargs.items():
            field_name = key.replace('_', ' ').title()
            formatted_text += f"*{field_name}:* {value}\n"
    
    return send_dm(client, user_id, formatted_text)
