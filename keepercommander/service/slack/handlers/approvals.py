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

"""Handlers for approval/deny button actions."""

import json
from typing import Dict, Any
from ..models import PermissionLevel
from ..views import update_approval_message, send_access_granted_dm, send_access_denied_dm
from ..utils import parse_duration_to_seconds, format_duration, get_user_email_from_slack


def handle_approve_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle approve button click.
    
    Grants access to the requested record/folder and notifies requester.
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract request data from button value
    action_data = json.loads(body["actions"][0]["value"])
    approval_id = action_data["approval_id"]
    requester_id = action_data["requester_id"]
    identifier = action_data["identifier"]
    is_uid = action_data["is_uid"]
    request_type = action_data["type"]
    justification = action_data.get("justification", "No justification provided")
    
    if not is_uid:
        from ..utils import send_error_dm
        send_error_dm(
            client, approver_id,
            "Cannot approve directly",
            "This request uses a description, not a UID. "
            "Please use the *Search* button to find the correct record first."
        )
        return
    
    # Extract selected duration from approval card (check state first, then blocks)
    message_blocks = body.get("message", {}).get("blocks", [])
    state = body.get("state")
    
    # Get selected permission level FIRST (needed to determine if duration applies)
    permission = _extract_permission_from_blocks(message_blocks, state)
    
    # Some permissions are always permanent (no duration)
    PERMANENT_ONLY_PERMISSIONS = [
        PermissionLevel.CAN_SHARE,
        PermissionLevel.EDIT_AND_SHARE,
        PermissionLevel.CHANGE_OWNER,
        PermissionLevel.MANAGE_USERS,
        PermissionLevel.MANAGE_ALL
    ]
    
    if permission in PERMANENT_ONLY_PERMISSIONS:
        # Force permanent access for these permissions
        duration_seconds = None
        duration_value = "permanent"
        duration_text = "Permanent"
        print(f"[INFO] {permission.value} is permanent-only, ignoring duration selector")
    else:
        # Normal duration handling
        duration_value = _extract_duration_from_blocks(message_blocks, state)
        
        # If not found in blocks, fall back to action_data default
        if not duration_value:
            duration_value = action_data.get("duration", "24h")
        
        duration_seconds = parse_duration_to_seconds(duration_value)
        duration_text = format_duration(duration_value)
    
    print(f"[DEBUG] Approve action - Duration: {duration_value} ({duration_seconds} seconds)")
    
    if not permission:
        # Default permissions if not found
        permission = PermissionLevel.CAN_EDIT if request_type == "record" else PermissionLevel.NO_PERMISSIONS
    
    # For one-time shares, convert permission to editable flag
    editable = (permission == PermissionLevel.CAN_EDIT)
    
    # Get user's real email from Slack
    user_email = get_user_email_from_slack(client, requester_id)
    
    # Grant access or create share link via Keeper
    try:
        if request_type == "record":
            result = keeper_client.grant_record_access(
                record_uid=identifier,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds
            )
            item_title = identifier  # In real implementation, fetch actual title
        elif request_type == "folder":
            result = keeper_client.grant_folder_access(
                folder_uid=identifier,
                user_email=user_email,
                permission=permission,
                duration_seconds=duration_seconds
            )
            item_title = identifier
        elif request_type == "one_time_share":
            # Create one-time share link with editable permission
            result = keeper_client.create_one_time_share(
                record_uid=identifier,
                duration_seconds=duration_seconds,
                editable=editable
            )
            item_title = identifier
        else:
            result = {'success': False, 'error': f'Unknown request type: {request_type}'}
        
        if result.get('success'):
            # Update approval message with beautiful formatting
            from datetime import datetime
            from ..views import send_share_link_dm
            
            expires_at = result.get('expires_at', 'Never')
            is_permanent = duration_value == "permanent"
            
            # Different handling for one-time share vs access grant
            if request_type == "one_time_share":
                # One-time share created
                status_msg = f"*One-Time Share Link Created*\nLink sent to requester • Expires: {expires_at}"
                approval_text = "One-Time Share Request Approved"
            else:
                # Access granted
                if is_permanent:
                    status_msg = "*Permanent Access Granted*\nNo expiration - Access remains active indefinitely"
                else:
                    status_msg = f"*Temporary Access Granted*\nAccess will expire on *{expires_at}*"
                approval_text = "Access Request Approved"
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                text=f"Request approved by <@{approver_id}>",
                blocks=[
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": approval_text,
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Record:* `{identifier}`\n"
                                    f"*Requester:* <@{requester_id}>\n"
                                    f"*Approved by:* <@{approver_id}>"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": status_msg
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Approved • {datetime.now().strftime('%B %d, %Y at %I:%M %p')}"
                            }
                        ]
                    }
                ]
            )
            
            # Send appropriate DM based on request type
            if request_type == "one_time_share":
                # Send one-time share link via DM
                send_share_link_dm(
                    client=client,
                    user_id=requester_id,
                    record_uid=identifier,
                    share_url=result.get('share_url'),
                    record_title=item_title,
                    expires_at=expires_at,
                    approval_id=approval_id
                )
                print(f"Approval {approval_id}: Created one-time share for {requester_id} by {approver_id}")
            else:
                # Send access granted DM
                send_access_granted_dm(
                    client=client,
                    user_id=requester_id,
                    approval_id=approval_id,
                    item_type=request_type,
                    item_title=item_title,
                    share_url=result.get('share_url', 'N/A'),
                    expires_at=result.get('expires_at', duration_text)
                )
            print(f"Approval {approval_id}: Granted {request_type} access to {requester_id} by {approver_id}")
        else:
            # Update with error
            update_approval_message(
                client=client,
                channel_id=body["channel"]["id"],
                message_ts=body["message"]["ts"],
                status=f"Approval failed: {result.get('error', 'Unknown error')}",
                original_blocks=body["message"]["blocks"]
            )
    except Exception as e:
        print(f"Error in approve handler: {e}")
        update_approval_message(
            client=client,
            channel_id=body["channel"]["id"],
            message_ts=body["message"]["ts"],
            status=f"Error processing approval: {str(e)}",
            original_blocks=body["message"]["blocks"]
        )


def handle_deny_action(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle deny button click.
    
    Denies the access request and notifies requester.
    
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract request data
    action_data = json.loads(body["actions"][0]["value"])
    approval_id = action_data["approval_id"]
    requester_id = action_data["requester_id"]
    request_type = action_data["type"]
    
    try:
        # Update approval message
        update_approval_message(
            client=client,
            channel_id=body["channel"]["id"],
            message_ts=body["message"]["ts"],
            status=f"Denied by <@{approver_id}>",
            original_blocks=body["message"]["blocks"]
        )
        
        # Notify requester via DM
        send_access_denied_dm(
            client=client,
            user_id=requester_id,
            approval_id=approval_id,
            item_type=request_type,
            approver_name=approver_name
        )
        
        print(f"Approval {approval_id}: Denied by {approver_id}")
    except Exception as e:
        print(f"Error in deny handler: {e}")
        update_approval_message(
            client=client,
            channel_id=body["channel"]["id"],
            message_ts=body["message"]["ts"],
            status=f"Error processing denial: {str(e)}",
            original_blocks=body["message"]["blocks"]
        )


def _extract_permission_from_blocks(blocks: list, state: dict = None) -> PermissionLevel:
    """
    Extract selected permission level from state or message blocks.
    """
    # First, try to get from state object (this has the actual selected value)
    if state and 'values' in state:
        for block_id, block_values in state['values'].items():
            if 'select_permission' in block_values:
                selected = block_values['select_permission'].get('selected_option')
                if selected:
                    permission_value = selected.get('value')
                    try:
                        return PermissionLevel(permission_value)
                    except ValueError:
                        pass
    
    # Fallback: check message blocks (only has initial_option)
    for block in blocks:
        if block.get("type") == "section" and "accessory" in block:
            accessory = block["accessory"]
            if accessory.get("type") == "static_select":
                selected_option = accessory.get("initial_option")
                if selected_option:
                    permission_value = selected_option.get("value")
                    try:
                        return PermissionLevel(permission_value)
                    except ValueError:
                        pass
    return None


def _extract_duration_from_blocks(blocks: list, state: dict = None) -> str:
    """
    Extract selected duration from state or message blocks.
    """
    # First, try to get from state object (this has the actual selected value)
    if state and 'values' in state:
        for block_id, block_values in state['values'].items():
            if 'select_duration' in block_values:
                selected = block_values['select_duration'].get('selected_option')
                if selected:
                    return selected.get('value')
    
    # Fallback: check message blocks (only has initial_option)
    for block in blocks:
        if block.get("type") == "section" and "accessory" in block:
            accessory = block["accessory"]
            if accessory.get("action_id") == "select_duration":
                selected_option = accessory.get("selected_option")
                if selected_option:
                    return selected_option.get("value")
                initial_option = accessory.get("initial_option")
                if initial_option:
                    return initial_option.get("value")
    return None

