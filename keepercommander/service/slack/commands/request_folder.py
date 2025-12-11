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

"""Handler for /keeper-request-folder slash command."""

from typing import Dict, Any
from ..models import RequestType
from ..utils import generate_approval_id, is_valid_uid, parse_command_text
from ..views import post_approval_request


def handle_request_folder(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle /keeper-request-folder [folder] [reason] command.
    """
    user_id = body["user_id"]
    user_name = body["user_name"]
    channel_id = body["channel_id"]
    text = body.get("text", "").strip()
    
    # Validate input
    if not text:
        client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            text="*Usage:* `/keeper-request-folder [folder-uid-or-description] [justification]`\n\n"
                 "*Examples:*\n"
                 "• `/keeper-request-folder kF8zQ2Nm5Wx9PtR3sY7a Need staging access`\n"
                 "• `/keeper-request-folder \"Staging Team Folder\" Need staging access`\n\n"
                 "*Tip:* Quotes are required for descriptions with spaces, but optional for UIDs"
        )
        return
    

    identifier, justification = parse_command_text(text)
    
    if not identifier:
        client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            text="Please provide a folder UID or description."
        )
        return
    
    # Check if justification is provided
    if not justification:
        client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            text=f"Justification is required.\n\n"
                 f"*Usage:* `/keeper-request-folder {identifier} <your reason for access>`"
        )
        return
    
    # Determine if UID or description
    is_uid = is_valid_uid(identifier)
    
    # Fetch folder details if UID is provided
    folder_details = None
    if is_uid:
        print(f"[INFO] Fetching folder details for UID: {identifier}")
        folder_details = keeper_client.get_folder_by_uid(identifier)
        
        if not folder_details:
            # UID not found - send error to user
            from ..utils import send_error_dm
            send_error_dm(
                client, user_id,
                "Folder Not Found",
                f"No folder found with UID: `{identifier}`\n\nPlease verify the UID and try again."
            )
            return
        
        # Validate it's actually a folder, not a record
        if folder_details.folder_type == 'record':
            print(f"[WARN] UID {identifier} is a record, not a folder")
            from ..utils import send_error_dm
            send_error_dm(
                client, user_id,
                "Invalid UID Type",
                f"The UID `{identifier}` is a **record**, not a folder.\n\n"
                f"Please use `/keeper-request-record {identifier} {justification}` instead."
            )
            return
    
    # Generate unique approval ID
    approval_id = generate_approval_id()
    
    # Post approval request to approvals channel
    try:
        post_approval_request(
            client=client,
            approvals_channel=config.slack.approvals_channel_id,
            approval_id=approval_id,
            requester_id=user_id,
            requester_name=user_name,
            identifier=identifier,
            is_uid=is_uid,
            request_type=RequestType.FOLDER,
            justification=justification,
            duration="24h",  # Default suggestion (approver can change)
            folder_details=folder_details
        )
        
        # Send confirmation to user via DM
        from ..utils import send_success_dm
        send_success_dm(
            client, user_id,
            "Folder access request submitted!",
                 f"Request ID: `{approval_id}`\n"
                 f"Folder: `{identifier}`\n"
                 f"Justification: {justification}\n\n"
                 f"Your request has been sent to <#{config.slack.approvals_channel_id}> for approval."
        )
            
    except Exception as e:
        print(f"Error posting approval request: {e}")
        
        # Send error message via DM
        from ..utils import send_error_dm
        send_error_dm(
            client, user_id,
            "Failed to submit access request",
            f"Please try again or contact support.\n\nError: {str(e)}"
        )

