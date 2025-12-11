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

"""Handler for /keeper-request-record slash command."""

from typing import Dict, Any
from ..models import RequestType
from ..utils import generate_approval_id, is_valid_uid, parse_command_text
from ..views import post_approval_request


def handle_request_record(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle /keeper-request-record [record] [reason] command.
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
            text="*Usage:* `/keeper-request-record [record-uid-or-description] [justification]`\n\n"
                 "*Examples:*\n"
                 "• `/keeper-request-record kR3cF9Xm2Lp8NqT1uV6w Emergency server access`\n"
                 "• `/keeper-request-record \"prod db EU region\" Need to run migration`\n\n"
        )
        return
    
    # Parse command text
    identifier, justification = parse_command_text(text)
    
    if not identifier:
        client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            text="Please provide a record UID or description."
        )
        return
    
    # Check if justification is provided
    if not justification:
        client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            text=f"Justification is required.\n\n"
                 f"*Usage:* `/keeper-request-record {identifier} <your reason for access>`"
        )
        return
    
    # Determine if UID or description
    is_uid = is_valid_uid(identifier)
    
    # Fetch record details if UID is provided
    record_details = None
    if is_uid:
        print(f"[INFO] Fetching record details for UID: {identifier}")
        record_details = keeper_client.get_record_by_uid(identifier)
        
        if not record_details:
            # UID not found - send error to user
            from ..utils import send_error_dm
            send_error_dm(
                client, user_id,
                "Record Not Found",
                f"No record found with UID: `{identifier}`\n\nPlease verify the UID and try again."
            )
            return
        
        # Validate it's actually a record, not a folder
        if record_details.record_type in ['folder', 'shared_folder', 'user_folder']:
            print(f"[WARN] UID {identifier} is a folder, not a record")
            from ..utils import send_error_dm
            send_error_dm(
                client, user_id,
                "Invalid UID Type",
                f"The UID `{identifier}` is a **folder**, not a record.\n\n"
                f"Please use `/keeper-request-folder {identifier} {justification}` instead."
            )
            return
    
    # Generate unique approval ID
    approval_id = generate_approval_id()

    try:
        post_approval_request(
            client=client,
            approvals_channel=config.slack.approvals_channel_id,
            approval_id=approval_id,
            requester_id=user_id,
            requester_name=user_name,
            identifier=identifier,
            is_uid=is_uid,
            request_type=RequestType.RECORD,
            justification=justification,
            duration="24h",
            record_details=record_details
        )
        
        # Send confirmation to user via DM
        from ..utils import send_success_dm
        send_success_dm(
            client, user_id,
            "Record access request submitted!",
                 f"Request ID: `{approval_id}`\n"
                 f"Record: `{identifier}`\n"
                 f"Justification: {justification}\n\n"
                 f"Your request has been sent to <#{config.slack.approvals_channel_id}> for approval."
        )
            
    except Exception as e:
        print(f"Error posting approval request: {e}")
        
        # Send error message via DM (works in channels and DMs)
        from ..utils import send_error_dm
        send_error_dm(
            client, user_id,
            "Failed to submit access request",
            f"Please try again or contact support.\n\nError: {str(e)}"
        )

