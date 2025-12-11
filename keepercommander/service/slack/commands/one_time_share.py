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

"""Handler for /keeper-one-time-share slash command."""

from typing import Dict, Any
from ..models import RequestType
from ..utils import generate_approval_id, is_valid_uid, parse_command_text
from ..views import post_approval_request


def handle_one_time_share(body: Dict[str, Any], client, config, keeper_client):
    """
    Creates an approval request for generating a one-time share link.
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
            text="*Usage:* `/keeper-one-time-share [record-uid-or-description] [justification]`\n\n"
                 "*Examples:*\n"
                 "• `/keeper-one-time-share kR3cF9Xm2Lp8NqT1uV6w Need to share with contractor John`\n"
                 "• `/keeper-one-time-share \"AWS Production Password\" Need to share with vendor`\n\n"
                 "*Tip:* Quotes are required for descriptions with spaces, but optional for UIDs"
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
                 f"*Usage:* `/keeper-one-time-share {identifier} <reason for creating share link>`"
        )
        return
    
    # Determine if UID or description
    is_uid = is_valid_uid(identifier)
    
    # Fetch record details if UID is provided
    record_details = None
    if is_uid:
        print(f"[INFO] Fetching record details for one-time share: {identifier}")
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
        
        # Check if UID is a folder (one-time-share only works for records)
        if record_details.record_type in ['folder', 'shared_folder', 'user_folder']:
            from ..utils import send_error_dm
            send_error_dm(
                client, user_id,
                "Invalid UID Type",
                f"The UID `{identifier}` is a **folder** (type: `{record_details.record_type}`), not a record.\n\n"
                f"⚠️ One-time share links can only be created for **records**, not folders.\n\n"
                f"Please use a record UID or description instead."
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
            request_type=RequestType.ONE_TIME_SHARE,
            justification=justification,
            duration="24h",  # Default suggestion (approver can change)
            record_details=record_details
        )
        
        # Send confirmation to user via DM
        from ..utils import send_success_dm
        send_success_dm(
            client, user_id,
            "One-Time Share request submitted!",
            f"Request ID: `{approval_id}`\n"
            f"Record: `{identifier}`\n"
            f"Justification: {justification}\n\n"
            f"Your request has been sent to <#{config.slack.approvals_channel_id}> for approval.\n"
            f"Once approved, the one-time share link will be sent to you via DM."
        )
            
    except Exception as e:
        print(f"Error posting one-time share request: {e}")
        
        # Send error message via DM
        from ..utils import send_error_dm
        send_error_dm(
            client, user_id,
            "Failed to submit one-time share request",
            f"Please try again or contact support.\n\nError: {str(e)}"
        )

