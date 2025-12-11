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

"""Handlers for PEDM approval interactions."""

from typing import Dict, Any


def handle_approve_pedm_request(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle PEDM approve button click.
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract approval UID from button value
    approval_uid = body["actions"][0]["value"]
    
    print(f"[INFO] PEDM approval action by {approver_name} for {approval_uid}")
    
    try:
        # Approve the PEDM request
        result = keeper_client.approve_pedm_request(approval_uid)
        
        if result.get('success'):
            # Update approval message
            status_text = f"*Status:* Approved by <@{approver_id}>\n*Updated:* {_format_timestamp()}"
            
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            
            # Add status section
            updated_blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": status_text
                }
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            print(f"[OK] PEDM request {approval_uid} approved by {approver_id}")
        else:
            # Update with error
            error_msg = result.get('error', 'Unknown error')
            status_text = f"*Status:* Approval failed - {error_msg}"
            
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            updated_blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": status_text}
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            print(f"[ERROR] Failed to approve PEDM request {approval_uid}: {error_msg}")
            
    except Exception as e:
        print(f"[ERROR] Exception in PEDM approve handler: {e}")
        import traceback
        traceback.print_exc()


def handle_deny_pedm_request(body: Dict[str, Any], client, config, keeper_client):
    """
    Handle PEDM deny button click.
    
    Denies the PEDM request and updates the card.
    """
    approver_id = body["user"]["id"]
    approver_name = body["user"]["name"]
    
    # Extract approval UID from button value
    approval_uid = body["actions"][0]["value"]
    
    print(f"[INFO] PEDM denial action by {approver_name} for {approval_uid}")
    
    try:
        # Deny the PEDM request
        result = keeper_client.deny_pedm_request(approval_uid)
        
        if result.get('success'):
            # Update approval message
            status_text = f"*Status:* Denied by <@{approver_id}>\n*Updated:* {_format_timestamp()}"
            
            # Remove action buttons
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            
            # Add status section
            updated_blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": status_text
                }
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            print(f"[OK] PEDM request {approval_uid} denied by {approver_id}")
        else:
            # Update with error
            error_msg = result.get('error', 'Unknown error')
            status_text = f"*Status:* Denial failed - {error_msg}"
            
            original_blocks = body["message"]["blocks"]
            updated_blocks = [b for b in original_blocks if b.get("type") != "actions"]
            updated_blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": status_text}
            })
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks,
                text=status_text
            )
            
            print(f"[ERROR] Failed to deny PEDM request {approval_uid}: {error_msg}")
            
    except Exception as e:
        print(f"[ERROR] Exception in PEDM deny handler: {e}")
        import traceback
        traceback.print_exc()


def _format_timestamp() -> str:
    """Format current timestamp for display."""
    from datetime import datetime
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

