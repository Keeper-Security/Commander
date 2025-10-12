#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from typing import Dict, Any, List
from datetime import datetime
from .config import slack_config


class SlackMessageBuilder:
    """Builder for Slack message formats used in approval workflow."""
    
    @staticmethod
    def build_approval_request(request_id: str, requester_email: str, 
                             record_uid: str, duration: str, 
                             required_approvals: int) -> Dict[str, Any]:
        """Build approval request message with interactive buttons."""
        
        approval_text = f"{required_approvals} approval{'s' if required_approvals != 1 else ''}"
        
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🔐 Keeper Record Access Request"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Requester:*\n{requester_email}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Record UID:*\n`{record_uid}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Duration:*\n{duration}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Required:*\n{approval_text}"
                        }
                    ]
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "✅ Approve"
                            },
                            "style": "primary",
                            "action_id": "approve",
                            "value": request_id
                        },
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "❌ Deny"
                            },
                            "style": "danger",
                            "action_id": "deny",
                            "value": request_id
                        }
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Request ID: `{request_id}`"
                        }
                    ]
                }
            ]
        }
    
    @staticmethod
    def build_approval_update(request_id: str, requester_email: str, 
                            record_uid: str, duration: str, 
                            approvals: List[str], denials: List[str],
                            required_approvals: int, status: str) -> Dict[str, Any]:
        """Build updated approval message showing current status."""
        
        approval_text = f"{required_approvals} approval{'s' if required_approvals != 1 else ''}"
        
        # Build status fields
        status_fields = [
            {
                "type": "mrkdwn",
                "text": f"*Requester:*\n{requester_email}"
            },
            {
                "type": "mrkdwn", 
                "text": f"*Record UID:*\n`{record_uid}`"
            },
            {
                "type": "mrkdwn",
                "text": f"*Duration:*\n{duration}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Required:*\n{approval_text}"
            }
        ]
        
        if approvals:
            status_fields.append({
                "type": "mrkdwn",
                "text": f"*Approved by:*\n{', '.join(approvals)}"
            })
            
        if denials:
            status_fields.append({
                "type": "mrkdwn",
                "text": f"*Denied by:*\n{', '.join(denials)}"
            })
        
        # Choose header based on status
        if status == "approved":
            header_text = "✅ Access Request APPROVED"
            header_style = "header"
        elif status == "denied":
            header_text = "❌ Access Request DENIED"
            header_style = "header"
        else:
            header_text = "🔐 Keeper Record Access Request"
            header_style = "header"
        
        blocks = [
            {
                "type": header_style,
                "text": {
                    "type": "plain_text",
                    "text": header_text
                }
            },
            {
                "type": "section",
                "fields": status_fields
            }
        ]
        
        # Add buttons only if still pending
        if status == "pending":
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ Approve"
                        },
                        "style": "primary",
                        "action_id": "approve",
                        "value": request_id
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "❌ Deny"
                        },
                        "style": "danger",
                        "action_id": "deny",
                        "value": request_id
                    }
                ]
            })
        
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Request ID: `{request_id}`"
                }
            ]
        })
        
        return {"blocks": blocks}
    
    @staticmethod
    def build_access_granted(record_uid: str, duration: str, vault_url: str = None) -> Dict[str, Any]:
        """Build access granted notification for requester."""
        
        if not vault_url:
            vault_url = slack_config.vault_url
        
        # Build vault link with record UID
        record_link = f"{vault_url}#detail/{record_uid}"
        
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "✅ Access Granted!"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Your request for access to record `{record_uid}` has been approved."
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Record UID:*\n`{record_uid}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Access Duration:*\n{duration}"
                        }
                    ]
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "🔗 Open in Vault"
                            },
                            "style": "primary",
                            "url": record_link
                        }
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "⚠️ You have view-only access. Access will be automatically revoked when the duration expires."
                        }
                    ]
                }
            ]
        }
    
    @staticmethod
    def build_access_denied(record_uid: str, reason: str = None) -> Dict[str, Any]:
        """Build access denied notification for requester."""
        
        reason_text = f": {reason}" if reason else ""
        
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "❌ Access Denied"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Your request for access to record `{record_uid}` has been denied{reason_text}."
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "If you believe this is in error, please contact your administrator."
                        }
                    ]
                }
            ]
        }
    
    @staticmethod
    def build_access_expired(record_uid: str) -> Dict[str, Any]:
        """Build access expiration notification for requester."""
        
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "⏰ Access Expired"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Your temporary access to record `{record_uid}` has expired and been revoked."
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "Request new access if you still need it."
                        }
                    ]
                }
            ]
        }
    
    @staticmethod
    def build_error_message(error_message: str) -> Dict[str, Any]:
        """Build generic error message."""
        
        return {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"❌ *Error:* {error_message}"
                    }
                }
            ]
        }
    
    @staticmethod
    def build_help_message() -> Dict[str, Any]:
        """Build help message showing usage instructions."""
        
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🤖 Keeper Commander Bot Help"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Request access to a Keeper record:*"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "`@keeper-bot request access <record_uid> for <duration>`"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Examples:*\n• `@keeper-bot request access ABC123 for 30m`\n• `@keeper-bot request access DEF456 for 2h`\n• `@keeper-bot request access GHI789 for 1d`"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Duration formats:*\n• `30m` = 30 minutes\n• `2h` = 2 hours\n• `1d` = 1 day"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "Access requests require approval and grant view-only access that expires automatically."
                        }
                    ]
                }
            ]
        }


# Global message builder instance  
message_builder = SlackMessageBuilder()
