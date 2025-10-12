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

import json
import hmac
import hashlib
import time
import re
from flask import Blueprint, request, jsonify, Response
from typing import Tuple, Dict, Any, Optional
from urllib.parse import parse_qs
from ..decorators.logging import logger
from ..slack import slack_config, slack_client, approval_manager, message_builder, scheduled_tasks


def create_slack_blueprint():
    """Create blueprint for Slack webhook endpoints."""
    bp = Blueprint("slack_bp", __name__)
    
    def verify_slack_signature(request_body: bytes, timestamp: str, signature: str) -> bool:
        """Verify Slack request signature for security."""
        if not slack_config.signing_secret:
            logger.warning("Slack signing secret not configured - skipping signature verification")
            return True
        
        # Check timestamp to prevent replay attacks (within 5 minutes)
        if abs(time.time() - int(timestamp)) > 300:
            logger.warning("Slack request timestamp too old")
            return False
        
        # Build signature
        sig_basestring = f"v0:{timestamp}:{request_body.decode('utf-8')}"
        expected_signature = 'v0=' + hmac.new(
            slack_config.signing_secret.encode(),
            sig_basestring.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures
        return hmac.compare_digest(expected_signature, signature)
    
    def get_user_email_from_slack_id(slack_user_id: str) -> Optional[str]:
        """Get user email from Slack user ID."""
        try:
            user_info = slack_client.get_user_info(slack_user_id)
            return user_info.get('user', {}).get('profile', {}).get('email')
        except Exception as e:
            logger.error(f"Failed to get user email for {slack_user_id}: {e}")
            return None
    
    def parse_access_request(text: str) -> Optional[Tuple[str, str]]:
        """Parse access request from Slack message text."""
        # Pattern: request access <record_uid> for <duration>
        pattern = r'request\s+access\s+([A-Za-z0-9_-]+)\s+for\s+(\d+[mhd])'
        
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2)
        
        return None
    
    @bp.route("/events", methods=["POST"])
    def handle_events() -> Tuple[Response, int]:
        """Handle Slack Events API."""
        try:
            # Verify request signature
            timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
            signature = request.headers.get('X-Slack-Signature', '')
            request_body = request.get_data()
            
            if not verify_slack_signature(request_body, timestamp, signature):
                logger.warning("Invalid Slack signature")
                return jsonify({"error": "Invalid signature"}), 401
            
            data = request.get_json()
            
            # Handle URL verification challenge
            if data.get('type') == 'url_verification':
                return jsonify({"challenge": data.get('challenge')}), 200
            
            # Handle event callbacks
            if data.get('type') == 'event_callback':
                event = data.get('event', {})
                
                # Handle app mentions
                if event.get('type') == 'app_mention':
                    return handle_app_mention(event)
                
                # Handle direct messages
                elif event.get('type') == 'message' and event.get('channel_type') == 'im':
                    return handle_direct_message(event)
            
            return jsonify({"status": "ok"}), 200
            
        except Exception as e:
            logger.error(f"Error handling Slack event: {e}")
            return jsonify({"error": "Internal error"}), 500
    
    @bp.route("/interactive", methods=["POST"])
    def handle_interactive() -> Tuple[Response, int]:
        """Handle Slack interactive components (buttons, etc.)."""
        try:
            # Verify request signature
            timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
            signature = request.headers.get('X-Slack-Signature', '')
            request_body = request.get_data()
            
            if not verify_slack_signature(request_body, timestamp, signature):
                logger.warning("Invalid Slack signature")
                return jsonify({"error": "Invalid signature"}), 401
            
            # Parse form data
            form_data = request.form.get('payload')
            if not form_data:
                return jsonify({"error": "No payload"}), 400
            
            data = json.loads(form_data)
            
            # Handle button interactions
            if data.get('type') == 'block_actions':
                return handle_button_click(data)
            
            return jsonify({"status": "ok"}), 200
            
        except Exception as e:
            logger.error(f"Error handling interactive component: {e}")
            return jsonify({"error": "Internal error"}), 500
    
    @bp.route("/status", methods=["GET"])
    def slack_status() -> Tuple[Response, int]:
        """Get Slack integration status."""
        try:
            status = {
                "configured": slack_config.is_configured(),
                "bot_token_present": bool(slack_config.bot_token),
                "signing_secret_present": bool(slack_config.signing_secret),
                "approval_channel": slack_config.approval_channel,
                "required_approvals": slack_config.required_approvals,
                "eligible_requestors_count": len(slack_config.eligible_requestors or []),
                "approvers_count": len(slack_config.approvers or []),
                "scheduled_tasks": scheduled_tasks.get_status()
            }
            
            return jsonify(status), 200
            
        except Exception as e:
            logger.error(f"Error getting Slack status: {e}")
            return jsonify({"error": "Internal error"}), 500
    
    def handle_app_mention(event: Dict[str, Any]) -> Tuple[Response, int]:
        """Handle app mention events."""
        try:
            text = event.get('text', '').lower()
            user = event.get('user')
            channel = event.get('channel')
            
            if not user:
                return jsonify({"status": "ok"}), 200
            
            # Get user email
            user_email = get_user_email_from_slack_id(user)
            if not user_email:
                logger.warning(f"Could not get email for Slack user {user}")
                return jsonify({"status": "ok"}), 200
            
            # Check for help request
            if 'help' in text:
                message_data = message_builder.build_help_message()
                slack_client.post_ephemeral(
                    channel=channel,
                    user=user,
                    **message_data
                )
                return jsonify({"status": "ok"}), 200
            
            # Parse access request
            request_info = parse_access_request(text)
            if not request_info:
                error_msg = message_builder.build_error_message(
                    "Invalid request format. Use: `@keeper-bot request access <record_uid> for <duration>`"
                )
                slack_client.post_ephemeral(
                    channel=channel,
                    user=user,
                    **error_msg
                )
                return jsonify({"status": "ok"}), 200
            
            record_uid, duration = request_info
            
            # Validate record exists
            if not scheduled_tasks.validate_record_exists(record_uid):
                error_msg = message_builder.build_error_message(
                    f"Record `{record_uid}` not found or not accessible."
                )
                slack_client.post_ephemeral(
                    channel=channel,
                    user=user,
                    **error_msg
                )
                return jsonify({"status": "ok"}), 200
            
            # Create access request
            access_request = approval_manager.create_request(
                requester_email=user_email,
                record_uid=record_uid,
                duration=duration,
                requester_slack_user=user
            )
            
            if not access_request:
                error_msg = message_builder.build_error_message(
                    "You are not authorized to request access to records."
                )
                slack_client.post_ephemeral(
                    channel=channel,
                    user=user,
                    **error_msg
                )
                return jsonify({"status": "ok"}), 200
            
            # Send approval request to designated channel
            success = approval_manager.send_approval_request(access_request)
            
            if success:
                # Confirm to user
                slack_client.post_ephemeral(
                    channel=channel,
                    user=user,
                    text=f"✅ Access request submitted for record `{record_uid}`. You will be notified when approved."
                )
            else:
                error_msg = message_builder.build_error_message(
                    "Failed to submit access request. Please try again later."
                )
                slack_client.post_ephemeral(
                    channel=channel,
                    user=user,
                    **error_msg
                )
            
            return jsonify({"status": "ok"}), 200
            
        except Exception as e:
            logger.error(f"Error handling app mention: {e}")
            return jsonify({"status": "ok"}), 200
    
    def handle_direct_message(event: Dict[str, Any]) -> Tuple[Response, int]:
        """Handle direct message events."""
        # For now, just respond with help message for DMs
        try:
            user = event.get('user')
            channel = event.get('channel')
            
            if user and channel:
                message_data = message_builder.build_help_message()
                slack_client.post_message(
                    channel=channel,
                    **message_data
                )
            
            return jsonify({"status": "ok"}), 200
            
        except Exception as e:
            logger.error(f"Error handling direct message: {e}")
            return jsonify({"status": "ok"}), 200
    
    def handle_button_click(data: Dict[str, Any]) -> Tuple[Response, int]:
        """Handle approval/denial button clicks."""
        try:
            actions = data.get('actions', [])
            if not actions:
                return jsonify({"status": "ok"}), 200
            
            action = actions[0]
            action_id = action.get('action_id')
            request_id = action.get('value')
            
            user = data.get('user', {})
            user_id = user.get('id')
            
            if not all([action_id, request_id, user_id]):
                return jsonify({"status": "ok"}), 200
            
            # Get user email
            user_email = get_user_email_from_slack_id(user_id)
            if not user_email:
                logger.warning(f"Could not get email for approver {user_id}")
                return jsonify({"status": "ok"}), 200
            
            # Process approval or denial
            if action_id == "approve":
                request_obj = approval_manager.process_approval(request_id, user_email, user_id)
            elif action_id == "deny":
                request_obj = approval_manager.process_denial(request_id, user_email, user_id)
            else:
                logger.warning(f"Unknown action: {action_id}")
                return jsonify({"status": "ok"}), 200
            
            if not request_obj:
                return jsonify({"status": "ok"}), 200
            
            # Update the approval message
            approval_manager.update_approval_message(request_obj)
            
            # If approved, grant access
            if request_obj.status == "approved":
                success = scheduled_tasks.grant_record_access(
                    request_obj.requester_email,
                    request_obj.record_uid,
                    request_obj.duration
                )
                
                if success:
                    # Notify requester of approval
                    approval_manager.notify_requester(request_obj, "approved")
                else:
                    logger.error(f"Failed to grant access for request {request_id}")
            
            # If denied, notify requester
            elif request_obj.status == "denied":
                approval_manager.notify_requester(request_obj, "denied")
            
            return jsonify({"status": "ok"}), 200
            
        except Exception as e:
            logger.error(f"Error handling button click: {e}")
            return jsonify({"status": "ok"}), 200
    
    return bp
