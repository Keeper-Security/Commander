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

import uuid
import time
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from ..decorators.logging import logger
from .config import slack_config
from .slack_client import slack_client
from .message_builder import message_builder


class AccessRequest:
    """Represents an access request with approval workflow state."""
    
    def __init__(self, requester_email: str, record_uid: str, duration: str,
                 requester_slack_user: str = None, channel: str = None):
        self.request_id = str(uuid.uuid4())
        self.requester_email = requester_email
        self.requester_slack_user = requester_slack_user
        self.record_uid = record_uid
        self.duration = duration
        self.channel = channel
        self.created_at = datetime.utcnow()
        self.status = "pending"  # pending, approved, denied, expired
        self.approvals = []  # List of approver emails
        self.denials = []    # List of denier emails
        self.approval_message_ts = None  # Slack message timestamp for updates
        self.granted_at = None
        self.expires_at = None
        
    def add_approval(self, approver_email: str) -> bool:
        """Add an approval and return True if request should be processed."""
        if approver_email not in self.approvals:
            self.approvals.append(approver_email)
            logger.info(f"Request {self.request_id} approved by {approver_email}")
        
        required = slack_config.required_approvals
        return len(self.approvals) >= required and self.status == "pending"
    
    def add_denial(self, denier_email: str) -> bool:
        """Add a denial and return True if request should be processed."""
        if denier_email not in self.denials:
            self.denials.append(denier_email)
            logger.info(f"Request {self.request_id} denied by {denier_email}")
        
        return self.status == "pending"
    
    def is_expired(self) -> bool:
        """Check if the access request has expired (for cleanup)."""
        # Consider pending requests expired after 24 hours
        if self.status == "pending":
            return (datetime.utcnow() - self.created_at) > timedelta(hours=24)
        
        # Check if granted access has expired
        if self.status == "approved" and self.expires_at:
            return datetime.utcnow() > self.expires_at
        
        return False
    
    def get_expiration_time(self) -> Optional[datetime]:
        """Parse duration and return expiration datetime."""
        try:
            duration = self.duration.lower().strip()
            
            # Parse duration format (e.g., "30m", "2h", "1d")
            if duration.endswith('m'):
                minutes = int(duration[:-1])
                return datetime.utcnow() + timedelta(minutes=minutes)
            elif duration.endswith('h'):
                hours = int(duration[:-1])
                return datetime.utcnow() + timedelta(hours=hours)
            elif duration.endswith('d'):
                days = int(duration[:-1])
                return datetime.utcnow() + timedelta(days=days)
            else:
                # Default to 30 minutes if format is unclear
                return datetime.utcnow() + timedelta(minutes=30)
                
        except (ValueError, IndexError):
            logger.warning(f"Invalid duration format: {self.duration}, defaulting to 30 minutes")
            return datetime.utcnow() + timedelta(minutes=30)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert request to dictionary for logging/debugging."""
        return {
            'request_id': self.request_id,
            'requester_email': self.requester_email,
            'record_uid': self.record_uid,
            'duration': self.duration,
            'status': self.status,
            'approvals': self.approvals,
            'denials': self.denials,
            'created_at': self.created_at.isoformat(),
            'granted_at': self.granted_at.isoformat() if self.granted_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }


class ApprovalManager:
    """Manages approval workflow and in-memory request storage."""
    
    def __init__(self):
        self.requests: Dict[str, AccessRequest] = {}
        self.lock = threading.RLock()
        
    def create_request(self, requester_email: str, record_uid: str, duration: str,
                      requester_slack_user: str = None) -> Optional[AccessRequest]:
        """Create a new access request."""
        
        # Validate requester eligibility
        if not slack_config.is_eligible_requestor(requester_email):
            logger.warning(f"Ineligible requestor: {requester_email}")
            return None
        
        # Validate record UID format (basic check)
        if not record_uid or len(record_uid.strip()) == 0:
            logger.warning(f"Invalid record UID: {record_uid}")
            return None
        
        with self.lock:
            request = AccessRequest(
                requester_email=requester_email,
                record_uid=record_uid.strip(),
                duration=duration,
                requester_slack_user=requester_slack_user
            )
            
            self.requests[request.request_id] = request
            logger.info(f"Created access request {request.request_id} for {requester_email}")
            
            return request
    
    def get_request(self, request_id: str) -> Optional[AccessRequest]:
        """Get request by ID."""
        with self.lock:
            return self.requests.get(request_id)
    
    def process_approval(self, request_id: str, approver_email: str, 
                        approver_slack_user: str) -> Optional[AccessRequest]:
        """Process an approval and return request if ready for access grant."""
        
        # Validate approver eligibility  
        if not slack_config.is_approver(approver_email):
            logger.warning(f"Ineligible approver: {approver_email}")
            return None
        
        with self.lock:
            request = self.requests.get(request_id)
            if not request:
                logger.warning(f"Request not found: {request_id}")
                return None
            
            # Check if already approved/denied
            if request.status != "pending":
                logger.info(f"Request {request_id} already {request.status}")
                return request
            
            # Don't allow self-approval
            if approver_email.lower() == request.requester_email.lower():
                logger.warning(f"Self-approval attempt by {approver_email} for request {request_id}")
                return None
            
            # Add approval
            should_grant = request.add_approval(approver_email)
            
            if should_grant:
                request.status = "approved"
                request.granted_at = datetime.utcnow()
                request.expires_at = request.get_expiration_time()
                logger.info(f"Request {request_id} approved with sufficient approvals")
            
            return request
    
    def process_denial(self, request_id: str, denier_email: str,
                      denier_slack_user: str) -> Optional[AccessRequest]:
        """Process a denial and return request."""
        
        # Validate denier eligibility
        if not slack_config.is_approver(denier_email):
            logger.warning(f"Ineligible denier: {denier_email}")
            return None
        
        with self.lock:
            request = self.requests.get(request_id)
            if not request:
                logger.warning(f"Request not found: {request_id}")
                return None
            
            # Check if already processed
            if request.status != "pending":
                logger.info(f"Request {request_id} already {request.status}")
                return request
            
            # Add denial
            should_deny = request.add_denial(denier_email)
            
            if should_deny:
                request.status = "denied"
                logger.info(f"Request {request_id} denied by {denier_email}")
            
            return request
    
    def get_expiring_requests(self) -> List[AccessRequest]:
        """Get requests that need access revocation."""
        with self.lock:
            expiring = []
            for request in self.requests.values():
                if request.status == "approved" and request.is_expired():
                    expiring.append(request)
            return expiring
    
    def mark_expired(self, request_id: str):
        """Mark a request as expired."""
        with self.lock:
            request = self.requests.get(request_id)
            if request:
                request.status = "expired"
                logger.info(f"Request {request_id} marked as expired")
    
    def cleanup_old_requests(self):
        """Remove old completed/expired requests from memory."""
        with self.lock:
            to_remove = []
            cutoff = datetime.utcnow() - timedelta(hours=48)  # Keep for 48 hours
            
            for request_id, request in self.requests.items():
                if request.status in ["denied", "expired"] and request.created_at < cutoff:
                    to_remove.append(request_id)
                elif request.status == "approved" and request.is_expired():
                    # Mark as expired but don't remove yet (for cleanup notification)
                    request.status = "expired"
            
            for request_id in to_remove:
                del self.requests[request_id]
                logger.debug(f"Cleaned up old request {request_id}")
    
    def get_pending_requests_count(self) -> int:
        """Get count of pending requests."""
        with self.lock:
            return sum(1 for r in self.requests.values() if r.status == "pending")
    
    def get_active_requests_count(self) -> int:
        """Get count of active (approved, non-expired) requests."""
        with self.lock:
            return sum(1 for r in self.requests.values() 
                      if r.status == "approved" and not r.is_expired())
    
    def send_approval_request(self, request: AccessRequest) -> bool:
        """Send approval request to Slack channel."""
        try:
            if not slack_config.approval_channel:
                logger.error("No approval channel configured")
                return False
            
            message_data = message_builder.build_approval_request(
                request.request_id,
                request.requester_email,
                request.record_uid,
                request.duration,
                slack_config.required_approvals
            )
            
            response = slack_client.post_message(
                channel=slack_config.approval_channel,
                **message_data
            )
            
            # Store message timestamp for future updates
            request.approval_message_ts = response.get('ts')
            request.channel = slack_config.approval_channel
            
            logger.info(f"Sent approval request {request.request_id} to Slack")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send approval request {request.request_id}: {e}")
            return False
    
    def update_approval_message(self, request: AccessRequest):
        """Update the approval message in Slack with current status."""
        try:
            if not request.approval_message_ts or not request.channel:
                logger.warning(f"Cannot update message for request {request.request_id} - missing message info")
                return
            
            message_data = message_builder.build_approval_update(
                request.request_id,
                request.requester_email, 
                request.record_uid,
                request.duration,
                request.approvals,
                request.denials,
                slack_config.required_approvals,
                request.status
            )
            
            slack_client.update_message(
                channel=request.channel,
                ts=request.approval_message_ts,
                **message_data
            )
            
            logger.debug(f"Updated approval message for request {request.request_id}")
            
        except Exception as e:
            logger.error(f"Failed to update approval message for request {request.request_id}: {e}")
    
    def notify_requester(self, request: AccessRequest, notification_type: str):
        """Send notification to requester via DM."""
        try:
            if not request.requester_slack_user:
                logger.warning(f"Cannot notify requester for {request.request_id} - no Slack user ID")
                return
            
            if notification_type == "approved":
                message_data = message_builder.build_access_granted(
                    request.record_uid,
                    request.duration
                )
            elif notification_type == "denied":
                message_data = message_builder.build_access_denied(
                    request.record_uid
                )
            elif notification_type == "expired":
                message_data = message_builder.build_access_expired(
                    request.record_uid
                )
            else:
                logger.warning(f"Unknown notification type: {notification_type}")
                return
            
            # Send as ephemeral message to approval channel
            if request.channel:
                slack_client.post_ephemeral(
                    channel=request.channel,
                    user=request.requester_slack_user,
                    **message_data
                )
            
            logger.info(f"Sent {notification_type} notification to requester for {request.request_id}")
            
        except Exception as e:
            logger.error(f"Failed to notify requester for {request.request_id}: {e}")


# Global approval manager instance
approval_manager = ApprovalManager()
