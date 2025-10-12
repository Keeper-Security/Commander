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

import threading
import time
from typing import Optional
from ..decorators.logging import logger
from ..util.command_util import CommandExecutor
from .approval_manager import approval_manager
from .config import slack_config


class SlackScheduledTasks:
    """Background task manager for Slack integration."""
    
    def __init__(self):
        self.worker_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.is_running = False
        
    def start(self):
        """Start the background task worker."""
        if self.is_running:
            logger.warning("Slack scheduled tasks already running")
            return
        
        self.stop_event.clear()
        self.worker_thread = threading.Thread(
            target=self._worker_loop,
            name="SlackScheduledTasks",
            daemon=True
        )
        self.worker_thread.start()
        self.is_running = True
        logger.info("Started Slack scheduled tasks worker")
    
    def stop(self):
        """Stop the background task worker."""
        if not self.is_running:
            return
        
        logger.info("Stopping Slack scheduled tasks worker")
        self.stop_event.set()
        
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=10)
        
        self.is_running = False
        logger.info("Stopped Slack scheduled tasks worker")
    
    def _worker_loop(self):
        """Main worker loop that runs background tasks."""
        logger.info("Slack scheduled tasks worker started")
        
        while not self.stop_event.is_set():
            try:
                # Run cleanup tasks every 5 minutes
                self._process_expiring_access()
                self._cleanup_old_requests()
                
                # Wait 5 minutes or until stop signal
                self.stop_event.wait(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Error in Slack scheduled tasks worker: {e}")
                # Continue running even if there's an error
                self.stop_event.wait(60)  # Wait 1 minute before retry
        
        logger.info("Slack scheduled tasks worker stopped")
    
    def _process_expiring_access(self):
        """Process access requests that have expired."""
        try:
            expiring_requests = approval_manager.get_expiring_requests()
            
            if not expiring_requests:
                return
            
            logger.info(f"Processing {len(expiring_requests)} expiring access requests")
            
            for request in expiring_requests:
                try:
                    # Revoke access via Commander
                    success = self._revoke_record_access(request.requester_email, request.record_uid)
                    
                    if success:
                        # Mark as expired
                        approval_manager.mark_expired(request.request_id)
                        
                        # Notify requester
                        approval_manager.notify_requester(request, "expired")
                        
                        logger.info(f"Revoked expired access for request {request.request_id}")
                    else:
                        logger.error(f"Failed to revoke access for request {request.request_id}")
                        
                except Exception as e:
                    logger.error(f"Error processing expiring request {request.request_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing expiring access: {e}")
    
    def _cleanup_old_requests(self):
        """Clean up old completed requests from memory."""
        try:
            approval_manager.cleanup_old_requests()
        except Exception as e:
            logger.error(f"Error cleaning up old requests: {e}")
    
    def _revoke_record_access(self, user_email: str, record_uid: str) -> bool:
        """Revoke record access using Commander share-record command."""
        try:
            command = f"share-record -a revoke -e {user_email} {record_uid}"
            
            logger.debug(f"Executing revoke command: {command}")
            response, status_code = CommandExecutor.execute(command)
            
            if status_code == 200:
                logger.info(f"Successfully revoked access to {record_uid} for {user_email}")
                return True
            else:
                logger.error(f"Failed to revoke access: status {status_code}, response: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing revoke command: {e}")
            return False
    
    def grant_record_access(self, user_email: str, record_uid: str, duration: str) -> bool:
        """Grant record access using Commander share-record command."""
        try:
            # Build command with view-only permissions and expiration
            command = f"share-record -e {user_email} --expire-in {duration} {record_uid}"
            
            logger.debug(f"Executing grant command: {command}")
            response, status_code = CommandExecutor.execute(command)
            
            if status_code == 200:
                logger.info(f"Successfully granted access to {record_uid} for {user_email}")
                return True
            else:
                logger.error(f"Failed to grant access: status {status_code}, response: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing grant command: {e}")
            return False
    
    def validate_record_exists(self, record_uid: str) -> bool:
        """Validate that a record exists and is accessible."""
        try:
            # Use 'get' command to check if record exists
            command = f"get {record_uid}"
            
            logger.debug(f"Validating record existence: {command}")
            response, status_code = CommandExecutor.execute(command)
            
            # If we get a 200 response, record exists and is accessible
            if status_code == 200:
                return True
            else:
                logger.warning(f"Record validation failed: status {status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error validating record {record_uid}: {e}")
            return False
    
    def get_status(self) -> dict:
        """Get status information about the scheduled tasks."""
        return {
            "is_running": self.is_running,
            "worker_alive": self.worker_thread.is_alive() if self.worker_thread else False,
            "pending_requests": approval_manager.get_pending_requests_count(),
            "active_requests": approval_manager.get_active_requests_count()
        }


# Global scheduled tasks instance
scheduled_tasks = SlackScheduledTasks()
