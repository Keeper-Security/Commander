#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import queue
import threading
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict

from ..util.command_util import CommandExecutor
from ..decorators.logging import logger, debug_decorator


# Queue configuration constants
DEFAULT_QUEUE_MAX_SIZE = 100
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes in seconds
DEFAULT_RESULT_RETENTION = 3600  # 1 hour in seconds


class RequestStatus(Enum):
    """Request status enumeration."""
    QUEUED = "queued"
    PROCESSING = "processing" 
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class QueuedRequest:
    """Represents a queued command request."""
    request_id: str
    command: str
    status: RequestStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None
    status_code: Optional[int] = None  # HTTP status code from command execution
    error_message: Optional[str] = None
    temp_files: list = None  # List of temporary file paths to clean up
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert request to dictionary for JSON serialization."""
        data = asdict(self)
        # Convert datetime objects to ISO strings and handle bytes objects
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, RequestStatus):
                data[key] = value.value
            elif isinstance(value, bytes):
                # Handle encrypted results - don't expose the raw bytes
                data[key] = {"encrypted": True, "type": "bytes"}
        return data


class RequestQueueManager:
    """Manages the request queue for sequential command processing."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize the queue manager."""
        if hasattr(self, '_initialized'):
            return
            
        self._initialized = True
        # Initialize with internal constants
        self.request_queue = queue.Queue(maxsize=DEFAULT_QUEUE_MAX_SIZE)
        self.active_requests: Dict[str, QueuedRequest] = {}
        self.completed_requests: Dict[str, QueuedRequest] = {}
        self.worker_thread = None
        self.is_running = False
        self.current_request_id = None
        self.request_timeout = DEFAULT_REQUEST_TIMEOUT
        self.result_retention = DEFAULT_RESULT_RETENTION
        self.data_lock = threading.Lock()  # Lock for shared data structures
        
        logger.debug("RequestQueueManager initialized")
    
    @debug_decorator
    def start(self):
        """Start the queue processing worker thread."""
        if self.worker_thread and self.worker_thread.is_alive():
            logger.warning("Queue worker already running")
            return
        
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()
        logger.debug("Request queue worker started")
    
    @debug_decorator
    def stop(self):
        """Stop the queue processing worker thread."""
        self.is_running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info("Request queue worker stopped")
    
    @debug_decorator
    def submit_request(self, command: str, temp_files: list = None) -> str:
        """Submit a new command request to the queue.
        
        Args:
            command: The command string to execute
            temp_files: List of temporary file paths to clean up after execution
            
        Returns:
            str: Unique request ID
            
        Raises:
            queue.Full: If the queue is at capacity
        """
        request_id = str(uuid.uuid4())
        request = QueuedRequest(
            request_id=request_id,
            command=command,
            status=RequestStatus.QUEUED,
            created_at=datetime.now(),
            temp_files=temp_files or []
        )
        
        try:
            self.request_queue.put(request, block=False)
            with self.data_lock:
                self.active_requests[request_id] = request
            logger.info(f"Request {request_id} queued: {command}")
            return request_id
        except queue.Full:
            logger.error("Error: Request queue is full")
            raise
    
    @debug_decorator
    def get_request_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a specific request.
        
        Args:
            request_id: The unique request identifier
            
        Returns:
            Dict containing request status and metadata, or None if not found
        """
        with self.data_lock:
            # Check active requests
            if request_id in self.active_requests:
                return self.active_requests[request_id].to_dict()
                
            # Check completed requests
            if request_id in self.completed_requests:
                return self.completed_requests[request_id].to_dict()
                
            return None
    
    @debug_decorator
    def get_request_result(self, request_id: str) -> Optional[Tuple[Any, int]]:
        """Get the result of a completed request.
        
        Args:
            request_id: The unique request identifier
            
        Returns:
            Tuple of (result, status_code) or None if not found/not completed
        """
        with self.data_lock:
            if request_id in self.completed_requests:
                request = self.completed_requests[request_id]
                if request.status == RequestStatus.COMPLETED:
                    status_code = request.status_code if request.status_code is not None else 200
                    return request.result, status_code
                elif request.status == RequestStatus.FAILED:
                    return {"error": request.error_message}, 500
            return None
    
    @debug_decorator
    def get_queue_status(self) -> Dict[str, Any]:
        """Get overall queue status information.
        
        Returns:
            Dict containing queue statistics
        """
        with self.data_lock:
            return {
                "queue_size": self.request_queue.qsize(),
                "active_requests": len(self.active_requests),
                "completed_requests": len(self.completed_requests),
                "currently_processing": self.current_request_id,
                "worker_running": self.is_running and self.worker_thread and self.worker_thread.is_alive()
            }
    
    def _process_queue(self):
        """Main worker thread loop for processing queued requests."""
        logger.debug("Queue worker thread started")
        
        while self.is_running:
            try:
                # Get next request from queue (blocking with timeout)
                request = self.request_queue.get(timeout=1.0)
                self._process_request(request)
                self.request_queue.task_done()
                
            except queue.Empty:
                # Check for expired requests during idle time
                self._cleanup_expired_requests()
                continue
            except Exception as e:
                logger.error(f"Unexpected error in queue worker: {e}")
                time.sleep(1)
        
        logger.info("Queue worker thread stopped")
    
    def _process_request(self, request: QueuedRequest):
        """Process a single request.
        
        Args:
            request: The request to process
        """
        from ..util.request_validation import RequestValidator
        
        self.current_request_id = request.request_id
        request.status = RequestStatus.PROCESSING
        request.started_at = datetime.now()
        
        logger.info(f"Processing request {request.request_id}: {request.command}")
        
        try:
            # Execute the command using existing CommandExecutor
            result, status_code = CommandExecutor.execute(request.command)
            
            # Mark as completed
            request.status = RequestStatus.COMPLETED
            request.completed_at = datetime.now()
            request.result = result
            request.status_code = status_code
            
            logger.info(f"Request {request.request_id} completed successfully")
            
        except Exception as e:
            # Mark as failed
            request.status = RequestStatus.FAILED
            request.completed_at = datetime.now()
            request.error_message = str(e)
            
            logger.error(f"Request {request.request_id} failed: {e}")
        
        finally:
            # Clean up temporary files
            if request.temp_files:
                RequestValidator.cleanup_temp_files(request.temp_files)
            
            # Move from active to completed
            with self.data_lock:
                if request.request_id in self.active_requests:
                    del self.active_requests[request.request_id]
                self.completed_requests[request.request_id] = request
                self.current_request_id = None
    
    def _cleanup_expired_requests(self):
        """Clean up expired and old completed requests."""
        now = datetime.now()
        
        with self.data_lock:
            # Find expired active requests
            expired_ids = []
            for request_id, request in self.active_requests.items():
                if request.status == RequestStatus.QUEUED:
                    age = (now - request.created_at).total_seconds()
                    if age > self.request_timeout:
                        request.status = RequestStatus.EXPIRED
                        expired_ids.append(request_id)
            
            # Move expired requests to completed
            for request_id in expired_ids:
                request = self.active_requests.pop(request_id)
                self.completed_requests[request_id] = request
                logger.warning(f"Request {request_id} expired after {self.request_timeout}s")
            
            # Clean up old completed requests
            cutoff_time = now - timedelta(seconds=self.result_retention)
            old_ids = []
            for request_id, request in self.completed_requests.items():
                if request.completed_at and request.completed_at < cutoff_time:
                    old_ids.append(request_id)
            
            for request_id in old_ids:
                del self.completed_requests[request_id]
                logger.debug(f"Cleaned up old request {request_id}")

queue_manager = RequestQueueManager()