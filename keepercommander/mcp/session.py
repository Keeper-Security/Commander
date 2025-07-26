#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander MCP Server
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Session management for MCP server to handle stateful commands."""

import threading
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import uuid

from ..params import KeeperParams


class MCPSession:
    """Represents a single MCP session with its own state"""
    
    def __init__(self, session_id: str, base_params: KeeperParams):
        self.session_id = session_id
        self.created_at = datetime.utcnow()
        self.last_accessed = datetime.utcnow()
        
        # Clone params to avoid sharing state between sessions
        self.params = KeeperParams()
        self.params.__dict__.update(base_params.__dict__.copy())
        
        # Session-specific state
        self.current_folder = None  # For cd command
        self.context = {}  # Additional context storage
    
    def touch(self):
        """Update last accessed time"""
        self.last_accessed = datetime.utcnow()
    
    def is_expired(self, timeout_minutes: int = 30) -> bool:
        """Check if session has expired"""
        return datetime.utcnow() - self.last_accessed > timedelta(minutes=timeout_minutes)


class SessionManager:
    """Manages MCP sessions for stateful command execution"""
    
    def __init__(self, base_params: KeeperParams, session_timeout: int = 30):
        self.base_params = base_params
        self.session_timeout = session_timeout
        self.sessions: Dict[str, MCPSession] = {}
        self._lock = threading.Lock()
    
    def get_or_create_session(self, session_id: Optional[str] = None) -> MCPSession:
        """Get existing session or create new one"""
        with self._lock:
            # Clean up expired sessions
            self._cleanup_expired()
            
            if not session_id:
                session_id = str(uuid.uuid4())
            
            if session_id not in self.sessions:
                self.sessions[session_id] = MCPSession(session_id, self.base_params)
            
            session = self.sessions[session_id]
            session.touch()
            return session
    
    def get_session(self, session_id: str) -> Optional[MCPSession]:
        """Get existing session by ID"""
        with self._lock:
            session = self.sessions.get(session_id)
            if session and not session.is_expired(self.session_timeout):
                session.touch()
                return session
            return None
    
    def remove_session(self, session_id: str):
        """Remove a session"""
        with self._lock:
            self.sessions.pop(session_id, None)
    
    def _cleanup_expired(self):
        """Remove expired sessions"""
        expired = [
            sid for sid, session in self.sessions.items()
            if session.is_expired(self.session_timeout)
        ]
        for sid in expired:
            del self.sessions[sid]
    
    def get_active_session_count(self) -> int:
        """Get count of active sessions"""
        with self._lock:
            self._cleanup_expired()
            return len(self.sessions)
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get information about all sessions"""
        with self._lock:
            self._cleanup_expired()
            return {
                'active_sessions': len(self.sessions),
                'session_timeout_minutes': self.session_timeout,
                'sessions': [
                    {
                        'id': session.session_id,
                        'created': session.created_at.isoformat(),
                        'last_accessed': session.last_accessed.isoformat(),
                        'current_folder': session.current_folder
                    }
                    for session in self.sessions.values()
                ]
            }