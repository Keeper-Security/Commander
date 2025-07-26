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

"""Permission management for MCP server."""

import time
from typing import Dict, List, Set, Optional
from collections import defaultdict
from threading import Lock

from .utils import matches_pattern, PermissionDeniedError, RateLimitError


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, requests_per_minute: int = 60, burst: int = 10):
        self.rate = requests_per_minute / 60.0  # requests per second
        self.burst = burst
        self.tokens = float(burst)
        self.last_update = time.time()
        self.lock = Lock()
    
    def is_allowed(self) -> bool:
        """Check if request is allowed under rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            
            # Add tokens based on elapsed time
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            
            return False


class PermissionManager:
    """Manages command permissions and rate limiting for MCP server"""
    
    def __init__(self, config: Dict):
        self.config = config or {}
        
        # Permission settings
        permissions = self.config.get('permissions', {})
        self.allowed_commands = set(permissions.get('allowed_commands', ['whoami']))
        self.deny_patterns = permissions.get('deny_patterns', ['login', '*2fa*', 'accept', 'decline'])
        
        # Rate limiting
        rate_config = permissions.get('rate_limit', {})
        self.rate_limiter = RateLimiter(
            requests_per_minute=rate_config.get('requests_per_minute', 60),
            burst=rate_config.get('burst', 10)
        )
        
        # Per-command rate limiters for specific limits
        self.command_limiters: Dict[str, RateLimiter] = {}
        command_limits = permissions.get('command_rate_limits', {})
        for cmd, limit in command_limits.items():
            self.command_limiters[cmd] = RateLimiter(
                requests_per_minute=limit.get('requests_per_minute', 60),
                burst=limit.get('burst', 10)
            )
    
    def is_command_allowed(self, command: str) -> bool:
        """Check if a command is allowed by permissions"""
        # Check deny patterns first
        if matches_pattern(command, self.deny_patterns):
            return False
        
        # Check if command is in allowed list
        return command in self.allowed_commands
    
    def check_rate_limit(self, command: str) -> None:
        """Check rate limit for command, raise RateLimitError if exceeded"""
        # Check global rate limit
        if not self.rate_limiter.is_allowed():
            raise RateLimitError(
                "Global rate limit exceeded",
                {"command": command, "limit": "global"}
            )
        
        # Check command-specific rate limit if exists
        if command in self.command_limiters:
            if not self.command_limiters[command].is_allowed():
                raise RateLimitError(
                    f"Rate limit exceeded for command: {command}",
                    {"command": command, "limit": "command"}
                )
    
    def validate_access(self, command: str) -> None:
        """Validate full access for a command (permissions + rate limit)"""
        # Check permissions
        if not self.is_command_allowed(command):
            raise PermissionDeniedError(
                f"Command '{command}' is not allowed",
                {"command": command, "allowed_commands": list(self.allowed_commands)}
            )
        
        # Check rate limit
        self.check_rate_limit(command)
    
    def add_allowed_command(self, command: str) -> None:
        """Add a command to the allowed list"""
        self.allowed_commands.add(command)
    
    def remove_allowed_command(self, command: str) -> None:
        """Remove a command from the allowed list"""
        self.allowed_commands.discard(command)
    
    def get_allowed_commands(self) -> List[str]:
        """Get list of allowed commands"""
        return sorted(list(self.allowed_commands))
    
    def add_deny_pattern(self, pattern: str) -> None:
        """Add a deny pattern"""
        if pattern not in self.deny_patterns:
            self.deny_patterns.append(pattern)
    
    def remove_deny_pattern(self, pattern: str) -> None:
        """Remove a deny pattern"""
        if pattern in self.deny_patterns:
            self.deny_patterns.remove(pattern)
    
    def get_deny_patterns(self) -> List[str]:
        """Get list of deny patterns"""
        return self.deny_patterns.copy()
    
    def to_config_dict(self) -> Dict:
        """Export current permissions to config format"""
        return {
            "allowed_commands": self.get_allowed_commands(),
            "deny_patterns": self.get_deny_patterns(),
            "rate_limit": {
                "requests_per_minute": int(self.rate_limiter.rate * 60),
                "burst": self.rate_limiter.burst
            }
        }