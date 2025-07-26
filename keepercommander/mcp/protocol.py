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

"""MCP protocol utilities and helpers."""

from typing import Dict, Any, List, Optional


class MCPProtocol:
    """MCP protocol constants and utilities"""
    
    # Protocol version
    VERSION = "1.0"
    
    # Method names
    LIST_TOOLS = "tools/list"
    CALL_TOOL = "tools/call"
    
    # Error codes
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    
    # Custom error codes (32000-32099)
    PERMISSION_DENIED = -32001
    COMMAND_NOT_FOUND = -32002
    COMMAND_EXECUTION_ERROR = -32003
    AUTHENTICATION_ERROR = -32004
    RATE_LIMIT_ERROR = -32005
    
    @staticmethod
    def create_error_response(code: int, message: str, 
                            data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create standard MCP error response"""
        error = {
            "code": code,
            "message": message
        }
        if data:
            error["data"] = data
        
        return {"error": error}
    
    @staticmethod
    def validate_tool_name(name: str) -> bool:
        """Validate tool name format"""
        if not name:
            return False
        
        # Must start with keeper_
        if not name.startswith('keeper_'):
            return False
        
        # Must contain only alphanumeric and underscore
        cmd_part = name[7:]  # Remove keeper_ prefix
        return all(c.isalnum() or c == '_' for c in cmd_part)
    
    @staticmethod
    def format_tool_description(description: str, aliases: List[str] = None) -> str:
        """Format tool description with aliases"""
        if not description:
            description = "Execute Keeper Commander command"
        
        if aliases:
            description += f" (aliases: {', '.join(aliases)})"
        
        return description