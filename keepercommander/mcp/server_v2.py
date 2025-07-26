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

"""
Main MCP server implementation for Keeper Commander - Version 2.

This module implements the MCP server using the latest MCP SDK API.
It provides AI agents with access to Keeper Commander functionality
through the standardized Model Context Protocol.
"""

import asyncio
import logging
import uuid
from typing import Dict, Any, Optional, List, Sequence

try:
    from mcp.server import Server
    from mcp.server.models import InitializationOptions
    from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    Server = None
    Tool = None
    TextContent = None
    InitializationOptions = None

from ..params import KeeperParams
from .adapter import CommandAdapter
from .permissions import PermissionManager
from .monitoring import MCPMetrics, MCPLogger
from .session import SessionManager
from .utils import MCPError, CommandExecutionError


class KeeperMCPServer:
    """MCP server for Keeper Commander using the new MCP SDK API"""
    
    def __init__(self, params: KeeperParams, config: Optional[Dict[str, Any]] = None):
        if not MCP_AVAILABLE:
            raise ImportError(
                "MCP SDK is not available. Please install with: pip install 'mcp>=1.0.0'"
            )
        
        self.params = params
        self.config = config or params.config.get('mcp', {})
        self.server_session_id = str(uuid.uuid4())
        
        # Initialize components
        self.server = Server("keeper-commander")
        self.permissions = PermissionManager(self.config)
        self.metrics = MCPMetrics()
        self.logger = MCPLogger(self.config)
        self.sessions = SessionManager(params, self.config.get('session_timeout', 30))
        
        # Set up logging
        self._logger = logging.getLogger('keepercommander.mcp.server')
        
        # Register handlers
        self._register_handlers()
    
    def _register_handlers(self):
        """Register MCP protocol handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available tools"""
            try:
                # Create adapter
                adapter = CommandAdapter(self.params)
                
                # Get all available tools
                all_tools = adapter.get_available_tools()
                
                # Filter by permissions
                allowed_tools = []
                for tool_dict in all_tools:
                    tool_name = tool_dict['name']
                    cmd_name = tool_name.replace('keeper_', '').replace('_', '-')
                    
                    if self.permissions.is_command_allowed(cmd_name):
                        # Convert to MCP Tool type
                        tool = Tool(
                            name=tool_dict['name'],
                            description=tool_dict['description'],
                            inputSchema=tool_dict['inputSchema']
                        )
                        allowed_tools.append(tool)
                
                self._logger.info(f"Listed {len(allowed_tools)} allowed tools")
                return allowed_tools
            
            except Exception as e:
                self._logger.error(f"Error listing tools: {e}")
                raise
        
        @self.server.call_tool()
        async def handle_call_tool(
            name: str, 
            arguments: Optional[Dict[str, Any]] = None
        ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
            """Execute a tool (command)"""
            # Extract command name for logging/permissions
            cmd_name = name.replace('keeper_', '').replace('_', '-')
            
            # Default empty arguments if None
            if arguments is None:
                arguments = {}
            
            # Get session ID from arguments if provided
            session_id = arguments.pop('_session_id', None) if '_session_id' in arguments else None
            session = self.sessions.get_or_create_session(session_id)
            
            # Log request
            self.logger.log_request('call_tool', name, arguments, session.session_id)
            
            try:
                # Track metrics
                with self.metrics.track_request('call_tool', name):
                    # Validate permissions and rate limit
                    self.permissions.validate_access(cmd_name)
                    
                    # Create session-specific adapter
                    session_adapter = CommandAdapter(session.params)
                    
                    # Handle stateful commands
                    if cmd_name == 'cd':
                        # Update session's current folder
                        result = await session_adapter.execute_command(name, arguments)
                        # Store the new folder in session context
                        if 'folder' in arguments:
                            session.current_folder = arguments['folder']
                    else:
                        # Execute command with session params
                        result = await session_adapter.execute_command(name, arguments)
                    
                    # Log success
                    self.logger.log_response('call_tool', name, True, 0, session.session_id)
                    
                    # Include session ID in response for client to use in subsequent calls
                    if not session_id:
                        result += f"\n\n[Session ID: {session.session_id}]"
                    
                    # Return result as TextContent
                    return [TextContent(
                        type="text",
                        text=result
                    )]
            
            except MCPError as e:
                # Log MCP errors
                self.logger.log_error('call_tool', name, e, session.session_id)
                
                # Track specific error types
                if hasattr(e, 'code'):
                    if e.code == -32001:  # Permission denied
                        self.metrics.track_permission_denial(cmd_name)
                    elif e.code == -32005:  # Rate limit
                        limit_type = e.details.get('limit_type', 'global')
                        self.metrics.track_rate_limit(cmd_name, limit_type)
                
                raise
            
            except Exception as e:
                # Log unexpected errors
                self.logger.log_error('call_tool', name, e, session.session_id)
                
                # Convert to MCP error
                error = CommandExecutionError(
                    f"Unexpected error: {str(e)}",
                    {"command": cmd_name, "error_type": type(e).__name__}
                )
                raise error
    
    async def run_stdio(self):
        """Run MCP server with stdio transport"""
        self._logger.info("Starting MCP server in stdio mode")
        self.metrics.track_connection('stdio')
        
        try:
            # Import here to avoid issues when MCP not available
            from mcp.server.stdio import stdio_server
            
            init_options = InitializationOptions(
                server_name="keeper-commander",
                server_version="1.0.0",
                capabilities={}
            )
            
            # stdio_server returns read and write streams
            async with stdio_server() as (read_stream, write_stream):
                # Run the server with the streams
                await self.server.run(
                    read_stream,
                    write_stream,
                    init_options
                )
        except Exception as e:
            self._logger.error(f"Error in MCP server: {e}")
            self._logger.error(f"Error type: {type(e).__name__}")
            import traceback
            self._logger.error(f"Traceback: {traceback.format_exc()}")
            raise
        finally:
            self.metrics.track_disconnection()
            self._logger.info("MCP server stopped")
    
    async def run_remote(self, host: str = 'localhost', port: int = 3001, 
                        tls_config: Optional[Dict[str, Any]] = None):
        """Run MCP server with WebSocket transport (remote mode)"""
        # This will be implemented in Phase 4
        raise NotImplementedError("Remote MCP access will be implemented in Phase 4")
    
    def get_status(self) -> Dict[str, Any]:
        """Get server status and metrics"""
        status = self.metrics.get_status()
        
        # Add permission info
        status['permissions'] = {
            'allowed_commands': self.permissions.get_allowed_commands(),
            'deny_patterns': self.permissions.get_deny_patterns()
        }
        
        # Add session info
        status['server_session'] = {
            'id': self.server_session_id,
            'transport': 'stdio'  # Will be dynamic when remote is added
        }
        
        # Add active sessions info
        status['sessions'] = self.sessions.get_session_info()
        
        return status