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
Model Context Protocol (MCP) server implementation for Keeper Commander.

This module provides AI agents with access to Keeper Commander functionality
through the standardized MCP protocol.
"""

from .server_v2 import KeeperMCPServer
from .permissions import PermissionManager
from .utils import MCPError, PermissionDeniedError, CommandNotFoundError, CommandExecutionError

__all__ = [
    'KeeperMCPServer',
    'PermissionManager',
    'MCPError',
    'PermissionDeniedError', 
    'CommandNotFoundError',
    'CommandExecutionError'
]

__version__ = '1.0.0'