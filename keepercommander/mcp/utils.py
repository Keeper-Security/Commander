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

"""MCP server utility functions and error classes."""

import fnmatch
from typing import Dict, Any, Optional, List


class MCPError(Exception):
    """Base exception for MCP-related errors"""
    
    code: int = -32000
    details: Optional[Dict[str, Any]] = None
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}
    
    def to_error_dict(self) -> Dict[str, Any]:
        """Convert to MCP error response format"""
        return {
            "code": self.code,
            "message": str(self),
            "data": self.details
        }


class PermissionDeniedError(MCPError):
    """Raised when a command is not allowed by permissions"""
    code = -32001


class CommandNotFoundError(MCPError):
    """Raised when a command is not found"""
    code = -32002


class CommandExecutionError(MCPError):
    """Raised when command execution fails"""
    code = -32003


class AuthenticationError(MCPError):
    """Raised when authentication fails"""
    code = -32004


class RateLimitError(MCPError):
    """Raised when rate limit is exceeded"""
    code = -32005


def is_command_interactive(command_class) -> bool:
    """Check if a command requires interactive input"""
    # Commands that typically require interactive input
    interactive_patterns = [
        'login',
        '2fa',
        'accept',
        'decline',
        'confirm'
    ]
    
    command_name = getattr(command_class, 'command', '').lower()
    
    # Check command name against patterns
    for pattern in interactive_patterns:
        if pattern in command_name:
            return True
    
    # Check if command has password prompts
    if hasattr(command_class, 'get_parser'):
        try:
            parser = command_class.get_parser()
            for action in parser._actions:
                if action.dest in ['password', 'old_password', 'new_password']:
                    if not action.default and action.required:
                        return True
        except:
            pass
    
    return False


def is_command_appropriate_for_mcp(command_name: str) -> bool:
    """
    Check if a command is appropriate for MCP usage.
    Returns True only if explicitly listed as appropriate.
    """
    # Master list of commands with their MCP appropriateness
    command_appropriateness = {
        # ===== APPROPRIATE COMMANDS (True) =====
        
        # Basic vault operations
        'list': True,              # List records - safe read operation
        'search': True,            # Search vault - safe read operation
        'get': True,               # Get record details - safe read operation
        'tree': True,              # Show folder tree - safe read operation
        'pwd': True,               # Show current folder - safe read operation
        'cd': True,                # Change directory - safe navigation
        'find-password': True,     # Find specific password - safe read
        
        # Folder operations
        'list-sf': True,           # List shared folders - safe read
        'list-folder': True,       # List folder contents - safe read
        'mkdir': True,             # Create folder - safe write operation
        'folder-add': True,        # Add folder - safe write operation
        
        # Record operations
        'add': True,               # Add new record - useful for AI
        'record-add': True,        # Add record - useful for AI
        'update': True,            # Update record - useful for AI
        'append-notes': True,      # Append to notes - safe partial update
        'record-history': True,    # Show record history - safe read
        
        # Attachments
        'download-attachment': True,  # Download files - safe read
        'upload-attachment': True,    # Upload files - safe write
        
        # Import/Export
        'export': True,            # Export vault data - safe read
        'import': True,            # Import records - batch operation
        
        # Info commands
        'whoami': True,            # Current user info - safe read
        'version': True,           # Version info - safe read
        'info': True,              # Account info - safe read
        'record-type-info': True,  # Record type schemas - safe read
        
        # Reports (safe reads)
        'security-audit': True,    # Security audit - safe analysis
        'password-report': True,   # Password strength - safe analysis
        'breach-watch': True,      # Breach monitoring - safe read
        'share-report': True,      # Sharing report - safe read
        'audit-log': True,         # Audit logs - safe read
        'audit-report': True,      # Audit report - safe read
        'audit-export': True,      # Export audit data - safe read
        
        # Enterprise operations (if available)
        'enterprise-info': True,   # Enterprise info - safe read
        'enterprise-user': True,   # List users - safe read
        'enterprise-role': True,   # List roles - safe read
        'enterprise-team': True,   # List teams - safe read
        'enterprise-node': True,   # List nodes - safe read
        'list-team': True,         # List teams - safe read
        'list-user': True,         # List users - safe read
        'list-group': True,        # List groups - safe read
        'compliance': True,        # Compliance reports - safe read
        'compliance-export': True, # Export compliance - safe read
        'security-audit-report': True,  # Security reports - safe read
        'user-report': True,       # User reports - safe read
        'activity-report': True,   # Activity reports - safe read
        
        # MSP operations (if available)
        'msp-info': True,          # MSP info - safe read
        'msp-billing-report': True,  # Billing report - safe read
        
        # Device management
        'device-list': True,       # List devices - safe read
        'device-approve': True,    # Approve devices - useful for automation
        'device-decline': True,    # Decline devices - useful for automation
        
        # Account management (useful for provisioning)
        'create-account': True,    # Account creation - useful for provisioning
        'register': True,          # Register account - useful for provisioning
        
        # Sharing operations (useful for collaboration)
        'share-record': True,      # Share records - useful for collaboration
        'share-folder': True,      # Share folders - useful for collaboration
        
        # Transfer operations (useful for automation)
        'account-share': True,     # Share account - useful for delegation
        'account-transfer': True,  # Transfer account - useful for offboarding
        'accept-transfer': True,   # Accept transfer - complete the process
        'cancel-transfer': True,   # Cancel transfer - abort if needed
        'decline-transfer': True,  # Decline transfer - reject if needed
        
        # Edit operations (useful for management)
        'edit-user': True,         # Edit users - user management
        'edit-group': True,        # Edit groups - group management
        'edit-role': True,         # Edit roles - role management
        'edit-team': True,         # Edit teams - team management
        
        # Move operations (useful for organization)
        'move': True,              # Move records - organize vault
        'mv': True,                # Move alias - organize vault
        
        # Help command (useful for discovery)
        'help': True,              # Help system - discover capabilities
        
        # ===== INAPPROPRIATE COMMANDS (False) =====
        
        # Destructive operations
        'delete': False,           # Deletes records - too dangerous
        'delete-all': False,       # Mass deletion - extremely dangerous
        'rm': False,               # Remove - dangerous
        'purge': False,            # Purge data - dangerous
        'delete-corrupted': False, # Delete corrupted - dangerous
        'delete-attachment': False,  # Delete files - dangerous
        
        # Authentication/Security (require interactive)
        'login': False,            # Requires credentials - interactive
        'logout': False,           # Ends session - disruptive
        '2fa': False,              # Two-factor auth - interactive
        'set-password': False,     # Password change - security risk
        'change-password': False,  # Password change - security risk
        
        # Interactive connections
        'connect': False,          # SSH/RDP gateway - interactive
        'ssh': False,              # SSH connection - interactive
        'rdp': False,              # RDP connection - interactive
        'tunnel': False,           # Create tunnel - interactive
        'shell': False,            # Interactive shell - not for AI
        'proxy': False,            # Proxy connection - interactive
        
        # Browser/Desktop integration
        'keeper-fill': False,      # Browser plugin - not for AI
        'sync-down': False,        # Sync operation - side effects
        
        # Rotation/Automation
        'rotate': False,           # Password rotation - complex operation
        
        # Internal/Debug commands
        'debug': False,            # Debug mode - internal only
        'check-verbose': False,    # Verbose check - debug only
        'test': False,             # Test command - internal only
        'echo': False,             # Echo command - not useful
        'history': False,          # Command history - not relevant
        'quit': False,             # Quit command - would end session
        'q': False,                # Quit alias - would end session
        'clear': False,            # Clear screen - not relevant
        'cls': False,              # Clear screen - not relevant
        
        # Push operations (side effects)
        'enterprise-push': False,  # Push to users - has side effects
        
        # MSP management operations
        'msp-add': False,          # Add MSP - management operation
        'msp-remove': False,       # Remove MSP - management operation
        'msp-update': False,       # Update MSP - management operation
        'switch-to-msp': False,    # Switch context - changes state
        'switch-to-mc': False,     # Switch context - changes state
        'msp-down': False,         # Download MSP - bulk operation
        'msp-convert-node': False, # Convert node - management operation
    }
    
    # Return the explicit setting, default to False if not listed
    return command_appropriateness.get(command_name, False)


def check_command_permission(command_name: str, params) -> tuple[bool, str]:
    """
    Check if user has permission to run a command based on their account type.
    This follows the same pattern used in Keeper Commander where commands
    inherit from EnterpriseCommand or MSPCommand base classes.
    
    Returns: (has_permission, error_message)
    """
    # Import here to avoid circular imports
    from ..commands.enterprise_common import EnterpriseCommand
    from ..commands.msp import MSPCommand
    
    # Get the actual command class
    from ..cli import commands, enterprise_commands, msp_commands
    
    # Find the command class
    command_class = None
    if command_name in commands:
        command_class = commands[command_name]
    elif command_name in enterprise_commands:
        command_class = enterprise_commands[command_name]
    elif command_name in msp_commands:
        command_class = msp_commands[command_name]
    
    if not command_class:
        return True, ""  # If we can't find it, let it through (will fail later)
    
    # Check if it's an enterprise command by checking inheritance
    if issubclass(command_class.__class__, EnterpriseCommand):
        if not params.enterprise:
            return False, "This command is only available for Administrators of Keeper."
    
    # Check if it's an MSP command
    if hasattr(command_class.__class__, '__bases__'):
        for base in command_class.__class__.__bases__:
            if base.__name__ == 'MSPCommand':
                # Check MSP permission (this is how MSP commands check)
                if not hasattr(params, 'is_msp') or not params.is_msp:
                    return False, "This command requires MSP (Managed Service Provider) permissions."
    
    # Additional checks for specific features
    report_commands = {
        'audit-report', 'audit-export', 'compliance-export',
        'security-audit-report', 'user-report', 'activity-report',
        'password-report', 'breach-watch'
    }
    
    if command_name in report_commands:
        # Check if reports are disabled (this would be in account info)
        if hasattr(params, 'license') and params.license:
            account_type = params.license.get('account_type', '')
            # Some account types don't have reports
            if account_type in ['family', 'free']:
                return False, "Reports are not available in your account type. Please upgrade your plan."
    
    return True, ""


def matches_pattern(text: str, patterns: List[str]) -> bool:
    """Check if text matches any of the glob patterns"""
    for pattern in patterns:
        if fnmatch.fnmatch(text, pattern):
            return True
    return False


def format_command_result(result: Any) -> str:
    """Format command execution result for MCP response"""
    if result is None:
        return "Command executed successfully"
    
    if isinstance(result, str):
        return result
    
    if isinstance(result, (list, dict)):
        import json
        return json.dumps(result, indent=2)
    
    return str(result)


def extract_command_parameters(command_class) -> Dict[str, Any]:
    """Extract parameter schema from command class"""
    schema = {
        "type": "object",
        "properties": {},
        "required": []
    }
    
    if not hasattr(command_class, 'get_parser'):
        return schema
    
    try:
        parser = command_class.get_parser()
        
        for action in parser._actions:
            if action.dest in ['help', 'command']:
                continue
                
            param_schema = {
                "description": action.help or f"Parameter {action.dest}"
            }
            
            # Determine parameter type
            if action.type == int:
                param_schema["type"] = "integer"
            elif action.type == float:
                param_schema["type"] = "number"
            elif action.type == bool or action.__class__.__name__ in ['_StoreTrueAction', '_StoreFalseAction']:
                param_schema["type"] = "boolean"
            elif action.nargs in ['*', '+']:
                param_schema["type"] = "array"
                param_schema["items"] = {"type": "string"}
            else:
                param_schema["type"] = "string"
            
            # Add choices if available
            if action.choices:
                param_schema["enum"] = list(action.choices)
            
            # Add to schema
            schema["properties"][action.dest] = param_schema
            
            # Mark as required if no default
            # For positional arguments (no option_strings), they are required unless nargs is '?' or '*'
            if action.required or (not action.option_strings and action.nargs not in ['?', '*']):
                schema["required"].append(action.dest)
            # For optional arguments, mark as required if explicitly required or has no default
            elif action.option_strings and action.required:
                schema["required"].append(action.dest)
    
    except Exception:
        # Return basic schema if parsing fails
        pass
    
    return schema