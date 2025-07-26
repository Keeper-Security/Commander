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

"""MCP server commands for Keeper Commander."""

import argparse
import asyncio
import json
import logging
import os
import sys
from typing import Optional

from .base import Command, GroupCommand, register_commands
from ..params import KeeperParams
from ..api import login
from ..display import bcolors


class MCPServerCommand(GroupCommand):
    """Main MCP server command group"""
    
    def __init__(self):
        super(MCPServerCommand, self).__init__()
        self.register_command('start', MCPStartCommand(), 'Start MCP server')
        self.register_command('stop', MCPStopCommand(), 'Stop MCP server')
        self.register_command('status', MCPStatusCommand(), 'Show MCP server status')
        self.register_command('config', MCPConfigCommand(), 'Manage MCP configuration')
        self.register_command('permissions', MCPPermissionsCommand(), 'Manage MCP permissions')
        self.register_command('remote', MCPRemoteCommand(), 'Manage remote access')
        self.default_verb = 'status'


class MCPStartCommand(Command):
    """Start MCP server"""
    
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='mcp-server start')
        parser.add_argument('--no-confirm', action='store_true', help='Skip security confirmation (for automated use)')
        return parser
    
    def execute(self, params, **kwargs):
        # Check if MCP is available
        try:
            from ..mcp.server_v2 import KeeperMCPServer
        except ImportError as e:
            print(f"{bcolors.FAIL}MCP SDK is not available. Please install with: pip install 'mcp>=1.0.0'{bcolors.ENDC}")
            print(f"{bcolors.FAIL}Error details: {e}{bcolors.ENDC}")
            return
        
        # Ensure user is logged in
        if not params.session_token:
            print(f"{bcolors.WARNING}Not logged in. Please login first.{bcolors.ENDC}")
            return
        
        # Get MCP config
        mcp_config = params.config.get('mcp', {})
        
        if not mcp_config.get('enabled', False):
            print(f"{bcolors.FAIL}MCP server is not enabled. Run 'mcp-server config --enable' to enable it.{bcolors.ENDC}")
            return
        
        # Check if running in MCP mode (stdio with no TTY) or --no-confirm flag
        no_confirm = kwargs.get('no_confirm', False)
        is_mcp_mode = not sys.stdin.isatty()  # No TTY means we're running as MCP server
        
        if not no_confirm and not is_mcp_mode:
            # Display security warning and current configuration
            print(f"\n{bcolors.FAIL}{'=' * 70}{bcolors.ENDC}")
            print(f"{bcolors.FAIL}KEEPER COMMANDER MCP SERVER - ALPHA RELEASE{bcolors.ENDC}")
            print(f"{bcolors.FAIL}{'=' * 70}{bcolors.ENDC}")
            print(f"\n{bcolors.WARNING}SECURITY WARNING:{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• This is an ALPHA feature - expect bugs and changes{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• Your vault data will be exposed to the connected AI/LLM{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• AI providers may log and retain command data{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• You are responsible for your AI provider's security{bcolors.ENDC}")
            print(f"\n{bcolors.OKBLUE}Current Configuration:{bcolors.ENDC}")
            
            # Show allowed commands
            allowed_commands = mcp_config.get('permissions', {}).get('allowed_commands', ['whoami'])
            print(f"\n{bcolors.OKBLUE}Allowed Commands ({len(allowed_commands)}):{bcolors.ENDC}")
            for cmd in allowed_commands[:10]:
                print(f"  {bcolors.OKGREEN}- {cmd}{bcolors.ENDC}")
            if len(allowed_commands) > 10:
                print(f"  {bcolors.WARNING}... and {len(allowed_commands) - 10} more{bcolors.ENDC}")
            
            # Show deny patterns
            deny_patterns = mcp_config.get('permissions', {}).get('deny_patterns', [])
            if deny_patterns:
                print(f"\n{bcolors.OKBLUE}Deny Patterns:{bcolors.ENDC}")
                for pattern in deny_patterns[:5]:
                    print(f"  {bcolors.FAIL}- {pattern}{bcolors.ENDC}")
            
            # Show rate limits
            rate_limit = mcp_config.get('permissions', {}).get('rate_limit', {})
            rpm = rate_limit.get('requests_per_minute', 60)
            print(f"\n{bcolors.OKBLUE}Rate Limit:{bcolors.ENDC} {rpm} requests/minute")
            
            # Show transport
            print(f"\n{bcolors.OKBLUE}Transport:{bcolors.ENDC} stdio (local only)")
            
            # Confirm with user
            print(f"\n{bcolors.WARNING}{'=' * 50}{bcolors.ENDC}")
            confirm = input(f"{bcolors.WARNING}Do you want to start the MCP server with these settings? (yes/no): {bcolors.ENDC}").strip().lower()
            
            if confirm != 'yes':
                print(f"{bcolors.WARNING}MCP server start cancelled.{bcolors.ENDC}")
                return
        
        # Create and run server
        try:
            server = KeeperMCPServer(params, mcp_config)
            
            # Only print to stdout if we're in interactive mode
            if not is_mcp_mode:
                print(f"\n{bcolors.OKGREEN}Starting Keeper Commander MCP server...{bcolors.ENDC}")
                print(f"{bcolors.OKBLUE}Allowed commands: {', '.join(server.permissions.get_allowed_commands())}{bcolors.ENDC}")
            else:
                # Log to stderr when running as MCP server
                logging.info("Starting Keeper Commander MCP server...")
                logging.info(f"Allowed commands: {', '.join(server.permissions.get_allowed_commands())}")
            
            # Run server
            asyncio.run(server.run_stdio())
            
        except KeyboardInterrupt:
            if not is_mcp_mode:
                print(f"\n{bcolors.WARNING}MCP server stopped by user{bcolors.ENDC}")
            else:
                logging.info("MCP server stopped by user")
        except Exception as e:
            if not is_mcp_mode:
                print(f"{bcolors.FAIL}Failed to start MCP server: {e}{bcolors.ENDC}")
                import traceback
                print(f"{bcolors.FAIL}Traceback:{bcolors.ENDC}")
                traceback.print_exc()
            else:
                logging.error(f"Failed to start MCP server: {e}")
                import traceback
                logging.error(f"Traceback: {traceback.format_exc()}")


class MCPStopCommand(Command):
    """Stop MCP server (placeholder)"""
    
    def get_parser(self):
        return argparse.ArgumentParser(prog='mcp-server stop')
    
    def execute(self, params, **kwargs):
        logging.info("MCP server runs in the foreground. Use Ctrl+C to stop it.")


class MCPStatusCommand(Command):
    """Show MCP server status"""
    
    def get_parser(self):
        return argparse.ArgumentParser(prog='mcp-server status')
    
    def execute(self, params, **kwargs):
        # Check if MCP is available
        try:
            from ..mcp.server_v2 import KeeperMCPServer
        except ImportError:
            print(f"{bcolors.FAIL}MCP SDK Status: Not installed{bcolors.ENDC}")
            print(f"{bcolors.WARNING}Run: pip install 'mcp>=1.0.0'{bcolors.ENDC}")
            return
        
        print(f"{bcolors.OKGREEN}MCP SDK Status: Installed{bcolors.ENDC}")
        
        # Check configuration
        mcp_config = params.config.get('mcp', {})
        enabled = mcp_config.get('enabled', False)
        
        print(f"\n{bcolors.HEADER}MCP Server Configuration{bcolors.ENDC}")
        print(f"{bcolors.HEADER}{'─' * 40}{bcolors.ENDC}")
        
        if enabled:
            print(f"  {bcolors.OKGREEN}Status: Enabled{bcolors.ENDC}")
            
            permissions = mcp_config.get('permissions', {})
            allowed = permissions.get('allowed_commands', ['whoami'])
            denied = permissions.get('deny_patterns', [])
            
            print(f"\n  {bcolors.OKBLUE}Permissions:{bcolors.ENDC}")
            if allowed:
                print(f"    {bcolors.OKGREEN}Allowed Commands:{bcolors.ENDC} {', '.join(allowed)}")
            else:
                print(f"    {bcolors.WARNING}Allowed Commands: none{bcolors.ENDC}")
            
            if denied:
                print(f"    {bcolors.FAIL}Deny Patterns:{bcolors.ENDC} {', '.join(denied)}")
            
            # Rate limits
            rate_limit = permissions.get('rate_limit', {})
            rpm = rate_limit.get('requests_per_minute', 60)
            print(f"\n  {bcolors.OKBLUE}Rate Limit:{bcolors.ENDC} {rpm} req/min")
            
            # Remote access
            remote = mcp_config.get('remote_access', {})
            print(f"\n  {bcolors.OKBLUE}Remote Access:{bcolors.ENDC}")
            if remote.get('enabled', False):
                port = remote.get('port', 3001)
                print(f"    {bcolors.OKGREEN}Enabled on port {port}{bcolors.ENDC}")
            else:
                print(f"    {bcolors.WARNING}Disabled{bcolors.ENDC}")
            
            # Session timeout
            timeout = mcp_config.get('session_timeout', 30)
            print(f"\n  {bcolors.OKBLUE}Session Timeout:{bcolors.ENDC} {timeout} minutes")
            
            # Logging
            logging_config = mcp_config.get('logging', {})
            if logging_config.get('enabled', True):
                print(f"\n  {bcolors.OKBLUE}Logging:{bcolors.ENDC}")
                print(f"    {bcolors.OKGREEN}Enabled{bcolors.ENDC}")
                print(f"    Level: {logging_config.get('level', 'info')}")
                if 'file' in logging_config:
                    print(f"    File: {logging_config['file']}")
        else:
            print(f"  {bcolors.FAIL}Status: Disabled{bcolors.ENDC}")
            print(f"\n  {bcolors.WARNING}Tip: Enable with 'mcp-server config --enable'{bcolors.ENDC}")


class MCPConfigCommand(Command):
    """Manage MCP configuration"""
    
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='mcp-server config')
        parser.add_argument('--enable', action='store_true', help='Enable MCP server')
        parser.add_argument('--disable', action='store_true', help='Disable MCP server')
        parser.add_argument('--show', action='store_true', help='Show current configuration')
        parser.add_argument('--remote-port', type=int, help='Set remote access port')
        parser.add_argument('--rate-limit', type=int, help='Set rate limit (requests per minute)')
        return parser
    
    def execute(self, params, **kwargs):
        enable = kwargs.get('enable', False)
        disable = kwargs.get('disable', False)
        show = kwargs.get('show', False)
        remote_port = kwargs.get('remote_port')
        rate_limit = kwargs.get('rate_limit')
        
        # Get or create MCP config
        if 'mcp' not in params.config:
            params.config['mcp'] = {
                'enabled': False,
                'permissions': {
                    'allowed_commands': ['whoami'],
                    'deny_patterns': ['login', '*2fa*', 'accept', 'decline'],
                    'rate_limit': {
                        'requests_per_minute': 60,
                        'burst': 10
                    }
                },
                'logging': {
                    'enabled': True,
                    'level': 'info'
                },
                'remote_access': {
                    'enabled': False,
                    'port': 3001,
                    'auth_tokens': []
                }
            }
        
        mcp_config = params.config['mcp']
        modified = False
        
        if enable:
            # Show security warning
            print(f"\n{bcolors.FAIL}{'='*70}{bcolors.ENDC}")
            print(f"{bcolors.FAIL}KEEPER COMMANDER MCP SERVER - ALPHA RELEASE WARNING{bcolors.ENDC}")
            print(f"{bcolors.FAIL}{'='*70}{bcolors.ENDC}")
            print(f"\n{bcolors.WARNING}IMPORTANT SECURITY NOTICE:{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• This is an ALPHA feature - use at your own risk{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• Your vault data will be accessible to AI/LLM systems{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• Commands executed through MCP may be logged by AI providers{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• You are responsible for ensuring your AI/LLM provider is secure{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• Only use with trusted AI systems and secure connections{bcolors.ENDC}")
            print(f"{bcolors.WARNING}• Review and limit permissions before connecting any AI{bcolors.ENDC}")
            
            print(f"\n{bcolors.FAIL}DISCLAIMER:{bcolors.ENDC}")
            print(f"By enabling MCP, you acknowledge that:")
            print(f"• You understand the security implications")
            print(f"• You accept full responsibility for data exposure")
            print(f"• Keeper Security is not liable for any data breaches")
            print(f"• This feature may change or be removed without notice")
            
            print(f"\n{bcolors.FAIL}{'='*70}{bcolors.ENDC}")
            confirm = input(f"\n{bcolors.FAIL}Do you understand and accept these risks? Type 'I ACCEPT' to continue: {bcolors.ENDC}").strip()
            
            if confirm != "I ACCEPT":
                print(f"\n{bcolors.WARNING}MCP server was NOT enabled. Configuration unchanged.{bcolors.ENDC}")
                return
            
            mcp_config['enabled'] = True
            modified = True
            print(f"\n{bcolors.OKGREEN}MCP server enabled{bcolors.ENDC}")
            print(f"{bcolors.WARNING}Remember: Only grant permissions for commands you actually need!{bcolors.ENDC}")
        
        if disable:
            mcp_config['enabled'] = False
            modified = True
            print(f"{bcolors.WARNING}MCP server disabled{bcolors.ENDC}")
        
        if remote_port:
            mcp_config.setdefault('remote_access', {})['port'] = remote_port
            modified = True
            print(f"{bcolors.OKBLUE}Remote port set to {remote_port}{bcolors.ENDC}")
        
        if rate_limit:
            mcp_config.setdefault('permissions', {}).setdefault('rate_limit', {})['requests_per_minute'] = rate_limit
            modified = True
            print(f"{bcolors.OKBLUE}Rate limit set to {rate_limit} requests per minute{bcolors.ENDC}")
        
        if show or not modified:
            print(f"\n{bcolors.HEADER}MCP Configuration{bcolors.ENDC}")
            print(f"{bcolors.HEADER}{'=' * 40}{bcolors.ENDC}")
            enabled = mcp_config.get('enabled', False)
            print(f"{bcolors.OKBLUE}Status:{bcolors.ENDC} {bcolors.OKGREEN if enabled else bcolors.WARNING}{'Enabled' if enabled else 'Disabled'}{bcolors.ENDC}")
            
            # Permissions
            perms = mcp_config.get('permissions', {})
            allowed = perms.get('allowed_commands', ['whoami'])
            print(f"\n{bcolors.OKBLUE}Allowed Commands ({len(allowed)}):{bcolors.ENDC}")
            for cmd in allowed[:5]:
                print(f"  {bcolors.OKGREEN}- {cmd}{bcolors.ENDC}")
            if len(allowed) > 5:
                print(f"  {bcolors.WARNING}... and {len(allowed) - 5} more{bcolors.ENDC}")
            
            # Raw JSON for detailed view
            if show:
                print(f"\n{bcolors.HEADER}Raw Configuration:{bcolors.ENDC}")
                print(json.dumps(mcp_config, indent=2))
        
        # Save configuration if modified
        if modified:
            try:
                with open(params.config_filename, 'w') as f:
                    json.dump(params.config, f, indent=2)
                print(f"\n{bcolors.OKGREEN}Configuration saved to {params.config_filename}{bcolors.ENDC}")
            except Exception as e:
                logging.error(f"Failed to save configuration: {e}")
                print(f"{bcolors.FAIL}Failed to save configuration: {e}{bcolors.ENDC}")


class MCPPermissionsCommand(Command):
    """Manage MCP permissions"""
    
    def _run_interactive_permissions(self, params, allowed, permissions):
        """Run interactive permissions selector with scrollable interface"""
        try:
            import termios
            import tty
            import select
            has_termios = True
        except ImportError:
            has_termios = False
        
        try:
            from ..mcp.utils import is_command_interactive
            from ..cli import (
                commands, command_info,
                enterprise_commands, enterprise_command_info,
                msp_commands, msp_command_info
            )
            
            # Build command list from all sources
            available_cmds = []
            
            # Process all command types
            all_cmd_sources = [
                (commands, command_info),
                (enterprise_commands, enterprise_command_info),
                (msp_commands, msp_command_info)
            ]
            
            for cmd_dict, info_dict in all_cmd_sources:
                for cmd_name, cmd_class in sorted(cmd_dict.items()):
                    if not is_command_interactive(cmd_class):
                        desc = info_dict.get(cmd_name, '')[:50]
                        if len(info_dict.get(cmd_name, '')) > 50:
                            desc += '...'
                        available_cmds.append((cmd_name, desc))
            
            if not available_cmds:
                print(f"{bcolors.FAIL}No commands available{bcolors.ENDC}")
                return False
            
            # Check if we can use terminal mode
            use_terminal_mode = has_termios and sys.stdin.isatty() and sys.stdout.isatty()
            
            if use_terminal_mode:
                # Terminal-based scrollable interface
                return self._run_terminal_interactive(available_cmds, allowed)
            else:
                # Fallback to simple numbered list
                return self._run_simple_interactive(available_cmds, allowed)
                
        except ImportError as e:
            print(f"{bcolors.FAIL}Missing required modules for interactive mode: {e}{bcolors.ENDC}")
            print(f"{bcolors.WARNING}Try using --add/--remove commands instead{bcolors.ENDC}")
            return False
    
    def _run_terminal_interactive(self, available_cmds, allowed):
        """Terminal-based scrollable interface with arrow keys"""
        import termios
        import tty
        
        print(f"\n{bcolors.HEADER}Interactive Permission Mode{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}Use arrow keys to navigate, SPACE to toggle, ENTER to save, Q to quit{bcolors.ENDC}\n")
        
        # Terminal setup
        old_settings = termios.tcgetattr(sys.stdin)
        saved = False
        try:
            tty.setraw(sys.stdin.fileno())
            
            current_pos = 0
            page_size = 15  # Show 15 items at a time
            top_index = 0
            
            def print_menu(current_pos, top_index):
                # Clear screen and reset cursor
                sys.stdout.write('\033[2J\033[H')
                sys.stdout.flush()
                
                # Helper function to write lines in raw mode
                def write_line(text):
                    sys.stdout.write(text + '\r\n')
                    sys.stdout.flush()
                
                # Header
                write_line(f"{bcolors.HEADER}Interactive Permission Mode{bcolors.ENDC}")
                write_line(f"{bcolors.OKBLUE}Arrow keys: Navigate | SPACE: Toggle | ENTER: Save | Q: Quit{bcolors.ENDC}")
                write_line(f"{bcolors.OKGREEN}Currently allowed: {len(allowed)} commands{bcolors.ENDC}")
                write_line("")  # Empty line
                
                # Calculate visible range
                if current_pos < top_index:
                    top_index = current_pos
                elif current_pos >= top_index + page_size:
                    top_index = current_pos - page_size + 1
                
                bottom_index = min(top_index + page_size, len(available_cmds))
                
                # Show scroll indicator if needed
                if top_index > 0:
                    write_line(f"{bcolors.WARNING}↑ {top_index} more above ↑{bcolors.ENDC}")
                else:
                    write_line("")
                
                # Display commands
                for i in range(top_index, bottom_index):
                    cmd_name, desc = available_cmds[i]
                    is_selected = i == current_pos
                    is_allowed = cmd_name in allowed
                    
                    # Format line
                    if is_selected:
                        marker = "▶"
                        color = bcolors.HEADER
                    else:
                        marker = " "
                        color = bcolors.OKGREEN if is_allowed else ""
                    
                    status = f"{bcolors.OKGREEN}✓{bcolors.ENDC}" if is_allowed else " "
                    
                    write_line(f"{marker} [{status}] {color}{cmd_name:<25}{bcolors.ENDC} {desc}")
                
                # Show scroll indicator if needed
                if bottom_index < len(available_cmds):
                    write_line(f"{bcolors.WARNING}↓ {len(available_cmds) - bottom_index} more below ↓{bcolors.ENDC}")
                else:
                    write_line("")
                
                # Status line
                write_line("")
                write_line(f"{bcolors.OKBLUE}Commands: {current_pos + 1}/{len(available_cmds)} | Allowed: {len(allowed)}{bcolors.ENDC}")
                
                return top_index
            
            # Main loop
            while True:
                top_index = print_menu(current_pos, top_index)
                
                # Get key press
                key = sys.stdin.read(1)
                
                if key == '\x1b':  # ESC sequence
                    next1 = sys.stdin.read(1)
                    next2 = sys.stdin.read(1)
                    
                    if next1 == '[':
                        if next2 == 'A':  # Up arrow
                            current_pos = max(0, current_pos - 1)
                        elif next2 == 'B':  # Down arrow
                            current_pos = min(len(available_cmds) - 1, current_pos + 1)
                        elif next2 == '5':  # Page Up
                            sys.stdin.read(1)  # consume ~
                            current_pos = max(0, current_pos - page_size)
                            top_index = max(0, top_index - page_size)
                        elif next2 == '6':  # Page Down
                            sys.stdin.read(1)  # consume ~
                            current_pos = min(len(available_cmds) - 1, current_pos + page_size)
                            top_index = min(len(available_cmds) - page_size, top_index + page_size)
                
                elif key == ' ':  # Space - toggle
                    cmd_name = available_cmds[current_pos][0]
                    if cmd_name in allowed:
                        allowed.discard(cmd_name)
                    else:
                        allowed.add(cmd_name)
                
                elif key == '\r' or key == '\n':  # Enter - save
                    sys.stdout.write('\033[2J\033[H')  # Clear screen
                    sys.stdout.flush()
                    saved = True
                    break
                
                elif key.lower() == 'q':  # Q - quit
                    sys.stdout.write('\033[2J\033[H')  # Clear screen
                    sys.stdout.flush()
                    saved = False
                    break
                
                elif key.lower() == 'a':  # A - select all
                    for cmd_name, _ in available_cmds:
                        allowed.add(cmd_name)
                
                elif key.lower() == 'c':  # C - clear all
                    allowed.clear()
        
        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            # After restoring, we can use print() again
            if saved:
                print(f"{bcolors.OKGREEN}Permissions saved!{bcolors.ENDC}")
            else:
                print(f"{bcolors.WARNING}Cancelled - no changes saved{bcolors.ENDC}")
        
        return saved
    
    def _run_simple_interactive(self, available_cmds, allowed):
        """Simple numbered list interface (fallback)"""
        print(f"\n{bcolors.HEADER}Interactive Permission Mode{bcolors.ENDC}")
        print(f"{bcolors.WARNING}Note: Running in simple mode. For better experience, run outside the Keeper shell.{bcolors.ENDC}\n")
        
        print(f"{bcolors.HEADER}Available Commands:{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}Currently allowed: {', '.join(sorted(allowed)) if allowed else '(none)'}{bcolors.ENDC}\n")
        
        # Show commands in pages
        page_size = 20
        page = 0
        
        while True:
            start = page * page_size
            end = min(start + page_size, len(available_cmds))
            
            print(f"\n{bcolors.HEADER}Commands {start+1}-{end} of {len(available_cmds)}:{bcolors.ENDC}")
            for i in range(start, end):
                cmd_name, desc = available_cmds[i]
                status = f"{bcolors.OKGREEN}[✓]{bcolors.ENDC}" if cmd_name in allowed else "[ ]"
                print(f"{i+1:3}. {status} {cmd_name:<25} {desc}")
            
            print(f"\n{bcolors.OKBLUE}Options:{bcolors.ENDC}")
            print("  Enter command number to toggle permission")
            print("  'n' - Next page")
            print("  'p' - Previous page") 
            print("  'a' - Allow all commands")
            print("  'c' - Clear all permissions")
            print("  's' - Save and exit")
            print("  'q' - Quit without saving")
            
            choice = input(f"\n{bcolors.WARNING}Choice: {bcolors.ENDC}").strip().lower()
            
            if choice == 'q':
                print(f"{bcolors.WARNING}Cancelled - no changes saved{bcolors.ENDC}")
                return False
            elif choice == 's':
                print(f"{bcolors.OKGREEN}Permissions saved!{bcolors.ENDC}")
                return True
            elif choice == 'n' and end < len(available_cmds):
                page += 1
            elif choice == 'p' and page > 0:
                page -= 1
            elif choice == 'a':
                for cmd_name, _ in available_cmds:
                    allowed.add(cmd_name)
                print(f"{bcolors.OKGREEN}All commands allowed!{bcolors.ENDC}")
            elif choice == 'c':
                allowed.clear()
                print(f"{bcolors.WARNING}All permissions cleared!{bcolors.ENDC}")
            else:
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(available_cmds):
                        cmd_name = available_cmds[idx][0]
                        if cmd_name in allowed:
                            allowed.discard(cmd_name)
                            print(f"{bcolors.WARNING}Removed permission for '{cmd_name}'{bcolors.ENDC}")
                        else:
                            allowed.add(cmd_name)
                            print(f"{bcolors.OKGREEN}Added permission for '{cmd_name}'{bcolors.ENDC}")
                except ValueError:
                    print(f"{bcolors.FAIL}Invalid choice{bcolors.ENDC}")
    
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='mcp-server permissions')
        parser.add_argument('--add', metavar='COMMAND', help='Add allowed command')
        parser.add_argument('--remove', metavar='COMMAND', help='Remove allowed command')
        parser.add_argument('--list', action='store_true', help='List all available commands')
        parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode to select commands')
        parser.add_argument('--show', action='store_true', help='Show current permissions')
        parser.add_argument('--add-deny', metavar='PATTERN', help='Add deny pattern')
        parser.add_argument('--remove-deny', metavar='PATTERN', help='Remove deny pattern')
        parser.add_argument('--enable-all', action='store_true', help='Enable all non-interactive commands')
        parser.add_argument('--disable-all', action='store_true', help='Disable all commands')
        parser.add_argument('--enable-safe', action='store_true', help='Enable safe read-only commands')
        return parser
    
    def execute(self, params, **kwargs):
        add_cmd = kwargs.get('add')
        remove_cmd = kwargs.get('remove')
        list_cmds = kwargs.get('list', False)
        interactive = kwargs.get('interactive', False)
        show = kwargs.get('show', False)
        add_deny = kwargs.get('add_deny')
        remove_deny = kwargs.get('remove_deny')
        enable_all = kwargs.get('enable_all', False)
        disable_all = kwargs.get('disable_all', False)
        enable_safe = kwargs.get('enable_safe', False)
        
        # Ensure MCP config exists
        if 'mcp' not in params.config:
            params.config['mcp'] = {
                'enabled': False,
                'permissions': {
                    'allowed_commands': ['whoami'],
                    'deny_patterns': ['login', '*2fa*', 'accept', 'decline']
                }
            }
        
        permissions = params.config['mcp'].setdefault('permissions', {})
        allowed = set(permissions.get('allowed_commands', ['whoami']))
        deny_patterns = permissions.get('deny_patterns', [])
        
        modified = False
        
        if list_cmds:
            # List all available commands
            try:
                from ..mcp.adapter import CommandAdapter
                from ..mcp.utils import is_command_interactive
                from ..cli import (
                    commands, command_info, 
                    enterprise_commands, enterprise_command_info,
                    msp_commands, msp_command_info
                )
                
                print(f"\n{bcolors.HEADER}Available Commands for MCP{bcolors.ENDC}")
                print(f"{bcolors.HEADER}{'─' * 60}{bcolors.ENDC}")
                
                # Group commands by category
                vault_cmds = []
                security_cmds = []
                enterprise_cmds = []
                msp_cmds = []
                other_cmds = []
                
                # Process all command types
                all_cmd_sources = [
                    (commands, command_info),
                    (enterprise_commands, enterprise_command_info),
                    (msp_commands, msp_command_info)
                ]
                
                for cmd_dict, info_dict in all_cmd_sources:
                    for cmd_name, cmd_class in sorted(cmd_dict.items()):
                        if not is_command_interactive(cmd_class):
                            desc = info_dict.get(cmd_name, '')[:50] + '...' if len(info_dict.get(cmd_name, '')) > 50 else info_dict.get(cmd_name, '')
                            is_allowed = cmd_name in allowed
                            
                            cmd_entry = (cmd_name, desc, is_allowed)
                            
                            # Categorize commands
                            if any(word in cmd_name for word in ['record', 'folder', 'list', 'search', 'get', 'tree', 'cd']):
                                vault_cmds.append(cmd_entry)
                            elif any(word in cmd_name for word in ['security', 'audit', 'breach', 'password-report', '2fa']):
                                security_cmds.append(cmd_entry)
                            elif any(word in cmd_name for word in ['enterprise', 'team', 'user', 'role', 'scim', 'device']):
                                enterprise_cmds.append(cmd_entry)
                            elif any(word in cmd_name for word in ['msp', 'mc', 'distributor']):
                                msp_cmds.append(cmd_entry)
                            else:
                                other_cmds.append(cmd_entry)
                
                # Display by category
                if vault_cmds:
                    print(f"\n{bcolors.OKBLUE}Vault Operations:{bcolors.ENDC}")
                    for cmd_name, desc, is_allowed in vault_cmds:
                        if is_allowed:
                            print(f"  {bcolors.OKGREEN}[Y]{bcolors.ENDC} {bcolors.OKGREEN}{cmd_name:<25}{bcolors.ENDC} {desc}")
                        else:
                            print(f"  {bcolors.WARNING}[ ]{bcolors.ENDC} {cmd_name:<25} {desc}")
                
                if security_cmds:
                    print(f"\n{bcolors.OKBLUE}Security & Compliance:{bcolors.ENDC}")
                    for cmd_name, desc, is_allowed in security_cmds:
                        if is_allowed:
                            print(f"  {bcolors.OKGREEN}[Y]{bcolors.ENDC} {bcolors.OKGREEN}{cmd_name:<25}{bcolors.ENDC} {desc}")
                        else:
                            print(f"  {bcolors.WARNING}[ ]{bcolors.ENDC} {cmd_name:<25} {desc}")
                
                if enterprise_cmds:
                    print(f"\n{bcolors.OKBLUE}Enterprise:{bcolors.ENDC}")
                    for cmd_name, desc, is_allowed in enterprise_cmds:
                        if is_allowed:
                            print(f"  {bcolors.OKGREEN}[Y]{bcolors.ENDC} {bcolors.OKGREEN}{cmd_name:<25}{bcolors.ENDC} {desc}")
                        else:
                            print(f"  {bcolors.WARNING}[ ]{bcolors.ENDC} {cmd_name:<25} {desc}")
                
                if msp_cmds:
                    print(f"\n{bcolors.OKBLUE}MSP (Managed Service Provider):{bcolors.ENDC}")
                    for cmd_name, desc, is_allowed in msp_cmds:
                        if is_allowed:
                            print(f"  {bcolors.OKGREEN}[Y]{bcolors.ENDC} {bcolors.OKGREEN}{cmd_name:<25}{bcolors.ENDC} {desc}")
                        else:
                            print(f"  {bcolors.WARNING}[ ]{bcolors.ENDC} {cmd_name:<25} {desc}")
                
                if other_cmds:
                    print(f"\n{bcolors.OKBLUE}Other Commands:{bcolors.ENDC}")
                    for cmd_name, desc, is_allowed in other_cmds:
                        if is_allowed:
                            print(f"  {bcolors.OKGREEN}[Y]{bcolors.ENDC} {bcolors.OKGREEN}{cmd_name:<25}{bcolors.ENDC} {desc}")
                        else:
                            print(f"  {bcolors.WARNING}[ ]{bcolors.ENDC} {cmd_name:<25} {desc}")
                
                print(f"\n{bcolors.OKGREEN}[Y] = Allowed{bcolors.ENDC}  {bcolors.WARNING}[ ] = Not allowed{bcolors.ENDC}")
                print(f"\n{bcolors.WARNING}Tips:{bcolors.ENDC}")
                print(f"  - Use {bcolors.OKBLUE}--add COMMAND{bcolors.ENDC} to allow a command")
                print(f"  - Use {bcolors.OKBLUE}--remove COMMAND{bcolors.ENDC} to disallow a command")
                print(f"  - Use {bcolors.OKBLUE}--show{bcolors.ENDC} to see current permissions")
                
            except ImportError:
                print(f"{bcolors.FAIL}MCP SDK not available. Please install with: pip install mcp>=0.1.0{bcolors.ENDC}")
            
            return
        
        if interactive:
            # Interactive permission setting mode
            saved = self._run_interactive_permissions(params, allowed, permissions)
            if saved:
                modified = True
            else:
                return
        
        if add_cmd:
            allowed.add(add_cmd)
            modified = True
            print(f"{bcolors.OKGREEN}Added '{add_cmd}' to allowed commands{bcolors.ENDC}")
        
        if remove_cmd:
            allowed.discard(remove_cmd)
            modified = True
            print(f"{bcolors.WARNING}Removed '{remove_cmd}' from allowed commands{bcolors.ENDC}")
        
        if enable_all:
            # Enable all non-interactive commands
            try:
                from ..mcp.utils import is_command_interactive
                from ..cli import commands, enterprise_commands, msp_commands
                
                enabled_count = 0
                
                # Enable from all command sources
                for cmd_dict in [commands, enterprise_commands, msp_commands]:
                    for cmd_name, cmd_class in cmd_dict.items():
                        if not is_command_interactive(cmd_class):
                            allowed.add(cmd_name)
                            enabled_count += 1
                
                modified = True
                print(f"{bcolors.OKGREEN}Enabled all {enabled_count} non-interactive commands{bcolors.ENDC}")
            except ImportError:
                print(f"{bcolors.FAIL}MCP SDK not available{bcolors.ENDC}")
        
        if disable_all:
            # Clear all allowed commands
            allowed.clear()
            modified = True
            print(f"{bcolors.WARNING}Disabled all commands{bcolors.ENDC}")
        
        if enable_safe:
            # Enable safe read-only commands
            safe_commands = [
                'whoami', 'list', 'search', 'get', 'tree', 'cd', 'pwd',
                'list-sf', 'list-team', 'list-user', 'list-group',
                'security-audit', 'password-report', 'record-history',
                'version', 'help', 'shell', 'history'
            ]
            
            # Check which ones actually exist
            try:
                from ..cli import commands, enterprise_commands, msp_commands
                added_count = 0
                for cmd in safe_commands:
                    if cmd in commands or cmd in enterprise_commands or cmd in msp_commands:
                        allowed.add(cmd)
                        added_count += 1
                
                modified = True
                print(f"{bcolors.OKGREEN}Enabled {added_count} safe read-only commands{bcolors.ENDC}")
            except ImportError:
                print(f"{bcolors.FAIL}Failed to load command list{bcolors.ENDC}")
        
        if add_deny:
            if add_deny not in deny_patterns:
                deny_patterns.append(add_deny)
                modified = True
                print(f"{bcolors.FAIL}Added '{add_deny}' to deny patterns{bcolors.ENDC}")
        
        if remove_deny:
            if remove_deny in deny_patterns:
                deny_patterns.remove(remove_deny)
                modified = True
                print(f"{bcolors.OKGREEN}Removed '{remove_deny}' from deny patterns{bcolors.ENDC}")
        
        if show or not modified:
            print(f"\n{bcolors.HEADER}Current MCP Permissions{bcolors.ENDC}")
            print(f"{bcolors.HEADER}{'=' * 40}{bcolors.ENDC}")
            
            print(f"\n{bcolors.OKBLUE}Allowed Commands:{bcolors.ENDC}")
            if allowed:
                for cmd in sorted(allowed):
                    print(f"  {bcolors.OKGREEN}- {cmd}{bcolors.ENDC}")
            else:
                print(f"  {bcolors.WARNING}(none){bcolors.ENDC}")
            
            print(f"\n{bcolors.OKBLUE}Deny Patterns:{bcolors.ENDC}")
            if deny_patterns:
                for pattern in deny_patterns:
                    print(f"  {bcolors.FAIL}- {pattern}{bcolors.ENDC}")
            else:
                print(f"  {bcolors.WARNING}(none){bcolors.ENDC}")
        
        # Update config if modified
        if modified:
            permissions['allowed_commands'] = sorted(list(allowed))
            permissions['deny_patterns'] = deny_patterns
            
            try:
                with open(params.config_filename, 'w') as f:
                    json.dump(params.config, f, indent=2)
                print(f"\nConfiguration saved to {params.config_filename}")
            except Exception as e:
                logging.error(f"Failed to save configuration: {e}")


class MCPRemoteCommand(GroupCommand):
    """Manage MCP remote access"""
    
    def __init__(self):
        super(MCPRemoteCommand, self).__init__()
        self.register_command('enable', MCPRemoteEnableCommand(), 'Enable remote access')
        self.register_command('disable', MCPRemoteDisableCommand(), 'Disable remote access')
        self.register_command('status', MCPRemoteStatusCommand(), 'Show remote access status')
        self.register_command('start', MCPRemoteStartCommand(), 'Start remote MCP server')
        self.register_command('token', MCPRemoteTokenCommand(), 'Manage authentication tokens')
        self.default_verb = 'status'


class MCPRemoteEnableCommand(Command):
    """Enable remote access"""
    
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='mcp-server remote enable')
        parser.add_argument('--port', type=int, default=3001, help='Port for remote access (default: 3001)')
        return parser
    
    def execute(self, params, **kwargs):
        port = kwargs.get('port', 3001)
        
        # Update config
        if 'mcp' not in params.config:
            params.config['mcp'] = {}
        
        if 'remote_access' not in params.config['mcp']:
            params.config['mcp']['remote_access'] = {
                'enabled': False,
                'port': 3001,
                'tls': {
                    'enabled': False,
                    'cert_file': '',
                    'key_file': ''
                },
                'auth_tokens': []
            }
        
        params.config['mcp']['remote_access']['enabled'] = True
        params.config['mcp']['remote_access']['port'] = port
        
        # Save config
        try:
            with open(params.config_filename, 'w') as f:
                json.dump(params.config, f, indent=2)
            print(f"{bcolors.OKGREEN}Remote access enabled on port {port}{bcolors.ENDC}")
            print(f"{bcolors.WARNING}Note: You need to generate auth tokens before starting the remote server{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Run: mcp-server remote token generate <name>{bcolors.ENDC}")
        except Exception as e:
            print(f"{bcolors.FAIL}Failed to save configuration: {e}{bcolors.ENDC}")


class MCPRemoteDisableCommand(Command):
    """Disable remote access"""
    
    def get_parser(self):
        return argparse.ArgumentParser(prog='mcp-server remote disable')
    
    def execute(self, params, **kwargs):
        if 'mcp' in params.config and 'remote_access' in params.config['mcp']:
            params.config['mcp']['remote_access']['enabled'] = False
            
            try:
                with open(params.config_filename, 'w') as f:
                    json.dump(params.config, f, indent=2)
                print(f"{bcolors.WARNING}Remote access disabled{bcolors.ENDC}")
            except Exception as e:
                print(f"{bcolors.FAIL}Failed to save configuration: {e}{bcolors.ENDC}")
        else:
            print(f"{bcolors.WARNING}Remote access was not configured{bcolors.ENDC}")


class MCPRemoteStatusCommand(Command):
    """Show remote access status"""
    
    def get_parser(self):
        return argparse.ArgumentParser(prog='mcp-server remote status')
    
    def execute(self, params, **kwargs):
        remote_config = params.config.get('mcp', {}).get('remote_access', {})
        enabled = remote_config.get('enabled', False)
        
        print(f"\n{bcolors.HEADER}Remote Access Status{bcolors.ENDC}")
        print(f"{bcolors.HEADER}{'=' * 40}{bcolors.ENDC}")
        
        if enabled:
            print(f"{bcolors.OKGREEN}Status: Enabled{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Port: {remote_config.get('port', 3001)}{bcolors.ENDC}")
            
            # TLS status
            tls_config = remote_config.get('tls', {})
            if tls_config.get('enabled', False):
                print(f"{bcolors.OKGREEN}TLS: Enabled{bcolors.ENDC}")
                print(f"  Certificate: {tls_config.get('cert_file', 'Not configured')}")
                print(f"  Key: {tls_config.get('key_file', 'Not configured')}")
            else:
                print(f"{bcolors.WARNING}TLS: Disabled (not recommended){bcolors.ENDC}")
            
            # Auth tokens
            tokens = remote_config.get('auth_tokens', [])
            print(f"\n{bcolors.OKBLUE}Authentication Tokens: {len(tokens)}{bcolors.ENDC}")
            if tokens:
                for token in tokens[:5]:  # Show first 5
                    name = token.get('name', 'Unknown')
                    created = token.get('created', 'Unknown')
                    print(f"  - {name} (created: {created})")
                if len(tokens) > 5:
                    print(f"  ... and {len(tokens) - 5} more")
            else:
                print(f"  {bcolors.WARNING}No tokens configured{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}Status: Disabled{bcolors.ENDC}")
            print(f"\n{bcolors.WARNING}To enable remote access:{bcolors.ENDC}")
            print(f"  1. Run: {bcolors.OKBLUE}mcp-server remote enable{bcolors.ENDC}")
            print(f"  2. Generate token: {bcolors.OKBLUE}mcp-server remote token generate <name>{bcolors.ENDC}")
            print(f"  3. Start server: {bcolors.OKBLUE}mcp-server remote start{bcolors.ENDC}")


class MCPRemoteStartCommand(Command):
    """Start remote MCP server"""
    
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='mcp-server remote start')
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
        parser.add_argument('--port', type=int, help='Port to bind to (uses config if not specified)')
        return parser
    
    def execute(self, params, **kwargs):
        # Check if MCP is available
        try:
            from ..mcp.server_v2 import KeeperMCPServer
            from ..mcp.remote import RemoteMCPServer
        except ImportError as e:
            print(f"{bcolors.FAIL}MCP SDK is not available. Please install with: pip install 'mcp>=1.0.0'{bcolors.ENDC}")
            return
        
        # Check if websockets is available
        try:
            import websockets
        except ImportError:
            print(f"{bcolors.FAIL}websockets library is not available. Please install with: pip install websockets{bcolors.ENDC}")
            return
        
        # Ensure user is logged in
        if not params.session_token:
            print(f"{bcolors.WARNING}Not logged in. Please login first.{bcolors.ENDC}")
            return
        
        # Get MCP config
        mcp_config = params.config.get('mcp', {})
        remote_config = mcp_config.get('remote_access', {})
        
        if not remote_config.get('enabled', False):
            print(f"{bcolors.FAIL}Remote access is not enabled. Run 'mcp-server remote enable' first.{bcolors.ENDC}")
            return
        
        # Check for auth tokens
        if not remote_config.get('auth_tokens'):
            print(f"{bcolors.FAIL}No authentication tokens configured.{bcolors.ENDC}")
            print(f"{bcolors.WARNING}Generate a token with: mcp-server remote token generate <name>{bcolors.ENDC}")
            return
        
        host = kwargs.get('host', '0.0.0.0')
        port = kwargs.get('port')
        
        # Security confirmation
        print(f"\n{bcolors.HEADER}Remote MCP Server Security Review{bcolors.ENDC}")
        print(f"{bcolors.HEADER}{'=' * 50}{bcolors.ENDC}")
        print(f"{bcolors.WARNING}WARNING: Starting remote MCP server will expose Keeper commands over network.{bcolors.ENDC}")
        print(f"\n{bcolors.OKBLUE}Configuration:{bcolors.ENDC}")
        print(f"  Host: {host}")
        print(f"  Port: {port or remote_config.get('port', 3001)}")
        print(f"  TLS: {'Enabled' if remote_config.get('tls', {}).get('enabled') else 'DISABLED (NOT SECURE)'}")
        print(f"  Auth tokens: {len(remote_config.get('auth_tokens', []))}")
        
        # Show allowed commands
        allowed_commands = mcp_config.get('permissions', {}).get('allowed_commands', ['whoami'])
        print(f"\n{bcolors.OKBLUE}Allowed Commands ({len(allowed_commands)}):{bcolors.ENDC}")
        for cmd in allowed_commands[:5]:
            print(f"  {bcolors.OKGREEN}- {cmd}{bcolors.ENDC}")
        if len(allowed_commands) > 5:
            print(f"  {bcolors.WARNING}... and {len(allowed_commands) - 5} more{bcolors.ENDC}")
        
        print(f"\n{bcolors.WARNING}{'=' * 50}{bcolors.ENDC}")
        confirm = input(f"{bcolors.WARNING}Do you want to start the remote MCP server? (yes/no): {bcolors.ENDC}").strip().lower()
        
        if confirm != 'yes':
            print(f"{bcolors.WARNING}Remote MCP server start cancelled.{bcolors.ENDC}")
            return
        
        # Create and start server
        try:
            # Create MCP server
            mcp_server = KeeperMCPServer(params, mcp_config)
            
            # Create remote server wrapper
            remote_server = RemoteMCPServer(mcp_server.server, mcp_config)
            
            # Run the remote server
            asyncio.run(remote_server.start_remote(host, port))
            
        except KeyboardInterrupt:
            print(f"\n{bcolors.WARNING}Remote MCP server stopped by user{bcolors.ENDC}")
        except Exception as e:
            print(f"{bcolors.FAIL}Failed to start remote MCP server: {e}{bcolors.ENDC}")
            import traceback
            traceback.print_exc()


class MCPRemoteTokenCommand(GroupCommand):
    """Manage authentication tokens"""
    
    def __init__(self):
        super(MCPRemoteTokenCommand, self).__init__()
        self.register_command('generate', MCPRemoteTokenGenerateCommand(), 'Generate new auth token')
        self.register_command('list', MCPRemoteTokenListCommand(), 'List auth tokens')
        self.register_command('revoke', MCPRemoteTokenRevokeCommand(), 'Revoke auth token')
        self.default_verb = 'list'


class MCPRemoteTokenGenerateCommand(Command):
    """Generate authentication token"""
    
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='mcp-server remote token generate')
        parser.add_argument('name', help='Name for this token (e.g., "claude-desktop")')
        return parser
    
    def execute(self, params, **kwargs):
        name = kwargs.get('name')
        
        if not name:
            print(f"{bcolors.FAIL}Token name is required{bcolors.ENDC}")
            return
        
        # Ensure config structure exists
        if 'mcp' not in params.config:
            params.config['mcp'] = {}
        if 'remote_access' not in params.config['mcp']:
            params.config['mcp']['remote_access'] = {'auth_tokens': []}
        if 'auth_tokens' not in params.config['mcp']['remote_access']:
            params.config['mcp']['remote_access']['auth_tokens'] = []
        
        # Check if name already exists
        tokens = params.config['mcp']['remote_access']['auth_tokens']
        if any(t.get('name') == name for t in tokens):
            print(f"{bcolors.FAIL}Token with name '{name}' already exists{bcolors.ENDC}")
            return
        
        # Generate token
        import secrets
        import datetime
        
        token = secrets.token_urlsafe(32)
        token_info = {
            'name': name,
            'token': token,
            'created': datetime.datetime.now().isoformat()
        }
        
        # Add to config
        params.config['mcp']['remote_access']['auth_tokens'].append(token_info)
        
        # Save config
        try:
            with open(params.config_filename, 'w') as f:
                json.dump(params.config, f, indent=2)
            
            print(f"\n{bcolors.OKGREEN}Authentication token generated successfully!{bcolors.ENDC}")
            print(f"\n{bcolors.HEADER}Token Information{bcolors.ENDC}")
            print(f"{bcolors.HEADER}{'=' * 60}{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Name:{bcolors.ENDC} {name}")
            print(f"{bcolors.OKBLUE}Token:{bcolors.ENDC} {token}")
            print(f"{bcolors.HEADER}{'=' * 60}{bcolors.ENDC}")
            print(f"\n{bcolors.WARNING}IMPORTANT: Save this token securely. It will not be shown again!{bcolors.ENDC}")
            print(f"\n{bcolors.OKBLUE}To use with MCP client, add to connection config:{bcolors.ENDC}")
            print(f'  "auth": {{"token": "{token}"}}\n')
            
        except Exception as e:
            print(f"{bcolors.FAIL}Failed to save token: {e}{bcolors.ENDC}")


class MCPRemoteTokenListCommand(Command):
    """List authentication tokens"""
    
    def get_parser(self):
        return argparse.ArgumentParser(prog='mcp-server remote token list')
    
    def execute(self, params, **kwargs):
        tokens = params.config.get('mcp', {}).get('remote_access', {}).get('auth_tokens', [])
        
        if not tokens:
            print(f"{bcolors.WARNING}No authentication tokens configured{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Generate one with: mcp-server remote token generate <name>{bcolors.ENDC}")
            return
        
        print(f"\n{bcolors.HEADER}Authentication Tokens{bcolors.ENDC}")
        print(f"{bcolors.HEADER}{'=' * 60}{bcolors.ENDC}")
        print(f"{'Name':<20} {'Token Preview':<20} {'Created':<20}")
        print(f"{'-' * 60}")
        
        for token_info in tokens:
            name = token_info.get('name', 'Unknown')
            token = token_info.get('token', '')
            created = token_info.get('created', 'Unknown')
            
            # Format created date
            if created != 'Unknown':
                try:
                    dt = datetime.datetime.fromisoformat(created)
                    created = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            
            # Show masked token
            token_preview = f"{token[:8]}..." if len(token) > 8 else "Invalid"
            
            print(f"{name:<20} {token_preview:<20} {created:<20}")
        
        print(f"\n{bcolors.OKBLUE}Total tokens: {len(tokens)}{bcolors.ENDC}")


class MCPRemoteTokenRevokeCommand(Command):
    """Revoke authentication token"""
    
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='mcp-server remote token revoke')
        parser.add_argument('name', help='Name of token to revoke')
        return parser
    
    def execute(self, params, **kwargs):
        name = kwargs.get('name')
        
        if not name:
            print(f"{bcolors.FAIL}Token name is required{bcolors.ENDC}")
            return
        
        tokens = params.config.get('mcp', {}).get('remote_access', {}).get('auth_tokens', [])
        
        # Find and remove token
        original_count = len(tokens)
        tokens = [t for t in tokens if t.get('name') != name]
        
        if len(tokens) == original_count:
            print(f"{bcolors.FAIL}Token '{name}' not found{bcolors.ENDC}")
            return
        
        # Update config
        params.config['mcp']['remote_access']['auth_tokens'] = tokens
        
        # Save config
        try:
            with open(params.config_filename, 'w') as f:
                json.dump(params.config, f, indent=2)
            print(f"{bcolors.OKGREEN}Token '{name}' revoked successfully{bcolors.ENDC}")
        except Exception as e:
            print(f"{bcolors.FAIL}Failed to save configuration: {e}{bcolors.ENDC}")


# Register the command
def register_commands(commands):
    commands['mcp-server'] = MCPServerCommand()


def register_command_info(aliases, command_info):
    command_info['mcp-server'] = 'Manage MCP (Model Context Protocol) server for AI agents'