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
Command adapter for translating between MCP and Commander.

This module serves as the bridge between MCP protocol and Keeper Commander's
command system. It handles command discovery, parameter mapping, execution,
and output formatting to ensure seamless integration between AI agents and
Commander functionality.
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from io import StringIO
import sys

from ..params import KeeperParams
from ..cli import (
    commands, command_info, aliases,
    enterprise_commands, enterprise_command_info,
    msp_commands, msp_command_info
)
from .. import api
from .formatter import OutputFormatter
from .utils import (
    is_command_interactive,
    extract_command_parameters,
    format_command_result,
    CommandNotFoundError,
    CommandExecutionError
)


class CommandAdapter:
    """Adapts Keeper Commander commands for MCP protocol"""
    
    def __init__(self, params: KeeperParams):
        self.params = params
        self._command_cache = {}
        self._discover_commands()
        
    def _sanitize_output(self, output: str, cmd_name: str) -> str:
        """
        Sanitize command output to prevent JSON parsing issues.
        
        Some commands output mixed text/JSON that can cause parsing errors.
        This method filters out problematic lines containing embedded JSON.
        """
        if not output:
            return output
            
        # Commands known to output problematic mixed text/JSON
        if cmd_name not in ['enterprise-role', 'enterprise-user', 'enterprise-team']:
            return output
            
        # Split output into lines and filter problematic ones
        lines = output.split('\n')
        filtered_lines = []
        skip_enforcements = False
        
        for line in lines:
            # Skip the Role Enforcements section which contains embedded JSON
            if 'Role Enforcements:' in line:
                skip_enforcements = True
                filtered_lines.append(line)
                filtered_lines.append('\n[Role enforcements data omitted - use --format json to see full details]')
                continue
            
            # Stop skipping when we hit an empty line after enforcements
            if skip_enforcements and line.strip() == '':
                skip_enforcements = False
                continue
                
            # Skip lines that are part of the enforcements section
            if skip_enforcements:
                continue
                
            # Keep all other lines
            filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)
    
    def _discover_commands(self):
        """Discover all available non-interactive commands"""
        self._command_cache = {}
        
        # Process main commands
        for cmd_name, cmd_class in commands.items():
            if not is_command_interactive(cmd_class):
                self._command_cache[cmd_name] = {
                    'class': cmd_class,
                    'description': command_info.get(cmd_name, ''),
                    'aliases': []
                }
        
        # Process enterprise commands
        for cmd_name, cmd_class in enterprise_commands.items():
            if not is_command_interactive(cmd_class):
                self._command_cache[cmd_name] = {
                    'class': cmd_class,
                    'description': enterprise_command_info.get(cmd_name, ''),
                    'aliases': []
                }
        
        # Process MSP commands
        for cmd_name, cmd_class in msp_commands.items():
            if not is_command_interactive(cmd_class):
                self._command_cache[cmd_name] = {
                    'class': cmd_class,
                    'description': msp_command_info.get(cmd_name, ''),
                    'aliases': []
                }
        
        # Add aliases
        for alias, cmd_name in aliases.items():
            if cmd_name in self._command_cache:
                self._command_cache[cmd_name]['aliases'].append(alias)
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools for MCP"""
        tools = []
        
        for cmd_name, cmd_info in self._command_cache.items():
            # Create tool definition
            tool = {
                "name": f"keeper_{cmd_name.replace('-', '_')}",
                "description": cmd_info['description'] or f"Execute {cmd_name} command",
                "inputSchema": extract_command_parameters(cmd_info['class'])
            }
            
            # Add aliases to description if any
            if cmd_info['aliases']:
                tool["description"] += f" (aliases: {', '.join(cmd_info['aliases'])})"
            
            tools.append(tool)
        
        return tools
    
    def get_command_from_tool(self, tool_name: str) -> Tuple[str, Any]:
        """Get command name and class from MCP tool name"""
        if not tool_name.startswith('keeper_'):
            raise CommandNotFoundError(f"Invalid tool name: {tool_name}")
        
        # Convert tool name back to command name
        cmd_name = tool_name[7:].replace('_', '-')  # Remove 'keeper_' prefix
        
        if cmd_name not in self._command_cache:
            raise CommandNotFoundError(
                f"Command '{cmd_name}' not found",
                {"tool": tool_name, "command": cmd_name}
            )
        
        return cmd_name, self._command_cache[cmd_name]['class']
    
    async def execute_command(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute a command and return formatted result"""
        cmd_name, cmd_class = self.get_command_from_tool(tool_name)
        
        # Capture output
        output_buffer = StringIO()
        error_buffer = StringIO()
        
        # Save original stdout/stderr
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        
        start_time = time.time()
        
        try:
            # Redirect output
            sys.stdout = output_buffer
            sys.stderr = error_buffer
            
            # cmd_class is already an instance, not a class
            command = cmd_class
            
            # Parse arguments if the command has a parser
            if hasattr(command, 'get_parser'):
                parser = command.get_parser()
                
                # Auto-add --format json for commands that support it (when not already specified)
                if cmd_name in ['enterprise-role', 'enterprise-user', 'enterprise-info', 'enterprise-team']:
                    if 'format' not in arguments:
                        # Check if the command supports --format flag
                        for action in parser._actions:
                            if action.dest == 'format' and '--format' in action.option_strings:
                                arguments['format'] = 'json'
                                break
                
                # Build argument list for parser
                argv = []
                positional_args = []
                
                for action in parser._actions:
                    if action.dest == 'help':
                        continue
                        
                    if action.dest in arguments:
                        value = arguments[action.dest]
                        
                        if action.option_strings:
                            # Optional argument
                            if action.__class__.__name__ in ['_StoreTrueAction', '_StoreFalseAction']:
                                # Boolean flag
                                if value:
                                    argv.append(action.option_strings[0])
                            else:
                                # Regular optional argument
                                argv.append(action.option_strings[0])
                                if isinstance(value, list):
                                    argv.extend(str(v) for v in value)
                                else:
                                    argv.append(str(value))
                        else:
                            # Positional argument - collect for later
                            if isinstance(value, list):
                                positional_args.extend(str(v) for v in value)
                            else:
                                positional_args.append(str(value))
                
                # Add positional arguments at the end
                argv.extend(positional_args)
                
                # Parse arguments
                try:
                    parsed_args = parser.parse_args(argv)
                    kwargs = vars(parsed_args)
                except SystemExit:
                    # Parser error - try to get help text
                    parser_error = error_buffer.getvalue()
                    raise CommandExecutionError(
                        f"Invalid arguments for {cmd_name}",
                        {"parser_error": parser_error, "arguments": arguments}
                    )
            else:
                # No parser, pass arguments directly
                kwargs = arguments
            
            # Execute command
            if hasattr(command, 'execute'):
                # Standard command execution
                result = await asyncio.to_thread(
                    command.execute,
                    self.params,
                    **kwargs
                )
            elif hasattr(command, 'execute_args'):
                # Some commands use execute_args
                args_str = ' '.join(str(v) for v in arguments.values())
                result = await asyncio.to_thread(
                    command.execute_args,
                    self.params,
                    args_str,
                    command=cmd_name
                )
            else:
                raise CommandExecutionError(
                    f"Command {cmd_name} has no execute method",
                    {"command": cmd_name}
                )
            
            # Get captured output
            output = output_buffer.getvalue()
            errors = error_buffer.getvalue()
            
            # Guard against problematic output patterns
            output = self._sanitize_output(output, cmd_name)
            
            # Format response for AI consumption
            execution_time = time.time() - start_time if 'start_time' in locals() else None
            
            if errors and not output:
                # Only errors - format as error
                formatted = OutputFormatter.format_error(errors)
                return OutputFormatter.add_metadata(formatted, cmd_name, execution_time)
            elif output:
                # Format stdout for AI consumption
                formatted = OutputFormatter.format_output(output, cmd_name)
                return OutputFormatter.add_metadata(formatted, cmd_name, execution_time)
            elif result is not None:
                # Use return value if no stdout
                formatted_result = format_command_result(result)
                formatted = OutputFormatter.format_output(formatted_result, cmd_name)
                return OutputFormatter.add_metadata(formatted, cmd_name, execution_time)
            else:
                # No output or return value
                return OutputFormatter.add_metadata(
                    json.dumps({"type": "success", "message": "Command executed successfully"}),
                    cmd_name,
                    execution_time
                )
            
        except SystemExit as e:
            # Some commands call sys.exit()
            output = output_buffer.getvalue()
            if e.code == 0:
                return output if output else "Command completed successfully"
            else:
                errors = error_buffer.getvalue()
                raise CommandExecutionError(
                    f"Command failed with exit code {e.code}",
                    {"exit_code": e.code, "output": output, "errors": errors}
                )
        
        except CommandExecutionError:
            # Re-raise our errors
            raise
        
        except Exception as e:
            # Include any captured output in error
            output = output_buffer.getvalue()
            errors = error_buffer.getvalue()
            
            error_details = {
                "command": cmd_name,
                "tool": tool_name,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "output": output,
                "errors": errors
            }
            
            raise CommandExecutionError(
                f"Command execution failed: {str(e)}",
                error_details
            )
        
        finally:
            # Restore stdout/stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
    
    def get_command_help(self, tool_name: str) -> str:
        """Get detailed help for a command"""
        cmd_name, cmd_class = self.get_command_from_tool(tool_name)
        
        help_text = f"Command: {cmd_name}\n"
        
        if cmd_name in command_info:
            help_text += f"Description: {command_info[cmd_name]}\n"
        
        if hasattr(cmd_class, 'get_parser'):
            parser = cmd_class.get_parser()
            help_text += f"\nUsage:\n{parser.format_help()}"
        
        return help_text