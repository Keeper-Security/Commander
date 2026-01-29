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

import re
from typing import Tuple, Set, Dict, List, Any
from ..decorators.logging import debug_decorator

class CommandValidator:
    @debug_decorator
    def parse_help_output(self, help_output: str) -> Tuple[Set, Dict]:
        """Parse help output to extract valid commands."""
        try:
            # Strip ANSI escape sequences that are used for colors and formatting
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_help_output = ansi_escape.sub('', help_output)
            
            valid_commands = set()
            command_info = {}
            current_category = None
            
            for line in clean_help_output.split('\n'):
                original_line = line
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Skip separator lines (lines with only dashes or special characters)
                if all(c in '─-=_' or c.isspace() for c in line):
                    continue
                
                # Check indentation level
                indent_count = len(original_line) - len(original_line.lstrip())
                if indent_count == 2 and line and not line.startswith('Type '):
                    # Skip common non-category lines
                    if line in ['Available Commands']:
                        continue
                    # This is likely a category header
                    current_category = line.rstrip(':').strip()
                    continue
                
                # Check if this is a command line (4+ spaces indent)
                if current_category and indent_count >= 4 and line:
                    self._process_new_command_line(line, valid_commands, command_info, current_category)
                    
            return valid_commands, command_info
        except Exception as e:
            import traceback 
            traceback.print_exc()
            return set(), {}
         

    @debug_decorator
    def _process_category_line(self, parts: List[str], valid_commands: Set, 
                           command_info: Dict, category: str) -> None:
        """Process a category line from help output."""
        if len(parts) > 1:
            main_command = parts[1].strip()
            valid_commands.add(main_command)
            command_info[main_command] = {'category': category}

            if len(parts) > 2 and not parts[2].startswith('...'):
                alias = parts[2].strip()
                valid_commands.add(alias)
                command_info[alias] = {'category': category, 'main_command': main_command}

    @debug_decorator
    def _process_command_line(self, parts: List[str], valid_commands: Set,
                          command_info: Dict, category: str) -> None:
        """Process a command line from help output."""
        if len(parts) >= 1:
            main_command = parts[0].strip()
            valid_commands.add(main_command)
            command_info[main_command] = {'category': category}

            if len(parts) >= 2 and not parts[1].startswith('...'):
                alias = parts[1].strip()
                valid_commands.add(alias)
                command_info[alias] = {'category': category, 'main_command': main_command}

    @debug_decorator
    def _process_new_command_line(self, line: str, valid_commands: Set,
                                 command_info: Dict, category: str) -> None:
        """Process a command line from new categorized help output."""
        # Extract command and alias from patterns like:
        # "command (alias1, alias2)   description"
        # "command (alias)   description"
        # "command   description"
        
        main_command = None
        aliases_str = None
        
        # Split line to get just the command part (before description)
        # Aliases should appear immediately after the command, before multiple spaces
        parts = line.split(None, 1)  # Split on first whitespace
        if not parts:
            return
        
        command_part = parts[0]
        
        # Check if the command part contains parentheses for aliases
        # Pattern: "command" or "command(alias)" or "command (alias)"
        if '(' in command_part and ')' in command_part:
            # Extract command and aliases from the first token
            paren_start = command_part.index('(')
            paren_end = command_part.index(')', paren_start)
            
            main_command = command_part[:paren_start].strip()
            aliases_str = command_part[paren_start+1:paren_end].strip()
        else:
            # No parentheses in first token, check if second token is aliases
            # Pattern: "command (alias1, alias2) description"
            if len(parts) > 1:
                rest = parts[1].lstrip()
                if rest.startswith('(') and ')' in rest:
                    # Find the closing parenthesis
                    paren_end = rest.index(')')
                    aliases_str = rest[1:paren_end].strip()
                    main_command = command_part
                else:
                    main_command = command_part
            else:
                main_command = command_part
        
        # Add main command
        if main_command:
            valid_commands.add(main_command)
            command_info[main_command] = {'category': category}
        
        # Add alias(es) if found - handle multiple comma-separated aliases
        if aliases_str:
            # Split on commas to handle multiple aliases like "pedm, kepm"
            aliases_list = [a.strip() for a in aliases_str.split(',')]
            for single_alias in aliases_list:
                if single_alias:  # Skip empty strings
                    valid_commands.add(single_alias)
                    command_info[single_alias] = {'category': category, 'main_command': main_command}

    def validate_command_list(self, commands: str, valid_commands: Set) -> str:
        """Validate input commands against valid commands."""
        input_commands = [cmd.strip() for cmd in commands.split(',')]
        validated_commands = []
        invalid_commands = []

        for cmd in input_commands:
            if ' ' not in cmd and cmd in valid_commands:
                validated_commands.append(cmd)
            else:
                invalid_commands.append(cmd)
                
        return ",".join(validated_commands), invalid_commands

    def generate_command_error_message(self, invalid_commands: List[str], command_info: Dict[str, Any]) -> str:
        """Generate helpful error message for invalid commands."""
        error_msg = [
            f"Invalid commands: {', '.join(invalid_commands)}", 
            "Available commands:"
        ]
        
        # Build a map of main commands to their aliases
        command_aliases = {}
        for cmd, info in command_info.items():
            if 'main_command' in info:
                main_cmd = info['main_command']
                if main_cmd not in command_aliases:
                    command_aliases[main_cmd] = []
                command_aliases[main_cmd].append(cmd)
        
        # Group commands by category
        category_commands = {}
        
        for cmd, info in command_info.items():
            # Skip aliases (they have main_command)
            if 'main_command' not in info:
                category = info.get('category', 'Other')
                if category not in category_commands:
                    category_commands[category] = []
                
                # Format command with aliases if they exist
                aliases = command_aliases.get(cmd, [])
                if aliases:
                    cmd_display = f"{cmd} ({', '.join(sorted(aliases))})"
                else:
                    cmd_display = cmd
                category_commands[category].append(cmd_display)

        # Sort categories and display commands
        for category in sorted(category_commands.keys()):
            commands = sorted(category_commands[category])
            if commands:
                error_msg.append(f"\n{category}:")
                # Join all commands with comma-space, no artificial line breaks
                error_msg.append("  " + ", ".join(commands))

        return "\n".join(error_msg)