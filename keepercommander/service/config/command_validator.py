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
                    
                # Check if this is a category header (ends with colon)
                if line.endswith(':') and not line.startswith(' '):
                    # Remove the colon and use as category
                    current_category = line[:-1].strip()
                    continue
                
                # Check if this is an indented command line (starts with spaces in original)
                if current_category and original_line.startswith('  ') and line:
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
        # "command (alias)   description"
        # "command   description"
        
        # Split on whitespace to separate command from description
        parts = line.split()
        if not parts:
            return
            
        main_command = parts[0]
        alias = None
        
        # Check if there's an alias in parentheses as the next token
        if len(parts) > 1 and parts[1].startswith('(') and parts[1].endswith(')'):
            # Extract alias: "(alias)" -> "alias"
            alias = parts[1][1:-1].strip()
        # Check if command and alias are combined: "command (alias)"
        elif '(' in main_command and ')' in main_command:
            # Extract main command and alias: "command (alias)"
            command_alias_part = main_command
            main_command = command_alias_part.split('(')[0].strip()
            alias_with_paren = command_alias_part.split('(')[1]
            alias = alias_with_paren.split(')')[0].strip()
        
        # Add main command
        if main_command:
            valid_commands.add(main_command)
            command_info[main_command] = {'category': category}
        
        # Add alias if found
        if alias:
            valid_commands.add(alias)
            command_info[alias] = {'category': category, 'main_command': main_command}

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
                
        return ", ".join(validated_commands), invalid_commands

    def generate_command_error_message(self, invalid_commands: List[str], command_info: Dict[str, Any]) -> str:
        """Generate helpful error message for invalid commands."""
        error_msg = [
            f"Invalid commands: {', '.join(invalid_commands)}", 
            "Available commands:"
        ]
        
        # Group commands by category, handling the new category names
        category_commands = {}
        
        for cmd, info in command_info.items():
            # Skip aliases (they have main_command)
            if 'main_command' not in info:
                category = info.get('category', 'Other')
                if category not in category_commands:
                    category_commands[category] = []
                category_commands[category].append(cmd)

        # Sort categories and display commands
        for category in sorted(category_commands.keys()):
            commands = category_commands[category]
            if commands:
                error_msg.append(f"\n{category}:")
                sorted_commands = sorted(commands)
                command_lines = []
                for i in range(0, len(sorted_commands), 12):
                    command_lines.append(", ".join(sorted_commands[i:i+12]))
                    try:
                        _ = sorted_commands[i+13]
                        command_lines[-1] += (", ")
                    except IndexError:
                        pass
                error_msg.extend(command_lines)

        return "\n".join(error_msg)