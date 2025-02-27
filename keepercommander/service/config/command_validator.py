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

from typing import List, Dict, Any
from ..decorators.logging import debug_decorator

class CommandValidator:
    @debug_decorator
    def parse_help_output(self, help_output: str) -> tuple[set, dict]:
        """Parse help output to extract valid commands."""
        valid_commands = set()
        command_info = {}
        current_category = None
        for line in help_output.split('\n'):
            line = line.strip()
            if not line or not (parts := line.split()):
                continue

            first_word = parts[0]
            if first_word in ['Vault', 'Enterprise', 'MSP']:
                self._process_category_line(parts, valid_commands, command_info, first_word)
                current_category = first_word
            elif current_category:
                self._process_command_line(parts, valid_commands, command_info, current_category)

        return valid_commands, command_info

    @debug_decorator
    def _process_category_line(self, parts: List[str], valid_commands: set, 
                           command_info: dict, category: str) -> None:
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
    def _process_command_line(self, parts: List[str], valid_commands: set,
                          command_info: dict, category: str) -> None:
        """Process a command line from help output."""
        if len(parts) >= 1:
            main_command = parts[0].strip()
            valid_commands.add(main_command)
            command_info[main_command] = {'category': category}

            if len(parts) >= 2 and not parts[1].startswith('...'):
                alias = parts[1].strip()
                valid_commands.add(alias)
                command_info[alias] = {'category': category, 'main_command': main_command}

    def validate_command_list(self, commands: str, valid_commands: set) -> str:
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
        
        category_commands = {'Vault': [], 'Enterprise': [], 'MSP': []}
        
        for cmd, info in command_info.items():
            if 'main_command' not in info:
                category = info.get('category', 'Unknown')
                if category in category_commands:
                    category_commands[category].append(cmd)

        for category, commands in category_commands.items():
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