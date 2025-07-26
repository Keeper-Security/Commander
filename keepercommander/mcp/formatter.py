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
Output formatters for AI-friendly command results.

This module provides formatters that convert Commander output into structured,
AI-consumable formats. It handles different output types (tables, lists, JSON)
and ensures consistent formatting for MCP clients.
"""

import json
import re
from typing import Any, Dict, List, Optional
from io import StringIO


class OutputFormatter:
    """Formats command output for AI consumption"""
    
    @staticmethod
    def format_table(output: str) -> str:
        """
        Convert ASCII table output to structured format.
        
        Many Commander commands output ASCII tables. This method converts them
        to a more structured format that's easier for AI to parse.
        """
        lines = output.strip().split('\n')
        if len(lines) < 3:  # Need at least header, separator, and one data row
            return output
        
        # Detect table by looking for separator lines (e.g., "----+----+----")
        separator_pattern = re.compile(r'^[\s\-\+\|]+$')
        separator_indices = [i for i, line in enumerate(lines) if separator_pattern.match(line)]
        
        if not separator_indices:
            return output
        
        # Try to parse as a simple table
        try:
            # Find header row (usually right before first separator)
            header_idx = separator_indices[0] - 1 if separator_indices[0] > 0 else 0
            headers = [h.strip() for h in re.split(r'\s{2,}|\|', lines[header_idx]) if h.strip()]
            
            # Parse data rows
            data_start = separator_indices[0] + 1
            rows = []
            
            for line in lines[data_start:]:
                if separator_pattern.match(line):
                    continue
                if not line.strip():
                    continue
                    
                # Split by multiple spaces or pipes
                values = [v.strip() for v in re.split(r'\s{2,}|\|', line) if v.strip()]
                
                if len(values) == len(headers):
                    row = dict(zip(headers, values))
                    rows.append(row)
            
            if rows:
                # Return as formatted JSON for better AI parsing
                return json.dumps({
                    "type": "table",
                    "headers": headers,
                    "rows": rows
                }, indent=2)
        
        except Exception:
            # If parsing fails, return original output
            pass
        
        return output
    
    @staticmethod
    def format_list(output: str) -> str:
        """
        Format list output for better AI consumption.
        
        Converts numbered or bulleted lists into structured format.
        """
        lines = output.strip().split('\n')
        
        # Detect list patterns
        numbered_pattern = re.compile(r'^\s*(\d+)\.\s+(.+)$')
        bullet_pattern = re.compile(r'^\s*[\*\-\•]\s+(.+)$')
        
        items = []
        list_type = None
        
        for line in lines:
            numbered_match = numbered_pattern.match(line)
            bullet_match = bullet_pattern.match(line)
            
            if numbered_match:
                list_type = 'numbered'
                items.append({
                    'index': int(numbered_match.group(1)),
                    'text': numbered_match.group(2).strip()
                })
            elif bullet_match:
                list_type = 'bullet'
                items.append({'text': bullet_match.group(1).strip()})
        
        if items and len(items) >= len(lines) * 0.5:  # At least half the lines are list items
            return json.dumps({
                "type": f"{list_type}_list",
                "items": items
            }, indent=2)
        
        return output
    
    @staticmethod
    def format_key_value(output: str) -> str:
        """
        Format key-value pair output.
        
        Many commands output data as "Key: Value" pairs. This formats them
        into a structured dictionary.
        """
        lines = output.strip().split('\n')
        kv_pattern = re.compile(r'^(.+?):\s*(.*)$')
        
        data = {}
        matched_lines = 0
        
        for line in lines:
            match = kv_pattern.match(line.strip())
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                # Convert camelCase or snake_case keys to readable format
                formatted_key = key.replace('_', ' ').title()
                data[formatted_key] = value
                matched_lines += 1
        
        # If most lines are key-value pairs, return as structured data
        if matched_lines >= len(lines) * 0.7:
            return json.dumps({
                "type": "key_value_pairs",
                "data": data
            }, indent=2)
        
        return output
    
    @staticmethod
    def format_record_output(output: str) -> str:
        """
        Format record output specially for password/credential data.
        
        Ensures sensitive information is properly marked and structured.
        """
        # Check if output contains password-like fields
        sensitive_fields = ['password', 'secret', 'key', 'token', 'credential']
        lower_output = output.lower()
        
        if any(field in lower_output for field in sensitive_fields):
            # Try to parse as key-value with sensitive data marking
            lines = output.strip().split('\n')
            data = {}
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Mark sensitive fields
                    is_sensitive = any(field in key.lower() for field in sensitive_fields)
                    
                    if is_sensitive and value:
                        data[key] = {
                            "value": value,
                            "sensitive": True
                        }
                    else:
                        data[key] = value
            
            if data:
                return json.dumps({
                    "type": "record",
                    "fields": data
                }, indent=2)
        
        return output
    
    @staticmethod
    def format_error(output: str) -> str:
        """
        Format error messages for clear AI understanding.
        
        Extracts error type, message, and suggestions when available.
        """
        error_patterns = [
            re.compile(r'Error:\s*(.+)', re.IGNORECASE),
            re.compile(r'Exception:\s*(.+)', re.IGNORECASE),
            re.compile(r'Failed:\s*(.+)', re.IGNORECASE),
        ]
        
        for pattern in error_patterns:
            match = pattern.search(output)
            if match:
                return json.dumps({
                    "type": "error",
                    "message": match.group(1).strip(),
                    "full_output": output
                }, indent=2)
        
        return output
    
    @staticmethod
    def format_output(output: str, command: Optional[str] = None) -> str:
        """
        Main formatting method that determines the best format for the output.
        
        Args:
            output: Raw command output
            command: Optional command name for context-specific formatting
        
        Returns:
            Formatted output suitable for AI consumption
        """
        if not output or not output.strip():
            return "Command executed successfully (no output)"
        
        output = output.strip()
        
        # Try JSON first (already structured)
        try:
            parsed = json.loads(output)
            # Already JSON, just ensure it's pretty-printed
            return json.dumps(parsed, indent=2)
        except json.JSONDecodeError as e:
            # Check if this might be malformed JSON that we can fix
            # Common issue: unquoted string values like {"role":PAM Admins}
            if output.startswith('{') and output.endswith('}'):
                # Try to fix common JSON issues
                try:
                    # Look for patterns like :"value" where value is unquoted
                    import re
                    # Pattern to find unquoted values after colons
                    pattern = r':\s*([^",\}\{]+)(?=[,\}])'
                    
                    def quote_value(match):
                        value = match.group(1).strip()
                        # Don't quote if it's already a valid JSON literal
                        if value in ('true', 'false', 'null') or value.replace('.', '', 1).replace('-', '', 1).isdigit():
                            return f': {value}'
                        # Quote the value
                        return f': "{value}"'
                    
                    fixed_output = re.sub(pattern, quote_value, output)
                    parsed = json.loads(fixed_output)
                    # Successfully fixed the JSON
                    return json.dumps(parsed, indent=2)
                except:
                    # Couldn't fix it, continue with other formatters
                    pass
        
        # Check for errors first
        if any(word in output.lower() for word in ['error', 'exception', 'failed']):
            formatted = OutputFormatter.format_error(output)
            if formatted != output:
                return formatted
        
        # Try different formatters based on output characteristics
        formatters = [
            OutputFormatter.format_table,
            OutputFormatter.format_key_value,
            OutputFormatter.format_list,
            OutputFormatter.format_record_output,
        ]
        
        for formatter in formatters:
            formatted = formatter(output)
            if formatted != output:  # Formatter succeeded
                return formatted
        
        # If no formatter matched, return cleaned output
        return output
    
    @staticmethod
    def add_metadata(output: str, command: str, execution_time: Optional[float] = None) -> str:
        """
        Add metadata to the output for better context.
        
        Args:
            output: Formatted command output
            command: Command that was executed
            execution_time: Optional execution time in seconds
        
        Returns:
            Output with metadata wrapper
        """
        metadata = {
            "command": command,
            "success": True
        }
        
        if execution_time is not None:
            metadata["execution_time_seconds"] = round(execution_time, 3)
        
        # Try to parse the output to embed it properly
        try:
            parsed_output = json.loads(output)
            return json.dumps({
                "metadata": metadata,
                "result": parsed_output
            }, indent=2)
        except json.JSONDecodeError:
            # Output is not JSON, include as string
            return json.dumps({
                "metadata": metadata,
                "result": {
                    "type": "text",
                    "content": output
                }
            }, indent=2)