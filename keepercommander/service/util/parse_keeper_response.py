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

from typing import Any, Dict
import re, json

class KeeperResponseParser:
    @staticmethod
    def _clean_ansi_codes(text: str) -> str:
        """Remove ANSI escape codes from text."""
        if not text:
            return text
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    @staticmethod
    def _format_multiline_message(text: str) -> str:
        """Format multi-line text for better JSON readability."""
        if not text:
            return text
        
        # Check if the text has multiple lines
        if '\n' in text:
            # Split into lines and return as array for better structure
            lines = [line.strip() for line in text.split('\n') if line.strip()]
            return lines
        
        return text
    
    @staticmethod
    def _preprocess_response(response: Any, log_output: str = None) -> tuple[str, bool]:
        """Preprocess response by cleaning ANSI codes and determining source.
        
        Returns:
            tuple: (cleaned_response_str, is_from_log_output)
        """
        # Priority: use log_output if no regular response OR if response is empty/whitespace
        if isinstance(response, dict):
            response_str = json.dumps(response)
        else:
            response_str = str(response).strip() if response else ""
        log_str = log_output.strip() if log_output else ""
        
        # Use log_output if response is empty/whitespace but log_output has content
        if (not response_str and log_str):
            response_str = log_str
            is_from_log = True
        elif response_str:
            is_from_log = False
        else:
            return "", False
            
        # Clean ANSI codes once
        cleaned_response = KeeperResponseParser._clean_ansi_codes(response_str)
        return cleaned_response, is_from_log
    
    @staticmethod
    def _find_parser_method(command: str) -> str:
        """Find the appropriate parser method for a command.
        
        Returns:
            str: Method name to call for parsing
        """
        # Check for JSON format first (highest priority)
        if '--format=json' in command or '--format json' in command:
            return '_parse_json_format_command'
        
        # Check for other substring matches
        substring_patterns = {
            'pam project import': '_parse_pam_project_import_command',
            'enterprise-push': '_parse_enterprise_push_command',
            'search record': '_parse_search_record_command',
            'search folder': '_parse_search_folder_command',
        }
        
        for pattern, method_name in substring_patterns.items():
            if pattern in command:
                return method_name
        
        # Check for exact command start matches
        exact_patterns = {
            'generate': '_parse_generate_command',
            'ls': '_parse_ls_command',
            'tree': '_parse_tree_command', 
            'whoami': '_parse_whoami_command',
            'this-device': '_parse_this_device_command',
            'mkdir': '_parse_mkdir_command',
            'record-add': '_parse_record_add_command',
            'get': '_parse_get_command',
            'download': '_parse_get_command',
        }
        
        for pattern, method_name in exact_patterns.items():
            if command.startswith(pattern):
                return method_name
        
        # Default to logging-based parsing
        return '_parse_logging_based_command'
    
    @staticmethod
    def parse_response(command: str, response: Any, log_output: str = None) -> Dict[str, Any]:
        """
        Main parser that routes to specific command parsers based on the command type.
        
        Args:
            command (str): The executed command
            response (Any): Response from the keeper commander
            log_output (str, optional): Captured log output from command execution
            
        Returns:
            Dict[str, Any]: Structured JSON response
        """
        # Preprocess response once
        response_str, is_from_log = KeeperResponseParser._preprocess_response(response, log_output)
        
        # Handle completely empty responses
        if not response_str:
            return KeeperResponseParser._handle_empty_response(command)
        
        # If from log output, use logging-based parsing directly
        if is_from_log:
            return KeeperResponseParser._parse_logging_based_command(command, response_str)
        
        # Find and call the appropriate parser method
        parser_method_name = KeeperResponseParser._find_parser_method(command)
        parser_method = getattr(KeeperResponseParser, parser_method_name)
        
        # Call the parser method with appropriate arguments
        if parser_method_name in ['_parse_generate_command', '_parse_json_format_command', 
                                '_parse_pam_project_import_command', '_parse_enterprise_push_command']:
            return parser_method(command, response_str)
        else:
            return parser_method(response_str) if parser_method_name != '_parse_logging_based_command' else parser_method(command, response_str)

    @staticmethod
    def _parse_ls_command(response: str) -> Dict[str, Any]:
        """Parse 'ls' command output into structured format."""
        result = {
            "status": "success",
            "command": "ls",
            "data": {
                "folders": [],
                "records": []
            }
        }

        if "# Folder UID" in response or "# Record UID" in response:
            sections = re.split(r'(?=#\s+(?:Folder|Record))', response)
            
            for section in sections:
                if not section.strip():
                    continue
                    
                lines = section.strip().split("\n")
                
                if "Folder UID" in lines[0]:
                    data_lines = [line for line in lines if re.match(r'\s*\d+\s+', line)]
                    for line in data_lines:
                        match = re.match(r'\s*(\d+)\s+(\S+)\s+(.+?)\s+(\S+)\s*$', line)
                        if match:
                            result["data"]["folders"].append({
                                "number": int(match.group(1)),
                                "name": match.group(3).strip(),
                            })
                
                elif "Record UID" in lines[0]:
                    data_lines = [line for line in lines if re.match(r'\s*\d+\s+', line)]
                    for line in data_lines:
                        match = re.match(r'\s*(\d+)\s+(\S+)\s+(\S*)\s+([^@]+?)(?:\s{2,}(.+))?$', line)
                        if match:
                            record = {
                                "number": int(match.group(1)),
                                "title": match.group(4).strip()
                            }
                            if match.group(5):
                                record["description"] = match.group(5).strip()
                            result["data"]["records"].append(record)
        else:
            # Handle simple format (just names)
            lines = response.strip().split('\n')
            folder_count = 0
            record_count = 0
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if line.endswith('/'):
                    folder_count += 1
                    result["data"]["folders"].append({
                        "number": folder_count,
                        "name": line[:-1],  # Remove trailing slash
                    })
                else:
                    record_count += 1
                    result["data"]["records"].append({
                        "number": record_count,
                        "title": line
                    })

        return result

    @staticmethod
    def _parse_tree_command(response: str) -> Dict[str, Any]:
        """Parse 'tree' command output into structured format."""
        result = {
            "status": "success",
            "command": "tree",
            "data": {
                "tree": [],
                "share_permissions_key": None
            }
        }
        
        lines = response.strip().split("\n")
        current_path = []
        
        # Check if this has share permissions key
        if "Share Permissions Key:" in response:
            # Extract share permissions key
            key_lines = []
            tree_start_idx = 0
            
            for i, line in enumerate(lines):
                if "Share Permissions Key:" in line:
                    # Find the key section
                    j = i
                    while j < len(lines) and not (line.strip() and " ├── " in lines[j] or " └── " in lines[j] or lines[j].strip() == "My Vault"):
                        if lines[j].strip() and not lines[j].startswith("="):
                            if "=" in lines[j] and lines[j].strip() != "Share Permissions Key:":
                                key_lines.append(lines[j].strip())
                        j += 1
                    tree_start_idx = j
                    break
            
            if key_lines:
                result["data"]["share_permissions_key"] = key_lines
            
            # Use only the tree part
            lines = lines[tree_start_idx:]
        
        for line in lines:
            if not line.strip():
                continue
            
            # Skip the root "My Vault" line
            if line.strip() == "My Vault":
                continue
            
            # Skip share permission lines
            if any(perm in line for perm in ["Share Permissions Key:", "=======", "RO =", "MU =", "MR =", "CE =", "CS ="]):
                continue
                
            # Calculate level based on tree characters
            cleaned_line = line
            level = 0
            
            # Count tree depth by looking for tree characters
            while True:
                if cleaned_line.startswith(" │   "):
                    level += 1
                    cleaned_line = cleaned_line[4:]
                elif cleaned_line.startswith(" ├── "):
                    cleaned_line = cleaned_line[5:]
                    break
                elif cleaned_line.startswith(" └── "):
                    cleaned_line = cleaned_line[5:]
                    break
                elif cleaned_line.startswith("    "):
                    level += 1
                    cleaned_line = cleaned_line[4:]
                else:
                    break
            
            # Parse the cleaned line
            name = cleaned_line.strip()
            if not name:
                continue
                
            is_record = "[Record]" in name
            is_shared = "[SHARED]" in name
            
            # Extract UID if present (for -v flag)
            uid = None
            uid_match = re.search(r'\(([^)]+)\)', name)
            if uid_match and not any(x in uid_match.group(1) for x in ["default:", "user:"]):
                uid = uid_match.group(1)
            
            # Extract share permissions if present (for -s flag)
            share_permissions = None
            perm_match = re.search(r'\(default:([^;]+); user:([^)]+)\)', name)
            if perm_match:
                share_permissions = {
                    "default": perm_match.group(1),
                    "user": perm_match.group(2)
                }
            
            # Clean the name from all indicators
            clean_name = name
            clean_name = re.sub(r' \([^)]*\) \[SHARED\] \([^)]*\)', '', clean_name)  # Remove UID + SHARED + permissions
            clean_name = re.sub(r' \([^)]*\) \[Record\]', '', clean_name)  # Remove UID + Record
            clean_name = re.sub(r' \([^)]*\) \[SHARED\]', '', clean_name)  # Remove UID + SHARED
            clean_name = re.sub(r' \([^)]*\)', '', clean_name)  # Remove just UID
            clean_name = clean_name.replace(" [Record]", "").replace(" [SHARED]", "")
            
            # Determine type
            item_type = "record" if is_record else "folder"
            
            # Build path
            while len(current_path) > level:
                current_path.pop()
            
            if len(current_path) == level:
                current_path.append(clean_name)
            else:
                current_path = current_path[:level] + [clean_name]
            
            # Create item structure
            item = {
                "name": clean_name,
                "type": item_type,
                "level": level,
                "path": "/".join(current_path),
                "shared": is_shared
            }
            
            # Add optional fields
            if uid:
                item["uid"] = uid
            if share_permissions:
                item["share_permissions"] = share_permissions
            
            result["data"]["tree"].append(item)
        
        return result

    @staticmethod
    def _parse_whoami_command(response: str) -> Dict[str, Any]:
        """Parse 'whoami' command output into structured format."""
        result = {
            "status": "success",
            "command": "whoami",
            "data": {}
        }
        
        if "Not logged in" in response:
            result["data"]["logged_in"] = False
            result["data"]["message"] = "Not logged in"
            return result
        
        result["data"]["logged_in"] = True
        
        # Parse each line of the whoami output
        for line in response.strip().split("\n"):
            line = line.strip()
            if not line or line == "":
                continue
                
            if ":" in line:
                # Split on first colon only
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                
                # Convert key to snake_case and normalize
                key_normalized = key.lower().replace(" ", "_").replace("&", "and")
                
                # Handle special cases
                if key_normalized == "user":
                    result["data"]["user"] = value
                elif key_normalized == "server":
                    result["data"]["server"] = value
                elif key_normalized == "data_center":
                    result["data"]["data_center"] = value
                elif key_normalized == "environment":
                    result["data"]["environment"] = value
                elif key_normalized == "admin":
                    result["data"]["admin"] = value.lower() == "yes"
                elif key_normalized == "account_type":
                    result["data"]["account_type"] = value
                elif key_normalized == "renewal_date":
                    result["data"]["renewal_date"] = value
                elif key_normalized == "storage_capacity":
                    result["data"]["storage_capacity"] = value
                elif key_normalized == "usage":
                    result["data"]["storage_usage"] = value
                elif key_normalized == "storage_renewal_date":
                    result["data"]["storage_renewal_date"] = value
                elif key_normalized == "breachwatch":
                    result["data"]["breachwatch"] = value.lower() == "yes"
                elif key_normalized == "reporting_and_alerts":
                    result["data"]["reporting_and_alerts"] = value.lower() == "yes"
                elif key_normalized == "records":
                    try:
                        result["data"]["records_count"] = int(value)
                    except ValueError:
                        result["data"]["records_count"] = value
                elif key_normalized == "shared_folders":
                    try:
                        result["data"]["shared_folders_count"] = int(value)
                    except ValueError:
                        result["data"]["shared_folders_count"] = value
                elif key_normalized == "teams":
                    try:
                        result["data"]["teams_count"] = int(value)
                    except ValueError:
                        result["data"]["teams_count"] = value
                elif key_normalized == "base_plan":
                    result["data"]["base_plan"] = value
                elif key_normalized == "expires":
                    result["data"]["license_expires"] = value
                elif key_normalized == "user_licenses":
                    result["data"]["user_licenses"] = value
                elif key_normalized == "secure_file_storage":
                    result["data"]["secure_file_storage"] = value
                elif "secure_add_ons" in key_normalized or key_normalized == "":
                    # Handle add-ons (multiple lines with same key or empty key)
                    if "add_ons" not in result["data"]:
                        result["data"]["add_ons"] = []
                    if value:  # Only add non-empty values
                        result["data"]["add_ons"].append(value)
                else:
                    # Generic handling for other fields
                    result["data"][key_normalized] = value
        
        return result

    @staticmethod
    def _parse_this_device_command(response: str) -> Dict[str, Any]:
        """Parse 'this-device' command output into structured format."""
        result = {
            "status": "success",
            "command": "this-device",
            "data": {}
        }
        
        # Parse each line of the this-device output
        for line in response.strip().split("\n"):
            line = line.strip()
            if not line or line == "":
                continue
                
            if ":" in line:
                # Split on first colon only
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                
                # Convert key to snake_case and normalize
                key_normalized = key.lower().replace(" ", "_").replace("-", "_")
                
                # Handle special cases and convert values
                if key_normalized == "device_name":
                    result["data"]["device_name"] = value
                elif key_normalized == "data_key_present":
                    result["data"]["data_key_present"] = value.upper() == "YES"
                elif key_normalized == "ip_auto_approve":
                    result["data"]["ip_auto_approve"] = value.upper() == "ON"
                elif key_normalized == "persistent_login":
                    result["data"]["persistent_login"] = value.upper() == "ON"
                elif key_normalized == "security_key_no_pin":
                    result["data"]["security_key_no_pin"] = value.upper() == "ON"
                elif key_normalized == "device_logout_timeout":
                    result["data"]["device_logout_timeout"] = value
                elif key_normalized == "is_sso_user":
                    result["data"]["is_sso_user"] = value.lower() == "true"
                else:
                    # Generic handling for other fields
                    result["data"][key_normalized] = value
            elif "Available sub-commands:" in line:
                # Extract sub-commands
                sub_commands = line.split("Available sub-commands:")[1].strip()
                if sub_commands:
                    result["data"]["available_sub_commands"] = [cmd.strip() for cmd in sub_commands.split(",")]
        
        return result

    @staticmethod
    def _parse_mkdir_command(response: str) -> Dict[str, Any]:
        """Parse 'mkdir' command output to extract folder UID."""
        response_str = response.strip()
        
        # Success case - try to extract UID
        result = {
            "status": "success",
            "command": "mkdir",
            "data": None
        }
        
        if re.match(r'^[a-zA-Z0-9_-]+$', response_str):
            result["data"] = {
                "folder_uid": response_str
            }
        else:
            uid_match = re.search(r'folder_uid=([a-zA-Z0-9_-]+)', response_str)
            if uid_match:
                result["data"] = {
                    "folder_uid": uid_match.group(1)
                }
            
        return result

    @staticmethod
    def _parse_record_add_command(response: str) -> Dict[str, Any]:
        """Parse 'record-add' command output to extract record UID or handle errors."""
        response_str = response.strip()
        
        # Check for error messages first
        response_lower = response_str.lower()
        error_patterns = ["error", "failed", "invalid", "unrecognized"]
        warning_patterns = ["already exists"]
        
        if any(pattern in response_lower for pattern in error_patterns):
            return {
                "status": "error",
                "command": "record-add",
                "error": response_str
            }
        elif any(pattern in response_lower for pattern in warning_patterns):
            return {
                "status": "warning",
                "command": "record-add",
                "message": response_str,
                "data": None
            }
        
        # Success case - try to extract UID
        result = {
            "status": "success",
            "command": "record-add",
            "data": None
        }
        
        if re.match(r'^[a-zA-Z0-9_-]+$', response_str):
            result["data"] = {
                "record_uid": response_str
            }
        else:
            uid_match = re.search(r'record_uid=([a-zA-Z0-9_-]+)', response_str)
            if uid_match:
                result["data"] = {
                    "record_uid": uid_match.group(1)
                }
        
        return result

    @staticmethod
    def _parse_search_record_command(response: str) -> Dict[str, Any]:
        """Parse 'search record' command output."""
        result = {
            "status": "success",
            "command": "search record",
            "data": []
        }
        
        lines = response.strip().split("\n")
        
        data_lines = [line for line in lines[2:] if line.strip() and not line.startswith('---')]
        
        for line in data_lines:
            match = re.match(r'\s*(\d+)\s+(\S+)\s+(\S*)\s+(.+?)\s{2,}(.+)?$', line)
            if match:
                record = {
                    "number": int(match.group(1)),
                    "uid": match.group(2),
                    "type": match.group(3),
                    "title": match.group(4).strip()
                }
                if match.group(5):
                    record["description"] = match.group(5).strip()
                result["data"].append(record)
        
        return result

    @staticmethod
    def _parse_search_folder_command(response: str) -> Dict[str, Any]:
        """Parse 'search folder' command output."""
        result = {
            "status": "success",
            "command": "search folder",
            "data": []
        }
        
        lines = response.strip().split("\n")
        
        data_lines = [line for line in lines[2:] if line.strip() and not line.startswith('---')]
        
        for line in data_lines:
            match = re.match(r'\s*(\d+)\s+(\S+)\s+(.+)$', line)
            if match:
                folder = {
                    "number": int(match.group(1)),
                    "uid": match.group(2),
                    "name": match.group(3).strip()
                }
                result["data"].append(folder)
        
        return result

    @staticmethod
    def _parse_get_command(response: str) -> Dict[str, Any]:
        """Parse 'get' command output."""
        result = {
            "status": "success",
            "command": "get",
            "data": {}
        }
        
        response_lines = response.strip().split("\n")
        
        # Handle special case for --format password (single line with just the password)
        if len(response_lines) == 1 and ":" not in response_lines[0]:
            # This is likely a password from --format password
            password_line = response_lines[0].strip()
            if password_line:
                result["data"]["password"] = password_line
                return result
        
        # Handle regular get command output with key-value pairs
        for line in response_lines:
            if ":" in line:
                key, value = line.split(":", 1)
                result["data"][key.strip().lower().replace(" ", "_")] = value.strip()
                
        return result
    
    @staticmethod
    def _parse_pam_project_import_command(command: str, response: str) -> Dict[str, Any]:
        """Parse 'pam project import' command output."""
        result = {
            "status": "success",
            "command": "pam project import",
            "data": {
                "dry_run": "--dry-run" in command,
                "messages": [],
                "access_token": None,
                "device_uid": None,
                "shared_folder_resources_uid": None,
                "shared_folder_users_uid": None,
                "note": None,
                "documentation_url": None
            }
        }
        
        lines = response.strip().split('\n')
        
        # Check if this is a dry run
        if "[DRY RUN]" in response:
            result["data"]["dry_run"] = True
            # Extract dry run messages
            for line in lines:
                if line.strip() and not line.startswith('[DRY RUN COMPLETE]'):
                    if line.startswith('[DRY RUN]'):
                        result["data"]["messages"].append(line.strip())
                    elif line.startswith('Will '):
                        result["data"]["messages"].append(line.strip())
                    elif 'Started parsing import data' in line or 'Will import file data here' in line:
                        result["data"]["messages"].append(line.strip())
        else:
            # Parse actual execution output
            json_start = -1
            for i, line in enumerate(lines):
                # Look for JSON output (starts with {)
                if line.strip().startswith('{'):
                    json_start = i
                    break
                elif line.strip():
                    result["data"]["messages"].append(line.strip())
            
            # Extract JSON data if found
            if json_start >= 0:
                json_lines = []
                brace_count = 0
                for line in lines[json_start:]:
                    json_lines.append(line)
                    brace_count += line.count('{') - line.count('}')
                    if brace_count == 0 and line.strip().endswith('}'):
                        break
                
                json_text = '\n'.join(json_lines)
                try:
                    json_data = json.loads(json_text)
                    result["data"]["access_token"] = json_data.get("access_token")
                    result["data"]["device_uid"] = json_data.get("device_uid")
                    result["data"]["shared_folder_resources_uid"] = json_data.get("shared_folder_resources_uid")
                    result["data"]["shared_folder_users_uid"] = json_data.get("shared_folder_users_uid")
                    result["data"]["note"] = json_data.get("note")
                except json.JSONDecodeError:
                    # If JSON parsing fails, add it as a message
                    result["data"]["messages"].append(json_text)
            
            # Extract documentation URL
            for line in lines:
                if "https://docs.keeper.io" in line:
                    result["data"]["documentation_url"] = line.split("https://docs.keeper.io")[1].strip()
                    result["data"]["documentation_url"] = "https://docs.keeper.io" + result["data"]["documentation_url"]
                    break
        
        return result
    
    @staticmethod
    def _parse_json_format_command(command: str, response: str) -> Dict[str, Any]:
        """
        Parse commands with --format=json flag into structured format.
        
        Args:
            command (str): The executed command (e.g., 'audit-report --format=json')
            response (str): JSON response string from the keeper commander
            
        Returns:
            Dict[str, Any]: Structured response with standard format
        """
        # Extract base command by removing --format=json or --format json
        if ' --format=json' in command:
            base_command = command.split(' --format=json')[0]
        elif ' --format json' in command:
            base_command = command.split(' --format json')[0]
        else:
            base_command = command.split()[0] if command.split() else command
        result = {
            "status": "success",
            "command": base_command,
            "data": None
        }

        try:
            parsed_data = json.loads(response)
            result["data"] = parsed_data
        
        except TypeError:
            result["data"] = response
            
        except json.JSONDecodeError:
            result["status"] = "error"
            result["error"] = "Invalid JSON response"
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            
        finally:
            return result

    @staticmethod
    def _parse_generate_command(command: str, response_str: str) -> Dict[str, Any]:
        """Parse generate command output to extract password(s) and metadata."""
        if not response_str:
            return {
                "status": "error",
                "command": "generate",
                "error": "Generate command produced no output"
            }
        
        try:
            # Check if it's JSON format output
            if '--format=json' in command:
                try:
                    json_data = json.loads(response_str)
                    return {
                        "status": "success",
                        "command": "generate",
                        "message": "Password generated successfully",
                        "data": json_data
                    }
                except json.JSONDecodeError:
                    pass
            
            # Check if it's quiet mode (password only)
            if '--quiet' in command or '--password-list' in command:
                passwords = [line.strip() for line in response_str.split('\n') if line.strip()]
                return {
                    "status": "success",
                    "command": "generate",
                    "message": "Password generated successfully",
                    "data": {
                        "passwords": passwords,
                        "count": len(passwords)
                    }
                }
            
            # Parse table format (default)
            lines = response_str.split('\n')
            passwords = []
            
            for line in lines:
                line = line.strip()
                if not line or 'Strength(%)' in line or 'BreachWatch' in line or 'Password' in line:
                    continue
                
                # Parse table row: "1    100          Passed       Cr?i+RRaKeDjil8xe}tD"
                parts = line.split()
                if len(parts) >= 3:
                    # Extract password (last part)
                    password = parts[-1]
                    
                    # Extract strength (second part)
                    try:
                        strength = int(parts[1])
                    except (ValueError, IndexError):
                        strength = None
                    
                    # Extract breach watch status (third part if exists)
                    breach_watch = None
                    if len(parts) >= 4:
                        breach_watch = parts[2] if parts[2] in ['Passed', 'Failed'] else None
                    
                    passwords.append({
                        "password": password,
                        "strength": strength,
                        "breach_watch": breach_watch
                    })
            
            if passwords:
                return {
                    "status": "success",
                    "command": "generate",
                    "message": "Password generated successfully",
                    "data": {
                        "passwords": passwords,
                        "count": len(passwords)
                    }
                }
            else:
                # Fallback: return the raw response as the password
                return {
                    "status": "success",
                    "command": "generate", 
                    "message": "Password generated successfully",
                    "data": {
                        "passwords": [{"password": response_str.strip()}],
                        "count": 1
                    }
                }
                
        except Exception as e:
            # If parsing fails, return raw response
            return {
                "status": "success",
                "command": "generate",
                "message": "Password generated successfully",
                "data": {
                    "passwords": [{"password": response_str.strip()}],
                    "count": 1,
                    "raw_output": response_str
                }
            }

    @staticmethod
    def _handle_empty_response(command: str) -> Dict[str, Any]:
        """Handle commands that produce no output but are successful."""
        # These commands truly produce no output (no logs, no stdout) and should be treated as silent success
        silent_success_commands = [
            "sync-down", "logout", "keep-alive", "set", "record-update", "append-notes", "mv", "ln"
        ]
        
        if any(cmd in command for cmd in silent_success_commands):
            # Command-specific success messages for truly silent commands
            if "sync-down" in command:
                message = "Vault synchronized successfully"
            elif "logout" in command:
                message = "Logged out successfully"
            elif "keep-alive" in command:
                message = "Session kept alive successfully"
            elif "set" in command:
                message = "Configuration updated successfully"
            elif "record-update" in command:
                message = "Record updated successfully"
            elif "append-notes" in command:
                message = "Notes appended successfully"
            elif "mv" in command:
                message = "Item moved successfully"
            elif "ln" in command:
                message = "Link created successfully"
            else:
                message = "Command executed successfully"
            
            return {
                "status": "success",
                "command": command.split()[0] if command.split() else command,
                "message": message,
                "data": None
            }
        else:
            return {
                "status": "success",
                "command": command.split()[0] if command.split() else command,
                "message": "Command executed successfully but produced no output",
                "data": None
            }

    @staticmethod
    def _parse_enterprise_push_command(command: str, response_str: str) -> Dict[str, Any]:
        """Parse enterprise-push command responses."""

        if "Pushed" in response_str and "record(s)" in response_str:
            # Extract the actual push message
            lines = response_str.split('\n')
            for line in lines:
                if "Pushed" in line and "record(s)" in line:
                    return {
                        "status": "success",
                        "command": "enterprise-push",
                        "message": line.strip(),
                        "data": None
                    }
        
        # Fallback for other enterprise-push responses
        return {
            "status": "success",
            "command": "enterprise-push", 
            "message": response_str if response_str else "Records pushed successfully to specified users",
            "data": None
        }


    @staticmethod
    def _parse_logging_based_command(command: str, response_str: str) -> Dict[str, Any]:
        """Parse commands that primarily use logging.info() for output."""
        response_str = response_str.strip()
        
        # Filter out biometric and persistent login messages for cleaner API responses
        response_str = KeeperResponseParser._filter_login_messages(response_str)
        
        # Determine status based on common patterns
        status = "success"
        
        # Check for error patterns (case insensitive)
        error_patterns = [
            "error", "failed", "invalid", "not found", "does not exist", 
            "permission denied", "unauthorized", "cannot be", "character", "reserved", "unrecognized"
        ]
        
        # Check for warning patterns
        warning_patterns = ["warning:", "already exists"]
        
        response_lower = response_str.lower()
        
        if any(pattern in response_lower for pattern in error_patterns):
            return {
                "status": "error",
                "command": command.split()[0] if command.split() else command,
                "error": response_str
            }
        elif any(pattern in response_lower for pattern in warning_patterns):
            status = "warning"
        
        # Return the actual log message with proper formatting
        if response_str:
            formatted_message = KeeperResponseParser._format_multiline_message(response_str)
            return {
                "status": status,
                "command": command.split()[0] if command.split() else command,
                "message": formatted_message,
                "data": None
            }
        else:
            # No output after cleaning - use existing empty response handler
            return KeeperResponseParser._handle_empty_response(command)
    
    @staticmethod
    def _filter_login_messages(response_str: str) -> str:
        """Filter out biometric and persistent login messages from response."""
        if not response_str:
            return response_str
        
        # Common login messages to filter out
        login_patterns = [
            "Logging in to Keeper Commander",
            "Successfully authenticated with Persistent Login",
            "Successfully authenticated with Biometric Login",
            "Attempting biometric authentication...",
            "Press Ctrl+C to skip biometric and use default login method",
            "Syncing...",
            "Decrypted [",
            "records that are affected by breaches",
            "Use \"breachwatch list\" command"
        ]
        
        lines = response_str.split('\n')
        filtered_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Skip login-related lines
            if any(pattern in line for pattern in login_patterns):
                continue
                
            filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)



def parse_keeper_response(command: str, response: Any, log_output: str = None) -> Dict[str, Any]:
    """
    Main entry point for parsing Keeper Commander responses.
    
    Args:
        command (str): The executed command
        response (Any): Response from the keeper commander
        log_output (str, optional): Captured log output from command execution
        
    Returns:
        Dict[str, Any]: Structured JSON response
    """
    return KeeperResponseParser.parse_response(command, response, log_output)