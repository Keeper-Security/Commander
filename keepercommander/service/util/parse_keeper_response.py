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
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    @staticmethod
    def parse_response(command: str, response: Any) -> Dict[str, Any]:
        """
        Main parser that routes to specific command parsers based on the command type.
        
        Args:
            command (str): The executed command
            response (Any): Response from the keeper commander
            
        Returns:
            Dict[str, Any]: Structured JSON response
        """
        if not response:
            return KeeperResponseParser._handle_empty_response(command)
        
        response_str = str(response).strip()
        # Clean ANSI codes from all responses
        response_str = KeeperResponseParser._clean_ansi_codes(response_str)
        
        if '--format=json' in command:
            return KeeperResponseParser._parse_json_format_command(command, response_str)
        elif "pam project import" in command:
            return KeeperResponseParser._parse_pam_project_import_command(command, response_str)
        elif "enterprise-push" in command:
            return KeeperResponseParser._parse_enterprise_push_command(command, response_str)
        elif command.startswith("ls"):
            return KeeperResponseParser._parse_ls_command(response_str)
        elif command.startswith("tree"):
            return KeeperResponseParser._parse_tree_command(response_str)
        elif command.startswith("mkdir"):
            return KeeperResponseParser._parse_mkdir_command(response_str)
        elif command.startswith("record-add"):
            return KeeperResponseParser._parse_record_add_command(response_str)
        elif "search record" in command:
            return KeeperResponseParser._parse_search_record_command(response_str)
        elif "search folder" in command:
            return KeeperResponseParser._parse_search_folder_command(response_str)
        elif command.startswith("get") or command.startswith("download"):
            return KeeperResponseParser._parse_get_command(response_str)
        else:
            return {
                "status": "success",
                "command": command,
                "data": response_str
            }

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
            "data": []
        }
        
        current_path = []
        for line in response.strip().split("\n"):
            if not line.strip():
                continue
                
            level = (len(line) - len(line.lstrip())) // 2
            name = line.strip()
            
            while len(current_path) > level:
                current_path.pop()
            if len(current_path) == level:
                current_path.append(name)
            
            result["data"].append({
                "level": level,
                "name": name,
                "path": "/".join(current_path)
            })
        
        return result

    @staticmethod
    def _parse_mkdir_command(response: str) -> Dict[str, Any]:
        """Parse 'mkdir' command output to extract folder UID."""
        result = {
            "status": "success",
            "command": "mkdir",
            "data": None
        }
        
        response_str = response.strip()
        
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
        """Parse 'record-add' command output to extract record UID."""
        result = {
            "status": "success",
            "command": "record-add",
            "data": None
        }
        
        response_str = response.strip()
        
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
        
        for line in response.strip().split("\n"):
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
        base_command = command.split(' --format=json')[0]
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
    def _handle_empty_response(command: str) -> Dict[str, Any]:
        """Handle commands that produce no output but are successful."""
        # Commands that succeed but produce no output
        silent_success_commands = ["import", "enterprise-push"]
        
        if any(cmd in command for cmd in silent_success_commands):
            # Command-specific success messages
            if "enterprise-push" in command:
                message = "Records pushed successfully to specified users"
            elif "import" in command:
                message = "Import completed successfully"
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
                "success": False,
                "error": "Command produced no output. This may indicate a command error or invalid syntax."
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


def parse_keeper_response(command: str, response: Any) -> Dict[str, Any]:
    """
    Main entry point for parsing Keeper Commander responses.
    
    Args:
        command (str): The executed command
        response (Any): Response from the keeper commander
        
    Returns:
        Dict[str, Any]: Structured JSON response
    """
    return KeeperResponseParser.parse_response(command, response)