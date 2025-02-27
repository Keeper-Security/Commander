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
            return {"status": "success", "data": None}
        
        response_str = str(response).strip()
        if '--format=json' in command:
            return KeeperResponseParser._parse_json_format_command(command, response_str)
        if command.startswith("ls"):
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
                            "uid": match.group(2),
                            "name": match.group(3).strip(),
                            "flags": match.group(4)
                        })
            
            elif "Record UID" in lines[0]:
                data_lines = [line for line in lines if re.match(r'\s*\d+\s+', line)]
                for line in data_lines:
                    match = re.match(r'\s*(\d+)\s+(\S+)\s+(\S*)\s+([^@]+?)(?:\s{2,}(.+))?$', line)
                    if match:
                        record = {
                            "number": int(match.group(1)),
                            "uid": match.group(2),
                            "type": match.group(3),
                            "title": match.group(4).strip()
                        }
                        if match.group(5):
                            record["description"] = match.group(5).strip()
                        result["data"]["records"].append(record)

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