#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander - Slack Integration
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Keeper Service Mode API client.
All backend Logic is being written in this module.
"""

import requests
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from .models import (
    KeeperRecord,
    KeeperFolder,
    PermissionLevel
)
from .config import KeeperConfig


class KeeperClient:
    """
    Interacting with Keeper Commander Service Mode API.
    """
    
    def __init__(self, config: KeeperConfig):
        """
        Initialize Keeper client.
        """
        self.base_url = config.service_url.rstrip('/')
        self.api_key = config.api_key
        
        # Create session for connection pooling
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'api-key': self.api_key,
                'Content-Type': 'application/json'
            })
    
    def health_check(self) -> bool:
        """
        It Checks if Keeper Service Mode is accessible or not.
        """
        try:
            response = self.session.get(f'{self.base_url}/queue/status', timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def search_records(self, query: str, limit: int = 20) -> List[KeeperRecord]:
        """
        Search for records using Service Mode search command with category filter.
        """
        try:
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f'search -c r "{query}" --format=json'},
                timeout=10
            )
            
            if response.status_code != 202:
                print(f"[DEBUG] Failed to submit search command: {response.status_code}")
                return []
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                print("[DEBUG] No request_id received")
                return []
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data:
                return self._parse_search_records_results(result_data, limit)
            else:
                print("[DEBUG] Search command timed out or failed")
                return []
                
        except Exception as e:
            print(f"[DEBUG] Error searching records: {e}")
            import traceback
            traceback.print_exc()
        return []
    
    def search_folders(self, query: str, limit: int = 20) -> List[KeeperFolder]:
        """
        Search for shared folders using Service Mode search command with category filter.
        """
        try:
            # Use search command with shared folder category filter (-c s)
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f'search -c s "{query}" --format=json'},
                timeout=10
            )
            
            if response.status_code != 202:
                print(f"[DEBUG] Failed to submit search command: {response.status_code}")
                return []
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                print("[DEBUG] No request_id received")
                return []
            
            # Poll for result with smart backoff
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data:
                # Parse results (no client-side filtering needed - search does it)
                return self._parse_search_folders_results(result_data, limit)
            else:
                print("[DEBUG] Search command timed out or failed")
                return []
                
        except Exception as e:
            print(f"[DEBUG] Error searching folders: {e}")
            import traceback
            traceback.print_exc()
        return []
    
    def get_record_by_uid(self, record_uid: str) -> Optional[KeeperRecord]:
        """
        Get record details by UID using Service Mode.
        """

        try:
            # Submit search command with UID
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f"search {record_uid} --format=json"},
                timeout=10
            )
            
            if response.status_code != 202:
                print(f"[ERROR] Failed to submit search command: {response.status_code}")
                return None
            
            result_data = response.json()
            result_id = result_data.get('request_id')
            
            if not result_id:
                print("[ERROR] No result_id in response")
                return None
            
            # Poll for results
            final_result = self._poll_for_result(result_id)
            
            if not final_result:
                print(f"[WARN] No record found for UID: {record_uid}")
                return None
            
            # Parse the search results - data is directly in the response
            data = final_result.get('data')
            
            if not data or not isinstance(data, list) or len(data) == 0:
                print(f"[WARN] No records in search results for UID: {record_uid}")
                return None

            record_data = data[0]
            
            # Extract basic fields
            title = record_data.get('name', 'Untitled Record')
            uid = record_data.get('uid', record_uid)

            # Check the 'type' field FIRST - this tells us if it's a folder or record
            item_type = record_data.get('type', 'record')
            
            # Initialize notes
            notes = ''
            
            # If it's a folder type, preserve that type
            if item_type in ['shared_folder', 'user_folder', 'folder']:
                record_type = item_type
                print(f"[INFO] Found folder: {title} (type: {record_type})")
            else:
                # For records, parse details for more specific type (login, etc.)
                details_str = record_data.get('details', '')
                record_type = 'login'  # default for records
                
                if details_str:
                    parts = details_str.split(', ')
                    for part in parts:
                        if part.startswith('Type: '):
                            record_type = part.replace('Type: ', '').strip()
                        elif part.startswith('Description: '):
                            notes = part.replace('Description: ', '').strip()
                
                print(f"[INFO] Found record: {title} (type: {record_type})")
            
            return KeeperRecord(
                uid=uid,
                title=title,
                record_type=record_type,
                folder_uid=None,
                notes=notes
            )
            
        except Exception as e:
            print(f"[ERROR] Failed to get record {record_uid}: {e}")
            import traceback
            traceback.print_exc()
        return None
    
    def get_folder_by_uid(self, folder_uid: str) -> Optional[KeeperFolder]:
        """
        Get folder details by UID using Service Mode.
        """

        try:
            # Submit search command with UID
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": f"search {folder_uid} --format=json"},
                timeout=10
            )
            
            if response.status_code != 202:
                print(f"[ERROR] Failed to submit search command: {response.status_code}")
                return None
            
            result_data = response.json()
            result_id = result_data.get('request_id')
            
            if not result_id:
                print("[ERROR] No result_id in response")
                return None
            
            # Poll for results
            final_result = self._poll_for_result(result_id)
            
            if not final_result:
                print(f"[WARN] No folder found for UID: {folder_uid}")
                return None

            data = final_result.get('data')

            if not data or not isinstance(data, list) or len(data) == 0:
                print(f"[WARN] No folders in search results for UID: {folder_uid}")
                return None

            folder_data = data[0]
            
            # Extract basic fields
            name = folder_data.get('name', 'Untitled Folder')
            uid = folder_data.get('uid', folder_uid)
            folder_type = folder_data.get('type', 'folder')
            
            print(f"[INFO] Found folder: {name} (type: {folder_type})")
            
            return KeeperFolder(
                uid=uid,
                name=name,
                parent_uid=None,
                folder_type=folder_type
            )
            
        except Exception as e:
            print(f"[ERROR] Failed to get folder {folder_uid}: {e}")
            import traceback
            traceback.print_exc()
        return None
    
    def grant_record_access(
        self,
        record_uid: str,
        user_email: str,
        permission: PermissionLevel,
        duration_seconds: Optional[int] = 86400
    ) -> Dict[str, Any]:
        """
        Grant access to a record with time limit using share-record command.
        """
        try:
            if permission == PermissionLevel.CHANGE_OWNER:
                # Change owner command
                cmd_parts = ["share-record", record_uid, "-e", user_email, "-a", "owner", "--force"]
                
                # Execute command (no expiration for ownership transfer)
                response = self.session.post(
                    f'{self.base_url}/executecommand-async',
                    json={"command": " ".join(cmd_parts)},
                    timeout=10
                )
                
                if response.status_code != 202:
                    return {'success': False, 'error': f"Failed to submit command: HTTP {response.status_code}"}
                
                result = response.json()
                request_id = result.get('request_id')
                
                if not request_id:
                    return {'success': False, 'error': "No request_id received from API"}
                
                result_data = self._poll_for_result(request_id, max_wait=10)
                
                if not result_data:
                    return {'success': False, 'error': "Command timed out or failed"}
                
                if result_data.get('status') == 'success':
                    return {
                        'success': True,
                        'expires_at': 'N/A (Ownership Transfer)',
                        'permission': permission.value,
                        'duration': 'permanent'
                    }
                else:
                    error_msg = result_data.get('message', 'Unknown error')
                    if isinstance(error_msg, list):
                        error_msg = '\n'.join(error_msg)
                    return {'success': False, 'error': f"Failed to transfer ownership: {error_msg}"}
            
            # Map permission level to share-record flags
            permission_flags = []
            if permission == PermissionLevel.VIEW_ONLY:
                pass
            elif permission == PermissionLevel.CAN_EDIT:
                permission_flags.append("-w")
            elif permission == PermissionLevel.CAN_SHARE:
                permission_flags.append("-s")
            elif permission == PermissionLevel.EDIT_AND_SHARE:
                permission_flags.append("-w")
                permission_flags.append("-s")


            # Build command parts
            cmd_parts = ["share-record", record_uid, "-e", user_email, "-a", "grant"]
            cmd_parts.extend(permission_flags)
            
            # Add time-limited access if duration is specified
            if duration_seconds is not None:
                expire_in = self._format_duration(duration_seconds)
                cmd_parts.extend(["--expire-in", expire_in])
                expires_at = datetime.now() + timedelta(seconds=duration_seconds)
                expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires_at_str = "Never (Permanent)"
            
            # added --force to skip confirmation prompts
            cmd_parts.append("--force")
            command = " ".join(cmd_parts)

            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=10)
            print(f"[DEBUG] Result data: {result_data}")
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            
            if result_data.get('status') == 'success':
                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': permission.value,
                    'duration': 'temporary' if duration_seconds else 'permanent'
                }
            else:
                error_msg = result_data.get('message', result_data.get('error', 'Unknown error'))
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                
                # Check for time-limited access conflict with share permissions
                if "time-limited access" in error_msg.lower() and "re-share" in error_msg.lower():
                    return {
                        'success': False,
                        'error': "⚠️ This user already has time-limited access to this record. "
                                 "Share permissions (Can Share, Edit & Share) require permanent access. "
                                 "Please revoke their existing access first, then grant the new permission."
                    }
                
                return {
                    'success': False,
                    'error': f"Failed to grant access: {error_msg}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Error granting record access: {str(e)}"
            }

    def _format_duration(self, seconds: int) -> str:
        """
        Convert seconds to Keeper share-record duration format.
        """
        if seconds < 3600:  # Less than 1 hour
            minutes = max(1, seconds // 60)
            return f"{minutes}mi"
        elif seconds < 86400:  # Less than 1 day
            hours = max(1, seconds // 3600)
            return f"{hours}h"
        elif seconds < 2592000:  # Less than 30 days
            days = max(1, seconds // 86400)
            return f"{days}d"
        elif seconds < 31536000:  # Less than 365 days
            months = max(1, seconds // 2592000)
            return f"{months}mo"
        else:  # 365+ days
            years = max(1, seconds // 31536000)
            return f"{years}y"
    
    def grant_folder_access(
        self,
        folder_uid: str,
        user_email: str,
        permission: PermissionLevel,
        duration_seconds: Optional[int] = 86400
    ) -> Dict[str, Any]:
        """
        Grant access to a folder with optional time limit using share-folder command.
        """
        try:
            # Map permission level to share-folder flags
            permission_flags = []
            
            if permission == PermissionLevel.NO_PERMISSIONS:
                # No user permissions: just view access (default read access)
                pass
            elif permission == PermissionLevel.MANAGE_USERS:
                # Can manage users
                permission_flags.extend(["-o", "on"])
            elif permission == PermissionLevel.MANAGE_RECORDS:
                # Can manage records
                permission_flags.extend(["-p", "on"])
            elif permission == PermissionLevel.MANAGE_ALL:
                # Can manage both users and records
                permission_flags.extend(["-o", "on", "-p", "on"])
            
            # Build command parts
            cmd_parts = ["share-folder", folder_uid, "-e", user_email, "-a", "grant"]
            cmd_parts.extend(permission_flags)
            
            # Add time-limited access if duration is specified
            if duration_seconds is not None:
                expire_in = self._format_duration(duration_seconds)
                cmd_parts.extend(["--expire-in", expire_in])
                expires_at = datetime.now() + timedelta(seconds=duration_seconds)
                expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires_at_str = "Never (Permanent)"
            
            # Always add -f to force (skip confirmation prompts)
            cmd_parts.append("-f")
            
            # Build full command string
            command = " ".join(cmd_parts)
            
            # Execute command using async API
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            
            if result_data.get('status') == 'success':
                return {
                    'success': True,
                    'expires_at': expires_at_str,
                    'permission': permission.value,
                    'duration': 'temporary' if duration_seconds else 'permanent'
                }
            else:
                error_msg = result_data.get('message', result_data.get('error', 'Unknown error'))
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                
                # Check for time-limited access conflict with manage permissions
                # Also catch "User share...failed" errors which indicate permission conflicts
                is_time_limited_conflict = "time-limited access" in error_msg.lower() and ("manage" in error_msg.lower() or "re-share" in error_msg.lower())
                is_user_share_failed = "user share" in error_msg.lower() and "failed" in error_msg.lower()
                
                if is_time_limited_conflict or is_user_share_failed:
                    return {
                        'success': False,
                        'error': "⚠️ This user already has time-limited access to this folder. "
                                 "Manage permissions (Can Manage Users, Can Manage Users & Records) require permanent access. "
                                 "Please revoke their existing access first, then grant the new permission."
                    }
                
                return {
                    'success': False,
                    'error': f"Failed to grant access: {error_msg}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Error granting folder access: {str(e)}"
            }

    def _poll_for_result(self, request_id: str, max_wait: int = 15) -> Optional[Dict[str, Any]]:
        """
        Poll for async command result till got the result.
        """
        import time
        
        poll_interval = 0.5 
        max_poll_interval = 2.0 
        elapsed = 0
        
        while elapsed < max_wait:
            try:
                # Poll the result endpoint
                response = self.session.get(
                    f'{self.base_url}/result/{request_id}',
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    status = result.get('status')
                    
                    if status == 'success':
                        return result
                    elif status == 'error':
                        print(f"[ERROR] Command failed: {result.get('message', 'Unknown error')}")
                        return result
                    elif status in ['pending', 'running']:
                        # Still processing, continue polling
                        pass
                    else:
                        print(f"[WARN] Unknown status: {status}")
                else:
                    print(f"[WARN] Poll returned status {response.status_code}")
                
                # Wait before next poll
                time.sleep(poll_interval)
                elapsed += poll_interval
                poll_interval = min(poll_interval * 1.5, max_poll_interval)
                
            except Exception as e:
                print(f"[ERROR] Error polling for result: {e}")
                return None
        
        print(f"[WARN] Polling timed out after {max_wait} seconds")
        return None
    
    def _parse_search_records_results(self, result_data: Dict, limit: int) -> List[KeeperRecord]:
        """
        Parse search command results for records.
        """
        records = []
        
        try:
            # Check if data is directly in result_data or needs extraction
            data = result_data.get('data', [])
            
            if not isinstance(data, list):
                print(f"[DEBUG] Unexpected data format: {type(data)}")
                return records
            
            print(f"[DEBUG] Got {len(data)} records from search")
            
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                # Extract fields from search response
                uid = item.get('uid', '')
                title = item.get('name', '')  # 'name' field contains the title
                record_type = 'login'  # Default type
                notes = ''
                
                # Parse details string: "Type: login, Description: bishal@gmail.com"
                details = item.get('details', '')
                if details:
                    parts = details.split(', ')
                    for part in parts:
                        if part.startswith('Type: '):
                            record_type = part.replace('Type: ', '').strip()
                        elif part.startswith('Description: '):
                            notes = part.replace('Description: ', '').strip()
                
                if uid and title:
                    records.append(KeeperRecord(
                        uid=uid,
                        title=title,
                        record_type=record_type,
                        notes=notes
                    ))
                    
                    if len(records) >= limit:
                        break
            
            return records
            
        except Exception as e:
            print(f"[ERROR] Error parsing search records results: {e}")
            import traceback
            traceback.print_exc()
            return records
    
    def _parse_search_folders_results(self, result_data: Dict, limit: int) -> List[KeeperFolder]:
        """
        Parse search command results for shared folders.
        """
        folders = []
        
        try:
            # Check if data is directly in result_data or needs extraction
            data = result_data.get('data', [])
            
            if not isinstance(data, list):
                print(f"[DEBUG] Unexpected data format: {type(data)}")
                return folders
            
            print(f"[DEBUG] Got {len(data)} folders from search")
            
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                # Extract fields from search response
                uid = item.get('uid', '')
                name = item.get('name', '')
                folder_type = item.get('type', 'shared_folder')
                
                if uid and name:
                    folders.append(KeeperFolder(
                        uid=uid,
                        name=name,
                        folder_type=folder_type
                    ))
                    
                    if len(folders) >= limit:
                        break
            
            return folders
            
        except Exception as e:
            print(f"[ERROR] Error parsing search folders results: {e}")
            import traceback
            traceback.print_exc()
            return folders
    
    def create_one_time_share(
        self,
        record_uid: str,
        duration_seconds: Optional[int] = 86400,
        editable: bool = False
    ) -> Dict[str, Any]:
        """
        Create a one-time share link for a record.
        """
        try:
            # Format duration for Keeper Commander
            if duration_seconds is None:
                expire_in = "7d"  # Default: 7 days for permanent-like access
            else:
                expire_in = self._format_duration(duration_seconds)
            
            # Build command - use 'create' subcommand with -e flag and optional --editable
            editable_flag = " --editable" if editable else ""
            command = f"one-time-share create{editable_flag} {record_uid} -e {expire_in}"
            
            print(f"[DEBUG] Creating one-time share: {command}")
            
            # Execute command using async API
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            
            if result_data.get('status') == 'success':
                # Calculate expiration time
                if duration_seconds:
                    expires_at = datetime.now() + timedelta(seconds=duration_seconds)
                    expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    expires_at_str = "Never (7 days default)"
                
                # Extract share URL from response
                # Expected format from docs: "URL : https://keepersecurity.com/vault/share#..."
                share_url = None
                
                # Try structured fields first
                share_url = result_data.get('url') or result_data.get('share_url') or result_data.get('link')
                
                # If not found, parse from message output
                if not share_url and 'message' in result_data:
                    import re
                    message = result_data.get('message')
                    
                    # Handle message as string (direct URL) - this is the common format
                    if isinstance(message, str):
                        # Check if the entire message is a URL
                        if message.startswith('http'):
                            share_url = message
                        else:
                            # Try to extract URL from text
                            url_match = re.search(r'https://[^\s]+', message)
                            if url_match:
                                share_url = url_match.group(0)
                    
                    # Handle message as list (array of strings)
                    elif isinstance(message, list):
                        for msg in message:
                            # Look for "URL : https://..." pattern from Keeper output
                            if 'URL' in str(msg) and 'https://' in str(msg):
                                url_match = re.search(r'https://keepersecurity\.com/vault/share[^\s]+', str(msg))
                                if url_match:
                                    share_url = url_match.group(0)
                                    break
                        
                        # If still not found, try generic URL extraction as fallback
                        if not share_url:
                            for msg in message:
                                if 'https://' in str(msg):
                                    url_match = re.search(r'(https://[^\s]+)', str(msg))
                                    if url_match:
                                        share_url = url_match.group(1)
                                        break
                
                if not share_url:
                    return {
                        'success': False,
                        'error': "Share link created but URL not found in response",
                        'raw_response': result_data
                    }
                
                return {
                    'success': True,
                    'share_url': share_url,
                    'expires_at': expires_at_str,
                    'duration': expire_in
                }
            else:
                error_msg = result_data.get('message', 'Unknown error')
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                return {
                    'success': False,
                    'error': f"Failed to create one-time share: {error_msg}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Error creating one-time share: {str(e)}"
            }
    
    def create_record(
        self,
        title: str,
        login: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        generate_password: bool = False,
        self_destruct_duration: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new record in Keeper vault using the 'record-add' command.
        """
        try:
            # Build the record-add command
            command_parts = ["record-add"]
            
            # Add record type (lowercase, space-separated, no quotes)
            command_parts.append('--record-type login')
            
            # Title is required (space-separated with single quotes)
            title_escaped = title.replace("'", "\\'")
            command_parts.append(f"--title '{title_escaped}'")

            if notes:
                notes_escaped = notes.replace("'", "\\'").replace('\n', '\\n')
                command_parts.append(f"--notes '{notes_escaped}'")
            
            # Self-destruct (space-separated, no quotes on duration)
            if self_destruct_duration:
                command_parts.append(f'--self-destruct {self_destruct_duration}')

            if login:
                login_escaped = login.replace(' ', '\\ ')
                command_parts.append(f'login={login_escaped}')
            
            if password:
                password_escaped = password.replace(' ', '\\ ')
                command_parts.append(f'password={password_escaped}')
            elif generate_password:
                command_parts.append('password=$GEN')
            
            if url:
                url_escaped = url.replace(' ', '\\ ')
                command_parts.append(f'url={url_escaped}')
            
            command = " ".join(command_parts)

            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {
                    'success': False,
                    'error': f"Failed to submit command: HTTP {response.status_code}"
                }
            
            result = response.json()
            request_id = result.get('request_id')
            
            if not request_id:
                return {
                    'success': False,
                    'error': "No request_id received from API"
                }
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=20)
            
            if not result_data:
                return {
                    'success': False,
                    'error': "Command timed out or failed"
                }
            
            if result_data.get('status') == 'success':
                # record-add doesn't return the UID, so we need to search for it
                print(f"[INFO] Record created successfully, searching for UID...")
                
                # Extract message for self-destruct URL (if applicable)
                message = result_data.get('message', '')
                if isinstance(message, list):
                    message = '\n'.join(message)
                
                # Search for the newly created record by exact title
                import time
                import re
                time.sleep(1)  
                
                try:
                    search_response = self.session.post(
                        f'{self.base_url}/executecommand-async',
                        json={"command": f'search "{title}" --format=json'},
                        timeout=10
                    )
                    
                    if search_response.status_code == 202:
                        search_request_id = search_response.json().get('request_id')
                        if search_request_id:
                            search_result = self._poll_for_result(search_request_id, max_wait=10)
                            
                            if search_result and search_result.get('status') == 'success':
                                # Parse search results
                                data = search_result.get('data', [])
                                if data and len(data) > 0:
                                    # Get the most recently created record (first match)
                                    newest_record = data[0]
                                    record_uid = newest_record.get('uid')
                                    
                                    if record_uid:
                                        generated_password = None
                                        if generate_password and not password:
                                            generated_password = "$GEN"
                                        return {
                                            'success': True,
                                            'record_uid': record_uid,
                                            'password': generated_password or password,
                                            'title': title,
                                            'self_destruct': bool(self_destruct_duration),
                                            'self_destruct_duration': self_destruct_duration
                                        }
                except Exception as search_error:
                    print(f"[ERROR] Failed to search for created record: {search_error}")
                    print(f"[WARN] Record created but UID not found via search")
                    return {
                        'success': False,
                        'error': "Record created but UID could not be retrieved. The record exists in your vault but the approval flow cannot continue automatically."
                    }
            else:
                error_msg = result_data.get('message', 'Unknown error')
                if isinstance(error_msg, list):
                    error_msg = '\n'.join(error_msg)
                return {
                    'success': False,
                    'error': f"Failed to create record: {error_msg}"
                }
                
        except Exception as e:
            print(f"[ERROR] Exception in create_record: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f"Error creating record: {str(e)}"
            }
    
    def sync_pedm_data(self) -> bool:
        """
        Sync PEDM data from server.
        """
        try:
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": "pedm sync-down"},
                timeout=10
            )
            
            if response.status_code != 202:
                print(f"[ERROR] Failed to submit PEDM sync command: {response.status_code}")
                return False
            
            request_id = response.json().get('request_id')
            if not request_id:
                print("[ERROR] No request_id received for PEDM sync")
                return False
            
            # Poll for result
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if not result_data:
                print("[WARN] PEDM sync command timed out")
                return False
            
            status = result_data.get('status')
            if status == 'error':
                error_msg = result_data.get('message', 'Unknown error')
                print(f"[ERROR] PEDM sync failed: {error_msg}")
                return False
            
            if status == 'success':
                print("[OK] PEDM data synced from server")
                return True
            
            return False
            
        except Exception as e:
            print(f"[ERROR] Exception syncing PEDM data: {e}")
            return False
    
    def get_pending_pedm_requests(self) -> List[Dict[str, Any]]:
        """
        Get pending PEDM approval requests.
        """
        try:
            sync_success = self.sync_pedm_data()
            
            if not sync_success:
                print("[WARN] PEDM sync failed, attempting to list anyway...")

            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": "pedm approval list --type pending --format=json"},
                timeout=10
            )
            
            if response.status_code != 202:
                print(f"[ERROR] Failed to submit PEDM list command: {response.status_code}")
                return []
            
            request_id = response.json().get('request_id')
            if not request_id:
                print("[ERROR] No request_id received for PEDM list")
                return []
            
            result_data = self._poll_for_result(request_id, max_wait=30)
            
            if not result_data:
                print("[WARN] PEDM list command timed out")
                return []
            
            status = result_data.get('status')
            if status == 'error':
                error_msg = result_data.get('message', 'Unknown error')
                print(f"[ERROR] PEDM command failed: {error_msg}")
                return []
            
            if status == 'success':
                data = result_data.get('data')
                
                # Handle None (no PEDM feature or no requests)
                if data is None:
                    print("[DEBUG] No PEDM data returned (feature may not be enabled)")
                    return []
                
                if isinstance(data, list):
                    print(f"[DEBUG] Retrieved {len(data)} pending PEDM request(s)")
                    return data
                else:
                    print(f"[ERROR] Unexpected PEDM data type: {type(data)}")
                    return []
            
            return []
            
        except Exception as e:
            print(f"[ERROR] Exception fetching PEDM requests: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def approve_pedm_request(self, approval_uid: str) -> Dict[str, Any]:
        """
        Approve a PEDM request.
        """
        try:
            command = f"pedm approval action --approve {approval_uid}"
            
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {'success': False, 'error': f"HTTP {response.status_code}"}
            
            request_id = response.json().get('request_id')
            if not request_id:
                return {'success': False, 'error': "No request_id"}
            
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data and result_data.get('status') == 'success':
                return {'success': True}
            else:
                error = result_data.get('message', 'Unknown error') if result_data else 'Timeout'
                return {'success': False, 'error': error}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def deny_pedm_request(self, approval_uid: str) -> Dict[str, Any]:
        """
        Deny a PEDM request.
        """
        try:
            command = f"pedm approval action --deny {approval_uid}"
            print(f"[INFO] Denying PEDM request: {approval_uid}")
            
            response = self.session.post(
                f'{self.base_url}/executecommand-async',
                json={"command": command},
                timeout=10
            )
            
            if response.status_code != 202:
                return {'success': False, 'error': f"HTTP {response.status_code}"}
            
            request_id = response.json().get('request_id')
            if not request_id:
                return {'success': False, 'error': "No request_id"}
            
            result_data = self._poll_for_result(request_id, max_wait=10)
            
            if result_data and result_data.get('status') == 'success':
                return {'success': True}
            else:
                error = result_data.get('message', 'Unknown error') if result_data else 'Timeout'
                return {'success': False, 'error': error}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}