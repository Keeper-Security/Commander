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

"""Data models for Keeper Slack Integration."""

from enum import Enum
from dataclasses import dataclass
from typing import Optional
from datetime import datetime


class RequestType(Enum):
    """Type of access request."""
    RECORD = "record"
    FOLDER = "folder"
    ONE_TIME_SHARE = "one_time_share"


class PermissionLevel(Enum):
    """Permission levels for record/folder access."""
    
    # Record permissions
    VIEW_ONLY = "view_only"
    CAN_EDIT = "can_edit"
    CAN_SHARE = "can_share"
    EDIT_AND_SHARE = "edit_and_share"
    CHANGE_OWNER = "change_owner"
    
    # Folder permissions
    NO_PERMISSIONS = "no_permissions"
    MANAGE_USERS = "manage_users"
    MANAGE_RECORDS = "manage_records"
    MANAGE_ALL = "manage_all"


class ShareType(Enum):
    """Type of share link."""
    ONE_TIME = "one_time"


@dataclass
class KeeperRecord:
    """Represents a Keeper record."""
    
    uid: str
    """Unique identifier for the record"""
    
    title: str
    """Record title"""
    
    record_type: str
    """Type of record (e.g., 'login', 'bankAccount')"""
    
    folder_uid: Optional[str] = None
    """UID of parent folder"""
    
    notes: Optional[str] = None
    """Record notes/description"""
    
    @property
    def display_name(self) -> str:
        """Get display name for UI."""
        return f"{self.title} ({self.uid[:8]}...)"


@dataclass
class KeeperFolder:
    """Represents a Keeper folder."""
    
    uid: str
    """Unique identifier for the folder"""
    
    name: str
    """Folder name"""
    
    parent_uid: Optional[str] = None
    """UID of parent folder"""
    
    folder_type: str = "folder"
    """Type of folder (e.g., 'folder', 'shared_folder')"""
    
    @property
    def display_name(self) -> str:
        """Get display name for UI."""
        return f"{self.name} ({self.uid[:8]}...)"


@dataclass
class ShareLink:
    """Represents a share link."""
    
    url: str
    """Share link URL"""
    
    record_uid: str
    """UID of shared record"""
    
    share_type: ShareType
    """Type of share"""
    
    created_at: datetime
    """When the link was created"""
    
    expires_at: Optional[datetime] = None
    """When the link expires (if applicable)"""


@dataclass
class AccessRequest:
    """Represents an access request."""
    
    approval_id: str
    """Unique identifier for this approval request"""
    
    requester_id: str
    """Slack user ID of requester"""
    
    requester_name: str
    """Slack username of requester"""
    
    request_type: RequestType
    """Type of request (record or folder)"""
    
    identifier: str
    """UID or description of requested item"""
    
    is_uid: bool
    """True if identifier is a UID, False if it's a description"""
    
    justification: str
    """Reason for requesting access"""
    
    created_at: datetime
    """When the request was created"""
    
    duration: str = "24h"
    """Duration of access (e.g., "1h", "24h", "7d", "permanent")"""
    
    status: str = "pending"
    """Status of request: pending, approved, denied"""
    
    approver_id: Optional[str] = None
    """Slack user ID of approver (if approved/denied)"""
    
    approver_name: Optional[str] = None
    """Slack username of approver (if approved/denied)"""
    
    resolved_at: Optional[datetime] = None
    """When the request was approved/denied"""


@dataclass
class ApprovalAction:
    """Represents data passed in approval button actions."""
    
    approval_id: str
    requester_id: str
    identifier: str
    is_uid: bool
    request_type: str
    justification: str
    duration: str = "24h"


@dataclass
class PEDMRequest:
    """PEDM approval request."""
    
    approval_uid: str
    """Unique identifier for PEDM approval request"""
    
    approval_type: str
    """Type: 'CommandLine' or 'PrivilegeElevation'"""
    
    status: str
    """Status: 'Pending', 'Approved', 'Denied'"""
    
    agent_uid: str
    """UID of the PEDM agent"""
    
    username: str
    """Username requesting privilege elevation"""
    
    command: str
    """Command line to be executed"""
    
    file_name: str
    """Executable file name (e.g., 'sudo', 'cmd.exe')"""
    
    file_path: str
    """Full path to executable"""
    
    description: str
    """Command description"""
    
    justification: str
    """User's justification for the request"""
    
    expire_in: int
    """Expiration time in minutes"""
    
    created: str
    """ISO timestamp when request was created"""
    
    @classmethod
    def from_dict(cls, data: dict) -> 'PEDMRequest':
        """
        Parse PEDM request from API response.
        """
        # Parse account_info array
        username = ""
        for info in data.get('account_info', []):
            if info.startswith('Username='):
                username = info.split('=', 1)[1]
                break
        
        # Parse application_info array
        description = ""
        file_name = ""
        file_path = ""
        command = ""
        
        for info in data.get('application_info', []):
            if info.startswith('Description='):
                description = info.split('=', 1)[1]
            elif info.startswith('FileName='):
                file_name = info.split('=', 1)[1]
            elif info.startswith('FilePath='):
                file_path = info.split('=', 1)[1]
            elif info.startswith('CommandLine='):
                command = info.split('=', 1)[1]
        
        return cls(
            approval_uid=data.get('approval_uid', ''),
            approval_type=data.get('approval_type', ''),
            status=data.get('status', 'Pending'),
            agent_uid=data.get('agent_uid', ''),
            username=username,
            command=command,
            file_name=file_name,
            file_path=file_path,
            description=description,
            justification=data.get('justification', ''),
            expire_in=data.get('expire_in', 30),
            created=data.get('created', '')
        )
    
    def get_full_command(self) -> str:
        """Get formatted full command string."""
        if self.approval_type == "CommandLine":
            return f"{self.file_name} {self.command}"
        else:  # PrivilegeElevation
            return f"{self.file_path}\\{self.file_name}" if '\\' in self.file_path else f"{self.file_path}/{self.file_name}"
    
    def get_expiration_datetime(self) -> datetime:
        """Calculate when this request expires."""
        from datetime import timedelta
        created_dt = datetime.fromisoformat(self.created.replace('Z', '+00:00'))
        return created_dt + timedelta(minutes=self.expire_in)

