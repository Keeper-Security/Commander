"""
VaultData - Immutable snapshot of vault data

Contains records, folders, and their relationships.
"""

from dataclasses import dataclass, field
from typing import Dict, Set, List, Any, Optional


@dataclass
class VaultData:
    """Immutable snapshot of vault data loaded from Keeper.

    This class holds all the vault data needed by SuperShell,
    organized for efficient lookup and navigation.
    """

    # Record data
    records: Dict[str, dict] = field(default_factory=dict)
    """Maps record_uid -> record data dict"""

    # Folder relationships
    record_to_folder: Dict[str, str] = field(default_factory=dict)
    """Maps record_uid -> folder_uid for direct folder membership"""

    records_in_subfolders: Set[str] = field(default_factory=set)
    """Set of record UIDs that are in actual subfolders (not root)"""

    # File attachments
    file_attachment_to_parent: Dict[str, str] = field(default_factory=dict)
    """Maps attachment_uid -> parent_record_uid"""

    record_file_attachments: Dict[str, List[str]] = field(default_factory=dict)
    """Maps record_uid -> list of attachment_uids"""

    # Linked records (addressRef, cardRef, etc.)
    linked_record_to_parent: Dict[str, str] = field(default_factory=dict)
    """Maps linked_record_uid -> parent_record_uid"""

    record_linked_records: Dict[str, List[str]] = field(default_factory=dict)
    """Maps record_uid -> list of linked_record_uids"""

    # Special record types
    app_record_uids: Set[str] = field(default_factory=set)
    """Set of Secrets Manager app record UIDs"""

    def get_record(self, record_uid: str) -> Optional[dict]:
        """Get a record by UID, returns None if not found."""
        return self.records.get(record_uid)

    def get_folder_for_record(self, record_uid: str) -> Optional[str]:
        """Get the folder UID containing a record."""
        return self.record_to_folder.get(record_uid)

    def is_in_subfolder(self, record_uid: str) -> bool:
        """Check if a record is in a subfolder (not root)."""
        return record_uid in self.records_in_subfolders

    def get_attachments(self, record_uid: str) -> List[str]:
        """Get attachment UIDs for a record."""
        return self.record_file_attachments.get(record_uid, [])

    def get_linked_records(self, record_uid: str) -> List[str]:
        """Get linked record UIDs for a record."""
        return self.record_linked_records.get(record_uid, [])

    def is_app_record(self, record_uid: str) -> bool:
        """Check if a record is a Secrets Manager app."""
        return record_uid in self.app_record_uids

    @property
    def record_count(self) -> int:
        """Total number of records in vault."""
        return len(self.records)
