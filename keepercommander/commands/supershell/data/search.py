"""
Search functions for SuperShell

Functions for searching and filtering vault records.
"""

from typing import Dict, Set, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ....params import KeeperParams


def search_records(
    query: str,
    records: Dict[str, dict],
    record_to_folder: Dict[str, str],
    params: 'KeeperParams'
) -> Optional[Set[str]]:
    """
    Search records with smart partial matching.
    Returns set of matching record UIDs, or None if no query.

    Search logic:
    - Tokenizes query by whitespace
    - Each token must match (partial) at least one field OR folder name
    - Order doesn't matter: "aws prod us" matches "us production aws"
    - Searches: title, url, custom field values, notes, AND folder name
    - If folder name matches, all records in that folder are candidates
      (but other tokens must still match the record)

    Args:
        query: Search query string
        records: Dict mapping record_uid -> record data
        record_to_folder: Dict mapping record_uid -> folder_uid
        params: Keeper params (for folder_cache)

    Returns:
        Set of matching record UIDs, or None if no query (show all)
    """
    if not query or not query.strip():
        return None  # None means show all

    # Tokenize query - split by whitespace and lowercase
    query_tokens = [token.lower().strip() for token in query.split() if token.strip()]
    if not query_tokens:
        return None

    matching_uids: Set[str] = set()

    # Build folder name cache for quick lookup
    folder_names: Dict[str, str] = {}
    if hasattr(params, 'folder_cache'):
        for folder_uid, folder in params.folder_cache.items():
            if hasattr(folder, 'name') and folder.name:
                folder_names[folder_uid] = folder.name.lower()

    for record_uid, record in records.items():
        # Build searchable text from all record fields
        record_parts = []

        # Record UID - important for searching by UID
        record_parts.append(record_uid)

        # Title
        if record.get('title'):
            record_parts.append(str(record['title']))

        # URL
        if record.get('login_url'):
            record_parts.append(str(record['login_url']))

        # Username/Login
        if record.get('login'):
            record_parts.append(str(record['login']))

        # Custom fields
        if record.get('custom_fields'):
            for field in record['custom_fields']:
                name = field.get('name', '')
                value = field.get('value', '')
                if name:
                    record_parts.append(str(name))
                if value:
                    record_parts.append(str(value))

        # Notes
        if record.get('notes'):
            record_parts.append(str(record['notes']))

        # Combine record text
        record_text = ' '.join(record_parts).lower()

        # Get folder UID and name for this record
        folder_uid = record_to_folder.get(record_uid)
        folder_name = folder_names.get(folder_uid, '') if folder_uid else ''

        # Combined text includes record fields, folder UID, AND folder name
        combined_text = record_text + ' ' + (folder_uid.lower() if folder_uid else '') + ' ' + folder_name

        # Check if ALL query tokens match somewhere (record OR folder)
        all_tokens_match = all(
            token in combined_text
            for token in query_tokens
        )

        if all_tokens_match:
            matching_uids.add(record_uid)

    return matching_uids


def filter_records_by_folder(
    records: Dict[str, dict],
    record_to_folder: Dict[str, str],
    folder_uid: str
) -> Set[str]:
    """Get all record UIDs in a specific folder.

    Args:
        records: Dict mapping record_uid -> record data
        record_to_folder: Dict mapping record_uid -> folder_uid
        folder_uid: Folder UID to filter by

    Returns:
        Set of record UIDs in the folder
    """
    return {
        record_uid
        for record_uid, rec_folder in record_to_folder.items()
        if rec_folder == folder_uid and record_uid in records
    }


def get_root_records(
    records: Dict[str, dict],
    records_in_subfolders: Set[str]
) -> Set[str]:
    """Get all record UIDs that are in the root folder (not in any subfolder).

    Args:
        records: Dict mapping record_uid -> record data
        records_in_subfolders: Set of record UIDs in subfolders

    Returns:
        Set of record UIDs in root folder
    """
    return {
        record_uid
        for record_uid in records
        if record_uid not in records_in_subfolders
    }


def count_records_in_folder(
    record_to_folder: Dict[str, str],
    folder_uid: str,
    filtered_uids: Optional[Set[str]] = None
) -> int:
    """Count records in a folder, optionally filtered by search results.

    Args:
        record_to_folder: Dict mapping record_uid -> folder_uid
        folder_uid: Folder UID to count
        filtered_uids: Optional set of UIDs to restrict count to

    Returns:
        Count of records in folder
    """
    count = 0
    for record_uid, rec_folder in record_to_folder.items():
        if rec_folder == folder_uid:
            if filtered_uids is None or record_uid in filtered_uids:
                count += 1
    return count
