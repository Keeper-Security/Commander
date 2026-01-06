"""
Vault data loading functions

Functions for loading and parsing vault data from Keeper params.
"""

import json
import logging
from typing import Dict, Set, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ....params import KeeperParams

from ..state import VaultData


def load_vault_data(params: 'KeeperParams') -> VaultData:
    """Load vault data from params and return a VaultData instance.

    This is a pure function that extracts vault data without side effects.

    Args:
        params: Keeper params with record_cache, folder_cache, etc.

    Returns:
        VaultData instance with all vault data loaded
    """
    from .... import vault

    # Initialize collections
    records: Dict[str, dict] = {}
    record_to_folder: Dict[str, str] = {}
    records_in_subfolders: Set[str] = set()
    file_attachment_to_parent: Dict[str, str] = {}
    record_file_attachments: Dict[str, List[str]] = {}
    linked_record_to_parent: Dict[str, str] = {}
    record_linked_records: Dict[str, List[str]] = {}
    app_record_uids: Set[str] = set()

    # Build record to folder mapping
    if hasattr(params, 'subfolder_record_cache'):
        for folder_uid, record_uids in params.subfolder_record_cache.items():
            for record_uid in record_uids:
                record_to_folder[record_uid] = folder_uid
                if folder_uid and folder_uid != '':
                    records_in_subfolders.add(record_uid)

    # Process records
    if hasattr(params, 'record_cache'):
        for record_uid, record_data in params.record_cache.items():
            try:
                record = vault.KeeperRecord.load(params, record_uid)
                if not record:
                    continue

                # Get record type
                record_type = _get_record_type(record, params, record_uid)

                record_dict = {
                    'uid': record_uid,
                    'title': record.title if hasattr(record, 'title') else 'Untitled',
                    'folder_uid': record_to_folder.get(record_uid),
                    'record_type': record_type,
                }

                # Track Secrets Manager apps
                if record_type == 'app':
                    app_record_uids.add(record_uid)

                # Extract file references
                file_refs = _extract_file_refs(record, record_uid)
                for ref_uid in file_refs:
                    file_attachment_to_parent[ref_uid] = record_uid
                if file_refs:
                    record_file_attachments[record_uid] = file_refs

                # Extract linked record references
                linked_refs = _extract_linked_refs(record, record_uid)
                for ref_uid in linked_refs:
                    linked_record_to_parent[ref_uid] = record_uid
                if linked_refs:
                    record_linked_records[record_uid] = linked_refs

                # Extract common fields
                _extract_record_fields(record, record_dict)

                records[record_uid] = record_dict

            except Exception as e:
                logging.debug(f"Error loading record {record_uid}: {e}")
                continue

    return VaultData(
        records=records,
        record_to_folder=record_to_folder,
        records_in_subfolders=records_in_subfolders,
        file_attachment_to_parent=file_attachment_to_parent,
        record_file_attachments=record_file_attachments,
        linked_record_to_parent=linked_record_to_parent,
        record_linked_records=record_linked_records,
        app_record_uids=app_record_uids,
    )


def _get_record_type(record: Any, params: 'KeeperParams', record_uid: str) -> str:
    """Extract record type using multiple approaches."""
    record_type = 'login'  # Default

    # Try get_record_type() method
    if hasattr(record, 'get_record_type'):
        try:
            rt = record.get_record_type()
            if rt:
                return rt
        except:
            pass

    # Try record_type property
    if hasattr(record, 'record_type'):
        try:
            rt = record.record_type
            if rt:
                return rt
        except:
            pass

    # Fallback: try cached data
    cached_rec = params.record_cache.get(record_uid, {})
    version = cached_rec.get('version', 2)
    if version == 3:
        try:
            rec_data = cached_rec.get('data_unencrypted')
            if rec_data:
                if isinstance(rec_data, bytes):
                    rec_data = rec_data.decode('utf-8')
                data_obj = json.loads(rec_data)
                rt = data_obj.get('type')
                if rt:
                    return rt
        except:
            pass
    elif version == 2:
        return 'legacy'

    return record_type


def _extract_file_refs(record: Any, record_uid: str) -> List[str]:
    """Extract file reference UIDs from record fields."""
    file_refs = []

    if not hasattr(record, 'fields'):
        return file_refs

    for field in record.fields:
        field_type = getattr(field, 'type', None)
        field_value = getattr(field, 'value', None)

        if field_type == 'fileRef':
            if field_value and isinstance(field_value, list):
                for ref_uid in field_value:
                    if isinstance(ref_uid, str) and ref_uid:
                        file_refs.append(ref_uid)

        elif field_type == 'script':
            if field_value and isinstance(field_value, list):
                for script_item in field_value:
                    if isinstance(script_item, dict):
                        ref_uid = script_item.get('fileRef')
                        if ref_uid and isinstance(ref_uid, str):
                            file_refs.append(ref_uid)

    return file_refs


def _extract_linked_refs(record: Any, record_uid: str) -> List[str]:
    """Extract linked record reference UIDs (addressRef, cardRef, etc.)."""
    linked_refs = []

    if not hasattr(record, 'fields'):
        return linked_refs

    for field in record.fields:
        field_type = getattr(field, 'type', None)
        field_value = getattr(field, 'value', None)

        if field_type in ('addressRef', 'cardRef'):
            if field_value and isinstance(field_value, list):
                for ref_uid in field_value:
                    if isinstance(ref_uid, str) and ref_uid:
                        linked_refs.append(ref_uid)

    return linked_refs


def _extract_record_fields(record: Any, record_dict: dict) -> None:
    """Extract common fields from record into record_dict."""
    # Basic fields
    if hasattr(record, 'login'):
        record_dict['login'] = record.login
    if hasattr(record, 'password'):
        record_dict['password'] = record.password
    if hasattr(record, 'login_url'):
        record_dict['login_url'] = record.login_url
    if hasattr(record, 'notes'):
        record_dict['notes'] = record.notes
    if hasattr(record, 'totp') and record.totp:
        record_dict['totp_url'] = record.totp

    # Typed record fields
    if hasattr(record, 'fields'):
        custom_fields = []
        for field in record.fields:
            field_type = getattr(field, 'type', None)
            field_value = getattr(field, 'value', None)
            field_label = getattr(field, 'label', None)

            # Extract password
            if field_type == 'password' and field_value and not record_dict.get('password'):
                if isinstance(field_value, list) and len(field_value) > 0:
                    record_dict['password'] = field_value[0]
                elif isinstance(field_value, str):
                    record_dict['password'] = field_value

            # Extract login
            if field_type == 'login' and field_value and not record_dict.get('login'):
                if isinstance(field_value, list) and len(field_value) > 0:
                    record_dict['login'] = field_value[0]
                elif isinstance(field_value, str):
                    record_dict['login'] = field_value

            # Extract URL
            if field_type == 'url' and field_value and not record_dict.get('login_url'):
                if isinstance(field_value, list) and len(field_value) > 0:
                    record_dict['login_url'] = field_value[0]
                elif isinstance(field_value, str):
                    record_dict['login_url'] = field_value

            # Extract TOTP
            if field_type == 'oneTimeCode' and field_value and not record_dict.get('totp_url'):
                if isinstance(field_value, list) and len(field_value) > 0:
                    record_dict['totp_url'] = field_value[0]
                elif isinstance(field_value, str):
                    record_dict['totp_url'] = field_value

            # Collect custom fields
            if field_label and field_value:
                custom_fields.append({
                    'name': field_label,
                    'value': str(field_value) if field_value else ''
                })

        if custom_fields:
            record_dict['custom_fields'] = custom_fields
