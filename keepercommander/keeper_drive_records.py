#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
KeeperDrive Records API Module

This module provides functions for creating records using the KeeperDrive v3 API.
"""

import json
import logging
import os
from typing import Optional, List, Dict, Any, Tuple

from . import utils, crypto, api
from .params import KeeperParams
from .proto import record_pb2, folder_pb2, record_endpoints_pb2, record_details_pb2, record_sharing_pb2
from .error import KeeperApiError
from .api import pad_aes_gcm


logger = logging.getLogger(__name__)


def _get_record_key_type(params: 'KeeperParams', record_uid: str) -> Optional[int]:
    """Return the record key type if available (for legacy AES-CBC vs AES-GCM)."""
    meta = params.meta_data_cache.get(record_uid) if hasattr(params, 'meta_data_cache') else None
    if meta and 'record_key_type' in meta:
        return meta.get('record_key_type')
    return None


def _encrypt_record_key_for_folder(
    record_key: bytes,
    encryption_key: bytes,
    record_key_type: Optional[int]
) -> Tuple[bytes, int]:
    """
    Encrypt record_key with encryption_key and return (ciphertext, encrypted_key_type).

    If record_key_type is legacy encrypted_by_data_key, use AES-CBC (v1);
    otherwise default to AES-GCM (v2).
    """
    if record_key_type == folder_pb2.encrypted_by_data_key:
        return crypto.encrypt_aes_v1(record_key, encryption_key), folder_pb2.encrypted_by_data_key
    if record_key_type == folder_pb2.encrypted_by_data_key_gcm:
        return crypto.encrypt_aes_v2(record_key, encryption_key), folder_pb2.encrypted_by_data_key_gcm
    # Default to AES-GCM for unknown/unsupported types
    return crypto.encrypt_aes_v2(record_key, encryption_key), folder_pb2.encrypted_by_data_key_gcm


def create_record_data_v3(
    record_uid: str,
    record_key: bytes,
    data: dict,
    non_shared_data: Optional[dict] = None,
    folder_uid: Optional[str] = None,
    folder_key: Optional[bytes] = None,
    record_key_type: Optional[int] = None,
    client_modified_time: Optional[int] = None,
    data_key: Optional[bytes] = None
) -> 'record_endpoints_pb2.RecordAdd':
    """
    Create a RecordAdd protobuf message for record creation.
    
    According to the v3 API documentation:
    - recordKey: The record key used to encrypt data and nonSharedData.
      If the record is created in a folder, recordKey is encrypted with the folderKey;
      otherwise, it is encrypted with the user's data key.
    - folderUid: Must be provided when the record is not created at the vault root level.
    - folderKey: Must be provided when the record is not created at the vault root level.
      Used to encrypt the record key (for folder access).
    - recordKeyType: Only supports encrypted_by_data_key_gcm
    
    Args:
        record_uid: The unique identifier for the record (base64-url encoded)
        record_key: The encryption key for the record (32 bytes for AES-256, unencrypted)
        data: Dictionary containing record fields (will be JSON-encoded and encrypted)
        non_shared_data: Optional non-shared data specific to the user
        folder_uid: Optional folder UID (required if not creating at vault root)
        folder_key: Optional folder key (required if folder_uid is provided)
        record_key_type: Optional encryption key type
        client_modified_time: Optional client modification time
        data_key: The user's data key for encrypting the record key (required when NOT in folder)
    
    Returns:
        RecordAdd protobuf message
    
    Raises:
        ValueError: If required parameters are missing based on context
    """
    record_add = record_endpoints_pb2.RecordAdd()
    
    # Required fields (use camelCase for protobuf fields in record_endpoints_pb2)
    record_add.recordUid = utils.base64_url_decode(record_uid)
    
    if folder_uid and folder_key:
        record_add.recordKey = crypto.encrypt_aes_v2(record_key, folder_key)
        record_add.folderUid = utils.base64_url_decode(folder_uid)
        record_add.folderKey = crypto.encrypt_aes_v2(record_key, folder_key)
    elif folder_uid and not folder_key:
        raise ValueError("folder_key is required when folder_uid is provided")
    else:
        if data_key is None:
            raise ValueError("data_key is required when creating record at vault root")
        record_add.recordKey = crypto.encrypt_aes_v2(record_key, data_key)
    
    if record_key_type is not None:
        record_add.recordKeyType = record_key_type
    else:
        from keepercommander.proto import folder_pb2
        record_add.recordKeyType = folder_pb2.encrypted_by_data_key_gcm
    
    # Encrypt record data with AES-256-GCM
    # First convert to JSON string, then pad it, then encrypt
    data_json = json.dumps(data)
    data_padded = pad_aes_gcm(data_json)
    data_bytes = data_padded.encode('utf-8') if isinstance(data_padded, str) else data_padded
    record_add.data = crypto.encrypt_aes_v2(data_bytes, record_key)
    
    # Optional fields
    if non_shared_data:
        non_shared_json = json.dumps(non_shared_data)
        non_shared_padded = pad_aes_gcm(non_shared_json)
        non_shared_bytes = non_shared_padded.encode('utf-8') if isinstance(non_shared_padded, str) else non_shared_padded
        record_add.nonSharedData = crypto.encrypt_aes_v2(non_shared_bytes, record_key)
    
    if client_modified_time:
        record_add.clientModifiedTime = client_modified_time
    
    return record_add


def record_add_v3(
    params: KeeperParams,
    records: List['record_endpoints_pb2.RecordAdd'],
    client_time: Optional[int] = None,
    security_data_key_type: Optional[int] = None
) -> 'record_pb2.RecordsModifyResponse':
    """
    Create new records using the KeeperDrive v3 API.
    
    This function creates one or more records in the user's vault using the
    new KeeperDrive record structure. Maximum 1000 records per request.
    
    Args:
        params: KeeperParams instance with session information
        records: List of RecordAdd messages (max 1000)
        client_time: Optional client timestamp
        security_data_key_type: Optional security data key type
    
    Returns:
        RecordsModifyResponse with results for each record
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If more than 1000 records are provided
    """
    if len(records) > 1000:
        raise ValueError("Maximum 1000 records can be created at a time")
    
    if not records:
        raise ValueError("At least one record must be provided")
    
    request = record_endpoints_pb2.RecordsAddRequest()
    request.records.extend(records)
    
    if client_time:
        request.clientTime = client_time
    
    if security_data_key_type:
        request.securityDataKeyType = security_data_key_type
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Creating {len(records)} record(s) via KeeperDrive v3 API")
        for rec in records:
            record_uid = utils.base64_url_encode(rec.recordUid)
            folder_uid = utils.base64_url_encode(rec.folderUid) if rec.folderUid else 'root'
            logger.debug(f"  Record UID: {record_uid}, Folder: {folder_uid}")
    
    # Make API call
    endpoint = 'vault/records/v3/add'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=record_pb2.RecordsModifyResponse
    )
    
    # Log response
    if logger.level <= logging.DEBUG:
        for result in response.records:
            record_uid = utils.base64_url_encode(result.record_uid)
            status_name = record_pb2.RecordModifyResult.Name(result.status)
            logger.debug(f"  Result for {record_uid}: {status_name} - {result.message}")
    
    return response


def record_update_v3(
    params: KeeperParams,
    records: List['record_pb2.RecordUpdate'],
    client_time: Optional[int] = None,
    security_data_key_type: Optional[int] = None
) -> 'record_pb2.RecordsModifyResponse':
    """
    Update existing records using the KeeperDrive v3 API.
    
    This function updates one or more records in the user's vault using the
    new KeeperDrive record structure. Maximum 1000 records per request.
    
    Args:
        params: KeeperParams instance with session information
        records: List of RecordUpdate messages (max 1000)
        client_time: Optional client timestamp
        security_data_key_type: Optional security data key type
    
    Returns:
        RecordsModifyResponse with results for each record
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If more than 1000 records are provided
    """
    if len(records) > 1000:
        raise ValueError("Maximum 1000 records can be updated at a time")
    
    if not records:
        raise ValueError("At least one record must be provided")
    
    request = record_pb2.RecordsUpdateRequest()
    request.records.extend(records)
    
    if client_time:
        request.client_time = client_time
    
    if security_data_key_type:
        request.security_data_key_type = security_data_key_type
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Updating {len(records)} record(s) via KeeperDrive v3 API")
        for rec in records:
            record_uid = utils.base64_url_encode(rec.record_uid)
            logger.debug(f"  Record UID: {record_uid}")
    
    # Make API call
    endpoint = 'vault/records/v3/update'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=record_pb2.RecordsModifyResponse
    )
    
    # Log response
    if logger.level <= logging.DEBUG:
        for result in response.records:
            record_uid = utils.base64_url_encode(result.record_uid)
            status_name = record_pb2.RecordModifyResult.Name(result.status)
            logger.debug(f"  Result for {record_uid}: {status_name} - {result.message}")
    
    return response


def create_record_v3(
    params: KeeperParams,
    record_type: str,
    title: str,
    fields: Dict[str, Any],
    folder_uid: Optional[str] = None,
    notes: Optional[str] = None,
    custom_fields: Optional[List[Dict]] = None
) -> Dict[str, Any]:
    """
    High-level function to create a single record in KeeperDrive.
    
    This is a convenience wrapper around record_add_v3 for creating a single record.
    
    Args:
        params: KeeperParams instance
        record_type: Record type (e.g., 'login', 'password', 'address')
        title: Title of the record
        fields: Dictionary of record fields
        folder_uid: Optional folder UID (None for vault root)
        notes: Optional notes
        custom_fields: Optional custom fields
    
    Returns:
        Dictionary with record creation results:
        {
            'record_uid': str,
            'status': str,
            'message': str,
            'success': bool,
            'revision': int
        }
    
    Raises:
        KeeperApiError: If the API request fails
    """
    # Generate new record UID
    record_uid = utils.generate_uid()
    
    # Generate record key (32 bytes for AES-256)
    record_key = os.urandom(32)
    
    # Build record data
    data = {
        'type': record_type,
        'title': title,
        'fields': []
    }
    
    # Add standard fields
    for field_type, field_value in fields.items():
        # Wrap value in a list if it's not already a list
        if not isinstance(field_value, list):
            field_value = [field_value]
        data['fields'].append({
            'type': field_type,
            'value': field_value
        })
    
    # Add notes as top-level property (matches update_record_v3 behavior)
    if notes is not None:
        data['notes'] = notes
    
    # Add custom fields if provided
    if custom_fields:
        data['fields'].extend(custom_fields)
    
    # Get folder key if creating in a folder
    folder_key = None
    if folder_uid:
        # Retrieve folder key from keeper_drive_folders or subfolder_cache
        if folder_uid in params.keeper_drive_folders:
            folder_obj = params.keeper_drive_folders[folder_uid]
            if 'folder_key_unencrypted' in folder_obj:
                folder_key = folder_obj['folder_key_unencrypted']
        
        if not folder_key and folder_uid in params.subfolder_cache:
            folder_obj = params.subfolder_cache[folder_uid]
            if 'folder_key_unencrypted' in folder_obj:
                folder_key = folder_obj['folder_key_unencrypted']
        
        if not folder_key:
            raise ValueError(f"Folder key not found for folder {folder_uid}. Try running 'sync-down' first.")
    
    # Get current timestamp in milliseconds
    current_time = utils.current_milli_time()
    
    # Create record data
    record_add = create_record_data_v3(
        record_uid=record_uid,
        record_key=record_key,
        data=data,
        folder_uid=folder_uid,
        folder_key=folder_key,
        data_key=params.data_key,
        client_modified_time=current_time
    )
    
    # Make API call
    response = record_add_v3(params, [record_add])
    
    # Parse response
    if response.records:
        result = response.records[0]
        status_name = record_pb2.RecordModifyResult.Name(result.status)
        success = result.status == record_pb2.RS_SUCCESS
        
        return {
            'record_uid': record_uid,
            'status': status_name,
            'message': result.message,
            'success': success,
            'revision': response.revision if hasattr(response, 'revision') else 0
        }
    else:
        raise KeeperApiError('no_results', 'No results returned from record creation')


def update_record_v3(
    params: KeeperParams,
    record_uid: str,
    data: Optional[Dict[str, Any]] = None,
    title: Optional[str] = None,
    record_type: Optional[str] = None,
    fields: Optional[Dict[str, Any]] = None,
    notes: Optional[str] = None,
    non_shared_data: Optional[dict] = None,
    revision: Optional[int] = None
) -> Dict[str, Any]:
    """
    Update a single record in KeeperDrive.
    
    This is a convenience wrapper around record_update_v3 for updating a single record.
    
    Args:
        params: KeeperParams instance
        record_uid: Record UID to update (base64-url encoded)
        data: Complete data dictionary (if provided, title/type/fields/notes are ignored)
        title: New title (if updating specific fields)
        record_type: New type (if updating specific fields)
        fields: New fields dictionary (if updating specific fields)
        notes: New notes (if updating specific fields)
        non_shared_data: Optional non-shared data
        revision: Optional revision number for optimistic locking
    
    Returns:
        Dictionary with update results:
        {
            'record_uid': str,
            'status': str,
            'message': str,
            'success': bool,
            'revision': int
        }
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If record not found in vault
    """
    # Get existing record from record_cache (where decrypted data lives)
    if record_uid not in params.record_cache:
        # Try syncing first
        from . import sync_down
        sync_down.sync_down(params)
        
        if record_uid not in params.record_cache:
            raise ValueError(f"Record {record_uid} not found. Please sync your vault first.")
    
    record_obj = params.record_cache[record_uid]
    
    # Get the unencrypted record key
    if 'record_key_unencrypted' not in record_obj:
        raise ValueError(f"Record key not available for {record_uid}")
    
    record_key = record_obj['record_key_unencrypted']
    
    # Build data if not provided
    if data is None:
        # Get existing data from decrypted cache
        existing_data = None
        if 'data_unencrypted' in record_obj:
            # Decrypt and parse existing data
            data_bytes = record_obj['data_unencrypted']
            if isinstance(data_bytes, bytes):
                data_str = data_bytes.decode('utf-8')
                existing_data = json.loads(data_str)
        
        # Start with existing data or empty structure
        if existing_data:
            data = existing_data.copy()
        else:
            data = {'fields': []}
        
        # Only update title if explicitly provided
        if title is not None:
            data['title'] = title
        
        # Only update type if explicitly provided
        if record_type is not None:
            data['type'] = record_type
        
        # Merge fields instead of replacing them
        if fields is not None:
            # Get existing fields
            existing_fields = data.get('fields', [])
            
            # Create a dictionary of existing fields by type for easy lookup
            existing_by_type = {}
            for existing_field in existing_fields:
                field_type = existing_field.get('type')
                if field_type:
                    if field_type not in existing_by_type:
                        existing_by_type[field_type] = []
                    existing_by_type[field_type].append(existing_field)
            
            # Update or add new fields
            for field_type, field_value in fields.items():
                # Wrap value in a list if it's not already a list
                if not isinstance(field_value, list):
                    field_value = [field_value]
                
                # If field type exists, update the first occurrence
                if field_type in existing_by_type and len(existing_by_type[field_type]) > 0:
                    existing_by_type[field_type][0]['value'] = field_value
                else:
                    # Add new field
                    data['fields'].append({
                        'type': field_type,
                        'value': field_value
                    })
        
        # Update notes if provided (notes is a top-level property, not a field)
        if notes is not None:
            data['notes'] = notes
    
    # Get current timestamp
    current_time = utils.current_milli_time()
    
    # Create RecordUpdate message
    record_update = record_pb2.RecordUpdate()
    record_update.record_uid = utils.base64_url_decode(record_uid)
    record_update.client_modified_time = current_time
    
    # Set revision if provided
    if revision is not None:
        record_update.revision = revision
    elif 'revision' in record_obj:
        record_update.revision = record_obj['revision']
    
    # Encrypt and set data
    data_json = json.dumps(data)
    data_padded = pad_aes_gcm(data_json)
    data_bytes = data_padded.encode('utf-8') if isinstance(data_padded, str) else data_padded
    record_update.data = crypto.encrypt_aes_v2(data_bytes, record_key)
    
    # Encrypt and set non_shared_data if provided
    if non_shared_data:
        non_shared_json = json.dumps(non_shared_data)
        non_shared_padded = pad_aes_gcm(non_shared_json)
        non_shared_bytes = non_shared_padded.encode('utf-8') if isinstance(non_shared_padded, str) else non_shared_padded
        record_update.non_shared_data = crypto.encrypt_aes_v2(non_shared_bytes, record_key)
    
    # Make API call
    response = record_update_v3(params, [record_update])
    
    # Parse response
    if response.records:
        result = response.records[0]
        status_name = record_pb2.RecordModifyResult.Name(result.status)
        success = result.status == record_pb2.RS_SUCCESS
        
        return {
            'record_uid': record_uid,
            'status': status_name,
            'message': result.message,
            'success': success,
            'revision': response.revision if hasattr(response, 'revision') else 0
        }
    else:
        raise KeeperApiError('no_results', 'No results returned from record update')


def create_records_batch_v3(
    params: KeeperParams,
    record_specs: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Create multiple records in a single API call.
    
    This function creates multiple records efficiently by batching them
    into a single API request.
    
    Args:
        params: KeeperParams instance
        record_specs: List of record specifications, each containing:
            - 'type': Record type (e.g., 'login')
            - 'title': Record title
            - 'fields': Dictionary of fields
            - 'folder_uid': Optional folder UID
            - 'notes': Optional notes
            - 'custom_fields': Optional custom fields
    
    Returns:
        List of dictionaries with results for each record
    
    Raises:
        KeeperApiError: If the API request fails
    """
    if len(record_specs) > 1000:
        raise ValueError("Maximum 1000 records can be created at a time")
    
    record_adds = []
    record_uid_map = {}
    
    for idx, spec in enumerate(record_specs):
        # Generate new record UID
        record_uid = utils.generate_uid()
        record_uid_map[idx] = record_uid
        
        # Generate record key
        record_key = os.urandom(32)
        
        # Build record data
        data = {
            'type': spec['type'],
            'title': spec['title'],
            'fields': []
        }
        
        # Add standard fields
        fields = spec.get('fields', {})
        for field_type, field_value in fields.items():
            # Wrap value in a list if it's not already a list
            if not isinstance(field_value, list):
                field_value = [field_value]
            data['fields'].append({
                'type': field_type,
                'value': field_value
            })
        
        # Add notes as top-level property
        notes = spec.get('notes')
        if notes is not None:
            data['notes'] = notes
        
        # Add custom fields if provided
        custom_fields = spec.get('custom_fields')
        if custom_fields:
            data['fields'].extend(custom_fields)
        
        # Get folder info
        folder_uid = spec.get('folder_uid')
        folder_key = None
        if folder_uid:
            # Retrieve folder key from keeper_drive_folders or subfolder_cache
            if folder_uid in params.keeper_drive_folders:
                folder_obj = params.keeper_drive_folders[folder_uid]
                if 'folder_key_unencrypted' in folder_obj:
                    folder_key = folder_obj['folder_key_unencrypted']
            
            if not folder_key and folder_uid in params.subfolder_cache:
                folder_obj = params.subfolder_cache[folder_uid]
                if 'folder_key_unencrypted' in folder_obj:
                    folder_key = folder_obj['folder_key_unencrypted']
            
            if not folder_key:
                raise ValueError(f"Folder key not found for folder {folder_uid}. Try running 'sync-down' first.")
        
        # Get current timestamp
        current_time = utils.current_milli_time()
        
        # Create record add
        record_add = create_record_data_v3(
            record_uid=record_uid,
            record_key=record_key,
            data=data,
            folder_uid=folder_uid,
            folder_key=folder_key,
            data_key=params.data_key,
            client_modified_time=current_time
        )
        
        record_adds.append(record_add)
    
    # Make API call
    response = record_add_v3(params, record_adds)
    
    # Parse results
    results = []
    for idx, result in enumerate(response.records):
        record_uid = record_uid_map.get(idx, utils.base64_url_encode(result.record_uid))
        status_name = record_pb2.RecordModifyResult.Name(result.status)
        success = result.status == record_pb2.RS_SUCCESS
        
        results.append({
            'record_uid': record_uid,
            'title': record_specs[idx].get('title'),
            'status': status_name,
            'message': result.message,
            'success': success,
            'revision': response.revision if hasattr(response, 'revision') else 0
        })
    
    return results


def get_record_details_v3(
    params: KeeperParams,
    record_uids: List[str],
    client_time: Optional[int] = None
) -> Dict[str, Any]:
    """
    Get record metadata details (title, color, etc.) for specified records.
    
    Uses the /vault/records/v3/details/data endpoint.
    
    Args:
        params: KeeperParams instance with session information
        record_uids: List of record UIDs (base64-url encoded strings)
        client_time: Optional client timestamp in milliseconds
    
    Returns:
        Dictionary with:
        {
            'data': List of RecordData objects with metadata,
            'forbidden_records': List of record UIDs user cannot access
        }
    
    Raises:
        KeeperApiError: If the API request fails
    """
    if not record_uids:
        raise ValueError("At least one record UID must be provided")
    
    # Create request
    request = record_details_pb2.RecordDataRequest()
    
    # Add record UIDs (convert from base64-url strings to bytes)
    for record_uid in record_uids:
        request.recordUids.append(utils.base64_url_decode(record_uid))
    
    # Add optional client time
    if client_time:
        request.clientTime = client_time
    else:
        request.clientTime = utils.current_milli_time()
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Getting details for {len(record_uids)} record(s)")
        for record_uid in record_uids:
            logger.debug(f"  Record UID: {record_uid}")
    
    # Make API call
    endpoint = 'vault/records/v3/details/data'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=record_details_pb2.RecordDataResponse
    )
    
    # Parse response
    result = {
        'data': [],
        'forbidden_records': []
    }
    
    # Process record data
    for record_data in response.data:
        # Try both camelCase and snake_case field names (protobuf might use either)
        record_uid = utils.base64_url_encode(getattr(record_data, 'recordUid', getattr(record_data, 'record_uid', b'')))
        
        # Decrypt the record to get title and other metadata
        title = "Unknown"
        record_type = "Unknown"
        
        try:
            # Get record key - try both field name styles
            record_key_value = getattr(record_data, 'recordKey', getattr(record_data, 'record_key', None))
            if not record_key_value:
                logger.debug(f"No record key found for {record_uid}")
                raise ValueError("No record key")
            
            # Decrypt record key - handle both string and bytes
            if isinstance(record_key_value, str):
                encrypted_record_key = utils.base64_url_decode(record_key_value)
            else:
                encrypted_record_key = record_key_value
            
            # Get record key type - try both field name styles
            record_key_type = getattr(record_data, 'recordKeyType', getattr(record_data, 'record_key_type', None))
            
            logger.debug(f"Record {record_uid} - key type: {record_key_type}, encrypted key length: {len(encrypted_record_key)}")
            
            # Determine decryption method based on key type (handle both string and enum values)
            decrypted_record_key = None
            if record_key_type == record_pb2.ENCRYPTED_BY_DATA_KEY or record_key_type == 'ENCRYPTED_BY_DATA_KEY':
                try:
                    decrypted_record_key = crypto.decrypt_aes_v1(encrypted_record_key, params.data_key)
                except Exception as e:
                    logger.debug(f"Data key decrypt failed for {record_uid}, will try folder key: {e}")
            elif record_key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM or record_key_type == 'ENCRYPTED_BY_DATA_KEY_GCM' or not record_key_type:
                try:
                    decrypted_record_key = crypto.decrypt_aes_v2(encrypted_record_key, params.data_key)
                except Exception as e:
                    logger.debug(f"Data key decrypt failed for {record_uid}, will try folder key: {e}")
            elif record_key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY or record_key_type == 'ENCRYPTED_BY_PUBLIC_KEY':
                decrypted_record_key = crypto.decrypt_rsa(encrypted_record_key, params.rsa_key2)
            elif record_key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC or record_key_type == 'ENCRYPTED_BY_PUBLIC_KEY_ECC':
                decrypted_record_key = crypto.decrypt_ec(encrypted_record_key, params.ecc_key)
            
            # If data key decryption failed, try folder key for records in folders
            if not decrypted_record_key and record_uid in params.keeper_drive_record_keys:
                logger.debug(f"Trying folder key decryption for {record_uid}")
                for rk in params.keeper_drive_record_keys[record_uid]:
                    if 'folder_uid' in rk:
                        folder_uid = rk['folder_uid']
                        if folder_uid in params.keeper_drive_folders:
                            folder_obj = params.keeper_drive_folders[folder_uid]
                            if 'folder_key_unencrypted' in folder_obj:
                                folder_key = folder_obj['folder_key_unencrypted']
                                try:
                                    # Try to decrypt with folder key
                                    decrypted_record_key = crypto.decrypt_aes_v2(encrypted_record_key, folder_key)
                                    logger.debug(f"Successfully decrypted {record_uid} with folder key")
                                    break
                                except:
                                    try:
                                        decrypted_record_key = crypto.decrypt_aes_v1(encrypted_record_key, folder_key)
                                        logger.debug(f"Successfully decrypted {record_uid} with folder key (CBC)")
                                        break
                                    except Exception as e:
                                        logger.debug(f"Folder key decrypt failed: {e}")
            
            logger.debug(f"Decrypted record key length: {len(decrypted_record_key) if decrypted_record_key else 0}")
            
            # Get encrypted record data - try both field name styles
            encrypted_record_data = getattr(record_data, 'encryptedRecordData', getattr(record_data, 'encrypted_record_data', None))
            
            if decrypted_record_key and encrypted_record_data:
                # Decrypt record data
                # encryptedRecordData comes as a base64-url string, need to decode it
                if isinstance(encrypted_record_data, str):
                    encrypted_data = utils.base64_url_decode(encrypted_record_data)
                else:
                    encrypted_data = encrypted_record_data
                
                decrypted_data = crypto.decrypt_aes_v2(encrypted_data, decrypted_record_key)
                
                # Parse JSON to get title (decrypted_data might have padding, so strip it)
                decrypted_str = decrypted_data.decode('utf-8').rstrip(' ')
                data_json = json.loads(decrypted_str)
                title = data_json.get('title', 'Unknown')
                record_type = data_json.get('type', 'Unknown')
        except Exception as e:
            import traceback
            logger.debug(f"Could not decrypt record {record_uid}: {e}")
            logger.debug(f"Full traceback: {traceback.format_exc()}")
        
        data_obj = {
            'record_uid': record_uid,
            'title': title,
            'type': record_type,
            'revision': getattr(record_data, 'revision', 0),
            'version': getattr(record_data, 'version', 0),
        }
        
        result['data'].append(data_obj)
    
    # Process forbidden records
    for forbidden_uid in response.forbiddenRecords:
        result['forbidden_records'].append(utils.base64_url_encode(forbidden_uid))
    
    if logger.level <= logging.DEBUG:
        logger.debug(f"Retrieved details for {len(result['data'])} record(s)")
        if result['forbidden_records']:
            logger.debug(f"Forbidden records: {len(result['forbidden_records'])}")
    
    return result


def get_record_accesses_v3(
    params: KeeperParams,
    record_uids: List[str]
) -> Dict[str, Any]:
    """
    Get access information for specified records (who has access and their permissions).
    
    Uses the /vault/records/v3/details/access endpoint.
    
    Args:
        params: KeeperParams instance with session information
        record_uids: List of record UIDs (base64-url encoded strings)
    
    Returns:
        Dictionary with:
        {
            'record_accesses': List of access information per record,
            'forbidden_records': List of record UIDs user cannot access
        }
    
    Raises:
        KeeperApiError: If the API request fails
    """
    if not record_uids:
        raise ValueError("At least one record UID must be provided")
    
    # Create request
    request = record_details_pb2.RecordAccessRequest()
    
    # Add record UIDs (convert from base64-url strings to bytes)
    for record_uid in record_uids:
        request.recordUids.append(utils.base64_url_decode(record_uid))
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Getting access information for {len(record_uids)} record(s)")
    
    # Make API call
    endpoint = 'vault/records/v3/details/access'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=record_details_pb2.RecordAccessResponse
    )
    
    # Parse response
    result = {
        'record_accesses': [],
        'forbidden_records': []
    }
    
    # Process record accesses
    for record_access in response.recordAccesses:
        access_data = record_access.data
        accessor_info = record_access.accessorInfo
        
        access_obj = {
            'record_uid': utils.base64_url_encode(access_data.recordUid),
            'accessor_name': accessor_info.name,
            'access_type': folder_pb2.AccessType.Name(access_data.accessType) if hasattr(access_data, 'accessType') else 'UNKNOWN',
            'access_type_uid': utils.base64_url_encode(access_data.accessTypeUid),
            'owner': access_data.owner if hasattr(access_data, 'owner') else False,
            'can_edit': access_data.can_edit if hasattr(access_data, 'can_edit') else False,
            'can_view': access_data.can_view if hasattr(access_data, 'can_view') else False,
            'can_share': access_data.can_share if hasattr(access_data, 'can_share') else False,
            'can_delete': access_data.can_delete if hasattr(access_data, 'can_delete') else False,
            'can_request_access': access_data.can_request_access if hasattr(access_data, 'can_request_access') else False,
            'can_approve_access': access_data.can_approve_access if hasattr(access_data, 'can_approve_access') else False,
        }
        
        result['record_accesses'].append(access_obj)
    
    # Process forbidden records
    for forbidden_uid in response.forbiddenRecords:
        result['forbidden_records'].append(utils.base64_url_encode(forbidden_uid))
    
    if logger.level <= logging.DEBUG:
        logger.debug(f"Retrieved access info for {len(result['record_accesses'])} accessor(s)")
        if result['forbidden_records']:
            logger.debug(f"Forbidden records: {len(result['forbidden_records'])}")
    
    return result


def _get_user_public_key(params, recipient_email, require_uid=True):
    """
    Get user's public key from various sources.
    
    Args:
        params: KeeperParams instance
        recipient_email: Email address of the user
        require_uid: If True, tries harder to find the UID (makes extra API call if needed)
    
    Returns: (public_key_object, use_ecc, user_uid_bytes)
    """
    recipient_uid = None
    recipient_public_key = None
    use_ecc = False
    
    # Try to get public key from key_cache first (most reliable)
    if recipient_email in params.key_cache:
        user_key = params.key_cache[recipient_email]
        # MUST use RSA to match web UI (prefer RSA over ECC)
        if user_key.rsa:
            recipient_public_key = crypto.load_rsa_public_key(user_key.rsa)
            use_ecc = False
        elif user_key.ec:
            recipient_public_key = crypto.load_ec_public_key(user_key.ec)
            use_ecc = True
    
    # If not in key_cache, try enterprise users
    if not recipient_public_key and hasattr(params, 'enterprise') and params.enterprise:
        for user in params.enterprise.get('users', []):
            if user.get('username', '').lower() == recipient_email.lower():
                recipient_uid = user.get('enterprise_user_id')
                # Try to get keys from enterprise user object (prefer RSA)
                if user.get('public_key'):
                    key_bytes = utils.base64_url_decode(user['public_key'])
                    recipient_public_key = crypto.load_rsa_public_key(key_bytes)
                    use_ecc = False
                elif user.get('public_key_ecc'):
                    key_bytes = utils.base64_url_decode(user['public_key_ecc'])
                    recipient_public_key = crypto.load_ec_public_key(key_bytes)
                    use_ecc = True
                break
    
    # If still no public key, try to fetch it via API
    if not recipient_public_key:
        logger.debug(f"Public key not in cache for {recipient_email}, fetching...")
        try:
            from keepercommander import api
            from keepercommander.proto import APIRequest_pb2
            
            # Call API directly to get public keys
            rq = APIRequest_pb2.GetPublicKeysRequest()
            rq.usernames.append(recipient_email)
            rs = api.communicate_rest(params, rq, 'vault/get_public_keys', rs_type=APIRequest_pb2.GetPublicKeysResponse)
            
            for pk in rs.keyResponses:
                if pk.username.lower() == recipient_email.lower():
                    if pk.errorCode in ['', 'success']:
                        # Prefer RSA if both are available (matching web UI behavior)
                        if pk.publicKey:
                            recipient_public_key = crypto.load_rsa_public_key(pk.publicKey)
                            use_ecc = False
                        elif pk.publicEccKey:
                            recipient_public_key = crypto.load_ec_public_key(pk.publicEccKey)
                            use_ecc = True
                        
                        # Also cache it for future use
                        from keepercommander.params import PublicKeys
                        params.key_cache[recipient_email] = PublicKeys(
                            aes=None, 
                            rsa=pk.publicKey if pk.publicKey else None,
                            ec=pk.publicEccKey if pk.publicEccKey else None
                        )
                    break
        except Exception as e:
            logger.debug(f"Failed to fetch public key for {recipient_email}: {e}")
    
    # Get recipient UID - try user_cache first (accountUid -> username mapping)
    recipient_uid_bytes = None
    if hasattr(params, 'user_cache'):
        for account_uid_str, username in params.user_cache.items():
            if username.lower() == recipient_email.lower():
                # Found it! account_uid_str is already base64url encoded string
                recipient_uid_bytes = utils.base64_url_decode(account_uid_str)
                logger.debug(f"Found UID for {recipient_email} in user_cache: {account_uid_str}")
                break
    
    # Fallback: try enterprise users for the userAccountUid
    if not recipient_uid_bytes and hasattr(params, 'enterprise') and params.enterprise:
        for user in params.enterprise.get('users', []):
            if user.get('username', '').lower() == recipient_email.lower():
                # Try to get userAccountUid first (base64 encoded bytes) - this is the correct one!
                if 'user_account_uid' in user:
                    recipient_uid_bytes = utils.base64_url_decode(user['user_account_uid'])
                    logger.debug(f"Found userAccountUid for {recipient_email} in enterprise: {user['user_account_uid']}")
                break
    
    # Try get_share_objects API BEFORE falling back to enterprise_user_id
    # Only do this if UID is required (e.g., for record sharing, but not for transfer)
    if not recipient_uid_bytes and require_uid:
        try:
            from keepercommander import api
            from keepercommander.proto.record_pb2 import GetShareObjectsRequest, GetShareObjectsResponse
            
            logger.debug(f"Attempting to get UID from get_share_objects for {recipient_email}")
            
            # Create protobuf request
            rq = GetShareObjectsRequest()
            
            # Call communicate_rest WITH rs_type to parse protobuf response
            rs = api.communicate_rest(params, rq, 'vault/get_share_objects', rs_type=GetShareObjectsResponse)
            
            # Even though userAccountUid is not in .pyi, protobuf allows dynamic field access
            # Check all user types for the userAccountUid field
            all_user_lists = [
                rs.shareRelationships,
                rs.shareFamilyUsers, 
                rs.shareEnterpriseUsers,
                rs.shareMCEnterpriseUsers
            ]
            
            for user_list in all_user_lists:
                for share_user in user_list:
                    if share_user.username.lower() == recipient_email.lower():
                        # Try to access userAccountUid field directly (even if not in .pyi)
                        if hasattr(share_user, 'userAccountUid'):
                            user_account_uid = getattr(share_user, 'userAccountUid', None)
                            if user_account_uid:
                                # userAccountUid can be either bytes or base64-url string
                                if isinstance(user_account_uid, bytes):
                                    recipient_uid_bytes = user_account_uid
                                elif isinstance(user_account_uid, str):
                                    recipient_uid_bytes = utils.base64_url_decode(user_account_uid)
                                else:
                                    continue
                                logger.debug(f"Found userAccountUid for {recipient_email} from get_share_objects")
                                break
                if recipient_uid_bytes:
                    break
            
        except Exception as e:
            logger.debug(f"Failed to get UID from get_share_objects for {recipient_email}: {e}")
    
    # LAST RESORT: Fallback to enterprise_user_id (integer) conversion
    # This is often WRONG and causes "Invalid accessUid" errors
    if not recipient_uid_bytes and hasattr(params, 'enterprise') and params.enterprise:
        for user in params.enterprise.get('users', []):
            if user.get('username', '').lower() == recipient_email.lower():
                # Only use enterprise_user_id as absolute last resort
                if 'enterprise_user_id' in user:
                    enterprise_user_id = user['enterprise_user_id']
                    if isinstance(enterprise_user_id, int):
                        recipient_uid_bytes = enterprise_user_id.to_bytes(8, byteorder='big', signed=False)
                        logger.warning(f"Using enterprise_user_id {enterprise_user_id} as fallback for {recipient_email} - this may cause errors!")
                break
    
    # Note: recipient_uid_bytes may be None if not found - that's OK for some operations like transfer
    # Callers that need the UID (like record sharing) should check for None
    return recipient_public_key, use_ecc, recipient_uid_bytes


def _get_record_from_cache(params, record_uid):
    """
    Get a record from either keeper_drive_records or record_cache.
    
    Args:
        params: KeeperParams instance
        record_uid: Record UID (base64-url encoded string)
    
    Returns:
        Record dictionary or None if not found
    """
    logger = logging.getLogger(__name__)
    
    # First try keeper_drive_records (for Keeper Drive v3 records)
    if hasattr(params, 'keeper_drive_records') and record_uid in params.keeper_drive_records:
        logger.debug(f"Found record {record_uid} in keeper_drive_records")
        return params.keeper_drive_records.get(record_uid)
    
    # Fallback to standard record_cache (for v2 records or records synced via standard sync)
    if record_uid in params.record_cache:
        logger.debug(f"Found record {record_uid} in record_cache")
        return params.record_cache.get(record_uid)
    
    return None


def share_record_v3(
    params: 'KeeperParams',
    record_uid: str,
    recipient_email: str,
    access_role_type: int,
    expiration_timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Share a record with a user using v3 API with role-based permissions.
    
    Args:
        params: KeeperParams instance with session information
        record_uid: UID of the record to share
        recipient_email: Email address of the user to share with
        access_role_type: Role type from folder_pb2 (VIEWER, CONTRIBUTOR, SHARED_MANAGER, CONTENT_MANAGER, MANAGER)
        expiration_timestamp: Optional expiration timestamp in milliseconds
    
    Returns:
        Dictionary with operation results
    """
    from . import sync_down
    
    logger = logging.getLogger(__name__)
    
    try:
        # Sync to ensure we have the latest data
        sync_down.sync_down(params)
        
        # Get the record
        record_uid_bytes = utils.base64_url_decode(record_uid)
        record = _get_record_from_cache(params, record_uid)
        
        if not record:
            raise ValueError(f"Record {record_uid} not found in cache")
        
        # Get the record key
        record_key = record.get('record_key_unencrypted')
        if not record_key:
            raise ValueError(f"Record {record_uid} has no decrypted key")
        
        # Get recipient's public key and UID using the helper function
        recipient_public_key, use_ecc, recipient_uid_bytes = _get_user_public_key(params, recipient_email)
        
        if not recipient_public_key:
            raise ValueError(f"User {recipient_email} has no public key")
        
        if not recipient_uid_bytes:
            raise ValueError(f"User {recipient_email} not found in enterprise")
        
        # Encrypt record key with recipient's public key (use RSA)
        logger.debug(f"Encrypting record key with RSA (use_ecc={use_ecc}, forcing RSA)")
        if use_ecc:
            # Should not happen now that we prefer RSA, but handle it
            encrypted_record_key = crypto.encrypt_ec(record_key, recipient_public_key)
        else:
            encrypted_record_key = crypto.encrypt_rsa(record_key, recipient_public_key)
        
        # Build permissions
        permissions = record_sharing_pb2.Permissions()
        permissions.recipientUid = recipient_uid_bytes
        permissions.recordUid = record_uid_bytes
        permissions.recordKey = encrypted_record_key
        permissions.useEccKey = False  # Must be False to match web UI (we force RSA)
        
        # Set access rules (matching web UI structure exactly)
        permissions.rules.accessTypeUid = recipient_uid_bytes  # Required: UID of the recipient
        permissions.rules.accessType = folder_pb2.AT_USER     # Required: Must be AT_USER
        permissions.rules.recordUid = record_uid_bytes         # Required: UID of the record
        permissions.rules.accessRoleType = access_role_type   # Set the specified role type
        permissions.rules.owner = False                        # Not the owner
        
        logger.debug(f"Setting access role type: {access_role_type}")
        
        # Set expiration if provided
        if expiration_timestamp:
            # Set tlaProperties on the rules field (not on permissions directly)
            permissions.rules.tlaProperties.expiration = expiration_timestamp
            logger.debug(f"Setting record access expiration to {expiration_timestamp}ms")
        
        # Build request
        request = record_sharing_pb2.Request()
        request.createSharingPermissions.append(permissions)
        
        # Send request
        logger.debug(f"Sharing record {record_uid} with {recipient_email}")
        
        response_data = api.communicate_rest(
            params,
            request,
            'vault/records/v3/share',
            rs_type=record_sharing_pb2.Response
        )
        
        # Parse response
        results = []
        for status in response_data.createdSharingStatus:
            status_name = record_sharing_pb2.SharingStatus.Name(status.status) if hasattr(record_sharing_pb2.SharingStatus, 'Name') else str(status.status)
            results.append({
                'record_uid': utils.base64_url_encode(status.recordUid),
                'recipient_uid': utils.base64_url_encode(status.recipientUid),
                'status': status_name,
                'message': status.message,
                'success': status.status == record_sharing_pb2.SUCCESS
            })
        
        return {
            'results': results,
            'success': all(r['success'] for r in results)
        }
    
    except Exception as e:
        logger.error(f"Error in share_record_v3: {e}")
        raise


def update_record_share_v3(
    params: 'KeeperParams',
    record_uid: str,
    recipient_email: str,
    access_role_type: Optional[int] = None,
    expiration_timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Update sharing permissions for a record using v3 API with role-based permissions.
    
    Args:
        params: KeeperParams instance with session information
        record_uid: UID of the record
        recipient_email: Email address of the user
        access_role_type: The role-based permission type (e.g., folder_pb2.VIEWER, folder_pb2.CONTRIBUTOR)
        expiration_timestamp: Optional expiration timestamp in milliseconds
    
    Returns:
        Dictionary with operation results
    """
    from . import sync_down
    from .proto import folder_pb2
    
    logger = logging.getLogger(__name__)
    
    try:
        # Sync to ensure we have the latest data
        sync_down.sync_down(params)
        
        # Get the record
        record_uid_bytes = utils.base64_url_decode(record_uid)
        record = _get_record_from_cache(params, record_uid)
        
        if not record:
            raise ValueError(f"Record {record_uid} not found in cache")
        
        # Get the record key
        record_key = record.get('record_key_unencrypted')
        if not record_key:
            raise ValueError(f"Record {record_uid} has no decrypted key")
        
        # Get recipient's public key and UID using the helper function
        recipient_public_key, use_ecc, recipient_uid_bytes = _get_user_public_key(params, recipient_email)
        
        if not recipient_public_key:
            raise ValueError(f"User {recipient_email} has no public key")
        
        if not recipient_uid_bytes:
            raise ValueError(f"User {recipient_email} not found in enterprise")
        
        # Encrypt record key with recipient's public key
        if use_ecc:
            encrypted_record_key = crypto.encrypt_ec(record_key, recipient_public_key)
        else:
            encrypted_record_key = crypto.encrypt_rsa(record_key, recipient_public_key)
        
        # Build permissions
        permissions = record_sharing_pb2.Permissions()
        permissions.recipientUid = recipient_uid_bytes
        permissions.recordUid = record_uid_bytes
        permissions.recordKey = encrypted_record_key
        permissions.useEccKey = use_ecc
        
        # Set access rules (matching the structure used in share_record_v3)
        permissions.rules.accessTypeUid = recipient_uid_bytes  # Required: UID of the recipient
        permissions.rules.accessType = folder_pb2.AT_USER     # Required: Must be AT_USER
        permissions.rules.recordUid = record_uid_bytes         # Required: UID of the record
        permissions.rules.owner = False                        # Not the owner
        
        # Set role-based access permission if provided
        if access_role_type is not None:
            permissions.rules.accessRoleType = access_role_type
        
        # Set expiration if provided
        if expiration_timestamp:
            # Set tlaProperties on the rules field (not on permissions directly)
            permissions.rules.tlaProperties.expiration = expiration_timestamp
            logger.debug(f"Setting record access expiration to {expiration_timestamp}ms")
        
        # Build request
        request = record_sharing_pb2.Request()
        request.updateSharingPermissions.append(permissions)
        
        # Send request
        logger.debug(f"Updating share permissions for record {record_uid} with {recipient_email}")
        
        response_data = api.communicate_rest(
            params,
            request,
            'vault/records/v3/share',
            rs_type=record_sharing_pb2.Response
        )
        
        # Parse response
        results = []
        for status in response_data.updatedSharingStatus:
            status_name = record_sharing_pb2.SharingStatus.Name(status.status) if hasattr(record_sharing_pb2.SharingStatus, 'Name') else str(status.status)
            results.append({
                'record_uid': utils.base64_url_encode(status.recordUid),
                'recipient_uid': utils.base64_url_encode(status.recipientUid),
                'status': status_name,
                'message': status.message,
                'success': status.status == record_sharing_pb2.SUCCESS
            })
        
        return {
            'results': results,
            'success': all(r['success'] for r in results)
        }
    
    except Exception as e:
        logger.error(f"Error in update_record_share_v3: {e}")
        raise


def unshare_record_v3(
    params: 'KeeperParams',
    record_uid: str,
    recipient_email: str
) -> Dict[str, Any]:
    """
    Revoke record sharing (unshare) using v3 API.
    
    Args:
        params: KeeperParams instance with session information
        record_uid: UID of the record
        recipient_email: Email address of the user to unshare with
    
    Returns:
        Dictionary with operation results
    """
    from . import sync_down
    
    logger = logging.getLogger(__name__)
    
    try:
        # Sync to ensure we have the latest data
        sync_down.sync_down(params)
        
        # Get the record - check both keeper_drive_records and record_cache
        record_uid_bytes = utils.base64_url_decode(record_uid)
        record = None
        
        # First try keeper_drive_records (for Keeper Drive v3 records)
        if hasattr(params, 'keeper_drive_records') and record_uid in params.keeper_drive_records:
            record = params.keeper_drive_records.get(record_uid)
            logger.debug(f"Found record {record_uid} in keeper_drive_records")
        
        # Fallback to standard record_cache (for v2 records or records synced via standard sync)
        if not record:
            record = params.record_cache.get(record_uid)
            if record:
                logger.debug(f"Found record {record_uid} in record_cache")
        
        if not record:
            raise ValueError(f"Record {record_uid} not found in cache")
        
        # Get recipient's UID using the helper function (we don't need public key for unsharing, just UID)
        _, _, recipient_uid_bytes = _get_user_public_key(params, recipient_email)
        
        if not recipient_uid_bytes:
            raise ValueError(f"User {recipient_email} not found")
        
        # Build permissions (minimal fields needed for revoke)
        permissions = record_sharing_pb2.Permissions()
        permissions.recipientUid = recipient_uid_bytes
        permissions.recordUid = record_uid_bytes
        
        # Set access rules (API requires accessType even for revoke)
        permissions.rules.accessType = folder_pb2.AT_USER  # Required: Must be AT_USER
        permissions.rules.recordUid = record_uid_bytes     # Required: UID of the record
        
        # Build request
        request = record_sharing_pb2.Request()
        request.revokeSharingPermissions.append(permissions)
        
        # Send request
        logger.debug(f"Revoking share for record {record_uid} from {recipient_email}")
        
        response_data = api.communicate_rest(
            params,
            request,
            'vault/records/v3/share',
            rs_type=record_sharing_pb2.Response
        )
        
        # Parse response
        results = []
        for status in response_data.revokedSharingStatus:
            status_name = record_sharing_pb2.SharingStatus.Name(status.status) if hasattr(record_sharing_pb2.SharingStatus, 'Name') else str(status.status)
            results.append({
                'record_uid': utils.base64_url_encode(status.recordUid),
                'recipient_uid': utils.base64_url_encode(status.recipientUid),
                'status': status_name,
                'message': status.message,
                'success': status.status == record_sharing_pb2.SUCCESS
            })
        
        return {
            'results': results,
            'success': all(r['success'] for r in results)
        }
    
    except Exception as e:
        logger.error(f"Error in unshare_record_v3: {e}")
        raise


def transfer_record_ownership_v3(
    params: 'KeeperParams',
    record_uid: str,
    new_owner_email: str
) -> Dict[str, Any]:
    """
    Transfer record ownership to another user using v3 API.
    
    Args:
        params: KeeperParams instance with session information
        record_uid: UID of the record to transfer
        new_owner_email: Email address of the new owner
    
    Returns:
        Dictionary with operation results
    """
    from . import sync_down
    
    logger = logging.getLogger(__name__)
    
    try:
        # Sync to ensure we have the latest data
        sync_down.sync_down(params)
        
        # Get the record
        record_uid_bytes = utils.base64_url_decode(record_uid)
        record = _get_record_from_cache(params, record_uid)
        
        if not record:
            raise ValueError(f"Record {record_uid} not found in cache")
        
        # Get the record key
        record_key = record.get('record_key_unencrypted')
        if not record_key:
            raise ValueError(f"Record {record_uid} has no decrypted key")
        
        # Get new owner's public key to encrypt the record key
        # Note: We only need the public key, not the UID - the transfer API identifies users by email
        # Pass require_uid=False to avoid unnecessary get_share_objects API call
        new_owner_public_key, use_ecc, _ = _get_user_public_key(params, new_owner_email, require_uid=False)
        
        if not new_owner_public_key:
            raise ValueError(f"User {new_owner_email} has no public key")
        
        # Encrypt record key with new owner's public key
        if use_ecc:
            encrypted_record_key = crypto.encrypt_ec(record_key, new_owner_public_key)
        else:
            encrypted_record_key = crypto.encrypt_rsa(record_key, new_owner_public_key)
        
        # Build transfer record
        transfer_record = record_pb2.TransferRecord()
        transfer_record.username = new_owner_email
        transfer_record.recordUid = record_uid_bytes
        transfer_record.recordKey = encrypted_record_key
        transfer_record.useEccKey = use_ecc
        
        # Build request
        request = record_pb2.RecordsOnwershipTransferRequest()
        request.transferRecords.append(transfer_record)
        
        # Send request
        logger.debug(f"Transferring ownership of record {record_uid} to {new_owner_email}")
        
        response_data = api.communicate_rest(
            params,
            request,
            'vault/records/v3/transfer',
            rs_type=record_pb2.RecordsOnwershipTransferResponse
        )
        
        # Parse response
        results = []
        for status in response_data.transferRecordStatus:
            results.append({
                'record_uid': utils.base64_url_encode(status.recordUid),
                'username': status.username,
                'status': status.status,
                'message': status.message,
                'success': 'success' in status.status.lower()  # Check if status contains 'success'
            })
        
        # Mark for sync since record ownership changed
        params.sync_data = True
        
        return {
            'results': results,
            'success': all(r['success'] for r in results)
        }
    
    except Exception as e:
        logger.error(f"Error in transfer_record_ownership_v3: {e}")
        raise


def transfer_records_ownership_batch_v3(
    params: 'KeeperParams',
    transfers: List[Dict[str, str]]
) -> Dict[str, Any]:
    """
    Transfer ownership of multiple records in batch using v3 API.
    
    Args:
        params: KeeperParams instance with session information
        transfers: List of transfer specifications, each with:
                  - 'record_uid': UID of the record
                  - 'new_owner_email': Email of new owner
    
    Returns:
        Dictionary with operation results
    """
    from . import sync_down
    
    logger = logging.getLogger(__name__)
    
    try:
        # Sync to ensure we have the latest data
        sync_down.sync_down(params)
        
        # Build transfer records
        transfer_records = []
        
        for transfer_spec in transfers:
            record_uid = transfer_spec.get('record_uid')
            new_owner_email = transfer_spec.get('new_owner_email')
            
            if not record_uid or not new_owner_email:
                logger.warning(f"Skipping invalid transfer spec: {transfer_spec}")
                continue
            
            # Get the record
            record_uid_bytes = utils.base64_url_decode(record_uid)
            record = params.record_cache.get(record_uid)
            
            if not record:
                logger.warning(f"Record {record_uid} not found in cache, skipping")
                continue
            
            # Get the record key
            record_key = record.get('record_key_unencrypted')
            if not record_key:
                logger.warning(f"Record {record_uid} has no decrypted key, skipping")
                continue
            
            # Get new owner's public key using the helper function (same as record sharing)
            new_owner_public_key, use_ecc, new_owner_uid = _get_user_public_key(params, new_owner_email)
            
            if not new_owner_public_key:
                logger.warning(f"User {new_owner_email} has no public key, skipping")
                continue
            
            if not new_owner_uid:
                logger.warning(f"User {new_owner_email} not found in enterprise, skipping")
                continue
            
            # Encrypt record key with new owner's public key
            if use_ecc:
                encrypted_record_key = crypto.encrypt_ec(record_key, new_owner_public_key)
            else:
                encrypted_record_key = crypto.encrypt_rsa(record_key, new_owner_public_key)
            
            # Build transfer record
            transfer_record = record_pb2.TransferRecord()
            transfer_record.username = new_owner_email
            transfer_record.recordUid = record_uid_bytes
            transfer_record.recordKey = encrypted_record_key
            transfer_record.useEccKey = use_ecc
            
            transfer_records.append(transfer_record)
        
        if not transfer_records:
            raise ValueError("No valid transfer records to process")
        
        # Build request
        request = record_pb2.RecordsOnwershipTransferRequest()
        request.transferRecords.extend(transfer_records)
        
        # Send request
        logger.debug(f"Transferring ownership of {len(transfer_records)} record(s)")
        
        response_data = api.communicate_rest(
            params,
            request,
            'vault/records/v3/transfer',
            rs_type=record_pb2.RecordsOnwershipTransferResponse
        )
        
        # Parse response
        results = []
        for status in response_data.transferRecordStatus:
            results.append({
                'record_uid': utils.base64_url_encode(status.recordUid),
                'username': status.username,
                'status': status.status,
                'message': status.message,
                'success': 'success' in status.status.lower()  # Check if status contains 'success'
            })
        
        # Mark for sync since record ownership changed
        params.sync_data = True
        
        return {
            'results': results,
            'success': all(r['success'] for r in results),
            'total': len(results),
            'successful': sum(1 for r in results if r['success']),
            'failed': sum(1 for r in results if not r['success'])
        }
    
    except Exception as e:
        logger.error(f"Error in transfer_records_ownership_batch_v3: {e}")
        raise


def folder_record_update_v3(
    params: 'KeeperParams',
    folder_uid: str,
    add_records: Optional[List[folder_pb2.RecordMetadata]] = None,
    update_records: Optional[List[folder_pb2.RecordMetadata]] = None,
    remove_records: Optional[List[folder_pb2.RecordMetadata]] = None
) -> folder_pb2.FolderRecordUpdateResponse:
    """
    Add, remove, or update records in a Keeper Drive folder.
    
    This is the low-level API call to /api/vault/folders/v3/record_update.
    
    Args:
        params: KeeperParams instance with session information
        folder_uid: UID of the target folder
        add_records: List of RecordMetadata to add (max 500)
        update_records: List of RecordMetadata to update (max 500)
        remove_records: List of RecordMetadata to remove (max 500)
    
    Returns:
        FolderRecordUpdateResponse with results for each operation
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If limits are exceeded or no operations provided
    """
    # Validate limits
    if add_records and len(add_records) > 500:
        raise ValueError("Maximum 500 records can be added at a time")
    if update_records and len(update_records) > 500:
        raise ValueError("Maximum 500 records can be updated at a time")
    if remove_records and len(remove_records) > 500:
        raise ValueError("Maximum 500 records can be removed at a time")
    
    # Ensure at least one operation is provided
    if not any([add_records, update_records, remove_records]):
        raise ValueError("At least one operation (add, update, or remove) must be provided")
    
    # Create request
    request = folder_pb2.FolderRecordUpdateRequest()
    request.folderUid = utils.base64_url_decode(folder_uid)
    
    if add_records:
        request.addRecords.extend(add_records)
    if update_records:
        request.updateRecords.extend(update_records)
    if remove_records:
        request.removeRecords.extend(remove_records)
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Folder record update: folder={folder_uid}, "
                    f"adds={len(add_records or [])}, "
                    f"updates={len(update_records or [])}, "
                    f"removes={len(remove_records or [])}")
    
    # Make API call
    endpoint = 'vault/folders/v3/record_update'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=folder_pb2.FolderRecordUpdateResponse
    )
    
    # Log response
    if logger.level <= logging.DEBUG and response.folderRecordUpdateResult:
        logger.debug(f"Folder record update returned {len(response.folderRecordUpdateResult)} results")
        for result in response.folderRecordUpdateResult:
            record_uid = utils.base64_url_encode(result.recordUid)
            logger.debug(f"  {record_uid}: {result.status} - {result.message}")
    
    return response


def add_record_to_folder_v3(
    params: 'KeeperParams',
    folder_uid: str,
    record_uid: str
) -> Dict[str, Any]:
    """
    Add an existing record to a Keeper Drive folder.
    
    Args:
        params: KeeperParams instance
        folder_uid: UID of the target folder
        record_uid: UID of the record to add
    
    Returns:
        Dictionary with operation results:
        {
            'folder_uid': str,
            'record_uid': str,
            'status': str,
            'message': str,
            'success': bool
        }
    
    Raises:
        ValueError: If folder or record not found
        KeeperApiError: If the API request fails
    """
    from . import keeper_drive
    
    # Resolve folder UID
    resolved_folder_uid = keeper_drive.resolve_folder_identifier(params, folder_uid)
    if not resolved_folder_uid:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved_folder_uid
    
    # Get folder key
    folder_key = None
    if folder_uid in params.keeper_drive_folders:
        folder_obj = params.keeper_drive_folders[folder_uid]
        if 'folder_key_unencrypted' in folder_obj:
            folder_key = folder_obj['folder_key_unencrypted']
    
    if not folder_key and folder_uid in params.subfolder_cache:
        folder_obj = params.subfolder_cache[folder_uid]
        if 'folder_key_unencrypted' in folder_obj:
            folder_key = folder_obj['folder_key_unencrypted']
    
    if not folder_key:
        raise ValueError(f"Folder key not found for folder {folder_uid}. Try running 'sync-down' first.")
    
    # Get record key
    record_key = None
    if record_uid in params.keeper_drive_records:
        record_obj = params.keeper_drive_records[record_uid]
        if 'record_key_unencrypted' in record_obj:
            record_key = record_obj['record_key_unencrypted']
    
    if not record_key and record_uid in params.record_cache:
        record_obj = params.record_cache[record_uid]
        if 'record_key_unencrypted' in record_obj:
            record_key = record_obj['record_key_unencrypted']
    
    if not record_key:
        raise ValueError(f"Record key not found for record {record_uid}. Record may not exist or is not accessible.")
    
    record_key_type = _get_record_key_type(params, record_uid)
    encrypted_record_key, encrypted_record_key_type = _encrypt_record_key_for_folder(
        record_key,
        folder_key,
        record_key_type
    )
    
    record_metadata = folder_pb2.RecordMetadata()
    record_metadata.recordUid = utils.base64_url_decode(record_uid)
    record_metadata.encryptedRecordKey = encrypted_record_key
    record_metadata.encryptedRecordKeyType = encrypted_record_key_type
    
    # Make API call
    response = folder_record_update_v3(params, folder_uid, add_records=[record_metadata])
    
    # Parse response
    if response.folderRecordUpdateResult:
        result = response.folderRecordUpdateResult[0]
        return {
            'folder_uid': folder_uid,
            'record_uid': record_uid,
            'status': folder_pb2.FolderModifyStatus.Name(result.status),
            'message': result.message,
            'success': result.status == folder_pb2.SUCCESS
        }
    else:
        # Success (no results means success)
        return {
            'folder_uid': folder_uid,
            'record_uid': record_uid,
            'status': 'SUCCESS',
            'message': 'Record added to folder successfully',
            'success': True
        }


def remove_record_from_folder_v3(
    params: 'KeeperParams',
    folder_uid: str,
    record_uid: str
) -> Dict[str, Any]:
    """
    Remove a record from a Keeper Drive folder.
    
    Args:
        params: KeeperParams instance
        folder_uid: UID of the target folder
        record_uid: UID of the record to remove
    
    Returns:
        Dictionary with operation results
    
    Raises:
        ValueError: If folder not found
        KeeperApiError: If the API request fails
    """
    from . import keeper_drive
    
    # Resolve folder UID
    resolved_folder_uid = keeper_drive.resolve_folder_identifier(params, folder_uid)
    if not resolved_folder_uid:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved_folder_uid
    
    # Create RecordMetadata (only UID needed for removal)
    record_metadata = folder_pb2.RecordMetadata()
    record_metadata.recordUid = utils.base64_url_decode(record_uid)
    # Note: encryptedRecordKey and encryptedRecordKeyType are not required for removal
    # But protobuf3 requires them since they're marked as required in the schema
    # We'll set dummy values
    record_metadata.encryptedRecordKey = b''
    record_metadata.encryptedRecordKeyType = folder_pb2.no_key
    
    # Make API call
    response = folder_record_update_v3(params, folder_uid, remove_records=[record_metadata])
    
    # Parse response
    if response.folderRecordUpdateResult:
        result = response.folderRecordUpdateResult[0]
        return {
            'folder_uid': folder_uid,
            'record_uid': record_uid,
            'status': folder_pb2.FolderModifyStatus.Name(result.status),
            'message': result.message,
            'success': result.status == folder_pb2.SUCCESS
        }
    else:
        return {
            'folder_uid': folder_uid,
            'record_uid': record_uid,
            'status': 'SUCCESS',
            'message': 'Record removed from folder successfully',
            'success': True
        }


def move_record_v3(
    params: 'KeeperParams',
    record_uid: str,
    from_folder_uid: Optional[str] = None,
    to_folder_uid: Optional[str] = None
) -> Dict[str, Any]:
    """
    Move a record from one folder to another, or to/from root.
    
    Args:
        params: KeeperParams instance
        record_uid: UID of the record to move
        from_folder_uid: Source folder UID (None for root)
        to_folder_uid: Destination folder UID (None for root)
    
    Returns:
        Dictionary with operation results:
        {
            'record_uid': str,
            'from_folder': str,
            'to_folder': str,
            'success': bool,
            'message': str
        }
    
    Raises:
        ValueError: If folders not found or both are root
        KeeperApiError: If the API request fails
    
    Example:
        # Move from folder A to folder B
        result = move_record_v3(params, 'rec123', 'folderA', 'folderB')
        
        # Move from folder to root
        result = move_record_v3(params, 'rec123', 'folderA', None)
        
        # Move from root to folder
        result = move_record_v3(params, 'rec123', None, 'folderB')
    """
    from . import keeper_drive, sync_down
    
    # Sync to ensure latest data
    sync_down.sync_down(params)
    
    # Validate: can't move from root to root
    if not from_folder_uid and not to_folder_uid:
        raise ValueError("Cannot move record from root to root. Both source and destination are root.")
    
    # Remove from source folder (if not root)
    if from_folder_uid:
        # Resolve source folder UID
        resolved_from_folder = keeper_drive.resolve_folder_identifier(params, from_folder_uid)
        if not resolved_from_folder:
            raise ValueError(f"Source folder '{from_folder_uid}' not found")
        from_folder_uid = resolved_from_folder
        
        # Create RecordMetadata for removal
        record_metadata_remove = folder_pb2.RecordMetadata()
        record_metadata_remove.recordUid = utils.base64_url_decode(record_uid)
        record_metadata_remove.encryptedRecordKey = b''
        record_metadata_remove.encryptedRecordKeyType = folder_pb2.no_key
        
        # Remove from source folder
        try:
            response_remove = folder_record_update_v3(params, from_folder_uid, remove_records=[record_metadata_remove])
            
            if response_remove.folderRecordUpdateResult:
                result = response_remove.folderRecordUpdateResult[0]
                if result.status != folder_pb2.SUCCESS:
                    return {
                        'record_uid': record_uid,
                        'from_folder': from_folder_uid,
                        'to_folder': to_folder_uid or 'root',
                        'success': False,
                        'message': f"Failed to remove from source folder: {result.message}"
                    }
        except Exception as e:
            return {
                'record_uid': record_uid,
                'from_folder': from_folder_uid,
                'to_folder': to_folder_uid or 'root',
                'success': False,
                'message': f"Error removing from source folder: {str(e)}"
            }
    
    # Add to destination (folder or root)
    # Get record key first (needed for both folder and root)
    record_key = None
    if record_uid in params.keeper_drive_records:
        record_obj = params.keeper_drive_records[record_uid]
        if 'record_key_unencrypted' in record_obj:
            record_key = record_obj['record_key_unencrypted']
    
    if not record_key and record_uid in params.record_cache:
        record_obj = params.record_cache[record_uid]
        if 'record_key_unencrypted' in record_obj:
            record_key = record_obj['record_key_unencrypted']
    
    if not record_key:
        raise ValueError(f"Record key not found for record {record_uid}. Record may not exist or is not accessible.")
    
    if to_folder_uid:
        # Adding to a folder
        # Resolve destination folder UID
        resolved_to_folder = keeper_drive.resolve_folder_identifier(params, to_folder_uid)
        if not resolved_to_folder:
            raise ValueError(f"Destination folder '{to_folder_uid}' not found")
        to_folder_uid = resolved_to_folder
        
        # Get folder key
        folder_key = None
        if to_folder_uid in params.keeper_drive_folders:
            folder_obj = params.keeper_drive_folders[to_folder_uid]
            if 'folder_key_unencrypted' in folder_obj:
                folder_key = folder_obj['folder_key_unencrypted']
        
        if not folder_key and to_folder_uid in params.subfolder_cache:
            folder_obj = params.subfolder_cache[to_folder_uid]
            if 'folder_key_unencrypted' in folder_obj:
                folder_key = folder_obj['folder_key_unencrypted']
        
        if not folder_key:
            raise ValueError(f"Folder key not found for destination folder {to_folder_uid}. Try running 'sync-down' first.")
        
        # Encrypt record key with folder key (respect legacy key type when available)
        record_key_type = _get_record_key_type(params, record_uid)
        encrypted_record_key, encrypted_record_key_type = _encrypt_record_key_for_folder(
            record_key,
            folder_key,
            record_key_type
        )
        
        # Create RecordMetadata for addition
        record_metadata_add = folder_pb2.RecordMetadata()
        record_metadata_add.recordUid = utils.base64_url_decode(record_uid)
        record_metadata_add.encryptedRecordKey = encrypted_record_key
        record_metadata_add.encryptedRecordKeyType = folder_pb2.encrypted_by_data_key_gcm
        
        # Add to destination folder
        try:
            response_add = folder_record_update_v3(params, to_folder_uid, add_records=[record_metadata_add])
            
            if response_add.folderRecordUpdateResult:
                result = response_add.folderRecordUpdateResult[0]
                if result.status != folder_pb2.SUCCESS:
                    return {
                        'record_uid': record_uid,
                        'from_folder': from_folder_uid or 'root',
                        'to_folder': to_folder_uid,
                        'success': False,
                        'message': f"Failed to add to destination folder: {result.message}"
                    }
        except Exception as e:
            return {
                'record_uid': record_uid,
                'from_folder': from_folder_uid or 'root',
                'to_folder': to_folder_uid,
                'success': False,
                'message': f"Error adding to destination folder: {str(e)}"
            }
    else:
        # Adding to root (to_folder_uid is None)
        # For root level, encrypt record key with user's data key
        record_key_type = _get_record_key_type(params, record_uid)
        encrypted_record_key, encrypted_record_key_type = _encrypt_record_key_for_folder(
            record_key,
            params.data_key,
            record_key_type
        )
        
        # Create RecordMetadata for addition to root
        record_metadata_add = folder_pb2.RecordMetadata()
        record_metadata_add.recordUid = utils.base64_url_decode(record_uid)
        record_metadata_add.encryptedRecordKey = encrypted_record_key
        record_metadata_add.encryptedRecordKeyType = encrypted_record_key_type
        
        # Add to root (use empty folder UID)
        try:
            # Use empty string for root folder UID
            response_add = folder_record_update_v3(params, '', add_records=[record_metadata_add])
            
            if response_add.folderRecordUpdateResult:
                result = response_add.folderRecordUpdateResult[0]
                if result.status != folder_pb2.SUCCESS:
                    return {
                        'record_uid': record_uid,
                        'from_folder': from_folder_uid or 'root',
                        'to_folder': 'root',
                        'success': False,
                        'message': f"Failed to add to root: {result.message}"
                    }
        except Exception as e:
            return {
                'record_uid': record_uid,
                'from_folder': from_folder_uid or 'root',
                'to_folder': 'root',
                'success': False,
                'message': f"Error adding to root: {str(e)}"
            }
    
    # Success
    return {
        'record_uid': record_uid,
        'from_folder': from_folder_uid or 'root',
        'to_folder': to_folder_uid or 'root',
        'success': True,
        'message': 'Record moved successfully'
    }


def manage_folder_records_batch_v3(
    params: 'KeeperParams',
    folder_uid: str,
    records_to_add: Optional[List[str]] = None,
    records_to_remove: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Batch add or remove records from a folder.
    
    Args:
        params: KeeperParams instance
        folder_uid: UID of the target folder
        records_to_add: List of record UIDs to add (max 500)
        records_to_remove: List of record UIDs to remove (max 500)
    
    Returns:
        List of result dictionaries for all operations
    
    Example:
        results = manage_folder_records_batch_v3(
            params,
            folder_uid='xxx',
            records_to_add=['rec1', 'rec2'],
            records_to_remove=['rec3']
        )
    """
    from . import keeper_drive
    
    # Resolve folder UID
    resolved_folder_uid = keeper_drive.resolve_folder_identifier(params, folder_uid)
    if not resolved_folder_uid:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved_folder_uid
    
    # Get folder key once
    folder_key = None
    if folder_uid in params.keeper_drive_folders:
        folder_obj = params.keeper_drive_folders[folder_uid]
        if 'folder_key_unencrypted' in folder_obj:
            folder_key = folder_obj['folder_key_unencrypted']
    
    if not folder_key and folder_uid in params.subfolder_cache:
        folder_obj = params.subfolder_cache[folder_uid]
        if 'folder_key_unencrypted' in folder_obj:
            folder_key = folder_obj['folder_key_unencrypted']
    
    if not folder_key:
        raise ValueError(f"Folder key not found for folder {folder_uid}. Try running 'sync-down' first.")
    
    adds_list = []
    removes_list = []
    operation_tracking = []  # Track operation type and record UID for result mapping
    
    # Process adds
    if records_to_add:
        for record_uid in records_to_add:
            # Get record key
            record_key = None
            if record_uid in params.keeper_drive_records:
                record_obj = params.keeper_drive_records[record_uid]
                if 'record_key_unencrypted' in record_obj:
                    record_key = record_obj['record_key_unencrypted']
            
            if not record_key and record_uid in params.record_cache:
                record_obj = params.record_cache[record_uid]
                if 'record_key_unencrypted' in record_obj:
                    record_key = record_obj['record_key_unencrypted']
            
            if not record_key:
                raise ValueError(f"Record key not found for record {record_uid}")
            
            # Encrypt ecord key with folder key (respect legacy key type when available)
            record_key_type = _get_record_key_type(params, record_uid)
            encrypted_record_key, encrypted_record_key_type = _encrypt_record_key_for_folder(
                record_key,
                folder_key,
                record_key_type
            )
            
            # Create RecordMetadata
            record_metadata = folder_pb2.RecordMetadata()
            record_metadata.recordUid = utils.base64_url_decode(record_uid)
            record_metadata.encryptedRecordKey = encrypted_record_key
            record_metadata.encryptedRecordKeyType = encrypted_record_key_type
            
            adds_list.append(record_metadata)
            operation_tracking.append(('add', record_uid))
    
    # Process removes
    if records_to_remove:
        for record_uid in records_to_remove:
            # Create RecordMetadata (minimal for removal)
            record_metadata = folder_pb2.RecordMetadata()
            record_metadata.recordUid = utils.base64_url_decode(record_uid)
            record_metadata.encryptedRecordKey = b''
            record_metadata.encryptedRecordKeyType = folder_pb2.no_key
            
            removes_list.append(record_metadata)
            operation_tracking.append(('remove', record_uid))
    
    # Make API call
    response = folder_record_update_v3(
        params,
        folder_uid,
        add_records=adds_list if adds_list else None,
        remove_records=removes_list if removes_list else None
    )
    
    # Build results (assume all successful initially)
    results = []
    for op_type, record_uid in operation_tracking:
        results.append({
            'operation': op_type,
            'folder_uid': folder_uid,
            'record_uid': record_uid,
            'status': 'SUCCESS',
            'message': f'{op_type.capitalize()} operation completed successfully',
            'success': True
        })
    
    # Override with failed operations from response
    if response.folderRecordUpdateResult:
        for result in response.folderRecordUpdateResult:
            record_uid_bytes = result.recordUid
            record_uid = utils.base64_url_encode(record_uid_bytes)
            
            # Find and update the corresponding result
            for i, (op_type, tracked_record) in enumerate(operation_tracking):
                if tracked_record == record_uid:
                    results[i] = {
                        'operation': op_type,
                        'folder_uid': folder_uid,
                        'record_uid': record_uid,
                        'status': folder_pb2.FolderModifyStatus.Name(result.status),
                        'message': result.message,
                        'success': result.status == folder_pb2.SUCCESS
                    }
                    break
    
    return results
