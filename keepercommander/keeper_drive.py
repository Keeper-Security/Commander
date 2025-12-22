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
KeeperDrive API Module

This module provides functions for interacting with KeeperDrive v3 APIs,
including folder creation, updates, and management.
"""

import json
import logging
import os
from typing import Optional, List, Dict, Any, Union

from . import utils, crypto, api
from .params import KeeperParams
from .proto import folder_pb2
from .error import KeeperApiError
from .subfolder import try_resolve_path


logger = logging.getLogger(__name__)


class FolderUsageType:
    """Folder usage type enum"""
    NORMAL = folder_pb2.UT_NORMAL
    # Add other types as they become available


class SetBooleanValue:
    """Boolean value setter enum for optional fields"""
    BOOLEAN_NO_CHANGE = folder_pb2.BOOLEAN_NO_CHANGE
    BOOLEAN_TRUE = folder_pb2.BOOLEAN_TRUE
    BOOLEAN_FALSE = folder_pb2.BOOLEAN_FALSE


def create_folder_data(
    folder_uid: str,
    folder_name: str,
    encryption_key: bytes,
    parent_uid: Optional[str] = None,
    folder_type: Optional[int] = None,
    inherit_permissions: Optional[int] = None,
    color: Optional[str] = None,
    owner_username: Optional[str] = None,
    owner_account_uid: Optional[str] = None
) -> folder_pb2.FolderData:
    """
    Create a FolderData protobuf message for folder creation.
    
    Args:
        folder_uid: The unique identifier for the folder (base64-url encoded)
        folder_name: The name of the folder
        encryption_key: The encryption key to use for the folder (32 bytes for AES-256)
        parent_uid: Optional parent folder UID (if not root)
        folder_type: Optional folder usage type (defaults to NORMAL)
        inherit_permissions: Optional permission inheritance setting
        color: Optional folder color
        owner_username: Optional owner username
        owner_account_uid: Optional owner account UID
    
    Returns:
        FolderData protobuf message
    """
    folder_data = folder_pb2.FolderData()
    
    # Required fields
    folder_data.folderUid = utils.base64_url_decode(folder_uid)
    
    # Build folder data dictionary
    data_dict = {'name': folder_name}
    if color and color != 'none':
        data_dict['color'] = color
    
    # Encrypt folder data with GCM (AES-256-GCM)
    data_json = json.dumps(data_dict).encode('utf-8')
    folder_data.data = crypto.encrypt_aes_v2(data_json, encryption_key)
    
    # Folder key (encrypted with parent key or user data key)
    # For now, we'll set this in the calling function based on context
    folder_data.folderKey = encryption_key
    
    # Optional fields
    if parent_uid:
        folder_data.parentUid = utils.base64_url_decode(parent_uid)
    
    if folder_type is not None:
        folder_data.type = folder_type
    
    if inherit_permissions is not None:
        folder_data.inheritUserPermissions = inherit_permissions
    
    # Owner info (typically set by server, but can be provided)
    if owner_username or owner_account_uid:
        owner_info = folder_pb2.UserInfo()
        if owner_username:
            owner_info.username = owner_username
        if owner_account_uid:
            owner_info.accountUid = utils.base64_url_decode(owner_account_uid)
        folder_data.ownerInfo.CopyFrom(owner_info)
    
    return folder_data


def encrypt_folder_key(folder_key: bytes, parent_key: bytes, use_gcm: bool = True) -> bytes:
    """
    Encrypt a folder key with a parent key (user data key or parent folder key).
    
    Args:
        folder_key: The folder key to encrypt (32 bytes)
        parent_key: The parent encryption key (32 bytes)
        use_gcm: Whether to use GCM encryption (default True for KeeperDrive)
    
    Returns:
        Encrypted folder key
    """
    if use_gcm:
        return crypto.encrypt_aes_v2(folder_key, parent_key)
    else:
        # Legacy CBC encryption
        return crypto.encrypt_aes_v1(folder_key, parent_key)


def folder_add_v3(
    params: KeeperParams,
    folders: List[folder_pb2.FolderData]
) -> folder_pb2.FolderAddResponse:
    """
    Create new folders using the KeeperDrive v3 API.
    
    This function creates one or more folders in the user's vault using the
    new KeeperDrive folder structure. Maximum 100 folders per request.
    
    Args:
        params: KeeperParams instance with session information
        folders: List of FolderData messages (max 100)
    
    Returns:
        FolderAddResponse with results for each folder
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If more than 100 folders are provided
    """
    if len(folders) > 100:
        raise ValueError("Maximum 100 folders can be created at a time")
    
    if not folders:
        raise ValueError("At least one folder must be provided")
    
    # Create request
    request = folder_pb2.FolderAddRequest()
    request.folderData.extend(folders)
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Creating {len(folders)} folder(s) via KeeperDrive v3 API")
        for fd in folders:
            folder_uid = utils.base64_url_encode(fd.folderUid)
            parent_uid = utils.base64_url_encode(fd.parentUid) if fd.parentUid else 'root'
            logger.debug(f"  Folder UID: {folder_uid}, Parent: {parent_uid}")
    
    # Make API call
    # Note: Use communicate_rest2 for v3 endpoints that don't use /rest/ prefix
    endpoint = 'vault/folders/v3/add'  # Full path without /rest/
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=folder_pb2.FolderAddResponse
    )
    
    # Log response
    if logger.level <= logging.DEBUG:
        for result in response.folderAddResults:
            folder_uid = utils.base64_url_encode(result.folderUid)
            logger.debug(f"  Result for {folder_uid}: {result.status} - {result.message}")
    
    return response


def create_folder_v3(
    params: KeeperParams,
    folder_name: str,
    parent_uid: Optional[str] = None,
    color: Optional[str] = None,
    inherit_permissions: bool = True
) -> Dict[str, Any]:
    """
    High-level function to create a single folder in KeeperDrive.
    
    This is a convenience wrapper around folder_add_v3 for creating a single folder.
    
    Args:
        params: KeeperParams instance
        folder_name: Name of the folder to create
        parent_uid: Optional parent folder UID (None for root)
        color: Optional folder color
        inherit_permissions: Whether to inherit parent permissions (default True)
    
    Returns:
        Dictionary with folder creation results:
        {
            'folder_uid': str,
            'status': str,
            'message': str,
            'success': bool
        }
    
    Raises:
        KeeperApiError: If the API request fails
    """
    # Generate new folder UID
    folder_uid = utils.generate_uid()
    
    # Generate folder key
    folder_key = os.urandom(32)  # AES-256 key
    
    # Determine encryption key (user data key or parent folder key)
    encryption_key = params.data_key  # Default to user data key
    if parent_uid:
        # Get parent folder key from params.keeper_drive_folders or params.subfolder_cache
        parent_folder_key = None
        if parent_uid in params.keeper_drive_folders:
            parent_folder = params.keeper_drive_folders[parent_uid]
            if 'folder_key_unencrypted' in parent_folder:
                parent_folder_key = parent_folder['folder_key_unencrypted']
        
        if not parent_folder_key and parent_uid in params.subfolder_cache:
            parent_folder = params.subfolder_cache[parent_uid]
            if 'folder_key_unencrypted' in parent_folder:
                parent_folder_key = parent_folder['folder_key_unencrypted']
        
        if parent_folder_key:
            encryption_key = parent_folder_key
            logging.debug(f"Using parent folder key for encrypting folder key (parent: {parent_uid})")
        else:
            logging.warning(f"Parent folder key not found for {parent_uid}, using user data key")
    
    # Encrypt folder key with parent key
    encrypted_folder_key = encrypt_folder_key(folder_key, encryption_key, use_gcm=True)
    
    # Create folder data
    folder_data = create_folder_data(
        folder_uid=folder_uid,
        folder_name=folder_name,
        encryption_key=folder_key,
        parent_uid=parent_uid,
        folder_type=FolderUsageType.NORMAL,
        inherit_permissions=SetBooleanValue.BOOLEAN_TRUE if inherit_permissions else SetBooleanValue.BOOLEAN_FALSE,
        color=color
    )
    
    # Set encrypted folder key
    folder_data.folderKey = encrypted_folder_key
    
    # Make API call
    response = folder_add_v3(params, [folder_data])
    
    # Parse response
    if response.folderAddResults:
        result = response.folderAddResults[0]
        return {
            'folder_uid': folder_uid,
            'status': folder_pb2.FolderModifyStatus.Name(result.status),
            'message': result.message,
            'success': result.status == folder_pb2.SUCCESS
        }
    else:
        raise KeeperApiError('no_results', 'No results returned from folder creation')


def create_folders_batch_v3(
    params: KeeperParams,
    folder_specs: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Create multiple folders in a single API call.
    
    Args:
        params: KeeperParams instance
        folder_specs: List of folder specifications, each containing:
            - name: str (required)
            - parent_uid: str (optional)
            - color: str (optional)
            - inherit_permissions: bool (optional, default True)
    
    Returns:
        List of result dictionaries for each folder
    
    Example:
        results = create_folders_batch_v3(params, [
            {'name': 'Projects', 'color': 'blue'},
            {'name': 'Work', 'parent_uid': 'xxx', 'color': 'red'}
        ])
    """
    if len(folder_specs) > 100:
        raise ValueError("Maximum 100 folders can be created at a time")
    
    folder_data_list = []
    folder_uid_map = {}  # Map index to folder_uid for result tracking
    
    for idx, spec in enumerate(folder_specs):
        folder_uid = utils.generate_uid()
        folder_uid_map[idx] = folder_uid
        
        folder_name = spec.get('name')
        if not folder_name:
            raise ValueError(f"Folder specification at index {idx} missing 'name'")
        
        parent_uid = spec.get('parent_uid')
        color = spec.get('color')
        inherit_permissions = spec.get('inherit_permissions', True)
        
        # Generate folder key
        folder_key = os.urandom(32)
        
        # Determine encryption key (user data key or parent folder key)
        encryption_key = params.data_key  # Default to user data key
        if parent_uid:
            # Get parent folder key from params.keeper_drive_folders or params.subfolder_cache
            parent_folder_key = None
            if parent_uid in params.keeper_drive_folders:
                parent_folder = params.keeper_drive_folders[parent_uid]
                if 'folder_key_unencrypted' in parent_folder:
                    parent_folder_key = parent_folder['folder_key_unencrypted']
            
            if not parent_folder_key and parent_uid in params.subfolder_cache:
                parent_folder = params.subfolder_cache[parent_uid]
                if 'folder_key_unencrypted' in parent_folder:
                    parent_folder_key = parent_folder['folder_key_unencrypted']
            
            if parent_folder_key:
                encryption_key = parent_folder_key
                logging.debug(f"Using parent folder key for encrypting folder key (parent: {parent_uid})")
            else:
                logging.warning(f"Parent folder key not found for {parent_uid}, using user data key")
        
        # Encrypt folder key
        encrypted_folder_key = encrypt_folder_key(folder_key, encryption_key, use_gcm=True)
        
        # Create folder data
        folder_data = create_folder_data(
            folder_uid=folder_uid,
            folder_name=folder_name,
            encryption_key=folder_key,
            parent_uid=parent_uid,
            folder_type=FolderUsageType.NORMAL,
            inherit_permissions=SetBooleanValue.BOOLEAN_TRUE if inherit_permissions else SetBooleanValue.BOOLEAN_FALSE,
            color=color
        )
        folder_data.folderKey = encrypted_folder_key
        
        folder_data_list.append(folder_data)
    
    # Make API call
    response = folder_add_v3(params, folder_data_list)
    
    # Parse results
    results = []
    for idx, result in enumerate(response.folderAddResults):
        folder_uid = folder_uid_map.get(idx, utils.base64_url_encode(result.folderUid))
        results.append({
            'folder_uid': folder_uid,
            'name': folder_specs[idx].get('name'),
            'status': folder_pb2.FolderModifyStatus.Name(result.status),
            'message': result.message,
            'success': result.status == folder_pb2.SUCCESS
        })
    
    return results


def folder_access_update_v3(
    params: KeeperParams,
    folder_access_adds: Optional[List[folder_pb2.FolderAccessData]] = None,
    folder_access_updates: Optional[List[folder_pb2.FolderAccessData]] = None,
    folder_access_removes: Optional[List[folder_pb2.FolderAccessData]] = None
) -> folder_pb2.FolderAccessResponse:
    """
    Manage access to Keeper Drive folders using the v3 API.
    
    This function grants, updates, or revokes access to folders.
    
    Args:
        params: KeeperParams instance with session information
        folder_access_adds: List of FolderAccessData to grant access (max 500)
        folder_access_updates: List of FolderAccessData to update access (max 500)
        folder_access_removes: List of FolderAccessData to revoke access (max 500)
    
    Returns:
        FolderAccessResponse with results for unsuccessful operations
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If limits are exceeded or no operations provided
    """
    # Validate limits
    if folder_access_adds and len(folder_access_adds) > 500:
        raise ValueError("Maximum 500 folder access entries can be granted at a time")
    if folder_access_updates and len(folder_access_updates) > 500:
        raise ValueError("Maximum 500 folder access entries can be updated at a time")
    if folder_access_removes and len(folder_access_removes) > 500:
        raise ValueError("Maximum 500 folder access entries can be revoked at a time")
    
    # Ensure at least one operation is provided
    if not any([folder_access_adds, folder_access_updates, folder_access_removes]):
        raise ValueError("At least one access operation (add, update, or remove) must be provided")
    
    # Create request
    request = folder_pb2.FolderAccessRequest()
    if folder_access_adds:
        request.folderAccessAdds.extend(folder_access_adds)
    if folder_access_updates:
        request.folderAccessUpdates.extend(folder_access_updates)
    if folder_access_removes:
        request.folderAccessRemoves.extend(folder_access_removes)
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Folder access update: adds={len(folder_access_adds or [])}, "
                    f"updates={len(folder_access_updates or [])}, "
                    f"removes={len(folder_access_removes or [])}")
    
    # Make API call
    endpoint = 'vault/folders/v3/access_update'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=folder_pb2.FolderAccessResponse
    )
    
    # Log response
    if logger.level <= logging.DEBUG and response.folderAccessResults:
        logger.debug(f"Folder access update returned {len(response.folderAccessResults)} results")
        for result in response.folderAccessResults:
            folder_uid = utils.base64_url_encode(result.folderUid)
            access_uid = utils.base64_url_encode(result.accessUid) if result.accessUid else 'N/A'
            logger.debug(f"  {folder_uid} / {access_uid}: {result.status} - {result.message}")
    
    return response


def grant_folder_access_v3(
    params: KeeperParams,
    folder_uid: str,
    user_uid: str,
    role: str = 'viewer',
    share_folder_key: bool = True,
    expiration_timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Grant a user access to a folder.
    
    Args:
        params: KeeperParams instance
        folder_uid: UID of the folder
        user_uid: UID of the user to grant access to
        role: Access role - 'viewer', 'contributor', 'content_manager', 'manager' (default: 'viewer')
        share_folder_key: Whether to encrypt and share the folder key (default: True)
        expiration_timestamp: Optional expiration time in milliseconds since epoch (default: None)
    
    Returns:
        Dictionary with operation results:
        {
            'folder_uid': str,
            'user_uid': str,
            'status': str,
            'message': str,
            'success': bool
        }
    
    Raises:
        ValueError: If folder or user not found, or invalid role
        KeeperApiError: If the API request fails
    """
    # Resolve folder UID
    resolved_folder_uid = resolve_folder_identifier(params, folder_uid)
    if not resolved_folder_uid:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved_folder_uid
    
    # Resolve user to UID and public key (reuse record-sharing helper)
    is_email = '@' in user_uid
    user_email = user_uid if is_email else None
    actual_user_uid_bytes = None
    user_public_key = None
    use_ecc = False
    
    if is_email:
        try:
            from keepercommander import keeper_drive_records
            user_public_key, use_ecc, actual_user_uid_bytes = keeper_drive_records._get_user_public_key(params, user_email)
        except Exception as e:
            raise ValueError(f"User with email '{user_email}' not found or has no public key. {e}")
    else:
        try:
            actual_user_uid_bytes = utils.base64_url_decode(user_uid)
            user_email = user_uid  # fallback
            if hasattr(params, 'user_cache'):
                for account_uid_str, username in params.user_cache.items():
                    if utils.base64_url_decode(account_uid_str) == actual_user_uid_bytes:
                        user_email = username
                        logging.debug(f"Found email {user_email} for UID {user_uid}")
                        break
        except Exception:
            raise ValueError(f"Invalid user UID format: {user_uid}")
    
    # Map role names to AccessRoleType enum
    role_map = {
        'viewer': folder_pb2.VIEWER,
        'contributor': folder_pb2.CONTRIBUTOR,
        'content_manager': folder_pb2.CONTENT_MANAGER,
        'manager': folder_pb2.MANAGER,
    }
    
    role_lower = role.lower()
    if role_lower not in role_map:
        raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(role_map.keys())}")
    
    access_role = role_map[role_lower]
    
    # Create FolderAccessData
    access_data = folder_pb2.FolderAccessData()
    access_data.folderUid = utils.base64_url_decode(folder_uid)
    
    # Set accessTypeUid - use the same format as record sharing (no padding, raw bytes)
    access_data.accessTypeUid = actual_user_uid_bytes
    access_data.accessType = folder_pb2.AT_USER
    access_data.accessRoleType = access_role
    
    # Set expiration if provided
    if expiration_timestamp:
        from keepercommander.proto import tla_pb2
        access_data.tlaProperties.expiration = expiration_timestamp
        logging.debug(f"Setting folder access expiration to {expiration_timestamp}ms")
    
    # Get and encrypt folder key if sharing
    if share_folder_key:
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
        
        # Get user's public key from cache/server if we don't have it yet
        if not user_public_key:
            user_keys = None
            if user_email in params.key_cache:
                user_keys = params.key_cache[user_email]
            
            if not user_keys:
                logging.debug(f"Loading public key for user {user_email}")
                api.load_user_public_keys(params, [user_email])
                if user_email in params.key_cache:
                    user_keys = params.key_cache[user_email]
            
            if not user_keys:
                raise ValueError(f"Public key not found for user {user_email}. User may not exist or key not available.")
            
            # Extract the actual public key from PublicKeys object
            if user_keys.rsa:
                user_public_key = crypto.load_rsa_public_key(user_keys.rsa)
                use_ecc = False
            elif user_keys.ec:
                user_public_key = crypto.load_ec_public_key(user_keys.ec)
                use_ecc = True
            else:
                raise ValueError(f"No valid public key (RSA or ECC) found for user {user_email}")
        
        # Encrypt folder key with user's public key
        if use_ecc:
            encrypted_folder_key = crypto.encrypt_ec(folder_key, user_public_key)
        else:
            encrypted_folder_key = crypto.encrypt_rsa(folder_key, user_public_key)
        
        # Set encrypted folder key with correct type
        encrypted_key = folder_pb2.EncryptedDataKey()
        encrypted_key.encryptedKey = encrypted_folder_key
        # Set the correct key type based on encryption method used
        if use_ecc:
            encrypted_key.encryptedKeyType = folder_pb2.encrypted_by_public_key_ecc
        else:
            encrypted_key.encryptedKeyType = folder_pb2.encrypted_by_public_key
        access_data.folderKey.CopyFrom(encrypted_key)
    
    # Make API call
    response = folder_access_update_v3(params, folder_access_adds=[access_data])
    
    # Parse response
    # NOTE: API documentation states folderAccessResults contains "unsuccessful" operations,
    # but in practice, the API returns results for ALL operations.
    # We determine success/failure by checking the status and message fields:
    # - status field with non-zero value = explicit failure
    # - message field present = error occurred
    # - neither status nor message = success (operation completed)
    if response.folderAccessResults:
        result = response.folderAccessResults[0]
        
        # Check status field - defaults to 0 (SUCCESS) if not set
        status_value = result.status
        
        # Check if this represents a failure:
        # 1. Non-zero status explicitly indicates failure
        # 2. Presence of error message indicates failure
        is_failure = (status_value != 0) or (result.message and len(result.message) > 0)
        
        if is_failure:
            # Operation failed
            if status_value != 0:
                status_name = folder_pb2.FolderModifyStatus.Name(status_value)
            else:
                status_name = 'ERROR'
            
            return {
                'folder_uid': folder_uid,
                'user_uid': user_uid,
                'status': status_name,
                'message': result.message if result.message else 'Operation failed',
                'success': False
            }
        else:
            # Operation succeeded (status=0, no error message)
            return {
                'folder_uid': folder_uid,
                'user_uid': user_uid,
                'status': 'SUCCESS',
                'message': 'Access granted successfully',
                'success': True
            }
    else:
        # No results = all operations succeeded (per API documentation)
        return {
            'folder_uid': folder_uid,
            'user_uid': user_uid,
            'status': 'SUCCESS',
            'message': 'Access granted successfully',
            'success': True
        }


def update_folder_access_v3(
    params: KeeperParams,
    folder_uid: str,
    user_uid: str,
    role: Optional[str] = None,
    hidden: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Update a user's access to a folder.
    
    Args:
        params: KeeperParams instance
        folder_uid: UID of the folder
        user_uid: UID of the user whose access to update
        role: New access role (optional)
        hidden: Whether to hide the folder access (optional)
    
    Returns:
        Dictionary with operation results
    
    Raises:
        ValueError: If folder or user not found
        KeeperApiError: If the API request fails
    """
    if role is None and hidden is None:
        raise ValueError("At least one field (role or hidden) must be provided for update")
    
    # Resolve folder UID
    resolved_folder_uid = resolve_folder_identifier(params, folder_uid)
    if not resolved_folder_uid:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved_folder_uid
    
    # Resolve user to UID (prefer record-sharing helper)
    is_email = '@' in user_uid
    user_email = user_uid if is_email else None
    actual_user_uid_bytes = None
    
    if is_email:
        try:
            from keepercommander import keeper_drive_records
            _pub_key, _use_ecc, actual_user_uid_bytes = keeper_drive_records._get_user_public_key(params, user_email)
        except Exception as e:
            raise ValueError(f"User with email '{user_email}' not found. {e}")
    else:
        try:
            actual_user_uid_bytes = utils.base64_url_decode(user_uid)
        except Exception:
            raise ValueError(f"Invalid user UID format: {user_uid}")
    
    # Create FolderAccessData
    access_data = folder_pb2.FolderAccessData()
    access_data.folderUid = utils.base64_url_decode(folder_uid)
    access_data.accessTypeUid = actual_user_uid_bytes
    access_data.accessType = folder_pb2.AT_USER
    
    # Update role if specified
    if role:
        role_map = {
            'viewer': folder_pb2.VIEWER,
            'contributor': folder_pb2.CONTRIBUTOR,
            'content_manager': folder_pb2.CONTENT_MANAGER,
            'manager': folder_pb2.MANAGER,
        }
        role_lower = role.lower()
        if role_lower not in role_map:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(role_map.keys())}")
        access_data.accessRoleType = role_map[role_lower]
    
    # Update hidden if specified
    if hidden is not None:
        access_data.hidden = hidden
    
    # Make API call
    response = folder_access_update_v3(params, folder_access_updates=[access_data])
    
    # Parse response
    if response.folderAccessResults:
        result = response.folderAccessResults[0]
        status_value = result.status
        is_failure = (status_value != 0) or (result.message and len(result.message) > 0)
        status_name = folder_pb2.FolderModifyStatus.Name(status_value) if status_value != 0 else 'SUCCESS'
        return {
            'folder_uid': folder_uid,
            'user_uid': user_uid,
            'status': status_name,
            'message': result.message if result.message else 'Access updated successfully',
            'success': not is_failure
        }
    else:
        return {
            'folder_uid': folder_uid,
            'user_uid': user_uid,
            'status': 'SUCCESS',
            'message': 'Access updated successfully',
            'success': True
        }


def revoke_folder_access_v3(
    params: KeeperParams,
    folder_uid: str,
    user_uid: str
) -> Dict[str, Any]:
    """
    Revoke a user's access to a folder.
    
    Args:
        params: KeeperParams instance
        folder_uid: UID of the folder
        user_uid: UID of the user whose access to revoke
    
    Returns:
        Dictionary with operation results
    
    Raises:
        ValueError: If folder or user not found
        KeeperApiError: If the API request fails
    """
    # Resolve folder UID
    resolved_folder_uid = resolve_folder_identifier(params, folder_uid)
    if not resolved_folder_uid:
        raise ValueError(f"Folder '{folder_uid}' not found")
    folder_uid = resolved_folder_uid
    
    # Resolve user to UID (prefer record-sharing helper)
    is_email = '@' in user_uid
    actual_user_uid_bytes = None
    
    if is_email:
        try:
            from keepercommander import keeper_drive_records
            _pub_key, _use_ecc, actual_user_uid_bytes = keeper_drive_records._get_user_public_key(params, user_uid)
        except Exception as e:
            raise ValueError(f"User with email '{user_uid}' not found. {e}")
    else:
        try:
            actual_user_uid_bytes = utils.base64_url_decode(user_uid)
        except Exception:
            raise ValueError(f"Invalid user UID format: {user_uid}")
    
    # Create FolderAccessData (only UIDs needed for removal)
    access_data = folder_pb2.FolderAccessData()
    access_data.folderUid = utils.base64_url_decode(folder_uid)
    access_data.accessTypeUid = actual_user_uid_bytes
    access_data.accessType = folder_pb2.AT_USER
    
    # Make API call
    response = folder_access_update_v3(params, folder_access_removes=[access_data])
    
    # Parse response
    if response.folderAccessResults:
        result = response.folderAccessResults[0]
        status_value = result.status
        is_failure = (status_value != 0) or (result.message and len(result.message) > 0)
        status_name = folder_pb2.FolderModifyStatus.Name(status_value) if status_value != 0 else 'SUCCESS'
        return {
            'folder_uid': folder_uid,
            'user_uid': user_uid,
            'status': status_name,
            'message': result.message if result.message else 'Access revoked successfully',
            'success': not is_failure
        }
    else:
        return {
            'folder_uid': folder_uid,
            'user_uid': user_uid,
            'status': 'SUCCESS',
            'message': 'Access revoked successfully',
            'success': True
        }


def manage_folder_access_batch_v3(
    params: KeeperParams,
    access_grants: Optional[List[Dict[str, Any]]] = None,
    access_updates: Optional[List[Dict[str, Any]]] = None,
    access_revokes: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """
    Batch manage folder access (grant, update, revoke) in a single API call.
    
    Args:
        params: KeeperParams instance
        access_grants: List of grant specifications:
            - folder_uid: str (required)
            - user_uid: str (required)
            - role: str (optional, default 'viewer')
        access_updates: List of update specifications:
            - folder_uid: str (required)
            - user_uid: str (required)
            - role: str (optional)
            - hidden: bool (optional)
        access_revokes: List of revoke specifications:
            - folder_uid: str (required)
            - user_uid: str (required)
    
    Returns:
        List of result dictionaries for all operations
    
    Example:
        results = manage_folder_access_batch_v3(
            params,
            access_grants=[
                {'folder_uid': 'xxx', 'user_uid': 'user1', 'role': 'viewer'},
                {'folder_uid': 'yyy', 'user_uid': 'user2', 'role': 'manager'}
            ],
            access_revokes=[
                {'folder_uid': 'zzz', 'user_uid': 'user3'}
            ]
        )
    """
    adds_list = []
    updates_list = []
    removes_list = []
    operation_tracking = []  # Track operation type and original spec for result mapping
    
    role_map = {
        'viewer': folder_pb2.VIEWER,
        'contributor': folder_pb2.CONTRIBUTOR,
        'content_manager': folder_pb2.CONTENT_MANAGER,
        'manager': folder_pb2.MANAGER,
    }
    
    # Process grants
    if access_grants:
        for spec in access_grants:
            folder_uid = resolve_folder_identifier(params, spec['folder_uid'])
            if not folder_uid:
                raise ValueError(f"Folder '{spec['folder_uid']}' not found")
            
            user_uid = spec['user_uid']
            role = spec.get('role', 'viewer').lower()
            
            if role not in role_map:
                raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(role_map.keys())}")
            
            # Determine if user_uid is an email or UID
            is_email = '@' in user_uid
            user_email = user_uid if is_email else None
            actual_user_uid_bytes = None
            
            if is_email:
                # Use the same logic as record sharing to get the correct account UID
                # Try to get UID from user_cache first (accountUid -> username mapping)
                if hasattr(params, 'user_cache'):
                    for account_uid_str, username in params.user_cache.items():
                        if username.lower() == user_email.lower():
                            # Found it! account_uid_str is already base64url encoded string
                            actual_user_uid_bytes = utils.base64_url_decode(account_uid_str)
                            logging.debug(f"Found UID for {user_email} in user_cache: {account_uid_str}")
                            break
                
                # Fallback: try enterprise users for the userAccountUid
                if not actual_user_uid_bytes and hasattr(params, 'enterprise') and params.enterprise:
                    for user in params.enterprise.get('users', []):
                        if user.get('username', '').lower() == user_email.lower():
                            # Try to get userAccountUid first (base64 encoded bytes)
                            if 'user_account_uid' in user:
                                actual_user_uid_bytes = utils.base64_url_decode(user['user_account_uid'])
                                logging.debug(f"Found userAccountUid for {user_email} in enterprise: {user['user_account_uid']}")
                            # Fallback to enterprise_user_id (integer) - convert to 8 bytes like record sharing
                            elif 'enterprise_user_id' in user:
                                enterprise_user_id = user['enterprise_user_id']
                                if isinstance(enterprise_user_id, int):
                                    actual_user_uid_bytes = enterprise_user_id.to_bytes(8, byteorder='big', signed=False)
                                    logging.debug(f"Converted enterprise_user_id {enterprise_user_id} to 8 bytes for {user_email}")
                            break
                
                if not actual_user_uid_bytes:
                    raise ValueError(f"User with email '{user_email}' not found in enterprise")
            else:
                # user_uid is already a UID (try to decode as base64)
                try:
                    actual_user_uid_bytes = utils.base64_url_decode(user_uid)
                    user_email = user_uid  # Use UID as fallback for email
                    
                    # Try to find the actual email from the UID
                    if hasattr(params, 'user_cache'):
                        for account_uid_str, username in params.user_cache.items():
                            if utils.base64_url_decode(account_uid_str) == actual_user_uid_bytes:
                                user_email = username
                                logging.debug(f"Found email {user_email} for UID {user_uid}")
                                break
                except:
                    raise ValueError(f"Invalid user UID format: {user_uid}")
            
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
                raise ValueError(f"Folder key not found for folder {folder_uid}")
            
            # Get user's public key from key_cache using email
            user_keys = None
            if user_email in params.key_cache:
                user_keys = params.key_cache[user_email]
            
            if not user_keys:
                # Try to load user's public key from server
                from keepercommander import api
                logging.debug(f"Loading public key for user {user_email}")
                api.load_user_public_keys(params, [user_email])
                if user_email in params.key_cache:
                    user_keys = params.key_cache[user_email]
            
            if not user_keys:
                raise ValueError(f"Public key not found for user {user_email}")
            
            # Extract the actual public key from PublicKeys object
            # For folder access, prefer RSA over ECC (API requires RSA for new user grants)
            user_public_key = None
            use_ecc = False
            if user_keys.rsa:
                user_public_key = crypto.load_rsa_public_key(user_keys.rsa)
                use_ecc = False
            elif user_keys.ec:
                user_public_key = crypto.load_ec_public_key(user_keys.ec)
                use_ecc = True
            else:
                raise ValueError(f"No valid public key (RSA or ECC) found for user {user_email}")
            
            # Encrypt folder key with user's public key
            if use_ecc:
                encrypted_folder_key = crypto.encrypt_ec(folder_key, user_public_key)
            else:
                encrypted_folder_key = crypto.encrypt_rsa(folder_key, user_public_key)
            
            # Create access data
            access_data = folder_pb2.FolderAccessData()
            access_data.folderUid = utils.base64_url_decode(folder_uid)
            
            # Set accessTypeUid - use the same format as record sharing (no padding, raw bytes)
            access_data.accessTypeUid = actual_user_uid_bytes
            access_data.accessType = folder_pb2.AT_USER
            access_data.accessRoleType = role_map[role]
            
            # Set encrypted folder key with correct type
            encrypted_key = folder_pb2.EncryptedDataKey()
            encrypted_key.encryptedKey = encrypted_folder_key
            # Set the correct key type based on encryption method used
            if use_ecc:
                encrypted_key.encryptedKeyType = folder_pb2.encrypted_by_public_key_ecc
            else:
                encrypted_key.encryptedKeyType = folder_pb2.encrypted_by_public_key
            access_data.folderKey.CopyFrom(encrypted_key)
            
            adds_list.append(access_data)
            operation_tracking.append(('grant', folder_uid, user_uid, spec))
    
    # Process updates
    if access_updates:
        for spec in access_updates:
            folder_uid = resolve_folder_identifier(params, spec['folder_uid'])
            if not folder_uid:
                raise ValueError(f"Folder '{spec['folder_uid']}' not found")
            
            user_uid = spec['user_uid']
            role = spec.get('role')
            hidden = spec.get('hidden')
            
            if role is None and hidden is None:
                raise ValueError(f"Update for {folder_uid}/{user_uid} must specify role or hidden")
            
            # Determine if user_uid is an email or UID
            is_email = '@' in user_uid
            actual_user_uid_bytes = None
            
            if is_email:
                # Use the same logic as record sharing to get the correct account UID
                if hasattr(params, 'user_cache'):
                    for account_uid_str, username in params.user_cache.items():
                        if username.lower() == user_uid.lower():
                            actual_user_uid_bytes = utils.base64_url_decode(account_uid_str)
                            logging.debug(f"Found UID for {user_uid} in user_cache: {account_uid_str}")
                            break
                
                if not actual_user_uid_bytes and hasattr(params, 'enterprise') and params.enterprise:
                    for user in params.enterprise.get('users', []):
                        if user.get('username', '').lower() == user_uid.lower():
                            if 'user_account_uid' in user:
                                actual_user_uid_bytes = utils.base64_url_decode(user['user_account_uid'])
                                logging.debug(f"Found userAccountUid for {user_uid} in enterprise: {user['user_account_uid']}")
                            elif 'enterprise_user_id' in user:
                                enterprise_user_id = user['enterprise_user_id']
                                if isinstance(enterprise_user_id, int):
                                    actual_user_uid_bytes = enterprise_user_id.to_bytes(8, byteorder='big', signed=False)
                                    logging.debug(f"Converted enterprise_user_id {enterprise_user_id} to 8 bytes for {user_uid}")
                            break
                
                if not actual_user_uid_bytes:
                    raise ValueError(f"User with email '{user_uid}' not found in enterprise")
            else:
                try:
                    actual_user_uid_bytes = utils.base64_url_decode(user_uid)
                except:
                    raise ValueError(f"Invalid user UID format: {user_uid}")
            
            access_data = folder_pb2.FolderAccessData()
            access_data.folderUid = utils.base64_url_decode(folder_uid)
            
            # Set accessTypeUid - use the same format as record sharing (no padding, raw bytes)
            access_data.accessTypeUid = actual_user_uid_bytes
            access_data.accessType = folder_pb2.AT_USER
            
            if role:
                role_lower = role.lower()
                if role_lower not in role_map:
                    raise ValueError(f"Invalid role '{role}'")
                access_data.accessRoleType = role_map[role_lower]
            
            if hidden is not None:
                access_data.hidden = hidden
            
            updates_list.append(access_data)
            operation_tracking.append(('update', folder_uid, user_uid, spec))
    
    # Process revokes
    if access_revokes:
        for spec in access_revokes:
            folder_uid = resolve_folder_identifier(params, spec['folder_uid'])
            if not folder_uid:
                raise ValueError(f"Folder '{spec['folder_uid']}' not found")
            
            user_uid = spec['user_uid']
            
            # Determine if user_uid is an email or UID
            is_email = '@' in user_uid
            actual_user_uid_bytes = None
            
            if is_email:
                # Use the same logic as record sharing to get the correct account UID
                if hasattr(params, 'user_cache'):
                    for account_uid_str, username in params.user_cache.items():
                        if username.lower() == user_uid.lower():
                            actual_user_uid_bytes = utils.base64_url_decode(account_uid_str)
                            logging.debug(f"Found UID for {user_uid} in user_cache: {account_uid_str}")
                            break
                
                if not actual_user_uid_bytes and hasattr(params, 'enterprise') and params.enterprise:
                    for user in params.enterprise.get('users', []):
                        if user.get('username', '').lower() == user_uid.lower():
                            if 'user_account_uid' in user:
                                actual_user_uid_bytes = utils.base64_url_decode(user['user_account_uid'])
                                logging.debug(f"Found userAccountUid for {user_uid} in enterprise: {user['user_account_uid']}")
                            elif 'enterprise_user_id' in user:
                                enterprise_user_id = user['enterprise_user_id']
                                if isinstance(enterprise_user_id, int):
                                    actual_user_uid_bytes = enterprise_user_id.to_bytes(8, byteorder='big', signed=False)
                                    logging.debug(f"Converted enterprise_user_id {enterprise_user_id} to 8 bytes for {user_uid}")
                            break
                
                if not actual_user_uid_bytes:
                    raise ValueError(f"User with email '{user_uid}' not found in enterprise")
            else:
                try:
                    actual_user_uid_bytes = utils.base64_url_decode(user_uid)
                except:
                    raise ValueError(f"Invalid user UID format: {user_uid}")
            
            access_data = folder_pb2.FolderAccessData()
            access_data.folderUid = utils.base64_url_decode(folder_uid)
            
            # Set accessTypeUid - use the same format as record sharing (no padding, raw bytes)
            access_data.accessTypeUid = actual_user_uid_bytes
            access_data.accessType = folder_pb2.AT_USER
            
            removes_list.append(access_data)
            operation_tracking.append(('revoke', folder_uid, user_uid, spec))
    
    # Make API call
    response = folder_access_update_v3(
        params,
        folder_access_adds=adds_list if adds_list else None,
        folder_access_updates=updates_list if updates_list else None,
        folder_access_removes=removes_list if removes_list else None
    )
    
    # Build results
    results = []
    
    # All successful operations (not in response.folderAccessResults)
    for op_type, folder_uid, user_uid, spec in operation_tracking:
        results.append({
            'operation': op_type,
            'folder_uid': folder_uid,
            'user_uid': user_uid,
            'status': 'SUCCESS',
            'message': f'{op_type.capitalize()} operation completed successfully',
            'success': True
        })
    
    # Override with failed operations from response
    if response.folderAccessResults:
        for result in response.folderAccessResults:
            folder_uid_bytes = result.folderUid
            access_uid_bytes = result.accessUid
            folder_uid = utils.base64_url_encode(folder_uid_bytes)
            user_uid = utils.base64_url_encode(access_uid_bytes) if access_uid_bytes else 'unknown'
            
            # Find and update the corresponding result
            for i, (op_type, tracked_folder, tracked_user, spec) in enumerate(operation_tracking):
                if tracked_folder == folder_uid and tracked_user == user_uid:
                    results[i] = {
                        'operation': op_type,
                        'folder_uid': folder_uid,
                        'user_uid': user_uid,
                        'status': folder_pb2.FolderModifyStatus.Name(result.status),
                        'message': result.message,
                        'success': False
                    }
                    break
    
    return results


def folder_update_v3(
    params: KeeperParams,
    folders: List[folder_pb2.FolderData]
) -> folder_pb2.FolderUpdateResponse:
    """
    Update existing folders using the KeeperDrive v3 API.
    
    This function updates one or more folders in the user's vault.
    Maximum 100 folder updates per request.
    
    Args:
        params: KeeperParams instance with session information
        folders: List of FolderData messages (max 100). Only folderUid and 
                either data or inheritUserPermissions are required.
    
    Returns:
        FolderUpdateResponse with results for each folder
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If more than 100 folders are provided
    """
    if len(folders) > 100:
        raise ValueError("Maximum 100 folders can be updated at a time")
    
    if not folders:
        raise ValueError("At least one folder must be provided")
    
    # Create request
    request = folder_pb2.FolderUpdateRequest()
    request.folderData.extend(folders)
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Updating {len(folders)} folder(s) via KeeperDrive v3 API")
        for fd in folders:
            folder_uid = utils.base64_url_encode(fd.folderUid)
            logger.debug(f"  Folder UID: {folder_uid}")
    
    # Make API call
    endpoint = 'vault/folders/v3/update'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=folder_pb2.FolderUpdateResponse
    )
    
    # Log response
    if logger.level <= logging.DEBUG:
        for result in response.folderUpdateResults:
            folder_uid = utils.base64_url_encode(result.folderUid)
            logger.debug(f"  Result for {folder_uid}: {result.status} - {result.message}")
    
    return response


def resolve_folder_identifier(params: KeeperParams, folder_identifier: str) -> Optional[str]:
    """
    Resolve a folder identifier (name, path, or UID) to a folder UID.
    
    Args:
        params: KeeperParams instance
        folder_identifier: Folder name, path, or UID
    
    Returns:
        Folder UID if found, None otherwise
    """
    # Check if it's already a UID in Keeper Drive or legacy caches
    if folder_identifier in params.keeper_drive_folders or folder_identifier in params.subfolder_cache:
        return folder_identifier
    
    # Try to resolve as folder path in folder_cache
    if folder_identifier in params.folder_cache:
        return folder_identifier
    
    # Search by name in Keeper Drive folders
    matching_folders = []
    for folder_uid, folder_obj in params.keeper_drive_folders.items():
        if folder_obj.get('name', '').lower() == folder_identifier.lower():
            matching_folders.append(folder_uid)
    
    # If exactly one match found, return it
    if len(matching_folders) == 1:
        return matching_folders[0]
    elif len(matching_folders) > 1:
        # Multiple folders with same name - ambiguous
        logging.warning(f"Multiple folders found with name '{folder_identifier}'. Please use folder UID instead.")
        logging.warning("Matching folder UIDs:")
        for uid in matching_folders:
            logging.warning(f"  - {uid}")
        return None
    
    # Try to resolve as folder path using standard resolution
    rs = try_resolve_path(params, folder_identifier)
    if rs is not None:
        folder, pattern = rs
        if folder and not pattern:
            return folder.uid
    
    return None


def update_folder_v3(
    params: KeeperParams,
    folder_uid: str,
    folder_name: Optional[str] = None,
    color: Optional[str] = None,
    inherit_permissions: Optional[bool] = None
) -> Dict[str, Any]:
    """
    High-level function to update a single folder in KeeperDrive.
    
    This is a convenience wrapper around folder_update_v3 for updating a single folder.
    At least one of folder_name, color, or inherit_permissions must be provided.
    
    Args:
        params: KeeperParams instance
        folder_uid: UID, name, or path of the folder to update
        folder_name: Optional new name for the folder
        color: Optional new color for the folder
        inherit_permissions: Optional new permission inheritance setting
    
    Returns:
        Dictionary with folder update results:
        {
            'folder_uid': str,
            'status': str,
            'message': str,
            'success': bool
        }
    
    Raises:
        KeeperApiError: If the API request fails
        ValueError: If no update fields are provided or folder not found
    """
    if folder_name is None and color is None and inherit_permissions is None:
        raise ValueError("At least one update field (name, color, or inherit_permissions) must be provided")
    
    # Resolve folder identifier to UID
    resolved_uid = resolve_folder_identifier(params, folder_uid)
    if not resolved_uid:
        raise ValueError(f"Folder '{folder_uid}' not found. Please provide a valid folder UID, name, or path.")
    
    folder_uid = resolved_uid
    
    # Get folder key from cache
    folder_key = None
    if folder_uid in params.keeper_drive_folders:
        folder_obj = params.keeper_drive_folders[folder_uid]
        if 'folder_key_unencrypted' in folder_obj:
            folder_key = folder_obj['folder_key_unencrypted']
    
    # Fallback to subfolder_cache for legacy folders
    if not folder_key and folder_uid in params.subfolder_cache:
        folder_obj = params.subfolder_cache[folder_uid]
        if 'folder_key_unencrypted' in folder_obj:
            folder_key = folder_obj['folder_key_unencrypted']
    
    if not folder_key:
        raise ValueError(f"Folder key not found for folder {folder_uid}. The folder exists but its encryption key is not available. Try running 'sync-down' first.")
    
    # Create folder data for update
    folder_data = folder_pb2.FolderData()
    folder_data.folderUid = utils.base64_url_decode(folder_uid)
    
    # Always include encrypted data to preserve existing folder properties
    # Get current folder data from cache to preserve existing values
    data_dict = {}
    folder_obj = params.keeper_drive_folders.get(folder_uid) or params.subfolder_cache.get(folder_uid)
    
    if folder_obj:
        # Preserve existing name if not updating it
        if folder_name is None:
            existing_name = folder_obj.get('name')
            if existing_name:
                data_dict['name'] = existing_name
        else:
            data_dict['name'] = folder_name
        
        # Preserve existing color if not updating it
        if color is None:
            existing_color = folder_obj.get('color')
            if existing_color and existing_color != 'none':
                data_dict['color'] = existing_color
        else:
            if color != 'none' and color != '':
                data_dict['color'] = color
            # If color is 'none' or empty, don't include it (removes color)
    else:
        # Fallback if folder not in cache - just use provided values
        if folder_name is not None:
            data_dict['name'] = folder_name
        if color is not None and color != 'none' and color != '':
            data_dict['color'] = color
    
    # Always encrypt and send folder data to preserve all properties
    data_json = json.dumps(data_dict).encode('utf-8')
    folder_data.data = crypto.encrypt_aes_v2(data_json, folder_key)
    
    # Update inherit permissions if specified
    if inherit_permissions is not None:
        folder_data.inheritUserPermissions = (
            SetBooleanValue.BOOLEAN_TRUE if inherit_permissions 
            else SetBooleanValue.BOOLEAN_FALSE
        )
    
    # Make API call
    response = folder_update_v3(params, [folder_data])
    
    # Parse response
    if response.folderUpdateResults:
        result = response.folderUpdateResults[0]
        return {
            'folder_uid': folder_uid,
            'status': folder_pb2.FolderModifyStatus.Name(result.status),
            'message': result.message,
            'success': result.status == folder_pb2.SUCCESS
        }
    else:
        raise KeeperApiError('no_results', 'No results returned from folder update')


def update_folders_batch_v3(
    params: KeeperParams,
    folder_updates: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Update multiple folders in a single API call.
    
    Args:
        params: KeeperParams instance
        folder_updates: List of folder update specifications, each containing:
            - folder_uid: str (required)
            - name: str (optional)
            - color: str (optional)
            - inherit_permissions: bool (optional)
    
    Returns:
        List of result dictionaries for each folder
    
    Example:
        results = update_folders_batch_v3(params, [
            {'folder_uid': 'xxx', 'name': 'New Projects', 'color': 'green'},
            {'folder_uid': 'yyy', 'inherit_permissions': False}
        ])
    """
    if len(folder_updates) > 100:
        raise ValueError("Maximum 100 folders can be updated at a time")
    
    folder_data_list = []
    
    for idx, update_spec in enumerate(folder_updates):
        folder_identifier = update_spec.get('folder_uid')
        if not folder_identifier:
            raise ValueError(f"Folder update specification at index {idx} missing 'folder_uid'")
        
        folder_name = update_spec.get('name')
        color = update_spec.get('color')
        inherit_permissions = update_spec.get('inherit_permissions')
        
        # Verify at least one field to update
        if folder_name is None and color is None and inherit_permissions is None:
            raise ValueError(f"Folder update at index {idx} must specify at least one field to update")
        
        # Resolve folder identifier to UID
        folder_uid = resolve_folder_identifier(params, folder_identifier)
        if not folder_uid:
            raise ValueError(f"Folder '{folder_identifier}' at index {idx} not found")
        
        # Get folder key from cache
        folder_key = None
        if folder_uid in params.keeper_drive_folders:
            folder_obj = params.keeper_drive_folders[folder_uid]
            if 'folder_key_unencrypted' in folder_obj:
                folder_key = folder_obj['folder_key_unencrypted']
        
        # Fallback to subfolder_cache
        if not folder_key and folder_uid in params.subfolder_cache:
            folder_obj = params.subfolder_cache[folder_uid]
            if 'folder_key_unencrypted' in folder_obj:
                folder_key = folder_obj['folder_key_unencrypted']
        
        if not folder_key:
            raise ValueError(f"Folder key not found for folder {folder_uid}. Try running 'sync-down' first.")
        
        # Create folder data
        folder_data = folder_pb2.FolderData()
        folder_data.folderUid = utils.base64_url_decode(folder_uid)
        
        # Always include encrypted data to preserve existing folder properties
        # Get current folder data from cache to preserve existing values
        data_dict = {}
        folder_obj = params.keeper_drive_folders.get(folder_uid) or params.subfolder_cache.get(folder_uid)
        
        if folder_obj:
            # Preserve existing name if not updating it
            if folder_name is None:
                existing_name = folder_obj.get('name')
                if existing_name:
                    data_dict['name'] = existing_name
            else:
                data_dict['name'] = folder_name
            
            # Preserve existing color if not updating it
            if color is None:
                existing_color = folder_obj.get('color')
                if existing_color and existing_color != 'none':
                    data_dict['color'] = existing_color
            else:
                if color != 'none' and color != '':
                    data_dict['color'] = color
                # If color is 'none' or empty, don't include it (removes color)
        else:
            # Fallback if folder not in cache - just use provided values
            if folder_name is not None:
                data_dict['name'] = folder_name
            if color is not None and color not in ('none', ''):
                data_dict['color'] = color
        
        # Always encrypt and send folder data to preserve all properties
        data_json = json.dumps(data_dict).encode('utf-8')
        folder_data.data = crypto.encrypt_aes_v2(data_json, folder_key)
        
        # Update inherit permissions
        if inherit_permissions is not None:
            folder_data.inheritUserPermissions = (
                SetBooleanValue.BOOLEAN_TRUE if inherit_permissions 
                else SetBooleanValue.BOOLEAN_FALSE
            )
        
        folder_data_list.append(folder_data)
    
    # Make API call
    response = folder_update_v3(params, folder_data_list)
    
    # Parse results
    results = []
    for idx, result in enumerate(response.folderUpdateResults):
        folder_uid = folder_updates[idx].get('folder_uid')
        results.append({
            'folder_uid': folder_uid,
            'status': folder_pb2.FolderModifyStatus.Name(result.status),
            'message': result.message,
            'success': result.status == folder_pb2.SUCCESS
        })
    
    return results


def get_folder_access_v3(
    params: KeeperParams,
    folder_uids: List[str],
    continuation_token: Optional[int] = None,
    page_size: Optional[int] = None
) -> Dict[str, Any]:
    """
    Retrieve accessors of Keeper Drive folders with pagination support.
    
    This function retrieves users and teams that have access to the specified folders
    using the v3 API endpoint with cursor-based pagination.
    
    Args:
        params: KeeperParams instance with session information
        folder_uids: List of folder UIDs to query (max: 100)
        continuation_token: Last modified timestamp for pagination (optional)
        page_size: Maximum number of accessors to return per page (default: 100, max: 1000)
    
    Returns:
        Dictionary containing:
            - results: List of folder access results (each containing folder_uid, accessors, or error)
            - continuation_token: Token for next page (if hasMore is true)
            - has_more: Boolean indicating if more results exist
    
    Raises:
        ValueError: If more than 100 folder UIDs are provided
        KeeperApiError: If the API request fails
    
    Example:
        result = get_folder_access_v3(
            params,
            folder_uids=['xxx', 'yyy'],
            page_size=50
        )
        
        # Access first folder's accessors
        for accessor in result['results'][0]['accessors']:
            print(f"User: {accessor['user_uid']}, Role: {accessor['role']}")
        
        # Pagination
        if result['has_more']:
            next_page = get_folder_access_v3(
                params,
                folder_uids=['xxx', 'yyy'],
                continuation_token=result['continuation_token'],
                page_size=50
            )
    """
    if len(folder_uids) > 100:
        raise ValueError("Maximum 100 folder UIDs can be queried at a time")
    
    if not folder_uids:
        raise ValueError("At least one folder UID must be provided")
    
    # Import the protobuf module for folder access
    from .proto import folder_access_pb2
    
    # Create the request
    request = folder_access_pb2.GetFolderAccessRequest()
    
    # Add folder UIDs
    for folder_identifier in folder_uids:
        # Resolve folder identifier to UID
        folder_uid = resolve_folder_identifier(params, folder_identifier)
        if not folder_uid:
            raise ValueError(f"Folder '{folder_identifier}' not found")
        request.folderUid.append(utils.base64_url_decode(folder_uid))
    
    # Add continuation token if provided
    if continuation_token is not None:
        token = folder_access_pb2.ContinuationToken()
        token.lastModified = continuation_token
        request.continuationToken.CopyFrom(token)
    
    # Add page size if provided
    if page_size is not None:
        if page_size > 1000:
            raise ValueError("Maximum page size is 1000")
        request.pageSize = page_size
    
    # Log request
    if logger.level <= logging.DEBUG:
        logger.debug(f"Retrieving folder access for {len(folder_uids)} folder(s)")
        for uid in folder_uids:
            logger.debug(f"  Folder UID: {uid}")
    
    # Make API call
    endpoint = 'vault/folders/v3/access'
    response = api.communicate_rest(
        params,
        request,
        endpoint,
        rs_type=folder_access_pb2.GetFolderAccessResponse
    )
    
    # Parse response
    results = []
    
    for folder_result in response.folderAccessResults:
        folder_uid = utils.base64_url_encode(folder_result.folderUid)
        
        if folder_result.HasField('error'):
            # Error case
            error = folder_result.error
            status_name = folder_pb2.FolderModifyStatus.Name(error.status)
            results.append({
                'folder_uid': folder_uid,
                'error': {
                    'status': status_name,
                    'message': error.message
                },
                'success': False
            })
        else:
            # Success case - parse accessors
            accessors = []
            for accessor in folder_result.accessors:
                accessor_uid = utils.base64_url_encode(accessor.accessTypeUid)
                access_type = folder_pb2.AccessType.Name(accessor.accessType)
                role_type = folder_pb2.AccessRoleType.Name(accessor.accessRoleType)
                
                username = None
                if access_type == 'AT_USER':
                    # Try cache first
                    if hasattr(params, 'user_cache') and params.user_cache:
                        username = params.user_cache.get(accessor_uid)
                    # Fallback to enterprise users
                    if not username and hasattr(params, 'enterprise') and params.enterprise:
                        for user in params.enterprise.get('users', []):
                            if user.get('user_account_uid') == accessor_uid:
                                username = user.get('username')
                                break
                
                accessor_info = {
                    'accessor_uid': accessor_uid,
                    'access_type': access_type,
                    'role': role_type,
                    'inherited': bool(accessor.inherited),
                    'hidden': bool(accessor.hidden),
                    'username': username,
                    'date_created': accessor.dateCreated or None,
                    'last_modified': accessor.lastModified or None
                }
                
                # Add permissions if available
                if accessor.HasField('permissions'):
                    perms = accessor.permissions
                    accessor_info['permissions'] = {
                        'can_add_users': bool(perms.canAddUsers),
                        'can_remove_users': bool(perms.canRemoveUsers),
                        'can_add_records': bool(perms.canAddRecords),
                        'can_remove_records': bool(perms.canRemoveRecords),
                        'can_delete_records': bool(perms.canDeleteRecords),
                        'can_create_folders': bool(perms.canCreateFolders),
                        'can_delete_folders': bool(perms.canDeleteFolders),
                        'can_change_user_permissions': bool(perms.canChangeUserPermissions),
                        'can_edit_records': bool(perms.canEditRecords),
                        'can_view_records': bool(perms.canViewRecords),
                    }
                
                accessors.append(accessor_info)
            
            results.append({
                'folder_uid': folder_uid,
                'accessors': accessors,
                'success': True
            })
    
    # Build response dictionary
    response_dict = {
        'results': results,
        'has_more': bool(response.hasMore)
    }
    
    # Add continuation token if available
    if response.HasField('continuationToken'):
        response_dict['continuation_token'] = response.continuationToken.lastModified
    
    # Log response
    if logger.level <= logging.DEBUG:
        logger.debug(f"Retrieved access info for {len(results)} folder(s)")
        logger.debug(f"  Has more: {response_dict['has_more']}")
    
    return response_dict
