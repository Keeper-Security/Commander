"""
Manage Keeper AI and JIT settings from DAG DATA edge for a PAM resource.

This module provides functionality to retrieve and parse Keeper AI
and JIT risk level settings (Critical/High/Medium/Low with Monitor/Terminate actions)
from the DAG DATA edges with path 'ai_settings' and 'jit_settings' on a resource vertex.
"""

import base64
import json
import logging
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ...params import KeeperParams
from ...keeper_dag import DAG, EdgeType
from ...keeper_dag.connection.commander import Connection
from ...keeper_dag.types import PamEndpoints
from ...vault import PasswordRecord
from ... import vault
from ...display import bcolors
from ..tunnel.port_forward.tunnel_helpers import get_config_uid, generate_random_bytes, get_keeper_tokens


def list_resource_data_edges(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    List all DATA edges on a resource vertex to inspect available paths.

    This is useful for discovering what settings are stored in the DAG,
    such as 'ai_settings', 'jit_settings', etc.

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        List of dictionaries containing edge information:
        [{"path": "ai_settings", "version": 0, "active": True, "is_encrypted": True}, ...]
    """
    try:
        # Get the record to access the record key
        record = vault.KeeperRecord.load(params, resource_uid)
        if not record:
            logging.warning(f"Record {resource_uid} not found")
            return []

        # Get record key for decryption
        record_key = None
        if resource_uid in params.record_cache:
            record_data = params.record_cache[resource_uid]
            record_key = record_data.get('record_key_unencrypted')

        if not record_key:
            logging.warning(f"Record key not available for {resource_uid}")
            return []

        # Get config UID if not provided
        if not config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
            if not config_uid:
                config_uid = resource_uid

        # Create DAG connection
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        # Create a dummy record for DAG
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key  # Use record key to decrypt keychain

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_write_protobuf=True
        )

        # Load the DAG
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=0,
            write_endpoint=PamEndpoints.PAM
        )
        linking_dag.load()

        # Get the resource vertex
        resource_vertex = linking_dag.get_vertex(resource_uid)
        if not resource_vertex:
            logging.warning(f"Resource vertex {resource_uid} not found in DAG")
            return []

        # Collect all DATA edges
        data_edges = []
        for edge in resource_vertex.edges:
            if edge and edge.edge_type == EdgeType.DATA:
                data_edges.append({
                    "path": edge.path,
                    "version": edge.version,
                    "active": edge.active,
                    "is_encrypted": edge.is_encrypted,
                    "has_content": edge.content is not None
                })

        return data_edges

    except Exception as e:
        logging.error(f"Error listing DATA edges for {resource_uid}: {e}", exc_info=True)
        return []


def get_resource_settings(
    params: KeeperParams,
    resource_uid: str,
    dag_path: str,
    config_uid: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Generic function to retrieve settings from a DAG DATA edge with the specified path for a resource.

    The settings are stored as encrypted JSON in a DATA edge on the resource vertex
    with the specified path. This function:
    1. Loads the DAG for the resource
    2. Finds the DATA edge with the specified path
    3. Decrypts the content using the record key
    4. Parses the JSON to return the settings structure

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, etc.)
        dag_path: Path of the DATA edge (e.g., 'ai_settings', 'jit_settings')
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        Dictionary containing settings if found, None otherwise.
    """
    try:
        # Get the record to access the record key
        record = vault.KeeperRecord.load(params, resource_uid)
        if not record:
            logging.warning(f"Record {resource_uid} not found")
            return None

        # Get record key for decryption
        record_key = None
        if resource_uid in params.record_cache:
            record_data = params.record_cache[resource_uid]
            record_key = record_data.get('record_key_unencrypted')

        if not record_key:
            logging.warning(f"Record key not available for {resource_uid}")
            return None

        # Get config UID if not provided
        if not config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
            if not config_uid:
                config_uid = resource_uid

        # Create DAG connection
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        # Create a dummy record for DAG (uses config UID as record UID)
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key  # Use record key to decrypt keychain

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_write_protobuf=True
        )

        # Load the DAG
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=0,
            write_endpoint=PamEndpoints.PAM
        )
        linking_dag.load()

        # Get the resource vertex
        resource_vertex = linking_dag.get_vertex(resource_uid)
        if not resource_vertex:
            logging.warning(f"Resource vertex {resource_uid} not found in DAG")
            return None

        # Find the DATA edge with the specified path (get highest version, regardless of active status)
        settings_edge = None
        highest_version = -1
        for edge in resource_vertex.edges:
            if edge and (edge.edge_type == EdgeType.DATA and
                         edge.path == dag_path):
                if edge.version > highest_version:
                    highest_version = edge.version
                    settings_edge = edge

        if not settings_edge:
            logging.debug(f"No '{dag_path}' DATA edge found for resource {resource_uid}")
            return None

        # Get the content from the edge
        edge_content = settings_edge.content
        if not edge_content:
            logging.debug(f"'{dag_path}' edge has no content for resource {resource_uid}")
            return None

        # Check if content appears to be encrypted (binary data that's not valid UTF-8)
        # Even if is_encrypted is False, inactive edges might not have been decrypted
        is_encrypted_content = settings_edge.is_encrypted
        if not is_encrypted_content and isinstance(edge_content, bytes):
            # Try to detect if it's encrypted by attempting to decode
            # Encrypted content will fail UTF-8 decoding
            try:
                test_decode = edge_content.decode('utf-8')
                # If decode succeeds, check if it looks like JSON (starts with { or [)
                if not (test_decode.strip().startswith('{') or test_decode.strip().startswith('[')):
                    # Doesn't look like JSON, might be encrypted
                    is_encrypted_content = True
            except (UnicodeDecodeError, AttributeError):
                # Decode failed - likely encrypted binary data
                is_encrypted_content = True

        # Check if edge is still encrypted
        if is_encrypted_content:
            # Content is encrypted - need to decrypt manually using record key
            if not isinstance(edge_content, (bytes, str)):
                logging.warning(f"Unexpected encrypted content type: {type(edge_content)}")
                return None

            # Convert to bytes if it's a string (base64 encoded)
            if isinstance(edge_content, str):
                try:
                    edge_content = base64.urlsafe_b64decode(edge_content + '==')
                except Exception as e:
                    logging.warning(f"Failed to decode base64 content: {e}")
                    return None

            # Decrypt using AES-GCM
            try:
                if len(edge_content) < 12:
                    logging.warning(f"Encrypted content too short: {len(edge_content)} bytes")
                    return None

                aesgcm = AESGCM(record_key)
                nonce = edge_content[:12]
                ciphertext = edge_content[12:]
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                logging.warning(f"Failed to decrypt {dag_path} content: {e}")
                return None

            # Parse JSON
            try:
                settings = json.loads(decrypted_bytes.decode('utf-8'))
                return settings
            except Exception as e:
                logging.warning(f"Failed to parse {dag_path} JSON: {e}")
                return None
        else:
            # Content is already decrypted by DAG
            if isinstance(edge_content, dict):
                return edge_content

            if isinstance(edge_content, str):
                try:
                    return json.loads(edge_content)
                except Exception as e:
                    logging.warning(f"Failed to parse already-decrypted content: {e}")
                    return None

            if isinstance(edge_content, bytes):
                # Try to decode as UTF-8 JSON
                try:
                    decoded_str = edge_content.decode('utf-8')
                    return json.loads(decoded_str)
                except UnicodeDecodeError:
                    # If UTF-8 decode fails, it might still be encrypted
                    # Try decrypting it
                    try:
                        if len(edge_content) >= 12:
                            aesgcm = AESGCM(record_key)
                            nonce = edge_content[:12]
                            ciphertext = edge_content[12:]
                            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                            return json.loads(decrypted_bytes.decode('utf-8'))
                    except Exception as decrypt_error:
                        logging.warning(f"Content appears encrypted but decryption failed: {decrypt_error}")
                    return None
                except Exception as e:
                    logging.warning(f"Failed to decode bytes content: {e}")
                    return None

            logging.warning(f"Unexpected decrypted content type: {type(edge_content)}")
            return None

    except Exception as e:
        logging.error(f"Error retrieving {dag_path} settings for {resource_uid}: {e}", exc_info=True)
        return None


def get_resource_jit_settings(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Retrieve JIT settings from the DAG DATA edge with path 'jit_settings' for a resource.

    This function checks if JIT settings are stored in a DAG DATA edge similar to AI settings.
    The settings are expected to be stored as encrypted JSON in a DATA edge on the resource vertex
    with path 'jit_settings'.

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, etc.)
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        Dictionary containing JIT settings if found, None otherwise.
    """
    return get_resource_settings(params, resource_uid, 'jit_settings', config_uid)


def get_resource_keeper_ai_settings(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Retrieve KeeperAI settings from the DAG DATA edge with path 'ai_settings' for a resource.

    The settings are stored as encrypted JSON in a DATA edge on the resource vertex
    with path 'ai_settings'. This function:
    1. Loads the DAG for the resource
    2. Finds the DATA edge with path 'ai_settings'
    3. Decrypts the content using the record key
    4. Parses the JSON to return the KeeperAISettings structure

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, etc.)
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        Dictionary containing KeeperAI settings with structure:
        {
            "version": "v1.0.0",
            "riskLevels": {
                "critical": {
                    "aiSessionTerminate": bool,
                    "tags": {
                        "allow": [...],
                        "deny": [...]
                    }
                },
                "high": {...},
                "medium": {...},
                "low": {
                    "aiSessionTerminate": bool,
                    "tags": {
                        "allow": [...]
                    }
                }
            }
        }
        Returns None if settings not found or error occurred.
    """
    return get_resource_settings(params, resource_uid, 'ai_settings', config_uid)


def set_resource_keeper_ai_settings(
    params: KeeperParams,
    resource_uid: str,
    settings: Dict[str, Any],
    config_uid: Optional[str] = None
) -> bool:
    """
    Save KeeperAI settings to the DAG DATA edge with path 'ai_settings' for a resource.

    The settings are stored as encrypted JSON in a DATA edge on the resource vertex
    with path 'ai_settings'. This function:
    1. Loads the DAG for the resource
    2. Finds and deactivates any existing 'ai_settings' DATA edge
    3. Adds a new DATA edge with the provided settings
    4. Encrypts the content using the record key
    5. Saves the DAG

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, etc.)
        settings: Dictionary containing KeeperAI settings to save
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        True if settings were saved successfully, False otherwise.
    """
    try:
        # Get the record to access the record key
        record = vault.KeeperRecord.load(params, resource_uid)
        if not record:
            logging.warning(f"Record {resource_uid} not found")
            return False

        # Get record key for encryption
        record_key = None
        if resource_uid in params.record_cache:
            record_data = params.record_cache[resource_uid]
            record_key = record_data.get('record_key_unencrypted')

        if not record_key:
            logging.warning(f"Record key not available for {resource_uid}")
            return False

        # Validate settings structure
        if not isinstance(settings, dict):
            logging.warning("Settings must be a dictionary")
            return False

        # Get config UID if not provided
        if not config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
            if not config_uid:
                config_uid = resource_uid

        # Create DAG connection
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        # Create a dummy record for DAG (uses config UID as record UID)
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key  # Use actual record key for encryption

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_write_protobuf=True
        )

        # Load the DAG with decryption enabled
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=0,
            write_endpoint=PamEndpoints.PAM,
            decrypt=True  # Enable decryption so we can encrypt on save
        )
        linking_dag.load()

        # Get the resource vertex
        resource_vertex = linking_dag.get_vertex(resource_uid)
        if not resource_vertex:
            logging.warning(f"Resource vertex {resource_uid} not found in DAG")
            return False

        # Ensure the vertex keychain has the record key for encryption
        # The DAG save will use vertex.key (first key in keychain) to encrypt DATA edges
        if not resource_vertex.keychain or len(resource_vertex.keychain) == 0:
            resource_vertex.keychain = [record_key]
        else:
            # Ensure record key is in keychain (prepend it so it's the first/primary key)
            keychain = resource_vertex.keychain
            if record_key not in keychain:
                keychain.insert(0, record_key)
                resource_vertex.keychain = keychain

        # Ensure there is a KEY edge so DATA edges can be added/encrypted.
        # Prefer existing parent vertices; fall back to root if none exist.
        if not resource_vertex.has_key:
            parent_vertices = resource_vertex.belongs_to_vertices()
            if parent_vertices:
                resource_vertex.belongs_to(parent_vertices[0], edge_type=EdgeType.KEY)
            else:
                resource_vertex.belongs_to_root(EdgeType.KEY)
            logging.debug(f"Added KEY edge for resource {resource_uid} to enable DATA encryption")

        # Find and deactivate existing 'ai_settings' edge for proper versioning
        existing_edge = None
        for edge in resource_vertex.edges:
            if edge and (edge.edge_type == EdgeType.DATA and
                         edge.path == 'ai_settings' and
                         edge.active):
                existing_edge = edge
                break

        if existing_edge:
            # Deactivate the existing edge
            existing_edge.active = False
            logging.debug(f"Deactivated existing 'ai_settings' edge (version {existing_edge.version})")

        # Add new DATA edge with the settings
        # The DAG will automatically encrypt it on save using vertex.key (record key)
        resource_vertex.add_data(
            content=settings,  # Will be serialized to JSON and encrypted on save
            path='ai_settings',
            needs_encryption=True,
            modified=True
        )

        # Save the DAG
        linking_dag.save()

        logging.debug(f"Successfully saved KeeperAI settings for resource {resource_uid}")
        return True

    except Exception as e:
        logging.error(f"Error saving KeeperAI settings for {resource_uid}: {e}", exc_info=True)
        return False


def set_resource_jit_settings(
    params: KeeperParams,
    resource_uid: str,
    settings: Dict[str, Any],
    config_uid: Optional[str] = None
) -> bool:
    """
    Save JIT settings to the DAG DATA edge with path 'jit_settings' for a resource.

    The settings are stored as encrypted JSON in a DATA edge on the resource vertex
    with path 'jit_settings'. This function:
    1. Loads the DAG for the resource
    2. Finds and deactivates any existing 'jit_settings' DATA edge
    3. Adds a new DATA edge with the provided settings
    4. Encrypts the content using the record key
    5. Saves the DAG

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, pamDirectory)
        settings: Dictionary containing JIT settings to save
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        True if settings were saved successfully, False otherwise.
    """
    try:
        # Return False if settings dict is empty
        if not settings or not isinstance(settings, dict):
            logging.debug(f"JIT settings empty or invalid for {resource_uid}, skipping")
            return False

        # Get the record to access the record key
        record = vault.KeeperRecord.load(params, resource_uid)
        if not record:
            logging.warning(f"Record {resource_uid} not found")
            return False

        # Get record key for encryption
        record_key = None
        if resource_uid in params.record_cache:
            record_data = params.record_cache[resource_uid]
            record_key = record_data.get('record_key_unencrypted')

        if not record_key:
            logging.warning(f"Record key not available for {resource_uid}")
            return False

        # Get config UID if not provided
        if not config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
            if not config_uid:
                config_uid = resource_uid

        # Create DAG connection
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        # Create a dummy record for DAG (uses config UID as record UID)
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key  # Use actual record key for encryption

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_write_protobuf=True
        )

        # Load the DAG with decryption enabled
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=0,
            write_endpoint=PamEndpoints.PAM,
            decrypt=True  # Enable decryption so we can encrypt on save
        )
        linking_dag.load()

        # Get the resource vertex
        resource_vertex = linking_dag.get_vertex(resource_uid)
        if not resource_vertex:
            logging.warning(f"Resource vertex {resource_uid} not found in DAG")
            return False

        # Ensure the vertex keychain has the record key for encryption
        # The DAG save will use vertex.key (first key in keychain) to encrypt DATA edges
        if not resource_vertex.keychain or len(resource_vertex.keychain) == 0:
            resource_vertex.keychain = [record_key]
        else:
            # Ensure record key is in keychain (prepend it so it's the first/primary key)
            keychain = resource_vertex.keychain
            if record_key not in keychain:
                keychain.insert(0, record_key)
                resource_vertex.keychain = keychain

        # Ensure there is a KEY edge so DATA edges can be added/encrypted.
        # Prefer existing parent vertices; fall back to root if none exist.
        if not resource_vertex.has_key:
            parent_vertices = resource_vertex.belongs_to_vertices()
            if parent_vertices:
                resource_vertex.belongs_to(parent_vertices[0], edge_type=EdgeType.KEY)
            else:
                resource_vertex.belongs_to_root(EdgeType.KEY)
            logging.debug(f"Added KEY edge for resource {resource_uid} to enable DATA encryption")

        # Find and deactivate existing 'jit_settings' edge for proper versioning
        existing_edge = None
        for edge in resource_vertex.edges:
            if edge and (edge.edge_type == EdgeType.DATA and
                         edge.path == 'jit_settings' and
                         edge.active):
                existing_edge = edge
                break

        if existing_edge:
            # Deactivate the existing edge
            existing_edge.active = False
            logging.debug(f"Deactivated existing 'jit_settings' edge (version {existing_edge.version})")

        # Add new DATA edge with the settings
        # The DAG will automatically encrypt it on save using vertex.key (record key)
        resource_vertex.add_data(
            content=settings,  # Will be serialized to JSON and encrypted on save
            path='jit_settings',
            needs_encryption=True,
            modified=True
        )

        # Save the DAG
        linking_dag.save()

        logging.debug(f"Successfully saved JIT settings for resource {resource_uid}")
        return True

    except Exception as e:
        logging.error(f"Error saving JIT settings for {resource_uid}: {e}", exc_info=True)
        return False


def refresh_meta_to_latest(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> bool:
    """
    Re-add the meta DATA edge with the same content so meta becomes the latest
    (highest version) and appears on top. Call after writing jit_settings and/or
    ai_settings.
    """
    try:
        record = vault.KeeperRecord.load(params, resource_uid)
        if not record:
            return False
        record_key = None
        if resource_uid in params.record_cache:
            record_data = params.record_cache[resource_uid]
            record_key = record_data.get('record_key_unencrypted')
        if not record_key:
            return False
        if not config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
            if not config_uid:
                config_uid = resource_uid
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key
        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_write_protobuf=True
        )
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=0,
            write_endpoint=PamEndpoints.PAM,
            decrypt=True
        )
        linking_dag.load()
        resource_vertex = linking_dag.get_vertex(resource_uid)
        if not resource_vertex:
            return False
        meta_edges = [e for e in (resource_vertex.edges or [])
                     if e and getattr(e, 'edge_type', None) == EdgeType.DATA
                     and getattr(e, 'path', None) == 'meta']
        if not meta_edges:
            return False
        best = max(meta_edges, key=lambda e: getattr(e, 'version', -1))
        try:
            content = best.content_as_dict
        except Exception:
            return False
        if content is None:
            return False
        resource_vertex.add_data(content=content, path='meta', needs_encryption=False)
        linking_dag.save()
        return True
    except Exception as e:
        logging.debug(f"refresh_meta_to_latest for {resource_uid}: {e}")
        return False


def refresh_link_to_config_to_latest(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> bool:
    """
    Dummy update to the LINK edge (resource -> PAM config) so LINK is the latest
    edge to config, not KEY. JIT/AI add a KEY edge for encryption; in a normal
    record the visible link to PAM config is LINK with path empty and content {}.
    Call after writing jit_settings and/or ai_settings.
    """
    try:
        record = vault.KeeperRecord.load(params, resource_uid)
        if not record:
            return False
        record_key = None
        if resource_uid in params.record_cache:
            record_data = params.record_cache[resource_uid]
            record_key = record_data.get('record_key_unencrypted')
        if not record_key:
            return False
        if not config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
            if not config_uid:
                config_uid = resource_uid
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key
        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_write_protobuf=True
        )
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=0,
            write_endpoint=PamEndpoints.PAM,
            decrypt=True
        )
        linking_dag.load()
        resource_vertex = linking_dag.get_vertex(resource_uid)
        config_vertex = linking_dag.get_vertex(config_uid)
        if not resource_vertex or not config_vertex:
            return False
        # Re-add LINK (path empty, content {}) so it becomes latest, above KEY added by JIT/AI
        resource_vertex.belongs_to(config_vertex, EdgeType.LINK, path=None, content={})
        linking_dag.save()
        return True
    except Exception as e:
        logging.debug(f"refresh_link_to_config_to_latest for {resource_uid}: {e}")
        return False


def print_keeper_ai_settings(params: KeeperParams, resource_uid: str, config_uid: Optional[str] = None):
    """
    Print KeeperAI settings in a human-readable format.

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource
        config_uid: Optional PAM config UID
    """
    settings = get_resource_keeper_ai_settings(params, resource_uid, config_uid)

    if not settings:
        print(f"{bcolors.WARNING}No KeeperAI settings found for resource {resource_uid}{bcolors.ENDC}")
        return

    print(f"\n{bcolors.OKBLUE}KeeperAI Settings for Resource: {resource_uid}{bcolors.ENDC}")
    print(f"Version: {settings.get('version', 'unknown')}")
    print(f"\n{bcolors.OKGREEN}Risk Level Configurations:{bcolors.ENDC}")

    risk_levels = settings.get('riskLevels', {})
    risk_level_order = ['critical', 'high', 'medium', 'low']

    for level in risk_level_order:
        level_data = risk_levels.get(level)
        if not level_data:
            continue

        terminate = level_data.get('aiSessionTerminate', False)
        tags = level_data.get('tags', {})
        allow_tags = tags.get('allow', [])
        deny_tags = tags.get('deny', []) if level != 'low' else []

        level_color = {
            'critical': bcolors.FAIL,
            'high': bcolors.WARNING,
            'medium': bcolors.OKBLUE,
            'low': bcolors.OKGREEN
        }.get(level, bcolors.ENDC)

        print(f"\n  {level_color}{level.upper()}{bcolors.ENDC}:")
        print(f"    Terminate Session: {bcolors.OKGREEN if terminate else bcolors.WARNING}{terminate}{bcolors.ENDC}")

        if allow_tags:
            print(f"    Allow Tags ({len(allow_tags)}):")
            for tag_item in allow_tags:
                tag_name = tag_item.get('tag', '') if isinstance(tag_item, dict) else str(tag_item)
                print(f"      - {tag_name}")

        if deny_tags:
            print(f"    Deny Tags ({len(deny_tags)}):")
            for tag_item in deny_tags:
                tag_name = tag_item.get('tag', '') if isinstance(tag_item, dict) else str(tag_item)
                print(f"      - {tag_name}")

    print()
