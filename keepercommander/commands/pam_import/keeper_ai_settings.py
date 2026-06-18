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
from ...keeper_dag.exceptions import DAGPathException
from ...keeper_dag.connection.commander import Connection
from ...keeper_dag.types import PamGraphId
from ...vault import PasswordRecord
from ... import vault
from ...display import bcolors
from ...proto import pam_pb2
from ... import utils
from ..pam._layer_b import should_fallback_on_layer_b_error, is_layer_b_feature_disabled
from ..tunnel.port_forward.tunnel_helpers import get_config_uid, get_keeper_tokens
from ...keeper_dag.crypto import encrypt_aes
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

AI_RISK_LEVELS = ('critical', 'high', 'medium', 'low')
AI_SETTINGS_VERSION = 'v1.0.0'


def empty_keeper_ai_settings_dict() -> Dict[str, Any]:
    """Vault-compatible default KeeperAI settings (``emptyKeeperAISettings`` in dag-pam-link.ts)."""
    empty_allow_deny = {'allow': [], 'deny': []}
    return {
        'version': AI_SETTINGS_VERSION,
        'riskLevels': {
            'critical': {'aiSessionTerminate': False, 'tags': dict(empty_allow_deny)},
            'high': {'aiSessionTerminate': False, 'tags': dict(empty_allow_deny)},
            'medium': {'aiSessionTerminate': False, 'tags': dict(empty_allow_deny)},
            'low': {'aiSessionTerminate': False, 'tags': {'allow': []}},
        },
    }


def is_default_keeper_ai_settings(settings: Optional[Dict[str, Any]]) -> bool:
    """True when settings are absent or match the vault empty/default template."""
    if not settings:
        return True
    risk_levels = settings.get('riskLevels')
    if not isinstance(risk_levels, dict) or not risk_levels:
        return True
    for level, level_data in risk_levels.items():
        if not isinstance(level_data, dict):
            return False
        if level_data.get('aiSessionTerminate', False):
            return False
        tags = level_data.get('tags')
        if not isinstance(tags, dict):
            continue
        if tags.get('allow'):
            return False
        if level != 'low' and tags.get('deny'):
            return False
    return True


def _find_highest_path_edge(vertex, head_uid: str, dag_path: str):
    """Return the highest-version edge for a self-loop DATA path (any edge type)."""
    best = None
    best_version = -1
    for edge in vertex.edges or []:
        if not edge or edge.head_uid != head_uid or edge.path != dag_path:
            continue
        if edge.version > best_version:
            best_version = edge.version
            best = edge
    return best


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
            use_read_protobuf=False,
            use_write_protobuf=False
        )

        # Load the DAG
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value
        )
        try:
            linking_dag.load()
        except DAGPathException as e:
            logging.debug(f"Skipping DATA edge listing for {resource_uid}: ambiguous DAG path ({e})")
            return []

        # Get the resource vertex
        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
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
    config_uid: Optional[str] = None,
    quiet_if_missing_vertex: bool = False,
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
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, pamDirectory, pamRemoteBrowser)
        dag_path: Path of the DATA edge (e.g., 'ai_settings', 'jit_settings')
        config_uid: Optional PAM config UID. If not provided, will be looked up.
        quiet_if_missing_vertex: Log at debug instead of warning when the resource
            vertex is absent (expected before first link to a PAM Configuration).

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
            use_read_protobuf=False,
            use_write_protobuf=False
        )

        # Load the DAG
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value
        )
        try:
            linking_dag.load()
        except DAGPathException as e:
            # The graph has duplicate/ambiguous vertices for this path. Treat it
            # as "no settings available" rather than aborting the caller (e.g.
            # pam launch); there is nothing we can read for this resource.
            logging.debug(f"Skipping {dag_path} for {resource_uid}: ambiguous DAG path ({e})")
            return None

        # Get the resource vertex
        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
        if not resource_vertex:
            log = logging.debug if quiet_if_missing_vertex else logging.warning
            log(f"Resource vertex {resource_uid} not found in DAG")
            return None

        # Highest-version edge for this path; DELETION means "no settings" (vault GSE_DELETION).
        settings_edge = _find_highest_path_edge(resource_vertex, resource_uid, dag_path)
        if settings_edge is None or settings_edge.edge_type == EdgeType.DELETION:
            logging.debug(f"No active '{dag_path}' DATA edge for resource {resource_uid}")
            return None
        if settings_edge.edge_type != EdgeType.DATA:
            logging.debug(f"Latest '{dag_path}' edge is not DATA for resource {resource_uid}")
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
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, pamDirectory, pamRemoteBrowser)
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        Dictionary containing JIT settings if found, None otherwise.
    """
    return get_resource_settings(params, resource_uid, 'jit_settings', config_uid)


def get_resource_keeper_ai_settings(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None,
    quiet_if_missing_vertex: bool = False,
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
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, pamDirectory, pamRemoteBrowser)
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
    return get_resource_settings(
        params, resource_uid, 'ai_settings', config_uid,
        quiet_if_missing_vertex=quiet_if_missing_vertex,
    )


def set_resource_keeper_ai_settings(
    params: KeeperParams,
    resource_uid: str,
    settings: Dict[str, Any],
    config_uid: Optional[str] = None
) -> bool:
    """
    Save KeeperAI settings on a PAM resource.

    Primary path: POSTs the encrypted settings to krouter's
    `/api/user/configure_resource` (Layer-B, permission-checked). krouter
    validates caller access then writes the `ai_settings` DAG DATA edge on the
    resource server-side.

    Fallback (env var `KEEPER_DAG_LB_FALLBACK`, default OFF / strict mode): on
    `RRC_NOT_ALLOWED*` from krouter, fall back to the legacy direct
    DAG-write path (`_set_resource_keeper_ai_settings_legacy`). Gateway then
    enforces at runtime. Default (unset/`0`) propagates denials; set to `1` to opt
    into fallback.

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource (pamMachine, pamDatabase, pamDirectory, pamRemoteBrowser)
        settings: Dictionary containing KeeperAI settings to save
        config_uid: Optional PAM config UID. If not provided, will be looked up.

    Returns:
        True if settings were saved successfully, False otherwise.
    """
    # Common setup — needed by both the new and legacy paths.
    common = _resolve_resource_settings_inputs(params, resource_uid, settings, config_uid)
    if common is None:
        return False
    record_key, resolved_config_uid = common

    if not settings:
        logging.debug(f"KeeperAI settings empty for {resource_uid}, skipping save")
        return False

    encrypted_content = encrypt_aes(json.dumps(settings).encode(), record_key)

    # krouter's configure_resource only writes a settings edge when it loads the
    # resource's existing edges (loopEdges), which it does only for requests that
    # carry meta/jit/connection (UserRest.kt). A keeperAiSettings-only request
    # leaves loopEdges null and the ai_settings write is silently dropped. The Web
    # Vault avoids this by always sending meta alongside the AI settings, so mirror
    # that: include the resource's current meta in the same request. When the
    # resource is not in the DAG yet (first link), bootstrap v1 meta instead.
    from ..tunnel.port_forward.TunnelGraph import build_resource_meta_v1

    current_meta = get_resource_settings(
        params, resource_uid, 'meta', resolved_config_uid, quiet_if_missing_vertex=True)
    if not isinstance(current_meta, dict):
        current_meta = build_resource_meta_v1({}, False)
    meta_bytes = json.dumps(current_meta).encode()

    # Primary: Layer-B configure_resource (permission-checked).
    from ..pam.router_helper import router_configure_resource, get_router_url
    host = get_router_url(params)
    endpoint = 'configure_resource'
    if not is_layer_b_feature_disabled(host, endpoint):
        rq = pam_pb2.PAMResourceConfig(
            recordUid=url_safe_str_to_bytes(resource_uid),
            networkUid=url_safe_str_to_bytes(resolved_config_uid),
            keeperAiSettings=encrypted_content,
            meta=meta_bytes,
        )
        try:
            router_configure_resource(params, rq)
            logging.debug(f"Saved KeeperAI settings via configure_resource for {resource_uid}")
            return True
        except Exception as err:
            if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                logging.error(f"configure_resource failed (no fallback): {err}", exc_info=True)
                return False
            logging.warning(
                f"configure_resource denied/unavailable for {resource_uid}; falling back to legacy "
                f"DAG-write (KEEPER_DAG_LB_FALLBACK enabled): {err}"
            )

    # Fallback: legacy direct DAG-write path.
    return _set_resource_keeper_ai_settings_legacy(
        params, resource_uid, settings, resolved_config_uid, record_key, encrypted_content
    )


def _resolve_resource_settings_inputs(
    params: KeeperParams,
    resource_uid: str,
    settings: Dict[str, Any],
    config_uid: Optional[str],
):
    """Validate inputs and resolve record_key + config_uid. Returns (record_key, config_uid) or None on failure.

    Shared by the new and legacy paths so behavior on bad input (missing record,
    bad settings dict, etc.) stays identical.
    """
    record = vault.KeeperRecord.load(params, resource_uid)
    if not record:
        logging.warning(f"Record {resource_uid} not found")
        return None

    record_key = None
    if resource_uid in params.record_cache:
        record_data = params.record_cache[resource_uid]
        record_key = record_data.get('record_key_unencrypted')
    if not record_key:
        logging.warning(f"Record key not available for {resource_uid}")
        return None

    if not isinstance(settings, dict):
        logging.warning("Settings must be a dictionary")
        return None

    if not config_uid:
        encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
        config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
        if not config_uid:
            config_uid = resource_uid

    return record_key, config_uid


def _set_resource_keeper_ai_settings_legacy(
    params: KeeperParams,
    resource_uid: str,
    settings: Dict[str, Any],
    config_uid: str,
    record_key: bytes,
    encrypted_content: bytes,
) -> bool:
    """Legacy direct DAG-write path. Used as fallback when configure_resource is denied.

    Loads the resource's DAG, deactivates any prior `ai_settings` edge, writes a new
    one with the pre-encrypted content, and saves. Pre-Phase-2 behavior, preserved verbatim.
    """
    try:
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_read_protobuf=False,
            use_write_protobuf=False,
        )

        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value,
            decrypt=True,
        )
        linking_dag.load()

        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
        if not resource_vertex:
            logging.warning(f"Resource vertex {resource_uid} not found in DAG")
            return False

        # Find and deactivate existing 'ai_settings' edge for proper versioning
        for edge in resource_vertex.edges:
            if edge and (edge.edge_type == EdgeType.DATA and
                         edge.path == 'ai_settings' and
                         edge.active):
                edge.active = False
                logging.debug(f"Deactivated existing 'ai_settings' edge (version {edge.version})")
                break

        resource_vertex.add_data(
            content=encrypted_content,
            path='ai_settings',
            needs_encryption=False,
            is_encrypted=True,
            modified=True,
        )
        linking_dag.save()

        logging.debug(f"Saved KeeperAI settings via legacy DAG-write for {resource_uid}")
        return True
    except Exception as e:
        logging.error(f"Error saving KeeperAI settings (legacy path) for {resource_uid}: {e}", exc_info=True)
        return False


def _delete_resource_data_edge_legacy(
    params: KeeperParams,
    resource_uid: str,
    config_uid: str,
    record_key: bytes,
    dag_path: str,
) -> Optional[bool]:
    """Delete a path-scoped self-loop DATA edge via GSE_DELETION (vault ``createDeletionEvent``).

    Returns:
        True if a DELETION edge was written,
        None if the path was already absent,
        False on error.
    """
    try:
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_read_protobuf=False,
            use_write_protobuf=False,
        )

        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value,
            decrypt=True,
        )
        linking_dag.load()

        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
        if not resource_vertex:
            logging.debug(f"No resource vertex {resource_uid} in DAG; '{dag_path}' already absent")
            return None

        highest = _find_highest_path_edge(resource_vertex, resource_uid, dag_path)
        if highest is None or highest.edge_type == EdgeType.DELETION:
            logging.debug(f"'{dag_path}' already deleted for resource {resource_uid}")
            return None

        for edge in resource_vertex.edges or []:
            if (edge and edge.edge_type == EdgeType.DATA and edge.path == dag_path
                    and edge.head_uid == resource_uid and edge.active):
                edge.active = False

        resource_vertex.belongs_to(
            resource_vertex,
            EdgeType.DELETION,
            path=dag_path,
        )
        linking_dag.save()

        logging.debug(f"Deleted '{dag_path}' via DELETION edge for resource {resource_uid}")
        return True
    except Exception as e:
        logging.error(f"Error deleting '{dag_path}' for {resource_uid}: {e}", exc_info=True)
        return False


def set_resource_jit_settings(
    params: KeeperParams,
    resource_uid: str,
    settings: Dict[str, Any],
    config_uid: Optional[str] = None,
    allow_empty: bool = False
) -> bool:
    """
    Save JIT settings on a PAM resource.

    Primary path: POSTs the encrypted settings to krouter's
    `/api/user/configure_resource` (Layer-B, permission-checked). Fallback
    behavior matches `set_resource_keeper_ai_settings` — see its docstring
    and `KEEPER_DAG_LB_FALLBACK`. Same shape, `jit_settings` instead of
    `ai_settings`.
    """
    # Empty-settings short-circuit retains the legacy semantics.
    if not isinstance(settings, dict):
        logging.debug(f"JIT settings invalid for {resource_uid}, skipping")
        return False
    if not settings and not allow_empty:
        logging.debug(f"JIT settings empty for {resource_uid}, skipping")
        return False

    common = _resolve_resource_settings_inputs(params, resource_uid, settings, config_uid)
    if common is None:
        return False
    record_key, resolved_config_uid = common

    encrypted_content = encrypt_aes(json.dumps(settings).encode(), record_key)

    # Primary: Layer-B configure_resource (permission-checked).
    from ..pam.router_helper import router_configure_resource, get_router_url
    host = get_router_url(params)
    endpoint = 'configure_resource'
    if not is_layer_b_feature_disabled(host, endpoint):
        rq = pam_pb2.PAMResourceConfig(
            recordUid=url_safe_str_to_bytes(resource_uid),
            networkUid=url_safe_str_to_bytes(resolved_config_uid),
            jitSettings=encrypted_content,
        )
        try:
            router_configure_resource(params, rq)
            logging.debug(f"Saved JIT settings via configure_resource for {resource_uid}")
            return True
        except Exception as err:
            if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                logging.error(f"configure_resource failed (no fallback): {err}", exc_info=True)
                return False
            logging.warning(
                f"configure_resource denied/unavailable for {resource_uid}; falling back to legacy "
                f"DAG-write (KEEPER_DAG_LB_FALLBACK enabled): {err}"
            )

    return _set_resource_jit_settings_legacy(
        params, resource_uid, resolved_config_uid, record_key, encrypted_content
    )


def _set_resource_jit_settings_legacy(
    params: KeeperParams,
    resource_uid: str,
    config_uid: str,
    record_key: bytes,
    encrypted_content: bytes,
) -> bool:
    """Legacy direct DAG-write path for JIT settings. See AI-settings analog for shape."""
    try:
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_read_protobuf=False,
            use_write_protobuf=False,
        )

        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value,
            decrypt=True,
        )
        linking_dag.load()

        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
        if not resource_vertex:
            logging.warning(f"Resource vertex {resource_uid} not found in DAG")
            return False

        for edge in resource_vertex.edges:
            if edge and (edge.edge_type == EdgeType.DATA and
                         edge.path == 'jit_settings' and
                         edge.active):
                edge.active = False
                logging.debug(f"Deactivated existing 'jit_settings' edge (version {edge.version})")
                break

        resource_vertex.add_data(
            content=encrypted_content,
            path='jit_settings',
            needs_encryption=False,
            is_encrypted=True,
            modified=True,
        )
        linking_dag.save()

        logging.debug(f"Saved JIT settings via legacy DAG-write for {resource_uid}")
        return True
    except Exception as e:
        logging.error(f"Error saving JIT settings (legacy path) for {resource_uid}: {e}", exc_info=True)
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
            use_read_protobuf=False,
            use_write_protobuf=False
        )
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value,
            decrypt=True
        )
        linking_dag.load()
        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
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
            use_read_protobuf=False,
            use_write_protobuf=False
        )
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value,
            decrypt=True
        )
        linking_dag.load()
        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
        config_vertex = linking_dag.get_vertex_by_uid(config_uid)
        if not resource_vertex or not config_vertex:
            return False
        # Re-add LINK (path empty, content {}) so it becomes latest, above KEY added by JIT/AI
        resource_vertex.belongs_to(config_vertex, EdgeType.LINK, path=None, content={})
        linking_dag.save()
        return True
    except Exception as e:
        logging.debug(f"refresh_link_to_config_to_latest for {resource_uid}: {e}")
        return False


def _get_audit_user_id(params: KeeperParams) -> str:
    if getattr(params, 'account_uid_bytes', None):
        return utils.base64_url_encode(params.account_uid_bytes)
    return getattr(params, 'user', '') or ''


def _make_tag_entry(tag: str, action: str, user_id: str) -> Dict[str, Any]:
    return {
        'tag': tag,
        'auditLog': [{
            'date': utils.current_milli_time(),
            'userId': user_id,
            'action': action,
        }],
    }


def _parse_tag_name(tag_item: Any) -> str:
    if isinstance(tag_item, dict):
        return str(tag_item.get('tag', '')).strip()
    return str(tag_item).strip()


def _get_tag_list(level_data: Dict[str, Any], list_name: str) -> List[Dict[str, Any]]:
    tags = level_data.setdefault('tags', {})
    entries = tags.get(list_name)
    if not isinstance(entries, list):
        entries = []
        tags[list_name] = entries
    return entries


def parse_ai_setting_spec(spec: str) -> tuple:
    """
    Parse CLI spec ``LEVEL``, ``LEVEL.SETTING``, or ``LEVEL.SETTING=VALUE``.

    Returns (level, setting_or_none, value_or_none). ``value_or_none`` is None when
    ``=`` is absent (unset-without-value forms).
    """
    if not spec or not str(spec).strip():
        raise ValueError('empty AI setting spec')

    text = str(spec).strip()
    level_part, sep, value_part = text.partition('=')
    if sep and value_part == '':
        raise ValueError(
            f'invalid AI setting spec (missing value): {spec}. '
            f'To remove a setting, use --unset|-u (e.g. -u high.terminate or -u high.allow=chmod).'
        )

    if '.' in level_part:
        level_name, setting_name = level_part.split('.', 1)
    else:
        level_name, setting_name = level_part, None

    level_name = level_name.strip().lower()
    if level_name not in AI_RISK_LEVELS:
        raise ValueError(f'invalid risk level "{level_name}" (expected: {", ".join(AI_RISK_LEVELS)})')

    if setting_name is not None:
        setting_name = setting_name.strip().lower()
        if setting_name not in ('terminate', 'allow', 'deny'):
            raise ValueError(f'invalid setting "{setting_name}" (expected: terminate, allow, deny)')
        if level_name == 'low' and setting_name == 'deny':
            raise ValueError('deny is not supported for the low risk level')

    value = value_part if sep else None
    return level_name, setting_name, value


def dedupe_ai_cli_option_specs(
    specs: Optional[List[str]],
    option_label: str,
) -> tuple:
    """Return unique specs in first-seen order and warnings for duplicate CLI options.

    ``option_label`` is shown in warnings (e.g. ``--set/-s``).
    """
    if not specs:
        return [], []

    order: List[str] = []
    counts: Dict[str, int] = {}
    for spec in specs:
        counts[spec] = counts.get(spec, 0) + 1
        if spec not in order:
            order.append(spec)

    warnings = [
        f'duplicate {option_label} ignored: {spec} ({counts[spec]}x)'
        for spec in order
        if counts[spec] > 1
    ]
    return order, warnings


def _is_full_ai_setting_spec(spec: str) -> bool:
    """True when spec is ``LEVEL.SETTING=VALUE`` (value present after ``=``)."""
    _, setting, value = parse_ai_setting_spec(spec)
    return setting is not None and value is not None


def _reconcile_set_unset_specs(
    unset_specs: Optional[List[str]],
    set_specs: Optional[List[str]],
) -> tuple:
    """Drop ``--unset`` specs mirrored by a ``--set`` on the same ``LEVEL.SETTING=VALUE``.

    Only applies when both sides use the full ``level.setting=value`` form. Partial
    unsets (e.g. ``-u high.allow`` or ``-u high.terminate``) are not reconciled.
    """
    unset_list = list(unset_specs or [])
    set_list = list(set_specs or [])
    warnings: List[str] = []
    if not unset_list or not set_list:
        return unset_list, set_list, warnings

    parsed_sets = [parse_ai_setting_spec(spec) for spec in set_list]
    drop_unset_specs = set()

    for u_spec in unset_list:
        if not _is_full_ai_setting_spec(u_spec):
            continue
        u_level, u_setting, _u_value = parse_ai_setting_spec(u_spec)

        for set_spec, (s_level, s_setting, _s_value) in zip(set_list, parsed_sets):
            if u_level != s_level or u_setting != s_setting:
                continue
            if not _is_full_ai_setting_spec(set_spec):
                continue
            drop_unset_specs.add(u_spec)
            if u_spec == set_spec:
                warnings.append(f'--set/-s overrides --unset/-u: {u_spec}')
            else:
                warnings.append(
                    f'--set/-s overrides --unset/-u: {u_spec} (mirrors -s {set_spec})'
                )
            break

    return [spec for spec in unset_list if spec not in drop_unset_specs], set_list, warnings


_LOW_TERMINATE_WARNING = 'risk level low.terminate always defaults to false.'


def _parse_terminate_value(value: str) -> bool:
    normalized = str(value).strip().casefold()
    if normalized == 'true':
        return True
    if normalized == 'false':
        return False
    raise ValueError(f'invalid terminate value "{value}" (expected true or false)')


def _existing_terminate_value(risk_levels: Dict[str, Any], level: str) -> Optional[bool]:
    level_data = risk_levels.get(level)
    if not isinstance(level_data, dict):
        return None
    value = level_data.get('aiSessionTerminate')
    if value is None:
        return None
    return bool(value)


def _ensure_ai_settings_dict(existing: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    settings = dict(existing) if isinstance(existing, dict) else {}
    settings['version'] = settings.get('version') or AI_SETTINGS_VERSION
    risk_levels = settings.get('riskLevels')
    if not isinstance(risk_levels, dict):
        risk_levels = {}
        settings['riskLevels'] = risk_levels
    return settings


def _ensure_level_dict(risk_levels: Dict[str, Any], level: str) -> Dict[str, Any]:
    level_data = risk_levels.get(level)
    if not isinstance(level_data, dict):
        level_data = {}
        risk_levels[level] = level_data
    return level_data


def _prune_level(level_data: Dict[str, Any]) -> bool:
    tags = level_data.get('tags')
    if isinstance(tags, dict):
        for key in list(tags.keys()):
            entries = tags.get(key)
            if not entries:
                tags.pop(key, None)
        if not tags:
            level_data.pop('tags', None)
    return not level_data


def _level_is_only_default_low(level_data: Dict[str, Any]) -> bool:
    if not isinstance(level_data, dict):
        return True
    tags = level_data.get('tags')
    has_tags = isinstance(tags, dict) and any(tags.get(k) for k in tags)
    if has_tags:
        return False
    terminate = level_data.get('aiSessionTerminate')
    return terminate is None or terminate is False


def _normalize_ai_settings_for_save(settings: Dict[str, Any]) -> Dict[str, Any]:
    risk_levels = settings.get('riskLevels')
    if not isinstance(risk_levels, dict):
        return {}

    for level in list(risk_levels.keys()):
        if level not in AI_RISK_LEVELS:
            risk_levels.pop(level, None)
            continue
        if _prune_level(risk_levels[level]):
            risk_levels.pop(level, None)

    low_data = risk_levels.get('low')
    if isinstance(low_data, dict):
        low_data['aiSessionTerminate'] = False
        tags = low_data.get('tags')
        if isinstance(tags, dict):
            tags.pop('deny', None)
            if not tags:
                low_data.pop('tags', None)
        if _prune_level(low_data) or _level_is_only_default_low(low_data):
            risk_levels.pop('low', None)

    if not risk_levels:
        return {}

    return {
        'version': settings.get('version', AI_SETTINGS_VERSION),
        'riskLevels': risk_levels,
    }


def apply_ai_setting_changes(
    existing: Optional[Dict[str, Any]],
    set_specs: Optional[List[str]],
    unset_specs: Optional[List[str]],
    params: KeeperParams,
) -> tuple:
    """Merge CLI --set/--unset operations into KeeperAI DAG settings.

    Returns ``(settings_dict, warnings)`` where ``warnings`` is a list of user-facing
    messages (e.g. silent conversions applied during save).
    """
    settings = _ensure_ai_settings_dict(existing)
    risk_levels = settings['riskLevels']
    user_id = _get_audit_user_id(params)
    warnings: List[str] = []

    unset_specs, set_specs, reconcile_warnings = _reconcile_set_unset_specs(unset_specs, set_specs)
    warnings.extend(reconcile_warnings)

    for spec in unset_specs or []:
        level, setting, value = parse_ai_setting_spec(spec)
        if setting is None:
            risk_levels.pop(level, None)
            continue

        level_data = risk_levels.get(level)
        if not isinstance(level_data, dict):
            continue

        if setting == 'terminate':
            level_data.pop('aiSessionTerminate', None)
        else:
            tags = level_data.get('tags')
            if not isinstance(tags, dict):
                continue
            entries = tags.get(setting)
            if not isinstance(entries, list):
                continue
            if value is None:
                tags.pop(setting, None)
            else:
                tags[setting] = [e for e in entries if _parse_tag_name(e) != value]
            if not tags.get(setting):
                tags.pop(setting, None)
            if not tags:
                level_data.pop('tags', None)

        if _prune_level(level_data):
            risk_levels.pop(level, None)

    for spec in set_specs or []:
        level, setting, value = parse_ai_setting_spec(spec)
        if setting is None:
            raise ValueError(f'--set requires LEVEL.SETTING=VALUE (got "{spec}")')
        if value is None:
            raise ValueError(f'--set requires a value (got "{spec}")')

        level_data = _ensure_level_dict(risk_levels, level)
        if setting == 'terminate':
            terminate_value = _parse_terminate_value(value)
            effective_value = False if level == 'low' else terminate_value
            if level == 'low' and terminate_value:
                if _LOW_TERMINATE_WARNING not in warnings:
                    warnings.append(_LOW_TERMINATE_WARNING)
            if _existing_terminate_value(risk_levels, level) == effective_value:
                continue
            level_data['aiSessionTerminate'] = effective_value
            continue

        tag_value = value.strip()
        if not tag_value:
            raise ValueError(f'--set tag value cannot be empty (got "{spec}")')

        entries = _get_tag_list(level_data, setting)
        if not any(_parse_tag_name(e) == tag_value for e in entries):
            action = 'added_to_allow' if setting == 'allow' else 'added_to_deny'
            entries.append(_make_tag_entry(tag_value, action, user_id))

    return _normalize_ai_settings_for_save(settings), warnings


def remove_resource_keeper_ai_settings(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> Optional[bool]:
    """Remove the ``ai_settings`` DATA edge (GSE_DELETION), restoring pre-AI DAG state.

    Web Vault treats a missing ``ai_settings`` edge as ``emptyKeeperAISettings`` in
    memory. Writing ``{}`` or the empty template leaves a DATA edge and can break WV;
    ``configure_resource`` does not clear ``keeperAiSettings`` when omitted — use graph-sync
    DELETION like ``DagOperations.createDeletionEvent`` + ``dagPamLinkAddData``.

    Returns:
        True if a DELETION edge was written,
        None if ``ai_settings`` was already absent,
        False on error.
    """
    common = _resolve_resource_settings_inputs(params, resource_uid, {}, config_uid)
    if common is None:
        return False
    record_key, resolved_config_uid = common

    return _delete_resource_data_edge_legacy(
        params, resource_uid, resolved_config_uid, record_key, 'ai_settings')


def print_keeper_ai_settings(params: KeeperParams, resource_uid: str, config_uid: Optional[str] = None):
    """
    Print KeeperAI settings in a human-readable format.

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource
        config_uid: Optional PAM config UID
    """
    settings = get_resource_keeper_ai_settings(params, resource_uid, config_uid)

    if is_default_keeper_ai_settings(settings):
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


def inspect_resource_in_graph(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None,
    show_raw_content: bool = False
) -> Dict[str, Any]:
    """
    Inspect all graph edges and vertices referencing a record UID.
    Returns edges (tail->head), vertices (UIDs), and DATA edges grouped by path with all versions.

    Args:
        params: KeeperParams instance
        resource_uid: UID of the PAM resource
        config_uid: Optional PAM config UID
        show_raw_content: If True, load DAG with decrypt=False and include raw stored content
            (encrypted bytes) in data_by_path. Use this to see what's actually stored without
            auto-decrypt skewing the picture.

    Returns:
        {
            "edges": [{"type": str, "tail": str, "head": str, "path": str|None, "version": int, "active": bool}, ...],
            "vertices": [uid, ...],
            "data_by_path": {"path_name": [{"version": int, "active": bool, "has_content": bool,
                "raw_content_len"?: int, "raw_content_preview"?: str}, ...], ...}
        }
    """
    result: Dict[str, Any] = {"edges": [], "vertices": [], "data_by_path": {}}
    try:
        vault.KeeperRecord.load(params, resource_uid)
        record_key = params.record_cache.get(resource_uid, {}).get('record_key_unencrypted')
        if not record_key:
            logging.warning(f"Record key not available for {resource_uid}")
            return result

        if not config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, resource_uid)
            if not config_uid:
                config_uid = resource_uid

        vault.KeeperRecord.load(params, config_uid)
        config_record_key = params.record_cache.get(config_uid, {}).get('record_key_unencrypted')
        if not config_record_key:
            logging.warning(f"Config record key not available for {config_uid}")
            return result

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = config_record_key

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_read_protobuf=False,
            use_write_protobuf=False
        )
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value,
            decrypt=not show_raw_content
        )
        linking_dag.load()

        # 1) All edges referencing record_uid (tail==ruid or head_uid==ruid)
        edge_records = []
        vertex_uids = {resource_uid}

        for vertex in linking_dag.all_vertices:
            tail_uid = vertex.uid
            for edge in (vertex.edges or []):
                if not edge:
                    continue
                head_uid = edge.head_uid
                if tail_uid != resource_uid and head_uid != resource_uid:
                    continue
                vertex_uids.add(tail_uid)
                vertex_uids.add(head_uid)
                edge_records.append({
                    "type": edge.edge_type.value if hasattr(edge.edge_type, 'value') else str(edge.edge_type),
                    "tail": tail_uid,
                    "head": head_uid,
                    "path": edge.path,
                    "version": getattr(edge, 'version', 0),
                    "active": getattr(edge, 'active', True),
                })
                if edge.edge_type == EdgeType.DATA:
                    path_key = edge.path or "(no path)"
                    if path_key not in result["data_by_path"]:
                        result["data_by_path"][path_key] = []
                    entry = {
                        "version": getattr(edge, 'version', 0),
                        "active": getattr(edge, 'active', True),
                        "has_content": edge.content is not None,
                    }
                    if show_raw_content and edge.content is not None:
                        raw = edge.content
                        if isinstance(raw, bytes):
                            entry["raw_content_len"] = len(raw)
                            # First 64 bytes as hex for encrypted blob preview
                            entry["raw_content_preview"] = raw[:64].hex()
                        else:
                            s = str(raw)
                            entry["raw_content_len"] = len(s)
                            entry["raw_content_preview"] = s[:128] + ("..." if len(s) > 128 else "")
                    result["data_by_path"][path_key].append(entry)

        result["edges"] = edge_records
        result["vertices"] = sorted(vertex_uids)
        return result

    except Exception as e:
        logging.error(f"Error inspecting graph for {resource_uid}: {e}", exc_info=True)
        result["error"] = str(e)
        return result


def get_resource_domain_dir_uid(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> Optional[str]:
    """
    Return the pamDirectory UID linked to the resource via a LINK edge with path 'domain'.
    Returns None if no such link exists.
    """
    try:
        record = vault.KeeperRecord.load(params, resource_uid)
        if not record:
            return None

        record_key = None
        if resource_uid in params.record_cache:
            record_key = params.record_cache[resource_uid].get('record_key_unencrypted')
        if not record_key:
            return None

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
            use_read_protobuf=False,
            use_write_protobuf=False
        )
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value
        )
        linking_dag.load()

        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
        if not resource_vertex:
            return None

        for edge in resource_vertex.edges:
            if (edge and edge.edge_type == EdgeType.LINK and
                    edge.path == 'domain' and edge.active):
                return edge.head_uid

        return None

    except Exception as e:
        logging.error(f"Error getting domain dir UID for {resource_uid}: {e}", exc_info=True)
        return None


def set_resource_domain_dir(
    params: KeeperParams,
    resource_uid: str,
    dir_uid: str,
    config_uid: Optional[str] = None
) -> bool:
    """
    Add or replace the LINK edge from resource to pamDirectory.

    Primary path: POSTs a `PAMResourceConfig` with `domainUid` set to krouter's
    `/api/user/configure_resource`. krouter handles "replace existing domain link"
    server-side (so the legacy disconnect-old-first dance is no longer needed).

    Fallback: same `KEEPER_DAG_LB_FALLBACK` policy as the AI/JIT helpers (see
    `set_resource_keeper_ai_settings`).
    """
    common = _resolve_resource_settings_inputs(params, resource_uid, {}, config_uid)
    if common is None:
        return False
    record_key, resolved_config_uid = common

    # Primary: Layer-B configure_resource (permission-checked).
    from ..pam.router_helper import router_configure_resource, get_router_url
    host = get_router_url(params)
    endpoint = 'configure_resource'
    if not is_layer_b_feature_disabled(host, endpoint):
        rq = pam_pb2.PAMResourceConfig(
            recordUid=url_safe_str_to_bytes(resource_uid),
            networkUid=url_safe_str_to_bytes(resolved_config_uid),
            domainUid=url_safe_str_to_bytes(dir_uid),
        )
        try:
            router_configure_resource(params, rq)
            logging.debug(f"Set domain dir link {resource_uid} -> {dir_uid} via configure_resource")
            return True
        except Exception as err:
            if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                logging.error(f"configure_resource failed (no fallback): {err}", exc_info=True)
                return False
            logging.warning(
                f"configure_resource denied/unavailable for {resource_uid}; falling back to legacy "
                f"DAG-write (KEEPER_DAG_LB_FALLBACK enabled): {err}"
            )

    return _set_resource_domain_dir_legacy(
        params, resource_uid, dir_uid, resolved_config_uid, record_key
    )


def _set_resource_domain_dir_legacy(
    params: KeeperParams,
    resource_uid: str,
    dir_uid: str,
    config_uid: str,
    record_key: bytes,
) -> bool:
    """Legacy direct DAG-write path: disconnect-old-then-link. Used as fallback only."""
    try:
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        dag_record = PasswordRecord()
        dag_record.record_uid = config_uid
        dag_record.record_key = record_key

        conn = Connection(
            params=params,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token,
            transmission_key=transmission_key,
            use_read_protobuf=False,
            use_write_protobuf=False,
        )
        linking_dag = DAG(
            conn=conn,
            record=dag_record,
            graph_id=PamGraphId.PAM.value,
            decrypt=True,
        )
        linking_dag.load()

        resource_vertex = linking_dag.get_vertex_by_uid(resource_uid)
        if not resource_vertex:
            logging.warning(f"Resource vertex {resource_uid} not found in DAG")
            return False

        # If a domain LINK to a different pamDirectory exists, disconnect it first.
        old_dir_uid = None
        for edge in resource_vertex.edges:
            if (edge and edge.edge_type == EdgeType.LINK and
                    edge.path == 'domain' and edge.active):
                old_dir_uid = edge.head_uid
                break
        if old_dir_uid and old_dir_uid != dir_uid:
            old_dir_vertex = linking_dag.get_vertex_by_uid(old_dir_uid)
            if old_dir_vertex:
                resource_vertex.disconnect_from(old_dir_vertex)
                logging.debug(f"Disconnected old domain LINK edge to {old_dir_uid}")

        dir_vertex = linking_dag.get_vertex_by_uid(dir_uid)
        if not dir_vertex:
            logging.warning(f"Directory vertex {dir_uid} not found in DAG")
            return False

        resource_vertex.belongs_to(dir_vertex, EdgeType.LINK, path="domain", content={})
        linking_dag.save()

        logging.debug(f"Set domain dir link {resource_uid} -> {dir_uid} via legacy DAG-write")
        return True
    except Exception as e:
        logging.error(f"Error setting domain dir (legacy path) for {resource_uid}: {e}", exc_info=True)
        return False


def remove_resource_jit_settings(
    params: KeeperParams,
    resource_uid: str,
    config_uid: Optional[str] = None
) -> bool:
    """
    Remove JIT settings by overwriting the 'jit_settings' DATA edge with an empty dict.

    Implementation note: DATA edges in the DAG library use `active` as a versioning
    marker (auto-managed by add_data when superseding), not a visibility toggle —
    get_resource_settings reads the highest-version edge regardless of `active`,
    and EdgeType.DELETION self-loops are not path-scoped in the library's lookup
    logic. Writing an empty {} via the same set_resource_jit_settings path that
    creation uses gives a clean, reliable removal: the new edge becomes the
    highest version, and _do_show treats {} as 'No JIT settings configured'.
    """
    if not set_resource_jit_settings(params, resource_uid, {}, config_uid, allow_empty=True):
        return False
    logging.debug(f"Cleared jit_settings for resource {resource_uid}")
    return True
