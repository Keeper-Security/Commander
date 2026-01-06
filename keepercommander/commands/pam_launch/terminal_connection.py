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

"""
Terminal connection module for PAM Launch command.

This module handles terminal-based protocol connections (SSH, Telnet, Kubernetes, 
MySQL, PostgreSQL, SQL Server) through Guacamole over WebRTC tunnels.
"""

from __future__ import annotations
import logging
import os
import sys
import base64
import json
from typing import TYPE_CHECKING, Optional, Dict, Any

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes, url_safe_str_to_bytes, string_to_bytes, bytes_to_string

from ...error import CommandError
from ... import vault
from ...keeper_dag import EdgeType
from ..ssh_agent import try_extract_private_key
from ..tunnel.port_forward.tunnel_helpers import (
    get_or_create_tube_registry,
    start_websocket_listener,
    register_conversation_key,
    register_tunnel_session,
    unregister_conversation_key,
    unregister_tunnel_session,
    TunnelSession,
    TunnelSignalHandler,
    tunnel_encrypt,
    tunnel_decrypt,
    get_tunnel_session,
    get_keeper_tokens,
    MAIN_NONCE_LENGTH,
    SYMMETRIC_KEY_LENGTH,
)
from ..tunnel.port_forward.TunnelGraph import TunnelDAG
from ..pam.pam_dto import GatewayAction, GatewayActionWebRTCSession
from ..pam.router_helper import (
    router_send_action_to_gateway,
    router_get_relay_access_creds,
    get_router_url,
    VERIFY_SSL,
)
from ...proto import pam_pb2
from ...display import bcolors

if TYPE_CHECKING:
    from ...params import KeeperParams


# Protocol type constants
class ProtocolType:
    """Terminal protocol types supported by PAM Launch"""
    SSH = 'ssh'
    TELNET = 'telnet'
    KUBERNETES = 'kubernetes'
    MYSQL = 'mysql'
    POSTGRESQL = 'postgresql'
    SQLSERVER = 'sqlserver'

    # All supported terminal protocols
    ALL_TERMINAL = {SSH, TELNET, KUBERNETES, MYSQL, POSTGRESQL, SQLSERVER}

    # Database protocols
    DATABASE = {MYSQL, POSTGRESQL, SQLSERVER}

    # Machine protocols
    MACHINE = {SSH, TELNET}


# Default ports for protocols
DEFAULT_PORTS = {
    ProtocolType.SSH: 22,
    ProtocolType.TELNET: 23,
    ProtocolType.KUBERNETES: 443,
    ProtocolType.MYSQL: 3306,
    ProtocolType.POSTGRESQL: 5432,
    ProtocolType.SQLSERVER: 1433,
}

# Default terminal metrics used to translate local console dimensions into the
# pixel-based values that Guacamole expects.
DEFAULT_TERMINAL_COLUMNS = 80
DEFAULT_TERMINAL_ROWS = 24
DEFAULT_CELL_WIDTH_PX = 10
DEFAULT_CELL_HEIGHT_PX = 19
DEFAULT_SCREEN_DPI = 96


def _build_screen_info(columns: int, rows: int) -> Dict[str, int]:
    """Convert character columns/rows into pixel measurements for the Gateway."""
    col_value = columns if isinstance(columns, int) and columns > 0 else DEFAULT_TERMINAL_COLUMNS
    row_value = rows if isinstance(rows, int) and rows > 0 else DEFAULT_TERMINAL_ROWS
    return {
        "columns": col_value,
        "rows": row_value,
        "pixel_width": col_value * DEFAULT_CELL_WIDTH_PX,
        "pixel_height": row_value * DEFAULT_CELL_HEIGHT_PX,
        "dpi": DEFAULT_SCREEN_DPI,
    }


DEFAULT_SCREEN_INFO = _build_screen_info(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS)

MAX_MESSAGE_SIZE_LINE = "a=max-message-size:1073741823"


def _ensure_max_message_size_attribute(sdp_offer: Optional[str]) -> Optional[str]:
    """
    Ensure the SDP offer advertises the same max-message-size attribute as Web Vault.

    Args:
        sdp_offer: Original SDP offer string returned by the WebRTC module.

    Returns:
        SDP string containing the MAX_MESSAGE_SIZE_LINE (added if it was missing).
    """
    if not sdp_offer or MAX_MESSAGE_SIZE_LINE in sdp_offer:
        return sdp_offer

    newline = "\r\n" if "\r\n" in sdp_offer else "\n"
    insert_location = None
    lower_offer = sdp_offer.lower()

    # Prefer to inject directly after the SCTP port attribute to mimic Web Vault ordering.
    sctp_idx = lower_offer.find("a=sctp-port:")
    if sctp_idx != -1:
        after_sctp = sdp_offer.find(newline, sctp_idx)
        if after_sctp == -1:
            insert_location = len(sdp_offer)
        else:
            insert_location = after_sctp + len(newline)
    else:
        # If the SCTP line is missing, try to inject immediately after the datachannel media line.
        media_idx = lower_offer.find("m=application")
        if media_idx != -1:
            after_media = sdp_offer.find(newline, media_idx)
            if after_media == -1:
                insert_location = len(sdp_offer)
            else:
                insert_location = after_media + len(newline)

    if insert_location is None:
        # Append at the end, keeping the existing newline style and ensuring we end with one blank line.
        suffix = "" if sdp_offer.endswith(newline) else newline
        updated_offer = f"{sdp_offer}{suffix}{MAX_MESSAGE_SIZE_LINE}{newline}"
    else:
        updated_offer = (
            sdp_offer[:insert_location]
            + f"{MAX_MESSAGE_SIZE_LINE}{newline}"
            + sdp_offer[insert_location:]
        )

    logging.debug("Injected `%s` into SDP offer to match Web Vault behavior", MAX_MESSAGE_SIZE_LINE)
    return updated_offer


def _notify_gateway_connection_close(params, router_token, terminated=True):
    """
    Notify the gateway/router that a WebRTC session should be closed.

    This mirrors the gateway's own POST to /api/device/connect_state so that
    stale tubes are cleaned up when Commander aborts before a session fully starts.

    Note: gateway_cookies parameter was removed in commit 338a9fda as router
    affinity is now handled server-side.
    """
    if not router_token:
        logging.debug("Skipping connection_close notification - router_token missing")
        return

    try:
        router_url = get_router_url(params)
        payload = {
            "token": router_token,
            "type": "connection_close",
        }
        if terminated is not None:
            payload["terminated"] = terminated

        response = requests.post(
            f"{router_url}/api/device/connect_state",
            json=payload,
            verify=VERIFY_SSL,
            timeout=10,
        )
        if response.status_code >= 400:
            logging.warning(
                "Gateway connection_close notification failed (%s): %s",
                response.status_code,
                response.text,
            )
        else:
            logging.debug("Sent connection_close notification for router token")
    except Exception as notify_err:
        logging.debug(f"Failed to notify gateway about connection_close: {notify_err}")


def detect_protocol(params: KeeperParams, record_uid: str) -> Optional[str]:
    """
    Detect the terminal protocol from a PAM record.

    Args:
        params: KeeperParams instance
        record_uid: Record UID

    Returns:
        Protocol string (ssh, telnet, kubernetes, mysql, postgresql, sqlserver) or None

    Raises:
        CommandError: If record type is not supported or protocol cannot be determined
    """
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord):
        raise CommandError('pam launch', f'Record {record_uid} is not a TypedRecord')

    record_type = record.record_type

    # pamMachine -> SSH or Telnet
    if record_type == 'pamMachine':
        # Check if telnet is explicitly configured
        # Look for telnet-specific fields or settings
        pam_settings = record.get_typed_field('pamSettings')
        if pam_settings:
            settings_value = pam_settings.get_default_value(dict)
            if settings_value:
                connection = settings_value.get('connection', {})
                if isinstance(connection, dict):
                    # Check for telnet protocol indicator
                    protocol_field = connection.get('protocol')
                    if protocol_field and 'telnet' in str(protocol_field).lower():
                        return ProtocolType.TELNET

        # Default to SSH for pamMachine
        return ProtocolType.SSH

    # pamDirectory -> Kubernetes
    elif record_type == 'pamDirectory':
        return ProtocolType.KUBERNETES

    # pamDatabase -> MySQL, PostgreSQL, or SQL Server
    elif record_type == 'pamDatabase':
        # Inspect the database type field
        pam_settings = record.get_typed_field('pamSettings')
        if pam_settings:
            settings_value = pam_settings.get_default_value(dict)
            if settings_value:
                connection = settings_value.get('connection', {})
                if isinstance(connection, dict):
                    db_type = connection.get('databaseType', '').lower()

                    if 'mysql' in db_type:
                        return ProtocolType.MYSQL
                    elif 'postgres' in db_type or 'postgresql' in db_type:
                        return ProtocolType.POSTGRESQL
                    elif 'sql server' in db_type or 'sqlserver' in db_type or 'mssql' in db_type:
                        return ProtocolType.SQLSERVER

        # Try to infer from port if database type not specified
        hostname_field = record.get_typed_field('pamHostname')
        if hostname_field:
            host_value = hostname_field.get_default_value(dict)
            if host_value:
                port = host_value.get('port')
                if port:
                    port_int = int(port) if isinstance(port, str) else port
                    if port_int == 3306:
                        return ProtocolType.MYSQL
                    elif port_int == 5432:
                        return ProtocolType.POSTGRESQL
                    elif port_int == 1433:
                        return ProtocolType.SQLSERVER

        # Default to MySQL if we can't determine
        logging.warning(f"Could not determine database type for record {record_uid}, defaulting to MySQL")
        return ProtocolType.MYSQL

    else:
        raise CommandError('pam launch', 
                         f'Record type "{record_type}" is not supported for terminal connections. '
                         f'Supported types: pamMachine, pamDirectory, pamDatabase')


def extract_terminal_settings(
    params: KeeperParams,
    record_uid: str,
    protocol: str,
    launch_credential_uid: Optional[str] = None,
    custom_host: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract terminal connection settings from a PAM record.

    Args:
        params: KeeperParams instance
        record_uid: Record UID
        protocol: Protocol type (from detect_protocol)
        launch_credential_uid: Optional override for userRecordUid (from --user CLI param)
        custom_host: Optional override for hostname (from --host CLI param)

    Returns:
        Dictionary containing terminal settings:
        - hostname: Target hostname
        - port: Target port
        - clipboard: {disableCopy: bool, disablePaste: bool}
        - terminal: {colorScheme: str, fontSize: str}
        - recording: {includeKeys: bool}
        - protocol_specific: Protocol-specific settings dict
        - allowSupplyUser: bool - User can supply credentials on-the-fly
        - allowSupplyHost: bool - User can supply host on-the-fly (forces userSupplied credential type)
        - userRecordUid: str or None - UID of linked pamUser record for credentials

    Raises:
        CommandError: If required fields are missing
    """
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord):
        raise CommandError('pam launch', f'Record {record_uid} is not a TypedRecord')

    settings = {
        'hostname': None,
        'port': None,
        'clipboard': {'disableCopy': False, 'disablePaste': False},
        'terminal': {'colorScheme': 'gray-black', 'fontSize': '12'},
        'recording': {'includeKeys': False},
        'protocol_specific': {},
        'allowSupplyUser': False,
        'allowSupplyHost': False,
        'userRecordUid': None,
    }

    # Extract hostname and port
    hostname_field = record.get_typed_field('pamHostname')
    if not hostname_field:
        raise CommandError('pam launch', f'No hostname configured for record {record_uid}')

    host_value = hostname_field.get_default_value(dict)
    if not host_value:
        raise CommandError('pam launch', f'Invalid hostname configuration for record {record_uid}')

    settings['hostname'] = host_value.get('hostName')

    # Override hostname if custom_host provided (requires allowSupplyHost - validated in launch.py)
    if custom_host:
        settings['hostname'] = custom_host
        logging.debug(f"Using custom host override: {custom_host}")

    # Validate hostname is present (either from record or CLI override)
    # Note: allowSupplyHost check happens later after pamSettings are parsed

    # Get port (use default if not specified)
    port_value = host_value.get('port')
    if port_value:
        settings['port'] = int(port_value) if isinstance(port_value, str) else port_value
    else:
        settings['port'] = DEFAULT_PORTS.get(protocol, 22)

    # Extract PAM settings
    pam_settings_field = record.get_typed_field('pamSettings')
    if pam_settings_field:
        pam_settings_value = pam_settings_field.get_default_value(dict)
        if pam_settings_value:
            connection = pam_settings_value.get('connection', {})
            if isinstance(connection, dict):
                # Clipboard settings
                settings['clipboard']['disableCopy'] = connection.get('disableCopy', False)
                settings['clipboard']['disablePaste'] = connection.get('disablePaste', False)

                # Terminal display settings
                color_scheme = connection.get('colorScheme')
                if color_scheme:
                    settings['terminal']['colorScheme'] = color_scheme

                font_size = connection.get('fontSize')
                if font_size:
                    settings['terminal']['fontSize'] = str(font_size)

                # Recording settings
                settings['recording']['includeKeys'] = connection.get('recordingIncludeKeys', False)

                # allowSupplyUser is inside connection
                settings['allowSupplyUser'] = connection.get('allowSupplyUser', False)

                # Extract linked pamUser record UID from pamSettings (may be overridden by CLI later)
                # When both admin and launch credentials exist, we must use launch credential
                dag_launch_uid = _get_launch_credential_uid(params, record_uid)
                if dag_launch_uid:
                    settings['userRecordUid'] = dag_launch_uid
                    logging.debug(f"Using launch credential from DAG: {settings['userRecordUid']}")
                else:
                    # Fallback to userRecords from pamSettings if DAG lookup fails
                    user_records = connection.get('userRecords', [])
                    if user_records and len(user_records) > 0:
                        settings['userRecordUid'] = user_records[0]
                        logging.debug(f"Using userRecordUid from pamSettings: {settings['userRecordUid']}")

                # Protocol-specific settings
                if protocol == ProtocolType.SSH:
                    settings['protocol_specific'] = _extract_ssh_settings(connection)
                elif protocol == ProtocolType.TELNET:
                    settings['protocol_specific'] = _extract_telnet_settings(connection)
                elif protocol == ProtocolType.KUBERNETES:
                    settings['protocol_specific'] = _extract_kubernetes_settings(connection)
                elif protocol in ProtocolType.DATABASE:
                    settings['protocol_specific'] = _extract_database_settings(connection, protocol)

            # allowSupplyHost is at top level of pamSettings value, not inside connection
            settings['allowSupplyHost'] = pam_settings_value.get('allowSupplyHost', False)

    # CLI overrides always take precedence (applied after pamSettings extraction)
    # These are validated in launch.py before being passed here
    logging.debug(f"DEBUG extract_terminal_settings: launch_credential_uid={launch_credential_uid}, current userRecordUid={settings.get('userRecordUid')}")
    if launch_credential_uid:
        settings['userRecordUid'] = launch_credential_uid
        logging.debug(f"Using launch credential from CLI override: {settings['userRecordUid']}")

    # Final validation: hostname must be present for connection to succeed
    # Note: userRecordUid is optional - if not present, _build_guacamole_connection_settings()
    # will fall back to credentials from the pamMachine record directly
    if not settings['hostname']:
        if settings['allowSupplyHost']:
            raise CommandError('pam launch',
                f'Hostname not found in record {record_uid}. Use --host to specify one.')
        else:
            raise CommandError('pam launch',
                f'Hostname not found in record {record_uid} and allowSupplyHost is not enabled.')

    return settings


def _extract_ssh_settings(connection: Dict[str, Any]) -> Dict[str, Any]:
    """Extract SSH-specific settings"""
    return {
        'publicHostKey': connection.get('publicHostKey', ''),
        'executeCommand': connection.get('executeCommand', ''),
        'sftpEnabled': connection.get('sftpEnabled', False),
    }


def _extract_telnet_settings(connection: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Telnet-specific settings"""
    return {
        'usernameRegex': connection.get('usernameRegex', ''),
        'passwordRegex': connection.get('passwordRegex', ''),
    }


def _extract_kubernetes_settings(connection: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Kubernetes-specific settings"""
    return {
        'namespace': connection.get('namespace', 'default'),
        'pod': connection.get('pod', ''),
        'container': connection.get('container', ''),
        'ignoreServerCertificate': connection.get('ignoreServerCertificate', False),
        'caCertificate': connection.get('caCertificate', ''),
        'clientCertificate': connection.get('clientCertificate', ''),
        'clientKey': connection.get('clientKey', ''),
    }


def _extract_database_settings(connection: Dict[str, Any], protocol: str) -> Dict[str, Any]:
    """Extract database-specific settings"""
    settings = {
        'defaultDatabase': connection.get('defaultDatabase', ''),
        'disableCsvExport': connection.get('disableCsvExport', False),
        'disableCsvImport': connection.get('disableCsvImport', False),
    }

    # Add protocol-specific database settings
    if protocol == ProtocolType.MYSQL:
        settings['useSSL'] = connection.get('useSSL', False)
    elif protocol == ProtocolType.POSTGRESQL:
        settings['useSSL'] = connection.get('useSSL', False)
    elif protocol == ProtocolType.SQLSERVER:
        settings['useSSL'] = connection.get('useSSL', True)  # SQL Server typically uses SSL by default

    return settings


def create_connection_context(params: KeeperParams,
                             record_uid: str,
                             gateway_uid: str,
                             protocol: str,
                             settings: Dict[str, Any],
                             connect_as: Optional[str] = None) -> Dict[str, Any]:
    """
    Build connection context for WebRTC tunnel.

    Args:
        params: KeeperParams instance
        record_uid: Record UID
        gateway_uid: Gateway UID
        protocol: Protocol type
        settings: Terminal settings from extract_terminal_settings
        connect_as: Optional username to connect as (overrides record)

    Returns:
        Connection context dictionary ready for tunnel opening
    """
    context = {
        'protocol': protocol,
        'recordUid': record_uid,
        'controllerUid': gateway_uid,
        'targetHost': {
            'hostname': settings['hostname'],
            'port': settings['port']
        },
        'clipboard': settings['clipboard'],
        'terminal': settings['terminal'],
        'recording': settings['recording'],
        'connectAs': connect_as,
        'conversationType': _get_conversation_type(protocol),
        # Credential supply flags
        'allowSupplyUser': settings.get('allowSupplyUser', False),
        'allowSupplyHost': settings.get('allowSupplyHost', False),
        # Linked pamUser record UID for credential extraction
        'userRecordUid': settings.get('userRecordUid'),
    }

    logging.debug(f"DEBUG create_connection_context: userRecordUid={context.get('userRecordUid')}")

    # Add protocol-specific settings
    if protocol == ProtocolType.SSH:
        context['ssh'] = settings['protocol_specific']
    elif protocol == ProtocolType.TELNET:
        context['telnet'] = settings['protocol_specific']
    elif protocol == ProtocolType.KUBERNETES:
        context['kubernetes'] = settings['protocol_specific']
    elif protocol in ProtocolType.DATABASE:
        context['database'] = settings['protocol_specific']
        context['database']['type'] = protocol

    return context


def _get_launch_credential_uid(params: 'KeeperParams', record_uid: str) -> Optional[str]:
    """
    Find the launch credential UID for a PAM record using the DAG.

    When a pamMachine record has both administrative credentials and launch credentials,
    we need to use the launch credential (marked with is_launch_credential=True in DAG).
    This function queries the DAG to find the correct credential.

    Args:
        params: KeeperParams instance
        record_uid: UID of the pamMachine record

    Returns:
        UID of the launch credential pamUser record, or None if not found
    """
    try:
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, record_uid,
                         transmission_key=transmission_key)

        if not tdag.linking_dag.has_graph:
            logging.debug(f"No DAG graph loaded for record {record_uid}")
            return None

        record_vertex = tdag.linking_dag.get_vertex(record_uid)
        if record_vertex is None:
            logging.debug(f"Record vertex not found in DAG for {record_uid}")
            return None

        # Find all ACL links where Head is recordUID
        # Look for the credential marked as is_launch_credential=True
        launch_credential = None
        admin_credential = None
        all_linked = []

        for user_vertex in record_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(record_vertex, EdgeType.ACL)
            if acl_edge:
                try:
                    content = acl_edge.content_as_dict or {}
                    is_admin = content.get('is_admin', False)
                    is_launch = content.get('is_launch_credential', None)

                    all_linked.append(user_vertex.uid)

                    if is_launch and launch_credential is None:
                        launch_credential = user_vertex.uid
                        logging.debug(f"Found launch credential via DAG: {launch_credential}")

                    if is_admin and admin_credential is None:
                        admin_credential = user_vertex.uid
                        logging.debug(f"Found admin credential via DAG: {admin_credential}")

                except Exception as e:
                    logging.debug(f"Error parsing ACL edge content: {e}")

        # Prefer launch credential, fall back to first linked if no specific launch credential
        if launch_credential:
            logging.debug(f"Using launch credential from DAG: {launch_credential}")
            return launch_credential
        elif all_linked:
            # If no explicit launch credential but we have linked users,
            # prefer non-admin credential
            for uid in all_linked:
                if uid != admin_credential:
                    logging.debug(f"Using non-admin linked credential: {uid}")
                    return uid
            # Fall back to first linked
            logging.debug(f"Using first linked credential: {all_linked[0]}")
            return all_linked[0]

        return None

    except Exception as e:
        logging.debug(f"Error accessing DAG for launch credential: {e}")
        return None


def _get_conversation_type(protocol: str) -> str:
    """Map protocol to Guacamole conversation type"""
    # Map our protocol names to Guacamole conversation types
    mapping = {
        ProtocolType.SSH: 'ssh',
        ProtocolType.TELNET: 'telnet',
        ProtocolType.KUBERNETES: 'kubernetes',
        ProtocolType.MYSQL: 'mysql',
        ProtocolType.POSTGRESQL: 'postgresql',
        ProtocolType.SQLSERVER: 'sql-server',
    }
    return mapping.get(protocol, protocol)


def _extract_user_record_credentials(
    params: 'KeeperParams',
    user_record_uid: str
) -> Dict[str, Any]:
    """
    Extract credentials from a linked pamUser record.

    This function extracts username, password, private key, and passphrase from
    a pamUser record. For SSH connections, the private key is extracted using
    try_extract_private_key() which checks keyPair fields, notes, custom fields,
    and attachments. The password field serves as the passphrase for encrypted
    private keys.

    Args:
        params: KeeperParams instance
        user_record_uid: UID of the linked pamUser record

    Returns:
        Dictionary containing:
        - username: Login username (str)
        - password: Password (str)
        - private_key: PEM-encoded private key if found (str or None)
        - passphrase: Passphrase for encrypted private key (str or None)
    """
    result = {
        'username': '',
        'password': '',
        'private_key': None,
        'passphrase': None,
    }

    # Load the pamUser record
    user_record = vault.KeeperRecord.load(params, user_record_uid)
    if not isinstance(user_record, vault.TypedRecord):
        logging.warning(f"User record {user_record_uid} is not a TypedRecord")
        return result

    # Extract username from login field
    login_field = user_record.get_typed_field('login')
    if login_field:
        result['username'] = login_field.get_default_value(str) or ''

    # Extract password
    password_field = user_record.get_typed_field('password')
    if password_field:
        result['password'] = password_field.get_default_value(str) or ''

    # Extract private key using try_extract_private_key()
    # This function checks: keyPair field, notes, custom fields (text, multiline, secret, note), and attachments
    key_result = try_extract_private_key(params, user_record)
    if key_result:
        private_key, passphrase = key_result
        result['private_key'] = private_key
        # The password field serves as the passphrase for encrypted private keys
        # If try_extract_private_key returned a passphrase (from password field), use it
        # Otherwise, use the password we already extracted
        result['passphrase'] = passphrase if passphrase else (result['password'] if result['password'] else None)

    logging.debug(
        f"Extracted credentials from pamUser {user_record_uid}: "
        f"username={'(set)' if result['username'] else '(empty)'}, "
        f"password={'(set)' if result['password'] else '(empty)'}, "
        f"private_key={'(set)' if result['private_key'] else '(empty)'}"
    )

    return result


def _build_guacamole_connection_settings(
    params: 'KeeperParams',
    record_uid: str,
    protocol: str,
    settings: Dict[str, Any],
    context: Dict[str, Any],
    screen_info: Dict[str, int],
    user_record_uid: Optional[str] = None,
    credential_type: str = 'linked',
) -> Dict[str, Any]:
    """
    Build connection settings for Guacamole handshake in PythonHandler mode.

    When guacd sends 'args' instruction requesting connection parameters,
    we respond with 'connect' containing these values.

    Credential handling follows gateway behavior:
    - If credential_type='linked' and user_record_uid is provided, extract credentials
      from the linked pamUser record (username, password, private key)
    - If credential_type='userSupplied', leave credentials empty (user provides on-the-fly)
    - SSH authentication precedence: private key is tried first, then password
      (standard SSH behavior handled by guacd)

    Args:
        params: KeeperParams instance
        record_uid: Record UID (pamMachine record)
        protocol: Protocol type (ssh, telnet, mysql, etc.)
        settings: Terminal settings from extract_terminal_settings()
        context: Connection context from create_connection_context()
        screen_info: Screen dimensions dict
        user_record_uid: Optional UID of linked pamUser record for credentials
        credential_type: Credential type ('linked', 'userSupplied', 'ephemeral')

    Returns:
        Dictionary with connection settings for GuacamoleHandler
    """
    username = ''
    password = ''
    private_key = None
    passphrase = None

    logging.debug(f"DEBUG _build_guacamole_connection_settings: credential_type={credential_type}, user_record_uid={user_record_uid}")

    # Determine how to get credentials based on credential_type
    if credential_type == 'userSupplied':
        # User-supplied credentials: leave empty, user will provide via guacamole prompt
        logging.debug("Using userSupplied credential type - leaving credentials empty")
    elif user_record_uid:
        # Extract credentials from linked pamUser record
        user_creds = _extract_user_record_credentials(params, user_record_uid)
        username = user_creds['username']
        password = user_creds['password']
        private_key = user_creds['private_key']
        passphrase = user_creds['passphrase']
        logging.debug(f"Using credentials from linked pamUser record: {user_record_uid}")
    else:
        # Fallback: Get credentials from the pamMachine record directly
        # (backward compatibility for records without linked pamUser)
        record = vault.KeeperRecord.load(params, record_uid)
        if isinstance(record, vault.TypedRecord):
            login_field = record.get_typed_field('login')
            if login_field:
                username = login_field.get_default_value(str) or ''

            password_field = record.get_typed_field('password')
            if password_field:
                password = password_field.get_default_value(str) or ''
        logging.debug("Using credentials from pamMachine record (no linked pamUser)")

    # Build guacd parameters dictionary
    # These map to guacd's expected parameter names
    # The 'protocol' field is required for guacd to know which backend to use
    guacd_protocol = _get_conversation_type(protocol)  # Convert to guacd protocol name (e.g., ssh, telnet)
    guacd_params = {
        'protocol': guacd_protocol,  # Required: tells guacd which protocol handler to use
        'hostname': settings.get('hostname', ''),
        'port': str(settings.get('port', '')),
        'username': username,
        'password': password,
    }

    logging.debug(f"DEBUG guacd_params built: username={'(set)' if username else '(empty)'}, password={'(set)' if password else '(empty)'}")

    # Add private key for SSH protocol if available
    # SSH authentication precedence: guacd/SSH tries private key first, then password
    # Both can be present simultaneously - this matches gateway behavior
    if protocol == ProtocolType.SSH and private_key:
        guacd_params['private-key'] = private_key
        if passphrase:
            guacd_params['passphrase'] = passphrase
        logging.debug("Added private-key to guacd_params for SSH authentication")

    # Add protocol-specific parameters
    protocol_specific = settings.get('protocol_specific', {})

    if protocol == ProtocolType.SSH:
        # SSH-specific params
        if protocol_specific.get('publicHostKey'):
            guacd_params['host-key'] = protocol_specific['publicHostKey']
        if protocol_specific.get('executeCommand'):
            guacd_params['command'] = protocol_specific['executeCommand']
        # Enable SFTP if configured
        if protocol_specific.get('sftpEnabled'):
            guacd_params['enable-sftp'] = 'true'

    elif protocol == ProtocolType.TELNET:
        # Telnet-specific params
        if protocol_specific.get('usernameRegex'):
            guacd_params['username-regex'] = protocol_specific['usernameRegex']
        if protocol_specific.get('passwordRegex'):
            guacd_params['password-regex'] = protocol_specific['passwordRegex']

    elif protocol == ProtocolType.KUBERNETES:
        # Kubernetes-specific params
        if protocol_specific.get('namespace'):
            guacd_params['namespace'] = protocol_specific['namespace']
        if protocol_specific.get('pod'):
            guacd_params['pod'] = protocol_specific['pod']
        if protocol_specific.get('container'):
            guacd_params['container'] = protocol_specific['container']
        if protocol_specific.get('caCertificate'):
            guacd_params['ca-cert'] = protocol_specific['caCertificate']
        if protocol_specific.get('clientCertificate'):
            guacd_params['client-cert'] = protocol_specific['clientCertificate']
        if protocol_specific.get('clientKey'):
            guacd_params['client-key'] = protocol_specific['clientKey']
        if protocol_specific.get('ignoreServerCertificate'):
            guacd_params['ignore-cert'] = 'true'

    elif protocol in ProtocolType.DATABASE:
        # Database-specific params
        if protocol_specific.get('defaultDatabase'):
            guacd_params['database'] = protocol_specific['defaultDatabase']

    # Terminal display settings
    terminal_settings = settings.get('terminal', {})
    if terminal_settings.get('colorScheme'):
        guacd_params['color-scheme'] = terminal_settings['colorScheme']
    if terminal_settings.get('fontSize'):
        guacd_params['font-size'] = terminal_settings['fontSize']

    # Clipboard settings
    clipboard_settings = settings.get('clipboard', {})
    if clipboard_settings.get('disableCopy'):
        guacd_params['disable-copy'] = 'true'
    if clipboard_settings.get('disablePaste'):
        guacd_params['disable-paste'] = 'true'

    # Build final connection settings
    connection_settings = {
        'protocol': protocol,
        'hostname': settings.get('hostname', ''),
        'port': settings.get('port', 22),
        'width': screen_info.get('pixel_width', 800),
        'height': screen_info.get('pixel_height', 600),
        'dpi': screen_info.get('dpi', 96),
        'guacd_params': guacd_params,
        # Supported mimetypes for terminal sessions
        'audio_mimetypes': [],  # No audio for terminal
        'video_mimetypes': [],  # No video for terminal
        'image_mimetypes': ['image/png', 'image/jpeg', 'image/webp'],
    }

    logging.debug(f"Built Guacamole connection settings for {protocol}: "
                  f"hostname={settings.get('hostname')}, port={settings.get('port')}, "
                  f"width={connection_settings['width']}x{connection_settings['height']}")

    return connection_settings


def _open_terminal_webrtc_tunnel(params: KeeperParams,
                                 record_uid: str,
                                 gateway_uid: str,
                                 protocol: str,
                                 settings: Dict[str, Any],
                                 context: Dict[str, Any],
                                 **kwargs) -> Dict[str, Any]:
    """
    Open a WebRTC tunnel for terminal/Guacamole connection.

    This function adapts start_rust_tunnel for terminal protocols by:
    - Using the protocol-specific conversation type
    - Not requiring local socket listening (Guacamole renders server-side)
    - Setting up for text/image streaming only (no audio/video)

    Args:
        params: KeeperParams instance
        record_uid: Record UID
        gateway_uid: Gateway UID
        protocol: Protocol type (ssh, telnet, etc.)
        settings: Terminal settings
        context: Connection context

    Returns:
        Dictionary with tunnel information:
        - success: bool
        - tube_id: str
        - conversation_id: str
        - tube_registry: PyTubeRegistry
        - signal_handler: TunnelSignalHandler
        - websocket_thread: Thread
        - error: error message if failed
    """
    logging.debug(f"{bcolors.HIGHINTENSITYWHITE}Establishing {protocol.upper()} terminal connection via WebRTC...{bcolors.ENDC}")
    screen_info = DEFAULT_SCREEN_INFO

    try:
        router_token = None

        # Get encryption seed from record
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            return {"success": False, "error": "Invalid record type"}

        # Get traffic encryption seed
        seed_field = record.get_typed_field('trafficEncryptionSeed')
        if seed_field:
            seed = seed_field.get_default_value()
            if isinstance(seed, str):
                seed = base64_to_bytes(seed)
        else:
            # Generate a random seed if not present
            import secrets
            seed = secrets.token_bytes(32)
            logging.debug("No trafficEncryptionSeed found, using generated seed")

        # Generate 128-bit (16-byte) random nonce
        nonce = os.urandom(MAIN_NONCE_LENGTH)

        # Derive the encryption key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SYMMETRIC_KEY_LENGTH,  # 256-bit key
            salt=nonce,
            info=b"KEEPER_TUNNEL_ENCRYPT_AES_GCM_128",
            backend=default_backend()
        ).derive(seed)
        symmetric_key = AESGCM(hkdf)

        # Get tube registry (Rust WebRTC library)
        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            return {"success": False, "error": "Rust WebRTC library (keeper_pam_webrtc_rs) not available"}

        # For terminal connections, we act as client (not server mode)
        tube_registry.set_server_mode(False)

        # Generate conversation ID
        conversation_id_original = GatewayAction.generate_conversation_id()
        conversation_id_bytes = url_safe_str_to_bytes(conversation_id_original)
        conversation_id = base64.b64encode(conversation_id_bytes).decode('utf-8')

        logging.debug(f"Generated conversation_id_original: {conversation_id_original}")
        logging.debug(f"Base64 encoded conversation_id: {conversation_id}")

        base64_nonce = bytes_to_base64(nonce)

        # Get relay server configuration
        relay_url = 'krelay.' + params.server
        krelay_url = os.getenv('KRELAY_URL')
        if krelay_url:
            relay_url = krelay_url

        response = router_get_relay_access_creds(params=params, expire_sec=60000000)
        if response is None:
            return {"success": False, "error": "Failed to get relay access credentials"}

        # Create WebRTC settings for terminal (no local socket needed)
        webrtc_settings = {
            "turn_only": False,
            "relay_url": relay_url,
            "stun_url": f"stun:{relay_url}:3478",
            "turn_url": f"turn:{relay_url}:3478",
            "turn_username": response.username,
            "turn_password": response.password,
            "conversationType": context['conversationType'],  # ssh, telnet, kubernetes, mysql, etc.
            "local_listen_addr": "",  # No local socket for terminal
            "target_host": settings['hostname'],
            "target_port": settings['port'],
            "socks_mode": False,  # Terminal connections don't use SOCKS
            "control_channel_label": "control",  # Ensure WebRTC data channel label matches gateway expectation
            "callback_token": bytes_to_base64(nonce)
        }

        # Debug: Log settings to verify control_channel_label is present
        logging.debug(f"WebRTC settings before create_tube: {json.dumps(webrtc_settings, default=str)}")

        # Register the encryption key in the global conversation store
        register_conversation_key(conversation_id, symmetric_key)
        # Create a temporary tunnel session
        import uuid
        temp_tube_id = str(uuid.uuid4())

        # Pre-create tunnel session to buffer early ICE candidates
        conversation_type = context.get('conversationType', protocol)

        tunnel_session = TunnelSession(
            tube_id=temp_tube_id,
            conversation_id=conversation_id,
            gateway_uid=gateway_uid,
            symmetric_key=symmetric_key,
            offer_sent=False,
            host=None,  # No local host for terminal
            port=None   # No local port for terminal
        )

        # Register the temporary session
        register_tunnel_session(temp_tube_id, tunnel_session)

        # Determine trickle ICE setting from kwargs
        no_trickle_ice = kwargs.get('no_trickle_ice', False)
        trickle_ice = not no_trickle_ice

        # Create signal handler for Rust events
        signal_handler = TunnelSignalHandler(
            params=params,
            record_uid=record_uid,
            gateway_uid=gateway_uid,
            symmetric_key=symmetric_key,
            base64_nonce=base64_nonce,
            conversation_id=conversation_id,
            tube_registry=tube_registry,
            tube_id=temp_tube_id,
            trickle_ice=trickle_ice
        )

        # Store signal handler reference
        tunnel_session.signal_handler = signal_handler  # type: ignore[assignment]

        logging.debug(f"{bcolors.OKBLUE}Creating WebRTC offer for {protocol} connection...{bcolors.ENDC}")
        if trickle_ice:
            logging.debug("Using trickle ICE for real-time candidate exchange")
        else:
            logging.debug("Trickle ICE disabled - using standard ICE")

        # Check if PythonHandler mode is requested
        use_python_handler = kwargs.get('use_python_handler', True)  # Default to True for new mode
        python_handler = None
        handler_callback = None

        if use_python_handler:
            # Import and create PythonHandler for simplified Guacamole protocol handling
            from .python_handler import create_python_handler

            logging.debug("Using PythonHandler mode - Rust handles control frames automatically")

            # Set conversationType to "python_handler" to enable PythonHandler protocol mode in Rust
            # The actual protocol (ssh, telnet, etc.) is passed via guacd_params["protocol"]
            # IMPORTANT: Only update webrtc_settings - gateway needs the actual protocol type (ssh, telnet, etc.)
            # The gateway validates conversationType against valid protocol types, not "python_handler"
            webrtc_settings["conversationType"] = "python_handler"
            # Keep context['conversationType'] as the actual protocol (ssh, telnet, etc.) for gateway
            # Do NOT change context["conversationType"] - gateway needs the real protocol type
            logging.debug(f"Set webrtc_settings conversationType to 'python_handler' (gateway will receive: {context['conversationType']})")

            # Determine credential type based on allowSupplyHost, allowSupplyUser flags
            # This matches gateway validation logic:
            # - If allowSupplyHost=True: must be 'userSupplied'
            # - If allowSupplyUser=True and no linked user: use 'userSupplied'
            # - If linked user present: use 'linked'
            allow_supply_host = context.get('allowSupplyHost', False)
            allow_supply_user = context.get('allowSupplyUser', False)
            user_record_uid = context.get('userRecordUid')

            logging.debug(f"DEBUG credential determination: allow_supply_host={allow_supply_host}, allow_supply_user={allow_supply_user}, user_record_uid={user_record_uid}")

            # credential_type is None when using pamMachine credentials directly (backward compatible)
            # Priority: if user_record_uid is provided (from CLI or record), use 'linked' to send those credentials
            credential_type = None
            if user_record_uid:
                # Linked user present (from CLI --user or record) - use linked credentials
                credential_type = 'linked'
                logging.debug(f"Using 'linked' credential type with userRecordUid: {user_record_uid}")
            elif allow_supply_host or allow_supply_user:
                # No credentials provided but supply flags enabled - user must provide interactively
                credential_type = 'userSupplied'
                logging.debug("No credentials provided, allowSupply enabled - using 'userSupplied' credential type")
            else:
                # No linked user, no supply flags - use pamMachine credentials directly
                logging.debug("No linked user or supply flags - using pamMachine credentials directly")

            # Build connection settings for Guacamole handshake
            # These are used when guacd sends 'args' instruction
            connection_settings = _build_guacamole_connection_settings(
                params=params,
                record_uid=record_uid,
                protocol=protocol,
                settings=settings,
                context=context,
                screen_info=screen_info,
                user_record_uid=user_record_uid,
                credential_type=credential_type,
            )

            # Create the handler and callback
            handler_callback, python_handler = create_python_handler(
                tube_registry=tube_registry,
                conversation_id=conversation_id,
                conn_no=1,
                connection_settings=connection_settings,
            )

            logging.debug(f"Created PythonHandler for conversation {conversation_id}")
            logging.debug(f"DEBUG: handler_callback is {'SET' if handler_callback else 'None'}, type={type(handler_callback)}")
            logging.debug(f"DEBUG: python_handler is {'SET' if python_handler else 'None'}")
            logging.debug(f"DEBUG: connection_settings has {len(connection_settings)} keys: {list(connection_settings.keys())}")

        # Create the tube to get the WebRTC offer
        logging.debug(f"DEBUG: Calling create_tube with handler_callback={'SET' if handler_callback else 'None'}")
        logging.debug(f"DEBUG: Calling create_tube with handler_callback={'SET' if handler_callback else 'None'}")
        logging.debug(f"DEBUG: webrtc_settings['conversationType'] = {webrtc_settings.get('conversationType')}")
        offer = tube_registry.create_tube(
            conversation_id=conversation_id,
            settings=webrtc_settings,
            trickle_ice=trickle_ice,
            callback_token=webrtc_settings["callback_token"],
            ksm_config="",
            krelay_server=relay_url,
            client_version="Commander-Python-Terminal",
            offer=None,  # Let Rust create the offer
            signal_callback=signal_handler.signal_from_rust,
            handler_callback=handler_callback,  # PythonHandler callback (None if not using)
        )

        if not offer or 'tube_id' not in offer or 'offer' not in offer:
            error_msg = "Failed to create tube"
            if offer:
                error_msg = offer.get('error', error_msg)
            # Clean up temporary session on failure
            unregister_tunnel_session(temp_tube_id)
            unregister_conversation_key(conversation_id)
            return {"success": False, "error": error_msg}

        commander_tube_id = offer['tube_id']
        logging.debug(f"Created tube with ID: {commander_tube_id}")
        logging.debug(f"Conversation ID for this tube: {conversation_id_original}")
        logging.debug(f"Data channel will be named: {conversation_id}")

        # Update signal handler and tunnel session with real tube ID
        signal_handler.tube_id = commander_tube_id
        tunnel_session.tube_id = commander_tube_id

        # Unregister temporary session and register with real tube ID
        unregister_tunnel_session(temp_tube_id)
        register_tunnel_session(commander_tube_id, tunnel_session)

        logging.debug(f"Registered encryption key for conversation: {conversation_id}")
        logging.debug(f"Expecting WebSocket responses for conversation ID: {conversation_id}")

        # Start WebSocket listener
        websocket_thread = start_websocket_listener(params, tube_registry, timeout=300, gateway_uid=gateway_uid, tunnel_session=tunnel_session)

        # Wait a moment for WebSocket to establish connection
        import time
        time.sleep(1.5)

        # Send offer to gateway via HTTP POST
        logging.debug(f"{bcolors.OKBLUE}Sending {protocol} connection offer to gateway...{bcolors.ENDC}")

        # Prepare the offer data with terminal-specific parameters
        # Match webvault format: host, size, audio, video, image (for guacd configuration)
        # These parameters are needed by Gateway to configure guacd BEFORE OpenConnection
        import shutil

        raw_columns = DEFAULT_TERMINAL_COLUMNS
        raw_rows = DEFAULT_TERMINAL_ROWS
        # Get terminal size for Guacamole size parameter
        try:
            terminal_size = shutil.get_terminal_size(fallback=(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS))
            raw_columns = terminal_size.columns
            raw_rows = terminal_size.lines
        except Exception:
            logging.debug("Falling back to default terminal size for offer payload")
        screen_info = _build_screen_info(raw_columns, raw_rows)
        logging.debug(
            f"Using terminal metrics columns={screen_info['columns']} rows={screen_info['rows']} -> "
            f"{screen_info['pixel_width']}x{screen_info['pixel_height']}px @ {screen_info['dpi']}dpi"
        )

        offer_payload = offer.get("offer")
        decoded_offer_bytes = None
        decoded_offer_text = None
        use_re_encoded_offer = False

        if isinstance(offer_payload, str):
            try:
                # Offers coming from the Rust module are base64-encoded SDP blobs.
                decoded_offer_bytes = base64.b64decode(offer_payload, validate=True)
                decoded_offer_text = decoded_offer_bytes.decode('utf-8')
                use_re_encoded_offer = True
            except Exception:
                decoded_offer_text = offer_payload
        elif isinstance(offer_payload, bytes):
            decoded_offer_text = offer_payload.decode('utf-8', errors='ignore')

        if decoded_offer_text is None:
            decoded_offer_text = offer_payload

        offer_sdp = _ensure_max_message_size_attribute(decoded_offer_text)

        if offer_sdp is None:
            offer_payload = offer.get("offer")
        elif use_re_encoded_offer:
            offer_payload = base64.b64encode(offer_sdp.encode('utf-8')).decode('utf-8')
        else:
            offer_payload = offer_sdp

        offer_data = {
            "offer": offer_payload,
            "audio": ["audio/L8", "audio/L16"],  # Supported audio codecs
            "video": [],  # Supported video codecs - None for terminal
            "size": [screen_info['pixel_width'], screen_info['pixel_height'], screen_info['dpi']],  # [width, height, dpi]
            "image": ["image/jpeg", "image/png", "image/webp"],  # Supported image formats
            # CRITICAL: Gateway needs 'host' to configure guacd connection
            "host": {
                "hostName": settings['hostname'],
                "port": settings['port']
            }
            # these are not sent by webvault during open connection for terminal connections
            # "protocol": protocol,
            # "terminalSettings": {
            #     "colorScheme": settings['terminal']['colorScheme'],
            #     "fontSize": settings['terminal']['fontSize'],
            # }
        }

        # TODO: Add protocol-specific settings to offer
        # if 'protocol_specific' in settings and settings['protocol_specific']:
        #     offer_data["protocolSettings"] = settings['protocol_specific']

        # Log what we're sending in the initial offer
        logging.debug(f"Sending initial offer with connection parameters: {json.dumps(offer_data, indent=2)}")

        string_data = json.dumps(offer_data)
        logging.debug(f"payload.inputs.data JSON before encryption: {string_data}")
        bytes_data = string_to_bytes(string_data)
        encrypted_data = tunnel_encrypt(symmetric_key, bytes_data)

        # Get userRecordUid and credential flags from context (extracted in extract_terminal_settings)
        user_record_uid = context.get('userRecordUid')
        allow_supply_host = context.get('allowSupplyHost', False)
        allow_supply_user = context.get('allowSupplyUser', False)

        # Determine credential type for gateway inputs
        # IMPORTANT: Priority must match the guacd credentials logic above:
        # 1. If user_record_uid is set (from CLI or record), use 'linked' - credentials come from that record
        # 2. If allowSupply* but no user_record_uid, use 'userSupplied' - user will type at prompt
        # 3. Otherwise, use pamMachine credentials directly (no credentialType)
        credential_type_for_gateway = None
        if user_record_uid:
            # Credentials will come from linked pamUser record (via python_handler)
            credential_type_for_gateway = 'linked'
            logging.debug(f"Using 'linked' credential type for gateway with userRecordUid: {user_record_uid}")
        elif allow_supply_host or allow_supply_user:
            # No credentials provided, user must type at prompt
            credential_type_for_gateway = 'userSupplied'
            logging.debug("No credentials provided, allowSupply enabled - using 'userSupplied' for gateway")
        else:
            logging.debug(f"No linked pamUser for record {record_uid} - using pamMachine credentials directly")

        time.sleep(1)  # Allow time for WebSocket listener to start

        # Send offer via HTTP POST - two paths: streaming vs non-streaming
        try:
            # Build inputs dict - matching working session format
            inputs = {
                "recordUid": record_uid,
                'kind': 'start',
                'base64Nonce': base64_nonce,
                'conversationType': context['conversationType'],
                "data": encrypted_data,
                "trickleICE": trickle_ice,  # Set trickle ICE flag
            }

            # Add credential type and userRecordUid based on mode
            if credential_type_for_gateway == 'linked' and user_record_uid:
                inputs['credentialType'] = 'linked'
                inputs['userRecordUid'] = user_record_uid
            elif credential_type_for_gateway == 'userSupplied':
                inputs['credentialType'] = 'userSupplied'
                # For userSupplied, set allow_supply_user flag in connect_as_settings
                # This matches gateway behavior (line 1203 in tunnel_vault_record.py)
                inputs['allowSupplyUser'] = True
                logging.debug("Using userSupplied credential type - user will provide credentials")
            # else: no credentialType - gateway uses pamMachine credentials directly (backward compatible)

            # Router token is no longer extracted from cookies (removed in commit 338a9fda)
            # Router affinity is now handled server-side

            # Generate messageId from conversationId (replace + with -, / with _)
            message_id = GatewayAction.conversation_id_to_message_id(conversation_id_original)
            logging.debug(f"Generated messageId: {message_id} from conversationId: {conversation_id_original}")

            # Two paths: streaming vs non-streaming
            if trickle_ice:
                # Streaming path: Response will come via WebSocket
                router_response = router_send_action_to_gateway(
                    params=params,
                    destination_gateway_uid_str=gateway_uid,
                    gateway_action=GatewayActionWebRTCSession(
                        conversation_id=conversation_id_original,
                        inputs=inputs,
                        message_id=message_id
                    ),
                    message_type=pam_pb2.CMT_CONNECT,
                    is_streaming=True,  # Response will come via WebSocket
                    gateway_timeout=30000
                )

                logging.debug(f"{bcolors.OKGREEN}Offer sent to gateway (streaming mode){bcolors.ENDC}")

                # Mark offer as sent
                signal_handler.offer_sent = True
                tunnel_session.offer_sent = True

                # Send any buffered ICE candidates
                if tunnel_session.buffered_ice_candidates:
                    logging.debug(f"Flushing {len(tunnel_session.buffered_ice_candidates)} buffered ICE candidates")
                    for candidate in tunnel_session.buffered_ice_candidates:
                        signal_handler._send_ice_candidate_immediately(candidate, commander_tube_id)
                    tunnel_session.buffered_ice_candidates.clear()

                logging.debug(f"{bcolors.OKGREEN}Terminal connection established for {protocol.upper()}{bcolors.ENDC}")
                logging.debug(f"{bcolors.OKBLUE}Connection state: {bcolors.ENDC}gathering candidates...")

                return {
                    "success": True,
                    "tube_id": commander_tube_id,
                    "conversation_id": conversation_id,
                    "tube_registry": tube_registry,
                    "signal_handler": signal_handler,
                    "websocket_thread": websocket_thread,
                    "status": "connecting",
                    "screen_info": screen_info,
                    "python_handler": python_handler,  # PythonHandler for simplified guac protocol
                    "use_python_handler": use_python_handler,
                }
            else:
                # Non-streaming path: Handle response immediately
                router_response = router_send_action_to_gateway(
                    params=params,
                    destination_gateway_uid_str=gateway_uid,
                    gateway_action=GatewayActionWebRTCSession(
                        conversation_id=conversation_id_original,
                        inputs=inputs,
                        message_id=message_id
                    ),
                    message_type=pam_pb2.CMT_CONNECT,
                    is_streaming=False,  # Response comes immediately in HTTP response
                    gateway_timeout=30000
                )

                logging.debug(f"{bcolors.OKGREEN}Offer sent to gateway (non-streaming mode){bcolors.ENDC}")
                logging.debug(f"Router response: {router_response}")

                # Handle immediate response
                if router_response and router_response.get('response'):
                    response_dict = router_response['response']
                    logging.debug(f"Received immediate response from gateway: {response_dict}")
                    response_payload = response_dict.get('payload') if isinstance(response_dict, dict) else "{}"
                    if isinstance(response_payload, str):
                        try:
                            response_payload = json.loads(response_payload)
                        except json.JSONDecodeError:
                            response_payload = {}

                    # Check for errors in response
                    if not (response_payload.get('is_ok') or response_payload.get('isOk')):
                        error_msg = response_payload.get('error', 'Unknown error from gateway')
                        raise Exception(f"Gateway error: {error_msg} Payload: {response_payload}")

                    # Decrypt and handle payload.data if present (contains SDP answer)
                    if response_payload.get('is_ok') and response_payload.get('data'):
                        data_field = response_payload.get('data', '')

                        # Check if this is a plain text acknowledgment (not encrypted)
                        if isinstance(data_field, str) and (
                            "ice candidate" in data_field.lower() or
                            "buffered" in data_field.lower() or
                            "connected" in data_field.lower() or
                            "disconnected" in data_field.lower() or
                            "error" in data_field.lower() or
                            data_field.endswith(conversation_id_original)
                        ):
                            logging.debug(f"Received plain text acknowledgment: {data_field}")
                        else:
                            # This is encrypted data - decrypt it
                            encrypted_data = data_field
                            if encrypted_data:
                                logging.debug(f"Found encrypted data in response, length: {len(encrypted_data)}")
                                try:
                                    decrypted_data = tunnel_decrypt(symmetric_key, encrypted_data)
                                    if decrypted_data:
                                        data_text = bytes_to_string(decrypted_data).replace("'", '"')
                                        logging.debug(f"Successfully decrypted data for {conversation_id_original}, length: {len(data_text)}")

                                        # Parse JSON
                                        try:
                                            data_json = json.loads(data_text)

                                            # Ensure data_json is a dictionary
                                            if isinstance(data_json, dict):
                                                logging.debug(f"🔓 Decrypted payload type: {data_json.get('type', 'unknown')}, keys: {list(data_json.keys())}")

                                                # Handle SDP answer
                                                if "answer" in data_json:
                                                    answer_sdp = data_json.get('answer')
                                                    if answer_sdp:
                                                        logging.debug(f"Found SDP answer in non-streaming response, sending to Rust for conversation: {conversation_id_original}")
                                                        tube_registry.set_remote_description(commander_tube_id, answer_sdp, is_answer=True)

                                                        if hasattr(tunnel_session, "gateway_ready_event") and tunnel_session.gateway_ready_event is not None:
                                                            tunnel_session.gateway_ready_event.set()
                                                        logging.debug(f"{bcolors.OKBLUE}Connection state: {bcolors.ENDC}SDP answer received, connecting...")

                                                        # Send any buffered local ICE candidates now that we have the answer
                                                        if tunnel_session.buffered_ice_candidates:
                                                            logging.debug(f"Sending {len(tunnel_session.buffered_ice_candidates)} buffered ICE candidates after answer")
                                                            for candidate in tunnel_session.buffered_ice_candidates:
                                                                signal_handler._send_ice_candidate_immediately(candidate, commander_tube_id)
                                                            tunnel_session.buffered_ice_candidates.clear()
                                                elif "offer" in data_json or (data_json.get("type") == "offer"):
                                                    # Gateway is sending us an ICE restart offer (unlikely in non-streaming mode)
                                                    logging.warning(f"Received ICE restart offer in non-streaming mode - this is unexpected")
                                        except json.JSONDecodeError as e:
                                            logging.error(f"Failed to parse decrypted data as JSON: {e}")
                                            logging.debug(f"Data text: {data_text[:200]}...")
                                    else:
                                        logging.warning(f"Decryption returned None for conversation {conversation_id_original}")
                                except Exception as e:
                                    logging.error(f"Failed to decrypt data in non-streaming response: {e}")
                                    logging.debug(f"Data content: {encrypted_data[:100]}...")
                                    # Don't fail the connection if decryption fails - might be a plain text response

                # Mark offer as sent
                signal_handler.offer_sent = True
                tunnel_session.offer_sent = True

                # No ICE candidates to send in non-streaming mode (all candidates in SDP)
                logging.debug(f"{bcolors.OKGREEN}Terminal connection established for {protocol.upper()}{bcolors.ENDC}")
                logging.debug(f"{bcolors.OKBLUE}Connection state: {bcolors.ENDC}established (non-streaming mode)...")

                return {
                    "success": True,
                    "tube_id": commander_tube_id,
                    "conversation_id": conversation_id,
                    "tube_registry": tube_registry,
                    "signal_handler": signal_handler,
                    "websocket_thread": websocket_thread,
                    "status": "connected",
                    "router_response": router_response,
                    "screen_info": screen_info,
                    "python_handler": python_handler,  # PythonHandler for simplified guac protocol
                    "use_python_handler": use_python_handler,
                }

        except Exception as e:
            signal_handler.cleanup()
            unregister_tunnel_session(commander_tube_id)
            unregister_conversation_key(conversation_id)
            _notify_gateway_connection_close(params, router_token)
            return {"success": False, "error": f"Failed to send offer via HTTP: {e}"}

    except Exception as e:
        logging.error(f"Error opening terminal WebRTC tunnel: {e}")
        if 'conversation_id' in locals() and conversation_id:
            unregister_conversation_key(conversation_id)
        if 'signal_handler' in locals():
            signal_handler.cleanup()
        return {"success": False, "error": f"Failed to establish tunnel: {e}"}


def launch_terminal_connection(params: KeeperParams, 
                               record_uid: str, 
                               gateway_info: Dict[str, Any],
                               connect_as: Optional[str] = None,
                               **kwargs) -> Dict[str, Any]:
    """
    Launch a terminal connection for a PAM record.

    This is the main entry point for terminal connections. It:
    1. Detects the protocol
    2. Extracts settings
    3. Builds connection context
    4. Opens WebRTC tunnel
    5. Manages lifecycle

    Args:
        params: KeeperParams instance
        record_uid: Record UID
        gateway_info: Gateway information from find_gateway
        connect_as: Optional username to connect as

    Returns:
        Dictionary with connection status:
        - success: bool
        - protocol: str
        - context: connection context dict
        - tunnel: tunnel result dict
        - error: error message if failed

    Raises:
        CommandError: If connection cannot be established
    """
    try:
        # Step 1: Detect protocol
        protocol = detect_protocol(params, record_uid)
        if not protocol:
            raise CommandError('pam launch', f'Could not detect protocol for record {record_uid}')

        logging.debug(f"Detected protocol: {protocol}")

        # Step 2: Extract settings (with optional CLI overrides)
        settings = extract_terminal_settings(
            params,
            record_uid,
            protocol,
            launch_credential_uid=kwargs.get('launch_credential_uid'),
            custom_host=kwargs.get('custom_host'),
        )
        logging.debug(f"Extracted settings: hostname={settings['hostname']}, port={settings['port']}")

        # Step 3: Build connection context
        context = create_connection_context(
            params, 
            record_uid, 
            gateway_info['gateway_uid'], 
            protocol, 
            settings,
            connect_as
        )
        logging.debug(f"Built connection context for {protocol}")

        # Step 4: Open WebRTC tunnel
        tunnel_result = _open_terminal_webrtc_tunnel(
            params,
            record_uid,
            gateway_info['gateway_uid'],
            protocol,
            settings,
            context,
            **kwargs
        )

        if not tunnel_result.get('success'):
            error_msg = tunnel_result.get('error', 'Unknown error')
            raise CommandError('pam launch', f'Failed to open WebRTC tunnel: {error_msg}')

        logging.debug(f"Terminal connection established for {protocol}")
        logging.debug(f"Target: {settings['hostname']}:{settings['port']}")
        logging.debug(f"Gateway: {gateway_info['gateway_name']} ({gateway_info['gateway_uid']})")

        return {
            'success': True,
            'protocol': protocol,
            'context': context,
            'settings': settings,
            'gateway_info': gateway_info,
            'tunnel': {
                **tunnel_result,
                'registry': tunnel_result.get('tube_registry')  # Add registry for CLI mode
            },
            'message': f'Terminal connection established for {protocol}'
        }

    except CommandError:
        raise
    except Exception as e:
        logging.error(f"Error launching terminal connection: {e}")
        raise CommandError('pam launch', f'Failed to launch terminal connection: {e}')


