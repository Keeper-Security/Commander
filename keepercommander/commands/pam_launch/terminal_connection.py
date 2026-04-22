#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
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
import base64
import json
import secrets
import shutil
import time
import uuid
from typing import TYPE_CHECKING, Optional, Dict, Any

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes, url_safe_str_to_bytes, string_to_bytes, bytes_to_string

from ...error import CommandError
from ...constants import get_keeper_server_hostname
from ... import vault, api
from ...keeper_dag import EdgeType
from ...proto.APIRequest_pb2 import GetKsmPublicKeysRequest, GetKsmPublicKeysResponse
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
    get_keeper_tokens,
    MAIN_NONCE_LENGTH,
    SYMMETRIC_KEY_LENGTH,
    parse_keeper_webrtc_version_from_sdp,
    set_remote_description_and_parse_version,
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
from .python_handler import create_python_handler
from . import jit

if TYPE_CHECKING:
    from ...params import KeeperParams

from ..pam_import.base import ConnectionProtocol
from .connect_timing import (
    PamConnectTiming,
    websocket_backend_delay_sec,
    websocket_backend_delay_legacy_sec,
    pre_offer_delay_sec,
    offer_retry_extra_delay_sec,
)

# Sentinel for "dag_linked_uid not resolved yet" — ``None`` is a valid resolved
# result (no DAG-linked launch credential), so we need a distinct marker.
_DAG_UID_UNSET = object()

# Protocol sets and defaults (ConnectionProtocol from pam_import.base)
GRAPHICAL = {ConnectionProtocol.RDP.value, ConnectionProtocol.VNC.value}  # not supported by CLI
ALL_TERMINAL = {
    ConnectionProtocol.SSH.value,
    ConnectionProtocol.TELNET.value,
    ConnectionProtocol.KUBERNETES.value,
    ConnectionProtocol.MYSQL.value,
    ConnectionProtocol.POSTGRESQL.value,
    ConnectionProtocol.SQLSERVER.value,
}
DATABASE = {
    ConnectionProtocol.MYSQL.value,
    ConnectionProtocol.POSTGRESQL.value,
    ConnectionProtocol.SQLSERVER.value,
}

DEFAULT_PORTS = {
    ConnectionProtocol.SSH.value: 22,
    ConnectionProtocol.TELNET.value: 23,
    ConnectionProtocol.KUBERNETES.value: 443,
    ConnectionProtocol.MYSQL.value: 3306,
    ConnectionProtocol.POSTGRESQL.value: 5432,
    ConnectionProtocol.SQLSERVER.value: 1433,
}

from .terminal_size import (
    DEFAULT_TERMINAL_COLUMNS,
    DEFAULT_TERMINAL_ROWS,
    GUACAMOLE_HANDSHAKE_DPI,
    _build_screen_info,
    get_terminal_size_pixels,
    scale_screen_info,
)

# Computed at import time using the best available platform APIs so the initial
# offer payload carries accurate pixel dimensions even before the connection
# loop runs. Falls back to fixed cell-size constants if the query fails.
try:
    DEFAULT_SCREEN_INFO = get_terminal_size_pixels()
except Exception:
    DEFAULT_SCREEN_INFO = _build_screen_info(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS)

MAX_MESSAGE_SIZE_LINE = "a=max-message-size:1073741823"

# Minimum keeper-pam-webrtc-rs version that supports ConnectAs payload in OpenConnection.
# Older Gateways (Rust module < this) do not parse connect_as_payload; omit it when not supported.
CONNECT_AS_MIN_VERSION = "2.1.6"


def _version_at_least(version: Optional[str], min_version: str) -> bool:
    """
    Compare semantic versions. Returns True if version >= min_version.

    Args:
        version: Parsed version (e.g. "2.1.4") or None (treated as unknown/old).
        min_version: Minimum required version (e.g. "2.1.0").

    Returns:
        True if version is known and >= min_version; False if unknown or older.
    """
    if not version:
        return False

    def parse(v: str) -> tuple:
        parts = []
        for p in v.split(".")[:3]:  # major.minor.patch
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    try:
        return parse(version) >= parse(min_version)
    except Exception:
        return False


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
    Detect the connection protocol from a PAM record.

    All machine types (pamMachine, pamDirectory, pamDatabase) allow any connection
    type (ssh, telnet, rdp, vnc, kubernetes, mysql, etc.). Extraction follows:
    first connection.protocol; for pamDatabase only, if still undetermined then
    connection.databaseType, then infer from port.

    Args:
        params: KeeperParams instance
        record_uid: Record UID

    Returns:
        Protocol string (ex. ssh, telnet, rdp, mysql, etc.) or None if
        not present/undetermined. If connection.protocol is set to a value that
        matches a ConnectionProtocol enum, returns that canonical value;
        otherwise returns the raw string (lowercased).
    """
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord):
        return None

    record_type = record.record_type
    if record_type not in ('pamMachine', 'pamDirectory', 'pamDatabase'):
        return None

    # Map lowercase protocol string to canonical ConnectionProtocol.value
    _protocol_values = {p.value.lower(): p.value for p in ConnectionProtocol}

    pam_settings = record.get_typed_field('pamSettings')
    if not pam_settings:
        return None

    settings_value = pam_settings.get_default_value(dict)
    if not settings_value:
        return None

    connection = settings_value.get('connection') or {}
    if not isinstance(connection, dict):
        return None

    # 1) Try connection.protocol (same for all record types)
    protocol_field = (connection.get('protocol') or '').strip()
    if protocol_field:
        protocol_lower = protocol_field.lower()
        return _protocol_values.get(protocol_lower, protocol_lower)

    # 2) For pamDatabase only: connection.databaseType, then infer from port
    if record_type == 'pamDatabase':
        db_type = (connection.get('databaseType') or '').lower()
        if 'mysql' in db_type:
            return ConnectionProtocol.MYSQL.value
        if 'postgres' in db_type or 'postgresql' in db_type:
            return ConnectionProtocol.POSTGRESQL.value
        if 'sql server' in db_type or 'sqlserver' in db_type or 'mssql' in db_type:
            return ConnectionProtocol.SQLSERVER.value

        hostname_field = record.get_typed_field('pamHostname')
        if hostname_field:
            host_value = hostname_field.get_default_value(dict)
            if host_value and host_value.get('port') is not None:
                try:
                    port_int = int(host_value['port'])
                except (TypeError, ValueError):
                    port_int = None
                if port_int == 3306:
                    return ConnectionProtocol.MYSQL.value
                if port_int == 5432:
                    return ConnectionProtocol.POSTGRESQL.value
                if port_int == 1433:
                    return ConnectionProtocol.SQLSERVER.value

    return None


_PAM_TYPES_WITH_CONNECTION_PORT = ['pamMachine', 'pamDatabase', 'pamDirectory']


def _pam_settings_connection_port(record: Any) -> Optional[int]:
    """
    For PAM machine record types only, return a valid pamSettings.connection.port if set.
    """
    if getattr(record, 'record_type', None) not in _PAM_TYPES_WITH_CONNECTION_PORT:
        return None
    if not hasattr(record, 'get_typed_field'):
        return None
    psf = record.get_typed_field('pamSettings')
    if not psf or not hasattr(psf, 'get_default_value'):
        return None
    pam_val = psf.get_default_value(dict)
    if not isinstance(pam_val, dict):
        return None
    connection = pam_val.get('connection')
    if not isinstance(connection, dict):
        return None
    conn_port = connection.get('port')
    if conn_port is None or conn_port == '':
        return None
    try:
        p = int(conn_port)
    except (ValueError, TypeError):
        return None
    if 1 <= p <= 65535:
        return p
    return None


def extract_terminal_settings(
    params: KeeperParams,
    record_uid: str,
    protocol: str,
    launch_credential_uid: Optional[str] = None,
    custom_host: Optional[str] = None,
    custom_port: Optional[int] = None,
    dag_linked_uid: Any = _DAG_UID_UNSET,
) -> Dict[str, Any]:
    """
    Extract terminal connection settings from a PAM record.

    Args:
        params: KeeperParams instance
        record_uid: Record UID
        protocol: Protocol type (from detect_protocol)
        launch_credential_uid: Optional override for userRecordUid (from --credential CLI param)
        custom_host: Optional override for hostname (from --host/--host-record/--credential CLI param)
        custom_port: Optional override for port (from --host/--host-record/--credential CLI param)

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

    # Resolve DAG-linked launch credential UID once; the pamSettings block and the
    # later CLI-override comparison both need the same value. Pam launch passes
    # a pre-resolved value via the kwarg so the 2–3 HTTP round-trips that build
    # a TunnelDAG only happen once per command instead of per call site.
    if dag_linked_uid is _DAG_UID_UNSET:
        dag_linked_uid = _get_launch_credential_uid(params, record_uid)

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
        # JIT (just-in-time) access block. Loaded by ``jit.load_jit_settings`` from
        # either the DAG (Web Vault authoritative) or the pamSettings.options mirror.
        # jit_mode is derived by ``jit.derive_jit_mode`` and is one of the
        # ``jit.JIT_MODE_*`` constants or ``None``.
        'jit_settings': None,
        'jit_mode': None,
    }

    # Extract hostname and port from record - enforce single non-empty host/pamHostname field.
    # Host requires non-empty hostName; port is pamSettings.connection.port (PAM types only)
    # when set, else the field's port — same precedence as launch._get_host_port_from_record.
    _pam_override_port = _pam_settings_connection_port(record)
    _host_candidates = []
    for _f in list(getattr(record, 'fields', None) or []) + list(getattr(record, 'custom', None) or []):
        if getattr(_f, 'type', None) in ('pamHostname', 'host'):
            _hv = _f.get_default_value(dict) if hasattr(_f, 'get_default_value') else {}
            _hn = ((_hv.get('hostName') or '').strip()) if isinstance(_hv, dict) else ''
            if not _hn:
                continue
            _pr = _pam_override_port if _pam_override_port is not None else (
                _hv.get('port') if isinstance(_hv, dict) else None
            )
            if not _pr:
                continue
            try:
                _pp = int(_pr)
                if 1 <= _pp <= 65535:
                    _host_candidates.append((_hn, _pp, _hv))
            except (ValueError, TypeError):
                pass
    if len(_host_candidates) > 1:
        raise CommandError('pam launch',
            f'Record {record_uid} has {len(_host_candidates)} non-empty host/pamHostname fields '
            '(expected exactly one). Clear the extra field before launching.')
    _record_host, _record_port_val, _host_value = _host_candidates[0] if _host_candidates else (None, None, {})

    settings['hostname'] = _record_host

    # CLI --host overrides record hostname (allowSupplyHost validated in launch.py)
    if custom_host:
        settings['hostname'] = custom_host
        logging.debug(f"Using custom host override: {custom_host}")

    # Port precedence: CLI (custom_port) > record (pamSettings.connection.port overrides host field
    # on PAM types, else field port) > pamSettings.connection.port when record port still unset >
    # protocol DEFAULT. pamSettings fallback runs in the pamSettings block below.
    if custom_port is not None:
        settings['port'] = custom_port
    elif _record_port_val is not None:
        settings['port'] = _record_port_val
    # else: remains None until pamSettings fallback or DEFAULT below

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
                # When both admin and launch credentials exist, we must use launch credential.
                # dag_linked_uid was resolved once at the top of the function.
                if dag_linked_uid:
                    settings['userRecordUid'] = dag_linked_uid
                    logging.debug(f"Using launch credential from DAG: {settings['userRecordUid']}")
                elif not launch_credential_uid:
                    # No DAG-linked credential and no -cr given.
                    # If allowSupply* is enabled, use pamSettings.connection.userRecords[0] as
                    # implicit credential and warn so the user can be explicit via -cr.
                    user_records = connection.get('userRecords', [])
                    if user_records and len(user_records) > 0:
                        fallback_uid = user_records[0]
                        settings['userRecordUid'] = fallback_uid
                        allow_supply_host_flag = pam_settings_value.get('allowSupplyHost', False)
                        allow_supply_user_flag = connection.get('allowSupplyUser', False)
                        if allow_supply_host_flag or allow_supply_user_flag:
                            logging.warning(
                                'Record %s: allowSupply* is enabled but no DAG-linked launch credential '
                                'was found; using pamSettings.connection.userRecords[0] (%s) as credential. '
                                'Pass --credential (-cr %s) to be explicit.',
                                record_uid, fallback_uid, fallback_uid,
                            )
                            settings['_fallbackCredential'] = True
                        else:
                            logging.debug(f"Using userRecordUid from pamSettings: {fallback_uid}")

                # pamSettings.connection.port when CLI and host-derived port are still absent
                if settings['port'] is None:
                    conn_port = connection.get('port')
                    if conn_port:
                        try:
                            settings['port'] = int(conn_port)
                        except (ValueError, TypeError):
                            pass

                # Protocol-specific settings
                if protocol == ConnectionProtocol.SSH.value:
                    settings['protocol_specific'] = _extract_ssh_settings(connection)
                elif protocol == ConnectionProtocol.TELNET.value:
                    settings['protocol_specific'] = _extract_telnet_settings(connection)
                elif protocol == ConnectionProtocol.KUBERNETES.value:
                    settings['protocol_specific'] = _extract_kubernetes_settings(connection)
                elif protocol in DATABASE:
                    settings['protocol_specific'] = _extract_database_settings(connection, protocol)

            # allowSupplyHost is at top level of pamSettings value, not inside connection
            settings['allowSupplyHost'] = pam_settings_value.get('allowSupplyHost', False)

            # JIT settings come from either the DAG (Web Vault authoritative, camelCase)
            # or pamSettings.options.jit_settings (declarative mirror, snake_case).
            # jit.load_jit_settings prefers the DAG and returns snake_case either way;
            # jit.derive_jit_mode centralises the mode rule.
            jit_raw = jit.load_jit_settings(params=params, record=record, record_uid=record_uid)
            jit_mode = jit.derive_jit_mode(jit_raw)
            if jit_mode:
                settings['jit_settings'] = dict(jit_raw)
                settings['jit_mode'] = jit_mode

    # Final port fallback to protocol default
    if settings['port'] is None:
        settings['port'] = DEFAULT_PORTS.get(protocol, 22)

    # CLI overrides: check if --credential provides a DIFFERENT user than DAG-linked.
    # dag_linked_uid is the once-resolved DAG value from the top of the function —
    # distinct from settings['userRecordUid'] which may have been set from the
    # userRecords[0] fallback (not DAG-linked) and must not be used for this comparison.
    if launch_credential_uid:
        if launch_credential_uid == dag_linked_uid:
            # CLI --credential matches DAG-linked credential - treat as if no --credential was provided
            # so gateway uses normal 'linked' flow
            logging.debug(f"CLI --credential matches DAG-linked credential {dag_linked_uid} - using normal 'linked' flow")
            settings['cliUserOverride'] = False
        else:
            # CLI --credential provides a different user - this is a real override
            settings['userRecordUid'] = launch_credential_uid
            settings['cliUserOverride'] = True
            logging.debug(f"CLI --credential overrides DAG credential: {launch_credential_uid} (was {dag_linked_uid})")
    elif settings.pop('_fallbackCredential', False):
        # userRecords[0] fallback with allowSupply* - treat as implicit -cr:
        # gateway may not have it in DAG, so use userSupplied + ConnectAs payload
        settings['cliUserOverride'] = True
        logging.debug(f"Implicit credential from userRecords[0] fallback: {settings.get('userRecordUid')} - treating as userSupplied")
    else:
        settings['cliUserOverride'] = False

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
    if protocol == ConnectionProtocol.MYSQL.value:
        settings['useSSL'] = connection.get('useSSL', False)
    elif protocol == ConnectionProtocol.POSTGRESQL.value:
        settings['useSSL'] = connection.get('useSSL', False)
    elif protocol == ConnectionProtocol.SQLSERVER.value:
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
        'conversationType': str(protocol).lower(),
        # Credential supply flags
        'allowSupplyUser': settings.get('allowSupplyUser', False),
        'allowSupplyHost': settings.get('allowSupplyHost', False),
        # Linked pamUser record UID for credential extraction
        'userRecordUid': settings.get('userRecordUid'),
        # True only when --credential was provided via CLI and differs from the DAG-linked record.
        # Required by the offer-building path to distinguish "flag enabled but nothing supplied"
        # from "flag enabled and user actually provided credentials".
        'cliUserOverride': settings.get('cliUserOverride', False),
        # JIT (just-in-time) settings. jit_mode is one of ``jit.JIT_MODE_*`` or ``None``.
        # jit_settings is the normalised snake_case dict loaded by ``jit.load_jit_settings``
        # from the DAG (Web Vault) or pamSettings.options.jit_settings (declarative mirror),
        # projected for the gateway by ``jit.build_{ephemeral,elevation}_payload``.
        # jit_enabled is True only when the operator passed --jit on the CLI, giving explicit
        # opt-in (records that happen to have jit_settings never auto-trigger JIT).
        'jit_settings': settings.get('jit_settings'),
        'jit_mode': settings.get('jit_mode'),
        'jit_enabled': settings.get('jit_enabled', False),
    }

    # Add protocol-specific settings
    if protocol == ConnectionProtocol.SSH.value:
        context['ssh'] = settings['protocol_specific']
    elif protocol == ConnectionProtocol.TELNET.value:
        context['telnet'] = settings['protocol_specific']
    elif protocol == ConnectionProtocol.KUBERNETES.value:
        context['kubernetes'] = settings['protocol_specific']
    elif protocol in DATABASE:
        context['database'] = settings['protocol_specific']
        context['database']['type'] = protocol

    return context




def _get_launch_credential_uid(
    params: 'KeeperParams',
    record_uid: str,
    tdag: Optional['TunnelDAG'] = None,
) -> Optional[str]:
    """
    Find the launch credential UID for a PAM record using the DAG.

    When a pamMachine record has both administrative credentials and launch credentials,
    we need to use the launch credential (marked with is_launch_credential=True in DAG).
    This function queries the DAG to find the correct credential.

    Args:
        params: KeeperParams instance
        record_uid: UID of the pamMachine record
        tdag: Optional pre-built TunnelDAG to reuse. When provided, skips the
            expensive ``TunnelDAG(...)`` construction (which issues 2–3 HTTP
            round-trips). Used by ``pam launch`` to avoid resolving the same
            DAG three times per command invocation.

    Returns:
        UID of the launch credential pamUser record, or None if not found
    """
    try:
        if tdag is None:
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

        # Find the credential explicitly marked as is_launch_credential=True in DAG
        launch_credential = None

        for user_vertex in record_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(record_vertex, EdgeType.ACL)
            if acl_edge:
                try:
                    content = acl_edge.content_as_dict or {}
                    if content.get('is_launch_credential', False) and launch_credential is None:
                        launch_credential = user_vertex.uid
                        logging.debug(f"Found launch credential via DAG: {launch_credential}")
                except Exception as e:
                    logging.debug(f"Error parsing ACL edge content: {e}")

        if launch_credential:
            logging.debug(f"Using launch credential from DAG: {launch_credential}")
            return launch_credential

        logging.debug(f"No explicit launch credential (is_launch_credential=True) in DAG for {record_uid}")
        return None

    except Exception as e:
        logging.debug(f"Error accessing DAG for launch credential: {e}")
        return None


# ECIES info string for ConnectAs payload encryption
# Must match the gateway's expected value
CONNECT_AS_ECIES_INFO = b'KEEPER_CONNECT_AS_ECIES_SECP256R1_HKDF_SHA256'


def _ecies_encrypt_with_hkdf(
    plaintext: bytes,
    recipient_public_key: bytes,
    info: bytes = CONNECT_AS_ECIES_INFO
) -> bytes:
    """
    Encrypt data using ECIES with HKDF key derivation.

    This implements ECIES (Elliptic Curve Integrated Encryption Scheme) using:
    - SECP256R1 (P-256) curve for ECDH key exchange
    - HKDF-SHA256 for key derivation with the provided info string
    - AES-256-GCM for symmetric encryption

    Args:
        plaintext: Data to encrypt
        recipient_public_key: 65-byte uncompressed public key of recipient
        info: HKDF info/context string (default: CONNECT_AS_ECIES_INFO)

    Returns:
        Encrypted payload: [ephemeral_pubkey (65)] + [nonce (12)] + [ciphertext + auth_tag]
    """
    # Generate ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Serialize ephemeral public key (65 bytes uncompressed)
    ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Load recipient's public key from bytes
    recipient_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        recipient_public_key
    )

    # Perform ECDH to get shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_key)

    # Derive encryption key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key
        salt=None,
        info=info,
        backend=default_backend()
    )
    encryption_key = hkdf.derive(shared_secret)

    # Generate random nonce for AES-GCM
    nonce = os.urandom(12)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(encryption_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Return: [ephemeral_pubkey (65)] + [nonce (12)] + [ciphertext + auth_tag]
    return ephemeral_public_key_bytes + nonce + ciphertext


def _build_connect_as_payload(
    params: 'KeeperParams',
    user_record_uid: str,
    gateway_public_key: bytes
) -> Optional[bytes]:
    """
    Build encrypted ConnectAs payload for credential passing to gateway.

    The ConnectAs payload contains user credentials from a pamUser record,
    encrypted using ECIES with HKDF. This allows the gateway to receive
    credentials via the OpenConnection message instead of looking them up in DAG.

    Args:
        params: KeeperParams instance
        user_record_uid: UID of the pamUser record containing credentials
        gateway_public_key: 65-byte public key of the gateway for ECIES encryption

    Returns:
        Encrypted payload in format expected by keeper-pam-webrtc-rs Gateway:
        [ephemeral_pubkey (65)] + [nonce (12)] + [ciphertext + auth_tag] = 185 bytes.
        Returns None if credentials cannot be extracted or encryption fails.
    """
    if not user_record_uid or not gateway_public_key:
        return None

    try:
        # Extract credentials from pamUser record
        creds = _extract_user_record_credentials(params, user_record_uid)

        # Build ConnectAs user data structure (matches webvault's ConnectAsUser)
        connect_as_user = {}
        if creds.get('username'):
            connect_as_user['username'] = creds['username']
        if creds.get('password'):
            connect_as_user['password'] = creds['password']
        if creds.get('private_key'):
            connect_as_user['private_key'] = creds['private_key']
        if creds.get('passphrase'):
            connect_as_user['passphrase'] = creds['passphrase']

        # The payload structure matches webvault: {"user": {...}}
        payload_dict = {'user': connect_as_user}
        payload_json = json.dumps(payload_dict).encode('utf-8')

        # keeper-pam-webrtc-rs protocol.rs expects:
        # [encrypted_data_len: 4 bytes] + [PK(65)] + [Nonce(12)] + [Encrypted(encrypted_data_len)]
        # Encrypted = ciphertext + auth_tag(16). Ciphertext len = plaintext len.
        # So plaintext must be >= 92 bytes to produce 108-byte encrypted portion.
        # Use space padding (not null) so decrypted JSON parses correctly.
        min_plaintext_len = 92
        if len(payload_json) < min_plaintext_len:
            payload_json = payload_json + b' ' * (min_plaintext_len - len(payload_json))

        logging.debug(f"ConnectAs payload: username={'(set)' if connect_as_user.get('username') else '(empty)'}, "
                      f"password={'(set)' if connect_as_user.get('password') else '(empty)'}, "
                      f"private_key={'(set)' if connect_as_user.get('private_key') else '(empty)'}")

        # Encrypt with ECIES+HKDF
        ecies_encrypted = _ecies_encrypt_with_hkdf(payload_json, gateway_public_key)

        # protocol.rs reads: connect_as_payload_len = get_u32(), then
        # required_crypto_block_len = 65 + 12 + connect_as_payload_len
        # The length is of the ENCRYPTED portion only (ciphertext+auth_tag) = 108
        encrypted_data_len = len(ecies_encrypted) - 65 - 12  # ciphertext + auth_tag
        length_bytes = encrypted_data_len.to_bytes(4, byteorder='big')
        connect_as_payload = length_bytes + ecies_encrypted

        logging.debug(f"Built ConnectAs payload: total_len={len(connect_as_payload)}, encrypted_data_len={encrypted_data_len}")

        return connect_as_payload

    except Exception as e:
        logging.error(f"Failed to build ConnectAs payload: {e}")
        return None


def _retrieve_gateway_public_key(
    params: 'KeeperParams',
    gateway_uid: str
) -> Optional[bytes]:
    """
    Retrieve the public key for a gateway.

    This function calls the vault/get_ksm_public_keys API to retrieve the
    gateway's public key needed for ECIES encryption of ConnectAs payloads.

    Args:
        params: KeeperParams instance
        gateway_uid: UID of the gateway

    Returns:
        65-byte uncompressed public key, or None if not found
    """
    try:
        gateway_uid_bytes = url_safe_str_to_bytes(gateway_uid)
        get_ksm_pubkeys_rq = GetKsmPublicKeysRequest()
        get_ksm_pubkeys_rq.controllerUids.append(gateway_uid_bytes)
        get_ksm_pubkeys_rs = api.communicate_rest(
            params, get_ksm_pubkeys_rq, 'vault/get_ksm_public_keys',
            rs_type=GetKsmPublicKeysResponse
        )

        if len(get_ksm_pubkeys_rs.keyResponses) == 0:
            logging.warning(f"No public key found for gateway {gateway_uid}")
            return None

        gateway_public_key_bytes = get_ksm_pubkeys_rs.keyResponses[0].publicKey
        logging.debug(f"Retrieved gateway public key: {len(gateway_public_key_bytes)} bytes")
        return gateway_public_key_bytes

    except Exception as e:
        logging.error(f"Error retrieving gateway public key: {e}")
        return None


def _get_single_str_field(record: Any, field_type: str) -> str:
    """
    Return the value of the single non-empty typed field matching field_type.

    Enforces exactly one non-empty field across both record.fields[] and record.custom[].
    Raises CommandError if multiple non-empty fields of that type are found.
    Returns '' if none are found.
    """
    nonempty_values = []
    for field in list(getattr(record, 'fields', None) or []) + list(getattr(record, 'custom', None) or []):
        if getattr(field, 'type', None) == field_type:
            val = field.get_default_value(str) if hasattr(field, 'get_default_value') else ''
            if val:
                nonempty_values.append(val)
    if len(nonempty_values) > 1:
        raise CommandError('pam launch',
            f'Record has {len(nonempty_values)} non-empty {field_type!r} fields '
            '(expected exactly one). Clear the extra field before launching.')
    return nonempty_values[0] if nonempty_values else ''


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

    # Extract username - enforce single non-empty login field across fields[] + custom[]
    result['username'] = _get_single_str_field(user_record, 'login')

    # Extract password - enforce single non-empty password field across fields[] + custom[]
    result['password'] = _get_single_str_field(user_record, 'password')

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
    normalize_crlf: bool = False,
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
        normalize_crlf: When True, map CRLF to LF on decoded STDOUT blobs and run downstream LF cleanup
            (``pam launch --normalize-crlf`` / ``-n``). Default False keeps raw CR/LF (CLI default).

    Returns:
        Dictionary with connection settings for GuacamoleHandler
    """
    username = ''
    password = ''
    private_key = None
    passphrase = None

    # Determine how to get credentials based on credential_type
    # Note: Even for 'userSupplied', if we have user_record_uid (from CLI --credential), extract credentials
    # because guacd_params go directly to guacd via our connect instruction
    if credential_type == 'ephemeral':
        # JIT ephemeral: gateway provisions the account and injects credentials into guacd
        # server-side. Leave Commander's guacd_params creds empty so the gateway's values win.
        logging.debug("Using ephemeral credential type - gateway supplies credentials")
    elif credential_type == 'userSupplied' and not user_record_uid:
        # True user-supplied: no credentials provided at all
        # Note: user may not be able to provide via guacamole prompt since STDIN/STDOUT not open yet
        logging.debug("Using userSupplied credential type with no pamUser - leaving credentials empty")
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
        # Enforces single non-empty login/password field across fields[] + custom[].
        record = vault.KeeperRecord.load(params, record_uid)
        if isinstance(record, vault.TypedRecord):
            username = _get_single_str_field(record, 'login')
            password = _get_single_str_field(record, 'password')
        logging.debug("Using credentials from pamMachine record (no linked pamUser)")

    # Build guacd parameters dictionary
    # These map to guacd's expected parameter names
    # The 'protocol' field is required for guacd to know which backend to use
    guacd_protocol = str(protocol).lower()
    guacd_params = {
        'protocol': guacd_protocol,  # Required: tells guacd which protocol handler to use
        'hostname': settings.get('hostname', ''),
        'port': str(settings.get('port', '')),
        'username': username,
        'password': password,
    }

    # Add private key for SSH protocol if available
    # SSH authentication precedence: guacd/SSH tries private key first, then password
    # Both can be present simultaneously - this matches gateway behavior
    if protocol == ConnectionProtocol.SSH.value and private_key:
        guacd_params['private-key'] = private_key
        if passphrase:
            guacd_params['passphrase'] = passphrase
        logging.debug("Added private-key to guacd_params for SSH authentication")

    # Add protocol-specific parameters
    protocol_specific = settings.get('protocol_specific', {})

    if protocol == ConnectionProtocol.SSH.value:
        # SSH-specific params
        if protocol_specific.get('publicHostKey'):
            guacd_params['host-key'] = protocol_specific['publicHostKey']
        if protocol_specific.get('executeCommand'):
            guacd_params['command'] = protocol_specific['executeCommand']
        # Enable SFTP if configured
        if protocol_specific.get('sftpEnabled'):
            guacd_params['enable-sftp'] = 'true'

    elif protocol == ConnectionProtocol.TELNET.value:
        # Telnet-specific params
        if protocol_specific.get('usernameRegex'):
            guacd_params['username-regex'] = protocol_specific['usernameRegex']
        if protocol_specific.get('passwordRegex'):
            guacd_params['password-regex'] = protocol_specific['passwordRegex']

    elif protocol == ConnectionProtocol.KUBERNETES.value:
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

    elif protocol in DATABASE:
        # Database-specific params
        if protocol_specific.get('defaultDatabase'):
            guacd_params['database'] = protocol_specific['defaultDatabase']

    # CLI mode: named pipe for terminal STDOUT (guacr terminal handlers; not graphical RDP/VNC)
    guacd_params['enable-pipe'] = 'true'

    # Terminal display settings
    terminal_settings = settings.get('terminal', {})
    if terminal_settings.get('colorScheme'):
        guacd_params['color-scheme'] = terminal_settings['colorScheme']
    _record_font_size = terminal_settings.get('fontSize')
    if _record_font_size and str(_record_font_size) != '12':
        logging.debug(
            "Record font-size %r is not supported for terminal sessions "
            "(pixel metrics are calibrated for font-size 12); converting to font-size 12.",
            _record_font_size,
        )
    guacd_params['font-size'] = '12'

    # PAM clipboard → guacd: only pass disable-* when the record sets them (guacd "true" = on).
    _pam_clip = settings.get('clipboard') or {}
    if _pam_clip.get('disablePaste'):
        guacd_params['disable-paste'] = 'true'
    if _pam_clip.get('disableCopy'):
        guacd_params['disable-copy'] = 'true'

    # Terminal dimensions and DPI must be in guacd_params so the 'connect' instruction
    # carries them to guacd. Without these, guacd initialises its font metrics at its
    # built-in default DPI (96), giving char_width ≈ 10 px. The kcm pixel formula uses
    # char_width = 19 px (calibrated for DPI 192), so a missing DPI in 'connect' causes
    # guacd to compute ~2× too many PTY columns from the pixel width we send.
    guacd_params['width'] = str(screen_info.get('pixel_width', 800))
    guacd_params['height'] = str(screen_info.get('pixel_height', 600))
    guacd_params['dpi'] = str(screen_info.get('dpi', GUACAMOLE_HANDSHAKE_DPI))

    # Build final connection settings
    connection_settings = {
        'protocol': protocol,
        'hostname': settings.get('hostname', ''),
        'port': settings.get('port', 22),
        'width': screen_info.get('pixel_width', 800),
        'height': screen_info.get('pixel_height', 600),
        # DPI comes from screen_info (192 for KCM mode, 96 for guacd/scale mode) — also
        # carried via guacd_params['dpi'] so the 'connect' instruction sets guacd's font
        # metrics to the correct DPI from the start.
        'dpi': screen_info.get('dpi', GUACAMOLE_HANDSHAKE_DPI),
        'guacd_params': guacd_params,
        # Supported mimetypes for terminal sessions
        'audio_mimetypes': [],  # No audio for terminal
        'video_mimetypes': [],  # No video for terminal
        'image_mimetypes': ['image/png', 'image/jpeg', 'image/webp'],
        # PAM clipboard policy (also in guacd_params as disable-* only when record disables)
        'clipboard': dict(settings.get('clipboard') or {}),
        # CLI-only: GuacamoleHandler / instruction router (not sent to guacd)
        'normalize_crlf': bool(normalize_crlf),
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
        _pam_tc = PamConnectTiming('pam-launch:webrtc-tunnel')
        _pam_tc.checkpoint('enter')
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
        relay_url = 'krelay.' + get_keeper_server_hostname(params.server)
        krelay_url = os.getenv('KRELAY_URL')
        if krelay_url:
            relay_url = krelay_url

        response = router_get_relay_access_creds(params=params, expire_sec=60000000)
        if response is None:
            return {"success": False, "error": "Failed to get relay access credentials"}
        _pam_tc.checkpoint('relay_creds_ok')

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

        # For trickle ICE, use shared tokens and bind_to_controller for ALB stickiness (same worker for WebSocket + POST)
        router_tokens = None
        http_session = None
        cookie_header = None
        if trickle_ice:
            router_tokens = get_keeper_tokens(params)
            http_session = requests.Session()
            krouter_host = get_router_url(params)
            try:
                bind_url = krouter_host + "/api/user/bind_to_controller/" + gateway_uid
                http_session.get(bind_url, verify=VERIFY_SSL, timeout=10)
            except Exception as e:
                logging.debug("bind_to_controller GET failed (continuing): %s", e)
            if http_session.cookies:
                cookie_header = "; ".join(f"{c.name}={c.value}" for c in http_session.cookies)
                logging.debug("Bound to controller for ALB stickiness (WebSocket and streaming HTTP will use same backend)")

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
            trickle_ice=trickle_ice,
            router_tokens=router_tokens,
            http_session=http_session
        )

        # Store signal handler reference
        tunnel_session.signal_handler = signal_handler  # type: ignore[assignment]

        # Start the dedicated WebSocket listener *before* ``create_tube``. The Rust
        # tube creation takes ~500ms; running the WebSocket TLS handshake / router
        # registration concurrently with it saves most of that window. The listener
        # only reads the ``conversation_id`` from tunnel_session; the tube_id is
        # used for the thread name and log context only (updated in-place after
        # ``create_tube`` returns). No message will arrive before the gateway has
        # received our offer, so there is no race between early listener start and
        # the tube-id being rewritten from the temp UUID to the real one.
        websocket_thread = start_websocket_listener(
            params, tube_registry, timeout=300, gateway_uid=gateway_uid,
            tunnel_session=tunnel_session,
            router_tokens=router_tokens,
            cookie_header=cookie_header,
        )
        _pam_tc.checkpoint('websocket_listener_started_early')

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

            # credential_type is None when using pamMachine credentials directly (backward compatible)
            # Priority: JIT ephemeral wins (gateway supplies creds); otherwise if user_record_uid
            # is provided (from CLI or record), use 'linked'; fallback to 'userSupplied' when
            # allowSupply* flags are enabled.
            jit_mode = context.get('jit_mode') if context.get('jit_enabled') else None
            credential_type = None
            if jit_mode in (jit.JIT_MODE_EPHEMERAL, jit.JIT_MODE_BOTH) and not allow_supply_host:
                # Gateway provisions the ephemeral account and injects credentials server-side;
                # leave guacd username/password empty on the client.
                credential_type = 'ephemeral'
                logging.debug("JIT ephemeral mode - using 'ephemeral' credential type (creds come from gateway)")
            elif user_record_uid:
                # Linked user present (from CLI --credential or record) - use linked credentials
                credential_type = 'linked'
                logging.debug(f"Using 'linked' credential type with userRecordUid: {user_record_uid}")
            elif allow_supply_host or allow_supply_user:
                # No credentials provided but supply flags enabled - user must provide interactively
                credential_type = 'userSupplied'
                logging.debug("No credentials provided, allowSupply enabled - using 'userSupplied' credential type")
            else:
                # No linked user, no supply flags - use pamMachine credentials directly
                logging.debug("No linked user or supply flags - using pamMachine credentials directly")

            # Fresh TTY metrics for the Python handshake — do not use ``screen_info`` from
            # function start (DEFAULT_SCREEN_INFO snapshot); that can be import-time or stale.
            _scale = kwargs.get('scale')
            if isinstance(_scale, int) and _scale > 0 and _scale != 100:
                _ts = shutil.get_terminal_size(fallback=(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS))
                screen_info = scale_screen_info(_ts.columns, _ts.lines, _scale)
                logging.debug(
                    "--scale %s%%: guacd-96 base, grid %sx%s → %sx%spx @ %sdpi",
                    _scale,
                    screen_info["columns"],
                    screen_info["rows"],
                    screen_info["pixel_width"],
                    screen_info["pixel_height"],
                    screen_info["dpi"],
                )
            else:
                try:
                    screen_info = get_terminal_size_pixels()
                except Exception:
                    logging.debug("Falling back to default terminal size for PythonHandler connection_settings")
                    screen_info = _build_screen_info(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS)

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
                normalize_crlf=bool(kwargs.get('normalize_crlf')),
            )

            # Create the handler and callback
            handler_callback, python_handler = create_python_handler(
                tube_registry=tube_registry,
                conversation_id=conversation_id,
                conn_no=1,
                connection_settings=connection_settings,
            )

            logging.debug(f"Created PythonHandler for conversation {conversation_id}")

        # Create the tube to get the WebRTC offer
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
        _pam_tc.checkpoint('create_tube_ok')

        # Update signal handler and tunnel session with real tube ID
        signal_handler.tube_id = commander_tube_id
        tunnel_session.tube_id = commander_tube_id

        # Unregister temporary session and register with real tube ID
        unregister_tunnel_session(temp_tube_id)
        register_tunnel_session(commander_tube_id, tunnel_session)

        logging.debug(f"Registered encryption key for conversation: {conversation_id}")
        logging.debug(f"Expecting WebSocket responses for conversation ID: {conversation_id}")

        # (WebSocket listener already started above, before create_tube.)

        # Wait for WebSocket to be ready before sending offer (same as pam tunnel start).
        # Use event.wait() when available so we proceed as soon as ready; fallback to short sleep.
        max_wait = 15.0
        # Router/gateway need a moment to register the conversation after the
        # WebSocket handshake. Default 0.30s; on first-offer failure we top up
        # with the delta to the legacy 2.0s before retrying (adaptive fallback).
        backend_delay = websocket_backend_delay_sec()
        if trickle_ice:
            if tunnel_session.websocket_ready_event:
                logging.debug(f"Waiting for dedicated WebSocket to connect (max {max_wait}s)...")
                websocket_ready = tunnel_session.websocket_ready_event.wait(timeout=max_wait)
                if not websocket_ready:
                    logging.error(f"Dedicated WebSocket did not become ready within {max_wait}s")
                    signal_handler.cleanup()
                    unregister_tunnel_session(commander_tube_id)
                    return {"success": False, "error": "WebSocket connection timeout"}
                logging.debug("Dedicated WebSocket connection established and ready for streaming")
                logging.debug(f"Waiting {backend_delay}s for backend to register conversation...")
                time.sleep(backend_delay)
                _pam_tc.checkpoint('websocket_ready_backend_delay_done')
            else:
                logging.warning("No WebSocket ready event for tunnel, using backend delay %.1fs", backend_delay)
                time.sleep(backend_delay)
                _pam_tc.checkpoint('websocket_no_event_backend_delay_done')
        else:
            # Non-trickle ICE: SDP answer comes via the HTTP offer response body
            # (handled further below in the non-streaming branch) and ICE candidates
            # are carried inside the offer SDP itself, so there is no streamed
            # conversation to register on the router/gateway side. The WebSocket
            # listener keeps running in the background for async signaling
            # (disconnect / state changes) but the main thread does not need to
            # block on it. Saves ~backend_delay + ~WS-TLS-handshake before the
            # offer POST (~700ms on a typical launch).
            logging.debug("Non-trickle ICE: skipping WebSocket-ready wait and backend_delay")
            _pam_tc.checkpoint('non_trickle_skip_backend_delay')

        # Send offer to gateway via HTTP POST
        logging.debug(f"{bcolors.OKBLUE}Sending {protocol} connection offer to gateway...{bcolors.ENDC}")

        # Prepare the offer data with terminal-specific parameters
        # Match webvault format: host, size, audio, video, image (for guacd configuration)
        # These parameters are needed by Gateway to configure guacd BEFORE OpenConnection
        # Get terminal size for Guacamole size parameter (offer payload).
        # get_terminal_size_pixels() queries the terminal internally and uses
        # platform-specific APIs (Windows: GetCurrentConsoleFontEx; Unix:
        # TIOCGWINSZ) to obtain exact pixel dimensions before falling back to
        # the fixed cell-size estimate.
        _scale = kwargs.get('scale')
        if isinstance(_scale, int) and _scale > 0 and _scale != 100:
            _ts = shutil.get_terminal_size(fallback=(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS))
            screen_info = scale_screen_info(_ts.columns, _ts.lines, _scale)
            logging.debug(
                "--scale %s%% (offer): guacd-96 base, grid %sx%s → %sx%spx @ %sdpi",
                _scale,
                screen_info["columns"],
                screen_info["rows"],
                screen_info["pixel_width"],
                screen_info["pixel_height"],
                screen_info["dpi"],
            )
        else:
            try:
                screen_info = get_terminal_size_pixels()
            except Exception:
                logging.debug("Falling back to default terminal size for offer payload")
                screen_info = _build_screen_info(DEFAULT_TERMINAL_COLUMNS, DEFAULT_TERMINAL_ROWS)
        logging.debug(
            f"Using terminal metrics columns={screen_info['columns']} rows={screen_info['rows']} -> "
            f"{screen_info['pixel_width']}x{screen_info['pixel_height']}px @ {screen_info['dpi']}dpi"
        )

        # Offer payload and Guacamole ``size`` handshake must agree. The handler was created
        # earlier; refresh its stored width/height/dpi so a slightly later ``args``/handshake
        # matches what we send in the connection offer (avoids PTY geometry vs. local TTY drift).
        if python_handler is not None:
            python_handler.connection_settings['width'] = screen_info['pixel_width']
            python_handler.connection_settings['height'] = screen_info['pixel_height']
            python_handler.connection_settings['dpi'] = screen_info['dpi']
            # Keep connect-instruction lookup in sync with top-level handshake size/DPI.
            _gp_sync = python_handler.connection_settings.setdefault('guacd_params', {})
            _gp_sync['width'] = str(screen_info['pixel_width'])
            _gp_sync['height'] = str(screen_info['pixel_height'])
            _gp_sync['dpi'] = str(screen_info['dpi'])

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

        # Gateway may configure guacd from this map before Python's `connect`.
        offer_guacd_params: Dict[str, Any] = {'enable-pipe': 'true'}
        _offer_clip = settings.get('clipboard') or {}
        if use_python_handler:
            _cs_gp = connection_settings.get('guacd_params') or {}
            for _k, _v in _cs_gp.items():
                if _k in ('disable-paste', 'disable-copy'):
                    continue
                offer_guacd_params[_k] = _v
        if _offer_clip.get('disablePaste'):
            offer_guacd_params['disable-paste'] = 'true'
        if _offer_clip.get('disableCopy'):
            offer_guacd_params['disable-copy'] = 'true'

        _offer_disable_copy = bool(_offer_clip.get('disableCopy'))
        _offer_disable_paste = bool(_offer_clip.get('disablePaste'))

        offer_data = {
            "offer": offer_payload,
            "audio": ["audio/L8", "audio/L16"],  # Supported audio codecs
            "video": [],  # Supported video codecs - None for terminal
            # [width, height, dpi] — matches screen_info / pixel mode (e.g. 96 guacd, 192 kcm)
            "size": [screen_info['pixel_width'], screen_info['pixel_height'], screen_info['dpi']],
            "image": ["image/jpeg", "image/png", "image/webp"],  # Supported image formats
            # CRITICAL: Gateway needs 'host' to configure guacd connection
            "host": {
                "hostName": settings['hostname'],
                "port": settings['port']
            },
            # enable-pipe + optional disable-paste/disable-copy from PAM (see offer_guacd_params)
            "guacd_params": offer_guacd_params,
            "terminalSettings": {
                "disableCopy": _offer_disable_copy,
                "disablePaste": _offer_disable_paste,
            },
            # Alternate shape (PAM record uses connection.clipboard)
            "clipboard": {
                "disableCopy": _offer_disable_copy,
                "disablePaste": _offer_disable_paste,
            },
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

        logging.debug(f"Sending initial offer with connection parameters: {json.dumps(offer_data, indent=2)}")
        data_bytes = string_to_bytes(json.dumps(offer_data))
        encrypted_data = tunnel_encrypt(symmetric_key, data_bytes)

        # Get userRecordUid and credential flags from context (extracted in extract_terminal_settings)
        user_record_uid = context.get('userRecordUid')
        allow_supply_host = context.get('allowSupplyHost', False)
        allow_supply_user = context.get('allowSupplyUser', False)

        # Determine credential type for gateway inputs
        # Gateway credential types:
        # - 'linked': Look up credential in DAG (for records with DAG-linked pamUser)
        # - 'userSupplied': Skip DAG lookup, credentials from ConnectAs (-cr) or user prompt
        # - 'ephemeral': Gateway provisions a short-lived account (JIT create_ephemeral); no
        #   credentials flow from Commander. Optional jitElevation adds a group/role delta
        #   applied on top of the ephemeral or linked account.
        # - None: Use pamMachine credentials directly
        # Priority: allowSupplyHost > JIT (ephemeral) > cliUserOverride > userRecordUid > none.
        # allowSupplyHost wins per the Web Vault contract (also noted in the launch.py TODO now
        # removed); JIT elevation piggy-backs on 'linked' so the gateway still receives the
        # linked credential to elevate.
        credential_type_for_gateway = None
        cli_user_override = context.get('cliUserOverride', False)
        jit_enabled = context.get('jit_enabled', False)
        jit_mode = context.get('jit_mode') if jit_enabled else None
        jit_settings = context.get('jit_settings') or {} if jit_enabled else {}
        # allowSupplyHost disables JIT per Web Vault precedence; launch.py already rejects the
        # combination when JIT is requested, so here we simply let the existing userSupplied /
        # linked path handle allowSupplyHost records.
        if allow_supply_host and jit_mode:
            logging.debug(
                "allowSupplyHost is enabled; ignoring jit_mode=%s per Web Vault precedence",
                jit_mode,
            )
            jit_mode = None

        if jit_mode in (jit.JIT_MODE_EPHEMERAL, jit.JIT_MODE_BOTH):
            # Gateway creates a short-lived account; Commander does not carry the credential.
            # For 'both' (create_ephemeral + elevate) the gateway also applies the elevation
            # delta, so jitElevation is still emitted alongside jitSettings.
            credential_type_for_gateway = 'ephemeral'
            logging.debug("JIT ephemeral mode active - using 'ephemeral' for gateway")
        elif cli_user_override:
            # User explicitly supplied a different credential via -cr.
            # The -cr record is NOT DAG-linked to this machine so 'linked' would fail;
            # credentials arrive via the ConnectAs payload (built in launch.py after tunnel opens).
            # NOTE: -H/-hr are not accepted without -cr (legacy, to match Web Vault behaviour),
            # so cli_user_override=True is the only reliable signal that the user supplied something.
            credential_type_for_gateway = 'userSupplied'
            logging.debug("CLI credential override active - using 'userSupplied' for gateway")
        elif user_record_uid:
            # DAG-linked pamUser (no CLI override) - gateway looks up credentials via DAG.
            # When jit_mode == 'elevation' this path still applies: the gateway elevates the
            # linked account for the session and reverts on disconnect.
            credential_type_for_gateway = 'linked'
            if jit_mode == jit.JIT_MODE_ELEVATION:
                logging.debug(
                    f"JIT elevation mode active - using 'linked' credentials + jitElevation for {user_record_uid}"
                )
            else:
                logging.debug(f"Using 'linked' credential type for gateway with userRecordUid: {user_record_uid}")
        else:
            logging.debug(f"No linked pamUser for record {record_uid} - using pamMachine credentials directly")

        # Formerly a fixed ``time.sleep(1)`` — now 0.0 by default because the
        # preceding backend_delay already covers router registration. Set
        # PAM_PRE_OFFER_LEGACY=1 (or PAM_PRE_OFFER_SEC=<float>) to restore.
        _pre_offer = pre_offer_delay_sec()
        _pam_tc.checkpoint('pre_offer_sleep_start')
        if _pre_offer > 0:
            time.sleep(_pre_offer)
        _pam_tc.checkpoint('pre_offer_sleep_done')

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
                # JIT elevation: linked account stays, gateway applies group/role delta for
                # the session and reverts on disconnect.
                if jit_mode == jit.JIT_MODE_ELEVATION:
                    elevation_payload = jit.build_elevation_payload(jit_settings)
                    if elevation_payload:
                        inputs['jitElevation'] = elevation_payload
                        logging.debug(f"Attached jitElevation payload: {elevation_payload}")
            elif credential_type_for_gateway == 'userSupplied':
                inputs['credentialType'] = 'userSupplied'
                # For userSupplied, set allow_supply_user flag in connect_as_settings
                # This matches gateway behavior (line 1203 in tunnel_vault_record.py)
                inputs['allowSupplyUser'] = True
                logging.debug("Using userSupplied credential type - user will provide credentials")
            elif credential_type_for_gateway == 'ephemeral':
                # JIT ephemeral: gateway provisions a short-lived account and returns creds.
                # For 'both' (create_ephemeral + elevate), jitElevation is emitted alongside.
                inputs['credentialType'] = 'ephemeral'
                ephemeral_payload = jit.build_ephemeral_payload(jit_settings)
                if ephemeral_payload:
                    inputs['jitSettings'] = ephemeral_payload
                if jit_mode == jit.JIT_MODE_BOTH:
                    elevation_payload = jit.build_elevation_payload(jit_settings)
                    if elevation_payload:
                        inputs['jitElevation'] = elevation_payload
                logging.debug(
                    f"Using ephemeral credential type - gateway will provision JIT account "
                    f"(jitSettings={ephemeral_payload})"
                )
            # else: no credentialType - gateway uses pamMachine credentials directly (backward compatible)

            # Add 2FA value if workflow requires MFA
            two_factor_value = kwargs.get('two_factor_value')
            if two_factor_value:
                inputs['twoFactorValue'] = two_factor_value

            # Router token is no longer extracted from cookies (removed in commit 338a9fda)
            # Router affinity is now handled server-side

            # Generate messageId from conversationId (replace + with -, / with _)
            message_id = GatewayAction.conversation_id_to_message_id(conversation_id_original)
            logging.debug(f"Generated messageId: {message_id} from conversationId: {conversation_id_original}")

            # --- Gateway offer POST with retry + adaptive backend-delay fallback ---
            # On a first-attempt failure that looks like a transient backend-not-ready
            # condition (timeout, 502/503/504, controller_down, RRC timeout), sleep
            # the retry base delay plus the delta between the fast default and the
            # legacy ``WEBSOCKET_BACKEND_DELAY`` so the cumulative wait on the retry
            # matches the pre-change behavior. Fast path stays fast; unlucky first
            # try still gets the full safety window before a second attempt.
            try:
                _max_offer_attempts = max(1, int(os.environ.get('PAM_GATEWAY_OFFER_MAX_ATTEMPTS', '2')))
            except (TypeError, ValueError):
                _max_offer_attempts = 2
            _offer_retry_extra = offer_retry_extra_delay_sec()
            _offer_backend_catchup = max(
                0.0,
                websocket_backend_delay_legacy_sec() - websocket_backend_delay_sec(),
            )
            _offer_transient_patterns = (
                'timeout', 'rrc_timeout', 'bad_state', 'connection',
                '502', '503', '504', 'controller_down',
            )

            def _send_gateway_offer_with_retry(is_streaming, **extra_kwargs):
                _resp = None
                for _oa in range(_max_offer_attempts):
                    if _oa > 0:
                        if _offer_backend_catchup > 0 or _offer_retry_extra > 0:
                            _pam_tc.checkpoint('gateway_offer_backend_catchup_delay_start')
                        time.sleep(_offer_retry_extra + _offer_backend_catchup)
                        if _offer_backend_catchup > 0 or _offer_retry_extra > 0:
                            _pam_tc.checkpoint('gateway_offer_backend_catchup_delay_done')
                    _pam_tc.checkpoint(
                        'gateway_offer_http_attempt_1' if _oa == 0
                        else 'gateway_offer_http_attempt_{}'.format(_oa + 1)
                    )
                    try:
                        _resp = router_send_action_to_gateway(
                            params=params,
                            destination_gateway_uid_str=gateway_uid,
                            gateway_action=GatewayActionWebRTCSession(
                                conversation_id=conversation_id_original,
                                inputs=inputs,
                                message_id=message_id,
                            ),
                            message_type=pam_pb2.CMT_CONNECT,
                            is_streaming=is_streaming,
                            gateway_timeout=30000,
                            **extra_kwargs,
                        )
                    except requests.exceptions.RequestException as _re:
                        if _oa < _max_offer_attempts - 1:
                            logging.warning(
                                'Gateway offer HTTP error (%s); retrying (attempt %s/%s)',
                                _re, _oa + 1, _max_offer_attempts,
                            )
                            continue
                        raise
                    except Exception as _ge:
                        _em = str(_ge).lower()
                        if _oa < _max_offer_attempts - 1 and any(
                            _p in _em for _p in _offer_transient_patterns
                        ):
                            logging.warning(
                                'Gateway offer transient failure (%s); retrying (attempt %s/%s)',
                                _ge, _oa + 1, _max_offer_attempts,
                            )
                            continue
                        raise
                    if _resp is None and _oa < _max_offer_attempts - 1:
                        logging.warning(
                            'Gateway offer returned no response; retrying (attempt %s/%s)',
                            _oa + 1, _max_offer_attempts,
                        )
                        continue
                    break
                _pam_tc.checkpoint('gateway_offer_http_done')
                return _resp

            # Two paths: streaming vs non-streaming
            if trickle_ice:
                # Streaming path: Response will come via WebSocket (use same tokens and session as WebSocket for ALB stickiness)
                offer_kwargs = {}
                if router_tokens and len(router_tokens) >= 3:
                    offer_kwargs = {
                        "transmission_key": router_tokens[2],
                        "encrypted_transmission_key": router_tokens[1],
                        "encrypted_session_token": router_tokens[0],
                    }
                if http_session is not None:
                    offer_kwargs["http_session"] = http_session
                router_response = _send_gateway_offer_with_retry(is_streaming=True, **offer_kwargs)

                logging.debug(f"{bcolors.OKGREEN}Offer sent to gateway (streaming mode){bcolors.ENDC}")

                # Mark offer as sent
                signal_handler.offer_sent = True
                tunnel_session.offer_sent = True

                # Send any buffered ICE candidates — one batched HTTP POST instead of N
                # serial ``_send_ice_candidate_immediately`` calls. The gateway's
                # ``add_ice_candidates_to_conversation_tunnel`` already iterates the
                # ``candidates`` array internally and each ``add_ice_candidate`` PyO3
                # call is spawn-and-return, so a batch costs the server ~the same as
                # a single candidate while collapsing ~N*500ms of client-side round
                # trips into one.
                if tunnel_session.buffered_ice_candidates:
                    logging.debug(f"Flushing {len(tunnel_session.buffered_ice_candidates)} buffered ICE candidates")
                    signal_handler._send_ice_candidates_batch(
                        tunnel_session.buffered_ice_candidates, commander_tube_id
                    )
                    tunnel_session.buffered_ice_candidates.clear()

                logging.debug(f"{bcolors.OKGREEN}Terminal connection established for {protocol.upper()}{bcolors.ENDC}")
                logging.debug(f"{bcolors.OKBLUE}Connection state: {bcolors.ENDC}gathering candidates...")

                _pam_tc.summary('webrtc_tunnel_open_ok_streaming')
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
                    "user_record_uid": user_record_uid,  # For ConnectAs payload
                    "gateway_uid": gateway_uid,  # For ConnectAs payload
                }
            else:
                # Non-streaming path: Handle response immediately
                router_response = _send_gateway_offer_with_retry(is_streaming=False)

                logging.debug(f"{bcolors.OKGREEN}Offer sent to gateway (non-streaming mode){bcolors.ENDC}")
                logging.debug(f"Router response: {router_response}")

                # Must be defined before return below; only refined inside `if router_response`.
                remote_webrtc_version = None

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

                                        # Parse JSON; fallback to raw SDP if decrypted data is plain SDP
                                        answer_sdp = None
                                        data_json = None
                                        try:
                                            data_json = json.loads(data_text)
                                            if isinstance(data_json, dict):
                                                logging.debug(f"🔓 Decrypted payload type: {data_json.get('type', 'unknown')}, keys: {list(data_json.keys())}")
                                                answer_sdp = data_json.get('answer') or data_json.get('sdp')
                                        except (json.JSONDecodeError, TypeError):
                                            if data_text.strip().startswith('v=') and 'm=' in data_text:
                                                answer_sdp = data_text.strip()
                                                logging.debug("Decrypted data appears to be raw SDP (not JSON), using as answer")

                                        if answer_sdp:
                                            logging.debug(f"Found SDP answer in non-streaming response, sending to Rust for conversation: {conversation_id_original}")
                                            remote_webrtc_version = set_remote_description_and_parse_version(
                                                tube_registry, commander_tube_id, answer_sdp, is_answer=True
                                            )

                                            if hasattr(tunnel_session, "gateway_ready_event") and tunnel_session.gateway_ready_event is not None:
                                                tunnel_session.gateway_ready_event.set()
                                            logging.debug(f"{bcolors.OKBLUE}Connection state: {bcolors.ENDC}SDP answer received, connecting...")

                                            if tunnel_session.buffered_ice_candidates:
                                                logging.debug(f"Sending {len(tunnel_session.buffered_ice_candidates)} buffered ICE candidates after answer")
                                                signal_handler._send_ice_candidates_batch(
                                                    tunnel_session.buffered_ice_candidates, commander_tube_id
                                                )
                                                tunnel_session.buffered_ice_candidates.clear()
                                        elif isinstance(data_json, dict) and ("offer" in data_json or data_json.get("type") == "offer"):
                                            logging.warning(f"Received ICE restart offer in non-streaming mode - this is unexpected")
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

                _pam_tc.summary('webrtc_tunnel_open_ok_non_streaming')
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
                    "user_record_uid": user_record_uid,  # For ConnectAs payload
                    "gateway_uid": gateway_uid,  # For ConnectAs payload
                    "remote_webrtc_version": remote_webrtc_version,  # From SDP for ConnectAs capability
                }

        except Exception as e:
            # Stop dedicated WebSocket before Rust/tube cleanup so we do not process a late
            # channel_closed after the CLI has already returned (avoids stray ERROR after prompt).
            try:
                if tunnel_session.websocket_stop_event and tunnel_session.websocket_thread:
                    tunnel_session.websocket_stop_event.set()
                    tunnel_session.websocket_thread.join(timeout=3.0)
            except Exception:
                logging.debug("Stopping WebSocket after HTTP offer failure", exc_info=True)
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
        _launch_tc = PamConnectTiming('pam-launch:terminal_connection')
        _launch_tc.checkpoint('enter')
        # Step 1: Detect protocol
        protocol = detect_protocol(params, record_uid)
        if not protocol or protocol not in ALL_TERMINAL:
            raise CommandError(
                'pam launch',
                f'Protocol {protocol!r} is not supported for record {record_uid}. '
                'Only terminal protocols (ssh, telnet, kubernetes, mysql, postgresql, sql-server) are supported.'
            )

        logging.debug(f"Detected protocol: {protocol}")
        _launch_tc.checkpoint('protocol_detected')

        # Step 2: Extract settings (with optional CLI overrides).
        # Forward the pre-resolved DAG launch credential UID when the caller supplied it
        # (pam launch does, to collapse three DAG loads into one); otherwise
        # extract_terminal_settings falls back to resolving it internally.
        settings = extract_terminal_settings(
            params,
            record_uid,
            protocol,
            launch_credential_uid=kwargs.get('launch_credential_uid'),
            custom_host=kwargs.get('custom_host'),
            custom_port=kwargs.get('custom_port'),
            dag_linked_uid=kwargs.get('dag_linked_uid', _DAG_UID_UNSET),
        )
        # JIT is opt-in via --jit. extract_terminal_settings always reads the record's
        # jit_settings so validation can inspect them, but we only treat JIT as "active"
        # (i.e. emit it to the gateway) when the operator explicitly requested it.
        settings['jit_enabled'] = bool(kwargs.get('jit'))
        if not settings['jit_enabled']:
            # Clear derived jit_mode so downstream branches fall through to the normal path.
            settings['jit_mode'] = None
            settings['jit_settings'] = None
        logging.debug(f"Extracted settings: hostname={settings['hostname']}, port={settings['port']}")
        _launch_tc.checkpoint('settings_extracted')

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
        _launch_tc.checkpoint('context_built')

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
        _launch_tc.checkpoint('webrtc_tunnel_opened')

        logging.debug(f"Terminal connection established for {protocol}")
        logging.debug(f"Target: {settings['hostname']}:{settings['port']}")
        logging.debug(f"Gateway: {gateway_info['gateway_name']} ({gateway_info['gateway_uid']})")

        _launch_tc.summary('terminal_connection_ok')
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
