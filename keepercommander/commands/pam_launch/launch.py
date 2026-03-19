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

from __future__ import annotations
import argparse
import os
import ipaddress
import logging
import re
import shutil
import signal
import time
from typing import TYPE_CHECKING, Dict, Any, Optional, Tuple

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from .terminal_connection import (
    _build_connect_as_payload,
    _retrieve_gateway_public_key,
    _get_launch_credential_uid,
    launch_terminal_connection,
    detect_protocol,
    ALL_TERMINAL,
    CONNECT_AS_MIN_VERSION,
    _version_at_least,
    _pam_settings_connection_port,
)
from .terminal_size import get_terminal_size_pixels, is_interactive_tty
from .guac_cli.stdin_handler import StdinHandler
from ..base import Command
from ..tunnel.port_forward.tunnel_helpers import (
    get_gateway_uid_from_record,
    get_config_uid_from_record,
    get_tunnel_session,
    unregister_tunnel_session,
    unregister_conversation_key,
)
from .rust_log_filter import (
    enter_pam_launch_terminal_rust_logging,
    exit_pam_launch_terminal_rust_logging,
)
from ..pam.gateway_helper import get_all_gateways
from ..pam.router_helper import router_get_connected_gateways
from ... import api, vault
from ...subfolder import try_resolve_path
from ...error import CommandError

if TYPE_CHECKING:
    from ...params import KeeperParams


def _parse_host_port(value: str) -> Tuple[str, int]:
    """
    Parse a 'host:port' or '[ipv6]:port' string into (host, port).

    Supported formats:
      - IPv4 / hostname:  192.168.1.1:22  or  server.example.com:3306
      - IPv6:             [::1]:22         or  [2001:db8::1]:443

    Raises:
        CommandError: if the format is invalid or the port is out of range.
    """
    value = value.strip()
    if value.startswith('['):
        end_bracket = value.find(']')
        if end_bracket == -1:
            raise CommandError('pam launch',
                f'Invalid host format {value!r}. Expected [ipv6]:port (e.g. [::1]:22).')
        host = value[1:end_bracket]
        rest = value[end_bracket + 1:]
        if not rest.startswith(':'):
            raise CommandError('pam launch',
                f'Invalid host format {value!r}. Expected [ipv6]:port (e.g. [::1]:22).')
        port_str = rest[1:]
    elif ':' in value:
        last_colon = value.rfind(':')
        host = value[:last_colon]
        port_str = value[last_colon + 1:]
    else:
        raise CommandError('pam launch',
            f'Invalid host format {value!r}. Expected host:port (e.g. 192.168.1.1:22 or server.example.com:3306).')
    try:
        port = int(port_str)
    except ValueError:
        raise CommandError('pam launch',
            f'Invalid port {port_str!r} in {value!r}. Port must be an integer 1-65535.')
    _validate_host_port(host, port)
    return host, port


def _validate_host_port(host: str, port: int) -> None:
    """
    Validate host (non-empty, valid IPv4/IPv6 or hostname) and port (1-65535).
    Raises CommandError if invalid.
    """
    if not host:
        raise CommandError('pam launch', 'Host cannot be empty.')
    if not (1 <= port <= 65535):
        raise CommandError('pam launch', f'Port {port} is out of range (valid range: 1-65535).')
    # Attempt strict IP validation; if it raises ValueError the host is treated as a hostname
    # (any non-empty hostname string is accepted — the gateway does the DNS resolution).
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass  # Not an IP literal — treat as hostname, basic non-empty check above is sufficient


def _iter_record_fields(record: Any):
    """Yield every TypedField from both record.fields and record.custom."""
    for field in list(getattr(record, 'fields', None) or []) + list(getattr(record, 'custom', None) or []):
        yield field


def _get_host_port_from_record(record: Any) -> Tuple[Optional[str], Optional[int]]:
    """
    Extract (hostName, port) from a record's pamHostname or host typed fields.

    Requires a non-empty hostName on exactly one such field. Port comes from
    pamSettings.connection.port when the record is pamMachine/pamDirectory/pamDatabase
    and that port is set (overrides the field's port); otherwise from the field's port.

    Raises CommandError if more than one qualifying host field is found (ambiguous).

    Returns:
        Tuple of (host, port) where either may be None if none found.
    """
    if not record:
        return None, None

    pam_override_port = _pam_settings_connection_port(record)
    candidates: list = []
    for field in _iter_record_fields(record):
        if getattr(field, 'type', None) not in ('pamHostname', 'host'):
            continue
        value = field.get_default_value(dict) if hasattr(field, 'get_default_value') else {}
        if not isinstance(value, dict):
            continue
        host = (value.get('hostName') or '').strip()
        if not host:
            continue
        port_raw = pam_override_port if pam_override_port is not None else value.get('port')
        if not port_raw:
            continue
        try:
            p = int(port_raw)
        except (ValueError, TypeError):
            continue
        if 1 <= p <= 65535:
            candidates.append((host, p))

    if len(candidates) > 1:
        raise CommandError('pam launch',
            f'Record has {len(candidates)} non-empty host/pamHostname fields with valid host and port '
            '(expected exactly one). Clear the extra field before launching.')
    if not candidates:
        return None, None
    return candidates[0]


def _record_has_credentials(record: Any) -> bool:
    """
    Return True if the record has exactly one non-empty login field and exactly one non-empty
    password field (value[0] != ''). Searches both fields[] and custom[].

    Raises CommandError if multiple non-empty fields of the same type are found (ambiguous).
    """
    if not record:
        return False

    def _count_nonempty(field_type: str) -> int:
        count = 0
        for field in _iter_record_fields(record):
            if getattr(field, 'type', None) == field_type:
                val = field.get_default_value(str) if hasattr(field, 'get_default_value') else ''
                if val:
                    count += 1
        return count

    login_count = _count_nonempty('login')
    if login_count > 1:
        raise CommandError('pam launch',
            f'Record has {login_count} non-empty login fields (expected exactly one). '
            'Clear the extra login field before launching.')
    if login_count == 0:
        return False

    password_count = _count_nonempty('password')
    if password_count > 1:
        raise CommandError('pam launch',
            f'Record has {password_count} non-empty password fields (expected exactly one). '
            'Clear the extra password field before launching.')
    if password_count == 0:
        return False

    return True


def _record_has_host_port(record: Any) -> bool:
    """Return True if the record has exactly one non-empty host/pamHostname field with valid host and port."""
    host, port = _get_host_port_from_record(record)
    return bool(host) and port is not None


class PAMLaunchCommand(Command):
    """PAM Launch command to launch a connection to a PAM resource"""

    # Valid PAM record types for launch
    VALID_PAM_RECORD_TYPES = {'pamDatabase', 'pamDirectory', 'pamMachine'}

    parser = argparse.ArgumentParser(prog='pam launch', description='Launch a connection to a PAM resource')
    parser.add_argument('record', type=str, action='store',
                        help='Record path or UID of the PAM resource to launch')
    parser.add_argument('--no-trickle-ice', '-nti', required=False, dest='no_trickle_ice', action='store_true',
                        help='Disable trickle ICE for WebRTC connections. By default, trickle ICE is enabled '
                             'for real-time candidate exchange.')
    parser.add_argument('--credential', '-cr', required=False, dest='launch_credential', type=str,
                        help='Record (UID, path, or title) for launch credentials')
    parser.add_argument('--host', '-H', required=False, dest='custom_host', type=str,
                        help='Host and port in format host:port (e.g. -H=192.168.1.1:22 or -H=[::1]:22 for IPv6). '
                             'Requires allowSupplyHost. Mutually exclusive with --host-record.')
    parser.add_argument('--host-record', '-hr', required=False, dest='host_record', type=str,
                        help='Record (UID, path, or title) with a host or pamHostname field containing hostName and port. '
                             'Requires allowSupplyHost. Mutually exclusive with --host.')

    def get_parser(self):
        return PAMLaunchCommand.parser

    def _is_valid_pam_record(self, params: KeeperParams, record_uid: str) -> bool:
        """
        Check if a record is a valid PAM record type.

        Args:
            params: KeeperParams instance
            record_uid: Record UID to check

        Returns:
            True if record is a valid PAM type (version 3 TypedRecord with PAM type), False otherwise
        """
        try:
            record = vault.KeeperRecord.load(params, record_uid)
            if not isinstance(record, vault.TypedRecord):
                return False
            if record.version != 3:
                return False
            return record.record_type in self.VALID_PAM_RECORD_TYPES
        except Exception as e:
            logging.debug(f"Error checking record type for {record_uid}: {e}")
            return False

    def find_record(self, params: KeeperParams, record_token: str) -> Optional[str]:
        """
        Find a record by UID, path, or title.

        Args:
            params: KeeperParams instance
            record_token: Record identifier (UID, path, or title)

        Returns:
            Record UID if found, None otherwise
        """
        if not record_token:
            return None

        record_token = record_token.strip()

        # Step 1: Try UID lookup
        uid_pattern = re.compile(r'^[A-Za-z0-9_-]{22}$')
        if uid_pattern.match(record_token):
            if record_token in params.record_cache:
                logging.debug(f"Found record by UID: {record_token}")
                return record_token

        # Step 2: Try path lookup
        record_uid = self._find_by_path(params, record_token)
        if record_uid:
            return record_uid

        # Step 3: Try full title match
        record_uid = self._find_by_title(params, record_token)
        if record_uid:
            return record_uid

        return None

    def _find_by_path(self, params: KeeperParams, path: str) -> Optional[str]:
        """
        Find record by path resolution.

        If exactly one record matches (any type), returns its UID. If two or more
        match, filters to PAM types only: returns the single PAM UID if one,
        else logs error (no PAM types vs multiple PAM matches) and returns None.

        Returns:
            Record UID if found, None otherwise
        """
        rs = try_resolve_path(params, path)
        if rs is None:
            return None

        folder, name = rs
        if folder is None or name is None:
            return None

        folder_uid = folder.uid or ''
        if folder_uid not in params.subfolder_record_cache:
            return None

        # All records in folder with matching title (any type)
        all_matched = []
        for uid in params.subfolder_record_cache[folder_uid]:
            r = api.get_record(params, uid)
            if r and r.title and r.title.lower() == name.lower():
                all_matched.append(uid)

        if len(all_matched) == 1:
            logging.debug(f"Found record by path: {path} -> {all_matched[0]}")
            return all_matched[0]

        if len(all_matched) >= 2:
            pam_matched = [uid for uid in all_matched if self._is_valid_pam_record(params, uid)]
            if len(pam_matched) == 1:
                logging.debug(f"Found record by path: {path} -> {pam_matched[0]} (1 PAM among {len(all_matched)} matches)")
                return pam_matched[0]
            if len(pam_matched) == 0:
                logging.error(
                    'pam launch: path "%s" matches %d record(s) but none are PAM types (pamMachine, pamDirectory, pamDatabase). Use UID or a path that resolves to a single PAM record.',
                    path, len(all_matched),
                )
                return None
            logging.error(
                'pam launch: path "%s" matches %d PAM records. Please use a unique identifier (UID or full path).',
                path, len(pam_matched),
            )
            return None

        return None

    def _find_by_title(self, params: KeeperParams, title: str) -> Optional[str]:
        """
        Find record by exact title match.

        If exactly one record matches (any type), returns its UID. If two or more
        match, filters to PAM types only: returns the single PAM UID if one,
        else logs error (no PAM types vs multiple PAM matches) and returns None.

        Returns:
            Record UID if found, None otherwise
        """
        all_matched = []
        for record_uid in params.record_cache:
            record = vault.KeeperRecord.load(params, record_uid)
            if record and record.title and record.title.lower() == title.lower():
                all_matched.append(record_uid)

        if len(all_matched) == 1:
            logging.debug(f"Found record by title: {title} -> {all_matched[0]}")
            return all_matched[0]

        if len(all_matched) >= 2:
            pam_matched = [uid for uid in all_matched if self._is_valid_pam_record(params, uid)]
            if len(pam_matched) == 1:
                logging.debug(f"Found record by title: {title} -> {pam_matched[0]} (1 PAM among {len(all_matched)} matches)")
                return pam_matched[0]
            if len(pam_matched) == 0:
                logging.error(
                    'pam launch: title "%s" matches %d record(s) but none are PAM types (pamMachine, pamDirectory, pamDatabase). Use UID or full path.',
                    title, len(all_matched),
                )
                return None
            logging.error(
                'pam launch: title "%s" matches %d PAM records. Please use a unique identifier (UID or full path).',
                title, len(pam_matched),
            )
            return None

        return None

    def find_gateway(self, params: KeeperParams, record_uid: str) -> Optional[Dict]:
        """
        Find the gateway associated with a PAM record.

        Args:
            params: KeeperParams instance
            record_uid: Record UID to find gateway for (must be pre-validated as PAM type)

        Returns:
            Dictionary with gateway information including:
            - gateway_uid: Gateway UID (str)
            - gateway_name: Gateway name (str)
            - config_uid: PAM configuration UID (str)
            - gateway_proto: Gateway protobuf object (pam_pb2.PAMController)
            Returns None if no gateway found

        Raises:
            CommandError: If gateway configuration issues exist
        """
        # Get the gateway UID from the record
        # Note: Record type validation happens in find_record()
        gateway_uid = get_gateway_uid_from_record(params, vault, record_uid)

        if not gateway_uid:
            raise CommandError('pam launch', f'No gateway found for record {record_uid}. ')

        logging.debug(f"Found gateway UID for record: {gateway_uid}")

        # Get all gateways to find the matching one
        all_gateways = get_all_gateways(params)

        # Find the gateway by UID
        gateway_uid_bytes = url_safe_str_to_bytes(gateway_uid)
        gateway_proto = next((g for g in all_gateways if g.controllerUid == gateway_uid_bytes), None)

        if not gateway_proto:
            raise CommandError('pam launch', f'Gateway {gateway_uid} not found in available gateways.')

        gateway_name = gateway_proto.controllerName if gateway_proto else 'Unknown'
        logging.debug(f"Found gateway: {gateway_name} ({gateway_uid})")

        # Get the configuration UID
        config_uid = get_config_uid_from_record(params, vault, record_uid)

        return {
            'gateway_uid': gateway_uid,
            'gateway_name': gateway_name,
            'config_uid': config_uid,
            'gateway_proto': gateway_proto
        }

    def execute(self, params: KeeperParams, **kwargs):
        """
        Execute the PAM launch command

        Args:
            params: KeeperParams instance containing session state
            **kwargs: Command arguments including 'record' (record path or UID)
        """
        # Save original root logger level and set to ERROR if not in DEBUG mode
        root_logger = logging.getLogger()
        original_level = root_logger.level

        if root_logger.getEffectiveLevel() > logging.DEBUG:
            root_logger.setLevel(logging.ERROR)

        try:
            # TODO: Add JIT - note that allowSupplyHost overrides all other supply modes.
            # When a PAM record has allowSupplyHost, allowSupplyUser, and JIT settings all enabled,
            # the Web Vault (and this CLI) treat allowSupplyHost as the active mode and ignore the
            # other two. Any validation logic below must reflect this precedence: if allowSupplyHost
            # is True, treat the record as "host+credential supply" mode regardless of the other flags.

            record_token = kwargs.get('record')

            if not record_token:
                logging.error("Record path or UID is required")
                return

            # Find the record
            record_uid = self.find_record(params, record_token)

            if not record_uid:
                raise CommandError('pam launch', f'Record not found: {record_token}')

            logging.debug(f"Found record: {record_uid}")

            record = vault.KeeperRecord.load(params, record_uid)
            if not isinstance(record, vault.TypedRecord):
                raise CommandError('pam launch', f'Record {record_uid} is not a TypedRecord')

            if not self._is_valid_pam_record(params, record_uid):
                record_type = getattr(record, 'record_type', type(record).__name__)
                raise CommandError('pam launch',f'Record {record_uid} of type "{record_type}" is not a machine record type (pamMachine, pamDirectory, pamDatabase)')

            # Only terminal protocols are supported (SSH, Telnet, Kubernetes, databases).
            protocol = detect_protocol(params, record_uid)
            if protocol not in ALL_TERMINAL:
                logging.error(
                    "pam launch only supports terminal protocols (ssh, telnet, kubernetes, mysql, postgresql, sql-server). "
                    "Protocol %r is not supported; use Web Vault for RDP/VNC/RBI etc.",
                    protocol,
                )
                return

            # Get DAG-linked credential UID early (needed for comparison and validation)
            dag_linked_uid = _get_launch_credential_uid(params, record_uid)
            if not dag_linked_uid:
                # Fallback: first entry in pamSettings.connection.userRecords
                _psf = record.get_typed_field('pamSettings')
                if _psf:
                    _psv = _psf.get_default_value(dict)
                    if _psv:
                        _conn = _psv.get('connection', {})
                        if isinstance(_conn, dict):
                            _ur = _conn.get('userRecords', [])
                            if _ur:
                                dag_linked_uid = _ur[0]

            # Read allowSupply flags from pamSettings
            pam_settings_field = record.get_typed_field('pamSettings')
            allow_supply_user = False
            allow_supply_host = False
            if pam_settings_field:
                pam_settings_value = pam_settings_field.get_default_value(dict)
                if pam_settings_value:
                    allow_supply_host = pam_settings_value.get('allowSupplyHost', False)
                    connection = pam_settings_value.get('connection', {})
                    if isinstance(connection, dict):
                        allow_supply_user = connection.get('allowSupplyUser', False)

            # Get record host/port for fallback validation
            hostname_on_record, port_on_record = _get_host_port_from_record(record)

            # --- Resolve --credential option ---
            launch_credential = kwargs.get('launch_credential')
            launch_credential_uid = None
            if launch_credential:
                # Reject early — before record resolution — when neither supply flag permits it.
                # (With host options the flag requirement is checked later; here we only gate the
                # case where -cr alone requires at least one supply flag to be meaningful.)
                if not allow_supply_user and not allow_supply_host:
                    raise CommandError('pam launch',
                        '--credential requires allowSupplyUser or allowSupplyHost to be enabled on the record.')
                launch_credential_uid = self.find_record(params, launch_credential)
                if not launch_credential_uid:
                    raise CommandError('pam launch', f'Credential record not found: {launch_credential}')

            # --- Parse --host / --host-record (mutually exclusive) ---
            raw_custom_host = kwargs.get('custom_host')
            host_record_token = kwargs.get('host_record')
            custom_host = None
            custom_port = None

            # All -H/-hr checks happen BEFORE any record resolution to give the right error first.

            # -H and -hr are mutually exclusive (conflicting options prevent execution).
            if raw_custom_host and host_record_token:
                raise CommandError('pam launch',
                    'Cannot use both --host and --host-record. Use one to specify the target host.')

            # Options conflict: -H/-hr require -cr (Web Vault: host and credentials supplied together).
            if (raw_custom_host or host_record_token) and not launch_credential:
                raise CommandError('pam launch',
                    '--host / --host-record requires --credential (-cr) to also be provided. '
                    'When allowSupplyHost is enabled, credentials and host must be supplied together.')

            # allowSupplyHost must be enabled to use -H/-hr at all.
            if (raw_custom_host or host_record_token) and not allow_supply_host:
                raise CommandError('pam launch',
                    '--host / --host-record requires allowSupplyHost to be enabled on the record. '
                    '(Web Vault: Record > Allow shared users to select their own host and credential)')

            if raw_custom_host:
                custom_host, custom_port = _parse_host_port(raw_custom_host)
                kwargs['custom_host'] = custom_host
                kwargs['custom_port'] = custom_port
                logging.debug(f"Parsed --host: {custom_host}:{custom_port}")

            if host_record_token:
                host_record_uid = self.find_record(params, host_record_token)
                if not host_record_uid:
                    raise CommandError('pam launch', f'Host record not found: {host_record_token}')
                host_record = vault.KeeperRecord.load(params, host_record_uid)
                if not host_record:
                    raise CommandError('pam launch', f'Could not load host record: {host_record_uid}')
                custom_host, custom_port = _get_host_port_from_record(host_record)
                if not custom_host:
                    raise CommandError('pam launch',
                        f'Record {host_record_token} has no hostname. '
                        'It must have a host or pamHostname field with hostName.')
                if custom_port is None:
                    raise CommandError('pam launch',
                        f'Record {host_record_token} has no valid port (1-65535). '
                        'It must have a host or pamHostname field with a port.')
                kwargs['custom_host'] = custom_host
                kwargs['custom_port'] = custom_port
                logging.debug(f"Using host from record {host_record_uid}: {custom_host}:{custom_port}")

            has_cli_host = custom_host is not None
            has_cli_cred = launch_credential_uid is not None

            # --credential record with no host options that matches DAG-linked -> treat as no --credential
            if has_cli_cred and not has_cli_host and launch_credential_uid == dag_linked_uid:
                logging.warning(
                    '--credential %s matches linked Launch Credential; treating as if no --credential provided',
                    launch_credential,
                )
                launch_credential_uid = None
                has_cli_cred = False

            # --host / --host-record require allowSupplyHost
            if has_cli_host and not allow_supply_host:
                raise CommandError('pam launch',
                    '--host / --host-record requires allowSupplyHost to be enabled on the record. '
                    '(Web Vault: Record > Allow shared users to select their own host and credential)')

            if has_cli_cred:
                # with host options -> allowSupplyHost; without -> allowSupplyUser or allowSupplyHost
                if has_cli_host:
                    if not allow_supply_host:
                        raise CommandError('pam launch',
                            '--credential with --host/--host-record requires allowSupplyHost to be enabled.')
                else:
                    if not allow_supply_user and not allow_supply_host:
                        raise CommandError('pam launch',
                            '--credential requires allowSupplyUser or allowSupplyHost to be enabled on the record.')

                # Strictly validate --credential record has login and password
                cred_record = vault.KeeperRecord.load(params, launch_credential_uid)
                if not cred_record:
                    raise CommandError('pam launch', f'Credential record not found: {launch_credential_uid}')
                if not _record_has_credentials(cred_record):
                    raise CommandError('pam launch',
                        f'Credential record {launch_credential_uid} must have non-empty login and password fields.')

                if allow_supply_host:
                    # allowSupplyHost mode: host comes from -H/-hr (CLI) or from the --credential record.
                    if has_cli_host:
                        # -H/-hr provided: CLI host wins. Warn if --credential also has a host.
                        if _record_has_host_port(cred_record):
                            _cr_host, _ = _get_host_port_from_record(cred_record)
                            logging.warning(
                                '--host / --host-record (%s:%s) overrides host %r from --credential record %s; '
                                'the credential record host will be ignored.',
                                custom_host, custom_port, _cr_host, launch_credential_uid,
                            )
                    else:
                        # no -H/-hr -> --credential record must supply host:port.
                        if not _record_has_host_port(cred_record):
                            raise CommandError('pam launch',
                                f'Credential record {launch_credential_uid} must have a non-empty host and port '
                                'when allowSupplyHost is enabled and no --host or --host-record is provided.')
                        cred_host, cred_port = _get_host_port_from_record(cred_record)
                        custom_host = cred_host
                        custom_port = cred_port
                        kwargs['custom_host'] = custom_host
                        kwargs['custom_port'] = custom_port
                        logging.debug(f"Using host from --credential record: {custom_host}:{custom_port}")

                else:
                    # allowSupplyUser mode: only login + password come from --credential.
                    # Any host/pamHostname on the --credential record is intentionally ignored;
                    # host and port always come from the PAM machine/connection record.
                    if _record_has_host_port(cred_record):
                        _cr_host, _ = _get_host_port_from_record(cred_record)
                        logging.warning(
                            'allowSupplyUser mode: host %r in --credential record %s is ignored; '
                            'host and port will come from the PAM machine record.',
                            _cr_host, launch_credential_uid,
                        )

                kwargs['launch_credential_uid'] = launch_credential_uid
                logging.debug(f"Using --credential: {launch_credential_uid}")

            else:
                # No --credential: validate that the record itself provides what's needed
                if not has_cli_host:
                    # No CLI host -> must come from the PAM launch record
                    if not hostname_on_record:
                        if allow_supply_host:
                            raise CommandError('pam launch',
                                'allowSupplyHost is enabled but no hostname on record. '
                                'Use --host, --host-record, or --credential with a host:port to specify.')
                        else:
                            raise CommandError('pam launch',
                                f'No hostname configured for record {record_uid}.')

                    # No CLI options at all -> validate DAG-linked credential has login + password
                    if dag_linked_uid:
                        dag_cred_record = vault.KeeperRecord.load(params, dag_linked_uid)
                        if dag_cred_record and not _record_has_credentials(dag_cred_record):
                            raise CommandError('pam launch',
                                f'Linked credential record {dag_linked_uid} has empty login or password. '
                                'Configure valid credentials or use --credential to override.')
                    elif not allow_supply_user and not allow_supply_host:
                        raise CommandError('pam launch',
                            f'No credentials configured for record {record_uid}. '
                            'Configure a linked credential or enable allowSupplyUser/allowSupplyHost.')

            # Find the gateway for this record
            gateway_info = self.find_gateway(params, record_uid)

            if not gateway_info:
                raise CommandError('pam launch', f'No gateway found for record {record_uid}')

            logging.debug(f"Found gateway: {gateway_info['gateway_name']} ({gateway_info['gateway_uid']})")
            logging.debug(f"Configuration: {gateway_info['config_uid']}")

            # Optionally check if Gateway appears online; if not, log warning and try anyway.
            try:
                connected_gateways = router_get_connected_gateways(params)
                if connected_gateways and connected_gateways.controllers:
                    connected_gateway_uids = [x.controllerUid for x in connected_gateways.controllers]
                    gateway_uid_bytes = url_safe_str_to_bytes(gateway_info['gateway_uid'])
                    if gateway_uid_bytes not in connected_gateway_uids:
                        logging.warning(
                            'Gateway "%s" (%s) seems offline - trying to connect anyway.',
                            gateway_info['gateway_name'], gateway_info['gateway_uid']
                        )
                    else:
                        logging.debug(f"✓ Gateway is online and connected")
                else:
                    logging.warning('Gateway seems offline - trying to connect anyway.')
            except Exception as e:
                logging.debug('Could not verify gateway status: %s. Continuing...', e)

            # Launch terminal connection
            result = launch_terminal_connection(params, record_uid, gateway_info, **kwargs)

            if result.get('success'):
                logging.debug(f"Terminal connection launched successfully")
                logging.debug(f"Protocol: {result.get('protocol')}")

                # Always start interactive CLI session
                # Pass launch_credential_uid to know if ConnectAs payload is needed
                self._start_cli_session(result, params, kwargs.get('launch_credential_uid'))
            else:
                error_msg = result.get('error', 'Unknown error')
                raise CommandError('pam launch', f'Failed to launch connection: {error_msg}')
        finally:
            # Restore original root logger level
            root_logger.setLevel(original_level)

    def _start_cli_session(self, tunnel_result: Dict[str, Any], params: KeeperParams,
                           launch_credential_uid: Optional[str] = None):
        """
        Start CLI session using PythonHandler protocol mode.

        In PythonHandler mode:
        - Python initiates connection via tube_registry.open_handler_connection()
        - Rust forwards OpenConnection to Gateway and handles Ping/Pong heartbeat
        - Gateway starts guacd and connects to target
        - Python receives Guacamole protocol data via callback
        - Python sends Guacamole responses back via tube_registry.send_handler_data()

        Flow:
        1. Wait for WebRTC connection to be established
        2. Send OpenConnection to Gateway (conn_no=1)
        3. Gateway starts guacd, sends 'args' instruction
        4. Python responds with 'connect', 'size', 'audio', 'image'
        5. guacd sends 'ready', terminal session begins

        Args:
            tunnel_result: Result from launch_terminal_connection
            params: KeeperParams instance
            launch_credential_uid: Optional UID resolved from CLI --credential (UID, path, or title); triggers ConnectAs payload when set
        """
        shutdown_requested = False

        def signal_handler_fn(signum, frame):
            nonlocal shutdown_requested
            shutdown_requested = True
            logging.warning("\n\n* Interrupt received - shutting down...")

        original_handler = signal.signal(signal.SIGINT, signal_handler_fn)

        rust_log_token = None
        try:
            rust_log_token = enter_pam_launch_terminal_rust_logging()
            tube_id = tunnel_result['tunnel'].get('tube_id')
            if not tube_id:
                raise CommandError('pam launch', 'No tube ID in tunnel result')

            tube_registry = tunnel_result['tunnel'].get('tube_registry')
            if not tube_registry:
                raise CommandError('pam launch', 'No tube registry in tunnel result')

            python_handler = tunnel_result['tunnel'].get('python_handler')
            if not python_handler:
                raise CommandError('pam launch', 'No python_handler in tunnel result - ensure Rust module supports PythonHandler mode')

            conversation_id = tunnel_result['tunnel'].get('conversation_id')

            logging.debug(f"Starting PythonHandler CLI session for tube {tube_id}")

            # Display connection banner
            logging.debug(f"\n{'-' * 60}")
            logging.debug(f"CLI Terminal Mode - PythonHandler")
            logging.debug(f"Protocol: {tunnel_result['protocol']}")
            logging.debug(f"Target: {tunnel_result['settings']['hostname']}:{tunnel_result['settings']['port']}")
            logging.debug(f"Tube ID: {tube_id}")
            logging.debug(f"{'-' * 60}")
            logging.debug("Python sends: OpenConnection (initiates guacd session)")
            logging.debug("Rust handles: Ping/Pong heartbeat, message routing")
            logging.debug("Python receives: Guacamole protocol data via callback")
            logging.debug(f"{'=' * 60}\n")

            # Start the Python handler
            python_handler.start()

            # Wait for WebRTC connection to be established
            logging.debug("Waiting for WebRTC connection...")
            max_wait = 15
            start_time = time.time()
            connected = False

            while time.time() - start_time < max_wait:
                try:
                    state = tube_registry.get_connection_state(tube_id)
                    if state and state.lower() == 'connected':
                        logging.debug(f"✓ WebRTC connection established: {state}")
                        connected = True
                        break
                except Exception as e:
                    logging.debug(f"Checking connection state: {e}")
                time.sleep(0.1)

            if not connected:
                raise CommandError('pam launch', "WebRTC connection not established within timeout")

            # Wait for DataChannel to be ready and Gateway to wire the session.
            # connection state "connected" can precede DataChannel readiness; Gateway also needs
            # time to associate the WebRTC connection with the channel and prepare guacd.
            # Configurable via PAM_OPEN_CONNECTION_DELAY (default 0.2s; use 2.0 if handshake never starts).
            open_conn_delay = float(os.environ.get('PAM_OPEN_CONNECTION_DELAY', '0.2'))
            time.sleep(open_conn_delay)

            # Send OpenConnection to Gateway to initiate guacd session
            # This is critical - without it, Gateway doesn't start guacd and no Guacamole traffic flows
            # Retry with exponential backoff if DataChannel isn't ready yet
            logging.debug(f"Sending OpenConnection to Gateway (conn_no=1, conversation_id={conversation_id})")

            # Build ConnectAs payload when cliUserOverride is set — this covers both:
            # (a) explicit -cr that differs from DAG-linked, and
            # (b) implicit userRecords[0] fallback (no DAG link, allowSupply* enabled, no -cr given).
            # In case (b) launch_credential_uid is None; use userRecordUid from settings instead.
            connect_as_payload = None
            gateway_uid = tunnel_result['tunnel'].get('gateway_uid')
            _tunnel_settings = tunnel_result.get('settings', {})
            cli_user_override = _tunnel_settings.get('cliUserOverride', False)
            effective_credential_uid = launch_credential_uid or (
                _tunnel_settings.get('userRecordUid') if cli_user_override else None
            )

            # Remote keeper-pam-webrtc-rs version: from tunnel (non-streaming) or session (streaming)
            remote_webrtc_version = tunnel_result['tunnel'].get('remote_webrtc_version')
            if remote_webrtc_version is None:
                sess = get_tunnel_session(tube_id)
                remote_webrtc_version = getattr(sess, 'remote_webrtc_version', None) if sess else None

            connect_as_supported = _version_at_least(remote_webrtc_version, CONNECT_AS_MIN_VERSION)

            if cli_user_override and effective_credential_uid and gateway_uid:
                # When using userRecords[0] fallback, include explanation in CommandError if ConnectAs fails
                connect_as_fallback_msg = ''
                if launch_credential_uid is None:
                    connect_as_fallback_msg = (
                        f'Using credential from userRecords[0] ({effective_credential_uid}) as ConnectAs fallback because '
                        'no launch credential on record; ConnectAs is enabled but no --credential was given. '
                    )
                if not connect_as_supported:
                    raise CommandError(
                        'pam launch',
                        connect_as_fallback_msg
                        + f'ConnectAs (--credential) requires Gateway with keeper-pam-webrtc-rs >= {CONNECT_AS_MIN_VERSION}. '
                        f'Remote version: {remote_webrtc_version or "unknown"}. '
                        'Please upgrade the Gateway to use --credential.'
                    )
                logging.debug(f"Building ConnectAs payload for credential: {effective_credential_uid}")
                gateway_public_key = _retrieve_gateway_public_key(params, gateway_uid)
                if gateway_public_key:
                    connect_as_payload = _build_connect_as_payload(params, effective_credential_uid, gateway_public_key)
                    if connect_as_payload:
                        logging.debug(f"ConnectAs payload built: {len(connect_as_payload)} bytes")
                    else:
                        logging.warning("Failed to build ConnectAs payload - credentials may not be passed to gateway")
                else:
                    logging.warning("Could not retrieve gateway public key - credentials may not be passed to gateway")

            max_retries = 5
            retry_delay = 0.1
            last_error = None

            for attempt in range(max_retries):
                try:
                    # Pass ConnectAs payload when user supplied credentials via -cr (matches vault behavior)
                    tube_registry.open_handler_connection(
                        conversation_id, 1, connect_as_payload
                    )
                    logging.debug("✓ OpenConnection sent successfully")
                    break
                except Exception as e:
                    last_error = e
                    error_str = str(e).lower()
                    # Check if error is DataChannel-related
                    if "datachannel" in error_str or "not opened" in error_str:
                        if attempt < max_retries - 1:
                            wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                            logging.debug(f"DataChannel not ready, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{max_retries})")
                            time.sleep(wait_time)
                            continue
                    # For other errors or final attempt, raise immediately
                    logging.error(f"Failed to send OpenConnection: {e}")
                    raise CommandError('pam launch', f"Failed to send OpenConnection: {e}")
            else:
                # All retries exhausted
                logging.error(f"Failed to send OpenConnection after {max_retries} attempts: {last_error}")
                raise CommandError('pam launch', f"Failed to send OpenConnection after {max_retries} attempts: {last_error}")

            # Wait for Guacamole ready
            print("Waiting for Guacamole connection...")

            # Clear screen by printing terminal height worth of newlines
            # This prevents raw mode from overwriting existing screen lines
            terminal_height = 24
            try:
                terminal_size = shutil.get_terminal_size()
                terminal_height = terminal_size.lines
            except Exception:
                terminal_height = 24
            print("\n" * terminal_height, end='', flush=True)

            guac_ready_timeout = 10.0  # Reduced from 30s - sync triggers readiness quickly

            guac_ready_result = python_handler.wait_for_ready(guac_ready_timeout)
            if guac_ready_result:
                logging.debug("* Guacamole connection ready!")
                logging.debug("Terminal session active. Press Ctrl+C to exit.")
            else:
                logging.warning(f"Guacamole did not report ready within {guac_ready_timeout}s")
                logging.warning("Terminal may still work if data is flowing.")

            # Check for STDOUT pipe support (feature detection)
            # This warns the user if CLI pipe mode is not supported by the gateway
            python_handler.check_stdout_pipe_support(timeout=10.0)

            # Create stdin handler for pipe/blob/end input pattern
            # StdinHandler reads raw stdin and sends via send_stdin (base64-encoded)
            # This matches kcm-cli's implementation for plaintext SSH/TTY streams
            stdin_handler = StdinHandler(
                stdin_callback=lambda data: python_handler.send_stdin(data),
                key_callback=lambda keysym, pressed: python_handler.send_key(keysym, pressed)
            )

            # Main event loop with stdin input
            try:
                # Start stdin handler (runs in background thread)
                stdin_handler.start()
                logging.debug("STDIN handler started")  # (pipe/blob/end mode)

                # --- Terminal resize tracking ---
                # Resize polling is skipped entirely in non-interactive (piped)
                # environments where get_terminal_size() returns a dummy value.
                _resize_enabled = is_interactive_tty()
                # Poll cols/rows cheaply every N iterations; a timestamp guard
                # ensures correctness if the loop sleep interval ever changes.
                _RESIZE_POLL_EVERY = 3        # iterations  (~0.3 s at 0.1 s/iter)
                _RESIZE_POLL_INTERVAL = 0.3   # seconds - authoritative threshold
                _RESIZE_DEBOUNCE = 0.25       # seconds - max send rate during drag
                _resize_poll_counter = 0
                _last_resize_poll_time = 0.0
                _last_resize_send_time = 0.0
                # Track the last *sent* size; only updated when we actually send.
                # This keeps re-detecting the change each poll during rapid resize
                # so the final resting size is always dispatched.
                _last_sent_cols = 0
                _last_sent_rows = 0
                if _resize_enabled:
                    try:
                        _init_ts = shutil.get_terminal_size()
                        _last_sent_cols = _init_ts.columns
                        _last_sent_rows = _init_ts.lines
                    except Exception:
                        _resize_enabled = False
                        logging.debug("Could not query initial terminal size - resize polling disabled")

                elapsed = 0
                while not shutdown_requested and python_handler.running:
                    # Check if tube/connection is closed
                    try:
                        state = tube_registry.get_connection_state(tube_id)
                        if state and state.lower() in ('closed', 'disconnected', 'failed'):
                            logging.debug(f"Tube/connection closed (state: {state}) - exiting")
                            python_handler.running = False
                            break
                    except Exception:
                        # If we can't check state, continue (tube might be closing)
                        pass
                    time.sleep(0.1)
                    elapsed += 0.1

                    # --- Resize polling (Phase 1: cheap cols/rows check) ---
                    # Check every _RESIZE_POLL_EVERY iterations AND at least
                    # _RESIZE_POLL_INTERVAL seconds since the last poll, so the
                    # check stays correct if the loop sleep ever changes.
                    if _resize_enabled:
                        _resize_poll_counter += 1
                        _now = time.time()
                        if (
                            _resize_poll_counter % _RESIZE_POLL_EVERY == 0
                            and _now - _last_resize_poll_time >= _RESIZE_POLL_INTERVAL
                        ):
                            _last_resize_poll_time = _now
                            try:
                                _cur_ts = shutil.get_terminal_size()
                                _cur_cols = _cur_ts.columns
                                _cur_rows = _cur_ts.lines
                            except Exception:
                                _cur_cols, _cur_rows = _last_sent_cols, _last_sent_rows

                            if (_cur_cols, _cur_rows) != (_last_sent_cols, _last_sent_rows):
                                # Phase 2: size changed - apply debounce then
                                # fetch exact pixels and send.
                                if _now - _last_resize_send_time >= _RESIZE_DEBOUNCE:
                                    try:
                                        _si = get_terminal_size_pixels(_cur_cols, _cur_rows)
                                        python_handler.send_size(
                                            _si['pixel_width'],
                                            _si['pixel_height'],
                                            _si['dpi'],
                                        )
                                        _last_sent_cols = _cur_cols
                                        _last_sent_rows = _cur_rows
                                        _last_resize_send_time = _now
                                        logging.debug(
                                            f"Terminal resized: {_cur_cols}x{_cur_rows} cols/rows "
                                            f"-> {_si['pixel_width']}x{_si['pixel_height']}px "
                                            f"@ {_si['dpi']}dpi"
                                        )
                                    except Exception as _e:
                                        logging.debug(f"Failed to send resize: {_e}")
                                # else: debounce active - _last_sent_cols/rows unchanged
                                # so the change is re-detected on the next eligible poll.

                    # Status indicator every 30 seconds
                    if elapsed % 30.0 < 0.1 and elapsed > 0.1:
                        rx = python_handler.messages_received
                        tx = python_handler.messages_sent
                        syncs = python_handler.sync_count
                        logging.debug(f"[{int(elapsed)}s] Session active (rx={rx}, tx={tx}, syncs={syncs})")

            except KeyboardInterrupt:
                logging.debug("\n\nExiting CLI terminal mode...")

            finally:
                # Stop stdin handler first (restores terminal)
                logging.debug("Stopping stdin handler...")
                try:
                    stdin_handler.stop()
                except Exception as e:
                    logging.debug(f"Error stopping stdin handler: {e}")

                # Cleanup - check if connection is already closed to avoid deadlock
                logging.debug("Stopping Python handler...")
                try:
                    # Check if tube is already closed - if so, skip sending disconnect
                    try:
                        state = tube_registry.get_connection_state(tube_id)
                        skip_disconnect = state and state.lower() in ('closed', 'disconnected', 'failed')
                    except Exception:
                        skip_disconnect = False

                    python_handler.stop(skip_disconnect=skip_disconnect)
                except Exception as e:
                    logging.debug(f"Error stopping Python handler: {e}")

                # Close the tube (Rust handles CloseConnection automatically)
                logging.debug("Closing WebRTC tunnel...")
                try:
                    tube_registry.close_tube(tube_id)
                    logging.debug(f"Closed tube: {tube_id}")
                except Exception as e:
                    logging.debug(f"Error closing tube: {e}")

                # Clean up registrations
                try:
                    unregister_tunnel_session(tube_id)
                    if conversation_id:
                        unregister_conversation_key(conversation_id)
                except Exception as e:
                    logging.debug(f"Error unregistering: {e}")

                logging.info("CLI session ended - cleanup complete")

        except CommandError:
            raise
        except Exception as e:
            logging.error(f"Error in PythonHandler CLI session: {e}")
            raise CommandError('pam launch', f'Failed to start CLI session: {e}')
        finally:
            exit_pam_launch_terminal_rust_logging(rust_log_token)
            signal.signal(signal.SIGINT, original_handler)
