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

from __future__ import annotations
import argparse
import logging
import re
import shutil
import signal
import sys
import time
from typing import TYPE_CHECKING, Dict, Any, Optional

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from .terminal_connection import launch_terminal_connection
from .guac_cli.stdin_handler import StdinHandler
from ..base import Command
from ..tunnel.port_forward.tunnel_helpers import (
    get_gateway_uid_from_record,
    get_config_uid_from_record,
    unregister_tunnel_session,
    unregister_conversation_key,
)
from ..pam.gateway_helper import get_all_gateways
from ..pam.router_helper import router_get_connected_gateways
from ... import api, vault
from ...subfolder import try_resolve_path
from ...error import CommandError

if TYPE_CHECKING:
    from ...params import KeeperParams


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
    # parser.add_argument('--user', '-u', required=False, dest='launch_credential_uid', type=str,
    #                     help='UID of pamUser record to use as launch credentials when allowSupplyUser is enabled. '
    #                          'Fails if allowSupplyUser is not enabled or the specified record is not found.')
    # parser.add_argument('--host', '-H', required=False, dest='custom_host', type=str,
    #                     help='Hostname or IP address to connect to when allowSupplyHost is enabled. '
    #                          'Fails if allowSupplyHost is not enabled.')

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

        Raises:
            CommandError: If multiple records match
        """
        if not record_token:
            return None

        record_token = record_token.strip()

        # Step 1: Try UID lookup
        uid_pattern = re.compile(r'^[A-Za-z0-9_-]{22}$')
        if uid_pattern.match(record_token):
            if record_token in params.record_cache:
                # Validate it's a PAM record type
                if self._is_valid_pam_record(params, record_token):
                    logging.debug(f"Found record by UID: {record_token}")
                    return record_token
                else:
                    logging.debug(f"Record {record_token} found but is not a valid PAM record type")
                    return None

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

        Args:
            params: KeeperParams instance
            path: Path to the record

        Returns:
            Record UID if found, None otherwise

        Raises:
            CommandError: If multiple records match
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

        # Find all records in the folder with matching title (only valid PAM types)
        matched_uids = []
        for uid in params.subfolder_record_cache[folder_uid]:
            r = api.get_record(params, uid)
            if r and r.title and r.title.lower() == name.lower():
                # Only include valid PAM record types
                if self._is_valid_pam_record(params, uid):
                    matched_uids.append(uid)

        if len(matched_uids) > 1:
            raise CommandError('pam launch', f'Multiple valid PAM records found with path "{path}". Please use a unique identifier.')

        if matched_uids:
            logging.debug(f"Found record by path: {path} -> {matched_uids[0]}")
            return matched_uids[0]

        return None

    def _find_by_title(self, params: KeeperParams, title: str) -> Optional[str]:
        """
        Find record by exact title match.

        Args:
            params: KeeperParams instance
            title: Title to match

        Returns:
            Record UID if found, None otherwise

        Raises:
            CommandError: If multiple records match
        """
        matched_uids = []
        for record_uid in params.record_cache:
            record = vault.KeeperRecord.load(params, record_uid)
            if record and record.title and record.title.lower() == title.lower():
                # Only include valid PAM record types
                if self._is_valid_pam_record(params, record_uid):
                    matched_uids.append(record_uid)

        if len(matched_uids) > 1:
            raise CommandError('pam launch', f'Multiple valid PAM records found with title "{title}". Please use a unique identifier (UID or full path).')

        if matched_uids:
            logging.debug(f"Found record by title: {title} -> {matched_uids[0]}")
            return matched_uids[0]

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
            record_token = kwargs.get('record')

            if not record_token:
                logging.error("Record path or UID is required")
                return

            # Find the record
            record_uid = self.find_record(params, record_token)

            if not record_uid:
                raise CommandError('pam launch', f'Record not found: {record_token}')

            logging.debug(f"Found record: {record_uid}")

            # Validate --user and --host parameters against allowSupply flags
            # Note: cmdline options override record data when provided
            # launch_credential_uid = kwargs.get('launch_credential_uid')
            # custom_host = kwargs.get('custom_host')

            # Load record to check allowSupply flags and existing values
            # record = vault.KeeperRecord.load(params, record_uid)
            # if not isinstance(record, vault.TypedRecord):
            #     raise CommandError('pam launch', f'Record {record_uid} is not a TypedRecord')

            # pam_settings_field = record.get_typed_field('pamSettings')
            # allow_supply_user = False
            # allow_supply_host = False
            # user_records_on_record = []
            # hostname_on_record = None

            # Get hostname from record
            # hostname_field = record.get_typed_field('pamHostname')
            # if hostname_field:
            #     host_value = hostname_field.get_default_value(dict)
            #     if host_value:
            #         hostname_on_record = host_value.get('hostName')

            # if pam_settings_field:
            #     pam_settings_value = pam_settings_field.get_default_value(dict)
            #     if pam_settings_value:
            #         # allowSupplyHost is at top level of pamSettings value
            #         allow_supply_host = pam_settings_value.get('allowSupplyHost', False)
            #         # allowSupplyUser is inside connection
            #         connection = pam_settings_value.get('connection', {})
            #         if isinstance(connection, dict):
            #             allow_supply_user = connection.get('allowSupplyUser', False)
            #             user_records_on_record = connection.get('userRecords', [])

            # Validation based on allowSupply flags
            # if allow_supply_host and allow_supply_user:
            #     # Both flags true: --user is required (no fallback to userRecords)
            #     if not launch_credential_uid:
            #         raise CommandError('pam launch',
            #             f'Both allowSupplyUser and allowSupplyHost are enabled. '
            #             f'You must provide --user to specify launch credentials.')
            #     # --host required if no hostname on record
            #     if not custom_host and not hostname_on_record:
            #         raise CommandError('pam launch',
            #             f'Both allowSupplyUser and allowSupplyHost are enabled and no hostname on record. '
            #             f'You must provide --host to specify the target host.')

            # elif allow_supply_user and not allow_supply_host:
            #     # Only allowSupplyUser: use --user if provided, else userRecords, else error
            #     if not launch_credential_uid and not user_records_on_record:
            #         raise CommandError('pam launch',
            #             f'allowSupplyUser is enabled but no credentials available. '
            #             f'Use --user to specify a pamUser record or configure userRecords on the record.')

            # elif allow_supply_host and not allow_supply_user:
            #     # Only allowSupplyHost: --host required if no hostname on record
            #     if not custom_host and not hostname_on_record:
            #         raise CommandError('pam launch',
            #             f'allowSupplyHost is enabled but no hostname available. '
            #             f'Use --host to specify the target host or configure hostname on the record.')

            # Validate --user parameter if provided
            # if launch_credential_uid:
            #     if not allow_supply_user:
            #         raise CommandError('pam launch',
            #             f'--user parameter requires allowSupplyUser to be enabled on the record. '
            #             f'allowSupplyUser is currently disabled for record {record_uid}.')

            #     # Validate the launch credential record exists and is a pamUser
            #     cred_record = vault.KeeperRecord.load(params, launch_credential_uid)
            #     if not cred_record:
            #         raise CommandError('pam launch',
            #             f'Launch credential record not found: {launch_credential_uid}')
            #     if not isinstance(cred_record, vault.TypedRecord) or cred_record.record_type != 'pamUser':
            #         raise CommandError('pam launch',
            #             f'Launch credential record {launch_credential_uid} must be a pamUser record. '
            #             f'Found: {cred_record.record_type if isinstance(cred_record, vault.TypedRecord) else "non-typed"}')

            #     logging.debug(f"Using custom launch credential: {launch_credential_uid}")

            # Validate --host parameter if provided
            # if custom_host:
            #     if not allow_supply_host:
            #         raise CommandError('pam launch',
            #             f'--host parameter requires allowSupplyHost to be enabled on the record. '
            #             f'allowSupplyHost is currently disabled for record {record_uid}.')

            #     logging.debug(f"Using custom host: {custom_host}")

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
                self._start_cli_session(result, params)
            else:
                error_msg = result.get('error', 'Unknown error')
                raise CommandError('pam launch', f'Failed to launch connection: {error_msg}')
        finally:
            # Restore original root logger level
            root_logger.setLevel(original_level)

    def _start_cli_session(self, tunnel_result: Dict[str, Any], params: KeeperParams):
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
        """
        shutdown_requested = False

        def signal_handler_fn(signum, frame):
            nonlocal shutdown_requested
            shutdown_requested = True
            logging.warning("\n\n* Interrupt received - shutting down...")

        original_handler = signal.signal(signal.SIGINT, signal_handler_fn)

        try:
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

            # Wait a brief moment for DataChannel to be ready after connection state becomes "connected"
            # The connection state can be "connected" before the DataChannel is actually ready to send data
            time.sleep(0.2)

            # Send OpenConnection to Gateway to initiate guacd session
            # This is critical - without it, Gateway doesn't start guacd and no Guacamole traffic flows
            # Retry with exponential backoff if DataChannel isn't ready yet
            logging.debug(f"Sending OpenConnection to Gateway (conn_no=1, conversation_id={conversation_id})")
            max_retries = 5
            retry_delay = 0.1
            last_error = None

            for attempt in range(max_retries):
                try:
                    tube_registry.open_handler_connection(conversation_id, 1)
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

            if python_handler.wait_for_ready(guac_ready_timeout):
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

        except Exception as e:
            logging.error(f"Error in PythonHandler CLI session: {e}")
            raise CommandError('pam launch', f'Failed to start CLI session: {e}')
        finally:
            signal.signal(signal.SIGINT, original_handler)
