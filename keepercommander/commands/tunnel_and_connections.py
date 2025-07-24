#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#
# RUST WEBRTC LOGGING:
# - Enhanced logging with initialize_rust_logger() function
# - Use 'pam tunnel loglevel --trace' to configure session-wide trace logging
# - IMPORTANT: Rust logger can only be initialized ONCE per process
# - Loglevel command must be run before any tunnel operations
# - If loglevel is not set, tunnel start will use default logging
#
# USAGE EXAMPLES:
# - For detailed logging:
#   pam tunnel loglevel --trace       (configure session)
#   pam tunnel start RECORD_UID       (start with trace logging)
#   pam tunnel list                   (list with trace logging)
# - For normal logging:
#   pam tunnel start RECORD_UID       (start with default logging)
# - Alternative: RUST_LOG=trace pam tunnel start RECORD_UID  (environment variable)
#
import argparse
import logging
import os
import sys
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes

from .base import Command, GroupCommand, dump_report_data, RecordMixin
from .tunnel.port_forward.TunnelGraph import TunnelDAG
from .tunnel.port_forward.tunnel_helpers import find_open_port, get_config_uid, get_keeper_tokens, \
    get_or_create_tube_registry, get_gateway_uid_from_record, initialize_rust_logger, RUST_LOGGER_INITIALIZED, \
    get_rust_logger_state, resolve_record, resolve_pam_config, resolve_folder, remove_field, start_rust_tunnel, \
    get_tunnel_session, CloseConnectionReasons
from .. import api, vault, record_management
from ..display import bcolors
from ..error import CommandError
from ..params import LAST_RECORD_UID
from ..subfolder import find_folders

# Group Commands
class PAMTunnelCommand(GroupCommand):

    def __init__(self):
        super(PAMTunnelCommand, self).__init__()
        self.register_command('loglevel', PAMTunnelLogLevelCommand(), 'Set logging level for tunnel session', 'g')
        self.register_command('start', PAMTunnelStartCommand(), 'Start Tunnel', 's')
        self.register_command('list', PAMTunnelListCommand(), 'List all Tunnels', 'l')
        self.register_command('stop', PAMTunnelStopCommand(), 'Stop Tunnel to the server', 'x')
        self.register_command('edit', PAMTunnelEditCommand(), 'Edit Tunnel settings', 'e')
        self.default_verb = 'list'


class PAMConnectionCommand(GroupCommand):

    def __init__(self):
        super(PAMConnectionCommand, self).__init__()
        # self.register_command('start', PAMConnectionStartCommand(), 'Start Connection', 's')
        # self.register_command('stop', PAMConnectionStopCommand(), 'Stop Connection', 'x')
        self.register_command('edit', PAMConnectionEditCommand(), 'Edit Connection settings', 'e')
        self.default_verb = 'edit'


# Individual Commands
class PAMTunnelLogLevelCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel loglevel', 
                                           description='Set logging level for tunnel session. '
                                                       'Run this before starting tunnels to configure logging.')
    pam_cmd_parser.add_argument('--trace', '-t', required=False, dest='trace', action='store_true',
                                help='Enable detailed WebRTC trace logging for the entire session. '
                                     'This setting cannot be changed once tunnels are started.')

    def get_parser(self):
        return PAMTunnelLogLevelCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        trace_logging = kwargs.get('trace', False)
        
        # Check if logger is already initialized
        if RUST_LOGGER_INITIALIZED:
            current_settings = get_rust_logger_state()
            if current_settings['verbose'] == trace_logging:
                if trace_logging:
                    print(f"{bcolors.OKGREEN}Tunnel session is already configured with trace logging enabled.{bcolors.ENDC}")
                else:
                    print(f"{bcolors.OKGREEN}Tunnel session is already configured with normal logging.{bcolors.ENDC}")
            else:
                if trace_logging:
                    print(f"{bcolors.FAIL}Cannot enable trace logging - tunnel session already configured with normal logging.{bcolors.ENDC}")
                    print(f"{bcolors.WARNING}Restart Commander to change logging configuration.{bcolors.ENDC}")
                else:
                    print(f"{bcolors.WARNING}Tunnel session is already configured with trace logging enabled.{bcolors.ENDC}")
                    print(f"{bcolors.OKBLUE}To disable trace logging, restart Commander.{bcolors.ENDC}")
            return
        
        # Initialize the Rust logger for the session
        debug_level = hasattr(params, 'debug') and params.debug
        log_level = logging.DEBUG if debug_level else logging.INFO
        
        if initialize_rust_logger(logger_name="keeper-pam-webrtc-rs", verbose=trace_logging, level=log_level):
             if trace_logging:
                 print(f"{bcolors.OKGREEN}Tunnel session configured with trace logging enabled.{bcolors.ENDC}")
                 print(f"{bcolors.OKBLUE}Detailed WebRTC logs will be shown for all tunnel operations.{bcolors.ENDC}")
                 print(f"{bcolors.OKBLUE}Now you can run: pam tunnel start RECORD_UID{bcolors.ENDC}")
             else:
                 print(f"{bcolors.OKGREEN}Tunnel session configured with normal logging.{bcolors.ENDC}")
                 print(f"{bcolors.OKBLUE}Use 'pam tunnel loglevel --trace' for detailed logging.{bcolors.ENDC}")
                 print(f"{bcolors.OKBLUE}Now you can run: pam tunnel start RECORD_UID{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}Failed to configure tunnel session logging.{bcolors.ENDC}")


class PAMTunnelListCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel list')

    def get_parser(self):
        return PAMTunnelListCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        # Rust logger should already be initialized by the loglevel command
        # If not initialized, use default settings
        if not RUST_LOGGER_INITIALIZED:
            debug_level = hasattr(params, 'debug') and params.debug
            log_level = logging.DEBUG if debug_level else logging.INFO
            initialize_rust_logger(logger_name="keeper-pam-webrtc-rs", verbose=False, level=log_level)
        
        # Try to get active tunnels from Rust PyTubeRegistry
        tube_registry = get_or_create_tube_registry(params)
        if tube_registry:
            if not tube_registry.has_active_tubes():
                logging.warning(f"{bcolors.OKBLUE}No Tunnels running{bcolors.ENDC}")
                return

            table = []
            headers = ['Tunnel ID', 'Listening On', 'Conversation IDs', 'Status']

            # Get all tube IDs
            tube_ids = tube_registry.all_tube_ids()
            
            for tube_id in tube_ids:
                # Get conversation IDs for this tube
                conversation_ids = tube_registry.get_conversation_ids_by_tube_id(tube_id)
                
                # Get listening address from tunnel session
                tunnel_session = get_tunnel_session(tube_id)
                if tunnel_session and tunnel_session.host and tunnel_session.port:
                    listening_on = f"{bcolors.OKGREEN}{tunnel_session.host}:{tunnel_session.port}{bcolors.ENDC}"
                else:
                    listening_on = f"{bcolors.WARNING}unknown{bcolors.ENDC}"
                
                # Try to get connection state
                try:
                    state = tube_registry.get_connection_state(tube_id)
                    status_color = f"{bcolors.OKGREEN}" if state.lower() == "connected" else f"{bcolors.WARNING}"
                    status = f"{status_color}{state}{bcolors.ENDC}"
                except:
                    status = f"{bcolors.WARNING}unknown{bcolors.ENDC}"
                
                # Format conversation IDs for display
                conv_ids_str = ', '.join(conversation_ids) if conversation_ids else 'none'
                
                row = [
                    f"{bcolors.OKBLUE}{tube_id}{bcolors.ENDC}",
                    listening_on,
                    conv_ids_str,
                    status,
                ]
                table.append(row)

            dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)
        else:
            # Rust WebRTC library is required for tunnel operations
            print(f"{bcolors.FAIL}This command requires the Rust WebRTC library (keeper_pam_webrtc_rs).{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Please ensure the keeper_pam_webrtc_rs module is installed and available.{bcolors.ENDC}")
            return


class PAMTunnelStopCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel stop')
    pam_cmd_parser.add_argument('uid', type=str, action='store', help='The Tunnel UID or Record UID')

    def get_parser(self):
        return PAMTunnelStopCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        uid = kwargs.get('uid')
        if not uid:
            raise CommandError('tunnel stop', '"uid" argument is required')
        
        # Rust logger should already be initialized by the loglevel command
        if not RUST_LOGGER_INITIALIZED:
            debug_level = hasattr(params, 'debug') and params.debug
            log_level = logging.DEBUG if debug_level else logging.INFO
            initialize_rust_logger(logger_name="keeper-pam-webrtc-rs", verbose=False, level=log_level)
        
        # Try to use Rust PyTubeRegistry first
        tube_registry = get_or_create_tube_registry(params)
        if tube_registry:
            # Find matching tubes using Rust API
            matching_tubes = tube_registry.find_tubes(uid)
            
            if not matching_tubes:
                # Also check if it's a tube ID directly
                if tube_registry.tube_found(uid):
                    matching_tubes = [uid]
                else:
                    raise CommandError('tunnel stop', f"No active tunnels found matching '{uid}'")
            
            # Stop all matching tubes by closing their connections
            stopped_count = 0
            for tube_id in matching_tubes:
                try:
                    # Get all conversation IDs for this tube
                    conversation_ids = tube_registry.get_conversation_ids_by_tube_id(tube_id)
                    
                    if conversation_ids:
                        # Close each connection on the tube with Normal reason (user-initiated stop)
                        for conversation_id in conversation_ids:
                            tube_registry.close_connection(conversation_id, reason=CloseConnectionReasons.Normal)
                        print(f"{bcolors.OKGREEN}Stopped tunnel: {tube_id}{bcolors.ENDC}")
                        stopped_count += 1
                    else:
                        # Fallback to close_tube if no conversation IDs found
                        tube_registry.close_tube(tube_id, reason=CloseConnectionReasons.Normal)
                        print(f"{bcolors.OKGREEN}Stopped tunnel: {tube_id}{bcolors.ENDC}")
                        stopped_count += 1
                    
                except Exception as e:
                    print(f"{bcolors.FAIL}Failed to stop tunnel {tube_id}: {e}{bcolors.ENDC}")
            
            if stopped_count == 0:
                raise CommandError('tunnel stop', f"Failed to stop any tunnels matching '{uid}'")
        else:
            # Rust WebRTC library is required for tunnel operations
            raise CommandError('tunnel stop', 'This command requires the Rust WebRTC library (keeper_pam_webrtc_rs). '
                                            'Please ensure the keeper_pam_webrtc_rs module is installed and available.')

        return


class PAMTunnelEditCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel edit')
    pam_cmd_parser.add_argument('record', type=str, action='store', help='The record path or UID of the PAM '
                                                                      'resource record with network information to use '
                                                                      'for tunneling')
    pam_cmd_parser.add_argument('--configuration', '-c', required=False, dest='config', action='store',
                                help='The PAM Configuration UID or path to use for tunneling. '
                                     'Use command `pam config list` to view available PAM Configurations.')
    pam_cmd_parser.add_argument('--enable-tunneling', '-et', required=False, dest='enable_tunneling', action='store_true',
                                help='Enable tunneling on the record')
    pam_cmd_parser.add_argument('--tunneling-override-port', '-top', required=False, dest='tunneling_override_port',
                                action='store', help='Port to use for tunneling. If not provided, '
                                                     'the port from the record will be used.')
    pam_cmd_parser.add_argument('--disable-tunneling', '-dt', required=False, dest='disable_tunneling',
                                action='store_true', help='Disable tunneling on the record')
    pam_cmd_parser.add_argument('--remove-tunneling-override-port', '-rtop', required=False,
                                dest='remove_tunneling_override_port', action='store_true',
                                help='Remove tunneling override port')

    def get_parser(self):
        return PAMTunnelEditCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        tunneling_override_port = kwargs.get('tunneling_override_port')

        if ((kwargs.get('enable_tunneling') and kwargs.get('disable_tunneling')) or
                (kwargs.get('enable_rotation') and kwargs.get('disable_rotation')) or
                (kwargs.get('tunneling-override-port') and kwargs.get('remove_tunneling_override_port'))):
            raise CommandError('pam-config-edit', 'Cannot enable and disable the same feature at the same time')

        # First check if enabled is true, then check if disabled is true. If not, then set it to None
        _tunneling = True if kwargs.get('enable_tunneling') else False if  kwargs.get('disable_tunneling') else None
        _remove_tunneling_override_port = kwargs.get('remove_tunneling_override_port')

        if tunneling_override_port:
            try:
                tunneling_override_port = int(tunneling_override_port)
            except ValueError:
                raise CommandError('tunnel edit', 'tunneling-override-port must be an integer')

        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('pam tunnel edit', '"record" parameter is required.')
        record = RecordMixin.resolve_single_record(params, record_name)
        if not record:
            raise CommandError('pam tunnel edit', f'{bcolors.FAIL}Record \"{record_name}\" not found.{bcolors.ENDC}')
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('pam tunnel edit', f'Record \"{record_name}\" can not be edited.')

        # config parameter is optional and maybe (auto)resolved from PAM record
        config_name = kwargs.get('config', None)
        cfg_rec = RecordMixin.resolve_single_record(params, config_name)
        if not cfg_rec and record.version == 6:
            cfg_rec = record  # trying to edit PAM Config itself
        config_uid = cfg_rec.record_uid if cfg_rec else None

        record_uid = record.record_uid
        record_type = record.record_type
        if record_type not in ("pamMachine pamDatabase pamDirectory pamNetworkConfiguration pamAwsConfiguration "
                               "pamRemoteBrowser pamAzureConfiguration").split():
            raise CommandError('', f"{bcolors.FAIL}This record's type is not supported for tunnels. "
                                   f"Tunnels are only supported on pamMachine, pamDatabase, pamDirectory, "
                                   f"pamRemoteBrowser, pamNetworkConfiguration pamAwsConfiguration, and "
                                   f"pamAzureConfiguration records{bcolors.ENDC}")

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        if record_type in "pamNetworkConfiguration pamAwsConfiguration pamAzureConfiguration".split():
            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, record_uid, is_config=True)
            tmp_dag.edit_tunneling_config(tunneling=_tunneling)
            tmp_dag.print_tunneling_config(record_uid, None)
        else:
            traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
            # Generate a 256-bit (32-byte) random seed
            seed = os.urandom(32)
            dirty = False
            if not traffic_encryption_key or not traffic_encryption_key.value:
                base64_seed = bytes_to_base64(seed)
                record_seed = vault.TypedField.new_field('trafficEncryptionSeed', base64_seed, "")
                # if field is present update in-place, if in rec definition add to fields[] else custom[]
                record_types_with_seed = ("pamDatabase", "pamDirectory", "pamMachine", "pamRemoteBrowser")
                if traffic_encryption_key:
                    traffic_encryption_key.value = [base64_seed]
                elif record.get_record_type() in record_types_with_seed:
                    record.fields.append(record_seed)  # DU-469
                else:
                    record.custom.append(record_seed)
                dirty = True
            if dirty:
                record_management.update_record(params, record)
                api.sync_down(params)

                traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
                if not traffic_encryption_key:
                    raise CommandError('', f"{bcolors.FAIL}Unable to add Seed to record {record_uid}. "
                                       f"Please make sure you have edit rights to record {record_uid} {bcolors.ENDC}")
            dirty = False

            existing_config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)

            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, config_uid)
            old_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, existing_config_uid)

            if config_uid and existing_config_uid != config_uid:
                old_dag.remove_from_dag(record_uid)
                tmp_dag.link_resource_to_config(record_uid)

            if tmp_dag is None or not tmp_dag.linking_dag.has_graph:
                raise CommandError('', f"{bcolors.FAIL}No PAM Configuration UID set. "
                                   f"This must be set or supplied for tunneling to work. This can be done by adding "
                                   f"{bcolors.OKBLUE}' --config [ConfigUID] "
                                   f" {bcolors.FAIL}The ConfigUID can be found by running "
                                   f"{bcolors.OKBLUE}'pam config list'{bcolors.ENDC}")

            if not tmp_dag.check_tunneling_enabled_config(enable_tunneling=_tunneling):
                tmp_dag.print_tunneling_config(config_uid, None)
                command = f"{bcolors.OKBLUE}'pam tunnel edit {config_uid}"
                if _tunneling and not tmp_dag.check_tunneling_enabled_config(
                        enable_tunneling=_tunneling):
                    command += f" --enable-tunneling" if _tunneling else ""

                print(f"{bcolors.FAIL}The settings are denied by PAM Configuration: {config_uid}. "
                      f"Please enable settings for the configuration by running\n"
                      f"{command}'{bcolors.ENDC}")
                return

            if not tmp_dag.is_tunneling_config_set_up(record_uid):
                tmp_dag.link_resource_to_config(record_uid)

            pam_settings = record.get_typed_field('pamSettings')
            if not pam_settings:
                pre_settings = {"connection": {}, "portForward": {}}
                if _tunneling and tunneling_override_port:
                    pre_settings["portForward"]["port"] = tunneling_override_port
                if pre_settings:
                    pam_settings = vault.TypedField.new_field('pamSettings', pre_settings, "")
                    record.custom.append(pam_settings)
                    dirty = True
            else:
                if not tmp_dag.is_tunneling_config_set_up(record_uid):
                    tmp_dag.link_resource_to_config(record_uid)
                if not pam_settings.value:
                    pam_settings.value.append({"connection": {}, "portForward": {}})
                if _tunneling and tunneling_override_port:
                    pam_settings.value[0]['portForward']['port'] = tunneling_override_port
                    dirty = True

                if _remove_tunneling_override_port and pam_settings.value[0]['portForward'].get('port'):
                    pam_settings.value[0]['portForward'].pop('port')
                    dirty = True
            if not tmp_dag.is_tunneling_config_set_up(record_uid):
                print(f"{bcolors.FAIL}No PAM Configuration UID set. This must be set for tunneling to work. "
                      f"This can be done by running "
                      f"{bcolors.OKBLUE}'pam tunnel edit {record_uid} --config [ConfigUID] --enable-tunneling' "
                      f"{bcolors.FAIL}The ConfigUID can be found by running "
                      f"{bcolors.OKBLUE}'pam config list'{bcolors.ENDC}")
                return
            allowed_settings_name = "allowedSettings"
            if record.record_type == "pamRemoteBrowser":
                allowed_settings_name = "pamRemoteBrowserSettings"

            if _tunneling is not None and tmp_dag.check_if_resource_allowed(record_uid, "portForwards") != _tunneling:
                dirty = True

            if dirty:
                tmp_dag.set_resource_allowed(resource_uid=record_uid, tunneling=_tunneling, allowed_settings_name=allowed_settings_name)

            # Print out the tunnel settings
            if not kwargs.get('silent'):
                tmp_dag.print_tunneling_config(record_uid, record.get_typed_field('pamSettings'), config_uid)


class PAMTunnelStartCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel start')
    pam_cmd_parser.add_argument('uid', type=str, action='store', help='The Record UID of the PAM resource '
                                                                      'record with network information to use for '
                                                                      'tunneling')
    pam_cmd_parser.add_argument('--host', '-o', required=False, dest='host', action='store',
                                default="127.0.0.1",
                                help='The address on which the server will be accepting connections. It could be an '
                                     'IP address or a hostname. '
                                     'Ex. set to 127.0.0.1 as default so only connections from the same machine will be'
                                     ' accepted.')
    pam_cmd_parser.add_argument('--port', '-p', required=False, dest='port', action='store',
                                type=int, default=0,
                                help='The port number on which the server will be listening for incoming connections. '
                                     'If not set, random open port on the machine will be used.')

    def get_parser(self):
        return PAMTunnelStartCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        # Python version validation (same as before)
        from_version = [3, 8, 0]   # including
        to_version = [3, 13, 0]    # excluding
        major_version = sys.version_info.major
        minor_version = sys.version_info.minor
        micro_version = sys.version_info.micro

        if (major_version, minor_version, micro_version) < (from_version[0], from_version[1], from_version[2]):
            print(f"{bcolors.FAIL}This command requires Python {from_version[0]}.{from_version[1]}.{from_version[2]} or higher. "
                  f"You are using {major_version}.{minor_version}.{micro_version}.{bcolors.ENDC}")
            return
        if (major_version, minor_version, micro_version) >= (to_version[0], to_version[1], to_version[2]):
            print(f"{bcolors.FAIL}This command is compatible with Python versions below {to_version[0]}.{to_version[1]}.{to_version[2]} "
                  f"(Current Python version: {major_version}.{minor_version}.{micro_version}){bcolors.ENDC}")
            return

        # Check for Rust WebRTC library availability
        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            print(f"{bcolors.FAIL}This command requires the Rust WebRTC library (keeper_pam_webrtc_rs).{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Please ensure the keeper_pam_webrtc_rs module is installed and available.{bcolors.ENDC}")
            return

        # Initialize Rust logger with defaults if not already set by loglevel command
        if not RUST_LOGGER_INITIALIZED:
            debug_level = hasattr(params, 'debug') and params.debug
            log_level = logging.DEBUG if debug_level else logging.INFO
            initialize_rust_logger(logger_name="keeper-pam-webrtc-rs", verbose=False, level=log_level)

        record_uid = kwargs.get('uid')
        host = kwargs.get('host')
        port = kwargs.get('port')
        
        if port is not None and port > 0:
            try:
                port = find_open_port(tried_ports=[], preferred_port=port, host=host)
            except CommandError as e:
                print(f"{bcolors.FAIL}{e}{bcolors.ENDC}")
                return
        else:
            port = find_open_port(tried_ports=[], host=host)
            if port is None:
                print(f"{bcolors.FAIL}Could not find open port to use for tunnel{bcolors.ENDC}")
                return

        # Sync and validate record
        api.sync_down(params)
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            print(f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
            return

        # Validate PAM settings
        pam_settings = record.get_typed_field('pamSettings')
        if not pam_settings:
            print(f"{bcolors.FAIL}PAM Settings not configured for record {record_uid}'.{bcolors.ENDC}")
            print(f"{bcolors.WARNING}This is done by running {bcolors.OKBLUE}'pam tunnel edit {record_uid} "
                  f"--enable-tunneling --config [ConfigUID]'"
                  f"{bcolors.WARNING} The ConfigUID can be found by running"
                  f"{bcolors.OKBLUE} 'pam config list'{bcolors.ENDC}.")
            return

        # Get target host and port
        target = record.get_typed_field('pamHostname')
        if not target:
            print(f"{bcolors.FAIL}Hostname not found for record {record_uid}.{bcolors.ENDC}")
            return
        target_host = target.get_default_value().get('hostName', None)
        target_port = target.get_default_value().get('port', None)
        if not target_host:
            print(f"{bcolors.FAIL}Host not found for record {record_uid}.{bcolors.ENDC}")
            return
        if not target_port:
            print(f"{bcolors.FAIL}Port not found for record {record_uid}.{bcolors.ENDC}")
            return

        # Check for SOCKS configuration
        allowed_hosts = record.get_typed_field('multiline', 'Allowed Hosts')
        allowed_ports = record.get_typed_field('multiline', 'Allowed Ports')
        socks = bool(allowed_hosts or allowed_ports)

        # Get encryption seed
        client_private_seed = record.get_typed_field('trafficEncryptionSeed')
        if not client_private_seed:
            print(f"{bcolors.FAIL}Traffic Encryption Seed not found for record {record_uid}.{bcolors.ENDC}")
            return
        base64_seed = client_private_seed.get_default_value(str).encode('utf-8')
        seed = base64_to_bytes(base64_seed)

        # Get gateway UID
        gateway_uid = get_gateway_uid_from_record(params, vault, record_uid)
        if not gateway_uid:
            print(f"{bcolors.FAIL}Gateway not found for record {record_uid}.{bcolors.ENDC}")
            return

        # Use Rust WebRTC implementation with trickle ICE
        print(f"{bcolors.OKBLUE}Using trickle ICE with HTTP POST sending and WebSocket receiving{bcolors.ENDC}")
        result = start_rust_tunnel(params, record_uid, gateway_uid, host, port, seed, target_host, target_port, socks)
        
        if result and result.get("success"):
            # The helper will show endpoint table when local socket is actually listening
            pass
        else:
            # Print failure message
            error_msg = result.get("error", "Unknown error") if result else "Failed to start tunnel"
            fail_dynamic_length = len("| Tunnel failed to start: ") + len(error_msg)
            fail_dashed_line = '+' + '-' * fail_dynamic_length + '+'
            
            print(f'\n{bcolors.FAIL}{fail_dashed_line}{bcolors.ENDC}')
            print(f'{bcolors.FAIL}| Tunnel failed to start: {error_msg}{bcolors.ENDC}')
            print(f'{bcolors.FAIL}{fail_dashed_line}{bcolors.ENDC}\n')


class PAMConnectionEditCommand(Command):
    choices = ['on', 'off', 'default']
    protocols = ['', 'http', 'kubernetes', 'mysql', 'postgresql', 'rdp', 'sql-server', 'ssh', 'telnet', 'vnc']
    parser = argparse.ArgumentParser(prog='pam connection edit')
    parser.add_argument('record', type=str, action='store', help='The record UID or path of the PAM '
                        'resource record with network information to use for connections')
    parser.add_argument('--configuration', '-c', required=False, dest='config', action='store',
                        help='The PAM Configuration UID or path to use for connections. '
                        'Use command `pam config list` to view available PAM Configurations.')
    parser.add_argument('--admin-user', '-a', required=False, dest='admin', action='store',
					help='The record path or UID of the PAM User record to configure the admin '
                    'credential on the PAM Resource')
    parser.add_argument('--protocol', '-p', dest='protocol', choices=protocols,
                        help='Set connection protocol')
    parser.add_argument('--connections', '-cn', dest='connections', choices=choices,
                        help='Set connections permissions')
    parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                        help='Set recording connections permissions for the resource')
    parser.add_argument('--typescript-recording', '-tr', dest='typescriptrecording', choices=choices,
                        help='Set TypeScript recording permissions for the resource')
    parser.add_argument('--connections-override-port', '-cop', required=False, dest='connections_override_port',
                        action='store', help='Port to use for connections. If not provided, '
                        'the port from the record will be used.')
    parser.add_argument('--silent', '-s', required=False, dest='silent', action='store_true',
					help='Silent mode - don\'t print PAM User, PAM Config etc.')

    def get_parser(self):
        return PAMConnectionEditCommand.parser

    def execute(self, params, **kwargs):
        connection_override_port = kwargs.get('connections_override_port', None)

        # Convert on/off/default to True/False/None
        _connections = TunnelDAG._convert_allowed_setting(kwargs.get('connections', None))
        _recording = TunnelDAG._convert_allowed_setting(kwargs.get('recording', None))
        _typescript_recording = TunnelDAG._convert_allowed_setting(kwargs.get('typescriptrecording', None))

        if connection_override_port:
            try:
                connection_override_port = int(connection_override_port)
            except ValueError:
                raise CommandError('connection edit', '--connections-override-port must be an integer')

        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('pam connection edit', 'Record parameter is required.')
        record = RecordMixin.resolve_single_record(params, record_name)
        if not record:
            raise CommandError('pam connection edit', f'{bcolors.FAIL}Record \"{record_name}\" not found.{bcolors.ENDC}')
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('pam connection edit', f'Record \"{record_name}\" can not be edited.')

        # config parameter is optional and maybe (auto)resolved from PAM record
        config_name = kwargs.get('config', None)
        cfg_rec = RecordMixin.resolve_single_record(params, config_name)
        if not cfg_rec and record.version == 6:
            cfg_rec = record  # trying to edit PAM Config itself
        config_uid = cfg_rec.record_uid if cfg_rec else None

        record_uid = record.record_uid
        record_type = record.record_type
        if record_type not in ("pamMachine pamDatabase pamDirectory pamNetworkConfiguration pamAwsConfiguration "
                               "pamRemoteBrowser pamAzureConfiguration").split():
            raise CommandError('', f"{bcolors.FAIL}This record's type is not supported for connections. "
                                   f"Connectins are only supported on pamMachine, pamDatabase, pamDirectory, "
                                   f"pamRemoteBrowser, pamNetworkConfiguration pamAwsConfiguration, and "
                                   f"pamAzureConfiguration records{bcolors.ENDC}")

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        if record_type in "pamNetworkConfiguration pamAwsConfiguration pamAzureConfiguration".split():
            tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, record_uid, is_config=True)
            tdag.edit_tunneling_config(connections=_connections, session_recording=_recording, typescript_recording=_typescript_recording)
            if not kwargs.get("silent", False): tdag.print_tunneling_config(record_uid, None)
        else:
            traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
            # Generate a 256-bit (32-byte) random seed
            seed = os.urandom(32)
            dirty = False
            if not traffic_encryption_key or not traffic_encryption_key.value:
                base64_seed = bytes_to_base64(seed)
                record_seed = vault.TypedField.new_field('trafficEncryptionSeed', base64_seed, "")
                # if field is present update in-place, if in rec definition add to fields[] else custom[]
                record_types_with_seed = ("pamDatabase", "pamDirectory", "pamMachine", "pamRemoteBrowser")
                if traffic_encryption_key:
                    traffic_encryption_key.value = [base64_seed]
                elif record.get_record_type() in record_types_with_seed:
                    record.fields.append(record_seed)  # DU-469
                else:
                    record.custom.append(record_seed)
                dirty = True

            protocol = kwargs.get("protocol", None)
            pam_settings = record.get_typed_field('pamSettings')
            if not pam_settings:
                pre_settings = {"connection": {}, "portForward": {}}
                if _connections:
                    if connection_override_port:
                        pre_settings["connection"]["port"] = connection_override_port
                    if protocol:
                        pre_settings["connection"]["protocol"] = protocol
                elif protocol or connection_override_port:
                    logging.warning(f'Connection override port and protocol can be set only when connections are enabled '
                            f'with {bcolors.OKGREEN}--connections=on{bcolors.ENDC} option')
                if pre_settings:
                    pam_settings = vault.TypedField.new_field('pamSettings', pre_settings, "")
                    record.custom.append(pam_settings)
                    dirty = True
            else:
                if not pam_settings.value:
                    pam_settings.value.append({"connection": {}, "portForward": {}})
                if _connections:
                    if connection_override_port:
                        pam_settings.value[0]["connection"]["port"] = connection_override_port
                    elif connection_override_port is not None:  # empty string means remove port override
                        pam_settings.value[0]["connection"].pop("port", None)
                    if protocol:
                        pam_settings.value[0]["connection"]["protocol"] = protocol
                    elif protocol is not None:  # empty string means remove protocol
                        pam_settings.value[0]["connection"].pop("protocol", None)
                    dirty = True
                elif protocol or connection_override_port:
                    logging.warning(f'Connection override port and protocol can be set only when connections are enabled '
                            f'with {bcolors.OKGREEN}--connections=on{bcolors.ENDC} option')
            if dirty:
                record_management.update_record(params, record)
                api.sync_down(params)

                traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
                if not traffic_encryption_key:
                    raise CommandError('', f"{bcolors.FAIL}Unable to add Seed to record {record_uid}. "
                                       f"Please make sure you have edit rights to record {record_uid} {bcolors.ENDC}")
            dirty = False

            existing_config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)

            tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, config_uid)
            old_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, existing_config_uid)

            if config_uid and existing_config_uid != config_uid:
                old_dag.remove_from_dag(record_uid)
                tdag.link_resource_to_config(record_uid)

            if tdag is None or not tdag.linking_dag.has_graph:
                raise CommandError('', f"{bcolors.FAIL}No PAM Configuration UID set. "
                                   f"This must be set or supplied for connections to work. This can be done by adding "
                                   f"{bcolors.OKBLUE}' --config [ConfigUID] "
                                   f" {bcolors.FAIL}The ConfigUID can be found by running "
                                   f"{bcolors.OKBLUE}'pam config list'{bcolors.ENDC}")

            if not tdag.check_tunneling_enabled_config(enable_connections=_connections,
                                                       enable_session_recording=_recording,
                                                       enable_typescript_recording=_typescript_recording):
                if not kwargs.get("silent", False): tdag.print_tunneling_config(config_uid, None)
                command = f"{bcolors.OKBLUE}'pam connection edit {config_uid}"
                if _connections and not tdag.check_tunneling_enabled_config(enable_connections=_connections):
                    command += f" --connections=on" if _connections else ""
                if _recording and not tdag.check_tunneling_enabled_config(enable_session_recording=_recording):
                    command += f" --connections-recording=on" if _recording else ""
                if _typescript_recording and not tdag.check_tunneling_enabled_config(enable_typescript_recording=_typescript_recording):
                    command += f" --typescript-recording=on" if _typescript_recording else ""

                print(f"{bcolors.FAIL}The settings are denied by PAM Configuration: {config_uid}. "
                      f"Please enable settings for the configuration by running\n"
                      f"{command}'{bcolors.ENDC}")
                return

            if not tdag.is_tunneling_config_set_up(record_uid):
                tdag.link_resource_to_config(record_uid)

            if not tdag.is_tunneling_config_set_up(record_uid):
                print(f"{bcolors.FAIL}No PAM Configuration UID set. This must be set for connections to work. "
                      f"This can be done by running {bcolors.OKBLUE}"
                      f"'pam connection edit {record_uid} --config [ConfigUID] --enable-connections' "
                      f"{bcolors.FAIL}The ConfigUID can be found by running {bcolors.OKBLUE}'pam config list'{bcolors.ENDC}")
                return
            allowed_settings_name = "allowedSettings"
            if record.record_type == "pamRemoteBrowser":
                allowed_settings_name = "pamRemoteBrowserSettings"

            if _connections is not None and tdag.check_if_resource_allowed(record_uid, "connections") != _connections:
                dirty = True
            if _recording is not None and tdag.check_if_resource_allowed(record_uid, "sessionRecording") != _recording:
                dirty = True
            if _typescript_recording is not None and tdag.check_if_resource_allowed(record_uid, "typescriptRecording") != _typescript_recording:
                dirty = True

            if dirty:
                tdag.set_resource_allowed(resource_uid=record_uid,
                                          allowed_settings_name=allowed_settings_name,
                                          connections=kwargs.get('connections', None),
                                          session_recording=kwargs.get('recording', None),
                                          typescript_recording=kwargs.get('typescriptrecording', None))

            # admin parameter is optional yet if not set connections may fail
            admin_name = kwargs.get('admin')
            adm_rec = RecordMixin.resolve_single_record(params, admin_name)
            admin_uid = adm_rec.record_uid if adm_rec else None
            if admin_uid and record_type in ("pamDatabase", "pamDirectory", "pamMachine"):
                tdag.link_user_to_resource(admin_uid, record_uid, is_admin=True, belongs_to=True)
                # tdag.link_user_to_config(admin_uid)  # is_iam_user=True

            # Print out PAM Settings
            if not kwargs.get("silent", False): tdag.print_tunneling_config(record_uid, record.get_typed_field('pamSettings'), config_uid)

class PAMSplitCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam split')
    pam_cmd_parser.add_argument('pam_machine_record', type=str, action='store',
                                help='The record UID or title of the legacy PAM Machine '
                                'record with built-in PAM User credentials.')
    pam_cmd_parser.add_argument('--configuration', '-c', required=False, dest='pam_config', action='store',
                                help='The PAM Configuration Name or UID - If the legacy record was configured '
                                     'for rotation this command will try to autodetect PAM Configuration settings '
                                     'otherwise you\'ll be prompted to provide the PAM Config.')
    pam_cmd_parser.add_argument('--folder', '-f', required=False, dest='pam_user_folder', action='store',
                                help='The folder where to store the new PAM User record - '
                                     'folder names/paths are case sensitive!'
                                     '(if skipped - PAM User will be created into the '
                                     'same folder as PAM Machine)')

    def get_parser(self):
        return PAMSplitCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        # Parse command params
        pam_config = kwargs.get('pam_config', '')  # PAM Configuration Name or UID
        folder = kwargs.get('pam_user_folder', '')  # destination folder
        record_uid = kwargs.get('pam_machine_record', '')  # existing record UID

        record_uid = resolve_record(params, record_uid) or record_uid
        record = vault.KeeperRecord.load(params, record_uid)
        if not record:
            raise CommandError('', f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
        if not isinstance(record, vault.TypedRecord) or record.record_type != "pamMachine":
            raise CommandError('', f"{bcolors.FAIL}Record {record_uid} is not of the expected type 'pamMachine'.{bcolors.ENDC}")

        pam_config_uid = resolve_pam_config(params, record_uid, pam_config)
        if not pam_config_uid:
            print(f"{bcolors.FAIL}Please provide a valid PAM Configuration.{bcolors.ENDC}")
            return

        folder_uid = resolve_folder(params, folder)
        if folder and not folder_uid:
            print(f"{bcolors.WARNING}Unable to find destination folder '{folder}' "
                  "(Note: folder names/paths are case sensitive) "
                  "- PAM User record will be stored into same folder "
                  f"as the originating PAM Machine record.{bcolors.ENDC}")

        flogin = record.get_typed_field('login')
        vlogin = flogin.get_default_value(str) if flogin else ''
        fpass = record.get_typed_field('password')
        vpass = fpass.get_default_value(str) if fpass else ''
        fpkey = record.get_typed_field('secret')
        vpkey = fpkey.get_default_value(str) if fpkey else ''
        if not(vlogin or vpass or vpkey):
            if not(flogin or fpass or fpkey):
                print(f"{bcolors.WARNING}Record {record_uid} is already in the new format.{bcolors.ENDC}")
            else:
                # No values present - just drop the old fields and add new ones,
                # thus converting the record to the new pamMachine format
                # NB! If the record was edited - newer clients moved these to custom fields
                if flogin:
                    remove_field(record, flogin)
                if fpass:
                    remove_field(record, fpass)
                if fpkey:
                    remove_field(record, fpkey)

                if not record.get_typed_field('trafficEncryptionSeed'):
                    record_seed = vault.TypedField.new_field('trafficEncryptionSeed', "", "")
                    record.fields.append(record_seed)
                if not record.get_typed_field('pamSettings'):
                    pam_settings = vault.TypedField.new_field('pamSettings', "", "")
                    record.fields.append(pam_settings)

                record_management.update_record(params, record)
                params.sync_data = True

                print(f"{bcolors.WARNING}Record {record_uid} has no data to split and "
                    "was converted to the new format. Remember to manually add "
                    f"Administrative Credentials later.{bcolors.ENDC}")
            return
        elif not vlogin or not(vpass or vpkey):
            print(f"{bcolors.WARNING}Record {record_uid} has incomplete user data "
                  "but splitting anyway. Remember to manually update linked "
                  f"Administrative Credentials record later.{bcolors.ENDC}")

        # Create new pamUser record
        user_rec = vault.KeeperRecord.create(params, 'pamUser')
        user_rec.type_name = 'pamUser'
        user_rec.title = str(record.title) + ' Admin User'
        if flogin:
            field = user_rec.get_typed_field('login')
            field.value = flogin.value
        if fpass:
            field = user_rec.get_typed_field('password')
            field.value = fpass.value
        if fpkey:
            field = user_rec.get_typed_field('secret')
            field.value = fpkey.value

        if not folder_uid:  # use the folder of the PAM Machine record
            folders = list(find_folders(params, record.record_uid))
            uniq_items = len(set(folders))
            if uniq_items < 1:
                print(f"{bcolors.WARNING}The new record will be created in root folder.{bcolors.ENDC}")
            elif uniq_items > 1:
                print(f"{bcolors.FAIL}Record '{record.record_uid}' is probably "
                      "a linked record with copies/links across multiple folders "
                      f"and PAM User record will be created in folder '{folders[0]}'.{bcolors.ENDC}")
            folder_uid = folders[0] if folders else ''  # '' means root folder

        record_management.add_record_to_folder(params, user_rec, folder_uid)
        pam_user_uid = params.environment_variables.get(LAST_RECORD_UID, '')
        api.sync_down(params)

        if flogin:
            remove_field(record, flogin)
        if fpass:
            remove_field(record, fpass)
        if fpkey:
            remove_field(record, fpkey)

        if not record.get_typed_field('trafficEncryptionSeed'):
            record_seed = vault.TypedField.new_field('trafficEncryptionSeed', "", "")
            record.fields.append(record_seed)
        if not record.get_typed_field('pamSettings'):
            pam_settings = vault.TypedField.new_field('pamSettings', "", "")
            record.fields.append(pam_settings)

        record_management.update_record(params, record)
        params.sync_data = True

        if pam_config_uid:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_config_uid, True)
            tdag.link_resource_to_config(record_uid)
            tdag.link_user_to_resource(pam_user_uid, record_uid, True, True)

        print(f"PAM Machine record {record_uid} user credentials were split into "
              f"a new PAM User record {pam_user_uid}")
