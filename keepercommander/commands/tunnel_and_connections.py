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

import argparse
import logging
import os
import sys
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes

from .base import Command, GroupCommand, dump_report_data, RecordMixin
from .tunnel.port_forward.TunnelGraph import TunnelDAG
from .tunnel.port_forward.tunnel_helpers import find_open_port, get_config_uid, get_keeper_tokens, \
    get_or_create_tube_registry, get_gateway_uid_from_record, resolve_record, resolve_pam_config, resolve_folder, \
    remove_field, start_rust_tunnel, get_tunnel_session, CloseConnectionReasons, create_rust_webrtc_settings
from .. import api, vault, record_management
from ..display import bcolors
from ..error import CommandError
from ..params import LAST_RECORD_UID
from ..subfolder import find_folders
from ..utils import value_to_boolean

# Group Commands
class PAMTunnelCommand(GroupCommand):

    def __init__(self):
        super(PAMTunnelCommand, self).__init__()
        self.register_command('start', PAMTunnelStartCommand(), 'Start Tunnel', 's')
        self.register_command('list', PAMTunnelListCommand(), 'List all Tunnels', 'l')
        self.register_command('stop', PAMTunnelStopCommand(), 'Stop Tunnel to the server', 'x')
        self.register_command('edit', PAMTunnelEditCommand(), 'Edit Tunnel settings', 'e')
        self.register_command('diagnose', PAMTunnelDiagnoseCommand(), 'Diagnose network connectivity to krelay server', 'd')
        self.default_verb = 'list'


class PAMConnectionCommand(GroupCommand):

    def __init__(self):
        super(PAMConnectionCommand, self).__init__()
        # self.register_command('start', PAMConnectionStartCommand(), 'Start Connection', 's')
        # self.register_command('stop', PAMConnectionStopCommand(), 'Stop Connection', 'x')
        self.register_command('edit', PAMConnectionEditCommand(), 'Edit Connection settings', 'e')
        self.default_verb = 'edit'


class PAMRbiCommand(GroupCommand):

    def __init__(self):
        super(PAMRbiCommand, self).__init__()
        self.register_command('edit', PAMRbiEditCommand(), 'Edit Remote Browser Isolation settings', 'e')
        self.default_verb = 'edit'


# Individual Commands
class PAMTunnelListCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel list')

    def get_parser(self):
        return PAMTunnelListCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        # Try to get active tunnels from Rust PyTubeRegistry
        # Logger initialization is handled by get_or_create_tube_registry()
        tube_registry = get_or_create_tube_registry(params)
        if tube_registry:
            if not tube_registry.has_active_tubes():
                logging.warning(f"{bcolors.OKBLUE}No Tunnels running{bcolors.ENDC}")
                return

            table = []
            headers = ['Record', 'Remote Target', 'Local Address', 'Tunnel ID', 'Conversation ID', 'Status']

            # Get all tube IDs
            tube_ids = tube_registry.all_tube_ids()

            for tube_id in tube_ids:
                # Get conversation IDs for this tube
                conversation_ids = tube_registry.get_conversation_ids_by_tube_id(tube_id)

                # Get tunnel session for detailed info
                tunnel_session = get_tunnel_session(tube_id)

                # Record title
                record_title = tunnel_session.record_title if tunnel_session and tunnel_session.record_title else f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                # Remote target
                if tunnel_session and tunnel_session.target_host and tunnel_session.target_port:
                    remote_target = f"{tunnel_session.target_host}:{tunnel_session.target_port}"
                else:
                    remote_target = f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                # Local listening address
                if tunnel_session and tunnel_session.host and tunnel_session.port:
                    local_addr = f"{bcolors.OKGREEN}{tunnel_session.host}:{tunnel_session.port}{bcolors.ENDC}"
                else:
                    local_addr = f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                # Tunnel ID (tube_id) - this is what's needed for stopping
                tunnel_id = tube_id

                # Conversation ID - WebRTC signaling identifier
                conv_id = conversation_ids[0] if conversation_ids else (tunnel_session.conversation_id if tunnel_session else 'none')

                # Connection state
                try:
                    state = tube_registry.get_connection_state(tube_id)
                    status_color = f"{bcolors.OKGREEN}" if state.lower() == "connected" else f"{bcolors.WARNING}"
                    status = f"{status_color}{state}{bcolors.ENDC}"
                except:
                    status = f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                row = [
                    record_title,
                    remote_target,
                    local_addr,
                    tunnel_id,
                    conv_id,
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
    pam_cmd_parser.add_argument('uid', type=str, action='store', nargs='?', help='The Tunnel ID, Conversation ID, or Record UID (omit with --all to stop all tunnels)')
    pam_cmd_parser.add_argument('--all', dest='stop_all', action='store_true', 
                                help='Stop all tunnels (if no UID) or all tunnels matching the UID (if UID provided)')

    def get_parser(self):
        return PAMTunnelStopCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        uid = kwargs.get('uid')
        stop_all = kwargs.get('stop_all', False)
        
        # Special case: --all with no UID means stop ALL tunnels
        if stop_all and not uid:
            return self._stop_all_tunnels(params)
        
        if not uid:
            raise CommandError('tunnel stop', '"uid" argument is required (or use --all to stop all tunnels)')

        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            raise CommandError('tunnel stop', 'This command requires the Rust WebRTC library')

        # Find matching tubes by tunnel ID (tube_id)
        matching_tubes = tube_registry.find_tubes(uid)
        if not matching_tubes and tube_registry.tube_found(uid):
            matching_tubes = [uid]

        # If not found by tunnel ID, try looking up by conversation ID
        if not matching_tubes:
            # Try as-is first
            tube_id = tube_registry.tube_id_from_connection_id(uid)
            
            # If not found, try URL-safe base64 conversion
            if not tube_id:
                # Convert standard base64 to URL-safe (+ to -, / to _, remove =)
                url_safe_uid = uid.replace('+', '-').replace('/', '_').rstrip('=')
                tube_id = tube_registry.tube_id_from_connection_id(url_safe_uid)
                
            # If still not found, try the reverse (URL-safe to standard)
            if not tube_id:
                # Convert URL-safe to standard base64 (- to +, _ to /)
                standard_uid = uid.replace('-', '+').replace('_', '/')
                # Add padding if needed
                padding_needed = (4 - len(standard_uid) % 4) % 4
                if padding_needed:
                    standard_uid += '=' * padding_needed
                tube_id = tube_registry.tube_id_from_connection_id(standard_uid)
            
            if tube_id:
                matching_tubes = [tube_id]

        if not matching_tubes:
            raise CommandError('tunnel stop', f"No active tunnels found matching '{uid}'")

        # Check if multiple tunnels match and --all flag is required
        if len(matching_tubes) > 1:
            if not stop_all:
                print(f"{bcolors.WARNING}Found {len(matching_tubes)} tunnels matching '{uid}':{bcolors.ENDC}")
                for tube_id in matching_tubes:
                    print(f"  - {tube_id}")
                print(f"\n{bcolors.FAIL}Multiple tunnels found. Use --all to stop all of them, or specify a Tunnel ID or Conversation ID to stop a specific tunnel.{bcolors.ENDC}")
                raise CommandError('tunnel stop', 'Multiple tunnels found - use --all flag or specify exact Tunnel/Conversation ID')
            else:
                print(f"{bcolors.WARNING}Stopping {len(matching_tubes)} tunnels matching '{uid}':{bcolors.ENDC}")
                for tube_id in matching_tubes:
                    print(f"  - {tube_id}")

        # Close all matching tubes
        stopped_count = 0
        for tube_id in matching_tubes:
            try:
                tube_registry.close_tube(tube_id, reason=CloseConnectionReasons.Normal)
                print(f"{bcolors.OKGREEN}Stopped tunnel: {tube_id}{bcolors.ENDC}")
                stopped_count += 1
            except Exception as e:
                print(f"{bcolors.FAIL}Failed to stop tunnel {tube_id}: {e}{bcolors.ENDC}")

        if stopped_count == 0:
            raise CommandError('tunnel stop', f"Failed to stop any tunnels matching '{uid}'")

    def _stop_all_tunnels(self, params):
        """Stop all active tunnels"""
        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            raise CommandError('tunnel stop', 'This command requires the Rust WebRTC library')

        # Get all active tunnel IDs
        all_tube_ids = tube_registry.all_tube_ids()
        
        if not all_tube_ids:
            print(f"{bcolors.WARNING}No active tunnels to stop.{bcolors.ENDC}")
            return

        # Confirm with user
        print(f"{bcolors.WARNING}About to stop {len(all_tube_ids)} active tunnel(s):{bcolors.ENDC}")
        for tube_id in all_tube_ids:
            print(f"  - {tube_id}")
        
        # Stop all tunnels
        stopped_count = 0
        failed_count = 0
        for tube_id in all_tube_ids:
            try:
                tube_registry.close_tube(tube_id, reason=CloseConnectionReasons.Normal)
                print(f"{bcolors.OKGREEN}Stopped tunnel: {tube_id}{bcolors.ENDC}")
                stopped_count += 1
            except Exception as e:
                print(f"{bcolors.FAIL}Failed to stop tunnel {tube_id}: {e}{bcolors.ENDC}")
                failed_count += 1

        # Summary
        if stopped_count > 0:
            print(f"\n{bcolors.OKGREEN}Successfully stopped {stopped_count} tunnel(s).{bcolors.ENDC}")
        if failed_count > 0:
            print(f"{bcolors.FAIL}Failed to stop {failed_count} tunnel(s).{bcolors.ENDC}")
        
        if stopped_count == 0:
            raise CommandError('tunnel stop', 'Failed to stop any tunnels')


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
    pam_cmd_parser.add_argument('--target-host', '-th', required=False, dest='target_host', action='store',
                                help='Target hostname/IP to tunnel to (required when allowSupplyHost is enabled on the resource)')
    pam_cmd_parser.add_argument('--target-port', '-tp', required=False, dest='target_port', action='store',
                                type=int,
                                help='Target port to tunnel to (required when allowSupplyHost is enabled on the resource)')
    pam_cmd_parser.add_argument('--no-trickle-ice', '-nti', required=False, dest='no_trickle_ice', action='store_true',
                                help='Disable trickle ICE for WebRTC connections. By default, trickle ICE is enabled '
                                     'for real-time candidate exchange.')

    def get_parser(self):
        return PAMTunnelStartCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        # Python version validation (same as before)
        from_version = [3, 8, 0]   # including
        major_version = sys.version_info.major
        minor_version = sys.version_info.minor
        micro_version = sys.version_info.micro

        if (major_version, minor_version, micro_version) < (from_version[0], from_version[1], from_version[2]):
            print(f"{bcolors.FAIL}This command requires Python {from_version[0]}.{from_version[1]}.{from_version[2]} or higher. "
                  f"You are using {major_version}.{minor_version}.{micro_version}.{bcolors.ENDC}")
            return

        # Check for Rust WebRTC library availability
        # Logger initialization is handled by get_or_create_tube_registry()
        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            print(f"{bcolors.FAIL}This command requires the Rust WebRTC library (keeper_pam_webrtc_rs).{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Please ensure the keeper_pam_webrtc_rs module is installed and available.{bcolors.ENDC}")
            return

        record_uid = kwargs.get('uid')
        host = kwargs.get('host')
        port = kwargs.get('port')
        no_trickle_ice = kwargs.get('no_trickle_ice', False)

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

        # Check if allow_supply_host is enabled
        pam_settings_value = pam_settings.get_default_value() if pam_settings else {}
        allow_supply_host = pam_settings_value.get('allowSupplyHost', False) if isinstance(pam_settings_value, dict) else False

        # Get target host and port
        if allow_supply_host:
            # User must supply target host and port via command arguments or interactive prompt
            target_host = kwargs.get('target_host')
            target_port = kwargs.get('target_port')

            # If not provided via command line, prompt interactively
            if not target_host:
                print(f"{bcolors.WARNING}This resource requires you to supply the target host and port.{bcolors.ENDC}")
                try:
                    target_host = input(f"{bcolors.OKBLUE}Enter target hostname or IP address: {bcolors.ENDC}").strip()
                    if not target_host:
                        print(f"{bcolors.FAIL}Target host is required.{bcolors.ENDC}")
                        return
                except (KeyboardInterrupt, EOFError):
                    print(f"\n{bcolors.FAIL}Cancelled.{bcolors.ENDC}")
                    return

            if not target_port:
                try:
                    target_port_str = input(f"{bcolors.OKBLUE}Enter target port number: {bcolors.ENDC}").strip()
                    if not target_port_str:
                        print(f"{bcolors.FAIL}Target port is required.{bcolors.ENDC}")
                        return
                    target_port = int(target_port_str)
                except (KeyboardInterrupt, EOFError):
                    print(f"\n{bcolors.FAIL}Cancelled.{bcolors.ENDC}")
                    return
                except ValueError:
                    print(f"{bcolors.FAIL}Invalid target port '{target_port_str}'. Port must be a number.{bcolors.ENDC}")
                    return

            # Validate target_port is an integer (if provided via kwargs)
            try:
                target_port = int(target_port)
            except (ValueError, TypeError):
                print(f"{bcolors.FAIL}Invalid target port '{target_port}'. Port must be a number.{bcolors.ENDC}")
                return

            # Validate port range
            if not (1 <= target_port <= 65535):
                print(f"{bcolors.FAIL}Invalid port number {target_port}. Port must be between 1 and 65535.{bcolors.ENDC}")
                return

            print(f"{bcolors.OKBLUE}Tunneling to user-supplied target: {target_host}:{target_port}{bcolors.ENDC}")
        else:
            # Get target from record
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

        # Use Rust WebRTC implementation with configurable trickle ICE
        trickle_ice = not no_trickle_ice
        result = start_rust_tunnel(params, record_uid, gateway_uid, host, port, seed, target_host, target_port, socks, trickle_ice, record.title, allow_supply_host=allow_supply_host)
        
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


class PAMTunnelDiagnoseCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel diagnose', 
                                           description='Diagnose network connectivity to krelay server. '
                                                       'Tests DNS resolution, TCP/UDP connectivity, AWS infrastructure, '
                                                       'and WebRTC peer connection setup for IT troubleshooting.')
    pam_cmd_parser.add_argument('record', type=str, action='store', 
                                help='The Record UID of the PAM resource record to test connectivity for')
    pam_cmd_parser.add_argument('--timeout', '-t', required=False, dest='timeout', action='store',
                                type=int, default=30,
                                help='Test timeout in seconds (default: 30)')
    pam_cmd_parser.add_argument('--verbose', '-v', required=False, dest='verbose', action='store_true',
                                help='Show detailed diagnostic output including ICE server lists')
    pam_cmd_parser.add_argument('--format', '-f', required=False, dest='format', action='store',
                                choices=['table', 'json'], default='table',
                                help='Output format: table (human-readable) or json (machine-readable)')
    pam_cmd_parser.add_argument('--test', required=False, dest='test_filter', action='store',
                                help='Comma-separated list of specific tests to run. Available: '
                                     'dns_resolution,aws_connectivity,tcp_connectivity,udp_binding,'
                                     'ice_configuration,webrtc_peer_connection')

    def get_parser(self):
        return PAMTunnelDiagnoseCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        timeout = kwargs.get('timeout', 30)
        verbose = kwargs.get('verbose', False)
        output_format = kwargs.get('format', 'table')
        test_filter = kwargs.get('test_filter')
        
        if not record_name:
            raise CommandError('pam tunnel diagnose', '"record" parameter is required.')

        # Check for Rust WebRTC library availability
        # Logger initialization is handled by get_or_create_tube_registry()
        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            print(f"{bcolors.FAIL}This command requires the Rust WebRTC library (keeper_pam_webrtc_rs).{bcolors.ENDC}")
            print(f"{bcolors.OKBLUE}Please ensure the keeper_pam_webrtc_rs module is installed and available.{bcolors.ENDC}")
            return 1

        # Resolve and validate the record
        api.sync_down(params)
        record = RecordMixin.resolve_single_record(params, record_name)
        if not record:
            print(f"{bcolors.FAIL}Record '{record_name}' not found.{bcolors.ENDC}")
            return 1
        if not isinstance(record, vault.TypedRecord):
            print(f"{bcolors.FAIL}Record '{record_name}' cannot be used for tunneling.{bcolors.ENDC}")
            return 1

        record_uid = record.record_uid
        record_type = record.record_type
        if record_type not in ("pamMachine pamDatabase pamDirectory pamNetworkConfiguration pamAwsConfiguration "
                               "pamRemoteBrowser pamAzureConfiguration").split():
            print(f"{bcolors.FAIL}Record type '{record_type}' is not supported for tunneling.{bcolors.ENDC}")
            print(f"Supported types: pamMachine, pamDatabase, pamDirectory, pamRemoteBrowser, "
                  f"pamNetworkConfiguration, pamAwsConfiguration, pamAzureConfiguration")
            return 1

        # Get the krelay server from the PAM configuration
        try:
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            pam_config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
            
            if not pam_config_uid:
                print(f"{bcolors.FAIL}No PAM Configuration found for record '{record_name}'.{bcolors.ENDC}")
                print(f"Please configure the record with: {bcolors.OKBLUE}pam tunnel edit {record_uid} --config [ConfigUID]{bcolors.ENDC}")
                return 1

            # The krelay server hostname is constructed from the params.server
            krelay_server = f"krelay.{params.server}"
            
        except Exception as e:
            print(f"{bcolors.FAIL}Failed to get PAM configuration: {e}{bcolors.ENDC}")
            return 1

        # Build test settings
        settings = {
            "use_turn": True,
            "turn_only": False
        }

        # Parse test filter if provided
        if test_filter:
            allowed_tests = {'dns_resolution', 'aws_connectivity', 'tcp_connectivity', 
                           'udp_binding', 'ice_configuration', 'webrtc_peer_connection'}
            requested_tests = set(test.strip() for test in test_filter.split(','))
            invalid_tests = requested_tests - allowed_tests
            if invalid_tests:
                print(f"{bcolors.FAIL}Invalid test names: {', '.join(invalid_tests)}{bcolors.ENDC}")
                print(f"Available tests: {', '.join(sorted(allowed_tests))}")
                return 1
            settings["test_filter"] = list(requested_tests)

        print(f"{bcolors.OKBLUE}Starting network connectivity diagnosis for krelay server: {krelay_server}{bcolors.ENDC}")
        print(f"Record: {record.title} ({record_uid})")
        print(f"Timeout: {timeout}s")
        print("")

        # Get TURN credentials for the connectivity test
        try:
            webrtc_settings = create_rust_webrtc_settings(
                params, host="127.0.0.1", port=0, 
                target_host="test", target_port=22, 
                socks=False, nonce=os.urandom(32)
            )
            turn_username = webrtc_settings.get("turn_username")
            turn_password = webrtc_settings.get("turn_password")
        except Exception as e:
            print(f"{bcolors.WARNING}Could not get TURN credentials: {e}{bcolors.ENDC}")
            turn_username = None
            turn_password = None

        # Run the connectivity test
        try:
            results = tube_registry.test_webrtc_connectivity(
                krelay_server=krelay_server,
                settings=settings,
                timeout_seconds=timeout,
                username=turn_username,
                password=turn_password
            )
            
            if output_format == 'json':
                import json
                print(json.dumps(results, indent=2))
                return 0
            else:
                # Use the built-in formatter for human-readable output
                formatted_output = tube_registry.format_connectivity_results(results, detailed=verbose)
                print(formatted_output)
                
                # Return appropriate exit code
                overall_result = results.get('overall_result', {})
                if overall_result.get('success', False):
                    return 0
                else:
                    return 1
                    
        except Exception as e:
            print(f"{bcolors.FAIL}Network connectivity test failed: {e}{bcolors.ENDC}")
            logging.debug(f"Full error details: {e}", exc_info=True)
            return 1


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
    parser.add_argument('--key-events', '-k', dest='key_events', choices=choices,
                        help='Toggle Key Events settings')
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
                                   f"Connections are only supported on pamMachine, pamDatabase, pamDirectory, "
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
                if not pam_settings.value[0]:
                    pam_settings.value[0] = {"connection": {}, "portForward": {}}
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

            # pam_settings.value already initialized above
            key_events = kwargs.get('key_events')  # on/off/default
            if key_events:
                psv = pam_settings.value[0] if pam_settings and pam_settings.value else {}
                vcon = psv.get('connection', {}) if isinstance(psv, dict) else {}
                rik = vcon.get('recordingIncludeKeys') if isinstance(vcon, dict) else None
                if key_events == 'default':
                    if rik is not None:
                        pam_settings.value[0]["connection"].pop('recordingIncludeKeys', None)
                        dirty = True
                    else:
                        logging.debug(f'recordingIncludeKeys is already set to "default" on record={record_uid}')
                elif key_events == 'on':
                    if value_to_boolean(key_events) != value_to_boolean(rik):
                        pam_settings.value[0]["connection"]["recordingIncludeKeys"] = True
                        dirty = True
                    else:
                        logging.debug(f'recordingIncludeKeys is already enabled on record={record_uid}')
                elif key_events == 'off':
                    if value_to_boolean(key_events) != value_to_boolean(rik):
                        pam_settings.value[0]["connection"]["recordingIncludeKeys"] = False
                        dirty = True
                    else:
                        logging.debug(f'recordingIncludeKeys is already disabled on record={record_uid}')
                else:
                    logging.debug(f'Unexpected value for --key-events {key_events} (ignored)')

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

class PAMRbiEditCommand(Command):
    choices = ['on', 'off', 'default']
    parser = argparse.ArgumentParser(prog='pam rbi edit')

    # Record and Configuration
    parser.add_argument('--record', '-r', type=str, required=True, dest='record', action='store',
                        help='The record UID or path of the RBI record.')
    parser.add_argument('--configuration', '-c', required=False, dest='config', action='store',
                        help='The PAM Configuration UID or path to use for connections. '
                        'Use command `pam config list` to view available PAM Configurations.')

    # RBI and Recording Settings
    parser.add_argument('--remote-browser-isolation', '-rbi', dest='rbi', choices=choices,
                        help='Set RBI permissions')
    parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                        help='Set recording connections permissions for the resource')
    parser.add_argument('--key-events', '-k', dest='key_events', choices=choices,
                        help='Toggle Key Events settings')

    # Browser Settings
    parser.add_argument('--allow-url-navigation', '-nav', dest='allow_url_navigation', choices=choices,
                        help='Allow navigation via direct URL manipulation (on/off/default)')
    parser.add_argument('--ignore-server-cert', '-isc', dest='ignore_server_cert', choices=choices,
                        help='Ignore server certificate errors (on/off/default)')

    # URL Filtering
    parser.add_argument('--allowed-urls', '-au', dest='allowed_urls', action='append',
                        help='Allowed URL patterns (can specify multiple times)')
    parser.add_argument('--allowed-resource-urls', '-aru', dest='allowed_resource_urls', action='append',
                        help='Allowed resource URL patterns (can specify multiple times)')

    # Autofill Settings
    parser.add_argument('--autofill-credentials', '-a', type=str, required=False, dest='autofill', action='store',
                        help='The record UID or path of the RBI Autofill Credentials record.')
    parser.add_argument('--autofill-targets', '-at', dest='autofill_targets', action='append',
                        help='Autofill target selectors (can specify multiple times)')

    # Clipboard Settings
    parser.add_argument('--allow-copy', '-cpy', dest='allow_copy', choices=choices,
                        help='Allow copying to clipboard (on/off/default)')
    parser.add_argument('--allow-paste', '-p', dest='allow_paste', choices=choices,
                        help='Allow pasting from clipboard (on/off/default)')

    # Audio Settings
    parser.add_argument('--disable-audio', '-da', dest='disable_audio', choices=choices,
                        help='Disable audio for RBI sessions (on/off/default)')
    parser.add_argument('--audio-channels', '-ac', dest='audio_channels', type=int,
                        help='Number of audio channels (e.g., 1 for mono, 2 for stereo)')
    parser.add_argument('--audio-bit-depth', '-bd', dest='audio_bit_depth', type=int, choices=[8, 16],
                        help='Audio bit depth (8 or 16)')
    parser.add_argument('--audio-sample-rate', '-sr', dest='audio_sample_rate', type=int,
                        help='Audio sample rate in Hz (e.g., 44100, 48000)')

    # Utility
    parser.add_argument('--silent', '-s', required=False, dest='silent', action='store_true',
                        help='Silent mode - don\'t print PAM User, PAM Config etc.')

    def get_parser(self):
        return PAMRbiEditCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record') or ''
        config_name = kwargs.get('config') or ''
        autofill = kwargs.get('autofill') or ''
        key_events = kwargs.get('key_events')  # on/off/default
        rbi = kwargs.get('rbi')  # on/off/default
        recording = kwargs.get('recording')  # on/off/default
        silent = kwargs.get('silent') or False

        # New RBI settings (Phase 1 - KC-1034)
        allow_url_navigation = kwargs.get('allow_url_navigation')  # on/off/default/None
        ignore_server_cert = kwargs.get('ignore_server_cert')  # on/off/default/None
        allowed_urls = kwargs.get('allowed_urls')  # list or None
        allowed_resource_urls = kwargs.get('allowed_resource_urls')  # list or None
        autofill_targets = kwargs.get('autofill_targets')  # list or None
        allow_copy = kwargs.get('allow_copy')  # on/off/default/None
        allow_paste = kwargs.get('allow_paste')  # on/off/default/None
        disable_audio = kwargs.get('disable_audio')  # on/off/default/None
        audio_channels = kwargs.get('audio_channels')  # int or None
        audio_bit_depth = kwargs.get('audio_bit_depth')  # int or None
        audio_sample_rate = kwargs.get('audio_sample_rate')  # int or None

        if not record_name:
            raise CommandError('pam rbi edit', 'Record parameter is required.')

        # Check if any setting argument is provided
        has_new_settings = any([
            allow_url_navigation is not None,
            ignore_server_cert is not None,
            allowed_urls is not None,
            allowed_resource_urls is not None,
            autofill_targets is not None,
            allow_copy is not None,
            allow_paste is not None,
            disable_audio is not None,
            audio_channels is not None,
            audio_bit_depth is not None,
            audio_sample_rate is not None
        ])

        if not (autofill or key_events or config_name or rbi or recording or has_new_settings):
            raise CommandError('pam rbi edit', 'At least one parameter is required. '
                               'If the record is not linked to PAM Config, -c option is required.')

        record = RecordMixin.resolve_single_record(params, record_name)
        if not record:
            raise CommandError('pam rbi edit', f'{bcolors.FAIL}Record \"{record_name}\" not found.{bcolors.ENDC}')
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('pam rbi edit', f'Record \"{record_name}\" can not be edited.')

        record_uid = record.record_uid
        record_type = record.record_type
        if record_type != "pamRemoteBrowser":
            raise CommandError('pam rbi edit', f"{bcolors.FAIL}Record {record_uid} of type {record_type} "
                               "cannot be set up for RBI connections. "
                               f"RBI connection records must be of type: pamRemoteBrowser{bcolors.ENDC}")

        # record data (JSON) manipulations: autofill, key_events
        dirty = False
        traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
        if not traffic_encryption_key or not traffic_encryption_key.value:
            seed = os.urandom(32)
            base64_seed = bytes_to_base64(seed)
            record_seed = vault.TypedField.new_field('trafficEncryptionSeed', base64_seed, "")
            if traffic_encryption_key:
                traffic_encryption_key.value = [base64_seed]
            else:
                record.fields.append(record_seed)
            dirty = True

        rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
        if not rbs_fld:
            rbsettings = {'connection': {'protocol': 'http', 'httpCredentialsUid': ''}}
            pam_rbsettings = vault.TypedField.new_field('pamRemoteBrowserSettings', rbsettings, '')
            record.fields.append(pam_rbsettings)
            dirty = True
        elif not rbs_fld.value:
            rbs_fld.value.append({'connection': {'protocol': 'http'}}) # type: ignore
            dirty = True

        if autofill:
            af_rec = RecordMixin.resolve_single_record(params, autofill)
            if not af_rec:
                raise CommandError('pam rbi edit', f'{bcolors.FAIL}Record \"{autofill}\" not found.{bcolors.ENDC}')
            if not isinstance(af_rec, vault.TypedRecord) or af_rec.version != 3 or af_rec.record_type not in ("login", "pamUser"):
                raise CommandError('pam rbi edit', f'Autofill credentials record \"{af_rec.record_uid}\" can not be linked. '
                                ' RBI autofill credential records must be of type "login" or "pamUser"')

            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            val1 = rbs_fld.value[0] if isinstance(rbs_fld, vault.TypedField) and rbs_fld.value else {}
            hcuid = val1.get('connection', {}).get('httpCredentialsUid') or '' if isinstance(val1, dict) else ''
            if af_rec.record_uid == hcuid:
                logging.debug(f'httpCredentialsUid={af_rec.record_uid} is already set up on record={record_uid}')
            elif rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                rbs_fld.value[0]["connection"]["httpCredentialsUid"] = af_rec.record_uid
                dirty = True
                if hcuid:
                    logging.debug(f'Updated existing httpCredentialsUid from: {hcuid} to: {af_rec.record_uid}')
            else:
                raise CommandError('pam rbi edit', f'{bcolors.FAIL}Failed to set httpCredentialsUid={af_rec.record_uid}{bcolors.ENDC}')

        if key_events:
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            val1 = rbs_fld.value[0] if isinstance(rbs_fld, vault.TypedField) and rbs_fld.value else {}
            vcon = val1.get('connection', {}) if isinstance(val1, dict) else {}
            rik = vcon.get('recordingIncludeKeys') if isinstance(vcon, dict) else None
            if key_events == 'default':
                if rik is not None:
                    rbs_fld.value[0]["connection"].pop('recordingIncludeKeys', None)
                    dirty = True
                else:
                    logging.debug(f'recordingIncludeKeys is already set to "default" on record={record_uid}')
            elif key_events == 'on':
                if value_to_boolean(key_events) != value_to_boolean(rik):
                    rbs_fld.value[0]["connection"]["recordingIncludeKeys"] = True
                    dirty = True
                else:
                    logging.debug(f'recordingIncludeKeys is already enabled on record={record_uid}')
            elif key_events == 'off':
                if value_to_boolean(key_events) != value_to_boolean(rik):
                    rbs_fld.value[0]["connection"]["recordingIncludeKeys"] = False
                    dirty = True
                else:
                    logging.debug(f'recordingIncludeKeys is already disabled on record={record_uid}')
            else:
                logging.debug(f'Unexpected value for --key-events {key_events} (ignored)')

        # Handle new RBI settings (KC-1034)
        # Helper function to update connection settings with on/off/default pattern
        def update_connection_toggle(field_name, setting_value, invert=False):
            """Update a connection field using on/off/default pattern.

            Args:
                field_name: The field name in the connection dict
                setting_value: 'on', 'off', or 'default'
                invert: If True, 'on' sets False and 'off' sets True (for disableCopy/disablePaste)
            """
            nonlocal dirty
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            if rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                connection = rbs_fld.value[0].get('connection', {})
                current_value = connection.get(field_name)

                if setting_value == 'default':
                    if current_value is not None:
                        rbs_fld.value[0]['connection'].pop(field_name, None)
                        dirty = True
                        logging.debug(f'Removed {field_name} (set to default) on record={record_uid}')
                    else:
                        logging.debug(f'{field_name} is already set to default on record={record_uid}')
                elif setting_value == 'on':
                    target_value = False if invert else True
                    if current_value != target_value:
                        rbs_fld.value[0]['connection'][field_name] = target_value
                        dirty = True
                        logging.debug(f'Set {field_name}={target_value} on record={record_uid}')
                    else:
                        logging.debug(f'{field_name} is already set to {target_value} on record={record_uid}')
                elif setting_value == 'off':
                    target_value = True if invert else False
                    if current_value != target_value:
                        rbs_fld.value[0]['connection'][field_name] = target_value
                        dirty = True
                        logging.debug(f'Set {field_name}={target_value} on record={record_uid}')
                    else:
                        logging.debug(f'{field_name} is already set to {target_value} on record={record_uid}')
                else:
                    logging.debug(f'Unexpected value for {field_name}: {setting_value} (ignored)')

        # Helper function for multi-value string fields
        def update_connection_string(field_name, values):
            nonlocal dirty
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            if rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                connection = rbs_fld.value[0].get('connection', {})
                new_value = '\n'.join(values) if values else ''
                if connection.get(field_name) != new_value:
                    rbs_fld.value[0]['connection'][field_name] = new_value
                    dirty = True
                    logging.debug(f'Set {field_name}={new_value!r} on record={record_uid}')
                else:
                    logging.debug(f'{field_name} is already set to {new_value!r} on record={record_uid}')

        # Helper function for integer fields
        def update_connection_int(field_name, value):
            nonlocal dirty
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            if rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                connection = rbs_fld.value[0].get('connection', {})
                if connection.get(field_name) != value:
                    rbs_fld.value[0]['connection'][field_name] = value
                    dirty = True
                    logging.debug(f'Set {field_name}={value} on record={record_uid}')
                else:
                    logging.debug(f'{field_name} is already set to {value} on record={record_uid}')

        # Browser Settings - allowUrlManipulation (on/off/default)
        if allow_url_navigation:
            update_connection_toggle('allowUrlManipulation', allow_url_navigation)

        # Browser Settings - ignoreInitialSslCert (on/off/default)
        if ignore_server_cert:
            update_connection_toggle('ignoreInitialSslCert', ignore_server_cert)

        # URL Filtering - allowedUrlPatterns (multi-value, joined with newlines)
        if allowed_urls is not None:
            update_connection_string('allowedUrlPatterns', allowed_urls)

        # URL Filtering - allowedResourceUrlPatterns (multi-value, joined with newlines)
        if allowed_resource_urls is not None:
            update_connection_string('allowedResourceUrlPatterns', allowed_resource_urls)

        # Autofill Targets - autofillConfiguration (multi-value, joined with newlines)
        if autofill_targets is not None:
            update_connection_string('autofillConfiguration', autofill_targets)

        # Clipboard Settings - disableCopy (inverted: on -> disableCopy=False, off -> disableCopy=True)
        if allow_copy:
            update_connection_toggle('disableCopy', allow_copy, invert=True)

        # Clipboard Settings - disablePaste (inverted: on -> disablePaste=False, off -> disablePaste=True)
        if allow_paste:
            update_connection_toggle('disablePaste', allow_paste, invert=True)

        # Audio Settings - disableAudio (on -> disableAudio=True, off -> disableAudio=False)
        if disable_audio:
            update_connection_toggle('disableAudio', disable_audio)

        # Audio Settings - audioChannels (integer) - same location as disableAudio (inside connection)
        if audio_channels is not None:
            update_connection_int('audioChannels', audio_channels)

        # Audio Settings - audioBps (integer)
        if audio_bit_depth is not None:
            update_connection_int('audioBps', audio_bit_depth)

        # Audio Settings - audioSampleRate (integer)
        if audio_sample_rate is not None:
            update_connection_int('audioSampleRate', audio_sample_rate)

        if dirty:
            record_management.update_record(params, record)
            api.sync_down(params)

            traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
            if not traffic_encryption_key:
                raise CommandError('', f"{bcolors.FAIL}Unable to add Seed to record {record_uid}. "
                                f"Please make sure you have edit rights to record {record_uid} {bcolors.ENDC}")
            params.sync_data = True

        # DAG manipulation options: config, rbi/connections, recording
        dirty = False
        if not (config_name or rbi or recording):
            return

        # resolve PAM Config
        encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
        existing_config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        existing_config_uid = str(existing_config_uid) if existing_config_uid else ''

        # config parameter is optional and may be (auto)resolved from RBI record
        cfg_rec = None
        if config_name:
            cfg_rec = RecordMixin.resolve_single_record(params, config_name)
            msg = ("not found" if cfg_rec is None else "not the right type"
                   if not isinstance(cfg_rec, vault.TypedRecord) or cfg_rec.version != 6 else "")
            if msg:
                logging.warning(f'{bcolors.FAIL}PAM Config record "{config_name}" {msg} {bcolors.ENDC}')
                cfg_rec = None
        if not cfg_rec:
            logging.debug(f"PAM Config - using config from record {record_uid}")
            cfg_rec = RecordMixin.resolve_single_record(params, existing_config_uid)
            msg = ("not found" if cfg_rec is None else "not the right type"
                   if not isinstance(cfg_rec, vault.TypedRecord) or cfg_rec.version != 6 else "")
            if msg:
                logging.warning(f'{bcolors.FAIL}PAM Config record "{existing_config_uid}" {msg} {bcolors.ENDC}')
                cfg_rec = None

        config_uid = cfg_rec.record_uid if cfg_rec else None
        if not config_uid:
            raise CommandError('pam rbi edit', f'{bcolors.FAIL}PAM Config record not found.{bcolors.ENDC}')

        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, config_uid)
        if tdag is None or not tdag.linking_dag.has_graph:
            raise CommandError('', f"{bcolors.FAIL}No valid PAM Configuration UID set. "
                               "This must be set or supplied for connections to work. "
                               "The ConfigUID can be found by running "
                               f"{bcolors.OKBLUE}'pam config list'{bcolors.ENDC}")

        if config_uid:
            if existing_config_uid and existing_config_uid != config_uid:
                old_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, existing_config_uid)
                old_dag.remove_from_dag(record_uid)
                logging.debug(f'Updated existing PAM Config UID from: {existing_config_uid} to: {config_uid}')
            tdag.link_resource_to_config(record_uid)

        # connections=on needed alongside remoteBrowserIsolation=on in PAM Config for RBI to work
        cfg_con_state = tdag.get_resource_setting(config_uid, 'allowedSettings', 'connections')
        cfg_rbi_state = tdag.get_resource_setting(config_uid, 'allowedSettings', 'remoteBrowserIsolation')
        cfg_rec_state = tdag.get_resource_setting(config_uid, 'allowedSettings', 'sessionRecording')
        if cfg_con_state != 'on' or cfg_rbi_state != 'on' or cfg_rec_state != 'on':
            if not silent:
                tdag.print_tunneling_config(config_uid, None)
            command = f"{bcolors.OKBLUE}'pam connection edit {config_uid}"
            command += ' --connections=on' if cfg_con_state != 'on' else ''
            command += ' --remote-browser-isolation=on' if cfg_rbi_state != 'on' else ''
            command += ' --connections-recording=on' if cfg_rec_state != 'on' else ''
            print(f"{bcolors.FAIL}Some settings may be denied by PAM Configuration: {config_uid} "
                  f" [ --connections={cfg_con_state} --remote-browser-isolation={cfg_rbi_state} "
                  f" --connections-recording={cfg_rec_state} ] "
                  f"To enable these settings for the configuration run\n"
                  f"{command}'{bcolors.ENDC}")

        if not tdag.is_tunneling_config_set_up(record_uid):
            tdag.link_resource_to_config(record_uid)

        if not tdag.is_tunneling_config_set_up(record_uid):
            print(f"{bcolors.FAIL}No PAM Configuration UID set. This must be set for connections to work. "
                f"This can be done by running {bcolors.OKBLUE}"
                f"'pam connection edit {record_uid} --config [ConfigUID] --enable-connections' "
                f"{bcolors.FAIL}The ConfigUID can be found by running {bcolors.OKBLUE}'pam config list'{bcolors.ENDC}")
            return

        con_val, rec_val = None, None
        rec_con_state = tdag.get_resource_setting(record_uid, 'allowedSettings', 'connections')
        rec_rec_state = tdag.get_resource_setting(record_uid, 'allowedSettings', 'sessionRecording')
        if (rbi is not None and rbi != rec_con_state) or (recording is not None and recording != rec_rec_state):
            con_val = rbi if rbi != rec_con_state else None
            rec_val = recording if recording != rec_rec_state else None
            dirty = True

        allowed_settings_name = "allowedSettings"
        # NB! Currently for remoteBrowserIsolation to work rec needs only "allowedSettings": {"connections": true}
        # allowed_settings_name = "pamRemoteBrowserSettings"
        # if rbi and rbi != tdag.get_resource_setting(record_uid, 'pamRemoteBrowserSettings', 'remoteBrowserIsolation'):
        #     dirty = True

        if dirty:
            tdag.set_resource_allowed(resource_uid=record_uid,
                                    allowed_settings_name=allowed_settings_name,
                                    connections=con_val,
                                    session_recording=rec_val)
        # if not kwargs.get("silent", False):
        #     tdag.print_tunneling_config(record_uid, record.get_typed_field('pamRemoteBrowserSettings'), config_uid)
        params.sync_data = True

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
