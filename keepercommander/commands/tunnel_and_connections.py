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
import datetime
import http.client
import json
import logging
import os
import platform
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from typing import List, Optional, Tuple
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes, url_safe_str_to_bytes

from .base import Command, GroupCommand, dump_report_data, RecordMixin
from .tunnel.port_forward.TunnelGraph import TunnelDAG
from .tunnel.port_forward.tunnel_helpers import find_open_port, get_config_uid, get_keeper_tokens, \
    get_or_create_tube_registry, get_gateway_uid_from_record, resolve_record, resolve_pam_config, resolve_folder, \
    remove_field, start_rust_tunnel, get_tunnel_session, unregister_tunnel_session, CloseConnectionReasons, \
    wait_for_tunnel_connection, create_rust_webrtc_settings
from .tunnel_registry import (
    PARENT_GRACE_SECONDS,
    is_pid_alive,
    list_registered_tunnels,
    register_tunnel,
    stop_tunnel_process,
    unregister_tunnel,
)
from .. import api, vault, record_management
from ..display import bcolors
from ..error import CommandError
from ..params import LAST_RECORD_UID
from ..subfolder import find_folders
from ..utils import value_to_boolean
from ..constants import get_keeper_server_hostname


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
        table = []
        headers = ['Record', 'Remote Target', 'Local Address', 'Tunnel ID', 'Conversation ID', 'Status']

        # In-process tunnels from the Rust PyTubeRegistry
        tube_registry = get_or_create_tube_registry(params)
        in_process_tube_ids = set()
        if tube_registry and tube_registry.has_active_tubes():
            tube_ids = tube_registry.all_tube_ids()
            for tube_id in tube_ids:
                in_process_tube_ids.add(tube_id)
                conversation_ids = tube_registry.get_conversation_ids_by_tube_id(tube_id)
                tunnel_session = get_tunnel_session(tube_id)

                record_title = tunnel_session.record_title if tunnel_session and tunnel_session.record_title else f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                if tunnel_session and tunnel_session.target_host and tunnel_session.target_port:
                    remote_target = f"{tunnel_session.target_host}:{tunnel_session.target_port}"
                else:
                    remote_target = f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                if tunnel_session and tunnel_session.host and tunnel_session.port:
                    local_addr = f"{bcolors.OKGREEN}{tunnel_session.host}:{tunnel_session.port}{bcolors.ENDC}"
                else:
                    local_addr = f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                conv_id = conversation_ids[0] if conversation_ids else (tunnel_session.conversation_id if tunnel_session else 'none')

                try:
                    state = tube_registry.get_connection_state(tube_id)
                    status_color = f"{bcolors.OKGREEN}" if state.lower() == "connected" else f"{bcolors.WARNING}"
                    status = f"{status_color}{state}{bcolors.ENDC}"
                except Exception:
                    status = f"{bcolors.WARNING}unknown{bcolors.ENDC}"

                table.append([record_title, remote_target, local_addr, tube_id, conv_id, status])

        # Cross-process tunnels from the file-based registry
        for entry in list_registered_tunnels():
            if entry.get('tube_id') in in_process_tube_ids:
                continue
            pid = entry.get('pid')
            rec = entry.get('record_title') or entry.get('record_uid', '?')
            th = entry.get('target_host')
            tp = entry.get('target_port')
            remote = f"{th}:{tp}" if th and tp else f"{bcolors.WARNING}n/a{bcolors.ENDC}"
            h = entry.get('host', '127.0.0.1')
            p = entry.get('port', '?')
            local = f"{bcolors.OKGREEN}{h}:{p}{bcolors.ENDC}"
            tid = entry.get('tube_id', '')
            mode = entry.get('mode', '?')
            status = f"{bcolors.OKGREEN}{mode} (PID {pid}){bcolors.ENDC}"
            table.append([rec, remote, local, tid, '', status])

        if not table:
            logging.warning(f"{bcolors.OKBLUE}No Tunnels running{bcolors.ENDC}")
            return

        dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


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

        # Fall back to file-based registry (cross-process tunnels)
        if not matching_tubes:
            for entry in list_registered_tunnels():
                if uid in (entry.get('tube_id', ''), entry.get('record_uid', ''),
                           entry.get('record_title', '')):
                    pid = entry.get('pid')
                    if pid and is_pid_alive(pid):
                        if stop_tunnel_process(pid):
                            print(f"{bcolors.OKGREEN}Sent stop signal to tunnel process "
                                  f"(PID {pid}, {entry.get('mode', '?')} mode){bcolors.ENDC}")
                        else:
                            print(f"{bcolors.FAIL}Failed to signal PID {pid}{bcolors.ENDC}")
                    else:
                        unregister_tunnel(pid)
                    return

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
        """Stop all active tunnels (in-process and cross-process)."""
        stopped_count = 0
        failed_count = 0

        # In-process tunnels
        tube_registry = get_or_create_tube_registry(params)
        if tube_registry:
            all_tube_ids = tube_registry.all_tube_ids()
            if all_tube_ids:
                print(f"{bcolors.WARNING}Stopping {len(all_tube_ids)} in-process tunnel(s):{bcolors.ENDC}")
                for tube_id in all_tube_ids:
                    try:
                        tube_registry.close_tube(tube_id, reason=CloseConnectionReasons.Normal)
                        print(f"  {bcolors.OKGREEN}Stopped: {tube_id}{bcolors.ENDC}")
                        stopped_count += 1
                    except Exception as e:
                        print(f"  {bcolors.FAIL}Failed: {tube_id}: {e}{bcolors.ENDC}")
                        failed_count += 1

        # Cross-process tunnels from file registry
        registered = list_registered_tunnels()
        if registered:
            print(f"{bcolors.WARNING}Stopping {len(registered)} external tunnel(s):{bcolors.ENDC}")
            for entry in registered:
                pid = entry.get('pid')
                if stop_tunnel_process(pid):
                    print(f"  {bcolors.OKGREEN}Sent stop signal to PID {pid} "
                          f"({entry.get('mode', '?')} mode, {entry.get('host')}:{entry.get('port')}){bcolors.ENDC}")
                    stopped_count += 1
                else:
                    print(f"  {bcolors.FAIL}Failed to signal PID {pid}{bcolors.ENDC}")
                    failed_count += 1
                    unregister_tunnel(pid)

        if stopped_count == 0 and failed_count == 0:
            print(f"{bcolors.WARNING}No active tunnels to stop.{bcolors.ENDC}")
            return

        if stopped_count > 0:
            print(f"\n{bcolors.OKGREEN}Successfully stopped {stopped_count} tunnel(s).{bcolors.ENDC}")
        if failed_count > 0:
            print(f"{bcolors.FAIL}Failed to stop {failed_count} tunnel(s).{bcolors.ENDC}")


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
    pam_cmd_parser.add_argument('--keeper-db-proxy', '-kdbp', required=False, dest='keeper_db_proxy',
                                choices=['on', 'off', 'default'],
                                help='Enable/disable Keeper Database Proxy for pamDatabase records (on/off/default)')

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
            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, record_uid, is_config=True,
                                transmission_key=transmission_key)
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

            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, config_uid,
                                transmission_key=transmission_key)
            old_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, existing_config_uid,
                                transmission_key=transmission_key)

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
            # Persist the record changes (new pamSettings field or port modifications)
            if dirty:
                record_management.update_record(params, record)
                api.sync_down(params)
                dirty = False
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

            # Handle --keeper-db-proxy option for database proxy routing (pamDatabase records only)
            keeper_db_proxy = kwargs.get('keeper_db_proxy')
            if keeper_db_proxy:
                if record_type != 'pamDatabase':
                    raise CommandError('pam tunnel edit',
                        f'{bcolors.FAIL}--keeper-db-proxy is only supported for pamDatabase records. '
                        f'Record "{record_name}" is of type "{record_type}".{bcolors.ENDC}')
                if keeper_db_proxy == 'on' and not tmp_dag.check_if_resource_has_launch_credential(record_uid):
                    raise CommandError('',
                        f'{bcolors.FAIL}No Launch Credentials assigned to record "{record_uid}". '
                        f'Please assign launch credentials to the record before enabling '
                        f'the database proxy.\n'
                        f'Use: {bcolors.OKBLUE}pam connection edit <record> '
                        f'--launch-user (-lu) <pamUser_record>{bcolors.ENDC}')
                if not pam_settings:
                    pam_settings = vault.TypedField.new_field('pamSettings', {"connection": {}, "portForward": {}}, "")
                    record.custom.append(pam_settings)
                if not pam_settings.value:
                    pam_settings.value.append({"connection": {}, "portForward": {}})
                if "connection" not in pam_settings.value[0]:
                    pam_settings.value[0]["connection"] = {}
                current_value = pam_settings.value[0]["connection"].get('allowKeeperDBProxy')
                if keeper_db_proxy == 'on' and current_value is not True:
                    pam_settings.value[0]["connection"]["allowKeeperDBProxy"] = True
                    dirty = True
                elif keeper_db_proxy == 'off' and current_value is not False:
                    pam_settings.value[0]["connection"]["allowKeeperDBProxy"] = False
                    dirty = True
                elif keeper_db_proxy == 'default' and current_value is not None:
                    pam_settings.value[0]["connection"].pop('allowKeeperDBProxy', None)
                    dirty = True

            if dirty:
                tmp_dag.set_resource_allowed(resource_uid=record_uid, tunneling=_tunneling, allowed_settings_name=allowed_settings_name)
                record_management.update_record(params, record)
                api.sync_down(params)

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
    pam_cmd_parser.add_argument('--foreground', '-fg', required=False, dest='foreground', action='store_true',
                                help='Keep the tunnel running in the foreground, blocking until '
                                     'SIGTERM/SIGINT/Ctrl+C is received. Use this flag when running '
                                     'tunnels from scripts, systemd services, or any non-interactive '
                                     'context where the process would otherwise exit immediately.')
    pam_cmd_parser.add_argument('--pid-file', required=False, dest='pid_file', action='store',
                                help='Write the process PID to a file when using --foreground. '
                                     'Enables stopping the tunnel from another terminal via '
                                     'kill -SIGTERM $(cat <pid-file>). The file is removed on shutdown.')
    pam_cmd_parser.add_argument('--run', '-R', required=False, dest='run_command', action='store',
                                help='Shell command to execute while tunnel is active. '
                                     'The command runs via the system shell (supports pipes, redirects, env vars). '
                                     'The tunnel is stopped and Commander exits with the command\'s exit code. '
                                     "Example: --run 'pg_dump -h localhost -p 5432 mydb > backup.sql'")
    pam_cmd_parser.add_argument('--timeout', required=False, dest='connect_timeout', action='store',
                                type=int, default=30,
                                help='Seconds to wait for the tunnel to connect before giving up '
                                     '(used with --foreground, --background, and --run). Default: 30')
    pam_cmd_parser.add_argument('--background', '-bg', required=False, dest='background', action='store_true',
                                help='Start the tunnel in a background process, wait for '
                                     'connection readiness, then return control to the caller. '
                                     'The tunnel continues running independently. Use --pid-file '
                                     'to write the daemon PID for later shutdown. Use '
                                     "'pam tunnel list' / 'pam tunnel stop' from any session.")

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

        # Workflow access check and 2FA prompt
        two_factor_value = None
        try:
            from .workflow import check_workflow_and_prompt_2fa
            should_proceed, two_factor_value = check_workflow_and_prompt_2fa(params, record_uid)
            if not should_proceed:
                return
        except ImportError:
            pass

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

            # If not provided via command line, prompt interactively (or error in batch mode)
            if not target_host:
                if params.batch_mode:
                    raise CommandError('tunnel start',
                                       'Target host is required in non-interactive mode. '
                                       'Use --target-host <HOST> --target-port <PORT>')
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
                if params.batch_mode:
                    raise CommandError('tunnel start',
                                       'Target port is required in non-interactive mode. '
                                       'Use --target-host <HOST> --target-port <PORT>')
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
            target_port = pam_settings_value.get("portForward", {}).get("port", target.get_default_value().get('port', None))
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

        # Validate mutual exclusivity of mode flags
        background = kwargs.get('background', False)
        foreground = kwargs.get('foreground', False)
        run_command = kwargs.get('run_command')
        mode_flags = sum(bool(f) for f in [background, foreground, run_command])
        if mode_flags > 1:
            raise CommandError('tunnel start',
                               '--foreground, --background, and --run are mutually exclusive. '
                               'Use only one at a time.')

        # --background: launch a separate Commander process with --foreground,
        # then poll the file-based tunnel registry for readiness.
        if background:
            if not params.batch_mode:
                print(f"\n{bcolors.OKBLUE}Note: --background is not needed inside the interactive shell.{bcolors.ENDC}")
                print(f"{bcolors.OKBLUE}The tunnel is already running and will persist until you exit the shell.{bcolors.ENDC}")
                print(f"{bcolors.OKBLUE}Use 'pam tunnel list' to see active tunnels, 'pam tunnel stop' to stop them.{bcolors.ENDC}\n")
                return

            connect_timeout = kwargs.get('connect_timeout', 30)
            pid_file = kwargs.get('pid_file')

            bg_cmd = [sys.executable, '-m', 'keepercommander']
            if params.config_filename:
                bg_cmd.extend(['--config', os.path.abspath(params.config_filename)])
            if hasattr(params, 'server') and params.server:
                bg_cmd.extend(['--server', params.server])

            tunnel_parts = ['pam', 'tunnel', 'start', record_uid,
                            '--port', str(port), '--foreground',
                            '--timeout', str(connect_timeout)]
            if host and host != '127.0.0.1':
                tunnel_parts.extend(['--host', host])
            if target_host:
                tunnel_parts.extend(['--target-host', str(target_host)])
            if target_port:
                tunnel_parts.extend(['--target-port', str(target_port)])
            if pid_file:
                tunnel_parts.extend(['--pid-file', pid_file])
            if no_trickle_ice:
                tunnel_parts.append('--no-trickle-ice')
            bg_cmd.append(' '.join(tunnel_parts))

            print(f"{bcolors.OKBLUE}Starting tunnel in background...{bcolors.ENDC}")
            try:
                bg_proc = subprocess.Popen(
                    bg_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except Exception as e:
                raise CommandError('tunnel start', f'Failed to launch background process: {e}')

            # Parent waits longer than child to account for process startup time.
            # The child's --timeout controls the actual WebRTC connection timeout.
            bg_deadline = time.time() + connect_timeout + PARENT_GRACE_SECONDS
            bg_info = None
            while time.time() < bg_deadline:
                for entry in list_registered_tunnels(clean_stale=False):
                    if entry.get('pid') == bg_proc.pid and entry.get('record_uid') == record_uid:
                        bg_info = entry
                        break
                if bg_info:
                    break
                poll_code = bg_proc.poll()
                if poll_code is not None:
                    stderr_output = ''
                    try:
                        stderr_output = bg_proc.stderr.read().decode('utf-8', errors='replace').strip()
                    except Exception:
                        pass
                    print(f"{bcolors.FAIL}Background tunnel process exited before tunnel was ready "
                          f"(code {poll_code}){bcolors.ENDC}")
                    if stderr_output:
                        print(f"{bcolors.FAIL}{stderr_output}{bcolors.ENDC}")
                    elif poll_code == 0:
                        print(f"{bcolors.FAIL}Process exited before registry registration. "
                              f"Check WebRTC connectivity and gateway logs.{bcolors.ENDC}")
                    return
                time.sleep(0.5)

            if not bg_info:
                print(f"{bcolors.FAIL}Tunnel did not become ready within the timeout{bcolors.ENDC}")
                try:
                    bg_proc.terminate()
                except Exception:
                    pass
                return

            print(f"\n{bcolors.OKGREEN}Tunnel running in background{bcolors.ENDC}")
            print(f"  Record:     {bg_info.get('record_title') or record_uid}")
            if bg_info.get('tube_id'):
                print(f"  Tube ID:    {bg_info['tube_id']}")
            print(f"  Listening:  {host}:{port}")
            print(f"  Daemon PID: {bg_proc.pid}")
            if pid_file:
                print(f"  PID file:   {pid_file}")
            print(f"\n{bcolors.OKGREEN}To stop: pam tunnel stop {record_uid}  or  "
                  f"kill -SIGTERM {bg_proc.pid}{bcolors.ENDC}")
            if pid_file:
                print(f"    or:   kill -SIGTERM $(cat {pid_file})")
            print(f"{bcolors.OKBLUE}Use 'pam tunnel list' from any Commander session "
                  f"to see this tunnel.{bcolors.ENDC}")
            if platform.system() == 'Windows':
                print(f"{bcolors.WARNING}Note: On Windows, tunnel stop uses hard termination. "
                      f"WebRTC cleanup is best-effort.{bcolors.ENDC}")
            return

        result = start_rust_tunnel(params, record_uid, gateway_uid, host, port, seed, target_host, target_port, socks, trickle_ice, record.title, allow_supply_host=allow_supply_host, two_factor_value=two_factor_value)

        if result and result.get("success"):
            connect_timeout = kwargs.get('connect_timeout', 30)

            if run_command:
                run_tube_id = result.get("tube_id")
                run_tube_registry = result.get("tube_registry")

                print(f"{bcolors.OKBLUE}Waiting for tunnel to connect (timeout: {connect_timeout}s)...{bcolors.ENDC}")
                conn_status = wait_for_tunnel_connection(result, timeout=connect_timeout, show_progress=False)

                if not conn_status.get("connected"):
                    err = conn_status.get("error", "Connection failed")
                    print(f"{bcolors.FAIL}Tunnel did not connect: {err}{bcolors.ENDC}")
                    if run_tube_registry and run_tube_id:
                        try:
                            run_tube_registry.close_tube(run_tube_id, reason=CloseConnectionReasons.Normal)
                            unregister_tunnel_session(run_tube_id)
                        except Exception:
                            pass
                    return

                try:
                    register_tunnel(os.getpid(), record_uid, run_tube_id, host, port,
                                    target_host, target_port, mode='run',
                                    record_title=record.title if record else None)
                except CommandError as reg_err:
                    print(f"{bcolors.FAIL}{reg_err}{bcolors.ENDC}")
                    if run_tube_registry and run_tube_id:
                        try:
                            run_tube_registry.close_tube(run_tube_id, reason=CloseConnectionReasons.Normal)
                            unregister_tunnel_session(run_tube_id)
                        except Exception:
                            pass
                    return

                print(f"{bcolors.OKGREEN}Tunnel ready{bcolors.ENDC}  {host}:{port} -> {target_host}:{target_port}")
                if platform.system() == 'Windows':
                    print(f"{bcolors.WARNING}Note: On Windows, tunnel stop uses hard termination. "
                          f"WebRTC cleanup is best-effort.{bcolors.ENDC}")
                print(f"{bcolors.OKBLUE}Running:{bcolors.ENDC} {run_command}\n")

                cmd_exit = 1
                try:
                    # shell=True is intentional: --run commands need shell features (pipes, redirects, env vars).
                    # The user is already authenticated to Keeper and controls the command string.
                    proc = subprocess.run(run_command, shell=True)
                    cmd_exit = proc.returncode if proc.returncode is not None else 1
                except KeyboardInterrupt:
                    cmd_exit = 130
                except Exception as run_err:
                    logging.warning("Error running command: %s", run_err)
                    cmd_exit = 1
                finally:
                    unregister_tunnel()
                    print(f"\n{bcolors.OKBLUE}Stopping tunnel {run_tube_id or record_uid}...{bcolors.ENDC}")
                    try:
                        if run_tube_registry and run_tube_id:
                            run_tube_registry.close_tube(run_tube_id, reason=CloseConnectionReasons.Normal)
                            unregister_tunnel_session(run_tube_id)
                        print(f"{bcolors.OKGREEN}Tunnel stopped.{bcolors.ENDC}")
                    except Exception as stop_err:
                        logging.warning("Error stopping tunnel: %s", stop_err)

                raise SystemExit(cmd_exit)

            elif foreground:
                if not params.batch_mode:
                    print(f"\n{bcolors.OKBLUE}Note: --foreground is not needed inside the interactive shell.{bcolors.ENDC}")
                    print(f"{bcolors.OKBLUE}The tunnel is already running and will persist until you exit the shell.{bcolors.ENDC}")
                    print(f"{bcolors.OKBLUE}Use 'pam tunnel list' to see active tunnels, 'pam tunnel stop' to stop them.{bcolors.ENDC}\n")
                else:
                    fg_tube_id = result.get("tube_id")
                    fg_tube_registry = result.get("tube_registry")
                    fg_shutdown = threading.Event()
                    pid_file = kwargs.get('pid_file')

                    def _fg_signal_handler(signum, _frame):
                        sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
                        print(f"\n{bcolors.WARNING}Received {sig_name}, stopping tunnel...{bcolors.ENDC}")
                        fg_shutdown.set()

                    prev_sigterm = signal.signal(signal.SIGTERM, _fg_signal_handler)
                    prev_sigint = signal.signal(signal.SIGINT, _fg_signal_handler)
                    prev_sighup = None
                    if hasattr(signal, 'SIGHUP'):
                        prev_sighup = signal.signal(signal.SIGHUP, _fg_signal_handler)

                    print(f"{bcolors.OKBLUE}Waiting for tunnel to connect (timeout: {connect_timeout}s)...{bcolors.ENDC}")
                    conn_status = wait_for_tunnel_connection(result, timeout=connect_timeout, show_progress=False)

                    if not conn_status.get("connected"):
                        signal.signal(signal.SIGTERM, prev_sigterm)
                        signal.signal(signal.SIGINT, prev_sigint)
                        if prev_sighup is not None:
                            signal.signal(signal.SIGHUP, prev_sighup)
                        err = conn_status.get("error", "Connection failed")
                        print(f"{bcolors.FAIL}Tunnel did not connect: {err}{bcolors.ENDC}")
                        if fg_tube_registry and fg_tube_id:
                            try:
                                fg_tube_registry.close_tube(fg_tube_id, reason=CloseConnectionReasons.Normal)
                                unregister_tunnel_session(fg_tube_id)
                            except Exception:
                                pass
                        return

                    if pid_file:
                        try:
                            with open(pid_file, 'w') as pf:
                                pf.write(str(os.getpid()))
                        except Exception as e:
                            logging.warning("Could not write PID file '%s': %s", pid_file, e)
                            pid_file = None

                    try:
                        register_tunnel(os.getpid(), record_uid, fg_tube_id, host, port,
                                        target_host, target_port, mode='foreground',
                                        record_title=record.title if record else None)
                    except CommandError as reg_err:
                        print(f"{bcolors.FAIL}{reg_err}{bcolors.ENDC}")
                        signal.signal(signal.SIGTERM, prev_sigterm)
                        signal.signal(signal.SIGINT, prev_sigint)
                        if prev_sighup is not None:
                            signal.signal(signal.SIGHUP, prev_sighup)
                        if fg_tube_registry and fg_tube_id:
                            try:
                                fg_tube_registry.close_tube(fg_tube_id, reason=CloseConnectionReasons.Normal)
                                unregister_tunnel_session(fg_tube_id)
                            except Exception:
                                pass
                        return

                    print(f"\n{bcolors.OKGREEN}Tunnel running in foreground mode{bcolors.ENDC}")
                    print(f"  Record:     {record_uid}")
                    if fg_tube_id:
                        print(f"  Tube ID:    {fg_tube_id}")
                    print(f"  Listening:  {host}:{port}")
                    print(f"  PID:        {os.getpid()}")
                    if pid_file:
                        print(f"  PID file:   {pid_file}")
                    print(f"\n{bcolors.OKGREEN}To stop: kill -SIGTERM {os.getpid()}  (or Ctrl+C)  or  pam tunnel stop {record_uid}{bcolors.ENDC}\n")
                    if platform.system() == 'Windows':
                        print(f"{bcolors.WARNING}Note: On Windows, tunnel stop uses hard termination. "
                              f"WebRTC cleanup is best-effort.{bcolors.ENDC}\n")

                    try:
                        fg_shutdown.wait()
                    except KeyboardInterrupt:
                        pass
                    finally:
                        unregister_tunnel()
                        signal.signal(signal.SIGTERM, prev_sigterm)
                        signal.signal(signal.SIGINT, prev_sigint)
                        if prev_sighup is not None:
                            signal.signal(signal.SIGHUP, prev_sighup)
                        print(f"\n{bcolors.OKBLUE}Stopping tunnel {fg_tube_id or record_uid}...{bcolors.ENDC}")
                        try:
                            if fg_tube_registry and fg_tube_id:
                                fg_tube_registry.close_tube(fg_tube_id, reason=CloseConnectionReasons.Normal)
                                unregister_tunnel_session(fg_tube_id)
                            else:
                                stop_cmd = PAMTunnelStopCommand()
                                stop_cmd.execute(params, uid=record_uid)
                            print(f"{bcolors.OKGREEN}Tunnel stopped.{bcolors.ENDC}")
                        except Exception as fg_err:
                            logging.warning("Error stopping tunnel during foreground shutdown: %s", fg_err)
                        finally:
                            if pid_file:
                                try:
                                    os.remove(pid_file)
                                except OSError:
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
    # ── parser ────────────────────────────────────────────────────────────────
    pam_cmd_parser = argparse.ArgumentParser(
        prog='pam tunnel diagnose',
        description='Diagnose network connectivity for KeeperPAM. '
                    'When run without a record the command tests connectivity using only the '
                    'logged-in session (krelay server, HTTPS API, WebSocket, UDP port range). '
                    'When a record is supplied the full WebRTC peer connection test is also run.')
    pam_cmd_parser.add_argument('record', type=str, nargs='?', default=None,
                                help='Optional: Record UID of a PAM resource for the full WebRTC peer connection test')
    pam_cmd_parser.add_argument('--timeout', '-t', required=False, dest='timeout', action='store',
                                type=int, default=30,
                                help='Test timeout in seconds (default: 30)')
    pam_cmd_parser.add_argument('--verbose', '-v', required=False, dest='verbose', action='store_true',
                                help='Show detailed diagnostic output including ICE server lists')
    pam_cmd_parser.add_argument('--format', '-f', required=False, dest='format', action='store',
                                choices=['table', 'json'], default='table',
                                help='Output format: table (human-readable) or json (machine-readable)')
    pam_cmd_parser.add_argument('--test', required=False, dest='test_filter', action='store',
                                help='Comma-separated list of specific WebRTC tests to run. Available: '
                                     'dns_resolution,aws_connectivity,tcp_connectivity,udp_binding,'
                                     'ice_configuration,webrtc_peer_connection')

    def get_parser(self):
        return PAMTunnelDiagnoseCommand.pam_cmd_parser

    # ── ANSI helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _use_color() -> bool:
        return sys.stdout.isatty() and os.environ.get('NO_COLOR') is None

    @staticmethod
    def _c(code: str, text: str) -> str:
        return f'\033[{code}m{text}\033[0m' if PAMTunnelDiagnoseCommand._use_color() else text

    @classmethod
    def _green(cls, t: str) -> str:  return cls._c('92', t)
    @classmethod
    def _bright(cls, t: str) -> str: return cls._c('1;92', t)
    @classmethod
    def _dim(cls, t: str) -> str:    return cls._c('2;32', t)
    @classmethod
    def _red(cls, t: str) -> str:    return cls._c('1;91', t)
    @classmethod
    def _check(cls) -> str:          return cls._bright('\u2713')
    @classmethod
    def _cross(cls) -> str:          return cls._red('\u2717')
    @classmethod
    def _bullet(cls) -> str:         return cls._bright('\u25ba')
    @classmethod
    def _sep(cls, w: int = 76) -> str:   return cls._dim('\u2500' * w)
    @classmethod
    def _dsep(cls, w: int = 78) -> str:  return cls._dim('\u2550' * w)

    # ── output helpers ────────────────────────────────────────────────────────
    _W = 80  # output width

    @classmethod
    def _print_header(cls):
        title = 'KeeperPAM  \u00b7  Gateway Network Readiness Tester'
        inner = cls._W - 2
        pad_l = (inner - len(title)) // 2
        pad_r = inner - len(title) - pad_l
        print(cls._bright('\u2554' + '\u2550' * inner + '\u2557'))
        print(cls._bright('\u2551' + ' ' * pad_l + title + ' ' * pad_r + '\u2551'))
        print(cls._bright('\u255a' + '\u2550' * inner + '\u255d'))

    @classmethod
    def _print_result(cls, name: str, passed: bool, detail: str, ms: int, indent: int = 4):
        icon = cls._check() if passed else cls._cross()
        ms_str = cls._dim(f'  {ms}ms')
        body = f'{cls._green(name)}  \u00b7  {cls._green(detail)}' if detail else cls._green(name)
        print(f'{" " * indent}{icon}  {body}{ms_str}')

    # ── STUN ──────────────────────────────────────────────────────────────────
    _MAGIC_COOKIE = 0x2112A442
    _STUN_PORT = 3478
    _UDP_SAMPLE_PORTS = [49152, 50000, 52000, 55000, 58000, 61000, 63000, 65535]

    @classmethod
    def _stun_request(cls, msg_type: int = 0x0001) -> bytes:
        return struct.pack('!HHI12s', msg_type, 0, cls._MAGIC_COOKIE, os.urandom(12))

    @classmethod
    def _recv_stun(cls, sock: socket.socket, timeout: float = 5.0) -> bytes:
        buf = b''
        deadline = time.monotonic() + timeout
        try:
            if sock.type == socket.SOCK_DGRAM:
                sock.settimeout(max(0.1, deadline - time.monotonic()))
                buf, _ = sock.recvfrom(2048)
            else:
                while len(buf) < 20:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    buf += chunk
        except (socket.timeout, OSError):
            pass
        return buf

    @classmethod
    def _parse_stun(cls, data: bytes) -> dict:
        out: dict = {}
        if len(data) < 20:
            return out
        msg_type, _msg_len, magic = struct.unpack('!HHI', data[:8])
        if magic != cls._MAGIC_COOKIE:
            return out
        msg_class = ((msg_type >> 7) & 0x2) | ((msg_type >> 4) & 0x1)
        out['is_success'] = msg_class == 2
        out['is_error'] = msg_class == 3
        offset = 20
        while offset + 4 <= len(data):
            attr_type, attr_len = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            attr = data[offset:offset + attr_len]
            if attr_type == 0x0020 and len(attr) >= 8 and attr[1] == 0x01:
                xip = struct.unpack('!I', attr[4:8])[0] ^ cls._MAGIC_COOKIE
                out['ext_ip'] = socket.inet_ntoa(struct.pack('!I', xip))
            elif attr_type == 0x0001 and len(attr) >= 8 and attr[1] == 0x01:
                out.setdefault('ext_ip', socket.inet_ntoa(attr[4:8]))
            elif attr_type == 0x0009 and len(attr) >= 4:
                out['error_code'] = (attr[2] & 0x07) * 100 + attr[3]
            offset += (attr_len + 3) & ~3
        return out

    # ── individual Python-side tests ──────────────────────────────────────────
    @classmethod
    def _test_https(cls, hostname: str, port: int = 443) -> Tuple[bool, str, int]:
        """Returns (passed, detail, ms)."""
        t0 = time.monotonic()
        conn = None
        try:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(hostname, port=port, context=ctx, timeout=10)
            conn.request('GET', '/', headers={'User-Agent': 'keeper-pam-diagnose/1.0'})
            resp = conn.getresponse()
            ms = int((time.monotonic() - t0) * 1000)
            return 100 <= resp.status < 600, f'HTTP {resp.status}  (reachable)', ms
        except Exception as exc:
            return False, str(exc)[:60], int((time.monotonic() - t0) * 1000)
        finally:
            if conn:
                try: conn.close()
                except Exception: pass

    @classmethod
    def _test_websocket(cls, hostname: str, port: int = 443) -> Tuple[bool, str, int]:
        """HTTP Upgrade probe — any 4xx means the server is reachable."""
        t0 = time.monotonic()
        conn = None
        try:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(hostname, port=port, context=ctx, timeout=10)
            conn.request('GET', '/', headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
                'User-Agent': 'keeper-pam-diagnose/1.0',
            })
            resp = conn.getresponse()
            ms = int((time.monotonic() - t0) * 1000)
            return 100 <= resp.status < 600, f'HTTP {resp.status}', ms
        except Exception as exc:
            return False, str(exc)[:60], int((time.monotonic() - t0) * 1000)
        finally:
            if conn:
                try: conn.close()
                except Exception: pass

    @classmethod
    def _test_tcp_stun(cls, hostname: str) -> Tuple[bool, str, int, Optional[str]]:
        """Returns (passed, detail, ms, ext_ip)."""
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((hostname, cls._STUN_PORT))
            sock.sendall(cls._stun_request(0x0001))
            parsed = cls._parse_stun(cls._recv_stun(sock))
            ms = int((time.monotonic() - t0) * 1000)
            ext_ip = parsed.get('ext_ip')
            detail = f'external IP  {ext_ip}' if ext_ip else 'TCP connected'
            return True, detail, ms, ext_ip
        except Exception as exc:
            return False, str(exc)[:60], int((time.monotonic() - t0) * 1000), None
        finally:
            if sock:
                try: sock.close()
                except Exception: pass

    @classmethod
    def _test_udp_stun(cls, hostname: str) -> Tuple[bool, str, int, Optional[str]]:
        """Returns (passed, detail, ms, ext_ip)."""
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(cls._stun_request(0x0001), (hostname, cls._STUN_PORT))
            parsed = cls._parse_stun(cls._recv_stun(sock))
            ms = int((time.monotonic() - t0) * 1000)
            ext_ip = parsed.get('ext_ip')
            if ext_ip:
                return True, f'external IP  {ext_ip}', ms, ext_ip
            return False, 'no STUN response', ms, None
        except Exception as exc:
            return False, str(exc)[:60], int((time.monotonic() - t0) * 1000), None
        finally:
            if sock:
                try: sock.close()
                except Exception: pass

    @classmethod
    def _test_turn(cls, hostname: str) -> Tuple[bool, str, int]:
        """Send unauthenticated TURN Allocate; expect 401 = reachable."""
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((hostname, cls._STUN_PORT))
            sock.sendall(cls._stun_request(0x0003))  # Allocate
            parsed = cls._parse_stun(cls._recv_stun(sock))
            ms = int((time.monotonic() - t0) * 1000)
            if parsed.get('is_error') and parsed.get('error_code') == 401:
                detail = 'reachable  \u00b7  auth required'
            elif parsed.get('is_success') or parsed.get('is_error'):
                detail = 'reachable'
            else:
                detail = 'TCP connected'
            return True, detail, ms
        except Exception as exc:
            return False, str(exc)[:60], int((time.monotonic() - t0) * 1000)
        finally:
            if sock:
                try: sock.close()
                except Exception: pass

    @classmethod
    def _test_udp_port(cls, ip: str, port: int, timeout: float = 1.5) -> Tuple[bool, int]:
        """Returns (reachable, ms). Timeout = no ICMP unreachable = assumed open."""
        import errno as _errno
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(cls._stun_request(0x0001), (ip, port))
            try:
                sock.recvfrom(512)
            except socket.timeout:
                pass  # no response = assume open
            except OSError as oserr:
                ms = int((time.monotonic() - t0) * 1000)
                if oserr.errno in (_errno.ECONNREFUSED, _errno.ENETUNREACH, _errno.EHOSTUNREACH):
                    return False, ms
            return True, int((time.monotonic() - t0) * 1000)
        except Exception:
            return False, int((time.monotonic() - t0) * 1000)
        finally:
            if sock:
                try: sock.close()
                except Exception: pass

    # ── execute ───────────────────────────────────────────────────────────────
    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        timeout = kwargs.get('timeout', 30)
        verbose = kwargs.get('verbose', False)
        output_format = kwargs.get('format', 'table')
        test_filter = kwargs.get('test_filter')

        server = params.server  # e.g. "keepersecurity.com" or "https://qa.keepersecurity.com"
        server_host = get_keeper_server_hostname(server)
        krelay_server = os.environ.get('KRELAY_URL') or f'krelay.{server_host}'
        connect_host = f'connect.{server_host}'

        # ── header ────────────────────────────────────────────────────────────
        self._print_header()
        print()
        now = datetime.datetime.utcnow()
        region_label = 'US' if server_host == 'keepersecurity.com' else server_host.split('.')[0].upper()
        print(self._green(f'  Region  {region_label}  \u00b7  {server}'))
        print(self._green(f'  Date    {now.strftime("%Y-%m-%d  %H:%M")} UTC'))
        if record_name:
            print(self._green(f'  Record  {record_name}'))
        print()

        t_overall_start = time.monotonic()
        all_passed: List[bool] = []
        blocked_names: List[str] = []
        public_ip: Optional[str] = None

        def _record(name: str, passed: bool, detail: str, ms: int):
            all_passed.append(passed)
            if not passed:
                blocked_names.append(name)
            self._print_result(name, passed, detail, ms)

        # ── section 1: DNS & cloud connectivity ───────────────────────────────
        print(f'{self._bullet()}  {self._bright("DNS & Cloud Connectivity")}')
        print(f'  {self._sep()}')

        # DNS
        t0 = time.monotonic()
        try:
            infos = socket.getaddrinfo(server_host, None, socket.AF_INET)
            ips = list(dict.fromkeys(a[4][0] for a in infos))
            ms = int((time.monotonic() - t0) * 1000)
            extra = f'(+{len(ips) - 1} addr)' if len(ips) > 1 else ''
            _record(f'DNS  {server_host}', True, f'\u2192  {ips[0]}  {extra}'.strip(), ms)
        except Exception as exc:
            _record(f'DNS  {server_host}', False, str(exc)[:60], int((time.monotonic() - t0) * 1000))

        passed, detail, ms = self._test_https(server_host)
        _record(f'HTTPS  {server_host}:443', passed, detail, ms)

        passed, detail, ms = self._test_websocket(connect_host)
        _record(f'WebSocket  {connect_host}:443', passed, detail, ms)

        print()

        # ── section 2: STUN / TURN ────────────────────────────────────────────
        print(f'{self._bullet()}  {self._bright("STUN / TURN")}  \u00b7  {self._green(krelay_server)}')
        print(f'  {self._sep()}')

        passed, detail, ms, ext_ip = self._test_tcp_stun(krelay_server)
        _record(f'TCP STUN  {krelay_server}:{self._STUN_PORT}', passed, detail, ms)
        if ext_ip:
            public_ip = ext_ip

        passed, detail, ms, ext_ip = self._test_udp_stun(krelay_server)
        _record(f'UDP STUN  {krelay_server}:{self._STUN_PORT}', passed, detail, ms)
        if ext_ip and not public_ip:
            public_ip = ext_ip

        passed, detail, ms = self._test_turn(krelay_server)
        _record(f'TURN relay  {krelay_server}:{self._STUN_PORT}', passed, detail, ms)

        print()

        # ── section 3: WebRTC media ports ─────────────────────────────────────
        try:
            krelay_ip = socket.gethostbyname(krelay_server)
        except Exception:
            krelay_ip = krelay_server

        udp_range_label = "UDP 49152\u201365535"
        print(f'{self._bullet()}  {self._bright("WebRTC Media Ports")}  \u00b7  {self._green(udp_range_label)}')
        print(f'  {self._sep()}')

        udp_timeout = min(float(timeout), 1.5)
        port_results: List[Tuple[int, bool, int]] = []
        for port in self._UDP_SAMPLE_PORTS:
            ok, ms = self._test_udp_port(krelay_ip, port, timeout=udp_timeout)
            port_results.append((port, ok, ms))
            all_passed.append(ok)
            if not ok:
                blocked_names.append(f'UDP:{port}')

        row = '    '
        for port, ok, _ in port_results:
            row += f'{self._check() if ok else self._cross()} {self._green(str(port))}   '
        print(row.rstrip())

        passed_ports = sum(1 for _, ok, _ in port_results if ok)
        print(f'    {self._check()}  {self._green(str(passed_ports))}/{len(port_results)} sampled ports reachable')
        print()

        # ── section 4: WebRTC connectivity (Rust library) ─────────────────────
        tube_registry = get_or_create_tube_registry(params)
        rust_results = None

        if tube_registry:
            print(f'{self._bullet()}  {self._bright("WebRTC Connectivity")}  \u00b7  {self._green("STUN/TURN/ICE/Peer")}')
            print(f'  {self._sep()}')

            # Resolve optional record for pam_config_uid
            if record_name:
                try:
                    api.sync_down(params)
                    record = RecordMixin.resolve_single_record(params, record_name)
                    if record and isinstance(record, vault.TypedRecord):
                        encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
                        pam_config_uid = get_config_uid(params, encrypted_session_token,
                                                        encrypted_transmission_key, record.record_uid)
                        if not pam_config_uid:
                            print(f'    {self._cross()}  {self._red(f"No PAM config found for record {record_name}")}')
                except Exception as exc:
                    logging.debug(f'Record lookup failed: {exc}', exc_info=True)

            # Get TURN credentials
            turn_username = turn_password = None
            try:
                from .pam.router_helper import router_get_relay_access_creds
                creds = router_get_relay_access_creds(params, expire_sec=60000000)
                turn_username = creds.username
                turn_password = creds.password
            except Exception as exc:
                logging.debug(f'Could not get TURN credentials: {exc}', exc_info=True)

            settings = {'use_turn': True, 'turn_only': False}
            if test_filter:
                allowed = {'dns_resolution', 'aws_connectivity', 'tcp_connectivity',
                           'udp_binding', 'ice_configuration', 'webrtc_peer_connection'}
                requested = {t.strip() for t in test_filter.split(',')}
                invalid = requested - allowed
                if invalid:
                    print(f"{bcolors.FAIL}Invalid test names: {', '.join(invalid)}{bcolors.ENDC}")
                    return 1
                settings['test_filter'] = list(requested)

            try:
                rust_results = tube_registry.test_webrtc_connectivity(
                    krelay_server=krelay_server,
                    settings=settings,
                    timeout_seconds=timeout,
                    username=turn_username,
                    password=turn_password,
                )
                if output_format == 'json':
                    import json
                    print(json.dumps(rust_results, indent=2))
                    return 0

                # Fold Rust test results into the unified pass/fail accounting
                for test in rust_results.get('test_results', []):
                    name = test.get('test_name', '?')
                    ok = test.get('success', False)
                    ms = int(test.get('duration_ms', 0))
                    msg = test.get('message', '')
                    _record(name.replace('_', ' ').title(), ok, msg, ms)

            except Exception as exc:
                print(f'    {self._cross()}  {self._red(f"WebRTC test failed: {exc}")}')
                all_passed.append(False)
                blocked_names.append('webrtc')
                logging.debug('WebRTC test error', exc_info=True)

            print()
        else:
            logging.debug('keeper_pam_webrtc_rs not available; skipping WebRTC section')

        # ── section 5: PAM configuration graph (record-specific) ────────────
        if record_name:
            print(f'{self._bullet()}  {self._bright("PAM Configuration")}  \u00b7  {self._green(record_name)}')
            print(f'  {self._sep()}')

            try:
                # Ensure vault is synced so the config record is in the local cache
                api.sync_down(params)
                record_obj = RecordMixin.resolve_single_record(params, record_name)
                record_uid = record_obj.record_uid if record_obj else record_name

                _supported_types = ('pamMachine', 'pamDatabase', 'pamDirectory', 'pamRemoteBrowser')
                rec_type_early = record_obj.record_type if record_obj and isinstance(record_obj, vault.TypedRecord) else None
                if rec_type_early and rec_type_early not in _supported_types:
                    print(f'    {self._cross()}  {self._red("Record type")}  {self._green(rec_type_early)}  '
                          f'{self._red("is not a PAM resource — skipping configuration checks")}')
                    print(f'    {self._dim("Supported types: " + ", ".join(_supported_types))}')
                    print()
                    # Skip to Technical Details
                    raise StopIteration

                # 1. Config linked — find the PAM config that owns this record
                enc_session_token, enc_transmission_key, _tx_key = get_keeper_tokens(params)
                config_uid = get_config_uid(params, enc_session_token, enc_transmission_key, record_uid)
                if config_uid:
                    _record('Config linked', True, config_uid, 0)
                else:
                    _record('Config linked', False, 'record not found in any PAM config graph', 0)

                if config_uid:
                    # 2. DAG loaded — fresh tokens required; TunnelDAG's Connection
                    #    needs its own key pair separate from the get_config_uid call,
                    #    and transmission_key must be passed so it can decrypt the response
                    enc_st2, enc_tk2, tx_key2 = get_keeper_tokens(params)
                    tdag = TunnelDAG(params, enc_st2, enc_tk2, config_uid, is_config=True,
                                     transmission_key=tx_key2)
                    dag_ok = tdag.linking_dag.has_graph
                    vertex_count = len(tdag.linking_dag._vertices) if dag_ok else 0
                    _record('DAG loaded', dag_ok,
                            '{} vertices'.format(vertex_count) if dag_ok else 'graph empty — config may be unconfigured',
                            0)

                    if dag_ok:
                        # 3. Resource linked — LINK edge from config → resource present
                        linked = tdag.resource_belongs_to_config(record_uid)
                        _record('Resource linked', linked,
                                'LINK edge present' if linked else 'resource not linked to config', 0)

                        rec_type = record_obj.record_type if record_obj else ''
                        is_rbi = rec_type == 'pamRemoteBrowser'

                        # 4. Config-level settings
                        con_config = tdag.check_tunneling_enabled_config(enable_connections=True)
                        _record('Connections at config', con_config,
                                'connections enabled' if con_config else 'connections disabled at config', 0)

                        if not is_rbi:
                            tun_config = tdag.check_tunneling_enabled_config(enable_tunneling=True)
                            _record('Tunneling at config', tun_config,
                                    'portForwards enabled' if tun_config else 'portForwards disabled at config', 0)

                        # 5. Resource-level settings
                        con_resource = tdag.check_if_resource_allowed(record_uid, 'connections')
                        _record('Connections at resource', con_resource,
                                'connections enabled' if con_resource else 'connections disabled at resource', 0)

                        if not is_rbi:
                            tun_resource = tdag.check_if_resource_allowed(record_uid, 'portForwards')
                            _record('Tunneling at resource', tun_resource,
                                    'portForwards enabled' if tun_resource else 'portForwards disabled at resource', 0)

                        # verbose: dump allowedSettings for config and resource
                        if verbose:
                            from .tunnel.port_forward.TunnelGraph import get_vertex_content
                            _setting_keys = [
                                ('connections',            'Connections'),
                                ('portForwards',           'Port Forwards'),
                                ('rotation',               'Rotation'),
                                ('sessionRecording',       'Session Recording'),
                                ('typescriptRecording',    'Typescript Recording'),
                                ('remoteBrowserIsolation', 'Remote Browser Isolation'),
                            ]
                            config_vertex   = tdag.linking_dag.get_vertex(tdag.record.record_uid)
                            resource_vertex = tdag.linking_dag.get_vertex(record_uid)
                            cfg_content     = get_vertex_content(config_vertex) or {}
                            res_content     = get_vertex_content(resource_vertex) or {}
                            cfg_settings    = cfg_content.get('allowedSettings', {})
                            res_settings    = res_content.get('allowedSettings', {})

                            _yes = self._bright('on ')
                            _no  = self._dim('off')
                            _def = self._dim('---')

                            def _fmt_bool(d, key):
                                v = d.get(key)
                                if v is True:  return _yes
                                if v is False: return _no
                                return _def

                            print()
                            print(f'      {self._dim("DAG allowedSettings"):<28}'
                                  f'{self._dim("Config"):<12}{self._dim("Resource")}')
                            print(f'      {self._dim("-" * 52)}')
                            for key, label in _setting_keys:
                                print(f'      {self._green(label):<28}'
                                      f'{_fmt_bool(cfg_settings, key):<12}'
                                      f'{_fmt_bool(res_settings, key)}')

                            # typed field on the vault record — field name differs by record type
                            def _val(v):
                                if v is None:  return self._dim('---')
                                if v is True:  return self._bright('true')
                                if v is False: return self._dim('false')
                                return self._green(str(v))

                            print()
                            if is_rbi:
                                rbs_field = record_obj.get_typed_field('pamRemoteBrowserSettings') if record_obj else None
                                rbs = {}
                                if rbs_field and rbs_field.value:
                                    rbs = rbs_field.value[0] if isinstance(rbs_field.value[0], dict) else {}
                                cn = rbs.get('connection', {}) or {}
                                print(f'      {self._dim("Record pamRemoteBrowserSettings")}')
                                print(f'      {self._dim("-" * 52)}')
                                print(f'      {self._green("connection.protocol"):<36}{_val(cn.get("protocol"))}')
                                print(f'      {self._green("connection.httpCredentialsUid"):<36}{_val(cn.get("httpCredentialsUid") or None)}')
                                print(f'      {self._green("connection.recordingIncludeKeys"):<36}{_val(cn.get("recordingIncludeKeys"))}')
                            else:
                                pam_settings_field = record_obj.get_typed_field('pamSettings') if record_obj else None
                                ps = {}
                                if pam_settings_field and pam_settings_field.value:
                                    ps = pam_settings_field.value[0] if isinstance(pam_settings_field.value[0], dict) else {}
                                pf = ps.get('portForward', {}) or {}
                                cn = ps.get('connection', {}) or {}
                                print(f'      {self._dim("Record pamSettings")}')
                                print(f'      {self._dim("-" * 52)}')
                                print(f'      {self._green("portForward.port"):<36}{_val(pf.get("port"))}')
                                print(f'      {self._green("connection.port"):<36}{_val(cn.get("port"))}')
                                print(f'      {self._green("connection.protocol"):<36}{_val(cn.get("protocol"))}')
                                print(f'      {self._green("connection.allowKeeperDBProxy"):<36}{_val(cn.get("allowKeeperDBProxy"))}')
                                print(f'      {self._green("connection.recordingIncludeKeys"):<36}{_val(cn.get("recordingIncludeKeys"))}')
                                print(f'      {self._green("allowSupplyHost"):<36}{_val(ps.get("allowSupplyHost"))}')
                                if ps.get('configUid'):
                                    print(f'      {self._green("configUid"):<36}{_val(ps.get("configUid"))}')

                # 6. Gateway registered — a controller UID is associated with this config
                gateway_uid = get_gateway_uid_from_record(params, vault, record_uid)
                if gateway_uid:
                    _record('Gateway registered', True, gateway_uid, 0)
                else:
                    _record('Gateway registered', False, 'no gateway registered for this config', 0)

                # 7. Gateway online — that gateway is currently connected to krouter
                if gateway_uid:
                    try:
                        from .pam.router_helper import router_get_connected_gateways
                        online_controllers = router_get_connected_gateways(params)
                        if online_controllers:
                            gw_bytes = url_safe_str_to_bytes(gateway_uid)
                            connected_uids = [c.controllerUid for c in online_controllers.controllers]
                            gw_online = gw_bytes in connected_uids
                            _record('Gateway online', gw_online,
                                    'connected to krouter' if gw_online else 'gateway offline or unreachable', 0)
                        else:
                            _record('Gateway online', False, 'could not retrieve connected gateways', 0)
                    except Exception as exc:
                        _record('Gateway online', False, str(exc)[:60], 0)

            except StopIteration:
                pass  # unsupported record type — already printed, skip gracefully
            except Exception as exc:
                print(f'    {self._cross()}  {self._red("PAM graph check failed: " + str(exc)[:70])}')
                all_passed.append(False)
                blocked_names.append('pam-graph')
                logging.debug('PAM graph check error', exc_info=True)

            print()

        # ── section 6: technical details ──────────────────────────────────────
        print(f'{self._bullet()}  {self._bright("Technical Details")}')
        print(f'  {self._sep()}')

        try:
            fqdn = socket.getfqdn()
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            fqdn = socket.gethostname()
            local_ip = '?'

        passed_total = sum(1 for v in all_passed if v)
        total_checks = len(all_passed)
        duration_s = time.monotonic() - t_overall_start
        blocked_str = 'none \u2013 all paths open' if not blocked_names else ', '.join(blocked_names)

        col = 10
        print(f'  {self._dim("Machine"):<{col}}{self._green(fqdn)}  \u00b7  {self._green(local_ip)}')
        if public_ip:
            print(f'  {self._dim("Public IP"):<{col}}{self._green(public_ip)} {self._dim("via STUN")}')
        print(f'  {self._dim("Duration"):<{col}}{self._green(f"{duration_s:.1f}s")}  \u00b7  '
              f'{self._green(f"{passed_total}/{total_checks} checks")}')
        print(f'  {self._dim("Blocked"):<{col}}{self._green(blocked_str)}')

        print()
        print(f'  {self._dsep()}')
        print()

        if passed_total == total_checks:
            summary = "GATEWAY READY  \u00b7  {} / {} checks passed".format(passed_total, total_checks)
            print(f'  {self._check()}  {self._bright(summary)}')
        else:
            summary = "GATEWAY NOT READY  \u00b7  {} / {} checks passed".format(passed_total, total_checks)
            print(f'  {self._cross()}  {self._red(summary)}')
            for name in blocked_names:
                print(f'       {self._red(name)}')

        print()
        print(f'  {self._dsep()}')
        print()

        return 0 if passed_total == total_checks else 1


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
    parser.add_argument('--launch-user', '-lu', required=False, dest='launch_user', action='store',
					help='The record path or UID of the PAM User record to configure as the launch '
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
            tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, record_uid, is_config=True,
                             transmission_key=transmission_key)
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

            tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, config_uid,
                             transmission_key=transmission_key)
            old_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, existing_config_uid,
                                transmission_key=transmission_key)

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

            # launch-user parameter sets the launch credential on the resource
            launch_user_name = kwargs.get('launch_user')
            if launch_user_name:
                launch_rec = RecordMixin.resolve_single_record(params, launch_user_name)
                if not launch_rec:
                    raise CommandError('',
                        f'{bcolors.FAIL}Launch user record "{launch_user_name}" not found.{bcolors.ENDC}')
                if not isinstance(launch_rec, vault.TypedRecord) or launch_rec.record_type != 'pamUser':
                    raise CommandError('',
                        f'{bcolors.FAIL}Launch user record must be a pamUser record type.{bcolors.ENDC}')
                launch_uid = launch_rec.record_uid
                if record_type in ("pamDatabase", "pamDirectory", "pamMachine"):
                    tdag.clear_launch_credential_for_resource(record_uid, exclude_user_uid=launch_uid)
                    tdag.link_user_to_resource(launch_uid, record_uid, is_launch_credential=True, belongs_to=True)
                    tdag.upgrade_resource_meta_to_v1(record_uid)

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
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
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

        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, config_uid,
                         transmission_key=transmission_key)
        if tdag is None or not tdag.linking_dag.has_graph:
            raise CommandError('', f"{bcolors.FAIL}No valid PAM Configuration UID set. "
                               "This must be set or supplied for connections to work. "
                               "The ConfigUID can be found by running "
                               f"{bcolors.OKBLUE}'pam config list'{bcolors.ENDC}")

        if config_uid:
            if existing_config_uid and existing_config_uid != config_uid:
                old_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, existing_config_uid,
                                    transmission_key=transmission_key)
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
            tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_config_uid, True,
                             transmission_key=transmission_key)
            tdag.link_resource_to_config(record_uid)
            tdag.link_user_to_resource(pam_user_uid, record_uid, True, True)

        print(f"PAM Machine record {record_uid} user credentials were split into "
              f"a new PAM User record {pam_user_uid}")
