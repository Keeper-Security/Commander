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

"""Universal Secret Sync (USS) commands for Keeper Commander."""

import argparse
import json
import logging
import time

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes, string_to_bytes

from .base import Command, GroupCommand, dump_report_data
from .pam import router_helper
from .pam.pam_dto import (
    GatewayAction,
    GatewayActionUniversalSyncRun,
    GatewayActionUniversalSyncRunInputs
)
from .pam.router_helper import router_send_action_to_gateway
from .pam.websocket_helper import start_websocket_listener, is_websocket_available
from .tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from .. import vault_extensions, crypto, vault, utils
from ..display import bcolors
from ..error import CommandError
from ..proto import pam_pb2
from ..uss_state import USSState


# Module-level USS state instance
_uss_state = USSState()


class PAMUniversalSyncConfigCommand(GroupCommand):

    def __init__(self):
        super(PAMUniversalSyncConfigCommand, self).__init__()
        self.register_command('list', PAMUniversalSyncConfigListCommand(), 'List all Universal Sync configurations', 'l')
        self.register_command('add', PAMUniversalSyncConfigAddCommand(), 'Add a new Universal Sync configuration', 'a')
        self.register_command('edit', PAMUniversalSyncConfigEditCommand(), 'Edit an existing Universal Sync configuration', 'e')
        self.register_command('remove', PAMUniversalSyncConfigRemoveCommand(), 'Remove a Universal Sync configuration', 'rm')
        self.register_command('pre-check', PAMUniversalSyncConfigPreCheckCommand(),
                              'Check whether folders are already attached to a USS config on another network', 'pc')
        self.default_verb = 'list'


class PAMUniversalSyncConfigListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-config list')
    parser.add_argument('--network', '-n', required=False, dest='network', action='store',
                        help='Specific Network UID or name to show detailed view')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                        help='Output format (table, json)')

    def get_parser(self):
        return PAMUniversalSyncConfigListCommand.parser

    def execute(self, params, **kwargs):
        network_uid = kwargs.get('network')
        format_type = kwargs.get('format', 'table')

        if not network_uid:
            # List view - show all configurations in summary table
            return self.print_uss_configurations_list(params, format_type)
        else:
            # Detailed view - show single configuration with folder sync status
            return self.print_uss_configuration_details(params, network_uid, format_type)

    @staticmethod
    def print_uss_configurations_list(params, format_type='table'):
        """Display summary list of all USS configurations"""
        from ..display import Spinner
        from ..keeper_dag import DAG
        from ..keeper_dag.connection.commander import Connection

        # Always fetch fresh data from DAG
        spinner = Spinner('Loading USS configurations...')
        spinner.start()
        try:
            # Get all configuration records (version 6)
            configurations = list(vault_extensions.find_records(params, record_version=6))

            # Only process these specific configuration types
            uss_supported_types = ('pamGcpConfiguration', 'pamAzureConfiguration', 'pamAwsConfiguration')

            configs_data = []
            for record in configurations:
                if not isinstance(record, vault.TypedRecord):
                    continue

                # Skip if not a supported USS configuration type
                if record.record_type not in uss_supported_types:
                    continue

                try:
                    # Create DAG connection and load graph for this record
                    # history_level=1 means only load latest/active edges, not full history
                    conn = Connection(params=params)
                    dag = DAG(conn=conn, record=record, graph_id=0, logger=logging, history_level=1)
                    dag.load(sync_point=0)

                    # Get root vertex and check for universal_sync loop edge
                    root = dag.get_root

                    universal_sync_edge = None
                    for edge in root.edges:
                        if edge.path == 'universal_sync' and edge.head_uid == root.uid:
                            universal_sync_edge = edge
                            break

                    if not universal_sync_edge:
                        continue

                    # Get the configuration data
                    config_data = universal_sync_edge.content_as_dict or {}

                    # Decrypt vault_name if present
                    vault_name = 'N/A'
                    vault_name_encrypted = config_data.get('vault_name')
                    if vault_name_encrypted:
                        try:
                            vault_name_bytes = crypto.decrypt_aes_v2(vault_name_encrypted, record.record_key)
                            vault_name = vault_name_bytes.decode('utf-8')
                        except Exception as e:
                            logging.debug(f"Failed to decrypt vault_name for record {record.record_uid}: {e}")
                            vault_name = 'N/A'

                    # Get folder UIDs - folders connected via universal_sync_folder (simple count only)
                    folder_count = 0
                    for vertex in root.has_vertices():
                        for edge in vertex.edges:
                            if edge.path == 'universal_sync_folder' and edge.head_uid == root.uid:
                                folder_count += 1
                                break

                    configs_data.append({
                        'record_uid': record.record_uid,
                        'record_title': record.title if hasattr(record, 'title') else 'N/A',
                        'record_type': record.record_type if hasattr(record, 'record_type') else 'N/A',
                        'enabled': config_data.get('enabled', False),
                        'dry_run_enabled': config_data.get('dry_run_enabled', False),
                        'folder_count': folder_count,
                        'vault_name': vault_name,
                    })
                except Exception as e:
                    # Skip records that fail to load or don't have USS config
                    logging.debug(f"Failed to load USS config for record {record.record_uid}: {e}")
                    continue
        finally:
            spinner.stop()

        # Check if any configurations were found
        if not configs_data:
            print(f"{bcolors.WARNING}No Universal Sync configurations found{bcolors.ENDC}")
            return

        # Build display data
        if format_type == 'json':
            print(json.dumps(configs_data, indent=2))
            return

        # Display as simple summary table
        table = []
        headers = ['Record UID', 'Title', 'Type', 'Enabled', 'Dry Run', 'Folders', 'Vault Name']

        for config in configs_data:
            enabled_str = f"{bcolors.OKGREEN}Yes{bcolors.ENDC}" if config['enabled'] else f"{bcolors.FAIL}No{bcolors.ENDC}"
            dry_run_str = f"{bcolors.WARNING}Yes{bcolors.ENDC}" if config['dry_run_enabled'] else "No"
            folder_count = config.get('folder_count', 0)
            folders_str = f"{folder_count} folder(s)" if folder_count > 0 else "None"

            row = [
                config['record_uid'],
                config['record_title'],
                config['record_type'],
                enabled_str,
                dry_run_str,
                folders_str,
                config['vault_name']
            ]
            table.append(row)

        dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)

    @staticmethod
    def print_uss_configuration_details(params, network_uid, format_type='table'):
        """Display detailed view of a single USS configuration with folder sync status"""
        from ..display import Spinner
        from ..keeper_dag import DAG
        from ..keeper_dag.connection.commander import Connection
        from datetime import datetime

        # Load the network record
        network = vault.KeeperRecord.load(params, network_uid)
        if not network:
            if format_type == 'json':
                return json.dumps({"error": f'Network "{network_uid}" not found'})
            else:
                raise CommandError('', f'{bcolors.FAIL}Network "{network_uid}" not found{bcolors.ENDC}')

        # Check if it's a supported USS configuration type
        uss_supported_types = ('pamGcpConfiguration', 'pamAzureConfiguration', 'pamAwsConfiguration')
        if not isinstance(network, vault.TypedRecord) or network.record_type not in uss_supported_types:
            if format_type == 'json':
                return json.dumps({"error": f'Record "{network_uid}" is not a USS configuration'})
            else:
                raise CommandError('', f'{bcolors.FAIL}Record "{network_uid}" is not a USS configuration{bcolors.ENDC}')

        spinner = Spinner('Loading USS configuration details...')
        spinner.start()
        try:
            # Create DAG connection and load graph
            conn = Connection(params=params)
            dag = DAG(conn=conn, record=network, graph_id=0, logger=logging, history_level=1)
            dag.load(sync_point=0)

            # Get root vertex and check for universal_sync loop edge
            root = dag.get_root

            universal_sync_edge = None
            for edge in root.edges:
                if edge.path == 'universal_sync' and edge.head_uid == root.uid:
                    universal_sync_edge = edge
                    break

            if not universal_sync_edge:
                spinner.stop()
                if format_type == 'json':
                    return json.dumps({"error": "No USS configuration found for this network"})
                else:
                    raise CommandError('', f'{bcolors.FAIL}No USS configuration found for this network{bcolors.ENDC}')

            # Get the configuration data
            config_data = universal_sync_edge.content_as_dict or {}

            # Decrypt vault_name if present
            vault_name = 'N/A'
            vault_name_encrypted = config_data.get('vault_name')
            if vault_name_encrypted:
                try:
                    vault_name_bytes = crypto.decrypt_aes_v2(vault_name_encrypted, network.record_key)
                    vault_name = vault_name_bytes.decode('utf-8')
                except Exception as e:
                    logging.debug(f"Failed to decrypt vault_name for network {network.record_uid}: {e}")
                    vault_name = 'N/A'

            # Get folder vertices with sync status
            folder_vertices = []
            for vertex in root.has_vertices():
                for edge in vertex.edges:
                    if edge.path == 'universal_sync_folder' and edge.head_uid == root.uid:
                        folder_vertices.append(vertex)
                        break

            # Collect folder information with sync status
            folder_details = []
            for folder_vertex in folder_vertices:
                folder_uid = folder_vertex.uid
                folder_name = None

                # Try to get folder from folder_cache
                if folder_uid in params.folder_cache:
                    folder = params.folder_cache[folder_uid]
                    folder_name = folder.name if hasattr(folder, 'name') else None
                # If not found, try subfolder_cache
                if not folder_name and folder_uid in params.subfolder_cache:
                    sf = params.subfolder_cache[folder_uid]
                    if 'data_unencrypted' in sf:
                        try:
                            data = json.loads(sf['data_unencrypted'].decode())
                            folder_name = data.get('name')
                        except Exception:
                            pass

                # Get universal_sync_complete loop edge for this folder
                sync_complete_data = None
                for edge in folder_vertex.edges:
                    if edge.path == 'universal_sync_complete' and edge.head_uid == folder_vertex.uid:
                        sync_complete_data = edge.content_as_dict
                        break

                folder_details.append({
                    'uid': folder_uid,
                    'name': folder_name or folder_uid,
                    'sync_complete_data': sync_complete_data
                })

        finally:
            spinner.stop()

        # Display results
        if format_type == 'json':
            result = {
                'record_uid': network.record_uid,
                'record_title': network.title if hasattr(network, 'title') else 'N/A',
                'record_type': network.record_type if hasattr(network, 'record_type') else 'N/A',
                'enabled': config_data.get('enabled', False),
                'dry_run_enabled': config_data.get('dry_run_enabled', False),
                'vault_name': vault_name,
                'folders': []
            }

            for folder in folder_details:
                sync_data = folder.get('sync_complete_data')
                folder_result = {
                    'uid': folder['uid'],
                    'name': folder['name'],
                    'last_synced': None,
                    'success': None
                }
                if sync_data:
                    folder_result['last_synced'] = sync_data.get('lastSynced')
                    folder_result['success'] = sync_data.get('success')
                result['folders'].append(folder_result)

            return json.dumps(result, indent=2)
        else:
            # Display as name-value pairs (like PAM config detail view)
            table = []
            header = ['name', 'value']

            table.append(['UID', network.record_uid])
            table.append(['Name', network.title if hasattr(network, 'title') else 'N/A'])
            table.append(['Config Type', network.record_type])
            table.append(['Enabled', 'Yes' if config_data.get('enabled', False) else 'No'])
            table.append(['Dry Run', 'Yes' if config_data.get('dry_run_enabled', False) else 'No'])
            table.append(['Vault Name', vault_name])
            table.append(['', ''])  # Blank row separator

            # Display folder sync details
            if folder_details:
                table.append([f'{bcolors.BOLD}Folders ({len(folder_details)}){bcolors.ENDC}', ''])
                for folder in folder_details:
                    sync_data = folder.get('sync_complete_data')

                    if sync_data:
                        # Get last synced timestamp
                        last_synced_ms = sync_data.get('lastSynced')
                        if last_synced_ms:
                            try:
                                dt = datetime.fromtimestamp(last_synced_ms / 1000)
                                last_synced_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                            except Exception:
                                last_synced_str = str(last_synced_ms)
                        else:
                            last_synced_str = 'Never'

                        # Get success status
                        success = sync_data.get('success', False)
                        if success:
                            status_str = f"{bcolors.OKGREEN}Success{bcolors.ENDC}"
                        else:
                            status_str = f"{bcolors.FAIL}Failed{bcolors.ENDC}"
                    else:
                        last_synced_str = 'Never'
                        status_str = 'N/A'

                    table.append([f'  {folder["name"]}', ''])
                    table.append([f'    Last Synced', last_synced_str])
                    table.append([f'    Status', status_str])
            else:
                table.append(['Folders', 'None'])

            dump_report_data(table, header, no_header=True, right_align=(0,))


class PAMUniversalSyncConfigAddCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-config add')
    parser.add_argument('--network', '-n', required=True, dest='network', action='store',
                        help='Network UID or name to configure universal sync')
    parser.add_argument('--enabled', '-e', dest='enabled', action='store',
                        choices=['true', 'false'], default='true', help='Enable or disable universal sync (default: true)')
    parser.add_argument('--dry-run', '-dr', dest='dry_run', action='store',
                        choices=['true', 'false'], default='false', help='Enable or disable dry run mode (default: false)')
    parser.add_argument('--folder', '-f', dest='folder', action='append',
                        help='Folder UID where synced records will be created (can be specified multiple times)')
    parser.add_argument('--sync-identity', '-si', dest='sync_identity', action='store',
                        help='Identity record UID to use for syncing')
    parser.add_argument('--vault-name', '-vn', dest='vault_name', action='store',
                        help='Vault name for universal sync')

    def get_parser(self):
        return PAMUniversalSyncConfigAddCommand.parser

    def execute(self, params, **kwargs):
        network_name = kwargs.get('network')
        if not network_name:
            raise CommandError('', f'{bcolors.FAIL}Network is required{bcolors.ENDC}')

        network = vault.KeeperRecord.load(params, network_name)
        if not network:
            raise CommandError('', f'{bcolors.FAIL}Network "{network_name}" not found{bcolors.ENDC}')

        rq = pam_pb2.PAMUniversalSyncConfig()
        rq.networkUid = url_safe_str_to_bytes(network.record_uid)

        enabled = kwargs.get('enabled')
        if enabled is not None:
            rq.enabled = enabled.lower() == 'true'

        dry_run = kwargs.get('dry_run')
        if dry_run is not None:
            rq.dryRunEnabled = dry_run.lower() == 'true'

        folders = kwargs.get('folder')
        if folders:
            for folder in folders:
                folder_uid = folder
                # Try to resolve folder by name if not a UID
                if len(folder_uid) != 22:
                    matching_folders = [f for f in params.folder_cache if params.folder_cache[f].name == folder]
                    if matching_folders:
                        folder_uid = matching_folders[0]

                folder_obj = pam_pb2.PAMUniversalSyncFolder()
                folder_obj.uid = url_safe_str_to_bytes(folder_uid)
                rq.folders.append(folder_obj)

        sync_identity = kwargs.get('sync_identity')
        if sync_identity:
            sync_identity_bytes = string_to_bytes(sync_identity)
            encrypted_sync_identity = crypto.encrypt_aes_v2(sync_identity_bytes, network.record_key)
            rq.syncIdentity = encrypted_sync_identity

        vault_name = kwargs.get('vault_name')
        if vault_name:
            vault_name_bytes = string_to_bytes(vault_name)
            encrypted_vault_name = crypto.encrypt_aes_v2(vault_name_bytes, network.record_key)
            rq.vaultName = encrypted_vault_name

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        try:
            router_helper.router_configure_universal_sync(params, rq, transmission_key,
                                                         encrypted_transmission_key,
                                                         encrypted_session_token)
            print(f'{bcolors.OKGREEN}Universal sync configuration added for network: {network.title}{bcolors.ENDC}')
        except Exception as e:
            raise CommandError('', f'{bcolors.FAIL}Error adding universal sync configuration: {e}{bcolors.ENDC}')


class PAMUniversalSyncConfigEditCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-config edit')
    parser.add_argument('--network', '-n', required=True, dest='network', action='store',
                        help='Network UID or name to configure universal sync')
    parser.add_argument('--enabled', '-e', dest='enabled', action='store',
                        choices=['true', 'false'], help='Enable or disable universal sync')
    parser.add_argument('--dry-run', '-dr', dest='dry_run', action='store',
                        choices=['true', 'false'], help='Enable or disable dry run mode')
    parser.add_argument('--folder', '-f', dest='folder', action='append',
                        help='Folder UID where synced records will be created (can be specified multiple times)')
    parser.add_argument('--sync-identity', '-si', dest='sync_identity', action='store',
                        help='Identity record UID to use for syncing')
    parser.add_argument('--vault-name', '-vn', dest='vault_name', action='store',
                        help='Vault name for universal sync')

    def get_parser(self):
        return PAMUniversalSyncConfigEditCommand.parser

    def execute(self, params, **kwargs):
        from ..keeper_dag import DAG
        from ..keeper_dag.connection.commander import Connection

        network_name = kwargs.get('network')
        if not network_name:
            raise CommandError('', f'{bcolors.FAIL}Network is required{bcolors.ENDC}')

        network = vault.KeeperRecord.load(params, network_name)
        if not network:
            raise CommandError('', f'{bcolors.FAIL}Network "{network_name}" not found{bcolors.ENDC}')

        # Load existing config from DAG
        # history_level=1 means only load latest/active edges, not full history
        try:
            conn = Connection(params=params)
            dag = DAG(conn=conn, record=network, graph_id=0, logger=logging, history_level=1)
            dag.load(sync_point=0)
            root = dag.get_root

            # Look for universal_sync loop edge
            universal_sync_edge = None
            for edge in root.edges:
                if edge.path == 'universal_sync' and edge.head_uid == root.uid:
                    universal_sync_edge = edge
                    break

            existing_config = universal_sync_edge.content_as_dict if universal_sync_edge else {}
        except Exception:
            existing_config = {}

        rq = pam_pb2.PAMUniversalSyncConfig()
        rq.networkUid = url_safe_str_to_bytes(network.record_uid)

        print(existing_config)

        # Use existing values if new values not provided
        enabled = kwargs.get('enabled')
        if enabled is not None:
            rq.enabled = enabled.lower() == 'true'
        elif 'enabled' in existing_config:
            rq.enabled = existing_config['enabled']

        dry_run = kwargs.get('dry_run')
        print(dry_run)
        if dry_run is not None:
            rq.dryRunEnabled = dry_run.lower() == 'true'
        elif 'dry_run_enabled' in existing_config:
            rq.dryRunEnabled = existing_config['dry_run_enabled']

        # Handle folders - if provided, replace all; if not, keep existing
        folders = kwargs.get('folder')
        if folders:
            for folder in folders:
                folder_uid = folder
                # Try to resolve folder by name if not a UID
                if len(folder_uid) != 22:
                    matching_folders = [f for f in params.folder_cache if params.folder_cache[f].name == folder]
                    if matching_folders:
                        folder_uid = matching_folders[0]

                folder_obj = pam_pb2.PAMUniversalSyncFolder()
                folder_obj.uid = url_safe_str_to_bytes(folder_uid)
                rq.folders.append(folder_obj)
        else:
            # Keep existing folders by loading them from DAG
            try:
                for vertex in root.has_vertices(None, True):
                    for edge in vertex.edges:
                        if edge.path == 'universal_sync_folder' and edge.head_uid == root.uid:
                            folder_obj = pam_pb2.PAMUniversalSyncFolder()
                            folder_obj.uid = url_safe_str_to_bytes(vertex.uid)
                            rq.folders.append(folder_obj)
                            break
            except Exception:
                pass

        sync_identity = kwargs.get('sync_identity')
        if sync_identity:
            sync_identity_bytes = string_to_bytes(sync_identity)
            encrypted_sync_identity = crypto.encrypt_aes_v2(sync_identity_bytes, network.record_key)
            rq.syncIdentity = encrypted_sync_identity

        vault_name = kwargs.get('vault_name')
        if vault_name:
            vault_name_bytes = string_to_bytes(vault_name)
            encrypted_vault_name = crypto.encrypt_aes_v2(vault_name_bytes, network.record_key)
            rq.vaultName = encrypted_vault_name

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        try:
            router_helper.router_configure_universal_sync(params, rq, transmission_key,
                                                         encrypted_transmission_key,
                                                         encrypted_session_token)
            print(f'{bcolors.OKGREEN}Universal sync configuration updated for network: {network.title}{bcolors.ENDC}')
        except Exception as e:
            raise CommandError('', f'{bcolors.FAIL}Error updating universal sync configuration: {e}{bcolors.ENDC}')


class PAMUniversalSyncConfigRemoveCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-config remove')
    parser.add_argument('--network', '-n', required=True, dest='network', action='store',
                        help='Network UID or name to remove universal sync configuration')

    def get_parser(self):
        return PAMUniversalSyncConfigRemoveCommand.parser

    def execute(self, params, **kwargs):
        network_name = kwargs.get('network')
        if not network_name:
            raise CommandError('', f'{bcolors.FAIL}Network is required{bcolors.ENDC}')

        network = vault.KeeperRecord.load(params, network_name)
        if not network:
            raise CommandError('', f'{bcolors.FAIL}Network "{network_name}" not found{bcolors.ENDC}')

        # Create empty request to remove config
        rq = pam_pb2.PAMUniversalSyncConfig()
        rq.networkUid = url_safe_str_to_bytes(network.record_uid)
        # All other fields are left empty, which signals removal

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        try:
            router_helper.router_configure_universal_sync(params, rq, transmission_key,
                                                         encrypted_transmission_key,
                                                         encrypted_session_token)
            print(f'{bcolors.OKGREEN}Universal sync configuration removed for network: {network.title}{bcolors.ENDC}')
        except Exception as e:
            raise CommandError('', f'{bcolors.FAIL}Error removing universal sync configuration: {e}{bcolors.ENDC}')


class PAMUniversalSyncConfigPreCheckCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-config pre-check')
    parser.add_argument('--network', '-n', required=True, dest='network', action='store',
                        help='Network UID or name being configured')
    parser.add_argument('--folder', '-f', required=True, dest='folder', action='append',
                        help='Folder UID or name to check (can be specified multiple times)')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                        help='Output format (table, json)')

    def get_parser(self):
        return PAMUniversalSyncConfigPreCheckCommand.parser

    def execute(self, params, **kwargs):
        network_name = kwargs.get('network')
        folders = kwargs.get('folder') or []
        format_type = kwargs.get('format', 'table')

        if not network_name:
            raise CommandError('', f'{bcolors.FAIL}Network is required{bcolors.ENDC}')
        if not folders:
            raise CommandError('', f'{bcolors.FAIL}At least one --folder is required{bcolors.ENDC}')

        network = vault.KeeperRecord.load(params, network_name)
        if not network:
            raise CommandError('', f'{bcolors.FAIL}Network "{network_name}" not found{bcolors.ENDC}')

        rq = pam_pb2.PAMUniversalSyncPreCheckRequest()
        rq.networkUid = url_safe_str_to_bytes(network.record_uid)

        for folder in folders:
            folder_uid = folder
            if len(folder_uid) != 22:
                matching_folders = [f for f in params.folder_cache if params.folder_cache[f].name == folder]
                if matching_folders:
                    folder_uid = matching_folders[0]
            rq.folderUids.append(url_safe_str_to_bytes(folder_uid))

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        try:
            response = router_helper.router_universal_sync_pre_check(
                params, rq, transmission_key, encrypted_transmission_key, encrypted_session_token)
        except Exception as e:
            raise CommandError('', f'{bcolors.FAIL}Error pre-checking universal sync folders: {e}{bcolors.ENDC}')

        results = []
        if response is not None:
            for r in response.results:
                folder_uid_str = utils.base64_url_encode(r.folderUid)
                folder_name = PAMUniversalSyncConfigPreCheckCommand._resolve_folder_name(params, folder_uid_str)
                results.append({
                    'folder_uid': folder_uid_str,
                    'folder_name': folder_name or folder_uid_str,
                    'is_used': bool(r.isUsed),
                })

        if format_type == 'json':
            print(json.dumps({
                'network_uid': network.record_uid,
                'results': results,
            }, indent=2))
            return

        if not results:
            print(f'{bcolors.WARNING}No results returned for pre-check{bcolors.ENDC}')
            return

        headers = ['Folder UID', 'Folder Name', 'Used by Another Network']
        table = []
        for item in results:
            used_str = f"{bcolors.FAIL}Yes{bcolors.ENDC}" if item['is_used'] else f"{bcolors.OKGREEN}No{bcolors.ENDC}"
            table.append([item['folder_uid'], item['folder_name'], used_str])
        dump_report_data(table, headers, fmt='table', filename='', row_number=False, column_width=None)

    @staticmethod
    def _resolve_folder_name(params, folder_uid):
        if folder_uid in params.folder_cache:
            folder = params.folder_cache[folder_uid]
            return folder.name if hasattr(folder, 'name') else None
        if folder_uid in params.subfolder_cache:
            sf = params.subfolder_cache[folder_uid]
            if 'data_unencrypted' in sf:
                try:
                    data = json.loads(sf['data_unencrypted'].decode())
                    return data.get('name')
                except Exception:
                    pass
        return None


class PAMUniversalSyncRunCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-run')
    parser.add_argument('--network', '-n', required=True, dest='network', action='store',
                        help='Network UID or name to run universal sync')
    parser.add_argument('--dry-run', '-dr', dest='dry_run', action='store_true',
                        help='Run in dry-run mode (default: false)')

    def get_parser(self):
        return PAMUniversalSyncRunCommand.parser

    def execute(self, params, **kwargs):
        from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
        from .pam.config_helper import configuration_controller_get
        from .pam.router_helper import router_get_connected_gateways

        network_name = kwargs.get('network')
        if not network_name:
            raise CommandError('', f'{bcolors.FAIL}Network is required{bcolors.ENDC}')

        network = vault.KeeperRecord.load(params, network_name)
        if not network:
            raise CommandError('', f'{bcolors.FAIL}Network "{network_name}" not found{bcolors.ENDC}')

        dry_run = kwargs.get('dry_run', False)

        # Get the controller/gateway UID associated with this network configuration
        controller = configuration_controller_get(params, url_safe_str_to_bytes(network.record_uid))
        if not controller.controllerUid:
            raise CommandError('', f'{bcolors.FAIL}Gateway UID not found for network configuration '
                                   f'{network.record_uid}.{bcolors.ENDC}')

        # Find connected controllers
        enterprise_controllers_connected = router_get_connected_gateways(params)

        controller_from_config_bytes = controller.controllerUid
        gateway_uid = utils.base64_url_encode(controller.controllerUid)
        if enterprise_controllers_connected:
            router_controllers = {controller.controllerUid: controller for controller in
                                  list(enterprise_controllers_connected.controllers)}
            connected_controller = router_controllers.get(controller_from_config_bytes)

            if not connected_controller:
                print(f'{bcolors.WARNING}The Gateway "{gateway_uid}" is down.{bcolors.ENDC}')
                return
        else:
            print(f'{bcolors.WARNING}There are no connected gateways.{bcolors.ENDC}')
            return

        action_inputs = GatewayActionUniversalSyncRunInputs(
            network_uid=network.record_uid,
            dry_run=dry_run
        )

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        conversation_id = GatewayAction.generate_conversation_id()

        # Start tracking the job in USS state
        _uss_state.start_job(conversation_id, network.record_uid, dry_run)

        # Dry-run mode uses streaming/websockets for real-time progress updates
        # Live mode uses non-streaming for consistency with rotation jobs
        use_streaming = dry_run

        # Initialize listener variable before try block to ensure it's accessible in exception handler
        listener = None

        try:
            if use_streaming:
                def handle_uss_message(message):
                    # Check for CTL_STATUS with OFFLINE
                    from .pam.websocket_helper import WebsocketMessageType
                    from ..discovery_common.types import ControllerStatus

                    message_type = message.get('type')
                    if message_type == WebsocketMessageType.CTL_STATUS.value:
                        controller_status = message.get('controllerStatus')
                        if controller_status == ControllerStatus.OFFLINE.value:
                            error_msg = 'Gateway went offline during job execution'
                            print(f"{bcolors.FAIL}Error: {error_msg}{bcolors.ENDC}")
                            _uss_state.fail_job(conversation_id, error_msg)
                            return False

                    if message.get('status') == 'OK':
                        # First, get the 'data' field from message (it's a JSON string)
                        data_str = message.get('payload', '')
                        try:
                            if isinstance(data_str, str) and data_str:
                                # Parse the JSON string to get the payload object
                                payload = json.loads(data_str)
                                # Now get the 'data' field from the parsed payload
                                data = payload.get('data') if isinstance(payload, dict) else payload
                            else:
                                data = data_str
                            _uss_state.complete_job(conversation_id, result=data)
                            return True
                        except (json.JSONDecodeError, Exception) as e:
                            logging.error(f"Error parsing USS completion data: {e}")
                            logging.error(f"Raw data_str: {data_str[:200] if isinstance(data_str, str) else data_str}")

                    if message.get('is_ok') is False:
                        error_msg = message.get('error_message', 'Unknown error')
                        print(f"{bcolors.FAIL}Error: {error_msg}{bcolors.ENDC}")
                        _uss_state.fail_job(conversation_id, error_msg)
                        return False

                    return None

                # Start WebSocket listener for streaming progress updates (dry-run only)
                ws_thread = None
                if is_websocket_available():
                    ws_thread, stop_event, listener = start_websocket_listener(
                        params, conversation_id, handle_uss_message, timeout=600
                    )
                    # Give WebSocket time to connect
                    time.sleep(1.5)
                else:
                    print(f'{bcolors.WARNING}WebSocket not available - progress updates will not be shown in real-time{bcolors.ENDC}')

            # Send the action
            router_response = router_send_action_to_gateway(
                params=params,
                gateway_action=GatewayActionUniversalSyncRun(inputs=action_inputs, conversation_id=conversation_id,
                                                              gateway_destination=gateway_uid),
                message_type=6,
                is_streaming=use_streaming,
                transmission_key=transmission_key,
                encrypted_transmission_key=encrypted_transmission_key,
                encrypted_session_token=encrypted_session_token
            )

            if router_response is None:
                print(f'{bcolors.FAIL}The router returned a failure.{bcolors.ENDC}')
                _uss_state.fail_job(conversation_id, 'Router returned a failure')
                if listener:
                    listener.stop()
                return

            if not use_streaming:
                from .pam.router_helper import print_router_response
                print_router_response(router_response, 'job_info', conversation_id, gateway_uid=gateway_uid)
                print(f"\nAfter action is finished, use: '{bcolors.OKGREEN}pam usc list -n {network.record_uid}{bcolors.ENDC}, to view sync results'")
            else:
                print(f"Scheduled action id: {bcolors.OKBLUE}{conversation_id}{bcolors.ENDC}")
                print(f"The action has been scheduled, use command '{bcolors.OKGREEN}pam usdri {conversation_id}{bcolors.ENDC}' to get status of the scheduled action")

                # Wait for websocket thread to complete (with timeout)
                if ws_thread and ws_thread.is_alive():
                    ws_thread.join(timeout=610)  # Wait slightly longer than websocket timeout

                    # Check if job is still running (meaning websocket timed out without completion)
                    job = _uss_state.get_job(conversation_id)
                    if job and job.status == 'running':
                        _uss_state.fail_job(conversation_id, 'WebSocket listener timed out after 10 minutes')
                        print(f"\n{bcolors.WARNING}WebSocket listener timed out. Job may still be running on gateway.{bcolors.ENDC}")

        except Exception as e:
            _uss_state.fail_job(conversation_id, str(e))
            # Close websocket connection on HTTP error
            if listener:
                listener.stop()
            raise CommandError('', f'{bcolors.FAIL}Error running universal sync: {e}{bcolors.ENDC}')


class PAMUniversalSyncJobInfoCommand(Command):
    """Command to check USS dry run info and results."""
    parser = argparse.ArgumentParser(prog='pam universal-sync-dry-run-info')
    parser.add_argument('job_id', nargs='?', help='Job ID (conversation ID) to display. If not provided, lists all jobs.')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                        help='Output format (table, json)')

    def get_parser(self):
        return PAMUniversalSyncJobInfoCommand.parser

    def execute(self, params, **kwargs):
        """Display USS job state and results."""
        job_id = kwargs.get('job_id')
        format_type = kwargs.get('format', 'table')

        if job_id:
            # Show specific job details
            job = _uss_state.get_job(job_id)
            if not job:
                print(f'{bcolors.FAIL}Job {job_id} not found{bcolors.ENDC}')
                return

            if format_type == 'json':
                print(json.dumps(job.to_dict(), indent=2))
            else:
                print(f'{bcolors.HEADER}=== USS Job Information ==={bcolors.ENDC}\n')
                table = []
                header = ['name', 'value']
                table.append(['Job ID', job.conversation_id])
                table.append(['Network UID', job.network_uid])
                table.append(['Dry Run', 'Yes' if job.dry_run else 'No'])
                table.append(['Status', job.status])
                table.append(['Started', job.started_at.strftime('%Y-%m-%d %H:%M:%S')])
                if job.completed_at:
                    table.append(['Completed', job.completed_at.strftime('%Y-%m-%d %H:%M:%S')])

                dump_report_data(table, header, no_header=True, right_align=(0,))

                if job.result and job.dry_run:
                    print(f'\n{bcolors.OKGREEN}Dry Run Result:{bcolors.ENDC}')
                    print(json.dumps(job.result, indent=2))
        else:
            # List all jobs
            all_jobs = _uss_state.get_all_jobs()

            if not all_jobs:
                print(f'{bcolors.WARNING}No USS jobs found{bcolors.ENDC}')
                return

            if format_type == 'json':
                jobs_data = [job.to_dict() for job in all_jobs.values()]
                print(json.dumps(jobs_data, indent=2))
            else:
                print(f'{bcolors.HEADER}=== USS Jobs ==={bcolors.ENDC}\n')
                table = []
                headers = ['Job ID', 'Network UID', 'Dry Run', 'Status', 'Started', 'Completed']

                for job in all_jobs.values():
                    completed_str = job.completed_at.strftime('%Y-%m-%d %H:%M:%S') if job.completed_at else 'N/A'
                    status_color = bcolors.OKGREEN if job.status == 'completed' else (bcolors.FAIL if job.status == 'failed' else bcolors.WARNING)
                    status_str = f"{status_color}{job.status}{bcolors.ENDC}"

                    row = [
                        job.conversation_id,
                        job.network_uid,
                        'Yes' if job.dry_run else 'No',
                        status_str,
                        job.started_at.strftime('%Y-%m-%d %H:%M:%S'),
                        completed_str
                    ]
                    table.append(row)

                dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)
                print(f'\n{bcolors.OKBLUE}Use "pam usdri <job-id>" to view detailed results{bcolors.ENDC}')


class PAMUniversalSyncStatusCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-status')
    parser.add_argument('--network', '-n', required=True, dest='network', action='store',
                        help='Network UID or name to check universal sync status')
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                        help='Output format (table, json)')
    parser.add_argument('--graph-id', '-g', dest='graph_id', type=int, default=0,
                        help='Graph ID to query (default: 0 for USS config graph)')

    def get_parser(self):
        return PAMUniversalSyncStatusCommand.parser

    def execute(self, params, **kwargs):
        from ..keeper_dag import DAG
        from ..keeper_dag.connection.commander import Connection
        from datetime import datetime

        network_name = kwargs.get('network')
        format_type = kwargs.get('format', 'table')
        graph_id = kwargs.get('graph_id', 0)

        if not network_name:
            raise CommandError('', f'{bcolors.FAIL}Network is required{bcolors.ENDC}')

        try:
            # Load the network record
            network = vault.KeeperRecord.load(params, network_name)
            if not network:
                raise CommandError('', f'{bcolors.FAIL}Network "{network_name}" not found{bcolors.ENDC}')

            network_uid = network.record_uid

            # Create DAG connection and load graph
            # history_level=1 means only load latest/active edges, not full history
            conn = Connection(params=params)
            dag = DAG(conn=conn, record=network, graph_id=graph_id, logger=logging, history_level=1)
            dag.load(sync_point=0)

            # Get root vertex
            root = dag.get_root

            # Find all vertices connected via universal_sync_folder edge
            folder_vertices = []
            for vertex in root.has_vertices(None, True):
                # Check if this vertex is connected via universal_sync_folder edge
                for edge in vertex.edges:
                    if edge.path == 'universal_sync_folder' and edge.head_uid == root.uid:
                        folder_vertices.append(vertex)
                        break

            if not folder_vertices:
                print(f"{bcolors.WARNING}No folders connected via universal_sync_folder edge for network {network_uid}{bcolors.ENDC}")
                return

            # Get universal_sync_complete data from each folder
            folder_status = []
            for folder_vertex in folder_vertices:
                folder_info = {
                    'folder_uid': folder_vertex.uid,
                    'status_history': []
                }

                # Look for all universal_sync_complete loop edges (all versions)
                status_edges = []
                for edge in folder_vertex.edges:
                    if edge.path == 'universal_sync_complete' and edge.head_uid == folder_vertex.uid:
                        status_edges.append(edge)

                # Sort by version (highest first)
                status_edges.sort(key=lambda e: e.version, reverse=True)

                # Collect all versions
                for edge in status_edges:
                    try:
                        status_data = edge.content_as_dict
                        folder_info['status_history'].append({
                            'version': edge.version,
                            'active': edge.active,
                            'data': status_data
                        })
                    except Exception:
                        # Skip edges that can't be decoded
                        pass

                folder_status.append(folder_info)

            # Display results
            if format_type == 'json':
                result = {
                    'network_uid': network_uid,
                    'network_title': network.title if hasattr(network, 'title') else 'N/A',
                    'folders': []
                }

                # Format the folder status for JSON output
                for folder_info in folder_status:
                    folder_data = {
                        'folder_uid': folder_info['folder_uid'],
                        'status_history': folder_info['status_history']
                    }
                    result['folders'].append(folder_data)

                print(json.dumps(result, indent=2))
            else:
                # Display as formatted output
                print(f"\n{bcolors.OKBLUE}Universal Sync Status for Configuration: {bcolors.OKGREEN}{network.title if hasattr(network, 'title') else 'N/A'} ({network_uid}){bcolors.ENDC}\n")

                for folder_info in folder_status:
                    folder_uid = folder_info['folder_uid']
                    status_history = folder_info['status_history']

                    print(f"{bcolors.BOLD}Folder: {bcolors.OKGREEN}{folder_uid}{bcolors.ENDC}")

                    if status_history:
                        print(f"  {bcolors.BOLD}Sync History ({len(status_history)} version(s)):{bcolors.ENDC}")

                        for idx, status_entry in enumerate(status_history):
                            version = status_entry['version']
                            active = status_entry['active']
                            status_data = status_entry['data']

                            # Display version header
                            active_marker = f"{bcolors.OKGREEN} [ACTIVE]{bcolors.ENDC}" if active else ""
                            print(f"\n    {bcolors.BOLD}Version {version}{active_marker}:{bcolors.ENDC}")

                            if status_data:
                                last_synced = status_data.get('lastSynced')
                                success = status_data.get('success')
                                status_text = f"{bcolors.OKGREEN}Success{bcolors.ENDC}" if success else f"{bcolors.FAIL}Failed{bcolors.ENDC}"

                                if last_synced:
                                    # Convert timestamp to human-readable format
                                    try:
                                        if isinstance(last_synced, (int, float)):
                                            dt = datetime.fromtimestamp(last_synced / 1000 if last_synced > 10000000000 else last_synced)
                                        else:
                                            dt = datetime.fromisoformat(last_synced.replace('Z', '+00:00'))
                                        human_date = dt.strftime('%Y-%m-%d %H:%M:%S')
                                    except Exception:
                                        human_date = str(last_synced)
                                    print(f"      Synced at: {human_date}")

                                print(f"      Status: {status_text}")

                                # Display any additional fields in the status data
                                for key, value in status_data.items():
                                    if key not in ['lastSynced', 'success']:
                                        print(f"      {key}: {value}")
                            else:
                                print(f"      {bcolors.WARNING}No data{bcolors.ENDC}")
                    else:
                        print(f"  {bcolors.WARNING}Folder has never been synced{bcolors.ENDC}")
                    print()

                print(f"{bcolors.OKBLUE}Total folders: {len(folder_status)}{bcolors.ENDC}\n")

        except Exception as e:
            print(f"{bcolors.FAIL}Error reading universal sync status: {e}{bcolors.ENDC}")
            logging.error(f"Error in universal-sync-status: {e}", exc_info=True)


def populate_uss_cache(params):
    """
    Populate USS configuration cache during vault sync.
    This should be called after sync_down to cache all USS configurations.
    Only checks pamGcpConfiguration, pamAzureConfiguration, and pamAwsConfiguration.
    """
    from ..keeper_dag import DAG
    from ..keeper_dag.connection.commander import Connection

    # Clear existing cache
    if not hasattr(params, 'uss_config_cache'):
        params.uss_config_cache = {}
    else:
        params.uss_config_cache.clear()

    # Get all configuration records (version 6)
    configurations = list(vault_extensions.find_records(params, record_version=6))

    # Only process these specific configuration types
    uss_supported_types = ('pamGcpConfiguration', 'pamAzureConfiguration', 'pamAwsConfiguration')

    for record in configurations:
        if not isinstance(record, vault.TypedRecord):
            continue

        # Skip if not a supported USS configuration type
        if record.record_type not in uss_supported_types:
            continue

        try:
            # Create DAG connection and load graph for this record
            # history_level=1 means only load latest/active edges, not full history
            conn = Connection(params=params)
            dag = DAG(conn=conn, record=record, graph_id=0, logger=logging, history_level=1)
            dag.load(sync_point=0)

            # Get root vertex and check for universal_sync loop edge
            root = dag.get_root

            universal_sync_edge = None
            for edge in root.edges:
                if edge.path == 'universal_sync' and edge.head_uid == root.uid:
                    universal_sync_edge = edge
                    break

            if universal_sync_edge:
                # Get the configuration data
                config_data = universal_sync_edge.content_as_dict or {}

                # Get folder UIDs - folders connected via universal_sync_folder
                folder_uids = []
                for vertex in root.has_vertices():
                    for edge in vertex.edges:
                        if edge.path == 'universal_sync_folder' and edge.head_uid == root.uid:
                            folder_uids.append(vertex.uid)
                            break

                # Cache the USS configuration
                params.uss_config_cache[record.record_uid] = {
                    'enabled': config_data.get('enabled', False),
                    'dry_run_enabled': config_data.get('dry_run_enabled', False),
                    'folders': folder_uids,
                    'vault_name': config_data.get('vault_name', 'N/A'),
                }
        except Exception as e:
            # Skip records that fail to load or don't have USS config
            logging.debug(f"Failed to load USS config for record {record.record_uid}: {e}")
            continue

    logging.debug(f"Populated USS cache with {len(params.uss_config_cache)} configurations")
