#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2026 Keeper Security Inc.
# Contact: sm@keepersecurity.com

"""Universal Secret Sync (USS) commands for Keeper Commander."""

import argparse
import json
import logging

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes, string_to_bytes

from .base import Command, GroupCommand, dump_report_data
from .pam import router_helper
from .pam.pam_dto import (
    GatewayAction,
    GatewayActionUniversalSyncRun,
    GatewayActionUniversalSyncRunInputs
)
from .pam.router_helper import router_send_action_to_gateway
from .tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from .. import vault_extensions, crypto, vault, utils
from ..display import bcolors
from ..error import CommandError
from ..proto import pam_pb2


class PAMUniversalSyncConfigCommand(GroupCommand):

    def __init__(self):
        super(PAMUniversalSyncConfigCommand, self).__init__()
        self.register_command('list', PAMUniversalSyncConfigListCommand(), 'List all Universal Sync configurations', 'l')
        self.register_command('add', PAMUniversalSyncConfigAddCommand(), 'Add a new Universal Sync configuration', 'a')
        self.register_command('edit', PAMUniversalSyncConfigEditCommand(), 'Edit an existing Universal Sync configuration', 'e')
        self.register_command('remove', PAMUniversalSyncConfigRemoveCommand(), 'Remove a Universal Sync configuration', 'rm')
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

                    # Decrypt vault_name if present. The router stores it under the
                    # 'vaultName' key as a base64-url string of the encrypted bytes.
                    vault_name = 'N/A'
                    vault_name_encrypted = config_data.get('vaultName')
                    if vault_name_encrypted:
                        try:
                            vault_name_bytes = crypto.decrypt_aes_v2(
                                utils.base64_url_decode(vault_name_encrypted), record.record_key)
                            vault_name = vault_name_bytes.decode('utf-8')
                        except Exception as e:
                            logging.debug(f"Failed to decrypt vault_name for record {record.record_uid}: {e}")
                            vault_name = 'N/A'

                    # Decrypt sync_identity if present. The router stores it under the
                    # 'syncIdentity' key as a base64-url string of the encrypted bytes; the
                    # decrypted value is the UID of the Identity record used for syncing.
                    sync_identity = 'N/A'
                    sync_identity_encrypted = config_data.get('syncIdentity')
                    if sync_identity_encrypted:
                        try:
                            sync_identity_bytes = crypto.decrypt_aes_v2(
                                utils.base64_url_decode(sync_identity_encrypted), record.record_key)
                            sync_identity_uid = sync_identity_bytes.decode('utf-8')
                            identity_record = vault.KeeperRecord.load(params, sync_identity_uid)
                            if identity_record and getattr(identity_record, 'title', None):
                                sync_identity = f'{identity_record.title} ({sync_identity_uid})'
                            else:
                                sync_identity = sync_identity_uid
                        except Exception as e:
                            logging.debug(f"Failed to decrypt sync_identity for record {record.record_uid}: {e}")
                            sync_identity = 'N/A'

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
                        'dry_run_enabled': config_data.get('dryRunEnabled', False),
                        'folder_count': folder_count,
                        'vault_name': vault_name,
                        'sync_identity': sync_identity,
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
        headers = ['Network UID', 'Title', 'Type', 'Enabled', 'Dry Run', 'Folders', 'Vault Name', 'Sync Identity']

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
                config['vault_name'],
                config['sync_identity']
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

            # Decrypt vault_name if present. The router stores it under the
            # 'vaultName' key as a base64-url string of the encrypted bytes.
            vault_name = 'N/A'
            vault_name_encrypted = config_data.get('vaultName')
            if vault_name_encrypted:
                try:
                    vault_name_bytes = crypto.decrypt_aes_v2(
                        utils.base64_url_decode(vault_name_encrypted), network.record_key)
                    vault_name = vault_name_bytes.decode('utf-8')
                except Exception as e:
                    logging.debug(f"Failed to decrypt vault_name for network {network.record_uid}: {e}")
                    vault_name = 'N/A'

            # Decrypt sync_identity if present. The router stores it under the
            # 'syncIdentity' key as a base64-url string of the encrypted bytes; the
            # decrypted value is the UID of the Identity record used for syncing.
            sync_identity = 'N/A'
            sync_identity_encrypted = config_data.get('syncIdentity')
            if sync_identity_encrypted:
                try:
                    sync_identity_bytes = crypto.decrypt_aes_v2(
                        utils.base64_url_decode(sync_identity_encrypted), network.record_key)
                    sync_identity_uid = sync_identity_bytes.decode('utf-8')
                    identity_record = vault.KeeperRecord.load(params, sync_identity_uid)
                    if identity_record and getattr(identity_record, 'title', None):
                        sync_identity = f'{identity_record.title} ({sync_identity_uid})'
                    else:
                        sync_identity = sync_identity_uid
                except Exception as e:
                    logging.debug(f"Failed to decrypt sync_identity for network {network.record_uid}: {e}")
                    sync_identity = 'N/A'

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
                'dry_run_enabled': config_data.get('dryRunEnabled', False),
                'vault_name': vault_name,
                'sync_identity': sync_identity,
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
                    folder_result['not_accessible'] = sync_data.get('notAccessible', False)
                    folder_result['error_message'] = sync_data.get('errorMessage')
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
            table.append(['Dry Run', 'Yes' if config_data.get('dryRunEnabled', False) else 'No'])
            table.append(['Vault Name', vault_name])
            table.append(['Sync Identity', sync_identity])
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

                    # On failure, surface the reason the gateway reported.
                    if sync_data and not sync_data.get('success', False):
                        if sync_data.get('notAccessible'):
                            table.append(['    Error', 'Folder not accessible to the gateway'])
                        elif sync_data.get('errorMessage'):
                            table.append(['    Error', sync_data.get('errorMessage')])
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

        # Use existing values if new values not provided
        enabled = kwargs.get('enabled')
        if enabled is not None:
            rq.enabled = enabled.lower() == 'true'
        elif 'enabled' in existing_config:
            rq.enabled = existing_config['enabled']

        dry_run = kwargs.get('dry_run')
        if dry_run is not None:
            rq.dryRunEnabled = dry_run.lower() == 'true'
        elif 'dryRunEnabled' in existing_config:
            rq.dryRunEnabled = existing_config['dryRunEnabled']

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

        # The router rebuilds the whole config object from the request, so any field
        # not re-sent is dropped. Preserve existing encrypted values when not provided.
        sync_identity = kwargs.get('sync_identity')
        if sync_identity:
            sync_identity_bytes = string_to_bytes(sync_identity)
            encrypted_sync_identity = crypto.encrypt_aes_v2(sync_identity_bytes, network.record_key)
            rq.syncIdentity = encrypted_sync_identity
        elif existing_config.get('syncIdentity'):
            rq.syncIdentity = utils.base64_url_decode(existing_config['syncIdentity'])

        vault_name = kwargs.get('vault_name')
        if vault_name:
            vault_name_bytes = string_to_bytes(vault_name)
            encrypted_vault_name = crypto.encrypt_aes_v2(vault_name_bytes, network.record_key)
            rq.vaultName = encrypted_vault_name
        elif existing_config.get('vaultName'):
            rq.vaultName = utils.base64_url_decode(existing_config['vaultName'])

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


class PAMUniversalSyncRunCommand(Command):
    parser = argparse.ArgumentParser(prog='pam universal-sync-run')
    parser.add_argument('--network', '-n', required=True, dest='network', action='store',
                        help='Network UID or name to run universal sync')

    def get_parser(self):
        return PAMUniversalSyncRunCommand.parser

    def execute(self, params, **kwargs):
        from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
        from .pam.config_helper import configuration_controller_get
        from .pam.router_helper import router_get_connected_gateways, print_router_response

        network_name = kwargs.get('network')
        if not network_name:
            raise CommandError('', f'{bcolors.FAIL}Network is required{bcolors.ENDC}')

        network = vault.KeeperRecord.load(params, network_name)
        if not network:
            raise CommandError('', f'{bcolors.FAIL}Network "{network_name}" not found{bcolors.ENDC}')

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

        action_inputs = GatewayActionUniversalSyncRunInputs(network_uid=network.record_uid)

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)

        conversation_id = GatewayAction.generate_conversation_id()

        try:
            router_response = router_send_action_to_gateway(
                params=params,
                gateway_action=GatewayActionUniversalSyncRun(inputs=action_inputs, conversation_id=conversation_id,
                                                              gateway_destination=gateway_uid),
                message_type=pam_pb2.CMT_USS,
                is_streaming=False,
                transmission_key=transmission_key,
                encrypted_transmission_key=encrypted_transmission_key,
                encrypted_session_token=encrypted_session_token
            )
        except Exception as e:
            raise CommandError('', f'{bcolors.FAIL}Error running universal sync: {e}{bcolors.ENDC}')

        if router_response is None:
            print(f'{bcolors.FAIL}The router returned a failure.{bcolors.ENDC}')
            return

        print_router_response(router_response, 'job_info', conversation_id, gateway_uid=gateway_uid)
        print(f"\nAfter action is finished, use: '{bcolors.OKGREEN}pam usc list -n {network.record_uid}{bcolors.ENDC}, to view sync results'")

