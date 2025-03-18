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
import asyncio
import fnmatch
import json
import logging
import os.path
import re
import queue
import sys
import threading
import time
from datetime import datetime
from typing import Dict, Optional, Any, Set, List


import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes, bytes_to_base64, base64_to_bytes

from .base import (Command, GroupCommand, user_choice, dump_report_data, report_output_parser, field_to_title,
                   FolderMixin, RecordMixin, register_pam_legacy_commands)
from .folder import FolderMoveCommand
from .ksm import KSMCommand
from .pam import gateway_helper, router_helper
from .pam.config_facades import PamConfigurationRecordFacade
from .pam.config_helper import configuration_controller_get, \
    pam_configurations_get_all, pam_configuration_remove, \
    pam_configuration_create_record_v6, record_rotation_get, \
    pam_decrypt_configuration_data

from .pam.pam_dto import (
    GatewayActionGatewayInfo,
    GatewayActionRotate,
    GatewayActionRotateInputs, GatewayAction, GatewayActionJobInfoInputs,
    GatewayActionJobInfo,
    GatewayActionJobCancel)

from .pam.router_helper import router_send_action_to_gateway, print_router_response, \
    router_get_connected_gateways, router_set_record_rotation_information, router_get_rotation_schedules, \
    get_router_url
from .record_edit import RecordEditMixin
from .tunnel.port_forward.endpoint import WebRTCConnection, TunnelEntrance, READ_TIMEOUT, \
    find_open_port, CloseConnectionReasons, SOCKS5Server, TunnelDAG, get_config_uid, MAIN_NONCE_LENGTH, \
    SYMMETRIC_KEY_LENGTH, get_keeper_tokens
from .. import api, utils, vault_extensions, crypto, vault, record_management, attachment, record_facades
from ..display import bcolors
from ..error import CommandError, KeeperApiError
from ..params import KeeperParams, LAST_RECORD_UID
from ..proto import pam_pb2, router_pb2, record_pb2
from ..subfolder import find_folders, find_parent_top_folder, \
    try_resolve_path, BaseFolderNode
from ..vault import TypedField
from ..discovery_common.record_link import RecordLink
from .discover.job_start import PAMGatewayActionDiscoverJobStartCommand
from .discover.job_status import PAMGatewayActionDiscoverJobStatusCommand
from .discover.job_remove import PAMGatewayActionDiscoverJobRemoveCommand
from .discover.result_process import PAMGatewayActionDiscoverResultProcessCommand
from .discover.rule_add import PAMGatewayActionDiscoverRuleAddCommand
from .discover.rule_list import PAMGatewayActionDiscoverRuleListCommand
from .discover.rule_remove import PAMGatewayActionDiscoverRuleRemoveCommand
from .discover.rule_update import PAMGatewayActionDiscoverRuleUpdateCommand
from .pam_debug.acl import PAMDebugACLCommand
from .pam_debug.graph import PAMDebugGraphCommand
from .pam_debug.info import PAMDebugInfoCommand
from .pam_debug.gateway import PAMDebugGatewayCommand
from .pam_service.list import PAMActionServiceListCommand
from .pam_service.add import PAMActionServiceAddCommand
from .pam_service.remove import PAMActionServiceRemoveCommand
from .pam_saas.add import PAMActionSaasAddCommand
from .pam_saas.info import PAMActionSaasInfoCommand
from .pam_saas.remove import PAMActionSaasRemoveCommand
from .pam_saas.config import PAMActionSaasConfigCommand


def register_commands(commands):
    commands['pam'] = PAMControllerCommand()


def register_command_info(_, command_info):
    command_info['pam'] = 'Manage PAM Components.'


class PAMControllerCommand(GroupCommand):

    def __init__(self):
        super(PAMControllerCommand, self).__init__()
        self.register_command('gateway', PAMGatewayCommand(), 'Manage Gateways', 'g')
        self.register_command('config', PAMConfigurationsCommand(), 'Manage PAM Configurations', 'c')
        self.register_command('rotation', PAMRotationCommand(), 'Manage Rotations', 'r')
        self.register_command('action', GatewayActionCommand(), 'Execute action on the Gateway', 'a')
        self.register_command('tunnel', PAMTunnelCommand(), 'Manage Tunnels', 't')
        self.register_command('split', PAMSplitCommand(), 'Split credentials from legacy PAM Machine', 's')
        self.register_command('legacy', PAMLegacyCommand(), 'Switch to legacy PAM commands')
        self.register_command('connection', PAMConnectionCommand(), 'Manage Connections', 'n')


class PAMGatewayCommand(GroupCommand):

    def __init__(self):
        super(PAMGatewayCommand, self).__init__()
        self.register_command('list', PAMGatewayListCommand(), 'List Gateways', 'l')
        self.register_command('new', PAMCreateGatewayCommand(), 'Create new Gateway', 'n')
        self.register_command('remove', PAMGatewayRemoveCommand(), 'Remove Gateway', 'rm')
        # self.register_command('connect', PAMConnect(), 'Connect')
        # self.register_command('disconnect', PAMDisconnect(), 'Disconnect')
        self.default_verb = 'list'


class PAMTunnelCommand(GroupCommand):

    def __init__(self):
        super(PAMTunnelCommand, self).__init__()
        self.register_command('start', PAMTunnelStartCommand(), 'Start Tunnel', 's')
        self.register_command('list', PAMTunnelListCommand(), 'List all Tunnels', 'l')
        self.register_command('stop', PAMTunnelStopCommand(), 'Stop Tunnel to the server', 'x')
        self.register_command('tail', PAMTunnelTailCommand(), 'View Tunnel Log', 't')
        self.register_command('edit', PAMTunnelEditCommand(), 'Edit Tunnel settings', 'e')
        self.default_verb = 'list'


class PAMConnectionCommand(GroupCommand):

    def __init__(self):
        super(PAMConnectionCommand, self).__init__()
        # self.register_command('start', PAMConnectionStartCommand(), 'Start Connection', 's')
        # self.register_command('stop', PAMConnectionStopCommand(), 'Stop Connection', 'x')
        self.register_command('edit', PAMConnectionEditCommand(), 'Edit Connection settings', 'e')
        self.default_verb = 'edit'


class PAMConfigurationsCommand(GroupCommand):

    def __init__(self):
        super(PAMConfigurationsCommand, self).__init__()
        self.register_command('new', PAMConfigurationNewCommand(), "Create new PAM Configuration", 'n')
        self.register_command('edit', PAMConfigurationEditCommand(), "Edit PAM Configuration", 'e')
        self.register_command('list', PAMConfigurationListCommand(),
                              'List available PAM Configurations associated with the Gateway', 'l')
        self.register_command('remove', PAMConfigurationRemoveCommand(), "Remove a PAM Configuration", 'rm')
        self.default_verb = 'list'


class PAMRotationCommand(GroupCommand):

    def __init__(self):
        super(PAMRotationCommand, self).__init__()
        self.register_command('edit',  PAMCreateRecordRotationCommand(), 'Edits Record Rotation configuration', 'new')
        self.register_command('list', PAMListRecordRotationCommand(), 'List Record Rotation configuration', 'l')
        self.register_command('info', PAMRouterGetRotationInfo(), 'Get Rotation Info', 'i')
        self.register_command('script', PAMRouterScriptCommand(), 'Add, delete, or edit script field')
        self.default_verb = 'list'


class PAMDiscoveryCommand(GroupCommand):

    def __init__(self):
        super(PAMDiscoveryCommand, self).__init__()
        self.register_command('start', PAMGatewayActionDiscoverJobStartCommand(), 'Start a discovery process', 's')
        self.register_command('status', PAMGatewayActionDiscoverJobStatusCommand(), 'Status of discovery jobs', 'st')
        self.register_command('remove', PAMGatewayActionDiscoverJobRemoveCommand(), 'Cancel or remove of discovery jobs', 'r')
        self.register_command('process', PAMGatewayActionDiscoverResultProcessCommand(), 'Process discovered items', 'p')
        self.register_command('rule', PAMDiscoveryRuleCommand(), 'Manage discovery rules')

        self.default_verb = 'status'


class PAMDiscoveryRuleCommand(GroupCommand):

    def __init__(self):
        super(PAMDiscoveryRuleCommand, self).__init__()
        self.register_command('add', PAMGatewayActionDiscoverRuleAddCommand(), 'Add a rule', 'a')
        self.register_command('list', PAMGatewayActionDiscoverRuleListCommand(), 'List all rules', 'l')
        self.register_command('remove', PAMGatewayActionDiscoverRuleRemoveCommand(), 'Remove a rule', 'r')
        self.register_command('update', PAMGatewayActionDiscoverRuleUpdateCommand(), 'Update a rule', 'u')
        self.default_verb = 'list'


class PAMActionServiceCommand(GroupCommand):

    def __init__(self):
        super(PAMActionServiceCommand, self).__init__()
        self.register_command('list', PAMActionServiceListCommand(),
                              'List all mappings', 'l')
        self.register_command('add', PAMActionServiceAddCommand(),
                              'Add a user and machine to the mapping', 'a')
        self.register_command('remove', PAMActionServiceRemoveCommand(),
                              'Remove a user and machine from the mapping', 'r')
        self.default_verb = 'list'


class PAMActionSaasCommand(GroupCommand):

    def __init__(self):
        super(PAMActionSaasCommand, self).__init__()
        self.register_command('info', PAMActionSaasInfoCommand(),
                              'Information of SaaS service rotation for a PAM User record.', 'i')
        self.register_command('add', PAMActionSaasAddCommand(),
                              'Add a SaaS rotation to a PAM User record.', 'a')
        self.register_command('remove', PAMActionSaasRemoveCommand(),
                              'Remove a SaaS rotation from a PAM User record', 'r')
        self.register_command('config', PAMActionSaasConfigCommand(),
                              'Create a configuration for a SaaS rotation.', 'c')


class GatewayActionCommand(GroupCommand):

    def __init__(self):
        super(GatewayActionCommand, self).__init__()
        self.register_command('gateway-info', PAMGatewayActionServerInfoCommand(), 'Info command', 'i')
        self.register_command('discover', PAMDiscoveryCommand(), 'Discover command', 'd')
        self.register_command('rotate', PAMGatewayActionRotateCommand(), 'Rotate command', 'r')
        self.register_command('job-info', PAMGatewayActionJobCommand(), 'View Job details', 'ji')
        self.register_command('job-cancel', PAMGatewayActionJobCommand(), 'View Job details', 'jc')
        self.register_command('service', PAMActionServiceCommand(),
                              'Manage services and scheduled tasks user mappings.', 's')
        self.register_command('saas', PAMActionSaasCommand(),
                              'Manage user SaaS rotations.', 'sa')
        self.register_command('debug', PAMDebugCommand(), 'PAM debug information')

        # self.register_command('job-list', DRCmdListJobs(), 'List Running jobs')


class PAMDebugCommand(GroupCommand):

    def __init__(self):
        super(PAMDebugCommand, self).__init__()
        self.register_command('info', PAMDebugInfoCommand(), 'Debug a record', 'i')
        self.register_command('gateway', PAMDebugGatewayCommand(), 'Debug a getway', 'g')
        self.register_command('graph', PAMDebugGraphCommand(), 'Render graphs', 'r')

        # Disable for now. Needs more work.
        # self.register_command('verify', PAMDebugVerifyCommand(), 'Verify graphs', 'v')
        self.register_command('acl', PAMDebugACLCommand(), 'Control ACL of PAM Users', 'c')


class PAMLegacyCommand(Command):
    parser = argparse.ArgumentParser(prog='pam legacy', description="Switch to using obsolete PAM commands")

    def get_parser(self):
        return PAMLegacyCommand.parser

    def execute(self, params, **kwargs):
        register_pam_legacy_commands()


class PAMCmdListJobs(Command):
    parser = argparse.ArgumentParser(prog='pam action job-list')
    parser.add_argument('--jobId', '-j', required=False, dest='job_id', action='store', help='ID of the Job running')

    def get_parser(self):
        return PAMCmdListJobs.parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            logging.warning(f'Connection doesn\'t exist. Please connect to the router before executing '
                            f'commands using following command {bcolors.OKGREEN}dr connect{bcolors.ENDC}')

            return

        destinations = kwargs.get('destinations', [])

        action = kwargs.get('action', [])

        command_payload = {
            'action': action,
            # 'args': command_arr[1:] if len(command_arr) > 1 else []
            'kwargs': kwargs
        }

        params.ws.send(command_payload, destinations)


class PAMCreateRecordRotationCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotation edit')
    record_group = parser.add_mutually_exclusive_group(required=True)
    record_group.add_argument('--record', '-r', dest='record_name', action='store',
                              help='Record UID, name, or pattern to be rotated manually or via schedule')
    record_group.add_argument('--folder', '-fd', dest='folder_name', action='store',
                              help='Used for bulk rotation setup. The folder UID or name that holds records to be '
                                   'configured')
    parser.add_argument('--force', '-f', dest='force', action='store_true', help='Do not ask for confirmation')
    parser.add_argument('--config', '-c', required=False, dest='config', action='store',
                        help='UID or path of the configuration record.')
    parser.add_argument('--iam-aad-config', '-iac', dest='iam_aad_config_uid', action='store',
                        help='UID of a PAM Configuration. Used for an IAM or Azure AD user in place of --resource.')
    parser.add_argument('--resource', '-rs', dest='resource', action='store', help='UID or path of the resource record.')
    schedule_group = parser.add_mutually_exclusive_group()
    schedule_group.add_argument('--schedulejson', '-sj', required=False, dest='schedule_json_data',
                                action='append', help='JSON of the scheduler. Example: -sj \'{"type": "WEEKLY", '
                                                      '"utcTime": "15:44", "weekday": "SUNDAY", "intervalCount": 1}\'')
    schedule_group.add_argument('--schedulecron', '-sc', required=False, dest='schedule_cron_data',
                                action='append', help='Cron tab string of the scheduler. Example: to run job daily at '
                                                      '5:56PM UTC enter following cron -sc "56 17 * * *"')
    schedule_group.add_argument('--on-demand', '-od', required=False, dest='on_demand',
                                action='store_true', help='Schedule On Demand')
    schedule_group.add_argument('--schedule-config', '-sf', required=False, dest='schedule_config',
                                action='store_true', help='Schedule from Configuration')
    parser.add_argument('--complexity',   '-x',  required=False, dest='pwd_complexity', action='store',
                        help='Password complexity: length, upper, lower, digits, symbols. Ex. 32,5,5,5,5')
    parser.add_argument('--admin-user', '-a', required=False, dest='admin', action='store',
                        help='UID or path for the PAMUser record to configure the admin credential on the PAM Resource as the Admin when rotating')
    state_group = parser.add_mutually_exclusive_group()
    state_group.add_argument('--enable', '-e', dest='enable', action='store_true', help='Enable rotation')
    state_group.add_argument('--disable', '-d', dest='disable', action='store_true', help='Disable rotation')

    def get_parser(self):
        return PAMCreateRecordRotationCommand.parser

    def execute(self, params, **kwargs):
        record_uids = set()   # type: Set[str]

        folder_uids = set()
        record_pattern = ''
        record_name = kwargs.get('record_name')

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        if record_name:
            if record_name in params.record_cache:
                record_uids.add(record_name)
            else:
                rs = try_resolve_path(params, record_name, find_all_matches=True)
                if rs is not None:
                    folder, record_title = rs
                    if record_title:
                        record_pattern = record_title
                        if isinstance(folder, BaseFolderNode):
                            folder_uids.add(folder.uid)
                        elif isinstance(folder, list):
                            for f in folder:
                                if isinstance(f, BaseFolderNode):
                                    folder_uids.add(f.uid)
                    else:
                        logging.warning('Record \"%s\" not found. Skipping.', record_name)

        folder_name = kwargs.get('folder_name')
        if folder_name:
            if folder_name in params.folder_cache:
                folder_uids.add(folder_name)
            else:
                rs = try_resolve_path(params, folder_name, find_all_matches=True)
                if rs is not None:
                    folder, record_title = rs
                    if not record_title:

                        def add_folders(sub_folder):   # type: (BaseFolderNode) -> None
                            folder_uids.add(sub_folder.uid or '')

                        if isinstance(folder, BaseFolderNode):
                            folder = [folder]
                        if isinstance(folder, list):
                            for f in folder:
                                FolderMixin.traverse_folder_tree(params, f.uid, add_folders)
                    else:
                        logging.warning('Folder \"%s\" not found. Skipping.', folder_name)

        if record_name and folder_name:
            raise CommandError('', 'Cannot use both --record and --folder at the same time.')

        if folder_uids:
            regex = re.compile(fnmatch.translate(record_pattern), re.IGNORECASE).match if record_pattern else None
            for folder_uid in folder_uids:
                folder_records = params.subfolder_record_cache.get(folder_uid)
                if not folder_records:
                    continue
                if record_pattern and record_pattern in folder_records:
                    record_uids.add(record_pattern)
                else:
                    for record_uid in folder_records:
                        if record_uid not in record_uids:
                            r = vault.KeeperRecord.load(params, record_uid)
                            if r:
                                if regex and not regex(r.title):
                                    continue
                                record_uids.add(record_uid)

        pam_records = []    # type: List[vault.TypedRecord]
        valid_record_types = ['pamDatabase', 'pamDirectory', 'pamMachine', 'pamUser', 'pamRemoteBrowser']
        for record_uid in record_uids:
            record = vault.KeeperRecord.load(params, record_uid)
            if record and isinstance(record, vault.TypedRecord) and record.record_type in valid_record_types:
                pam_records.append(record)

        if len(pam_records) == 0:
            rts = ', '.join(valid_record_types)
            raise CommandError('', f'No PAM record is found. Valid PAM record types: {rts}')
        else:
            logging.info('Selected %d PAM record(s) for rotation', len(pam_records))

        pam_configurations = {x.record_uid: x for x in vault_extensions.find_records(params, record_version=6) if isinstance(x, vault.TypedRecord)}

        config_uid = kwargs.get('config')
        cfg_rec = RecordMixin.resolve_single_record(params, kwargs.get('config', None))
        if cfg_rec and cfg_rec.version == 6 and cfg_rec.record_uid in pam_configurations:
            config_uid = cfg_rec.record_uid

        pam_config = None   # type: Optional[vault.TypedRecord]
        if config_uid:
            if config_uid in pam_configurations:
                pam_config = pam_configurations[config_uid]
            else:
                raise CommandError('', f'Record uid {config_uid} is not a PAM Configuration record.')

        schedule_json_data = kwargs.get('schedule_json_data')
        schedule_cron_data = kwargs.get('schedule_cron_data')    # See this page for more details: http://www.quartz-scheduler.org/documentation/quartz-2.3.0/tutorials/crontrigger.html#examples
        schedule_on_demand = kwargs.get('on_demand') is True
        schedule_config = kwargs.get('schedule_config') is True
        schedule_data = None   # type: Optional[List]
        if isinstance(schedule_json_data, list):
            schedule_data = [json.loads(x) for x in schedule_json_data]
        elif isinstance(schedule_cron_data, list):
            schedule_data = []
            for cron in schedule_cron_data:
                comps = [x.strip() for x in cron.split(' ')]
                if len(comps) != 5:
                    raise CommandError('', f'Cron value is expected to have 5 components: minute hour day_of_month month day_of_week')
                schedule_data.append(TypedField.import_schedule_field(cron))
        elif schedule_on_demand is True:
            schedule_data = []

        pwd_complexity = kwargs.get("pwd_complexity")
        pwd_complexity_rule_list = None     # type: Optional[dict]
        if pwd_complexity is not None:
            if pwd_complexity:
                pwd_complexity_list = [s.strip() for s in pwd_complexity.split(',')]
                if len(pwd_complexity_list) != 5 or not all(n.isnumeric() for n in pwd_complexity_list):
                    raise CommandError('', 'Invalid rules to generate password. Format is "length, upper, lower, digits, symbols". Ex: 32,5,5,5,5')
                pwd_complexity_rule_list = {
                    'length': int(pwd_complexity_list[0]),
                    'caps': int(pwd_complexity_list[1]),
                    'lowercase': int(pwd_complexity_list[2]),
                    'digits': int(pwd_complexity_list[3]),
                    'special': int(pwd_complexity_list[4])
                }
            else:
                pwd_complexity_rule_list = {}

        resource_uid = kwargs.get('resource')
        res_rec = RecordMixin.resolve_single_record(params, kwargs.get('resource', None))
        if res_rec and isinstance(res_rec, vault.TypedRecord):
            resource_uid = res_rec.record_uid

        skipped_header = ['record_uid', 'record_title', 'problem', 'description']
        skipped_records = []
        valid_header = ['record_uid', 'record_title', 'enabled', 'configuration_uid', 'resource_uid', 'schedule', 'complexity']
        valid_records = []

        r_requests = []   # type: List[router_pb2.RouterRecordRotationRequest]

        def config_resource(_dag, target_record, target_config_uid):
            if not _dag.linking_dag.has_graph:
                # Add DAG for resource
                if target_config_uid:
                    _dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, target_config_uid)
                    _dag.edit_tunneling_config(rotation=True)
                else:
                    raise CommandError('', f'{bcolors.FAIL}Resource "{target_record.record_uid}" is not associated '
                                           f'with any configuration. '
                                           f'{bcolors.OKBLUE}pam rotation edit -rs {target_record.record_uid} '
                                           f'--config CONFIG{bcolors.ENDC}')
            resource_dag = None
            if not _dag.resource_belongs_to_config(target_record.record_uid):
                # Change DAG to this new configuration.
                resource_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key,
                                             target_record.record_uid)
                _dag.link_resource_to_config(target_record.record_uid)

            admin = kwargs.get('admin')
            adm_rec = RecordMixin.resolve_single_record(params, kwargs.get('admin', None))
            if adm_rec and isinstance(adm_rec, vault.TypedRecord):
                admin = adm_rec.record_uid

            if admin and target_record.record_type != 'pamRemoteBrowser':
                _dag.link_user_to_resource(admin, target_record.record_uid, is_admin=True)

            _rotation_enabled = True if kwargs.get('enable') else False if kwargs.get('disable') else None

            if _rotation_enabled is not None:
                _dag.set_resource_allowed(target_record, rotation=_rotation_enabled,
                                                    allowed_settings_name="rotation")

            if resource_dag is not None and resource_dag.linking_dag.has_graph:
                # TODO: Make sure this doesn't remove everything from the new dag too
                resource_dag.remove_from_dag(target_record.record_uid)

            _dag.print_tunneling_config(target_record .record_uid, config_uid=target_config_uid)

        def config_iam_aad_user(_dag, target_record, target_iam_aad_config_uid):
            if _dag and not _dag.linking_dag.has_graph:
                _dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, target_iam_aad_config_uid)
                if not _dag or not _dag.linking_dag.has_graph:
                    _dag.edit_tunneling_config(rotation=True)
            old_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, target_record.record_uid)
            if old_dag.linking_dag.has_graph and old_dag.record.record_uid != target_iam_aad_config_uid:
                old_dag.remove_from_dag(target_record.record_uid)

            # with IAM users the user is at the level the resource is usually at,
            if not _dag.user_belongs_to_config(target_record.record_uid):
                old_resource_uid = _dag.get_resource_uid(target_record.record_uid)
                if old_resource_uid is not None:
                    print(
                        f'{bcolors.WARNING}User "{target_record.record_uid}" is associated with another resource: '
                        f'{old_resource_uid}. '
                        f'Now moving it to {target_iam_aad_config_uid} and it will no longer be rotated on {old_resource_uid}.'
                        f'{bcolors.ENDC}')
                    if old_resource_uid == _dag.record.record_uid:
                        _dag.unlink_user_from_resource(target_record.record_uid)
                    _dag.link_user_to_resource(target_record.record_uid, old_resource_uid, belongs_to=False)
                _dag.link_user_to_config(target_record.record_uid)


            current_record_rotation = params.record_rotation_cache.get(target_record.record_uid)

            # 1. PAM Configuration UID
            record_config_uid = _dag.record.record_uid
            record_pam_config = pam_config
            if not record_config_uid:
                if current_record_rotation:
                    record_config_uid = current_record_rotation.get('configuration_uid')
                    pc = vault.KeeperRecord.load(params, record_config_uid)
                    if pc is None:
                        skipped_records.append([target_record.record_uid, target_record.title, 'PAM Configuration was deleted',
                                                'Specify a configuration UID parameter [--config]'])
                        return
                    if not isinstance(pc, vault.TypedRecord) or pc.version != 6:
                        skipped_records.append([target_record.record_uid, target_record.title, 'PAM Configuration is invalid',
                                                'Specify a configuration UID parameter [--config]'])
                        return
                    record_pam_config = pc
                else:
                    skipped_records.append([target_record.record_uid, target_record.title, 'No current PAM Configuration',
                                            'Specify a configuration UID parameter [--config]'])
                    return

            # 2. Schedule
            record_schedule_data = schedule_data
            if record_schedule_data is None:
                if current_record_rotation and not schedule_config:
                    try:
                        current_schedule = current_record_rotation.get('schedule')
                        if current_schedule:
                            record_schedule_data = json.loads(current_schedule)
                    except:
                        pass
                else:
                    schedule_field = record_pam_config.get_typed_field('schedule', 'defaultRotationSchedule')
                    if schedule_field and isinstance(schedule_field.value, list) and len(schedule_field.value) > 0:
                        if isinstance(schedule_field.value[0], dict):
                            record_schedule_data = [schedule_field.value[0]]

            # 3. Password complexity
            if pwd_complexity_rule_list is None:
                if current_record_rotation:
                    pwd_complexity_rule_list_encrypted = utils.base64_url_decode(current_record_rotation['pwd_complexity'])
                else:
                    pwd_complexity_rule_list_encrypted = b''
            else:
                if len(pwd_complexity_rule_list) > 0:
                    pwd_complexity_rule_list_encrypted = router_helper.encrypt_pwd_complexity(pwd_complexity_rule_list,
                                                                                              record.record_key)
                else:
                    pwd_complexity_rule_list_encrypted = b''

            # 4. Resource record
            record_resource_uid = iam_aad_config_uid
            if record_resource_uid is None:
                if current_record_rotation:
                    record_resource_uid = current_record_rotation.get('resourceUid')
            if record_resource_uid is None:
                resource_field = record_pam_config.get_typed_field('pamResources')
                if resource_field and isinstance(resource_field.value, list) and len(resource_field.value) > 0:
                    resources = resource_field.value[0]
                    if isinstance(resources, dict):
                        resource_uids = resources.get('resourceRef')
                        if isinstance(resource_uids, list) and len(resource_uids) > 0:
                            if len(resource_uids) == 1:
                                record_resource_uid = resource_uids[0]
                            else:
                                skipped_records.append([target_record.record_uid, target_record.title,
                                                        f'PAM Configuration: {len(resource_uids)} admin resources',
                                                        'Specify both configuration UID and resource UID  [--config, --resource]'])
                                return

            disabled = False
            # 5. Enable rotation
            if kwargs.get('enable'):
                _dag.set_resource_allowed(iam_aad_config_uid, rotation=True, is_config=bool(target_iam_aad_config_uid))
            elif kwargs.get('disable'):
                _dag.set_resource_allowed(iam_aad_config_uid, rotation=False, is_config=bool(target_iam_aad_config_uid))
                disabled = True

            schedule = 'On-Demand'
            if isinstance(record_schedule_data, list) and len(record_schedule_data) > 0:
                if isinstance(record_schedule_data[0], dict):
                    schedule = record_schedule_data[0].get('type')
            complexity = ''
            if pwd_complexity_rule_list_encrypted:
                try:
                    decrypted_complexity = crypto.decrypt_aes_v2(pwd_complexity_rule_list_encrypted, target_record.record_key)
                    c = json.loads(decrypted_complexity.decode())
                    complexity = f"{c.get('length', 0)},{c.get('caps', 0)},{c.get('lowercase', 0)},{c.get('digits', 0)},{c.get('special', 0)}"
                except:
                    pass
            valid_records.append(
                [target_record.record_uid, target_record.title, not disabled, record_config_uid, record_resource_uid, schedule,
                 complexity])

            # 6. Construct Request object
            rq = router_pb2.RouterRecordRotationRequest()
            if current_record_rotation:
                rq.revision = current_record_rotation.get('revision', 0)
            rq.recordUid = utils.base64_url_decode(target_record.record_uid)
            rq.configurationUid = utils.base64_url_decode(record_config_uid)
            rq.resourceUid = utils.base64_url_decode(record_resource_uid) if record_resource_uid else b''
            rq.schedule = json.dumps(record_schedule_data) if record_schedule_data else ''
            rq.pwdComplexity = pwd_complexity_rule_list_encrypted
            rq.disabled = disabled
            r_requests.append(rq)

        def config_user(_dag, target_record, target_resource_uid, target_config_uid=None):

            # NOOP rotation
            noop_rotation = str(kwargs.get('noop', False) or False).upper() == 'TRUE'
            if target_record and not noop_rotation:  # check from record data
                noop_field = target_record.get_typed_field('text', 'NOOP')
                if (noop_field and noop_field.value and
                        isinstance(noop_field.value, list) and
                        str(noop_field.value[0]).upper() == 'TRUE'):
                    noop_rotation = True
                    # script_field = target_record.get_typed_field('script', 'rotationScripts')
                    # if script_field and isinstance(script_field.value, list) and len(script_field.value) > 0:
                    #     record_refs = [x.get('recordRef')[0] for x in script_field.value if isinstance(x, dict) and x.get('recordRef', [])]
                    #     if record_refs:
                    #         logging.warning(f'Record "{target_record.record_uid}" is set for NOOP rotation '
                    #                         f'but rotation scripts reference some recordRef: {record_refs}')

            if _dag and _dag.linking_dag:
                admin_record_uids = _dag.get_all_admins()
                if folder_name and target_record.record_uid in admin_record_uids:
                    # If iterating through a folder, skip admin records
                    skipped_records.append([target_record.record_uid, target_record.title, 'Admin Credential',
                                            'This record is used as Admin credentials on a PAM Configuration. Skipped'])
                    return

            if isinstance(target_resource_uid, str) and len(target_resource_uid) > 0:
                _dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, target_resource_uid)
                if not _dag or not _dag.linking_dag.has_graph:
                    if target_config_uid and target_resource_uid:
                        config_resource(_dag, target_record, target_config_uid)
                    if not _dag or not _dag.linking_dag.has_graph:
                        raise CommandError('', f'{bcolors.FAIL}Resource "{target_resource_uid}" is not associated '
                                               f'with any configuration. '
                                               f'{bcolors.OKBLUE}pam rotation edit -rs {target_resource_uid} '
                                               f'--config CONFIG{bcolors.ENDC}')

                if not _dag.check_if_resource_has_admin(target_resource_uid):
                    raise CommandError('', f'PAM Resource "{target_resource_uid}'" does not have "
                                           "admin credentials. Please link an admin credential to this resource. "
                                           f"{bcolors.OKBLUE}pam rotation edit -rs {target_resource_uid} "
                                           f"--admin-user ADMIN{bcolors.ENDC}")
            current_record_rotation = params.record_rotation_cache.get(target_record.record_uid)

            if not _dag or not _dag.linking_dag.has_graph:
                _dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, target_resource_uid)
                if not _dag.linking_dag.has_graph:
                    raise CommandError('', f'{bcolors.FAIL}Resource "{target_resource_uid}" is not associated '
                                           f'with any configuration.'
                                           f'{bcolors.OKBLUE}pam rotation edit -rs {target_resource_uid} '
                                           f'--config CONFIG{bcolors.ENDC}')
            # Noop and resource cannot be both assigned
            if noop_rotation:
                target_resource_uid = target_record.record_uid
                record_resource_uid = None
            else:
                if not target_resource_uid:
                    # Get the resource configuration from DAG
                    resource_uids = _dag.get_all_owners(target_record.record_uid)
                    if len(resource_uids) > 1:
                        raise CommandError('', f'{bcolors.FAIL}Record "{target_record.record_uid}" is '
                                            f'associated with multiple resources so you must supply '
                                            f'{bcolors.OKBLUE}"--resource/-rs RESOURCE".{bcolors.ENDC}')
                    elif len(resource_uids) == 0:
                        raise CommandError('',
                                        f'{bcolors.FAIL}Record "{target_record.record_uid}" is not associated with'
                                        f' any resource. Please use {bcolors.OKBLUE}"pam rotation user '
                                        f'{target_record.record_uid} --resource RESOURCE" {bcolors.FAIL}to associate '
                                        f'it.{bcolors.ENDC}')
                    target_resource_uid = resource_uids[0]

                if not _dag.resource_belongs_to_config(target_resource_uid):
                    raise CommandError('',
                                    f'{bcolors.FAIL}Resource "{target_resource_uid}" is not associated with the '
                                    f'configuration of the user "{target_record.record_uid}". To associated the resources '
                                    f'to this config run {bcolors.OKBLUE}"pam rotation resource {target_resource_uid} '
                                    f'--config {_dag.record.record_uid}"{bcolors.ENDC}')
                if not _dag.user_belongs_to_resource(target_record.record_uid, target_resource_uid):
                    old_resource_uid = _dag.get_resource_uid(target_record.record_uid)
                    if old_resource_uid is not None and old_resource_uid != target_resource_uid:
                        print(
                            f'{bcolors.WARNING}User "{target_record.record_uid}" is associated with another resource: '
                            f'{old_resource_uid}. '
                            f'Now moving it to {target_resource_uid} and it will no longer be rotated on {old_resource_uid}.'
                            f'{bcolors.ENDC}')
                        _dag.link_user_to_resource(target_record.record_uid, old_resource_uid, belongs_to=False)
                    _dag.link_user_to_resource(target_record.record_uid, target_resource_uid, belongs_to=True)

            # 1. PAM Configuration UID
            record_config_uid = _dag.record.record_uid
            record_pam_config = pam_config
            if not record_config_uid:
                if current_record_rotation:
                    record_config_uid = current_record_rotation.get('configuration_uid')
                    pc = vault.KeeperRecord.load(params, record_config_uid)
                    if pc is None:
                        skipped_records.append([target_record.record_uid, target_record.title, 'PAM Configuration was deleted',
                                                'Specify a configuration UID parameter [--config]'])
                        return
                    if not isinstance(pc, vault.TypedRecord) or pc.version != 6:
                        skipped_records.append([target_record.record_uid, target_record.title, 'PAM Configuration is invalid',
                                                'Specify a configuration UID parameter [--config]'])
                        return
                    record_pam_config = pc
                else:
                    skipped_records.append([target_record.record_uid, target_record.title, 'No current PAM Configuration',
                                            'Specify a configuration UID parameter [--config]'])
                    return

            # 2. Schedule
            record_schedule_data = schedule_data
            if record_schedule_data is None:
                if current_record_rotation:
                    try:
                        current_schedule = current_record_rotation.get('schedule')
                        if current_schedule:
                            record_schedule_data = json.loads(current_schedule)
                    except:
                        pass
                elif record_pam_config:
                    schedule_field = record_pam_config.get_typed_field('schedule', 'defaultRotationSchedule')
                    if schedule_field and isinstance(schedule_field.value, list) and len(schedule_field.value) > 0:
                        if isinstance(schedule_field.value[0], dict):
                            record_schedule_data = [schedule_field.value[0]]
                else:
                    record_schedule_data = []

            # 3. Password complexity
            if pwd_complexity_rule_list is None:
                if current_record_rotation:
                    pwd_complexity_rule_list_encrypted = utils.base64_url_decode(current_record_rotation['pwd_complexity'])
                else:
                    pwd_complexity_rule_list_encrypted = b''
            else:
                if len(pwd_complexity_rule_list) > 0:
                    pwd_complexity_rule_list_encrypted = router_helper.encrypt_pwd_complexity(pwd_complexity_rule_list,
                                                                                              record.record_key)
                else:
                    pwd_complexity_rule_list_encrypted = b''

            # 4. Resource record
            # Noop and resource cannot be both assigned
            if not noop_rotation:
                record_resource_uid = target_resource_uid
                if record_resource_uid is None:
                    if current_record_rotation:
                        record_resource_uid = current_record_rotation.get('resourceUid')
                if record_resource_uid is None:
                    resource_field = record_pam_config.get_typed_field('pamResources')
                    if resource_field and isinstance(resource_field.value, list) and len(resource_field.value) > 0:
                        resources = resource_field.value[0]
                        if isinstance(resources, dict):
                            resource_uids = resources.get('resourceRef')
                            if isinstance(resource_uids, list) and len(resource_uids) > 0:
                                if len(resource_uids) == 1:
                                    record_resource_uid = resource_uids[0]
                                else:
                                    skipped_records.append([target_record.record_uid, target_record.title,
                                                            f'PAM Configuration: {len(resource_uids)} admin resources',
                                                            'Specify both configuration UID and resource UID  [--config, --resource]'])
                                    return

            disabled = False
            # 5. Enable rotation
            if kwargs.get('enable'):
                _dag.set_resource_allowed(target_resource_uid, rotation=True)
            elif kwargs.get('disable'):
                _dag.set_resource_allowed(target_resource_uid, rotation=False)
                disabled = True

            schedule = 'On-Demand'
            if isinstance(record_schedule_data, list) and len(record_schedule_data) > 0:
                if isinstance(record_schedule_data[0], dict):
                    schedule = record_schedule_data[0].get('type')
            complexity = ''
            if pwd_complexity_rule_list_encrypted:
                try:
                    decrypted_complexity = crypto.decrypt_aes_v2(pwd_complexity_rule_list_encrypted, target_record.record_key)
                    c = json.loads(decrypted_complexity.decode())
                    complexity = f"{c.get('length', 0)},{c.get('caps', 0)},{c.get('lowercase', 0)},{c.get('digits', 0)},{c.get('special', 0)}"
                except:
                    pass
            valid_records.append(
                [target_record.record_uid, target_record.title, not disabled, record_config_uid, record_resource_uid, schedule,
                 complexity])

            # 6. Construct Request object
            rq = router_pb2.RouterRecordRotationRequest()
            if current_record_rotation:
                rq.revision = current_record_rotation.get('revision', 0)
            rq.recordUid = utils.base64_url_decode(target_record.record_uid)
            rq.configurationUid = utils.base64_url_decode(record_config_uid)
            rq.resourceUid = utils.base64_url_decode(record_resource_uid) if record_resource_uid else b''
            rq.schedule = json.dumps(record_schedule_data) if record_schedule_data else ''
            rq.pwdComplexity = pwd_complexity_rule_list_encrypted
            rq.disabled = disabled
            if noop_rotation:
                rq.noop = True
                rq.resourceUid = b''  # Noop and resource cannot be both assigned
            r_requests.append(rq)

        for _record in pam_records:
            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, _record.record_uid)
            if _record.record_type in ['pamMachine', 'pamDatabase', 'pamDirectory', 'pamRemoteBrowser']:
                config_resource(tmp_dag, _record, config_uid)
            elif _record.record_type == 'pamUser':
                iam_aad_config_uid = kwargs.get('iam_aad_config_uid')

                if iam_aad_config_uid and iam_aad_config_uid not in pam_configurations:
                    raise CommandError('', f'Record uid {iam_aad_config_uid} is not a PAM Configuration record.')

                if resource_uid and iam_aad_config_uid:
                    raise CommandError('', f'Cannot use both --resource and --iam-aad-config_uid at once.'
                                           f' --resource is used to configure users found on a resource.'
                                           f' --iam-aad-config-uid is used to configure AWS IAM or Azure AD users')

                if iam_aad_config_uid:
                    config_iam_aad_user(tmp_dag, _record, iam_aad_config_uid)
                else:
                    config_user(tmp_dag, _record, resource_uid, config_uid)

        force = kwargs.get('force') is True

        if len(skipped_records) > 0:
            skipped_header = [field_to_title(x) for x in skipped_header]
            dump_report_data(skipped_records, skipped_header, title='The following record(s) were skipped')

            if len(r_requests) > 0 and not force:
                answer = user_choice('\nDo you want to cancel password rotation?', 'Yn', 'Y')
                if answer.lower().startswith('y'):
                    return

        if len(r_requests) > 0:
            valid_header = [field_to_title(x) for x in valid_header]
            dump_report_data(valid_records, valid_header, title='The following record(s) will be updated')
            if not force:
                answer = user_choice('\nDo you want to update password rotation?', 'Yn', 'Y')
                if answer.lower().startswith('n'):
                    return

            for rq in r_requests:
                record_uid = utils.base64_url_encode(rq.recordUid)
                try:
                    router_set_record_rotation_information(params, rq, transmission_key, encrypted_transmission_key,
                                                           encrypted_session_token)
                except KeeperApiError as kae:
                    logging.warning('Record "%s": Set rotation error "%s": %s',
                                    record_uid, kae.result_code, kae.message)
            params.sync_data = True


class PAMListRecordRotationCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotation list')
    parser.add_argument('--verbose', '-v', required=False, default=False, dest='is_verbose', action='store_true',
                        help='Verbose output')

    def get_parser(self):
        return PAMListRecordRotationCommand.parser

    def execute(self, params, **kwargs):

        is_verbose = kwargs.get('is_verbose')

        rq = pam_pb2.PAMGenericUidsRequest()
        schedules_proto = router_get_rotation_schedules(params, rq)
        if schedules_proto:
            schedules = list(schedules_proto.schedules)
        else:
            schedules = []

        enterprise_all_controllers = list(gateway_helper.get_all_gateways(params))
        enterprise_controllers_connected_resp = router_get_connected_gateways(params)
        enterprise_controllers_connected_uids_bytes = \
            [x.controllerUid for x in enterprise_controllers_connected_resp.controllers]

        all_pam_config_records = pam_configurations_get_all(params)
        table = []

        headers = []
        headers.append('Record UID')
        headers.append('Record Title')
        headers.append('Record Type')
        headers.append('Schedule')

        headers.append('Gateway')
        if is_verbose:
            headers.append('Gateway UID')

        headers.append('PAM Configuration (Type)')
        if is_verbose:
            headers.append('PAM Configuration UID')

        for s in schedules:
            row = []

            record_uid = utils.base64_url_encode(s.recordUid)
            controller_uid = s.controllerUid
            controller_details = next(
                (ctr for ctr in enterprise_all_controllers if ctr.controllerUid == controller_uid), None)
            configuration_uid = s.configurationUid
            configuration_uid_str = utils.base64_url_encode(configuration_uid)
            pam_configuration = next((pam_config for pam_config in all_pam_config_records if
                                      pam_config.get('record_uid') == configuration_uid_str), None)

            is_controller_online = any(
                (poc for poc in enterprise_controllers_connected_uids_bytes if poc == controller_uid))

            row_color = ''
            if record_uid in params.record_cache:
                row_color = bcolors.HIGHINTENSITYWHITE
                rec = params.record_cache[record_uid]

                data_json = rec['data_unencrypted'].decode('utf-8') if isinstance(rec['data_unencrypted'], bytes) else \
                    rec['data_unencrypted']
                data = json.loads(data_json)

                record_title = data.get('title')
                record_type = data.get('type') or ''
            else:
                row_color = bcolors.WHITE

                record_title = '[record inaccessible]'
                record_type = '[record inaccessible]'

            if record_type != "pamUser":
                # only pamUser records are supported for rotation
                continue

            row.append(f'{row_color}{record_uid}')
            row.append(record_title)
            row.append(record_type)

            if s.noSchedule is True:
                # Per Sergey A:
                # > noSchedule=true means manual
                # > false is by default in proto and matches the default state for most records (would have a schedule)
                schedule_str = '[Manual Rotation]'
            else:
                if s.scheduleData:
                    schedule_arr = s.scheduleData.replace('RotateActionJob|', '').split('.')
                    if len(schedule_arr) == 4:
                        schedule_str = f'{schedule_arr[0]} on {schedule_arr[1]} at {schedule_arr[2]} UTC with interval count of {schedule_arr[3]}'
                    elif len(schedule_arr) == 3:
                        schedule_str = f'{schedule_arr[0]} at {schedule_arr[1]} UTC with interval count of {schedule_arr[2]}'
                    else:
                        schedule_str = s.scheduleData
                else:
                    schedule_str = f'{bcolors.FAIL}[empty]'

            row.append(f'{schedule_str}')

            # Controller Info

            enterprise_controllers_connected = router_get_connected_gateways(params)
            connected_controller = None
            if enterprise_controllers_connected and controller_details:
                router_controllers = {controller.controllerUid: controller for controller in
                                      list(enterprise_controllers_connected.controllers)}
                connected_controller = router_controllers.get(controller_details.controllerUid)

            if connected_controller:
                controller_stat_color = bcolors.OKGREEN
            else:
                controller_stat_color = bcolors.WHITE

            controller_color = bcolors.WHITE
            if is_controller_online:
                controller_color = bcolors.OKGREEN

            if controller_details:
                row.append(f'{controller_stat_color}{controller_details.controllerName}{bcolors.ENDC}')
            else:
                row.append(f'{controller_stat_color}[Does not exist]{bcolors.ENDC}')

            if is_verbose:
                row.append(f'{controller_color}{utils.base64_url_encode(controller_uid)}{bcolors.ENDC}')

            if not pam_configuration:
                if not is_verbose:
                    row.append(f"{bcolors.FAIL}[No config found]{bcolors.ENDC}")
                else:
                    row.append(
                        f"{bcolors.FAIL}[No config found. Looks like configuration {configuration_uid_str} was removed but rotation schedule was not modified{bcolors.ENDC}")

            else:
                pam_data_decrypted = pam_decrypt_configuration_data(pam_configuration)
                pam_config_name = pam_data_decrypted.get('title')
                pam_config_type = pam_data_decrypted.get('type')
                row.append(f"{pam_config_name} ({pam_config_type})")

            if is_verbose:
                row.append(f'{utils.base64_url_encode(configuration_uid)}{bcolors.ENDC}')

            table.append(row)

        table.sort(key=lambda x: (x[1]))

        dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)

        print(f"\n{bcolors.OKBLUE}----------------------------------------------------------{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}Example to rotate record to which this user has access to:{bcolors.ENDC}")
        print(f"\t{bcolors.OKBLUE}pam action rotate -r [RECORD UID]{bcolors.ENDC}")


class PAMGatewayListCommand(Command):
    parser = argparse.ArgumentParser(prog='dr-gateway')
    parser.add_argument('--force', '-f', required=False, default=False, dest='is_force', action='store_true',
                        help='Force retrieval of gateways')
    parser.add_argument('--verbose', '-v', required=False, default=False, dest='is_verbose', action='store_true',
                        help='Verbose output')

    def get_parser(self):
        return PAMGatewayListCommand.parser

    def execute(self, params, **kwargs):

        is_force = kwargs.get('is_force')
        is_verbose = kwargs.get('is_verbose')

        is_router_down = False
        krouter_url = router_helper.get_router_url(params)
        enterprise_controllers_connected = None
        try:
            enterprise_controllers_connected = router_get_connected_gateways(params)

        except requests.exceptions.ConnectionError as errc:
            is_router_down = True
            if not is_force:
                logging.warning(f"Looks like router is down. Use '{bcolors.OKGREEN}-f{bcolors.ENDC}' flag to "
                                f"retrieve list of all available routers associated with your enterprise.\n\nRouter"
                                f" URL [{krouter_url}]")
                return
            else:
                logging.info(f"{bcolors.WARNING}Looks like router is down. Router URL [{krouter_url}]{bcolors.ENDC}")

        except Exception as e:
            logging.warning(f"Unhandled error during retrieval of the connected gateways.")
            raise e

        enterprise_controllers_all = gateway_helper.get_all_gateways(params)

        if not enterprise_controllers_all:
            print(f"{bcolors.OKBLUE}\nThis Enterprise does not have Gateways yet. To create new Gateway, use command "
                  f"`{bcolors.ENDC}{bcolors.OKGREEN}pam gateway new{bcolors.ENDC}{bcolors.OKBLUE}`\n\n"
                  f"NOTE: If you have added new Gateway, you might still need to initialize it before it is "
                  f"listed.{bcolors.ENDC}")
            return

        table = []

        headers = []
        headers.append('KSM Application Name (UID)')
        headers.append('Gateway Name')
        headers.append('Gateway UID')
        headers.append('Status')

        if is_verbose:
            headers.append('Device Name')
            headers.append('Device Token')
            headers.append('Created On')
            headers.append('Last Modified')
            headers.append('Node ID')

        for c in enterprise_controllers_all:

            connected_controller = None
            if enterprise_controllers_connected:
                router_controllers = {controller.controllerUid: controller for controller in
                                      list(enterprise_controllers_connected.controllers)}
                connected_controller = router_controllers.get(c.controllerUid)

            row_color = ''
            if not is_router_down:
                row_color = bcolors.FAIL

                if connected_controller:
                    row_color = bcolors.OKGREEN

            add_cookie = False

            row = []

            ksm_app_uid_str = utils.base64_url_encode(c.applicationUid)
            ksm_app = KSMCommand.get_app_record(params, ksm_app_uid_str)

            if ksm_app:
                ksm_app_data_unencrypted_json = ksm_app.get('data_unencrypted')
                ksm_app_data_unencrypted_dict = json.loads(ksm_app_data_unencrypted_json)
                ksm_app_title = ksm_app_data_unencrypted_dict.get('title')
                ksm_app_info = f'{ksm_app_title} ({ksm_app_uid_str})'
            else:
                ksm_app_info = f'[APP NOT ACCESSIBLE OR DELETED] ({ksm_app_uid_str})'

            row.append(f'{row_color if ksm_app else bcolors.WHITE}{ksm_app_info}{bcolors.ENDC}')
            row.append(f'{row_color}{c.controllerName}{bcolors.ENDC}')
            row.append(f'{row_color}{utils.base64_url_encode(c.controllerUid)}{bcolors.ENDC}')

            if is_router_down:
                status = 'UNKNOWN'
            elif connected_controller:
                status = "ONLINE"
            else:
                status = "OFFLINE"

            row.append(f'{row_color}{status}{bcolors.ENDC}')

            if is_verbose:
                row.append(f'{row_color}{c.deviceName}{bcolors.ENDC}')
                row.append(f'{row_color}{c.deviceToken}{bcolors.ENDC}')
                row.append(f'{row_color}{datetime.fromtimestamp(c.created / 1000)}{bcolors.ENDC}')
                row.append(f'{row_color}{datetime.fromtimestamp(c.lastModified / 1000)}{bcolors.ENDC}')
                row.append(f'{row_color}{c.nodeId}{bcolors.ENDC}')

            table.append(row)
        table.sort(key=lambda x: (x[3] or '', x[0].lower()))

        if is_verbose:
            krouter_host = get_router_url(params)
            print(f"\n{bcolors.BOLD}Router Host: {bcolors.OKBLUE}{krouter_host}{bcolors.ENDC}\n")

        dump_report_data(table, headers, fmt='table', filename="",
                         row_number=False, column_width=None)


class PAMConfigurationListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam config list')
    parser.add_argument('--config', '-c', required=False, dest='pam_configuration', action='store',
                        help='Specific PAM Configuration UID')
    parser.add_argument('--verbose', '-v', required=False, dest='verbose', action='store_true', help='Verbose')

    def get_parser(self):
        return PAMConfigurationListCommand.parser

    def execute(self, params, **kwargs):
        pam_configuration_uid = kwargs.get('pam_configuration')
        is_verbose = kwargs.get('verbose')

        if not pam_configuration_uid:  # Print ALL root level configs
            PAMConfigurationListCommand.print_root_rotation_setting(params, is_verbose)
        else:  # Print element configs (config that is not a root)
            PAMConfigurationListCommand.print_pam_configuration_details(params, pam_configuration_uid, is_verbose)

            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_configuration_uid,
                                is_config=True)
            tmp_dag.print_tunneling_config(pam_configuration_uid, None)

    @staticmethod
    def print_pam_configuration_details(params, config_uid, is_verbose=False):
        configuration = vault.KeeperRecord.load(params, config_uid)
        if not configuration:
            raise Exception(f'Configuration {config_uid} not found')
        if configuration.version != 6:
            raise Exception(f'{config_uid} is not PAM Configuration')
        if not isinstance(configuration, vault.TypedRecord):
            raise Exception(f'{config_uid} is not PAM Configuration')

        facade = PamConfigurationRecordFacade()
        facade.record = configuration
        table = []
        header = ['name', 'value']
        table.append(['UID', configuration.record_uid])
        table.append(['Name', configuration.title])
        table.append(['Config Type', configuration.record_type])
        folder_uid = facade.folder_uid
        sf = None
        if folder_uid in params.shared_folder_cache:
            sf = api.get_shared_folder(params, folder_uid)
        table.append(['Shared Folder', f'{sf.name} ({sf.shared_folder_uid})' if sf else ''])
        table.append(['Gateway UID', facade.controller_uid])
        table.append(['Resource Record UIDs', facade.resource_ref])

        for field in configuration.fields:
            if field.type in ('pamResources', 'fileRef'):
                continue
            values = list(field.get_external_value())
            if not values:
                continue
            field_name = field.get_field_name()
            if field.type == 'schedule':
                field_name = 'Default Schedule'

            table.append([field_name, values])
        dump_report_data(table, header, no_header=True, right_align=(0,))

    @staticmethod
    def print_root_rotation_setting(params, is_verbose=False):
        table = []
        headers = ['UID', 'Config Name', 'Config Type', 'Shared Folder', 'Gateway UID', 'Resource Record UIDs']
        if is_verbose:
            headers.append('Fields')

        configurations = list(vault_extensions.find_records(params, record_version=6))
        facade = PamConfigurationRecordFacade()
        for c in configurations:  # type: vault.TypedRecord
            if c.record_type in ('pamAwsConfiguration', 'pamAzureConfiguration', 'pamNetworkConfiguration'):
                facade.record = c
                shared_folder_parents = find_parent_top_folder(params, c.record_uid)
                if shared_folder_parents:
                    sf = shared_folder_parents[0]
                    row = [c.record_uid, c.title, c.record_type, f'{sf.name} ({sf.uid})',
                           facade.controller_uid, facade.resource_ref]

                    if is_verbose:
                        fields = []
                        for field in c.fields:
                            if field.type in ('pamResources', 'fileRef'):
                                continue
                            value = ', '.join(field.get_external_value())
                            if value:
                                fields.append(f'{field.get_field_name()}: {value}')
                        row.append(fields)

                    table.append(row)
                else:
                    logging.warning(f'Following configuration is not in the shared folder: UID: %s, Title: %s',
                                    c.record_uid, c.title)
            else:
                logging.warning(f'Following configuration has unsupported type: UID: %s, Title: %s', c.record_uid,
                                c.title)

        table.sort(key=lambda x: (x[1] or ''))
        dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


common_parser = argparse.ArgumentParser(add_help=False)
common_parser.add_argument('--environment', '-env', dest='config_type', action='store',
                           choices=['local', 'aws', 'azure'], help='PAM Configuration Type', )
common_parser.add_argument('--title', '-t', dest='title', action='store', help='Title of the PAM Configuration')
common_parser.add_argument('--gateway', '-g', dest='gateway_uid', action='store', help='Gateway UID or Name')
common_parser.add_argument('--shared-folder', '-sf', dest='shared_folder_uid', action='store',
                           help='Share Folder where this PAM Configuration is stored. Should be one of the folders to '
                                'which the gateway has access to.')
common_parser.add_argument('--schedule', '-sc', dest='default_schedule', action='store', help='Default Schedule: Use CRON syntax')
common_parser.add_argument('--port-mapping', '-pm', dest='port_mapping', action='append', help='Port Mapping')
network_group = common_parser.add_argument_group('network', 'Local network configuration')
network_group.add_argument('--network-id', dest='network_id', action='store', help='Network ID')
network_group.add_argument('--network-cidr', dest='network_cidr', action='store', help='Network CIDR')
aws_group = common_parser.add_argument_group('aws', 'AWS configuration')
aws_group.add_argument('--aws-id', dest='aws_id', action='store', help='AWS ID')
aws_group.add_argument('--access-key-id', dest='access_key_id', action='store', help='Access Key Id')
aws_group.add_argument('--access-secret-key', dest='access_secret_key', action='store', help='Access Secret Key')
aws_group.add_argument('--region-name', dest='region_names', action='append', help='Region Names')
azure_group = common_parser.add_argument_group('azure', 'Azure configuration')
azure_group.add_argument('--azure-id', dest='azure_id', action='store', help='Azure Id')
azure_group.add_argument('--client-id', dest='client_id', action='store', help='Client Id')
azure_group.add_argument('--client-secret', dest='client_secret', action='store', help='Client Secret')
azure_group.add_argument('--subscription_id', dest='subscription_id', action='store',
                         help='Subscription Id')
azure_group.add_argument('--tenant-id', dest='tenant_id', action='store', help='Tenant Id')
azure_group.add_argument('--resource-group', dest='resource_group', action='append', help='Resource Group')


class PamConfigurationEditMixin(RecordEditMixin):
    pam_record_types = None

    def __init__(self):
        super().__init__()

    @staticmethod
    def get_pam_record_types(params):
        if PamConfigurationEditMixin.pam_record_types is None:
            rts = [y for x, y in params.record_type_cache.items() if x // 1000000 == record_pb2.RT_PAM]
            PamConfigurationEditMixin.pam_record_types = []
            for rt in rts:
                try:
                    rt_obj = json.loads(rt)
                    if '$id' in rt_obj:
                        PamConfigurationEditMixin.pam_record_types.append(rt_obj['$id'])
                except:
                    pass
        return PamConfigurationEditMixin.pam_record_types

    def parse_pam_configuration(self, params, record, **kwargs):
        # type: (KeeperParams, vault.TypedRecord, Dict[str, Any]) -> None
        field = record.get_typed_field('pamResources')
        if not field:
            value = {}
            field = vault.TypedField.new_field('pamResources', value)
            record.fields.append(field)

        if len(field.value) == 0:
            field.value.append(dict())
        value = field.value[0]

        gateway_uid = None  # type: Optional[str]
        gateway = kwargs.get('gateway_uid')  # type: Optional[str]
        if gateway:
            gateways = gateway_helper.get_all_gateways(params)
            gateway_uid = next((utils.base64_url_encode(x.controllerUid) for x in gateways
                                if utils.base64_url_encode(x.controllerUid) == gateway
                                or x.controllerName.casefold() == gateway.casefold()), None)
        if gateway_uid:
            value['controllerUid'] = gateway_uid

        # apps = KSMCommand.get_app_info(params, utils.base64_url_encode(gateway.applicationUid))
        # if not apps:
        #     raise Exception(f'Application for gateway %s not found', gateway_name)
        # app = apps[0]
        # shares = [x for x in app.shares if x.shareType == APIRequest_pb2.SHARE_TYPE_FOLDER]
        # if len(shares) == 0:
        #     raise Exception(f'Gateway %s has no shared folders', gateway.controllerName)

        shared_folder_uid = None  # type: Optional[str]
        folder_name = kwargs.get('shared_folder_uid')  # type: Optional[str]
        if folder_name:
            if folder_name in params.shared_folder_cache:
                shared_folder_uid = folder_name
            else:
                for sf_uid in params.shared_folder_cache:
                    sf = api.get_shared_folder(params, sf_uid)
                    if sf and sf.name.casefold() == folder_name.casefold():
                        shared_folder_uid = sf_uid
                        break
        if shared_folder_uid:
            value['folderUid'] = shared_folder_uid
        else:
            for f in record.fields:
                if f.type == 'pamResources' and f.value and len(f.value) > 0 and 'folderUid' in f.value[0]:
                    shared_folder_uid = f.value[0]['folderUid']
                    break
            if not shared_folder_uid:
                raise CommandError('pam config edit', 'Shared Folder not found')

        rrr = kwargs.get('remove_records')
        if rrr:
            pam_record_lookup = {}
            rti = PamConfigurationEditMixin.get_pam_record_types(params)
            for r in vault_extensions.find_records(params, record_type=rti):
                pam_record_lookup[r.record_uid] = r.record_uid
                pam_record_lookup[r.title.lower()] = r.record_uid

            record_uids = set()
            if 'resourceRef' in value:
                record_uids.update(value['resourceRef'])
            if isinstance(rrr, list):
                for r in rrr:
                    if r in pam_record_lookup:
                        record_uids.remove(r)
                        continue
                    r_l = r.lower()
                    if r_l in pam_record_lookup:
                        record_uids.remove(r_l)
                        continue
                    logging.warning(f'Failed to find PAM record: {r}')

            value['resourceRef'] = list(record_uids)

    def parse_properties(self, params, record, **kwargs):  # type: (KeeperParams, vault.TypedRecord, ...) -> None
        extra_properties = []
        self.parse_pam_configuration(params, record, **kwargs)
        port_mapping = kwargs.get('port_mapping')
        if isinstance(port_mapping, list) and len(port_mapping) > 0:
            pm = "\n".join(port_mapping)
            extra_properties.append(f'multiline.portMapping={pm}')
        schedule = kwargs.get('default_schedule')
        if schedule:
            extra_properties.append(f'schedule.defaultRotationSchedule={schedule}')
        else:
            extra_properties.append(f'schedule.defaultRotationSchedule=On-Demand')

        if record.record_type == 'pamNetworkConfiguration':
            network_id = kwargs.get('network_id')
            if network_id:
                extra_properties.append(f'text.networkId={network_id}')
            network_cidr = kwargs.get('network_cidr')
            if network_cidr:
                extra_properties.append(f'text.networkCIDR={network_cidr}')
        elif record.record_type == 'pamAwsConfiguration':
            aws_id = kwargs.get('aws_id')
            if aws_id:
                extra_properties.append(f'text.awsId={aws_id}')
            access_key_id = kwargs.get('access_key_id')
            if access_key_id:
                extra_properties.append(f'secret.accessKeyId={access_key_id}')
            access_secret_key = kwargs.get('access_secret_key')
            if access_secret_key:
                extra_properties.append(f'secret.accessSecretKey={access_secret_key}')
            region_names = kwargs.get('region_names')
            if region_names:
                regions = '\n'.join(region_names)
                extra_properties.append(f'multiline.regionNames={regions}')
        elif record.record_type == 'pamAzureConfiguration':
            azure_id = kwargs.get('azure_id')
            if azure_id:
                extra_properties.append(f'text.azureId={azure_id}')
            client_id = kwargs.get('client_id')
            if client_id:
                extra_properties.append(f'secret.clientId={client_id}')
            client_secret = kwargs.get('client_secret')
            if client_secret:
                extra_properties.append(f'secret.clientSecret={client_secret}')
            subscription_id = kwargs.get('subscription_id')
            if subscription_id:
                extra_properties.append(f'secret.subscriptionId={subscription_id}')
            tenant_id = kwargs.get('tenant_id')
            if tenant_id:
                extra_properties.append(f'secret.tenantId={tenant_id}')
            resource_group = kwargs.get('resource_group')
            if isinstance(resource_group, list) and len(resource_group) > 0:
                rg = '\n'.join(resource_group)
                extra_properties.append(f'multiline.resourceGroups={rg}')
        if extra_properties:
            self.assign_typed_fields(record, [RecordEditMixin.parse_field(x) for x in extra_properties])

    def verify_required(self, record):  # type: (vault.TypedRecord) -> None
        for field in record.fields:
            if field.required:
                if len(field.value) == 0:
                    if field.type == 'schedule':
                        field.value = [{
                            'type': 'ON_DEMAND'
                        }]
                    else:
                        self.warnings.append(f'Empty required field: "{field.get_field_name()}"')
        for custom in record.custom:
            if custom.required:
                custom.required = False


class PAMConfigurationNewCommand(Command, PamConfigurationEditMixin):
    choices = ['on', 'off', 'default']
    parser = argparse.ArgumentParser(prog='pam config new', parents=[common_parser])
    parser.add_argument('--connections', '-c', dest='connections', choices=choices,
                        help='Set connections permissions')
    parser.add_argument('--tunneling', '-u', dest='tunneling', choices=choices,
                        help='Set tunneling permissions')
    parser.add_argument('--rotation', '-r', dest='rotation', choices=choices,
                        help='Set rotation permissions')
    parser.add_argument('--remote-browser-isolation', '-rbi', dest='remotebrowserisolation', choices=choices,
                        help='Set remote browser isolation permissions')
    parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                        help='Set recording connections permissions for the resource')
    parser.add_argument('--typescript-recording', '-tr', dest='typescriptrecording', choices=choices,
                        help='Set TypeScript recording permissions for the resource')

    def __init__(self):
        super().__init__()

    def get_parser(self):
        return PAMConfigurationNewCommand.parser

    def execute(self, params, **kwargs):
        self.warnings.clear()

        config_type = kwargs.get('config_type')
        if not config_type:
            raise CommandError('pam-config-new', '--environment parameter is required')
        if config_type == 'aws':
            record_type = 'pamAwsConfiguration'
        elif config_type == 'azure':
            record_type = 'pamAzureConfiguration'
        elif config_type == 'local':
            record_type = 'pamNetworkConfiguration'
        else:
            raise CommandError('pam-config-new', f'--environment {config_type} is not supported'
                                                 f' supported options are aws, azure, or local')

        title = kwargs.get('title')
        if not title:
            raise CommandError('pam-config-new', '--title parameter is required')

        record = vault.TypedRecord(version=6)
        record.type_name = record_type
        record.title = title

        rt_fields = RecordEditMixin.get_record_type_fields(params, record.record_type)
        if rt_fields:
            RecordEditMixin.adjust_typed_record_fields(record, rt_fields)

        # resolve folder path to UID
        sf_name = kwargs.get('shared_folder_uid', '')
        if sf_name:
            fpath = try_resolve_path(params, sf_name)
            # [-1] == '' -> existing folder, 'path/' -> non-existing folder
            if fpath and len(fpath) >= 2 and fpath[-1] == '':
                sfuid = fpath[-2].uid
                if sfuid: kwargs['shared_folder_uid'] = sfuid

        self.parse_properties(params, record, **kwargs)

        field = record.get_typed_field('pamResources')
        if not field:
            raise CommandError('pam-config-new', 'PAM configuration record does not contain resource field')

        gateway_uid = None
        shared_folder_uid = None
        value = field.get_default_value(dict)
        if value:
            gateway_uid = value.get('controllerUid')
            shared_folder_uid = value.get('folderUid')

        if not shared_folder_uid:
            raise CommandError('pam-config-new', '--shared-folder parameter is required to create a PAM configuration')

        self.verify_required(record)

        pam_configuration_create_record_v6(params, record, shared_folder_uid)

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        # Add DAG for configuration
        tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, record_uid=record.record_uid,
                            is_config=True)
        tmp_dag.edit_tunneling_config(
            kwargs.get('connections'),
            kwargs.get('tunneling'),
            kwargs.get('rotation'),
            kwargs.get('recording'),
            kwargs.get('typescriptrecording'),
            kwargs.get('remotebrowserisolation')
        )
        tmp_dag.print_tunneling_config(record.record_uid, None)

        # Moving v6 record into the folder
        api.sync_down(params)
        FolderMoveCommand().execute(params, src=record.record_uid, dst=shared_folder_uid, force=True)

        params.environment_variables[LAST_RECORD_UID] = record.record_uid
        params.sync_data = True

        if gateway_uid:
            pcc = pam_pb2.PAMConfigurationController()
            pcc.configurationUid = utils.base64_url_decode(record.record_uid)
            pcc.controllerUid = utils.base64_url_decode(gateway_uid)
            api.communicate_rest(params, pcc, 'pam/set_configuration_controller')

        for w in self.warnings:
            logging.warning(w)

        params.environment_variables[LAST_RECORD_UID] = record.record_uid
        return record.record_uid


class PAMConfigurationEditCommand(Command, PamConfigurationEditMixin):
    choices = ['on', 'off', 'default']
    parser = argparse.ArgumentParser(prog='pam config edit', parents=[common_parser])
    parser.add_argument('uid', type=str, action='store', help='The Config UID to edit')
    parser.add_argument('--remove-resource-record', '-rrr', dest='remove_records', action='append',
                        help='Resource Record UID to remove')
    parser.add_argument('--connections', '-c', dest='connections', choices=choices,
                        help='Set connections permissions')
    parser.add_argument('--tunneling', '-u', dest='tunneling', choices=choices,
                        help='Set tunneling permissions')
    parser.add_argument('--rotation', '-r', dest='rotation', choices=choices,
                        help='Set rotation permissions')
    parser.add_argument('--remote-browser-isolation', '-rbi', dest='remotebrowserisolation', choices=choices,
                        help='Set remote browser isolation permissions')
    parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                        help='Set recording connections permissions for the resource')
    parser.add_argument('--typescript-recording', '-tr', dest='typescriptrecording', choices=choices,
                        help='Set TypeScript recording permissions for the resource')

    def __init__(self):
        super(PAMConfigurationEditCommand, self).__init__()

    def get_parser(self):
        return PAMConfigurationEditCommand.parser

    def execute(self, params, **kwargs):
        self.warnings.clear()

        configuration = None

        config_name = kwargs.get('uid')
        if not config_name:
            raise CommandError('pam config edit', 'PAM Configuration UID or Title is required')
        if config_name in params.record_cache:
            configuration = vault.KeeperRecord.load(params, config_name)
        else:
            l_name = config_name.casefold()
            for c in vault_extensions.find_records(params, record_version=6):
                if c.title.casefold() == l_name:
                    configuration = c
                    break
        if not configuration:
            raise CommandError('pam-config-edit', f'PAM configuration "{config_name}" not found')
        if not isinstance(configuration, vault.TypedRecord) or configuration.version != 6:
            raise CommandError('pam-config-edit', f'PAM configuration "{config_name}" not found')

        config_type = kwargs.get('config_type')
        if config_type:
            if not config_type:
                raise CommandError('pam-config-new', '--environment parameter is required')
            if config_type == 'aws':
                record_type = 'pamAwsConfiguration'
            elif config_type == 'azure':
                record_type = 'pamAzureConfiguration'
            elif config_type == 'local':
                record_type = 'pamNetworkConfiguration'
            else:
                record_type = configuration.record_type

            if record_type != configuration.record_type:
                configuration.type_name = record_type
                rt_fields = RecordEditMixin.get_record_type_fields(params, record_type)
                if rt_fields:
                    RecordEditMixin.adjust_typed_record_fields(configuration, rt_fields)

        title = kwargs.get('title')
        if title:
            configuration.title = title

        field = configuration.get_typed_field('pamResources')
        if not field:
            raise CommandError('pam-config-edit', 'PAM configuration record does not contain resource field')

        orig_gateway_uid = ''
        orig_shared_folder_uid = ''
        value = field.get_default_value(dict)
        if value:
            orig_gateway_uid = value.get('controllerUid') or ''
            orig_shared_folder_uid = value.get('folderUid') or ''

        self.parse_properties(params, configuration, **kwargs)
        self.verify_required(configuration)

        record_management.update_record(params, configuration)

        value = field.get_default_value(dict)
        if value:
            gateway_uid = value.get('controllerUid') or ''
            if gateway_uid != orig_gateway_uid:
                pcc = pam_pb2.PAMConfigurationController()
                pcc.configurationUid = utils.base64_url_decode(configuration.record_uid)
                pcc.controllerUid = utils.base64_url_decode(gateway_uid)
                api.communicate_rest(params, pcc, 'pam/set_configuration_controller')
            shared_folder_uid = value.get('folderUid') or ''
            if shared_folder_uid != orig_shared_folder_uid:
                FolderMoveCommand().execute(params, src=configuration.record_uid, dst=shared_folder_uid)

        # check if there are any permission changes
        _connections = kwargs.get('connections', None)
        _tunneling = kwargs.get('tunneling', None)
        _rotation = kwargs.get('rotation', None)
        _rbi = kwargs.get('remotebrowserisolation', None)
        _recording = kwargs.get('recording', None)
        _typescript_recording = kwargs.get('typescriptrecording', None)

        if (_connections is not None or _tunneling is not None or _rotation is not None or _rbi is not None or
                _recording is not None or _typescript_recording is not None):
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key,
                                configuration.record_uid, is_config=True)
            tmp_dag.edit_tunneling_config(_connections, _tunneling, _rotation, _recording, _typescript_recording, _rbi)
            tmp_dag.print_tunneling_config(configuration.record_uid, None)
        for w in self.warnings:
            logging.warning(w)

        params.sync_data = True


class PAMConfigurationRemoveCommand(Command):
    parser = argparse.ArgumentParser(prog='pam config remove')
    parser.add_argument('uid', type=str, action='store',
                        help='PAM Configuration UID. To view all rotation settings with their UIDs, use command '
                             '`pam config list`')

    def get_parser(self):
        return PAMConfigurationRemoveCommand.parser

    def execute(self, params, **kwargs):
        pam_config_name = kwargs.get('uid')
        if not pam_config_name:
            raise CommandError('pam config edit', 'PAM Configuration UID is required')
        pam_config_uid = None
        for config in vault_extensions.find_records(params, record_version=6):
            if config.record_uid == pam_config_name:
                pam_config_uid = config.record_uid
                break
            if config.title.casefold() == pam_config_name.casefold():
                pass
        if not pam_config_name:
            raise Exception(f'Configuration "{pam_config_name}" not found')
        pam_config = vault.KeeperRecord.load(params, pam_config_uid)
        if not pam_config:
            raise Exception(f'Configuration "{pam_config_uid}" not found')
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_config.record_uid,
                            is_config=True)
        if tmp_dag.linking_dag.has_graph:
            tmp_dag.remove_from_dag(pam_config_uid)
        pam_configuration_remove(params, pam_config_uid)
        params.sync_data = True


class PAMRouterGetRotationInfo(Command):
    parser = argparse.ArgumentParser(prog='dr-router-get-rotation-info-parser')
    parser.add_argument('--record-uid', '-r', required=True, dest='record_uid', action='store',
                        help='Record UID to rotate')

    def get_parser(self):
        return PAMRouterGetRotationInfo.parser

    def execute(self, params, **kwargs):

        record_uid = kwargs.get('record_uid')
        record_uid_bytes = url_safe_str_to_bytes(record_uid)

        rri = record_rotation_get(params, record_uid_bytes)
        rri_status_name = router_pb2.RouterRotationStatus.Name(rri.status)
        if rri_status_name == 'RRS_ONLINE':

            print(f'Rotation Status: {bcolors.OKBLUE}Ready to rotate ({rri_status_name}){bcolors.ENDC}')
            configuration_uid = utils.base64_url_encode(rri.configurationUid)
            print(f'PAM Config UID: {bcolors.OKBLUE}{configuration_uid}{bcolors.ENDC}')
            print(f'Node ID: {bcolors.OKBLUE}{rri.nodeId}{bcolors.ENDC}')

            print(f"Gateway Name where the rotation will be performed: {bcolors.OKBLUE}{(rri.controllerName if rri.controllerName else '-')}{bcolors.ENDC}")
            print(f"Gateway Uid: {bcolors.OKBLUE}{(utils.base64_url_encode(rri.controllerUid) if rri.controllerUid else '-') } {bcolors.ENDC}")

            def is_resource_ok(resource_id, params, configuration_uid):
                if resource_id not in params.record_cache:
                    return False

                configuration = vault.KeeperRecord.load(params, configuration_uid)
                if not isinstance(configuration, vault.TypedRecord):
                    return False

                field = configuration.get_typed_field('pamResources')
                if not (field and isinstance(field.value, list) and len(field.value) == 1):
                    return False

                rv = field.value[0]
                if not isinstance(rv, dict):
                    return False

                resources = rv.get('resourceRef')
                return isinstance(resources, list) and resource_id in resources

            if rri.resourceUid:
                resource_id = utils.base64_url_encode(rri.resourceUid)
                resource_ok = is_resource_ok(resource_id, params, configuration_uid)
                print(f"Admin Resource Uid: {bcolors.OKBLUE if resource_ok else bcolors.FAIL}{resource_id}"
                      f"{bcolors.ENDC}")

            # print(f"Router Cookie: {bcolors.OKBLUE}{(rri.cookie if rri.cookie else '-')}{bcolors.ENDC}")
            # print(f"scriptName: {bcolors.OKGREEN}{rri.scriptName}{bcolors.ENDC}")
            if rri.pwdComplexity:
                print(f"Password Complexity: {bcolors.OKGREEN}{rri.pwdComplexity}{bcolors.ENDC}")
                try:
                    record = params.record_cache.get(record_uid)
                    if record:
                        complexity = crypto.decrypt_aes_v2(utils.base64_url_decode(rri.pwdComplexity), record['record_key_unencrypted'])
                        c = json.loads(complexity.decode())
                        print(f"Password Complexity Data: {bcolors.OKBLUE}Length: {c.get('length')}; Lowercase: {c.get('lowercase')}; Uppercase: {c.get('caps')}; Digits: {c.get('digits')}; Symbols: {c.get('special')} {bcolors.ENDC}")
                except:
                    pass
            else:
                print(f"Password Complexity: {bcolors.OKGREEN}[not set]{bcolors.ENDC}")

            print(f"Is Rotation Disabled: {bcolors.OKGREEN}{rri.disabled}{bcolors.ENDC}")
            print(f"\nCommand to manually rotate: {bcolors.OKGREEN}pam action rotate -r {record_uid}{bcolors.ENDC}")
        else:
            print(f'{bcolors.WARNING}Rotation Status: Not ready to rotate ({rri_status_name}){bcolors.ENDC}')


class PAMRouterScriptCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('list', PAMScriptListCommand(), 'List script fields')
        self.register_command('add', PAMScriptAddCommand(), 'List Record Rotation Schedulers')
        self.register_command('edit', PAMScriptEditCommand(), 'Add, delete, or edit script field')
        self.register_command('delete', PAMScriptDeleteCommand(), 'Delete script field')
        self.default_verb = 'list'


class PAMScriptListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script view', parents=[report_output_parser],
                                     description='List script fields')
    parser.add_argument('pattern', nargs='?', help='Record UID, path, or search pattern')

    def get_parser(self):
        return PAMScriptListCommand.parser

    def execute(self, params, **kwargs):
        pattern = kwargs.get('pattern')

        table = []
        header = ['record_uid', 'title', 'record_type', 'script_uid', 'script_name', 'records', 'command']
        for record in vault_extensions.find_records(params, search_str=pattern, record_version=3,
                                                    record_type=('pamUser', 'pamDirectory')):
            if not isinstance(record, vault.TypedRecord):
                continue
            for field in (x for x in record.fields if x.type == 'script'):
                value = field.get_default_value(dict)
                if not value:
                    continue
                file_ref = value.get('fileRef')
                if not file_ref:
                    continue
                file_record = vault.KeeperRecord.load(params, file_ref)
                if not file_record:
                    continue
                records = value.get('recordRef')
                command = value.get('command')
                table.append([record.record_uid, record.title, record.record_type, file_record.record_uid,
                              file_record.title, records, command])
        fmt = kwargs.get('format')
        if fmt != 'json':
            header = [field_to_title(x) for x in header]
        return dump_report_data(table, header, fmt=fmt, filename=kwargs.get('output'), row_number=True)


class PAMScriptAddCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script add', description='Add script to record')
    parser.add_argument('--script', required=True, dest='script', action='store',
                        help='Script file name')
    parser.add_argument('--add-credential', dest='add_credential', action='append',
                        help='Record with rotation credential')
    parser.add_argument('--script-command', dest='script_command', action='store',
                        help='Script command')
    parser.add_argument('record', help='Record UID or Title')

    def get_parser(self):
        return PAMScriptAddCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('rotate script', '"record" argument is required')
        records = list(vault_extensions.find_records(
            params, search_str=record_name, record_version=3, record_type=('pamUser', 'pamDirectory')))
        if len(records) == 0:
            raise CommandError('rotate script', f'Record "{record_name}" not found')
        if len(records) > 1:
            raise CommandError('rotate script', f'Record "{record_name}" is not unique. Use record UID.')
        record = records[0]
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('rotate script', f'Record "{record.title}" is not a rotation record.')

        script_field = next((x for x in record.fields if x.type == 'script'), None)
        if not script_field:
            script_field = vault.TypedField.new_field('script', [], 'rotationScripts')
            record.fields.append(script_field)

        file_name = kwargs.get('script')
        full_name = os.path.expanduser(file_name)
        if not os.path.isfile(full_name):
            raise CommandError('rotate script', f'File "{file_name}" not found.')

        facade = record_facades.FileRefRecordFacade()
        facade.record = record
        pre = set(facade.file_ref)
        upload_task = attachment.FileUploadTask(full_name)
        attachment.upload_attachments(params, record, [upload_task])
        post = set(facade.file_ref)
        df = post.difference(pre)
        if len(df) == 1:
            file_uid = df.pop()
            facade.file_ref.remove(file_uid)
            script_value = {
                'fileRef': file_uid,
                'recordRef': [],
                'command': '',
            }
            script_field.value.append(script_value)
            record_refs = kwargs.get('add_credential')
            if isinstance(record_refs, list):
                for ref in record_refs:
                    if ref in params.record_cache:
                        script_value['recordRef'].append(ref)
            cmd = kwargs.get('script_command')
            if cmd:
                script_value['command'] = cmd

        record_management.update_record(params, record)
        params.sync_data = True


class PAMScriptEditCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script edit', description='Edit script field')
    parser.add_argument('--script', required=True, dest='script', action='store',
                        help='Script UID or name')
    parser.add_argument('-ac', '--add-credential', dest='add_credential', action='append',
                        help='Add a record with rotation credential')
    parser.add_argument('-rc', '--remove-credential', dest='remove_credential', action='append',
                        help='Remove a record with rotation credential')
    parser.add_argument('--script-command', dest='script_command', action='store',
                        help='Script command')
    parser.add_argument('record', help='Record UID or Title')

    def get_parser(self):
        return PAMScriptEditCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('rotate script', '"record" argument is required')

        script_name = kwargs.get('script')  # type: Optional[str]
        if not script_name:
            raise CommandError('rotate script', '"script" argument is required')

        records = list(vault_extensions.find_records(
            params, search_str=record_name, record_version=3, record_type=('pamUser', 'pamDirectory')))
        if len(records) == 0:
            raise CommandError('rotate script', f'Record "{record_name}" not found')
        if len(records) > 1:
            raise CommandError('rotate script', f'Record "{record_name}" is not unique. Use record UID.')
        record = records[0]
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('rotate script', f'Record "{record.title}" is not a rotation record.')

        script_field = next((x for x in record.fields if x.type == 'script'), None)
        if script_field is None:
            raise CommandError('rotate script', f'Record "{record.title}" has no rotation scripts.')
        script_value = next((x for x in script_field.value if x.get('fileRef') == script_name), None)
        if script_value is None:
            s_name = script_name.casefold()
            for x in script_field.value:
                file_uid = x.get('fileRef')
                file_record = vault.KeeperRecord.load(params, file_uid)
                if isinstance(file_record, vault.FileRecord):
                    if file_record.title.casefold() == s_name:
                        script_value = x
                        break
                    elif file_record.name.casefold() == s_name:
                        script_value = x
                        break

        if not isinstance(script_value, dict):
            raise CommandError('rotate script', f'Record "{record.title}" does not have script "{script_name}"')

        modified = False
        refs = set()
        record_refs = script_value.get('recordRef')
        if isinstance(record_refs, list):
            refs.update(record_refs)
        remove_credential = kwargs.get('remove_credential')
        if isinstance(remove_credential, list) and remove_credential:
            refs.difference_update(remove_credential)
            modified = True
        add_credential = kwargs.get('add_credential')
        if isinstance(add_credential, list) and add_credential:
            refs.update(add_credential)
            modified = True
        if modified:
            script_value['recordRef'] = list(refs)
        command = kwargs.get('script_command')
        if command:
            script_value['command'] = command
            modified = True

        if not modified:
            raise CommandError('rotate script', 'Nothing to do')

        record_management.update_record(params, record)
        params.sync_data = True


class PAMScriptDeleteCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script delete', description='Delete script field')
    parser.add_argument('--script', required=True, dest='script', action='store',
                        help='Script UID or name')
    parser.add_argument('record', help='Record UID or Title')

    def get_parser(self):
        return PAMScriptDeleteCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('rotate script', '"record" argument is required')

        script_name = kwargs.get('script')  # type: Optional[str]
        if not script_name:
            raise CommandError('rotate script', '"script" argument is required')

        records = list(vault_extensions.find_records(
            params, search_str=record_name, record_version=3, record_type=('pamUser', 'pamDirectory')))
        if len(records) == 0:
            raise CommandError('rotate script', f'Record "{record_name}" not found')
        if len(records) > 1:
            raise CommandError('rotate script', f'Record "{record_name}" is not unique. Use record UID.')
        record = records[0]
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('rotate script', f'Record "{record.title}" is not a rotation record.')

        script_field = next((x for x in record.fields if x.type == 'script'), None)
        if script_field is None:
            raise CommandError('rotate script', f'Record "{record.title}" has no rotation scripts.')
        script_value = next((x for x in script_field.value if x.get('fileRef') == script_name), None)
        if script_value is None:
            s_name = script_name.casefold()
            for x in script_field.value:
                file_uid = x.get('fileRef')
                file_record = vault.KeeperRecord.load(params, file_uid)
                if isinstance(file_record, vault.FileRecord):
                    if file_record.title.casefold() == s_name:
                        script_value = x
                        break
                    elif file_record.name.casefold() == s_name:
                        script_value = x
                        break

        if not isinstance(script_value, dict):
            raise CommandError('rotate script', f'Record "{record.title}" does not have script "{script_name}"')

        script_field.value.remove(script_value)
        record_management.update_record(params, record)
        params.sync_data = True


class PAMGatewayActionJobCancelCommand(Command):
    parser = argparse.ArgumentParser(prog='pam-action-job-cancel-command')
    parser.add_argument('job_id')

    def get_parser(self):
        return PAMGatewayActionJobCancelCommand.parser

    def execute(self, params, **kwargs):
        job_id = kwargs.get('job_id')

        print(f"Job id to cancel [{job_id}]")

        generic_job_id_inputs = GatewayActionJobInfoInputs(job_id)

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionJobCancel(inputs=generic_job_id_inputs, conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False
        )
        print_router_response(router_response, 'job_info', conversation_id)


class PAMGatewayActionJobCommand(Command):
    parser = argparse.ArgumentParser(prog='pam-action-job-command')
    parser.add_argument('--gateway', '-g', required=False, dest='gateway_uid', action='store',
                        help='Gateway UID. Needed only if there are more than one gateway running')
    parser.add_argument('job_id')

    def get_parser(self):
        return PAMGatewayActionJobCommand.parser

    def execute(self, params, **kwargs):
        job_id = kwargs.get('job_id')
        gateway_uid = kwargs.get('gateway_uid')

        print(f"Job id to check [{job_id}]")

        action_inputs = GatewayActionJobInfoInputs(job_id)

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionJobInfo(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_uid
        )

        print_router_response(router_response, 'job_info', original_conversation_id=conversation_id, gateway_uid=gateway_uid)


class PAMGatewayActionRotateCommand(Command):
    parser = argparse.ArgumentParser(prog='dr-rotate-command')
    parser.add_argument('--record-uid', '-r', required=True, dest='record_uid', action='store',
                        help='Record UID to rotate')

    # parser.add_argument('--config', '-c', required=True, dest='configuration_uid', action='store',
    #                                           help='Rotation configuration UID')

    def get_parser(self):
        return PAMGatewayActionRotateCommand.parser

    def execute(self, params, **kwargs):
        record_uid = kwargs.get('record_uid')
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            print(f'{bcolors.FAIL}Record [{record_uid}] is not available.{bcolors.ENDC}')
            return

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        # Find record by record uid
        ri = record_rotation_get(params, utils.base64_url_decode(record.record_uid))
        ri_pwd_complexity_encrypted = ri.pwdComplexity
        if not ri_pwd_complexity_encrypted:
            rule_list_dict = {
                'length': 20,
                'caps': 1,
                'lowercase': 1,
                'digits': 1,
                'special': 1,
            }
            ri_pwd_complexity_encrypted = utils.base64_url_encode(router_helper.encrypt_pwd_complexity(rule_list_dict, record.record_key))
        # else:
        #     rule_list_json = crypto.decrypt_aes_v2(utils.base64_url_decode(ri_pwd_complexity_encrypted), record.record_key)
        #     complexity = json.loads(rule_list_json.decode())

        resource_uid = None

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        if not config_uid:
            # Still try it the old way
            # Configuration on the UI is "Rotation Setting"
            ri_rotation_setting_uid = utils.base64_url_encode(ri.configurationUid)
            resource_uid = utils.base64_url_encode(ri.resourceUid)
            pam_config = vault.KeeperRecord.load(params, ri_rotation_setting_uid)
            if not isinstance(pam_config, vault.TypedRecord):
                print(f'{bcolors.FAIL}PAM Configuration [{ri_rotation_setting_uid}] is not available.{bcolors.ENDC}')
                return
            facade = PamConfigurationRecordFacade()
            facade.record = pam_config

            config_uid = facade.controller_uid

        if not resource_uid:
            tmp_dag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, record.record_uid)
            resource_uid = tmp_dag.get_resource_uid(record_uid)
            if not resource_uid:
                # NOOP records don't need resource_uid

                is_noop = False
                pam_config = vault.KeeperRecord.load(params, config_uid)

                # Check the graph for the noop setting.
                record_link = RecordLink(record=pam_config, params=params, fail_on_corrupt=False)
                acl = record_link.get_acl(record_uid, pam_config.record_uid)
                if acl is not None and acl.rotation_settings is not None:
                    is_noop = acl.rotation_settings.noop

                # If it was false  in the graph, or did not exist, check the record.
                if is_noop is False:
                    noop_field = record.get_typed_field('text', 'NOOP')
                    is_noop = utils.value_to_boolean(noop_field.value[0]) if noop_field and noop_field.value else False

                if not is_noop:
                    print(f'{bcolors.FAIL}Resource UID not found for record [{record_uid}]. please configure it '
                          f'{bcolors.OKBLUE}"pam rotation user {record_uid} --resource RESOURCE_UID"{bcolors.ENDC}')
                    return

        controller = configuration_controller_get(params, url_safe_str_to_bytes(config_uid))
        if not controller.controllerUid:
            raise CommandError('', f'{bcolors.FAIL}Gateway UID not found for configuration '
                                   f'{config_uid}.')

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

        # rrs = RouterRotationStatus.Name(ri.status)
        # if rrs == 'RRS_NO_ROTATION':
        #     print(f'{bcolors.FAIL}Record [{record_uid}] does not have rotation associated with it.{bcolors.ENDC}')
        #     return
        # elif rrs == 'RRS_CONTROLLER_DOWN':
        #     controller_details = next((ctr for ctr in all_enterprise_controllers_all if ctr.controllerUid == ri.controllerUid), None)
        #
        #     print(f'{bcolors.WARNING}The Gateway "{controller_details.controllerName}" [uid={ri_controller_uid}] '
        #           f'that is setup to perform this rotation is currently offline.{bcolors.ENDC}')
        #     return
        # elif rrs == 'RRS_NO_CONTROLLER':
        #     print(f'{bcolors.FAIL}There is no such gateway (uid: {pam_config_data.get("controllerUid")}) exists that is associated to PAM Configuration \'{pam_config_data.get("name")}\' (uid: {CommonHelperMethods.bytes_to_url_safe_str(ri.configurationUid)}).{bcolors.ENDC}')
        #     return
        # elif rrs == 'RRS_ONLINE':
        #     print(f'{bcolors.OKGREEN}Gateway is online{bcolors.ENDC}')
        # else:
        #     print(f'{bcolors.FAIL}Unknown router rotation status [{rrs}]{bcolors.ENDC}')
        #     return

        action_inputs = GatewayActionRotateInputs(
            record_uid=record_uid,
            configuration_uid=config_uid,
            pwd_complexity_encrypted=ri_pwd_complexity_encrypted,
            resource_uid=resource_uid
        )

        conversation_id = GatewayAction.generate_conversation_id()

        router_response = router_send_action_to_gateway(
            params=params, gateway_action=GatewayActionRotate(inputs=action_inputs, conversation_id=conversation_id,
                                                              gateway_destination=gateway_uid),
            message_type=pam_pb2.CMT_ROTATE, is_streaming=False,
            transmission_key=transmission_key,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token)

        print_router_response(router_response, 'job_info', conversation_id, gateway_uid=gateway_uid)


class PAMGatewayActionServerInfoCommand(Command):
    parser = argparse.ArgumentParser(prog='dr-info-command')
    parser.add_argument('--gateway', '-g', required=False, dest='gateway_uid', action='store', help='Gateway UID')
    parser.add_argument('--verbose', '-v', required=False, dest='verbose', action='store_true', help='Verbose Output')

    def get_parser(self):
        return PAMGatewayActionServerInfoCommand.parser

    def execute(self, params, **kwargs):
        destination_gateway_uid_str = kwargs.get('gateway_uid')
        is_verbose = kwargs.get('verbose')
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionGatewayInfo(is_scheduled=False),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=destination_gateway_uid_str
        )

        print_router_response(router_response, 'gateway_info', is_verbose=is_verbose, gateway_uid=destination_gateway_uid_str)


class PAMGatewayActionDiscoverCommandBase(Command):

    """
    The discover command base.

    Contains static methods to get the configuration record, get and update the discovery store. These are method
    used by multiple discover actions.
    """

    # If the discovery data field does not exist, or the field contains no values, use the template to init the
    # field.
    STORE_VALUE_TEMPLATE = {
        "ignore_list": [],
        "jobs": []
    }

    STORE_LABEL = "discoveryStore"

    @staticmethod
    def get_configuration(params, configuration_uid):

        configuration_record = vault.KeeperRecord.load(params, configuration_uid)
        if not isinstance(configuration_record, vault.TypedRecord):
            print(f'{bcolors.FAIL}PAM Configuration [{configuration_uid}] is not available.{bcolors.ENDC}')
            return

        configuration_facade = PamConfigurationRecordFacade()
        configuration_facade.record = configuration_record

        return configuration_record, configuration_facade

    @staticmethod
    def get_discovery_store(configuration_record):

        # Get the discovery store. It contains information about discovery job for a configuration. It is on the custom
        # fields.
        discovery_field = None
        if configuration_record.custom is not None:
            discovery_field = next((field
                                    for field in configuration_record.custom
                                    if field.label == PAMGatewayActionDiscoverCommandBase.STORE_LABEL),
                                   None)

        discovery_field_exists = True
        if discovery_field is None:
            logging.debug("discovery store field does not exists, creating")
            discovery_field = TypedField.new_field("_hidden",
                                                   [PAMGatewayActionDiscoverCommandBase.STORE_VALUE_TEMPLATE],
                                                   PAMGatewayActionDiscoverCommandBase.STORE_LABEL)
            discovery_field_exists = False
        else:
            logging.debug("discovery store record exists")

        # The value should not be [], if it is, init with the defaults.
        if len(discovery_field.value) == 0:
            logging.debug("discovery store does not have a value, set to the default value")
            discovery_field.value = [PAMGatewayActionDiscoverCommandBase.STORE_VALUE_TEMPLATE]

        # TODO - REMOVE ME, this is just so we have one job
        # discovery_field.value = [PAMGatewayActionDiscoverCommandBase.STORE_VALUE_TEMPLATE]

        return discovery_field.value[0], discovery_field, discovery_field_exists

    @staticmethod
    def update_discovery_store(params, configuration_record, discovery_store, discovery_field, discovery_field_exists):

        discovery_field.value = [discovery_store]
        if discovery_field_exists is False:
            if configuration_record.custom is None:
                configuration_record.custom = []
            configuration_record.custom.append(discovery_field)

        # Update the record here to prevent a race-condition
        record_management.update_record(params, configuration_record)
        params.sync_data = True


class PAMGatewayRemoveCommand(Command):
    dr_remove_controller_parser = argparse.ArgumentParser(prog='dr-remove-gateway')
    dr_remove_controller_parser.add_argument('--gateway', '-g', required=True, dest='gateway',
                                             help='UID of the Gateway', action='store')

    def get_parser(self):
        return PAMGatewayRemoveCommand.dr_remove_controller_parser

    def execute(self, params, **kwargs):
        gateway_name = kwargs.get('gateway')
        gateways = gateway_helper.get_all_gateways(params)

        gateway = next((x for x in gateways
                        if utils.base64_url_encode(x.controllerUid) == gateway_name
                        or x.controllerName.lower() == gateway_name.lower()), None)
        if gateway:
            gateway_helper.remove_gateway(params, gateway.controllerUid)
            logging.info('Gateway %s has been removed.', gateway.controllerName)
        else:
            logging.warning('Gateway %s not found', gateway_name)


class PAMCreateGatewayCommand(Command):
    dr_create_controller_parser = argparse.ArgumentParser(prog='dr-create-gateway')
    dr_create_controller_parser.add_argument('--name', '-n', required=True, dest='gateway_name',
                                             help='Name of the Gateway',
                                             action='store')
    dr_create_controller_parser.add_argument('--application', '-a', required=True, dest='ksm_app',
                                             help='KSM Application name or UID. Use command `sm app list` to view '
                                                  'available KSM Applications.', action='store')
    dr_create_controller_parser.add_argument('--token-expires-in-min', '-e', type=int, dest='token_expire_in_min',
                                             action='store',
                                             help='Time for the one time token to expire. Maximum 1440 minutes (24 hrs). Default: 60',
                                             default=60)
    dr_create_controller_parser.add_argument('--return_value', '-r', dest='return_value', action='store_true',
                                             help='Return value from the command for automation purposes')
    dr_create_controller_parser.add_argument('--config-init', '-c', type=str, dest='config_init', action='store',
                                             choices=['json', 'b64'],
                                             help='Initialize client config and return configuration string.')  # json, b64, file

    def get_parser(self):
        return PAMCreateGatewayCommand.dr_create_controller_parser

    def execute(self, params, **kwargs):

        gateway_name = kwargs.get('gateway_name')
        ksm_app = kwargs.get('ksm_app')
        is_return_value = kwargs.get('return_value')
        config_init = kwargs.get('config_init')
        token_expire_in_min = kwargs.get('token_expire_in_min')

        ott_expire_in_min = token_expire_in_min

        logging.debug(f'gateway_name =[{gateway_name}]')
        logging.debug(f'ksm_app =[{ksm_app}]')
        logging.debug(f'ott_expire_in_min =[{ott_expire_in_min}]')

        one_time_token = gateway_helper.create_gateway(params, gateway_name, ksm_app, config_init, ott_expire_in_min)

        if is_return_value:
            return one_time_token
        else:
            print(f'The one time token has been created in application [{bcolors.OKBLUE}{ksm_app}{bcolors.ENDC}].\n\n'
                  f'The new Gateway named {bcolors.OKBLUE}{gateway_name}{bcolors.ENDC} will show up in a list '
                  f'of gateways once it is initialized on the Gateway.\n\n')

            if config_init:
                print('Use following initialized config be used in the controller:')
            else:
                print(f'Following one time token will expire in {bcolors.OKBLUE}{ott_expire_in_min}{bcolors.ENDC} '
                      f'minutes):')

            print('-----------------------------------------------')
            print(bcolors.OKGREEN + one_time_token + bcolors.ENDC)
            print('-----------------------------------------------')


# TUNNELING
class PAMTunnelListCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel list')

    def get_parser(self):
        return PAMTunnelListCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        def gather_tabel_row_data(thread):
            # {"thread": t, "host": host, "port": port, "started": datetime.now(),
            r_row = []
            run_time = None
            hours = 0
            minutes = 0
            seconds = 0

            entrance = thread.get('entrance')
            if entrance is not None:
                r_row.append(f"{bcolors.OKBLUE}{entrance.pc.endpoint_name}{bcolors.ENDC}")
            else:
                r_row.append(f"{bcolors.WARNING}Connecting..{bcolors.ENDC}")

            r_row.append(f"{thread.get('host', '')}")

            if entrance is not None and entrance.print_ready_event.is_set():
                if thread.get('started'):
                    run_time = datetime.now() - thread.get('started')
                    hours, remainder = divmod(run_time.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)

                r_row.append(
                    f"{bcolors.OKBLUE}{entrance.port}{bcolors.ENDC}"
                )
            else:
                r_row.append(f"{bcolors.WARNING}Connecting...{bcolors.ENDC}")
            r_row.append(f"{thread.get('record_uid', '')}")
            if entrance is not None and entrance.print_ready_event.is_set():
                text_line = ""
                if run_time:
                    if run_time.days == 1:
                        text_line += f"{run_time.days} day "
                    elif run_time.days > 1:
                        text_line += f"{run_time.days} days "
                    text_line += f"{hours} hr " if hours > 0 or run_time.days > 0 else ''
                text_line += f"{minutes} min "
                text_line += f"{seconds} sec"
                r_row.append(text_line)
            else:
                r_row.append(f"{bcolors.WARNING}Connecting...{bcolors.ENDC}")
            return r_row

        if not params.tunnel_threads:
            logging.warning(f"{bcolors.OKBLUE}No Tunnels running{bcolors.ENDC}")
            return

        table = []
        headers = ['Tunnel ID', 'Host', 'Port', 'Record UID', 'Up Time']

        for i, convo_id in enumerate(params.tunnel_threads):
            row = gather_tabel_row_data(params.tunnel_threads[convo_id])
            if row:
                table.append(row)

        dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


def clean_up_tunnel(params, convo_id):
    tunnel_data = None
    index = None
    for i, co in enumerate(params.tunnel_threads):
        tmp_entrance = params.tunnel_threads[co].get('entrance', {})
        if tmp_entrance and tmp_entrance.pc.endpoint_name == convo_id:
            tunnel_data = params.tunnel_threads[co]
            index = i
            break
    if tunnel_data:
        kill_server_event = tunnel_data.get("kill_server_event")
        if kill_server_event:
            if not kill_server_event.is_set():
                kill_server_event.set()
            # whatever the read timeout is, wait for 2 seconds more
            time.sleep(READ_TIMEOUT + 2)
        p = tunnel_data.get("process", None)
        if p and p.is_alive():
            p.join()
        if params.tunnel_threads.get(index):
            del params.tunnel_threads[index]
        if params.tunnel_threads_queue.get(index):
            del params.tunnel_threads_queue[index]
    else:
        if params.debug:
            print(f"{bcolors.WARNING}No tunnel data found to remove for {convo_id}{bcolors.ENDC}")


class PAMTunnelStopCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel stop')
    pam_cmd_parser.add_argument('uid', type=str, action='store', help='The Tunnel UID or Record UID')

    def get_parser(self):
        return PAMTunnelStopCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        convo_id = kwargs.get('uid')
        if not convo_id:
            raise CommandError('tunnel stop', '"uid" argument is required')
        tunnel_data = []
        for co in params.tunnel_threads:
            tmp_entrance = params.tunnel_threads[co].get('entrance', {})
            if tmp_entrance and tmp_entrance.pc.endpoint_name == convo_id:
                tunnel_data.append(tmp_entrance)
            elif tmp_entrance and tmp_entrance.pc.record_uid == convo_id:
                tunnel_data.append(tmp_entrance)
        if not tunnel_data:
            raise CommandError('tunnel stop', f"No tunnel data to remove found for {convo_id}")
        for co in tunnel_data:
            clean_up_tunnel(params, co.pc.endpoint_name)
        clean_up_tunnel(params, convo_id)

        return


class PAMTunnelTailCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel tail')
    pam_cmd_parser.add_argument('uid', type=str, action='store', help='The Tunnel UID')

    def get_parser(self):
        return PAMTunnelTailCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        convo_id = kwargs.get('uid')
        if not convo_id:
            raise CommandError('tunnel tail', '"uid" argument is required')
        tunnel_data = None
        index = None
        for i, co in enumerate(params.tunnel_threads):
            tmp_entrance = params.tunnel_threads[co].get('entrance', {})
            if tmp_entrance and tmp_entrance.pc.endpoint_name == convo_id:
                tunnel_data = tmp_entrance
                index = i
                break
        if not tunnel_data:
            raise CommandError('tunnel tail', f"Tunnel UID {convo_id} not found")

        log_queue = params.tunnel_threads_queue.get(index)

        logger_level = logging.getLogger().getEffectiveLevel()
        aio_log_level = logging.getLogger('aiortc').getEffectiveLevel()

        logging.getLogger('aiortc').setLevel(logging.DEBUG)
        logging.getLogger('aioice').setLevel(logging.DEBUG)
        logging.getLogger(tunnel_data.pc.endpoint_name).setLevel(logging.DEBUG)

        if log_queue:
            try:
                while True:
                    while not log_queue.empty():
                        print(f'    {bcolors.OKBLUE}{log_queue.get()}{bcolors.ENDC}')
            except KeyboardInterrupt:
                print(f'    {bcolors.WARNING}Exiting tail command{bcolors.ENDC}')
                return

            except Exception as e:
                print(f'    {bcolors.WARNING}Exiting due to exception: {e}{bcolors.ENDC}')
                return
            finally:
                logging.getLogger('aiortc').setLevel(aio_log_level)
                logging.getLogger('aioice').setLevel(aio_log_level)
                logging.getLogger(tunnel_data.pc.endpoint_name).setLevel(logger_level)
        else:
            print(f'    {bcolors.FAIL}Invalid conversation ID{bcolors.ENDC}')
            return


class SocketNotConnectedException(Exception):
    pass


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

        # First check if enabled is true then check if disabled is true. if not then set it to None
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

        # config parameter is optional and may be (auto)resolved from PAM record
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
                    # TODO follow template
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

    class QueueHandler(logging.Handler):
        # Custom logging handler that will put messages into a queue of the tunnel threads
        def __init__(self, log_queue):
            super().__init__()
            self.log_queue = log_queue

        def emit(self, record):
            log_entry = self.format(record)
            try:
                self.log_queue.put_nowait(log_entry)
            except queue.Full:
                # If the queue is full, remove the oldest (first) item
                self.log_queue.get_nowait()
                # Then add the new log entry
                self.log_queue.put_nowait(log_entry)

    def setup_logging(self, convo_id, log_queue, logging_level):
        logger = logging.getLogger(convo_id)
        logger.setLevel(logging_level)
        logger.propagate = False
        queue_handler = self.QueueHandler(log_queue)
        logger.addHandler(queue_handler)
        logger.debug("Logging setup complete.")
        return logger

    async def connect(self, params, record_uid, gateway_uid, convo_num, host, port,
                      log_queue, seed, target_host, target_port, socks):

        # Setup custom logging to put logs into log_queue
        logger = self.setup_logging(str(convo_num), log_queue, logging.getLogger().getEffectiveLevel())

        print(f"{bcolors.HIGHINTENSITYWHITE}Establishing tunnel between Commander and Gateway. Please wait..."
              f"{bcolors.ENDC}")

        # Symmetric key
        """
        Generate a 256-bit (32-byte) random seed
        seed = os.urandom(32)
        """
        if isinstance(seed, str):
            seed = base64_to_bytes(seed)
        # Generate a 128-bit (16-byte) random nonce
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

        # Set up the pc
        print_ready_event = asyncio.Event()
        kill_server_event = asyncio.Event()
        pc = WebRTCConnection(params=params, record_uid=record_uid, gateway_uid=gateway_uid, symmetric_key=symmetric_key,
                              print_ready_event=print_ready_event, kill_server_event=kill_server_event,
                              logger=logger, server=params.server)

        try:
            await pc.signal_channel('start', bytes_to_base64(nonce))
        except Exception as e:
            raise CommandError('Tunnel Start', f"{e}")

        logger.debug("starting private tunnel")

        if socks:
            private_tunnel = SOCKS5Server(host=host, port=port, pc=pc, print_ready_event=print_ready_event,
                                          logger=logger,
                                          connect_task=params.tunnel_threads[convo_num].get("connect_task", None),
                                          kill_server_event=kill_server_event, target_host=target_host,
                                          target_port=target_port)
        else:
            private_tunnel = TunnelEntrance(host=host, port=port, pc=pc, print_ready_event=print_ready_event,
                                            logger=logger,
                                            connect_task=params.tunnel_threads[convo_num].get("connect_task", None),
                                            kill_server_event=kill_server_event, target_host=target_host,
                                            target_port=target_port)

        t1 = asyncio.create_task(private_tunnel.start_server())
        params.tunnel_threads[convo_num].update({"server": t1, "entrance": private_tunnel,
                                                 "kill_server_event": kill_server_event})

        logger.debug("--> START LISTENING FOR MESSAGES FROM GATEWAY --------")
        try:
            await asyncio.gather(t1, private_tunnel.reader_task)
        except asyncio.CancelledError:
            pass
        finally:
            logger.debug("--> STOP LISTENING FOR MESSAGES FROM GATEWAY --------")

    def pre_connect(self, params, record_uid, gateway_uid, convo_num, host, port,
                    seed, target_host, target_port, socks):
        tunnel_name = f"{convo_num}"

        def custom_exception_handler(_loop, context):
            # Check if the exception is present in the context
            if "exception" in context:
                exception = context["exception"]
                if isinstance(exception, ConnectionError):
                    # Handle only ConnectionError
                    logging.debug(f"Caught ConnectionError in asyncio: {exception}")
            else:
                # Log the default message if no exception is found
                logging.error(context["message"])

        loop = None
        try:
            # Create a new asyncio event loop and set the custom exception handler
            loop = asyncio.new_event_loop()
            params.tunnel_threads[convo_num].update({"loop": loop})
            asyncio.set_event_loop(loop)
            loop.set_exception_handler(custom_exception_handler)
            output_queue = queue.Queue(maxsize=500)
            params.tunnel_threads_queue[convo_num] = output_queue
            # Create a Task from the coroutine
            connect_task = loop.create_task(
                self.connect(
                    params=params,
                    record_uid=record_uid,
                    gateway_uid=gateway_uid,
                    convo_num=convo_num,
                    host=host,
                    port=port,
                    log_queue=output_queue,
                    seed=seed,
                    target_host=target_host,
                    target_port=target_port,
                    socks=socks
                )
            )
            params.tunnel_threads[convo_num].update({"connect_task": connect_task})
            try:
                # Run the task until it is complete
                loop.run_until_complete(connect_task)
            except asyncio.CancelledError:
                pass
        except SocketNotConnectedException as es:
            print(f"{bcolors.FAIL}Socket not connected exception in connection {tunnel_name}: {es}{bcolors.ENDC}")
        except KeyboardInterrupt:
            print(f"{bcolors.OKBLUE}Exiting: connection {tunnel_name}{bcolors.ENDC}")
        except CommandError as ce:
            print(f"{bcolors.FAIL}{ce}{bcolors.ENDC}")
        except Exception as e:
            print(f"{bcolors.FAIL}An exception occurred in connection {tunnel_name}: {e}{bcolors.ENDC}")
        finally:
            if loop:
                try:
                    tunnel_data = params.tunnel_threads.get(convo_num, None)
                    co_entrance = tunnel_data.get('entrance')
                    if co_entrance:
                        tunnel_name = co_entrance.pc.endpoint_name
                    if not tunnel_data:
                        logging.debug(f"{bcolors.WARNING}No tunnel data found for {tunnel_name}{bcolors.ENDC}")
                        return

                    if convo_num in params.tunnel_threads_queue:
                        del params.tunnel_threads_queue[convo_num]

                    entrance = tunnel_data.get("entrance", None)
                    if entrance:
                        loop.run_until_complete(entrance.stop_server(CloseConnectionReasons.ConnectionFailed))

                    del params.tunnel_threads[convo_num]
                    logging.debug(f"Cleaned up data for {tunnel_name}")

                    try:
                        for task in asyncio.all_tasks(loop):
                            task.cancel()
                        loop.stop()
                        loop.close()
                        logging.debug(f"{tunnel_name} Loop cleaned up")
                    except Exception as e:
                        logging.debug(f"{bcolors.WARNING}Exception while stopping event loop: {e}{bcolors.ENDC}")
                except Exception as e:
                    print(
                        f"{bcolors.FAIL}An exception occurred in pre_connect for connection {tunnel_name}: {e}"
                        f"{bcolors.ENDC}")
                finally:
                    clean_up_tunnel(params, convo_num)
                    print(f"{bcolors.OKBLUE}Tunnel {tunnel_name} closed.{bcolors.ENDC}")

    def execute(self, params, **kwargs):
        # https://pypi.org/project/aiortc/
        # aiortc Requires: Python >=3.8
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

        record_uid = kwargs.get('uid')
        convo_num = len(params.tunnel_threads)
        params.tunnel_threads[convo_num] = {}
        host = kwargs.get('host')
        port = kwargs.get('port')
        if port is not None and port > 0:
            try:
                port = find_open_port(tried_ports=[], preferred_port=port, host=host)
            except CommandError as e:
                print(f"{bcolors.FAIL}{e}{bcolors.ENDC}")
                del params.tunnel_threads[convo_num]
                return
        else:
            port = find_open_port(tried_ports=[], host=host)
            if port is None:
                print(f"{bcolors.FAIL}Could not find open port to use for tunnel{bcolors.ENDC}")
                del params.tunnel_threads[convo_num]
                return

        api.sync_down(params)
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            print(f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
            return

        pam_settings = record.get_typed_field('pamSettings')
        if not pam_settings:
            print(f"{bcolors.FAIL}PAM Settings not configured for record {record_uid}'.{bcolors.ENDC}")
            print(f"{bcolors.WARNING}This is done by running {bcolors.OKBLUE}'pam tunnel edit {record_uid} "
                  f"--enable-tunneling --config [ConfigUID]'"
                  f"{bcolors.WARNING} The ConfigUID can be found by running"
                  f"{bcolors.OKBLUE} 'pam config list'{bcolors.ENDC}.")
            return

        # SOCKS5 Proxy uses this to determine what connection to use for the tunnel
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

        # IP or a CIDR subnet.
        allowed_hosts = record.get_typed_field('multiline', 'Allowed Hosts')

        allowed_ports = record.get_typed_field('multiline', 'Allowed Ports')
        socks = False
        if allowed_hosts or allowed_ports:
            socks = True

        client_private_seed = record.get_typed_field('trafficEncryptionSeed')
        if not client_private_seed:
            print(f"{bcolors.FAIL}Traffic Encryption Seed not found for record {record_uid}.{bcolors.ENDC}")
            return
        base64_seed = client_private_seed.get_default_value(str).encode('utf-8')
        seed = base64_to_bytes(base64_seed)

        # gateway = kwargs.get('gateway_uid')  # type: Optional[str]
        # if gateway:
        #     gateways = gateway_helper.get_all_gateways(params)
        #     gateway_uid = next((utils.base64_url_encode(x.controllerUid) for x in gateways
        #                         if utils.base64_url_encode(x.controllerUid) == gateway
        #                         or x.controllerName.casefold() == gateway.casefold()), None)
        gateway_uid = self.get_gateway_uid_from_record(params, record_uid)
        if not gateway_uid:
            print(f"{bcolors.FAIL}Gateway not found for record {record_uid}.{bcolors.ENDC}")
            return

        t = threading.Thread(target=self.pre_connect, args=(params, record_uid, gateway_uid, convo_num,
                                                            host, port, seed, target_host, target_port, socks)
                             )

        # Setting the thread as a daemon thread
        t.daemon = True
        t.start()

        if not params.tunnel_threads.get(convo_num):
            params.tunnel_threads[convo_num] = {"thread": t, "host": host, "port": port,
                                                "started": datetime.now(), "record_uid": record_uid}
        else:
            entrance = params.tunnel_threads[convo_num].get("entrance", None)
            if entrance is not None:
                endpoint_name = entrance.pc.endpoint_name
            params.tunnel_threads[convo_num].update({"thread": t, "host": host, "port": port,
                                                    "started": datetime.now(), "record_uid": record_uid})
        count = 0
        wait_time = 120
        entrance = None
        while count < wait_time:
            if params.tunnel_threads.get(convo_num):
                entrance = params.tunnel_threads[convo_num].get("entrance", None)
                if entrance:
                    break
            else:
                break
            count += .1
            time.sleep(.1)

        def print_fail(con_num):
            con_name = ''
            con_entrance = None
            if con_num in params.tunnel_threads:
                con_entrance = params.tunnel_threads[con_num].get("entrance", None)
            fail_dynamic_length = len("| Endpoint ") + len(" failed to start..")
            if con_entrance:
                con_name = con_entrance.pc.endpoint_name
                fail_dynamic_length = len("| Endpoint ") + len(con_name) + len(" failed to start..")

                clean_up_tunnel(params, con_entrance.pc.endpoint_name)
                time.sleep(.5)
            # Dashed line adjusted to the length of the middle line
            fail_dashed_line = '+' + '-' * fail_dynamic_length + '+'
            print(f'\n{bcolors.FAIL}{fail_dashed_line}{bcolors.ENDC}')
            print(f'{bcolors.FAIL}| Endpoint {bcolors.ENDC}{con_name}{bcolors.FAIL} failed to start..{bcolors.ENDC}')
            print(f'{bcolors.FAIL}{fail_dashed_line}{bcolors.ENDC}\n')

        if entrance is not None:
            while not entrance.print_ready_event.is_set() and count < wait_time * 2:
                count += .1
                time.sleep(.1)
                if entrance.kill_server_event.is_set():
                    break

            if entrance.print_ready_event.is_set():
                # Sleep a little bit to print out last
                time.sleep(.5)
                host = host + ":" if host else ''
                # Total length of the dynamic parts (endpoint name, host, and port)
                dynamic_length = \
                    (len("| Endpoint : Listening on: ") +
                     len(entrance.pc.endpoint_name) +
                     len(host) +
                     len(str(entrance.port)))

                # Dashed line adjusted to the length of the middle line
                dashed_line = '+' + '-' * dynamic_length + '+'

                endpoint_name = entrance.pc.endpoint_name

                # Print statements
                print(f'\n{bcolors.OKGREEN}{dashed_line}{bcolors.ENDC}')
                print(
                    f'{bcolors.OKGREEN}| Endpoint {bcolors.ENDC}{bcolors.OKBLUE}{endpoint_name}{bcolors.ENDC}'
                    f'{bcolors.OKGREEN}: Listening on: {bcolors.ENDC}'
                    f'{bcolors.BOLD}{bcolors.OKBLUE}{host}{entrance.port}{bcolors.ENDC}{bcolors.OKGREEN} |{bcolors.ENDC}')
                print(f'{bcolors.OKGREEN}{dashed_line}{bcolors.ENDC}')
                print(
                    f'{bcolors.OKGREEN}View all open tunnels   : {bcolors.ENDC}{bcolors.OKBLUE}pam tunnel list{bcolors.ENDC}')
                print(f'{bcolors.OKGREEN}Tail logs on open tunnel: {bcolors.ENDC}'
                      f'{bcolors.OKBLUE}pam tunnel tail ' +
                      (f'-- ' if endpoint_name[0] == '-' else '') +
                      f'{endpoint_name}{bcolors.ENDC}')
                print(f'{bcolors.OKGREEN}Stop a tunnel           : {bcolors.ENDC}'
                      f'{bcolors.OKBLUE}pam tunnel stop ' +
                      (f'-- ' if endpoint_name[0] == '-' else '') +
                      f'{endpoint_name}{bcolors.ENDC}\n')
            else:
                print_fail(convo_num)
        else:
            print_fail(convo_num)

    def get_config_uid_from_record(self, params, record_uid):
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('', f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
        record_type = record.record_type
        if record_type not in ("pamMachine pamDatabase pamDirectory pamRemoteBrowser").split():
            raise CommandError('', f"{bcolors.FAIL}This record's type is not supported for tunnels. "
                                f"Tunnels are only supported on pamMachine, pamDatabase, pamDirectory, "
                                f"and pamRemoteBrowser records{bcolors.ENDC}")

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        existing_config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        return existing_config_uid

    def get_gateway_uid_from_record(self, params, record_uid):
        gateway_uid = ''
        pam_config_uid = self.get_config_uid_from_record(params, record_uid)
        if pam_config_uid:
            record = vault.KeeperRecord.load(params, pam_config_uid)
            if record:
                field = record.get_typed_field('pamResources')
                value = field.get_default_value(dict)
                if value:
                    gateway_uid = value.get('controllerUid', '') or ''

        return gateway_uid


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

        # config parameter is optional and may be (auto)resolved from PAM record
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
                    # TODO follow template
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
        def remove_field(record, field): # type: (vault.TypedRecord, vault.TypedField) -> bool
            # Since TypedRecord.get_typed_field scans both fields[] and custom[]
            # we need corresponding remove field lookup
            fld = next((x for x in record.fields if field.type == x.type and
                        (not field.label or
                        (x.label and field.label.casefold() == x.label.casefold()))), None)
            if fld is not None:
                record.fields.remove(field)
                return True

            fld = next((x for x in record.custom if field.type == x.type and
                        (not field.label or
                        (x.label and field.label.casefold() == x.label.casefold()))), None)
            if fld is not None:
                record.custom.remove(field)
                return True

            return False

        def resolve_record(params, name):
            record_uid = None
            if name in params.record_cache:
                record_uid = name  # unique record UID
            else:
                # lookup unique folder/record path
                rs = try_resolve_path(params, name)
                if rs is not None:
                    folder, name = rs
                    if folder is not None and name is not None:
                        folder_uid = folder.uid or ''
                        if folder_uid in params.subfolder_record_cache:
                            for uid in params.subfolder_record_cache[folder_uid]:
                                r = api.get_record(params, uid)
                                if r.title.lower() == name.lower():
                                    record_uid = uid
                                    break
            if not record_uid:
                # lookup unique record title
                records = []
                for uid in params.record_cache:
                    data_json = params.record_cache[uid].get("data_unencrypted", "{}") or {}
                    data = json.loads(data_json)
                    if "pamMachine" == str(data.get("type", "")):
                        title = data.get('title', '') or ''
                        if title.lower() == name.lower():
                            records.append(uid)
                uniq_recs = len(set(records))
                if uniq_recs > 1:
                    print(f"{bcolors.FAIL}Multiple PAM Machine records match title '{name}' - "
                          f"specify unique record path/name.{bcolors.ENDC}")
                elif records:
                    record_uid = records[0]
            return record_uid

        def resolve_folder(params, name):
            folder_uid = ''
            if name:
                # lookup unique folder path
                folder_uid = FolderMixin.resolve_folder(params, name)
                # lookup unique folder name/uid
                if not folder_uid and name != '/':
                    folders = []
                    for fkey in params.subfolder_cache:
                        data_json = params.subfolder_cache[fkey].get('data_unencrypted', '{}') or {}
                        data = json.loads(data_json)
                        fname = data.get('name', '') or ''
                        if fname == name:
                            folders.append(fkey)
                    uniq_items = len(set(folders))
                    if uniq_items > 1:
                        print(f"{bcolors.FAIL}Multiple folders match '{name}' - specify unique "
                                f"folder name or use folder UID (or omit --folder parameter to create "
                                f"PAM User record in same folder as PAM Machine record).{bcolors.ENDC}")
                        folders = []
                    folder_uid = folders[0] if folders else ''
            return folder_uid

        def resolve_pam_config(params, record_uid, pam_config_option):
            # PAM Config lookup - Legacy PAM Machine will have associated PAM Config
            # only if it is set up for rotation - otherwise PAM Config must be provided
            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            pamcfg_rec = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
            if not pamcfg_rec and not pam_config_option:
                print(f"{bcolors.FAIL}Unable to find PAM Config associated with record '{record_uid}' "
                    "- please provide PAM Config with --configuration|-c option. "
                    "(Note: Legacy PAM Machine is linked to PAM Config only if "
                    f"the machine is set up for rotation).{bcolors.ENDC}")
                return

            pamcfg_cmd = ''
            if pam_config_option:
                pam_uids = []
                for uid in params.record_cache:
                    if params.record_cache[uid].get('version', 0) == 6:
                        r = api.get_record(params, uid)
                        if r.record_uid == pam_config_option or r.title.lower() == pam_config_option.lower():
                            pam_uids.append(uid)
                uniq_recs = len(set(pam_uids))
                if uniq_recs > 1:
                    print(f"{bcolors.FAIL}Multiple PAM Config records match '{pam_config_option}' - "
                            f"specify unique record UID/Title.{bcolors.ENDC}")
                elif pam_uids:
                    pamcfg_cmd = pam_uids[0]
                elif not pamcfg_rec:
                    print(f"{bcolors.FAIL}Unable to find PAM Configuration '{pam_config_option}'.{bcolors.ENDC}")

            # PAM Config set on command line overrides the PAM Machine associated PAM Config
            pam_config_uid = pamcfg_cmd or pamcfg_rec or ""
            if pamcfg_cmd and pamcfg_rec and pamcfg_cmd != pamcfg_rec:
                print(f"{bcolors.WARNING}PAM Config associated with record '{record_uid}' "
                    "is different from PAM Config set with --configuration|-c option. "
                    f"Using the configuration from command line option.{bcolors.ENDC}")

            return pam_config_uid

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
            # print(f"{bcolors.WARNING}Failed to find PAM Configuration for {record_uid} "
            #       "and unable to link new PAM User to PAM Machine. Remember to manually link "
            #       f"Administrative Credentials record later.{bcolors.ENDC}")

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
                # No values present - just drop the old fields and add new ones
                # thus converting the record to the new pamMachine format
                # NB! If record was edited - newer clients moved these to custom fields
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

        return
