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
import fnmatch
import json
import logging
import os.path
import re
import time
from datetime import datetime
from typing import Dict, Optional, Any, Set, List


import requests
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

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
from .tunnel.port_forward.TunnelGraph import TunnelDAG
from .tunnel.port_forward.tunnel_helpers import get_config_uid, get_keeper_tokens
from .. import api, utils, vault_extensions, crypto, vault, record_management, attachment, record_facades
from ..display import bcolors
from ..error import CommandError, KeeperApiError
from ..params import KeeperParams, LAST_RECORD_UID
from ..proto import pam_pb2, router_pb2, record_pb2
from ..subfolder import find_parent_top_folder, try_resolve_path, BaseFolderNode
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
from .pam_debug.rotation_setting import PAMDebugRotationSettingsCommand
from .pam_debug.link import PAMDebugLinkCommand
from .pam_import.edit import PAMProjectCommand
from .pam_service.list import PAMActionServiceListCommand
from .pam_service.add import PAMActionServiceAddCommand
from .pam_service.remove import PAMActionServiceRemoveCommand
from .pam_saas.add import PAMActionSaasAddCommand
from .pam_saas.user import PAMActionSaasUserCommand
from .pam_saas.remove import PAMActionSaasRemoveCommand
from .pam_saas.config import PAMActionSaasConfigCommand
from .pam_saas.update import PAMActionSaasUpdateCommand
from .tunnel_and_connections import PAMTunnelCommand, PAMConnectionCommand, PAMSplitCommand


# These characters are based on the Vault
PAM_DEFAULT_SPECIAL_CHAR = '''!@#$%^?();',.=+[]<>{}-_/\\*&:"`~|'''


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
        self.register_command('project', PAMProjectCommand(), 'PAM Project Import/Export', 'p')


class PAMGatewayCommand(GroupCommand):

    def __init__(self):
        super(PAMGatewayCommand, self).__init__()
        self.register_command('list', PAMGatewayListCommand(), 'List Gateways', 'l')
        self.register_command('new', PAMCreateGatewayCommand(), 'Create new Gateway', 'n')
        self.register_command('remove', PAMGatewayRemoveCommand(), 'Remove Gateway', 'rm')
        # self.register_command('connect', PAMConnect(), 'Connect')
        # self.register_command('disconnect', PAMDisconnect(), 'Disconnect')
        self.default_verb = 'list'


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
        self.register_command('config', PAMActionSaasConfigCommand(),
                              'Create a configuration for a SaaS rotation.', 'c')
        self.register_command('add', PAMActionSaasAddCommand(),
                              'Add a SaaS rotation to a PAM User record.', 'a')
        self.register_command('remove', PAMActionSaasRemoveCommand(),
                              'Remove a SaaS rotation from a PAM User record', 'r')
        self.register_command('user', PAMActionSaasUserCommand(),
                              "Get user's SaaS rotations", 'i')
        self.register_command('update', PAMActionSaasUpdateCommand(),
                              'Update existing configuration.', 'u')


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
        self.register_command('gateway', PAMDebugGatewayCommand(), 'Debug a gateway', 'g')
        self.register_command('graph', PAMDebugGraphCommand(), 'Render graphs', 'r')

        # Disable for now. Needs more work.
        # self.register_command('verify', PAMDebugVerifyCommand(), 'Verify graphs', 'v')
        self.register_command('acl', PAMDebugACLCommand(), 'Control ACL of PAM Users', 'c')
        self.register_command('link', PAMDebugLinkCommand(), 'Link resource to configuration', 'l')
        self.register_command('rs-reset', PAMDebugRotationSettingsCommand(),
                              'Create/reset rotation settings', 'rs')


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
                        help='Password complexity: length, upper, lower, digits, symbols. Ex. 32,5,5,5,5[,SPECIAL CHARS]')
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
            if not kwargs.get('silent'):
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
                pwd_complexity_list = [s.strip() for s in pwd_complexity.split(',', maxsplit=5)]
                if len(pwd_complexity_list) < 5 or not all(n.isnumeric() for n in pwd_complexity_list[:5]):
                    raise CommandError('', 'Invalid rules to generate password. ''Format is "length, '
                                           'upper, lower, digits, symbols". Ex: 32,5,5,5,5[,SPECIAL CHARS]')

                special_chars = PAM_DEFAULT_SPECIAL_CHAR
                if len(pwd_complexity_list) == 6:

                    # Get the special characters.
                    # Only take chars in our special char list.
                    special_chars = ""
                    for char in PAM_DEFAULT_SPECIAL_CHAR:
                        if char in pwd_complexity_list[5]:
                            special_chars += char

                pwd_complexity_rule_list = {
                    'length': int(pwd_complexity_list[0]),
                    'caps': int(pwd_complexity_list[1]),
                    'lowercase': int(pwd_complexity_list[2]),
                    'digits': int(pwd_complexity_list[3]),
                    'special': int(pwd_complexity_list[4]),
                    'specialChars': special_chars
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

        def config_resource(_dag, target_record, target_config_uid, silent=None):
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
                _dag.set_resource_allowed(target_record.record_uid, rotation=_rotation_enabled,
                                                    allowed_settings_name="rotation")

            if resource_dag is not None and resource_dag.linking_dag.has_graph:
                # TODO: Make sure this doesn't remove everything from the new dag too
                resource_dag.remove_from_dag(target_record.record_uid)

            if not silent:
                _dag.print_tunneling_config(target_record.record_uid, config_uid=target_config_uid)

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
                    complexity = f"{c.get('length', 0)},"\
                                 f"{c.get('caps', 0)},"\
                                 f"{c.get('lowercase', 0)},"\
                                 f"{c.get('digits', 0)},"\
                                 f"{c.get('special', 0)},"\
                                 f"{c.get('specialChars', PAM_DEFAULT_SPECIAL_CHAR)}"
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

        def config_user(_dag, target_record, target_resource_uid, target_config_uid=None, silent=None):
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
                        config_resource(_dag, target_record, target_config_uid, silent=silent)
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
                                           f'with any configuration. '
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
                    # some rotations (iam_user/noop) link straight to pamConfiguration
                    if target_resource_uid != _dag.record.record_uid:
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
                    complexity = f"{c.get('length', 0)},"\
                                 f"{c.get('caps', 0)},"\
                                 f"{c.get('lowercase', 0)},"\
                                 f"{c.get('digits', 0)},"\
                                 f"{c.get('special', 0)}," \
                                 f"{c.get('specialChars', PAM_DEFAULT_SPECIAL_CHAR)}"
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
                config_resource(tmp_dag, _record, config_uid, silent=kwargs.get('silent'))
            elif _record.record_type == 'pamUser':
                iam_aad_config_uid = kwargs.get('iam_aad_config_uid')

                if iam_aad_config_uid and iam_aad_config_uid not in pam_configurations:
                    raise CommandError('', f'Record uid {iam_aad_config_uid} is not a PAM Configuration record.')

                if resource_uid and iam_aad_config_uid:
                    raise CommandError('', 'Cannot use both --resource and --iam-aad-config_uid at once.'
                                           ' --resource is used to configure users found on a resource.'
                                           ' --iam-aad-config-uid is used to configure AWS IAM or Azure AD users')

                if iam_aad_config_uid:
                    config_iam_aad_user(tmp_dag, _record, iam_aad_config_uid)
                else:
                    config_user(tmp_dag, _record, resource_uid, config_uid, silent=kwargs.get('silent'))

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
            if not kwargs.get('silent'):
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
        headers.append('Gateway Version')

        if is_verbose:
            headers.append('Device Name')
            headers.append('Device Token')
            headers.append('Created On')
            headers.append('Last Modified')
            headers.append('Node ID')
            headers.append('OS')
            headers.append('OS Release')
            headers.append('Machine Type')
            headers.append('OS Version')

        # Create a lookup dictionary for connected controllers
        connected_controllers_dict = {}
        if enterprise_controllers_connected:
            connected_controllers_dict = {controller.controllerUid: controller for controller in
                                          list(enterprise_controllers_connected.controllers)}

        for c in enterprise_controllers_all:

            connected_controller = None
            if enterprise_controllers_connected:
                connected_controller = connected_controllers_dict.get(c.controllerUid)

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

            # Version information
            version = ""
            version_parts = []
            if connected_controller and hasattr(connected_controller, 'version') and connected_controller.version:
                version_parts = connected_controller.version.split(';')
                # In non-verbose mode, just show the Gateway Version part
                version = version_parts[0] if version_parts else connected_controller.version

            row.append(f'{row_color}{version}{bcolors.ENDC}')

            if is_verbose:
                row.append(f'{row_color}{c.deviceName}{bcolors.ENDC}')
                row.append(f'{row_color}{c.deviceToken}{bcolors.ENDC}')
                row.append(f'{row_color}{datetime.fromtimestamp(c.created / 1000)}{bcolors.ENDC}')
                row.append(f'{row_color}{datetime.fromtimestamp(c.lastModified / 1000)}{bcolors.ENDC}')
                row.append(f'{row_color}{c.nodeId}{bcolors.ENDC}')
                
                # Add version components as separate columns in verbose mode
                os_name = version_parts[1] if len(version_parts) > 1 else ""
                os_release = version_parts[2] if len(version_parts) > 2 else ""
                machine_type = version_parts[3] if len(version_parts) > 3 else ""
                os_version = version_parts[4] if len(version_parts) > 4 else ""
                
                row.append(f'{row_color}{os_name}{bcolors.ENDC}')
                row.append(f'{row_color}{os_release}{bcolors.ENDC}')
                row.append(f'{row_color}{machine_type}{bcolors.ENDC}')
                row.append(f'{row_color}{os_version}{bcolors.ENDC}')

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
                        print(f"Password Complexity Data: {bcolors.OKBLUE}"
                              f"Length: {c.get('length')}; Lowercase: {c.get('lowercase')}; "
                              f"Uppercase: {c.get('caps')}; "
                              f"Digits: {c.get('digits')}; "
                              f"Symbols: {c.get('special')}; "
                              f"Symbols Chars: {c.get('specialChars')} {bcolors.ENDC}")
                except:
                    pass
            else:
                print(f"Password Complexity: {bcolors.OKGREEN}[not set]{bcolors.ENDC}")

            print(f"Is Rotation Disabled: {bcolors.OKGREEN}{rri.disabled}{bcolors.ENDC}")
            
            # Get schedule information
            rq = pam_pb2.PAMGenericUidsRequest()
            schedules_proto = router_get_rotation_schedules(params, rq)
            if schedules_proto:
                schedules = list(schedules_proto.schedules)
                for s in schedules:
                    if s.recordUid == record_uid_bytes:
                        if s.noSchedule is True:
                            print(f"Schedule Type: {bcolors.OKBLUE}Manual Rotation{bcolors.ENDC}")
                        else:
                            if s.scheduleData:
                                schedule_arr = s.scheduleData.replace('RotateActionJob|', '').split('.')
                                if len(schedule_arr) == 4:
                                    schedule_str = f'{schedule_arr[0]} on {schedule_arr[1]} at {schedule_arr[2]} UTC with interval count of {schedule_arr[3]}'
                                elif len(schedule_arr) == 3:
                                    schedule_str = f'{schedule_arr[0]} at {schedule_arr[1]} UTC with interval count of {schedule_arr[2]}'
                                else:
                                    schedule_str = s.scheduleData
                                print(f"Schedule: {bcolors.OKBLUE}{schedule_str}{bcolors.ENDC}")
                        break
            
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
    parser = argparse.ArgumentParser(prog='pam action rotate')
    parser.add_argument('--record-uid', '-r', dest='record_uid', action='store', help='Record UID to rotate')
    parser.add_argument('--folder', '-f', dest='folder', action='store', help='Shared folder UID or title pattern to rotate')
    # parser.add_argument('--recursive', '-a', dest='recursive', default=False, action='store', help='Enable recursion to rotate sub-folders too')
    # parser.add_argument('--record-pattern', '-p', dest='pattern', action='store', help='Record title match pattern')
    parser.add_argument('--dry-run', '-n', dest='dry_run', default=False, action='store_true', help='Enable dry-run mode')
    # parser.add_argument('--config', '-c', dest='configuration_uid', action='store', help='Rotation configuration UID')

    def get_parser(self):
        return PAMGatewayActionRotateCommand.parser

    def execute(self, params, **kwargs):
        record_uid = kwargs.get('record_uid', '')
        folder = kwargs.get('folder', '')
        recursive = kwargs.get('recursive', False)
        pattern = kwargs.get('pattern', '')  # additional record title match pattern
        dry_run = kwargs.get('dry_run', False)

        # record, folder or pattern - at least one required
        if not record_uid and not folder:
            print(f'the following arguments are required: {bcolors.OKBLUE}--record-uid/-r{bcolors.ENDC} or {bcolors.OKBLUE}--folder/-f{bcolors.ENDC}')
            return

        # single record UID - ignore all folder options
        if not folder:
            self.record_rotate(params, record_uid)
            return

        # folder UID or pattern (ignore --record-uid/-r option)
        folders = []  # root folders matching UID or title pattern
        records = []  # record UIDs of all v3/pamUser records

        # 1. find all shared_folder/shared_folder_folder matching --folder=UID/pattern
        if folder in params.folder_cache:  # folder UID
            fldr = params.folder_cache.get(folder)
            # only shared_folder can be shared to KSM App/Gateway for rotation
            # but its children shared_folder_folder can contain rotation records too
            if fldr.type in (BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType):
                folders.append(folder)
            else:
                logging.debug(f'Folder skipped (not a shared folder/subfolder) - {folder} {fldr.name}')
        else:
            rx_name = self.str_to_regex(folder)
            for fuid in params.folder_cache:
                fldr = params.folder_cache.get(fuid)
                # requirement - shared folder only (not for user_folder containing shf w/ recursion)
                if fldr.type in (BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType):
                    if fldr.name and rx_name.search(fldr.name):
                        folders.append(fldr.uid)

        folders = list(set(folders))  # Remove duplicate UIDs
        # 2. pattern could match both parent and child - drop all children (w/ a matching parent)
        if recursive and len(folders) > 1:
            roots: Dict[str, list] = {}  # group by shared_folder_uid
            for fuid in folders:  # no shf inside shf yet
                roots.setdefault(params.folder_cache.get(fuid).shared_folder_uid, []).append(fuid)
            uniq = []
            for fuid in roots:
                fldrs = list(set(roots[fuid]))
                if len(fldrs) == 1:  # no siblings
                    uniq.append(fldrs[0])
                elif fuid in fldrs:  # parent shf is topmost
                    uniq.append(fuid)
                else:  # topmost sibling(s)
                    fldrset = set(fldrs)
                    for fldr in fldrs:
                        path = []
                        child = fldr
                        while params.folder_cache[child].uid != fuid:
                            path.append(child)
                            child = params.folder_cache[child].parent_uid
                        path.append(child)  # add root shf
                        path = path[1:] if path else [] # skip child uid
                        if not set(path) & fldrset:  # no intersect
                            uniq.append(fldr)
            folders = list(set(uniq))

        # 3. collect all recs pamUsers w/ rotation set-up --recursive or not
        for fldr in folders:
            if recursive:
                logging.warning('--recursive/-a option not implemented (ignored)')
                # params.folder_cache: type=shared_folder_folder, uid=shffUID, shared_folder_uid ='shfUID'
                # params.subfolder_cache/subfolder_record_cache

            if fldr not in params.subfolder_record_cache:
                logging.debug(f"folder {fldr} empty - not in subfolder_record_cache (skipped)")
                continue
            for ruid in params.subfolder_record_cache[fldr]:
                if ruid in params.record_cache:
                    if params.record_cache[ruid].get('version') == 3:
                        data = params.record_cache[ruid].get('data_unencrypted', '')
                        ddict = json.loads(data) if data else {}
                        if str(ddict.get("type", '')).lower() == 'pamUser'.lower() and ruid not in records:
                            records.append(ruid)
        records = list(set(records))  # Remove duplicate UIDs

        # 4. print number of folders and records to rotate - folders: 2+0/16, records 50,000
        print(f'Selected for rotation - folders: {len(folders)}, records: {len(records)}, recursive={recursive}')

        # 5. in debug - print actual folders and records selected for rotation
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            for fldr in folders:
                fobj = params.folder_cache.get(fldr, None)
                title = fobj.name if isinstance(fobj, BaseFolderNode) else ''
                logging.debug(f'Rotation Folder UID: {fldr} {title}')
            for rec in records:
                title = json.loads(params.record_cache.get(rec, {}).get('data_unencrypted', '')).get('title', '')
                logging.debug(f'Rotation Record UID: {rec} {title}')

        # 6. exit if --dry-run
        if dry_run:
            return

        # 7. rotate and handle any throttles (to work with 50,000 records)
        for record_uid in records:
            delay = 0
            while True:
                try:
                    # Handle throttles in-loop on in-record_rotate
                    self.record_rotate(params, record_uid, True)
                    break
                except Exception as e:
                    msg = str(e)  # what is considered a throttling error...
                    if re.search(r"throttle", msg, re.IGNORECASE):
                        delay = (delay+10) % 100  # reset every 1.5 minutes
                        logging.debug(f'Record UID: {record_uid} was throttled (retry in {delay} sec)')
                        time.sleep(1+delay)
                    else:
                        logging.error(f'Record UID: {record_uid} skipped: non-throttling, non-recoverable error: {msg}')
                        break

    def record_rotate(self, params, record_uid, slient:bool = False):
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

        if not slient:
            print_router_response(router_response, 'job_info', conversation_id, gateway_uid=gateway_uid)

    def str_to_regex(self, text):
        text = str(text)
        try:
            pattern = re.compile(text, re.IGNORECASE)
        except: # re.error: yet maybe TypeError, MemoryError, RecursionError etc.
            pattern = re.compile(re.escape(text), re.IGNORECASE)
            logging.debug(f"regex pattern {text} failed to compile (using it as plaintext pattern)")
        return pattern

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
                  f'of gateways once it is initialized.\n\n')

            if config_init:
                print('Use the following initialized config in the Gateway:')
            else:
                print(f'Following one time token will expire in {bcolors.OKBLUE}{ott_expire_in_min}{bcolors.ENDC} '
                      f'minutes):')

            print('-----------------------------------------------')
            print(bcolors.OKGREEN + one_time_token + bcolors.ENDC)
            print('-----------------------------------------------')
