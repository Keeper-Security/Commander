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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from .base import Command, GroupCommand, user_choice, dump_report_data, report_output_parser, field_to_title, FolderMixin
from .folder import FolderMoveCommand
from .ksm import KSMCommand
from .pam import gateway_helper, router_helper
from .pam.config_facades import PamConfigurationRecordFacade
from .pam.config_helper import pam_configurations_get_all, pam_configuration_remove, pam_configuration_create_record_v6, record_rotation_get, \
    pam_decrypt_configuration_data
from .pam.pam_dto import GatewayActionGatewayInfo, GatewayActionDiscoverInputs, GatewayActionDiscover, \
    GatewayActionRotate, \
    GatewayActionRotateInputs, GatewayAction, GatewayActionJobInfoInputs, \
    GatewayActionJobInfo, GatewayActionJobCancel
from .pam.router_helper import router_send_action_to_gateway, print_router_response, \
    router_get_connected_gateways, router_set_record_rotation_information, router_get_rotation_schedules, \
    get_router_url
from .record_edit import RecordEditMixin
from .tunnel.port_forward.endpoint import establish_symmetric_key, WebRTCConnection, TunnelEntrance, READ_TIMEOUT, \
    find_open_port, CloseConnectionReasons
from .. import api, utils, vault_extensions, crypto, vault, record_management, attachment, record_facades
from ..display import bcolors
from ..error import CommandError, KeeperApiError
from ..params import KeeperParams, LAST_RECORD_UID
from ..proto import pam_pb2, router_pb2, record_pb2
from ..proto.APIRequest_pb2 import GetKsmPublicKeysRequest, GetKsmPublicKeysResponse
from ..subfolder import find_parent_top_folder, try_resolve_path, BaseFolderNode
from ..vault import TypedField


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
        self.register_command('disable', PAMTunnelDisableCommand(), 'Disable Tunnel', 'd')
        self.register_command('enable', PAMTunnelEnableCommand(), 'Enable Tunnel', 'e')
        # self.default_verb = 'list'


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
        self.register_command('set',  PAMCreateRecordRotationCommand(), 'Sets Record Rotation configuration', 'new')
        self.register_command('list', PAMListRecordRotationCommand(), 'List Record Rotation configuration', 'l')
        self.register_command('info', PAMRouterGetRotationInfo(), 'Get Rotation Info', 'i')
        self.register_command('script', PAMRouterScriptCommand(), 'Add, delete, or edit script field')
        self.default_verb = 'list'


class GatewayActionCommand(GroupCommand):

    def __init__(self):
        super(GatewayActionCommand, self).__init__()
        self.register_command('gateway-info', PAMGatewayActionServerInfoCommand(), 'Info command', 'i')
        self.register_command('unreleased-discover', PAMGatewayActionDiscoverCommand(), 'Discover command')
        self.register_command('rotate', PAMGatewayActionRotateCommand(), 'Rotate command', 'r')
        self.register_command('job-info', PAMGatewayActionJobCommand(), 'View Job details', 'ji')
        self.register_command('job-cancel', PAMGatewayActionJobCommand(), 'View Job details', 'jc')

        # self.register_command('job-list', DRCmdListJobs(), 'List Running jobs')


class PAMCmdListJobs(Command):
    parser = argparse.ArgumentParser(prog='pam action job-list')
    parser.add_argument('--jobId', '-j', required=False, dest='job_id', action='store',  help='ID of the Job running')

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
    parser = argparse.ArgumentParser(prog='pam rotation set')
    record_group = parser.add_mutually_exclusive_group(required=True)
    record_group.add_argument('--record', dest='record_name', action='store', help='Record UID, name, or pattern to be rotated manually or via schedule')
    record_group.add_argument('--folder', dest='folder_name', action='store', help='Folder UID or name that holds records to be rotated manually or via schedule')
    parser.add_argument('--force', '-f', dest='force', action='store_true', help='Do not ask for confirmation')
    parser.add_argument('--config', dest='config_uid', action='store', help='UID of the PAM Configuration')
    parser.add_argument('--resource', dest='resource_uid', action='store', help='UID of the resource record.')
    schedule_group = parser.add_mutually_exclusive_group()
    schedule_group.add_argument('--schedulejson', '-sj', required=False, dest='schedule_json_data', action='append', help='Json of the scheduler. Example: -sj \'{"type": "WEEKLY", "utcTime": "15:44", "weekday": "SUNDAY", "intervalCount": 1}\'')
    schedule_group.add_argument('--schedulecron', '-sc', required=False, dest='schedule_cron_data', action='append', help='Cron tab string of the scheduler. Example: to run job daily at 5:56PM UTC enter following cron -sc "56 17 * * *"')
    schedule_group.add_argument('--on-demand', '-sm', required=False, dest='on_demand', action='store_true', help='Schedule On Demand')
    parser.add_argument('--complexity',   '-x',  required=False, dest='pwd_complexity', action='store', help='Password complexity: length, upper, lower, digits, symbols. Ex. 32,5,5,5,5')
    state_group = parser.add_mutually_exclusive_group()
    state_group.add_argument('--enable', dest='enable', action='store_true', help='Enable rotation')
    state_group.add_argument('--disable', dest='disable', action='store_true', help='Disable rotation')

    def get_parser(self):
        return PAMCreateRecordRotationCommand.parser

    def execute(self, params, **kwargs):
        record_uids = set()   # type: Set[str]

        folder_uids = set()
        record_pattern = ''
        record_name = kwargs.get('record_name')
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
        valid_record_types = {'pamDatabase', 'pamDirectory', 'pamMachine', 'pamUser'}
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

        config_uid = kwargs.get('config_uid')
        pam_config = None   # type: Optional[vault.TypedRecord]
        if config_uid:
            if config_uid in pam_configurations:
                pam_config = pam_configurations[config_uid]
            else:
                raise CommandError('', f'Record uid {config_uid} is not a PAM Configuration record.')

        schedule_json_data = kwargs.get('schedule_json_data')
        schedule_cron_data = kwargs.get('schedule_cron_data')    # See this page for more details: http://www.quartz-scheduler.org/documentation/quartz-2.3.0/tutorials/crontrigger.html#examples
        schedule_on_demand = kwargs.get('on_demand') is True
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

        resource_uid = kwargs.get('resource_uid')
        if isinstance(resource_uid, str) and len(resource_uid) > 0:
            if pam_config is None:
                raise CommandError('', '"--resource" parameter requires "--config" parameter to be set as well.')
            resource_field = pam_config.get_typed_field('pamResources')
            if resource_field and isinstance(resource_field.value, list) and len(resource_field.value) > 0:
                resources = resource_field.value[0]
                if isinstance(resources, dict):
                    resource_uids = resources.get('resourceRef')
                    if isinstance(resource_uids, list):
                        if resource_uid not in resource_uids:
                            raise CommandError('', f'PAM Configuration "{pam_config.record_uid}" does not have admin credential for UID "{resource_uid}"')
            else:
                raise CommandError('', f'PAM Configuration "{pam_config.record_uid}'" does not have admin credentials")

        skipped_header = ['record_uid', 'record_title', 'problem', 'description']
        skipped_records = []
        valid_header = ['record_uid', 'record_title', 'enabled', 'configuration_uid', 'resource_uid', 'schedule', 'complexity']
        valid_records = []

        requests = []   # type: List[router_pb2.RouterRecordRotationRequest]
        for record in pam_records:
            current_record_rotation = params.record_rotation_cache.get(record.record_uid)

            # 1. PAM Configuration UID
            record_config_uid = config_uid
            record_pam_config = pam_config
            if not record_config_uid:
                if current_record_rotation:
                    record_config_uid = current_record_rotation.get('configuration_uid')
                    pc = vault.KeeperRecord.load(params, record_config_uid)
                    if pc is None:
                        skipped_records.append([record.record_uid, record.title, 'PAM Configuration was deleted', 'Specify a configuration UID parameter [--config]'])
                        continue
                    if not isinstance(pc, vault.TypedRecord) or pc.version != 6:
                        skipped_records.append([record.record_uid, record.title, 'PAM Configuration is invalid', 'Specify a configuration UID parameter [--config]'])
                        continue
                    record_pam_config = pc
                else:
                    skipped_records.append([record.record_uid, record.title, 'No current PAM Configuration', 'Specify a configuration UID parameter [--config]'])
                    continue

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
                    pwd_complexity_rule_list_encrypted = router_helper.encrypt_pwd_complexity(pwd_complexity_rule_list, record.record_key)
                else:
                    pwd_complexity_rule_list_encrypted = b''

            # 4. Resource record
            record_resource_uid = resource_uid
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
                                skipped_records.append([record.record_uid, record.title, f'PAM Configuration: {len(resource_uids)} admin resources',
                                                        'Specify both configuration UID and resource UID  [--config, --resource]'])
                                continue

            # 5. Enable rotation
            disabled = current_record_rotation.get('disabled') if current_record_rotation else False
            if kwargs.get('enable') is True:
                disabled = False
            elif kwargs.get('disable') is True:
                disabled = True

            schedule = 'On-Demand'
            if isinstance(record_schedule_data, list) and len(record_schedule_data) > 0:
                if isinstance(record_schedule_data[0], dict):
                    schedule = record_schedule_data[0].get('type')
            complexity = ''
            if pwd_complexity_rule_list_encrypted:
                try:
                    decrypted_complexity = crypto.decrypt_aes_v2(pwd_complexity_rule_list_encrypted, record.record_key)
                    c = json.loads(decrypted_complexity.decode())
                    complexity = f"{c.get('length', 0)},{c.get('caps', 0)},{c.get('lowercase', 0)},{c.get('digits', 0)},{c.get('special', 0)}"
                except:
                    pass
            valid_records.append([record.record_uid, record.title, not disabled, record_config_uid, record_resource_uid, schedule, complexity])

            # 6. Construct Request object
            rq = router_pb2.RouterRecordRotationRequest()
            if current_record_rotation:
                rq.revision = current_record_rotation.get('revision')
            rq.recordUid = utils.base64_url_decode(record.record_uid)
            rq.configurationUid = utils.base64_url_decode(record_config_uid)
            rq.resourceUid = utils.base64_url_decode(record_resource_uid) if record_resource_uid else b''
            rq.schedule = json.dumps(record_schedule_data) if record_schedule_data else ''
            rq.pwdComplexity = pwd_complexity_rule_list_encrypted
            rq.disabled = disabled
            requests.append(rq)

        force = kwargs.get('force') is True

        if len(skipped_records) > 0:
            skipped_header = [field_to_title(x) for x in skipped_header]
            dump_report_data(skipped_records, skipped_header, title='The following record(s) were skipped')

            if len(requests) > 0 and not force:
                answer = user_choice('\nDo you want to cancel password rotation?', 'Yn', 'Y')
                if answer.lower().startswith('y'):
                    return

        if len(requests) > 0:
            valid_header = [field_to_title(x) for x in valid_header]
            dump_report_data(valid_records, valid_header, title='The following record(s) will be updated')
            if not force:
                answer = user_choice('\nDo you want to update password rotation?', 'Yn', 'Y')
                if answer.lower().startswith('n'):
                    return

            for rq in requests:
                record_uid = utils.base64_url_encode(rq.recordUid)
                try:
                    router_set_record_rotation_information(params, rq)
                except KeeperApiError as kae:
                    logging.warning('Record "%s": Set rotation error "%s": %s', record_uid, kae.result_code, kae.message)
            params.sync_data = True


class PAMListRecordRotationCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotation list')
    parser.add_argument('--verbose', '-v', dest='is_verbose', action='store_true', help='Verbose output')

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
            controller_details = next((ctr for ctr in enterprise_all_controllers if ctr.controllerUid == controller_uid), None)
            configuration_uid = s.configurationUid
            configuration_uid_str = utils.base64_url_encode(configuration_uid)
            pam_configuration = next((pam_config for pam_config in all_pam_config_records if pam_config.get('record_uid') == configuration_uid_str), None)

            is_controller_online = any((poc for poc in enterprise_controllers_connected_uids_bytes if poc == controller_uid))

            row_color = ''
            if record_uid in params.record_cache:
                row_color = bcolors.HIGHINTENSITYWHITE
                rec = params.record_cache[record_uid]

                data_json = rec['data_unencrypted'].decode('utf-8') if isinstance(rec['data_unencrypted'], bytes) else rec['data_unencrypted']
                data = json.loads(data_json)

                record_title = data.get('title')
                record_type = data.get('type') or ''
            else:
                row_color = bcolors.WHITE

                record_title = '[record inaccessible]'
                record_type = '[record inaccessible]'

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
                # Find connected controller (TODO: Optimize, don't search for controllers every time, no N^n)
                router_controllers = [x.controllerUid for x in enterprise_controllers_connected.controllers]
                connected_controller = next(
                    (x for x in router_controllers if x == controller_details.controllerUid), None)

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
                    row.append(f"{bcolors.FAIL}[No config found. Looks like configuration {configuration_uid_str} was removed but rotation schedule was not modified{bcolors.ENDC}")

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
    parser.add_argument('--force', '-f', required=False, default=False, dest='is_force', action='store_true', help='Force retrieval of gateways')
    parser.add_argument('--verbose', '-v', required=False, default=False, dest='is_verbose', action='store_true', help='Verbose output')

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
                # Find connected controller (TODO: Optimize, don't search for controllers every time, no N^n)
                router_controllers = list(enterprise_controllers_connected.controllers)
                connected_controller = next((x for x in router_controllers if x.controllerUid == c.controllerUid), None)

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
                row.append(f'{row_color}{datetime.fromtimestamp(c.created/1000)}{bcolors.ENDC}')
                row.append(f'{row_color}{datetime.fromtimestamp(c.lastModified/1000)}{bcolors.ENDC}')
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

        if not pam_configuration_uid:    # Print ALL root level configs
            PAMConfigurationListCommand.print_root_rotation_setting(params, is_verbose)
        else:   # Print element configs (config that is not a root)
            PAMConfigurationListCommand.print_pam_configuration_details(params, pam_configuration_uid, is_verbose)

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
        for c in configurations:   # type: vault.TypedRecord
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
                    logging.warning(f'Following configuration is not in the shared folder: UID: %s, Title: %s', c.record_uid, c.title)
            else:
                logging.warning(f'Following configuration has unsupported type: UID: %s, Title: %s', c.record_uid, c.title)

        table.sort(key=lambda x: (x[1] or ''))
        dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


common_parser = argparse.ArgumentParser(add_help=False)
common_parser.add_argument('--config-type', '-ct', dest='config_type', action='store',
                           choices=['network', 'aws', 'azure'], help='PAM Configuration Type', )
common_parser.add_argument('--title', '-t', dest='title', action='store', help='Title of the PAM Configuration')
common_parser.add_argument('--gateway', '-g', dest='gateway', action='store', help='Gateway UID or Name')
common_parser.add_argument('--shared-folder', '-sf', dest='shared_folder', action='store',
                           help='Share Folder where this PAM Configuration is stored. Should be one of the folders to '
                                'which the gateway has access to.')
common_parser.add_argument('--resource-record', '-rr', dest='resource_records', action='append',
                           help='Resource Record UID')
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

        gateway_uid = None   # type: Optional[str]
        gateway = kwargs.get('gateway')   # type: Optional[str]
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

        shared_folder_uid = None   # type: Optional[str]
        folder_name = kwargs.get('shared_folder')    # type: Optional[str]
        if folder_name:
            if folder_name in params.shared_folder_cache:
                shared_folder_uid = folder_name
            else:
                for sf_uid in params.shared_folder_cache:
                    sf = api.get_shared_folder(params, sf_uid)
                    if sf:
                        if sf.name.casefold() == folder_name.casefold():
                            shared_folder_uid = sf_uid
                            break
        if shared_folder_uid:
            value['folderUid'] = shared_folder_uid

        rr = kwargs.get('resource_records')
        rrr = kwargs.get('remove_records')
        if rr or rrr:
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
            if isinstance(rr, list):
                for r in rr:
                    if r in pam_record_lookup:
                        record_uids.add(r)
                        continue
                    r_l = r.lower()
                    if r_l in pam_record_lookup:
                        record_uids.add(r_l)
                    self.warnings.append(f'Failed to find PAM record: {r}')

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

    def verify_required(self, record):    # type: (vault.TypedRecord) -> None
        for field in record.fields:
            if field.required:
                if len(field.value) == 0:
                    if field.type == 'schedule':
                        field.value = [{
                            'type': 'RUN_ONCE',
                            'time': '2000-01-01T00:00:00',
                            'tz': 'Etc/UTC',
                        }]
                    else:
                        self.warnings.append(f'Empty required field: "{field.get_field_name()}"')
        for custom in record.custom:
            if custom.required:
                custom.required = False


class PAMConfigurationNewCommand(Command, PamConfigurationEditMixin):
    parser = argparse.ArgumentParser(prog='pam config new', parents=[common_parser])

    def __init__(self):
        super().__init__()

    def get_parser(self):
        return PAMConfigurationNewCommand.parser

    def execute(self, params, **kwargs):
        self.warnings.clear()

        config_type = kwargs.get('config_type')
        if not config_type:
            raise CommandError('pam-config-new', '--config-type parameter is required')
        if config_type == 'aws':
            record_type = 'pamAwsConfiguration'
        elif config_type == 'azure':
            record_type = 'pamAzureConfiguration'
        else:
            record_type = 'pamNetworkConfiguration'

        title = kwargs.get('title')
        if not title:
            raise CommandError('pam-config-new', '--title parameter is required')

        record = vault.TypedRecord(version=6)
        record.type_name = record_type
        record.title = title

        rt_fields = RecordEditMixin.get_record_type_fields(params, record.record_type)
        if rt_fields:
            RecordEditMixin.adjust_typed_record_fields(record, rt_fields)

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
            raise CommandError('pam-config-new', '--shared_folder parameter is required to create a PAM configuration')

        self.verify_required(record)

        pam_configuration_create_record_v6(params, record, shared_folder_uid)

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

        return record.record_uid


class PAMConfigurationEditCommand(Command, PamConfigurationEditMixin):
    parser = argparse.ArgumentParser(prog='pam config edit', parents=[common_parser])
    parser.add_argument('--remove-resource-record', '-rrr', dest='remove_records', action='append',
                        help='Resource Record UID to remove')
    parser.add_argument('--config', '-c', required=True, dest='config', action='store',
                        help='PAM Configuration UID or Title')

    def __init__(self):
        super(PAMConfigurationEditCommand, self).__init__()

    def get_parser(self):
        return PAMConfigurationEditCommand.parser

    def execute(self, params, **kwargs):
        self.warnings.clear()

        configuration = None
        config_name = kwargs.get('config')
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
                raise CommandError('pam-config-new', '--config-type parameter is required')
            if config_type == 'aws':
                record_type = 'pamAwsConfiguration'
            elif config_type == 'azure':
                record_type = 'pamAzureConfiguration'
            elif config_type == 'network':
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

        for w in self.warnings:
            logging.warning(w)
        params.sync_data = True


class PAMConfigurationRemoveCommand(Command):
    parser = argparse.ArgumentParser(prog='pam config remove')
    parser.add_argument('--config', '-c', required=True, dest='pam_config', action='store',
                        help='PAM Configuration UID. To view all rotation settings with their UIDs, '
                             'use command `pam config list`')

    def get_parser(self):
        return PAMConfigurationRemoveCommand.parser

    def execute(self, params, **kwargs):
        pam_config_name = kwargs.get('pam_config')
        pam_config_uid = None
        for config in vault_extensions.find_records(params, record_version=6):
            if config.record_uid == pam_config_name:
                pam_config_uid = config.record_uid
                break
            if config.title.casefold() == pam_config_name.casefold():
                pass
        if not pam_config_name:
            raise Exception(f'Configuration "{pam_config_name}" not found')

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
            if rri.resourceUid:
                resource_id = utils.base64_url_encode(rri.resourceUid)
                resource_ok = False
                if resource_id in params.record_cache:
                    configuration = vault.KeeperRecord.load(params, configuration_uid)
                    if isinstance(configuration, vault.TypedRecord):
                        field = configuration.get_typed_field('pamResources')
                        if field and isinstance(field.value, list) and len(field.value) == 1:
                            rv = field.value[0]
                            if isinstance(rv, dict):
                                resources = rv.get('resourceRef')
                                if isinstance(resources, list):
                                    resource_ok = resource_id in resources
                print(f"Admin Resource Uid: {bcolors.OKBLUE if resource_ok else bcolors.FAIL}{resource_id}{bcolors.ENDC}")

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
        self.register_command('list',  PAMScriptListCommand(), 'List script fields')
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

        script_name = kwargs.get('script')   # type: Optional[str]
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

        script_name = kwargs.get('script')   # type: Optional[str]
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
        print_router_response(router_response, conversation_id)


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

        print_router_response(router_response, original_conversation_id=conversation_id, response_type='job_info')


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

        ri_rotation_setting_uid = utils.base64_url_encode(ri.configurationUid)  # Configuration on the UI is "Rotation Setting"
        resource_uid = utils.base64_url_encode(ri.resourceUid)

        pam_config = vault.KeeperRecord.load(params, ri_rotation_setting_uid)
        if not isinstance(pam_config, vault.TypedRecord):
            print(f'{bcolors.FAIL}PAM Configuration [{ri_rotation_setting_uid}] is not available.{bcolors.ENDC}')
            return
        facade = PamConfigurationRecordFacade()
        facade.record = pam_config

        # Find connected controllers
        enterprise_controllers_connected = router_get_connected_gateways(params)

        if enterprise_controllers_connected:
            # Find connected controller (TODO: Optimize, don't search for controllers every time, no N^n)
            router_controllers = list(enterprise_controllers_connected.controllers)
            controller_from_config_bytes = utils.base64_url_decode(facade.controller_uid)
            connected_controller = next((x.controllerUid for x in router_controllers
                                         if x.controllerUid == controller_from_config_bytes), None)

            if not connected_controller:
                print(f'{bcolors.WARNING}The Gateway "{facade.controller_uid}" is down.{bcolors.ENDC}')
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
            configuration_uid=ri_rotation_setting_uid,
            pwd_complexity_encrypted=ri_pwd_complexity_encrypted,
            resource_uid=resource_uid
        )

        conversation_id = GatewayAction.generate_conversation_id()

        router_response = router_send_action_to_gateway(
            params=params, gateway_action=GatewayActionRotate(inputs=action_inputs, conversation_id=conversation_id,
                                                              gateway_destination=facade.controller_uid),
            message_type=pam_pb2.CMT_ROTATE, is_streaming=False)

        print_router_response(router_response, conversation_id)


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

        print_router_response(router_response, response_type='gateway_info', is_verbose=is_verbose)


class PAMGatewayActionDiscoverCommand(Command):
    parser = argparse.ArgumentParser(prog='dr-discover-command')
    parser.add_argument('--shared-folder', '-f', required=True, dest='shared_folder_uid', action='store',
                        help='UID of the Shared Folder where results will be stored')
    parser.add_argument('--provider-record', '-p', required=True, dest='provider_record_uid', action='store',
                        help='Provider Record UID that defines network')
    # parser.add_argument('--destinations', '-d', required=False, dest='destinations', action='store',
    #                     help='Controller id')

    def get_parser(self):
        return PAMGatewayActionDiscoverCommand.parser

    def execute(self, params, **kwargs):

        provider_record_uid = kwargs.get('provider_record_uid')
        shared_folder_uid = kwargs.get('shared_folder_uid')

        action_inputs = GatewayActionDiscoverInputs(shared_folder_uid, provider_record_uid)
        conversation_id = GatewayAction.generate_conversation_id()

        router_response = router_send_action_to_gateway(
            params,
            GatewayActionDiscover(inputs=action_inputs, conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False)

        print_router_response(router_response, conversation_id)


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
                                             choices=['json', 'b64'], help='Initialize client config and return configuration string.')  # json, b64, file

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











############################################## TUNNELING ###############################################################
class PAMTunnelListCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel list')

    def get_parser(self):
        return PAMTunnelListCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        def gather_tabel_row_data(thread):
            # {"thread": t, "host": host, "port": port, "started": datetime.now(),
            row = []
            run_time = None
            hours = 0
            minutes = 0
            seconds = 0

            entrance = thread.get('entrance')
            #
            # row.append(f"{thread.get('name', '')}")
            if entrance is not None:
                row.append(f"{bcolors.OKBLUE}{entrance.pc.endpoint_name}{bcolors.ENDC}")
            else:
                row.append(f"{bcolors.WARNING}Connecting..{bcolors.ENDC}")

            row.append(f"{thread.get('host', '')}")

            if entrance is not None and entrance.print_ready_event.is_set():
                if thread.get('started'):
                    run_time = datetime.now() - thread.get('started')
                    hours, remainder = divmod(run_time.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)

                row.append(
                    f"{bcolors.OKBLUE}{entrance._port}{bcolors.ENDC}"
                )
            else:
                row.append(f"{bcolors.WARNING}Connecting...{bcolors.ENDC}")
            row.append(f"{thread.get('record_uid', '')}")
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
                row.append(text_line)
            else:
                row.append(f"{bcolors.WARNING}Connecting...{bcolors.ENDC}")
            return row

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


def retrieve_gateway_public_key(gateway_uid, params, api, utils) -> bytes:
    gateway_uid_bytes = utils.base64_url_decode(gateway_uid)
    get_ksm_pubkeys_rq = GetKsmPublicKeysRequest()
    get_ksm_pubkeys_rq.controllerUids.append(gateway_uid_bytes)
    get_ksm_pubkeys_rs = api.communicate_rest(params, get_ksm_pubkeys_rq, 'vault/get_ksm_public_keys',
                                              rs_type=GetKsmPublicKeysResponse)

    if len(get_ksm_pubkeys_rs.keyResponses) == 0:
        # No keys found
        print(f"{bcolors.FAIL}No keys found for gateway {gateway_uid}{bcolors.ENDC}")
        return b''
    try:
        gateway_public_key_bytes = get_ksm_pubkeys_rs.keyResponses[0].publicKey
    except Exception as e:
        # No public key found
        print(f"{bcolors.FAIL}Error getting public key for gateway {gateway_uid}: {e}{bcolors.ENDC}")
        gateway_public_key_bytes = b''

    return gateway_public_key_bytes


class PAMTunnelEnableCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel enable')
    pam_cmd_parser.add_argument('uid', type=str, action='store', help='The Record UID of the PAM '
                                                                      'resource record with network information to use '
                                                                      'for tunneling')
    pam_cmd_parser.add_argument('--configuration', '-c', required=False, dest='config', action='store',
                                help='The PAM Configuration UID to use for tunneling. '
                                     'Use command `pam config list` to view available PAM Configurations.')

    def get_parser(self):
        return PAMTunnelEnableCommand.pam_cmd_parser

    def execute(self, params, **kwargs):
        record_uid = kwargs.get('uid')
        config_uid = kwargs.get('config')
        if not record_uid:
            raise CommandError('tunnel Enable', '"record UID" argument is required')
        dirty = False

        record = vault.KeeperRecord.load(params, record_uid)

        if not isinstance(record, vault.TypedRecord):
            print(f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
            return

        record_type = record.record_type
        if record_type not in "pamMachine pamDatabase pamDirectory".split():
            print(f"{bcolors.FAIL}This record's type is not supported for tunnels. "
                  f"Tunnels are only supported on Pam Machine, Pam Database, and Pam Directory records{bcolors.ENDC}")
            return

        if config_uid:
            configuration = vault.KeeperRecord.load(params, config_uid)
            if not isinstance(configuration, vault.TypedRecord):
                print(f"{bcolors.FAIL}Configuration {config_uid} not found.{bcolors.ENDC}")
                return
            if (configuration.record_type not in
                    'pamNetworkConfiguration pamAwsConfiguration pamAzureConfiguration'.split()):
                print(f"{bcolors.FAIL}The record {config_uid} is not a Pam Configuration.{bcolors.ENDC}")
                return

        pam_settings = record.get_typed_field('pamSettings')
        if not pam_settings:
            pre_settings = {"portForward": {"enabled": True}}
            if config_uid:
                pre_settings["configUid"] = config_uid
            pam_settings = vault.TypedField.new_field('pamSettings', pre_settings, "")
            record.custom.append(pam_settings)
            dirty = True
        else:
            if config_uid:
                if pam_settings.value[0].get('configUid') != config_uid:
                    pam_settings.value[0]['configUid'] = config_uid
                    dirty = True
            if not pam_settings.value[0]['portForward']['enabled']:
                pam_settings.value[0]['portForward']['enabled'] = True
                dirty = True
        if not pam_settings.value[0].get('configUid'):
            print(f"{bcolors.FAIL}No PAM Configuration UID set. This must be set for tunneling to work. "
                  f"This can be done by running 'pam tunnel enable {record_uid} --config [ConfigUID]' "
                  f"The ConfigUID can be found by running 'pam config list'{bcolors.ENDC}")
            return

        client_private_key = record.get_typed_field('trafficEncryptionKey')
        if not client_private_key:
            # Generate an EC private key
            # TODO: maybe try to use keeper method to generate key
            # private_key, _ = crypto.generate_ec_key()
            # client_private_key_value = crypto.unload_ec_private_key(private_key).decode('utf-8')
            private_key = ec.generate_private_key(
                ec.SECP256R1(),  # Using P-256 curve
                backend=default_backend()
            )
            # Serialize to PEM format
            client_private_key_value = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            client_private_key = vault.TypedField.new_field('trafficEncryptionKey',
                                                            client_private_key_value, "")
            record.custom.append(client_private_key)
            dirty = True

        if dirty:
            record_management.update_record(params, record)
            api.sync_down(params)
        if pam_settings.value[0].get('configUid'):
            print(f"{bcolors.OKGREEN}Tunneling enabled for {record_uid} using configuration "
                  f"{pam_settings.value[0].get('configUid')} {bcolors.ENDC}")
        else:
            print(f"{bcolors.OKGREEN}Tunneling enabled for {record_uid}{bcolors.ENDC}")


class PAMTunnelDisableCommand(Command):
    pam_cmd_parser = argparse.ArgumentParser(prog='pam tunnel disable')
    pam_cmd_parser.add_argument('uid', type=str, action='store', help='The Record UID of the PAM '
                                                                      'resource record with network information to use '
                                                                      'for tunneling')

    def get_parser(self):
        return PAMTunnelDisableCommand.pam_cmd_parser

    def execute(self, params, **kwargs):

        record_uid = kwargs.get('uid')
        if not record_uid:
            raise CommandError('tunnel Disable', '"record" argument is required')

        record = vault.KeeperRecord.load(params, record_uid)

        if not isinstance(record, vault.TypedRecord):
            print(f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
            return

        pam_settings = record.get_typed_field('pamSettings')
        if pam_settings:
            if pam_settings.value[0]['portForward']['enabled']:
                pam_settings.value[0]['portForward']['enabled'] = False
                record_management.update_record(params, record)
                api.sync_down(params)
        print(f"{bcolors.OKGREEN}Tunneling disabled for {record_uid}{bcolors.ENDC}")


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

    async def connect(self, params, record_uid, convo_num, gateway_uid, host, port,
                      log_queue, gateway_public_key_bytes, client_private_key):

        # Setup custom logging to put logs into log_queue
        logger = self.setup_logging(str(convo_num), log_queue, logging.getLogger().getEffectiveLevel())

        print(f"{bcolors.HIGHINTENSITYWHITE}Establishing tunnel between Commander and Gateway. Please wait...{bcolors.ENDC}")
        # get the keys
        gateway_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), gateway_public_key_bytes)

        """
# Generate an EC private key
private_key = ec.generate_private_key(
    ec.SECP256R1(),  # Using P-256 curve
    backend=default_backend()
)
# Serialize to PEM format
private_key_str = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')
        """

        client_private_key_pem = serialization.load_pem_private_key(
            client_private_key.encode(),
            password=None,
            backend=default_backend()
        )

        # Get symmetric key
        symmetric_key = establish_symmetric_key(client_private_key_pem, gateway_public_key)

        # Set up the pc
        print_ready_event = asyncio.Event()
        kill_server_event = asyncio.Event()
        pc = WebRTCConnection(params=params, record_uid=record_uid, gateway_uid=gateway_uid,
                              symmetric_key=symmetric_key, print_ready_event=print_ready_event,
                              kill_server_event=kill_server_event, logger=logger, server=params.server)

        try:
            await pc.signal_channel('start')
        except Exception as e:
            raise CommandError('Tunnel Start', f"{e}")

        logger.debug("starting private tunnel")

        private_tunnel = TunnelEntrance(host=host, port=port, pc=pc, print_ready_event=print_ready_event, logger=logger,
                                        connect_task=params.tunnel_threads[convo_num].get("connect_task", None),
                                        kill_server_event=kill_server_event)

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

    def pre_connect(self, params, record_uid, convo_num, gateway_uid, host, port,
                    gateway_public_key_bytes, client_private_key):
        tunnel_name = f"{convo_num}"
        def custom_exception_handler(loop, context):
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
                    convo_num=convo_num,
                    gateway_uid=gateway_uid,
                    host=host,
                    port=port,
                    log_queue=output_queue,
                    gateway_public_key_bytes=gateway_public_key_bytes,
                    client_private_key=client_private_key
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
                    print(f"{bcolors.FAIL}An exception occurred in pre_connect for connection {tunnel_name}: {e}{bcolors.ENDC}")
                finally:
                    clean_up_tunnel(params, convo_num)
                    print(f"{bcolors.OKBLUE}Tunnel {tunnel_name} closed.{bcolors.ENDC}")

    def execute(self, params, **kwargs):
        # https://pypi.org/project/aiortc/
        # aiortc Requires: Python >=3.8
        version = [3, 8, 0]
        major_version = sys.version_info.major
        minor_version = sys.version_info.minor
        micro_version = sys.version_info.micro

        if (major_version, minor_version, micro_version) < (version[0], version[1], version[2]):
            print(f"{bcolors.FAIL}This code requires Python {version[0]}.{version[1]}.{version[2]} or higher. "
                  f"You are using {major_version}.{minor_version}.{micro_version}.{bcolors.ENDC}")
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
                return
        else:
            port = find_open_port(tried_ports=[], host=host)
            if port is None:
                print(f"{bcolors.FAIL}Could not find open port to use for tunnel{bcolors.ENDC}")
                return

        api.sync_down(params)
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            print(f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
            return

        pam_settings = record.get_typed_field('pamSettings')
        if not pam_settings:
            print(f"{bcolors.FAIL}PAM Settings not enabled for record {record_uid}'.{bcolors.ENDC}")
            print(f"{bcolors.WARNING}This is done by running 'pam tunnel enable {record_uid} "
                  f"--config [ConfigUID]' The ConfigUID can be found by running 'pam config list'{bcolors.ENDC}.")
            return

        try:
            pam_info = pam_settings.value[0]
            enabled_port_forward = pam_info.get("portForward", {}).get("enabled", False)
            if not enabled_port_forward:
                print(f"{bcolors.FAIL}PAM Settings not enabled for record {record_uid}. "
                      f"{bcolors.WARNING}This is done by running 'pam tunnel enable {record_uid}'.{bcolors.ENDC}")
                return
        except Exception as e:
            print(f"{bcolors.FAIL}Error parsing PAM Settings for record {record_uid}: {e}{bcolors.ENDC}")
            return

        client_private_key = record.get_typed_field('trafficEncryptionKey')
        if not client_private_key:
            print(f"{bcolors.FAIL}Traffic Encryption Key not found for record {record_uid}.{bcolors.ENDC}")
            return

        client_private_key_value = client_private_key.get_default_value(str)

        configuration_uid = pam_info.get("configUid", None)
        if not configuration_uid:
            print(f"{bcolors.FAIL}Configuration UID not found for record {record_uid}.{bcolors.ENDC}")
            return
        configuration = vault.KeeperRecord.load(params, configuration_uid)
        if not isinstance(configuration, vault.TypedRecord):
            print(f"{bcolors.FAIL}Configuration {configuration_uid} not found.{bcolors.ENDC}")
            return

        pam_resources = configuration.get_typed_field('pamResources')
        if not pam_resources:
            print(f"{bcolors.FAIL}PAM Resources not found for configuration {configuration_uid}.{bcolors.ENDC}")
            return
        if len(pam_resources.value) == 0:
            print(f"{bcolors.FAIL}PAM Resources not found for configuration {configuration_uid}.{bcolors.ENDC}")
            return
        gateway_uid = ''
        try:
            gateway_uid = pam_resources.value[0].get("controllerUid", '')
        except Exception as e:
            print(f"{bcolors.FAIL}Error parsing PAM Resources for configuration {configuration_uid}: {e}{bcolors.ENDC}")
            CommandError('Tunnel Start', f"{e}")

        if not gateway_uid:
            print(f"{bcolors.FAIL}Gateway UID not found for configuration {configuration_uid}.{bcolors.ENDC}")
            return

        gateway_public_key_bytes = retrieve_gateway_public_key(gateway_uid, params, api, utils)

        if not gateway_public_key_bytes:
            print(f"{bcolors.FAIL}Could not retrieve public key for gateway {gateway_uid}{bcolors.ENDC}")
            return

        t = threading.Thread(target=self.pre_connect, args=(params, record_uid, convo_num, gateway_uid, host, port,
                                                            gateway_public_key_bytes, client_private_key_value)
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

