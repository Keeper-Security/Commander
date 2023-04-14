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
import json
import logging
from datetime import datetime
from typing import Dict, Optional, Any

import requests
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from .base import Command, GroupCommand, dump_report_data
from .folder import FolderMoveCommand
from .ksm import KSMCommand
from .pam import gateway_helper, router_helper
from .pam.config_facades import PamConfigurationRecordFacade
from .pam.config_helper import pam_configurations_get_all, pam_configuration_get_one, \
    pam_configuration_remove, pam_configuration_create_record_v6, record_rotation_get, \
    pam_configuration_get_single_value_from_field_by_id, pam_decrypt_configuration_data
from .pam.pam_dto import GatewayActionGatewayInfo, GatewayActionDiscoverInputs, GatewayActionDiscover, \
    GatewayActionRotate, \
    GatewayActionRotateInputs, GatewayAction, GatewayActionJobInfoInputs, \
    GatewayActionJobInfo, GatewayActionJobCancel
from .pam.router_helper import router_send_action_to_gateway, print_router_response, \
    router_get_connected_gateways, router_set_record_rotation_information, router_get_rotation_schedules, get_router_url
from .record_edit import RecordEditMixin
from .. import api, utils, vault_extensions, vault, record_management
from ..display import bcolors
from ..error import CommandError
from ..params import KeeperParams, LAST_RECORD_UID
from ..proto import pam_pb2, router_pb2, record_pb2
from ..subfolder import find_parent_top_folder


def register_commands(commands):
    commands['pam'] = PAMControllerCommand()


def register_command_info(_, command_info):
    command_info['pam'] = 'Manage PAM Components'


class PAMControllerCommand(GroupCommand):

    def __init__(self):
        super(PAMControllerCommand, self).__init__()
        self.register_command('gateway', PAMGatewayCommand(), 'Manage Gateways', 'g')
        self.register_command('config', PAMConfigurationsCommand(), 'Manage PAM Configurations', 'c')
        self.register_command('rotation', PAMRotationCommand(), 'Manage Rotations', 'r')
        self.register_command('action', GatewayActionCommand(), 'Execute action on the Gateway', 'a')


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
        self.register_command('new',  PAMCreateRecordRotationCommand(), 'Create New Record Rotation Schedule', 'n')
        self.register_command('list', PAMListRecordRotationCommand(), 'List Record Rotation Schedulers', 'l')
        self.register_command('info', PAMRouterGetRotationInfo(), 'Get Rotation Info', 'i')
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
        # self.register_command('tunnel', DRTunnelCommand(), 'Tunnel to the server')


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
    parser = argparse.ArgumentParser(prog='pam rotation new')
    parser.add_argument('--record',       '-r',  required=True, dest='record_uid', action='store', help='Record UID that will be rotated manually or via schedule')
    parser.add_argument('--config',       '-c',  required=True, dest='config_uid', action='store', help='UID of the PAM Configuration.')
    parser.add_argument('--resource',     '-rs',  required=False, dest='resource_uid', action='store', help='UID of the resource recourd.')
    parser.add_argument('--schedulejson', '-sj', required=False, dest='schedule_json_data', action='append', help='Json of the scheduler. Example: -sj \'{"type": "WEEKLY", "utcTime": "15:44", "weekday": "SUNDAY", "intervalCount": 1}\'')
    parser.add_argument('--schedulecron', '-sc', required=False, dest='schedule_cron_data', action='append', help='Cron tab string of the scheduler. Example: to run job daily at 5:56PM UTC enter following cron -sc "0 56 17 * * ?"')
    parser.add_argument('--complexity',   '-x',  required=False, dest='pwd_complexity', action='store', help='Password complexity: length, upper, lower, digits, symbols. Ex. 32,5,5,5,5')

    def get_parser(self):
        return PAMCreateRecordRotationCommand.parser

    def execute(self, params, **kwargs):

        record_uid = kwargs.get('record_uid')
        config_uid = kwargs.get('config_uid')
        resource_uid = kwargs.get('resource_uid')
        pwd_complexity = kwargs.get("pwd_complexity")

        schedule_json_data = kwargs.get('schedule_json_data')
        schedule_cron_data = kwargs.get('schedule_cron_data') # See this page for more details: http://www.quartz-scheduler.org/documentation/quartz-2.3.0/tutorials/crontrigger.html#examples

        # Check if record uid is available to this user
        record_to_rotate = params.record_cache.get(record_uid)
        if not record_to_rotate:
            print(f'{bcolors.FAIL}Record [{record_uid}] is not available.{bcolors.ENDC}')
            return

        if schedule_json_data and schedule_cron_data:
            print(f'{bcolors.WARNING}Only one type of the schedule is allowed, JSON or Cron.{bcolors.ENDC}')
            return

        if schedule_json_data:
            schedule_data = [json.loads(x) for x in schedule_json_data]
        else:
            schedule_data = schedule_cron_data

        # 2. Load password complexity rules
        if not pwd_complexity:
            pwd_complexity_rule_list_encrypted = b''
        else:
            pwd_complexity_list = [s.strip() for s in pwd_complexity.split(',')]
            if len(pwd_complexity_list) != 5 or not all(n.isnumeric() for n in pwd_complexity_list):
                logging.warning(
                    'Invalid rules to generate password. Format is "length, upper, lower, digits, symbols". Ex: 32,5,5,5,5'
                )
                return

            rule_list_dict = {
                'length': int(pwd_complexity_list[0]),
                'caps': int(pwd_complexity_list[1]),
                'lowercase': int(pwd_complexity_list[2]),
                'digits': int(pwd_complexity_list[3]),
                'special': int(pwd_complexity_list[4])
            }

            pwd_complexity_rule_list_encrypted = router_helper.encrypt_pwd_complexity(rule_list_dict, record_to_rotate.get('record_key_unencrypted'))


        # 3. Resource record check

        pam_config = pam_configuration_get_one(params, config_uid)
        pamResourcesField = pam_configuration_get_single_value_from_field_by_id(pam_config.get('data_decrypted'), 'pamresources')
        resources = pamResourcesField.get('resourceRef')

        if len(resources) > 1 and resource_uid is None:
            print(f"{bcolors.WARNING}There are more than 1 resource associated with this configuration. "
                  f"Please provide UID of the resource to be associated with this rotation by supplying UID using "
                  f"'--resource' or '-rs' flag{bcolors.ENDC}")
            return
        elif len(resources) > 1 and resource_uid:
            found_resource = next((r for r in resources if r == resource_uid), None)

            if not found_resource:
                print(f"{bcolors.WARNING}The resource UID provided does not mach any of theresources associated to "
                      f"this configuration. Following resources are part of this configuration: "
                      f"{','.join(resources)}{bcolors.ENDC}")
                return
        else:
            # Means that there is only one resource
            resource_uid = resources[0]


        # 4. Construct Request object
        rq = router_pb2.RouterRecordRotationRequest()
        rq.recordUid = url_safe_str_to_bytes(record_uid)
        rq.configurationUid = url_safe_str_to_bytes(config_uid)
        rq.resourceUid = url_safe_str_to_bytes(resource_uid)
        rq.schedule = json.dumps(schedule_data) if schedule_data else ''
        rq.pwdComplexity = pwd_complexity_rule_list_encrypted
        rs = router_set_record_rotation_information(params, rq)

        print(f"Successfully saved new Record Rotation Setting.")

        if schedule_json_data and schedule_cron_data:
            print(f"Rotation of the record [{record_uid}] was scheduled to rotate using following schedule setting: {bcolors.OKBLUE}{schedule_data}{bcolors.ENDC}")
        else:
            print(f"Rotation of this record can only be performed manually")
        print(f"To rotate manually use the following command: {bcolors.OKGREEN}pam action rotate -r {record_uid}{bcolors.ENDC}")


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
        schedules = list(schedules_proto.schedules)

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
            if enterprise_controllers_connected:
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
                           help='Share Folder where this PAM Configuration is stored')
common_parser.add_argument('--resource-record', '-rr', dest='resource_records', action='append',
                           help='Resource Record UID')
common_parser.add_argument('--schedule', '-sc', dest='default_schedule', action='store', help='Default Schedule')
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
            print(f'PAM Config UID: {bcolors.OKBLUE}{utils.base64_url_encode(rri.configurationUid)}{bcolors.ENDC}')
            print(f'Node ID: {bcolors.OKBLUE}{rri.nodeId}{bcolors.ENDC}')

            print(f"Gateway Name where the rotation will be performed: {bcolors.OKBLUE}{(rri.controllerName if rri.controllerName else '-')}{bcolors.ENDC}")
            print(f"Gateway Uid: {bcolors.OKBLUE}{(utils.base64_url_encode(rri.controllerUid) if rri.controllerUid else '-') } {bcolors.ENDC}")
            # print(f"Router Cookie: {bcolors.OKBLUE}{(rri.cookie if rri.cookie else '-')}{bcolors.ENDC}")
            # print(f"scriptName: {bcolors.OKGREEN}{rri.scriptName}{bcolors.ENDC}")
            print(f"Password Complexity: {bcolors.OKGREEN}{rri.pwdComplexity if rri.pwdComplexity else '[not set]'}{bcolors.ENDC}")
            print(f"Is Rotation Disabled: {bcolors.OKGREEN}{rri.disabled}{bcolors.ENDC}")
            print(f"\nCommand to manually rotate: {bcolors.OKGREEN}pam action rotate -r {record_uid}{bcolors.ENDC}")
        else:
            print(f'{bcolors.WARNING}Rotation Status: Not ready to rotate ({rri_status_name}){bcolors.ENDC}')


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

        ri_rotation_setting_uid = utils.base64_url_encode(ri.configurationUid)  # Configuration on the UI is "Rotation Setting"
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
            record_uid=record_uid, configuration_uid=ri_rotation_setting_uid,
            pwd_complexity_encrypted=ri_pwd_complexity_encrypted)

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


class PAMTunnelCommand(Command):
    parser = argparse.ArgumentParser(prog='dr-tunnel-command')
    parser.add_argument('--uid', '-u', required=True, dest='record_uid', action='store',
                        help='UID of the record that has server credentials')
    parser.add_argument('--destinations', '-d', required=False, dest='destinations', action='store',
                        help='Controller ID')

    def get_parser(self):
        return PAMTunnelCommand.parser

    def execute(self, params, **kwargs):
        record_uid = kwargs.get('record_uid')

        print(f'record_uid = [{record_uid}]')

        if getattr(params, 'ws', None) is None:
            logging.warning(f'Connection doesn\'t exist. Please connect to the router before executing '
                            f'actions using following command {bcolors.OKGREEN}dr connect{bcolors.ENDC}')
            return

        destinations = kwargs.get('destinations', [])

        action = kwargs.get('action', [])

        command_payload = {
            'action': action,
            # 'args': command_arr[1:] if len(command_arr) > 1 else []
            # 'kwargs': kwargs
        }

        params.ws.send(command_payload, destinations)

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


"""
WS_INIT = {'kind': 'init'}
WS_LOG_FOLDER = 'dr-logs'
WS_HEADERS = {
    'ClientVersion': 'ms16.2.4'
}
WS_SERVER_PING_INTERVAL_SEC = 5


pam_cmd_parser = argparse.ArgumentParser(prog='dr-cmd')
pam_cmd_parser.add_argument('--dest', '-d', nargs='*', type=str, action='store', dest='destinations',
                            help='Destination, usually Controller Client ID')
pam_cmd_parser.add_argument('command', nargs='*', type=str, action='store', help='Controller command')


class PAMConnection:
    def __init__(self):
        if not os.path.isdir(WS_LOG_FOLDER):
            os.makedirs(WS_LOG_FOLDER)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

        # one log file per opened connection
        self.ws_log_file = os.path.join(WS_LOG_FOLDER, f'{timestamp}.log')
        self.ws_app = None
        self.thread = None

    def connect(self, session_token):
        try:
            import websocket
        except ImportError:
            logging.warning(f'websocket-client module is missing. '
                            f'Use following command to install it '
                            f'`{bcolors.OKGREEN}pip3 install -U websocket-client{bcolors.ENDC}`')
            return

        headers = WS_HEADERS
        headers['Authorization'] = f'User {session_token}'
        self.ws_app = websocket.WebSocketApp(
            f'{WS_URL}?Auth={session_token}&AuthType=User',
            header=headers,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        self.thread = Thread(target=self.ws_app.run_forever, kwargs={
            'ping_interval': WS_SERVER_PING_INTERVAL_SEC,
            # frequency how ofter ping is send to the server to keep the connection alive
            'ping_payload': 'client-hello'
        },
                             daemon=True)
        self.thread.start()

    def disconnect(self):
        if self.thread and self.thread.is_alive():
            self.ws_app.close()
            self.thread.join()

    def init(self):
        # self.ws_app.send(json.dumps(WS_INIT))
        self.log('Connection initialized')

    def log(self, msg, time=True):
        with open(self.ws_log_file, 'a') as ws_log:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f ') if time else ''
            ws_log.write(f'{timestamp}{msg}\n')

    def send(self, command_payload, destination_client_ids=None):
        data_dict = {}

        data_dict['kind'] = 'command'
        data_dict['payload'] = command_payload

        if destination_client_ids:
            # Send only to specified clients, else will send to all clients
            data_dict['clientIds'] = [destination_client_ids]

        data_json = json.dumps(data_dict)

        self.ws_app.send(data_json)
        self.log(f'Data sent {data_json}')

    def process_event(self, event):
        self.log(f'New Event to process [{event}]')

        event_kind = event.get('kind', None)

        if event_kind:
            if event_kind == 'ctl_state':
                new_controllers = event['controllers']
                # dropped = self.controllers - new_controllers
                self.log(f'Controller state: {new_controllers}')
            elif event_kind == 'ctl_response':
                payload = event.get('payload')

                if utils.is_json(payload):
                    is_success = payload.get('success')
                    status_message = payload.get('statusMessage')
                    data = payload['data']
                    self.log(f'is_success: [{is_success}], status_message: [{status_message}], data: [{data}]')

                else:
                    data = payload
                    self.log(f'Guacd response data: [{data}]')

            else:
                self.log(f'Event: {event}')
        else:
            self.log(f'No event kind was sent')

            if 'message' in event:
                logging.warning(event.get('message'))
            else:
                logging.warning(str(event))

    def on_open(self, ws):
        self.log('Connection open')
        self.init()

    def on_message(self, ws, event_json):
        self.log(f'ws.listener.on_message:{event_json}')

        try:
            event = json.loads(event_json)
        except json.decoder.JSONDecodeError:
            self.log(f'Raw event: {event_json}')
        else:
            self.process_event(event)

    def on_error(self, ws, error_event):
        self.log(f'ws.listener.on_error:{error_event}')

    def on_close(self, ws, close_status_code, close_msg):
        self.log(f'ws.listener.on_close: close_status_code=[{close_status_code}], close_msg=[{close_msg}]')


class PAMConnect(Command):
    parser = argparse.ArgumentParser(prog='pam gateway connect')
    def get_parser(self):
        return PAMConnect.parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            params.ws = PAMConnection()
            params.ws.connect(params.session_token)
            logging.info(f'Connected {params.config["device_token"]}')
        else:
            logging.warning('Connection exists')


class PAMDisconnect(Command):
    parser = argparse.ArgumentParser(prog='dr-disconnect')

    def get_parser(self):
        return PAMDisconnect.parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            logging.warning("Connection doesn't exist")
        else:
            params.ws.disconnect()
            params.ws = None
"""
