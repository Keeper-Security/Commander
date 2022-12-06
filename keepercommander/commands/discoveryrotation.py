#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2022 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#
import argparse
import json
import logging
import os
from datetime import datetime
from threading import Thread

import requests
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes, bytes_to_string

from keepercommander.commands.base import raise_parse_exception, suppress_exit, Command
from keepercommander.display import bcolors
from .base import GroupCommand, dump_report_data
from .pam import gateway_helper, router_helper
from .pam.config_helper import config_get_all, config_create, config_get_one, config_remove
from .pam.gateway_helper import create_gateway
from .pam.pam_dto import GatewayActionGatewayInfo, GatewayActionDiscoverInputs, GatewayActionDiscover, \
    GatewayActionRotate, \
    GatewayActionRotateInputs, GatewayAction, GatewayActionListAccessRecords, GatewayActionJobInfoInputs, \
    GatewayActionJobInfo, GatewayActionJobCancel
from .pam.router_helper import router_send_action_to_gateway, print_router_response, \
    router_get_record_rotation_info, \
    router_get_connected_gateways, router_set_record_rotation_information, router_get_rotation_schedules
from .utils import KSMCommand
from ..loginv3 import CommonHelperMethods
from ..proto.enterprise_pb2 import RouterRotationStatus, RouterRecordRotationRequest, PAMGenericUidsRequest
from ..utils import is_json, base64_url_encode

WS_INIT = {'kind': 'init'}
WS_LOG_FOLDER = 'dr-logs'
WS_URL = 'localho'
WS_HEADERS = {
    'ClientVersion': 'ms16.2.4'
}

WS_SERVER_PING_INTERVAL_SEC = 5


pam_list_controllers_parser = argparse.ArgumentParser(prog='dr-list-gateways')
pam_list_controllers_parser.add_argument('--connected', '-c', dest='connected_only', action='store_true',
                                         help='Return only active Gateways that are connected')
pam_list_controllers_parser.error = raise_parse_exception
pam_list_controllers_parser.exit = suppress_exit

pam_connect_parser = argparse.ArgumentParser(prog='dr-connect')
pam_connect_parser.error = raise_parse_exception
pam_connect_parser.exit = suppress_exit

pam_disconnect_parser = argparse.ArgumentParser(prog='dr-disconnect')
pam_disconnect_parser.error = raise_parse_exception
pam_disconnect_parser.exit = suppress_exit

pam_cmd_parser = argparse.ArgumentParser(prog='dr-cmd')
pam_cmd_parser.add_argument('--dest', '-d', nargs='*', type=str, action='store', dest='destinations',
                            help='Destination, usually Controller Client ID')
pam_cmd_parser.add_argument('command', nargs='*', type=str, action='store', help='Controller command')
pam_cmd_parser.error = raise_parse_exception
pam_cmd_parser.exit = suppress_exit


def register_commands(commands):
    commands['pam'] = PAMControllerCommand()


def register_command_info(_, command_info):
    command_info['pam'] = 'Manage PAM Components'


class PAMControllerCommand(GroupCommand):

    def __init__(self):
        super(PAMControllerCommand, self).__init__()
        self.register_command('gateway', PAMGatewayCommand(), 'Manage PAM Gateways')
        self.register_command('action', GatewayActionCommand(), 'Execute action on the Gateway')
        self.register_command('config', PAMConfigsCommand(), 'Manage PAM Configurations')
        self.register_command('rotation', PAMRotationCommand(), 'Manage Rotations')


class PAMRotationCommand(GroupCommand):

    def __init__(self):
        super(PAMRotationCommand, self).__init__()
        self.register_command('new',  PAMCreateRecordRotationCommand(), 'Create New Record Rotation Schedule')
        self.register_command('list', PAMListRecordRotationCommand(), 'List Record Rotation Schedulers')
        self.register_command('info', PAMRouterGetRotationInfo(), 'Get Rotation Info')


class PAMGatewayCommand(GroupCommand):

    def __init__(self):
        super(PAMGatewayCommand, self).__init__()
        self.register_command('list', PAMGatewayListCommand(), 'View Gateways')
        self.register_command('new', PAMCreateGatewayCommand(), 'Create new Gateway')
        self.register_command('remove', PAMGatewayRemoveCommand(), 'Remove Gateway')
        # self.register_command('connect', PAMConnect(), 'Connect')
        # self.register_command('disconnect', PAMDisconnect(), 'Disconnect')


class GatewayActionCommand(GroupCommand):

    def __init__(self):
        super(GatewayActionCommand, self).__init__()
        self.register_command('gateway-info', PAMGatewayActionServerInfoCommand(), 'Info command')
        # self.register_command('discover', GatewayActionDiscoverCommand(), 'Discover command')
        self.register_command('rotate', PAMGatewayActionRotateCommand(), 'Rotate command')
        self.register_command('job-info', PAMGatewayActionJobCommand(), 'View Job details')
        self.register_command('job-cancel', PAMGatewayActionJobCommand(), 'View Job details')

        # self.register_command('list-jobs', DRCmdListJobs(), 'List Running jobs')
        # self.register_command('tunnel', DRTunnelCommand(), 'Tunnel to the server')


class PAMConfigsCommand(GroupCommand):

    def __init__(self):
        super(PAMConfigsCommand, self).__init__()
        self.register_command('new', PAMConfigNewCommand(), "Create new configuration")
        self.register_command('list', DRExecListConfigsCommand(), 'List available configurations on the Gateway')
        self.register_command('list-access-records', DRExecListAccessRecordsCommand(), 'List available Access Records')
        self.register_command('remove', PAMConfigRemoveCommand(), "Remove a configuration")


class PAMCmdListJobs(Command):
    dr_cmd_list_jobs_command_parser = argparse.ArgumentParser(prog='dr-list-jobs-command')
    dr_cmd_list_jobs_command_parser.add_argument('--jobId', '-j', required=False, dest='job_id', action='store',
                                                 help='ID of the Job running')
    dr_cmd_list_jobs_command_parser.error = raise_parse_exception
    dr_cmd_list_jobs_command_parser.exit = suppress_exit

    def get_parser(self):
        return self.dr_cmd_list_jobs_command_parser

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
    pam_scheduler_new_parser = argparse.ArgumentParser(prog='pam-create-record-rotation-scheduler')
    pam_scheduler_new_parser.add_argument('--record', '-r', required=True, dest='record_uid', action='store',
                                          help='Record UID that will be rotated manually or via schedule')
    pam_scheduler_new_parser.add_argument('--config', '-c', required=True, dest='config_uid', action='store',
                                          help='UID of the resource configuration '
                                               'record. Note that this is not the '
                                               'Access Record, but the second, child, '
                                               'record in the configuration')
    pam_scheduler_new_parser.add_argument('--schedulejson', '-sj', required=False, dest='schedule_json_data',
                                          action='append',
                                          help='Json of the scheduler. Example: -sj \'{"type": "WEEKLY", "utcTime": '
                                               '"15:44", "weekday": "SUNDAY", "intervalCount": 1}\'')
    pam_scheduler_new_parser.add_argument('--schedulecron', '-sc', required=False, dest='schedule_cron_data',
                                          action='append', help='Cron tab string of the scheduler. Example: to run job '
                                                                'daily at 5:56PM UTC enter following cron -sc "0 56 17 * * ?"')
    pam_scheduler_new_parser.add_argument('--complexity', '-p', required=False, dest='pwd_complexity', action='store',
                                          help='Password complexity: length, upper, lower, digits, symbols. Ex. 32,5,5,'
                                               '5,5')
    pam_scheduler_new_parser.add_argument('--script', '-s', required=False, dest='script_file_name', action='store',
                                          help='Post execution script file name')

    pam_scheduler_new_parser.error = raise_parse_exception
    pam_scheduler_new_parser.exit = suppress_exit

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return self.pam_scheduler_new_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any

        record_uid = kwargs.get('record_uid')
        config_uid = kwargs.get('config_uid')
        rule_string = kwargs.get("pwd_complexity")
        script_name = kwargs.get('script_file_name')

        schedule_json_data = kwargs.get('schedule_json_data')
        schedule_cron_data = kwargs.get('schedule_cron_data') # See this page for more details: http://www.quartz-scheduler.org/documentation/quartz-2.3.0/tutorials/crontrigger.html#examples

        if schedule_json_data and schedule_cron_data:
            print(f'{bcolors.WARNING}Only one type of the schedule is allowed, JSON or Cron.{bcolors.ENDC}')
            return

        if schedule_json_data:
            schedule_data = [json.loads(x) for x in schedule_json_data]
        else:
            schedule_data = schedule_cron_data

        # 2. Load password complexity rules
        if not rule_string:
            rule_list_json_str = ''
        else:
            rule_list = [s.strip() for s in rule_string.split(',')]
            if len(rule_list) != 5 or not all(n.isnumeric() for n in rule_list):
                logging.warning(
                    'Invalid rules to generate password. Format is "length, upper, lower, digits, symbols". Ex: 32,5,5,5,5'
                )
                return

            rule_list_dict = {
                'length': int(rule_list[0]),
                'caps': int(rule_list[1]),
                'lowercase': int(rule_list[2]),
                'digits': int(rule_list[3]),
                'special': int(rule_list[4])
            }

            rule_list_json_str = json.dumps(rule_list_dict)

        # 3. Construct Request object
        rq = RouterRecordRotationRequest()
        rq.recordUid = url_safe_str_to_bytes(record_uid)
        rq.configurationUid = url_safe_str_to_bytes(config_uid)
        rq.schedule = json.dumps(schedule_data) if schedule_data else ''
        rq.pwdComplexity = rule_list_json_str
        rq.scriptName = script_name if script_name else ''

        rs = router_set_record_rotation_information(params, rq)

        print(f"Successfully saved new Record Rotation Setting.")

        if schedule_json_data and schedule_cron_data:
            print(f"Rotation of the record [{record_uid}] was scheduled to rotate using following schedule setting: {bcolors.OKBLUE}{schedule_data}{bcolors.ENDC}")
        else:
            print(f"Rotation of this record can only be performed manually")
        print(f"To rotate manually use the following command: {bcolors.OKGREEN}pam action rotate -r {record_uid}{bcolors.ENDC}")


class PAMListRecordRotationCommand(Command):
    pam_list_record_rotation = argparse.ArgumentParser(prog='pam-list-record-rotation-schedulers')
    pam_list_record_rotation.add_argument('--verbose', '-v', required=False, default=False, dest='is_verbose',
                                          action='store_true', help='Verbose output')
    pam_list_record_rotation.error = raise_parse_exception
    pam_list_record_rotation.exit = suppress_exit

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return self.pam_list_record_rotation

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any

        is_verbose = kwargs.get('is_verbose')

        rq = PAMGenericUidsRequest()

        schedules_proto = router_get_rotation_schedules(params, rq)
        schedules = list(schedules_proto.schedules)

        enterprise_all_controllers = list(gateway_helper.get_all_gateways(params))
        enterprise_controllers_connected_resp = router_get_connected_gateways(params)
        enterprise_controllers_connected = list(enterprise_controllers_connected_resp.controllers)

        all_configs = list(config_get_all(params).configurations)
        table = []

        headers = []
        headers.append('Record UID')
        headers.append('Record Title')
        headers.append('Record Type')
        headers.append('Schedule')

        headers.append('Gateway')
        if is_verbose:
            headers.append('Gateway UID')

        headers.append('Configuration (Type)')
        if is_verbose:
            headers.append('Configuration UID')

        for s in schedules:
            row = []

            record_uid = CommonHelperMethods.bytes_to_url_safe_str(s.recordUid)
            controller_uid = s.controllerUid
            controller_details = next((ctr for ctr in enterprise_all_controllers if ctr.controllerUid == controller_uid), None)
            configuration_uid = s.configurationUid
            configuration = next((conf for conf in all_configs if conf.configurationUid == configuration_uid), None)
            configuration_data = json.loads(configuration.data)

            is_controller_online = next((poc for poc in enterprise_controllers_connected if poc.controllerUid == controller_uid), False)

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

                record_title = '[no access to record]'
                record_type = ''

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

            controller_color = bcolors.WHITE
            if is_controller_online:
                controller_color = bcolors.OKGREEN

            if controller_details:
                row.append(f'{controller_color}{controller_details.controllerName}{bcolors.ENDC}')
            else:
                row.append(f'{controller_color}[Does not exist]{bcolors.ENDC}')

            if is_verbose:
                row.append(f'{controller_color}{base64_url_encode(controller_uid)}{bcolors.ENDC}')

            row.append(f"{json.loads(configuration.data).get('name')} ({json.loads(configuration.data).get('configType')})")
            if is_verbose:
                row.append(f'{base64_url_encode(configuration_uid)}{bcolors.ENDC}')

            table.append(row)

        table.sort(key=lambda x: (x[1]))

        dump_report_data(table, headers, fmt='table', filename="",
                         row_number=False, column_width=None)


class PAMGatewayListCommand(Command):
    pam_cmd_controllers_parser = argparse.ArgumentParser(prog='dr-gateway')
    pam_cmd_controllers_parser.add_argument('--force', '-f', required=False, default=False, dest='is_force',
                                            action='store_true', help='Force retrieval of gateways')
    pam_cmd_controllers_parser.add_argument('--verbose', '-v', required=False, default=False, dest='is_verbose',
                                            action='store_true', help='Verbose output')
    pam_cmd_controllers_parser.error = raise_parse_exception
    pam_cmd_controllers_parser.exit = suppress_exit

    def get_parser(self):
        return self.pam_cmd_controllers_parser

    def execute(self, params, **kwargs):

        is_force = kwargs.get('is_force')
        is_verbose = kwargs.get('is_verbose')

        is_router_down = False
        krouter_url = router_helper.get_router_url(params)
        enterprise_controllers_connected = []
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
        headers.append('UID')
        headers.append('Gateway Name')
        headers.append('KSM App UID')
        headers.append('Status')

        if is_verbose:
            headers.append('Device Name')
            headers.append('Device Token')
            headers.append('Created On')
            headers.append('Last Modified')
            headers.append('Node ID')
            headers.append('Router Cookie')

        for c in enterprise_controllers_all:

            connected_controller = None
            if enterprise_controllers_connected:
                # Find connected controller (TODO: Optimize, don't search for controllers every time, no N^n)
                router_controllers = list(enterprise_controllers_connected.controllers)
                connected_controller = next((ent_con_cntr for ent_con_cntr in router_controllers if
                                             ent_con_cntr.controllerUid == c.controllerUid), None)

            row_color = ''
            if not is_router_down:
                row_color = bcolors.FAIL

                if connected_controller:
                    row_color = bcolors.OKGREEN

            add_cookie = False

            row = []
            row.append(f'{row_color}{CommonHelperMethods.bytes_to_url_safe_str(c.controllerUid)}')
            row.append(c.controllerName)

            ksm_app_uid_str = CommonHelperMethods.bytes_to_url_safe_str(c.applicationUid)
            ksm_app = KSMCommand.get_app_record(params, ksm_app_uid_str)

            if ksm_app:
                ksm_app_data_unencrypted_json = ksm_app.get('data_unencrypted')
                ksm_app_data_unencrypted_dict = json.loads(ksm_app_data_unencrypted_json)
                ksm_app_title = ksm_app_data_unencrypted_dict.get('title')
                ksm_app_info = f'{ksm_app_title} (uid: {ksm_app_uid_str})'
            else:
                ksm_app_info = f'[APP NOT ACCESSIBLE OR DELETED] (uid: {ksm_app_uid_str})'

            row.append(ksm_app_info)

            if is_router_down:
                row.append('UNKNOWN' + bcolors.ENDC)
            elif connected_controller:
                row.append("ONLINE" + bcolors.ENDC)
                add_cookie = True
            else:
                row.append("OFFLINE" + bcolors.ENDC)

            if is_verbose:
                row.append(c.deviceName)
                row.append(c.deviceToken)
                row.append(datetime.fromtimestamp(c.created/1000))
                row.append(datetime.fromtimestamp(c.lastModified/1000))
                row.append(c.nodeId)
                row.append(f"{connected_controller.get('cookie')}{bcolors.ENDC}" if add_cookie else "")

            table.append(row)
        table.sort(key=lambda x: (x[3] or '', x[1].lower()))

        dump_report_data(table, headers, fmt='table', filename="",
                         row_number=False, column_width=None)


class DRExecListAccessRecordsCommand(Command):
    command_parser = argparse.ArgumentParser(prog='dr-exec-list-access-records-command')
    command_parser.add_argument('--gateway', '-g', required=False, dest='gateway', action='store',
                                help='Destination Gateway')

    def get_parser(self):
        return self.command_parser

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            gateway_helper.get_connected_gateways(params)

        message_id = GatewayAction.generate_message_id(is_bytes=True)

        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionListAccessRecords()
        )

        if not router_response:
            return

        access_records = router_response.get('response').get('data').get('access_records')

        table = []
        headers = ['UID', 'Title', 'Type', 'Has Access']

        for ar in access_records:
            has_access_to_record = ar.get("uid") in params.record_cache

            row_color = bcolors.FAIL
            if has_access_to_record:
                row_color = bcolors.OKGREEN

            row = [
                f'{row_color}{ar.get("uid")}',
                ar.get("title"),
                ar.get("type"),
                f"Yes{bcolors.ENDC}" if has_access_to_record else f"No{bcolors.ENDC}"
            ]

            table.append(row)
        table.sort(key=lambda x: (x[3] or '', x[1].lower()))

        dump_report_data(table, headers, fmt='table', filename="",
                         row_number=False, column_width=None)


class DRExecListConfigsCommand(Command):

    command_parser = argparse.ArgumentParser(prog='dr-exec-list-configs-command')
    command_parser.add_argument('--config', '-c', required=False, dest='config',action='store', help='Configuration UID')
    command_parser.add_argument('--verbose', '-v', required=False, dest='verbose',action='store_true', help='Verbose')

    def get_parser(self):
        return self.command_parser

    def execute(self, params, **kwargs):

        config_uid = kwargs.get('config')
        is_verbose = kwargs.get('verbose')

        if not config_uid: # Print ALL root level configs
            DRExecListConfigsCommand.print_root_configs(params, is_verbose)
        else:   # Print element configs (config that is not a root)
            DRExecListConfigsCommand.print_config_details(params, config_uid, is_verbose)

    @staticmethod
    def print_config_details(params, config_uid, is_verbose=False):
        config_uid_bytes = url_safe_str_to_bytes(config_uid)
        conf = config_get_one(params, config_uid_bytes)

        def print_config_element(child, level):
            level += 2
            spaces = " " * level
            element_uid = CommonHelperMethods.bytes_to_url_safe_str(child.elementUid)
            print(f'{spaces} +-- uid  : {element_uid}')
            if is_verbose:
                dep_data_str = " ".join(bytes_to_string(child.data).replace("\n", " ").split())
                print(f'{spaces}     data : {bcolors.OKBLUE}{dep_data_str}{bcolors.ENDC}')
            # print(f'{spaces} created        : {datetime.fromtimestamp(child.created/1000)}')
            # print(f'{spaces} lastModified   : {datetime.fromtimestamp(child.lastModified/1000)}')

            if child.children:
                # print(f"{spaces} --- DEPENDENT CONFIGS ({len(child.children)})")
                for cc in child.children:
                    print_config_element(cc, level)
            # print(f'{spaces}----------------------')

        print("--- CONFIGURATION ---")
        print(f'Uid         : {CommonHelperMethods.bytes_to_url_safe_str(conf.configurationUid)}')
        print(f'Node id     : {conf.nodeId}')
        print(f'Gateway UID : {CommonHelperMethods.bytes_to_url_safe_str(conf.controllerUid)}')
        if is_verbose:
            data_str = " ".join(bytes_to_string(conf.data).replace("\n", " ").split())
            print(f'Data        : {bcolors.OKBLUE}{data_str}{bcolors.ENDC}')
        # print(f'created: {datetime.fromtimestamp(conf.created/1000)}')
        # print(f'lastModified: {datetime.fromtimestamp(conf.lastModified/1000)}')

        if conf.children:
            print(f"\n--- DEPENDENT CONFIGS {len(conf.children)}")
            for c in conf.children:
                print_config_element(c, 0)

    @staticmethod
    def print_root_configs(params, is_verbose=False):
        resp = config_get_all(params)

        all_root_configs = resp.configurations

        table = []
        headers = ['UID',
                   'Node Id',
                   'Gateway UID',
                   'Created',
                   'Last Modified',
                   '# of Child Elements'
                   ]

        if is_verbose:
            headers.append('Data')

        for c in all_root_configs:
            row = [
                CommonHelperMethods.bytes_to_url_safe_str(c.configurationUid),
                c.nodeId,
                CommonHelperMethods.bytes_to_url_safe_str(c.controllerUid),
                datetime.fromtimestamp(c.created / 1000),
                datetime.fromtimestamp(c.lastModified / 1000),
                len(c.children)
            ]
            if is_verbose:
                row.append(f"{bcolors.OKBLUE}{bytes_to_string(c.data)}{bcolors.ENDC}")

            table.append(row)

        table.sort(key=lambda x: (x[3] or ''))

        dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


class PAMConfigRemoveCommand(Command):
    pam_config_rem_command_parser = argparse.ArgumentParser(prog='dr-remove_config-command')
    pam_config_rem_command_parser.add_argument('--config', '-c', required=True, dest='config',
                                               action='store', help='Configuration or Configuration Element UID. '
                                                                   'To view all configurations with their UIDs, '
                                                                   'use command `pam config list`')

    def get_parser(self):
        return self.pam_config_rem_command_parser

    def execute(self, params, **kwargs):
        config_uid = kwargs.get('config')
        config_uid_bytes = url_safe_str_to_bytes(config_uid)

        is_removed = config_remove(params, config_uid_bytes)

        if is_removed:
            print("Configuration was removed")
        else:
            print("Couldn't delete configuration")


class PAMConfigNewCommand(Command):

    dr_config_new_command_parser = argparse.ArgumentParser(prog='dr-create_config-command')

    dr_config_new_command_parser.add_argument('--gateway', '-g', required=True, dest='gateway',
                                              action='store', help='Gateway Name or UID')
    dr_config_new_command_parser.add_argument('--config', '-c', required=False, dest='config',
                                              action='store', help='Parent Configuration UID. To view all '
                                                                   'configurations with their UIDs, use command '
                                                                   '`pam config list`')

    # dr_config_new_command_parser.add_argument('--config-data', '-d', required=False, dest='config_data',
    #                                           action='store', help='Raw config data in JSON')
    #
    dr_config_new_command_parser.add_argument('--config-name', '-cn', required=False, dest='config_name',
                                              action='store', help='Name of the configuration')
    dr_config_new_command_parser.add_argument('--config-type', '-ct', required=False, dest='config_type',
                                              action='store', help='Configuration type', choices=['aws', 'azure', 'local'])
    dr_config_new_command_parser.add_argument('--config-primary-access-record-uid', '-cp', required=False,
                                              dest='config_primary_access_record_uid', action='store',
                                              help='Record UID that will be used as primary access to access resources.'
                                                   ' Example, this record will have root credentials to MySQL database '
                                                   'that can manage other users credentials.')
    dr_config_new_command_parser.add_argument('--config-resource-records', '-cr', required=False,
                                              dest='config_resource_access_records_uids', action='append',
                                              help='', default=[])

    dr_config_new_command_parser.add_argument('--config-record-types', '-cy', required=False,
                                              dest='config_record_types', action='store',
                                              help='Record types that the action will be performed against',
                                              nargs='+', default=[])
    dr_config_new_command_parser.add_argument('--config-default-schedule', '-cd', required=False,
                                              dest='config_default_schedule', action='store',
                                              help='Default scheduler')

    def get_parser(self):
        return self.dr_config_new_command_parser

    def execute(self, params, **kwargs):
        gateway_str = kwargs.get('gateway')
        config_uid = kwargs.get('config')
        gateway_uid_bytes = url_safe_str_to_bytes(gateway_str)
        all_gateways = gateway_helper.get_all_gateways(params)

        config_data_raw = kwargs.get('config_data')
        config_name = kwargs.get('config_name')
        config_type = kwargs.get('config_type')
        config_primary_access_record_uid = kwargs.get('config_primary_access_record_uid')
        config_resource_access_records_uids = kwargs.get('config_resource_access_records_uids')
        config_record_types = kwargs.get('config_record_types')
        config_default_schedule = kwargs.get('config_default_schedule')

        found_gateways = list(filter(lambda g: g.controllerUid == gateway_uid_bytes or g.controllerName == gateway_str, all_gateways))

        if len(found_gateways) == 0:
            logging.warning(f'Gateway name or uid [{bcolors.OKBLUE}{gateway_str}{bcolors.ENDC}] you enter does not exist.')
            return
        elif len(found_gateways) > 1:
            found_gateway_uids_str = ', '.join([f'{bcolors.OKBLUE}{CommonHelperMethods.bytes_to_url_safe_str(d.controllerUid)}{bcolors.ENDC}' for d in found_gateways])
            logging.warning(f'Following Gateway UIDs are already associated with [{bcolors.OKGREEN}{gateway_str}{bcolors.ENDC}] name: {found_gateway_uids_str}. Please use UID instead to identify the exact Gateway.')
            return

        if not config_name:
            logging.warning(f'Configuration name (--config-name, -cn) is required')
            return

        if not config_primary_access_record_uid:
            logging.warning(f'Primary access record (--config-primary_access_record_uid, -cp) is required')
            return

        if not config_type:
            logging.warning(f'Configuration type (--config-type, -ct) is required. '
                            f'Use one of the following: aws, azure, local')
            return

        config_type = config_type     # available options: AWS | Azure | Local

        if config_data_raw:
            config_data_json = config_data_raw
        else:

            config_data_dict = {}
            config_data_dict['name'] = config_name
            config_data_dict['primaryAccessRecord'] = config_primary_access_record_uid
            config_data_dict['type'] = config_type
            config_data_dict['recordTypes'] = config_record_types
            if config_default_schedule:
                # config_data_dict['defaultSchedule'] = config_default_schedule
                config_data_dict['defaultSchedule'] = [
                    {"type": "WEEKLY", "utcTime": "15:44", "weekday": "SUNDAY", "intervalCount": 1},
                    {"type": "WEEKLY", "utcTime": "15:44", "weekday": "MONDAY", "intervalCount": 1}
                ]

            config_data_json = json.dumps(config_data_dict, indent=2)

        child_config_data_jsons = None

        if config_resource_access_records_uids:
            child_config_data_jsons = []

            for craru in config_resource_access_records_uids:
                child_config_data_dict = {}
                child_config_data_dict['resourceRecord'] = craru
                child_config_data_json = json.dumps(child_config_data_dict, indent=2)
                child_config_data_jsons.append(child_config_data_json)

        config_creation_resp = config_create(
            params=params,
            gateway_uid_bytes=gateway_uid_bytes,
            config_json_str=config_data_json,
            child_config_json_strings=child_config_data_jsons,
            parent_uid_bytes=url_safe_str_to_bytes(config_uid) if config_uid else None
         )

        print('Configuration has been created:')
        print(f'\tConfig uid: {CommonHelperMethods.bytes_to_url_safe_str(config_creation_resp["configUid"])}')
        if config_creation_resp['childConfigUids']:
            for ccu in config_creation_resp['childConfigUids']:
                print(f'\tDependent config uid: {CommonHelperMethods.bytes_to_url_safe_str(ccu)}')


class PAMRouterGetRotationInfo(Command):
    dr_router_get_rotation_info_parser = argparse.ArgumentParser(prog='dr-router-get-rotation-info-parser')
    dr_router_get_rotation_info_parser.add_argument('--record-uid', '-r', required=True, dest='record_uid',
                                                    action='store', help='Record UID to rotate')

    dr_router_get_rotation_info_parser.error = raise_parse_exception
    dr_router_get_rotation_info_parser.exit = suppress_exit

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return self.dr_router_get_rotation_info_parser

    def execute(self, params, **kwargs):

        record_uid = kwargs.get('record_uid')
        record_uid_bytes = url_safe_str_to_bytes(record_uid)

        rri = router_get_record_rotation_info(params, record_uid_bytes)
        rri_status_name = RouterRotationStatus.Name(rri.status)
        if rri_status_name == 'RRS_ONLINE':

            print(f'Rotation Status: {bcolors.OKBLUE}Ready to rotate ({rri_status_name}){bcolors.ENDC}')
            print(f"Configuration Uid: {bcolors.OKBLUE}{(base64_url_encode(rri.configurationUid) if rri.configurationUid else '-') }{bcolors.ENDC}")
            print(f"Gateway Name where the rotation will be performed: {bcolors.OKBLUE}{(rri.controllerName if rri.controllerName else '-')}{bcolors.ENDC}")
            print(f"Gateway Uid: {bcolors.OKBLUE}{(base64_url_encode(rri.controllerUid) if rri.controllerUid else '-') }{bcolors.ENDC}")
            # print(f"Router Cookie: {bcolors.OKBLUE}{(rri.cookie if rri.cookie else '-')}{bcolors.ENDC}")
            print(f"\nCommand to manually rotate: {bcolors.OKGREEN}pam action rotate -r {record_uid}{bcolors.ENDC}")
        else:
            print(f'{bcolors.WARNING}Rotation Status: Not ready to rotate ({rri_status_name}){bcolors.ENDC}')


class PAMGatewayActionJobCancelCommand(Command):
    command_parser = argparse.ArgumentParser(prog='pam-action-job-cancel-command')
    command_parser.add_argument('job_id')

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return self.command_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any

        job_id = kwargs.get('job_id')

        print(f"Job id to cancel [{job_id}]")

        generic_job_id_inputs = GatewayActionJobInfoInputs(job_id)

        message_id = GatewayAction.generate_message_id()
        router_response = router_send_action_to_gateway(params=params, gateway_action=GatewayActionJobCancel(inputs=generic_job_id_inputs,
                                                                                                             message_id=message_id))
        print_router_response(router_response, message_id)


class PAMGatewayActionJobCommand(Command):
    pam_action_job_command_parser = argparse.ArgumentParser(prog='pam-action-job-command')
    pam_action_job_command_parser.add_argument('job_id')

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return self.pam_action_job_command_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any

        job_id = kwargs.get('job_id')

        print(f"Job id to check [{job_id}]")

        action_inputs = GatewayActionJobInfoInputs(job_id)

        message_id = GatewayAction.generate_message_id()
        router_response = router_send_action_to_gateway(params=params, gateway_action=GatewayActionJobInfo(inputs=action_inputs,
                                                                                                           message_id=message_id))
        print_router_response(router_response, message_id)


class PAMGatewayActionRotateCommand(Command):
    pam_cmd_rotate_command_parser = argparse.ArgumentParser(prog='dr-rotate-command')
    pam_cmd_rotate_command_parser.add_argument('--record-uid', '-r', required=True, dest='record_uid', action='store',
                                               help='Record UID to rotate')
    # dr_cmd_rotate_command_parser.add_argument('--config', '-c', required=True, dest='configuration_uid', action='store',
    #                                           help='Rotation configuration UID')
    pam_cmd_rotate_command_parser.error = raise_parse_exception
    pam_cmd_rotate_command_parser.exit = suppress_exit

    def get_parser(self):
        return self.pam_cmd_rotate_command_parser

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        record_uid = kwargs.get('record_uid')
        record_uid_bytes = url_safe_str_to_bytes(record_uid)

        # rq = PAMGenericUidRequest()
        # rq.uid = record_uid_bytes
        #
        # router_send_rotation_action_to_gateway(params, rq)
        #
        # return

        # TODO: Check if this record even exist

        # Find record by record uid
        ri = router_get_record_rotation_info(params, record_uid_bytes)
        ri_pwd_complexity = ri.pwdComplexity
        ri_configuration_uid = base64_url_encode(ri.configurationUid)
        ri_controller_uid = base64_url_encode(ri.controllerUid)
        ri_router_worker_lb_cookie_str = ri.cookie

        all_enterprise_controllers_all = list(gateway_helper.get_all_gateways(params))

        rrs = RouterRotationStatus.Name(ri.status)
        if rrs == 'RRS_NO_ROTATION':
            print(f'{bcolors.FAIL}Record [{record_uid}] does not have rotation associated with it.{bcolors.ENDC}')
            return
        elif rrs == 'RRS_CONTROLLER_DOWN':
            controller_details = next((ctr for ctr in all_enterprise_controllers_all if ctr.controllerUid == ri.controllerUid), None)

            print(f'{bcolors.WARNING}The Gateway "{controller_details.controllerName}" [uid={ri_controller_uid}] '
                  f'that is setup to perform this rotation is currently offline.{bcolors.ENDC}')
            return
        elif rrs == 'RRS_NO_CONTROLLER':
            print(f'{bcolors.FAIL}There are no gateways associated with this Record Rotation Setting.{bcolors.ENDC}')
            return
        elif rrs == 'RRS_ONLINE':
            print(f'{bcolors.OKGREEN}Controller is online{bcolors.ENDC}')
        else:
            print(f'{bcolors.FAIL}Unknown router rotation status [{rrs}]{bcolors.ENDC}')
            return

        action_inputs = GatewayActionRotateInputs(record_uid=record_uid, configuration_uid=ri_configuration_uid,
                                                  pwd_complexity=ri_pwd_complexity)

        message_id = GatewayAction.generate_message_id()

        router_response = router_send_action_to_gateway(params=params,
                                                        gateway_action=GatewayActionRotate(inputs=action_inputs,
                                                                                           message_id=message_id,
                                                                                           gateway_destination=ri_controller_uid)
                                                        )

        print_router_response(router_response, message_id)


class PAMGatewayActionServerInfoCommand(Command):
    pam_cmd_discover_command_parser = argparse.ArgumentParser(prog='dr-info-command')
    pam_cmd_discover_command_parser.error = raise_parse_exception
    pam_cmd_discover_command_parser.exit = suppress_exit

    def get_parser(self):
        return self.pam_cmd_discover_command_parser

    def execute(self, params, **kwargs):

        router_response = router_send_action_to_gateway(params=params, gateway_action=GatewayActionGatewayInfo())

        print_router_response(router_response)


class PAMGatewayActionDiscoverCommand(Command):
    pam_cmd_discover_command_parser = argparse.ArgumentParser(prog='dr-discover-command')
    pam_cmd_discover_command_parser.add_argument('--shared-folder', '-f', required=True, dest='shared_folder_uid',
                                                 action='store',
                                                 help='UID of the Shared Folder where results will be stored')
    pam_cmd_discover_command_parser.add_argument('--provider-record', '-p', required=True, dest='provider_record_uid',
                                                 action='store', help='Provider Record UID that defines network')
    # dr_cmd_discover_command_parser.add_argument('--destinations', '-d', required=False, dest='destinations', action='store',
    #                                           help='Controller id')

    pam_cmd_discover_command_parser.error = raise_parse_exception
    pam_cmd_discover_command_parser.exit = suppress_exit

    def get_parser(self):
        return self.pam_cmd_discover_command_parser

    def execute(self, params, **kwargs):

        shared_folder_uid = kwargs.get('shared_folder_uid')
        provider_record_uid = kwargs.get('provider_record_uid')

        action_inputs = GatewayActionDiscoverInputs(shared_folder_uid, provider_record_uid)
        message_id = GatewayAction.generate_message_id()

        router_response = router_send_action_to_gateway(
                                        params,
                                        GatewayActionDiscover(inputs=action_inputs, message_id=message_id)
                                       )

        print_router_response(router_response, message_id)


class PAMTunnelCommand(Command):
    pam_tunnel_command_parser = argparse.ArgumentParser(prog='dr-tunnel-command')
    pam_tunnel_command_parser.add_argument('--uid', '-u', required=True, dest='record_uid', action='store',
                                           help='UID of the record that has server credentials')
    pam_tunnel_command_parser.add_argument('--destinations', '-d', required=False, dest='destinations', action='store',
                                           help='Controller id')

    pam_tunnel_command_parser.error = raise_parse_exception
    pam_tunnel_command_parser.exit = suppress_exit

    def get_parser(self):
        return self.pam_tunnel_command_parser

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

                if is_json(payload):
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
    def get_parser(self):
        return pam_connect_parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            params.ws = PAMConnection()
            params.ws.connect(params.session_token)
            logging.info(f'Connected {params.config["device_token"]}')
        else:
            logging.warning('Connection exists')


class PAMDisconnect(Command):
    def get_parser(self):
        return pam_disconnect_parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            logging.warning("Connection doesn't exist")
        else:
            params.ws.disconnect()
            params.ws = None


class PAMGatewayRemoveCommand(Command):
    dr_remove_controller_parser = argparse.ArgumentParser(prog='dr-remove-gateway')
    dr_remove_controller_parser.add_argument('--gateway', '-g', required=True, dest='gateway',
                                             help='UID of the Gateway', action='store')
    dr_remove_controller_parser.error = raise_parse_exception
    dr_remove_controller_parser.exit = suppress_exit

    def get_parser(self):
        return PAMGatewayRemoveCommand.dr_remove_controller_parser

    def execute(self, params, **kwargs):

        gateway_uid = kwargs.get('gateway')     # TODO: also handle the name of the gateway

        gateway_helper.remove_gateway(params, gateway_uid)

        print(f"Gateway {gateway_uid} has been removed.")


class PAMCreateGatewayCommand(Command):

    dr_create_controller_parser = argparse.ArgumentParser(prog='dr-create-gateway')
    dr_create_controller_parser.add_argument('--name', '-n', required=True, dest='gateway_name',
                                             help='Name of the Gateway',
                                             action='store')
    dr_create_controller_parser.add_argument('--application', '-a', required=True, dest='ksm_app',
                                             help='KSM Application name or UID. Use command `sm app list` to view '
                                                  'available KSM Applications.', action='store')
    dr_create_controller_parser.add_argument('--return_value', '-r', dest='return_value', action='store_true',
                                             help='Return value from the command for automation purposes')
    dr_create_controller_parser.add_argument('--config-init', '-c', type=str, dest='config_init', action='store',
                                             choices=['json', 'b64'], help='Initialize client config and return configuration string.')  # json, b64, file

    dr_create_controller_parser.error = raise_parse_exception
    dr_create_controller_parser.exit = suppress_exit

    def get_parser(self):
        return PAMCreateGatewayCommand.dr_create_controller_parser

    def execute(self, params, **kwargs):

        gateway_name = kwargs.get('gateway_name')
        ksm_app = kwargs.get('ksm_app')
        is_return_value = kwargs.get('return_value')
        config_init = kwargs.get('config_init')

        ott_expire_in_min = 5

        logging.debug(f'gateway_name   =[{gateway_name}]')
        logging.debug(f'ksm_app        =[{ksm_app}]')

        one_time_token = create_gateway(params, gateway_name, ksm_app, config_init, ott_expire_in_min)

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

            print('--------------------------------')
            print(bcolors.OKGREEN + one_time_token + bcolors.ENDC)
            print('--------------------------------')
