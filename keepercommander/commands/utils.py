#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import re
import os
import base64
import argparse
import logging
import datetime
import getpass
import sys
import platform

import requests
import tempfile
import json

from urllib.parse import urlsplit

from google.protobuf.json_format import MessageToDict
from tabulate import tabulate
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Math.Numbers import Integer

from ..display import bcolors
from ..params import KeeperParams, LAST_RECORD_UID, LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID
from ..record import Record
from .. import api, rest_api, loginv3
from .base import raise_parse_exception, suppress_exit, user_choice, Command
from ..subfolder import try_resolve_path, find_folders, get_folder_path
from . import aliases, commands, enterprise_commands
from ..error import CommandError
from .. import __version__
from ..versioning import is_binary_app, is_up_to_date_version

SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH2_AGENTC_ADD_IDENTITY = 17
SSH2_AGENTC_REMOVE_IDENTITY = 18
SSH2_AGENTC_ADD_ID_CONSTRAINED = 25

SSH_AGENT_CONSTRAIN_LIFETIME = 1


def register_commands(commands):
    commands['sync-down'] = SyncDownCommand()
    commands['this-device'] = ThisDeviceCommand()
    commands['delete-all'] = RecordDeleteAllCommand()
    commands['whoami'] = WhoamiCommand()
    commands['login'] = LoginCommand()
    commands['logout'] = LogoutCommand()
    commands['check-enforcements'] = CheckEnforcementsCommand()
    commands['connect'] = ConnectCommand()
    commands['delete-corrupted'] = DeleteCorruptedCommand()
    commands['echo'] = EchoCommand()
    commands['set'] = SetCommand()
    commands['help'] = HelpCommand()
    commands['version'] = VersionCommand()


def register_command_info(aliases, command_info):
    aliases['d'] = 'sync-down'
    aliases['delete_all'] = 'delete-all'
    aliases['v'] = 'version'
    for p in [whoami_parser, this_device_parser, login_parser, logout_parser, echo_parser, set_parser, help_parser, version_parser]:
        command_info[p.prog] = p.description
    command_info['sync-down|d'] = 'Download & decrypt data'


whoami_parser = argparse.ArgumentParser(prog='whoami', description='Display information about the currently logged in user.')
whoami_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
whoami_parser.error = raise_parse_exception
whoami_parser.exit = suppress_exit

this_device_available_command_verbs = ['rename', 'register', 'persistent-login', 'ip-auto-approve', 'timeout']
this_device_parser = argparse.ArgumentParser(prog='this-device', description='Display and modify settings of the current device.')
this_device_parser.add_argument('ops', nargs='*', help="operation str: " + ", ".join(this_device_available_command_verbs))
this_device_parser.error = raise_parse_exception
this_device_parser.exit = suppress_exit


login_parser = argparse.ArgumentParser(prog='login', description='Login to Keeper.')
login_parser.add_argument('-p', '--pass', dest='password', action='store', help='master password')
login_parser.add_argument('email', nargs='?', type=str, help='account email')
login_parser.error = raise_parse_exception
login_parser.exit = suppress_exit


logout_parser = argparse.ArgumentParser(prog='logout', description='Logout from Keeper.')
logout_parser.error = raise_parse_exception
logout_parser.exit = suppress_exit


check_enforcements_parser = argparse.ArgumentParser(prog='check-enforcements',
                                                    description='Check enterprise enforcements')
check_enforcements_parser.error = raise_parse_exception
check_enforcements_parser.exit = suppress_exit


connect_parser = argparse.ArgumentParser(prog='connect', description='Establishes connection to external server')
connect_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                            help='display help on command format and template parameters')
connect_parser.add_argument('-n', '--new', dest='new_data', action='store_true', help='request per-user data')
connect_parser.add_argument('-s', '--sort', dest='sort_by', action='store', choices=['endpoint', 'title', 'folder'],
                            help='sort output')
connect_parser.add_argument('-f', '--filter', dest='filter_by', action='store', help='filter output')
connect_parser.add_argument('endpoint', nargs='?', action='store', type=str,
                            help='endpoint name or full record path to endpoint')
connect_parser.error = raise_parse_exception
connect_parser.exit = suppress_exit


echo_parser = argparse.ArgumentParser(prog='echo', description='Displays an argument to output.')
echo_parser.add_argument('argument', nargs='?', action='store', type=str, help='argument')
echo_parser.error = raise_parse_exception
echo_parser.exit = suppress_exit


set_parser = argparse.ArgumentParser(prog='set', description='Set an environment variable.')
set_parser.add_argument('name', action='store', type=str, help='name')
set_parser.add_argument('value', action='store', type=str, help='value')
set_parser.error = raise_parse_exception
set_parser.exit = suppress_exit


help_parser = argparse.ArgumentParser(prog='help', description='Displays help on a specific command.')
help_parser.add_argument('command', action='store', type=str, help='Commander\'s command')
help_parser.error = raise_parse_exception
help_parser.exit = suppress_exit


version_parser = argparse.ArgumentParser(prog='version', description='Displays version of the installed Commander.')
version_parser.error = raise_parse_exception
version_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
version_parser.exit = suppress_exit


class SyncDownCommand(Command):
    def execute(self, params, **kwargs):
        api.sync_down(params)

        accepted = False
        if len(params.pending_share_requests) > 0:
            for user in params.pending_share_requests:
                accepted = False
                print('Note: You have pending share request from ' + user)
                answer = user_choice('Do you want to accept these request?', 'yn', 'n')
                rq = {
                    'command': 'accept_share' if answer == 'y' else 'cancel_share',
                    'from_email': user
                }
                try:
                    rs = api.communicate(params, rq)
                    if rs['result'] == 'success':
                        accepted = accepted or answer == 'y'
                except Exception as e:
                    logging.debug('Accept share exception: %s', e)

            params.pending_share_requests.clear()

            if accepted:
                params.sync_data = True


class ThisDeviceCommand(Command):

    def get_parser(self):
        return this_device_parser

    def execute(self, params, **kwargs):

        ops = kwargs.get('ops')

        if len(ops) == 0:

            ThisDeviceCommand.print_device_info(params)
            return

        if len(ops) >= 1 and ops[0].lower() != 'register':
            if len(ops) == 1 and ops[0].lower() != 'register':
                logging.error("Must supply action and value. Available sub-commands: " + ", ".join(this_device_available_command_verbs))
                return

            if len(ops) != 2:
                logging.error("Must supply action and value. Available sub-commands: " + ", ".join(this_device_available_command_verbs))
                return

        action = ops[0].lower()

        def register_device():
            is_device_registered = loginv3.LoginV3API.register_encrypted_data_key_for_device(params)

            if is_device_registered:
                print(bcolors.OKGREEN + "Successfully registered device" + bcolors.ENDC)
            else:
                print(bcolors.OKGREEN + "Device already registered" + bcolors.ENDC)

        if action == 'rename' or action == 'ren':
            value = ops[1]
            loginv3.LoginV3API.rename_device(params, value)
            print(bcolors.OKGREEN + "Successfully renamed device to '" + value + "'" + bcolors.ENDC)

        elif action == 'register':
            register_device()

        elif action == 'persistent_login' or action == 'persistent-login' or action == 'pl':
            value = ops[1]

            value_extracted = ThisDeviceCommand.get_setting_str_to_value('persistent_login', value)
            loginv3.LoginV3API.set_user_setting(params, 'persistent_login', value_extracted)
            msg = (bcolors.OKGREEN + "ENABLED" + bcolors.ENDC) if value_extracted == '1' else (bcolors.FAIL + "DISABLED" + bcolors.ENDC)
            print("Successfully " + msg + " Persistent Login on this device")

            register_device()

            if value_extracted == '1':

                _, this_device = ThisDeviceCommand.get_account_summary_and_this_device(params)

                if this_device:
                    if 'encryptedDataKeyPresent' not in this_device:
                        print(bcolors.WARNING + "\tThis device is not registered. To register, run command `this-device register`" + bcolors.ENDC)

        elif action == 'ip_auto_approve' or action == 'ip-auto-approve' or action == 'iaa':
            value = ops[1]

            value_extracted = ThisDeviceCommand.get_setting_str_to_value('ip_disable_auto_approve', value)
            msg = (bcolors.OKGREEN + "ENABLED" + bcolors.ENDC) if value_extracted == '1' else (bcolors.FAIL + "DISABLED" + bcolors.ENDC)
            # invert ip_auto_approve value before passing it to ip_disable_auto_approve
            value_extracted = '0' if value_extracted == '1' else '1' if value_extracted == '0' else value_extracted
            loginv3.LoginV3API.set_user_setting(params, 'ip_disable_auto_approve', value_extracted)
            print("Successfully " + msg + " 'ip_auto_approve'")

        elif action == 'timeout' or action == 'to':

            value = ops[1]
            value_extracted = ThisDeviceCommand.get_setting_str_to_value('logout_timer', value)
            loginv3.LoginV3API.set_user_setting(params, 'logout_timer', value_extracted)
            print("Successfully modified 'logout_timer' setting")

        else:
            raise Exception("Unknown sub-command " + action + ". Available sub-commands: ", ", ".join(this_device_available_command_verbs))

    @staticmethod
    def get_setting_str_to_value(name: str, value: str):

        name = name.lower()
        value = value.lower()

        if name == 'persistent_login' or name == 'ip_disable_auto_approve':
            if value and value.lower() in (val.lower() for val in ('yes', 'y', 'on', '1', 'true')):
                final_val = '1'
            elif value and value.lower() in (val.lower() for val in ('no', 'n', 'off', '0', 'false')):
                final_val = '0'
            else:
                raise Exception("Unknown value. Available values 'yes'/'no', 'y'/'n', 'on'/'off', '1'/'0', 'true'/'false'")
        elif name == 'logout_timer':
            if not loginv3.CommonHelperMethods.check_int(value):
                raise Exception("Entered value is not an integer. Please enter integer")
            final_val = value
        else:
            raise Exception("Unhandled settings name '" + name + "'")

        return final_val

    @staticmethod
    def get_account_summary_and_this_device(params: KeeperParams):
        def to_alphanumerics(text):
            # remove ALL non - alphanumerics
            return re.sub(r'[\W_]+', '', text)

        def compare_device_tokens(t1: str, t2: str):
            t1 = to_alphanumerics(t1)
            t2 = to_alphanumerics(t2)

            return t1 == t2

        acct_summary = loginv3.LoginV3API.accountSummary(params)
        acct_summary_dict = MessageToDict(acct_summary)

        devices = acct_summary_dict['devices']

        if 'device_token' not in params.config:
            current_device_token = rest_api.get_device_token(params.rest_context)
        else:
            current_device_token = params.config['device_token']

        this_device = next((item for item in devices if compare_device_tokens(item['encryptedDeviceToken'], current_device_token)), None)

        return acct_summary_dict, this_device

    @staticmethod
    def print_device_info(params: KeeperParams):

        acct_summary_dict, this_device = ThisDeviceCommand.get_account_summary_and_this_device(params)

        print('{:>20}: {}'.format('Device Name', this_device['deviceName']))
        print("{:>20}: {}".format('Client Version', this_device['clientVersion']))

        if 'encryptedDataKeyPresent' in this_device:
            print("{:>20}: {}".format('Data Key Present', (bcolors.OKGREEN + 'YES' + bcolors.ENDC) if this_device['encryptedDataKeyPresent'] else (bcolors.FAIL + 'NO' + bcolors.ENDC)))
        else:
            print("{:>20}: {}".format('Data Key Present', (bcolors.FAIL + 'missing' + bcolors.ENDC)))

        if 'ipDisableAutoApprove' in acct_summary_dict['settings']:
            ipDisableAutoApprove = acct_summary_dict['settings']['ipDisableAutoApprove']
            # ip_disable_auto_approve - If enabled, the device is NOT automatically approved
            # If disabled, the device will be auto approved
            ipAutoApprove = not ipDisableAutoApprove
            print("{:>20}: {}".format('IP Auto Approve',
                                      (bcolors.OKGREEN + 'ON' + bcolors.ENDC)
                                      if ipAutoApprove else
                                      (bcolors.FAIL + 'OFF' + bcolors.ENDC)))
        else:
            print("{:>20}: {}".format('IP Auto Approve', (bcolors.OKGREEN + 'ON' + bcolors.ENDC)))
            # ip_disable_auto_approve = 0 / disabled (default) <==> IP Auto Approve :ON

        if 'persistentLogin' in acct_summary_dict['settings']:
            persistentLogin = acct_summary_dict['settings']['persistentLogin']
            print("{:>20}: {}".format('Persistent Login',
                                      (bcolors.OKGREEN + 'ON' + bcolors.ENDC)
                                      if persistentLogin else
                                      (bcolors.FAIL + 'OFF' + bcolors.ENDC)))

        else:
            print("{:>20}: {}".format('Persistent Login', (bcolors.FAIL + 'OFF' + bcolors.ENDC)))

        if 'logoutTimer' in acct_summary_dict['settings']:
            logoutTimer = acct_summary_dict['settings']['logoutTimer']
            logoutTimerMin = int(logoutTimer) / 1000 / 60
            print("{:>20}: {} minutes".format('Logout Timeout', int(logoutTimerMin)))

        else:
            print("{:>20}: Default".format('Logout Timeout'))

        print("\nAvailable sub-commands: ", bcolors.OKBLUE + (", ".join(this_device_available_command_verbs)) + bcolors.ENDC)


class RecordDeleteAllCommand(Command):
    def execute(self, params, **kwargs):
        uc = user_choice('Are you sure you want to delete all Keeper records on the server?', 'yn', default='n')
        if uc.lower() == 'y':
            api.sync_down(params)
            if len(params.record_cache) == 0:
                raise CommandError('delete-all', 'No records to delete')

            request = {
                'command': 'record_update',
                'delete_records': [key for key in params.record_cache.keys()]
            }
            logging.info('removing %s records from Keeper', len(params.record_cache))
            response_json = api.communicate(params, request)
            success = [info for info in response_json['delete_records'] if info['status'] == 'success']
            if len(success) > 0:
                logging.info("%s records deleted successfully", len(success))
            failures = [info for info in response_json['delete_records'] if info['status'] != 'success']
            if len(failures) > 0:
                logging.warning("%s records failed to delete", len(failures))

            params.revision = 0
            params.sync_data = True


class WhoamiCommand(Command):
    def get_parser(self):
        return whoami_parser

    def execute(self, params, **kwargs):
        is_verbose = kwargs.get('verbose') or False
        if is_verbose:
            if params.server:
                parts = urlsplit(params.server)
                host = parts[1]
                cp = host.rfind(':')
                if cp > 0:
                    host = host[:cp]

                host_str = host.lower()

                if host_str.endswith('.eu'):
                    data_center = 'EU'
                elif host_str.endswith('.com'):
                    data_center = 'US'
                elif host_str.endswith('.au'):
                    data_center = 'AU'
                else:
                    # Ideally we should determine TLD which might require additional lib
                    data_center = host_str

                print('{0:>20s}: {1}'.format('Data Center', data_center))
                environment = ''
                if host.startswith('dev.'):
                    environment = 'DEV'
                elif host.startswith('qa.'):
                    environment = 'QA'
                if environment:
                    print('{0:>20s}: {1}'.format('Environment', environment))
            print('')

        if params.session_token:
            print('{0:>20s}: {1:<20s}'.format('Logged in as', params.user))
            if params.license:
                print('')
                account_type = params.license['account_type'] if 'account_type' in params.license else None
                account_type_name = 'Enterprise' if account_type == 2 \
                    else 'Family Plan' if account_type == 1 \
                    else params.license['product_type_name']
                print('{0:>20s} {1:>20s}: {2}'.format('Account', 'Type', account_type_name))
                print('{0:>20s} {1:>20s}: {2}'.format('', 'Renewal Date', params.license['expiration_date']))
                if 'bytes_total' in params.license:
                    storage_bytes = int(params.license['bytes_total'])  # note: int64 in protobuf in python produces string as opposed to an int or long.
                    storage_gb = storage_bytes >> 30
                    storage_bytes_used = params.license['bytes_used'] if 'bytes_used' in params.license else 0
                    print('{0:>20s} {1:>20s}: {2}GB'.format('Storage', 'Capacity', storage_gb))
                    storage_usage = (int(storage_bytes_used) * 100 // storage_bytes) if storage_bytes != 0 else 0     # note: int64 in protobuf in python produces string  as opposed to an int or long.
                    print('{0:>20s} {1:>20s}: {2}%'.format('', 'Usage', storage_usage))
                    print('{0:>20s} {1:>20s}: {2}'.format('', 'Renewal Date', params.license['storage_expiration_date']))

            if is_verbose:
                print('')
                print('{0:>20s}: {1}'.format('Records', len(params.record_cache)))
                sf_count = len(params.shared_folder_cache)
                if sf_count > 0:
                    print('{0:>20s}: {1}'.format('Shared Folders', sf_count))
                team_count = len(params.team_cache)
                if team_count > 0:
                    print('{0:>20s}: {1}'.format('Teams', team_count))

        else:
            print('{0:>20s}:'.format('Not logged in'))


class VersionCommand(Command):
    def get_parser(self):
        return whoami_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):

        this_app_version = __version__
        version_details = is_up_to_date_version()
        is_verbose = kwargs.get('verbose') or False

        if not is_verbose:
            print('{0}: {1}'.format('Commander Version', this_app_version))
        else:
            print('{0:>20s}: {1}'.format('Commander Version', __version__))
            print('{0:>20s}: {1}'.format('Python Version', sys.version.replace("\n", "")))
            print('{0:>20s}: {1}'.format('Operating System', loginv3.CommonHelperMethods.get_os() + '(' + platform.release() + ')'))
            print('{0:>20s}: {1}'.format('Working directory', os.getcwd()))
            print('{0:>20s}: {1}'.format('Config. File', params.config_filename))
            print('{0:>20s}: {1}'.format('Executable', sys.executable))

        if version_details.get('is_up_to_date') is None:
            logging.debug(bcolors.WARNING + "It appears that internet connection is offline" + bcolors.ENDC)
        elif not version_details.get('is_up_to_date'):

            latest_version = version_details.get('current_github_version')

            print((bcolors.WARNING +
                   'Latest Commander Version: %s\n'
                   'You can download the current version at: %s \n' + bcolors.ENDC)
                  % (latest_version, version_details.get('new_version_download_url')))
        if is_binary_app():
            print("Installation path: {0} ".format(sys._MEIPASS))


class LoginCommand(Command):
    def get_parser(self):
        return login_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        params.clear_session()

        user = kwargs.get('email') or ''
        password = kwargs.get('password') or ''

        try:
            if not user:
                user = input('... {0:>16}: '.format('User(Email)')).strip()
            if not user:
                return

            if not password and not params.login_v3:
                password = getpass.getpass(prompt='... {0:>16}: '.format('Password'), stream=None).strip()
                if not password:
                    return
        except KeyboardInterrupt as e:
            logging.info('Canceled')
            return

        params.user = user.lower()
        params.password = password

        api.login(params)


class CheckEnforcementsCommand(Command):
    def get_parser(self):
        return check_enforcements_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        if params.enforcements:
            if 'enterprise_invited' in params.enforcements:
                print('You\'ve been invited to join {0}.'.format(params.enforcements['enterprise_invited']))
                action = user_choice('A(ccept)/D(ecline)/I(gnore)?: ', 'adi')
                action = action.lower()
                if action == 'a':
                    action = 'accept'
                elif action == 'd':
                    action = 'decline'
                if action in ['accept', 'decline']:
                    e_rq = {
                        'command': '{0}_enterprise_invite'.format(action)
                    }
                    if action == 'accept':
                        verification_code = input('Please enter the verification code sent via email: ')
                        if verification_code:
                            e_rq['verification_code'] = verification_code
                        else:
                            e_rq = None
                    if e_rq:
                        try:
                            api.communicate(params, e_rq)
                            logging.info('%s enterprise invite', 'Accepted' if action == 'accept' else 'Declined')
                            #TODO reload enterprise settings
                        except Exception as e:
                            logging.error('Enterprise %s failure: %s', action, e)

        if params.settings:
            if 'share_account_to' in params.settings:
                dt = datetime.datetime.fromtimestamp(params.settings['must_perform_account_share_by'] // 1000)
                print('Your Keeper administrator has enabled the ability to transfer your vault records\n'
                      'in accordance with company operating procedures and policies.\n'
                      'Please acknowledge this change in account settings by typing ''Accept''.')
                print('If you do not accept this change by {0}, you will be locked out of your account.'.format(dt.strftime('%a, %d %b %Y')))

                try:
                    api.accept_account_transfer_consent(params, params.settings['share_account_to'])
                finally:
                    del params.settings['must_perform_account_share_by']
                    del params.settings['share_account_to']


class LogoutCommand(Command):
    def get_parser(self):
        return logout_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        params.clear_session()


connect_command_description = '''
Connect Command Syntax Description:

This command reads the custom fields for names starting with "connect:"

  connect:<name>                                    command 
  connect:<name>:description                        command description
  connect:<name>:ssh-key:<key-comment>              ssh private key to add to ssh-agent
  connect:<name>:env:<Environment Variable To Set>  sets environment variable

Connection command may contain template parameters.
Parameter syntax is ${<parameter_name>}

Supported parameters:

    ${user_email}                   Keeper user email address
    ${login}                        Record login
    ${password}                     Record password
    ${text:<name>}                  non secured user variable. Stored to non-shared data
    ${mask:<name>}                  secured user variable. Stored to non-shared data
    ${file:<attachment_name>}       stores attachment into temporary file. parameter is replaced with temp file name
    ${body:<attachment_name>}       content of the attachment file.
    ${<custom_field_name>}          custom field value

SSH Example:

Title: SSH to my Server via Gateway
Custom Field 1 Name: connect:my_server:description
Custom Field 1 Value: Production Server Inside Gateway
Custom Field 2 Name: connect:my_server
Custom Field 2 Value: ssh -o "ProxyCommand ssh -i ${file:gateway.pem} ec2-user@gateway.mycompany.com -W %h:%p" -i ${file:server.pem} ec2-user@server.company.com
File Attachments:
gateway.pem
server.pem

To initiate connection: "connect my_server"

Connect to Postgres Example:
Title:    Postgres
Login:    PGuser
Password: **************
Custom Field 1 Name:  connect:postgres
Custom Field 1 Value: psql --host=11.22.33.44 --port=3306 --username=${login} --dbname=postgres --no-password
Custom Field 2 Name:  connect:postgres:env:PGPASSWORD
Custom Field 2 Value: ${password}

To initiate connection: "connect postgres"
'''

endpoint_pattern = re.compile(r'^connect:([^:]+)$')
endpoint_desc_pattern = re.compile(r'^connect:([^:]+):description$')
endpoint_parameter_pattern = re.compile(r'\${(.+?)}')


class ConnectSshAgent:
    def __init__(self, path):
        self.path = path
        self._fd = None

    def __enter__(self):
        if os.name == 'posix':
            if not self.path:
                raise Exception('Add ssh-key. \'SSH_AUTH_SOCK\' environment variable is not set')
            from socket import AF_UNIX, SOCK_STREAM, socket
            self._fd = socket(AF_UNIX, SOCK_STREAM, 0)
            self._fd.settimeout(1)
            self._fd.connect(self.path)
        elif os.name == 'nt':
            path = self.path or  r'\\.\pipe\openssh-ssh-agent'
            self._fd = open(path, 'rb+', buffering=0)
        else:
            raise Exception('SSH Agent Connect: Unsupported platform')
        return self

    def __exit__(self, type, value, traceback):
        if self._fd:
            self._fd.close()

    def send(self, rq):     # type: (bytes) -> bytes
        if self._fd:
            rq_len = len(rq)
            to_send = rq_len.to_bytes(4, byteorder='big') + rq

            if os.name == 'posix':
                self._fd.send(to_send)
                lb = self._fd.recv(4)
                rs_len = int.from_bytes(lb, byteorder='big')
                return self._fd.recv(rs_len)
            elif os.name == 'nt':
                b = self._fd.write(to_send)
                self._fd.flush()
                lb = self._fd.read(4)
                rs_len = int.from_bytes(lb, byteorder='big')
                return self._fd.read(rs_len)
        raise Exception('SSH Agent Connect: Unsupported platform')


class ConnectEndpoint:
    def __init__(self, name, description, record_uid, record_title, paths):
        self.name = name                    # type: str
        self.description = description      # type: str
        self.record_uid = record_uid        # type: str
        self.record_title = record_title    # type: str
        self.paths = paths                  # type: list


class ConnectCommand(Command):
    LastRevision = 0 # int
    Endpoints = []          # type: [ConnectEndpoint]

    def get_parser(self):
        return connect_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(connect_command_description)
            return

        ConnectCommand.find_endpoints(params)

        endpoint = kwargs.get('endpoint')
        if endpoint:
            endpoints = [x for x in ConnectCommand.Endpoints if x.name == endpoint]
            if not endpoints:
                rpos = endpoint.rfind(':')
                if rpos > 0:
                    try_path = endpoint[:rpos]
                    endpoint_name = endpoint[rpos+1:]
                else:
                    try_path = endpoint
                    endpoint_name = ''
                record_uid = ''
                if try_path in params.record_cache:
                    record_uid = try_path
                else:
                    rs = try_resolve_path(params, try_path)
                    if rs is not None:
                        folder, title = rs
                        if folder is not None and title is not None:
                            folder_uid = folder.uid or ''
                            if folder_uid in params.subfolder_record_cache:
                                for uid in params.subfolder_record_cache[folder_uid]:
                                    r = api.get_record(params, uid)
                                    if r.title.lower() == title.lower():
                                        record_uid = uid
                                        break
                if record_uid:
                    endpoints = [x for x in ConnectCommand.Endpoints
                                 if x.record_uid == record_uid and endpoint_name in {'', x.name}]

            if len(endpoints) > 0:
                if len(endpoints) == 1:
                    record = api.get_record(params, endpoints[0].record_uid)
                    ConnectCommand.connect_endpoint(params, endpoints[0].name, record, kwargs.get('new_data') or False)
                else:
                    logging.warning("Connect endpoint '{0}' is not unique".format(endpoint))
                    ConnectCommand.dump_endpoints(endpoints)
                    logging.info("Use full endpoint path: /<Folder>/<Title>[:<Endpoint>]")
                    folder = endpoints[0].paths[0] if len(endpoints[0].paths) > 0 else '/'
                    logging.info('Example: connect "{0}/{1}:{2}"'
                                 .format(folder, endpoints[0].record_title, endpoints[0].name))
            else:
                logging.info("Connect endpoint '{0}' not found".format(endpoint))
        else:
            if ConnectCommand.Endpoints:
                sorted_by = kwargs['sort_by'] or 'endpoint'
                filter_by = kwargs['filter_by'] or ''
                logging.info("Available connect endpoints")
                if filter_by:
                    logging.info('Filtered by \"%s\"', filter_by)
                    filter_by = filter_by.lower()
                ConnectCommand.dump_endpoints(ConnectCommand.Endpoints, filter_by, sorted_by)
            else:
                logging.info("No connect endpoints found")
            return

    @staticmethod
    def dump_endpoints(endpoints, filter_by='', sorted_by=''):
        logging.info('')
        headers = ["#", 'Endpoint', 'Description', 'Record Title', 'Folder(s)']
        table = []
        for endpoint in endpoints:
            title = endpoint.record_title
            folder = endpoint.paths[0] if len(endpoint.paths) > 0 else '/'
            if filter_by:
                if not any([x for x in [endpoint.name.lower(), title.lower(), folder.lower()] if x.find(filter_by) >= 0]):
                    continue
            if len(title) > 23:
                title = title[:20] + '...'
            table.append([0, endpoint.name, endpoint.description or '', title, folder])
        table.sort(key=lambda x: x[4] if sorted_by == 'folder' else x[3] if sorted_by == 'title' else x[1])
        for i in range(len(table)):
            table[i][0] = i + 1
        print(tabulate(table, headers=headers))
        print('')

    @staticmethod
    def delete_ssh_keys(delete_requests):
        try:
            ssh_socket_path = os.environ.get('SSH_AUTH_SOCK')
            with ConnectSshAgent(ssh_socket_path) as fd:
                for rq in delete_requests:
                    recv_payload = fd.send(rq)
                    if recv_payload and  recv_payload[0] == SSH_AGENT_FAILURE:
                        logging.info('Failed to delete added ssh key')
        except Exception as e:
            logging.error(e)


    @staticmethod
    def add_environment_variables(params, endpoint, record, temp_files, non_shared):
        # type: (KeeperParams, str, Record, [str], dict) -> [str]
        rs = []         # type: [str]
        key_prefix = 'connect:{0}:env:'.format(endpoint)
        for cf in record.custom_fields:
            cf_name = cf['name']        # type: str
            if cf_name.startswith(key_prefix):
                key_name = cf_name[len(key_prefix):]
                if not key_name:
                    continue
                cf_value = cf['value']  # type: str
                while True:
                    m = endpoint_parameter_pattern.search(cf_value)
                    if not m:
                        break
                    p = m.group(1)
                    val = ConnectCommand.get_parameter_value(params, record, p, temp_files, non_shared)
                    if not val:
                        raise Exception('Add environment variable. Failed to resolve key parameter: {0}'.format(p))
                    cf_value = cf_value[:m.start()] + val + cf_value[m.end():]
                if cf_value:
                    rs.append(key_name)
                    os.putenv(key_name, cf_value)
        return rs

    @staticmethod
    def add_ssh_keys(params, endpoint, record, temp_files, non_shared):
        # type: (KeeperParams, str, Record, [str], dict) -> [bytes]
        rs = []
        key_prefix = 'connect:{0}:ssh-key'.format(endpoint)
        ssh_socket_path = os.environ.get('SSH_AUTH_SOCK')
        for cf in record.custom_fields:
            cf_name = cf['name']        # type: str
            if cf_name.startswith(key_prefix):
                key_name = cf_name[len(key_prefix)+1:] or 'Commander'
                cf_value = cf['value']  # type: str
                parsed_values = []
                while True:
                    m = endpoint_parameter_pattern.search(cf_value)
                    if not m:
                        break
                    p = m.group(1)
                    val = ConnectCommand.get_parameter_value(params, record, p, temp_files, non_shared)
                    if not val:
                        raise Exception('Add ssh-key. Failed to resolve key parameter: {0}'.format(p))
                    parsed_values.append(val)
                    cf_value = cf_value[m.end():]
                if len(parsed_values) > 0:
                    cf_value = cf_value.strip()
                    if cf_value:
                        parsed_values.append(cf_value)

                    private_key = RSA.importKey(parsed_values[0], parsed_values[1] if len(parsed_values) > 0 else None)
                    with ConnectSshAgent(ssh_socket_path) as fd:
                        payload = SSH2_AGENTC_ADD_IDENTITY.to_bytes(1, byteorder='big')
                        payload += ConnectCommand.ssh_agent_encode_str('ssh-rsa')
                        payload += ConnectCommand.ssh_agent_encode_long(private_key.n)
                        payload += ConnectCommand.ssh_agent_encode_long(private_key.e)
                        payload += ConnectCommand.ssh_agent_encode_long(private_key.d)
                        payload += ConnectCommand.ssh_agent_encode_long(int(Integer(private_key.q).inverse(private_key.p)))
                        payload += ConnectCommand.ssh_agent_encode_long(private_key.p)
                        payload += ConnectCommand.ssh_agent_encode_long(private_key.q)
                        payload += ConnectCommand.ssh_agent_encode_str(key_name)
                        # windows ssh implementation does not support constrained identities
                        #payload += SSH_AGENT_CONSTRAIN_LIFETIME.to_bytes(1, byteorder='big')
                        #payload += int(10).to_bytes(4, byteorder='big')

                        recv_payload = fd.send(payload)
                        if recv_payload and recv_payload[0] == SSH_AGENT_FAILURE:
                            raise Exception('Add ssh-key. Failed to add ssh key \"{0}\" to ssh-agent'.format(key_name))

                        payload = ConnectCommand.ssh_agent_encode_str('ssh-rsa')
                        payload += ConnectCommand.ssh_agent_encode_long(private_key.e)
                        payload += ConnectCommand.ssh_agent_encode_long(private_key.n)
                        payload = SSH2_AGENTC_REMOVE_IDENTITY.to_bytes(1, byteorder='big') + ConnectCommand.ssh_agent_encode_bytes(payload)

                        rs.append(payload)
        return rs

    @staticmethod
    def ssh_agent_encode_bytes(b):      # type: (bytes) -> bytes
        return len(b).to_bytes(4, byteorder='big') + b

    @staticmethod
    def ssh_agent_encode_long(l):       # type: (int) -> bytes
        len = (l.bit_length() + 7) // 8
        b = l.to_bytes(length=len, byteorder='big')
        if b[0] >= 0x80:
            b = b'\x00' + b
        return ConnectCommand.ssh_agent_encode_bytes(b)

    @staticmethod
    def ssh_agent_encode_str(s):                  # type: (str) -> bytes
        return ConnectCommand.ssh_agent_encode_bytes(s.encode('utf-8'))

    @staticmethod
    def find_endpoints(params):
        # type: (KeeperParams) -> None
        if ConnectCommand.LastRevision < params.revision:
            ConnectCommand.LastRevision = params.revision
            ConnectCommand.Endpoints.clear()
            for record_uid in params.record_cache:
                record = api.get_record(params, record_uid)
                if record.custom_fields:
                    endpoints = []
                    endpoints_desc = {}
                    for field in record.custom_fields:
                        if 'name' in field:
                            field_name = field['name']
                            m = endpoint_pattern.match(field_name)
                            if m:
                                endpoints.append(m[1])
                            else:
                                m = endpoint_desc_pattern.match(field_name)
                                if m:
                                    endpoints_desc[m[1]] = field.get('value') or ''
                    if endpoints:
                        paths = []
                        for folder_uid in find_folders(params, record_uid):
                            path = '/' + get_folder_path(params, folder_uid, '/')
                            paths.append(path)
                        for endpoint in endpoints:
                            epoint = ConnectEndpoint(endpoint, endpoints_desc.get(endpoint) or '', record_uid, record.title, paths)
                            ConnectCommand.Endpoints.append(epoint)
            ConnectCommand.Endpoints.sort(key=lambda x: x.name)

    attachment_cache = {}
    @staticmethod
    def load_attachment_file(params, attachment, record):
        # type: (KeeperParams, dict, Record) -> bytes
        rq = {
            'command': 'request_download',
            'file_ids': [attachment['id']]
        }
        api.resolve_record_access_path(params, record.record_uid, path=rq)
        rs = api.communicate(params, rq)
        if 'url' in rs['downloads'][0]:
            url = rs['downloads'][0]['url']
            key = base64.urlsafe_b64decode(attachment['key'] + '==')
            rq_http = requests.get(url, stream=True)
            iv = rq_http.raw.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            finished = False
            decrypted = None
            body = b''
            while not finished:
                if decrypted:
                    body += decrypted
                    decrypted = None

                to_decrypt = rq_http.raw.read(10240)
                finished = len(to_decrypt) < 10240
                if len(to_decrypt) > 0:
                    decrypted = cipher.decrypt(to_decrypt)
            if decrypted:
                decrypted = api.unpad_binary(decrypted)
                body += decrypted

            return body

    @staticmethod
    def get_command_string(params, record, template, temp_files, non_shared):
        # type: (KeeperParams, Record, str, list, dict) -> str or None
        command = template
        while True:
            m = endpoint_parameter_pattern.search(command)
            if not m:
                break
            p = m.group(1)
            pv = ConnectCommand.get_parameter_value(params, record, p, temp_files, non_shared)
            command = command[:m.start()] + (pv or '') + command[m.end():]
        logging.debug(command)
        return command

    @staticmethod
    def get_parameter_value(params, record, parameter, temp_files, non_shared):
        # type: (KeeperParams, Record, str, list, dict) -> str or None
        if parameter.startswith('file:') or parameter.startswith('body:'):
            file_name = parameter[5:]
            if file_name not in ConnectCommand.attachment_cache:
                attachment = None
                if record.attachments:
                    for atta in record.attachments:
                        if file_name == atta['id'] or file_name.lower() in [atta[x].lower() for x in ['name', 'title'] if x in atta]:
                            attachment = atta
                            break
                if not attachment:
                    logging.error('Attachment file \"%s\" not found', file_name)
                    return None
                body = ConnectCommand.load_attachment_file(params, attachment, record)
                if body:
                    ConnectCommand.attachment_cache[file_name] = body
            if file_name not in ConnectCommand.attachment_cache:
                logging.error('Attachment file \"%s\" not found', file_name)
                return None
            body = ConnectCommand.attachment_cache[file_name] # type: bytes
            if parameter.startswith('file:'):
                tf = tempfile.NamedTemporaryFile(delete=False)
                tf.write(body)
                tf.flush()
                temp_files.append(tf.name)
                tf.close()
                return tf.name
            else:
                return body.decode('utf-8')
        elif parameter.startswith('text:') or parameter.startswith('mask:'):
            var_name = parameter[5:]
            val = non_shared.get(var_name)
            if val is None:
                prompt = 'Type value for \'{0}\' > '.format(var_name)
                if parameter.startswith('text:'):
                    val = input(prompt)
                else:
                    val = getpass.getpass(prompt)
                non_shared[var_name] = val
            return val
        elif parameter == 'user_email':
            return params.user
        elif parameter == 'login':
            return record.login
        elif parameter == 'password':
            return record.unmasked_password or record.password
        else:
            value = record.get(parameter)
            if value:
                return value
        logging.error('Parameter \"%s\" cannot be resolved', parameter)

    @staticmethod
    def connect_endpoint(params, endpoint, record, new_data):
        # type: (KeeperParams, str, Record, bool) -> None
        temp_files = []

        cmndr = {}
        non_shared_data = params.non_shared_data_cache.get(record.record_uid)
        if non_shared_data is not None:
            if 'data_unencrypted' in non_shared_data:
                non_shared = json.loads(non_shared_data['data_unencrypted'])
                cmndr = non_shared.get('commander') or {}
        non_shared = cmndr if not new_data else {}

        try:
            command = record.get('connect:' + endpoint + ':pre')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, non_shared)
                if command:
                    os.system(command)

            command = record.get('connect:' + endpoint)
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, non_shared)
                if command:
                    added_keys = ConnectCommand.add_ssh_keys(params, endpoint, record, temp_files, non_shared)
                    added_envs = ConnectCommand.add_environment_variables(params, endpoint, record, temp_files, non_shared)
                    logging.info('Connecting to %s...', endpoint)
                    os.system(command)
                    if added_keys:
                        ConnectCommand.delete_ssh_keys(added_keys)
                    if added_envs:
                        for name in added_envs:
                            os.putenv(name, '')

            command = record.get('connect:' + endpoint + ':post')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, non_shared)
                if command:
                    os.system(command)

        finally:
            for file in temp_files:
                os.remove(file)


class EchoCommand(Command):
    def get_parser(self):
        return echo_parser

    def execute(self, params, **kwargs):
        argument = kwargs.get('argument')
        if argument:
            print(argument)
        else:
            envs = {LAST_RECORD_UID, LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID}
            for name in params.environment_variables:
                envs.add(name)
            names = [x for x in envs]
            names.sort()
            for name in names:
                if name in params.environment_variables:
                    print('${{{0}}} = "{1}"'.format(name, params.environment_variables[name] ))
                else:
                    print('${{{0}}} ='.format(name))


class SetCommand(Command):
    def get_parser(self):
        return set_parser

    def execute(self, params, **kwargs):
        name = kwargs['name']
        value = kwargs.get('value')
        if value:
            params.environment_variables[name] = value
        else:
            if name in params.environment_variables:
                del params.environment_variables[name]


class HelpCommand(Command):
    def get_parser(self):
        return help_parser

    def execute(self, params, **kwargs):
        cmd = kwargs.get('command')
        if cmd:
            if cmd in aliases:
                ali = aliases[cmd]
                if type(ali) == tuple:
                    cmd = ali[0]
                else:
                    cmd = ali
            parser = None       # type: argparse.ArgumentParser or None
            if cmd in commands:
                parser = commands[cmd].get_parser()
            elif cmd in enterprise_commands:
                parser = enterprise_commands[cmd].get_parser()
            if parser:
                parser.print_help()

    def is_authorised(self):
        return False


class DeleteCorruptedCommand(Command):
    def execute(self, params, **kwargs):
        bad_records = set()
        for record_uid in params.record_cache:
            record = params.record_cache[record_uid]
            if not record.get('data_unencrypted'):
                if record_uid in params.meta_data_cache:
                    meta_data = params.meta_data_cache[record_uid];
                    if meta_data.get('owner'):
                        bad_records.add(record_uid)
        if len(bad_records) > 0:
            uc = user_choice('Do you want to delete {0} corrupted records?'.format(len(bad_records)), 'yn', default='n')
            if uc.lower() == 'y':
                request = {
                    'command': 'record_update',
                    'delete_records': list(bad_records)
                }
                logging.info('Deleting %s records from Keeper', len(params.record_cache))
                response_json = api.communicate(params, request)
                success = [info for info in response_json['delete_records'] if info['status'] == 'success']
                if len(success) > 0:
                    logging.info("%s records deleted successfully", len(success))
                failures = [info for info in response_json['delete_records'] if info['status'] != 'success']
                if len(failures) > 0:
                    logging.warning("%s records failed to delete", len(failures))
        else:
            logging.info('No corrupted records are found.')
