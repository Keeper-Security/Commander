# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import base64
import getpass
import hmac
import json
import logging
import os
import platform
import re
import sys
import urllib.parse
from datetime import datetime, timedelta
from time import time
from typing import Optional

from google.protobuf.json_format import MessageToDict
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import aliases, commands, enterprise_commands, msp_commands
from .base import raise_parse_exception, suppress_exit, user_choice, Command, dump_report_data, as_boolean
from .helpers.timeout import (
    enforce_timeout_range, format_timeout, get_delta_from_timeout_setting, get_timeout_setting_from_delta, parse_timeout
)
from .helpers.whoami import get_hostname, get_environment, get_data_center
from .recordv3 import RecordRemoveCommand
from .. import __version__
from .. import api, rest_api, loginv3, crypto, utils, vault
from ..api import communicate_rest, pad_aes_gcm, encrypt_aes_plain
from ..constants import get_abbrev_by_host
from ..display import bcolors
from ..error import CommandError, KeeperApiError
from ..generator import KeeperPasswordGenerator, DicewarePasswordGenerator
from ..loginv3 import CommonHelperMethods
from ..params import KeeperParams, LAST_RECORD_UID, LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID
from ..proto import ssocloud_pb2 as ssocloud
from ..proto.APIRequest_pb2 import ApiRequest, ApiRequestPayload, ApplicationShareType, AddAppClientRequest, \
    GetAppInfoRequest, GetAppInfoResponse, AppShareAdd, AddAppSharesRequest, RemoveAppClientsRequest, \
    RemoveAppSharesRequest, Salt, MasterPasswordReentryRequest, UNMASK, UserAuthRequest, ALTERNATE, UidRequest, \
    GetApplicationsSummaryResponse
from ..proto.record_pb2 import ApplicationAddRequest
from ..recordv3 import init_recordv3_commands
from ..rest_api import execute_rest
from ..utils import json_to_base64, password_score
from ..versioning import is_binary_app, is_up_to_date_version
from .connect import ConnectSshCommand


BREACHWATCH_MAX = 5


def register_commands(commands):
    commands['sync-down'] = SyncDownCommand()
    commands['this-device'] = ThisDeviceCommand()
    commands['delete-all'] = RecordDeleteAllCommand()
    commands['whoami'] = WhoamiCommand()
    commands['proxy'] = ProxyCommand()
    commands['login'] = LoginCommand()
    commands['logout'] = LogoutCommand()
    commands['check-enforcements'] = CheckEnforcementsCommand()
    commands['accept-transfer'] = AcceptTransferCommand()
    commands['ssh'] = ConnectSshCommand()
    commands['delete-corrupted'] = DeleteCorruptedCommand()
    commands['echo'] = EchoCommand()
    commands['set'] = SetCommand()
    commands['help'] = HelpCommand()
    commands['secrets-manager'] = KSMCommand()
    commands['version'] = VersionCommand()
    commands['keep-alive'] = KeepAliveCommand()
    commands['generate'] = GenerateCommand()
    commands['reset-password'] = ResetPasswordCommand()


def register_command_info(aliases, command_info):
    aliases['d'] = 'sync-down'
    aliases['delete_all'] = 'delete-all'
    aliases['gen'] = 'generate'
    aliases['v'] = 'version'
    aliases['sm'] = 'secrets-manager'
    aliases['secrets'] = 'secrets-manager'
    for p in [sync_down_parser, whoami_parser, this_device_parser, proxy_parser, login_parser, logout_parser, echo_parser, set_parser, help_parser,
              version_parser, ksm_parser, keepalive_parser, generate_parser, reset_password_parser
              ]:
        command_info[p.prog] = p.description


available_ksm_commands = f"""
{bcolors.BOLD}Keeper Secrets Manager{bcolors.ENDC}
Commands to configure and manage the Keeper Secrets Manager platform.

  Usage:

  {bcolors.BOLD}View Applications:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app list{bcolors.ENDC}

  {bcolors.BOLD}Get Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app get {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.ENDC}

  {bcolors.BOLD}Create Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app create {bcolors.OKBLUE}[NAME]{bcolors.ENDC}

  {bcolors.BOLD}Remove Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app remove {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.ENDC}
    Options: 
      --purge : Remove the application and purge it from the trash
      --force : Do not prompt for confirmation

  {bcolors.BOLD}Add Client Device:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager client add --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--unlock-ip{bcolors.ENDC}
    Options: 
      --name [CLIENT NAME] : Name of the client (Default: Random 10 characters string)
      --first-access-expires-in-min [MIN] : First time access expiration (Default 60, Max 1440)
      --access-expire-in-min [MIN] : Client access expiration (Default: no expiration)
      --unlock-ip : Does not lock IP address to first requesting device
      --count [NUM] : Number of tokens to generate (Default: 1)
      --config-init [json, b64 or k8s] : Initialize configuration string from a one-time token

  {bcolors.BOLD}Remove Client Device:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager client remove --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--client {bcolors.OKBLUE}[NAME OR ID]{bcolors.ENDC}
    Options: 
      --force : Do not prompt for confirmation
      --client : Client name or ID. Provide `*` or `all` to delete all clients at once
      
  {bcolors.BOLD}Add Secret to Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share add --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD OR SHARED FOLDER UID]{bcolors.ENDC}
    Options: 
      --editable : Allow secrets to be editable by the client

  {bcolors.BOLD}Remove Secret from Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share remove --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD OR SHARED FOLDER UID]{bcolors.ENDC}

  -----
  Note: If the UID you are using contains a dash (-) in the beginning, the value should be wrapped 
  in quotes and prepended with an equal sign. For example:
  {bcolors.OKGREEN}secrets-manager share add --app={bcolors.OKBLUE}"-fwZjKGbKnZCo1Fh8gsf5w"{bcolors.OKGREEN} --secret={bcolors.OKBLUE}"-FcesCt6YXcJzpHWWRgoDA"{bcolors.ENDC}

  To learn about Keeper Secrets Manager visit:
  {bcolors.WARNING}https://docs.keeper.io/secrets-manager/{bcolors.ENDC}

"""

sync_down_parser = argparse.ArgumentParser(prog='sync-down|d', description='Download & decrypt data.')
sync_down_parser.add_argument('-f', '--force', dest='force', action='store_true', help='full data sync')

whoami_parser = argparse.ArgumentParser(prog='whoami', description='Display information about the currently logged in user.')
whoami_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
whoami_parser.error = raise_parse_exception
whoami_parser.exit = suppress_exit


this_device_available_command_verbs = ['rename', 'register', 'persistent-login', 'ip-auto-approve', 'timeout']
this_device_parser = argparse.ArgumentParser(prog='this-device', description='Display and modify settings of the current device.')
this_device_parser.add_argument('ops', nargs='*', help="operation str: " + ", ".join(this_device_available_command_verbs))
this_device_parser.error = raise_parse_exception
this_device_parser.exit = suppress_exit


proxy_parser = argparse.ArgumentParser(prog='proxy', description='Sets proxy server')
proxy_parser.add_argument('-a', '--action', dest='action', action='store', choices=['list', 'add', 'remove'], help='action')
proxy_parser.add_argument('address', nargs='?', type=str, metavar="schema://[user:password@]host:port",
                          help='"add": proxy address. Schemas are "socks5h", "http", "socks4", etc')
proxy_parser.error = raise_parse_exception
proxy_parser.exit = suppress_exit


login_parser = argparse.ArgumentParser(prog='login', description='Login to Keeper.')
login_parser.add_argument('-p', '--pass', dest='password', action='store', help='master password')
login_parser.add_argument('email', nargs='?', type=str, help='account email')
login_parser.error = raise_parse_exception
login_parser.exit = suppress_exit


logout_parser = argparse.ArgumentParser(prog='logout', description='Logout from Keeper')
logout_parser.error = raise_parse_exception
logout_parser.exit = suppress_exit


check_enforcements_parser = argparse.ArgumentParser(prog='check-enforcements',
                                                    description='Check enterprise enforcements')
check_enforcements_parser.error = raise_parse_exception
check_enforcements_parser.exit = suppress_exit


accept_transfer_parser = argparse.ArgumentParser(prog='accept-transfer', description='Accept account transfer')
accept_transfer_parser.error = raise_parse_exception
accept_transfer_parser.exit = suppress_exit


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


ksm_parser = argparse.ArgumentParser(prog='secrets-manager', description='Keeper Secrets Management (KSM) Commands',
                                     add_help=False)
ksm_parser.add_argument('command', type=str, action='store', nargs="*",
                        help='One of: "app list", "app get", "app create", "app remove", "client add", "client remove", "share add" or "share remove"')
ksm_parser.add_argument('--secret', '-s', type=str, action='append', required=False,
                                           help='Record UID')
ksm_parser.add_argument('--app', '-a', type=str, action='store', required=False,
                                           help='Application Name or UID')
ksm_parser.add_argument('--client', '-i', type=str, dest='client_names_or_ids', action='append', required=False,
                                           help='Client Name or ID')
ksm_parser.add_argument('--first-access-expires-in-min', '-x', type=int, dest='firstAccessExpiresIn', action='store',
                        help='Time for the first request to expire in minutes from the time when this command is '
                             'executed. Maximum 1440 minutes (24 hrs). Default: 60',
                        default=60)
ksm_parser.add_argument('--access-expire-in-min', '-p', type=int, dest='accessExpireInMin', action='store',
                        help='Time interval that this client can access the KSM application. After this time, access '
                             'is denied. Time is entered in minutes starting from the time when command is executed. '
                             'Default: Not expiration')

ksm_parser.add_argument('--count', '-c', type=int, dest='count', action='store',
                        help='Number of tokens to return. Default: 1', default=1)
ksm_parser.add_argument('--help', '-h', dest='helpflag', action="store_true", help='Display help')
ksm_parser.add_argument('--editable', '-e', action='store_true', required=False,
                        help='Is this share going to be editable or not.')
ksm_parser.add_argument('--unlock-ip', '-l', dest='unlockIp', action='store_true', help='Unlock IP Address.')
ksm_parser.add_argument('--return-tokens', dest='returnTokens', action='store_true', help='Return Tokens')
ksm_parser.add_argument('--name', '-n', type=str, dest='name', action='store', help='client name')
ksm_parser.add_argument('--purge', dest='purge', action='store_true', help='remove the record from all folders and purge it from the trash')
ksm_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
ksm_parser.add_argument('--config-init', type=str, dest='config_init', action='store',
                        help='Initialize client config')    # json, b64, file


# ksm_parser.add_argument('identifier', type=str, action='store', help='Object identifier (name or uid)')
ksm_parser.error = raise_parse_exception
ksm_parser.exit = suppress_exit


version_parser = argparse.ArgumentParser(prog='version|v', description='Displays version of the installed Commander.')
version_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
version_parser.add_argument('-p', '--packages', action='store_true', help='Show installed Python packages')
version_parser.error = raise_parse_exception
version_parser.exit = suppress_exit


keepalive_parser = argparse.ArgumentParser(prog='keep-alive', description='Tell the server we are here, forestalling a timeout.')
keepalive_parser.error = raise_parse_exception
keepalive_parser.exit = suppress_exit


generate_parser = argparse.ArgumentParser(prog='generate', description='Generate a new password')
generate_parser.add_argument('--clipboard', '-cc', dest='clipboard', action='store_true', help='Copy to clipboard')
generate_parser.add_argument('--quiet', '-q', dest='quiet', action='store_true', help='Only print password list')
generate_parser.add_argument(
    '--password-list', '-p', dest='password_list', action='store_true',
    help='Also print password list apart from formatted table or json'
)
generate_parser.add_argument('--output', '-o', dest='output_file', action='store', help='Output to specified file')
generate_parser.add_argument(
    '--format', '-f', dest='output_format', action='store', choices=['table', 'json'],
    default='table', help='Output format for displaying password, strength, and BreachWatch if available'
)
generate_parser.add_argument(
    '--json-indent', '-i', dest='json_indent', action='store', default=2, type=int,
    help='JSON format indent (0 for compact, >0 for pretty print)'
)
generate_parser.add_argument(
    '--no-breachwatch', '-nb', dest='no_breachwatch', action='store_true',
    help='Skip BreachWatch detection if BreachWatch is enabled for this account'
)
generate_parser.add_argument(
    '--number', '-n', type=int, dest='number', action='store', help='Number of passwords', default=1
)

random_group = generate_parser.add_argument_group('Random')
random_group.add_argument(
    '--count', '-c', type=int, dest='length', action='store', help='Length of password', default=20
)
random_group.add_argument(
    '-r', '--rules', dest='rules', action='store',
    help='Use comma separated complexity integers (uppercase, lowercase, numbers, symbols)'
)
random_group.add_argument(
    '--symbols', '-s', type=int, dest='symbols', action='store',
    help='Minimum number of symbols in password or 0 for none'
)
random_group.add_argument(
    '--digits', '-d', type=int, dest='digits', action='store',
    help='Minimum number of digits in password or 0 for none'
)
random_group.add_argument(
    '--uppercase', '-u', type=int, dest='uppercase', action='store',
    help='Minimum number of uppercase letters in password or 0 for none'
)
random_group.add_argument(
    '--lowercase', '-l', type=int, dest='lowercase', action='store',
    help='Minimum number of lowercase letters in password or 0 for none'
)

dice_group = generate_parser.add_argument_group('Diceware')
dice_group.add_argument(
    '--dice-rolls', '-dr', type=int, dest='dice_rolls', action='store', help='Number of dice rolls'
)
dice_group.add_argument(
    '--word-list',  dest='word_list', action='store', help='Optional. File path to word list'
)

reset_password_parser = argparse.ArgumentParser(prog='reset-password', description='Reset Master Password')
reset_password_parser.add_argument('--delete-sso', dest='delete_alternate', action='store_true',
                                   help='deletes SSO master password')
reset_password_parser.add_argument('--current', '-c', dest='current_password', action='store', help='current password')
reset_password_parser.add_argument('--new', '-n', dest='new_password', action='store', help='new password')


def ms_to_str(ms, frmt='%Y-%m-%d %H:%M:%S'):
    dt = datetime.fromtimestamp(ms // 1000)
    df_frmt_str = dt.strftime(frmt)

    return df_frmt_str


class SyncDownCommand(Command):
    def get_parser(self):
        return sync_down_parser

    def execute(self, params, **kwargs):
        if kwargs.get('force'):
            params.revision = 0
            if params.config:
                if 'skip_records' in params.config:
                    del params.config['skip_records']

        api.sync_down(params, record_types=True)

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
            if ThisDeviceCommand.is_persistent_login_disabled(params):
                logging.warning('"Stay Logged In" feature is restricted by Keeper Administrator')
                return

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
            timeout_delta = enforce_timeout_range(ThisDeviceCommand.get_setting_str_to_value('logout_timer', value))
            loginv3.LoginV3API.set_user_setting(params, 'logout_timer', get_timeout_setting_from_delta(timeout_delta))
            dispay_value = 'default value' if timeout_delta == timedelta(0) else format_timeout(timeout_delta)
            print(f'Successfully set "logout_timer" to {dispay_value}.')

        else:
            raise Exception("Unknown sub-command " + action + ". Available sub-commands: ", ", ".join(this_device_available_command_verbs))

    @staticmethod
    def is_persistent_login_disabled(params):  # type: (KeeperParams) -> bool
        if params.enforcements and 'booleans' in params.enforcements:
            return next((x['value'] for x in params.enforcements['booleans'] if x['key'] == 'restrict_persistent_login'), False)
        else:
            return False

    @staticmethod
    def get_setting_str_to_value(name: str, value: str):

        name = name.lower()
        value = value.lower()

        if name == 'persistent_login' or name == 'ip_disable_auto_approve':
            final_val = '1' if as_boolean(value) else '0'
        elif name == 'logout_timer':
            final_val = parse_timeout(value)
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

        print('{:>32}: {}'.format('Device Name', this_device['deviceName']))
        # print("{:>32}: {}".format('API Client Version', rest_api.CLIENT_VERSION))

        if 'encryptedDataKeyPresent' in this_device:
            print("{:>32}: {}".format('Data Key Present', (bcolors.OKGREEN + 'YES' + bcolors.ENDC) if this_device['encryptedDataKeyPresent'] else (bcolors.FAIL + 'NO' + bcolors.ENDC)))
        else:
            print("{:>32}: {}".format('Data Key Present', (bcolors.FAIL + 'missing' + bcolors.ENDC)))

        if 'ipDisableAutoApprove' in acct_summary_dict['settings']:
            ipDisableAutoApprove = acct_summary_dict['settings']['ipDisableAutoApprove']
            # ip_disable_auto_approve - If enabled, the device is NOT automatically approved
            # If disabled, the device will be auto approved
            ipAutoApprove = not ipDisableAutoApprove
            print("{:>32}: {}".format('IP Auto Approve',
                                      (bcolors.OKGREEN + 'ON' + bcolors.ENDC)
                                      if ipAutoApprove else
                                      (bcolors.FAIL + 'OFF' + bcolors.ENDC)))
        else:
            print("{:>32}: {}".format('IP Auto Approve', (bcolors.OKGREEN + 'ON' + bcolors.ENDC)))
            # ip_disable_auto_approve = 0 / disabled (default) <==> IP Auto Approve :ON

        persistentLogin = acct_summary_dict['settings'].get('persistentLogin', False)
        print("{:>32}: {}".format('Persistent Login',
                                  (bcolors.OKGREEN + 'ON' + bcolors.ENDC)
                                  if persistentLogin and not ThisDeviceCommand.is_persistent_login_disabled(params) else
                                  (bcolors.FAIL + 'OFF' + bcolors.ENDC)))

        if 'logoutTimer' in acct_summary_dict['settings']:
            device_timeout = get_delta_from_timeout_setting(acct_summary_dict['settings']['logoutTimer'])
            print("{:>32}: {}".format('Device Logout Timeout', format_timeout(device_timeout)))

        else:
            device_timeout = timedelta(hours=1)
            print("{:>32}: Default".format('Logout Timeout'))

        if 'Enforcements' in acct_summary_dict and 'longs' in acct_summary_dict['Enforcements']:
            logout_timeout = next((x['value'] for x in acct_summary_dict['Enforcements']['longs']
                                    if x['key'] == 'logout_timer_desktop'), None)
            if logout_timeout:
                enterprise_timeout = timedelta(minutes=int(logout_timeout))
                print("{:>32}: {}".format('Enterprise Logout Timeout', format_timeout(enterprise_timeout)))

                print("{:>32}: {}".format('Effective Logout Timeout',
                                          format_timeout(min(enterprise_timeout, device_timeout))))

        print('{:>32}: {}'.format('Is SSO User', params.settings['sso_user'] if 'sso_user' in params.settings else False))

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
        if params.session_token:
            hostname = get_hostname(params.rest_context.server_base)
            print('{0:>20s}: {1:<20s}'.format('User', params.user))
            print('{0:>20s}: {1:<20s}'.format('Server', hostname))
            print('{0:>20s}: {1:<20s}'.format('Data Center', get_data_center(hostname)))
            environment = get_environment(hostname)
            if environment:
                print('{0:>20s}: {1:<20s}'.format('Environment', get_environment(hostname)))
            if params.license:
                account_type = params.license['account_type'] if 'account_type' in params.license else None
                if account_type == 2:
                    display_admin = 'No' if params.enterprise is None else 'Yes'
                    print('{0:>20s}: {1:<20s}'.format('Admin', display_admin))

                print('')
                account_type_name = 'Enterprise' if account_type == 2 \
                    else 'Family Plan' if account_type == 1 \
                    else params.license['product_type_name']
                print('{0:>20s}: {1:<20s}'.format('Account Type', account_type_name))
                print('{0:>20s}: {1:<20s}'.format('Renewal Date', params.license['expiration_date']))
                if 'bytes_total' in params.license:
                    storage_bytes = int(params.license['bytes_total'])  # note: int64 in protobuf in python produces string as opposed to an int or long.
                    storage_gb = storage_bytes >> 30
                    storage_bytes_used = params.license['bytes_used'] if 'bytes_used' in params.license else 0
                    print('{0:>20s}: {1:<20s}'.format('Storage Capacity', f'{storage_gb}GB'))
                    storage_usage = (int(storage_bytes_used) * 100 // storage_bytes) if storage_bytes != 0 else 0     # note: int64 in protobuf in python produces string  as opposed to an int or long.
                    print('{0:>20s}: {1:<20s}'.format('Usage', f'{storage_usage}%'))
                    print('{0:>20s}: {1:<20s}'.format('Storage Renewal Date', params.license['storage_expiration_date']))
                print('{0:>20s}: {1:<20s}'.format('BreachWatch', 'Yes' if params.license.get('breach_watch_enabled') else 'No'))
                if params.enterprise:
                    print('{0:>20s}: {1:<20s}'.format('Reporting & Alerts', 'Yes' if params.license.get('audit_and_reporting_enabled') else 'No'))

            if kwargs.get('verbose', False):
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
        return version_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        version_details = is_up_to_date_version(params)
        is_verbose = kwargs.get('verbose', False)
        show_packages = kwargs.get('packages', False)

        this_app_version = __version__

        if version_details.get('is_up_to_date') is None:
            this_app_version = f'{this_app_version} (Current version)'

        if not is_verbose:
            print('{0}: {1}'.format('Commander Version', this_app_version))
        else:
            print('{0:>20s}: {1}'.format('Commander Version', this_app_version))
            print("{0:>20s}: {1}".format('API Client Version', rest_api.CLIENT_VERSION))
            print('{0:>20s}: {1}'.format('Python Version', sys.version.replace("\n", "")))
            print('{0:>20s}: {1}'.format('Operating System', loginv3.CommonHelperMethods.get_os() + '(' + platform.release() + ')'))
            print('{0:>20s}: {1}'.format('Working directory', os.getcwd()))
            print('{0:>20s}: {1}'.format('Package directory', os.path.dirname(api.__file__)))
            print('{0:>20s}: {1}'.format('Config. File', params.config_filename))
            print('{0:>20s}: {1}'.format('Executable', sys.executable))

        if logging.getLogger().isEnabledFor(logging.DEBUG) or show_packages:
            import pkg_resources
            installed_packages = pkg_resources.working_set
            installed_packages_list = sorted(["%s==%s" % (i.key, i.version) for i in installed_packages])
            print('{0:>20s}: {1}'.format('Packages', installed_packages_list))

        if version_details.get('is_up_to_date') is None:
            logging.debug("It appears that Commander is up to date")
        elif not version_details.get('is_up_to_date'):

            latest_version = version_details.get('current_github_version')

            print((bcolors.WARNING +
                   'Latest Commander Version: %s\n'
                   'You can download the current version at: %s \n' + bcolors.ENDC)
                  % (latest_version, version_details.get('new_version_download_url')))
        if is_binary_app():
            print("Installation path: {0} ".format(sys._MEIPASS))


class KeepAliveCommand(Command):
    """Just issue a keepalive to keep the interactive session from timing out."""
    def get_parser(self):
        """Return the argparse parser.  This one has no options, but we want a help message anyway."""
        return keepalive_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        """Just send the keepalive."""
        api.send_keepalive(params)


class ProxyCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return proxy_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        action = kwargs.get('action')
        if action == 'add':
            proxy_server = kwargs.get('address')  # type: str
            if proxy_server:
                is_valid = False
                for prefix in {'socks5', 'http', 'https'}:
                    if proxy_server.startswith(prefix):
                        is_valid = True
                        break
                if not is_valid:
                    logging.warning('Proxy server "%s" does not appear to be a valid proxy URL', proxy_server)
                    proxy_server = ''
            else:
                logging.warning('"add" action requires "proxy" parameter.')

            if proxy_server:
                params.proxy = proxy_server
            else:
                return
        elif action == 'remove':
            params.proxy = None

        if params.proxy:
            logging.info('Proxy server: %s', params.proxy)
        else:
            logging.info('Proxy is not configured.')


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
        except KeyboardInterrupt as e:
            logging.info('Canceled')
            return

        params.user = user.lower()
        params.password = password

        try:
            api.login(params, new_login=True)
            init_recordv3_commands(params)
        except Exception as exc:
            logging.warning(str(exc))


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

        share_account_by = params.get_share_account_timestamp()
        if share_account_by is not None:
            account_transfer_command = AcceptTransferCommand()
            account_transfer_command.execute(params, **kwargs)


class AcceptTransferCommand(Command):
    def get_parser(self):
        return check_enforcements_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        share_account_by = params.get_share_account_timestamp()
        if share_account_by is not None:
            if api.accept_account_transfer_consent(params):
                if 'must_perform_account_share_by' in params.settings:
                    del params.settings['must_perform_account_share_by']
                if 'share_account_to' in params.settings:
                    del params.settings['share_account_to']
                logging.info('Account transfer accepted.')
            else:
                logging.info('Account transfer canceled.')
        else:
            logging.info('There is no account transfer to accept.')


class KSMCommand(Command):

    CLIENT_SHORT_ID_LENGTH = 8

    def get_parser(self):
        return ksm_parser

    def execute(self, params, **kwargs):

        ksm_command = kwargs.get('command')
        ksm_helpflag = kwargs.get('helpflag')

        if len(ksm_command) == 0 or ksm_helpflag:
            print(available_ksm_commands)
            return

        ksm_obj = ksm_command[0]
        ksm_action = ksm_command[1] if len(ksm_command) > 1 else None

        if ksm_obj in ['help', 'h']:
            print(available_ksm_commands)
            return

        if ksm_obj == 'apps' or \
                (ksm_obj in ['app', 'apps'] and ksm_action == 'list'):
            KSMCommand.print_all_apps_records(params)
            return

        if ksm_obj == 'clients' or (ksm_obj in ['client', 'clients'] and ksm_action == 'list'):
            print(bcolors.WARNING + "Listing clients is not available" + bcolors.ENDC)
            return

        if ksm_obj in ['app', 'apps'] and ksm_action == 'get':

            if len(ksm_command) != 3:
                print(f"{bcolors.WARNING}Application name is required.\n  Example: {bcolors.OKGREEN}secrets-manager app get {bcolors.OKBLUE}MyApp{bcolors.ENDC}")
                return

            ksm_app_uid_or_name = ksm_command[2]

            ksm_app = KSMCommand.get_app_record(params, ksm_app_uid_or_name)

            if not ksm_app:
                print((bcolors.WARNING + "Application '%s' not found." + bcolors.ENDC) % ksm_app_uid_or_name)
                return

            KSMCommand.get_and_print_app_info(params, ksm_app.get('record_uid'))
            return

        if ksm_obj in ['client'] and ksm_action == 'get':
            ksm_obj_uid = ksm_command[2]
            print(bcolors.WARNING + "Viewing clients is not available" + bcolors.ENDC)
            return

        if ksm_obj in ['app', 'apps'] and ksm_action in ['add', 'create']:
            if len(ksm_command) < 3:
                print(
                    f'''{bcolors.WARNING}Application name is missing.{bcolors.ENDC}\n'''
                    f'''\tEx: {bcolors.OKGREEN}secrets-manager app create {bcolors.OKBLUE}MyApp{bcolors.ENDC}'''
                    )
                return

            ksm_app_name = ksm_command[2]

            force_to_add = False # TODO: externalize this

            KSMCommand.add_new_v5_app(params, ksm_app_name, force_to_add)
            return

        if ksm_obj in ['app', 'apps'] and ksm_action in ['remove', 'rem', 'rm']:
            app_name_or_uid = ksm_command[2]
            purge = kwargs.get('purge')
            force = kwargs.get('force')

            KSMCommand.remove_v5_app(params=params, app_name_or_uid=app_name_or_uid, purge=purge, force=force)

            return

        if ksm_obj in ['share', 'secret'] and ksm_action is None:
            print("  Add Secret to the App\n\n"
                  + bcolors.OKGREEN + "    secrets-manager share add --app " + bcolors.OKBLUE + "[APP NAME or APP UID]"
                  + bcolors.OKGREEN + " --secret " + bcolors.OKBLUE + "[SECRET UID or SHARED FOLDER UID]"
                  + bcolors.OKGREEN + " --editable" + bcolors.ENDC + "\n")
            return

        if ksm_obj in ['share', 'secret'] and ksm_action in ['add', 'create']:

            app_name_or_uid = kwargs.get('app')
            secret_uid = kwargs.get('secret')   # TODO: Allow multiple secrets
            is_editable = kwargs.get('editable')

            if not secret_uid:
                print(bcolors.WARNING + "\nRecord or Shared Folder UID is required." + bcolors.ENDC)
                print(f"Example to add secret:"
                      + bcolors.OKGREEN + " secrets-manager share add --app " + bcolors.OKBLUE + "[APP NAME or APP UID]" \
                      + bcolors.OKGREEN + " --secret " + bcolors.OKBLUE + "[SECRET UID or SHARED FOLDER UID]" \
                      + bcolors.OKGREEN + " --editable" + bcolors.ENDC + "\n")
                return

            KSMCommand.add_app_share(params, secret_uid, app_name_or_uid, is_editable)
            return

        if ksm_obj in ['share', 'secret'] and ksm_action in ['remove', 'rem', 'rm']:
            app_name_or_uid = kwargs['app'] if 'app' in kwargs else None
            secret_uids = kwargs.get('secret')

            KSMCommand.remove_share(params, app_name_or_uid, secret_uids)
            return

        if ksm_obj in ['client', 'c'] and ksm_action in ['add', 'create']:

            app_name_or_uid = kwargs['app'] if 'app' in kwargs else None

            if not app_name_or_uid:
                print(bcolors.WARNING + "App name is required" + bcolors.ENDC)
                print(f"{bcolors.OKGREEN}  secrets-manager client add "
                      f"{bcolors.OKGREEN}--app {bcolors.OKBLUE}[APP NAME or APP UID] "
                      f"{bcolors.OKGREEN}--secret {bcolors.OKBLUE}[SECRET UID or SHARED FOLDER UID] "
                      f"{bcolors.OKGREEN}--name {bcolors.OKBLUE}[CLIENT NAME] "
                      f"{bcolors.OKGREEN}--config-init [{bcolors.OKBLUE}json{bcolors.OKGREEN}, "
                      f"{bcolors.OKBLUE}b64{bcolors.OKGREEN} or "
                      f"{bcolors.OKBLUE}k8s{bcolors.OKGREEN}]")
                return

            count = kwargs.get('count')
            unlock_ip = kwargs.get('unlockIp')

            client_name = kwargs.get('name')
            config_init = kwargs.get('config_init')

            first_access_expire_on = kwargs.get('firstAccessExpiresIn')
            access_expire_in_min = kwargs.get('accessExpireInMin')

            is_return_tokens = kwargs.get('returnTokens')

            tokens = KSMCommand.add_client(params,
                                           app_name_or_uid,
                                           count, unlock_ip,
                                           first_access_expire_on,
                                           access_expire_in_min,
                                           client_name,
                                           config_init)
            return ', '.join(tokens) if is_return_tokens else None

        if ksm_obj in ['client', 'c'] and ksm_action in ['remove', 'rem', 'rm']:

            app_name_or_uid = kwargs['app'] if 'app' in kwargs else None

            client_names_or_ids = kwargs.get('client_names_or_ids')

            force = kwargs.get('force')

            if len(client_names_or_ids) == 1 and client_names_or_ids[0] in ['*', 'all']:
                KSMCommand.remove_all_clients(params, app_name_or_uid, force)
            else:
                KSMCommand.remove_client(params, app_name_or_uid, client_names_or_ids)

            return

        print(f"{bcolors.WARNING}Unknown combination of KSM commands. Type 'secrets-manager' for more details'{bcolors.ENDC}")

    @staticmethod
    def add_app_share(params, secret_uids, app_name_or_uid, is_editable):

        rec_cache_val = KSMCommand.get_app_record(params, app_name_or_uid)
        if rec_cache_val is None:
            logging.warning('Application "%s" not found.' % app_name_or_uid)
            return

        app_record_uid = rec_cache_val.get('record_uid')
        master_key = rec_cache_val.get('record_key_unencrypted')

        KSMCommand.share_secret(
            params=params,
            app_uid=app_record_uid,
            master_key=master_key,
            secret_uids=secret_uids,
            is_editable=is_editable
        )

    @staticmethod
    def record_data_as_dict(record_dict):
        data_json_str = record_dict.get('data_unencrypted').decode("utf-8")
        data_dict = json.loads(data_json_str)
        return data_dict

    @staticmethod
    def print_all_apps_records(params):

        print(f"\n{bcolors.BOLD}List all Secrets Manager Applications{bcolors.ENDC}\n")
        rs = api.communicate_rest(params, None, 'vault/get_applications_summary', rs_type=GetApplicationsSummaryResponse)
        app_summary = {utils.base64_url_encode(x.appRecordUid): {
            'last_access': x.lastAccess,
            'record_shares': x.recordShares,
            'folder_shares': x.folderShares,
            'folder_records': x.folderRecords,
            'client_count': x.clientCount,
        } for x in rs.applicationSummary}

        apps_table_fields = [f'{bcolors.OKGREEN}App Name{bcolors.ENDC}', f'{bcolors.OKBLUE}App UID{bcolors.ENDC}', 'Records', 'Folders', 'Devices', 'Last Access']
        apps_table = []
        for app_uid in app_summary:
            app = app_summary[app_uid]
            app_record = vault.KeeperRecord.load(params, app_uid)
            if isinstance(app_record, vault.ApplicationRecord):
                la = app['last_access']
                if la > 0:
                    last_access = datetime.fromtimestamp(la // 1000)
                else:
                    last_access = None
                row = [f'{bcolors.OKGREEN}{app_record.title}{bcolors.ENDC}', f'{bcolors.OKBLUE}{app_uid}{bcolors.ENDC}',
                       app['folder_records'], app['folder_shares'], app['client_count'], last_access]
                apps_table.append(row)

        apps_table.sort(key=lambda x: x[0].lower())

        if len(apps_table) == 0:
            print(f'{bcolors.WARNING}No Applications to list.{bcolors.ENDC}\n\nTo create new application, use command {bcolors.OKGREEN}secrets-manager app create {bcolors.OKBLUE}[NAME]{bcolors.ENDC}')
        else:
            dump_report_data(apps_table, apps_table_fields, fmt='table')

        print("")

    @staticmethod
    def get_app_info(params, app_uid):

        rq = GetAppInfoRequest()
        rq.appRecordUid.append(CommonHelperMethods.url_safe_str_to_bytes(app_uid))

        rs = communicate_rest(params, rq, 'vault/get_app_info')

        get_app_info_rs = GetAppInfoResponse()
        get_app_info_rs.ParseFromString(rs)

        return get_app_info_rs.appInfo

    @staticmethod
    def get_sm_app_record_by_uid(params, uid):
        rec = params.record_cache.get(uid)

        if rec.get('version') != 5:
            raise Exception(f'Record {uid} is not a Secrets Manager application')

        data_json_str = rec.get('data_unencrypted').decode("utf-8")
        data_dict = json.loads(data_json_str)

        return data_dict

    @staticmethod
    def get_and_print_app_info(params, uid):

        app_info = KSMCommand.get_app_info(params, uid)

        def shorten_client_id(all_clients, original_id, number_of_characters):

            new_id = original_id[0:number_of_characters]

            res = list(filter(lambda x: CommonHelperMethods.bytes_to_url_safe_str(x.clientId).startswith(new_id), all_clients))
            if len(res) == 1 or new_id == original_id:
                return new_id
            else:
                return shorten_client_id(all_clients, original_id, number_of_characters+1)

        if len(app_info) == 0:
            print(bcolors.WARNING + 'No Secrets Manager Applications returned.' + bcolors.ENDC)
            return
        else:
            for ai in app_info:

                app_uid_str = CommonHelperMethods.bytes_to_url_safe_str(ai.appRecordUid)

                app = KSMCommand.get_sm_app_record_by_uid(params, app_uid_str)
                print(f'\nSecrets Manager Application\n'
                      f'App Name: {app.get("title")}\n'
                      f'App UID: {app_uid_str}')

                if len(ai.clients) > 0:

                    client_count = 1
                    for c in ai.clients:
                        id = c.id
                        client_id = CommonHelperMethods.bytes_to_url_safe_str(c.clientId)
                        created_on = f'{bcolors.OKGREEN}{ms_to_str(c.createdOn)}{bcolors.ENDC}'
                        first_access = f'{bcolors.WARNING}Never{bcolors.ENDC}' if c.firstAccess == 0 else f'{bcolors.OKGREEN}{ms_to_str(c.firstAccess)}{bcolors.ENDC}'
                        last_access = f'{bcolors.WARNING}Never{bcolors.ENDC}' if c.lastAccess == 0 else f'{bcolors.OKGREEN}{ms_to_str(c.lastAccess)}{bcolors.ENDC}'
                        lock_ip = f'{bcolors.OKGREEN}Enabled{bcolors.ENDC}' if c.lockIp else f'{bcolors.WARNING}Disabled{bcolors.ENDC}'

                        current_milli_time = round(time() * 1000)

                        if c.accessExpireOn == 0:
                            expire_access = f'{bcolors.OKGREEN}Never{bcolors.ENDC}'
                        elif c.accessExpireOn <= current_milli_time:
                            expire_access = f'{bcolors.FAIL}{ms_to_str(c.accessExpireOn)}{bcolors.ENDC}'
                        else:
                            expire_access = f'{bcolors.WARNING}{ms_to_str(c.accessExpireOn)}{bcolors.ENDC}'

                        ip_address = c.ipAddress
                        # public_key = c.publicKey

                        short_client_id = shorten_client_id(ai.clients, client_id, KSMCommand.CLIENT_SHORT_ID_LENGTH)

                        client_devices_str = f"\n{bcolors.BOLD}Client Device {client_count}{bcolors.ENDC}\n"\
                                             f"=============================\n"\
                                             f'  Device Name: {bcolors.OKGREEN}{id}{bcolors.ENDC}\n' \
                                             f'  Short ID: {bcolors.OKGREEN}{short_client_id}{bcolors.ENDC}\n' \
                                             f'  Created On: {created_on}\n' \
                                             f'  Expires On: {expire_access}\n' \
                                             f'  First Access: {first_access}\n' \
                                             f'  Last Access: {last_access}\n' \
                                             f'  IP Lock: {lock_ip}\n' \
                                             f'  IP Address: {ip_address if c.ipAddress else "--"}'

                        print(client_devices_str)
                        client_count += 1

                else:
                    print(f'\n\t{bcolors.WARNING}No client devices registered for this Application{bcolors.ENDC}')

                print(bcolors.BOLD + "\nApplication Access\n" + bcolors.ENDC)

                if ai.shares:

                    recs = params.record_cache

                    shares_table_fields = ['Share Type', 'UID', 'Title', 'Permissions']
                    shares_table = []

                    for s in ai.shares:

                        uid_str = CommonHelperMethods.bytes_to_url_safe_str(s.secretUid)
                        uid_str_c = bcolors.OKBLUE + uid_str + bcolors.ENDC

                        sht = ApplicationShareType.Name(s.shareType)
                        editable_status_color = bcolors.OKGREEN if s.editable else bcolors.WARNING
                        editable_status = editable_status_color + ("Editable" if s.editable else "Read-Only") + bcolors.ENDC

                        if sht == 'SHARE_TYPE_RECORD':
                            record = recs.get(uid_str)
                            record_data_dict = KSMCommand.record_data_as_dict(record)
                            row = [
                                'RECORD',
                                uid_str_c,
                                record_data_dict.get('title'),
                                editable_status]
                        elif sht == 'SHARE_TYPE_FOLDER':
                            if uid_str not in params.shared_folder_cache:
                                # logging.warning(f"Shared folder uid {uid_str} is not present in the cache. Looks like "
                                #                 f"it was removed or was not sync to this client yet. Try to perform "
                                #                 f"the `sync-down` to download latest data to local cache." % sht)
                                continue
                            cached_sf = params.shared_folder_cache[uid_str]
                            shf_name = cached_sf.get('name_unencrypted')
                            # shf_num_of_records = len(cached_sf.get('records'))
                            row = [
                                'FOLDER',
                                uid_str_c,
                                shf_name,
                                editable_status]
                        else:
                            logging.warning("Unknown Share Type %s" % sht)
                            continue

                        shares_table.append(row)

                    shares_table.sort(key=lambda x: x[2].lower())
                    dump_report_data(shares_table, shares_table_fields, fmt='table')
                    print()
                else:
                    print('\tThere are no shared secrets to this application')

    @staticmethod
    def share_secret(params, app_uid, master_key, secret_uids, is_editable=False):

        app_shares = []

        added_secret_uids_type_pairs = []

        for uid in secret_uids:
            is_record = uid in params.record_cache
            is_shared_folder = api.is_shared_folder(params, uid)

            if is_record:
                rec = params.record_cache[uid]
                share_key_decrypted = rec['record_key_unencrypted']
                share_type = 'SHARE_TYPE_RECORD'
            elif is_shared_folder:
                cached_sf = params.shared_folder_cache[uid]
                shared_folder_key_unencrypted = cached_sf.get('shared_folder_key_unencrypted')
                share_key_decrypted = shared_folder_key_unencrypted
                share_type = 'SHARE_TYPE_FOLDER'
            else:
                print(f"""{bcolors.WARNING}\tUID="{uid}" is not a Record nor Shared Folder. Only individual records or 
                Shared Folders can be added to the application.{bcolors.ENDC} Make sure your local cache is up to date by
                running 'sync-down' command and trying again.""")

                continue

            added_secret_uids_type_pairs.append((uid, share_type))

            encrypted_secret_key = rest_api.encrypt_aes(share_key_decrypted, master_key)

            app_share = AppShareAdd()
            app_share.secretUid = CommonHelperMethods.url_safe_str_to_bytes(uid)
            app_share.shareType = ApplicationShareType.Value(share_type)
            app_share.encryptedSecretKey = encrypted_secret_key
            app_share.editable = is_editable

            app_shares.append(app_share)

        if len(added_secret_uids_type_pairs) == 0:
            return

        app_share_add_rq = AddAppSharesRequest()
        app_share_add_rq.appRecordUid = CommonHelperMethods.url_safe_str_to_bytes(app_uid)
        app_share_add_rq.shares.extend(app_shares)

        api_request_payload = ApiRequestPayload()
        api_request_payload.payload = app_share_add_rq.SerializeToString()
        api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')

        rs = execute_rest(params.rest_context, 'vault/app_share_add', api_request_payload)

        if type(rs) is bytes:

            print((bcolors.OKGREEN + '\nSuccessfully added secrets to app uid=%s, editable=' + bcolors.BOLD + '%s:' + bcolors.ENDC) % (app_uid, is_editable))
            print('\n'.join(map(lambda x: ('\t' + str(x[0])) + ' ' + ('Record' if ('RECORD' in str(x[1])) else 'Shared Folder'), added_secret_uids_type_pairs)))
            print('\n')
            return True

        if type(rs) is dict:
            if rs.get('message') == 'Duplicate share, already added':
                logging.error("One of the secret UIDs is already shared to this application. "
                              "Please remove already shared UIDs from your command and try again.")
                # this is a backend limitation. If at least one record is already shared to the app, the backend
                # returns error.
            else:
                raise KeeperApiError(rs['error'], rs['message'])

        return False

    @staticmethod
    def get_app_record(params, app_name_or_uid):

        for rec_cache_val in params.record_cache.values():

            if rec_cache_val.get('version') == 5:
                r_uid = rec_cache_val.get('record_uid')
                r_unencr_json_data = rec_cache_val.get('data_unencrypted').decode('utf-8')
                r_unencr_dict = json.loads(r_unencr_json_data)

                if r_unencr_dict.get('title') == app_name_or_uid or r_uid == app_name_or_uid:
                    return rec_cache_val

        return None

    @staticmethod
    def search_app_records(params, search_str):

        search_results_rec_data = []

        for record_uid in params.record_cache:
            rec = params.record_cache[record_uid]

            if rec.get('version') == 5:
                data = json.loads(rec.get('data_unencrypted'))
                rec_uid = rec.get('record_uid')
                rec_title = data.get('title')

                if rec_uid == search_str.strip() or rec_title.lower() == search_str.strip().lower():
                    search_results_rec_data.append(
                        {
                            'uid': rec_uid,
                            'data': data
                        })

        return search_results_rec_data

    @staticmethod
    def remove_v5_app(params, app_name_or_uid, purge, force):

        app = KSMCommand.get_app_record(params, app_name_or_uid)

        if not app:
            logging.warning('Application "%s" not found.' % app_name_or_uid)
            return
        app_uid = app.get('record_uid')

        app_info = KSMCommand.get_app_info(params, app_uid)

        clients_count = len(app_info[0].clients)
        shared_folders_count = sum(map(lambda s: s.shareType == 1, app_info[0].shares))
        shared_records_count = sum(map(lambda s: s.shareType == 0, app_info[0].shares))

        if not force:

            print("This Application (uid: %s) has %d client(s), %d shared folder(s), and %d record(s)."
                  % (app_uid, clients_count, shared_folders_count, shared_records_count))
            uc = user_choice('\tAre you sure you want to delete this application?', 'yn', default='n')
            if uc.lower() != 'y':
                return

        logging.info("Removed Application uid: %s" % app_uid)

        cmd = RecordRemoveCommand()
        cmd.execute(params, purge=purge, force=True, record=app_uid)

    @staticmethod
    def add_new_v5_app(params, app_name, force_to_add=False):

        logging.debug("Creating new KSM Application named '%s'" % app_name)

        found_app = KSMCommand.get_app_record(params, app_name)
        if (found_app is not None) and (found_app is not force_to_add):
            logging.warning('Application with the same name "%s" already exists.' % app_name)
            return

        app_record_data = {
            'title': app_name,
            'type': 'app'
        }

        data_json = json.dumps(app_record_data)
        record_key_unencrypted = os.urandom(32)
        record_key_encrypted = encrypt_aes_plain(record_key_unencrypted, params.data_key)

        app_record_uid_str = api.generate_record_uid()
        app_record_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(app_record_uid_str)

        data = data_json.decode('utf-8') if isinstance(data_json, bytes) else data_json
        data = pad_aes_gcm(data)

        rdata = bytes(data, 'utf-8')
        rdata = encrypt_aes_plain(rdata, record_key_unencrypted)
        rdata = base64.urlsafe_b64encode(rdata).decode('utf-8')
        rdata = loginv3.CommonHelperMethods.url_safe_str_to_bytes(rdata)

        client_modif_time = api.current_milli_time()

        ra = ApplicationAddRequest()
        ra.app_uid = app_record_uid
        ra.record_key = record_key_encrypted
        ra.client_modified_time = client_modif_time
        ra.data = rdata

        params.revision = 0
        rs = communicate_rest(params, ra, 'vault/application_add')

        print(bcolors.OKGREEN + "Application was successfully added" + bcolors.ENDC)

        params.sync_data = True

    @staticmethod
    def remove_share(params, app_name_or_uid, secret_uids):
        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        app_uid = app.get('record_uid')

        rq = RemoveAppSharesRequest()

        rq.appRecordUid = CommonHelperMethods.url_safe_str_to_bytes(app_uid)
        rq.shares.extend(list(map(lambda uid_str: CommonHelperMethods.url_safe_str_to_bytes(uid_str), secret_uids)))

        api_request_payload = ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')

        rs = execute_rest(params.rest_context, 'vault/app_share_remove', api_request_payload)

        if type(rs) is dict:
            raise KeeperApiError(rs['error'], rs['message'])
        else:
            print(bcolors.OKGREEN + "Secret share was successfully removed from the application\n" + bcolors.ENDC)

    @staticmethod
    def remove_all_clients(params, app_name_or_uid, force):
        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        app_uid = app.get('record_uid')

        app_info = KSMCommand.get_app_info(params, app_uid)

        clients_count = len(app_info[0].clients)

        if clients_count == 0:
            print(bcolors.WARNING + "No client devices registered for this Application\n" + bcolors.ENDC)
            return

        if not force:

            print("This app has %d client(s) connections." % clients_count)
            uc = user_choice('\tAre you sure you want to delete all clients from this application?', 'yn', default='n')
            if uc.lower() != 'y':
                return

        client_ids_to_rem = []

        for ai in app_info:

            if len(ai.clients) > 0:
                for c in ai.clients:
                    client_id = CommonHelperMethods.bytes_to_url_safe_str(c.clientId)

                    client_ids_to_rem.append(client_id)

        KSMCommand.remove_client(params, app_name_or_uid, client_ids_to_rem)

    @staticmethod
    def remove_client(params, app_name_or_uid, client_names_and_hashes):

        def convert_ids_and_hashes_to_hashes(cnahs, app_uid):

            client_id_hashes_bytes = []

            app_info = KSMCommand.get_app_info(params, app_uid)

            for ai in app_info:

                if len(ai.clients) > 0:
                    for c in ai.clients:
                        name = c.id
                        client_id = CommonHelperMethods.bytes_to_url_safe_str(c.clientId)

                        for cnah in cnahs:
                            if name == cnah:
                                client_id_hashes_bytes.append(c.clientId)
                            else:
                                if len(cnah) >= KSMCommand.CLIENT_SHORT_ID_LENGTH and client_id.startswith(cnah):
                                    client_id_hashes_bytes.append(c.clientId)

            return client_id_hashes_bytes

        if not app_name_or_uid:
            raise Exception("No app provided")

        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        app_uid = app.get('record_uid')

        client_hashes = convert_ids_and_hashes_to_hashes(client_names_and_hashes, app_uid)

        found_clients_count = len(client_hashes)
        if found_clients_count == 0:
            print(bcolors.WARNING + "No Client Devices found with given name or ID\n" + bcolors.ENDC)
            return
        else:
            uc = user_choice(
                '\tAre you sure you want to delete %d matching clients from this application?' % found_clients_count
                , 'yn', default='n')
            if uc.lower() != 'y':
                return

        rq = RemoveAppClientsRequest()

        rq.appRecordUid = CommonHelperMethods.url_safe_str_to_bytes(app_uid)
        rq.clients.extend(client_hashes)

        api_request_payload = ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')

        rs = execute_rest(params.rest_context, 'vault/app_client_remove', api_request_payload)

        if type(rs) is dict:
            raise KeeperApiError(rs['error'], rs['message'])
        else:
            print(bcolors.OKGREEN + "\nClient removal was successful\n" + bcolors.ENDC)

    @staticmethod
    def add_client(params, app_name_or_uid, count, unlock_ip, first_access_expire_on, access_expire_in_min,
                   client_name=None, config_init=None):

        is_ip_unlocked = as_boolean(unlock_ip, False)
        curr_ms = int(time() * 1000)

        first_access_expire_on_ms = curr_ms + (int(first_access_expire_on) * 60 * 1000)

        if access_expire_in_min:
            access_expire_on_ms = curr_ms + (int(access_expire_in_min) * 60 * 1000)
        else:
            access_expire_on_ms = curr_ms

        if not app_name_or_uid:
            raise Exception("No app provided")

        rec_cache_val = KSMCommand.get_app_record(params, app_name_or_uid)

        if not rec_cache_val:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        logging.debug("App uid=%s, unlock_ip=%s" % (rec_cache_val.get('record_uid'), unlock_ip))

        master_key = rec_cache_val.get('record_key_unencrypted')

        keys_str = ""
        otat_str = ""

        tokens = []

        for i in range(count):
            secret_bytes = os.urandom(32)
            counter_bytes = b'KEEPER_SECRETS_MANAGER_CLIENT_ID'
            digest = 'sha512'

            try:
                mac = hmac.new(secret_bytes, counter_bytes, digest).digest()
            except Exception as e:
                logging.error(e.args[0])
                return

            encrypted_master_key = rest_api.encrypt_aes(master_key, secret_bytes)

            rq = AddAppClientRequest()
            rq.appRecordUid = CommonHelperMethods.url_safe_str_to_bytes(rec_cache_val.get('record_uid'))
            rq.encryptedAppKey = encrypted_master_key
            rq.lockIp = not is_ip_unlocked
            rq.firstAccessExpireOn = first_access_expire_on_ms

            if access_expire_in_min:
                rq.accessExpireOn = access_expire_on_ms

            rq.clientId = mac

            if client_name:
                if count == 1:
                    rq.id = client_name
                else:
                    rq.id = client_name + " " + str((i+1))

            api_request_payload = ApiRequestPayload()
            api_request_payload.payload = rq.SerializeToString()
            api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')

            rs = execute_rest(params.rest_context, 'vault/app_client_add', api_request_payload)

            if type(rs) is bytes:
                if keys_str:
                    keys_str += '\n'

                if not is_ip_unlocked:
                    lock_ip_stat = bcolors.OKGREEN + "Enabled" + bcolors.ENDC
                else:
                    lock_ip_stat = bcolors.HIGHINTENSITYRED + "Disabled" + bcolors.ENDC
                exp_date_str = bcolors.BOLD + datetime.fromtimestamp(
                    first_access_expire_on_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') + bcolors.ENDC

                if access_expire_in_min:
                    app_expire_on_str = bcolors.BOLD + datetime.fromtimestamp(
                        access_expire_on_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') + bcolors.ENDC
                else:
                    app_expire_on_str = bcolors.WARNING + "Never" + bcolors.ENDC

                token = CommonHelperMethods.bytes_to_url_safe_str(secret_bytes)

                if not config_init:
                    abbrev = get_abbrev_by_host(params.server.lower())

                    if abbrev:
                        token_w_prefix = f'{abbrev}:{token}'
                    else:
                        if not params.server.startswith('http'):
                            tmp_server = "https://" + params.server
                        else:
                            tmp_server = params.server

                        token_w_prefix = f'{urllib.parse.urlparse(tmp_server).netloc.lower()}:{token}'

                    otat_str += f'\nOne-Time Access Token: {bcolors.OKGREEN}{token_w_prefix}{bcolors.ENDC}\n'
                    tokens.append(token_w_prefix)

                else:
                    config_str = KSMCommand.init_ksm_config(params,
                                                            one_time_token=token,
                                                            config_init=config_init)
                    otat_str += f'\nInitialized Config: {bcolors.OKGREEN}{config_str}{bcolors.ENDC}\n'
                    tokens.append(config_str)

                if client_name:
                    otat_str += f'Name: {client_name}\n'

                otat_str += f'IP Lock: {lock_ip_stat}\n' \
                            f'Token Expires On: {exp_date_str}\n' \
                            f'App Access Expires on: {app_expire_on_str}\n'

            if type(rs) is dict:
                raise KeeperApiError(rs['error'], rs['message'])
        print(f'\nSuccessfully generated Client Device\n'
              f'====================================\n'
              f'{otat_str}')

        if config_init and not unlock_ip:
            print(bcolors.WARNING + "\tWarning: Configuration is now locked to your current IP. To keep in unlock you "
                                    "can add flag `--unlock-ip` or use the One-time token to generate configuration on "
                                    "the host that has the IP that needs to be locked." + bcolors.ENDC)

            logging.warning('')

        return tokens

    @staticmethod
    def init_ksm_config(params, one_time_token, config_init):

        try:
            from keeper_secrets_manager_core import SecretsManager
            from keeper_secrets_manager_core.configkeys import ConfigKeys
            from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
        except Exception:
            raise Exception("Keeper Secrets Manager is not installed.\n"
                            "Install it using pip `pip3 install keeper-secrets-manager-core`")

        ksm_conf_storage = InMemoryKeyValueStorage()

        secrets_manager = SecretsManager(
            hostname=params.config.get('server'),
            token=one_time_token,
            # verify_ssl_certs=False,
            config=ksm_conf_storage
        )

        secrets_manager.get_secrets("NON-EXISTING-RECORD-UID")

        config_dict = {
            ConfigKeys.KEY_HOSTNAME.value:             ksm_conf_storage.config.get(ConfigKeys.KEY_HOSTNAME),
            ConfigKeys.KEY_CLIENT_ID.value:            ksm_conf_storage.config.get(ConfigKeys.KEY_CLIENT_ID),
            ConfigKeys.KEY_PRIVATE_KEY.value:          ksm_conf_storage.config.get(ConfigKeys.KEY_PRIVATE_KEY),
            ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID.value: ksm_conf_storage.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID),
            ConfigKeys.KEY_APP_KEY.value:              ksm_conf_storage.config.get(ConfigKeys.KEY_APP_KEY),
        }

        # if the SDK version is below 16.2.0 then this key won't be present
        if 'KEY_OWNER_PUBLIC_KEY' in ConfigKeys.__members__ and ksm_conf_storage.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY):
            config_dict[ConfigKeys.KEY_OWNER_PUBLIC_KEY.value] = ksm_conf_storage.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY)

        config_str = json.dumps(config_dict)

        if config_init in ['b64', 'k8s']:
            config_str = json_to_base64(config_str)
        if config_init == 'k8s':
            config_str = "\n" \
                         + "apiVersion: v1\n" \
                         + "data:\n" \
                         + "  config: " + config_str + "\n" \
                         + "kind: Secret\n" \
                         + "metadata:\n" \
                         + "  name: ksm-config\n" \
                         + "  namespace: default\n" \
                         + "type: Opaque"

        return config_str


class LogoutCommand(Command):
    def get_parser(self):
        return logout_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        if params.session_token:
            try:
                api.communicate_rest(params, None, 'vault/logout_v3')
            except:
                pass
        if params.sso_login_info and 'idp_session_id' in params.sso_login_info:
            sso_url = params.sso_login_info.get('sso_url') or ''
            sp_url_builder = urllib.parse.urlparse(sso_url)
            sp_url_query = urllib.parse.parse_qsl(sp_url_builder.query)
            session_id = params.sso_login_info.get('idp_session_id') or ''
            if params.sso_login_info.get('is_cloud'):
                sso_rq = ssocloud.SsoCloudRequest()
                sso_rq.clientVersion = rest_api.CLIENT_VERSION
                sso_rq.embedded = True
                sso_rq.username = params.user.lower()
                sso_rq.idpSessionId = session_id
                transmission_key = utils.generate_aes_key()
                rq_payload = ApiRequestPayload()
                rq_payload.apiVersion = 3
                rq_payload.payload = sso_rq.SerializeToString()
                api_rq = ApiRequest()
                api_rq.locale = params.rest_context.locale or 'en_US'

                server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]
                if isinstance(server_public_key, rsa.RSAPublicKey):
                    api_rq.encryptedTransmissionKey = crypto.encrypt_rsa(transmission_key, server_public_key)
                elif isinstance(server_public_key, ec.EllipticCurvePublicKey):
                    api_rq.encryptedTransmissionKey = crypto.encrypt_ec(transmission_key, server_public_key)
                else:
                    raise ValueError('Invalid server public key')
                api_rq.publicKeyId = params.rest_context.server_key_id
                api_rq.encryptedPayload = crypto.encrypt_aes_v2(rq_payload.SerializeToString(), transmission_key)
                sp_url_query.append(('payload', utils.base64_url_encode(api_rq.SerializeToString())))
            else:
                sp_url_query.append(('embedded', ''))
                sp_url_query.append(('token', ''))
                sp_url_query.append(('user', params.user.lower()))
                if session_id:
                    sp_url_query.append(('session_id', session_id))

            sp_url_builder = sp_url_builder._replace(path=sp_url_builder.path.replace('/login', '/logout'), query=urllib.parse.urlencode(sp_url_query, doseq=True))
            sp_url = urllib.parse.urlunparse(sp_url_builder)
            logging.info('SSO Logout URL\n%s', sp_url)

        params.clear_session()


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
            elif cmd in msp_commands:
                parser = msp_commands[cmd].get_parser()
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
                    meta_data = params.meta_data_cache[record_uid]
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


class GenerateCommand(Command):
    def get_parser(self):
        return generate_parser

    def execute(self, params, number=None, no_breachwatch=None,
                length=None, symbols=None, digits=None, uppercase=None, lowercase=None, rules=None,
                output_format=None, output_file=None, json_indent=None, quiet=False, password_list=False,
                clipboard=False, return_result=False, **kwargs):
        """
        Executes "generate" command

        Parameters
        ----------
        params : KeeperParams
            Connected KeeperParams instance
        number : int
            Number of passwords. Default: 1
        length : int
            Length of password. Default: 20
        symbols : int
            Minimum number of symbols in password if positive exact if 0 or negative. Default: None
        digits : int
            Minimum number of digits in password if positive exact if 0 or negative. Default: None
        uppercase : int
            Minimum number of uppercase letters in password if positive exact if 0 or negative. Default: None
        lowercase : int
            Minimum number of lowercase letters in password if positive exact if 0 or negative. Default: None
        rules : str
            Use comma separated complexity integers (uppercase, lowercase, numbers, symbols)
        no_breachwatch : bool
            Skip BreachWatch detection if BreachWatch is enabled for this account
        output_format : str
            Output format for displaying password, strength, and BreachWatch if available. 'table' or 'json'
        output_file : str
            File name to store result. stdout is omitted
        json_indent : int
            JSON format indent (0 for compact, >0 for pretty print). Default: 2
        quiet : bool
            Only print password list
        password_list: bool
            Also print password list apart from formatted table or json
        clipboard: bool
            Copy to clipboard
        return_result : bool
            If True return tuple of password dict and formatted output string
        """

        dice_rolls = kwargs.get('dice_rolls')
        if isinstance(dice_rolls, int) and dice_rolls > 0:
            kpg = DicewarePasswordGenerator(dice_rolls, kwargs.get('word_list'))
        else:
            if rules and all(i is None for i in (symbols, digits, uppercase, lowercase)):
                kpg = KeeperPasswordGenerator.create_from_rules(rules, length)
                if kpg is None:
                    logging.warning('Using default password complexity rules')
                    kpg = KeeperPasswordGenerator(length=length)
            else:
                if rules:
                    logging.warning(
                        'Ignoring "rules" option used with "symbols", "digits", "uppercase", or "lowercase" option'
                    )
                kpg = KeeperPasswordGenerator(
                    length=length, symbols=symbols, digits=digits, caps=uppercase, lower=lowercase
                )

        get_new_password_count = number
        no_breachwatch = no_breachwatch or getattr(params, 'breach_watch', None) is None

        passwords = []
        breachwatch_count = 0
        while len(passwords) < get_new_password_count:
            new_passwords = [kpg.generate() for i in range(get_new_password_count - len(passwords))]
            if no_breachwatch:
                passwords = [{'password': p, 'strength': password_score(p)} for p in new_passwords]

            else:
                euids = []
                breachwatch_count += 1
                breachwatch_maxed = breachwatch_count >= BREACHWATCH_MAX
                for breach_result in params.breach_watch.scan_passwords(params, new_passwords):
                    pw = breach_result[0]
                    if breach_result[1].euid:
                        euids.append(breach_result[1].euid)
                    if breach_result[1].breachDetected:
                        if breachwatch_maxed:
                            passwords.append(
                                {'password': pw, 'strength': password_score(pw), 'breach_watch': 'Failed'}
                            )
                    else:
                        passwords.append(
                            {'password': pw, 'strength': password_score(pw), 'breach_watch': 'Passed'}
                        )
                params.breach_watch.delete_euids(params, euids)

        if quiet:
            formatted_output = ''
        elif output_format == 'table':
            breach_watch = '' if no_breachwatch else '{breach_watch:13}'
            format_template = '{count:<5}{strength:<13}' + breach_watch + '{password}'
            header = format_template.format(
                count='', strength='Strength(%)', breach_watch='BreachWatch', password='Password'
            )
            password_output = [format_template.format(count=i, **p) for i, p in enumerate(passwords, start=1)]
            formatted_output = header + '\n' + '\n'.join(password_output)
        elif output_format == 'json':
            formatted_output = json.dumps(passwords, indent=json_indent or None)
        else:
            formatted_output = ''

        if quiet or password_list:
            skip_line = '\n\n' if password_list else ''
            formatted_output += skip_line + '\n'.join(p['password'] for p in passwords)

        if clipboard:
            import pyperclip
            pyperclip.copy(formatted_output)
            logging.info('New passwords copied to clipboard')
        elif not output_file:
            print(formatted_output)

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(formatted_output)
            except Exception as e:
                logging.warning('Error writing to file {}: {}'.format(output_file, str(e)))
            else:
                logging.info('Wrote to file {}'.format(output_file))

        if return_result:
            return passwords, formatted_output


class ResetPasswordCommand(Command):
    def get_parser(self):
        return reset_password_parser

    def execute(self, params, **kwargs):
        current_password = kwargs.get('current_password')
        current_alternates = []    # type: list[dict]
        current_master = None      # type: Optional[Salt]
        is_sso_user = params.settings.get('sso_user', False)
        if is_sso_user:
            allow_alternate_passwords = False
            if 'booleans' in params.enforcements:
                allow_alternate_passwords = next((x.get('value') for x in params.enforcements['booleans']
                                                  if x.get('key') == 'allow_alternate_passwords'), False)
            if not allow_alternate_passwords:
                logging.warning('You do not have the required privilege to perform this operation.')
                return

            sync_rq = {
                'command': 'sync_down',
                'revision': 0,
                'include': ['user_auth'] + api.EXPLICIT
            }
            sync_rs = api.communicate(params, sync_rq)
            if 'user_auth' in sync_rs:
                current_alternates = [x for x in sync_rs['user_auth'] if x['login_type'] == 'ALTERNATE']
        else:
            current_master = api.communicate_rest(params, None, 'authentication/get_salt_and_iterations', rs_type=Salt)

        is_delete_alternate = kwargs.get('delete_alternate')
        if is_delete_alternate:
            if is_sso_user:
                logging.info('Deleting SSO Master Password for \"%s\"', params.user)
            else:
                logging.warning('\"%s\" in not SSO account', params.user)
                return
        else:
            if is_sso_user:
                logging.info('%s SSO Master Password for \"%s\"',
                             'Changing' if len(current_alternates) > 0 else 'Setting', params.user)
            else:
                logging.info('Changing Master Password for \"%s\"', params.user)

        if current_master or len(current_alternates) > 0:
            if not current_password:
                current_password = getpass.getpass(prompt='{0:>24}: '.format('Current Password'), stream=None).strip()
                if not current_password:
                    return
            if current_master:
                current_salt = current_master.salt
                current_iterations = current_master.iterations
            else:
                current_salt = utils.base64_url_decode(current_alternates[0]['salt'])
                current_iterations = current_alternates[0]['iterations']

            auth_hash = crypto.derive_keyhash_v1(current_password, current_salt, current_iterations)
            rq = MasterPasswordReentryRequest()
            rq.pbkdf2Password = utils.base64_url_encode(auth_hash)
            rq.action = UNMASK
            try:
                api.communicate_rest(params, rq, 'authentication/validate_master_password')
            except:
                logging.warning('Current password incorrect')
                return
        else:
            current_password = ''

        if is_delete_alternate:
            if len(current_alternates) > 0:
                uid_rq = UidRequest()
                uid_rq.uid.extend((utils.base64_url_decode(x['uid']) for x in current_alternates))
                api.communicate_rest(params, uid_rq, 'authentication/delete_v2_alternate_password')
                logging.info('SSO Master Password has been deleted')
            else:
                logging.info('SSO Master password is not found')
            return

        new_password = kwargs.get('new_password')
        if not new_password:
            password1 = getpass.getpass(prompt='{0:>24}: '.format('New Password'), stream=None).strip()
            password2 = getpass.getpass(prompt='{0:>24}: '.format('Re-enter New Password'), stream=None).strip()
            print('')
            if password1 != password2:
                logging.warning('New password does not match')
                return
            if current_password and password1 == current_password:
                logging.warning('Please choose a different password')
                return
            new_password = password1

        rules = params.settings['rules']
        failed_rules = []
        for rule in rules:
            is_match = re.match(rule['pattern'], new_password)
            if not rule.get('match', True):
                is_match = not is_match
            if not is_match:
                failed_rules.append(rule['description'])
        if failed_rules:
            logging.warning('\n%s\n%s', params.settings.get('password_rules_intro', 'Password rules:'), '\n'.join((f'  {x}' for x in failed_rules)))
            return

        if params.breach_watch:
            euids = []
            for result in params.breach_watch.scan_passwords(params, [new_password]):
                if result[1].euid:
                    euids.append(result[1].euid)
                logging.info('Breachwatch password scan result: %s', 'WEAK' if result[1].breachDetected else 'GOOD')
            if euids:
                params.breach_watch.delete_euids(params, euids)
        else:
            score = utils.password_score(new_password)
            logging.info('Password strength: %s', 'WEAK' if score < 40 else 'FAIR' if score < 60 else 'MEDIUM' if score < 80 else 'STRONG')

        iterations = current_master.iterations if current_master else \
            max((x['iterations'] for x in current_alternates)) if len(current_alternates) > 0 else 100000

        auth_salt = crypto.get_random_bytes(16)
        if is_sso_user:
            ap_rq = UserAuthRequest()
            ap_rq.uid = utils.base64_url_decode(current_alternates[0]['uid']) if len(current_alternates) > 0 else crypto.get_random_bytes(16)
            ap_rq.salt = auth_salt
            ap_rq.iterations = iterations
            ap_rq.authHash = crypto.derive_keyhash_v1(new_password, auth_salt, iterations)
            key = crypto.derive_keyhash_v2('data_key', new_password, auth_salt, iterations)
            ap_rq.encryptedDataKey = crypto.encrypt_aes_v2(params.data_key, key)
            ap_rq.encryptedClientKey = crypto.encrypt_aes_v2(params.client_key, key)
            ap_rq.loginType = ALTERNATE
            ap_rq.name = current_alternates[0]['name'] if len(current_alternates) > 0 else 'alternate'
            api.communicate_rest(params, ap_rq, 'authentication/set_v2_alternate_password')
            logging.info(f'SSO Master Password has been {("changed" if len(current_alternates) > 0 else "set")}')
        else:
            data_salt = crypto.get_random_bytes(16)
            mp_rq = {
                'command': 'change_master_password',
                'auth_verifier': utils.base64_url_encode(utils.create_auth_verifier(new_password, auth_salt, iterations)),
                'encryption_params': utils.base64_url_encode(utils.create_encryption_params(new_password, data_salt, iterations, params.data_key))
            }
            api.communicate(params, mp_rq)
            logging.info('Master Password has been changed')


