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
import datetime
import getpass
import json
import logging
import os
import platform
import re
import sys
import urllib.parse
from datetime import timedelta
from typing import Optional, Dict, List

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from google.protobuf.json_format import MessageToDict

from keepercommander.commands.breachwatch import BreachWatchScanCommand
from . import aliases, commands, enterprise_commands, msp_commands, msp
from .base import raise_parse_exception, suppress_exit, user_choice, Command, GroupCommand, as_boolean
from .helpers.record import get_record_uids as get_ruids
from .helpers.timeout import (
    enforce_timeout_range, format_timeout, get_delta_from_timeout_setting, get_timeout_setting_from_delta, parse_timeout
)
from .helpers.whoami import get_hostname, get_environment, get_data_center
from .ksm import KSMCommand, ksm_parser
from .. import __version__, vault
from .. import api, rest_api, loginv3, crypto, utils, constants
from ..breachwatch import BreachWatch
from ..display import bcolors
from ..error import CommandError
from ..generator import KeeperPasswordGenerator, DicewarePasswordGenerator, CryptoPassphraseGenerator
from ..params import KeeperParams, LAST_RECORD_UID, LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID
from ..proto import ssocloud_pb2, enterprise_pb2, APIRequest_pb2, client_pb2
from ..utils import password_score
from ..vault import KeeperRecord
from ..versioning import is_binary_app, is_up_to_date_version

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
    commands['delete-corrupted'] = DeleteCorruptedCommand()
    commands['echo'] = EchoCommand()
    commands['set'] = SetCommand()
    commands['help'] = HelpCommand()
    commands['secrets-manager'] = KSMCommand()
    commands['version'] = VersionCommand()
    commands['keep-alive'] = KeepAliveCommand()
    commands['generate'] = GenerateCommand()
    commands['reset-password'] = ResetPasswordCommand()
    commands['sync-security-data'] = SyncSecurityDataCommand()


def register_command_info(aliases, command_info):
    aliases['d'] = 'sync-down'
    aliases['delete_all'] = 'delete-all'
    aliases['gen'] = 'generate'
    aliases['v'] = 'version'
    aliases['sm'] = 'secrets-manager'
    aliases['secrets'] = 'secrets-manager'
    aliases['ssd'] = 'sync-security-data'
    for p in [sync_down_parser, whoami_parser, this_device_parser, proxy_parser, login_parser, logout_parser, echo_parser, set_parser, help_parser,
              version_parser, ksm_parser, keepalive_parser, generate_parser, reset_password_parser,
              sync_security_data_parser]:
        command_info[p.prog] = p.description


sync_down_parser = argparse.ArgumentParser(prog='sync-down', description='Download & decrypt data.')
sync_down_parser.add_argument('-f', '--force', dest='force', action='store_true', help='full data sync')

whoami_parser = argparse.ArgumentParser(prog='whoami', description='Display information about the currently logged in user.')
whoami_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
whoami_parser.error = raise_parse_exception
whoami_parser.exit = suppress_exit


this_device_available_command_verbs = ['rename', 'register', 'persistent-login', 'ip-auto-approve', 'no-yubikey-pin', 'timeout']
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
help_help = 'Commander\'s command (Optional -- if not specified, list of available commands is displayed)'
help_parser.add_argument('command', action='store', type=str, nargs='*',  help=help_help)
help_parser.error = raise_parse_exception
help_parser.exit = suppress_exit


version_parser = argparse.ArgumentParser(prog='version', description='Displays version of the installed Commander.')
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

passphrase_group = generate_parser.add_argument_group('Keeper Passphrase')
passphrase_group.add_argument('--recoveryphrase', dest='recoveryphrase', action='store_true',
                              help='Generate Generate a 24-word recovery phrase')

dice_group = generate_parser.add_argument_group('Diceware')
dice_group.add_argument('--dice-rolls', '-dr', type=int, dest='dice_rolls', action='store',
                        help='Number of dice rolls')
dice_group.add_argument('--delimiter', '-dl', dest='delimiter', choices=('-', '+', ':', '.', '/', '_', '='),
                        default=' ', action='store', help='Optional. Word delimiter (space if omitted)')
dice_group.add_argument('--word-list',  dest='word_list', action='store',
                        help='Optional. File path to word list')

crypto_group = generate_parser.add_argument_group('Crypto')
crypto_group.add_argument('--crypto', dest='crypto', action='store_true', help='Generate crypto wallet passphrase')

reset_password_parser = argparse.ArgumentParser(prog='reset-password', description='Reset Master Password')
reset_password_parser.add_argument('--delete-sso', dest='delete_alternate', action='store_true',
                                   help='deletes SSO master password')
reset_password_parser.add_argument('--current', '-c', dest='current_password', action='store', help='current password')
reset_password_parser.add_argument('--new', '-n', dest='new_password', action='store', help='new password')

sync_security_data_parser = argparse.ArgumentParser(prog='sync-security-data', description='Sync security data.')
record_name_help = 'Path or UID of record whose security data is to be updated. Multiple values allowed. ' \
                   'Set to "@all" to update security data for all records.'
sync_security_data_parser.add_argument('record', type=str, action='store', nargs="+", help=record_name_help)
sync_security_data_parser.add_argument('--force', '-f', action='store_true', help='force update of security data (ignore existing security data timestamp)')
sync_security_data_parser.add_argument('--quiet', '-q', action='store_true', help='run command w/ minimal output')
sync_security_data_parser.error = raise_parse_exception
sync_security_data_parser.exit = suppress_exit


class SyncDownCommand(Command):
    def get_parser(self):
        return sync_down_parser

    def execute(self, params, **kwargs):
        force = kwargs.get('force') is True
        if force:
            params.revision = 0
            params.sync_down_token = b''
            if params.config:
                if 'skip_records' in params.config:
                    del params.config['skip_records']

        api.sync_down(params, record_types=force)
        if force:
            from keepercommander.loginv3 import LoginV3Flow
            LoginV3Flow.populateAccountSummary(params)

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
            print("Successfully " + msg + " Persistent Login on this account")

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

        elif action == 'no-yubikey-pin':
            value = ops[1]
            value_extracted = ThisDeviceCommand.get_setting_str_to_value('no-yubikey-pin', value)
            msg = (bcolors.OKGREEN + "ENABLED" + bcolors.ENDC) if value_extracted == '0' else (bcolors.FAIL + "DISABLED" + bcolors.ENDC)
            loginv3.LoginV3API.set_user_setting(params, 'security_keys_no_user_verify', value_extracted)
            print("Successfully " + msg + " Security Key PIN verification")

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

        if name == 'persistent_login' or name == 'ip_disable_auto_approve' or name == 'no-yubikey-pin':
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

        no_user_verify = acct_summary_dict['settings'].get('securityKeysNoUserVerify', False)
        print("{:>32}: {}".format(
            'Security Key No PIN', (bcolors.OKGREEN + 'ON' + bcolors.ENDC)
            if no_user_verify else (bcolors.FAIL + 'OFF' + bcolors.ENDC)))

        if 'securityKeysNoUserVerify' in acct_summary_dict['settings']:
            device_timeout = get_delta_from_timeout_setting(acct_summary_dict['settings']['logoutTimer'])
            print("{:>32}: {}".format('Device Logout Timeout', format_timeout(device_timeout)))

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

            if params.enterprise:
                print('')
                print('{0:>20s}:'.format('Enterprise License'))
                for x in params.enterprise.get('licenses', []):
                    product_type_id = x.get('product_type_id', 0)
                    tier = x.get('tier', 0)
                    if product_type_id in (3, 5):
                        plan = 'Enterprise' if tier == 1 else 'Business'
                    elif product_type_id in (9, 10):
                        distributor = x.get('distributor', False)
                        plan = 'Distributor' if distributor else 'Managed MSP'
                    elif product_type_id in (11, 12):
                        plan = 'Keeper MSP'
                    elif product_type_id == 8:
                        plan = 'MC ' + 'Enterprise' if tier == 1 else 'Business'
                    else:
                        plan = 'Unknown'
                    if product_type_id in (5, 10, 12):
                        plan += ' Trial'
                    print('{0:>20s}: {1}'.format('Base Plan', plan))
                    paid = x.get('paid') is True
                    if paid:
                        exp = x.get('expiration')
                        if exp > 0:
                            dt = datetime.datetime.fromtimestamp(exp // 1000) + datetime.timedelta(days=1)
                            n = datetime.datetime.now()
                            td = (dt - n).days
                            expires = str(dt.date())
                            if td > 0:
                                expires += f' (in {td} days)'
                            else:
                                expires += ' (expired)'
                            print('{0:>20s}: {1}'.format('Expires', expires))
                    print('{0:>20s}: {1}'.format('User Licenses', f'Plan: {x.get("number_of_seats", "")}    Active: {x.get("seats_allocated", "")}    Invited: {x.get("seats_pending", "")}'))
                    file_plan = x.get('file_plan')
                    file_plan_lookup = {x[0]: x[2] for x in constants.ENTERPRISE_FILE_PLANS}
                    print('{0:>20s}: {1}'.format('Secure File Storage', file_plan_lookup.get(file_plan, '')))
                    addons = []
                    addon_lookup = {a[0]: a[1] for a in constants.MSP_ADDONS}
                    for ao in x.get('add_ons'):
                        if isinstance(ao, dict):
                            enabled = ao.get('enabled') is True
                            if enabled:
                                name = ao.get('name')
                                addon_name = addon_lookup.get(name) or name
                                if name == 'secrets_manager':
                                    api_count = ao.get('api_call_count')
                                    if isinstance(api_count, int) and api_count > 0:
                                        addon_name += f' ({api_count:,} API calls)'
                                elif name == 'connection_manager':
                                    seats = ao.get('seats')
                                    if isinstance(seats, int) and seats > 0:
                                        addon_name += f' ({seats} licenses)'
                                addons.append(addon_name)
                    for i, addon in enumerate(addons):
                        print('{0:>20s}: {1}'.format('Secure Add Ons' if i == 0 else '', addon))
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
        if msp.current_mc_id:
            msp.current_mc_id = None
            msp.mc_params_dict.clear()

        new_login = kwargs.get('new_login', True)
        if new_login:
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
        if not password and isinstance(params.config, dict):
            if 'user' in params.config and 'password' in params.config:
                if params.config['user'] == params.user:
                    password = params.config['password']

        params.password = password

        try:
            api.login(params, new_login=new_login)
        except Exception as exc:
            logging.warning(str(exc))

        if params.session_token:
            SyncDownCommand().execute(params, force=True)
            if params.is_enterprise_admin:
                api.query_enterprise(params, True)
            try:
                if params.breach_watch:
                    BreachWatchScanCommand().execute(params, suppress_no_op=True)
                if params.enterprise_ec_key:
                    SyncSecurityDataCommand().execute(params, record='@all', suppress_no_op=True)
            except Exception as e:
                logging.warning(f'A problem was encountered while updating BreachWatch/security data: {e}')
                logging.debug(e, exc_info=True)


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


class LogoutCommand(Command):
    def get_parser(self):
        return logout_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        if msp.current_mc_id:
            msp.current_mc_id = None
            msp.mc_params_dict.clear()

        if params.session_token:
            try:
                api.communicate_rest(params, None, 'vault/logout_v3')
            except:
                pass

        if isinstance(params.tunnel_threads, dict) and len(params.tunnel_threads) > 0:
            try:
                from .discoveryrotation import clean_up_tunnel
                for convo_id in list(params.tunnel_threads.keys()):
                    clean_up_tunnel(params, convo_id)
            except Exception as e:
                logging.debug('Port forwarding cleanup error: %s', e)

        if params.sso_login_info and 'idp_session_id' in params.sso_login_info:
            sso_url = params.sso_login_info.get('sso_url') or ''
            sp_url_builder = urllib.parse.urlparse(sso_url)
            sp_url_query = urllib.parse.parse_qsl(sp_url_builder.query)
            session_id = params.sso_login_info.get('idp_session_id') or ''
            if params.sso_login_info.get('is_cloud'):
                sso_rq = ssocloud_pb2.SsoCloudRequest()
                sso_rq.clientVersion = rest_api.CLIENT_VERSION
                sso_rq.embedded = True
                sso_rq.username = params.user.lower()
                sso_rq.idpSessionId = session_id
                transmission_key = utils.generate_aes_key()
                rq_payload = APIRequest_pb2.ApiRequestPayload()
                rq_payload.apiVersion = 3
                rq_payload.payload = sso_rq.SerializeToString()
                api_rq = APIRequest_pb2.ApiRequest()
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
        help_commands = kwargs.get('command')
        if not help_commands:
            from keepercommander.cli import display_command_help
            display_command_help(params.enterprise_ec_key)
            return

        if isinstance(help_commands, list) and len(help_commands) > 0:
            cmd = help_commands[0]
            help_commands = help_commands[1:]
            if cmd in aliases:
                ali = aliases[cmd]
                if type(ali) == tuple:
                    cmd = ali[0]
                else:
                    cmd = ali

            if cmd in commands:
                command = commands[cmd]
            elif cmd in enterprise_commands:
                command = enterprise_commands[cmd]
            elif cmd in msp_commands:
                command = msp_commands[cmd]
            else:
                command = None

            if isinstance(command, Command):
                parser = command.get_parser()
                if parser:
                    parser.print_help()
            elif isinstance(command, GroupCommand):
                if len(help_commands) == 0:
                    command.print_help(command=cmd)
                else:
                    while len(help_commands) > 0:
                        cmd = help_commands[0]
                        help_commands = help_commands[1:]
                        if cmd in command.subcommands:
                            subcommand = command.subcommands[cmd]
                            if isinstance(subcommand, Command):
                                parser = subcommand.get_parser()
                                if parser:
                                    parser.print_help()
                                break
                            elif isinstance(subcommand, GroupCommand):
                                command = subcommand
                        else:
                            command.print_help(command=cmd)
                            break

    def is_authorised(self):
        return False


class DeleteCorruptedCommand(Command):
    def execute(self, params, **kwargs):
        bad_records = set()
        for record_uid in params.record_cache:
            record = params.record_cache[record_uid]
            if not record.get('data_unencrypted'):
                if record_uid in params.record_owner_cache:
                    own = params.record_owner_cache[record_uid]
                    if own.owner is True:
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

        if kwargs.get('crypto') is True:
            kpg = CryptoPassphraseGenerator()
        if kwargs.get('recoveryphrase') is True:
            kpg = DicewarePasswordGenerator(24, word_list_file='bip-39.english.txt', delimiter=' ')
        elif isinstance(kwargs.get('dice_rolls'), int):
            dice_rolls = kwargs.get('dice_rolls')
            delimiter = kwargs.get('delimiter') or ' '
            kpg = DicewarePasswordGenerator(dice_rolls, word_list_file=kwargs.get('word_list'), delimiter=delimiter)
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

        passwords = []    # type: List[Dict]
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
        current_master = None      # type: Optional[APIRequest_pb2.Salt]
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
                'include': ['user_auth', 'explicit']
            }
            sync_rs = api.communicate(params, sync_rq)
            if 'user_auth' in sync_rs:
                current_alternates = [x for x in sync_rs['user_auth'] if x['login_type'] == 'ALTERNATE']
        else:
            current_master = api.communicate_rest(params, None, 'authentication/get_salt_and_iterations',
                                                  rs_type=APIRequest_pb2.Salt)

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
            rq = APIRequest_pb2.MasterPasswordReentryRequest()
            rq.pbkdf2Password = utils.base64_url_encode(auth_hash)
            rq.action = APIRequest_pb2.UNMASK
            try:
                rs = api.communicate_rest(params, rq, 'authentication/validate_master_password',
                                          rs_type=APIRequest_pb2.MasterPasswordReentryResponse, payload_version=1)
                if rs.status != APIRequest_pb2.MP_SUCCESS:
                    logging.info('Failed to change password')
            except:
                logging.warning('Current password incorrect')
                return
        else:
            current_password = ''

        if is_delete_alternate:
            if len(current_alternates) > 0:
                uid_rq = APIRequest_pb2.UidRequest()
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

        rules_rq = enterprise_pb2.DomainPasswordRulesRequest()
        rules_rq.username = params.user
        rules_rs = api.communicate_rest(params, rules_rq, 'authentication/get_domain_password_rules',
                                        rs_type=APIRequest_pb2.NewUserMinimumParams)
        failed_rules = []
        for i in range(len(rules_rs.passwordMatchRegex)):
            rule = rules_rs.passwordMatchRegex[i]
            is_match = re.match(rule, new_password)
            if not is_match:
                failed_rules.append(rules_rs.passwordMatchDescription[i])
        if failed_rules:
            logging.warning('Password rules:\n%s', '\n'.join((f'  {x}' for x in failed_rules)))
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
            max((x['iterations'] for x in current_alternates)) \
            if len(current_alternates) > 0 else constants.PBKDF2_ITERATIONS
        iterations = max(iterations, constants.PBKDF2_ITERATIONS)

        auth_salt = crypto.get_random_bytes(16)
        if is_sso_user:
            ap_rq = APIRequest_pb2.UserAuthRequest()
            ap_rq.uid = utils.base64_url_decode(current_alternates[0]['uid']) if len(current_alternates) > 0 else crypto.get_random_bytes(16)
            ap_rq.salt = auth_salt
            ap_rq.iterations = iterations
            ap_rq.authHash = crypto.derive_keyhash_v1(new_password, auth_salt, iterations)
            key = crypto.derive_keyhash_v2('data_key', new_password, auth_salt, iterations)
            ap_rq.encryptedDataKey = crypto.encrypt_aes_v2(params.data_key, key)
            ap_rq.encryptedClientKey = crypto.encrypt_aes_v2(params.client_key, key)
            ap_rq.loginType = APIRequest_pb2.ALTERNATE
            ap_rq.name = current_alternates[0]['name'] if len(current_alternates) > 0 else 'alternate'
            api.communicate_rest(params, ap_rq, 'authentication/set_v2_alternate_password')
            logging.info(f'SSO Master Password has been {("changed" if len(current_alternates) > 0 else "set")}')
        else:
            auth_verifier = utils.create_auth_verifier(new_password, auth_salt, iterations)
            data_salt = crypto.get_random_bytes(16)
            encryption_params = utils.create_encryption_params(new_password, data_salt, iterations, params.data_key)
            mp_rq = {
                'command': 'change_master_password',
                'auth_verifier': utils.base64_url_encode(auth_verifier),
                'encryption_params': utils.base64_url_encode(encryption_params)
            }
            api.communicate(params, mp_rq)
            logging.info('Master Password has been changed')


class SyncSecurityDataCommand(Command):
    def get_parser(self):
        return sync_security_data_parser

    def execute(self, params, **kwargs):
        def get_security_data(record, pw_obj):     # type: (KeeperRecord, Dict or None) -> APIRequest_pb2.SecurityData
            sd = APIRequest_pb2.SecurityData()
            password = BreachWatch.extract_password(record)
            # Send empty security data for this record if password was removed -- this removes the old security data
            sd_data = None
            if password:
                strength = utils.password_score(password)
                sd_data = {'strength': strength}
                login_url = BreachWatch.extract_url(record)
                parse_results = urllib.parse.urlparse(login_url)
                domain = parse_results.hostname or parse_results.path
                update_bw_result = bw_enabled and bool(pw_obj)
                if update_bw_result:
                    status = pw_obj.get('status')
                    sd_data['bw_result'] = client_pb2.BWStatus.Value(status) if status else client_pb2.BWStatus.GOOD
                if domain:
                    # truncate domain string if needed to avoid reaching RSA encryption data size limitation
                    sd_data['domain'] = domain[:200]
            if sd_data:
                try:
                    sd.data = crypto.encrypt_rsa(json.dumps(sd_data).encode('utf-8'), params.enterprise_rsa_key)
                except Exception as e:
                    logging.error(f'Error: {e}')
                    logging.error(f'Enterprise RSA key length = {params.enterprise_rsa_key.key_size}')
                    return
            sd.uid = utils.base64_url_decode(record.record_uid)
            return sd

        def update_security_data(record_sds):   # type: (List[APIRequest_pb2.SecurityData]) -> None
            if record_sds:
                update_rq = APIRequest_pb2.SecurityDataRequest()
                for rsd in record_sds:
                    update_rq.recordSecurityData.append(rsd)
                api.communicate_rest(params, update_rq, 'enterprise/update_security_data')

        def get_record_uids():
            uids = set()
            names = kwargs.get('record')
            if isinstance(names, str):
                names = [names]
            if names:
                if '@all' in names:
                    return set(params.record_cache.keys())
                for name in names:
                    record_uids = get_ruids(params, name)
                    if not record_uids:
                        logging.warning(f'Record {name} could not be found (skipping security data update).')
                    else:
                        uids.update(get_ruids(params, name))
            return uids

        if not params.enterprise_ec_key:
            msg = 'Command not allowed -- This command is limited to enterprise users only.'
            raise CommandError('sync-security-data', msg)

        force_update = kwargs.get('force', False)
        update_limit = 1000
        api.sync_down(params)
        sd_objs = params.breach_watch_security_data or {}
        sd_rec_uids = set(sd_objs.keys())
        pw_recs = list(BreachWatch.get_records(params, lambda r, s: r.record_uid in get_record_uids(), owned=True))
        pw_rec_uids = {r.record_uid for r, _ in pw_recs}
        owned_rec_uids = {r for r, ro in params.record_owner_cache.items() if ro.owner}
        no_pw_rec_uids = owned_rec_uids - pw_rec_uids
        ex_pw_rec_uids = no_pw_rec_uids & sd_rec_uids
        ex_pw_recs = [(vault.KeeperRecord.load(params, r), None) for r in ex_pw_rec_uids]
        to_update = [*pw_recs, *ex_pw_recs]

        bw_enabled = bool(params.breach_watch)

        def has_stale_security_data(record):
            record_security_data = sd_objs.get(record.record_uid, {})
            sd_revision = record_security_data.get('revision', 0)
            if bw_enabled:
                bw_recs = params.breach_watch_records or {}
                bw_revision = bw_recs.get(record.record_uid, {}).get('revision', 0)
                return sd_revision < bw_revision
            else:
                return sd_revision < record.revision

        # Limit security-data updates to records modified AFTER its most recent security-data update
        if not force_update:
            to_update = [(r, p) for r, p in to_update if has_stale_security_data(r)]

        sds = [get_security_data(r, s) for r, s in to_update] if to_update else []
        # Remove empty security-data update requests (resulting from failed RSA encryption)
        sds = [sd for sd in sds if sd]
        while sds:
            update_security_data(sds[:update_limit])
            sds = sds[update_limit:]
        if to_update:
            BreachWatch.save_reused_pw_count(params)
            api.sync_down(params)
        if not kwargs.get('quiet'):
            if to_update:
                logging.info(f'Updated security data for [{len(to_update)}] record(s)')
            elif not kwargs.get('suppress_no_op'):
                logging.info('No records requiring security-data updates found')
