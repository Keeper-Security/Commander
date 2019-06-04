#_  __
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
from typing import Optional

import requests
import tempfile
import json

from urllib.parse import urlsplit
from tabulate import tabulate
from Cryptodome.Cipher import AES

from ..params import KeeperParams, LAST_RECORD_UID, LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID
from ..record import Record
from .. import api
from .base import raise_parse_exception, suppress_exit, user_choice, Command
from ..subfolder import try_resolve_path


def register_commands(commands):
    commands['sync-down'] = SyncDownCommand()
    commands['delete-all'] = RecordDeleteAllCommand()
    commands['whoami'] = WhoamiCommand()
    commands['login'] = LoginCommand()
    commands['logout'] = LogoutCommand()
    commands['check-enforcements'] = CheckEnforcementsCommand()
    commands['connect'] = ConnectCommand()
    commands['echo'] = EchoCommand()
    commands['set'] = SetCommand()


def register_command_info(aliases, command_info):
    aliases['d'] = 'sync-down'
    aliases['delete_all'] = 'delete-all'
    for p in [whoami_parser, login_parser, logout_parser, echo_parser, set_parser]:
        command_info[p.prog] = p.description
    command_info['sync-down|d'] = 'Download & decrypt data'


whoami_parser = argparse.ArgumentParser(prog='whoami', description='Information about logged in user')
whoami_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
whoami_parser.error = raise_parse_exception
whoami_parser.exit = suppress_exit


login_parser = argparse.ArgumentParser(prog='login', description='Login to Keeper')
login_parser.add_argument('-p', '--password', dest='password', action='store', help='master password')
login_parser.add_argument('email', nargs='?', type=str, help='account email')
login_parser.error = raise_parse_exception
login_parser.exit = suppress_exit


logout_parser = argparse.ArgumentParser(prog='logout', description='Logout from Keeper')
logout_parser.error = raise_parse_exception
logout_parser.exit = suppress_exit


check_enforcements_parser = argparse.ArgumentParser(prog='check-enforcements', description='Check enterprise enforcements')
check_enforcements_parser.error = raise_parse_exception
check_enforcements_parser.exit = suppress_exit


connect_parser = argparse.ArgumentParser(prog='connect', description='Establishes connection to external server')
connect_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help on command format and template parameters')
connect_parser.add_argument('-n', '--new', dest='new_data', action='store_true', help='request per-user data')
connect_parser.add_argument('-r', '--record', dest='record',  type=str, help='record UID or name')
connect_parser.add_argument('endpoint', nargs='?', action='store', type=str, help='endpoint')
connect_parser.error = raise_parse_exception
connect_parser.exit = suppress_exit


echo_parser = argparse.ArgumentParser(prog='echo', description='Displays argument to output')
echo_parser.add_argument('argument', nargs='?', action='store', type=str, help='argument')
echo_parser.error = raise_parse_exception
echo_parser.exit = suppress_exit


set_parser = argparse.ArgumentParser(prog='set', description='Set environment variable')
set_parser.add_argument('name', action='store', type=str, help='name')
set_parser.add_argument('value', action='store', type=str, help='value')
set_parser.error = raise_parse_exception
set_parser.exit = suppress_exit


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
                except:
                    pass

            params.pending_share_requests.clear()

            if accepted:
                params.sync_data = True


class RecordDeleteAllCommand(Command):
    def execute(self, params, **kwargs):
        uc = user_choice('Are you sure you want to delete all Keeper records on the server?', 'yn', default='n')
        if uc.lower() == 'y':
            api.sync_down(params)
            if len(params.record_cache) == 0:
                logging.warning('No records to delete')
                return

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
                data_center = 'EU' if host.endswith('.eu') else 'US'
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
                print('{0:>20s} {1:>20s}: {2}'.format('Account', 'Type', params.license['product_type_name']))
                print('{0:>20s} {1:>20s}: {2}'.format('', 'Renewal Date', params.license['expiration_date']))
                if 'bytes_total' in params.license:
                    storage_bytes = params.license['bytes_total']
                    storage_gb = storage_bytes >> 30
                    print('{0:>20s} {1:>20s}: {2}GB'.format('Storage', 'Capacity', storage_gb))
                    storage_usage = params.license['bytes_used'] * 100 // storage_bytes
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

            if not password:
                password = getpass.getpass(prompt='... {0:>16}: '.format('Password'), stream=None).strip()
            if not password:
                return
        except KeyboardInterrupt as e:
            logging.info('Canceled')
            return

        params.user = user
        params.password = password

        logging.info('Logging in...')
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

  endpoint:<name>                command 
  endpoint:<name>:description    command description

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
'''

endpoint_pattern =  re.compile(r'^connect:([^:]+)$')
endpoint_desc_pattern =  re.compile(r'^connect:([^:]+):description$')
endpoint_parameter_pattern = re.compile(r'\${(.+?)}')


class ConnectCommand(Command):
    def get_parser(self):
        return connect_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(connect_command_description)
            return

        record = kwargs['record'] if 'record' in kwargs else None
        records = []
        folder = None
        if record:
            rs = try_resolve_path(params, kwargs['pattern'])
            if rs is not None:
                folder, record = rs

        if not folder:
            folder = params.folder_cache[params.current_folder] if params.current_folder else params.root_folder
        folder_uid = folder.uid or ''
        if folder_uid in params.subfolder_record_cache:
            for uid in params.subfolder_record_cache[folder_uid]:
                r = api.get_record(params, uid)
                if record:
                    if record == r.record_uid or record.lower() == r.title.lower():
                        records.append(r)
                else:
                    records.append(r)

        endpoint = kwargs.get('endpoint')
        if not endpoint:
            endpoints = []
            endpoints_desc = {}
            for record in records:
                if record.custom_fields:
                    for field in record.custom_fields:
                        if 'name' in field:
                            m = endpoint_pattern.match(field['name'])
                            if m:
                                endpoints.append(m[1])
                            else:
                                m = endpoint_desc_pattern.match(field['name'])
                                if m:
                                    endpoints_desc[m[1]] = field.get('value') or ''
            if endpoints:
                print("Available connect endpoints")
                endpoints.sort()
                table = [[i + 1, e, endpoints_desc.get(e) or ''] for i, e in enumerate(endpoints)]
                headers = ["#", 'Endpoint', 'Description']
                print(tabulate(table, headers=headers))
                print('')
            else:
                logging.info("No connect endpoints found")
            return

        for record in records:
            if record.custom_fields:
                for field in record.custom_fields:
                    if 'name' in field:
                        m = endpoint_pattern.match(field['name'])
                        if m:
                            if m[1] == endpoint:
                                ConnectCommand.connect_endpoint(params, endpoint, record, kwargs.get('new_data') or False)
                                return

        logging.info("Connect endpoint '{0}' not found".format(endpoint))

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
    def ask_personal_parameter(params, ask, record):
        # type: (KeeperParams, str, Record) -> str
        old_value = ''
        if record.record_uid in params.non_shared_data_cache:
            nsd = params.non_shared_data_cache[record.record_uid]
            if 'commander' in nsd:
                old_value = nsd['commander'].get(ask) or ''

        question = record.get('ask:{0}:description') or 'Parameter \"{0}\" requires input.'.format(ask)
        print(question)
        if old_value:
            value = input('Press <Enter> to accept last value \"{0}\"> '.format(old_value))
            if not value:
                value = old_value
        else:
            value = input('> ')

        if not value and value != old_value:
            nsd = params.non_shared_data_cache.get(record.record_uid) or {}
            if 'commander' not in nsd:
                nsd['commander'] = {}
            nsd['commander'][ask] = value


        return value

    @staticmethod
    def get_command_string(params, record, template, temp_files, new_data):
        # type: (KeeperParams, Record, str, list, bool) -> Optional[str]
        command = template
        store_non_shared = False
        non_shared = None
        while True:
            m = endpoint_parameter_pattern.search(command)
            if not m:
                break
            p = m.group(1)
            pv = ''
            if p.startswith('file:') or p.startswith('body:'):
                file_name = p[5:]
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
                if p.startswith('file:'):
                    tf = tempfile.NamedTemporaryFile(delete=False)
                    tf.write(body)
                    tf.flush()
                    temp_files.append(tf.name)
                    tf.close()
                    pv = tf.name
                else:
                    pv = body.decode('utf-8')
            elif p.startswith('text:') or p.startswith('mask:'):
                var_name = p[5:]
                non_shared_data = params.non_shared_data_cache.get(record.record_uid)
                if non_shared_data is not None:
                    if 'data_unencrypted' in non_shared_data:
                        non_shared = json.loads(non_shared_data['data_unencrypted'])
                if non_shared_data is None:
                    non_shared = {}
                cmndr = non_shared.get('commander')
                if cmndr is None:
                    cmndr = {}
                    non_shared['commander'] = cmndr
                pv = cmndr.get(var_name)
                if new_data or pv is None:
                    prompt = 'Type value for \'{0}\' > '.format(var_name)
                    if p.startswith('text:'):
                        pv = input(prompt)
                    else:
                        pv = getpass.getpass(prompt)
                    cmndr[var_name] = pv
                    store_non_shared = True
            elif p == 'user_email':
                pv = params.user
            elif p == 'login':
                pv = record.login
            elif p == 'password':
                pv = record.password
            else:
                value = record.get(p)
                if value:
                    pv = value
                else:
                    logging.error('Parameter \"%s\" cannot be resolved', m[0])
                    return
            command = command[:m.start()] + pv + command[m.end():]

        if store_non_shared:
            api.store_non_shared_data(params, record.record_uid, non_shared)

        logging.debug(command)
        return command

    @staticmethod
    def connect_endpoint(params, endpoint, record, new_data):
        # type: (KeeperParams, str, Record, bool) -> None
        temp_files = []
        try:
            command = record.get('connect:' + endpoint + ':pre')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, new_data)
                if command:
                    os.system(command)

            command = record.get('connect:' + endpoint)
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, new_data)
                if command:
                    logging.info('Connecting to %s...', endpoint)
                    os.system(command)

            command = record.get('connect:' + endpoint + ':post')
            if command:
                command = ConnectCommand.get_command_string(params, record, command, temp_files, new_data)
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
