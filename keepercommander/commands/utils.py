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

import argparse

from getpass import getpass
from urllib.parse import urlsplit

from .. import api, display, imp_exp
from .base import raise_parse_exception, suppress_exit, user_choice, Command


def register_commands(commands):
    commands['sync-down'] = SyncDownCommand()
    commands['rotate'] = RecordRotateCommand()
    commands['import'] = RecordImportCommand()
    commands['import'] = RecordImportCommand()
    commands['import_sf'] = SharedFolderImportCommand()
    commands['export'] = RecordExportCommand()
    commands['delete_all'] = RecordDeleteAllCommand()
    commands['whoami'] = WhoamiCommand()
    commands['login'] = LoginCommand()
    commands['logout'] = LogoutCommand()
    commands['test'] = TestCommand()


def register_command_info(aliases, command_info):
    aliases['r'] = 'rotate'
    aliases['d'] = 'sync-down'

    for p in [rotate_parser, import_parser, export_parser, whoami_parser, login_parser, logout_parser]:
        command_info[p.prog] = p.description
    command_info['sync-down|d'] = 'Download & decrypt data'


rotate_parser = argparse.ArgumentParser(prog='rotate|r', description='Rotate Keeper record')
rotate_parser.add_argument('--print', dest='print', action='store_true', help='display the record content after rotation')
rotate_parser.add_argument('--match', dest='match', action='store', help='regular expression to select records for password rotation')
rotate_parser.add_argument('uid', nargs='?', type=str, action='store', help='record UID')
rotate_parser.error = raise_parse_exception
rotate_parser.exit = suppress_exit


import_parser = argparse.ArgumentParser(prog='import', description='Import data from local file to Keeper')
import_parser.add_argument('--display-csv', '-dc', dest='display_csv', action='store_true',  help='display Keeper CSV import instructions')
import_parser.add_argument('--display-json', '-dj', dest='display_json', action='store_true',  help='display Keeper JSON import instructions')
import_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'keepass'], required=True, help='file format')
import_parser.add_argument('-s', '--shared', dest='shared', action='store_true', help='import folders as Keeper shared folders')
import_parser.add_argument('-p', '--permissions', dest='permissions', action='store', help='default shared folder permissions: manage (U)sers, manage (R)ecords, can (E)dit, can (S)hare, or (A)ll, (N)one')
import_parser.add_argument('filename', type=str, help='file name')
import_parser.error = raise_parse_exception
import_parser.exit = suppress_exit


import_sf_parser = argparse.ArgumentParser(prog='import_sf', description='Create shared folders from JSON input file')
import_sf_parser.add_argument('filename', type=str, help='file name')
import_sf_parser.error = raise_parse_exception
import_sf_parser.exit = suppress_exit


export_parser = argparse.ArgumentParser(prog='export', description='Export data from Keeper to local file')
export_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'keepass'], required=True, help='file format')
export_parser.add_argument('filename', type=str, nargs='?', help='file name or console output if omitted (except keepass)')
export_parser.error = raise_parse_exception
export_parser.exit = suppress_exit


test_parser = argparse.ArgumentParser(prog='test', description='Test KeeperCommander environment')
test_parser.add_argument('area', type=str, choices=['aes', 'rsa'], help='test area')
test_parser.error = raise_parse_exception
test_parser.exit = suppress_exit


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


class SyncDownCommand(Command):
    def execute(self, params, **kwargs):
        api.sync_down(params)
        if params.enterprise:
            api.query_enterprise(params)


class RecordRotateCommand(Command):
    def get_parser(self):
        return rotate_parser

    def execute(self, params, **kwargs):
        print_result = kwargs['print'] if 'print' in kwargs else None
        uid = kwargs['uid'] if 'uid' in kwargs else None
        match = kwargs['match'] if 'match' in kwargs else None
        if uid:
            api.rotate_password(params, uid)
            if print_result:
                display.print_record(params, uid)
        elif match:
            results = api.search_records(params, match)
            for r in results:
                api.rotate_password(params, r.record_uid)
                if print_result:
                    display.print_record(params, r.record_uid)


csv_instructions = '''CSV Import Instructions

File Format:
Folder,Title,Login,Password,Website Address,Notes,Custom Fields

• To specify subfolders, use backslash "\\" between folder names
• To make a shared folder specify the name or path to it in the 7th field

Example 1: Create a regular folder at the root level with 2 custom fields
My Business Stuff,Twitter,marketing@company.com,123456,https://twitter.com,These are some notes,,API Key,5555,Date Created, 2018-04-02

Example 2: Create a shared subfolder inside another folder with edit and re-share permission
Personal,Twitter,craig@gmail.com,123456,https://twitter.com,,Social Media#edit#reshare

To load the sample data:
import --format=csv sample_data/import.csv
'''

json_instructions = '''JSON Import Instructions

Example JSON import file can be found in sample_data/import.json.txt.

The JSON file supports creating records, folders and shared folders.

Within shared folders, you can also automatically assign user or team permissions.

To load the sample file into your vault, run this command:
import --format=json sample_data/import.json.txt
'''

class ImporterCommand(Command):
    def execute_args(self, params, args, **kwargs):
        if args.find('--display-csv') >= 0 or args.find('-dc') >= 0:
            print(csv_instructions)
        elif args.find('--display-json') >= 0 or args.find('-dj') >= 0:
            print(json_instructions)
        else:
            Command.execute_args(self, params, args, **kwargs)


class RecordImportCommand(ImporterCommand):
    def get_parser(self):
        return import_parser

    def execute(self, params, **kwargs):
        format = kwargs['format'] if 'format' in kwargs else None
        filename = kwargs['filename'] if 'filename' in kwargs else None
        shared = kwargs.get('shared') or False
        manage_users = False
        manage_records = False
        can_edit = False
        can_share = False
        if format and filename:
            permissions = kwargs.get('permissions')
            if shared and not permissions:
                permissions = user_choice('Default shared folder permissions: manage (U)sers, manage (R)ecords, can (E)dit, can (S)hare, or (A)ll, (N)one', 'uresan', show_choice=False, multi_choice=True)
            if permissions:
                chars = set()
                chars.update([x for x in permissions.lower()])
                if 'a' in chars:
                    manage_users = True
                    manage_records = True
                    can_edit = True
                    can_share = True
                else:
                    if 'u' in chars:
                        manage_users = True
                    if 'r' in chars:
                        manage_records = True
                    if 'e' in chars:
                        can_edit = True
                    if 's' in chars:
                        can_share = True

            api.print_info('Processing... please wait.')
            imp_exp._import(params, format, filename, shared=shared,
                            manage_users=manage_users, manage_records=manage_records,
                            can_edit=can_edit, can_share=can_share)
        else:
            api.print_error('Missing argument')


class SharedFolderImportCommand(Command):
    def get_parser(self):
        return import_sf_parser

    def execute(self, params, **kwargs):
        filename = kwargs['filename'] if 'filename' in kwargs else None
        if format and filename:
            imp_exp.create_sf(params, filename)
        else:
            api.print_error('Missing `filename` argument')


class RecordExportCommand(ImporterCommand):
    def get_parser(self):
        return export_parser

    def execute(self, params, **kwargs):
        format = kwargs['format'] if 'format' in kwargs else None
        filename = kwargs['filename'] if 'filename' in kwargs else None
        if format:
            api.print_info('Processing... please wait.')
            imp_exp.export(params, format, filename)
        else:
            api.print_error('Missing argument')


class RecordDeleteAllCommand(Command):
    def execute(self, params, **kwargs):
        uc = user_choice('Are you sure you want to delete all Keeper records on the server?', 'yn', default='n')
        if uc.lower() == 'y':
            imp_exp.delete_all(params)


class TestCommand(Command):
    def get_parser(self):
        return test_parser

    def execute(self, params, **kwargs):
        area = kwargs['area'] if 'area' in kwargs else None
        if area == 'rsa':
            api.test_rsa(params)
        elif area == 'aes':
            api.test_aes(params)


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
                password = getpass(prompt='... {0:>16}: '.format('Password'), stream=None).strip()
            if not password:
                return
        except KeyboardInterrupt as e:
            print('Canceled')
            return

        params.user = user
        params.password = password

        print('Logging in...')
        api.login(params)


class LogoutCommand(Command):
    def get_parser(self):
        return logout_parser

    def is_authorised(self):
        return False

    def execute(self, params, **kwargs):
        params.clear_session()

