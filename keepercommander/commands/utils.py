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
import logging

from getpass import getpass
from urllib.parse import urlsplit

from .. import api
from .base import raise_parse_exception, suppress_exit, user_choice, Command


def register_commands(commands):
    commands['sync-down'] = SyncDownCommand()
    commands['delete_all'] = RecordDeleteAllCommand()
    commands['whoami'] = WhoamiCommand()
    commands['login'] = LoginCommand()
    commands['logout'] = LogoutCommand()


def register_command_info(aliases, command_info):
    aliases['r'] = 'rotate'
    aliases['d'] = 'sync-down'
    for p in [rotate_parser, whoami_parser, login_parser, logout_parser]:
        command_info[p.prog] = p.description
    command_info['sync-down|d'] = 'Download & decrypt data'


rotate_parser = argparse.ArgumentParser(prog='rotate|r', description='Rotate Keeper record')
rotate_parser.add_argument('--print', dest='print', action='store_true', help='display the record content after rotation')
rotate_parser.add_argument('--match', dest='match', action='store', help='regular expression to select records for password rotation')
rotate_parser.add_argument('uid', nargs='?', type=str, action='store', help='record UID')
rotate_parser.error = raise_parse_exception
rotate_parser.exit = suppress_exit

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


