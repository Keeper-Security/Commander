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
import base64
import datetime

import getpass
from urllib.parse import urlsplit

from Cryptodome.PublicKey import RSA

from .. import api
from .base import raise_parse_exception, suppress_exit, user_choice, Command


def register_commands(commands):
    commands['sync-down'] = SyncDownCommand()
    commands['delete_all'] = RecordDeleteAllCommand()
    commands['whoami'] = WhoamiCommand()
    commands['login'] = LoginCommand()
    commands['logout'] = LogoutCommand()
    commands['check-enforcements'] = CheckEnforcementsCommand()


def register_command_info(aliases, command_info):
    aliases['d'] = 'sync-down'
    for p in [whoami_parser, login_parser, logout_parser]:
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
