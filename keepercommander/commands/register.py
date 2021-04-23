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

import argparse
import getpass
import re
import os
import base64
import json
import logging
import requests
import time

from urllib.parse import urlsplit, urlunsplit
from email.utils import parseaddr

from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from Cryptodome.Math.Numbers import Integer

from .. import api, generator, loginv3
from .base import dump_report_data, user_choice
from .record import RecordAddCommand
from ..params import KeeperParams
from ..subfolder import BaseFolderNode, SharedFolderFolderNode, try_resolve_path, find_folders
from .enterprise import EnterpriseCommand, EnterprisePushCommand
from ..display import bcolors
from ..error import KeeperApiError, CommandError
from .base import raise_parse_exception, suppress_exit, Command


EMAIL_PATTERN = r"(?i)^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$"


def register_commands(commands):
    commands['share-record'] = ShareRecordCommand()
    commands['share-folder'] = ShareFolderCommand()
    commands['share-report'] = ShareReportCommand()
    commands['record-permission'] = RecordPermissionCommand()
    commands['create-user'] = RegisterCommand()
    commands['file-report'] = FileReportCommand()


def register_command_info(aliases, command_info):
    aliases['sr'] = 'share-record'
    aliases['sf'] = 'share-folder'
    aliases['cu'] = 'create-user'

    for p in [share_record_parser, share_folder_parser, share_report_parser, record_permission_parser,
              file_report_parser, register_parser]:
        command_info[p.prog] = p.description


share_record_parser = argparse.ArgumentParser(prog='share-record|sr', description='Change the sharing permissions of an individual record')
share_record_parser.add_argument('-e', '--email', dest='email', action='append', required=True, help='account email')
share_record_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke', 'owner', 'cancel'],
                                 default='grant', action='store', help='user share action. \'grant\' if omitted')
share_record_parser.add_argument('-s', '--share', dest='can_share', action='store_true', help='can re-share record')
share_record_parser.add_argument('-w', '--write', dest='can_edit', action='store_true', help='can modify record')
share_record_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
share_record_parser.error = raise_parse_exception
share_record_parser.exit = suppress_exit

share_folder_parser = argparse.ArgumentParser(prog='share-folder|sf', description='Change a shared folders permissions.')
share_folder_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke'], default='grant',
                                 action='store', help='shared folder action. \'grant\' if omitted')
share_folder_parser.add_argument('-e', '--email', dest='user', action='append',
                                 help='account email, team, or \'*\' as default folder permission')
share_folder_parser.add_argument('-r', '--record', dest='record', action='append',
                                 help='record name, record UID, or \'*\' as default folder permission')
share_folder_parser.add_argument('-p', '--manage-records', dest='manage_records', action='store_true',
                                 help='account permission: can manage records.')
share_folder_parser.add_argument('-o', '--manage-users', dest='manage_users', action='store_true',
                                 help='account permission: can manage users.')
share_folder_parser.add_argument('-s', '--can-share', dest='can_share', action='store_true',
                                 help='record permission: can be shared')
share_folder_parser.add_argument('-d', '--can-edit', dest='can_edit', action='store_true',
                                 help='record permission: can be modified.')
share_folder_parser.add_argument('-f', '--force', dest='force', action='store_true',
                                 help='Apply permission changes ignoring default folder permissions. Used on the '
                                      'initial sharing action')
share_folder_parser.add_argument('folder', nargs='?', type=str, action='store', help='shared folder path or UID')
share_folder_parser.error = raise_parse_exception
share_folder_parser.exit = suppress_exit

share_report_parser = argparse.ArgumentParser(prog='share-report', description='Display report of shared records.')
share_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv'], default='table',
                                 help='output format.')
share_report_parser.add_argument('--output', dest='output', action='store',
                                 help='output file name. (ignored for table format)')
share_report_parser.add_argument('-r', '--record', dest='record', action='append', help='record name or UID')
share_report_parser.add_argument('-e', '--email', dest='user', action='append', help='user email or team name')
share_report_parser.add_argument('-o', '--owner', dest='owner', action='store_true',
                                 help='record ownership information')
share_report_parser.add_argument('--share-date', dest='share_date', action='store_true',
                                 help='include date when the record was shared. This flag will only apply to the '
                                      'detailed owner report. This data is available only to those users who have '
                                      'permissions to execute reports for their company. Example of the report that '
                                      'includes shared date: `share-report -v -o --share-date --format table`')
share_report_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                                 help='display verbose information')
share_report_parser.error = raise_parse_exception
share_report_parser.exit = suppress_exit

record_permission_parser = argparse.ArgumentParser(prog='record-permission', description='Modify a records permissions.')
record_permission_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                      help='Display the permissions changes without committing them')
record_permission_parser.add_argument('--force', dest='force', action='store_true',
                                      help='Apply permission changes without any confirmation')
record_permission_parser.add_argument('-R', '--recursive', dest='recursive', action='store_true',
                                      help='Apply permission changes to all sub-folders')
record_permission_parser.add_argument('--share-record', dest='share_record', action='store_true',
                                      help='Change a records sharing permissions')
record_permission_parser.add_argument('--share-folder', dest='share_folder', action='store_true',
                                      help='Change a folders sharing permissions')
record_permission_parser.add_argument('-a', '--action', dest='action', action='store', choices=['grant', 'revoke'],
                                      required=True, help='The action being taken')
record_permission_parser.add_argument('-s', '--can-share', dest='can_share', action='store_true',
                                      help='Set record permission: can be shared')
record_permission_parser.add_argument('-d', '--can-edit', dest='can_edit', action='store_true',
                                      help='Set record permission: can be edited')
record_permission_parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or folder UID')
record_permission_parser.error = raise_parse_exception
record_permission_parser.exit = suppress_exit

register_parser = argparse.ArgumentParser(prog='create-user', description='Send an invitation to the user to join Keeper')
# register_parser.add_argument('--store-record', dest='store', action='store_true',
#                              help='store credentials into Keeper record (must be logged in)')
# register_parser.add_argument('--generate', dest='generate', action='store_true', help='generate password')
# register_parser.add_argument('--pass', dest='password', action='store', help='user password')
# register_parser.add_argument('--data-center', dest='data_center', choices=['us', 'eu'], action='store',
#                              help='data center.')
# register_parser.add_argument('--expire', dest='expire', action='store_true',
#                              help='expire master password (enterprise only)')
# register_parser.add_argument('--records', dest='records', action='store',
#                              help='populate vault with default records (enterprise only)')
# register_parser.add_argument('--question', dest='question', action='store', help='security question')
# register_parser.add_argument('--answer', dest='answer', action='store', help='security answer')
register_parser.add_argument('--name', dest='name', action='store', help='user name (enterprise only)')
register_parser.add_argument('--node', dest='node', action='store', help='node name or node ID (enterprise only)')
register_parser.add_argument('email', action='store', help='email')
register_parser.error = raise_parse_exception
register_parser.exit = suppress_exit


file_report_parser = argparse.ArgumentParser(prog='file-report', description='List records with file attachments.')
file_report_parser.add_argument('-d', '--try-download', dest='try_download', action='store_true',
                                help='Try downloading every attachment you have access to.')
file_report_parser.error = raise_parse_exception
file_report_parser.exit = suppress_exit


class RegisterCommand(Command):
    def is_authorised(self):
        return False

    def get_parser(self):
        return register_parser

    @staticmethod
    def get_iterations():
        return 100000

    def execute(self, params, **kwargs):

        if params.login_v3:
            logging.debug("Registering user using Login V3 flow to add users")
            loginv3.LoginV3API.register_for_login_v3(params, kwargs)
            return

        email = kwargs['email'] if 'email' in kwargs else None

        if email:
            _, email = parseaddr(email)
        if not email:
            raise CommandError('register', 'A valid email address is expected.')

        rq = {
            'command': 'pre_register',
            'email': email
        }

        rs = api.run_command(params, rq)
        if rs['result_code'] != 'Failed_to_find_user':
            if rs['result'] == 'success':
                logging.warning('User \'%s\' already exists in Keeper', email)
            else:
                logging.error(rs['message'])
            # return
        else:
            password_rules = rs['password_rules']

        # check enterprise
        verification_code = None
        if params.enterprise:
            node_id = None
            if kwargs.get('node'):
                for node in params.enterprise['nodes']:
                    if kwargs['node'] in {str(node['node_id']), node['data'].get('displayname')}:
                        node_id = node['node_id']
                        break
                    elif not node.get('parent_id') and kwargs['node'] == params.enterprise['enterprise_name']:
                        node_id = node['node_id']
                        break
            if node_id is None:
                for node in params.enterprise['nodes']:
                    if not node.get('parent_id'):
                        node_id = node['node_id']
                        break
            data = {}
            name = kwargs.get('name')
            if name:
                data['displayname'] = name
            else:
                raise CommandError('register', '\'name\' parameter is required for enterprise users')

            rq = {
                'command': 'enterprise_user_add',
                'enterprise_user_id': EnterpriseCommand.get_enterprise_id(params),
                'enterprise_user_username': email,
                'encrypted_data': api.encrypt_aes(json.dumps(data).encode('utf-8'),
                                                  params.enterprise['unencrypted_tree_key']),
                'node_id': node_id,
                'suppress_email_invite': True
            }
            try:
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    verification_code = rs.get('verification_code')
                    # re-read password rules
                    rq = {
                        'command': 'pre_register',
                        'email': email
                    }
                    rs = api.run_command(params, rq)
                    if 'password_rules' in rs:
                        password_rules = rs['password_rules']
            except Exception as e:
                logging.warning(e["message"])

        password = kwargs['password'] if 'password' in kwargs else None
        generate = kwargs['generate'] if 'generate' in kwargs else None
        if generate:
            password = generator.generate(16)
        else:
            while not password:
                pwd = getpass.getpass(prompt='Password: ', stream=None)
                failed_rules = []
                if password_rules:
                    for r in password_rules:
                        m = re.match(r['pattern'], pwd)
                        if r['match']:
                            if m is None:
                                failed_rules.append(r['description'])
                        else:
                            if m is not None:
                                failed_rules.append(r['description'])
                if len(failed_rules) == 0:
                    password = pwd
                else:
                    logging.error(rs['password_rules_intro'])
                    for fr in failed_rules:
                        logging.error(fr)

        new_params = KeeperParams()
        new_params.server = params.server
        data_center = kwargs.get('data_center')
        if data_center:
            parts = list(urlsplit(new_params.server))
            host = parts[1]
            port = ''
            colon_pos = host.rfind(':')
            if colon_pos > 0:
                port = host[colon_pos:]
                host = host[:colon_pos]
            suffix = '.eu' if data_center == 'eu' else '.com'
            if not host.endswith(suffix):
                dot_pos = host.rfind('.')
                if dot_pos > 0:
                    host = host[:dot_pos] + suffix
            parts[1] = host + port
            new_params.server = urlunsplit(parts)

        data_key = os.urandom(32)
        iterations = self.get_iterations()
        auth_salt = os.urandom(16)
        enc_salt = os.urandom(16)
        backup_salt = os.urandom(16)

        private_key, public_key = loginv3.CommonHelperMethods.generate_rsa_key_pair()

        rq = {
            'command': 'register',
            'version': 1,
            'email': email,
            'auth_verifier': api.create_auth_verifier(password, auth_salt, iterations),
            'encryption_params': api.create_encryption_params(password, enc_salt, iterations, data_key),
            'encrypted_private_key': api.encrypt_aes(private_key, data_key),
            'public_key': base64.urlsafe_b64encode(public_key).decode().rstrip('='),
            'client_key': api.encrypt_aes(os.urandom(32), data_key)
        }
        if verification_code:
            rq['verification_code'] = verification_code

        rs = api.run_command(new_params, rq)
        if rs['result'] == 'success':
            logging.info("Created account: %s ", email)

            if kwargs.get('question'):
                if not kwargs.get('answer'):
                    print('...' + 'Security Question: '.rjust(24) + kwargs['question'])
                    kwargs['answer'] = input('...' + 'Security Answer: '.rjust(24))
                if kwargs.get('answer'):
                    try:
                        param1 = KeeperParams()
                        param1.server = new_params.server
                        param1.user = email
                        param1.password = password
                        param1.rest_context.device_id = params.rest_context.device_id
                        api.login(param1)
                        answer = kwargs['answer'].lower().replace(' ', '')
                        rq = {
                            'command': 'set_data_key_backup',
                            'version': 2,
                            'data_key_backup': api.create_encryption_params(answer, backup_salt, iterations, data_key),
                            'security_question': kwargs['question'],
                            'security_answer_salt': base64.urlsafe_b64encode(backup_salt).decode().rstrip('='),
                            'security_answer_iterations': iterations,
                            'security_answer_hash': base64.urlsafe_b64encode(
                                api.derive_key(answer, backup_salt, iterations)).decode().rstrip('=')
                        }
                        api.communicate(param1, rq)
                        logging.info('Master password backup is created.')
                    except Exception as e:
                        logging.error('Failed to create master password backup. %s', e)

            if params.enterprise:
                api.query_enterprise(params)
                file_name = kwargs.get('records')
                should_accept_share = False
                if file_name:
                    try:
                        push = EnterprisePushCommand()
                        push.execute(params, user=[email], file=file_name)
                        should_accept_share = True
                    except Exception as e:
                        logging.info('Error accepting shares: %s', e)

                # first accept shares from enterprise admin
                if should_accept_share:
                    try:
                        param1 = KeeperParams()
                        param1.server = new_params.server
                        param1.user = email
                        param1.password = password
                        param1.rest_context.device_id = params.rest_context.device_id
                        api.login(param1)
                        rq = {
                            'command': 'accept_share',
                            'from_email': params.user
                        }
                        api.communicate(param1, rq)
                    except Exception as e:
                        logging.info('Error accepting shares: %s', e)

                # last expire password
                if kwargs.get('expire'):
                    try:
                        rq = {
                            'command': 'set_master_password_expire',
                            'email': email
                        }
                        api.communicate(params, rq)
                    except Exception as e:
                        logging.info('Error expiring master password: %s', e)

            store = kwargs['store'] if 'store' in kwargs else None
            if store:
                if params.session_token:
                    try:
                        add_command = RecordAddCommand()
                        add_command.execute(params, title='Keeper credentials for {0}'.format(email), login=email,
                                            password=password, force=True)
                    except Exception:
                        store = False
                        logging.error('Failed to create record in Keeper')
                else:
                    store = False
            if generate and not store:
                logging.warning('Generated password: %s', password)

            if params.enterprise:
                api.query_enterprise(params)
        else:
            logging.error(rs['message'])


class ShareFolderCommand(Command):
    def get_parser(self):
        return share_folder_parser

    def execute(self, params, **kwargs):
        folder = None
        name = kwargs.get('folder')
        if name:
            if name in params.folder_cache:
                folder = params.folder_cache[name]
            else:
                rs = try_resolve_path(params, name)
                if rs is not None:
                    folder, name = rs
                    if len(name or '') > 0:
                        folder = None
                    elif folder.type == BaseFolderNode.RootFolderType:
                        folder = None

        if folder is None:
            raise CommandError('share-folder', 'Enter name of the existing folder')

        if folder.type not in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            raise CommandError('share-folder', 'You can change permission of shared folders only')

        shared_folder_uid = folder.shared_folder_uid if folder.type == BaseFolderNode.SharedFolderFolderType else folder.uid
        if shared_folder_uid in params.shared_folder_cache:
            sh_fol = params.shared_folder_cache[shared_folder_uid]
            # TODO check permission to modify shared folder

            action = kwargs.get('action') or 'grant'

            as_users = set()
            as_teams = set()

            default_account = False
            if 'user' in kwargs:
                for u in (kwargs.get('user') or []):
                    if u == '*':
                        default_account = True
                    else:
                        em = re.match(EMAIL_PATTERN, u)
                        if em is not None:
                            as_users.add(u.lower())
                        else:
                            api.load_available_teams(params)
                            team = next((x for x in params.available_team_cache
                                         if u == x.get('team_uid') or
                                         u.lower() == (x.get('team_name') or '').lower()), None)
                            if team:
                                team_uid = team['team_uid']
                                as_teams.add(team_uid)
                            else:
                                logging.warning('User %s could not be resolved as email or team', u)

            record_uids = []
            default_record = False
            if 'record' in kwargs:
                records = kwargs.get('record') or []
                for r in records:
                    if r == '*':
                        default_record = True
                    elif r in params.record_cache:
                        record_uids.append(r)
                    else:
                        r_uid = None
                        rs = try_resolve_path(params, r)
                        if rs is not None:
                            sf, name = rs
                            if name:
                                shared_folder_uid = sf.uid or ''
                                if shared_folder_uid in params.subfolder_record_cache:
                                    for uid in params.subfolder_record_cache[shared_folder_uid]:
                                        rec = api.get_record(params, uid)
                                        if name in {rec.title, rec.record_uid}:
                                            r_uid = rec.record_uid
                                            break
                        if r_uid:
                            record_uids.append(r_uid)
                        else:
                            logging.error('\'%s\' is not an existing record title or UID', r)

            request = {
                'command': 'shared_folder_update',
                'pt': 'Commander',
                'operation': 'update',
                'shared_folder_uid': sh_fol['shared_folder_uid'],
                'revision': sh_fol['revision']
            }

            if default_account:
                if kwargs.get('manage_records'):
                    request['default_manage_records'] = action == 'grant'
                if kwargs.get('manage_users'):
                    request['default_manage_users'] = action == 'grant'

            if default_record:
                if kwargs.get('can_edit'):
                    request['default_can_edit'] = action == 'grant'
                if kwargs.get('can_share'):
                    request['default_can_share'] = action == 'grant'

            if len(as_users) > 0:
                email_set = set()
                if 'users' in sh_fol:
                    for user in sh_fol['users']:
                        email_set.add(user['username'])
                mr = kwargs.get('manage_records')
                mu = kwargs.get('manage_users')
                for email in as_users:
                    uo = {
                        'username': email
                    }
                    share_action = ''
                    if email in email_set:
                        if action == 'grant':
                            if mr:
                                uo['manage_records'] = True
                            if mu:
                                uo['manage_users'] = True
                            share_action = 'update_users'
                        else:
                            if mr or mu:
                                if mr:
                                    uo['manage_records'] = False
                                if mu:
                                    uo['manage_users'] = False
                                share_action = 'update_users'
                            else:
                                share_action = 'remove_users'
                    elif action == 'grant':
                        api.load_user_public_keys(params, [email])
                        rsa_key = params.key_cache.get(email)
                        if rsa_key:
                            uo['manage_records'] = sh_fol.get('default_manage_records') or False
                            uo['manage_users'] = sh_fol.get('default_manage_users') or False
                            uo['shared_folder_key'] = api.encrypt_rsa(sh_fol['shared_folder_key_unencrypted'], rsa_key)
                            share_action = 'add_users'
                        else:
                            logging.warning('User %s not found', email)

                    if share_action:
                        if share_action not in request:
                            request[share_action] = []
                        request[share_action].append(uo)

            if len(as_teams) > 0:
                existing_teams = {}
                if 'teams' in sh_fol:
                    for team in sh_fol['teams']:
                        team_uid = team['team_uid']
                        existing_teams[team_uid] = team

                mr = kwargs.get('manage_records')
                mu = kwargs.get('manage_users')
                for team_uid in as_teams:
                    to = {
                        'team_uid': team_uid
                    }
                    share_action = ''
                    if team_uid in existing_teams:
                        existing_permissions = existing_teams[team_uid]
                        if action == 'grant':
                            if mr:
                                to['manage_records'] = True
                            else:
                                to['manage_records'] = existing_permissions.get('manage_records') or False
                            if mu:
                                to['manage_users'] = True
                            else:
                                to['manage_users'] = existing_permissions.get('manage_users') or False
                            share_action = 'update_teams'
                        else:
                            if mr or mu:
                                if mr:
                                    to['manage_records'] = False
                                if mu:
                                    to['manage_users'] = False
                                share_action = 'update_teams'
                            else:
                                share_action = 'remove_teams'
                    elif action == 'grant':
                        api.load_team_keys(params, [team_uid])
                        team_key = params.key_cache.get(team_uid)
                        if team_key:
                            if kwargs.get('force'):
                                to['manage_records'] = mr
                                to['manage_users'] = mu
                            else:
                                to['manage_records'] = sh_fol.get('default_manage_records') or False
                                to['manage_users'] = sh_fol.get('default_manage_users') or False
                            shared_folder_key = sh_fol['shared_folder_key_unencrypted']
                            if type(team_key) == bytes:
                                to['shared_folder_key'] = api.encrypt_aes(shared_folder_key, team_key)
                            else:
                                to['shared_folder_key'] = api.encrypt_rsa(shared_folder_key, team_key)
                            share_action = 'add_teams'

                    if share_action:
                        if share_action not in request:
                            request[share_action] = []
                        request[share_action].append(to)

            if len(record_uids) > 0:
                ruid_set = set()
                if 'records' in sh_fol:
                    for r in sh_fol['records']:
                        ruid_set.add(r['record_uid'])
                team_uid = ''
                if 'key_type' not in sh_fol:
                    if 'teams' in sh_fol:
                        for team in sh_fol['teams']:
                            team_uid = team['team_uid']
                            if team.get('manage_records'):
                                break

                for record_uid in record_uids:
                    ro = {
                        'record_uid': record_uid
                    }
                    if team_uid:
                        ro['team_uid'] = team_uid
                        ro['shared_folder_uid'] = sh_fol['shared_folder_uid']

                    share_action = ''
                    ce = kwargs.get('can_edit')
                    cs = kwargs.get('can_share')
                    if record_uid in ruid_set:
                        if action == 'grant':
                            if ce:
                                ro['can_edit'] = True
                            if cs:
                                ro['can_share'] = True
                            share_action = 'update_records'
                        else:
                            if ce or cs:
                                if ce:
                                    ro['can_edit'] = False
                                if cs:
                                    ro['can_share'] = False
                                share_action = 'update_records'
                            else:
                                share_action = 'remove_records'
                    else:
                        if action == 'grant':
                            ro['can_edit'] = ce
                            ro['can_share'] = cs
                            rec = params.record_cache[record_uid]
                            ro['record_key'] = api.encrypt_aes(rec['record_key_unencrypted'],
                                                               sh_fol['shared_folder_key_unencrypted'])
                            share_action = 'add_records'

                    if share_action:
                        if share_action not in request:
                            request[share_action] = []
                        request[share_action].append(ro)

            try:
                response = api.communicate(params, request)
                params.sync_data = True

                for node in ['add_teams', 'update_teams', 'remove_teams']:
                    if node in response:
                        for t in response[node]:
                            team_uid = t['team_uid']
                            team = next((x for x in params.available_team_cache if x.get('team_uid') == team_uid), None)
                            if team:
                                if t['status'] == 'success':
                                    logging.info('Team share \'%s\' %s', team['team_name'],
                                                    'added' if node == 'add_teams' else
                                                    'updated' if node == 'update_teams' else
                                                    'removed')
                                else:
                                    logging.warning('Team share \'%s\' failed', team['team_name'])

                for node in ['add_users', 'update_users', 'remove_users']:
                    if node in response:
                        for s in response[node]:
                            if s['status'] == 'success':
                                logging.info('User share \'%s\' %s', s['username'],
                                                'added' if node == 'add_users' else
                                                'updated' if node == 'update_users' else
                                                'removed')
                            elif s['status'] == 'invited':
                                logging.info('User \'%s\' invited', s['username'])
                            else:
                                logging.warning('User share \'%s\' failed', s['username'])

                for node in ['add_records', 'update_records', 'remove_records']:
                    if node in response:
                        for r in response[node]:
                            rec = api.get_record(params, r['record_uid'])
                            if r['status'] == 'success':
                                logging.info('Record share \'%s\' %s', rec.title,
                                                'added' if node == 'add_records' else
                                                'updated' if node == 'update_records' else
                                                'removed')
                            else:
                                logging.warning('Record share \'%s\' failed', rec.title)

            except KeeperApiError as kae:
                if kae.result_code != 'bad_inputs_nothing_to_do':
                    raise kae


class ShareRecordCommand(Command):
    def get_parser(self):
        return share_record_parser

    def execute(self, params, **kwargs):
        emails = kwargs.get('email') or []
        if not emails:
            raise CommandError('share-record', '\'email\' parameter is missing')

        action = kwargs.get('action') or 'grant'

        if action == 'cancel':
            answer = user_choice(bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                                 'This action cannot be undone.\n\n' +
                                 'Do you want to cancel all shares with user(s): ' + ', '.join(emails) + ' ?', 'yn',
                                 'n')
            if answer.lower() in {'y', 'yes'}:
                for email in emails:
                    rq = {
                        'command': 'cancel_share',
                        'to_email': email
                    }
                    try:
                        rs = api.communicate(params, rq)
                    except KeeperApiError as kae:
                        if kae.result_code == 'share_not_found':
                            logging.info('{0}: No shared records are found.'.format(email))
                        else:
                            logging.warning('{0}: {1}.'.format(email, kae.message))
                    except Exception as e:
                        logging.warning('{0}: {1}.'.format(email, e))
                params.sync_data = True
            return

        name = kwargs['record'] if 'record' in kwargs else None
        if not name:
            self.get_parser().print_help()
            return

        record_uid = None
        if name in params.record_cache:
            record_uid = name
        else:
            rs = try_resolve_path(params, name)
            if rs is not None:
                folder, name = rs
                if folder is not None and name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == name.lower():
                                record_uid = uid
                                break

        if record_uid is None:
            raise CommandError('share-record', 'Enter name or uid of existing record')

        public_keys = {}
        rq = {
            'command': 'public_keys',
            'key_owners': emails
        }
        rs = api.communicate(params, rq)
        if 'public_keys' in rs:
            for pk in rs['public_keys']:
                if 'public_key' in pk:
                    email = pk['key_owner'].lower()
                    if email != params.user.lower():
                        public_keys[email] = pk['public_key']
                else:
                    logging.error('\'%s\' is not a known Keeper account', pk['key_owner'])
        if len(public_keys) == 0:
            raise CommandError('share-record', 'No existing Keeper accounts provided.')

        record_path = api.resolve_record_share_path(params, record_uid)
        if record_path is None:
            raise CommandError('share-record', 'You do not have permissions to share this record.')

        rq = {
            'command': 'get_records',
            'include': ['shares'],
            'records': [record_path]
        }
        rs = api.communicate(params, rq)
        existing_shares = {}
        if 'records' in rs:
            if 'user_permissions' in rs['records'][0]:
                for po in rs['records'][0]['user_permissions']:
                    existing_shares[po['username'].lower()] = po

        can_edit = kwargs.get('can_edit') or False
        can_share = kwargs.get('can_share') or False

        record_key = params.record_cache[record_uid]['record_key_unencrypted']

        rq = {
            'command': 'record_share_update',
            'pt': 'Commander'
        }
        if action == 'owner':
            if len(public_keys) > 1:
                raise CommandError('share-record', 'You can transfer ownership to a single account only')

        for email in public_keys:
            current = existing_shares.get(email)
            ro = {
                'to_username': email
            }
            ro.update(record_path)
            share_action = ''
            if action == 'grant':
                if current is None:
                    rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_keys[email] + '=='))
                    ro['record_key'] = api.encrypt_rsa(record_key, rsa_key)
                    ro['editable'] = can_edit,
                    ro['shareable'] = can_share
                else:
                    ro['editable'] = True if can_edit else current['editable']
                    ro['shareable'] = True if can_share else current['shareable']

                share_action = 'add_shares' if current is None else 'update_shares'
            elif action == 'revoke':
                if current:
                    if can_share or can_edit:
                        ro['editable'] = False if can_edit else current['editable']
                        ro['shareable'] = False if can_share else current['shareable']
                        share_action = 'update_shares'
                    else:
                        share_action = 'remove_shares'
            elif action == 'owner':
                if record_uid in params.meta_data_cache and params.meta_data_cache[record_uid].get('owner'):
                    ro['transfer'] = True
                    if current is None:
                        rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_keys[email] + '=='))
                        ro['record_key'] = api.encrypt_rsa(record_key, rsa_key)
                        share_action = 'add_shares'
                    else:
                        share_action = 'update_shares'
                else:
                    logging.error('You should be a record owner to be able to transfer ownership')
                    return
            else:
                pass

            if share_action:
                if share_action not in rq:
                    rq[share_action] = []
                    rq[share_action].append(ro)

        rs = api.communicate(params, rq)

        if 'add_statuses' in rs:
            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] in ['success']]
            if emails:
                logging.info('Record is successfully shared with: %s', ', '.join(emails))

            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] in ['pending_accept']]
            if emails:
                logging.info('Recipient must accept request to complete sharing. Invitation sent to %s. ',
                             ', '.join(emails))

            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] not in ['success', 'pending_accept']]
            if emails:
                logging.info('Failed to share record with: %s', ', '.join(emails))

        if 'remove_statuses' in rs:
            emails = [x['to_username'] for x in rs['remove_statuses'] if x['status'] == 'success']
            if emails:
                logging.info('Stopped sharing record with: %s', ', '.join(emails))


class ShareReportCommand(Command):
    def get_parser(self):
        return share_report_parser

    def execute(self, params, **kwargs):
        verbose = kwargs.get('verbose') or False
        record_uids = []
        user_filter = set()
        record_filter = set()

        if kwargs.get('record'):
            records = kwargs.get('record') or []
            for r in records:
                if r in params.record_cache:
                    record_filter.add(r)
                else:
                    r_uid = None
                    rs = try_resolve_path(params, r)
                    if rs is not None:
                        sf, name = rs
                        if name:
                            shared_folder_uid = sf.uid or ''
                            if shared_folder_uid in params.subfolder_record_cache:
                                for uid in params.subfolder_record_cache[shared_folder_uid]:
                                    rec = api.get_record(params, uid)
                                    if name in {rec.title, rec.record_uid}:
                                        r_uid = rec.record_uid
                                        break
                    if r_uid:
                        record_filter.add(r_uid)
                    else:
                        raise CommandError('share-report', '\'{0}\' is not an existing record title or UID'.format(r))

            record_uids = [x for x in record_filter]
        elif kwargs.get('user'):
            for u in kwargs['user']:
                user_filter.add(u)

            record_uids = [x['record_uid'] for x in params.record_cache.values() if x['shared']]
        else:
            record_uids = [x['record_uid'] for x in params.record_cache.values() if x['shared']]

        api.get_record_shares(params, record_uids)

        if not kwargs.get('owner'):
            record_shares = {}
            sf_shares = {}
            for uid in record_uids:
                record = params.record_cache[uid]
                if 'shares' in record:
                    if 'user_permissions' in record['shares']:
                        for up in record['shares']['user_permissions']:
                            user_name = up['username']
                            if user_filter:
                                if user_name not in user_filter:
                                    continue
                            if user_name not in record_shares:
                                record_shares[user_name] = set()
                            if uid not in record_shares[user_name]:
                                record_shares[user_name].add(uid)
                    if 'shared_folder_permissions' in record['shares']:
                        names = set()
                        for sfp in record['shares']['shared_folder_permissions']:
                            shared_folder_uid = sfp['shared_folder_uid']
                            if shared_folder_uid in params.shared_folder_cache:
                                shared_folder = params.shared_folder_cache[sfp['shared_folder_uid']]
                                names.clear()
                                if 'users' in shared_folder:
                                    for u in shared_folder['users']:
                                        user_name = u['username']
                                        if user_filter:
                                            if user_name not in user_filter:
                                                continue
                                        names.add(user_name)
                                if 'teams' in shared_folder:
                                    for t in shared_folder['teams']:
                                        user_name = t['name']
                                        if user_filter:
                                            if user_name not in user_filter:
                                                continue
                                        names.add(user_name)

                                for user_name in names:
                                    if user_name not in sf_shares:
                                        sf_shares[user_name] = set()
                                    if shared_folder_uid not in sf_shares[user_name]:
                                        sf_shares[user_name].add(shared_folder_uid)

                                if 'records' in shared_folder:
                                    for sfr in shared_folder['records']:
                                        uid = sfr['record_uid']
                                        if record_filter:
                                            if not uid in record_filter:
                                                continue
                                        for user_name in names:
                                            if user_filter:
                                                if user_name not in user_filter:
                                                    continue
                                            if user_name not in record_shares:
                                                record_shares[user_name] = set()
                                            if uid not in record_shares[user_name]:
                                                record_shares[user_name].add(uid)

            if kwargs.get('record'):
                if len(record_shares) > 0:
                    users_shares = {}
                    for user in record_shares:
                        for uid in record_shares[user]:
                            if uid not in users_shares:
                                users_shares[uid] = set()
                            users_shares[uid].add(user)
                    for record_uid in users_shares:
                        record = api.get_record(params, record_uid)
                        print('')
                        print('{0:>20s}   {1}'.format('Record UID:', record.record_uid))
                        print('{0:>20s}   {1}'.format('Title:', record.title))
                        for i, user in enumerate(users_shares[record_uid]):
                            print('{0:>20s}   {1}'.format('Shared with:' if i == 0 else '', user))
                        print('')

            elif kwargs.get('user'):
                if len(record_shares) > 0:
                    user_names = [x for x in record_shares.keys()]
                    user_names.sort()
                    headers = ['#', 'Record UID', 'Title']
                    for user in user_names:
                        record_uids = record_shares[user]
                        records = [api.get_record(params, x) for x in record_uids]
                        records.sort(key=lambda x: x.title.lower())
                        table = [[i + 1, r.record_uid, r.title] for i, r in enumerate(records)]
                        title = 'Records shared with: {0}'.format(user)
                        dump_report_data(table, headers, title=title, fmt=kwargs.get('format'),
                                         filename=kwargs.get('output'), append=True)

                if len(sf_shares) > 0:
                    user_names = [x for x in sf_shares.keys()]
                    user_names.sort(key=lambda x: x.lower())
                    headers = ['#', 'Shared Folder UID', 'Name']
                    for user in user_names:
                        sf_uids = sf_shares[user]
                        sfs = [api.get_shared_folder(params, x) for x in sf_uids]
                        sfs.sort(key=lambda x: x.name.lower())
                        table = [[i + 1, sf.shared_folder_uid, sf.name] for i, sf in enumerate(sfs)]
                        title = 'Folders shared with: {0}'.format(user)
                        dump_report_data(table, headers, title=title, fmt=kwargs.get('format'),
                                         filename=kwargs.get('output'), append=True)
            else:
                if params.user in record_shares:
                    del record_shares[params.user]
                if params.user in sf_shares:
                    del sf_shares[params.user]

                headers = ['#', 'Shared to', 'Records']
                table = []
                for user_name, uids in record_shares.items():
                    if verbose:
                        records = []
                        for uid in uids:
                            record = api.get_record(params, uid)
                            records.append('{0}  {1}'.format(uid, record.title if record else ''))
                        table.append([user_name, records])
                    else:
                        table.append([user_name, len(uids)])
                [(s[0], list(s[1]) if verbose else len(s[1])) for s in record_shares.items()]
                table.sort(key=lambda x: len(x[1]) if type(x[1]) == list else x[1], reverse=True)
                table = [[i + 1, s[0], s[1]] for i, s in enumerate(table)]
                dump_report_data(table, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

        else:

            include_share_date = kwargs.get('share_date')
            record_owners = {}
            record_shared_with = {}
            is_an_enterprise_user_by_ref = [True] # To track if use is part of an enterprise. If not then call backend only once.
            total_record = len(record_uids)
            count = 0
            for uid in record_uids:

                if include_share_date:

                    rem_count = total_record - count
                    percent = int(((rem_count/total_record)*100))
                    percent_indicator_left = int(50 - (percent/2))
                    percent_indicator_right = int(50 - percent_indicator_left)

                    print(
                          (bcolors.OKBLUE + 'Generating report: |' + bcolors.ENDC) +
                          ((bcolors.OKBLUE + '█' + bcolors.ENDC) * percent_indicator_left) +
                          ((bcolors.OKBLUE + '_' + bcolors.ENDC) * percent_indicator_right) +
                          (bcolors.OKBLUE + '|' + bcolors.ENDC),
                          (bcolors.OKBLUE + str(100-percent) + "%" + bcolors.ENDC), end='\x1b[1K\r')

                count = count + 1

                record = params.record_cache[uid]
                if 'shares' in record:
                    record_shared_with[uid] = []
                    record_share_details = self.get_record_share_activities(params, uid, is_an_enterprise_user_by_ref) if include_share_date else None
                    if 'user_permissions' in record['shares']:
                        for up in record['shares']['user_permissions']:
                            user_name = up['username']
                            if up.get('owner'):
                                record_owners[uid] = user_name
                            else:
                                can_edit = up.get('editable') or False
                                can_share = up.get('shareable') or False
                                permission = self.get_permission_text(can_edit, can_share)
                                date_shared = self.get_date_for_share(record_share_details, user_name)
                                record_shared_with[uid].append('{0} -> {1}{2}'.format(user_name, permission, date_shared))
                    if 'shared_folder_permissions' in record['shares']:
                        for sfp in record['shares']['shared_folder_permissions']:
                            shared_folder_uid = sfp['shared_folder_uid']
                            if shared_folder_uid in params.shared_folder_cache:
                                shared_folder = params.shared_folder_cache[sfp['shared_folder_uid']]
                                rp = None
                                if 'records' in shared_folder:
                                    for record in shared_folder['records']:
                                        if record.get('record_uid') == uid:
                                            rp = record
                                            break
                                if rp:
                                    can_edit = rp.get('can_edit')
                                    can_share = rp.get('can_share')
                                    permission = self.get_permission_text(can_edit, can_share)
                                    if 'users' in shared_folder:
                                        for u in shared_folder['users']:
                                            date_shared = self.get_date_for_share_folder_record(record_share_details, shared_folder_uid)
                                            user_name = u['username']
                                            record_shared_with[uid].append('{0} => {1}{2}'.format(user_name, permission, date_shared))
                                    if 'teams' in shared_folder:
                                        for t in shared_folder['teams']:
                                            date_shared = self.get_date_for_share_folder_record(record_share_details, shared_folder_uid)
                                            team_name = t['name']
                                            record_shared_with[uid].append('{0} => {1}{2}'.format(team_name, permission, date_shared))

            if len(record_owners) > 0:
                headers = ['#', 'Record Title', 'Record UID', 'Owner', 'Shared with']
                table = []
                for uid, user_name in record_owners.items():
                    record = api.get_record(params, uid)
                    row = [record.title[0:32] if record else '', uid, user_name]
                    share_to = record_shared_with.get(uid)
                    if verbose:
                        share_to.sort()
                        row.append(share_to)
                    else:
                        row.append(len(share_to) if share_to else 0)
                    table.append(row)
                table.sort(key=lambda x: len(x[3]) if type(x[3]) == list else x[3], reverse=True)
                table = [[i + 1, s[0], s[1], s[2], s[3]] for i, s in enumerate(table)]
                dump_report_data(table, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

    @staticmethod
    def get_permission_text(can_edit, can_share, can_view=True):
        if can_edit or can_share:
            if can_edit and can_view:
                return 'Can Share & Edit'
            if can_share:
                return 'Can Share'
            return 'Can Edit'
        else:
            return 'View Only' if can_view else 'Launch Only'

    @staticmethod
    def get_record_share_activities(params: KeeperParams, record_uid: str, is_an_enterprise_user_by_ref):

        if not is_an_enterprise_user_by_ref[0]:
            # no need to execute the query to get analytics data because we know that user is not part of the enterprise
            return None

        rq = {
            'command': 'get_audit_event_reports',
            'report_type': 'raw',
            'scope': 'enterprise',
            'limit': 1000,
            'order': 'ascending',
            'filter': {
                'audit_event_type': [
                    'share'
                    , 'record_share_outside_user'
                    , 'remove_share'

                    , 'folder_add_team'
                    , 'folder_remove_team'

                    , 'folder_add_record'
                    , 'folder_remove_record'

                    # ,'change_share'
                    # ,'transfer_owner'
                    # ,'accept_share'
                    # ,'cancel_share'
                ],
                'record_uid': record_uid
            }
        }

        try:
            rs = api.communicate(params, rq)

        except Exception as e:

            if e.result_code == 'not_an_enterprise_user':
                # logging.warning("In order to see shared time details, user must be part of the Keeper account.")
                is_an_enterprise_user_by_ref[0] = False
                return None
            elif e.result_code == 'access_denied':
                logging.debug("You do not have permissions to access report for your organization. In order to "
                                "allow user to access reports, ask administrator to grant permission \"Run Reports\" "
                                "permission.")
                is_an_enterprise_user_by_ref[0] = False
                return None

        is_an_enterprise_user_by_ref[0] = True

        rs = api.communicate(params, rq)

        if rs['result'] == 'success':
            audit_events = rs['audit_event_overview_report_rows']

            # sort list by creation date
            audit_events = sorted(audit_events, key=lambda i: i['created'])

        else:
            logging.warning("Error retrieving values")

            return None

        # Remove mutually exclusive records (ex. "share -> remove_share -> share -> remove_share -> share" will
        # become just "share")
        latest_record_share_events = {}
        latest_folder_share_events = {}

        for event in audit_events:

            if 'to_username' in event:  # INDIVIDUAL record sharing

                key = str(event['record_uid']) + '-' + str(event['to_username'])

                if event['audit_event_type'] in ['share', 'record_share_outside_user', 'remove_share']:
                    if key in latest_record_share_events and event['audit_event_type'] == 'remove_share':
                        del latest_record_share_events[key]
                    elif event['audit_event_type'] in ['share', 'record_share_outside_user']:
                        latest_record_share_events[key] = event
                    else:
                        pass

            elif 'shared_folder_uid' in event:  # FOLDER sharing

                key = str(event['record_uid']) + '-' + str(event['shared_folder_uid'])

                if event['audit_event_type'] in ['folder_add_record', 'folder_remove_record']:
                    if key in latest_folder_share_events and event['audit_event_type'] == 'folder_remove_record':
                        del latest_folder_share_events[key]
                    elif event['audit_event_type'] == 'folder_add_record':
                        latest_folder_share_events[key] = event
                    else:
                        pass

        return list(latest_record_share_events.values()) + list(latest_folder_share_events.values())

    @staticmethod
    def get_date_for_share(share_activity_list: list, user_name: str):
        if not share_activity_list or len(share_activity_list) == 0:
            return ""

        activity = next((s for s in share_activity_list if 'to_username' in s and s['to_username'] == user_name), None)

        if activity is None:
            return ""

        activity_created_ms = activity['created']
        date_formatted = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(activity_created_ms))

        if activity['audit_event_type'] == 'record_share_outside_user':
            return '\t(externally shared on {0})'.format(date_formatted)
        else:
            return '\t(shared on {0})'.format(date_formatted)

    @staticmethod
    def get_date_for_share_folder_record(share_activity_list: list, shared_folder_uid: str):
        if not share_activity_list or len(share_activity_list) == 0:
            return ""

        activity = next((s for s in share_activity_list if ('folder' in s['audit_event_type'] and s["shared_folder_uid"] == shared_folder_uid)), None)

        if activity is None:
            return ""

        activity_created_ms = activity['created']
        date_formatted = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(activity_created_ms))

        return '\t(shared on {0})'.format(date_formatted)

class RecordPermissionCommand(Command):
    def get_parser(self):
        return record_permission_parser

    def execute(self, params, **kwargs):
        folder_name = kwargs['folder'] if 'folder' in kwargs else ''
        folder_uid = None
        if folder_name:
            if folder_name in params.folder_cache:
                folder_uid = folder_name
            else:
                rs = try_resolve_path(params, folder_name)
                if rs is not None:
                    folder, pattern = rs
                    if len(pattern) == 0:
                        folder_uid = folder.uid
                    else:
                        raise CommandError('record-permission', 'Folder {0} not found'.format(folder_name))

        if folder_uid:
            folder = params.folder_cache[folder_uid]  # type: BaseFolderNode or SharedFolderFolderNode
        else:
            folder = params.root_folder

        share_record = kwargs.get('share_record') or False
        share_folder = kwargs.get('share_folder') or False
        if not share_record and not share_folder:
            share_record = True
            share_folder = True

        flat_subfolders = [folder]
        if kwargs.get('recursive'):
            fols = set()
            fols.add(folder.uid)
            pos = 0
            while pos < len(flat_subfolders):
                folder = flat_subfolders[pos]
                if folder.subfolders:
                    for f_uid in folder.subfolders:
                        if f_uid not in fols:
                            f = params.folder_cache[f_uid]
                            if f:
                                flat_subfolders.append(f)
                            fols.add(f_uid)
                pos += 1
            logging.debug('Folder count: %s', len(flat_subfolders))

        should_have = True if kwargs['action'] == 'grant' else False
        change_share = kwargs['can_share'] or False
        change_edit = kwargs['can_edit'] or False

        if not change_share and not change_edit:
            raise CommandError('record-permission',
                               'Please choose at least one on the following options: can-edit, can-share')

        if not kwargs.get('force'):
            logging.info('\nRequest to {0} {1}{3}{2} permission(s) in "{4}" folder {5}'
                         .format('GRANT' if should_have else 'REVOKE',
                                 '"Can Edit"' if change_edit else '',
                                 '"Can Share"' if change_share else '',
                                 ' & ' if change_edit and change_share else '',
                                 folder_name,
                                 'recursively' if kwargs.get('recursive') else 'only'))

        uids = set()

        direct_shares_update = []
        direct_shares_skip = []

        # direct shares
        if share_record:
            uids.clear()
            for folder in flat_subfolders:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    uids.update(params.subfolder_record_cache[folder_uid])

            if len(uids) > 0:
                api.get_record_shares(params, uids)
                for record_uid in uids:
                    if record_uid in uids and record_uid in params.record_cache:
                        record = params.record_cache[record_uid]
                        has_record_share_permissions = False
                        if record_uid in params.meta_data_cache:
                            md = params.meta_data_cache[record_uid]
                            has_record_share_permissions = md['can_share']

                        if 'shares' in record:
                            if 'user_permissions' in record['shares']:
                                for up in record['shares']['user_permissions']:
                                    if up['owner']:  # exclude record owners
                                        continue
                                    username = up['username']
                                    if username == params.user:  # exclude self
                                        continue
                                    if (change_edit and should_have != up['editable']) or \
                                            (change_share and should_have != up['shareable']):
                                        cmd = {
                                            'to_username': up['username'],
                                            'record_uid': record_uid,
                                            'editable': up['editable'],
                                            'shareable': up['shareable']
                                        }
                                        if has_record_share_permissions:
                                            if change_edit:
                                                cmd['editable'] = should_have
                                            if change_share:
                                                cmd['shareable'] = should_have
                                            direct_shares_update.append(cmd)
                                        else:
                                            direct_shares_skip.append(cmd)

        # shared folder record permissions
        shared_folder_update = {}  # dict<shared_folder_uid, list[sf_record]>
        shared_folder_skip = {}

        if share_folder:
            for folder in flat_subfolders:
                if folder.type not in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                    continue
                uids.clear()
                if folder.uid in params.subfolder_record_cache:
                    uids.update(params.subfolder_record_cache[folder.uid])

                shared_folder_uid = folder.uid
                if type(folder) == SharedFolderFolderNode:
                    shared_folder_uid = folder.shared_folder_uid
                if shared_folder_uid in params.shared_folder_cache:
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    team_uid = None
                    has_manage_records_permission = False
                    if 'shared_folder_key' in shared_folder:
                        has_manage_records_permission = shared_folder.get('manage_records') or False
                    if not has_manage_records_permission:
                        if 'teams' in shared_folder:
                            for sft in shared_folder['teams']:
                                uid = sft['team_uid']
                                if sft.get('manage_records') and uid in params.team_cache:
                                    t = api.get_team(params, uid)
                                    if not t.restrict_share:
                                        team_uid = uid
                                        has_manage_records_permission = True
                                        break

                    if 'records' in shared_folder:
                        for rp in shared_folder['records']:
                            record_uid = rp['record_uid']
                            has_record_share_permissions = False
                            if record_uid in params.meta_data_cache:
                                md = params.meta_data_cache[record_uid]
                                has_record_share_permissions = md['can_share']

                            container = shared_folder_update \
                                if has_record_share_permissions and has_manage_records_permission else shared_folder_skip
                            if shared_folder_uid not in container:
                                container[shared_folder_uid] = {}
                            record_permissions = container[shared_folder_uid]

                            if record_uid in uids and record_uid not in record_permissions:
                                if (change_edit and should_have != rp['can_edit']) or \
                                        (change_share and should_have != rp['can_share']):
                                    cmd = {
                                        'record_uid': record_uid,
                                        'shared_folder_uid': shared_folder_uid,
                                        'can_edit': rp['can_edit'],
                                        'can_share': rp['can_share']
                                    }
                                    if team_uid:
                                        cmd['team_uid'] = team_uid
                                    if change_edit:
                                        cmd['can_edit'] = should_have
                                    if change_share:
                                        cmd['can_share'] = should_have
                                    record_permissions[record_uid] = cmd

        if len(shared_folder_update) > 0:
            uids.clear()
            uids.update(shared_folder_update.keys())
            for shared_folder_uid in uids:
                if len(shared_folder_update[shared_folder_uid]) == 0:
                    del shared_folder_update[shared_folder_uid]

        if len(shared_folder_skip) > 0:
            uids.clear()
            uids.update(shared_folder_skip.keys())
            for shared_folder_uid in uids:
                if len(shared_folder_skip[shared_folder_uid]) == 0:
                    del shared_folder_skip[shared_folder_uid]

        if len(direct_shares_skip) > 0:
            if kwargs.get('dry_run'):
                last_record_uid = ''
                table = []
                for i, cmd in enumerate(direct_shares_skip):
                    record_uid = cmd['record_uid']
                    row = [i + 1, '', '', '']
                    if record_uid != last_record_uid:
                        last_record_uid = record_uid
                        record = params.record_cache[record_uid]
                        record_owners = [x['username'] for x in record['shares']['user_permissions'] if x['owner']]
                        record_owner = record_owners[0] if len(record_owners) > 0 else ''
                        rec = api.get_record(params, record_uid)
                        row[1] = record_uid
                        row[2] = rec.title[:32]
                        row[3] = record_owner
                    row.append(cmd['to_username'])
                    table.append(row)
                headers = ['#', 'Record UID', 'Title', 'Owner', 'Email']
                title = bcolors.FAIL + ' SKIP ' + bcolors.ENDC + 'Direct Record Share permission(s). Not permitted'
                dump_report_data(table, headers, title=title)
                logging.info('')
                logging.info('')

        if len(shared_folder_skip) > 0:
            if kwargs.get('dry_run'):
                table = []
                for shared_folder_uid in shared_folder_skip:
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    uid = shared_folder_uid
                    name = shared_folder.name[:32]
                    for record_uid in shared_folder_skip[shared_folder_uid]:
                        record = api.get_record(params, record_uid)
                        row = [len(table) + 1, uid, name, record_uid, record.title]
                        uid = ''
                        name = ''
                        table.append(row)
                if len(table) > 0:
                    headers = ['#', 'Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    title = (bcolors.FAIL + ' SKIP ' + bcolors.ENDC +
                             'Shared Folder Record Share permission(s). Not permitted')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

        if len(direct_shares_update) > 0:
            if not kwargs.get('force'):
                last_record_uid = ''
                table = []
                for i, cmd in enumerate(direct_shares_update):
                    record_uid = cmd['record_uid']
                    row = [i + 1, '', '']
                    if record_uid != last_record_uid:
                        last_record_uid = record_uid
                        rec = api.get_record(params, record_uid)
                        row[1] = record_uid
                        row[2] = rec.title[:32]
                    row.append(cmd['to_username'])
                    if change_edit:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'editable' in cmd else '')
                    if change_share:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'shareable' in cmd else '')
                    table.append(row)

                headers = ['#', 'Record UID', 'Title', 'Email']
                if change_edit:
                    headers.append('Can Edit')
                if change_share:
                    headers.append('Can Share')

                title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                    .format('GRANT' if should_have else 'REVOKE')
                dump_report_data(table, headers, title=title)
                logging.info('')
                logging.info('')

        if len(shared_folder_update) > 0:
            if not kwargs.get('force'):
                table = []
                for shared_folder_uid in shared_folder_update:
                    commands = shared_folder_update[shared_folder_uid]
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    uid = shared_folder_uid
                    name = shared_folder.name[:32]
                    for record_uid in commands:
                        cmd = commands[record_uid]
                        record = api.get_record(params, record_uid)
                        row = [len(table) + 1, uid, name, record_uid, record.title[:32]]
                        if change_edit:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if 'can_edit' in cmd else '')
                        if change_share:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if 'can_share' in cmd else '')
                        table.append(row)
                        uid = ''
                        name = ''

                if len(table) > 0:
                    headers = ['#', 'Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    if change_edit:
                        headers.append('Can Edit')
                    if change_share:
                        headers.append('Can Share')
                    title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Shared Folder Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

        if not kwargs.get('dry_run') and (len(shared_folder_update) > 0 or len(direct_shares_update) > 0):
            print('\n\n' + bcolors.WARNING + bcolors.BOLD + 'ALERT!!!' + bcolors.ENDC)
            answer = user_choice("Do you want to proceed with these permission changes?", 'yn', 'n') \
                if not kwargs.get('force') else 'Y'
            if answer.lower() == 'y':
                table = []
                while len(direct_shares_update) > 0:
                    batch = direct_shares_update[:80]
                    direct_shares_update = direct_shares_update[80:]
                    rq = {
                        'command': 'record_share_update',
                        'pt': 'Commander',
                        'update_shares': batch
                    }

                    rs = api.communicate(params, rq)
                    if 'update_statuses' in rs:
                        for i, status in enumerate(rs['update_statuses']):
                            code = status['status']
                            if code != 'success':
                                record_uid = status['record_uid']
                                username = status.get('username') or status.get('to_username')
                                table.append([len(table) + 1, record_uid, username, code, status.get('message')])

                if len(table) > 0:
                    headers = ['#', 'Record UID', 'Email', 'Error Code', 'Message']
                    title = (bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

                table = []
                for shared_folder_uid in shared_folder_update:
                    updates = list(shared_folder_update[shared_folder_uid].values())
                    while len(updates) > 0:
                        batch = updates[:80]
                        updates = updates[80:]
                        rq = {
                            'command': 'shared_folder_update',
                            'pt': 'Commander',
                            'operation': 'update',
                            'shared_folder_uid': shared_folder_uid,
                            'update_records': batch,
                            'force_update': True
                        }
                        if 'team_uid' in batch[0]:
                            rq['from_team_uid'] = batch[0]['team_uid']
                        rs = api.communicate(params, rq)
                        if 'update_records' in rs:
                            for status in rs['update_records']:
                                code = status['status']
                                if code != 'success':
                                    table.append([len(table) + 1, shared_folder_uid, status['record_uid'],
                                                  code, status.get('message')])

                if len(table) > 0:
                    headers = ['#', 'Shared Folder UID', 'Record UID', 'Error Code', 'Message']
                    title = (
                                bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC + ' Shared Folder Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

                params.sync_data = True


class FileReportCommand(Command):
    def get_parser(self):
        return file_report_parser

    def execute(self, params, **kwargs):
        headers = ['#', 'Title', 'Record UID', 'File ID']
        if kwargs.get('try_download'):
            headers.append('Downloadable')
        table = []
        for record_uid in params.record_cache:
            r = api.get_record(params, record_uid)
            if not r.attachments:
                continue
            file_ids = {}
            for atta in r.attachments:
                file_id = atta.get('id')
                file_ids[file_id] = ''
            if kwargs.get('try_download'):
                ids = [x for x in file_ids]
                rq = {
                    'command': 'request_download',
                    'file_ids': ids,
                }
                api.resolve_record_access_path(params, r.record_uid, path=rq)
                logging.info('Downloading attachments for record %s', r.title)
                try:
                    rs = api.communicate(params, rq)
                    urls = {}
                    for file_id, dl in zip(ids, rs['downloads']):
                        if 'url' in dl:
                            urls[file_id] = dl['url']
                        elif 'error_code' in dl:
                            file_ids[file_id] = dl['error_code']
                    for file_id in urls:
                        url = urls[file_id]
                        opt_rs = requests.get(url, headers={"Range": "bytes=0-1"})
                        file_ids[file_id] = 'OK' if opt_rs.status_code in {200, 206} else str(opt_rs.status_code)
                except Exception as e:
                    logging.debug(e)
            for file_id in file_ids:
                row = [len(table) + 1, r.title, r.record_uid, file_id]
                if kwargs.get('try_download'):
                    row.append(file_ids[file_id] or '-')
                table.append(row)

        dump_report_data(table, headers)
