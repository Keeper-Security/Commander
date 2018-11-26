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
from urllib.parse import urlsplit, urlunsplit
from email.utils import parseaddr

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from Cryptodome.Math.Numbers import Integer

from .. import api, generator
from .record import RecordAddCommand
from ..params import KeeperParams
from ..subfolder import BaseFolderNode, try_resolve_path
from .enterprise import EnterpriseCommand

from .base import raise_parse_exception, suppress_exit, Command


EMAIL_PATTERN=r"(?i)^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$"


def register_commands(commands):
    commands['share-record'] = ShareRecordCommand()
    commands['share-folder'] = ShareFolderCommand()
    commands['create-user'] = RegisterCommand()


def register_command_info(aliases, command_info):
    aliases['sr'] = 'share-record'
    aliases['sf'] = 'share-folder'
    aliases['cu'] = 'create-user'

    for p in [share_record_parser, share_folder_parser, register_parser]:
        command_info[p.prog] = p.description


share_record_parser = argparse.ArgumentParser(prog='share-record|sr', description='Change record share permissions')
share_record_parser.add_argument('-e', '--email', dest='email', action='append', required=True, help='account email')
share_record_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke', 'owner'], default='grant', action='store', help='user share action. \'grant\' if omitted')
share_record_parser.add_argument('-s', '--share', dest='can_share', action='store_true', help='can re-share record')
share_record_parser.add_argument('-w', '--write', dest='can_edit', action='store_true', help='can modify record')
share_record_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
share_record_parser.error = raise_parse_exception
share_record_parser.exit = suppress_exit


share_folder_parser = argparse.ArgumentParser(prog='share-folder|sf', description='Change shared folder permissions')
share_folder_parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke'], default='grant', action='store', help='shared folder action. \'grant\' if omitted')
share_folder_parser.add_argument('-u', '--user', dest='user', action='append', help='account email, team, or \'*\' as default folder permission')
share_folder_parser.add_argument('-r', '--record', dest='record', action='append', help='record name, record UID, or \'*\' as default folder permission')
share_folder_parser.add_argument('-p', '--manage-records', dest='manage_records', action='store_true', help='account permission: can manage records.')
share_folder_parser.add_argument('-o', '--manage-users', dest='manage_users', action='store_true', help='account permission: can manage users.')
share_folder_parser.add_argument('-s', '--can-share', dest='can_share', action='store_true', help='record permission: can be shared')
share_folder_parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true', help='record permission: can be modified.')
share_folder_parser.add_argument('folder', nargs='?', type=str, action='store', help='shared folder path or UID')
share_folder_parser.error = raise_parse_exception
share_folder_parser.exit = suppress_exit


register_parser = argparse.ArgumentParser(prog='create-user', description='Create Keeper User')
register_parser.add_argument('--store-record', dest='store', action='store_true', help='store credentials into Keeper record (must be logged in)')
register_parser.add_argument('--generate', dest='generate', action='store_true', help='generate password')
register_parser.add_argument('--pass', dest='password', action='store', help='user password')
register_parser.add_argument('--data-center', dest='data_center', choices=['us', 'eu'], action='store', help='data center.')
register_parser.add_argument('--node', dest='node', action='store', help='node name or node ID (enterprise only)')
register_parser.add_argument('--name', dest='name', action='store', help='user name (enterprise only)')
register_parser.add_argument('--question', dest='question', action='store', help='security question')
register_parser.add_argument('--answer', dest='answer', action='store', help='security answer')
register_parser.add_argument('email', action='store', help='email')
register_parser.error = raise_parse_exception
register_parser.exit = suppress_exit


class RegisterCommand(Command):
    def is_authorised(self):
        return False

    def get_parser(self):
        return register_parser

    def execute(self, params, **kwargs):
        email = kwargs['email'] if 'email' in kwargs else None

        if email:
            _, email = parseaddr(email)
        if not email:
            print('A valid email address is expected.')
            return

        rq = {
            'command': 'pre_register',
            'email': email
        }

        rs = api.run_command(params, rq)
        if rs['result_code'] != 'Failed_to_find_user':
            if rs['result'] == 'success':
                print('User \'{0}\' already exists in Keeper'.format(email))
            else:
                print(rs['message'])
            return

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
                api.print_error('\'name\' parameter is required for enterprise users')
                return
            rq = {
                'command': 'enterprise_user_add',
                'enterprise_user_id': EnterpriseCommand.get_enterprise_id(params),
                'enterprise_user_username': email,
                'encrypted_data': api.encrypt_aes(json.dumps(data).encode('utf-8'), params.enterprise['unencrypted_tree_key']),
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
            except:
                pass

        password = kwargs['password'] if 'password' in kwargs else None
        generate = kwargs['generate'] if 'generate' in kwargs else None
        if generate:
            password = generator.generate(16)
        else:
            while not password:
                pwd = getpass.getpass(prompt='Password: ', stream=None)
                failed_rules = []
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
                    print(rs['password_rules_intro'])
                    for fr in failed_rules:
                        print(fr)

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
            parts[1] = host+port
            new_params.server = urlunsplit(parts)

        iterations = 100000
        salt = os.urandom(16)
        auth_verifier = b''
        auth_verifier = auth_verifier + b'\x01' + iterations.to_bytes(3, 'big') + salt
        derived_key = api.derive_key(password, salt, iterations)
        auth_verifier = auth_verifier + derived_key

        encryption_params=b''
        salt = os.urandom(16)
        encryption_params = encryption_params + b'\x01' + iterations.to_bytes(3, 'big') + salt
        data_key = os.urandom(32)
        dk = data_key + data_key
        encryption_key = api.derive_key(password, salt, iterations)
        iv = os.urandom(16)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        encryption_params = encryption_params + iv + cipher.encrypt(dk)

        rsa_key = RSA.generate(2048)
        private_key = DerSequence([0,
                                   rsa_key.n,
                                   rsa_key.e,
                                   rsa_key.d,
                                   rsa_key.p,
                                   rsa_key.q,
                                   rsa_key.d % (rsa_key.p-1),
                                   rsa_key.d % (rsa_key.q-1),
                                   Integer(rsa_key.q).inverse(rsa_key.p)
                                   ]).encode()
        pub_key = rsa_key.publickey()
        public_key = DerSequence([pub_key.n,
                                  pub_key.e
                                  ]).encode()

        rq = {
            'command': 'register',
            'version': 1,
            'email': email,
            'auth_verifier': base64.urlsafe_b64encode(auth_verifier).rstrip(b'=').decode(),
            'encryption_params': base64.urlsafe_b64encode(encryption_params).rstrip(b'=').decode(),
            'encrypted_private_key': api.encrypt_aes(private_key, data_key),
            'public_key': base64.urlsafe_b64encode(public_key).rstrip(b'=').decode(),
            'security_answer_iterations': 1000,
            'security_answer_salt': base64.urlsafe_b64encode(salt).rstrip(b'=').decode(),
            'security_question': 'What is your favorite password manager application?',
            'security_answer_hash': api.auth_verifier_old('keeper', salt, 1000),
            'client_key': api.encrypt_aes(os.urandom(32), data_key)
        }
        if verification_code:
            rq['verification_code'] = verification_code

        rs = api.run_command(new_params, rq)
        if rs['result'] == 'success':
            if kwargs.get('question'):
                api.print_info("Account {0} created".format(email))
                if not kwargs.get('answer'):
                    api.print_info('...' + 'Security Question: '.rjust(24) + kwargs['question'])
                    kwargs['answer'] = input('...' + 'Security Answer: '.rjust(24))
                if kwargs.get('answer'):
                    try:
                        param1 = KeeperParams()
                        param1.server = new_params.server
                        param1.user = email
                        param1.password = password
                        api.login(param1)
                        salt = os.urandom(16)
                        iterations = 100000
                        security_key = api.derive_key(kwargs['answer'], salt, iterations)
                        iv = os.urandom(16)
                        cipher = AES.new(security_key, AES.MODE_CBC, iv)
                        encryption_params = b'\x01' + iterations.to_bytes(3, 'big') + salt
                        data_key_backup = encryption_params + iv + cipher.encrypt(dk)
                        rq = {
                            'command': 'set_data_key_backup',
                            'version': 2,
                            'data_key_backup': base64.urlsafe_b64encode(data_key_backup).rstrip(b'=').decode(),
                            'security_question': kwargs['question'],
                            'security_answer_salt': base64.urlsafe_b64encode(salt).rstrip(b'=').decode(),
                            'security_answer_iterations': iterations,
                            'security_answer_hash': api.auth_verifier_old(kwargs['answer'], salt, iterations)
                        }
                        api.communicate(param1, rq)
                        api.print_info('Master password backup is created.')
                    except Exception as e:
                        api.print_error('Failed to create master password backup.')

            store = kwargs['store'] if 'store' in kwargs else None
            if store:
                if params.session_token:
                    try:
                        add_command = RecordAddCommand()
                        add_command.execute(params, title='Keeper credentials for {0}'.format(email), login=email, password=password, force=True)
                    except Exception:
                        store = False
                        api.print_error('Failed to create record in Keeper')
                else:
                    store = False
            if generate and not store:
                print('Generated password: {0}'.format(password))

            if params.enterprise:
                api.query_enterprise(params)
        else:
            api.print_error(rs['message'])


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
            print('Enter name of the existing folder')
            return

        if folder.type not in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            print('You can change permission of shared folders only')
            return


        shared_folder_uid = folder.shared_folder_uid if folder.type == BaseFolderNode.SharedFolderFolderType else folder.uid
        if shared_folder_uid in params.shared_folder_cache:
            sh_fol = params.shared_folder_cache[shared_folder_uid]
            #TODO check permission to modify shared folder

            action = kwargs.get('action') or 'grant'

            public_keys = {}
            team_keys = {}
            default_account = False
            if 'user' in kwargs:
                emails = []
                teams = []
                for u in (kwargs.get('user') or []):
                    if u == '*':
                        default_account = True
                    else:
                        em = re.match(EMAIL_PATTERN, u)
                        if not em is None:
                            emails.append(u)
                        else:
                            team_uid = None
                            for tid in params.team_cache:
                                if tid == u or params.team_cache[tid]['name'].lower() == u.lower():
                                    team_uid = params.team_cache[tid]['team_uid']
                                    break
                            if team_uid:
                                teams.append(team_uid)
                            else:
                                print('User {0} could not be resolved as email or team'.format(u))
                if len(emails) > 0:
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
                                print('\'{0}\' is not a known Keeper account'.format(pk['key_owner']))

                if len(teams) > 0:
                    rq = {
                        'command': 'team_get_keys',
                        'teams': teams
                    }
                    rs = api.communicate(params, rq)
                    if 'keys' in rs:
                        for tk in rs['keys']:
                            if 'key' in tk:
                                team_uid = tk['team_uid']
                                if tk['type'] == 1:
                                    team_keys[team_uid] = api.decrypt_data(tk['key'], params.data_key)
                                elif tk['type'] == 2:
                                    team_keys[team_uid] = api.decrypt_rsa(tk['key'], params.rsa_key)
                                elif tk['type'] == 3:
                                    team_keys[team_uid] = base64.urlsafe_b64decode(tk['key'] + '==')

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
                                        r = params.record_cache[uid]
                                        rec = api.get_record(params, uid)
                                        if name in {rec.title, rec.record_uid}:
                                            r_uid = rec.record_uid
                                            break
                        if r_uid:
                            record_uids.append(r_uid)
                        else:
                            print('\'{0}\' is not an existing record title or UID'.format(r))

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

            if len(public_keys) > 0:
                email_set = set()
                if 'users' in sh_fol:
                    for user in sh_fol['users']:
                        email_set.add(user['username'])
                mr = kwargs.get('manage_records')
                mu = kwargs.get('manage_users')
                for email in public_keys:
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
                        uo['manage_records'] = mr
                        uo['manage_users'] = mu
                        rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_keys[email] + '=='))
                        uo['shared_folder_key'] = api.encrypt_rsa(sh_fol['shared_folder_key'], rsa_key)
                        share_action = 'add_users'

                    if share_action:
                        if not share_action in request:
                            request[share_action] = []
                        request[share_action].append(uo)

            if len(team_keys) > 0:
                team_set = set()
                if 'teams' in sh_fol:
                    for team in sh_fol['teams']:
                        team_set.add(team['team_uid'])

                mr = kwargs.get('manage_records')
                mu = kwargs.get('manage_users')
                for team_uid in team_keys:
                    to = {
                        'team_uid': team_uid
                    }
                    share_action = ''
                    if team_uid in team_set:
                        if action == 'grant':
                            if mr:
                                to['manage_records'] = True
                            if mu:
                                to['manage_users'] = True
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
                        to['manage_records'] = mr
                        to['manage_users'] = mu
                        to['shared_folder_key'] = api.encrypt_aes(sh_fol['shared_folder_key'], team_keys[team_uid])
                        share_action = 'add_teams'

                    if share_action:
                        if not share_action in request:
                            request[share_action] = []
                        request[share_action].append(to)

            if len(record_uids) > 0:
                ruid_set = set()
                if 'records' in sh_fol:
                    for r in sh_fol['records']:
                        ruid_set.add(r['record_uid'])
                team_uid = ''
                if not 'key_type' in sh_fol:
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
                            ro['record_key'] = api.encrypt_aes(rec['record_key_unencrypted'], sh_fol['shared_folder_key'])
                            share_action = 'add_records'

                    if share_action:
                        if not share_action in request:
                            request[share_action] = []
                        request[share_action].append(ro)
            response = api.communicate(params, request)
            api.sync_down(params)

            for node in ['add_teams', 'update_teams', 'remove_teams']:
                if node in response:
                    for t in response[node]:
                        team = api.get_team(params, t['team_uid'])
                        if t['status'] == 'success':
                            print('Team share \'{0}\' {1}'.format(team.name, 'added' if node =='add_teams' else 'updated' if node == 'update_teams' else 'removed'))
                        else:
                            print('Team share \'{0}\' failed'.format(team.name))

            for node in ['add_users', 'update_users', 'remove_users']:
                if node in response:
                    for s in response[node]:
                        if s['status'] == 'success':
                            print('User share \'{0}\' {1}'.format(s['username'], 'added' if node =='add_users' else 'updated' if node == 'update_users' else 'removed'))
                        elif s['status'] == 'invited':
                            print('User \'{0}\' invited'.format(s['username']))
                        else:
                            print('User share \'{0}\' failed'.format(s['username']))

            for node in ['add_records', 'update_records', 'remove_records']:
                if node in response:
                    for r in response[node]:
                        rec = api.get_record(params, r['record_uid'])
                        if r['status'] == 'success':
                            print('Record share \'{0}\' {1}'.format(rec.title, 'added' if node =='add_records' else 'updated' if node == 'update_records' else 'removed'))
                        else:
                            print('Record share \'{0}\' failed'.format(rec.title))


class ShareRecordCommand(Command):
    def get_parser(self):
        return share_record_parser

    def execute(self, params, **kwargs):
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
            print('Enter name or uid of existing record')
            return

        emails = kwargs.get('email') or []
        if not emails:
            print('\'email\' parameter is missing')
            return

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
                    print('\'{0}\' is not a known Keeper account'.format(pk['key_owner']))
        if len(public_keys) == 0:
            print('No existing Keeper accounts provided.')
            return

        record_path = api.resolve_record_share_path(params, record_uid)
        if record_path is None:
            api.print_error('You do not have permissions to share this record.')
            return

        rq = {
            'command': 'get_records',
            'include': ['shares'],
            'records': [record_path],
            'client_time': api.current_milli_time()
        }
        rs = api.communicate(params, rq)
        existing_shares = {}
        if 'records' in rs:
            if 'user_permissions' in rs['records'][0]:
                for po in rs['records'][0]['user_permissions']:
                    existing_shares[po['username'].lower()] = po

        can_edit = kwargs.get('can_edit') or False
        can_share= kwargs.get('can_share') or False

        record_key = params.record_cache[record_uid]['record_key_unencrypted']

        rq = {
            'command': 'record_share_update',
            'pt': 'Commander'
        }
        action = kwargs.get('action') or 'grant'
        if action == 'owner':
            if len(public_keys) > 1:
                print('TYou can transfer ownership to a single account only')
                return

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
                if not current is None:
                    if can_share or can_edit:
                        ro['editable'] = False if can_edit else current['editable']
                        ro['shareable'] =  False if can_share else current['shareable']
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
                    print('You should be a record owner to be able to transfer ownership')
                    return
            else:
                pass

            if share_action:
                if not share_action in rq:
                    rq[share_action] = []
                    rq[share_action].append(ro)

        rs = api.communicate(params, rq)

        if 'add_statuses' in rs:
            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] in ['success']]
            if emails:
                print('Record is successfully shared with: {0}'.format(', '.join(emails)))

            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] in ['pending_accept']]
            if emails:
                print('Recipient must accept request to complete sharing. Invitation sent to {0}. '.format(', '.join(emails)))

            emails = [x['to_username'] for x in rs['add_statuses'] if x['status'] not in ['success', 'pending_accept']]
            if emails:
                print('Failed to share record with: {0}'.format(', '.join(emails)))

        if 'remove_statuses' in rs:
            emails = [x['to_username'] for x in rs['remove_statuses'] if x['status'] == 'success']
            if emails:
                print('Stopped sharing record with: {0}'.format(', '.join(emails)))
