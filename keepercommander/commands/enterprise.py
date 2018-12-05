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
import json
import base64
import requests
import logging
import platform
import datetime
import fnmatch
import re
import gzip

from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from Cryptodome.Math.Numbers import Integer
from tabulate import tabulate
from asciitree import LeftAligned
from collections import OrderedDict as OD

from .base import user_choice, suppress_exit, raise_parse_exception, Command
from .record import RecordAddCommand
from .. import api
from ..display import bcolors


def register_commands(commands):
    commands['enterprise-info'] = EnterpriseInfoCommand()
    commands['enterprise-user'] = EnterpriseUserCommand()
    commands['enterprise-role'] = EnterpriseRoleCommand()
    commands['enterprise-team'] = EnterpriseTeamCommand()
    commands['audit-log'] = AuditLogCommand()


def unregister_commands(commands):
    for cmd in ['enterprise-info', 'enterprise-user', 'enterprise-role', 'enterprise-team', 'audit-log']:
        commands.pop(cmd, None)


def register_command_info(aliases, command_info):
    aliases['ei'] = 'enterprise-info'
    aliases['eu'] = 'enterprise-user'
    aliases['er'] = 'enterprise-role'
    aliases['et'] = 'enterprise-team'
    aliases['al'] = 'audit-log'

    for p in [enterprise_info_parser, enterprise_user_parser, enterprise_role_parser, enterprise_team_parser, audit_log_parser]:
        command_info[p.prog] = p.description


enterprise_info_parser = argparse.ArgumentParser(prog='enterprise-info|ei', description='Display enterprise information')
enterprise_info_parser.add_argument('-n', '--nodes', dest='nodes', action='store_true', help='print node tree')
enterprise_info_parser.add_argument('-u', '--users', dest='users', action='store_true', help='print user list')
enterprise_info_parser.add_argument('-t', '--teams', dest='teams', action='store_true', help='print team list')
enterprise_info_parser.add_argument('-r', '--roles', dest='roles', action='store_true', help='print role list')
enterprise_info_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_info_parser.add_argument('--node', dest='node', action='store', help='limit results to node (name or ID)')
enterprise_info_parser.error = raise_parse_exception
enterprise_info_parser.exit = suppress_exit


enterprise_user_parser = argparse.ArgumentParser(prog='enterprise-user|eu', description='Enterprise user management')
enterprise_user_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_user_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_user_parser.add_argument('--expire', dest='expire', action='store_true', help='expire master password')
enterprise_user_parser.add_argument('--lock', dest='lock', action='store_true', help='lock user')
enterprise_user_parser.add_argument('--unlock', dest='unlock', action='store_true', help='unlock user')
enterprise_user_parser.add_argument('--add', dest='add', action='store_true', help='invite user')
enterprise_user_parser.add_argument('--delete', dest='delete', action='store_true', help='delete user')
enterprise_user_parser.add_argument('--name', dest='displayname', action='store', help='set user display name')
enterprise_user_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
enterprise_user_parser.add_argument('--add-role', dest='add_role', action='append', help='role name or role ID')
enterprise_user_parser.add_argument('--remove-role', dest='remove_role', action='append', help='role name or role ID')
enterprise_user_parser.add_argument('--add-team', dest='add_team', action='append', help='team name or team UID')
enterprise_user_parser.add_argument('--remove-team', dest='remove_team', action='append', help='team name or team UID')
enterprise_user_parser.add_argument('email', type=str, action='store', help='user email or user ID or user search pattern')
enterprise_user_parser.error = raise_parse_exception
enterprise_user_parser.exit = suppress_exit


enterprise_role_parser = argparse.ArgumentParser(prog='enterprise-role|er', description='Enterprise role management')
#enterprise_role_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_role_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_role_parser.add_argument('--add-user', dest='add_user', action='append', help='add user to role')
enterprise_role_parser.add_argument('--remove-user', dest='remove_user', action='append', help='remove user from role')
enterprise_role_parser.add_argument('role', type=str, action='store', help='role name or role ID')
enterprise_role_parser.error = raise_parse_exception
enterprise_role_parser.exit = suppress_exit


enterprise_team_parser = argparse.ArgumentParser(prog='enterprise-team|et', description='Enterprise team management')
enterprise_team_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_team_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_team_parser.add_argument('--add', dest='add', action='store_true', help='create team')
enterprise_team_parser.add_argument('--delete', dest='delete', action='store_true', help='delete team')
enterprise_team_parser.add_argument('--add-user', dest='add_user', action='append', help='add user to team')
enterprise_team_parser.add_argument('--remove-user', dest='remove_user', action='append', help='remove user from team')
enterprise_team_parser.add_argument('--restrict-edit', dest='restrict_edit', choices=['on', 'off'], action='store', help='disable record edits')
enterprise_team_parser.add_argument('--restrict-share', dest='restrict_share', choices=['on', 'off'], action='store', help='disable record re-shares')
enterprise_team_parser.add_argument('--restrict-view', dest='restrict_view', choices=['on', 'off'], action='store', help='disable view/copy passwords')
enterprise_team_parser.add_argument('--name', dest='name', action='store', help='set team name')
enterprise_team_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
enterprise_team_parser.add_argument('team', type=str, action='store', help='team name or team UID (except --add command)')
enterprise_team_parser.error = raise_parse_exception
enterprise_team_parser.exit = suppress_exit


audit_log_parser = argparse.ArgumentParser(prog='audit-log', description='Export enterprise audit log')
audit_log_parser.add_argument('--target', dest='target', choices=['splunk', 'syslog'], required=True, action='store', help='export target')
audit_log_parser.add_argument('--record', dest='record', action='store', help='keeper record name or UID')
audit_log_parser.error = raise_parse_exception
audit_log_parser.exit = suppress_exit


def lock_text(lock):
    return 'Locked' if lock == 1 else 'Disabled' if lock == 2 else ''


class EnterpriseCommand(Command):
    def __init__(self):
        Command.__init__(self)
        self.public_keys = {}
        self.team_keys = {}

    def execute_args(self, params, args, **kwargs):
        if params.enterprise:
            Command.execute_args(self, params, args, **kwargs)
        else:
            print('This command  is only available for Administrators of Keeper.')

    def get_public_key(self, params, email):
        public_key = self.public_keys.get(email.lower())
        if public_key is None:
            rq = {
                'command': 'public_keys',
                'key_owners': [email]
            }
            rs = api.communicate(params, rq)
            if 'public_keys' in rs:
                pko = rs['public_keys'][0]
                if 'public_key' in pko:
                    public_key = RSA.importKey(base64.urlsafe_b64decode(pko['public_key'] + '=='))
                    self.public_keys[email.lower()] = public_key
        return public_key

    def get_team_key(self, params, team_uid):
        team_key = self.team_keys.get(team_uid)
        if team_key is None:
            rq = {
                'command': 'team_get_keys',
                'teams': [team_uid]
            }
            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                ko = rs['keys'][0]
                if 'key' in ko:
                    if ko['type'] == 1:
                        team_key = api.decrypt_aes(ko['key'], params.data_key)
                    elif ko['type'] == 2:
                        team_key = api.decrypt_rsa(ko['key'], params.rsa_key)
                    elif ko['type'] == 3:
                        team_key = base64.urlsafe_b64decode(ko['key'] + '==')
                if team_key is not None:
                    team_key = team_key[:32]
                    self.team_keys[team_uid] = team_key
        return team_key

    @staticmethod
    def get_enterprise_id(params):
        rq = {
            'command': 'enterprise_allocate_ids',
            'number_requested': 1
        }
        rs = api.communicate(params, rq)
        if rs['result'] == 'success':
            return rs['base_id']

    @staticmethod
    def get_node_path(params, node_id):
        nodes = {}
        for node in params.enterprise['nodes']:
            nodes[node['node_id']] = (node['data'].get('displayname') or params.enterprise['enterprise_name'], node.get('parent_id') or 0)
        path = ''
        node = nodes.get(node_id)
        while node:
            path = '{0}{1}{2}'.format(node[0], '\\' if path else '', path)
            node = nodes.get(node[1])
        return path


class EnterpriseInfoCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_info_parser

    def execute(self, params, **kwargs):

        print('Enterprise name: {0}'.format(params.enterprise['enterprise_name']))

        root_node = None
        node_scope = set()
        node_tree = {}
        if kwargs.get('node'):
            subnode = kwargs.get('node')
            for node in params.enterprise['nodes']:
                node_tree[node['node_id']] = []
                if subnode.lower() in {str(node['node_id']), (node['data'].get('displayname') or '').lower()}:
                    root_node = node['node_id']
                    print('Output is limited to \'{0}\' node'.format(node['data'].get('displayname') or str(node['node_id'])))
        if root_node:
            for node in params.enterprise['nodes']:
                if 'parent_id' in node:
                    node_tree[node['parent_id']].append(node['node_id'])
            nl = [root_node]
            pos = 0
            while pos < len(nl):
                nl.extend(node_tree[nl[pos]])
                pos += 1
                if pos > 100:
                    break
            node_scope.update(nl)
        else:
            for node in params.enterprise['nodes']:
                if not node.get('parent_id'):
                    root_node = node['node_id']
                node_scope.add(node['node_id'])

        nodes = {}
        for node in params.enterprise['nodes']:
            node_id = node['node_id']
            if node_id not in node_scope:
                continue

            nodes[node_id] = {
                'node_id': node_id,
                'parent_id': node.get('parent_id') or 0,
                'name': node['data'].get('displayname') or '',
                'users': [],
                'teams': [],
                'children': []
            }
        for node in nodes:
            parent_id = nodes[node]['parent_id']
            if parent_id in nodes:
                nodes[parent_id]['children'].append(node)

        users = {}
        if 'users' in params.enterprise:
            for user in params.enterprise['users']:
                node_id = user['node_id']
                if node_id not in node_scope:
                    continue

                user_id = user['enterprise_user_id']
                u = {
                    'id': user_id,
                    'node_id': node_id,
                    'username': user['username'],
                    'name': user['data'].get('displayname') or '',
                    'status': user['status'],
                    'lock': user['lock']
                }
                if 'account_share_expiration' in user:
                    u['account_share_expiration'] = user['account_share_expiration']
                users[user_id] = u
                if node_id in nodes:
                    nodes[node_id]['users'].append(user_id)

        teams = {}
        if 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                node_id = team['node_id']
                if node_id not in node_scope:
                    continue
                team_id = team['team_uid']
                teams[team_id] = {
                    'id': team_id,
                    'node_id': node_id,
                    'name': team['name'],
                    'restrict_sharing': team['restrict_sharing'],
                    'restrict_edit': team['restrict_edit'],
                    'restrict_view': team['restrict_view'],
                    'users': []
                }
                if node_id in nodes:
                    nodes[node_id]['teams'].append(team_id)

        if 'team_users' in params.enterprise:
            for tu in params.enterprise['team_users']:
                if tu['team_uid'] in teams:
                    teams[tu['team_uid']]['users'].append(tu['enterprise_user_id'])

        roles = {}
        if 'roles' in params.enterprise:
            for role in params.enterprise['roles']:
                node_id = role['node_id']
                if node_id not in node_scope:
                    continue
                role_id = role['role_id']
                roles[role_id] = {
                    'id': role_id,
                    'node_id': node_id,
                    'name': role['data'].get('displayname') or '',
                    'visible_below': role['visible_below'],
                    'new_user_inherit': role['new_user_inherit']
                }

        show_users = kwargs.get('users') or False
        show_teams = kwargs.get('teams') or False
        show_roles = kwargs.get('roles') or False

        def node_path(node_id):
            path = ''
            n = nodes.get(node_id)
            while n:
                if path:
                    path = '\\' + path
                name = n['name'] if n['parent_id'] else params.enterprise['enterprise_name']
                path = name + path
                if n['parent_id']:
                    n = nodes.get(n['parent_id'])
                else:
                    n = None
            return path

        def restricts(team):
            rs = ''
            rs += 'R ' if team['restrict_view'] else '  '
            rs += 'W ' if team['restrict_edit'] else '  '
            rs += 'S' if team['restrict_sharing'] else ' '
            return rs

        if not show_users and not show_teams and not show_roles:
            def tree_node(node):
                children = [nodes[x] for x in node['children']]
                children.sort(key=lambda x: x['name'])
                n = OD()
                for ch in children:
                    name = ch['name']
                    if kwargs.get('verbose'):
                        name += ' ({0})'.format(ch['node_id'])
                    n['[{0}]'.format(name)] = tree_node(ch)

                if len(node['users']) > 0:
                    if kwargs.get('verbose'):
                        us = [users[x] for x in node['users']]
                        us.sort(key=lambda x: x['username'])
                        ud = OD()
                        for u in us:
                            ud['{0} ({1})'.format(u['username'], u['id'])] = {}
                        n['User(s)'] = ud
                    else:
                        n['{0} user(s)'.format(len(node['users']))] = {}

                if len(node['teams']) > 0:
                    if kwargs.get('verbose'):
                        ts = [teams[x] for x in node['teams']]
                        ts.sort(key=lambda x: x['name'])
                        td = OD()
                        for t in ts:
                            td['{0} ({1})'.format(t['name'], t['id'])] = {}
                        n['Teams(s)'] = td
                    else:
                        n['{0} team(s)'.format(len(node['teams']))] = {}
                return n

            r = nodes[root_node]
            root_name = r['name']
            if not r['parent_id'] and root_name == '':
                root_name = params.enterprise['enterprise_name']
                if kwargs.get('verbose'):
                    root_name += ' ({0})'.format(r['node_id'])
            tree = {
                '[{0}]'.format(root_name): tree_node(r)
            }
            tr = LeftAligned()
            print('')
            print(tr(tree))
        else:
            if show_users:
                rows = []
                for u in users.values():
                    status = lock_text(u['lock'])
                    if not status:
                        if 'account_share_expiration' in u:
                            expire_at = datetime.datetime.fromtimestamp(u['account_share_expiration']/1000.0)
                            if expire_at < datetime.datetime.now():
                                status = 'Blocked'
                            else:
                                status = 'Transfer Acceptance'
                        else:
                            status = u['status'].capitalize()
                    rows.append([u['id'], u['username'], u['name'], status, node_path(u['node_id'])])
                rows.sort(key=lambda x: x[1])

                print('')
                print(tabulate(rows, headers=["User ID", 'Email', 'Name', 'Status', 'Node']))

            if show_teams:
                rows = []
                for t in teams.values():
                    rows.append([t['id'], t['name'], restricts(t), node_path(t['node_id'])])
                rows.sort(key=lambda x: x[1])

                print('')
                print(tabulate(rows, headers=["Team ID", 'Name', 'Restricts', 'Node']))

            if show_roles:
                rows = []
                for r in roles.values():
                    rows.append([r['id'], r['name'], 'Y' if r['visible_below'] else '', 'Y' if r['new_user_inherit'] else '', node_path(r['node_id'])])
                rows.sort(key=lambda x: x[1])

                print('')
                print(tabulate(rows, headers=["Role ID", 'Name', 'Cascade?', 'New User?', 'Node']))

        print('')


class EnterpriseUserCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_user_parser

    def execute(self, params, **kwargs):
        user = None
        matched_users = []
        email = kwargs['email']
        if 'users' in params.enterprise:
            for u in params.enterprise['users']:
                if email in {str(u['enterprise_user_id']), u['username']}:
                    user = u
                    break

        if not user:
            regex = re.compile(fnmatch.translate(email)).match
            if 'users' in params.enterprise:
                for u in params.enterprise['users']:
                    if regex(u['username']):
                        matched_users.append(u)

        node_id = None
        if kwargs.get('node'):
            for node in params.enterprise['nodes']:
                if kwargs['node'] in {str(node['node_id']), node['data'].get('displayname')}:
                    node_id = node['node_id']
                    break
                elif not node.get('parent_id') and kwargs['node'] == params.enterprise['enterprise_name']:
                    node_id = node['node_id']
                    break

        user_name = kwargs.get('displayname')

        if kwargs.get('delete'):
            if user:
                answer = 'y' if kwargs.get('force') else \
                    user_choice(
                        bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                        'Deleting a user will also delete any records owned and shared by this user.\n'+
                        'Before you delete this user(s), we strongly recommend you lock their account\n' +
                        'and transfer any important records to other user(s).\n' +
                        'This action cannot be undone.\n\n' +
                        'Do you want to proceed with deletion?', 'yn', 'n')
                if answer.lower() == 'y':
                    rq = {
                        'command': 'enterprise_user_delete',
                        'enterprise_user_id': user['enterprise_user_id']
                    }
                    rs = api.communicate(params, rq)
                    if rs['result'] == 'success':
                        print('User {0} is deleted'.format(user['username']))
                        api.query_enterprise(params)
            else:
                print('No such user')
            return

        elif kwargs.get('add'):
            dt = {}
            if user_name:
                dt['displayname'] = user_name
            if node_id is None:
                for node in params.enterprise['nodes']:
                    if not node.get('parent_id'):
                        node_id = node['node_id']
                        break
            rq = {
                'command': 'enterprise_user_add',
                'enterprise_user_id': self.get_enterprise_id(params),
                'node_id': node_id,
                'encrypted_data': api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key']),
                'enterprise_user_username': email
            }
            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                print('User {0} is added'.format(user['username']))
                api.query_enterprise(params)
            return

        if user:
            if kwargs.get('lock') or kwargs.get('unlock'):
                is_locked = user['lock'] != 0
                to_lock = kwargs.get('lock')
                if kwargs.get('lock') or kwargs.get('unlock'):
                    to_lock = not is_locked
                rq = {
                    'command': 'enterprise_user_lock',
                    'enterprise_user_id': user['enterprise_user_id'],
                    'lock': 'locked' if to_lock else 'unlocked'
                }
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    user['lock'] = 1 if to_lock else 0
                    print('User {0} is {1}'.format(user['username'], 'locked' if to_lock else 'unlocked'))

            elif kwargs.get('expire'):
                answer = 'y' if  kwargs.get('force') else \
                    user_choice(
                        bcolors.BOLD + '\nConfirm\n' + bcolors.ENDC +
                        'User will be required to create a new Master Password on the next login.\n' +
                        'Are you sure you want to expire master password?', 'yn', 'n')
                if answer.lower() == 'y':
                    rq = {
                        'command': 'set_master_password_expire',
                        'email': user['username']
                    }
                    rs = api.communicate(params, rq)
                    if rs['result'] == 'success':
                        print('User {0} has master password expired'.format(user['username']))

            elif kwargs.get('add_role') or kwargs.get('remove_role'):
                roles = {}
                for is_add in [False, True]:
                    l = kwargs.get('add_role') if is_add else kwargs.get('remove_role')
                    if l:
                        for r in l:
                            role_node = None
                            if 'roles' in params.enterprise:
                                for role in params.enterprise['roles']:
                                    if r in {str(role['role_id']), role['data'].get('displayname')}:
                                        role_node = role
                                        break
                            if role_node:
                                roles[role_node['role_id']] = is_add, role_node['data'].get('displayname')
                            else:
                                print('Role {0} cannot be resolved'.format(r))
                if len(roles) > 0:
                    admin_confirmed = False
                    for role_id in roles:
                        is_add, role_name = roles[role_id]
                        rq = {
                            'command': 'role_user_add' if is_add else 'role_user_remove',
                            'enterprise_user_id': user['enterprise_user_id'],
                            'role_id': role_id
                        }
                        need_confirm = False
                        if is_add:
                            if 'managed_nodes' in params.enterprise:
                                for mn in params.enterprise['managed_nodes']:
                                    if mn['role_id'] == role_id:
                                        public_key = self.get_public_key(params, user['username'])
                                        if public_key is None:
                                            print('Cannot get public key for user {0}'.format(user['username']))
                                            return
                                        rq['tree_key'] = api.encrypt_rsa(params.enterprise['unencrypted_tree_key'], public_key)
                                        need_confirm = True
                                        break
                            if 'role_keys' in params.enterprise:
                                for rk in params.enterprise['role_keys']:
                                    if rk['role_id'] == role_id:
                                        public_key = self.get_public_key(params, user['username'])
                                        if public_key is None:
                                            print('Cannot get public key for user {0}'.format(user['username']))
                                            return
                                        role_key = None
                                        if rk['key_type'] == 'encrypted_by_data_key':
                                            role_key = api.decrypt_aes(rk['encrypted_key'], params.data_key)
                                        elif rk['key_type'] == 'encrypted_by_public_key':
                                            role_key = api.decrypt_aes(rk['encrypted_key'], params.rsa_key)
                                        if role_key:
                                            need_confirm = True
                                            rq['role_admin_key'] = api.encrypt_aes(role_key, public_key)
                                        break
                        if need_confirm and not admin_confirmed:
                            answer = 'y' if kwargs.get('force') else user_choice('Do you want to grant administrative privileges to {0}'.format(user['username']), 'yn', 'n')
                            if answer == 'y':
                                admin_confirmed = True
                            else:
                                return
                        rs = api.communicate(params, rq)
                        if rs['result'] == 'success':
                            print('Role {0} {1} {2}'.format(role_name, 'added to' if is_add else 'removed from', user['username']))
                    api.query_enterprise(params)

            elif kwargs.get('add_team') or kwargs.get('remove_team'):
                teams = {}
                for is_add in [False, True]:
                    tl = kwargs.get('add_team') if is_add else kwargs.get('remove_team')
                    if tl:
                        for t in tl:
                            team_node = None
                            if 'teams' in params.enterprise:
                                for team in params.enterprise['teams']:
                                    if t in { team['team_uid'], team['name']}:
                                        team_node = team
                                        break
                            if team_node:
                                team_uid = team_node['team_uid']
                                teams[team_uid] = is_add, team_node['name']
                            else:
                                print('Team {0} could be resolved'.format(t))
                if len(teams) > 0:
                    for team_uid in teams:
                        is_add, team_name = teams[team_uid]
                        rq = {
                            'command': 'team_enterprise_user_add' if is_add else 'team_enterprise_user_remove',
                            'enterprise_user_id': user['enterprise_user_id'],
                            'team_uid': team_uid
                        }
                        if is_add:
                            team_key = self.get_team_key(params, team_uid)
                            public_key = self.get_public_key(params, user['username'])
                            if team_key and public_key:
                                rq['team_key'] = api.encrypt_rsa(team_key, public_key)
                                rq['user_type'] = 0
                        rs = api.communicate(params, rq)
                        if rs['result'] == 'success':
                            print('Team {0} {1} {2}'.format(team_name, 'added to' if is_add else 'removed from', user['username']))
                    api.query_enterprise(params)

            elif user_name or node_id:
                dt = user['data'].copy()
                if user_name:
                    dt['displayname'] = user_name
                rq = {
                    'command': 'enterprise_user_update',
                    'enterprise_user_id': user['enterprise_user_id'],
                    'node_id': node_id if node_id is not None else user['node_id'],
                    'encrypted_data': api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key']),
                    'enterprise_user_username': user['username']
                }
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    print('User {0} is modified'.format(user['username']))
                    api.query_enterprise(params)

            else:
                is_verbose = kwargs.get('verbose') or False
                self.display_user(params, user, is_verbose)
        else:
            if len(matched_users) > 0:
                is_verbose = kwargs.get('verbose') or False
                skip = True
                for user in matched_users:
                    if skip:
                        skip = False
                    else:
                        print('\n')
                    self.display_user(params, user, is_verbose)
            else:
                print('No such user')

    def display_user(self, params, user, is_verbose = False):
        print('{0:>16s}: {1}'.format('User ID', user['enterprise_user_id']))
        print('{0:>16s}: {1}'.format('Email', user['username']))
        print('{0:>16s}: {1}'.format('Display Name', user['data'].get('displayname') or ''))
        status = lock_text(user['lock'])
        if not status:
            if 'account_share_expiration' in user:
                expire_at = datetime.datetime.fromtimestamp(user['account_share_expiration']/1000.0)
                if expire_at < datetime.datetime.now():
                    status = 'Blocked'
                else:
                    status = 'Transfer Acceptance'
            else:
                status = user['status'].capitalize()
        print('{0:>16s}: {1}'.format('Status', status))

        if 'team_users' in params.enterprise and 'teams' in params.enterprise:
            team_nodes = {}
            for t in params.enterprise['teams']:
                team_nodes[t['team_uid']] = t
            user_id = user['enterprise_user_id']
            ts = [t['team_uid'] for t in params.enterprise['team_users'] if t['enterprise_user_id'] == user_id]
            for i in range(len(ts)):
                team_node = team_nodes[ts[i]]
                print('{0:>16s}: {1:<22s} {2}'.format('Team' if i == 0 else '', team_node['name'], team_node['team_uid'] if is_verbose else ''))

        if 'role_users' in params.enterprise:
            role_ids = [x['role_id'] for x in params.enterprise['role_users'] if x['enterprise_user_id'] == user['enterprise_user_id']]
            if len(role_ids) > 0:
                role_nodes = {}
                for r in params.enterprise['roles']:
                    role_nodes[r['role_id']] = r
                for i in range(len(role_ids)):
                    role_node = role_nodes[role_ids[i]]
                    print('{0:>16s}: {1:<22s} {2}'.format('Role' if i == 0 else '', role_node['data']['displayname'], role_node['role_id'] if is_verbose else ''))


class EnterpriseRoleCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_role_parser

    def execute(self, params, **kwargs):
        r_arg = kwargs['role']
        role = None
        if 'roles' in params.enterprise:
            for r in params.enterprise['roles']:
                if r_arg in {str(r['role_id']), r['data'].get('displayname') or ''}:
                    role = r
                    break

        show_info = True

        if kwargs.get('add_user') or kwargs.get('remove_user'):
            show_info = False
            users = {}
            for is_add in [False, True]:
                ul = kwargs.get('add_user') if is_add else kwargs.get('remove_user')
                if ul:
                    for u in ul:
                        uname = u.lower()
                        user_node = None
                        if 'users' in params.enterprise:
                            for user in params.enterprise['users']:
                                if uname in { str(user['enterprise_user_id']),
                                              user['username'].lower(),
                                              (user['data'].get('displayname') or '').lower() }:
                                    user_node = user
                                    break
                        if user_node:
                            user_id = user_node['enterprise_user_id']
                            users[user_id] = is_add, user_node['username']
                        else:
                            print('User {0} could be resolved'.format(u))
            if len(users) > 0:
                has_managed_nodes = False
                role_key = False
                if 'managed_nodes' in params.enterprise:
                    for mn in params.enterprise['managed_nodes']:
                        if mn['role_id'] == role['role_id']:
                            has_managed_nodes = True
                            break
                if 'role_keys' in params.enterprise:
                    for rk in params.enterprise['role_keys']:
                        if rk['role_id'] == role['role_id']:
                            if rk['key_type'] == 'encrypted_by_data_key':
                                role_key = api.decrypt_aes(rk['encrypted_key'] , params.data_key)
                            elif rk['key_type'] == 'encrypted_by_public_key':
                                role_key = api.decrypt_aes(rk['encrypted_key'] , params.rsa_key)
                            break
                for user_id in users:
                    is_add, user_email = users[user_id]
                    rq = {
                        'command': 'role_user_add' if is_add else 'role_user_remove',
                        'role_id': role['role_id'],
                        'enterprise_user_id': user_id
                    }
                    if is_add:
                        if has_managed_nodes:
                            public_key = self.get_public_key(params, user_email)
                            if public_key:
                                rq['tree_key'] = api.encrypt_rsa(params.enterprise['unencrypted_tree_key'], public_key)
                        if role_key:
                            public_key = self.get_public_key(params, user_email)
                            if public_key:
                                rq['role_admin_key'] = api.encrypt_rsa(role_key, public_key)

                    rs = api.communicate(params, rq)
                    if rs['result'] == 'success':
                        print('User {0} {1} role {2}'.format(user_email, 'added to' if is_add else 'removed from', role['data'].get('displayname') or ''))
                api.query_enterprise(params)

        if role:
            if show_info:
                role_id = role['role_id']
                print('{0:>24s}: {1}'.format('Role ID', role_id))
                print('{0:>24s}: {1}'.format('Role Name', role['data'].get('displayname')))
                print('{0:>24s}: {1}'.format('Node', self.get_node_path(params, role['node_id'])))
                print('{0:>24s}: {1}'.format('Cascade?', 'Yes' if role['visible_below'] else 'No'))
                print('{0:>24s}: {1}'.format('New user?', 'Yes' if role['new_user_inherit'] else 'No'))
                if 'role_users' in params.enterprise:
                    user_ids = [x['enterprise_user_id'] for x in params.enterprise['role_users'] if x['role_id'] == role_id]
                    if len(user_ids) > 0:
                        users = {}
                        for user in params.enterprise['users']:
                            users[user['enterprise_user_id']] = user['username']
                        user_ids.sort(key=lambda x: users[x])
                        for i in range(len(user_ids)):
                            user_id = user_ids[i]
                            print('{0:>24s}: {1:<32s} {2}'.format('User(s)' if i == 0 else '', users[user_id], user_id if kwargs.get('verbose') else ''))

                if 'role_enforcements' in params.enterprise:
                    enforcements = None
                    for e in params.enterprise['role_enforcements']:
                        if role_id == e['role_id']:
                            enforcements = e['enforcements']
                            break
                    if enforcements:
                        print('{0:>24s}: '.format('Role Enforcements'))
                        if 'master_password_minimum_length' in enforcements:
                            print('{0:>24s}: '.format('Password Complexity'))
                            for p in [('Length', 'master_password_minimum_length'),
                                      ('Digits', 'master_password_minimum_digits'),
                                      ('Special Characters', 'master_password_minimum_special'),
                                      ('Uppercase Letters', 'master_password_minimum_upper'),
                                      ('Lowercase Letters', 'master_password_minimum_lower')]:
                                if enforcements.get(p[1]) > 0:
                                    print('{0:>24s}: {1}'.format(p[0], enforcements.get(p[1])))
        else:
            print('Role not found')


class EnterpriseTeamCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_team_parser

    def execute(self, params, **kwargs):
        t_arg = kwargs['team']
        team = None
        if 'teams' in params.enterprise:
            for t in params.enterprise['teams']:
                if t_arg == t['team_uid'] or t_arg.lower() == t['name'].lower():
                    team = t
                    break

        node_id = None
        if kwargs.get('node'):
            for node in params.enterprise['nodes']:
                if kwargs['node'] in {str(node['node_id']), node['data'].get('displayname')}:
                    node_id = node['node_id']
                    break
                elif not node.get('parent_id') and kwargs['node'] == params.enterprise['enterprise_name']:
                    node_id = node['node_id']
                    break

        if kwargs.get('delete'):
            if team is not None:
                answer = 'y' if kwargs.get('force') else \
                    user_choice('Delete Team\n\nAre you sure you want to delete {0}'.format(team['name']), 'yn', 'n')
                if answer.lower() == 'y':
                    rq = {
                        'command': 'team_delete',
                        'team_uid': team['team_uid']
                    }
                    rs = api.communicate(params, rq)
                    if rs['result'] == 'success':
                        print('Team {0} deleted'.format(team['name']))
                        api.query_enterprise(params)
            else:
                print('Team not found')
            return

        if kwargs.get('add'):
            if team is None:
                if node_id is None:
                    for node in params.enterprise['nodes']:
                        if not node.get('parent_id'):
                            node_id = node['node_id']
                            break
                team_uid = api.generate_record_uid()
                team_key = api.generate_aes_key()
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
                    'command': 'team_add',
                    'team_uid': team_uid,
                    'team_name': t_arg,
                    'restrict_edit': kwargs.get('restrict_edit') == 'on' if kwargs.get('restrict_edit') else False,
                    'restrict_share': kwargs.get('restrict_share') == 'on' if kwargs.get('restrict_share') else False,
                    'restrict_view': kwargs.get('restrict_view') == 'on' if kwargs.get('restrict_view') else False,
                    'public_key': base64.urlsafe_b64encode(public_key).rstrip(b'=').decode(),
                    'private_key': api.encrypt_aes(private_key, team_key),
                    'node_id': node_id,
                    'team_key': api.encrypt_aes(team_key, params.data_key),
                    'manage_only': True
                }
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    print('Team {0} created'.format(t_arg))
                    api.query_enterprise(params)
            else:
                print('Team {0} already exists'.format(t_arg))
            return

        if team:
            show_info = True
            team_name = kwargs.get('name')
            if team_name or node_id or kwargs.get('restrict_edit') or kwargs.get('restrict_share') or kwargs.get('restrict_view'):
                rq = {
                    'command': 'team_update',
                    'team_uid': team['team_uid'],
                    'team_name': team_name or team['name'],
                    'restrict_edit': kwargs.get('restrict_edit') == 'on' if kwargs.get('restrict_edit') else team['restrict_edit'],
                    'restrict_share': kwargs.get('restrict_share') == 'on' if kwargs.get('restrict_share') else team['restrict_sharing'],
                    'restrict_view': kwargs.get('restrict_view') == 'on' if kwargs.get('restrict_view') else team['restrict_view'],
                    'node_id': node_id or team['node_id']
                }
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    print('Team {0} modified'.format(team['name']))
                    show_info = False
                    api.query_enterprise(params)

            if kwargs.get('add_user') or kwargs.get('remove_user'):
                show_info = False
                users = {}
                for is_add in [False, True]:
                    ul = kwargs.get('add_user') if is_add else kwargs.get('remove_user')
                    if ul:
                        for u in ul:
                            uname = u.lower()
                            user_node = None
                            if 'users' in params.enterprise:
                                for user in params.enterprise['users']:
                                    if uname in { str(user['enterprise_user_id']),
                                                  user['username'].lower(),
                                                  (user['data'].get('displayname') or '').lower() }:
                                        user_node = user
                                        break
                            if user_node:
                                user_id = user_node['enterprise_user_id']
                                users[user_id] = is_add, user_node['username']
                            else:
                                print('User {0} could be resolved'.format(u))
                if len(users) > 0:
                    for user_id in users:
                        is_add, user_email = users[user_id]
                        rq = {
                            'command': 'team_enterprise_user_add' if is_add else 'team_enterprise_user_remove',
                            'team_uid': team['team_uid'],
                            'enterprise_user_id': user_id
                        }
                        if is_add:
                            public_key = self.get_public_key(params, user_email)
                            team_key = self.get_team_key(params, team['team_uid'])
                            if public_key and team_key:
                                rq['user_type'] = 0
                                rq['team_key'] = api.encrypt_rsa(team_key, public_key)
                        rs = api.communicate(params, rq)
                        if rs['result'] == 'success':
                            api.query_enterprise(params)
                            print('User {0} {1} team {2}'.format(user_email, 'added to' if is_add else 'removed from', team['name']))

            if show_info:
                team_uid = team['team_uid']
                print('{0:>24s}: {1}'.format('Team UID', team_uid))
                print('{0:>24s}: {1}'.format('Team Name', team['name']))
                print('{0:>24s}: {1:<32s} {2}'.format('Node', self.get_node_path(params, team['node_id']), str(team['node_id'])))
                print('{0:>24s}: {1}'.format('Restrict Edit?', 'Yes' if team['restrict_edit'] else 'No'))
                print('{0:>24s}: {1}'.format('Restrict Share?', 'Yes' if team['restrict_sharing'] else 'No'))
                print('{0:>24s}: {1}'.format('Restrict View?', 'Yes' if team['restrict_view'] else 'No'))

                if 'team_users' in params.enterprise:
                    user_ids = [x['enterprise_user_id'] for x in params.enterprise['team_users'] if x['team_uid'] == team_uid]
                    user_names = {}
                    for u in params.enterprise['users']:
                        user_names[u['enterprise_user_id']] = u['username']
                    user_ids.sort(key=lambda x: user_names.get(x))
                    for i in range(len(user_ids)):
                        print('{0:>24s}: {1:<32s} {2}'.format('User(s)' if i == 0 else '', user_names[user_ids[i]], user_ids[i] if kwargs.get('verbose') else ''))
        else:
            print('Team not found')


class AuditLogBaseExport:
    def __init__(self):
        self.store_record = False
        self.should_cancel = False

    def chunk_size(self):
        return 1000

    def default_record_title(self):
        raise NotImplemented()

    def get_properties(self, record, props):
        """
        :type record: Record
        :type props: dict
        :rtype: None
        """
        raise NotImplemented()

    def convert_event(self, props, event):
        raise NotImplemented()

    def export_events(self, props, events):
        '''
        :type props: dict
        :type events: list
        :rtype: None
        '''
        raise NotImplemented()


class AuditLogSplunkExport(AuditLogBaseExport):
    def __init__(self):
        AuditLogBaseExport.__init__(self)

    def default_record_title(self):
        return 'Audit Log: Splunk'

    def get_properties(self, record, props):
        try:
            logging.captureWarnings(True)
            url = record.login_url
            if not url:
                api.print_info('Enter HTTP Event Collector (HEC) endpoint in format [host:port].\nExample: splunk.company.com:8088')
                while not url:
                    address = input('...' + 'Splunk HEC endpoint: '.rjust(32))
                    if not address:
                        return
                    for test_url in ['https://{0}/services/collector'.format(address), 'http://{0}/services/collector'.format(address)]:
                        try:
                            if api.is_interactive_mode:
                                print('Testing \'{0}\' ...'.format(test_url), end='', flush=True)
                            rs = requests.post(test_url, json='', verify=False)
                            if rs.status_code == 401:
                                js = rs.json()
                                if 'code' in js:
                                    if js['code'] == 2:
                                        url = test_url
                        except:
                            pass
                        if url:
                            api.print_info('Found.')
                            break
                        else:
                            api.print_info('Failed.')
                record.login_url = url
                self.store_record = True
            props['hec_url'] = url

            token = record.password
            if not token:
                while not token:
                    test_token = input('...' + 'Splunk Token: '.rjust(32))
                    if not test_token:
                        return
                    try:
                        auth={'Authorization': 'Splunk {0}'.format(test_token)}
                        rs = requests.post(url, json='', headers=auth, verify=False)
                        if rs.status_code == 400:
                            js = rs.json()
                            if 'code' in js:
                                if js['code'] == 6:
                                    token = test_token
                    except:
                        pass
                record.password = token
                self.store_record = True
            props['token'] = token
            props['host'] = platform.node()
        finally:
            logging.captureWarnings(False)

    def convert_event(self, props, event):
        evt = event.copy()
        evt.pop('id')
        created = evt.pop('created')
        js = {
            'time': created,
            'host': props['host'],
            'source': props['enterprise_name'],
            'sourcetype': '_json',
            'event': evt
        }
        return json.dumps(js)

    def export_events(self, props, events):
        auth = { 'Authorization': 'Splunk {0}'.format(props['token']) }
        try:
            logging.captureWarnings(True)
            rs = requests.post(props['hec_url'], data='\n'.join(events), headers=auth, verify=False)
        finally:
            logging.captureWarnings(False)

        if rs.status_code == 200:
            self.store_record = True
        else:
            self.should_cancel = True


class AuditLogSyslogExport(AuditLogBaseExport):
    def __init__(self):
        AuditLogBaseExport.__init__(self)

    def default_record_title(self):
        return 'Audit Log: Syslog'

    def get_properties(self, record, props):
        filename = record.login
        if not filename:
            api.print_info('Enter filename for syslog messages.')
            filename = input('...' + 'Syslog file name: '.rjust(32))
            if not filename:
                return
            if not filename.endswith('.gz'):
                gz = input('...' + 'Gzip messages? (y/N): '.rjust(32))
                if gz.lower() == 'y':
                    filename = filename + '.gz'
            record.login = filename
            self.store_record = True
        props['filename'] = record.login

    def convert_event(self, props, event):
        pri = 13 * 8 + 6
        dt = datetime.datetime.fromtimestamp(event['created'], tz=datetime.timezone.utc)
        message = '<{0}>1 {1} {2} {3} - {4}'.format(pri, dt.strftime('%Y-%m-%dT%H:%M:%SZ'), event['ip_address'], 'Keeper', event['id'])

        evt = event.copy()
        evt.pop('id')
        evt.pop('created')
        evt.pop('ip_address')
        structured = 'Keeper@Commander'
        for key in evt:
            structured += ' {0}="{1}"'.format(key, evt[key])
        structured = '[' + structured + ']'
        message = message + ' ' + structured

        return message

    def export_events(self, props, events):
        is_gzipped = props['filename'].endswith('.gz')
        logf = gzip.GzipFile(filename=props['filename'], mode='ab') if is_gzipped else open(props['filename'], mode='ab')
        try:
            for line in events:
                logf.write(line.encode('utf-8'))
                logf.write(b'\n')
            self.store_record = True
        except:
            self.should_cancel = True
        finally:
            logf.flush()
            logf.close()




class AuditLogCommand(EnterpriseCommand):
    def get_parser(self):
        return audit_log_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')

        log_export = None # type: AuditLogBaseExport
        if target == 'splunk':
            log_export = AuditLogSplunkExport()
        elif target == 'syslog':
            log_export = AuditLogSyslogExport()
        else:
            print('Audit log export: unsupported target')
            return

        record = None
        record_name = kwargs.get('record') or log_export.default_record_title()
        for r_uid in params.record_cache:
            rec = api.get_record(params, r_uid)
            if record_name in [rec.record_uid, rec.title]:
                record = rec
        if record is None:
            answer = user_choice('Do you want to create a Keeper record to store audit log settings?', 'yn', 'n')
            if answer.lower() == 'y':
                record_title = input('Choose the title for audit log record [Default: {0}]: '.format(record_name)) or log_export.default_record_title()
                cmd = RecordAddCommand()
                record_uid = cmd.execute(params, **{
                    'title': record_title,
                    'force': True
                })
                if record_uid:
                    api.sync_down(params)
                    record = api.get_record(params, record_uid)
        if record is None:
            return

        props = {}
        props['enterprise_name'] = params.enterprise['enterprise_name']
        log_export.store_record = False
        log_export.get_properties(record, props)

        #query data
        last_event_time = 0
        val = record.get('last_event_time')
        if val:
            try:
                last_event_time = int(val)
            except:
                pass

        events = []
        finished = False
        new_event_time = None

        created_before = 0
        count = 0
        logged_ids = set()
        chunk_length = log_export.chunk_size()

        while not finished:
            finished = True
            rq = {
                'command': 'get_enterprise_audit_events',
                'limit': 1000,
                'report_type': 'month'
            }
            if created_before > 0:
                rq['created_before'] = created_before * 1000

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                if 'audit_events' in rs:
                    if len(rs['audit_events']) > 0:
                        finished = False
                        for event in rs['audit_events']:
                            created_before = int(event['created'])
                            if new_event_time is None:
                                new_event_time = created_before
                            if created_before < last_event_time:
                                finished = True
                                break

                            event_id = event['id']
                            if event_id not in logged_ids:
                                logged_ids.add(event_id)
                                events.append(log_export.convert_event(props, event))

            if len(events) == 0:
                finished = True
            while len(events) > 0:
                to_store = events[:chunk_length]
                events = events[chunk_length:]
                log_export.export_events(props, to_store)
                if log_export.should_cancel:
                    finished = True
                    break
                else:
                    count += len(to_store)


        if log_export.store_record:
            print('Exported {0} audit event{1}'.format(count, 's' if count != 1 else ''))
            if new_event_time is not None:
                record.set_field('last_event_time', str(new_event_time))
            params.sync_data = True
            api.update_record(params, record, silent=True)
