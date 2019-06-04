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
import time
import socket
import ssl
import hashlib
import hmac
import copy
import os

from urllib.parse import urlparse
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
from ..record import Record
from ..params import KeeperParams, LAST_TEAM_UID
from ..generator import generate


def register_commands(commands):
    commands['enterprise-info'] = EnterpriseInfoCommand()
    #commands['enterprise-node'] = EnterpriseNodeCommand()
    commands['enterprise-user'] = EnterpriseUserCommand()
    commands['enterprise-role'] = EnterpriseRoleCommand()
    commands['enterprise-team'] = EnterpriseTeamCommand()
    commands['enterprise-push'] = EnterprisePushCommand()
    commands['audit-log'] = AuditLogCommand()
    commands['audit-report'] = AuditReportCommand()


def register_command_info(aliases, command_info):
    aliases['ei'] = 'enterprise-info'
    aliases['eu'] = 'enterprise-user'
    aliases['er'] = 'enterprise-role'
    aliases['et'] = 'enterprise-team'
    aliases['al'] = 'audit-log'

    for p in [enterprise_info_parser, enterprise_user_parser, enterprise_role_parser, enterprise_team_parser, enterprise_push_parser,
              audit_log_parser, audit_report_parser]:
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


enterprise_node_parser = argparse.ArgumentParser(prog='enterprise-node|en', description='Enterprise node management')
enterprise_node_parser.add_argument('--wipe-out', action='store_true', help='wipe out node content')
enterprise_node_parser.add_argument('node', type=str, action='store', help='node name or node ID')
enterprise_node_parser.error = raise_parse_exception
enterprise_node_parser.exit = suppress_exit


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
enterprise_team_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
enterprise_team_parser.add_argument('team', type=str, action='store', help='team name or team UID (except --add command)')
enterprise_team_parser.error = raise_parse_exception
enterprise_team_parser.exit = suppress_exit


enterprise_push_parser = argparse.ArgumentParser(prog='enterprise-push', description='Populate user\'s vault with default records')
enterprise_push_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help on file format and template parameters')
enterprise_push_parser.add_argument('--team', dest='team', action='append', help='Team name or team UID. Records will be assigned to all users in the team.')
enterprise_push_parser.add_argument('--user', dest='user', action='append', help='User email or User ID. Records will be assigned to the user.')
enterprise_push_parser.add_argument('file', nargs='?', type=str, action='store', help='file name in JSON format that contains template records')
enterprise_push_parser.error = raise_parse_exception
enterprise_push_parser.exit = suppress_exit


audit_log_parser = argparse.ArgumentParser(prog='audit-log', description='Export enterprise audit log')
audit_log_parser.add_argument('--target', dest='target', choices=['splunk', 'syslog', 'syslog-port', 'sumo', 'azure-la', 'json'], required=True, action='store', help='export target')
audit_log_parser.add_argument('--record', dest='record', action='store', help='keeper record name or UID')
audit_log_parser.error = raise_parse_exception
audit_log_parser.exit = suppress_exit


audit_report_parser = argparse.ArgumentParser(prog='audit-report', description='Run audit report')
audit_report_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
audit_report_parser.add_argument('--report-type', dest='report_type', choices=['raw', 'dim', 'hour', 'day', 'week', 'month', 'span'], action='store', help='report type')
audit_report_parser.add_argument('--report-format', dest='report_format', action='store', choices=['message', 'fields'], help='output format (raw reports only)')
audit_report_parser.add_argument('--columns', dest='columns', action='append', help='Can be repeated. (ignored for raw reports)')
audit_report_parser.add_argument('--aggregate', dest='aggregate', action='append', choices=['occurrences', 'first_created', 'last_created'], help='aggregated value. Can be repeated. (ignored for raw reports)')
audit_report_parser.add_argument('--timezone', dest='timezone', action='store', help='return results for specific timezone')
audit_report_parser.add_argument('--limit', dest='limit', type=int, action='store', help='maximum number of returned rows')
audit_report_parser.add_argument('--order', dest='order', action='store', choices=['desc', 'asc'], help='sort order')
audit_report_parser.add_argument('--created', dest='created', action='store', help='Filter: Created date. Predefined filters: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year')
audit_report_parser.add_argument('--event-type', dest='event_type', action='store', help='Filter: Audit Event Type')
audit_report_parser.add_argument('--username', dest='username', action='store', help='Filter: Username of event originator')
audit_report_parser.add_argument('--to-username', dest='to_username', action='store', help='Filter: Username of event target')
audit_report_parser.add_argument('--record-uid', dest='record_uid', action='store', help='Filter: Record UID')
audit_report_parser.add_argument('--shared-folder-uid', dest='shared_folder_uid', action='store', help='Filter: Shared Folder UID')
audit_report_parser.error = raise_parse_exception
audit_report_parser.exit = suppress_exit


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
            logging.error('This command  is only available for Administrators of Keeper.')

    def get_public_keys(self, params, emails):
        # type: (EnterpriseCommand, KeeperParams, dict) -> None

        for email in emails:
            emails[email] = self.public_keys.get(email.lower())

        email_list = [x[0] for x in emails.items() if x[1] is None]
        if len(email_list) == 0:
            return

        rq = {
            'command': 'public_keys',
            'key_owners': email_list
        }
        rs = api.communicate(params, rq)
        for pko in rs['public_keys']:
            if 'public_key' in pko:
                public_key = RSA.importKey(base64.urlsafe_b64decode(pko['public_key'] + '=='))
                self.public_keys[pko['key_owner'].lower()] = public_key
                emails[pko['key_owner']] = public_key

    def get_public_key(self, params, email):
        # type: (EnterpriseCommand, KeeperParams, str) -> None

        public_key = self.public_keys.get(email.lower())
        if public_key is None:
            emails = {
                email: None
            }
            self.get_public_keys(params, emails)
            public_key = emails[email]

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


class EnterpriseNodeCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_node_parser

    @staticmethod
    def get_subnodes(params, nodes, index):
        if index < len(nodes):
            node_id = nodes[index]
            for node in params.enterprise['nodes']:
                parent_id = node.get('parent_id')
                if parent_id == node_id:
                    nodes.append(node['node_id'])
            EnterpriseNodeCommand.get_subnodes(params, nodes, index + 1)

    def execute(self, params, **kwargs):
        node_name = kwargs['node']
        node_id = None
        for node in params.enterprise['nodes']:
            if node_name in {str(node['node_id']), node['data'].get('displayname')}:
                node_id = node['node_id']
                break
            elif not node.get('parent_id') and node_name == params.enterprise['enterprise_name']:
                node_id = node['node_id']
                break
        if not node_id:
            logging.error('Node %s is not found.', node_name)
            return

        node = [x for x in params.enterprise['nodes'] if x['node_id'] == node_id][0]
        if not node.get('parent_id'):
            logging.error('Cannot wipe out root node')
            return

        answer = user_choice(
            bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
            'This action cannot be undone.\n\n' +
            'Do you want to proceed with deletion?', 'yn', 'n')
        if answer.lower() != 'y':
            return

        sub_nodes = [node['node_id']]
        EnterpriseNodeCommand.get_subnodes(params, sub_nodes, 0)

        nodes = set(sub_nodes)

        commands = []

        if 'queued_teams' in params.enterprise:
            queued_teams = [x for x in params.enterprise['queued_teams'] if x['node_id'] in nodes]
            for qt in queued_teams:
                rq = {
                    'command': 'team_delete',
                    'team_uid': qt['team_uid']
                }
                commands.append(rq)

        managed_nodes = [x for x in params.enterprise['managed_nodes'] if x['managed_node_id'] in nodes]
        roles = [x for x in params.enterprise['roles'] if x['node_id'] in nodes]
        role_set = set([x['role_id'] for x in managed_nodes])
        role_set = role_set.union([x['role_id'] for x in roles])
        for ru in params.enterprise['role_users']:
            if ru['role_id'] in role_set:
                rq = {
                    'command': 'role_user_remove',
                    'role_id': ru['role_id'],
                    'enterprise_user_id': ru['enterprise_user_id']
                }
                commands.append(rq)
        for mn in managed_nodes:
            rq = {
                'command': 'role_managed_node_remove',
                'role_id': mn['role_id'],
                'managed_node_id': mn['managed_node_id']
            }
            commands.append(rq)
        for r in roles:
            rq = {
                'command': 'role_delete',
                'role_id': r['role_id']
            }
            commands.append(rq)
        users = [x for x in params.enterprise['users'] if x['node_id'] in nodes]
        for u in users:
            rq = {
                'command': 'enterprise_user_delete',
                'enterprise_user_id': u['enterprise_user_id']
            }
            commands.append(rq)

        teams = [x for x in params.enterprise['teams'] if x['node_id'] in nodes]
        for t in teams:
            rq = {
                'command': 'team_delete',
                'team_uid': t['team_uid']
            }
            commands.append(rq)

        sub_nodes.pop(0)
        sub_nodes.reverse()
        for node_id in sub_nodes:
            rq = {
                'command': 'node_delete',
                'node_id': node_id
            }
            commands.append(rq)

        api.execute_batch(params, commands)
        api.query_enterprise(params)


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
                        logging.info('User %s is deleted', user['username'])
                        api.query_enterprise(params)
            else:
                logging.warning('No such user')
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
                logging.info('User %s is added', email)
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
                    logging.info('User %s is %s', user['username'], 'locked' if to_lock else 'unlocked')

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
                        logging.info('User %s has master password expired', user['username'])

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
                                logging.warning('Role %s cannot be resolved', r)
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
                                            logging.warning('Cannot get public key for user %s', user['username'])
                                            return
                                        rq['tree_key'] = api.encrypt_rsa(params.enterprise['unencrypted_tree_key'], public_key)
                                        need_confirm = True
                                        break
                            if 'role_keys' in params.enterprise:
                                for rk in params.enterprise['role_keys']:
                                    if rk['role_id'] == role_id:
                                        public_key = self.get_public_key(params, user['username'])
                                        if public_key is None:
                                            logging.warning('Cannot get public key for user %s', user['username'])
                                            return
                                        role_key = None
                                        if rk['key_type'] == 'encrypted_by_data_key':
                                            role_key = api.decrypt_aes(rk['encrypted_key'], params.data_key)
                                        elif rk['key_type'] == 'encrypted_by_public_key':
                                            role_key = api.decrypt_rsa(rk['encrypted_key'], params.rsa_key)
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
                            logging.info('Role %s %s %s', role_name, 'added to' if is_add else 'removed from', user['username'])
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
                                logging.warning('Team %s could be resolved', t)
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
                            logging.info('Team %s %s %s', team_name, 'added to' if is_add else 'removed from', user['username'])
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
                    logging.info('User %s is modified', user['username'])
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
                logging.warning('No such user')

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
        r_arg = str(kwargs['role'])
        role = None
        if 'roles' in params.enterprise:
            for r in params.enterprise['roles']:
                if r_arg in {str(r['role_id']), r['data'].get('displayname') or ''}:
                    role = r
                    break

        show_info = True

        if role and (kwargs.get('add_user') or kwargs.get('remove_user')):
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
                            logging.warning('User %s could be resolved', u)
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
                                role_key = api.decrypt_rsa(rk['encrypted_key'] , params.rsa_key)
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
                        logging.info('User %s %s role %s', user_email, 'added to' if is_add else 'removed from', role['data'].get('displayname') or '')
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
            logging.warning('Role not found')


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
                        logging.info('Team %s deleted', team['name'])
                        api.query_enterprise(params)
            else:
                logging.warning('Team not found')
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
                    logging.info('Team %s created', t_arg)
                    api.query_enterprise(params)
                    params.environment_variables[LAST_TEAM_UID] = team_uid
            else:
                logging.warning('Team %s already exists', t_arg)
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
                                logging.warning('User %s could be resolved', u)
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
                            logging.info('User %s %s team %s', user_email, 'added to' if is_add else 'removed from', team['name'])

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
            logging.warning('Team not found')


syslog_templates = None


def loadSyslogTemplates(params):
    global syslog_templates
    if syslog_templates is None:
        syslog_templates = {}
        rq = {
            'command': 'get_audit_event_dimensions',
            'columns': ['audit_event_type']
        }
        rs = api.communicate(params, rq)
        for et in rs['dimensions']['audit_event_type']:
            name = et.get('name')
            syslog = et.get('syslog')
            if name and syslog:
                syslog_templates[name] = syslog


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

    @staticmethod
    def get_event_message(event):
        message = ''
        if event['audit_event_type'] in syslog_templates:
            info = syslog_templates[event['audit_event_type']]
            while True:
                pattern = re.search('\$\{(\w+)\}', info)
                if pattern:
                    field = pattern[1]
                    val = event.get(field)
                    if val is None:
                        val = '<missing>'

                    sp = pattern.span()
                    info = info[:sp[0]] + str(val) + info[sp[1]:]
                else:
                    break
            message = info
        return message


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
                print('Enter HTTP Event Collector (HEC) endpoint in format [host:port].\nExample: splunk.company.com:8088')
                while not url:
                    address = input('...' + 'Splunk HEC endpoint: '.rjust(32))
                    if not address:
                        return
                    for test_url in ['https://{0}/services/collector'.format(address), 'http://{0}/services/collector'.format(address)]:
                        try:
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
                            print('Found.')
                            break
                        else:
                            print('Failed.')
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


class AuditLogSyslogBaseExport(AuditLogBaseExport):
    def __init__(self):
        AuditLogBaseExport.__init__(self)

    def convert_event(self, props, event):
        pri = 13 * 8 + 6
        dt = datetime.datetime.fromtimestamp(event['created'], tz=datetime.timezone.utc)
        ip = "-"
        if 'ip_address' in event:
            ip = event['ip_address']

        message = '<{0}>1 {1} {2} {3} - {4}'.format(pri, dt.strftime('%Y-%m-%dT%H:%M:%SZ'), ip, 'Keeper', event['id'])

        evt = event.copy()
        evt.pop('id')
        evt.pop('created')
        if 'ip_address' in evt:
            evt.pop('ip_address')
        structured = 'Keeper@Commander'
        for key in evt:
            structured += ' {0}="{1}"'.format(key, evt[key])
        structured = '[' + structured + ']'
        return message + ' ' + structured + ' ' + AuditLogBaseExport.get_event_message(evt)


class AuditLogSyslogFileExport(AuditLogSyslogBaseExport):
    def __init__(self):
        AuditLogSyslogBaseExport.__init__(self)

    def default_record_title(self):
        return 'Audit Log: Syslog'

    def get_properties(self, record, props):
        filename = record.login
        if not filename:
            print('Enter filename for syslog messages.')
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

    def export_events(self, props, events):
        is_gzipped = props['filename'].endswith('.gz')
        logf = gzip.GzipFile(filename=props['filename'], mode='ab') if is_gzipped else open(props['filename'], mode='ab')
        try:
            for line in events:
                logf.write(line.encode('utf-8'))
                logf.write(b'\n')
        finally:
            logf.flush()
            logf.close()


class AuditLogSyslogPortExport(AuditLogSyslogBaseExport):
    def __init__(self):
        AuditLogSyslogBaseExport.__init__(self)

    def default_record_title(self):
        return 'Audit Log: Syslog Port'

    def get_properties(self, record, props):
        is_new_config = False

        host = None
        port = None
        is_ssl = False
        is_udp = False
        url = record.login_url
        if url:
            p = urlparse(url)
            if p.scheme in ['syslog', 'syslogs', 'syslogu']:
                if p.scheme == 'syslogu':
                    is_udp = True
                else:
                    is_ssl = p.scheme == 'syslogs'
                host = p.hostname
                port = p.port

        if not host or not port:
            print('Enter Syslog connection parameters:')
            host_name = input('...' + 'Syslog host name: '.rjust(32))
            if not host_name:
                raise Exception('Syslog host name is empty')
            host = host_name

            conn_type = input('...' + 'Syslog port type [T]cp/[U]dp. Default TCP: '.rjust(32))
            is_udp = conn_type.lower() in ['u', 'udp']
            port_number = input('...' + 'Syslog port number: '.rjust(32))
            if not port_number:
                raise Exception('Syslog port is empty')
            if not port_number.isdigit():
                raise Exception('Syslog port is a numeric value')
            port = int(port_number)
            if not is_udp:
                has_ssl = input('...' + 'Syslog port requires SSL/TLS (y/N): '.rjust(32))
                is_ssl = has_ssl.lower() == 'y'

            is_new_config = True

        if is_new_config:
            print('Connecting to \'{0}:{1}\' ...'.format(host, port))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if not is_udp else socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                if is_ssl:
                    s = ssl.wrap_socket(sock)
                else:
                    s = sock
                s.connect((host, port))
            record.login_url = 'syslog{0}://{1}:{2}'.format('u' if is_udp else 's' if is_ssl else '', host, port)
            self.store_record = True

        props['is_udp'] = is_udp
        props['is_ssl'] = is_ssl
        props['host'] = host
        props['port'] = port

    def export_events(self, props, events):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if not props['is_udp'] else socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                if props['is_ssl']:
                    s = ssl.wrap_socket(sock)
                else:
                    s = sock
                s.connect((props['host'], props['port']))
                for line in events:
                    s.send(line.encode('utf-8'))
                    s.send(b'\n')
        except:
            self.should_cancel = True


class AuditLogSumologicExport(AuditLogBaseExport):
    def __init__(self):
        AuditLogBaseExport.__init__(self)

    def default_record_title(self):
        return 'Audit Log: Sumologic'

    def get_properties(self, record, props):
        url = record.login_url
        if not url:
            print('Enter HTTP Logs Collector URL.')
            url = input('...' + 'HTTP Collector URL: '.rjust(32))
            if not url:
                raise Exception('HTTP Collector URL is required.')
            record.login_url = url
            self.store_record = True
        props['url'] = record.login_url

    def convert_event(self, props, event):
        evt = event.copy()
        evt.pop('id')
        dt = datetime.datetime.fromtimestamp(evt.pop('created'), tz=datetime.timezone.utc)
        evt['timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        evt['message'] = AuditLogBaseExport.get_event_message(evt)
        return json.dumps(evt, separators=(',', ':'))

    def export_events(self, props, events):
        str = '\n'.join(events)

        headers = {"Content-type": "application/text"}
        rs = requests.post(props['url'], data=str.encode('utf-8'), headers=headers)
        if rs.status_code == 200:
            self.store_record = True
        else:
            self.should_cancel = True

    def chunk_size(self):
        return 250


class AuditLogJsonExport(AuditLogBaseExport):
    def __init__(self):
        AuditLogBaseExport.__init__(self)
        
    def default_record_title(self):
        return 'Audit Log: JSON'

    def get_properties(self, record, props):
        filename = record.login
        if not filename:
            filename = input('JSON File name: ')
            if not filename:
                return
            record.login = filename
            self.store_record = True
        props['filename'] = record.login

        with open(filename, mode='w') as logf:
            json.dump([], logf)

    def convert_event(self, props, event):
        dt = datetime.datetime.fromtimestamp(event['created'], tz=datetime.timezone.utc)
        evt = event.copy()
        evt.pop('id')
        evt.pop('created')
        evt['timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        return evt

    def export_events(self, props, events):
        filename = props['filename']

        with open(filename, mode='r') as logf:
            try:
                data = json.load(logf)
                for record in events:
                    data.append(record)
            except ValueError:
                data = events

        with open(filename, mode='w') as logf:
            json.dump(data, logf)


class AuditLogAzureLogAnalyticsExport(AuditLogBaseExport):
    def __init__(self):
        AuditLogBaseExport.__init__(self)

    def default_record_title(self):
        return 'Audit Log: Azure Log Analytics'

    def get_properties(self, record, props):
        wsid = record.login
        if not wsid:
            print('Enter Azure Log Analytics workspace ID.')
            wsid = input('Workspace ID: ')
            if not wsid:
                raise Exception('Workspace ID is required.')
            record.login = wsid
            self.store_record = True
        props['wsid'] = record.login

        wskey = record.password
        if not wskey:
            print('Enter Azure Log Analytics primary or secondary key.')
            wskey = input('Key: ')
            if not wskey:
                raise Exception('Key is required.')
            record.password = wskey
            self.store_record = True
        props['wskey'] = record.password

    def convert_event(self, props, event):
        evt = event.copy()
        evt.pop('id')
        dt = datetime.datetime.fromtimestamp(evt.pop('created'), tz=datetime.timezone.utc)
        evt['timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        return evt

    def export_events(self, props, events):
        url = "https://{0}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01".format(props['wsid'])
        data = json.dumps(events)
        dt = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        shared_key = self.build_shared_key(props['wsid'], props['wskey'], len(data), dt)
        headers = {
            "Authorization": "SharedKey {0}".format(shared_key),
            "Content-type": "application/json",
            "Log-Type": "Keeper",
            "x-ms-date": dt
        }
        rs = requests.post(url, data=data.encode('utf-8'), headers=headers)
        if rs.status_code == 200:
            self.store_record = True
        else:
            print(rs.content)
            self.should_cancel = True

    def chunk_size(self):
        return 250

    def build_shared_key(self, wsid, wskey, content_length, date_string):
        string_to_hash = 'POST\n'
        string_to_hash += '{0}\n'.format(str(content_length))
        string_to_hash += 'application/json\n'
        string_to_hash += 'x-ms-date:{0}\n'.format(date_string)
        string_to_hash += '/api/logs'

        bytes_to_hash = string_to_hash.encode('utf-8')
        decoded_key = base64.b64decode(wskey)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode('utf-8')

        return "{0}:{1}".format(wsid, encoded_hash)


class AuditLogCommand(EnterpriseCommand):
    def get_parser(self):
        return audit_log_parser

    def execute(self, params, **kwargs):
        loadSyslogTemplates(params)

        target = kwargs.get('target')

        log_export = None # type: Optional[AuditLogBaseExport]
        if target == 'splunk':
            log_export = AuditLogSplunkExport()
        elif target == 'syslog':
            log_export = AuditLogSyslogFileExport()
        elif target == 'syslog-port':
            log_export = AuditLogSyslogPortExport()
        elif target == 'sumo':
            log_export = AuditLogSumologicExport()
        elif target == 'json':
            log_export = AuditLogJsonExport()
        elif target == 'azure-la':
            log_export = AuditLogAzureLogAnalyticsExport()
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
        count = 0
        logged_ids = set()
        chunk_length = log_export.chunk_size()

        while not finished:
            finished = True
            rq = {
                'command': 'get_audit_event_reports',
                'report_type': 'raw',
                'scope': 'enterprise',
                'limit': 1000,
                'order': 'ascending'
            }

            if last_event_time > 0:
                rq['filter'] = {
                    'created': {'min': last_event_time}
                }

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                finished = True
                if 'audit_event_overview_report_rows' in rs:
                    audit_events = rs['audit_event_overview_report_rows']
                    if len(audit_events) > 1:
                        # remove events from the tail for the last second
                        last_event_time = int(audit_events[-1]['created'])
                        while len(audit_events) > 0:
                            event = audit_events[-1]
                            if int(event['created']) < last_event_time:
                                break
                            audit_events = audit_events[:-1]

                        for event in audit_events:
                            event_id = event['id']
                            if event_id not in logged_ids:
                                logged_ids.add(event_id)
                                events.append(log_export.convert_event(props, event))

                        finished = len(events) == 0

            while len(events) > 0:
                to_store = events[:chunk_length]
                events = events[chunk_length:]
                log_export.export_events(props, to_store)
                if log_export.should_cancel:
                    finished = True
                    break
                count += len(to_store)
                print('+', end='', flush=True)

        if last_event_time > 0:
            logging.info('')
            logging.info('Exported %d audit event(s)', count)
            record.set_field('last_event_time', str(last_event_time))
            params.sync_data = True
            api.update_record(params, record, silent=True)


audit_report_description = '''
Audit Report Command Syntax Description:

Event properties
  id                event ID
  created           event time
  username          user that created audit event
  to_username       user that is audit event target 
  from_username     user that is audit event source 
  ip_address        IP address 
  geo_location      location
  audit_event_type  audit event type
  keeper_version    Keeper application
  channel           2FA channel
  status            Keeper API result_code
  record_uid        Record UID 
  shared_folder_uid Shared Folder UID
  node              Node ID (enterprise events only)
  team_uid          Team UID (enterprise events only)

--report-type: 
            raw     Returns individual events. All event properties are returned.
                    Valid parameters: filters. Ignored parameters: columns, aggregates

  span hour day	    Aggregates audit event by created date. Span drops date aggregation
     week month     Valid parameters: filters, columns, aggregates

            dim     Returns event property description (audit_event_type, keeper_version) or distinct values. 
                    Valid parameters: columns. Ignored parameters: filters, aggregates

--columns:          Defines break down report properties.
                    can be any event property except: id, created

--aggregates:       Defines the aggregate value: 
     occurrences    number of events. COUNT(*)
   first_created    starting date. MIN(created)
    last_created    ending date. MAX(created)

--limit:            Limits the number of returned records

--order:            "desc" or "asc"
                    raw report type: created
                    aggregate reports: first aggregate

Filters             Supported: '=', '>', '<', '>=', '<=', 'IN(<>,<>,<>)'. Default '='
--created           Predefined ranges: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year
                    Range 'BETWEEN <> AND <>'
                    where value is UTC date or epoch time in seconds
--event-type        Audit Event Type.  Value is event id or event name
--username          Email
--to-username
--record-uid	    Record UID
--shared-folder-uid Shared Folder UID
'''

in_pattern = re.compile(r"\s*in\s*\(\s*(.*)\s*\)", re.IGNORECASE)
between_pattern = re.compile(r"\s*between\s+(\S*)\s+and\s+(.*)", re.IGNORECASE)


class AuditReportCommand(Command):
    def __init__(self):
        self.team_lookup = None
        self.role_lookup = None
        self.node_lookup = None

    def get_value(self, params, field, event):
        if field == 'message':
            message = ''
            if event['audit_event_type'] in syslog_templates:
                info = syslog_templates[event['audit_event_type']]
                while True:
                    pattern = re.search('\$\{(\w+)\}', info)
                    if pattern:
                        token = pattern[1]
                        val = self.get_value(params, token, event) if field != token else None
                        if val is None:
                            logging.error('Event value is missing: %s', pattern[1])
                            val = '<missing>'

                        sp = pattern.span()
                        info = info[:sp[0]] + str(val) + info[sp[1]:]
                    else:
                        break
                message = info
            return message

        elif field in event:
            val = event.get(field)
            if field == 'team_uid':
                val = self.resolve_team_name(params, val)
            elif field == 'role_id':
                val = self.resolve_role_name(params, val)
            elif field == 'node':
                val = self.resolve_node_name(params, val)
            return val
        return ''

    def resolve_team_name(self, params, team_uid):
        if self.team_lookup is None:
            self.team_lookup = {}
            if params.enterprise:
                if 'teams' in params.enterprise:
                    for team in params.enterprise['teams']:
                        if 'team_uid' in team and 'name' in team:
                            self.team_lookup[team['team_uid']] = team['name']
        if team_uid in self.team_lookup:
            return '{0} ({1})'.format(self.team_lookup[team_uid], team_uid)
        return team_uid

    def resolve_role_name(self, params, role_id):
        if self.role_lookup is None:
            self.role_lookup = {}
            if params.enterprise:
                if 'roles' in params.enterprise:
                    for role in params.enterprise['roles']:
                        if 'role_id' in role:
                            id = str(role['role_id'])
                            name = role['data'].get('displayname')
                            if name:
                                self.role_lookup[id] = name
        if role_id in self.role_lookup:
            return '{0} ({1})'.format(self.role_lookup[role_id], role_id)
        return role_id

    def resolve_node_name(self, params, node_id):
        if self.node_lookup is None:
            self.node_lookup = {}
            if params.enterprise:
                if 'nodes' in params.enterprise:
                    for node in params.enterprise['nodes']:
                        if 'node_id' in node:
                            id = str(node['node_id'])
                            name = node['data'].get('displayname') or params.enterprise['enterprise_name']
                            if name:
                                self.node_lookup[id] = name
        id = str(node_id)
        if id in self.node_lookup:
            return '{0} ({1})'.format(self.node_lookup[id], id)
        return id

    def get_parser(self):
        return audit_report_parser

    @staticmethod
    def convert_value(field, value, **kwargs):
        if not value:
            return ''

        if field == "created":
            dt = datetime.datetime.utcfromtimestamp(int(value)).replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
            rt = kwargs.get('report_type') or ''
            if rt in {'day', 'week'}:
                dt = dt.date()
            elif rt == 'month':
                dt = dt.strftime('%B, %Y')
            elif rt == 'hour':
                dt = dt.strftime('%Y-%m-%d @%H:00')

            return dt
        elif field in {"first_created", "last_created"}:
            return datetime.datetime.utcfromtimestamp(int(value)).replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
        else:
            return value

    def execute(self, params, **kwargs):
        loadSyslogTemplates(params)

        if kwargs.get('syntax_help'):
            logging.info(audit_report_description)
            return
        if not kwargs['report_type']:
            logging.error('report-type parameter is missing')
            return
        report_type = kwargs['report_type']
        rq = {
            'report_type': report_type,
            'scope': 'enterprise' if params is not None else 'user'
        }
        if report_type == 'dim':
            rq['command'] = 'get_audit_event_dimensions'
        else:
            rq['command'] = 'get_audit_event_reports' if params.enterprise else 'get_audit_event_reports'

        if kwargs.get('timezone'):
            rq['timezone'] = kwargs['timezone']
        else:
            tt = time.tzname
            if tt:
                if time.daylight < len(tt):
                    rq['timezone'] = tt[time.daylight]
                else:
                    rq['timezone'] = tt[0]
            else:
                now = time.time()
                utc_offset = datetime.datetime.fromtimestamp(now) - datetime.datetime.utcfromtimestamp(now)
                hours = (utc_offset.days * 24) + int(utc_offset.seconds / 60 / 60)
                rq['timezone'] = hours

        columns = []
        if report_type != 'raw' and kwargs.get('columns'):
            columns = kwargs['columns']
            rq['columns'] = columns
        if report_type == 'dim' and len(columns) == 0:
            logging.error("'columns' parameter is missing")
            return

        aggregates = []
        if report_type not in {'raw', 'dim'} and kwargs.get('aggregate'):
            if kwargs.get('aggregate'):
                aggregates = kwargs['aggregate']
                rq['aggregate'] = aggregates

        if kwargs.get('limit'):
            rq['limit'] = kwargs['limit']
        else:
            rq['limit'] = 50

        if kwargs.get('order'):
            rq['order'] = 'ascending' if kwargs['order'] == 'asc' else 'descending'

        filter = {}
        if kwargs['created']:
            if kwargs['created'] in ['today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month', 'year_to_date', 'last_year']:
                filter['created'] = kwargs['created']
            else:
                filter['created'] = self.get_filter(kwargs['created'], AuditReportCommand.convert_date)
        if kwargs['event_type']:
            filter['audit_event_type'] = self.get_filter(kwargs['event_type'], AuditReportCommand.convert_str_or_int)
        if kwargs['username']:
            filter['username'] = self.get_filter(kwargs['username'], AuditReportCommand.convert_str)
        if kwargs['to_username']:
            filter['to_username'] = self.get_filter(kwargs['to_username'], AuditReportCommand.convert_str)
        if kwargs['record_uid']:
            filter['record_uid'] = self.get_filter(kwargs['record_uid'], AuditReportCommand.convert_str)
        if kwargs['shared_folder_uid']:
            filter['shared_folder_uid'] = self.get_filter(kwargs['shared_folder_uid'], AuditReportCommand.convert_str)

        if filter:
            rq['filter'] = filter

        rs = api.communicate(params, rq)
        fields = []
        table = []

        if report_type == 'raw':
            fields.extend(['created', 'audit_event_type', 'username', 'ip_address', 'keeper_version', 'geo_location'])
            misc_fields = ['to_username', 'from_username', 'record_uid', 'shared_folder_uid', 'node',
                           'channel', 'status'] if kwargs.get('report_format') == 'fields' else ['message']

            for event in rs['audit_event_overview_report_rows']:
                if misc_fields:
                    lenf = len(fields)
                    for mf in misc_fields:
                        if mf == 'message':
                            fields.append(mf)
                        elif mf in event:
                            val = event.get(mf)
                            if val:
                                fields.append(mf)
                    if len(fields) > lenf:
                        for f in fields[lenf:]:
                            misc_fields.remove(f)

                row = []
                for field in fields:
                    value = self.get_value(params, field, event)
                    row.append(self.convert_value(field, value))
                table.append(row)
            print(tabulate(table, headers=fields))

        elif report_type == 'dim':
            for dim in rs['dimensions']:
                print('\n{0}\n'.format(dim))
                if dim in {'audit_event_type', 'keeper_version', 'ip_address'}:
                    if dim == 'audit_event_type':
                        fields = ['id', 'name', 'category', 'syslog']
                    elif dim == 'keeper_version':
                        fields = ['version_id', 'type_id', 'type_name', 'type_category']
                    elif dim == 'ip_address':
                        fields = ['ip_address', 'city', 'region', 'country_code']
                    table = []
                    for row in rs['dimensions'][dim]:
                        table.append([row.get(x) for x in fields])
                    print(tabulate(table, headers=fields))
                else:
                    for row in rs['dimensions'][dim]:
                        print(row)

        else:
            if aggregates:
                fields.extend(aggregates)
            else:
                fields.append('occurrences')
            if report_type != 'span':
                fields.append('created')
            if columns:
                fields.extend(columns)
            for event in rs['audit_event_overview_report_rows']:
                row = []
                for f in fields:
                    row.append(self.convert_value(f, event.get(f), report_type=report_type))
                table.append(row)
            print(tabulate(table, headers=fields))

    @staticmethod
    def convert_date(value):
        if not value.isdigit():
            if len(value) <= 10:
                value = datetime.datetime.strptime(value, '%Y-%m-%d')
            else:
                value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
            value = value.timestamp()
        return int(value)

    @staticmethod
    def convert_int(value):
        return int(value)

    @staticmethod
    def convert_str(value):
        return value

    @staticmethod
    def convert_str_or_int(value):
        if value.isdigit():
            return int(value)
        else:
            return value

    @staticmethod
    def get_filter(filter_value, convert):
        filter_value = filter_value.strip()
        bet = between_pattern.match(filter_value)
        if bet is not None:
            dt1, dt2, *_ = bet.groups()
            dt1 = convert(dt1)
            dt2 = convert(dt2)
            return {'min': dt1, 'max': dt2}

        inp = in_pattern.match(filter_value)
        if inp is not None:
            arr = []
            for v in inp.groups()[0].split(','):
                arr.append(convert(v.strip()))
            return arr

        for prefix in ['>=', '<=', '>', '<', '=']:
            if filter_value.startswith(prefix):
                value = convert(filter_value[len(prefix):].strip())
                if prefix == '>=':
                    return {'min': value}
                if prefix == '<=':
                    return {'max': value}
                if prefix == '>':
                    return {'min': value, 'exclude_min': True}
                if prefix == '<':
                    return {'max': value, 'exclude_max': True}
                return value

        return convert(filter_value)


enterprise_push_description = '''
Template record file example:

[
    {
        "title": "Record For ${user_name}",
        "login": "${user_email}",
        "password": "${generate_password}",
        "login_url": "",
        "notes": "",
        "custom_fields": {
            "key1": "value1",
            "key2": "value2"
        }
    }
]


Supported template parameters:

    ${user_email}            User email address
    ${generate_password}     Generate random password
    ${user_name}             User name

'''
parameter_pattern = re.compile(r'\${(\w+)}')


class EnterprisePushCommand(EnterpriseCommand):

    @staticmethod
    def substitute_field_params(field, values):
        # type: (str, dict) -> str
        global parameter_pattern
        value = field
        while True:
            m = parameter_pattern.search(value)
            if not m:
                break
            p = m.group(1)
            pv = values.get(p) or p
            value = value[:m.start()] + pv + value[m.end():]
        return value

    @staticmethod
    def enumerate_and_substitute_list_values(container, values):
        # type: (list, dict) -> list
        result = []
        for p in container:
            if type(p) == str:
                value = EnterprisePushCommand.substitute_field_params(p, values)
                result.append(value)
            elif type(p) == dict:
                EnterprisePushCommand.enumerate_and_substitute_dict_fields(p, values)
                result.append(p)
            elif type(p) == list:
                result.append(EnterprisePushCommand.enumerate_and_substitute_list_values(p, values))
            else:
                result.append(p)
        return result

    @staticmethod
    def enumerate_and_substitute_dict_fields(container, values):
        # type: (dict, dict) -> None
        for p in container.items():
            if type(p[1]) == str:
                value = EnterprisePushCommand.substitute_field_params(p[1], values)
                if p[1] != value:
                    container[p[0]] = value
            elif type(p[1]) == dict:
                EnterprisePushCommand.enumerate_and_substitute_dict_fields(p[1], values)
            elif type(p[1]) == list:
                container[p[0]] = EnterprisePushCommand.enumerate_and_substitute_list_values(p[1], values)

    @staticmethod
    def substitute_record_params(params, email, record_data):
        # type: (KeeperParams, str, dict) -> None

        values = {
            'user_email': email,
            'generate_password': generate(length=32)
        }
        for u in params.enterprise['users']:
            if u['username'].lower() == email.lower():
                values['user_name'] = u['data'].get('displayname') or ''
                break

        EnterprisePushCommand.enumerate_and_substitute_dict_fields(record_data, values)

    def get_parser(self):
        return enterprise_push_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(enterprise_push_description)
            return

        name = kwargs.get('file') or ''
        if not name:
            logging.error('The template file name arguments are required')
            return

        template_records = None
        file_name = os.path.abspath(os.path.expanduser(name))
        if os.path.isfile(file_name):
            with open(file_name, 'r') as f:
                template_records = json.load(f)
        else:
            logging.error('File %s does not exists', name)
            return

        emails = {}
        users = kwargs.get('user')
        if type(users) is list:
            for user in users:
                user_email = None
                for u in params.enterprise['users']:
                    if user.lower() in [u['username'].lower(), (u['data'].get('displayname') or '').lower(), str(u['enterprise_user_id'])]:
                        user_email = u['username']
                        break
                if user_email:
                    if user_email.lower() != params.user.lower():
                        emails[user_email] = None
                else:
                    logging.warning('Cannot find user %s', user)

        teams = kwargs.get('team')
        if type(teams) is list:
            users_map = {}
            for u in params.enterprise['users']:
                users_map[u['enterprise_user_id']] = u['username']
            users_in_team = {}

            if 'team_users' in params.enterprise:
                for tu in params.enterprise['team_users']:
                    team_uid = tu['team_uid']
                    if not team_uid in users_in_team:
                        users_in_team[team_uid] = []
                    if tu['enterprise_user_id'] in users_map:
                        users_in_team[team_uid].append(users_map[tu['enterprise_user_id']])

            for team in teams:
                team_uid = None
                if team in params.enterprise['teams']:
                    team_uid = team_uid
                else:
                    for t in params.enterprise['teams']:
                        if team.lower() == t['name'].lower():
                            team_uid = t['team_uid']
                if team_uid:
                    if team_uid in users_in_team:
                        for user_email in users_in_team[team_uid]:
                            if user_email.lower() != params.user.lower():
                                emails[user_email] = None
                else:
                    logging.warning('Cannot find team %s', team)

        if len(emails) == 0:
            logging.warning('No users')
            return

        self.get_public_keys(params, emails)
        commands = []
        record_keys = {}
        for email in emails:
            if emails[email]:
                record_keys[email] = {}
                if template_records:
                    for r in template_records:
                        record = copy.deepcopy(r)
                        EnterprisePushCommand.substitute_record_params(params, email, record)
                        record_uid = api.generate_record_uid()
                        record_key = api.generate_aes_key()
                        record_add_command = {
                            'command': 'record_add',
                            'record_uid': record_uid,
                            'record_type': 'password',
                            'record_key': api.encrypt_aes(record_key, params.data_key),
                            'folder_type': 'user_folder',
                            'how_long_ago': 0
                        }

                        data = {
                            'title': record.get('title') or '',
                            'secret1': record.get('login') or '',
                            'secret2': record.get('password') or '',
                            'link': record.get('login_url') or '',
                            'notes': record.get('notes') or ''
                        }
                        if 'custom_fields' in record:
                            data['custom'] = [{
                                'name': x[0],
                                'value': x[1]
                            } for x in record['custom_fields'].items()]
                        record_add_command['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key)
                        commands.append(record_add_command)

                        record_keys[email][record_uid] = api.encrypt_rsa(record_key, emails[email])
            else:
                logging.warning('User %s is not created yet', email)

        transfers = []
        for email in record_keys:
            for record_uid, record_key in record_keys[email].items():
                transfers.append({
                    'to_username': email,
                    'record_uid': record_uid,
                    'record_key': record_key,
                    'transfer': True
                })

        while transfers:
            chunk = transfers[:90]
            transfers = transfers[90:]
            commands.append({
                'command': 'record_share_update',
                'pt': 'Commander',
                'add_shares': chunk
            })

        api.execute_batch(params, commands)

        params.sync_data = True


