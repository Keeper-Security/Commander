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
import copy
import datetime
import ipaddress
import itertools
import json
import logging
import os
import re
import string
import time
from argparse import RawTextHelpFormatter
from collections import OrderedDict as OD
from typing import Set, Dict, Any, Union, List

from asciitree import LeftAligned
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import aram  # audit_report_parser, audit_log_parser, AuditLogCommand, AuditReportCommand
from . import compliance
from .aram import ActionReportCommand
from .base import user_choice, suppress_exit, raise_parse_exception, dump_report_data, Command
from .enterprise_common import EnterpriseCommand
from .scim import ScimCommand
from .transfer_account import EnterpriseTransferUserCommand, transfer_user_parser
from .. import api, rest_api, crypto, utils, constants
from ..display import bcolors
from ..error import CommandError
from ..generator import generate
from ..params import KeeperParams
from ..proto import record_pb2 as record_proto
from ..proto.APIRequest_pb2 import (UserDataKeyRequest, UserDataKeyResponse, SecurityReportRequest,
                                    SecurityReportResponse)
from ..proto.enterprise_pb2 import (EnterpriseUserIds, ApproveUserDeviceRequest, ApproveUserDevicesRequest,
                                    ApproveUserDevicesResponse, EnterpriseUserDataKeys, SetRestrictVisibilityRequest)


def register_commands(commands):
    commands['enterprise-down'] = GetEnterpriseDataCommand()
    commands['enterprise-info'] = EnterpriseInfoCommand()
    commands['enterprise-node'] = EnterpriseNodeCommand()
    commands['enterprise-user'] = EnterpriseUserCommand()
    commands['enterprise-role'] = EnterpriseRoleCommand()
    commands['enterprise-team'] = EnterpriseTeamCommand()
    commands['enterprise-push'] = EnterprisePushCommand()
    commands['team-approve'] = TeamApproveCommand()
    commands['device-approve'] = DeviceApproveCommand()
    commands['scim'] = ScimCommand()
    commands['transfer-user'] = EnterpriseTransferUserCommand()

    commands['audit-log'] = aram.AuditLogCommand()
    commands['audit-report'] = aram.AuditReportCommand()
    commands['aging-report'] = aram.AgingReportCommand()
    commands['security-audit-report'] = SecurityAuditReportCommand()
    commands['user-report'] = UserReportCommand()
    commands['action-report'] = ActionReportCommand()

    compliance.register_commands(commands)


def register_command_info(aliases, command_info):
    aliases['al'] = 'audit-log'
    aliases['ed'] = 'enterprise-down'
    aliases['ei'] = 'enterprise-info'
    aliases['en'] = 'enterprise-node'
    aliases['eu'] = 'enterprise-user'
    aliases['er'] = 'enterprise-role'
    aliases['et'] = 'enterprise-team'
    aliases['sar'] = 'security-audit-report'
    aliases['tu'] = 'transfer-user'

    for p in [enterprise_data_parser, enterprise_info_parser, enterprise_node_parser, enterprise_user_parser,
              enterprise_role_parser, enterprise_team_parser, transfer_user_parser,
              enterprise_push_parser, team_approve_parser, device_approve_parser,
              aram.audit_log_parser, aram.audit_report_parser, aram.aging_report_parser, aram.action_report_parser,
              security_audit_report_parser, user_report_parser]:
        command_info[p.prog] = p.description

    compliance.register_command_info(aliases, command_info)

SUPPORTED_NODE_COLUMNS = ['parent_node', 'user_count', 'users', 'team_count', 'teams', 'role_count', 'roles']
SUPPORTED_USER_COLUMNS = ['name', 'status', 'transfer_status', 'node', 'team_count', 'teams', 'role_count', 'roles']
SUPPORTED_TEAM_COLUMNS = ['restricts', 'node', 'user_count', 'users', 'queued_user_count', 'queued_users']
SUPPORTED_ROLE_COLUMNS = ['visible_below', 'default_role', 'admin', 'node', 'user_count', 'users']

enterprise_data_parser = argparse.ArgumentParser(prog='enterprise-down|ed',
                                                 description='Download & decrypt enterprise data.')

enterprise_info_parser = argparse.ArgumentParser(prog='enterprise-info|ei',
                                                 description='Display a tree structure of your enterprise.',
                                                 formatter_class=RawTextHelpFormatter)
enterprise_info_parser.add_argument('-n', '--nodes', dest='nodes', action='store_true', help='print node tree')
enterprise_info_parser.add_argument('-u', '--users', dest='users', action='store_true', help='print user list')
enterprise_info_parser.add_argument('-t', '--teams', dest='teams', action='store_true', help='print team list')
enterprise_info_parser.add_argument('-r', '--roles', dest='roles', action='store_true', help='print role list')
enterprise_info_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_info_parser.add_argument('--node', dest='node', action='store', help='limit results to node (name or ID)')
enterprise_info_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                    default='table', help='output format. applicable to users, teams, and roles.')
enterprise_info_parser.add_argument('--output', dest='output', action='store',
                                    help='output file name. (ignored for table format)')
enterprise_info_parser.add_argument('--columns', dest='columns', action='store',
                                    help='comma-separated list of available columns per argument:' +
                                         '\n for `nodes` (%s)' % ', '.join(SUPPORTED_NODE_COLUMNS) +
                                         '\n for `users` (%s)' % ', '.join(SUPPORTED_USER_COLUMNS) +
                                         '\n for `teams` (%s)' % ', '.join(SUPPORTED_TEAM_COLUMNS) +
                                         '\n for `roles` (%s)' % ', '.join(SUPPORTED_ROLE_COLUMNS)
                                    )

enterprise_info_parser.add_argument('pattern', nargs='?', type=str,
                                    help='search pattern. applicable to users, teams, and roles.')
enterprise_info_parser.error = raise_parse_exception
enterprise_info_parser.exit = suppress_exit


enterprise_node_parser = argparse.ArgumentParser(prog='enterprise-node|en', description='Manage an enterprise node(s).')
enterprise_node_parser.add_argument('--wipe-out', dest='wipe_out', action='store_true', help='wipe out node content')
enterprise_node_parser.add_argument('--add', dest='add', action='store_true', help='create node')
enterprise_node_parser.add_argument('--parent', dest='parent', action='store', help='Parent Node Name or ID')
enterprise_node_parser.add_argument('--name', dest='displayname', action='store', help='set node display name')
enterprise_node_parser.add_argument('--delete', dest='delete', action='store_true', help='delete node')
enterprise_node_parser.add_argument('--toggle-isolated', dest='toggle_isolated', action='store_true', help='Render node invisible')
enterprise_node_parser.add_argument('node', type=str, nargs='+', help='Node Name or ID. Can be repeated.')
enterprise_node_parser.error = raise_parse_exception
enterprise_node_parser.exit = suppress_exit


enterprise_user_parser = argparse.ArgumentParser(prog='enterprise-user|eu', description='Manage an enterprise user(s).')
enterprise_user_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_user_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_user_parser.add_argument('--expire', dest='expire', action='store_true', help='expire master password')
enterprise_user_parser.add_argument('--extend', dest='extend', action='store_true',
                                    help='extend vault transfer consent by 7 days. Supports the following pseudo users: @all')
enterprise_user_parser.add_argument('--lock', dest='lock', action='store_true', help='lock user')
enterprise_user_parser.add_argument('--unlock', dest='unlock', action='store_true', help='unlock user. Supports the following pseudo users: @all')
enterprise_user_parser.add_argument('--disable-2fa', dest='disable_2fa', action='store_true', help='disable 2fa for user')
enterprise_user_parser.add_argument('--add', dest='add', action='store_true', help='invite user. same as --invite')
enterprise_user_parser.add_argument('--invite', dest='invite', action='store_true', help='invite user')
enterprise_user_parser.add_argument('--delete', dest='delete', action='store_true', help='delete user')
enterprise_user_parser.add_argument('--name', dest='displayname', action='store', help='set user display name')
enterprise_user_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
enterprise_user_parser.add_argument('--add-role', dest='add_role', action='append', help='role name or role ID')
enterprise_user_parser.add_argument('--remove-role', dest='remove_role', action='append', help='role name or role ID')
enterprise_user_parser.add_argument('--add-team', dest='add_team', action='append', help='team name or team UID')
enterprise_user_parser.add_argument('-hsf', '--hide-shared-folders', dest='hide_shared_folders', action='store',
                                    choices=['on', 'off'], help='User does not see shared folders. --add-team only')
enterprise_user_parser.add_argument('--remove-team', dest='remove_team', action='append', help='team name or team UID')
enterprise_user_parser.add_argument('email', type=str, nargs='+', help='User Email or ID. Can be repeated.')
enterprise_user_parser.error = raise_parse_exception
enterprise_user_parser.exit = suppress_exit


enterprise_role_parser = argparse.ArgumentParser(prog='enterprise-role|er', description='Manage an enterprise role(s).')
#enterprise_role_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_role_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_role_parser.add_argument('--format', dest='format', action='store', choices=['text', 'json'],
                                    default='table', help='output format.')
enterprise_role_parser.add_argument('--output', dest='output', action='store',
                                    help='output file name. (ignored for table format)')
enterprise_role_parser.add_argument('--add', dest='add', action='store_true', help='create role')
enterprise_role_parser.add_argument('--copy', dest='copy', action='store_true', help='copy role with enforcements')
enterprise_role_parser.add_argument('--clone', dest='clone', action='store_true', help='copy role with users and enforcements')
#enterprise_role_parser.add_argument('--visible-below', dest='visible_below', action='store', choices=['on', 'off'], help='visible to all nodes. \'add\' only')
enterprise_role_parser.add_argument('--new-user', dest='new_user', action='store', choices=['on', 'off'], help='assign this role to new users. \'add\' only')
enterprise_role_parser.add_argument('--delete', dest='delete', action='store_true', help='delete role')
enterprise_role_parser.add_argument('--node', dest='node', action='store', help='node Name or ID')
enterprise_role_parser.add_argument('--name', dest='name', action='store', help='role\'s new name')
enterprise_role_parser.add_argument('-au', '--add-user', action='append', metavar='EMAIL', help='add user to role')
enterprise_role_parser.add_argument('-ru', '--remove-user', action='append', metavar='EMAIL', help='remove user from role')
enterprise_role_parser.add_argument('-at', '--add-team', action='append', metavar='TEAM', help='add team to role')
enterprise_role_parser.add_argument('-rt', '--remove-team', action='append', metavar='TEAM', help='remove team from role')
enterprise_role_parser.add_argument('-aa', '--add-admin', action='append', metavar='NODE', help='add managed node to role')
enterprise_role_parser.add_argument('-ra', '--remove-admin', action='append', metavar='NODE', help='remove managed node from role')
enterprise_role_parser.add_argument('-ap', '--add-privilege', dest='add_privilege', action='append',
                                    metavar='PRIVILEGE', help='add privilege to managed node')
enterprise_role_parser.add_argument('-rp', '--remove-privilege', dest='remove_privilege', action='append',
                                    metavar='PRIVILEGE', help='remove privilege from managed node')
enterprise_role_parser.add_argument('--enforcement', dest='enforcements', action='append', metavar='KEY:VALUE',
                                    help='sets role enforcement')
enterprise_role_parser.add_argument('--cascade', dest='cascade', action='store', choices=['on', 'off'],
                                    help='apply to the children nodes. \'add-admin\' only')
enterprise_role_parser.add_argument('role', type=str, nargs='+', help='Role Name or ID. Can be repeated.')
enterprise_role_parser.error = raise_parse_exception
enterprise_role_parser.exit = suppress_exit


enterprise_team_parser = argparse.ArgumentParser(prog='enterprise-team|et', description='Manage an enterprise team(s).')
enterprise_team_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_team_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_team_parser.add_argument('--add', dest='add', action='store_true', help='create team')
enterprise_team_parser.add_argument('--approve', dest='approve', action='store_true', help='approve queued team')
enterprise_team_parser.add_argument('--delete', dest='delete', action='store_true', help='delete team')
enterprise_team_parser.add_argument('-au', '--add-user', action='append', help='add user to team')
enterprise_team_parser.add_argument('-ru', '--remove-user', action='append', help='remove user from team')
enterprise_team_parser.add_argument('-ar', '--add-role', action='append', help='add user to team')
enterprise_team_parser.add_argument('-rr', '--remove-role', action='append', help='remove user from team')
enterprise_team_parser.add_argument('-hsf', '--hide-shared-folders', dest='hide_shared_folders', action='store',
                                    choices=['on', 'off'], help='User does not see shared folders. --add-user only')
enterprise_team_parser.add_argument('--restrict-edit', dest='restrict_edit', choices=['on', 'off'], action='store', help='disable record edits')
enterprise_team_parser.add_argument('--restrict-share', dest='restrict_share', choices=['on', 'off'], action='store', help='disable record re-shares')
enterprise_team_parser.add_argument('--restrict-view', dest='restrict_view', choices=['on', 'off'], action='store', help='disable view/copy passwords')
enterprise_team_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
enterprise_team_parser.add_argument('--name', dest='name', action='store', help='team\'s new name')
enterprise_team_parser.add_argument('team', type=str, nargs='+', help='Team Name or UID')
enterprise_team_parser.error = raise_parse_exception
enterprise_team_parser.exit = suppress_exit

team_approve_parser = argparse.ArgumentParser(prog='team-approve', description='Enable or disable automated team and user approval.')
team_approve_parser.add_argument('--team', dest='team', action='store_true', help='Approve teams only.')
team_approve_parser.add_argument('--email', dest='user', action='store_true', help='Approve team users only.')
team_approve_parser.add_argument('--restrict-edit', dest='restrict_edit', choices=['on', 'off'], action='store', help='disable record edits')
team_approve_parser.add_argument('--restrict-share', dest='restrict_share', choices=['on', 'off'], action='store', help='disable record re-shares')
team_approve_parser.add_argument('--restrict-view', dest='restrict_view', choices=['on', 'off'], action='store', help='disable view/copy passwords')
team_approve_parser.error = raise_parse_exception
team_approve_parser.exit = suppress_exit

device_approve_parser = argparse.ArgumentParser(prog='device-approve', description='Approve Cloud SSO Devices.')
device_approve_parser.add_argument('--reload', '-r', dest='reload', action='store_true', help='reload list of pending approval requests')
device_approve_parser.add_argument('--approve', '-a', dest='approve', action='store_true', help='approve user devices')
device_approve_parser.add_argument('--deny', '-d', dest='deny', action='store_true', help='deny user devices')
device_approve_parser.add_argument('--trusted-ip', dest='check_ip', action='store_true', help='approve only devices coming from a trusted IP address')
device_approve_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                    default='table', help='Output format. Applicable to list of devices in the queue.')
device_approve_parser.add_argument('--output', dest='output', action='store',
                                    help='Output file name (ignored for table format)')
device_approve_parser.add_argument('device', type=str, nargs='?', action="append", help='User email or device ID')
device_approve_parser.error = raise_parse_exception
device_approve_parser.exit = suppress_exit

scim_parser = argparse.ArgumentParser(prog='scim', description='Manage SCIM endpoints.')
scim_parser.add_argument('command', type=str, nargs='?', help='SCIM Command. list, view, create, edit, delete')
scim_parser.add_argument('target', type=str, nargs='?', help='SCIM ID or Name. Command: view, edit, delete')
scim_parser.add_argument('--reload', '-r', dest='reload', action='store_true', help='Reload list of scim endpoints')
scim_parser.add_argument('--force', '-f', dest='force', action='store_true', help='Delete with no confirmation')
scim_parser.add_argument('--node', dest='node', help='Node Name or ID. Command: create')
scim_parser.add_argument('--prefix', dest='prefix', action='store',
                         help='Role Prefix. Command: create, edit. '
                              'SCIM groups staring with prefix will be imported to Keeper as Roles')
scim_parser.add_argument('--unique-groups', dest='unique_groups', action='store_true',
                         help='Unique Groups. Command: create, edit')
scim_parser.error = raise_parse_exception
scim_parser.exit = suppress_exit

enterprise_push_parser = argparse.ArgumentParser(prog='enterprise-push', description='Populate user\'s vault with default records')
enterprise_push_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='Display help on file format and template parameters.')
enterprise_push_parser.add_argument('--team', dest='team', action='append', help='Team name or team UID. Records will be assigned to all users in the team.')
enterprise_push_parser.add_argument('--email', dest='user', action='append', help='User email or User ID. Records will be assigned to the user.')
enterprise_push_parser.add_argument('file', nargs='?', type=str, action='store', help='File name in JSON format that contains template records.')
enterprise_push_parser.error = raise_parse_exception
enterprise_push_parser.exit = suppress_exit


security_audit_report_parser = argparse.ArgumentParser(prog='security-audit-report', description='Run a security audit report.')
security_audit_report_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
security_audit_report_parser.add_argument('-b', '--breachwatch', dest='breachwatch', action='store_true', help='display BreachWatch report')
security_audit_report_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table', help='output format.')
security_audit_report_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
security_audit_report_parser.error = raise_parse_exception
security_audit_report_parser.exit = suppress_exit


user_report_parser = argparse.ArgumentParser(prog='user-report', description='Run a user report.')
user_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json', 'csv'], default='table', help='output format.')
user_report_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
user_report_parser.add_argument('--days', dest='days', action='store', type=int, default=365,
                                help='number of days to look back for last login (set to <= 0 to disable limit).')
user_report_parser.add_argument('-l', '--last-login', dest='last_login', action='store_true',
                                help='simplify report to include only last-login-related info')
user_report_parser.error = raise_parse_exception
user_report_parser.exit = suppress_exit


def get_user_status_dict(user):

    def lock_text(lock):
        return 'Locked' if lock == 1 else 'Disabled' if lock == 2 else ''

    account_status = 'Invited' if user['status'] == 'invited' else 'Active'

    if user['lock'] > 0:
        account_status = lock_text(user['lock'])

    acct_transfer_status = ''

    if 'account_share_expiration' in user:
        expire_at = datetime.datetime.fromtimestamp(user['account_share_expiration']/1000.0)
        if expire_at < datetime.datetime.now():
            acct_transfer_status = 'Blocked'
        else:
            acct_transfer_status = 'Pending Transfer'
    return {
        'acct_status': account_status,
        'acct_transfer_status': acct_transfer_status
    }


class GetEnterpriseDataCommand(Command):
    def get_parser(self):
        return enterprise_data_parser

    def execute(self, params, **kwargs):
        api.query_enterprise(params)


class EnterpriseInfoCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_info_parser

    def execute(self, params, **kwargs):

        print('Enterprise name: {0}'.format(params.enterprise['enterprise_name']))

        user_managed_nodes = set(self.get_user_managed_nodes(params))
        node_scope = set()
        if kwargs.get('node'):
            subnode = kwargs.get('node').lower()
            root_nodes = [x['node_id'] for x in self.resolve_nodes(params, subnode) if x['node_id'] in user_managed_nodes]
            if len(root_nodes) == 0:
                logging.warning('Node \"%s\" not found', subnode)
                return
            if len(root_nodes) > 1:
                logging.warning('More than one node \"%s\" found. Use Node ID.', subnode)
                return
            logging.info('Output is limited to \"%s\" node', subnode)

            node_tree = {}
            for node in params.enterprise['nodes']:
                parent_id = node.get('parent_id')
                if parent_id not in node_tree:
                    node_tree[parent_id] = []
                node_tree[parent_id].append(node['node_id'])

            nl = [x for x in root_nodes]
            pos = 0
            while pos < len(nl):
                if nl[pos] in node_tree:
                    nl.extend(node_tree[nl[pos]])
                pos += 1
                if pos > 100:
                    break
            node_scope.update([x for x in nl if x in user_managed_nodes])
        else:
            node_scope.update((x['node_id'] for x in params.enterprise['nodes'] if x['node_id'] in user_managed_nodes))
            root_nodes = list(self.get_user_root_nodes(params))

        nodes = {}
        for node in params.enterprise['nodes']:
            node_id = node['node_id']
            if node_id not in node_scope:
                continue

            nodes[node_id] = {
                'node_id': node_id,
                'parent_id': node.get('parent_id') or 0,
                'name': node['data'].get('displayname') or '',
                'isolated': node.get('restrict_visibility') or False,
                'users': [],
                'teams': [],
                'queued_teams': [],
                'roles': [],
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
                    'username': user['username'] if 'username' in user else '[none]',
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
                    'users': [],
                    'queued_users': [],
                }
                if node_id in nodes:
                    nodes[node_id]['teams'].append(team_id)

        if 'team_users' in params.enterprise:
            for tu in params.enterprise['team_users']:
                team_uid = tu['team_uid']
                if tu['team_uid'] in teams:
                    user_id = tu['enterprise_user_id']
                    teams[team_uid]['users'].append(user_id)

        queued_teams = {}
        if 'queued_teams' in params.enterprise:
            for queued_team in params.enterprise['queued_teams']:
                node_id = queued_team['node_id']
                if node_id not in node_scope:
                    continue
                team_id = queued_team['team_uid']
                queued_teams[team_id] = {
                    'id': team_id,
                    'node_id': node_id,
                    'name': queued_team['name'],
                    'queued_users': [],
                }
                if node_id in nodes:
                    nodes[node_id]['queued_teams'].append(team_id)

        if 'queued_team_users' in params.enterprise:
            for tu in params.enterprise['queued_team_users']:
                if tu['team_uid'] in queued_teams:
                    queued_teams[tu['team_uid']]['queued_users'].extend(tu['users'])
                elif tu['team_uid'] in teams:
                    teams[tu['team_uid']]['queued_users'].extend(tu['users'])

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
                    'new_user_inherit': role['new_user_inherit'],
                    'is_admin': False,
                    'users': []
                }
                if node_id in nodes:
                    nodes[node_id]['roles'].append(role_id)

        if 'role_users' in params.enterprise:
            for ru in params.enterprise['role_users']:
                role_id = ru['role_id']
                if role_id in roles:
                    roles[role_id]['users'].append(ru['enterprise_user_id'])

        if 'managed_nodes' in params.enterprise:
            for mn in params.enterprise['managed_nodes']:
                role_id = mn['role_id']
                if role_id in roles:
                    roles[role_id]['is_admin'] = True

        show_nodes = kwargs.get('nodes') or False
        show_users = kwargs.get('users') or False
        show_teams = kwargs.get('teams') or False
        show_roles = kwargs.get('roles') or False

        def user_email(user_id):
            if user_id in users:
                return users[user_id]['username']
            else:
                return str(user_id)

        def restricts(team):
            rs = ''
            rs += 'R ' if team['restrict_view'] else '  '
            rs += 'W ' if team['restrict_edit'] else '  '
            rs += 'S' if team['restrict_sharing'] else ' '
            return rs

        if not show_users and not show_teams and not show_roles and not show_nodes:
            def tree_node(node):
                children = [nodes[x] for x in node['children']]
                children.sort(key=lambda x: x['name'])
                n = OD()
                for ch in children:
                    name = ch['name']
                    if kwargs.get('verbose'):
                        name += ' ({0})'.format(ch['node_id'])
                    n['[{0}]{1}'.format(name, ' |Isolated| ' if ch.get('isolated') else '')] = tree_node(ch)

                if len(node['users']) > 0:
                    if kwargs.get('verbose'):
                        logging.debug('users: %s' % json.dumps(users, indent=4, sort_keys=True))
                        us = [users[x] for x in node['users']]
                        us.sort(key=lambda x: x['username'] if 'username' in x else 'a')
                        ud = OD()
                        for u in us:
                            ud['{0} ({1})'.format(u['username'] if 'username' in u else '[none]', u['id'])] = {}
                        n['User(s)'] = ud
                    else:
                        n['{0} user(s)'.format(len(node['users']))] = {}

                if len(node['roles']) > 0:
                    if kwargs.get('verbose'):
                        ts = [roles[x] for x in node['roles']]
                        ts.sort(key=lambda x: x['name'])
                        td = OD()
                        for i, t in enumerate(ts):
                            td['{0} ({1})'.format(t['name'], t['id'])] = {}
                            if i >= 50:
                                td['{0} More Role(s)'.format(len(ts)-i)] = {}
                                break
                        n['Role(s)'] = td
                    else:
                        n['{0} role(s)'.format(len(node['roles']))] = {}

                if len(node['teams']) > 0:
                    if kwargs.get('verbose'):
                        ts = [teams[x] for x in node['teams']]
                        ts.sort(key=lambda x: x['name'])
                        td = OD()
                        for i, t in enumerate(ts):
                            td['{0} ({1})'.format(t['name'], t['id'])] = {}
                            if i >= 50:
                                td['{0} More Team(s)'.format(len(ts)-i)] = {}
                                break
                        n['Teams(s)'] = td
                    else:
                        n['{0} team(s)'.format(len(node['teams']))] = {}

                if len(node['queued_teams']) > 0:
                    if kwargs.get('verbose'):
                        ts = [queued_teams[x] for x in node['queued_teams']]
                        ts.sort(key=lambda x: x['name'])
                        td = OD()
                        for i, t in enumerate(ts):
                            td['{0} ({1})'.format(t['name'], t['id'])] = {}
                            if i >= 50:
                                td['{0} More Queued Team(s)'.format(len(ts)-i)] = {}
                                break
                        n['Queued Teams(s)'] = td
                    else:
                        n['{0} queued team(s)'.format(len(node['queued_teams']))] = {}

                return n

            tree = OD()
            for node_id in root_nodes:
                r = nodes[node_id]
                root_name = r['name']
                if not r['parent_id'] and root_name == '':
                    root_name = params.enterprise['enterprise_name']
                if kwargs.get('verbose'):
                    root_name += ' ({0})'.format(r['node_id'])
                tree['{0} {1}'.format(root_name, ' |Isolated| ' if r.get('isolated') else '')] = tree_node(r)
            if len(root_nodes) > 1:
                tree = OD([('', tree)])
            else:
                print('')

            tr = LeftAligned()
            print(tr(tree))
        else:
            columns = set()
            if kwargs.get('columns'):
                columns.update((x.strip() for x in kwargs.get('columns').split(',')))
            pattern = (kwargs.get('pattern') or '').lower()
            if show_nodes:
                supported_columns = SUPPORTED_NODE_COLUMNS
                if len(columns) == 0:
                    columns.update(('parent_node', 'user_count', 'team_count', 'role_count'))
                else:
                    wc = columns.difference(supported_columns)
                    if len(wc) > 0:
                        logging.warning('\n\nSupported node columns: %s\n', ', '.join(supported_columns))

                displayed_columns = [x for x in supported_columns if x in columns]
                rows = []
                for n in nodes.values():
                    node_id = n['node_id']
                    row = [node_id, n['name']]
                    for column in displayed_columns:
                        if column == 'parent_node':
                            parent_id = n.get('parent_id', 0)
                            row.append(self.get_node_path(params, parent_id) if parent_id > 0 else '')
                        elif column == 'user_count':
                            us = n.get('users', [])
                            row.append(len(us))
                        elif column == 'users':
                            us = n.get('users', [])
                            user_names = [users[x]['username'] for x in us if x in users]
                            row.append(user_names)
                        elif column == 'team_count':
                            ts = n.get('teams', [])
                            row.append(len(ts))
                        elif column == 'teams':
                            ts = n.get('teams', [])
                            team_names = [teams[x]['name'] for x in ts if x in teams]
                            row.append(team_names)
                        elif column == 'role_count':
                            rs = n.get('roles', [])
                            row.append(len(rs))
                        elif column == 'roles':
                            rs = n.get('roles', [])
                            role_names = [roles[x]['name'] for x in rs if x in roles]
                            row.append(role_names)

                    if pattern:
                        if not any(1 for x in row if x and str(x).lower().find(pattern) >= 0):
                            continue
                    rows.append(row)

                rows.sort(key=lambda x: x[1])

                print('')
                headers = ['node_id', 'name']
                headers.extend(displayed_columns)
                if kwargs.get('format') != 'json':
                    headers = [string.capwords(x.replace('_', ' ')) for x in headers]
                return dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))
            elif show_users:
                supported_columns = SUPPORTED_USER_COLUMNS
                if len(columns) == 0:
                    columns.update(('name', 'status', 'transfer_status', 'node'))
                else:
                    wc = columns.difference(supported_columns)
                    if len(wc) > 0:
                        logging.warning('\n\nSupported user columns: %s\n', ', '.join(supported_columns))

                displayed_columns = [x for x in supported_columns if x in columns]
                rows = []
                for u in users.values():

                    user_status_dict = get_user_status_dict(u)

                    user_id = u['id']
                    row = [user_id, u['username']]
                    for column in displayed_columns:
                        if column == 'name':
                            row.append(u['name'])
                        elif column == 'status':
                            row.append(user_status_dict['acct_status'])
                        elif column == 'transfer_status':
                            row.append(user_status_dict['acct_transfer_status'])
                        elif column == 'node':
                            row.append(self.get_node_path(params, u['node_id']))
                        elif column == 'team_count':
                            row.append(len([1 for t in teams.values() if t['users'] and user_id in t['users']]))
                        elif column == 'teams':
                            team_names = [t["name"] for t in teams.values() if t['users'] and user_id in t['users']]
                            row.append(team_names)
                        elif column == 'role_count':
                            row.append(len([1 for r in roles.values() if r['users'] and user_id in r['users']]))
                        elif column == 'roles':
                            role_names = [r['name'] for r in roles.values() if r['users'] and user_id in r['users']]
                            row.append(role_names)

                    if pattern:
                        if not any(1 for x in row if x and str(x).lower().find(pattern) >= 0):
                            continue
                    rows.append(row)
                rows.sort(key=lambda x: x[1])

                print('')
                headers = ['user_id', 'email']
                headers.extend(displayed_columns)
                if kwargs.get('format') != 'json':
                    headers = [string.capwords(x.replace('_', ' ')) for x in headers]
                return dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

            if show_teams:
                supported_columns = SUPPORTED_TEAM_COLUMNS
                if len(columns) == 0:
                    columns.update(('restricts', 'node', 'user_count'))
                    if 'queued_team_users' in params.enterprise:
                        if len(params.enterprise['queued_team_users']) > 0:
                            columns.update(('queued_user_count',))
                else:
                    wc = columns.difference(supported_columns)
                    if len(wc) > 0:
                        logging.warning('\n\nSupported team columns: %s\n', ', '.join(supported_columns))

                displayed_columns = [x for x in supported_columns if x in columns]
                rows = []
                for t in teams.values():
                    row = [t['id'], t['name']]
                    for column in displayed_columns:
                        if column == 'restricts':
                            row.append(restricts(t))
                        elif column == 'node':
                            row.append(self.get_node_path(params, t['node_id']))
                        elif column == 'user_count':
                            row.append(len(t['users']))
                        elif column == 'users':
                            row.append([user_email(x) for x in t['users']])
                        elif column == 'queued_user_count':
                            row.append(len(t['queued_users']))
                        elif column == 'queued_users':
                            row.append([user_email(x) for x in t['queued_users']])
                    if pattern:
                        if not any(1 for x in row if x and str(x).lower().find(pattern) >= 0):
                            continue
                    rows.append(row)

                for t in queued_teams.values():
                    row = [t['id'], t['name']]

                    for column in displayed_columns:
                        if column == 'restricts':
                            row.append('Queued')
                        elif column == 'node':
                            row.append(self.get_node_path(params, t['node_id']))
                        elif column in {'user_count', 'users'}:
                            row.append('')
                        elif column == 'queued_user_count':
                            row.append(len(t['queued_users']))
                        elif column == 'queued_users':
                            row.append([user_email(x) for x in t['queued_users']])
                    if pattern:
                        if not any(1 for x in row if x and str(x).lower().find(pattern) >= 0):
                            continue
                    rows.append(row)

                rows.sort(key=lambda x: x[1])

                print('')
                headers = ['team_uid', 'name']
                headers.extend(displayed_columns)
                if kwargs.get('format') != 'json':
                    headers = [string.capwords(x.replace('_', ' ')) for x in headers]
                return dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

            if show_roles:
                supported_columns = SUPPORTED_ROLE_COLUMNS
                if len(columns) == 0:
                    columns.update(('default_role', 'admin', 'node', 'user_count'))
                else:
                    wc = columns.difference(supported_columns)
                    if len(wc) > 0:
                        logging.warning('\n\nSupported role columns: %s\n', ', '.join(supported_columns))

                displayed_columns = [x for x in supported_columns if x in columns]

                rows = []
                for r in roles.values():
                    row = [r['id'], r['name']]
                    for column in displayed_columns:
                        if column == 'visible_below':
                            row.append('Y' if r['visible_below'] else '')
                        elif column == 'default_role':
                            row.append('Y' if r['new_user_inherit'] else '')
                        elif column == 'admin':
                            row.append('Y' if r['is_admin'] else '')
                        elif column == 'node':
                            row.append(self.get_node_path(params, r['node_id']))
                        elif column == 'user_count':
                            row.append(len(r['users']))
                        elif column == 'users':
                            row.append([user_email(x) for x in r['users']])
                    if pattern:
                        if not any(1 for x in row if x and str(x).lower().find(pattern) >= 0):
                            continue
                    rows.append(row)

                rows.sort(key=lambda x: x[1])

                print('')

                headers = ['role_id', 'name']
                headers.extend(displayed_columns)
                if kwargs.get('format') != 'json':
                    headers = [string.capwords(x.replace('_', ' ')) for x in headers]
                return dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

        print('')


class EnterpriseNodeCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_node_parser

    @staticmethod
    def get_subnodes(params, nodes, index):
        while index < len(nodes):
            node_id = nodes[index]
            for node in params.enterprise['nodes']:
                parent_id = node.get('parent_id')
                if parent_id == node_id:
                    nodes.append(node['node_id'])
            index += 1

    def execute(self, params, **kwargs):
        if kwargs.get('delete') and kwargs.get('add'):
            raise CommandError('enterprise-node', "'add' and 'delete' parameters are mutually exclusive.")

        node_lookup = {}    # type: Dict[str, Union[Dict, List[Dict]]]
        if 'nodes' in params.enterprise:
            for node in params.enterprise['nodes']:
                node_lookup[str(node['node_id'])] = node
                node_name = node['data'].get('displayname') or ''
                if not node_name and 'parent_id' not in node:
                    node_name = params.enterprise['enterprise_name']
                if node_name:
                    node_name = node_name.lower()
                    n = node_lookup.get(node_name)
                    if n is None:
                        node_lookup[node_name] = node
                    elif type(n) == list:
                        n.append(node)
                    else:
                        node_lookup[node_name] = [n, node]

        parent_id = None
        if kwargs.get('parent'):
            parent_name = kwargs.get('parent')
            n = node_lookup.get(parent_name)
            if not n:
                n = node_lookup.get(parent_name.lower())
            if not n:
                raise CommandError('enterprise-node', 'Cannot resolve parent node %s'.format(parent_name))
            if isinstance(n, list):
                raise CommandError('enterprise-node', 'Parent node %s in not unique'.format(parent_name))
            parent_id = n['node_id']

        matched = {}
        unmatched_nodes = set()

        for node_name in kwargs['node']:
            n = node_lookup.get(node_name)
            if not n:
                n = node_lookup.get(node_name.lower())
            if n:
                if type(n) == list:
                    logging.warning('Node name \'%s\' is not unique. Skipping.', node_name)
                else:
                    matched[n['node_id']] = n
            else:
                unmatched_nodes.add(node_name)

        matched_nodes = list(matched.values())

        request_batch = []
        if kwargs.get('add'):
            for node in matched_nodes:
                logging.warning('Node \'%s\' already exists: Skipping.', node['data'].get('displayname'))

            if not unmatched_nodes:
                raise CommandError('enterprise-node', 'No nodes to add.')

            if parent_id is None:
                for node in params.enterprise['nodes']:
                    if not node.get('parent_id'):
                        parent_id = node['node_id']
                        break

            for node_name in unmatched_nodes:
                dt = {'displayname': node_name}
                encrypted_data = api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key'])
                rq = {
                    'command': 'node_add',
                    'node_id': self.get_enterprise_id(params),
                    'parent_id': parent_id,
                    'encrypted_data': encrypted_data
                }
                request_batch.append(rq)
        elif kwargs.get('toggle_isolated'):
            if not matched_nodes:
                raise CommandError('enterprise-node', 'No nodes to toggle.')

            for mn in matched_nodes:
                node_id = mn['node_id']
                data = mn['data']
                displayname = data['displayname']
                request = SetRestrictVisibilityRequest()
                request.nodeId = node_id
                try:
                    api.communicate_rest(params, request, 'enterprise/set_restrict_visibility')
                    mn['restrict_visibility'] = not (mn.get('restrict_visibility') or False)
                    logging.warning('good result: {}'.format(displayname))
                except Exception as e:
                    logging.warning('node \"%s\": toggle isolation failed: %s', displayname, e)
            api.query_enterprise(params)
        else:
            for node_name in unmatched_nodes:
                logging.warning('Node \'%s\' is not found: Skipping', node_name)

            if not matched_nodes:
                return

            if kwargs.get('delete'):
                depths = {}

                def traverse_to_root(node_id, depth):
                    if not node_id:
                        return depth
                    nd = node_lookup.get(str(node_id))
                    if nd:
                        return traverse_to_root(nd.get('parent_id'), depth + 1)
                    else:
                        return depth

                for node in matched_nodes:
                    depths[node['node_id']] = traverse_to_root(node['node_id'], 0)
                matched_nodes.sort(key=lambda x: depths[x['node_id']] or 0, reverse=True)
                for node in matched_nodes:
                    rq = {
                        'command': 'node_delete',
                        'node_id': node['node_id']
                    }
                    request_batch.append(rq)
            elif kwargs.get('wipe_out'):
                if len(matched_nodes) != 1:
                    raise CommandError('enterprise-node', 'Cannot wipe-out more than one node')
                node = matched_nodes[0]
                if not node.get('parent_id'):
                    raise CommandError('enterprise-node', 'Cannot wipe out root node')

                answer = user_choice(
                    bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                    'This action cannot be undone.\n\n' +
                    'Do you want to proceed with deletion?', 'yn', 'n')
                if answer.lower() != 'y':
                    return

                sub_nodes = [node['node_id']]
                EnterpriseNodeCommand.get_subnodes(params, sub_nodes, 0)
                nodes = set(sub_nodes)

                if 'queued_teams' in params.enterprise:
                    queued_teams = [x for x in params.enterprise['queued_teams'] if x['node_id'] in nodes]
                    for qt in queued_teams:
                        rq = {
                            'command': 'team_delete',
                            'team_uid': qt['team_uid']
                        }
                        request_batch.append(rq)

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
                        request_batch.append(rq)
                for mn in managed_nodes:
                    rq = {
                        'command': 'role_managed_node_remove',
                        'role_id': mn['role_id'],
                        'managed_node_id': mn['managed_node_id']
                    }
                    request_batch.append(rq)
                for r in roles:
                    rq = {
                        'command': 'role_delete',
                        'role_id': r['role_id']
                    }
                    request_batch.append(rq)

                users = [x for x in params.enterprise['users'] if x['node_id'] in nodes]
                for u in users:
                    rq = {
                        'command': 'enterprise_user_delete',
                        'enterprise_user_id': u['enterprise_user_id']
                    }
                    request_batch.append(rq)

                if 'teams' in params.enterprise:
                    teams = [x for x in params.enterprise['teams'] if x['node_id'] in nodes]
                    for t in teams:
                        rq = {
                            'command': 'team_delete',
                            'team_uid': t['team_uid']
                        }
                        request_batch.append(rq)

                sub_nodes.pop(0)
                sub_nodes.reverse()
                for node_id in sub_nodes:
                    rq = {
                        'command': 'node_delete',
                        'node_id': node_id
                    }
                    request_batch.append(rq)
            elif parent_id or kwargs.get('name'):

                def is_in_chain(node_id, parent_id):
                    if node_id == parent_id:
                        return True
                    nn = node_lookup.get(node_id)
                    if not nn:
                        return False
                    return is_in_chain(nn['parent_id'], parent_id)

                if kwargs.get('name') and len(matched_nodes) > 1:
                    logging.warning('Cannot assign the same name to % nodes', len(matched_nodes) > 1)
                    kwargs['name'] = None
                if not parent_id or not kwargs.get('name'):
                    for node in matched_nodes:
                        encrypted_data = node['encrypted_data']
                        if kwargs.get('name'):
                            dt = node['data']
                            dt['dsplayname'] = kwargs.get('name')
                            encrypted_data = api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key'])
                        if parent_id:
                            if is_in_chain(parent_id, node['node_id']):
                                logging.warning('Cannot move node to itself or its children')
                                continue
                        rq = {
                            'command': 'node_update',
                            'node_id': node['node_id'],
                            'encrypted_data': encrypted_data
                        }
                        if parent_id:
                            rq['parent_id'] = parent_id
                        request_batch.append(rq)

        if request_batch:
            rss = api.execute_batch(params, request_batch)
            for rq, rs in zip(request_batch, rss):
                command = rq.get('command')
                if command == 'node_add':
                    if rs['result'] == 'success':
                        logging.info('Node is created')
                    else:
                        logging.warning('Failed to create node: %s', rs['message'])
                elif command in {'node_delete', 'node_update'}:
                    node_id = rq['node_id']
                    node_name = str(node_id)
                    node = node_lookup.get(node_name)
                    if node:
                        node_name = node['data'].get('displayname') or node_name
                    verb = 'deleted' if command == 'node_delete' else 'updated'
                    if rs['result'] == 'success':
                        logging.info('\'%s\' node is %s', node_name, verb)
                    else:
                        logging.warning('\'%s\' node is not %s. Error: %s', node_name, verb, rs['message'])
                else:
                    if rs['result'] != 'success':
                        raise CommandError('enterprise-node', '\'{0}\' command error: {1}'.format(command,  rs['message']))
            api.query_enterprise(params)


class EnterpriseUserCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_user_parser

    def execute(self, params, **kwargs):
        if kwargs.get('delete') and kwargs.get('add'):
            raise CommandError('enterprise-user', "'add' and 'delete' parameters are mutually exclusive.")

        if kwargs.get('lock') and kwargs.get('unlock'):
            raise CommandError('enterprise-user', "'lock' and 'unlock' parameters are mutually exclusive.")

        matched_users = []
        unmatched_emails = set()

        user_lookup = {}
        if 'users' in params.enterprise:
            for u in params.enterprise['users']:

                user_lookup[str(u['enterprise_user_id'])] = u

                if 'username' in u:
                    user_lookup[u['username'].lower()] = u
                else:
                    logging.debug('All users: %s', params.enterprise['users'])
                    logging.debug('WARNING: username is missing from the user id=%s, obj=%s', u['enterprise_user_id'], u)

        emails = kwargs['email']
        if emails:
            for email in emails:
                email = email.lower()
                if email == '@all':
                    if kwargs.get('unlock') or kwargs.get('extend'):
                        now = round(time.time() * 1000)
                        for u in params.enterprise['users'] if 'users' in params.enterprise else []:
                            if kwargs.get('unlock') and u.get('lock', 0) == 1:
                                matched_users.append(u)
                            if kwargs.get('extend'):
                                if 'account_share_expiration' in u:
                                    if 0 < u['account_share_expiration'] < now:
                                        matched_users.append(u)
                    else:
                        logging.warning('@all pseudo-user can be used with \'unlock\' and \'extend\' actions only.')
                else:
                    if email in user_lookup:
                        matched_users.append(user_lookup[email])
                    else:
                        unmatched_emails.add(email)

        node_id = None
        node_name = kwargs.get('node')
        if node_name:
            nodes = list(self.resolve_nodes(params, node_name))
            if len(nodes) == 0:
                logging.warning('Node \"%s\" is not found', node_name)
                return
            if len(nodes) > 1:
                logging.warning('More than one nodes \"%s\" are found', node_name)
                return
            node_id = nodes[0]['node_id']

        user_name = kwargs.get('displayname')

        request_batch = []
        disable_2fa_users = []

        if kwargs.get('add') or kwargs.get('invite'):
            if node_id is None:
                root_nodes = list(self.get_user_root_nodes(params))
                if len(root_nodes) == 0:
                    raise CommandError('enterprise-user', 'No root nodes were detected. Specify --node parameter')
                node_id = root_nodes[0]

            if not unmatched_emails and not matched_users:
                raise CommandError('enterprise-user', 'No email address to invite.')

            for email in unmatched_emails:
                dt = {}
                if user_name:
                    dt['displayname'] = user_name
                encrypted_data = api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key'])
                rq = {
                    'command': 'enterprise_user_add',
                    'enterprise_user_id': self.get_enterprise_id(params),
                    'node_id': node_id,
                    'encrypted_data': encrypted_data,
                    'enterprise_user_username': email
                }
                request_batch.append(rq)
            for user in matched_users:
                if user.get('status') == 'invited':
                    rq = {
                        'command': 'resend_enterprise_invite',
                        'enterprise_user_id': user['enterprise_user_id'],
                    }
                    request_batch.append(rq)
                else:
                    logging.warning('%s has already accepted invitation. Skipping', user['username'])
        else:
            for email in unmatched_emails:
                logging.warning('User %s is not found: Skipping', email)

            if not matched_users:
                raise CommandError('enterprise-user', 'No such user(s)')

            if kwargs.get('delete'):
                answer = 'y' if kwargs.get('force') else \
                    user_choice(
                        bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                        'Deleting a user will also delete any records owned and shared by this user.\n'+
                        'Before you delete this user(s), we strongly recommend you lock their account\n' +
                        'and transfer any important records to other user(s).\n' +
                        'This action cannot be undone.\n\n' +
                        'Do you want to proceed with deletion?', 'yn', 'n')
                if answer.lower() == 'y':
                    for user in matched_users:
                        rq = {
                            'command': 'enterprise_user_delete',
                            'enterprise_user_id': user['enterprise_user_id']
                        }
                        request_batch.append(rq)
            else:
                if kwargs.get('lock') or kwargs.get('unlock'):
                    for user in matched_users:
                        if user['status'] == 'active':
                            to_lock = kwargs.get('lock')
                            request_batch.append({
                                'command': 'enterprise_user_lock',
                                'enterprise_user_id': user['enterprise_user_id'],
                                'lock': 'locked' if to_lock else 'unlocked'
                            })
                        else:
                            logging.warning('%s has not accepted invitation yet: Skipping', user['username'])

                if kwargs.get('disable_2fa'):
                    for user in matched_users:
                        if user['status'] == 'active':
                            disable_2fa_users.append(user)
                        else:
                            logging.warning('%s has not accepted invitation yet: Skipping', user['username'])

                if kwargs.get('expire'):
                    answer = 'y' if kwargs.get('force') else \
                        user_choice(
                            bcolors.BOLD + '\nConfirm\n' + bcolors.ENDC +
                            'User will be required to create a new Master Password on the next login.\n' +
                            'Are you sure you want to expire master password?', 'yn', 'n')
                    if answer.lower() == 'y':
                        for user in matched_users:
                            request_batch.append({
                                'command': 'set_master_password_expire',
                                'email': user['username']
                            })

                if kwargs.get('extend'):
                    for user in matched_users:
                        request_batch.append({
                            'command': 'extend_account_share_expiration',
                            'enterprise_user_id': user['enterprise_user_id']
                        })

                if kwargs.get('add_role') or kwargs.get('remove_role'):
                    role_changes = {}
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
                                    role_changes[role_node['role_id']] = is_add, role_node['data'].get('displayname')
                                else:
                                    logging.warning('Role %s cannot be resolved', r)

                    if len(role_changes) > 0:
                        for role_id in role_changes:
                            is_add, role_name = role_changes[role_id]
                            role_users = set()
                            if 'role_users' in params.enterprise:
                                for ru in params.enterprise['role_users']:
                                    if ru['role_id'] == role_id:
                                        role_users.add(ru['enterprise_user_id'])

                            role_key = None
                            is_managed_role = False
                            if is_add:
                                if 'managed_nodes' in params.enterprise:
                                    for mn in params.enterprise['managed_nodes']:
                                        if mn['role_id'] == role_id:
                                            is_managed_role = True
                                            break
                            if is_managed_role:

                                if 'role_keys2' in params.enterprise:
                                    for rk2 in params.enterprise['role_keys2']:
                                        if rk2['role_id'] == role_id:
                                            encrypted_key_decoded = base64.urlsafe_b64decode(rk2['role_key'] + '==')
                                            role_key = rest_api.decrypt_aes(encrypted_key_decoded,
                                                                            params.enterprise['unencrypted_tree_key'])
                                            break

                                if 'role_keys' in params.enterprise and role_key is None:
                                    for rk in params.enterprise['role_keys']:
                                        if rk['role_id'] == role_id:
                                            if rk['key_type'] == 'encrypted_by_data_key':
                                                role_key = api.decrypt_data(rk['encrypted_key'], params.data_key)
                                            elif rk['key_type'] == 'encrypted_by_public_key':
                                                role_key = api.decrypt_rsa(rk['encrypted_key'], params.rsa_key)
                                            break

                            user_pkeys = {}
                            for user in matched_users:
                                if is_add and user['enterprise_user_id'] in role_users:
                                    logging.warning('User %s is already in \'%s\' group: Add to group is skipped', user['username'], role_name)
                                    continue
                                if not is_add and user['enterprise_user_id'] not in role_users:
                                    logging.warning('User %s is not in \'%s\': Remove from group is skipped', user['username'], role_name)
                                    continue

                                user_id = user['enterprise_user_id']
                                rq = {
                                    'command': 'role_user_add' if is_add else 'role_user_remove',
                                    'enterprise_user_id': user['enterprise_user_id'],
                                    'role_id': role_id
                                }
                                if is_managed_role:
                                    if user_id not in user_pkeys:
                                        answer = 'y' if kwargs.get('force') else user_choice('Do you want to grant administrative privileges to {0}'.format(user['username']), 'yn', 'n')
                                        public_key = None
                                        if answer == 'y':
                                            public_key = self.get_public_key(params, user['username'])
                                            if public_key is None:
                                                logging.warning('Cannot get public key for user %s', user['username'])
                                        user_pkeys[user_id] = public_key
                                    if user_pkeys[user_id]:
                                        encrypted_tree_key = crypto.encrypt_rsa(params.enterprise['unencrypted_tree_key'], user_pkeys[user_id])
                                        rq['tree_key'] = utils.base64_url_encode(encrypted_tree_key)
                                        if role_key:
                                            encrypted_role_key = crypto.encrypt_rsa(role_key, user_pkeys[user_id])
                                            rq['role_admin_key'] = utils.base64_url_encode(encrypted_role_key)
                                        request_batch.append(rq)
                                else:
                                    request_batch.append(rq)

                if kwargs.get('add_team') or kwargs.get('remove_team'):
                    teams = {}
                    for is_add in [False, True]:
                        tl = kwargs.get('add_team') if is_add else kwargs.get('remove_team')
                        if tl:
                            for t in tl:
                                team_node = None
                                if 'teams' in params.enterprise:
                                    for team in params.enterprise['teams']:
                                        if t == team['team_uid'] or t.lower() == team['name'].lower():
                                            team_node = team
                                            break
                                if team_node:
                                    team_uid = team_node['team_uid']
                                    teams[team_uid] = is_add, team_node['name']
                                else:
                                    raise CommandError('enterprise-user', 'Team {0} could be resolved'.format(t))

                    if teams:
                        for team_uid in teams:
                            is_add, team_name = teams[team_uid]
                            for user in matched_users:
                                if is_add:
                                    user_id = user['enterprise_user_id']
                                    if user['status'] == 'active':
                                        hsf = kwargs.get('hide_shared_folders') or ''
                                        is_added = False
                                        if 'team_users' in params.enterprise:
                                            is_added = \
                                                any(1 for t in params.enterprise['team_users']
                                                    if t['team_uid'] == team_uid and t['enterprise_user_id'] == user_id)
                                        if is_added:
                                            if not hsf:
                                                continue
                                            rq = {
                                                'command': 'team_enterprise_user_update',
                                                'team_uid': team_uid,
                                                'enterprise_user_id': user_id,
                                            }
                                        else:
                                            rq = {
                                                'command': 'team_enterprise_user_add',
                                                'team_uid': team_uid,
                                                'enterprise_user_id': user_id,
                                            }
                                            team_key = self.get_team_key(params, team_uid)
                                            public_key = self.get_public_key(params, user['username'])
                                            encrypted_team_key = crypto.encrypt_rsa(team_key, public_key)
                                            if team_key and public_key:
                                                rq['team_key'] = utils.base64_url_encode(encrypted_team_key)
                                                rq['user_type'] = 0
                                        if hsf:
                                            rq['user_type'] = 0 if hsf == 'off' else 2
                                        request_batch.append(rq)
                                    else:
                                        rq = {
                                            'command': 'team_queue_user',
                                            'team_uid': team_uid,
                                            'enterprise_user_id': user['enterprise_user_id']
                                        }
                                        request_batch.append(rq)
                                else:
                                    rq = {
                                        'command': 'team_enterprise_user_remove',
                                        'enterprise_user_id': user['enterprise_user_id'],
                                        'team_uid': team_uid
                                    }
                                    request_batch.append(rq)
                if node_id:
                    for user in matched_users:
                        if node_id != user['node_id']:
                            encrypted_data = user['encrypted_data']
                            if 'key_type' in user and user['key_type'] == 'no_key':
                                dt = {
                                    'displayname': user['data'].get('displayname') or ''
                                }
                                encrypted_data = api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key'])
                            rq = {
                                'command': 'enterprise_user_update',
                                'enterprise_user_id': user['enterprise_user_id'],
                                'node_id': node_id,
                                'encrypted_data': encrypted_data,
                                'enterprise_user_username': user['username']
                            }
                            request_batch.append(rq)

        if request_batch:
            rss = api.execute_batch(params, request_batch)
            for rq, rs in zip(request_batch, rss):
                command = rq.get('command')
                if command == 'enterprise_user_add':
                    if rs['result'] == 'success':
                        logging.info('%s user invited', rq['enterprise_user_username'])
                    else:
                        logging.warning('%s failed to invite user: %s', rq['enterprise_user_username'], rs['message'])
                else:
                    user = None
                    if not user and 'username' in rq:
                        user = user_lookup.get(rq['username'].lower())
                    if not user and 'email' in rq:
                        user = user_lookup.get(rq['email'].lower())
                    if not user and 'enterprise_user_id' in rq:
                        user = user_lookup.get(str(rq['enterprise_user_id']))
                    if user:
                        if command == 'set_master_password_expire':
                            if rs['result'] == 'success':
                                logging.info('%s password expired', user['username'])
                            else:
                                logging.warning('%s failed to expire password: %s', user['username'], rs['message'])
                        elif command == 'resend_enterprise_invite':
                            if rs['result'] == 'success':
                                logging.info('Invitation has been re-sent to %s', user['username'])
                            else:
                                logging.warning('Failed to re-send invitation to %s: %s', user['username'], rs['message'])
                        elif command == 'extend_account_share_expiration':
                            if rs['result'] == 'success':
                                logging.info('%s vault transfer consent expiration extended by 7 days', user['username'])
                            else:
                                logging.warning('%s failed to extend vault transfer consent expiration: %s', user['username'], rs['message'])
                        elif command == 'enterprise_user_delete':
                            if rs['result'] == 'success':
                                logging.info('%s user deleted', user['username'])
                            else:
                                logging.warning('%s failed to delete user: %s', user['username'], rs['message'])
                        elif command == 'enterprise_user_update':
                            node_names = [x['data'].get('displayname') for x in params.enterprise['nodes'] if x['node_id'] == rq['node_id']]
                            node_name = node_names[0] if len(node_names) > 0 else str(rq['node_id'])
                            if rs['result'] == 'success':
                                logging.info('%s user moved to node \'%s\'', user['username'], node_name or 'Root')
                            else:
                                logging.warning('%s failed to move user to node \'%s\': %s', user['username'], node_name or 'Root', rs['message'])
                        elif command == 'enterprise_user_lock':
                            is_locked = rq['lock'] == 'locked'
                            if rs['result'] == 'success':
                                logging.info('%s is %s', user['username'], 'locked' if is_locked else 'unlocked')
                            else:
                                logging.warning(' %s failed to %s user: %s', user['username'], 'lock' if is_locked else 'unlock', rs['message'])
                        elif command in {'role_user_add', 'role_user_remove'}:
                            role_names = [x['data'].get('displayname') for x in params.enterprise['roles'] if x['role_id'] == rq['role_id']]
                            role_name = role_names[0] if len(role_names) > 0 else str(rq['role_id'])
                            if rs['result'] == 'success':
                                logging.info('%s %s role \'%s\'', user['username'], 'added to' if command == 'role_user_add' else 'removed from', role_name)
                            else:
                                logging.warning('%s failed to %s role \'%s\': %s', user['username'], 'add to' if command == 'role_user_add' else 'remove from', role_name, rs['message'])
                        elif command in {'team_enterprise_user_add', 'team_enterprise_user_remove', 'team_queue_user'}:
                            team_names = [x['name'] for x in params.enterprise['teams'] if x['team_uid'] == rq['team_uid']]
                            team_name = team_names[0] if len(team_names) > 0 else rq['team_uid']
                            if rs['result'] == 'success':
                                logging.info('%s %s team \'%s\'', user['username'], 'removed from' if command == 'team_enterprise_user_remove' else 'added to', team_name)
                            else:
                                logging.warning('%s failed to %s team \'%s\': %s', user['username'], 'removed from' if command == 'team_enterprise_user_remove' else 'added to', team_name, rs['message'])
                        else:
                            if rs['result'] != 'success':
                                logging.warning('\'%s\' error: %s', command, rs['message'])
                    else:
                        if rs['result'] != 'success':
                            logging.warning('Error: %s', rs['message'])
            api.query_enterprise(params)

        if disable_2fa_users:
            uids = EnterpriseUserIds()
            for user in disable_2fa_users:
                uids.enterpriseUserId.append(user['enterprise_user_id'])
            api.communicate_rest(params, uids, 'enterprise/disable_two_fa')
            users = [x['username'] for x in disable_2fa_users]
            logging.warning("2FA successfully removed for %s", ", ".join(users))

        if not request_batch and not disable_2fa_users:
            is_verbose = kwargs.get('verbose') or False
            print('\n')
            for user in matched_users:
                self.display_user(params, user, is_verbose)
                print('\n')

    def display_user(self, params, user, is_verbose=False):
        print('{0:>16s}: {1}'.format('User ID', user['enterprise_user_id']))
        print('{0:>16s}: {1}'.format('Email', user['username'] if 'username' in user else '[empty]'))
        print('{0:>16s}: {1}'.format('Display Name', user['data'].get('displayname') or ''))
        node_id = user['node_id']
        print('{0:>16s}: {1:<24s}{2}'.format(
            'Node', self.get_node_path(params, node_id), f' [{node_id}]' if is_verbose else ''))

        status_dict = get_user_status_dict(user)

        acct_status = status_dict['acct_status']
        acct_transfer_status = status_dict['acct_transfer_status']

        print('{0:>16s}: {1}'.format('Status', acct_status))

        if acct_transfer_status:
            print('{0:>16s}: {1}'.format('Transfer Status', acct_transfer_status))

        if 'role_users' in params.enterprise:
            role_ids = [x['role_id'] for x in params.enterprise['role_users'] if x['enterprise_user_id'] == user['enterprise_user_id']]
            if len(role_ids) > 0:
                role_nodes = {}
                for r in params.enterprise['roles']:
                    role_nodes[r['role_id']] = r
                for i in range(len(role_ids)):
                    role_node = role_nodes[role_ids[i]]
                    print('{0:>16s}: {1:<22s} {2}'.format('Role' if i == 0 else '', role_node['data']['displayname'], role_node['role_id'] if is_verbose else ''))

        team_nodes = {}
        if 'teams' in params.enterprise:
            for t in params.enterprise['teams']:
                team_nodes[t['team_uid']] = t
        if 'queued_teams' in params.enterprise:
            for t in params.enterprise['queued_teams']:
                team_nodes[t['team_uid']] = t

        if 'team_users' in params.enterprise:
            user_id = user['enterprise_user_id']
            ts = [t for t in params.enterprise['team_users'] if t['enterprise_user_id'] == user_id]
            ts.sort(key=lambda x: team_nodes[x['team_uid']]['name'])
            for i, tu in enumerate(ts):
                team_node = team_nodes[tu['team_uid']]
                user_type = tu['user_type']
                print('{0:>16s}: {1:<24s}{2} {3}'.format(
                    'Team' if i == 0 else '', team_node['name'],
                    f' [{team_node["team_uid"]}]' if is_verbose else '',
                    ' (No Shared Folders)' if user_type == 2 else '',
                ))

        if 'queued_team_users' in params.enterprise:
            user_id = user['enterprise_user_id']
            ts = [t['team_uid'] for t in params.enterprise['queued_team_users'] if user_id in t['users']]
            ts.sort(key=lambda x: team_nodes[x]['name'])
            for i in range(len(ts)):
                team_node = team_nodes[ts[i]]
                print('{0:>16s}: {1:<24s}{2}'.format(
                    'Queued Team' if i == 0 else '', team_node['name'],
                    f' [{team_node["team_uid"]}]' if is_verbose else ''))


class EnterpriseRoleCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_role_parser

    def execute(self, params, **kwargs):
        if kwargs.get('add') and kwargs.get('remove'):
            raise CommandError('enterprise-role', "'add' and 'delete' parameters are mutually exclusive.")

        role_lookup = {}
        if 'roles' in params.enterprise:
            for r in params.enterprise['roles']:
                role_lookup[str(r['role_id'])] = r
                name = r['data'].get('displayname') or ''
                if name:
                    name = name.lower()
                    if name in role_lookup:
                        if type(role_lookup[name]) == list:
                            role_lookup[name].append(r)
                        else:
                            old = role_lookup[name]
                            role_lookup[name] = [old, r]
                    else:
                        role_lookup[name] = r

        node_id = None

        node_name = kwargs.get('node')
        if node_name:
            nodes = list(self.resolve_nodes(params, node_name))
            if len(nodes) == 0:
                logging.warning('Node \"%s\" is not found', node_name)
                return
            if len(nodes) > 1:
                logging.warning('More than one node \"%s\" are found', node_name)
                return
            node_id = nodes[0]['node_id']

        matched = {}
        role_names = set()

        for role_name in kwargs['role']:
            role_name = str(role_name)
            r = role_lookup.get(role_name.lower())
            if r is None:
                role_names.add(role_name)
            elif type(r) == list:
                role_in_node = None
                if node_id:
                    for ro in r:
                        if ro['node_id'] == node_id:
                            role_in_node = ro
                            break
                if role_in_node:
                    matched[role_in_node['role_id']] = role_in_node
                else:
                    logging.warning('Role name \'%s\' is not unique. Use Role ID. Skipping', role_name)
            elif type(r) == dict:
                matched[r['role_id']] = r

        matched_roles = list(matched.values())

        request_batch = []
        non_batch_update_msgs = []
        skip_display = False
        if kwargs.get('add'):
            for role in matched_roles:
                logging.warning('Role \'%s\' already exists: Skipping', role['data'].get('displayname'))
            if not role_names:
                return

            if node_id is None:
                root_nodes = list(self.get_user_root_nodes(params))
                if len(root_nodes) == 0:
                    raise CommandError('enterprise-user', 'No root nodes were detected. Specify --node parameter')
                node_id = root_nodes[0]

            for role_name in role_names:
                dt = { "displayname": role_name }
                rq = {
                    "command": "role_add",
                    "role_id": self.get_enterprise_id(params),
                    "node_id": node_id,
                    "encrypted_data": api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key']),
                    "visible_below": (kwargs.get('visible_below') == 'on') or False,
                    "new_user_inherit": (kwargs.get('new_user') == 'on') or False
                }
                request_batch.append(rq)
        else:
            for role_name in role_names:
                logging.warning('Role %s is not found: Skipping', role_name)

            if not matched_roles:
                return

            add_team, remove_team = kwargs.get('add_team'), kwargs.get('remove_team')
            add_user, remove_user = kwargs.get('add_user'), kwargs.get('remove_user')

            if kwargs.get('delete'):
                for role in matched_roles:
                    request_batch.append({ "command": "role_delete", "role_id": role['role_id'] })

            elif add_team or remove_team or add_user or remove_user:
                if add_team or remove_team:
                    non_batch_update_msgs += self.change_role_teams(params, matched_roles, add_team, remove_team)

                if add_user or remove_user:
                    request_batch += self.get_role_users_change_batch(
                        params, matched_roles, add_user, remove_user
                    )

            elif kwargs.get('enforcements'):
                skip_display = True
                for enforcement in kwargs['enforcements']:
                    tokens = enforcement.split(':')
                    if len(tokens) != 2:
                        logging.warning('Enforcement %s is skipped. Expected format:  KEY:[VALUE]', enforcement)
                        continue
                    key = tokens[0].strip().lower()
                    enforcement_type = constants.ENFORCEMENTS.get(key)
                    if not enforcement_type:
                        logging.warning('Enforcement \"%s\" does not exist', key)
                        continue
                    enforcement_value = tokens[1].strip()
                    if enforcement_value:
                        if enforcement_type == 'long':
                            try:
                                enforcement_value = int(enforcement_value)
                            except ValueError:
                                logging.warning('Enforcement %s expects integer value', key)
                                continue
                        elif enforcement_type == 'boolean':
                            enforcement_value = enforcement_value.lower()
                            if enforcement_value in {'true', 't', '1'}:
                                enforcement_value = True
                            elif enforcement_value in {'false', 'f', '0'}:
                                enforcement_value = None
                            else:
                                logging.warning('Enforcement %s expects boolean value', key)
                                continue
                        elif enforcement_type == 'string':
                            pass
                        elif enforcement_type.startswith('ternary_'):
                            if enforcement_value in {'e', 'enforce'}:
                                enforcement_value = 'enforce'
                            elif enforcement_value in {'d', 'disable'}:
                                enforcement_value = 'disable'
                            else:
                                logging.warning('Enforcement %s expects either "enforce" or "disable"', key)
                                continue
                        elif enforcement_type == 'two_factor_duration':
                            if enforcement_value == 'login':
                                enforcement_value = '0'
                            elif enforcement_value == '30_days':
                                enforcement_value = '0,30'
                            elif enforcement_value == 'forever':
                                enforcement_value = '0,30,9999'
                            else:
                                logging.warning('Enforcement %s expects "login", "30_days", or "forever"', key)
                                continue
                        elif enforcement_type == 'ip_whitelist':
                            ip_ranges = [x.strip().lower() for x in enforcement_value.split(',')]
                            all_resolved = True
                            for i in range(len(ip_ranges)):
                                range_str = ip_ranges[i]
                                ranges = range_str.split('-')
                                if len(ranges) == 2:
                                    try:
                                        ip_addr1 = ipaddress.ip_address(ranges[0])
                                        ip_addr2 = ipaddress.ip_address(ranges[1])
                                        if ip_addr1 > ip_addr2:
                                            ip_ranges[i] = f'{ip_addr2}-{ip_addr1}'
                                        else:
                                            ip_ranges[i] = f'{ip_addr1}-{ip_addr2}'
                                    except ValueError:
                                        all_resolved = False
                                elif len(ranges) == 1:
                                    try:
                                        ip_addr = ipaddress.ip_address(range_str)
                                        ip_ranges[i] = f'{ip_addr}-{ip_addr}'
                                    except ValueError:
                                        try:
                                            ip_net = ipaddress.ip_network(range_str)
                                            ip_ranges[i] = f'{ip_net[0]}-{ip_net[-1]}'
                                        except ValueError:
                                            all_resolved = False
                                else:
                                    all_resolved = False
                                if not all_resolved:
                                    logging.warning('Enforcement %s. IP address range \'%s\' not valid', key, range_str)
                                    break
                            if all_resolved:
                                enforcement_value = ','.join(ip_ranges)
                            else:
                                continue
                        elif enforcement_type == 'record_types':
                            record_types = {
                                'std': [],
                                'ent': []
                            }
                            types = [x.strip().lower() for x in enforcement_value.split(',')]

                            rq = record_proto.RecordTypesRequest()
                            rq.standard = True
                            rq.user = True
                            rq.enterprise = True
                            record_types_rs = api.communicate_rest(params, rq, 'vault/get_record_types', rs_type=record_proto.RecordTypesResponse)
                            lookup = {}
                            for rti in record_types_rs.recordTypes:
                                try:
                                    rto = json.loads(rti.content)
                                    if '$id' in rto:
                                        lookup[rto['$id'].lower()] = (rti.recordTypeId, rti.scope)
                                except:
                                    pass
                            all_resolved = True
                            for rt in types:
                                if rt in lookup:
                                    rti = lookup[rt]
                                    if rti[1] == record_proto.RT_STANDARD:
                                        record_types['std'].append(rti[0])
                                    elif rti[1] == record_proto.RT_ENTERPRISE:
                                        record_types['ent'].append(rti[0])
                                else:
                                    if rt == 'all':
                                        record_types['std'].clear()
                                        record_types['ent'].clear()
                                        for rti in lookup.values():
                                            if rti[1] == record_proto.RT_STANDARD:
                                                record_types['std'].append(rti[0])
                                            elif rti[1] == record_proto.RT_ENTERPRISE:
                                                record_types['ent'].append(rti[0])
                                        break
                                    else:
                                        logging.warning('Enforcement %s. Record type \'%s\' not found', key, rt)
                                        all_resolved = False
                                        break
                            if not all_resolved:
                                continue
                            enforcement_value = record_types
                        else:
                            logging.warning('Enforcement \"%s\". Value type \"%s\" is not supported', key, enforcement_type)
                            continue
                    else:
                        enforcement_value = None

                    role_enforcements = params.enterprise.get('role_enforcements') or []
                    for role in matched_roles:
                        role_id = role['role_id']
                        enforcements = next((x['enforcements'] for x in role_enforcements if x['role_id'] == role_id), None)
                        existing_enforcement = enforcements.get(key) if enforcements else None
                        if enforcement_value is not None:
                            rq = {
                                'command': 'role_enforcement_update' if existing_enforcement else 'role_enforcement_add',
                                'role_id': role_id,
                                'enforcement': key
                            }
                            if isinstance(enforcement_value, bool):
                                if existing_enforcement:
                                    logging.warning('Enforcement \"%s\" is already set for role %d. Skipping', key, role_id)
                                    continue
                            else:
                                rq['value'] = enforcement_value
                            request_batch.append(rq)
                        else:
                            if existing_enforcement:
                                rq = {
                                    'command': 'role_enforcement_remove',
                                    'role_id': role_id,
                                    'enforcement': key
                                }
                                request_batch.append(rq)
                            else:
                                logging.warning('Enforcement \"%s\" is not set for role %d. Skipping', key, role_id)

            elif kwargs.get('add_admin') or kwargs.get('remove_admin'):
                skip_display = True
                node_lookup = {}
                if 'nodes' in params.enterprise:
                    for node in params.enterprise['nodes']:
                        node_lookup[str(node['node_id'])] = node
                        if node.get('parent_id'):
                            node_name = node['data'].get('displayname')
                        else:
                            node_name = params.enterprise['enterprise_name']
                        node_name = node_name.lower()
                        value = node_lookup.get(node_name)
                        if value is None:
                             value = node
                        elif type(value) == list:
                            value.append(node)
                        else:
                            value = [value, node]
                        node_lookup[node_name] = value

                node_changes = {}
                for is_add in [False, True]:
                    ul = kwargs.get('add_admin') if is_add else kwargs.get('remove_admin')
                    if ul:
                        for u in ul:
                            value = node_lookup.get(u.lower())
                            if value:
                                if value is None:
                                    logging.warning('Node %s could be resolved', u)
                                if type(value) == dict:
                                    node_changes[value['node_id']] = is_add, value['data'].get('displayname') or params.enterprise['enterprise_name']
                                elif type(value) == list:
                                    logging.warning('Node name \'%s\' is not unique. Use Node ID. Skipping', u)

                for role in matched_roles:
                    role_id = role['role_id']
                    for node_id in node_changes:
                        is_add, node_name = node_changes[node_id]
                        rq = {
                            "command": "role_managed_node_add" if is_add else "role_managed_node_remove",
                            "role_id": role_id,
                            "managed_node_id": node_id
                        }
                        if is_add:
                            rq['cascade_node_management'] = (kwargs.get('cascade') == 'on') or False
                            rq['tree_keys'] = []
                            if 'role_users' in params.enterprise:
                                for user_id in [x['enterprise_user_id'] for x in params.enterprise['role_users'] if x['role_id'] == role_id]:
                                    emails = [x['username'] for x in params.enterprise['users'] if x['enterprise_user_id'] == user_id]
                                    if emails:
                                        public_key = self.get_public_key(params, emails[0])
                                        encrypted_tree_key = crypto.encrypt_rsa(params.enterprise['unencrypted_tree_key'], public_key)
                                        if public_key:
                                            rq['tree_keys'].append({
                                                "enterprise_user_id": user_id,
                                                "tree_key": utils.base64_url_encode(encrypted_tree_key)
                                            })
                        request_batch.append(rq)

            elif kwargs.get('add_privilege') or kwargs.get('remove_privilege'):
                if len(matched_roles) != 1:
                    logging.warning('Add/Remove managed node privilege command expects exactly one role.')
                    return

                if not node_id:
                    logging.warning('Add/Remove managed node privilege: node parameter is required')
                    return
                role_id = matched_roles[0]['role_id']
                node = next((x for x in params.enterprise.get('managed_nodes', [])
                             if x['role_id'] == role_id and x['managed_node_id'] == node_id), None)
                if not node:
                    logging.warning('Role "%d" does not manage node "%d"', role_id, node_id)
                    return
                privileges = {x['privilege'] for x in params.enterprise.get('role_privileges', [])
                              if x['role_id'] == role_id and x['managed_node_id'] == node_id}
                all_privileges = {x[1].lower() for x in constants.ROLE_PRIVILEGES}
                for is_add in [True, False]:
                    parameter = 'add_privilege' if is_add else 'remove_privilege'
                    privilege_list = kwargs.get(parameter)
                    if isinstance(privilege_list, (list, tuple)):
                        for privilege in privilege_list:
                            privilege = privilege.lower()
                            if privilege not in all_privileges:
                                logging.warning('Add/Remove managed node privilege: invalid privilege: %s', privilege)
                                return
                            if is_add:
                                if privilege in ['transfer_account', 'manage_companies']:
                                    logging.warning('Add managed node privilege: Commander does not support \"%s\" privilege', privilege)
                                    return
                            if is_add and privilege in privileges:
                                logging.info('Add privilege: Role "%d", Mode "%s" already contains privilege "%s" ',
                                             role_id, node_id, privilege)
                                continue
                            if not is_add and privilege not in privileges:
                                logging.info('Remove privilege: Role "%d", Mode "%s" does not contains privilege "%s" ',
                                             role_id, node_id, privilege)
                                continue

                            rq = {
                                'command': 'managed_node_privilege_add' if is_add else 'managed_node_privilege_remove',
                                'role_id': role_id,
                                'managed_node_id': node_id,
                                'privilege': privilege
                            }
                            request_batch.append(rq)

            elif kwargs.get('copy') or kwargs.get('clone'):
                role_name = kwargs.get('name')
                role = matched_roles[0]
                if not role_name:
                    role_name = role['data'].get('displayname')
                if not node_id:
                    node_id = role['node_id']
                dt = { "displayname": role_name }
                role_id = self.get_enterprise_id(params)
                rq = {
                    "command": "role_add",
                    "role_id": role_id,
                    "node_id": node_id,
                    "encrypted_data": api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key']),
                    "visible_below": role.get('visible_below') or False,
                    "new_user_inherit": role.get('new_user_inherit') or False
                }
                request_batch.append(rq)
                if 'role_enforcements' in params.enterprise:
                    lookup = {x['role_id']: x['enforcements'] for x in params.enterprise['role_enforcements']}
                    enforcements = {}
                    for r in matched_roles:
                        enf = lookup.get(r.get('role_id'))
                        if isinstance(enf, dict):
                            for k, v in enf.items():
                                if k not in enforcements:
                                    enforcements[k] = v
                    for k, v in enforcements.items():
                        rq = {
                            'command': 'role_enforcement_add',
                            'role_id': role_id,
                            'enforcement': k
                        }
                        if v is not None:
                            enforcement_type = constants.ENFORCEMENTS.get(k)
                            if enforcement_type == 'boolean':
                                if not isinstance(v, bool):
                                    v = True
                            elif enforcement_type == 'long':
                                if not isinstance(v, int):
                                    try:
                                        v = int(v)
                                    except:
                                        continue
                            elif enforcement_type in {'json', 'record_types', 'jsonarray'}:
                                if not isinstance(v, dict):
                                    try:
                                        v = json.loads(v)
                                    except:
                                        continue
                            rq['value'] = v
                        request_batch.append(rq)
                if kwargs.get('clone'):
                    if 'role_users' in params.enterprise:
                        roles = {x['role_id'] for x in matched_roles}
                        users = set()
                        for x in params.enterprise['role_users']:
                            if x['role_id'] in roles:
                                users.add(x['enterprise_user_id'])
                        for user_id in users:
                            rq = {
                                'command': 'role_user_add',
                                'role_id': role_id,
                                'enterprise_user_id': user_id,
                            }
                            request_batch.append(rq)

            elif node_id or kwargs.get('visible_below') or kwargs.get('new_user') or kwargs.get('name'):
                if kwargs.get('name') and len(matched_roles) > 1:
                    logging.warning('Cannot assign the same name to %s roles', len(matched_roles))
                    kwargs['name'] = None

                for role in matched_roles:
                    encrypted_data = role['encrypted_data']
                    if kwargs.get('name'):
                        role_name = kwargs.get('name').strip()
                        dt = { "displayname": role_name }
                        encrypted_data = api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key'])
                    rq = {
                        "command": "role_update",
                        "role_id": role['role_id'],
                        "node_id": node_id or role['node_id'],
                        "encrypted_data": encrypted_data
                    }
                    if kwargs.get('visible_below'):
                        rq['visible_below'] = kwargs.get('visible_below') == 'on'
                    if kwargs.get('new_user'):
                        rq['new_user_inherit'] = kwargs['new_user'] == 'on'
                    request_batch.append(rq)

        if request_batch:
            rss = api.execute_batch(params, request_batch)
            for rq, rs in zip(request_batch, rss):
                command = rq.get('command')
                if command == 'role_add':
                    if rs['result'] == 'success':
                        logging.info('Role created')
                    else:
                        logging.warning('Failed to create role: %s', rs['message'])
                else:
                    role = None
                    if not role and 'role_id' in rq:
                        role = role_lookup.get(str(rq['role_id']))
                    if role:
                        role_name = role['data'].get('displayname')
                        if command in { 'role_delete', 'role_update' }:
                            if rs['result'] == 'success':
                                logging.info('\'%s\' role is %s', role_name, 'deleted' if command == 'role_delete' else 'updated')
                            else:
                                logging.warning('\'%s\' failed to %s role: %s', role_name, 'delete' if command == 'role_delete' else 'update',  rs['message'])
                        elif command in {'role_user_add', 'role_user_remove'}:
                            user_names = [x['username'] for x in params.enterprise['users'] if x['enterprise_user_id'] == rq['enterprise_user_id']]
                            user_name = user_names[0] if len(user_names) > 0 else str(rq['enterprise_user_id'])
                            if rs['result'] == 'success':
                                logging.info('\'%s\' role %s %s', role_name, 'assigned to' if command == 'role_user_add' else 'removed from', user_name)
                            else:
                                logging.warning('\'%s\' role failed to %s %s: %s', role_name, 'assign' if command == 'role_user_add' else 'remove', user_name, rs['message'])
                        elif command in {'role_managed_node_add', 'role_managed_node_remove'}:
                            node_names = [x for x in params.enterprise['nodes'] if x['node_id'] == rq['managed_node_id']]
                            node_name = (node_names[0]['data'].get('displayname') or params.enterprise['enterprise_name']) if len(node_names) > 0 else ''
                            if rs['result'] == 'success':
                                logging.info('\'%s\' role is %s managing node \'%s\'',
                                             role_name, 'assigned to' if command == 'role_managed_node_add' else 'removed from', node_name)
                            else:
                                logging.warning('\'%s\' role failed to %s managing node \'%s\': %s',
                                                role_name, 'assign' if command == 'role_managed_node_add' else 'remove', node_name, rs['message'])
                        elif command in {'managed_node_privilege_add', 'managed_node_privilege_remove'}:
                            node_names = [x for x in params.enterprise['nodes'] if x['node_id'] == rq['managed_node_id']]
                            node_name = (node_names[0]['data'].get('displayname') or params.enterprise['enterprise_name']) if len(node_names) > 0 else ''
                            privilege = rq['privilege']
                            if rs['result'] == 'success':
                                logging.info('Node \'%s\' in role \'%s\' has \'%s\' privilege %s',
                                             node_name, role_name, privilege,
                                             'assigned' if command == 'managed_node_privilege_add' else 'removed')
                            else:
                                logging.warning('Failed to %s \'%s\' privilege to node \'%s\' in role \'%s\': %s',
                                                'assign' if command == 'managed_node_privilege_add' else 'remove',
                                                privilege, node_name, role_name, rs['message'])

                        elif command in {'role_enforcement_add', 'role_enforcement_update', 'role_enforcement_remove'}:
                            enforcement = rq['enforcement']
                            if rs['result'] == 'success':
                                logging.info('Enforcement \'%s\' is %s role \'%s\'',
                                             enforcement,
                                             'removed from' if command == 'role_enforcement_remove' else 'set to',
                                             role_name)
                            else:
                                logging.warning('Enforcement \'%s\' role failed to be %s role \'%s\': %s',
                                                enforcement,
                                                'removed from' if command == 'role_enforcement_remove' else 'set to',
                                                role_name,
                                                rs['message'])
                        else:
                            if rs['result'] != 'success':
                                logging.warning('\'%s\' error: %s', command, rs['message'])
                    else:
                        if rs['result'] != 'success':
                            logging.warning('Error: %s', rs['message'])

        if request_batch or len(non_batch_update_msgs) > 0:
            for update_msg in non_batch_update_msgs:
                logging.info(update_msg)
            api.query_enterprise(params)
        else:
            if kwargs.get('format') == 'json':
                json_roles = []
                for role in matched_roles:
                    json_roles.append(self.dump_role_json(params, role))
                if len(json_roles) == 1:
                    json_roles = json_roles[0]
                file_name = kwargs.get('output')
                if file_name:
                    with open(file_name, 'w') as f:
                        json.dump(json_roles, f, indent=4)
                else:
                    return json.dumps(json_roles, indent=4)
            else:
                if not skip_display:
                    for role in matched_roles:
                        print('\n')
                        self.display_role(params, role, kwargs.get('verbose'))
                    print('\n')

    def dump_role_json(self, params, role):
        role_id = role['role_id']
        ret = {
            'role_id': role_id,
            'name': role['data'].get('displayname'),
            'node_id':  role['node_id'],
            'node_name': self.get_node_path(params, role['node_id']),
            'default_role': role.get('new_user_inherit', False),
            'users': [],
            'teams': []
        }
        if 'role_users' in params.enterprise:
            user_ids = [r['enterprise_user_id'] for r in params.enterprise['role_users'] if r['role_id'] == role_id]
            if len(user_ids) > 0:
                users = {u['enterprise_user_id']: u['username'] for u in params.enterprise['users']}
                ret['users'] = [{'user_id': i, 'username': users[i]} for i in user_ids if i in users]

        if 'role_teams' in params.enterprise:
            team_ids = [r['team_uid'] for r in params.enterprise['role_teams'] if r['role_id'] == role_id]
            if len(team_ids) > 0:
                teams = {t['team_uid']: t['name'] for t in params.enterprise['teams']}
                ret['teams'] = [{'team_id': i, 'team_name': teams[i]} for i in team_ids if i in teams]

        if 'managed_nodes' in params.enterprise:
            node_ids = [x['managed_node_id'] for x in params.enterprise['managed_nodes'] if x['role_id'] == role_id]
            if len(node_ids) > 0:
                nodes = {x['node_id']: x['data'].get('displayname') or params.enterprise['enterprise_name'] for x in params.enterprise['nodes']}
                ret['managed_nodes'] = [{
                    'node_id': x,
                    'node_name': nodes[x]
                } for x in node_ids if x in nodes]

        if 'role_enforcements' in params.enterprise:
            enforcements = next((x for x in params.enterprise['role_enforcements'] if role_id == x['role_id']), None)
            if isinstance(enforcements, dict):
                ret['enforcements'] = {}
                for k, v in enforcements.get('enforcements', {}).items():
                    enforcement_type = constants.ENFORCEMENTS.get(k)
                    if enforcement_type == 'boolean':
                        if not isinstance(v, bool):
                            v = True
                    elif enforcement_type == 'long':
                        if not isinstance(v, int):
                            try:
                                v = int(v)
                            except:
                                continue
                    elif enforcement_type in {'json', 'jsonarray'}:
                        if not isinstance(v, dict):
                            try:
                                v = json.loads(v)
                            except:
                                continue
                    elif enforcement_type == 'record_types':
                        try:
                            rto = v if isinstance(v, dict) else json.loads(v)
                            if params.record_type_cache:
                                record_types = []
                                for record_type_id in itertools.chain(rto.get('std') or [], rto.get('ent') or []):
                                    if record_type_id in params.record_type_cache:
                                        rtc = json.loads(params.record_type_cache[record_type_id])
                                        if '$id' in rtc:
                                            record_types.append(rtc['$id'])
                                v = ', '.join(record_types)
                        except:
                            v = 'Error'
                    elif enforcement_type == 'two_factor_duration':
                        value = [x.strip() for x in v.split(',')]
                        value = ['login' if x == '0' else
                                 '30_days' if x == '30' else
                                 'forever' if x == '9999' else x for x in value]
                        v = ', '.join(value)

                    ret['enforcements'][k] = v
        return ret

    def display_role(self, params, role, is_verbose=False):
        role_id = role['role_id']
        print('{0:>24s}: {1}'.format('Role ID', role_id))
        print('{0:>24s}: {1}'.format('Role Name', role['data'].get('displayname')))
        print('{0:>24s}: {1}'.format('Node', self.get_node_path(params, role['node_id'])))
        print('{0:>24s}: {1}'.format('Default Role', 'Yes' if role['new_user_inherit'] else 'No'))
        if 'role_users' in params.enterprise:
            user_ids = [r['enterprise_user_id'] for r in params.enterprise['role_users'] if r['role_id'] == role_id]
            if len(user_ids) > 0:
                users = {u['enterprise_user_id']: u['username'] for u in params.enterprise['users']}
                user_ids.sort(key=lambda x: users[x])
                for i, user_id in enumerate(user_ids):
                    print('{0:>25s} {1:<32s} {2}'.format(
                        'User(s):' if i == 0 else '', users[user_id], user_id if is_verbose else ''
                    ))

        if 'role_teams' in params.enterprise:
            team_ids = [r['team_uid'] for r in params.enterprise['role_teams'] if r['role_id'] == role_id]
            if len(team_ids) > 0:
                teams = {t['team_uid']: t['name'] for t in params.enterprise['teams']}
                team_ids.sort(key=lambda x: teams[x])
                for i, team_id in enumerate(team_ids):
                    print('{0:>25s} {1:<32s} {2}'.format(
                        'Team(s):' if i == 0 else '', teams[team_id], team_id if is_verbose else ''
                    ))

        if 'managed_nodes' in params.enterprise:
            node_ids = {x['managed_node_id']: x['cascade_node_management']
                        for x in params.enterprise['managed_nodes'] if x['role_id'] == role_id}
            is_msp = EnterpriseCommand.is_msp(params)
            if len(node_ids) > 0:
                nodes = {}
                for node in params.enterprise['nodes']:
                    nodes[node['node_id']] = node['data'].get('displayname') or params.enterprise['enterprise_name']
                privileges = {}    # type: Dict[str, Set[int]]
                for rp in params.enterprise.get('role_privileges', []):
                    if rp['role_id'] != role_id:
                        continue
                    privilege = rp['privilege'].lower()
                    if privilege not in privileges:
                        privileges[privilege] = set()
                    privileges[privilege].add(rp['managed_node_id'])
                headers = ['Privilege']
                if is_verbose:
                    headers.append('Code')
                for node_id in node_ids:
                    headers.append(nodes[node_id])

                table = []
                for priv in constants.ROLE_PRIVILEGES:
                    if priv[2] == constants.PrivilegeScope.Hidden:
                        continue
                    if priv[2] == constants.PrivilegeScope.MSP and not is_msp:
                        continue
                    privilege = priv[1].lower()
                    nodes = privileges[privilege] if privilege in privileges else set()
                    if not is_verbose and len(nodes) == 0:
                        continue

                    row = [priv[0]]
                    if is_verbose:
                        row.append(privilege)
                    for node_id in node_ids:
                        row.append('X' if node_id in nodes else '')
                    table.append(row)

                table.append(['------------------------'])
                if is_verbose:
                    row = ['Node ID', '']
                    for node_id in node_ids:
                        row.append(node_id)
                    table.append(row)
                row = ['Cascade Node Permissions']
                if is_verbose:
                    row.append('')
                for node_id in node_ids:
                    row.append('Yes' if node_ids[node_id] else 'No')
                table.append(row)

                dump_report_data(table, headers, title='Managed Node Privileges')

        if 'role_enforcements' in params.enterprise:
            enforcements = None
            for e in params.enterprise['role_enforcements']:
                if role_id == e['role_id']:
                    enforcements = e['enforcements']
                    break
            if enforcements:
                print('\n{0:>24s}: '.format('Role Enforcements'))
                enforcement_list = constants.enforcement_list()
                if not is_verbose:
                    enforcement_list = [x for x in enforcement_list if x[1] in enforcements]
                last_group = ''
                for e in enforcement_list:
                    if e[0] != last_group:
                        last_group = e[0]
                        print('\n{0}'.format(last_group))
                    value = enforcements.get(e[1])
                    if value:
                        value_type = e[2]
                        if value_type == 'record_types':
                            try:
                                rto = value if isinstance(value, dict) else json.loads(value)
                                if params.record_type_cache:
                                    record_types = []
                                    for record_type_id in itertools.chain(rto.get('std') or [], rto.get('ent') or []):
                                        if record_type_id in params.record_type_cache:
                                            rtc = json.loads(params.record_type_cache[record_type_id])
                                            if '$id' in rtc:
                                                record_types.append(rtc['$id'])
                                    value = ', '.join(record_types)
                            except:
                                value = 'Error'
                        elif value_type == 'two_factor_duration':
                            value = [x.strip() for x in value.split(',')]
                            value = ['login' if x == '0' else
                                     '30_days' if x == '30' else
                                     'forever' if x == '9999' else x for x in value]
                            value = ', '.join(value)
                        else:
                            value = str(value)
                    else:
                        value = ''
                    print('{0:<40s}: {1}'.format(e[1], value))


class EnterpriseTeamCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_team_parser

    def execute(self, params, **kwargs):
        if (kwargs.get('add') or kwargs.get('approve')) and kwargs.get('remove'):
            raise CommandError('enterprise-team', "'add'/'approve' and 'delete' commands are mutually exclusive.")

        team_lookup = {}
        if 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                team_lookup[team['team_uid']] = team
                team_lookup[team['name'].lower()] = team

        if 'queued_teams' in params.enterprise:
            for team in params.enterprise['queued_teams']:
                team_lookup[team['team_uid']] = team
                team_lookup[team['name'].lower()] = team

        node_id = None
        node_name = kwargs.get('node')
        if node_name:
            nodes = list(self.resolve_nodes(params, node_name))
            if len(nodes) == 0:
                logging.warning('Node \"%s\" is not found', node_name)
                return
            if len(nodes) > 1:
                logging.warning('More than one node \"%s\" are found', node_name)
                return
            node_id = nodes[0]['node_id']

        matched = {}
        team_names = set()

        for team_name in kwargs.get('team', []):
            t = team_lookup.get(team_name)
            if t is None:
                t = team_lookup.get(team_name.lower())
            if t is None:
                team_names.add(team_name)
            elif type(t) == list:
                team_in_node = None
                if node_id:
                    for ro in t:
                        if ro['node_id'] == node_id:
                            team_in_node = ro
                            break
                if team_in_node:
                    matched[team_in_node['team_uid']] = team_in_node
                else:
                    logging.warning('Team name \'%s\' is not unique. Use Team UID. Skipping', team_name)
            elif type(t) == dict:
                matched[t['team_uid']] = t

        matched_teams = list(matched.values())
        request_batch = []
        non_batch_update_msgs = []

        if kwargs.get('add') or kwargs.get('approve'):
            queue = []
            for team in matched_teams:
                if kwargs.get('approve'):
                    if 'restrict_edit' not in team:
                        queue.append(team)
                        continue
                logging.warning('Team \'%s\' already exists: Skipping', team['name'])

            if kwargs.get('add'):
                queue.extend(team_names)

            if not queue:
                return

            if node_id is None:
                root_nodes = list(self.get_user_root_nodes(params))
                if len(root_nodes) == 0:
                    raise CommandError('enterprise-user', 'No root nodes were detected. Specify --node parameter')
                node_id = root_nodes[0]

            for item in queue:
                is_new_team = type(item) == str
                team_name = item if is_new_team else item['name']
                team_node_id = node_id if is_new_team else item['node_id']
                team_uid = api.generate_record_uid() if is_new_team else item['team_uid']
                team_key = api.generate_aes_key()
                encrypted_team_key = rest_api.encrypt_aes(team_key, params.enterprise['unencrypted_tree_key'])

                private_key, public_key = crypto.generate_rsa_key()
                encrypted_private_key = crypto.encrypt_aes_v1(crypto.unload_rsa_private_key(private_key), team_key)
                rq = {
                    'command': 'team_add',
                    'team_uid': team_uid,
                    'team_name': team_name,
                    'restrict_edit': kwargs.get('restrict_edit') == 'on',
                    'restrict_share': kwargs.get('restrict_share') == 'on',
                    'restrict_view': kwargs.get('restrict_view') == 'on',
                    'public_key': utils.base64_url_encode(crypto.unload_rsa_public_key(public_key)),
                    'private_key': utils.base64_url_encode(encrypted_private_key),
                    'node_id': team_node_id,
                    'team_key': utils.base64_url_encode(crypto.encrypt_aes_v1(team_key, params.data_key)),
                    'encrypted_team_key': utils.base64_url_encode(encrypted_team_key),
                    'manage_only': True
                }
                request_batch.append(rq)
        else:
            for team_name in team_names:
                logging.warning('\'%s\' team is not found: Skipping', team_name)

            if not matched_teams:
                return

            if kwargs.get('delete'):
                answer = 'y' if kwargs.get('force') else \
                    user_choice('Delete Team(s)\n\nAre you sure you want to delete {0} team(s)'.format(len(matched_teams)), 'yn', 'n')
                if answer.lower() == 'y':
                    for team in matched_teams:
                        rq = {
                            'command': 'team_delete',
                            'team_uid': team['team_uid']
                        }
                        request_batch.append(rq)

            if kwargs.get('add_role') or kwargs.get('remove_role'):
                non_batch_update_msgs = self.change_team_roles(
                    params, matched_teams, kwargs.get('add_role'), kwargs.get('remove_role')
                )

            if kwargs.get('add_user') or kwargs.get('remove_user'):
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
                                                  user['username'].lower() }:
                                        user_node = user
                                        break
                            if user_node:
                                user_id = user_node['enterprise_user_id']
                                users[user_id] = is_add, user_node
                            else:
                                logging.warning('User %s could not be resolved', u)

                if len(users) > 0:
                    for team in matched_teams:
                        team_uid = team['team_uid']
                        is_real_team = 'restrict_edit' in team
                        for user_id in users:
                            is_add, user = users[user_id]
                            rq = None
                            if is_add:
                                is_active_user = user['status'] == 'active'
                                if is_real_team and is_active_user:
                                    hsf = kwargs.get('hide_shared_folders') or ''
                                    is_added = False
                                    if 'team_users' in params.enterprise:
                                        is_added = \
                                            any(1 for t in params.enterprise['team_users']
                                                if t['team_uid'] == team_uid and t['enterprise_user_id'] == user_id)
                                    if is_added:
                                        if not hsf:
                                            continue
                                        rq = {
                                            'command': 'team_enterprise_user_update',
                                            'team_uid': team_uid,
                                            'enterprise_user_id': user_id,
                                        }
                                    else:
                                        public_key = self.get_public_key(params, user['username'])
                                        team_key = self.get_team_key(params, team['team_uid'])
                                        encrypted_team_key = crypto.encrypt_rsa(team_key, public_key)
                                        if public_key and team_key:
                                            rq = {
                                                'command': 'team_enterprise_user_add',
                                                'team_uid': team['team_uid'],
                                                'enterprise_user_id': user_id,
                                                'user_type': 0,
                                                'team_key': utils.base64_url_encode(encrypted_team_key)
                                            }
                                    if hsf:
                                        rq['user_type'] = 2 if hsf == 'on' else 1
                                else:
                                    rq = {
                                        'command': 'team_queue_user',
                                        'team_uid': team['team_uid'],
                                        'enterprise_user_id': user_id
                                    }
                            else:
                                rq = {
                                    'command': 'team_enterprise_user_remove',
                                    'team_uid': team['team_uid'],
                                    'enterprise_user_id': user_id
                                }
                            if rq:
                                request_batch.append(rq)
            elif node_id or kwargs.get('name') or kwargs.get('restrict_edit') or kwargs.get('restrict_share') or kwargs.get('restrict_view'):
                if kwargs.get('name') and len(matched_teams) > 1:
                    logging.warning('Cannot set same name to %s teams', len(matched_teams))
                    kwargs['name'] = None

                for team in matched_teams:
                    rq = {
                        'command': 'team_update',
                        'team_uid': team['team_uid'],
                        'team_name': kwargs.get('name') or team['name'],
                        'restrict_edit': kwargs.get('restrict_edit') == 'on' if kwargs.get('restrict_edit') else team['restrict_edit'],
                        'restrict_share': kwargs.get('restrict_share') == 'on' if kwargs.get('restrict_share') else team['restrict_sharing'],
                        'restrict_view': kwargs.get('restrict_view') == 'on' if kwargs.get('restrict_view') else team['restrict_view'],
                        'node_id': node_id or team['node_id']
                    }
                    request_batch.append(rq)

        if request_batch:
            rss = api.execute_batch(params, request_batch)
            for rq, rs in zip(request_batch, rss):
                command = rq.get('command')
                team_name = None
                if 'team_name' in rq:
                    team_name = rq['team_name']
                elif 'team_uid' in rq:
                    team = team_lookup.get(rq['team_uid'])
                    if team:
                        team_name = team['name']
                if not team_name:
                    team_name = rq['team_uid']
                if command in { 'team_add', 'team_delete', 'team_update' }:
                    verb = 'created' if command == 'team_add' else 'deleted' if command == 'team_delete' else 'updated'
                    if rs['result'] == 'success':
                        logging.info('\'%s\' team is %s', team_name, verb)
                    else:
                        logging.warning('\'%s\' team is not %s: %s', team_name, verb, rs['message'])
                elif command in {'team_enterprise_user_add', 'team_queue_user', 'team_enterprise_user_remove'}:
                    user_id = rq['enterprise_user_id']
                    user_names = [x['username'] for x in params.enterprise['users'] if x['enterprise_user_id'] == user_id]
                    user_name = user_names[0] if len(user_names) > 0 else str(user_id)
                    if rs['result'] == 'success':
                        logging.info('\'%s\' %s team %s user %s', team_name, 'queued' if command == 'team_queue_user' else '',
                                     'deleted' if command == 'team_enterprise_user_remove' else 'added', user_name)
                    else:
                        logging.warning('\'%s\' %s team failed to %s user %s: %s', team_name, 'queued' if command == 'team_queue_user' else '',
                                        'delete' if command == 'team_enterprise_user_remove' else 'add', user_name, rs['message'])

        if request_batch or len(non_batch_update_msgs) > 0:
            for update_msg in non_batch_update_msgs:
                logging.info(update_msg)
            api.query_enterprise(params)
        else:
            for team in matched_teams:
                print('\n')
                self.display_team(params, team, kwargs.get('verbose'))
            print('\n')

    def display_team(self, params, team, is_verbose = False):
        team_uid = team['team_uid']
        is_queued_team = 'restrict_edit' not in team

        print('{0:>16s}: {1}'.format('Queued ' if is_queued_team else '' + 'Team UID', team_uid))
        print('{0:>16s}: {1}'.format('Queued ' if is_queued_team else '' + 'Team Name', team['name']))
        print('{0:>16s}: {1:<24s}{2}'.format(
            'Node', self.get_node_path(params, team['node_id']),
            f' [{team["node_id"]}]' if is_verbose else ''))
        if not is_queued_team:
            print('{0:>16s}: {1}'.format('Restrict Edit?', 'Yes' if team['restrict_edit'] else 'No'))
            print('{0:>16s}: {1}'.format('Restrict Share?', 'Yes' if team['restrict_sharing'] else 'No'))
            print('{0:>16s}: {1}'.format('Restrict View?', 'Yes' if team['restrict_view'] else 'No'))

        if 'role_teams' in params.enterprise:
            role_ids = [r['role_id'] for r in params.enterprise['role_teams'] if r['team_uid'] == team_uid]
            if len(role_ids) > 0:
                roles = {r['role_id']: r['data'].get('displayname', '[empty]') for r in params.enterprise['roles']}
                role_ids.sort(key=lambda x: roles[x])
                for i, role_id in enumerate(role_ids):
                    print('{0:>17s} {1:<24s} {2}'.format(
                        'Role(s):' if i == 0 else '', roles[role_id], role_id if is_verbose else ''
                    ))

        user_names = {u['enterprise_user_id']: u.get('username', '[empty]') for u in params.enterprise['users']}
        if 'team_users' in params.enterprise:
            user_teams = [x for x in params.enterprise['team_users'] if x['team_uid'] == team_uid]
            user_teams.sort(key=lambda x: user_names.get(x['enterprise_user_id']))
            for i, tu in enumerate(user_teams):
                user_id = tu['enterprise_user_id']
                print('{0:>17s} {1:<24s}{2} {3}'.format(
                    'Active User(s):' if i == 0 else '',
                    user_names[user_id] if user_id in user_names else f'(Unmanaged User: {user_id})',
                    f' [{user_id}]' if is_verbose else '',
                    '(No Shared Folders)' if tu.get('user_type') == 2 else ''
                ))

        if 'queued_team_users' in params.enterprise:
            user_ids = []
            for qtu in params.enterprise['queued_team_users']:
                if qtu['team_uid'] == team['team_uid']:
                    user_ids.extend(qtu['users'])
            user_ids.sort(key=lambda x: user_names.get(x))
            for i in range(len(user_ids)):
                print('{0:>16s}: {1:<24s} {2}'.format('Queued User(s)' if i == 0 else '', user_names[user_ids[i]], user_ids[i] if is_verbose else ''))


security_audit_report_description = '''
Security Audit Report Command Syntax Description:

Column Name       Description
  username          user name
  email             e-mail address
  weak              number of records whose password strength is in the weak category
  medium            number of records whose password strength is in the medium category
  strong            number of records whose password strength is in the strong category
  reused            number of reused passwords
  unique            number of unique passwords
  securityScore     security score
  twoFactorChannel  2FA - ON/OFF

--report-type:
            csv     CSV format
            json    JSON format
            table   Table format (default)
'''


class SecurityAuditReportCommand(EnterpriseCommand):
    def __init__(self):
        super(SecurityAuditReportCommand, self).__init__()
        self.user_lookup = None

    def get_parser(self):
        return security_audit_report_parser

    def get_security_score(self, total, strong, unique, twoFactorOn, masterPassword):
        strongByTotal = 0 if (total == 0) else (strong / total)
        uniqueByTotal = 0 if (total == 0) else (unique / total)
        twoFactorOnVal = 1 if (twoFactorOn is True) else 0
        score = (strongByTotal + uniqueByTotal + masterPassword + twoFactorOnVal) / 4
        return score

    def resolve_user_info(self, params, enterprise_user_id):
        if self.user_lookup is None:
            self.user_lookup = {}
            if params.enterprise:
                if 'users' in params.enterprise:
                    for user in params.enterprise['users']:
                        if 'enterprise_user_id' in user and 'username' in user:
                            email = user['username']
                            username = user['data']['displayname'] if 'data' in user and 'displayname' in user['data'] else None
                            if (username is None or not username.strip()) and 'encrypted_data' in user and 'key_type' in user:
                                username = user['encrypted_data'] if user['key_type'] == 'no_key' else None
                            username = email if username is None or not username.strip() else username
                            node_id = user.get('node_id', 0)
                            self.user_lookup[user['enterprise_user_id']] = \
                                {
                                    'username': username,
                                    'email': email,
                                    'node_id': node_id
                                }

        info = {
            'username': enterprise_user_id,
            'email': enterprise_user_id
        }

        if enterprise_user_id in self.user_lookup:
            info = self.user_lookup[enterprise_user_id]

        return info

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(security_audit_report_description)
            return

        rq = SecurityReportRequest()
        security_report_data_rs = api.communicate_rest(params, rq, 'enterprise/get_security_report_data', rs_type=SecurityReportResponse)

        rows = []
        for sr in security_report_data_rs.securityReport:
            user_info = self.resolve_user_info(params, sr.enterpriseUserId)
            user = user_info['username'] if 'username' in user_info else str(sr.enterpriseUserId)
            email = user_info['email'] if 'email' in user_info else str(sr.enterpriseUserId)
            node_id = user_info.get('node_id', 0)
            node_path = self.get_node_path(params, node_id) if node_id > 0 else ''
            twofa_on = False if sr.twoFactor == 'two_factor_disabled' else True
            row = {
                'username': user,
                'email': email,
                'node_path': node_path,
                'total': 0,
                'weak': 0,
                'medium': 0,
                'strong': 0,
                'reused': sr.numberOfReusedPassword,
                'unique': 0,
                'passed': 0,
                'at_risk': 0,
                'ignored': 0,
                'securityScore': 25,
                'twoFactorChannel': 'Off' if sr.twoFactor == 'two_factor_disabled' else 'On'
            }
            master_password_strength = 1

            if sr.encryptedReportData:
                sri = rest_api.decrypt_aes(sr.encryptedReportData, params.enterprise['unencrypted_tree_key'])
                data = json.loads(sri)
                if 'weak_record_passwords' in data:
                    row['weak'] = data['weak_record_passwords']
                if 'strong_record_passwords' in data:
                    row['strong'] = data['strong_record_passwords']
                if 'total_record_passwords' in data:
                    row['total'] = data['total_record_passwords']
                if 'passed_records' in data:
                    row['passed'] = data['passed_records']
                if 'at_risk_records' in data:
                    row['at_risk'] = data['at_risk_records']
                if 'ignored_records' in data:
                    row['ignored'] = data['ignored_records']

                row['medium'] = row['total'] - row['weak'] - row['strong']
                row['unique'] = row['total'] - row['reused']

                score = self.get_security_score(row['total'], row['strong'], row['unique'], twofa_on, master_password_strength)
                score = int(100 * round(score, 2))
                row['securityScore'] = score
            rows.append(row)

        fields = ('username', 'email', 'at_risk', 'passed', 'ignored') if kwargs.get('breachwatch') else \
            ('username', 'email', 'weak', 'medium', 'strong', 'reused', 'unique', 'securityScore', 'twoFactorChannel', 'node_path')
        field_descriptions = fields

        fmt = kwargs.get('format', 'table')
        if fmt == 'table':
            field_descriptions = (self.get_title_for_field(x) for x in fields)

        table = []
        for raw in rows:
            row = []
            for f in fields:
                row.append(raw[f])
            table.append(row)
        return dump_report_data(table, field_descriptions, fmt=fmt, filename=kwargs.get('output'))

    @staticmethod
    def get_title_for_field(field):  # type: (str) -> str
        if field == 'username':
            return 'User'
        elif field == 'email':
            return 'E-Mail'
        elif field == 'node_path':
            return 'Node'
        elif field == 'securityScore':
            return 'Security Score'
        elif field == 'twoFactorChannel':
            return '2FA'
        elif field == 'at_risk':
            return 'At Risk'

        return field.capitalize()


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
            raise CommandError('enterprise-push', 'The template file name arguments are required')

        file_name = os.path.abspath(os.path.expanduser(name))
        if os.path.isfile(file_name):
            with open(file_name, 'r') as f:
                template_records = json.load(f)
        else:
            raise CommandError('enterprise-push', 'File {0} does not exists'.format(name))

        emails = EnterprisePushCommand.collect_emails(params, kwargs)   # type: Dict[str, Any]

        if len(emails) == 0:
            raise CommandError('enterprise-push', 'No users')

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

                        encrypted_record_key = crypto.encrypt_rsa(record_key, emails[email])
                        record_keys[email][record_uid] = utils.base64_url_encode(encrypted_record_key)
            else:
                logging.warning('User %s is not created yet', email)

        for email in record_keys:
            for record_uid, record_key in record_keys[email].items():

                commands.append({
                    'command': 'record_share_update',
                    'pt': 'Commander',
                    'add_shares': [{
                                        'to_username': email,
                                        'record_uid': record_uid,
                                        'record_key': record_key,
                                        'transfer': True
                                    }]
                })

        rss = api.execute_batch(params, commands)
        if rss:
            for rs in rss:
                if 'result' in rs:
                    if rs['result'] != 'success':
                        logging.error('Push error (%s): %s', rs.get('result_code'), rs.get('message'))
        params.sync_data = True

    @staticmethod
    def collect_emails(params, kwargs):
        # Collect emails from individual users and from teams
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

            if 'teams' in params.enterprise:
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
            else:
                logging.warning('There are no teams to manage. Try to refresh your local data by synching data from the server (use command `enterprise-down`).')

        return emails


class UserReportCommand(EnterpriseCommand):
    def __init__(self):
        super(UserReportCommand, self).__init__()
        self.nodes = {}
        self.roles = {}
        self.teams = {}
        self.users = {}
        self.user_roles = {}
        self.user_teams = {}

    def get_parser(self):
        return user_report_parser

    def execute(self, params, **kwargs):
        self.nodes.clear()
        if 'nodes' in params.enterprise:
            for node in params.enterprise['nodes']:
                self.nodes[node['node_id']] = {
                    'parent_id': node.get('parent_id') or 0,
                    'name': node['data'].get('displayname') or ''
                }

        self.roles.clear()
        if 'roles' in params.enterprise:
            for role in params.enterprise['roles']:
                if 'data' in role:
                    self.roles[role['role_id']] = role['data'].get('displayname') or ''

        self.teams.clear()
        if 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                self.teams[team['team_uid']] = team['name']

        self.users.clear()
        if 'users' in params.enterprise:
            for user in params.enterprise['users']:
                u = {
                    'enterprise_user_id': user['enterprise_user_id'],
                    'node_id': user['node_id'],
                    'username': user['username'],
                    'name': user['data'].get('displayname') or '',
                    'status': user['status'],
                    'lock': user['lock']
                }
                if 'account_share_expiration' in user:
                    u['account_share_expiration'] = user['account_share_expiration']
                self.users[user['enterprise_user_id']] = u

        self.user_roles.clear()
        if 'role_users' in params.enterprise:
            for ru in params.enterprise['role_users']:
                if ru['enterprise_user_id'] not in self.user_roles:
                    self.user_roles[ru['enterprise_user_id']] = []
                if ru['role_id'] in self.roles:
                    self.user_roles[ru['enterprise_user_id']].append(self.roles[ru['role_id']])

        self.user_teams = {}
        if 'team_users' in params.enterprise:
            for tu in params.enterprise['team_users']:
                if tu['enterprise_user_id'] not in self.user_teams:
                    self.user_teams[tu['enterprise_user_id']] = []
                if tu['team_uid'] in self.teams:
                    self.user_teams[tu['enterprise_user_id']].append(self.teams[tu['team_uid']])

        look_back_days = kwargs.get('days') or 365
        report_filter = {'audit_event_type': 'login'}
        if look_back_days > 0:
            logging.info(f'Querying latest login for the last {look_back_days} days')
            from_date = datetime.datetime.utcnow() - datetime.timedelta(days=look_back_days)
            report_filter['created'] = {'min': int(from_date.timestamp())}
        rq = {
            "command": "get_enterprise_audit_event_reports",
            "report_type": "span",
            "aggregate": ["last_created"],
            "columns": ["username"],
            "filter": report_filter,
            "timezone": "UTC"
        }

        last_login = {}
        rs = api.communicate(params, rq)
        for row in rs['audit_event_overview_report_rows']:
            username = row['username']
            last_login[username.lower()] = row['last_created']
        if len(rs['audit_event_overview_report_rows']) >= 1000:
            active = (x['username'].lower() for x in self.users.values() if x['status'] == 'active')
            missing = [x for x in active if x not in last_login]
            while len(missing) > 0:
                report_filter['username'] = missing[:999]
                missing = missing[999:]
                rs = api.communicate(params, rq)
                for row in rs['audit_event_overview_report_rows']:
                    username = row['username']
                    last_login[username.lower()] = row['last_created']

        for user in self.users.values():
            key = user['username'].lower()
            if key in last_login:
                user['last_login'] = datetime.datetime.utcfromtimestamp(int(last_login[key])).replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)

        user_list = list(self.users.values())
        user_list.sort(key=lambda x: x['username'].lower())

        last_login_report = kwargs.get('last_login')
        rows = []
        headers_basic = ['email', 'name', 'status', 'transfer_status', 'last_login']
        headers_extra = [*headers_basic, 'node', 'roles', 'teams']
        headers = headers_basic if last_login_report else headers_extra
        for user in user_list:
            status_dict = get_user_status_dict(user)

            acct_status = status_dict['acct_status']
            acct_transfer_status = status_dict['acct_transfer_status']

            path = self.get_node_path(params, user['node_id'])
            teams = self.user_teams.get(user['enterprise_user_id']) or []
            roles = self.user_roles.get(user['enterprise_user_id']) or []
            teams.sort(key=str.lower)
            roles.sort(key=str.lower)
            ll = user.get('last_login')
            last_log = str(ll) if ll else ''
            row_basic = [
                user['username'],  # email
                user['name'],  # name
                acct_status,  # status == acct_status
                acct_transfer_status,  # acct_transfer_status
                last_log,  # last_login
            ]
            row_extra = [
                *row_basic,
                path,  # node
                roles,  # roles
                teams  # teams
            ]
            rows.append(row_basic if last_login_report else row_extra)

        if kwargs.get('format') != 'json':
            headers = [string.capwords(x.replace('_', ' ')) for x in headers]
        return dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

    @staticmethod
    def get_user_status(user):
        status = 'Invited' if user['status'] == 'invited' else 'Active'
        lock = user['lock']
        if lock == 1:
            status = 'Locked'
        elif lock == 2:
            status = 'Disabled'
        if 'account_share_expiration' in user:
            expire_at = datetime.datetime.fromtimestamp(user['account_share_expiration']/1000.0)
            if expire_at < datetime.datetime.now():
                status = 'Blocked'
            else:
                status = 'Pending Transfer'
        return status


class TeamApproveCommand(EnterpriseCommand):
    def get_parser(self):
        return team_approve_parser

    def execute(self, params, **kwargs):
        approve_teams = True
        approve_users = True
        if kwargs.get('team') or kwargs.get('user'):
            approve_teams = kwargs.get('team') or False
            approve_users = kwargs.get('user') or False

        request_batch = []
        if approve_teams and 'queued_teams' in params.enterprise:
            for team in params.enterprise['queued_teams']:
                team_name = team['name']
                team_node_id = team['node_id']
                team_uid = team['team_uid']
                team_key = api.generate_aes_key()
                tree_key = params.enterprise['unencrypted_tree_key']
                pri_key, pub_key = crypto.generate_rsa_key()
                private_key = crypto.unload_rsa_private_key(pri_key)
                private_key = crypto.encrypt_aes_v1(private_key, team_key)
                public_key = crypto.unload_rsa_public_key(pub_key)

                rq = {
                    'command': 'team_add',
                    'team_uid': team_uid,
                    'team_name': team_name,
                    'restrict_edit': kwargs.get('restrict_edit') == 'on',
                    'restrict_share': kwargs.get('restrict_share') == 'on',
                    'restrict_view': kwargs.get('restrict_view') == 'on',
                    'public_key': utils.base64_url_encode(public_key),
                    'private_key': utils.base64_url_encode(private_key),
                    'node_id': team_node_id,
                    'team_key': utils.base64_url_encode(crypto.encrypt_aes_v1(team_key, params.data_key)),
                    'encrypted_team_key': utils.base64_url_encode(crypto.encrypt_aes_v2(team_key, tree_key)),
                    'manage_only': True
                }
                request_batch.append(rq)
            if request_batch:
                rs = api.execute_batch(params, request_batch)
                if rs:
                    success = 0
                    failure = 0
                    for status in rs:
                        if 'result' in status:
                            if status['result'] == 'success':
                                success += 1
                            else:
                                failure += 1
                    if success or failure:
                        logging.info('Team approval: success %s; failure %s', success, failure)
                api.query_enterprise(params)

        request_batch.clear()
        if approve_users and 'queued_team_users' in params.enterprise and \
                'teams' in params.enterprise and 'users' in params.enterprise:
            active_users = {}
            for u in params.enterprise['users']:
                if u['status'] == 'active' and u['lock'] == 0:
                    active_users[u['enterprise_user_id']] = u['username']

            teams = {}
            for t in params.enterprise['teams']:
                teams[t['team_uid']] = t

            for qtu in params.enterprise['queued_team_users']:
                team_uid = qtu['team_uid']
                if team_uid in teams:
                    if 'users' in qtu:
                        for u_id in qtu['users']:
                            if u_id not in active_users:
                                continue
                            rq = {
                                'command': 'team_enterprise_user_add',
                                'team_uid': team_uid,
                                'enterprise_user_id': u_id,
                            }
                            team_key = self.get_team_key(params, team_uid)
                            public_key = self.get_public_key(params, active_users[u_id])
                            encrypted_team_key = crypto.encrypt_rsa(team_key, public_key)
                            if team_key and public_key:
                                rq['team_key'] = utils.base64_url_encode(encrypted_team_key)
                                rq['user_type'] = 0
                                request_batch.append(rq)
            if request_batch:
                rs = api.execute_batch(params, request_batch)
                if rs:
                    success = 0
                    failure = 0
                    for status in rs:
                        if 'result' in status:
                            if status['result'] == 'success':
                                success += 1
                            else:
                                failure += 1
                    if success or failure:
                        logging.info('Team User approval: success %s; failure %s', success, failure)
                api.query_enterprise(params)


class DeviceApproveCommand(EnterpriseCommand):
    def get_parser(self):
        return device_approve_parser

    @staticmethod
    def token_to_string(token): # type: (bytes) -> str
        src = token[0:10]
        if src.hex:
            return src.hex()
        return ''.join('{:02x}'.format(x) for x in src)

    def execute(self, params, **kwargs):
        if kwargs.get('reload'):
            api.query_enterprise(params)

        approval_requests = params.enterprise.get('devices_request_for_admin_approval')
        if not approval_requests:
            logging.info('There are no pending devices to approve')
            return

        if kwargs.get('approve') and kwargs.get('deny'):
            raise CommandError('device-approve', "'approve' and 'deny' parameters are mutually exclusive.")

        devices = kwargs.get('device')
        matching_devices = {}
        for device in approval_requests:
            device_id = device.get('encrypted_device_token')
            if not device_id:
                continue
            device_id = DeviceApproveCommand.token_to_string(utils.base64_url_decode(device_id))
            found = False
            if isinstance(devices, (list, tuple)):
                for name in devices:
                    if name:
                        if device_id.startswith(name):
                            found = True
                            break
                        ent_user_id = device.get('enterprise_user_id')
                        u = next((x for x in params.enterprise['users'] if x.get('enterprise_user_id') == ent_user_id), None)
                        if u:
                            if u.get('username') == name:
                                found = True
                                break
                    else:
                        found = True
            else:
                found = True
            if found:
                matching_devices[device_id] = device

        if len(matching_devices) == 0:
            logging.info('No matching devices found')
            return

        if kwargs.get('approve') and kwargs.get('check_ip'):
            user_ids = set([x['enterprise_user_id'] for x in matching_devices.values() if 'enterprise_user_id' in x])
            emails = {}
            for u in params.enterprise['users']:
                user_id = u['enterprise_user_id']
                if user_id in user_ids:
                    emails[user_id] = u['username']

            last_year = datetime.datetime.now() - datetime.timedelta(days=365)
            rq = {
                'command': 'get_audit_event_reports',
                'report_type': 'span',
                'scope': 'enterprise',
                'columns': ['ip_address', 'username'],
                'filter': {
                    'audit_event_type': 'login',
                    'created': {
                        "min": int(last_year.timestamp())
                    },
                    'username': list(emails.values())
                },
                'limit': 1000
            }
            rs = api.communicate(params, rq)
            ip_map = {}
            if 'audit_event_overview_report_rows' in rs:
                for row in rs['audit_event_overview_report_rows']:
                    if 'username' in row and 'ip_address' in row:
                        uname = row['username']
                        if uname not in ip_map:
                            ip_map[uname] = set()
                        ip_map[uname].add(row['ip_address'])

            # Filter out users that tried to login from an untrusted IP
            trusted_devices = {}    # To avoid array modification in a loop, we will store this into a separated dict

            for k, v in matching_devices.items():
                p_uname = emails.get(v.get('enterprise_user_id'))
                p_ip_addr = v.get('ip_address')
                keep = p_uname and p_ip_addr and p_uname in ip_map and p_ip_addr in ip_map[p_uname]
                if keep:
                    trusted_devices[k] = v
                else:
                    logging.warning("The user %s attempted to login from an unstrusted IP (%s). "
                                    "To force the approval, run the same command without the --trusted-ip argument", p_uname, p_ip_addr)

            matching_devices = trusted_devices

        if len(matching_devices) == 0:
            logging.info('No matching devices found')
            return

        if kwargs.get('approve') or kwargs.get('deny'):
            approve_rq = ApproveUserDevicesRequest()
            data_keys = {}
            curve = ec.SECP256R1()
            if kwargs.get('approve'):
                # resolve user data keys shared with enterprise
                user_ids = set([x['enterprise_user_id'] for x in matching_devices.values()])
                user_ids.difference_update(data_keys.keys())
                if len(user_ids) > 0:
                    ecc_private_key = None
                    if 'keys' in params.enterprise:
                        if 'ecc_encrypted_private_key' in params.enterprise['keys']:
                            keys = params.enterprise['keys']
                            try:
                                ecc_private_key_data = utils.base64_url_decode(keys['ecc_encrypted_private_key'])
                                ecc_private_key_data = api.decrypt_aes_plain(ecc_private_key_data, params.enterprise['unencrypted_tree_key'])
                                private_value = int.from_bytes(ecc_private_key_data, byteorder='big', signed=False)
                                ecc_private_key = ec.derive_private_key(private_value, curve, default_backend())
                            except Exception as e:
                                logging.debug(e)

                    if ecc_private_key:
                        data_key_rq = UserDataKeyRequest()
                        data_key_rq.enterpriseUserId.extend(user_ids)
                        data_key_rs = api.communicate_rest(params, data_key_rq, 'enterprise/get_enterprise_user_data_key', rs_type=EnterpriseUserDataKeys)
                        for key in data_key_rs.keys:
                            enc_data_key = key.userEncryptedDataKey
                            if enc_data_key:
                                try:
                                    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, enc_data_key[:65])
                                    shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
                                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                                    digest.update(shared_key)
                                    enc_key = digest.finalize()
                                    data_key = api.decrypt_aes_plain(enc_data_key[65:], enc_key)
                                    data_keys[key.enterpriseUserId] = data_key
                                except Exception as e:
                                    logging.debug(e)

                # resolve user data keys from Account Transfer
                user_ids = set([x['enterprise_user_id'] for x in matching_devices.values()])
                user_ids.difference_update(data_keys.keys())
                if len(user_ids) > 0:
                    data_key_rq = UserDataKeyRequest()
                    data_key_rq.enterpriseUserId.extend(user_ids)
                    data_key_rs = api.communicate_rest(params, data_key_rq, 'enterprise/get_user_data_key_shared_to_enterprise', rs_type=UserDataKeyResponse)
                    if data_key_rs.noEncryptedDataKey:
                        user_ids = set(data_key_rs.noEncryptedDataKey)
                        usernames = [x['username'] for x in params.enterprise['users'] if x['enterprise_user_id'] in user_ids]
                        if usernames:
                            logging.info('User(s) \"%s\" have no accepted account transfers or did not share encryption key', ', '.join(usernames))
                    if data_key_rs.accessDenied:
                        user_ids = set(data_key_rs.noEncryptedDataKey)
                        usernames = [x['username'] for x in params.enterprise['users'] if x['enterprise_user_id'] in user_ids]
                        if usernames:
                            logging.info('You cannot manage these user(s): %s', ', '.join(usernames))
                    if data_key_rs.userDataKeys:
                        for dk in data_key_rs.userDataKeys:
                            try:
                                role_key = rest_api.decrypt_aes(dk.roleKey, params.enterprise['unencrypted_tree_key'])
                                private_key = api.decrypt_rsa_key(dk.privateKey, role_key)
                                for user_dk in dk.enterpriseUserIdDataKeyPairs:
                                    if user_dk.enterpriseUserId not in data_keys:
                                        data_key_str = base64.urlsafe_b64encode(user_dk.encryptedDataKey).strip(b'=').decode()
                                        data_key = api.decrypt_rsa(data_key_str, private_key)
                                        data_keys[user_dk.enterpriseUserId] = data_key
                            except Exception as ex:
                                logging.debug(ex)

            for device in matching_devices.values():
                ent_user_id = device['enterprise_user_id']
                device_rq = ApproveUserDeviceRequest()
                device_rq.enterpriseUserId = ent_user_id
                device_rq.encryptedDeviceToken = utils.base64_url_decode(device['encrypted_device_token'])
                device_rq.denyApproval = True if kwargs.get('deny') else False
                if kwargs.get('approve'):
                    public_key = device['device_public_key']
                    if not public_key or len(public_key) == 0:
                        continue
                    data_key = data_keys.get(ent_user_id)
                    if not data_key:
                        continue
                    try:
                        ephemeral_key = ec.generate_private_key(curve,  default_backend())
                        device_public_key = ec.EllipticCurvePublicKey. \
                            from_encoded_point(curve, utils.base64_url_decode(device['device_public_key']))
                        shared_key = ephemeral_key.exchange(ec.ECDH(), device_public_key)
                        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                        digest.update(shared_key)
                        enc_key = digest.finalize()
                        encrypted_data_key = rest_api.encrypt_aes(data_key, enc_key)
                        eph_public_key = ephemeral_key.public_key().public_bytes(
                            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                        device_rq.encryptedDeviceDataKey = eph_public_key + encrypted_data_key
                    except Exception as e:
                        logging.info(e)
                        return
                approve_rq.deviceRequests.append(device_rq)

            if len(approve_rq.deviceRequests) == 0:
                return

            rs = api.communicate_rest(params, approve_rq, 'enterprise/approve_user_devices', rs_type=ApproveUserDevicesResponse)
            api.query_enterprise(params)
        else:
            print('')
            headers = [
                'Date',
                'Email',
                'Device ID',
                'Device Name',
                'Device Type',
                'IP Address',
                'Client Version',
                'Location']

            if kwargs.get('format') == 'json':
                headers = [x.replace(' ', '_').lower() for x in headers]

            rows = []
            for k, v in matching_devices.items():
                user = next((x for x in params.enterprise['users']
                             if x.get('enterprise_user_id') == v.get('enterprise_user_id')), None)
                if not user:
                    continue

                date_formatted = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(v.get('date')/1000.0))

                rows.append([
                    date_formatted,
                    user.get('username'),
                    k,
                    v.get('device_name'),
                    v.get('device_type'),
                    v.get('ip_address'),
                    v.get('client_version'),
                    v.get('location')
                ])
            rows.sort(key=lambda x: x[0])
            return dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))
