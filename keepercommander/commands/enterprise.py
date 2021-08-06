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
import string

import requests
import logging
import platform
import datetime
import re
import gzip
import time
import socket
import ssl
import hashlib
import hmac
import copy
import os

from urllib.parse import urlparse, urlunparse
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from Cryptodome.Math.Numbers import Integer
from asciitree import LeftAligned
from collections import OrderedDict as OD
from argparse import RawTextHelpFormatter

from .base import user_choice, suppress_exit, raise_parse_exception, dump_report_data, Command
from .record import RecordAddCommand
from .. import api, rest_api, APIRequest_pb2 as proto
from ..display import bcolors
from ..record import Record
from ..params import KeeperParams
from ..generator import generate
from ..error import CommandError
from .enterprise_pb2 import (EnterpriseUserIds, ApproveUserDeviceRequest, ApproveUserDevicesRequest,
                             ApproveUserDevicesResponse, EnterpriseUserDataKeys, SetRestrictVisibilityRequest)
from ..APIRequest_pb2 import ApiRequestPayload, UserDataKeyRequest, UserDataKeyResponse


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
    commands['scim'] = EnterpriseScimCommand()

    commands['audit-log'] = AuditLogCommand()
    commands['audit-report'] = AuditReportCommand()
    commands['security-audit-report'] = SecurityAuditReportCommand()
    commands['user-report'] = UserReportCommand()


def register_command_info(aliases, command_info):
    aliases['al'] = 'audit-log'
    aliases['ed'] = 'enterprise-down'
    aliases['ei'] = 'enterprise-info'
    aliases['en'] = 'enterprise-node'
    aliases['eu'] = 'enterprise-user'
    aliases['er'] = 'enterprise-role'
    aliases['et'] = 'enterprise-team'
    aliases['sar'] = 'security-audit-report'

    for p in [enterprise_data_parser, enterprise_info_parser, enterprise_node_parser, enterprise_user_parser,
              enterprise_role_parser, enterprise_team_parser,
              enterprise_push_parser,
              team_approve_parser, device_approve_parser, scim_parser,
              audit_log_parser, audit_report_parser, security_audit_report_parser, user_report_parser]:
        command_info[p.prog] = p.description


SUPPORTED_USER_COLUMNS = ['name', 'status', 'transfer_status', 'node', 'team_count', 'teams', 'role_count', 'roles']
SUPPORTED_TEAM_COLUMNS = ['restricts', 'node', 'user_count', 'users']
SUPPORTED_ROLE_COLUMNS = ['is_visible_below', 'is_new_user', 'is_admin', 'node', 'user_count', 'users']

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
                                         '\n for `users` (%s)' % ', '.join(SUPPORTED_USER_COLUMNS) +
                                         '\n for `teams` (%s)' % ', '.join(SUPPORTED_TEAM_COLUMNS) +
                                         '\n for `roles` (%s)' % ', '.join(SUPPORTED_ROLE_COLUMNS)
                                    )

enterprise_info_parser.add_argument('pattern', nargs='?', type=str,
                                    help='search pattern. applicable to users, teams, and roles.')
enterprise_info_parser.error = raise_parse_exception
enterprise_info_parser.exit = suppress_exit


enterprise_node_parser = argparse.ArgumentParser(prog='enterprise-node|en', description='Manage an enterprise node.')
enterprise_node_parser.add_argument('--wipe-out', dest='wipe_out', action='store_true', help='wipe out node content')
enterprise_node_parser.add_argument('--add', dest='add', action='store_true', help='create node')
enterprise_node_parser.add_argument('--parent', dest='parent', action='store', help='Parent Node Name or ID')
enterprise_node_parser.add_argument('--name', dest='displayname', action='store', help='set node display name')
enterprise_node_parser.add_argument('--delete', dest='delete', action='store_true', help='delete node')
enterprise_node_parser.add_argument('--toggle-isolated', dest='toggle_isolated', action='store_true', help='Render node invisible')
enterprise_node_parser.add_argument('node', type=str, nargs='+', help='Node Name or ID. Can be repeated.')
enterprise_node_parser.error = raise_parse_exception
enterprise_node_parser.exit = suppress_exit


enterprise_user_parser = argparse.ArgumentParser(prog='enterprise-user|eu', description='Manage an enterprise user.')
enterprise_user_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_user_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_user_parser.add_argument('--expire', dest='expire', action='store_true', help='expire master password')
enterprise_user_parser.add_argument('--extend', dest='extend', action='store_true', help='extend vault transfer consent by 7 days')
enterprise_user_parser.add_argument('--lock', dest='lock', action='store_true', help='lock user')
enterprise_user_parser.add_argument('--unlock', dest='unlock', action='store_true', help='unlock user')
enterprise_user_parser.add_argument('--disable-2fa', dest='disable_2fa', action='store_true', help='disable 2fa for user')
enterprise_user_parser.add_argument('--add', dest='add', action='store_true', help='invite user')
enterprise_user_parser.add_argument('--delete', dest='delete', action='store_true', help='delete user')
enterprise_user_parser.add_argument('--name', dest='displayname', action='store', help='set user display name')
enterprise_user_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
enterprise_user_parser.add_argument('--add-role', dest='add_role', action='append', help='role name or role ID')
enterprise_user_parser.add_argument('--remove-role', dest='remove_role', action='append', help='role name or role ID')
enterprise_user_parser.add_argument('--add-team', dest='add_team', action='append', help='team name or team UID')
enterprise_user_parser.add_argument('--remove-team', dest='remove_team', action='append', help='team name or team UID')
enterprise_user_parser.add_argument('email', type=str, nargs='+', help='User Email or ID. Can be repeated.')
enterprise_user_parser.error = raise_parse_exception
enterprise_user_parser.exit = suppress_exit


enterprise_role_parser = argparse.ArgumentParser(prog='enterprise-role|er', description='Manage an enterprise role(s).')
#enterprise_role_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_role_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_role_parser.add_argument('--add', dest='add', action='store_true', help='create role')
enterprise_role_parser.add_argument('--visible-below', dest='visible_below', action='store', choices=['on', 'off'], help='visible to all nodes. \'add\' only')
enterprise_role_parser.add_argument('--new-user', dest='new_user', action='store', choices=['on', 'off'], help='assign this role to new users. \'add\' only')
enterprise_role_parser.add_argument('--delete', dest='delete', action='store_true', help='delete role')
enterprise_role_parser.add_argument('--node', dest='node', action='store', help='node Name or ID')
enterprise_role_parser.add_argument('--name', dest='name', action='store', help='role\'s new name')
enterprise_role_parser.add_argument('--add-user', dest='add_user', action='append', help='add user to role')
enterprise_role_parser.add_argument('--remove-user', dest='remove_user', action='append', help='remove user from role')
enterprise_role_parser.add_argument('--add-admin', dest='add_admin', action='append', help='add managed node to role')
enterprise_role_parser.add_argument('--cascade', dest='cascade', action='store', choices=['on', 'off'], help='apply to the children nodes. \'add-admin\' only')
enterprise_role_parser.add_argument('--remove-admin', dest='remove_admin', action='append', help='remove managed node from role')
enterprise_role_parser.add_argument('role', type=str, nargs='+', help='Role Name ID. Can be repeated.')
enterprise_role_parser.error = raise_parse_exception
enterprise_role_parser.exit = suppress_exit


enterprise_team_parser = argparse.ArgumentParser(prog='enterprise-team|et', description='Manage an enterprise team.')
enterprise_team_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
enterprise_team_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
enterprise_team_parser.add_argument('--add', dest='add', action='store_true', help='create team')
enterprise_team_parser.add_argument('--approve', dest='approve', action='store_true', help='approve queued team')
enterprise_team_parser.add_argument('--delete', dest='delete', action='store_true', help='delete team')
enterprise_team_parser.add_argument('--add-user', dest='add_user', action='append', help='add user to team')
enterprise_team_parser.add_argument('--remove-user', dest='remove_user', action='append', help='remove user from team')
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
scim_parser.add_argument('command', type=str, nargs='?', help='Automator Command. list, view, create, edit, delete')
scim_parser.add_argument('target', type=str, nargs='?', help='Automator ID or Name. Command: view, edit, delete')
scim_parser.add_argument('--reload', '-r', dest='reload', action='store_true', help='Reload list of scim endpoints')
scim_parser.add_argument('--force', '-f', dest='force', action='store_true', help='Delete with no confirmation')
scim_parser.add_argument('--node', dest='node', help='Node Name or ID. Command: create')
scim_parser.add_argument('--prefix', dest='prefix', action='store',
                         help='Role Prefix. Command: create, edit. '
                              'SCIM groups staring with prefix will be imported to Keeper as Roles')
scim_parser.add_argument('--unique-groups', dest='unique_groups', action='store_true',
                         help='Unique Groups. Command: create, edit')

enterprise_push_parser = argparse.ArgumentParser(prog='enterprise-push', description='Populate user\'s vault with default records')
enterprise_push_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='Display help on file format and template parameters.')
enterprise_push_parser.add_argument('--team', dest='team', action='append', help='Team name or team UID. Records will be assigned to all users in the team.')
enterprise_push_parser.add_argument('--email', dest='user', action='append', help='User email or User ID. Records will be assigned to the user.')
enterprise_push_parser.add_argument('file', nargs='?', type=str, action='store', help='File name in JSON format that contains template records.')
enterprise_push_parser.error = raise_parse_exception
enterprise_push_parser.exit = suppress_exit


audit_log_parser = argparse.ArgumentParser(prog='audit-log', description='Export the enterprise audit log.')
audit_log_parser.add_argument('--anonymize', dest='anonymize', action='store_true', help='Anonymizes audit log by replacing email and user name with corresponding enterprise user id. If user was removed or if user\'s email was changed then the audit report will show that particular entry as deleted user.')
audit_log_parser.add_argument('--target', dest='target', choices=['splunk', 'syslog', 'syslog-port', 'sumo', 'azure-la', 'json'], required=True, action='store', help='export target')
audit_log_parser.add_argument('--record', dest='record', action='store', help='keeper record name or UID')
audit_log_parser.error = raise_parse_exception
audit_log_parser.exit = suppress_exit


audit_report_parser = argparse.ArgumentParser(prog='audit-report', description='Run an audit trail report.')
audit_report_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
audit_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv'], default='table', help='output format.')
audit_report_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
audit_report_parser.add_argument('--details', dest='details', action='store_true', help='lookup column details')
audit_report_parser.add_argument('--report-type', dest='report_type', choices=['raw', 'dim', 'hour', 'day', 'week', 'month', 'span'], required=True, action='store', help='report type')
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


security_audit_report_parser = argparse.ArgumentParser(prog='security-audit-report', description='Run a security audit report.')
security_audit_report_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
security_audit_report_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table', help='output format.')
security_audit_report_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
security_audit_report_parser.error = raise_parse_exception
security_audit_report_parser.exit = suppress_exit


user_report_parser = argparse.ArgumentParser(prog='user-report', description='Run a user report.')
user_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json', 'csv'], default='table', help='output format.')
user_report_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
user_report_parser.add_argument('--days', dest='days', action='store', type=int, default=365, help='number of days to look back for last login.')
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


class EnterpriseCommand(Command):
    def __init__(self):
        Command.__init__(self)
        self.public_keys = {}
        self.team_keys = {}

    def execute_args(self, params, args, **kwargs):
        if params.enterprise:
            Command.execute_args(self, params, args, **kwargs)
        else:
            raise CommandError('', 'This command  is only available for Administrators of Keeper.')

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
        # type: (EnterpriseCommand, KeeperParams, str) -> any

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
            if 'teams' in params.enterprise:
                for team in params.enterprise['teams']:
                    if team['team_uid'] == team_uid:
                        if 'encrypted_team_key' in team:
                            enc_team_key = team['encrypted_team_key']  # type: str
                            team_key = rest_api.decrypt_aes(base64.urlsafe_b64decode(enc_team_key + '=='), params.enterprise['unencrypted_tree_key'])
                        break

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
                        team_key = api.decrypt_data(ko['key'], params.data_key)
                    elif ko['type'] == 2:
                        team_key = api.decrypt_rsa(ko['key'], params.rsa_key)

        if team_key is not None:
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

    @staticmethod
    def resolve_nodes(params, name):   # type (KeeperParams, str) -> collections.Iterable[dict]
        node_id = 0
        node_name = ''
        if name:
            node_name = str(name).lower()
            try:
                node_id = int(name)
            except ValueError:
                pass

        for node in params.enterprise['nodes']:
            if node_id > 0:
                if node['node_id'] == node_id:
                    yield node
                    continue
            if node_name:
                if 'parent_id' in node:
                    display_name = node['data'].get('displayname') or ''
                else:
                    display_name = params.enterprise['enterprise_name'] or ''
                if display_name and display_name.lower() == node_name:
                    yield node
            else:
                if 'parent_id' not in node:
                    yield node


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
                    'users': []
                }
                if node_id in nodes:
                    nodes[node_id]['teams'].append(team_id)

        if 'team_users' in params.enterprise:
            for tu in params.enterprise['team_users']:
                if tu['team_uid'] in teams:
                    teams[tu['team_uid']]['users'].append(tu['enterprise_user_id'])

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
                    'users': []
                }
                if node_id in nodes:
                    nodes[node_id]['queued_teams'].append(team_id)

        if 'queued_team_users' in params.enterprise:
            for tu in params.enterprise['queued_team_users']:
                if tu['team_uid'] in queued_teams:
                    queued_teams[tu['team_uid']]['users'].extend(tu['users'])
                elif tu['team_uid'] in teams:
                    teams[tu['team_uid']]['users'].extend(tu['users'])

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
            columns = set()
            if kwargs.get('columns'):
                columns.update(kwargs.get('columns').split(','))
            pattern = (kwargs.get('pattern') or '').lower()
            if show_users:
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
                            row.append(node_path(u['node_id']))
                        elif column == 'team_count':
                            row.append(len([1 for t in teams.values() if t['users'] and user_id in t['users']]))
                        elif column == 'teams':
                            team_names = [t['name'] for t in teams.values() if t['users'] and user_id in t['users']]
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
                dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

            if show_teams:
                supported_columns = SUPPORTED_TEAM_COLUMNS
                if len(columns) == 0:
                    columns.update(('restricts', 'node', 'user_count'))
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
                            row.append(node_path(t['node_id']))
                        elif column == 'user_count':
                            row.append(len(t['users']))
                        elif column == 'users':
                            row.append([user_email(x) for x in t['users']])
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
                            row.append(node_path(t['node_id']))
                        elif column == 'user_count':
                            row.append(len(t['users']))
                        elif column == 'users':
                            row.append([user_email(x) for x in t['users']])
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
                dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

            if show_roles:
                supported_columns = SUPPORTED_TEAM_COLUMNS
                if len(columns) == 0:
                    columns.update(('is_visible_below', 'is_new_user', 'is_admin','node', 'user_count'))
                else:
                    wc = columns.difference(supported_columns)
                    if len(wc) > 0:
                        logging.warning('\n\nSupported team columns: %s\n', ', '.join(supported_columns))

                displayed_columns = [x for x in supported_columns if x in columns]

                rows = []
                for r in roles.values():
                    row = [r['id'], r['name']]
                    for column in displayed_columns:
                        if column == 'is_visible_below':
                            row.append('Y' if r['visible_below'] else '')
                        elif column == 'is_new_user':
                            row.append('Y' if r['new_user_inherit'] else '')
                        elif column == 'is_admin':
                            row.append('Y' if r['is_admin'] else '')
                        elif column == 'node':
                            row.append(node_path(r['node_id']))
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
                dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

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
        if kwargs.get('delete') and kwargs.get('add'):
            raise CommandError('enterprise-node', "'add' and 'delete' parameters are mutually exclusive.")

        node_lookup = {}
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
            if n:
                if type(n) == list:
                    raise CommandError('enterprise-node', 'Parent node %s in not unique'.format(parent_name))
                parent_id = n['node_id']
            else:
                raise CommandError('enterprise-node', 'Cannot resolve parent node %s'.format(parent_name))

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
                api_request_payload = proto.ApiRequestPayload()
                api_request_payload.payload = request.SerializeToString()
                api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')
                rs = rest_api.execute_rest(params.rest_context, 'enterprise/set_restrict_visibility', api_request_payload)
                # FIXME: Should this error checking/reporting be in a reusuble callable instead?
                if rs == b'':
                    print('good result: {}'.format(displayname))
                elif isinstance(rs, dict):
                    if 'error' in rs:
                        print('bad result: {}:'.format(displayname))
                        print('error: {}'.format(rs['error']))
                        if 'additional_info' in rs:
                            print('additional_info: {}'.format(rs['additional_info']))
                else:
                    print('Unexpected result: ', rs)
                continue
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
                    logging.debug('All users: %s' % params.enterprise['users'])
                    logging.debug('WARNING: username is missing from the user id=%s, obj=%s' % (u['enterprise_user_id'], u))

        emails = kwargs['email']
        if emails:
            for email in emails:
                email = email.lower()
                if email in user_lookup:
                    matched_users.append(user_lookup[email])
                else:
                    unmatched_emails.add(email)

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

        request_batch = []
        disable_2fa_users = []

        if kwargs.get('add'):
            for user in matched_users:
                logging.warning('User %s already exists: Skipping', user['username'])

            if not unmatched_emails:
                raise CommandError('enterprise-user', 'No email address to add.')

            dt = {}
            if user_name:
                dt['displayname'] = user_name
            encrypted_data = api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key'])
            if node_id is None:
                for node in params.enterprise['nodes']:
                    if not node.get('parent_id'):
                        node_id = node['node_id']
                        break

            for email in unmatched_emails:
                rq = {
                    'command': 'enterprise_user_add',
                    'enterprise_user_id': self.get_enterprise_id(params),
                    'node_id': node_id,
                    'encrypted_data': encrypted_data,
                    'enterprise_user_username': email
                }
                request_batch.append(rq)
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
                    answer = 'y' if  kwargs.get('force') else \
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
                                        rq['tree_key'] = api.encrypt_rsa(params.enterprise['unencrypted_tree_key'], user_pkeys[user_id])
                                        if role_key:
                                            rq['role_admin_key'] = api.encrypt_rsa(role_key, user_pkeys[user_id])
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
                                    if user['status'] == 'active':
                                        rq = {
                                            'command': 'team_enterprise_user_add',
                                            'team_uid': team_uid,
                                            'enterprise_user_id': user['enterprise_user_id'],
                                        }
                                        team_key = self.get_team_key(params, team_uid)
                                        public_key = self.get_public_key(params, user['username'])
                                        if team_key and public_key:
                                            rq['team_key'] = api.encrypt_rsa(team_key, public_key)
                                            rq['user_type'] = 0
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
            ts = [t['team_uid'] for t in params.enterprise['team_users'] if t['enterprise_user_id'] == user_id]
            ts.sort(key=lambda x: team_nodes[x]['name'])
            for i in range(len(ts)):
                team_node = team_nodes[ts[i]]
                print('{0:>16s}: {1:<22s} {2}'.format('Team' if i == 0 else '', team_node['name'], team_node['team_uid'] if is_verbose else ''))

        if 'queued_team_users' in params.enterprise:
            user_id = user['enterprise_user_id']
            ts = [t['team_uid'] for t in params.enterprise['queued_team_users'] if user_id in t['users']]
            ts.sort(key=lambda x: team_nodes[x]['name'])
            for i in range(len(ts)):
                team_node = team_nodes[ts[i]]
                print('{0:>16s}: {1:<22s} {2}'.format('Queued Team' if i == 0 else '', team_node['name'], team_node['team_uid'] if is_verbose else ''))


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
        if kwargs.get('node'):
            for node in params.enterprise['nodes']:
                if kwargs['node'] in {str(node['node_id']), node['data'].get('displayname')}:
                    node_id = node['node_id']
                    break
                elif not node.get('parent_id') and kwargs['node'] == params.enterprise['enterprise_name']:
                    node_id = node['node_id']
                    break

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
        if kwargs.get('add'):
            for role in matched_roles:
                logging.warning('Role \'%s\' already exists: Skipping', role['data'].get('displayname'))
            if not role_names:
                return

            if node_id is None:
                for node in params.enterprise['nodes']:
                    if not node.get('parent_id'):
                        node_id = node['node_id']
                        break

            for role_name in role_names:
                dt = { "displayname": role_name }
                rq = {
                    "command": "role_add",
                    "role_id": self.get_enterprise_id(params),
                    "node_id": node_id,
                    "encrypted_data": api.encrypt_aes(json.dumps(dt).encode('utf-8'), params.enterprise['unencrypted_tree_key']),
                    "visible_below": (kwargs['visible_below'] == 'on') or False,
                    "new_user_inherit": (kwargs['new_user'] == 'on') or False
                }
                request_batch.append(rq)
        else:
            for role_name in role_names:
                logging.warning('Role %s is not found: Skipping', role_name)

            if not matched_roles:
                return

            if kwargs.get('delete'):
                for role in matched_roles:
                    request_batch.append({ "command": "role_delete", "role_id": role['role_id'] })

            elif kwargs.get('add_user') or kwargs.get('remove_user'):
                user_changes = {}
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
                                user_changes[user_id] = is_add, user_node['username']
                            else:
                                logging.warning('User %s could be resolved', u)

                user_pkeys = {}
                for role in matched_roles:
                    role_id = role['role_id']
                    for user_id in user_changes:
                        is_add, email = user_changes[user_id]
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
                                        role_key = rest_api.decrypt_aes(encrypted_key_decoded, params.enterprise['unencrypted_tree_key'])
                                        break

                            if 'role_keys' in params.enterprise and role_key is None:
                                for rk in params.enterprise['role_keys']:
                                    if rk['role_id'] == role_id:
                                        if rk['key_type'] == 'encrypted_by_data_key':
                                            role_key = api.decrypt_data(rk['encrypted_key'], params.data_key)
                                        elif rk['key_type'] == 'encrypted_by_public_key':
                                            role_key = api.decrypt_rsa(rk['encrypted_key'], params.rsa_key)
                                        break
                        rq = {
                            'command': 'role_user_add' if is_add else 'role_user_remove',
                            'enterprise_user_id': user_id,
                            'role_id': role_id
                        }
                        if is_managed_role:
                            if user_id not in user_pkeys:
                                answer = 'y' if kwargs.get('force') else user_choice('Do you want to grant administrative privileges to {0}'.format(email), 'yn', 'n')
                                public_key = None
                                if answer == 'y':
                                    public_key = self.get_public_key(params, email)
                                    if public_key is None:
                                        logging.warning('Cannot get public key for user %s', email)
                                user_pkeys[user_id] = public_key
                            if user_pkeys[user_id]:
                                rq['tree_key'] = api.encrypt_rsa(params.enterprise['unencrypted_tree_key'], user_pkeys[user_id])
                                if role_key:
                                    rq['role_admin_key'] = api.encrypt_rsa(role_key, user_pkeys[user_id])
                                request_batch.append(rq)
                        else:
                            request_batch.append(rq)

            elif kwargs.get('add_admin') or kwargs.get('remove_admin'):
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
                                        if public_key:
                                            rq['tree_keys'].append({
                                                "enterprise_user_id": user_id,
                                                "tree_key": api.encrypt_rsa(params.enterprise['unencrypted_tree_key'], public_key)
                                            })
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
                                logging.info('\'%s\' role is %s managing node \'%s\'', role_name, 'assigned to' if command == 'role_managed_node_add' else 'removed from', node_name)
                            else:
                                logging.warning('\'%s\' role failed to %s managing node \'%s\': %s', role_name, 'assign' if command == 'role_managed_node_add' else 'remove', node_name, rs['message'])
                        else:
                            if rs['result'] != 'success':
                                logging.warning('\'%s\' error: %s', command, rs['message'])
                    else:
                        if rs['result'] != 'success':
                            logging.warning('Error: %s', rs['message'])
            api.query_enterprise(params)
        else:
            for role in matched_roles:
                print('\n')
                self.display_role(params, role, kwargs.get('verbose'))
            print('\n')

    def display_role(self, params, role, is_verbose = False):
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
                    print('{0:>24s}: {1:<32s} {2}'.format('User(s)' if i == 0 else '', users[user_id], user_id if is_verbose else ''))

        if 'managed_nodes' in params.enterprise:
            node_ids = [x['managed_node_id'] for x in params.enterprise['managed_nodes'] if x['role_id'] == role_id]
            if len(node_ids) > 0:
                nodes = {}
                for node in params.enterprise['nodes']:
                    nodes[node['node_id']] = node['data'].get('displayname') or params.enterprise['enterprise_name']
                node_ids.sort(key=lambda x: nodes[x])
                for i in range(len(node_ids)):
                    node_id = node_ids[i]
                    print('{0:>24s}: {1:<32s} {2}'.format('Manages Nodes(s)' if i == 0 else '', nodes[node_id], node_id if is_verbose else ''))

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
                        value = enforcements.get(p[1])
                        if value is not None:
                            print('{0:>24s}: {1}'.format(p[0], value))


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
        if kwargs.get('node'):
            parent_node = kwargs.get('node')

            if parent_node:
                for node in params.enterprise['nodes']:
                    if parent_node in {str(node['node_id']), node['data'].get('displayname')}:
                        node_id = node['node_id']
                        break
                    elif not node.get('parent_id') and parent_node == params.enterprise['enterprise_name']:
                        node_id = node['node_id']
                        break

                if not node_id:
                    logging.warning("Node %s does not exist", parent_node)
                    return

        matched = {}
        team_names = set()

        for team_name in kwargs['team']:
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
                for node in params.enterprise['nodes']:
                    if not node.get('parent_id'):
                        node_id = node['node_id']
                        break

            for item in queue:
                is_new_team = type(item) == str
                team_name = item if is_new_team else item['name']
                team_node_id = node_id if is_new_team else item['node_id']
                team_uid = api.generate_record_uid() if is_new_team else item['team_uid']
                team_key = api.generate_aes_key()
                encrypted_team_key = rest_api.encrypt_aes(team_key, params.enterprise['unencrypted_tree_key'])
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
                    'team_name': team_name,
                    'restrict_edit': kwargs.get('restrict_edit') == 'on',
                    'restrict_share': kwargs.get('restrict_share') == 'on',
                    'restrict_view': kwargs.get('restrict_view') == 'on',
                    'public_key': base64.urlsafe_b64encode(public_key).decode().rstrip('='),
                    'private_key': api.encrypt_aes(private_key, team_key),
                    'node_id': team_node_id,
                    'team_key': api.encrypt_aes(team_key, params.data_key),
                    'encrypted_team_key': base64.urlsafe_b64encode(encrypted_team_key).decode().rstrip('='),
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
                                logging.warning('User %s could be resolved', u)

                if len(users) > 0:
                    for team in matched_teams:
                        is_real_team = 'restrict_edit' in team
                        for user_id in users:
                            is_add, user = users[user_id]
                            rq = None
                            if is_add:
                                is_active_user = user['status'] == 'active'
                                if is_real_team and is_active_user:
                                    public_key = self.get_public_key(params, user['username'])
                                    team_key = self.get_team_key(params, team['team_uid'])
                                    if public_key and team_key:
                                        rq = {
                                            'command': 'team_enterprise_user_add',
                                            'team_uid': team['team_uid'],
                                            'enterprise_user_id': user_id,
                                            'user_type': 0,
                                            'team_key': api.encrypt_rsa(team_key, public_key)
                                        }
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
                if kwargs['name'] and len(matched_teams) > 1:
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
            api.query_enterprise(params)
        else:
            for team in matched_teams:
                print('\n')
                self.display_team(params, team, kwargs.get('verbose'))
            print('\n')

    def display_team(self, params, team, is_verbose = False):
        team_uid = team['team_uid']
        is_queued_team = 'restrict_edit' not in team

        print('{0:>24s}: {1}'.format('Queued ' if is_queued_team else '' + 'Team UID', team_uid))
        print('{0:>24s}: {1}'.format('Queued ' if is_queued_team else '' + 'Team Name', team['name']))
        print('{0:>24s}: {1:<32s} {2}'.format('Node', self.get_node_path(params, team['node_id']), str(team['node_id'])))
        if not is_queued_team:
            print('{0:>24s}: {1}'.format('Restrict Edit?', 'Yes' if team['restrict_edit'] else 'No'))
            print('{0:>24s}: {1}'.format('Restrict Share?', 'Yes' if team['restrict_sharing'] else 'No'))
            print('{0:>24s}: {1}'.format('Restrict View?', 'Yes' if team['restrict_view'] else 'No'))

        user_names = {}
        for u in params.enterprise['users']:
            user_names[u['enterprise_user_id']] = u['username'] if 'username' in u else '[empty]'

        if 'team_users' in params.enterprise:
            user_ids = [x['enterprise_user_id'] for x in params.enterprise['team_users'] if x['team_uid'] == team_uid]
            # user_ids.sort(key=lambda x: user_names.get(x))
            for i in range(len(user_ids)):
                print('{0:>24s}: {1:<32s} {2}'.format('Active User(s)' if i == 0 else '', (user_names[user_ids[i]] if user_ids[i] in user_names else "(Unmanaged User id: " + user_ids[i] + ")"), user_ids[i] if is_verbose else ''))

        if 'queued_team_users' in params.enterprise:
            user_ids = []
            for qtu in params.enterprise['queued_team_users']:
                if qtu['team_uid'] == team['team_uid']:
                    user_ids.extend(qtu['users'])
            user_ids.sort(key=lambda x: user_names.get(x))
            for i in range(len(user_ids)):
                print('{0:>24s}: {1:<32s} {2}'.format('Queued User(s)' if i == 0 else '', user_names[user_ids[i]], user_ids[i] if is_verbose else ''))


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
                                elif js['code'] == 10:
                                    logging.error('HEC\'s Indexer Acknowledgement parameter is not supported yet')
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

    def resolve_uid(self, cache, username):
        uname = username or ''
        uid = cache.get(uname)
        if not uid:
            md5 = hashlib.md5(str(uname).encode('utf-8')).hexdigest()
            cache[uname] = 'DELETED-'+md5
            uid = cache.get(uname)
        return uid


    def execute(self, params, **kwargs):
        loadSyslogTemplates(params)

        target = kwargs.get('target')

        log_export = None        # type: AuditLogBaseExport
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
            raise CommandError('audit-log', 'Audit log export: unsupported target')

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
            raise CommandError('audit-log', 'Record not found')

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

        anonymize = bool(kwargs.get('anonymize'))
        ent_user_ids = {}
        if anonymize and params.enterprise and 'users' in params.enterprise:
            ent_user_ids = { x.get('username'): x.get('enterprise_user_id') for x in params.enterprise['users'] }

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
                    event_count = len(audit_events)
                    if event_count > 1:
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
                                if anonymize:
                                    uname = event.get('email') or event.get('username') or ''
                                    ent_uid = self.resolve_uid(ent_user_ids, uname)
                                    event['username'] = ent_uid
                                    event['email'] = ent_uid
                                    to_uname = event.get('to_username') or ''
                                    if to_uname:
                                        event['to_username'] = self.resolve_uid(ent_user_ids, to_uname)
                                    from_uname = event.get('from_username') or ''
                                    if from_uname:
                                        event['from_username'] = self.resolve_uid(ent_user_ids, from_uname)
                                events.append(log_export.convert_event(props, event))

                        finished = len(events) == 0
                        if finished:
                            if event_count > 900:
                                finished = False
                                last_event_time += 1

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
            if count > 0:
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
        self._detail_lookup = None

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

    @property
    def detail_lookup(self):
        if self._detail_lookup is None:
            self._detail_lookup = {}
        return self._detail_lookup

    def convert_value(self, field, value, **kwargs):
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
        elif field in {'record_uid', 'shared_folder_uid', 'team_uid', 'node'}:
            if kwargs.get('details') and kwargs.get('params'):
                params = kwargs['params']
                if value not in self.detail_lookup:
                    self.detail_lookup[value] = ''
                    if field == 'record_uid':
                        if value in params.record_cache:
                            r = api.get_record(params, value)
                            if r:
                                self.detail_lookup[value] = r.title or ''
                    elif field == 'shared_folder_uid':
                        if value in params.shared_folder_cache:
                            sf = api.get_shared_folder(params, value)
                            if sf:
                                self.detail_lookup[value] = sf.name or ''
                    elif field == 'team_uid' and params.enterprise:
                        team = None
                        if 'teams' in params.enterprise:
                            team = next((x for x in params.enterprise['teams'] if x['team_uid'] == value), None)
                        if not team and 'queued_teams' in params.enterprise:
                            team = next((x for x in params.enterprise['queued_teams'] if x['team_uid'] == value), None)
                        if team and 'name' in team:
                            self.detail_lookup[value] = team['name'] or ''
                    elif field == 'node' and params.enterprise:
                        node = None
                        if 'nodes' in params.enterprise:
                            node = next((x for x in params.enterprise['nodes'] if str(x['node_id']) == value), None)
                        if node and 'data' in node:
                            self.detail_lookup[value] = node['data'].get('displayname') or ''

                detail_value = self.detail_lookup.get(value)
                if detail_value:
                    return '{1} ({0})'.format(value, detail_value)
        return value

    def execute(self, params, **kwargs):
        loadSyslogTemplates(params)

        if kwargs.get('syntax_help'):
            logging.info(audit_report_description)
            return
        if not kwargs['report_type']:
            raise CommandError('audit-report', 'report-type parameter is missing')

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
            raise CommandError('audit-report', "'columns' parameter is missing")

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

        details = kwargs.get('details') or False
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
                    row.append(self.convert_value(field, value, details=details, params=params))
                table.append(row)
            dump_report_data(table, fields, fmt=kwargs.get('format'), filename=kwargs.get('output'))

        elif report_type == 'dim':
            to_append = False
            for dim in rs['dimensions']:
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
                else:
                    fields = [dim]
                    table = []
                    for row in rs['dimensions'][dim]:
                        table.append([row])
                dump_report_data(table, fields, fmt=kwargs.get('format'), filename=kwargs.get('output'), append=to_append)
                to_append = True

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
                    row.append(self.convert_value(f, event.get(f), report_type=report_type, details=details, params=params))
                table.append(row)
            dump_report_data(table, fields, fmt=kwargs.get('format'), filename=kwargs.get('output'))

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


class SecurityAuditReportCommand(Command):
    def __init__(self):
        self.user_lookup = None

    def get_parser(self):
        return security_audit_report_parser

    def get_security_score(self, total, strong, unique, twoFactorOn, masterPassword):
        strongByTotal = 0 if (total == 0 ) else (strong / total)
        uniqueByTotal = 0 if (total == 0 ) else (unique / total)
        twoFactorOnVal = 1 if (twoFactorOn == True) else 0
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
                            self.user_lookup[user['enterprise_user_id']] = { 'username': username, 'email': email }

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

        format = 'table'
        if kwargs.get('format'):
            format = kwargs['format']

        rq = proto.SecurityReportRequest()
        rs = api.communicate_rest(params, rq, 'enterprise/get_security_report_data')

        security_report_data_rs = proto.SecurityReportResponse()
        security_report_data_rs.ParseFromString(rs)

        rows = []
        for sr in security_report_data_rs.securityReport:
            user_info = self.resolve_user_info(params, sr.enterpriseUserId)
            user = user_info['username'] if 'username' in user_info else str(sr.enterpriseUserId)
            email = user_info['email'] if 'email' in user_info else str(sr.enterpriseUserId)
            twofa_on = False if sr.twoFactor == 'two_factor_disabled' else True
            row = {
                'username': user,
                'email': email,
                'weak': 0,
                'medium': 0,
                'strong': 0,
                'reused': sr.numberOfReusedPassword,
                'unique': 0,
                'securityScore': 25,
                'twoFactorChannel': 'Off' if sr.twoFactor == 'two_factor_disabled' else 'On'
            }
            master_password_strength = 1

            if sr.encryptedReportData:
                sri = rest_api.decrypt_aes(sr.encryptedReportData, params.enterprise['unencrypted_tree_key'])
                data = json.loads(sri)
                row['weak'] = data['weak_record_passwords'] if 'weak_record_passwords' in data else 0
                row['strong'] = data['strong_record_passwords'] if 'weak_record_passwords' in data else 0
                row['medium'] = data['total_record_passwords'] - row['weak'] - row['strong']
                row['unique'] = data['total_record_passwords'] - row['reused']
                score = self.get_security_score(data['total_record_passwords'], row['strong'], row['unique'], twofa_on, master_password_strength)
                score = int(100 * round(score, 2))
                row['securityScore'] = score
            rows.append(row)

        fields = ('username', 'email', 'weak', 'medium', 'strong', 'reused', 'unique', 'securityScore', 'twoFactorChannel')
        field_descriptions = fields
        if format == 'table':
            field_descriptions = ('User', 'e-mail', 'Weak', 'Medium', 'Strong', 'Reused', 'Unique', 'Security Score', '2FA')

        table = []
        for raw in rows:
            row = []
            for f in fields:
                row.append(raw[f])
            table.append(row)
        dump_report_data(table, field_descriptions, fmt=format, filename=kwargs.get('output'))


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

        emails = EnterprisePushCommand.collect_emails(params, kwargs)

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

                        record_keys[email][record_uid] = api.encrypt_rsa(record_key, emails[email])
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


class UserReportCommand(Command):
    def __init__(self):
        Command.__init__(self)
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
        logging.info('Quering latest login for the last {0} days'.format(look_back_days))
        from_date = datetime.datetime.utcnow() - datetime.timedelta(days=look_back_days)
        report_filter = {
            "audit_event_type": "login",
            "created": {
                "min": int(from_date.timestamp())
            }
        }
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

        rows = []
        headers = ['email', 'name', 'status', 'transfer_status', 'last_login', 'node', 'roles', 'teams']
        for user in user_list:
            status_dict = get_user_status_dict(user)

            acct_status = status_dict['acct_status']
            acct_transfer_status = status_dict['acct_transfer_status']

            path = self.get_node_path(user['node_id'])
            teams = self.user_teams.get(user['enterprise_user_id']) or []
            roles = self.user_roles.get(user['enterprise_user_id']) or []
            teams.sort(key=str.lower)
            roles.sort(key=str.lower)
            ll = user.get('last_login')
            last_log = str(ll) if ll else ''
            rows.append([
                user['username'],       # email
                user['name'],           # name
                acct_status,            # status == acct_status
                acct_transfer_status,   # acct_transfer_status
                last_log,               # last_login
                ' -> '.join(path),      # node
                roles,                  # roles
                teams                   # teams
            ])

        if kwargs.get('format') != 'json':
            headers = [string.capwords(x.replace('_', ' ')) for x in headers]
        dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))

    def get_node_path(self, node_id):
        path = []
        while node_id:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node_name = node['name'] or 'Root'
                path.append(node_name)
                node_id = node['parent_id']
            else:
                break
        path.reverse()
        return path

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
        if kwargs['team'] or kwargs['user']:
            approve_teams = kwargs['team'] or False
            approve_users = kwargs['user'] or False

        request_batch = []
        if approve_teams and 'queued_teams' in params.enterprise:
            for team in params.enterprise['queued_teams']:
                team_name = team['name']
                team_node_id = team['node_id']
                team_uid = team['team_uid']
                team_key = api.generate_aes_key()
                encrypted_team_key = rest_api.encrypt_aes(team_key, params.enterprise['unencrypted_tree_key'])
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
                    'team_name': team_name,
                    'restrict_edit': kwargs.get('restrict_edit') == 'on',
                    'restrict_share': kwargs.get('restrict_share') == 'on',
                    'restrict_view': kwargs.get('restrict_view') == 'on',
                    'public_key': base64.urlsafe_b64encode(public_key).decode().rstrip('='),
                    'private_key': api.encrypt_aes(private_key, team_key),
                    'node_id': team_node_id,
                    'team_key': api.encrypt_aes(team_key, params.data_key),
                    'encrypted_team_key': base64.urlsafe_b64encode(encrypted_team_key).decode().rstrip('='),
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
                            if team_key and public_key:
                                rq['team_key'] = api.encrypt_rsa(team_key, public_key)
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

    DevicesToApprove = None

    @staticmethod
    def token_to_string(token): # type: (bytes) -> str
        src = token[0:10]
        if src.hex:
            return src.hex()
        return ''.join('{:02x}'.format(x) for x in src)

    def execute(self, params, **kwargs):
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives import serialization
        except:
            print('To use this feature, install cryptography package\n' + bcolors.OKGREEN + '\'pip install cryptography\'' + bcolors.ENDC)
            return

        if DeviceApproveCommand.DevicesToApprove is None or kwargs.get('reload'):
            request = {
                'command': 'get_enterprise_data',
                'include': ['devices_request_for_admin_approval']
            }
            response = api.communicate(params, request)
            DeviceApproveCommand.DevicesToApprove = response.get('devices_request_for_admin_approval') or []
        if not DeviceApproveCommand.DevicesToApprove:
            logging.info('There are no pending devices to approve')
            return

        if kwargs.get('approve') and kwargs.get('deny'):
            raise CommandError('device-approve', "'approve' and 'deny' parameters are mutually exclusive.")

        devices = kwargs['device']
        matching_devices = {}
        for device in DeviceApproveCommand.DevicesToApprove:
            device_id = device.get('encrypted_device_token')
            if not device_id:
                continue
            device_id = DeviceApproveCommand.token_to_string(base64.urlsafe_b64decode(device_id + '=='))
            found = False
            if devices:
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
                    logging.warning("The user %s attempted to login from an unstrusted IP (%s). To force the approval, run the same command without the --trusted-ip argument", p_uname, p_ip_addr)

            matching_devices = trusted_devices

        if len(matching_devices) == 0:
            logging.info('No matching devices found')
            return

        if kwargs.get('approve') or kwargs.get('deny'):
            approve_rq = ApproveUserDevicesRequest()
            data_keys = {}
            if kwargs.get('approve'):

                # resolve user data keys shared with enterprise
                user_ids = set([x['enterprise_user_id'] for x in matching_devices.values()])
                user_ids.difference_update(data_keys.keys())
                if len(user_ids) > 0:
                    ecc_private_key = None
                    curve = ec.SECP256R1()
                    if 'keys' in params.enterprise:
                        if 'ecc_encrypted_private_key' in params.enterprise['keys']:
                            keys = params.enterprise['keys']
                            try:
                                ecc_private_key_data = base64.urlsafe_b64decode(keys['ecc_encrypted_private_key'] + '==')
                                ecc_private_key_data = rest_api.decrypt_aes(ecc_private_key_data, params.enterprise['unencrypted_tree_key'])
                                private_value = int.from_bytes(ecc_private_key_data, byteorder='big', signed=False)
                                ecc_private_key = ec.derive_private_key(private_value, curve, default_backend())
                            except Exception as e:
                                logging.debug(e)

                    if ecc_private_key:
                        data_key_rq = UserDataKeyRequest()
                        data_key_rq.enterpriseUserId.extend(user_ids)
                        api_request_payload = ApiRequestPayload()
                        api_request_payload.payload = data_key_rq.SerializeToString()
                        api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')
                        rs = api.rest_api.execute_rest(params.rest_context, 'enterprise/get_enterprise_user_data_key', api_request_payload)
                        if type(rs) is bytes:
                            data_key_rs = EnterpriseUserDataKeys()
                            data_key_rs.ParseFromString(rs)
                            for key in data_key_rs.keys:
                                enc_data_key = key.userEncryptedDataKey
                                if enc_data_key:
                                    try:
                                        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, enc_data_key[:65])
                                        shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
                                        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                                        digest.update(shared_key)
                                        enc_key = digest.finalize()
                                        data_key = rest_api.decrypt_aes(enc_data_key[65:], enc_key)
                                        data_keys[key.enterpriseUserId] = data_key
                                    except Exception as e:
                                        logging.debug(e)

                # resolve user data keys from Account Transfer
                user_ids = set([x['enterprise_user_id'] for x in matching_devices.values()])
                user_ids.difference_update(data_keys.keys())
                if len(user_ids) > 0:
                    data_key_rq = UserDataKeyRequest()
                    data_key_rq.enterpriseUserId.extend(user_ids)
                    api_request_payload = ApiRequestPayload()
                    api_request_payload.payload = data_key_rq.SerializeToString()
                    api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')
                    rs = api.rest_api.execute_rest(params.rest_context, 'enterprise/get_user_data_key_shared_to_enterprise', api_request_payload)
                    if type(rs) is bytes:
                        data_key_rs = UserDataKeyResponse()
                        data_key_rs.ParseFromString(rs)
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
                    else:
                        logging.warning(rs)

            for device in matching_devices.values():
                ent_user_id = device['enterprise_user_id']
                device_rq = ApproveUserDeviceRequest()
                device_rq.enterpriseUserId = ent_user_id
                device_rq.encryptedDeviceToken = base64.urlsafe_b64decode(device['encrypted_device_token'] + '==')
                device_rq.denyApproval = True if kwargs.get('deny') else False
                if kwargs.get('approve'):
                    public_key = device['device_public_key']
                    if not public_key or len(public_key) == 0:
                        continue
                    data_key = data_keys.get(ent_user_id)
                    if not data_key:
                        continue
                    try:
                        curve = ec.SECP256R1()
                        ephemeral_key = ec.generate_private_key(curve,  default_backend())
                        device_public_key = ec.EllipticCurvePublicKey. \
                            from_encoded_point(curve, base64.urlsafe_b64decode(device['device_public_key'] + '=='))
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

            api_request_payload = ApiRequestPayload()
            api_request_payload.payload = approve_rq.SerializeToString()
            api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')
            rs = api.rest_api.execute_rest(params.rest_context, 'enterprise/approve_user_devices', api_request_payload)
            if type(rs) is bytes:
                approve_rs = ApproveUserDevicesResponse()
                approve_rs.ParseFromString(rs)
                DeviceApproveCommand.DevicesToApprove = None
            else:
                logging.warning(rs)
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
            dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))
            print('')


scim_description = '''
SCIM Command Syntax Description:
scim command [target] [--options]
 Command            Description
=================================================================
 list               Displays the list of SCIM endpoints
 create             Creates SCIM endpoint
 view               Prints SCIM endpoint details
 edit               Changes SCIM endpoint configuration
 delete             Deletes SCIM endpoint
 
  list, create
 'target' parameter is ignored 
 
view, edit, delete
 these commands require 'target' parameter: SCIM endpoint ID
 
 Option             Commands
=================================================================
 --reload           all : Reloads SCIM configuration
 --node             create : Node ID or Name 
 --prefix           create, edit : Role prefix
 --unique-groups    create, edit : Unique groups 
 --force            delete : Do not ask for delete confirmation
'''


class EnterpriseScimCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> argparse.ArgumentParser or None
        return scim_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        if kwargs.get('reload'):
            api.query_enterprise(params)

        command = kwargs.get('command') or ''
        if command == 'list' or command == '':
            if command == '':
                logging.info(scim_description)

            self.dump_scims(params)
            return

        if command == 'create':
            node_name = kwargs.get('node')
            if not node_name:
                logging.warning('\"--node\" option is required for \"create\" command')
                return
            nodes = list(self.resolve_nodes(params, node_name))
            if len(nodes) > 1:
                logging.warning('Node name \'%s\' is not unique. Use Node ID.', node_name)
                return
            elif len(nodes) == 0:
                logging.warning('Node name \'%s\' is not found', node_name)
                return

            matched_node = nodes[0]
            if not matched_node.get('parent_id'):
                logging.warning('Root node cannot be used for SCIM endpoint')
                return
            token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
            rq = {
                'command': 'scim_add',
                'scim_id': self.get_enterprise_id(params),
                'node_id': matched_node['node_id'],
                'token': token,
            }
            prefix = kwargs.get('prefix')
            if prefix:
                rq['prefix'] = prefix
            if kwargs.get('unique_groups'):
                rq['unique_groups'] = True

            api.communicate(params, rq)
            api.query_enterprise(params)
            logging.info('')
            logging.info('SCIM ID: %d', rq['scim_id'])
            logging.info('SCIM URL: %s', self.get_scim_url(params, matched_node['node_id']))
            logging.info('Provisioning Token: %s', token)
            logging.info('')
            return token

        target = kwargs.get('target')
        if not target:
            logging.warning('\"target\" parameter is required for \"%s\" command', command)
            return
        scims = []
        if params.enterprise and 'scims' in params.enterprise:
            try:
                target_id = int(target)
            except ValueError:
                logging.warning('SCIM ID should be integer: %s', target)
                return
            for info in params.enterprise['scims']:
                if target_id == info['scim_id'] or target_id == info['node_id']:
                    scims.append(info)
                    break
        if len(scims) == 0:
            logging.warning('SCIM endpoint with ID \"%d\" not found', target)
            return
        scim = scims[0]

        if command == 'edit':
            token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
            rq = {
                'command': 'scim_update',
                'scim_id': scim['scim_id'],
                'token': token,
            }
            prefix = kwargs.get('prefix')
            if prefix:
                rq['prefix'] = prefix
            if kwargs.get('unique_groups'):
                rq['unique_groups'] = True

            api.communicate(params, rq)
            api.query_enterprise(params)
            logging.info('')
            logging.info('SCIM ID: %d', scim['scim_id'])
            logging.info('SCIM URL: %s', self.get_scim_url(params, scim['node_id']))
            logging.info('Provisioning Token: %s', token)
            logging.info('')
            return token

        if command == 'view':
            logging.info('{0:>20s}: {1}'.format('SCIM ID', scim['scim_id']))
            node_id = scim['node_id']
            logging.info('{0:>20s}: {1}'.format('SCIM URL', self.get_scim_url(params, node_id)))
            logging.info('{0:>20s}: {1}'.format('Node ID', node_id))
            logging.info('{0:>20s}: {1}'.format('Node Name', EnterpriseCommand.get_node_path(params, node_id)))
            logging.info('{0:>20s}: {1}'.format('Prefix', scim.get('role_prefix') or ''))
            logging.info('{0:>20s}: {1}'.format('Status', scim['status']))
            last_synced = scim.get('last_synced')
            if last_synced:
                logging.info('{0:>20s}: {1}'.format('Last Synced', time.localtime(last_synced)))

        elif command == 'delete':
            answer = 'y' if kwargs.get('force') else \
                user_choice(bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                            'You are about to delete SCIM endpoint {0}'.format(scim['scim_id']) +
                            '\n\nDo you want to proceed with deletion?', 'yn', 'n')
            if answer.lower() != 'y':
                return

            rq = {
                'command': 'scim_delete',
                'scim_id': scim['scim_id'],
            }
            api.communicate(params, rq)
            api.query_enterprise(params)
            logging.warning('SCIM endpoint \"%d\" at node \"%d\" deleted', scim['scim_id'], scim['node_id'])
        else:
            logging.warning('Unsupported command \"%s\"', command)


    @staticmethod
    def get_scim_url(params, node_id):  # type:  (KeeperParams, int) -> any
        p = urlparse(params.rest_context.server_base)
        return urlunparse((p.scheme, p.netloc, '/api/rest/scim/v2/' + str(node_id), None, None, None))

    @staticmethod
    def dump_scims(params):    # type: (KeeperParams) -> None
        table = []
        headers = ['SCIM ID', 'Node Name', 'Node ID', 'Prefix', 'Status', 'Last Synced']
        if params.enterprise and 'scims' in params.enterprise:
            for info in params.enterprise['scims']:
                node_id = info['node_id']
                last_synced = info.get('last_synced')
                if last_synced:
                    last_synced = str(time.localtime(last_synced))
                else:
                    last_synced = ''
                row = [info['scim_id'], EnterpriseCommand.get_node_path(params, node_id), node_id,
                       info.get('role_prefix') or '', info['status'], last_synced]
                table.append(row)
        dump_report_data(table, headers=headers)
