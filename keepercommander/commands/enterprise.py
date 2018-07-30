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

from .base import suppress_exit, raise_parse_exception, Command


def register_commands(commands, aliases, command_info):
    commands['enterprise-info'] = EnterpriseInfoCommand()
    commands['enterprise-user'] = EnterpriseUserCommand()

    aliases['ei'] = 'enterprise-info'
    aliases['eu'] = 'enterprise-user'

    for p in [enterprise_info_parser, enterprise_user_parser]:
        command_info[p.prog] = p.description


enterprise_info_parser = argparse.ArgumentParser(prog='enterprise-info|ei', description='Print enterprise information command')
enterprise_info_parser.add_argument('-n', '--nodes', dest='nodes', action='store_true', help='print node tree')
enterprise_info_parser.add_argument('-u', '--users', dest='users', action='store_true', help='print user list')
enterprise_info_parser.add_argument('-t', '--teams', dest='teams', action='store_true', help='print team list')
enterprise_info_parser.add_argument('-r', '--root-node', dest='root_node', action='store', help='root node name')
enterprise_info_parser.error = raise_parse_exception
enterprise_info_parser.exit = suppress_exit


enterprise_user_parser = argparse.ArgumentParser(prog='enterprise-user|eu', description='Enterprise user management')
enterprise_user_parser.add_argument('-i', '--invite', dest='invite', action='store_true', help='invite user')
enterprise_user_parser.add_argument('-l', '--lock', dest='lock', action='store_true', help='lock user')
enterprise_user_parser.add_argument('-e', '--expire', dest='expire', action='store_true', help='expire user password')
enterprise_user_parser.add_argument('-d', '--delete', dest='delete', action='store_true', help='delete user')
enterprise_user_parser.add_argument('-n', '--rename', dest='rename', action='store', help='rename user')
enterprise_user_parser.add_argument('email', type=str, action='store', help='user email')
enterprise_user_parser.error = raise_parse_exception
enterprise_user_parser.exit = suppress_exit


class EnterpriseCommand(Command):
    def execute_args(self, params, args, **kwargs):
        if params.enterprise:
            Command.execute_args(self, params, args, **kwargs)
        else:
            print('This command  is only available for Administrators of Keeper.')


class EnterpriseInfoCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_info_parser

    def execute(self, params, **kwargs):
        nodes = {}
        for node in params.enterprise['nodes']:
            nodes[node['node_id']] = {
                'parent_id': node.get('parent_id') or '',
                'name': node['data'].get('name'),
                'users': [],
                'teams': []
            }

        users = {}
        if 'users' in params.enterprise:
            for user in params.enterprise['users']:
                user_id = user['enterprise_user_id']
                node_id = user['node_id']
                u = {
                    'id': user_id,
                    'node_id': node_id,
                    'username': user['username'],
                    'name': user['data'].get('name') or '',
                    'status': user['status'],
                    'lock': user['lock']
                }
                users[user_id] = u
                if node_id in nodes:
                    nodes[node_id]['users'].append(user_id)

        teams = {}
        if 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                team_id = team['team_uid']
                node_id = team['node_id']
                teams[team_id] = {
                    'id': team_id,
                    'node_id': node_id,
                    'name': team['name'],
                    'restrict_sharing': team['restrict_sharing'],
                    'restrict_edit': team['restrict_edit'],
                    'restrict_view': team['restrict_view']
                }
                if node_id in nodes:
                    nodes[node_id]['teams'].append(team_id)


class EnterpriseUserCommand(EnterpriseCommand):
    def get_parser(self):
        return enterprise_user_parser

    def execute(self, params, **kwargs):
        pass
