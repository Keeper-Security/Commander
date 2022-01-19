#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import collections

from .base import Command
from .. import api, utils, crypto
from ..error import CommandError
from ..params import KeeperParams


class EnterpriseCommand(Command):
    def __init__(self):
        super(EnterpriseCommand, self).__init__()
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
                public_key = crypto.load_rsa_public_key(utils.base64_url_decode(pko['public_key']))
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
                            team_key = crypto.decrypt_aes_v2(utils.base64_url_decode(enc_team_key), params.enterprise['unencrypted_tree_key'])
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
                    encrypted_key = utils.base64_url_decode(ko['key'])
                    key_type = ko['type']
                    if key_type == 1:
                        team_key = crypto.decrypt_aes_v1(encrypted_key, params.data_key)
                    elif key_type == 2:
                        team_key = crypto.decrypt_rsa(encrypted_key, params.rsa_key)
                    elif key_type == 3:
                        team_key = crypto.decrypt_aes_v2(encrypted_key, params.data_key)

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
    def resolve_nodes(params, name):   # type: (KeeperParams, str) -> collections.Iterable[dict]
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

    @staticmethod
    def get_user_root_nodes(params):  # type: (KeeperParams) -> collections.Iterable[int]
        if 'user_root_nodes' not in params.enterprise:
            EnterpriseCommand._load_managed_nodes(params)

        for x in params.enterprise['user_root_nodes']:
            yield x

    @staticmethod
    def get_user_managed_nodes(params):  # type: (KeeperParams) -> collections.Iterable[int]
        if 'user_managed_nodes' not in params.enterprise:
            EnterpriseCommand._load_managed_nodes(params)

        for x in params.enterprise['user_managed_nodes']:
            yield x

    @staticmethod
    def _load_managed_nodes(params):  # type: (KeeperParams) -> None
        if 'nodes' not in params.enterprise:
            return
        nodes = params.enterprise['nodes']
        root_node_id = next((x['node_id'] for x in nodes if x['node_id'] & 0xffffffff == 2), None)
        if not root_node_id:
            return

        enterprise_user_id = None
        if 'users' in params.enterprise:
            enterprise_user_id = next((x['enterprise_user_id'] for x in params.enterprise['users'] if x.get('username', '').lower() == params.user.lower()), None)

        root_nodes = set()
        managed_nodes = set()
        if enterprise_user_id:
            current_user_roles = set((x['role_id'] for x in params.enterprise['role_users'] if x['enterprise_user_id'] == enterprise_user_id))
            is_main_admin = any(True for x in params.enterprise['managed_nodes'] if x['role_id'] in current_user_roles and x['cascade_node_management'] and x['managed_node_id'] == root_node_id)
        else:
            is_main_admin = True
            current_user_roles = set()
        if is_main_admin:
            root_nodes.add(root_node_id)
            managed_nodes.update((x['node_id'] for x in nodes))
        else:
            singles = []
            for mn in params.enterprise['managed_nodes']:
                role_id = mn['role_id']
                if role_id not in current_user_roles:
                    continue
                node_id = mn['managed_node_id']
                if mn['cascade_node_management']:
                    managed_nodes.add(node_id)
                else:
                    singles.append(node_id)

            missed = set()
            lookup = {x['node_id']: x for x in nodes}
            for node in nodes:
                node_id = node['node_id']
                if node_id in managed_nodes:
                    continue

                stack = []
                while node_id in lookup:
                    if node_id in managed_nodes:
                        managed_nodes.update(stack)
                        stack.clear()
                        break
                    if node_id in missed:
                        break
                    stack.append(node_id)
                    node_id = lookup[node_id].get('parent_id', 0)
                missed.update(stack)
            managed_nodes.update(singles)

            for mn in params.enterprise['managed_nodes']:
                role_id = mn['role_id']
                if role_id not in current_user_roles:
                    continue
                node_id = mn['managed_node_id']
                if node_id in lookup:
                    parent_id = lookup[node_id].get('parent_id', 0)
                    if parent_id not in managed_nodes:
                        root_nodes.add(node_id)

        params.enterprise['user_root_nodes'] = list(root_nodes)
        params.enterprise['user_managed_nodes'] = list(managed_nodes)
