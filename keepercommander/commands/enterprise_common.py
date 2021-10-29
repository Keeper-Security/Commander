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
from ..params import KeeperParams
from .. import api, utils, crypto
from ..error import CommandError


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
    def get_root_nodes(params):  # type: (KeeperParams) -> [dict]
        node_set = {x['node_id'] for x in params.enterprise['nodes']}
        for node in params.enterprise['nodes']:
            parent_id = node.get('parent_id') or ''
            if parent_id not in node_set:
                yield node
