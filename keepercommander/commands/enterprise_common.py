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

import base64
import collections
import logging

from .base import Command, user_choice
from .. import api, utils, crypto, rest_api
from ..error import CommandError
from ..params import KeeperParams
from ..proto.enterprise_pb2 import RoleTeam, RoleTeams


def decrypt_role_key(params, role_key):
    if role_key['key_type'] == 'encrypted_by_data_key':
        return api.decrypt_data(role_key['encrypted_key'], params.data_key)
    elif role_key['key_type'] == 'encrypted_by_public_key':
        return api.decrypt_rsa(role_key['encrypted_key'], params.rsa_key)
    else:
        return None


class EnterpriseCommand(Command):
    def __init__(self):
        super(EnterpriseCommand, self).__init__()
        self.public_keys = {}
        self.team_keys = {}
        self._node_map = None

    def execute_args(self, params, args, **kwargs):
        if params.enterprise:
            return Command.execute_args(self, params, args, **kwargs)
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

    def get_role_users_change_batch(self, params, roles, add_user, remove_user, force=False):
        """Get batch of requests for changing enterprise role users"""
        request_batch = []
        user_changes = {}
        for is_add in (False, True):
            ul = add_user if is_add else remove_user
            if ul:
                for u in ul:
                    user_node = next((
                        user for user in params.enterprise.get('users', [])
                        if u.lower() in (str(user['enterprise_user_id']), user['username'].lower())
                    ), None)
                    if user_node:
                        user_id = user_node['enterprise_user_id']
                        user_changes[user_id] = is_add, user_node['username']
                    else:
                        logging.warning('User %s could be resolved', u)

        user_pkeys = {}
        for role in roles:
            role_id = role['role_id']
            for user_id in user_changes:
                is_add, email = user_changes[user_id]
                role_key = None
                if is_add:
                    is_managed_role = next((
                        True for mn in params.enterprise.get('managed_nodes', []) if mn['role_id'] == role_id
                    ), False)
                else:
                    is_managed_role = False

                if is_managed_role:
                    role_keys2 = params.enterprise.get('role_keys2', [])
                    role_key = next((rk2['role_key'] for rk2 in role_keys2 if rk2['role_id'] == role_id), None)
                    if role_key:
                        encrypted_key_decoded = base64.urlsafe_b64decode(role_key + '==')
                        role_key = rest_api.decrypt_aes(
                            encrypted_key_decoded, params.enterprise['unencrypted_tree_key']
                        )
                    else:
                        role_keys = params.enterprise.get('role_keys', [])
                        role_key = next((
                            decrypt_role_key(params, rk) for rk in role_keys if rk['role_id'] == role_id
                        ), None)
                rq = {
                    'command': 'role_user_add' if is_add else 'role_user_remove',
                    'enterprise_user_id': user_id,
                    'role_id': role_id
                }
                if is_managed_role:
                    if user_id not in user_pkeys:
                        answer = 'y' if force else user_choice(
                            'Do you want to grant administrative privileges to {0}'.format(email), 'yn', 'n')
                        public_key = None
                        if answer == 'y':
                            public_key = self.get_public_key(params, email)
                            if public_key is None:
                                logging.warning('Cannot get public key for user %s', email)
                        user_pkeys[user_id] = public_key
                    if user_pkeys[user_id]:
                        encrypted_tree_key = crypto.encrypt_rsa(params.enterprise['unencrypted_tree_key'],
                                                                user_pkeys[user_id])
                        rq['tree_key'] = utils.base64_url_encode(encrypted_tree_key)
                        if role_key:
                            encrypted_role_key = crypto.encrypt_rsa(role_key, user_pkeys[user_id])
                            rq['role_admin_key'] = utils.base64_url_encode(encrypted_role_key)
                        request_batch.append(rq)
                else:
                    request_batch.append(rq)
        return request_batch

    @staticmethod
    def decrypt_role_key(params, rk):
        if rk['key_type'] == 'encrypted_by_data_key':
            return api.decrypt_data(rk['encrypted_key'], params.data_key)
        elif rk['key_type'] == 'encrypted_by_public_key':
            return api.decrypt_rsa(rk['encrypted_key'], params.rsa_key)
        else:
            return None

    @staticmethod
    def change_role_teams(params, roles, add_team, remove_team):
        """Change enterprise role teams"""
        update_msgs = []
        add_teams = None
        remove_teams = None
        team_changes = {}
        for is_add in (False, True):
            team_list = add_team if is_add else remove_team
            if team_list:
                if is_add:
                    add_teams = RoleTeams()
                else:
                    remove_teams = RoleTeams()
                for team in team_list:
                    team_node = next((
                        t for t in params.enterprise.get('teams', []) if team in (t['team_uid'], t['name'])
                    ), None)
                    if team_node:
                        team_changes[team_node['team_uid']] = is_add, team_node['name']
                    else:
                        logging.warning('Team %s could be resolved', team)

        for role in roles:
            role_id = role['role_id']
            for team_id in team_changes:
                is_add, team_name = team_changes[team_id]
                if is_add:
                    is_managed_role = next((
                        True for mn in params.enterprise.get('managed_nodes', []) if mn['role_id'] == role_id
                    ), False)
                else:
                    is_managed_role = False

                if is_managed_role:
                    logging.warning('Teams cannot be assigned to roles with administrative permissions.')
                else:
                    role_team = RoleTeam()
                    role_team.role_id = role_id
                    role_team.teamUid = utils.base64_url_decode(team_id)
                    role_name = role['data']['displayname']
                    if is_add:
                        add_teams.role_team.append(role_team)
                        update_msgs.append(f"'{role_name}' role assigned to team '{team_name}'")
                    else:
                        remove_teams.role_team.append(role_team)
                        update_msgs.append(f"'{role_name}' role removed from team '{team_name}'")
        if remove_teams:
            api.communicate_rest(params, remove_teams, 'enterprise/role_team_remove')
        if add_teams:
            api.communicate_rest(params, add_teams, 'enterprise/role_team_add')
        return update_msgs

    @staticmethod
    def change_team_roles(params, teams, add_roles, remove_roles):
        update_msgs = []
        add_role_teams = None
        remove_role_teams = None
        role_changes = {}
        for is_add in (False, True):
            role_list = add_roles if is_add else remove_roles
            if role_list:
                if is_add:
                    add_role_teams = RoleTeams()
                else:
                    remove_role_teams = RoleTeams()
                for role in role_list:
                    role_node = next((
                        r for r in params.enterprise['roles']
                        if role in (str(r['role_id']), r['data'].get('displayname'))
                    ), None)
                    if role_node:
                        role_changes[role_node['role_id']] = is_add, role_node['data'].get('displayname')
                    else:
                        logging.warning('Role %s cannot be resolved', role)

        if len(role_changes) > 0:
            for role_id in role_changes:
                is_add, role_name = role_changes[role_id]
                role_teams = {r['team_uid'] for r in params.enterprise.get('role_teams', []) if r['role_id'] == role_id}
                if is_add:
                    is_managed_role = next((
                        True for mn in params.enterprise.get('managed_nodes', []) if mn['role_id'] == role_id
                    ), False)
                else:
                    is_managed_role = False

                if is_managed_role:
                    logging.warning('Teams cannot be assigned to roles with administrative permissions.')
                else:
                    for team in teams:
                        if is_add and team['team_uid'] in role_teams:
                            logging.warning(
                                'Team %s is already in "%s" role: Add to role is skipped', team['name'], role_name
                            )
                        elif not is_add and team['team_uid'] not in role_teams:
                            logging.warning(
                                'Team %s is not in "%s" role: Remove from role is skipped', team['name'], role_name
                            )
                        else:
                            role_team = RoleTeam()
                            role_team.role_id = role_id
                            role_team.teamUid = utils.base64_url_decode(team['team_uid'])
                            team_name = team['name']
                            if is_add:
                                add_role_teams.role_team.append(role_team)
                                update_msgs.append(f"'{role_name}' role assigned to team '{team_name}'")
                            else:
                                remove_role_teams.role_team.append(role_team)
                                update_msgs.append(f"'{role_name}' role removed from team '{team_name}'")
        if remove_role_teams:
            api.communicate_rest(params, remove_role_teams, 'enterprise/role_team_remove')
        if add_role_teams:
            api.communicate_rest(params, add_role_teams, 'enterprise/role_team_add')
        return update_msgs

    @staticmethod
    def get_enterprise_id(params):
        rq = {
            'command': 'enterprise_allocate_ids',
            'number_requested': 1
        }
        rs = api.communicate(params, rq)
        if rs['result'] == 'success':
            return rs['base_id']

    def get_node_path(self, params, node_id, omit_root=False):
        if self._node_map is None:
            self._node_map = {
                x['node_id']: (x['data'].get('displayname') if x.get('parent_id', 0) > 0 else params.enterprise['enterprise_name'], x.get('parent_id', 0))
                for x in params.enterprise['nodes']}
        path = ''
        node = self._node_map.get(node_id)
        while node:
            if omit_root and node[1] == 0:
                break
            path = '{0}{1}{2}'.format(node[0], '\\' if path else '', path)
            node = self._node_map.get(node[1])
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

    @staticmethod
    def is_msp(params):     # type: (KeeperParams) -> bool
        if params.enterprise:
            if 'licenses' in params.enterprise:
                msp_license = next((x for x in params.enterprise['licenses'] if x['lic_status'].startswith('msp')),
                                   None)
                if msp_license:
                    return True
        return False
