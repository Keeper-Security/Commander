import json
import os
from unittest import TestCase

import pytest

from keepercommander import api, crypto, utils
from keepercommander.commands.enterprise import EnterpriseTeamCommand, EnterpriseRoleCommand
from keepercommander.error import KeeperApiError
from keepercommander.params import KeeperParams


@pytest.mark.integration
@pytest.mark.cross_enterprise
class TestCrossEnterpriseCommands(TestCase):
    params1 = None
    params2 = None

    @classmethod
    def setUpClass(cls):
        cls.params1 = KeeperParams()
        config_filename = os.path.join(os.path.dirname(__file__), 'cross-enterprise.json')
        with open(config_filename, 'r') as f:
            config = json.load(f)
            cls.params1.server = config['server']
            cls.params1.user = config['user']
            cls.params1.password = config['password']
            cls.params1.device_private_key = config['private_key']
            cls.params1.device_token = config['device_token']
            cls.params1.clone_code = config['clone_code']
            cls.params1.config = config
        api.login(cls.params1)

        cls.params2 = KeeperParams()
        cls.params2.server = cls.params1.server
        cls.params2.device_private_key = cls.params1.device_private_key
        cls.params2.device_token = cls.params1.device_token
        cls.params2.clone_code = cls.params1.clone_code
        cls.params2.user = config['enterprise2']['user']
        cls.params2.password = config['enterprise2']['password']
        api.login(cls.params2)

    def test_add_user_to_team(self):
        param1 = TestCrossEnterpriseCommands.params1     # type: KeeperParams
        param2 = TestCrossEnterpriseCommands.params2     # type: KeeperParams

        users = [x for x in param2.enterprise['users'] if x['username'] != param2.user]
        self.assertGreater(len(users), 0, 'cannot resolve user')
        user = users[0]
        ent2_user_id = user['enterprise_user_id']

        api.load_user_public_keys(param2, [user['username']], send_invites=False)
        pk = param2.key_cache[user['username']]
        self.assertIsNotNone(pk)
        public_key = crypto.load_rsa_public_key(pk.rsa)

        #real team
        uids = []
        if 'teams' in param1.enterprise:
            uids = [x['team_uid'] for x in param1.enterprise['teams']]
        team_cmd = EnterpriseTeamCommand()
        if len(uids) == 0:
            team_cmd.execute(param1, add=True, team=['Team1'])
            uids = [x['team_uid'] for x in param1.enterprise['teams']]

        self.assertGreater(len(uids), 0, 'cannot resolve team')
        ent1_team_uid = uids[0]
        team_key = team_cmd.get_team_key(param1, ent1_team_uid)
        self.assertIsNotNone(team_key)
        rq = {
            "command": "team_enterprise_user_add",
            "team_uid": ent1_team_uid,
            "enterprise_user_id": ent2_user_id,
            "user_type": 0,
            "team_key": crypto.encrypt_rsa(team_key, public_key)
        }
        failed = False
        try:
            api.communicate(param1, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_enterprise_user_id")
        self.assertTrue(failed)

        failed = False
        try:
            api.communicate(param2, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "access_denied")
        self.assertTrue(failed)

        rq = {
            "command": "team_delete",
            "team_uid": ent1_team_uid
        }
        failed = False
        try:
            api.communicate(param2, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "access_denied")
        self.assertTrue(failed)

    def test_add_user_to_role(self):
        param1 = TestCrossEnterpriseCommands.params1     # type: KeeperParams
        param2 = TestCrossEnterpriseCommands.params2     # type: KeeperParams

        users = [x for x in param2.enterprise['users']]
        self.assertGreater(len(users), 0, 'cannot resolve user')
        user = users[0]
        ent2_user_id = user['enterprise_user_id']

        ids = []
        if 'roles' in param1.enterprise:
            ids = [x['role_id'] for x in param1.enterprise['roles']]
        role_cmd = EnterpriseRoleCommand()
        if len(ids) == 0:
            role_cmd.execute(param1, add=True, role=['Role1'])
            ids = [x['role_id'] for x in param1.enterprise['roles']]

        self.assertGreater(len(ids), 0, 'cannot resolve role')
        ent1_role_id = ids[0]
        rq = {
            "command": "role_user_add",
            "role_id": ent1_role_id,
            "enterprise_user_id": ent2_user_id
        }
        failed = False
        try:
            api.communicate(param1, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_enterprise_user_id")
        self.assertTrue(failed)

        failed = False
        try:
            api.communicate(param2, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_role_id")
        self.assertTrue(failed)

        rq = {
            "command": "role_delete",
            "role_id": ent1_role_id
        }
        failed = False
        try:
            api.communicate(param2, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_role_id")
        self.assertTrue(failed)

    def test_lock_user(self):
        param1 = TestCrossEnterpriseCommands.params1     # type: KeeperParams
        param2 = TestCrossEnterpriseCommands.params2     # type: KeeperParams

        users = [x for x in param2.enterprise['users']]
        self.assertGreater(len(users), 0, 'cannot resolve user')
        user = users[0]
        ent2_user_id = user['enterprise_user_id']

        rq = {
            "command": "enterprise_user_lock",
            "enterprise_user_id": ent2_user_id,
            "lock": "locked",
            "delete_if_pending": True
        }
        failed = False
        try:
            api.communicate(param1, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_enterprise_user_id")
        self.assertTrue(failed)

        rq = {
            "command": "enterprise_user_delete",
            "enterprise_user_id": ent2_user_id
        }
        failed = False
        try:
            api.communicate(param1, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_enterprise_user_id")
        self.assertTrue(failed)

    def test_add_node(self):
        param1 = TestCrossEnterpriseCommands.params1     # type: KeeperParams
        param2 = TestCrossEnterpriseCommands.params2     # type: KeeperParams

        ent1_parent_id = [x['node_id'] for x in param1.enterprise['nodes']][0]

        cmd = EnterpriseRoleCommand()
        ent2_node_id = cmd.get_enterprise_id(param2)
        dt = { "displayname": "Node ID" }
        encrypted_data = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(dt).encode('utf-8'), param2.enterprise['unencrypted_tree_key']))
        rq = {
            "command": "node_add",
            "node_id": ent2_node_id,
            "parent_id": ent1_parent_id,
            "encrypted_data": encrypted_data
        }
        failed = False
        try:
            api.communicate(param2, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_parent_id")
        self.assertTrue(failed)

    def test_role_create(self):
        param1 = TestCrossEnterpriseCommands.params1 # type: KeeperParams
        param2 = TestCrossEnterpriseCommands.params2 # type: KeeperParams

        ent1_parent_id = [x['node_id'] for x in param1.enterprise['nodes']][0]

        cmd = EnterpriseRoleCommand()
        ent2_role_id = cmd.get_enterprise_id(param2)
        dt = { "displayname": "Role" }
        encrypted_data = utils.base64_url_encode(
            crypto.encrypt_aes_v1(json.dumps(dt).encode('utf-8'), param2.enterprise['unencrypted_tree_key']))
        rq = {
            "command": "role_add",
            "role_id": ent2_role_id,
            "node_id": ent1_parent_id,
            "encrypted_data": encrypted_data,
            "visible_below": True,
            "new_user_inherit": False
        }
        failed = False
        try:
            api.communicate(param2, rq)
        except KeeperApiError as err:
            failed = True
            self.assertEqual(err.result_code, "bad_inputs_node_id")
        self.assertTrue(failed)

    def test_team_get_key(self):
        param1 = TestCrossEnterpriseCommands.params1     # type: KeeperParams
        param2 = TestCrossEnterpriseCommands.params2     # type: KeeperParams

        uids = [x['team_uid'] for x in param1.enterprise['teams']]
        self.assertGreater(len(uids), 0, 'cannot resolve team')
        ent1_team_uid = uids[0]

        rq = {
            "command": "team_get_keys",
            "teams": [ent1_team_uid]
        }
        rs = api.communicate(param2, rq)
        self.assertEqual(rs['keys'][0]['result_code'], "doesnt_exist")
