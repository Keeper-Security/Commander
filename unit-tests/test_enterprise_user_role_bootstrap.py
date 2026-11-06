import json
from unittest import TestCase, mock

from keepercommander import crypto, utils
from keepercommander.commands.enterprise import EnterpriseRoleCommand
from keepercommander.commands.enterprise_create_user import CreateEnterpriseUserCommand
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams, PublicKeys
from keepercommander.proto import enterprise_pb2


def _make_enterprise_params():
    params = KeeperParams()
    params.server = 'https://keepersecurity.com/api/v2/'
    params.user = 'admin@acme.com'
    params.forbid_rsa = True
    tree_key = utils.generate_aes_key()
    _, ec_pub = crypto.generate_ec_key()
    ec_pub_bytes = crypto.unload_ec_public_key(ec_pub)
    params.enterprise_ec_key = ec_pub
    params.enterprise = {
        'enterprise_name': 'Acme Corp',
        'unencrypted_tree_key': tree_key,
        'keys': {
            'ecc_public_key': utils.base64_url_encode(ec_pub_bytes),
        },
        'nodes': [
            {'node_id': 100, 'parent_id': 0, 'data': {'displayname': 'Acme Corp'}},
            {'node_id': 200, 'parent_id': 100, 'data': {'displayname': 'Engineering'}},
        ],
        'roles': [
            {
                'role_id': 10,
                'node_id': 100,
                'data': {'displayname': 'DevOps'},
                'encrypted_data': 'enc-devops',
                'visible_below': True,
                'new_user_inherit': False,
            },
            {
                'role_id': 20,
                'node_id': 100,
                'data': {'displayname': 'Auditors'},
                'encrypted_data': 'enc-auditors',
                'visible_below': True,
                'new_user_inherit': False,
            },
        ],
        'users': [
            {
                'enterprise_user_id': 1,
                'username': 'admin@acme.com',
                'node_id': 100,
                'status': 'active',
                'lock': 0,
                'data': {'displayname': 'Admin'},
            },
            {
                'enterprise_user_id': 2,
                'username': 'alice@acme.com',
                'node_id': 100,
                'status': 'active',
                'lock': 0,
                'data': {'displayname': 'Alice'},
            },
        ],
        'role_users': [
            {'role_id': 10, 'enterprise_user_id': 1},
        ],
        'managed_nodes': [
            {'role_id': 10, 'managed_node_id': 100, 'cascade_node_management': True},
        ],
        'role_privileges': [],
        'role_enforcements': [],
    }
    params.key_cache['alice@acme.com'] = PublicKeys(ec=ec_pub_bytes)
    params.key_cache['newuser@acme.com'] = PublicKeys(ec=ec_pub_bytes)
    return params


class TestCreateEnterpriseUserBootstrap(TestCase):
    def _mock_provision_response(self, code='success'):
        rs = enterprise_pb2.EnterpriseUsersProvisionResponse()
        res = enterprise_pb2.EnterpriseUsersProvisionResult()
        res.enterpriseUserId = 999
        res.code = code
        rs.results.append(res)
        return rs

    @mock.patch('keepercommander.commands.enterprise_create_user.OneTimeShareCreateCommand.execute')
    @mock.patch('keepercommander.commands.enterprise_create_user.record_management.update_record')
    @mock.patch('keepercommander.commands.enterprise_create_user.record_management.add_record_to_folder')
    @mock.patch('keepercommander.commands.enterprise_create_user.api.sync_down')
    @mock.patch('keepercommander.commands.enterprise_create_user.api.execute_batch')
    @mock.patch('keepercommander.commands.enterprise_create_user.api.query_enterprise')
    @mock.patch('keepercommander.commands.enterprise_create_user.api.communicate_rest')
    @mock.patch('keepercommander.commands.enterprise_create_user.LoginV3API.get_device_id', return_value=b'dev-token')
    @mock.patch('keepercommander.commands.enterprise_create_user.EnterpriseCommand.get_enterprise_id', return_value=999)
    def test_create_user_with_add_role_and_json_format(
        self,
        _mock_ent_id,
        _mock_dev_id,
        mock_comm_rest,
        mock_query_ent,
        mock_exec_batch,
        _mock_sync,
        mock_add_rec,
        _mock_upd_rec,
        mock_ots,
    ):
        params = _make_enterprise_params()
        mock_comm_rest.return_value = self._mock_provision_response('success')

        def _populate_new_user(p, *args, **kwargs):
            if not any(u['enterprise_user_id'] == 999 for u in p.enterprise['users']):
                p.enterprise['users'].append({
                    'enterprise_user_id': 999,
                    'username': 'newuser@acme.com',
                    'node_id': 100,
                    'status': 'active',
                    'lock': 0,
                    'data': {'displayname': 'New User'},
                })

        mock_query_ent.side_effect = _populate_new_user

        def _assign_uid(p, rec, folder_uid=None):
            rec.record_uid = 'REC_UID_999'

        mock_add_rec.side_effect = _assign_uid
        mock_ots.return_value = 'https://keepersecurity.com/vault/#ots/xyz'

        cmd = CreateEnterpriseUserCommand()
        out = cmd.execute(
            params,
            email='newuser@acme.com',
            name='New User',
            node='Acme Corp',
            add_role=['Auditors', '20'],  # duplicate by name and ID should be deduplicated
            format='json',
        )

        data = json.loads(out)
        self.assertEqual(data['enterprise_user_id'], 999)
        self.assertEqual(data['email'], 'newuser@acme.com')
        self.assertEqual(data['name'], 'New User')
        self.assertEqual(data['node_id'], 100)
        self.assertEqual(data['record_uid'], 'REC_UID_999')
        self.assertEqual(data['one_time_share_url'], 'https://keepersecurity.com/vault/#ots/xyz')
        self.assertEqual(data['roles'], [{'role_id': 20, 'name': 'Auditors'}])

        mock_exec_batch.assert_called_once()
        batch_arg = mock_exec_batch.call_args[0][1]
        self.assertEqual(len(batch_arg), 1)
        self.assertEqual(batch_arg[0]['command'], 'role_user_add')
        self.assertEqual(batch_arg[0]['role_id'], 20)
        self.assertEqual(batch_arg[0]['enterprise_user_id'], 999)

    @mock.patch('keepercommander.commands.enterprise_create_user.OneTimeShareCreateCommand.execute', return_value=None)
    @mock.patch('keepercommander.commands.enterprise_create_user.record_management.add_record_to_folder')
    @mock.patch('keepercommander.commands.enterprise_create_user.api.sync_down')
    @mock.patch('keepercommander.commands.enterprise_create_user.api.query_enterprise')
    @mock.patch('keepercommander.commands.enterprise_create_user.api.communicate_rest')
    @mock.patch('keepercommander.commands.enterprise_create_user.LoginV3API.get_device_id', return_value=b'dev-token')
    @mock.patch('keepercommander.commands.enterprise_create_user.EnterpriseCommand.get_enterprise_id', return_value=999)
    def test_create_user_auto_hydrates_enterprise_and_verbose_returns_uid(
        self,
        _mock_ent_id,
        _mock_dev_id,
        mock_comm_rest,
        mock_query_ent,
        _mock_sync,
        mock_add_rec,
        _mock_ots,
    ):
        hydrated_params = _make_enterprise_params()
        cold_params = KeeperParams()
        cold_params.server = hydrated_params.server
        cold_params.forbid_rsa = True
        cold_params.enterprise_ec_key = hydrated_params.enterprise_ec_key
        cold_params.enterprise = None

        def _hydrate(p, *args, **kwargs):
            p.enterprise = hydrated_params.enterprise

        mock_query_ent.side_effect = _hydrate
        mock_comm_rest.return_value = self._mock_provision_response('success')
        mock_add_rec.side_effect = lambda p, rec, folder_uid=None: setattr(rec, 'record_uid', 'REC_VERBOSE_1')

        cmd = CreateEnterpriseUserCommand()
        uid = cmd.execute(cold_params, email='newuser@acme.com', node='Acme Corp', verbose=True)
        self.assertEqual(uid, 'REC_VERBOSE_1')

    @mock.patch('keepercommander.commands.enterprise_create_user.api.query_enterprise')
    def test_create_user_raises_when_not_enterprise_admin(self, _mock_query_ent):
        params = KeeperParams()
        params.enterprise = None
        cmd = CreateEnterpriseUserCommand()
        with self.assertRaises(CommandError):
            cmd.execute(params, email='newuser@acme.com')


class TestEnterpriseRoleCombinedUpdates(TestCase):
    @mock.patch('keepercommander.commands.enterprise.api.query_enterprise')
    @mock.patch('keepercommander.commands.enterprise.api.load_user_public_keys')
    @mock.patch('keepercommander.commands.enterprise.api.execute_batch')
    def test_combine_add_user_add_admin_enforcement_and_visible_below(
        self,
        mock_exec_batch,
        _mock_load_keys,
        _mock_query_ent,
    ):
        params = _make_enterprise_params()
        mock_exec_batch.side_effect = lambda p, batch: [{'result': 'success', 'result_code': 'success', 'message': ''} for _ in batch]

        cmd = EnterpriseRoleCommand()
        cmd.execute(
            params,
            role=['Auditors'],
            add_user=['alice@acme.com'],
            add_admin=['Engineering'],
            enforcements=['master_password_minimum_length:16'],
            visible_below='off',
            force=True,
        )

        mock_exec_batch.assert_called_once()
        batch = mock_exec_batch.call_args[0][1]
        commands = [rq['command'] for rq in batch]
        self.assertIn('role_user_add', commands)
        self.assertIn('role_enforcement_add', commands)
        self.assertIn('role_managed_node_add', commands)
        self.assertIn('role_update', commands)

        # Verify role_managed_node_add includes tree_key for alice@acme.com added in the same batch
        mn_rq = next(rq for rq in batch if rq['command'] == 'role_managed_node_add')
        self.assertEqual(mn_rq['managed_node_id'], 200)
        tree_key_user_ids = [tk['enterprise_user_id'] for tk in mn_rq.get('tree_keys', [])]
        self.assertIn(2, tree_key_user_ids)

        # Verify role_update kept the role's own node_id (100) rather than mutating to managed_node_id (200)
        upd_rq = next(rq for rq in batch if rq['command'] == 'role_update')
        self.assertEqual(upd_rq['node_id'], 100)
        self.assertFalse(upd_rq['visible_below'])
