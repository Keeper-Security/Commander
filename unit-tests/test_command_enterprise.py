import logging
import json
from datetime import datetime, timedelta
from typing import Optional
from unittest import TestCase, mock

from data_enterprise import EnterpriseEnvironment, get_enterprise_data, enterprise_allocate_ids
from keepercommander import api, crypto, utils, vault
from keepercommander.params import KeeperParams, PublicKeys
from keepercommander.error import CommandError
from data_vault import VaultEnvironment, get_connected_params
from keepercommander.commands import enterprise, aram


vault_env = VaultEnvironment()
ent_env = EnterpriseEnvironment()


class TestEnterprise(TestCase):
    expected_commands = []

    def setUp(self):
        TestEnterprise.use_data_key = True
        TestEnterprise.expected_commands.clear()
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = TestEnterprise.communicate_success
        self.query_enterprise_mock = mock.patch('keepercommander.api.query_enterprise').start()
        self.query_enterprise_mock.side_effect = TestEnterprise.query_enterprise
        self.load_user_public_keys_mock = mock.patch('keepercommander.api.load_user_public_keys').start()
        self.load_user_public_keys_mock.side_effect = TestEnterprise.load_user_public_keys

    def tearDown(self):
        mock.patch.stopall()

    def test_get_enterprise(self):
        params = get_connected_params()
        api.query_enterprise(params)
        self.assertIsNotNone(params.enterprise)
        self.assertEqual(params.enterprise['unencrypted_tree_key'], ent_env.tree_key)
        self.assertEqual(len(params.enterprise['nodes']), 2)

    def test_get_enterprise_public_key(self):
        TestEnterprise.use_data_key = False
        params = get_connected_params()
        api.query_enterprise(params)
        self.assertIsNotNone(params.enterprise)
        self.assertEqual(params.enterprise['unencrypted_tree_key'], ent_env.tree_key)
        self.assertEqual(len(params.enterprise['nodes']), 2)

    def test_enterprise_info_command(self):
        params = get_connected_params()
        api.query_enterprise(params)

        with mock.patch('builtins.print'):
            cmd = enterprise.EnterpriseInfoCommand()
            cmd.execute(params, verbose=True)

    def test_enterprise_info_users_verbose_returns_ids(self):
        """With -v, node/teams/roles include separate name and ID fields; without -v, names only."""
        params = get_connected_params()
        api.query_enterprise(params)
        cmd = enterprise.EnterpriseInfoCommand()
        columns = 'name,node,teams,roles'

        report = cmd.execute(
            params, users=True, format='json', columns=columns, quiet=True)
        users = json.loads(report)
        user1 = next(u for u in users if u['user_id'] == ent_env.user1_id)
        self.assertEqual(user1['node'], 'Enterprise 1')
        self.assertEqual(user1['teams'], [ent_env.team1_name])
        self.assertEqual(user1['roles'], [ent_env.role1_name])

        report = cmd.execute(
            params, users=True, format='json', columns=columns, verbose=True, quiet=True)
        users = json.loads(report)
        user1 = next(u for u in users if u['user_id'] == ent_env.user1_id)
        self.assertEqual(user1['node'], {
            'node_id': str(ent_env.node1_id),
            'node_name': 'Enterprise 1',
        })
        self.assertEqual(user1['teams'], [{
            'team_uid': ent_env.team1_uid,
            'team_name': ent_env.team1_name,
        }])
        self.assertEqual(user1['roles'], [{
            'role_id': str(ent_env.role1_id),
            'role_name': ent_env.role1_name,
        }])

    def test_enterprise_add_user(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseUserCommand()
        TestEnterprise.expected_commands = ['enterprise_user_add']
        cmd.execute(params, add=True, email='user2@keepercommander.com')
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_delete_user(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseUserCommand()
        TestEnterprise.expected_commands = ['enterprise_user_delete']
        cmd.execute(params, delete=True, force=True, email=[ent_env.user2_email])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_lock_user(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseUserCommand()
        TestEnterprise.expected_commands = ['enterprise_user_lock', 'enterprise_user_lock']
        cmd.execute(params, unlock=True, email=[ent_env.user2_email])
        cmd.execute(params, lock=True, email=[ent_env.user2_email])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_wrong_user(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseUserCommand()
        with self.assertRaises(CommandError):
            with self.assertLogs(level=logging.WARNING):
                cmd.execute(params, lock=True, email=['wrong.user@keepersecurity.com'])

    def test_enterprise_expire_password(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseUserCommand()
        TestEnterprise.expected_commands = ['set_master_password_expire']
        cmd.execute(params, expire=True, force=True, email=[ent_env.user2_email])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

        with mock.patch('keepercommander.commands.enterprise.user_choice') as mock_choice:
            TestEnterprise.expected_commands = ['set_master_password_expire']
            mock_choice.return_value = 'y'
            cmd.execute(params, expire=True, email=[ent_env.user2_email])
            with mock.patch('builtins.print'):
                self.assertEqual(len(TestEnterprise.expected_commands), 0)
                mock_choice.return_value = 'n'
                cmd.execute(params, expire=True, email=[ent_env.user2_email])

    def test_enterprise_user_update(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseUserCommand()
        TestEnterprise.expected_commands = ['enterprise_user_update']
        cmd.execute(params, node='Enterprise 1', email=[ent_env.user2_email])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

        TestEnterprise.expected_commands = ['enterprise_user_update']
        cmd.execute(params, node='{0}'.format(ent_env.node1_id), email=[ent_env.user2_email])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_user_team(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseUserCommand()
        TestEnterprise.expected_commands = ['team_enterprise_user_add']
        cmd.execute(params, add_team=[ent_env.team1_uid], email=[ent_env.user2_email])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

        TestEnterprise.expected_commands = ['team_enterprise_user_remove']
        cmd.execute(params, remove_team=[ent_env.team1_uid], email=[ent_env.user2_email])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseRoleCommand()
        with mock.patch('builtins.print'):
            cmd.execute(params, role=[ent_env.role1_name])

        with mock.patch('keepercommander.commands.enterprise_common.user_choice') as mock_choice:
            mock_choice.return_value = 'y'
            TestEnterprise.expected_commands = ['role_user_add']
            cmd.execute(params, add_user=[ent_env.user2_email], role=[ent_env.role1_id])
            self.assertEqual(len(TestEnterprise.expected_commands), 0)

        TestEnterprise.expected_commands = ['role_user_remove']
        cmd.execute(params, remove_user=[ent_env.user2_email], role=[ent_env.role1_name])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

        with self.assertLogs(level=logging.WARNING):
            cmd.execute(params, add_user=[ent_env.user2_email], verbose=True, role=['Invalid'])
            with mock.patch('builtins.print'):
                cmd.execute(params, add_user=['invalid@keepersecurity.com'], verbose=True, role=[ent_env.role1_name])

    def test_enterprise_role_add_transfer_account_privilege_denied(self):
        """KC-1412: Delegated admin without transfer_account privilege cannot grant it (CVE fix)"""
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseRoleCommand()
        # Role1 (current user) has only manage_nodes, manage_user, manage_roles (no transfer_account)
        # Try to grant transfer_account to Role2 - should be denied by KC-1412 fix
        with self.assertLogs(level=logging.WARNING) as log:
            cmd.execute(params, add_privilege=['transfer_account'], role=[ent_env.role2_name],
                       node='Enterprise 1')
            # KC-1412 fix: Check for the privilege denial message
            self.assertTrue(any('You do not have the required privilege' in msg for msg in log.output))

        # Expected: no command sent to server (returned early due to lack of authorization)
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_add_manage_teams_privilege_denied(self):
        """KC-1412: Delegated admin without manage_teams privilege cannot grant it (CVE fix)"""
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseRoleCommand()
        # Role1 has no manage_teams privilege - try to grant it, should be denied
        with self.assertLogs(level=logging.WARNING) as log:
            cmd.execute(params, add_privilege=['manage_teams'], role=[ent_env.role2_name],
                       node='Enterprise 1')
            # KC-1412 fix: Check for the privilege denial message
            self.assertTrue(any('You do not have the required privilege' in msg for msg in log.output))

        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_add_privilege_with_authorization(self):
        """KC-1412: Admin with transfer_account privilege CAN grant it (regression test)"""
        params = get_connected_params()
        api.query_enterprise(params)

        # Use the admin role which has transfer_account in test data
        # Add admin role to User1 so they have the privilege
        params.enterprise['role_users'].append({
            'role_id': ent_env.role_admin_id,
            'enterprise_user_id': ent_env.user1_id
        })

        cmd = enterprise.EnterpriseRoleCommand()
        TestEnterprise.expected_commands = ['managed_node_privilege_add']
        # Now User1 has transfer_account via Admin role, can grant it to Role2
        cmd.execute(params, add_privilege=['transfer_account'], role=[ent_env.role2_name],
                   node='Enterprise 1')
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_require_account_share_enforcement_denied_delegated_admin(self):
        """KC-1412: Delegated admin (non-root) cannot set require_account_share enforcement (CVE fix)"""
        params = get_connected_params()
        api.query_enterprise(params)

        # Node2 is a sub-node (has parent_id), so user in that node is not root admin
        # Modify to make Role1 manage Node2 instead
        params.enterprise['managed_nodes'] = [
            {
                'role_id': ent_env.role1_id,
                'managed_node_id': ent_env.node2_id,
                'cascade_node_management': True,
            }
        ]

        cmd = enterprise.EnterpriseRoleCommand()
        # Try to set require_account_share enforcement by role name
        # This should be denied because the user is not a root admin (managing non-root node)
        # KC-1412 fix should reject this with a warning and return early
        with self.assertLogs(level=logging.WARNING):
            cmd.execute(params, enforcements=[f'require_account_share:Admin Role'],
                       role=[ent_env.role1_name])

        # No command should be sent to server (returned early due to root admin check)
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_require_account_share_enforcement_allowed_root_admin(self):
        """KC-1412: Root admin CAN set require_account_share enforcement (regression test)"""
        params = get_connected_params()
        api.query_enterprise(params)

        # Role1 manages Node1 (root node, no parent_id) - user is root admin
        # Set enforcement to Admin Role which has transfer_account privilege
        cmd = enterprise.EnterpriseRoleCommand()
        TestEnterprise.expected_commands = ['role_enforcement_add']
        cmd.execute(params, enforcements=['require_account_share:Admin Role'],
                   role=[ent_env.role1_name])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_other_enforcements_work_delegated_admin(self):
        """KC-1412: Delegated admin CAN set non-sensitive enforcements (regression test)"""
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseRoleCommand()
        # Non-sensitive enforcement should work for delegated admin
        TestEnterprise.expected_commands = ['role_enforcement_add']
        cmd.execute(params, enforcements=['require_two_factor:True'],
                   role=[ent_env.role1_name])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_cascade_privilege_grant(self):
        """KC-1435: Privilege grant on child node respects cascade from parent (regression test)"""
        params = get_connected_params()
        api.query_enterprise(params)

        # Set up: Admin role has transfer_account on Node1 (root)
        # Add admin role's transfer_account privilege to parent node
        params.enterprise['role_privileges'].append({
            'role_id': ent_env.role_admin_id,
            'managed_node_id': ent_env.node1_id,
            'privilege': 'transfer_account'
        })
        # Add User1 to admin role so they have transfer_account via cascade
        params.enterprise['role_users'].append({
            'role_id': ent_env.role_admin_id,
            'enterprise_user_id': ent_env.user1_id
        })
        # Role2 manages Node2 (child of Node1) with cascade enabled
        params.enterprise['managed_nodes'].append({
            'role_id': ent_env.role2_id,
            'managed_node_id': ent_env.node2_id,
            'cascade_node_management': False,
        })

        cmd = enterprise.EnterpriseRoleCommand()
        TestEnterprise.expected_commands = ['managed_node_privilege_add']
        # Attempt to grant transfer_account on the child node — should succeed because
        # the user's transfer_account privilege on parent Node1 cascades down to Node2
        cmd.execute(params, add_privilege=['transfer_account'], role=[ent_env.role2_name],
                   node='Sub node 1')
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_mixed_case_username(self):
        """KC-1435: Username matching is case-insensitive (regression test)"""
        params = get_connected_params()
        # Mock user with mixed-case username
        params.user = 'User@TEST.COM'
        api.query_enterprise(params)

        # Update the test data user to match in lowercase
        params.enterprise['users'][0]['username'] = 'user@test.com'

        # Add admin role to User1 for transfer_account
        params.enterprise['role_users'].append({
            'role_id': ent_env.role_admin_id,
            'enterprise_user_id': ent_env.user1_id
        })

        cmd = enterprise.EnterpriseRoleCommand()
        TestEnterprise.expected_commands = ['managed_node_privilege_add']
        # Should succeed despite mixed-case username in params.user
        cmd.execute(params, add_privilege=['transfer_account'], role=[ent_env.role2_name],
                   node='Enterprise 1')
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_role_enforcement_removal_restricted_non_root(self):
        """KC-1435: Delegated admin cannot remove require_account_share enforcement (CVE fix)"""
        params = get_connected_params()
        api.query_enterprise(params)

        # Set up Role1 to manage Node2 (non-root)
        params.enterprise['managed_nodes'] = [
            {
                'role_id': ent_env.role1_id,
                'managed_node_id': ent_env.node2_id,
                'cascade_node_management': True,
            }
        ]
        # Add existing enforcement on Role2
        params.enterprise['role_enforcements'] = [
            {
                'role_id': ent_env.role2_id,
                'enforcements': {
                    'require_account_share': 'Admin Role'
                }
            }
        ]

        cmd = enterprise.EnterpriseRoleCommand()
        # Attempt to remove the enforcement — should be denied by KC-1435 fix
        # because delegated admin managing non-root node cannot modify it
        with self.assertLogs(level=logging.WARNING):
            cmd.execute(params, enforcements=['require_account_share'],
                       role=[ent_env.role2_name])

        # No command should be sent (denied by KC-1435 fix)
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_team(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseTeamCommand()
        with mock.patch('builtins.print'):
            cmd.execute(params, team=[ent_env.team1_uid])

        TestEnterprise.expected_commands = ['team_add']
        cmd.execute(params, add=True, restrict_edit='on', node=str(ent_env.node1_id), team=['Team 3'])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

        with mock.patch('keepercommander.commands.enterprise.user_choice') as mock_choice:
            TestEnterprise.expected_commands = ['team_delete']
            mock_choice.return_value = 'y'
            cmd.execute(params, delete=True, team=['Team 1'])
            self.assertEqual(len(TestEnterprise.expected_commands), 0)

            with mock.patch('builtins.print'):
                mock_choice.return_value = 'n'
                cmd.execute(params, delete=True, team=[ent_env.team1_uid])
                self.assertEqual(len(TestEnterprise.expected_commands), 0)

        with self.assertLogs(level=logging.WARNING):
            cmd.execute(params, delete=True, team=['Unknown Team'])
            self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_enterprise_team_user(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterpriseTeamCommand()

        TestEnterprise.expected_commands = ['team_enterprise_user_add']
        cmd.execute(params, add_user=[ent_env.user2_email], team=[ent_env.team1_uid])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

        # Manually update the mock data to reflect that user2 is now in team1
        params.enterprise['team_users'].append({
            'team_uid': ent_env.team1_uid,
            'enterprise_user_id': ent_env.user2_id,
            'user_type': 0
        })

        TestEnterprise.expected_commands = ['team_enterprise_user_remove']
        cmd.execute(params, remove_user=[ent_env.user2_email], team=[ent_env.team1_uid])
        self.assertEqual(len(TestEnterprise.expected_commands), 0)

    def test_audit_log_splunk_properties_success(self):
        splunk = aram.AuditLogSplunkExport()
        props = {}
        record = vault.PasswordRecord()

        with mock.patch('builtins.print'), mock.patch('builtins.input') as mock_input, mock.patch('requests.post') as mock_post:
            resp1 = mock.Mock()
            resp1.status_code = 401
            resp1.json.return_value = {'code': 2}
            resp2 = mock.Mock()
            resp2.status_code = 400
            resp2.json.return_value = {'code': 6}
            mock_input.side_effect = ['www.splunk.com', 'Splunk Token', KeyboardInterrupt()]
            mock_post.side_effect = [resp1, resp2, Exception()]
            splunk.get_properties(record, props)
            self.assertIn('hec_url', props)
            self.assertIn('token', props)
            self.assertEqual(props['hec_url'], record.link)
            self.assertEqual(props['token'], record.password)
            self.assertTrue(splunk.store_record)

    def test_audit_log_splunk_properties_cancel(self):
        splunk = aram.AuditLogSplunkExport()
        props = {}
        record = vault.PasswordRecord()
        with mock.patch('builtins.print'), mock.patch('builtins.input') as mock_input, mock.patch('requests.post') as mock_post:
            resp1 = mock.Mock()
            resp1.status_code = 404
            mock_input.side_effect = ['www.splunk.com', KeyboardInterrupt()]
            mock_post.side_effect = [resp1, Exception()]
            with self.assertRaises(KeyboardInterrupt):
                splunk.get_properties(record, props)

    def test_audit_log_splunk_convert_event(self):
        splunk = aram.AuditLogSplunkExport()
        props = {
            'host': 'h',
            'enterprise_name': 'Unittest'
        }
        splunk.convert_event(props, self.get_audit_event())

    def test_audit_audit_report_parse_date_filter(self):
        cmd = aram.AuditReportCommand()

        epoch_max = int(datetime.now().timestamp())
        dt_max = datetime.fromtimestamp(epoch_max)

        dt_min = dt_max - timedelta(days=1)
        epoch_min = int(dt_min.timestamp())

        val = cmd.get_filter(dt_max.strftime('%Y-%m-%dT%H:%M:%SZ'), cmd.convert_date)
        self.assertTrue(type(val) == int)
        self.assertEqual(epoch_max, val)

        rng = cmd.get_filter('>{0}'.format(dt_min.strftime('%Y-%m-%dT%H:%M:%SZ')), cmd.convert_date)
        self.assertTrue(type(rng) == dict)
        self.assertIn('min', rng)
        self.assertIn('exclude_min', rng)
        self.assertTrue(rng['exclude_min'])
        self.assertNotIn('max', rng)
        self.assertEqual(rng['min'], epoch_min)

        rng = cmd.get_filter('<= {0}'.format(dt_max.strftime('%Y-%m-%dT%H:%M:%SZ')), cmd.convert_date)
        self.assertTrue(type(rng) == dict)
        self.assertIn('max', rng)
        self.assertFalse(rng.get('exclude_max') or False)
        self.assertNotIn('min', rng)
        self.assertEqual(rng['max'], epoch_max)

        rng = cmd.get_filter('between {0} and {1}'.format(dt_min.strftime('%Y-%m-%dT%H:%M:%SZ'), dt_max.strftime('%Y-%m-%dT%H:%M:%SZ')), cmd.convert_date)
        self.assertTrue(type(rng) == dict)
        self.assertIn('min', rng)
        self.assertIn('max', rng)
        self.assertEqual(rng['min'], epoch_min)
        self.assertEqual(rng['max'], epoch_max)

    def test_audit_audit_report_parse_int_filter(self):
        cmd = aram.AuditReportCommand()
        arr = cmd.get_filter('In (1,2,3, 4, 6,   5,7, 0)', cmd.convert_int)
        self.assertTrue(type(arr) == list)
        arr.sort()
        self.assertListEqual(arr, [0, 1, 2, 3, 4, 5, 6, 7])

    def test_audit_report_sox_fetch_uses_freshness_when_record_details_allowed(self):
        params = mock.Mock()
        cmd = aram.AuditReportCommand()
        cmd.allow_sox_data_fetch = True
        sox_data = mock.Mock()
        before = int(datetime.now().timestamp())
        with mock.patch('keepercommander.commands.aram.is_compliance_reporting_enabled', return_value=True), \
                mock.patch('keepercommander.commands.aram.get_compliance_data', return_value=sox_data) as mock_get:
            self.assertIs(cmd.get_sox_data(params), sox_data)
        min_updated = mock_get.call_args.kwargs.get('min_updated')
        self.assertGreaterEqual(min_updated, before)

    def test_audit_report_sox_fetch_uses_cache_only_by_default(self):
        params = mock.Mock()
        cmd = aram.AuditReportCommand()
        sox_data = mock.Mock()
        with mock.patch('keepercommander.commands.aram.is_compliance_reporting_enabled', return_value=True), \
                mock.patch('keepercommander.commands.aram.get_compliance_data', return_value=sox_data) as mock_get:
            self.assertIs(cmd.get_sox_data(params), sox_data)
        self.assertEqual(mock_get.call_args.kwargs.get('min_updated'), 0)

    def test_enterprise_push_command(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = enterprise.EnterprisePushCommand()

        template_body = '''
[
    {
        "title": "Record For ${user_name}",
        "login": "${user_email}",
        "password": "${generate_password}",
        "login_url": "https://keepersecurity.com",
        "notes": "notes",
        "custom_fields": {
            "key1": "value1",
            "key2": "${user_email}"
        }
    },
    {
        "title": "Empty record"
    }

]'''
        templates = json.loads(template_body)
        values = {
            'user_name': api.generate_record_uid(),
            'generate_password': api.generate_record_uid(),
            'user_email': api.generate_record_uid()
        }
        cmd.enumerate_and_substitute_dict_fields(templates[0], values)
        cmd.enumerate_and_substitute_dict_fields(templates[1], values)
        self.assertEqual(templates[0]['title'], 'Record For {0}'.format(values['user_name']))
        self.assertEqual(templates[0]['password'], values['generate_password'])
        self.assertEqual(templates[0]['custom_fields']['key2'], values['user_email'])
        self.assertEqual(templates[1]['title'], 'Empty record')

        with self.assertRaises(CommandError):
            cmd.execute(params, file='template.json')

        with self.assertRaises(CommandError):
            cmd.execute(params, user=[ent_env.user2_email])

    @staticmethod
    def get_audit_event():
        return {
            'id': 123456789098,
            'created': int(datetime.now().timestamp()),
            'username': vault_env.user,
            'ip_address': '9.9.9.9',
            'audit_event_type': 'login',
            'keeper_version': 'c16.0.0'
        }

    @staticmethod
    def load_user_public_keys(params, emails, send_invites=False):
        keys = PublicKeys(rsa=crypto.unload_rsa_public_key(vault_env.public_key))
        for email in emails:
            params.key_cache[email] = keys

    @staticmethod
    def query_enterprise(params, force=False, tree_key=None):
        # type: (KeeperParams, Optional[bool], Optional[bytes]) -> None
        params.enterprise = get_enterprise_data(params)
        if params.enterprise:
            encrypted_tree_key = utils.base64_url_decode(params.enterprise['tree_key'])
            params.enterprise['unencrypted_tree_key'] = crypto.decrypt_aes_v1(encrypted_tree_key, params.data_key)

            tree_key = params.enterprise['unencrypted_tree_key']
            for key in params.enterprise:
                o = params.enterprise[key]
                if not isinstance(o, list):
                    continue
                for elem in o:
                    if not isinstance(elem, dict):
                        continue
                    if 'encrypted_data' in elem:
                        decrypted_data = crypto.decrypt_aes_v1(utils.base64_url_decode(elem['encrypted_data']), tree_key)
                        elem['data'] = json.loads(decrypted_data.decode('utf-8'))

    @staticmethod
    def communicate_success(params, request):
        # type: (any, dict) -> dict
        if request['command'] == 'enterprise_allocate_ids':
            return enterprise_allocate_ids(params, request)

        rs = {
            'result': 'success',
            'result_code': '',
            'message': ''
        }
        if request['command'] == 'team_get_keys':
            rs['keys'] = [{
                'team_uid': x,
                'key': utils.base64_url_encode(crypto.encrypt_aes_v1(ent_env.team_key, vault_env.data_key)),
                'type': 1
            } for x in request['teams']]
            return rs
        if request['command'] == 'public_keys':
            rs['public_keys'] = [{
                'key_owner': x,
                'public_key': vault_env.encoded_public_key
            } for x in request['key_owners']]
            return rs

        cmd = TestEnterprise.expected_commands.pop(0)
        if cmd == request['command']:
            return rs
        if request['command'] == 'execute':
            request = request['requests'][0]
            if cmd == request['command']:
                return rs
        raise Exception()
