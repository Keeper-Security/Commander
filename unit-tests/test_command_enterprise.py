import logging
import json
from datetime import datetime, timedelta
from typing import Optional
from unittest import TestCase, mock

from data_enterprise import EnterpriseEnvironment, get_enterprise_data, enterprise_allocate_ids
from keepercommander import api, crypto, utils, vault
from keepercommander.params import KeeperParams
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

        def get_public_keys(_params, emails):
            for email in emails:
                emails[email] = vault_env.public_key

    @staticmethod
    def get_audit_event():
        return {
            'id': 123456789098,
            'created': int(datetime.now().timestamp()),
            'username': vault_env.user,
            'ip_address': '9.9.9.9',
            'audit_event_type': 'login',
            'keeper_version': 'c14.0.0.0'
        }

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
