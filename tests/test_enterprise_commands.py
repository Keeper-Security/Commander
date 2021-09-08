import logging
from unittest import TestCase, mock

import pytest

from data_config import read_config_file
from keepercommander.params import KeeperParams
from keepercommander import cli, api


@pytest.mark.integration
class TestEnterpriseCommands(TestCase):
    params = None

    @classmethod
    def setUpClass(cls):
        cls.params = KeeperParams()
        read_config_file(cls.params, 'enterprise.json')
        api.login(cls.params)
        TestEnterpriseCommands.wipe_out_data()

    @classmethod
    def tearDownClass(cls):
        params = cls.params     # type: KeeperParams
        api.query_enterprise(params)
        for user in params.enterprise['users']:
            if user['status'] == 'actove' and user['lock'] != 0:
                request = {
                    'command': 'enterprise_user_lock',
                    'enterprise_user_id': user['enterprise_user_id'],
                    'lock': 'unlocked'
                }
                api.communicate(params, request)

        cli.do_command(params, 'logout')

    @classmethod
    def wipe_out_data(cls):
        params = cls.params    # type: KeeperParams
        managed_roles = set()
        for mn in params.enterprise['managed_nodes']:
            managed_roles.add(mn['role_id'])

        for ru in params.enterprise['role_users']:
            if ru['role_id'] not in managed_roles:
                request = {
                    'command': 'role_user_remove',
                    'role_id': ru['role_id'],
                    'enterprise_user_id': ru['enterprise_user_id']
                }
                api.communicate(params, request)

        for user in params.enterprise['users']:
            if user['status'] == 'invited':
                request = {
                    'command': 'enterprise_user_delete',
                    'enterprise_user_id': user['enterprise_user_id']
                }
                api.communicate(params, request)

        if 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                request = {
                    'command': 'team_delete',
                    'team_uid': team['team_uid']
                }
                api.communicate(params, request)
        api.query_enterprise(params)

    def test_commands(self):
        params = TestEnterpriseCommands.params    # type: KeeperParams
        self.assertIsNotNone(params.enterprise)
        test_user = params.config['user']
        new_user = 'integration.user@keepersecurity.com'
        new_team = 'Test Team'
        with mock.patch('builtins.input', side_effect=KeyboardInterrupt()), mock.patch('builtins.print'):
            cli.do_command(params, 'enterprise-info --verbose')

            cli.do_command(params, 'enterprise-team --add "{0}"'.format(new_team))
            cli.do_command(params, 'enterprise-team --restrict-edit=on --restrict-share=on --restrict-view=off "{0}"'.format(new_team))

            cli.do_command(params, 'enterprise-user --add --name="Test User" {0}'.format(new_user))
            cli.do_command(params, 'enterprise-user --lock "{0}"'.format(test_user))
            cli.do_command(params, 'enterprise-user --unlock "{0}"'.format(test_user))

            cli.do_command(params, 'enterprise-team --add-user="{0}" "{1}"'.format(test_user, new_team))
            cli.do_command(params, 'enterprise-team --remove-user="{0}" "{1}"'.format(test_user, new_team))
            cli.do_command(params, 'enterprise-user --add-team="{0}" "{1}"'.format(new_team, test_user))
            cli.do_command(params, 'enterprise-user --remove-team="{0}" "{1}"'.format(new_team, test_user))

            role_id = None
            managed_roles = set()
            for mn in params.enterprise['managed_nodes']:
                managed_roles.add(mn['role_id'])

            for role in params.enterprise['roles']:
                if role['role_id'] not in managed_roles:
                    role_id = role['role_id']
                    break
            if role_id:
                cli.do_command(params, 'enterprise-role --add-user="{0}" "{1}"'.format(new_user, role_id))

    def test_add_enterprise_user(self):
        params = TestEnterpriseCommands.params    # type: KeeperParams
        self.assertIsNotNone(params.enterprise)

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
            "key2": "value2"
        }
    },
    {
        "title": "Empty record"
    }

]'''

        new_user = 'integration.new.user@keepersecurity.com'
        with mock.patch('builtins.open', mock.mock_open(read_data=template_body)), mock.patch('os.path.abspath', return_value='template.json'), mock.patch('os.path.isfile', return_value=True):

            with self.assertLogs(level=logging.WARNING):
                cli.do_command(params, 'create-user --generate --name="New User" --expire --records="template.json" --question="This app name?" --answer="Commander" {0}'.format(new_user))
