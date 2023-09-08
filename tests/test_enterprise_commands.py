import json
import logging
from typing import Optional
from unittest import TestCase, mock

import pytest

import keepercommander.commands.security_audit
from data_config import read_config_file
from keepercommander.params import KeeperParams
from keepercommander import cli, api
from keepercommander.commands import aram, enterprise


@pytest.mark.integration
class TestEnterpriseCommands(TestCase):
    params = None   # type: Optional[KeeperParams]

    @classmethod
    def setUpClass(cls):
        cls.params = KeeperParams()
        read_config_file(cls.params, 'enterprise.json')
        api.login(cls.params)
        TestEnterpriseCommands.wipe_out_data()

    @classmethod
    def tearDownClass(cls):
        params = cls.params
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
        if 'managed_nodes' in params.enterprise:
            for mn in params.enterprise['managed_nodes']:
                managed_roles.add(mn['role_id'])

        if 'role_users' in params.enterprise:
            for ru in params.enterprise['role_users']:
                if ru['role_id'] not in managed_roles:
                    request = {
                        'command': 'role_user_remove',
                        'role_id': ru['role_id'],
                        'enterprise_user_id': ru['enterprise_user_id']
                    }
                    api.communicate(params, request)

        if 'users' in params.enterprise:
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
        with mock.patch('builtins.open', mock.mock_open(read_data=template_body)), \
                mock.patch('os.path.abspath', return_value='template.json'), \
                mock.patch('os.path.isfile', return_value=True):

            with self.assertLogs(level=logging.WARNING):
                cli.do_command(params, f'create-user --generate --name="New User" --expire --records="template.json" '
                                       f'--question="This app name?" --answer="Commander" {new_user}')

    def test_report_commands(self):
        params = TestEnterpriseCommands.params
        self.assertIsNotNone(params.enterprise)

        user_report = enterprise.UserReportCommand()
        report_json = user_report.execute(params,  format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))

        device_approve = enterprise.DeviceApproveCommand()
        device_approve.execute(params, reload=True, format='json')

        enterprise_info = enterprise.EnterpriseInfoCommand()
        report_csv = enterprise_info.execute(params, nodes=True, columns=','.join(enterprise.SUPPORTED_NODE_COLUMNS), format='csv')
        self.assertTrue(len(report_csv) > 0)
        report_json = enterprise_info.execute(params, users=True, columns=','.join(enterprise.SUPPORTED_USER_COLUMNS), format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))
        report_json = enterprise_info.execute(params, teams=True, columns=','.join(enterprise.SUPPORTED_TEAM_COLUMNS), format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))
        report_csv = enterprise_info.execute(params, roles=True, columns=','.join(enterprise.SUPPORTED_ROLE_COLUMNS), format='csv')
        self.assertTrue(len(report_csv) > 0)

        audit_report = aram.AuditReportCommand()
        report_json = audit_report.execute(params, report_type='dim', columns=['audit_event_type'], format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))
        report_json = audit_report.execute(params, report_type='raw', created='last_30_days', format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))
        report_json = audit_report.execute(params, report_type='day', columns=['audit_event_type'], aggregate=['occurrences', 'first_created', 'last_created'],
                                           created='last_30_days', format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))

        security_audit_report = keepercommander.commands.security_audit.SecurityAuditReportCommand()
        report_json = security_audit_report.execute(params, format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))

        report_json = security_audit_report.execute(params, breachwatch=True, format='json')
        report = json.loads(report_json)
        self.assertTrue(isinstance(report, list))
