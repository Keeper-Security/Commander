import unittest
from unittest import mock

from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.params import KeeperParams


class TestEnterpriseRoleTeamValidation(unittest.TestCase):
    def test_change_team_roles_skips_api_for_admin_role(self):
        params = KeeperParams()
        admin_role_id = 894448414228484
        params.enterprise = {
            'roles': [{'role_id': admin_role_id, 'data': {'displayname': 'Admin Role'}}],
            'managed_nodes': [{'role_id': admin_role_id}],
            'role_teams': [],
        }
        teams = [{'team_uid': '4GjeorSt3FiI2KBhgCKI2Q', 'name': 'Test Team'}]

        with mock.patch('keepercommander.api.communicate_rest') as communicate_rest:
            msgs = EnterpriseCommand.change_team_roles(
                params, teams, add_roles=[str(admin_role_id)], remove_roles=None)

        self.assertEqual(msgs, [])
        communicate_rest.assert_not_called()

    def test_change_role_teams_skips_api_for_admin_role(self):
        params = KeeperParams()
        admin_role_id = 894448414228484
        params.enterprise = {
            'teams': [{'team_uid': '4GjeorSt3FiI2KBhgCKI2Q', 'name': 'Test Team'}],
            'managed_nodes': [{'role_id': admin_role_id}],
        }
        roles = [{'role_id': admin_role_id, 'data': {'displayname': 'Admin Role'}}]

        with mock.patch('keepercommander.api.communicate_rest') as communicate_rest:
            msgs = EnterpriseCommand.change_role_teams(
                params, roles, add_team=['4GjeorSt3FiI2KBhgCKI2Q'], remove_team=None)

        self.assertEqual(msgs, [])
        communicate_rest.assert_not_called()
