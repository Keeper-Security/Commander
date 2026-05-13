import unittest

from keepercommander.commands.keeper_tenant_migrate.users import (
    CATEGORY_A,
    CATEGORY_B,
    CATEGORY_C,
    CATEGORY_D,
    CATEGORY_E,
    CATEGORY_UNKNOWN,
    FakeUserClient,
    UserCreationResult,
    UserRunner,
    detect_invite_conflict_category,
    remap_user_node,
)


class DetectInviteConflictCategoryTests(unittest.TestCase):
    def test_personal_conflict_markers(self):
        self.assertEqual(
            detect_invite_conflict_category('Email already registered in Personal Keeper'),
            CATEGORY_B,
        )

    def test_enterprise_conflict_markers(self):
        self.assertEqual(
            detect_invite_conflict_category('User is already in another tenant'),
            CATEGORY_C,
        )

    def test_no_match_returns_empty_string(self):
        self.assertEqual(detect_invite_conflict_category('some other error'), '')
        self.assertEqual(detect_invite_conflict_category(''), '')
        self.assertEqual(detect_invite_conflict_category(None), '')

    def test_case_insensitive(self):
        self.assertEqual(
            detect_invite_conflict_category('CONSUMER VAULT already exists'),
            CATEGORY_B,
        )


class RemapUserNodeTests(unittest.TestCase):
    def test_subtree_user_uses_leaf_name(self):
        self.assertEqual(
            remap_user_node('My company\\Dept\\Team', 'My company', 'Keeperdemo',
                            default_node='Keeperdemo'),
            'Team',
        )

    def test_root_user_falls_back_to_default(self):
        self.assertEqual(
            remap_user_node('My company', 'My company', 'Keeperdemo',
                            default_node='Keeperdemo'),
            'Keeperdemo',
        )

    def test_empty_src_returns_default(self):
        self.assertEqual(
            remap_user_node('', 'My company', 'Root', default_node='DefaultNode'),
            'DefaultNode',
        )


class UserRunnerCategoryTests(unittest.TestCase):
    def _runner(self, client, **kwargs):
        return UserRunner(client, source_root='My company',
                          target_root='Keeperdemo',
                          default_node='MIGRATION-TEST-NODE', **kwargs)

    def test_category_a_invites_new_user(self):
        client = FakeUserClient()
        runner = self._runner(client)
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}], inventory={
            'entities': {'users': [
                {'email': 'a@x', 'node': 'My company\\Sub', 'job_title': 'Eng',
                 'teams': [], 'roles': [], 'aliases': []},
            ]},
        })
        self.assertEqual(results[0].status, 'YES')
        self.assertEqual(results[0].category, CATEGORY_A)
        invite_calls = [c for c in client.calls if c[0] == 'invite_user']
        self.assertEqual(invite_calls[0][1], ('a@x', 'A', 'Sub', 'Eng'))

    def test_category_d_from_plan_skips_invite(self):
        client = FakeUserClient()
        runner = self._runner(client)
        results = runner.run(
            [{'email': 'a@x', 'full_name': 'A'}],
            transition_plan=[{'source_email': 'a@x', 'category': CATEGORY_D}],
        )
        self.assertEqual(results[0].status, 'EXISTS')
        # No invite was called
        self.assertFalse(any(c[0] == 'invite_user' for c in client.calls))

    def test_category_e_extends_invite(self):
        client = FakeUserClient()
        runner = self._runner(client)
        results = runner.run(
            [{'email': 'e@x', 'full_name': 'E'}],
            transition_plan=[{'source_email': 'e@x', 'category': CATEGORY_E}],
        )
        self.assertEqual(results[0].status, 'EXTENDED')
        self.assertTrue(any(c[0] == 'extend_user_invite' for c in client.calls))

    def test_category_e_extend_failure_marks_failed(self):
        client = FakeUserClient(fail_on={'extend_user_invite'})
        runner = self._runner(client)
        results = runner.run(
            [{'email': 'e@x', 'full_name': 'E'}],
            transition_plan=[{'source_email': 'e@x', 'category': CATEGORY_E}],
        )
        self.assertEqual(results[0].status, 'FAILED')

    def test_category_unknown_is_blocked(self):
        client = FakeUserClient()
        runner = self._runner(client)
        results = runner.run(
            [{'email': 'u@x', 'full_name': 'U'}],
            transition_plan=[{'source_email': 'u@x', 'category': CATEGORY_UNKNOWN}],
        )
        self.assertEqual(results[0].status, 'BLOCKED')
        # No invite/extend attempted
        op_names = [c[0] for c in client.calls]
        self.assertNotIn('invite_user', op_names)
        self.assertNotIn('extend_user_invite', op_names)

    def test_existing_user_is_skipped_without_invite(self):
        client = FakeUserClient(existing_users=['a@x'])
        runner = self._runner(client)
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}])
        self.assertEqual(results[0].status, 'EXISTS')
        self.assertFalse(any(c[0] == 'invite_user' for c in client.calls))


class UserRunnerInviteConflictTests(unittest.TestCase):
    def _runner(self, invite_behavior):
        client = FakeUserClient(invite_behavior=invite_behavior)
        return client, UserRunner(client, source_root='My company',
                                  target_root='Keeperdemo',
                                  default_node='N')

    def test_personal_conflict_reclassifies_to_b(self):
        client, runner = self._runner(
            lambda email: (False, 'This email is already registered in a personal vault'),
        )
        results = runner.run([{'email': 'b@x', 'full_name': 'B'}])
        self.assertEqual(results[0].status, 'CONFLICT_B')
        self.assertEqual(results[0].category, CATEGORY_B)

    def test_enterprise_conflict_reclassifies_to_c(self):
        client, runner = self._runner(
            lambda email: (False, 'User exists in another tenant'),
        )
        results = runner.run([{'email': 'c@x', 'full_name': 'C'}])
        self.assertEqual(results[0].category, CATEGORY_C)


class UserRunnerPlacementTests(unittest.TestCase):
    def _runner(self, **kwargs):
        client = FakeUserClient(**kwargs)
        return client, UserRunner(client, source_root='My company',
                                  target_root='Keeperdemo',
                                  default_node='N')

    def test_placement_applies_teams_with_hsf_flag_for_matching_teams(self):
        client, runner = self._runner()
        inventory = {'entities': {'users': [{
            'email': 'a@x', 'node': 'My company\\Sub', 'job_title': '',
            'teams': ['Visible-Team', 'Hidden-Team'],
            'hide_shared_folders_teams': ['Hidden-Team'],
            'roles': ['R1'],
            'aliases': ['alt@x'],
        }]}}
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}], inventory=inventory)
        self.assertEqual(results[0].status, 'YES')
        team_calls = [c for c in client.calls if c[0] == 'add_user_team']
        # First team: hsf=False; Second team: hsf=True
        self.assertEqual(team_calls[0][1], ('a@x', 'Visible-Team', False))
        self.assertEqual(team_calls[1][1], ('a@x', 'Hidden-Team', True))
        self.assertIn('alt@x', results[0].assignments['aliases'])
        self.assertIn('R1', results[0].assignments['roles'])

    def test_placement_gates_team_add_when_team_missing_on_target(self):
        """Mirror of the StructureRestore created_teams gate. When the
        target tenant doesn't have the source team (structure stage
        missed it / was skipped), add_user_team should be suppressed
        and the team recorded under teams_skipped rather than firing
        the call (which Commander would fail anyway)."""
        client, runner = self._runner(existing_teams=['Present-Team'])
        inventory = {'entities': {'users': [{
            'email': 'a@x', 'node': '', 'job_title': '',
            'teams': ['Present-Team', 'Missing-Team'],
            'roles': [], 'aliases': [],
        }]}}
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}],
                              inventory=inventory)
        team_calls = [c for c in client.calls if c[0] == 'add_user_team']
        # Only Present-Team made it through to the client.
        self.assertEqual(len(team_calls), 1)
        self.assertEqual(team_calls[0][1][1], 'Present-Team')
        # Missing-Team recorded as skipped on the result.
        skipped = results[0].assignments.get('teams_skipped') or []
        self.assertEqual(skipped, ['Missing-Team'])

    def test_placement_gates_role_add_when_role_missing_on_target(self):
        client, runner = self._runner(existing_roles=['Present-Role'])
        inventory = {'entities': {'users': [{
            'email': 'a@x', 'node': '', 'job_title': '',
            'teams': [],
            'roles': ['Present-Role', 'Missing-Role'],
            'aliases': [],
        }]}}
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}],
                              inventory=inventory)
        role_calls = [c for c in client.calls if c[0] == 'add_user_role']
        self.assertEqual(len(role_calls), 1)
        self.assertEqual(role_calls[0][1][1], 'Present-Role')
        skipped = results[0].assignments.get('roles_skipped') or []
        self.assertEqual(skipped, ['Missing-Role'])

    def test_placement_gate_off_when_client_returns_empty_listings(self):
        """Backwards compat: legacy FakeUserClient (no existing_teams /
        existing_roles configured) returns empty sets — the gate stays
        OFF and every team/role add proceeds as before."""
        client, runner = self._runner()  # default: no listings
        inventory = {'entities': {'users': [{
            'email': 'a@x', 'node': '', 'job_title': '',
            'teams': ['T1', 'T2'], 'roles': ['R1'], 'aliases': [],
        }]}}
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}],
                              inventory=inventory)
        team_calls = [c for c in client.calls if c[0] == 'add_user_team']
        role_calls = [c for c in client.calls if c[0] == 'add_user_role']
        self.assertEqual(len(team_calls), 2)
        self.assertEqual(len(role_calls), 1)
        # No skipped entries when gate is off.
        self.assertNotIn('teams_skipped', results[0].assignments)
        self.assertNotIn('roles_skipped', results[0].assignments)

    def test_existing_user_gets_job_title_set_explicitly(self):
        client, runner = self._runner(existing_users=['a@x'])
        inventory = {'entities': {'users': [{
            'email': 'a@x', 'node': '', 'job_title': 'Manager',
            'teams': [], 'roles': [], 'aliases': [],
        }]}}
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}], inventory=inventory)
        job_calls = [c for c in client.calls if c[0] == 'set_user_job_title']
        self.assertEqual(job_calls[0][1], ('a@x', 'Manager'))
        self.assertTrue(results[0].assignments['job_title'])

    def test_blocked_user_skips_all_placement(self):
        client, runner = self._runner()
        inventory = {'entities': {'users': [{
            'email': 'u@x', 'node': '', 'teams': ['T'], 'roles': ['R'], 'aliases': ['alt@x'],
        }]}}
        runner.run(
            [{'email': 'u@x', 'full_name': 'U'}],
            inventory=inventory,
            transition_plan=[{'source_email': 'u@x', 'category': CATEGORY_UNKNOWN}],
        )
        # No team/role/alias calls recorded
        for op in ('add_user_team', 'add_user_role', 'add_user_alias'):
            self.assertFalse(any(c[0] == op for c in client.calls),
                             f'unexpected {op} call for blocked user')


class QueuedTeamApprovalTests(unittest.TestCase):
    def test_invited_user_triggers_queue_approvals(self):
        client = FakeUserClient()
        runner = UserRunner(client, source_root='S', target_root='T',
                             default_node='N')
        inventory = {'entities': {
            'users': [{'email': 'a@x', 'teams': [], 'roles': [],
                        'aliases': []}],
            'teams': [
                {'name': 'QTeam1', 'queued_users': ['a@x']},
                {'name': 'QTeam2', 'queued_users': [{'username': 'a@x'}]},
                {'name': 'OtherTeam', 'queued_users': ['other@x']},
            ],
        }}
        results = runner.run([{'email': 'a@x', 'full_name': 'A'}],
                              inventory=inventory)
        approves = [c for c in client.calls
                     if c[0] == 'approve_team_queue_user']
        self.assertEqual(len(approves), 2)
        approved_names = [c[1][1] for c in approves]
        self.assertIn('QTeam1', approved_names)
        self.assertIn('QTeam2', approved_names)
        self.assertIn('QTeam1', results[0].assignments['team_queue_approved'])

    def test_blocked_user_no_approvals(self):
        client = FakeUserClient()
        runner = UserRunner(client, default_node='N')
        inventory = {'entities': {
            'users': [{'email': 'u@x'}],
            'teams': [{'name': 'Q', 'queued_users': ['u@x']}],
        }}
        runner.run([{'email': 'u@x', 'full_name': 'U'}],
                    inventory=inventory,
                    transition_plan=[{'source_email': 'u@x',
                                       'category': CATEGORY_UNKNOWN}])
        self.assertFalse(any(c[0] == 'approve_team_queue_user'
                              for c in client.calls))

    def test_queued_captured_by_live_inventory(self):
        from keepercommander.commands.keeper_tenant_migrate.live_inventory import build_team_entities
        ent = {'teams': [
            {'name': 'T', 'node_id': 1,
             'queued_users': [{'username': 'a@x'}, 'b@x', '', None]},
        ]}
        teams = build_team_entities(ent, descendants=None,
                                     path_map={1: 'root'}, prefix='')
        self.assertEqual(teams[0]['queued_users'], ['a@x', 'b@x'])


if __name__ == '__main__':
    unittest.main()
