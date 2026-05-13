import unittest

from keepercommander.commands.keeper_tenant_migrate.manual_actions import (
    ADMIN,
    DURING_OWNERSHIP,
    DURING_SHARES,
    DURING_USERS,
    POST_MIGRATION,
    PREREQUISITE,
    SOURCE_USER,
    TARGET_USER,
    enumerate_actions,
    render_actions_markdown,
)


def _inv(users=None, records=None, sfs=None):
    return {
        'entities': {
            'users': users or [],
            'records': records or [],
            'shared_folders': sfs or [],
            'nodes': [], 'teams': [], 'roles': [],
        },
    }


class EnumerateActionsTests(unittest.TestCase):
    def test_every_source_user_gets_path_a_b_prerequisite(self):
        inv = _inv(users=[{'email': 'a@x'}, {'email': 'b@x'}])
        actions = enumerate_actions(inv)
        prereq = [a for a in actions if a['phase'] == PREREQUISITE]
        self.assertEqual(len(prereq), 2)
        self.assertEqual({a['email'] for a in prereq}, {'a@x', 'b@x'})
        self.assertTrue(all(a['actor'] == SOURCE_USER for a in prereq))

    def test_category_d_skips_during_users_action(self):
        """User already in target (category D) doesn't need to accept invite."""
        inv = _inv(users=[{'email': 'a@x'}])
        plan = [{'source_email': 'a@x', 'category': 'D'}]
        actions = enumerate_actions(inv, transition_plan=plan)
        during_users = [a for a in actions
                        if a['phase'] == DURING_USERS and a['email'] == 'a@x']
        self.assertEqual(during_users, [])

    def test_category_unknown_becomes_admin_action(self):
        inv = _inv(users=[{'email': 'locked@x'}])
        plan = [{'source_email': 'locked@x', 'category': 'UNKNOWN'}]
        actions = enumerate_actions(inv, transition_plan=plan)
        during_users = [a for a in actions
                        if a['phase'] == DURING_USERS and a['email'] == 'locked@x']
        self.assertEqual(len(during_users), 1)
        self.assertEqual(during_users[0]['actor'], ADMIN)
        self.assertIn('unlock', during_users[0]['note'].lower())

    def test_direct_share_grantee_not_on_target_flagged(self):
        inv = _inv(
            users=[{'email': 'owner@x'}],
            records=[{'title': 'Rec1',
                      'direct_shares': [{'username': 'grantee@x'}]}],
        )
        target = {'users': [{'email': 'owner@x'}]}  # grantee missing
        actions = enumerate_actions(inv, target_state=target)
        shares = [a for a in actions
                  if a['phase'] == DURING_SHARES and a['email'] == 'grantee@x']
        self.assertEqual(len(shares), 1)
        self.assertIn('records-shares', shares[0]['blocks'])

    def test_direct_share_grantee_already_on_target_is_silent(self):
        inv = _inv(
            users=[{'email': 'owner@x'}],
            records=[{'title': 'Rec1',
                      'direct_shares': [{'username': 'grantee@x'}]}],
        )
        target = {'users': [{'email': 'owner@x'}, {'email': 'grantee@x'}]}
        actions = enumerate_actions(inv, target_state=target)
        shares = [a for a in actions
                  if a['phase'] == DURING_SHARES and a['email'] == 'grantee@x']
        self.assertEqual(shares, [])

    def test_sf_member_not_on_target_flagged(self):
        inv = _inv(
            users=[{'email': 'owner@x'}],
            sfs=[{'name': 'SF1', 'users': [{'username': 'xmember@x'}]}],
        )
        target = {'users': []}
        actions = enumerate_actions(inv, target_state=target)
        own = [a for a in actions
               if a['phase'] == DURING_OWNERSHIP and a['email'] == 'xmember@x']
        self.assertEqual(len(own), 1)
        self.assertIn('apply-membership', own[0]['note'])

    def test_post_migration_has_admin_decommission_note(self):
        inv = _inv(users=[{'email': 'a@x'}])
        actions = enumerate_actions(inv)
        admin_post = [a for a in actions
                      if a['phase'] == POST_MIGRATION and a['actor'] == ADMIN]
        self.assertEqual(len(admin_post), 1)
        self.assertIn('decommission', admin_post[0]['note'].lower())

    def test_empty_inventory_still_produces_decommission_reminder(self):
        actions = enumerate_actions(_inv())
        post = [a for a in actions if a['phase'] == POST_MIGRATION]
        self.assertEqual(len(post), 1)   # admin decommission reminder

    def test_category_b_makes_user_responsible(self):
        inv = _inv(users=[{'email': 'b@x'}])
        plan = [{'source_email': 'b@x', 'category': 'B'}]
        actions = enumerate_actions(inv, transition_plan=plan)
        during = [a for a in actions
                  if a['phase'] == DURING_USERS and a['email'] == 'b@x']
        self.assertEqual(len(during), 1)
        self.assertEqual(during[0]['actor'], SOURCE_USER)
        self.assertIn('personal', during[0]['note'].lower())


class RenderActionsMarkdownTests(unittest.TestCase):
    def test_empty_list_explicit_message(self):
        md = render_actions_markdown([])
        self.assertIn('None', md)

    def test_populated_list_renders_checkboxes_by_phase(self):
        inv = _inv(users=[{'email': 'alice@x'}])
        md = render_actions_markdown(enumerate_actions(inv))
        self.assertIn('# Customer manual actions', md)
        self.assertIn('prerequisite', md.lower())
        self.assertIn('- [ ]', md)


if __name__ == '__main__':
    unittest.main()
