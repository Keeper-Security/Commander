import unittest

from keepercommander.commands.keeper_tenant_migrate.dry_run import (
    CONFLICT, CREATE, DELETE, SKIP, UNCHECKED,
    DryRun,
    classify_plan,
    render_report,
    summarize,
)
from keepercommander.commands.keeper_tenant_migrate.structure import FakeClient


class DryRunWrapperTests(unittest.TestCase):
    def test_mutating_calls_dont_reach_real_client(self):
        real = FakeClient()
        dry = DryRun(real)
        dry.create_node('N', 'P')
        dry.create_team('T', 'N', 'off', 'off', 'off')
        # Real client must not have seen anything
        self.assertEqual(real.calls, [])
        # Dry-run stored both
        self.assertEqual([c[0] for c in dry.calls],
                         ['create_node', 'create_team'])

    def test_passthrough_for_read_methods(self):
        class ReadyClient(FakeClient):
            def count_nodes(self, scope_node=''):
                return 5
            def count_teams(self, scope_node=''):
                return 3
            def count_roles(self, scope_node=''):
                return 0
            def count_users(self, scope_node=''):
                return 0
            def list_entities(self):
                return {'nodes': [{'name': 'X'}], 'teams': [], 'roles': []}
        dry = DryRun(ReadyClient())
        self.assertEqual(dry.count_nodes(), 5)
        self.assertEqual(dry.list_entities()['nodes'][0]['name'], 'X')

    def test_method_returns_shape_matches_real_protocol(self):
        dry = DryRun(FakeClient())
        # invite_user expected shape = (bool, str)
        ok, out = dry.invite_user('a@x', 'A', 'N', 'Eng')
        self.assertTrue(ok)
        self.assertIn('dry', out)
        # share_record expected shape = status string
        self.assertEqual(dry.share_record('uid', 'a@x', True, True), 'OK')
        # download_attachments expected shape = list
        self.assertEqual(dry.download_attachments('u', '/tmp/x'), [])

    def test_default_boolean_success_for_other_ops(self):
        dry = DryRun(FakeClient())
        self.assertTrue(dry.create_role('R', 'N', 'off'))
        self.assertTrue(dry.toggle_node_isolated('N'))
        self.assertTrue(dry.delete_team('T'))


class ClassifyPlanTests(unittest.TestCase):
    def _drove(self, ops):
        dry = DryRun(FakeClient())
        for op in ops:
            getattr(dry, op[0])(*op[1:])
        return dry

    def test_create_node_missing_on_target(self):
        dry = self._drove([('create_node', 'NewNode', 'Root')])
        out = classify_plan(dry, {'nodes': []})
        self.assertEqual(out[0]['classification'], CREATE)

    def test_create_node_already_present_is_skip(self):
        dry = self._drove([('create_node', 'Existing', 'Root')])
        out = classify_plan(dry, {'nodes': [{'name': 'Existing'}]})
        self.assertEqual(out[0]['classification'], SKIP)

    def test_create_team_same_name_wrong_node_is_conflict(self):
        dry = self._drove([('create_team', 'T', 'NodeA', 'off', 'off', 'off')])
        tgt = {'teams': [{'name': 'T', 'parent': 'NodeB', 'restricts': ''}]}
        out = classify_plan(dry, tgt)
        self.assertEqual(out[0]['classification'], CONFLICT)
        self.assertIn('different node', out[0]['detail'])

    def test_create_team_restricts_mismatch_is_conflict(self):
        dry = self._drove([('create_team', 'T', 'N', 'on', 'on', 'off')])
        tgt = {'teams': [{'name': 'T', 'parent': 'N', 'restricts': 'W'}]}
        out = classify_plan(dry, tgt)
        self.assertEqual(out[0]['classification'], CONFLICT)
        self.assertIn('restricts', out[0]['detail'])

    def test_create_team_matching_is_skip(self):
        dry = self._drove([('create_team', 'T', 'N', 'off', 'off', 'off')])
        tgt = {'teams': [{'name': 'T', 'parent': 'N', 'restricts': ''}]}
        out = classify_plan(dry, tgt)
        self.assertEqual(out[0]['classification'], SKIP)

    def test_delete_ops_classified(self):
        dry = DryRun(FakeClient())
        dry.delete_team('MIGTEST-T')
        dry.delete_role('MIGTEST-R')
        dry.delete_node('MIGTEST-N')
        out = classify_plan(dry, {})
        self.assertEqual({c['classification'] for c in out}, {DELETE})

    def test_unknown_op_is_unchecked(self):
        class WeirdClient(FakeClient):
            def weird_op(self, x):
                return True
        dry = DryRun(WeirdClient())
        dry.weird_op('x')
        out = classify_plan(dry, {})
        self.assertEqual(out[0]['classification'], UNCHECKED)


class SummarizeAndRenderTests(unittest.TestCase):
    def test_summarize_counts_by_category(self):
        classified = [
            {'classification': CREATE, 'op': 'x', 'detail': ''},
            {'classification': CREATE, 'op': 'y', 'detail': ''},
            {'classification': SKIP, 'op': 'z', 'detail': ''},
        ]
        counts = summarize(classified)
        self.assertEqual(counts[CREATE], 2)
        self.assertEqual(counts[SKIP], 1)

    def test_render_report_emits_all_categories(self):
        classified = [
            {'classification': CREATE, 'op': 'create_node', 'detail': 'node foo'},
            {'classification': CONFLICT, 'op': 'create_team', 'detail': 'team bar'},
        ]
        md = render_report(classified)
        self.assertIn('# Dry-run plan', md)
        self.assertIn('CREATE', md)
        self.assertIn('CONFLICT', md)
        self.assertIn('node foo', md)
        self.assertIn('team bar', md)


if __name__ == '__main__':
    unittest.main()
