import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.reconcile import (
    Reconciler,
    build_target_index,
    compare_by_key,
    compute_deltas,
    render_report,
    verify_inventory_checksum,
)


def _sample_inventory():
    return {
        'captured_at': '2026-04-18T12:00:00Z',
        'source_user': 'admin@src',
        'source_root': 'My company',
        'target_user': 'admin@tgt',
        'target_root': 'Keeperdemo',
        'counts': {'nodes': 2, 'teams': 2, 'roles': 1,
                   'users': 1, 'shared_folders': 1,
                   'records': 1, 'attachments': 0, 'direct_shares': 0},
        'entities': {
            'nodes': [{'name': 'MIGRATION-TEST-NODE'}, {'name': 'Isolated-Sub'}],
            'teams': [{'name': 'Team-A'}, {'name': 'Team-B'}],
            'roles': [{'name': 'MIGTEST-Admin',
                       'managed_nodes': [{'privileges': ['MANAGE_USER']}],
                       'enforcements': {'two_factor_required': True},
                       'users': [], 'teams': []}],
            'users': [{'email': 'alice@x'}],
            'shared_folders': [{'name': 'SF-1'}],
            'records': [{'has_totp': False}],
        },
    }


class CompareByKeyTests(unittest.TestCase):
    def test_splits_found_and_missing(self):
        items = [{'name': 'A'}, {'name': 'B'}, {'name': 'C'}]
        found, missing = compare_by_key(items, {'A', 'C'})
        self.assertEqual(found, ['A', 'C'])
        self.assertEqual(missing, ['B'])


class BuildTargetIndexTests(unittest.TestCase):
    def test_returns_sets_per_entity_type(self):
        target = {
            'nodes': [{'name': 'N1'}, {'name': 'N2'}],
            'users': [{'email': 'alice@x'}, {'email': 'BOB@X'}],
            'shared_folders': [{'name': 'SF'}],
        }
        idx = build_target_index(target)
        self.assertEqual(idx['nodes'], {'N1', 'N2'})
        self.assertEqual(idx['users'], {'alice@x', 'bob@x'})  # lowercased
        self.assertEqual(idx['shared_folders'], {'SF'})
        # Missing entity types yield empty sets
        self.assertEqual(idx['teams'], set())
        self.assertEqual(idx['roles'], set())


class ComputeDeltasTests(unittest.TestCase):
    def test_delta_is_zero_when_everything_matches(self):
        inv = _sample_inventory()
        target = {
            'nodes': inv['entities']['nodes'],
            'teams': inv['entities']['teams'],
            'roles': inv['entities']['roles'],
            'users': inv['entities']['users'],
            'shared_folders': inv['entities']['shared_folders'],
        }
        d = compute_deltas(inv, target)
        self.assertEqual(d['total_missing'], 0)
        self.assertEqual(d['success_pct'], 100.0)

    def test_missing_items_counted(self):
        inv = _sample_inventory()
        target = {'nodes': [{'name': 'MIGRATION-TEST-NODE'}],  # one missing
                  'teams': inv['entities']['teams'],
                  'roles': [], 'users': [], 'shared_folders': []}
        d = compute_deltas(inv, target)
        self.assertEqual(len(d['deltas']['nodes']['missing']), 1)
        self.assertIn('Isolated-Sub', d['deltas']['nodes']['missing'])
        self.assertEqual(d['total_missing'], 4)  # 1 node + 1 role + 1 user + 1 sf


class RenderReportTests(unittest.TestCase):
    def test_all_matched_report_shows_green_status(self):
        inv = _sample_inventory()
        target = {
            'nodes': inv['entities']['nodes'],
            'teams': inv['entities']['teams'],
            'roles': inv['entities']['roles'],
            'users': inv['entities']['users'],
            'shared_folders': inv['entities']['shared_folders'],
        }
        report = render_report(inv, target, inventory_path='/tmp/inv.json')
        self.assertIn('Executive Summary', report)
        self.assertIn('All entities from source inventory', report)
        self.assertIn('Role Detail', report)
        self.assertIn('MIGTEST-Admin', report)

    def test_missing_items_produce_action_sections(self):
        inv = _sample_inventory()
        target = {'nodes': [], 'teams': [], 'roles': [], 'users': [], 'shared_folders': []}
        report = render_report(inv, target)
        self.assertIn('Missing Nodes', report)
        self.assertIn('Missing Users', report)
        self.assertIn('tenant-migrate structure', report)

    def test_target_identity_falls_back_to_target_state(self):
        """Regression guard: inventory is produced against source only, so
        target_user/target_root in it are empty. Report should then fall
        back to target_state's captured_user + root-node name instead of
        rendering a blank '**Target**:  ()' line."""
        inv = _sample_inventory()
        # Force the legacy empty target_user/target_root keys.
        inv['target_user'] = ''
        inv['target_root'] = ''
        target = {
            'nodes': [{'name': 'Keeperdemo', 'isolated': False}],
            'teams': [], 'roles': [], 'users': [], 'shared_folders': [],
            'captured_user': 'jlima+msp@keeperdemo.io',
        }
        report = render_report(inv, target)
        self.assertIn('jlima+msp@keeperdemo.io', report)
        self.assertIn('(Keeperdemo)', report)
        self.assertNotIn('**Target**:  ()', report)

    def test_target_user_from_inventory_wins_over_target_state(self):
        """When inventory carries a target_user (pre-populated by an
        auto-migrate wrapper), that wins over target_state's captured_user
        — inventory is the run-spec record."""
        inv = _sample_inventory()
        inv['target_user'] = 'runspec@target.io'
        inv['target_root'] = 'RunspecRoot'
        target = {
            'nodes': [{'name': 'DifferentRoot'}],
            'teams': [], 'roles': [], 'users': [], 'shared_folders': [],
            'captured_user': 'captured@target.io',
        }
        report = render_report(inv, target)
        self.assertIn('runspec@target.io', report)
        self.assertIn('(RunspecRoot)', report)
        self.assertNotIn('captured@target.io', report)


class VerifyInventoryChecksumTests(unittest.TestCase):
    def test_matching_sidecar_returns_true(self):
        with tempfile.NamedTemporaryFile('wb', suffix='.json', delete=False) as t:
            t.write(b'{"captured_at":"x"}')
            path = t.name
        try:
            import hashlib
            checksum = hashlib.sha256(open(path, 'rb').read()).hexdigest()
            with open(path + '.sha256', 'w') as f:
                f.write(checksum + '\n')
            ok, actual, expected = verify_inventory_checksum(path)
            self.assertTrue(ok)
            self.assertEqual(actual, expected)
        finally:
            os.unlink(path)
            os.unlink(path + '.sha256')

    def test_missing_sidecar_returns_true(self):
        with tempfile.NamedTemporaryFile('wb', suffix='.json', delete=False) as t:
            t.write(b'{}')
            path = t.name
        try:
            ok, _, expected = verify_inventory_checksum(path)
            self.assertTrue(ok)
            self.assertEqual(expected, '')
        finally:
            os.unlink(path)

    def test_tampered_file_fails(self):
        with tempfile.NamedTemporaryFile('wb', suffix='.json', delete=False) as t:
            t.write(b'{}')
            path = t.name
        try:
            with open(path + '.sha256', 'w') as f:
                f.write('0' * 64 + '\n')
            ok, actual, expected = verify_inventory_checksum(path)
            self.assertFalse(ok)
            self.assertNotEqual(actual, expected)
        finally:
            os.unlink(path)
            os.unlink(path + '.sha256')


class ReconcilerIntegrationTests(unittest.TestCase):
    def test_run_writes_report_and_summary(self):
        inv = _sample_inventory()
        tmp = tempfile.mkdtemp()
        try:
            inv_path = os.path.join(tmp, 'inv.json')
            with open(inv_path, 'w') as f:
                json.dump(inv, f)
            target = {
                'nodes': [{'name': 'MIGRATION-TEST-NODE'}],
                'teams': inv['entities']['teams'],
                'roles': inv['entities']['roles'],
                'users': [], 'shared_folders': [],
            }
            r = Reconciler(inv_path, target_state_provider=lambda: target)
            result = r.run(os.path.join(tmp, 'recon.md'))
            self.assertTrue(os.path.exists(result['report_path']))
            self.assertEqual(len(result['summary']['deltas']['users']['missing']), 1)
        finally:
            import shutil
            shutil.rmtree(tmp)


if __name__ == '__main__':
    unittest.main()
