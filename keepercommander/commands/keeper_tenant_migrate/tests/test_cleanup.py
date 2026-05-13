import unittest

from keepercommander.commands.keeper_tenant_migrate.cleanup import (
    FakeCleanupClient,
    cleanup,
    matching_entities,
)


class MatchingEntitiesTests(unittest.TestCase):
    def test_filters_by_prefix(self):
        entities = {
            'teams': [{'name': 'MIGTEST-T1'}, {'name': 'OtherTeam'}],
            'roles': [{'name': 'MIGTEST-R1'}],
            'nodes': [{'name': 'MIGTEST-Root'}],
        }
        out = matching_entities(entities, 'MIGTEST-')
        self.assertEqual([t['name'] for t in out['teams']], ['MIGTEST-T1'])
        self.assertEqual([r['name'] for r in out['roles']], ['MIGTEST-R1'])

    def test_empty_prefix_rejected(self):
        with self.assertRaises(ValueError):
            matching_entities({}, '')


class CleanupTests(unittest.TestCase):
    def test_deletes_in_team_role_node_order(self):
        entities = {
            'teams': [{'name': 'MIGTEST-T'}],
            'roles': [{'name': 'MIGTEST-R'}],
            'nodes': [{'name': 'MIGTEST-N'}],
        }
        client = FakeCleanupClient(entities=entities)
        summary = cleanup(client, 'MIGTEST-')
        self.assertEqual(summary['teams'], 1)
        self.assertEqual(summary['roles'], 1)
        self.assertEqual(summary['nodes'], 1)
        self.assertEqual([c[0] for c in client.calls],
                         ['team', 'role', 'node'])

    def test_deepest_nodes_deleted_first(self):
        entities = {
            'teams': [], 'roles': [],
            'nodes': [
                {'name': 'MIGTEST-Root',  'parent': ''},
                {'name': 'MIGTEST-Child', 'parent': 'Parent\\X'},
                {'name': 'MIGTEST-Grand', 'parent': 'Parent\\X\\Y'},
            ],
        }
        client = FakeCleanupClient(entities=entities)
        cleanup(client, 'MIGTEST-')
        nodes = [c[1] for c in client.calls if c[0] == 'node']
        self.assertEqual(nodes, ['MIGTEST-Grand', 'MIGTEST-Child', 'MIGTEST-Root'])

    def test_failures_counted_not_raised(self):
        entities = {
            'teams': [{'name': 'MIGTEST-T'}],
            'roles': [], 'nodes': [],
        }
        client = FakeCleanupClient(entities=entities,
                                    fail_on={('team', 'MIGTEST-T')})
        summary = cleanup(client, 'MIGTEST-')
        self.assertEqual(summary['errors'], 1)
        self.assertEqual(summary['teams'], 0)

    def test_empty_prefix_rejected(self):
        with self.assertRaises(ValueError):
            cleanup(FakeCleanupClient(), '')

    def test_include_records_off_by_default(self):
        """Records must be untouched unless include_records is opted in.

        Regression guard: records live in user vaults and are
        qualitatively different from enterprise structure — we must
        never delete them unless the caller explicitly asks.
        """
        entities = {
            'teams': [], 'roles': [], 'nodes': [],
            'records': [
                {'uid': 'u1', 'title': 'MIGTEST-Login-Record'},
                {'uid': 'u2', 'title': 'MIGTEST-Notes-Record'},
            ],
        }
        client = FakeCleanupClient(entities=entities)
        summary = cleanup(client, 'MIGTEST-')
        self.assertEqual(summary['records'], 0)
        record_calls = [c for c in client.calls if c[0] == 'record']
        self.assertEqual(record_calls, [])

    def test_include_records_deletes_only_matching(self):
        entities = {
            'teams': [], 'roles': [], 'nodes': [],
            'records': [
                {'uid': 'u1', 'title': 'MIGTEST-Login-Record'},
                {'uid': 'u2', 'title': 'MIGTEST-Notes-Record'},
                {'uid': 'u3', 'title': 'admin_user'},        # survives
                {'uid': 'u4', 'title': 'app_packages:abc'},  # survives
            ],
        }
        client = FakeCleanupClient(entities=entities)
        summary = cleanup(client, 'MIGTEST-', include_records=True)
        self.assertEqual(summary['records'], 2)
        record_calls = sorted(c[1] for c in client.calls if c[0] == 'record')
        self.assertEqual(record_calls, ['u1', 'u2'])

    def test_include_records_failure_counted_not_raised(self):
        entities = {
            'teams': [], 'roles': [], 'nodes': [],
            'records': [{'uid': 'u1', 'title': 'MIGTEST-R1'}],
        }
        client = FakeCleanupClient(entities=entities,
                                    fail_on={('record', 'u1')})
        summary = cleanup(client, 'MIGTEST-', include_records=True)
        self.assertEqual(summary['errors'], 1)
        self.assertEqual(summary['records'], 0)

    def test_silent_node_no_op_is_counted_as_error(self):
        """Regression guard for the bug surfaced by Tier 6 rehearsal
        2026-04-19: Commander's enterprise-node --delete logs a warning
        ('node has children', 'objects on this node') but does NOT
        raise on certain failures. The plugin used to count the call
        as success because .execute() returned cleanly. Fix: verify
        the entity is actually gone by re-checking list_entities().
        """
        entities = {
            'teams': [], 'roles': [],
            'nodes': [
                {'name': 'MIGTEST-Child-Node', 'parent': 'Parent\\X'},
                {'name': 'MIGTEST-OtherNode', 'parent': 'Parent\\X'},
            ],
        }
        # Simulate Commander's silent-warning pattern on Child-Node.
        client = FakeCleanupClient(
            entities=entities,
            silent_fail_on={('node', 'MIGTEST-Child-Node')},
        )
        summary = cleanup(client, 'MIGTEST-')
        # OtherNode deleted cleanly.
        self.assertEqual(summary['nodes'], 1)
        # Child-Node silent no-op → error.
        self.assertEqual(summary['errors'], 1)
        # The entity that silently failed is still in the fake state.
        remaining = [n['name'] for n in client.entities['nodes']]
        self.assertIn('MIGTEST-Child-Node', remaining)
        self.assertNotIn('MIGTEST-OtherNode', remaining)

    def test_grandchild_deleted_before_child_via_parent_chain(self):
        """Regression guard for Tier 6 rehearsal finding 2026-04-19:
        inventory stores parent as a plain name (no backslashes), so
        the old `parent.count('\\\\')` heuristic returned 0 for every
        node → arbitrary delete order → silent 'has children' failures.
        Fix walks the parent chain to compute true depth.
        """
        entities = {
            'teams': [], 'roles': [],
            'nodes': [
                # Order chosen to break the naive sort: Child first,
                # Grandchild second. True-depth sort must still put
                # Grandchild first.
                {'name': 'MIGTEST-Child-Node', 'parent': 'MIGRATION-TEST-NODE'},
                {'name': 'MIGTEST-Grandchild-Node', 'parent': 'MIGTEST-Child-Node'},
                {'name': 'MIGTEST-Isolated-Node', 'parent': 'MIGRATION-TEST-NODE'},
            ],
        }
        client = FakeCleanupClient(entities=entities)
        cleanup(client, 'MIGTEST-')
        node_calls = [c[1] for c in client.calls if c[0] == 'node']
        # Grandchild must be deleted BEFORE Child so Child's delete
        # doesn't hit Commander's 'node has children' silent failure.
        self.assertLess(
            node_calls.index('MIGTEST-Grandchild-Node'),
            node_calls.index('MIGTEST-Child-Node'),
            f'Grandchild must precede Child in delete order: {node_calls}',
        )

    def test_shared_folders_filtered_by_prefix(self):
        """Bug 25 — SFs flow through matching_entities like other kinds."""
        entities = {
            'teams': [], 'roles': [], 'nodes': [],
            'shared_folders': [
                {'uid': 'sf1', 'name': 'MIGTEST-SF-Main'},
                {'uid': 'sf2', 'name': 'OtherSF'},        # survives
            ],
        }
        out = matching_entities(entities, 'MIGTEST-')
        self.assertEqual([sf['uid'] for sf in out['shared_folders']], ['sf1'])

    def test_shared_folders_deleted_after_records_before_teams(self):
        """Bug 25 — SF deletion runs after records (records inside an
        SF cascade out cleanly) and before teams (an SF's team grants
        survive otherwise)."""
        entities = {
            'teams': [{'name': 'MIGTEST-T'}],
            'roles': [], 'nodes': [],
            'records': [{'uid': 'r1', 'title': 'MIGTEST-Login-Record'}],
            'shared_folders': [{'uid': 'sf1', 'name': 'MIGTEST-SF-Main'}],
        }
        client = FakeCleanupClient(entities=entities)
        cleanup(client, 'MIGTEST-', include_records=True)
        kinds = [c[0] for c in client.calls]
        self.assertEqual(
            kinds, ['record', 'shared_folder', 'team'],
            f'order must be record → shared_folder → team: {kinds}',
        )

    def test_shared_folders_summary_counted(self):
        entities = {
            'teams': [], 'roles': [], 'nodes': [],
            'shared_folders': [
                {'uid': 'sf1', 'name': 'MIGTEST-SF-Main'},
                {'uid': 'sf2', 'name': 'MIGTEST-SF-Other'},
            ],
        }
        client = FakeCleanupClient(entities=entities)
        summary = cleanup(client, 'MIGTEST-')
        self.assertEqual(summary['shared_folders'], 2)
        self.assertEqual(summary['errors'], 0)
        self.assertEqual(client.entities['shared_folders'], [])

    def test_shared_folder_silent_no_op_counted_as_error(self):
        """Bug 25 — same trust-but-verify pattern as nodes/teams.
        rmdir can silently fail (record-still-attached cases) and
        we must not count those as success.
        """
        entities = {
            'teams': [], 'roles': [], 'nodes': [],
            'shared_folders': [{'uid': 'sf1', 'name': 'MIGTEST-SF-Main'}],
        }
        client = FakeCleanupClient(
            entities=entities,
            silent_fail_on={('shared_folder', 'sf1')},
        )
        summary = cleanup(client, 'MIGTEST-')
        self.assertEqual(summary['shared_folders'], 0)
        self.assertEqual(summary['errors'], 1)
        self.assertEqual(client.entities['shared_folders'],
                         [{'uid': 'sf1', 'name': 'MIGTEST-SF-Main'}])

    def test_clients_without_sf_support_unaffected(self):
        """Bug 25 — entities without a shared_folders key short-circuit
        cleanly. Older test fixtures (and any legacy CleanupClient
        subclass) keep working without changes.
        """
        entities = {
            'teams': [{'name': 'MIGTEST-T'}],
            'roles': [], 'nodes': [],
        }
        client = FakeCleanupClient(entities=entities)
        # Force the 'shared_folders' projection key away to simulate
        # a pre-Bug-25 client.
        client.entities.pop('shared_folders', None)
        summary = cleanup(client, 'MIGTEST-')
        self.assertEqual(summary['shared_folders'], 0)
        self.assertEqual(summary['teams'], 1)

    def test_silent_team_role_record_no_ops_counted_as_errors(self):
        """Same trust-but-verify guard across all four entity kinds."""
        entities = {
            'teams': [{'name': 'MIGTEST-T'}],
            'roles': [{'name': 'MIGTEST-R'}],
            'nodes': [{'name': 'MIGTEST-N'}],
            'records': [{'uid': 'u1', 'title': 'MIGTEST-R1'}],
        }
        client = FakeCleanupClient(
            entities=entities,
            silent_fail_on={
                ('team', 'MIGTEST-T'),
                ('role', 'MIGTEST-R'),
                ('node', 'MIGTEST-N'),
                ('record', 'u1'),
            },
        )
        summary = cleanup(client, 'MIGTEST-', include_records=True)
        self.assertEqual(summary['teams'], 0)
        self.assertEqual(summary['roles'], 0)
        self.assertEqual(summary['nodes'], 0)
        self.assertEqual(summary['records'], 0)
        self.assertEqual(summary['errors'], 4)


if __name__ == '__main__':
    unittest.main()
