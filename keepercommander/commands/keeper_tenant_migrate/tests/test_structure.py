import os
import tempfile
import unittest
from unittest.mock import patch

from keepercommander.commands.keeper_tenant_migrate.structure import (
    FakeClient,
    StepResult,
    StructureRestore,
    _enforcement_already_applied,
    build_id_to_role_name,
    build_source_role_meta,
    classify_enforcement,
    dedupe_node_names,
    dedupe_role_names,
    dedupe_team_names,
    extract_isolated_nodes,
    find_schema_violations,
    plan_managed_nodes,
    plan_role_team_assignments,
    plan_role_user_assignments,
    plan_user_node_assignments,
    plan_user_team_assignments,
    resolve_builtin_role_collision,
    restricts_flags,
    target_node_for_user,
    topological_node_order,
)


class TopologicalNodeOrderTests(unittest.TestCase):
    def test_parent_emitted_before_child(self):
        nodes = [
            {'node_id': 3, 'name': 'Grand', 'parent_id': 2, 'isolated': False},
            {'node_id': 2, 'name': 'Child', 'parent_id': 1, 'isolated': False},
            {'node_id': 1, 'name': 'Root', 'parent_id': '', 'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='Root', target_root='TenantRoot')
        names = [o[0] for o in out]
        self.assertEqual(names, ['Root', 'Child', 'Grand'])

    def test_duplicate_child_names_under_distinct_parents_kept_separate(self):
        """Bug 58 (rehearsal-10): name-keyed mode collapsed sibling
        nodes that share a name across parents (Subsidiary 1/2/3 each
        had a 'Finance' child) into a single entry. Only one got
        created on target, the other two went silently missing.
        Composite-keying by source `id` keeps them distinct."""
        nodes = [
            {'id': '1', 'name': 'Root', 'parent': '', 'isolated': False},
            {'id': '10', 'name': 'Sub1', 'parent': 'Root', 'isolated': False},
            {'id': '20', 'name': 'Sub2', 'parent': 'Root', 'isolated': False},
            {'id': '30', 'name': 'Sub3', 'parent': 'Root', 'isolated': False},
            {'id': '11', 'name': 'Finance', 'parent': 'Sub1',
             'isolated': False},
            {'id': '21', 'name': 'Finance', 'parent': 'Sub2',
             'isolated': False},
            {'id': '31', 'name': 'Finance', 'parent': 'Sub3',
             'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='',
                                      target_root='Keeperdemo')
        finance_entries = [o for o in out if o[0] == 'Finance']
        # Bug 58: pre-fix this returned 1 entry. Now returns 3, one
        # per distinct parent.
        self.assertEqual(len(finance_entries), 3)
        parents = sorted(o[1] for o in finance_entries)
        self.assertEqual(parents, ['Sub1', 'Sub2', 'Sub3'])

    def test_accepts_name_based_inventory_shape(self):
        """live_inventory.py emits id/parent (name) shape — drivers must accept both."""
        nodes = [
            {'id': '3', 'name': 'Grand', 'parent': 'Child', 'isolated': False},
            {'id': '2', 'name': 'Child', 'parent': 'Root', 'isolated': False},
            {'id': '1', 'name': 'Root', 'parent': '', 'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='Root', target_root='TenantRoot')
        self.assertEqual([o[0] for o in out], ['Root', 'Child', 'Grand'])
        self.assertEqual(out[0][1], 'TenantRoot')  # scope root reparented
        # The scope-root gets reparented to target_root
        self.assertEqual(out[0][1], 'TenantRoot')
        # Children keep their true parent
        self.assertEqual(out[1][1], 'Root')

    def test_full_tenant_top_level_children_remap_to_target_root(self):
        """2026-04-20 live full-tenant regression. Source's enterprise-root
        node had displayname='root' literally; top-level children emitted
        parent='root', which doesn't exist on target. Fix: full-tenant
        mode remaps any direct child of the source root to target_root,
        regardless of what the source root's name actually is."""
        nodes = [
            {'id': '1', 'name': 'root', 'parent': '', 'isolated': False},
            {'id': '2', 'name': 'Alan Demo', 'parent': 'root',
             'isolated': False},
            {'id': '3', 'name': 'Master Company', 'parent': 'root',
             'isolated': False},
            {'id': '4', 'name': 'Sub', 'parent': 'Master Company',
             'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='',
                                      target_root='Keeperdemo')
        # Source root itself is NOT emitted — already exists on target as
        # Keeperdemo.
        names = [n for n, _, _ in out]
        self.assertNotIn('root', names)
        by_name = {n: p for n, p, _ in out}
        # Top-level children reparented to Keeperdemo.
        self.assertEqual(by_name['Alan Demo'], 'Keeperdemo')
        self.assertEqual(by_name['Master Company'], 'Keeperdemo')
        # Nested children keep their real source parent.
        self.assertEqual(by_name['Sub'], 'Master Company')

    def test_full_tenant_remap_works_when_root_name_is_enterprise_name(self):
        """Same fix applies when the source root's displayname IS the
        enterprise name (most common case) — the direct children still
        can't use 'My company' as a parent on Keeperdemo."""
        nodes = [
            {'id': '1', 'name': 'My company', 'parent': '',
             'isolated': False},
            {'id': '2', 'name': 'Finance', 'parent': 'My company',
             'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='',
                                      target_root='Keeperdemo')
        by_name = {n: p for n, p, _ in out}
        self.assertNotIn('My company', by_name)
        self.assertEqual(by_name['Finance'], 'Keeperdemo')

    def test_real_root_without_scope_is_skipped(self):
        nodes = [
            {'node_id': 1, 'name': 'My company', 'parent_id': '', 'isolated': False},
            {'node_id': 2, 'name': 'Sub', 'parent_id': 1, 'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='', target_root='Root')
        names = [o[0] for o in out]
        self.assertEqual(names, ['Sub'])

    def test_isolated_flag_preserved(self):
        nodes = [
            {'node_id': 1, 'name': 'Scoped', 'parent_id': '', 'isolated': True},
        ]
        out = topological_node_order(nodes, scope_node_name='Scoped', target_root='Root')
        self.assertEqual(out[0][2], True)

    def test_scope_root_excluded_children_preserve_under_scope_node(self):
        # Bug 1 (2026-04-20): when scope_node is set, its descendants are
        # inventoried but the scope root itself is not. Direct children
        # carry parent=<scope_node_name>, which no longer exists in
        # node_map — they were silently dropped. Original fix was to
        # remap to target_root.
        #
        # Bug 16 (2026-04-27): that original remap was wrong — it
        # silently flattened the subtree. Children should land UNDER
        # the scope node on target (which the operator pre-creates as
        # a container), preserving source topology.
        nodes = [
            {'id': '1', 'name': 'MIGTEST-Child',
             'parent': 'MIGRATION-TEST-NODE', 'isolated': False},
            {'id': '2', 'name': 'MIGTEST-Grand',
             'parent': 'MIGTEST-Child', 'isolated': False},
            {'id': '3', 'name': 'MIGTEST-Isolated',
             'parent': 'MIGRATION-TEST-NODE', 'isolated': True},
        ]
        out = topological_node_order(
            nodes,
            scope_node_name='MIGRATION-TEST-NODE',
            target_root='Keeperdemo',
        )
        self.assertEqual(len(out), 3)
        names = {n[0]: n for n in out}
        # Bug 16 fix — top-level children land under the scope node on
        # target (preserves topology), NOT as siblings under target_root.
        self.assertEqual(names['MIGTEST-Child'][1], 'MIGRATION-TEST-NODE')
        self.assertEqual(names['MIGTEST-Isolated'][1], 'MIGRATION-TEST-NODE')
        # Nested child keeps its inventory-carried parent
        self.assertEqual(names['MIGTEST-Grand'][1], 'MIGTEST-Child')
        # Topological invariant: parent before child
        order = [n[0] for n in out]
        self.assertLess(order.index('MIGTEST-Child'),
                         order.index('MIGTEST-Grand'))

    def test_full_tenant_mode_unaffected_by_bug16_fix(self):
        # Sanity: the Bug 16 fix is gated on scope_lower being truthy.
        # Full-tenant mode (no scope) must continue using target_root
        # for direct children of the source enterprise root.
        nodes = [
            {'id': 'r', 'name': 'My company', 'parent': '',
             'isolated': False},
            {'id': '1', 'name': 'TopLevel-A', 'parent': 'My company',
             'isolated': False},
        ]
        out = topological_node_order(
            nodes,
            scope_node_name='',  # full-tenant mode
            target_root='Keeperdemo',
        )
        names = {n[0]: n for n in out}
        # Source root not emitted (already exists on target)
        self.assertNotIn('My company', names)
        # Top-level child reparents to target_root in full-tenant mode
        self.assertEqual(names['TopLevel-A'][1], 'Keeperdemo')

    def test_missing_ids_skipped(self):
        nodes = [
            {'node_id': '', 'name': 'NoId', 'parent_id': ''},
            {'node_id': 5, 'name': '', 'parent_id': ''},  # no name
            {'node_id': 1, 'name': 'Good', 'parent_id': '', 'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='Good', target_root='Root')
        self.assertEqual([o[0] for o in out], ['Good'])


class ExtractIsolatedNodesTests(unittest.TestCase):
    def test_returns_isolated_names_only(self):
        nodes = [
            {'name': 'A', 'isolated': True},
            {'name': 'B', 'isolated': False},
            {'name': 'C', 'isolated': True},
            {'name': '', 'isolated': True},  # empty name skipped
        ]
        self.assertEqual(extract_isolated_nodes(nodes), ['A', 'C'])


class RestrictsFlagsTests(unittest.TestCase):
    def test_all_three_on(self):
        self.assertEqual(restricts_flags('R W S'), ('on', 'on', 'on'))

    def test_none(self):
        self.assertEqual(restricts_flags(''), ('off', 'off', 'off'))
        self.assertEqual(restricts_flags(None), ('off', 'off', 'off'))

    def test_partial(self):
        # R=edit, W=view, S=share — only S
        self.assertEqual(restricts_flags('S'), ('on', 'off', 'off'))
        self.assertEqual(restricts_flags('R'), ('off', 'on', 'off'))
        self.assertEqual(restricts_flags('W'), ('off', 'off', 'on'))

    def test_case_insensitive(self):
        self.assertEqual(restricts_flags('r w s'), ('on', 'on', 'on'))


class DedupeTeamNamesTests(unittest.TestCase):
    def test_unique_names_pass_through(self):
        teams = [
            {'name': 'Alpha', 'node': 'My company\\NodeA', 'restricts': ''},
            {'name': 'Beta', 'node': 'My company\\NodeB', 'restricts': 'R'},
        ]
        rows, renames = dedupe_team_names(teams, source_root='My company', target_root='Root')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['create_name'], 'Alpha')
        self.assertEqual(rows[0]['node'], 'NodeA')  # leaf
        self.assertEqual(renames, [])

    def test_duplicate_name_gets_suffixed_with_leaf_node(self):
        teams = [
            {'name': 'Shared', 'node': 'My company\\NodeA', 'restricts': ''},
            {'name': 'Shared', 'node': 'My company\\NodeB', 'restricts': 'R W'},
        ]
        rows, renames = dedupe_team_names(teams, source_root='My company', target_root='Root')
        create_names = sorted(r['create_name'] for r in rows)
        self.assertEqual(create_names, ['Shared (NodeA)', 'Shared (NodeB)'])
        # Restrictions preserved through suffixing
        r_w_team = next(r for r in rows if r['create_name'] == 'Shared (NodeB)')
        self.assertEqual(r_w_team['restrict_edit'], 'on')
        self.assertEqual(r_w_team['restrict_view'], 'on')
        self.assertEqual(len(renames), 2)

    def test_source_root_node_maps_to_target_root(self):
        teams = [{'name': 'T', 'node': 'My company', 'restricts': ''}]
        rows, _ = dedupe_team_names(teams, source_root='My company', target_root='Keeperdemo')
        self.assertEqual(rows[0]['node'], 'Keeperdemo')

    def test_dedup_rename_log_key_is_raw_source_node(self):
        """Bug 61 fix — same contract as dedupe_role_names: rename_log
        second tuple element must be the RAW source-side `.node`
        verbatim so validate.py's `team.get('node', '')` lookup
        through `target_name_for` resolves."""
        teams = [
            {'name': 'Shared', 'node': 'My company\\NodeA', 'restricts': ''},
            {'name': 'Shared', 'node': 'My company\\NodeB', 'restricts': ''},
            {'name': 'Other', 'node': 'My company', 'restricts': ''},
            {'name': 'Other', 'node': 'My company\\NodeA', 'restricts': ''},
        ]
        _, renames = dedupe_team_names(
            teams, source_root='My company', target_root='Keeperdemo')
        rename_by_orig_node = {(orig, src_node): renamed
                               for orig, src_node, renamed in renames}
        self.assertIn(('Shared', 'My company\\NodeA'), rename_by_orig_node)
        self.assertIn(('Shared', 'My company\\NodeB'), rename_by_orig_node)
        # Source-root case stores 'My company' verbatim, not 'Keeperdemo'.
        self.assertIn(('Other', 'My company'), rename_by_orig_node)


class DedupeNodeNamesTests(unittest.TestCase):
    """Bug 73 — node analog of dedupe_team_names. Suffixes duplicate
    leaf names with the parent leaf; rename_log mirrors the team/role
    shape so it round-trips through rename_map.json."""

    def test_unique_names_pass_through(self):
        order = [
            ('SubA', 'Root', False),
            ('Finance', 'SubA', False),
        ]
        rows, renames = dedupe_node_names(order)
        self.assertEqual([r['create_name'] for r in rows], ['SubA', 'Finance'])
        self.assertEqual(renames, [])

    def test_duplicate_leaf_under_distinct_parents_suffixed(self):
        order = [
            ('SubA', 'Root', False),
            ('SubB', 'Root', False),
            ('Finance', 'SubA', False),
            ('Finance', 'SubB', False),
        ]
        rows, renames = dedupe_node_names(order)
        finance_rows = [r for r in rows if r['original_name'] == 'Finance']
        self.assertEqual(
            sorted(r['create_name'] for r in finance_rows),
            ['Finance (SubA)', 'Finance (SubB)'],
        )
        self.assertEqual(len(renames), 2)
        # Each rename log entry: (orig, parent, renamed)
        for orig, parent, renamed in renames:
            self.assertEqual(orig, 'Finance')
            self.assertIn(parent, ('SubA', 'SubB'))
            self.assertEqual(renamed, f'Finance ({parent})')

    def test_three_way_duplicate_all_get_suffixed(self):
        order = [
            ('Sub1', 'Root', False),
            ('Sub2', 'Root', False),
            ('Sub3', 'Root', False),
            ('Finance', 'Sub1', False),
            ('Finance', 'Sub2', False),
            ('Finance', 'Sub3', False),
        ]
        rows, renames = dedupe_node_names(order)
        finance = [r['create_name'] for r in rows if r['original_name'] == 'Finance']
        self.assertEqual(sorted(finance),
                         ['Finance (Sub1)', 'Finance (Sub2)', 'Finance (Sub3)'])
        self.assertEqual(len(renames), 3)

    def test_isolated_flag_preserved_through_rename(self):
        order = [
            ('A', 'Root', False),
            ('B', 'Root', False),
            ('Restricted', 'A', True),
            ('Restricted', 'B', True),
        ]
        rows, _ = dedupe_node_names(order)
        for r in rows:
            if r['original_name'] == 'Restricted':
                self.assertTrue(r['isolated'])


class StructureRestoreDriverTests(unittest.TestCase):
    def _make(self, **kwargs):
        client = FakeClient(**kwargs)
        return client, StructureRestore(
            client, source_root='My company', target_root='Keeperdemo',
            scope_node='MIGRATION-TEST-NODE',
        )

    def test_step_record_types_success(self):
        client, restore = self._make()
        restore.step_record_types('/tmp/fake_record_types.json')
        self.assertEqual(restore.counters['SUCCESS'], 1)
        self.assertEqual(client.calls[0][0], 'load_record_types')

    def test_step_record_types_missing_path_is_noop(self):
        _, restore = self._make()
        restore.step_record_types('')
        self.assertEqual(restore.counters['SUCCESS'], 0)
        self.assertEqual(restore.counters['FAILED'], 0)

    def test_step_nodes_creates_in_topological_order(self):
        client, restore = self._make()
        nodes = [
            {'node_id': 2, 'name': 'Child', 'parent_id': 1},
            {'node_id': 1, 'name': 'MIGRATION-TEST-NODE', 'parent_id': ''},
        ]
        restore.step_nodes(nodes)
        node_calls = [c for c in client.calls if c[0] == 'create_node']
        self.assertEqual(node_calls[0][1], ('MIGRATION-TEST-NODE', 'Keeperdemo'))
        self.assertEqual(node_calls[1][1], ('Child', 'MIGRATION-TEST-NODE'))
        self.assertEqual(restore.counters['SUCCESS'], 2)

    def test_step_nodes_marks_failures(self):
        client = FakeClient(fail_on={'create_node'})
        restore = StructureRestore(
            client, source_root='My company', target_root='Keeperdemo',
            scope_node='MIGRATION-TEST-NODE',
        )
        restore.step_nodes([{'node_id': 1, 'name': 'MIGRATION-TEST-NODE', 'parent_id': ''}])
        self.assertEqual(restore.counters['FAILED'], 1)
        self.assertIn('already exist', restore.results[0].notes)

    def test_step_nodes_tracks_created_set(self):
        """PR-B hardening: successful creations land in created_nodes so
        downstream steps can gate on real target state."""
        client, restore = self._make()
        restore.step_nodes([
            {'node_id': 1, 'name': 'MIGRATION-TEST-NODE', 'parent_id': ''},
            {'node_id': 2, 'name': 'Child', 'parent_id': 1},
        ])
        self.assertIn('Child', restore.created_nodes)

    def test_step_nodes_renames_duplicate_leaves_by_default(self):
        """Bug 73 — three Finance nodes under three Subsidiaries land
        on target as 'Finance (Sub1)', 'Finance (Sub2)', 'Finance (Sub3)'
        and node_rename_log records the mapping."""
        client, restore = self._make()
        nodes = [
            {'node_id': 1, 'name': 'MIGRATION-TEST-NODE', 'parent_id': ''},
            {'node_id': 10, 'name': 'Sub1', 'parent_id': 1},
            {'node_id': 11, 'name': 'Sub2', 'parent_id': 1},
            {'node_id': 12, 'name': 'Sub3', 'parent_id': 1},
            {'node_id': 100, 'name': 'Finance', 'parent_id': 10},
            {'node_id': 101, 'name': 'Finance', 'parent_id': 11},
            {'node_id': 102, 'name': 'Finance', 'parent_id': 12},
        ]
        restore.step_nodes(nodes)
        created = [c[1] for c in client.calls if c[0] == 'create_node']
        finance_creates = sorted(name for name, _parent in created
                                 if name.startswith('Finance'))
        self.assertEqual(finance_creates,
                         ['Finance (Sub1)', 'Finance (Sub2)', 'Finance (Sub3)'])
        # rename_log carries (orig, parent, renamed) for each duplicate
        self.assertEqual(len(restore.node_rename_log), 3)
        for orig, parent, renamed in restore.node_rename_log:
            self.assertEqual(orig, 'Finance')
            self.assertIn(parent, ('Sub1', 'Sub2', 'Sub3'))
            self.assertEqual(renamed, f'Finance ({parent})')
        # All three renamed nodes tracked in created_nodes for downstream
        # gating (step_isolated_flags, etc.)
        self.assertIn('Finance (Sub1)', restore.created_nodes)
        self.assertIn('Finance (Sub3)', restore.created_nodes)

    def test_step_nodes_preserve_flag_skips_rename(self):
        """Bug 73 opt-in: --preserve-duplicate-node-names sends the
        original duplicate names through untouched; rename_log stays
        empty. Relies on the SDK boundary's direct `node_add` bypass
        to actually land them server-side (live-test pending)."""
        client = FakeClient()
        restore = StructureRestore(
            client, source_root='My company', target_root='Keeperdemo',
            scope_node='MIGRATION-TEST-NODE',
            preserve_duplicate_node_names=True,
        )
        nodes = [
            {'node_id': 1, 'name': 'MIGRATION-TEST-NODE', 'parent_id': ''},
            {'node_id': 10, 'name': 'Sub1', 'parent_id': 1},
            {'node_id': 11, 'name': 'Sub2', 'parent_id': 1},
            {'node_id': 100, 'name': 'Finance', 'parent_id': 10},
            {'node_id': 101, 'name': 'Finance', 'parent_id': 11},
        ]
        restore.step_nodes(nodes)
        created = [c[1] for c in client.calls if c[0] == 'create_node']
        finance_creates = [name for name, _parent in created if name == 'Finance']
        self.assertEqual(len(finance_creates), 2)
        self.assertEqual(restore.node_rename_log, [])

    def test_step_isolated_flags_targets_renamed_node(self):
        """Bug 73 — when a duplicate-name source node also has
        isolated=True, step_isolated_flags must call toggle on the
        RENAMED target name, not the original ambiguous leaf."""
        client, restore = self._make()
        nodes = [
            {'node_id': 1, 'name': 'MIGRATION-TEST-NODE', 'parent_id': ''},
            {'node_id': 10, 'name': 'Sub1', 'parent_id': 1},
            {'node_id': 11, 'name': 'Sub2', 'parent_id': 1},
            {'node_id': 100, 'name': 'Restricted', 'parent_id': 10,
             'isolated': True},
            {'node_id': 101, 'name': 'Restricted', 'parent_id': 11,
             'isolated': True},
        ]
        # Reflect topological_node_order's flat-name shape into the
        # source list step_isolated_flags walks. The driver test suite
        # uses the live-inventory-style dicts, so isolated-pair source
        # rows here mirror that shape with parent as a NAME.
        flat_nodes = [
            {'name': 'MIGRATION-TEST-NODE', 'parent': '', 'isolated': False},
            {'name': 'Sub1', 'parent': 'MIGRATION-TEST-NODE', 'isolated': False},
            {'name': 'Sub2', 'parent': 'MIGRATION-TEST-NODE', 'isolated': False},
            {'name': 'Restricted', 'parent': 'Sub1', 'isolated': True},
            {'name': 'Restricted', 'parent': 'Sub2', 'isolated': True},
        ]
        restore.step_nodes(nodes)
        client.calls = [c for c in client.calls if c[0] != 'create_node']
        restore.step_isolated_flags(flat_nodes)
        toggle_calls = [c[1] for c in client.calls
                        if c[0] == 'toggle_node_isolated']
        toggled = sorted(name for (name,) in toggle_calls)
        self.assertEqual(toggled,
                         ['Restricted (Sub1)', 'Restricted (Sub2)'])

    def test_step_teams_tracks_created_set(self):
        client, restore = self._make()
        restore.step_teams([
            {'name': 'T1', 'node': 'My company\\X', 'restricts': ''},
        ])
        self.assertIn('T1', restore.created_teams)

    def test_step_roles_tracks_created_set(self):
        client, restore = self._make()
        restore.step_roles([
            {'name': 'R1', 'node': 'My company\\X'},
        ])
        self.assertIn('R1', restore.created_roles)

    def test_step_teams_records_rename_log_on_restore(self):
        """Duplicates get suffixed with leaf-node name; the rename
        information lands on restore.team_rename_log so commands.py
        can include it in the structure audit event."""
        client, restore = self._make()
        restore.step_teams([
            {'name': 'Engineering', 'node': 'My company\\Sub1',
             'restricts': ''},
            {'name': 'Engineering', 'node': 'My company\\Sub2',
             'restricts': ''},
        ])
        renamed = [r for r in restore.team_rename_log
                    if r[0] == 'Engineering']
        self.assertEqual(len(renamed), 2)
        # rename tuple shape: (original, source_node, renamed)
        for orig, _node, renamed_name in renamed:
            self.assertEqual(orig, 'Engineering')
            self.assertNotEqual(renamed_name, 'Engineering')

    def test_step_roles_records_rename_log_on_restore(self):
        client, restore = self._make()
        restore.step_roles([
            {'name': 'Auditors', 'node': 'My company\\Sub1'},
            {'name': 'Auditors', 'node': 'My company\\Sub2'},
        ])
        renamed = [r for r in restore.role_rename_log
                    if r[0] == 'Auditors']
        self.assertEqual(len(renamed), 2)

    def test_rename_logs_initialize_empty(self):
        """Default state: rename logs are empty lists; commands.py's
        `if restore.team_rename_log or restore.role_rename_log:` gate
        relies on the empty-truthiness."""
        _, restore = self._make()
        self.assertEqual(restore.team_rename_log, [])
        self.assertEqual(restore.role_rename_log, [])

    def test_step_managed_nodes_skips_uncreated_roles(self):
        """2026-04-20 regression: step_managed_nodes looped over every
        role including those that failed to create, producing a cascade
        of 'Role X is not found: Skipping' lines. Gate fix: if the role
        isn't in created_roles (and the set is populated), SKIPPED not
        FAILED."""
        client, restore = self._make()
        # Simulate step_roles having run; only 'Good' landed.
        restore.created_roles = {'Good'}
        roles_complete = [
            {'name': 'Good', 'node': 'My company\\X',
             'managed_nodes': [
                 {'node_name': 'X', 'cascade': True,
                  'privileges': ['manage_user']},
             ]},
            {'name': 'Missing', 'node': 'My company\\Y',
             'managed_nodes': [
                 {'node_name': 'Y', 'cascade': True,
                  'privileges': ['manage_user', 'manage_roles']},
             ]},
        ]
        restore.step_managed_nodes(roles_complete)
        # Good got its managed_node + privilege calls through.
        self.assertGreaterEqual(restore.counters['SUCCESS'], 2)
        # Missing got exactly one SKIPPED record (not one per privilege).
        skipped = [r for r in restore.results
                    if r.status == StepResult.SKIPPED and 'Missing' in r.name]
        self.assertEqual(len(skipped), 1)
        self.assertIn('suppressed', skipped[0].notes)

    def test_step_managed_nodes_gate_off_when_no_set_populated(self):
        """Backwards compat: if created_roles is empty (e.g. caller
        didn't run step_roles — plan-dir load path), the gate is off and
        every role gets normal processing."""
        client, restore = self._make()
        # created_roles intentionally empty.
        restore.step_managed_nodes([
            {'name': 'Any', 'managed_nodes': [
                {'node_name': 'X', 'cascade': False, 'privileges': []},
            ]},
        ])
        self.assertEqual(restore.counters['SKIPPED'], 0)

    def test_step_managed_nodes_preflight_flags_admin_plus_team(self):
        """Bug 13 — pre-flight should reject roles carrying both
        managed_nodes and teams (Keeper schema rule), recording a
        FAILED with a schema-impossible message and suppressing the
        per-node API calls."""
        client, restore = self._make()
        roles_complete = [
            {'name': 'Hybrid',
             'managed_nodes': [
                 {'node_name': 'X', 'cascade': False,
                  'privileges': ['manage_user']}
             ],
             'teams': ['SomeTeam']},
        ]
        restore.step_managed_nodes(roles_complete)
        failed = [r for r in restore.results
                   if r.status == StepResult.FAILED and r.name == 'Hybrid']
        self.assertEqual(len(failed), 1)
        self.assertIn('schema-impossible', failed[0].notes)
        self.assertEqual(restore.counters['SUCCESS'], 0,
                          'no API call should be made for a violator role')

    def test_find_schema_violations_passes_legitimate_shapes(self):
        """Real source data: a role is admin (managed_nodes only) OR
        regular (teams only) OR trivial (neither). Pre-flight must
        return [] for all three patterns."""
        legitimate = [
            {'name': 'AdminOnly',
             'managed_nodes': [{'node_name': 'X', 'cascade': False,
                                 'privileges': []}],
             'teams': []},
            {'name': 'RegularOnly',
             'managed_nodes': [], 'teams': ['SomeTeam']},
            {'name': 'Trivial',
             'managed_nodes': [], 'teams': []},
            {'name': 'Empty'},  # missing both keys
        ]
        self.assertEqual(find_schema_violations(legitimate), [])

    def test_find_schema_violations_skips_unnamed_roles(self):
        """Defensive: roles with no name shouldn't crash the check."""
        self.assertEqual(
            find_schema_violations([{'managed_nodes': [{}], 'teams': ['T']}]),
            [],
        )

    def test_record_types_translator_invoked_for_typed_keys(self):
        """When record_types_translator is provided and the key is
        typed `record_types`, the value must be translated before it
        reaches the CLI batch. Source-side IDs JSON → CLI-acceptable
        comma-names string."""
        client, restore = self._make()
        restore.created_roles = {'R1'}
        captured_translator_calls = []

        def _translator(value):
            captured_translator_calls.append(value)
            return 'login,databaseCredentials'

        roles = [{
            'name': 'R1',
            'enforcements': {
                'restrict_record_types': '{"std":[12,6],"ent":[]}',
                # A non-record_types key flows through unchanged
                'restrict_export': 'true',
            },
        }]
        restore.step_enforcements(
            roles, record_types_translator=_translator)
        # Translator was called with the source value
        self.assertEqual(captured_translator_calls,
                          ['{"std":[12,6],"ent":[]}'])
        # The CLI batch should have received the translated value
        batch_calls = [c for c in client.calls
                        if c[0] == 'set_role_enforcements_simple_batch']
        self.assertEqual(len(batch_calls), 1)
        pairs = dict(batch_calls[0][1][1])
        self.assertEqual(pairs['restrict_record_types'],
                          'login,databaseCredentials')
        self.assertEqual(pairs['restrict_export'], 'true')

    def test_record_types_translator_skipped_when_none(self):
        """Backwards compat: when no translator is provided, the
        record_types value passes through unchanged (legacy behavior;
        Commander rejects it server-side but we don't crash)."""
        client, restore = self._make()
        restore.created_roles = {'R1'}
        roles = [{
            'name': 'R1',
            'enforcements': {
                'restrict_record_types': '{"std":[12,6],"ent":[]}',
            },
        }]
        restore.step_enforcements(roles)
        batch_calls = [c for c in client.calls
                        if c[0] == 'set_role_enforcements_simple_batch']
        pairs = dict(batch_calls[0][1][1]) if batch_calls else {}
        # Raw value passed through to CLI batch unchanged
        self.assertEqual(pairs.get('restrict_record_types'),
                          '{"std":[12,6],"ent":[]}')

    def test_enforcement_already_applied_string_compare(self):
        """Default path: string equality between source and target
        values. Used for the bulk of enforcement keys where the value
        is portable across tenants."""
        self.assertTrue(_enforcement_already_applied(
            'restrict_export', 'true', {'restrict_export': 'true'}))
        self.assertFalse(_enforcement_already_applied(
            'restrict_export', 'true', {'restrict_export': 'false'}))
        # Missing on target → not applied
        self.assertFalse(_enforcement_already_applied(
            'restrict_export', 'true', {}))

    def test_enforcement_already_applied_account_share_cross_tenant(self):
        """Bug 17: require_account_share value is the role's own ID,
        which differs cross-tenant by design. Treat any non-empty
        target value as already-applied so resume doesn't re-issue
        and trigger Commander's 'cannot update enforcement' rejection."""
        # Source value is source role ID; target has a different ID.
        self.assertTrue(_enforcement_already_applied(
            'require_account_share',
            '34574486733148',
            {'require_account_share': '51788715655810'}))
        # Source value is some-thing; target empty → not applied
        self.assertFalse(_enforcement_already_applied(
            'require_account_share',
            '34574486733148',
            {}))
        # Backwards compat: if target somehow has the source value,
        # it should still be skipped (already applied).
        self.assertTrue(_enforcement_already_applied(
            'require_account_share',
            '34574486733148',
            {'require_account_share': '34574486733148'}))

    def test_classify_error_routes_schema_markers_to_failed(self):
        """Bug 13 — server's "no objects provided" / "teams cannot be
        assigned to roles with administrative permissions" must produce
        a FAILED with the actual constraint named, not pass through as
        opaque text."""
        _, restore = self._make()
        for marker in (
            'no objects provided',
            'Teams cannot be assigned to roles with administrative permissions',
        ):
            status, reason = restore._classify_error(marker)
            self.assertEqual(status, 'FAILED')
            self.assertIn('Keeper schema rule', reason)

    def test_step_isolated_flags_gates_on_created_nodes(self):
        """Mirror gate: when step_nodes failed to create a node, the
        downstream toggle-isolated call should suppress to one SKIPPED
        instead of attempting (and failing) the API call."""
        client, restore = self._make()
        restore.created_nodes = {'Good'}
        restore.step_isolated_flags([
            {'name': 'Good', 'isolated': True},
            {'name': 'Missing', 'isolated': True},
        ])
        suppressed = [r for r in restore.results
                       if r.status == StepResult.SKIPPED
                       and 'Missing' in r.name and 'suppressed' in r.notes]
        self.assertEqual(len(suppressed), 1)

    def test_step_isolated_flags_only_toggles_isolated(self):
        client, restore = self._make()
        restore.step_isolated_flags([
            {'name': 'A', 'isolated': False},
            {'name': 'B', 'isolated': True},
            {'name': 'C', 'isolated': True},
        ])
        toggle_calls = [c for c in client.calls if c[0] == 'toggle_node_isolated']
        self.assertEqual([c[1][0] for c in toggle_calls], ['B', 'C'])

    def test_step_vault_folders_creates_parents_before_children(self):
        """PR-B regression guard. vault_folders list is parents-first —
        walking it with uid_map should resolve each child's parent to
        a target UID created by an earlier iteration."""
        client, restore = self._make()
        vault_folders = [
            {'uid': 'src-parent', 'name': 'MIGTEST-Parent',
             'type': 'user_folder', 'parent_uid': '',
             'parent_chain': []},
            {'uid': 'src-sf', 'name': 'MIGTEST-SF',
             'type': 'shared_folder', 'parent_uid': 'src-parent',
             'parent_chain': ['src-parent']},
            {'uid': 'src-sub', 'name': 'MIGTEST-Sub',
             'type': 'shared_folder_folder',
             'parent_uid': 'src-sf',
             'parent_chain': ['src-sf', 'src-parent']},
        ]
        uid_map = restore.step_vault_folders(vault_folders)
        self.assertEqual(uid_map['src-parent'], 'uf-MIGTEST-Parent-root')
        self.assertEqual(uid_map['src-sf'],
                          'sf-MIGTEST-SF-uf-MIGTEST-Parent-root')
        self.assertEqual(uid_map['src-sub'],
                          'sff-MIGTEST-Sub-sf-MIGTEST-SF-uf-MIGTEST-Parent-root')
        # Every call made in order — parent before child.
        create_calls = [c for c in client.calls
                         if c[0] in ('add_user_folder', 'add_shared_folder',
                                      'add_subfolder')]
        self.assertEqual(create_calls[0][0], 'add_user_folder')
        self.assertEqual(create_calls[1][0], 'add_shared_folder')
        self.assertEqual(create_calls[2][0], 'add_subfolder')
        self.assertEqual(restore.counters['SUCCESS'], 3)

    def test_step_vault_folders_sf_default_perms_pass_through(self):
        client, restore = self._make()
        vf = [{
            'uid': 'src-sf', 'name': 'MIGTEST-SF',
            'type': 'shared_folder', 'parent_uid': '',
            'parent_chain': [],
            'default_manage_users': True,
            'default_manage_records': True,
            'default_can_edit': False,
            'default_can_share': True,
        }]
        restore.step_vault_folders(vf)
        sf_call = next(c for c in client.calls if c[0] == 'add_shared_folder')
        # Fake stores defaults in the tuple tail — see
        # FakeClient.add_shared_folder.
        _, args = sf_call
        (_, _, _, mu, mr, ce, cs) = args
        self.assertTrue(mu)
        self.assertTrue(mr)
        self.assertFalse(ce)
        self.assertTrue(cs)

    def test_step_vault_folders_unresolved_parent_is_failure(self):
        client, restore = self._make()
        vf = [{
            'uid': 'src-orphan', 'name': 'MIGTEST-Orphan',
            'type': 'shared_folder_folder',
            'parent_uid': 'MISSING-PARENT',
            'parent_chain': ['MISSING-PARENT'],
        }]
        restore.step_vault_folders(vf)
        self.assertEqual(restore.counters['FAILED'], 1)
        self.assertIn('not in uid_map', restore.results[-1].notes)

    def test_step_vault_folders_empty_list_skipped(self):
        client, restore = self._make()
        restore.step_vault_folders([])
        self.assertEqual(restore.counters['SKIPPED'], 1)

    def test_step_vault_folders_client_failure_is_failed(self):
        client = FakeClient(fail_on={'add_user_folder'})
        restore = StructureRestore(
            client, source_root='My company', target_root='Keeperdemo',
            scope_node='MIGRATION-TEST-NODE',
        )
        restore.step_vault_folders([
            {'uid': 'src-1', 'name': 'MIGTEST-UF',
             'type': 'user_folder', 'parent_uid': '',
             'parent_chain': []},
        ])
        self.assertEqual(restore.counters['FAILED'], 1)
        self.assertIn('empty UID', restore.results[-1].notes)

    def test_step_vault_folders_strips_trailing_whitespace_on_name(self):
        # Bug 55 (v1.5.6): Commander rejects shared folder creation
        # when the name has trailing/leading whitespace (returns
        # empty UID with no error). Plugin must strip on the way in
        # so the parent SF lands and child subfolders inherit the
        # uid_map. Surfaced 2026-05-01 rehearsal-8 — 'Keeper Demo
        # Console users ' (trailing space) returned empty UID, then
        # 4 child subfolders cascade-failed.
        client, restore = self._make()
        restore.step_vault_folders([
            {'uid': 'src-sf', 'name': 'My SF With Spaces  ',
             'type': 'shared_folder', 'parent_uid': '',
             'parent_chain': []},
        ])
        # The Fake client synthesizes UID `sf-<name>-...`; assert
        # the call landed (SUCCESS) and that the recorded name is
        # the stripped form (no trailing whitespace).
        self.assertEqual(restore.counters['FAILED'], 0)
        self.assertEqual(restore.counters['SUCCESS'], 1)
        last = restore.results[-1]
        self.assertEqual(last.name, 'My SF With Spaces')

    def test_step_vault_folders_subfolder_without_parent_errors(self):
        client, restore = self._make()
        restore.step_vault_folders([
            {'uid': 'src-sub', 'name': 'MIGTEST-Sub',
             'type': 'shared_folder_folder', 'parent_uid': '',
             'parent_chain': []},
        ])
        # Empty parent on a subfolder resolves to target='' which the
        # Commander impl rejects (and Fake still synthesizes). We assert
        # SUCCESS here in the Fake path; Commander rejection is covered
        # by commander_clients tests when added.
        self.assertEqual(restore.counters['SUCCESS'], 1)

    def test_step_teams_preserves_duplicates_note(self):
        client, restore = self._make()
        teams = [
            {'name': 'Shared', 'node': 'My company\\NodeA', 'restricts': ''},
            {'name': 'Shared', 'node': 'My company\\NodeB', 'restricts': 'R'},
            {'name': 'Unique', 'node': 'My company\\NodeA', 'restricts': 'S'},
        ]
        renames = restore.step_teams(teams)
        self.assertEqual(len(renames), 2)
        # Duplicates have a note; unique team does not
        shared_rows = [r for r in restore.results if r.name.startswith('Shared (')]
        self.assertEqual(len(shared_rows), 2)
        for r in shared_rows:
            self.assertIn('duplicate', r.notes)


class StructureRestorePaceTests(unittest.TestCase):
    """v1.4.0 throttle management. _pace() runs after every API call
    inside step loops to give the tenant's rate-limit budget a chance
    to replenish and to let the admin's browser session log in while a
    long migration is running."""

    def _restore(self, **throttle):
        client = FakeClient()
        r = StructureRestore(client, **throttle)
        r._sleep = lambda s: r.__dict__.setdefault('_sleeps', []).append(s)
        return r

    def test_pace_noop_when_all_zero(self):
        r = self._restore()
        r._pace()
        r._pace()
        self.assertEqual(getattr(r, '_sleeps', []), [])

    def test_delay_floor_applies_to_every_call(self):
        r = self._restore(delay=2.0)
        r._pace()
        r._pace()
        r._pace()
        self.assertEqual(r._sleeps, [2.0, 2.0, 2.0])

    def test_jitter_adds_bounded_random_on_top_of_delay(self):
        r = self._restore(delay=1.0, jitter=0.5)
        for _ in range(10):
            r._pace()
        for s in r._sleeps:
            self.assertGreaterEqual(s, 1.0)
            self.assertLessEqual(s, 1.5)

    def test_reserve_quota_extends_every_nth_call(self):
        """Every 3 calls should get an extra 2s on top of delay."""
        r = self._restore(delay=1.0, reserve_quota_every=3,
                           reserve_quota_seconds=2.0)
        for _ in range(6):
            r._pace()
        # Calls 1, 2, 4, 5 = 1.0; Calls 3, 6 = 3.0
        self.assertEqual(r._sleeps[0], 1.0)
        self.assertEqual(r._sleeps[1], 1.0)
        self.assertEqual(r._sleeps[2], 3.0)
        self.assertEqual(r._sleeps[3], 1.0)
        self.assertEqual(r._sleeps[4], 1.0)
        self.assertEqual(r._sleeps[5], 3.0)

    def test_reserve_quota_alone_with_no_delay(self):
        """Users who don't want a floor delay but DO want the
        reserve-quota yield should get just the quota pause."""
        r = self._restore(reserve_quota_every=2, reserve_quota_seconds=1.5)
        for _ in range(4):
            r._pace()
        self.assertEqual(r._sleeps, [1.5, 1.5])

    def test_step_nodes_invokes_pace_once_per_node(self):
        """Wiring check: step_nodes calls _pace() after every create
        call, not just at the end of the loop. Source root is skipped
        (lives on target as target_root) so only the non-root nodes
        generate pace calls."""
        client = FakeClient()
        restore = StructureRestore(client, delay=0.1,
                                    source_root='My company',
                                    target_root='Keeperdemo')
        restore._sleep = lambda s: restore.__dict__.setdefault('_sleeps', []).append(s)
        restore.step_nodes([
            {'node_id': 1, 'name': 'Root', 'parent_id': ''},
            {'node_id': 2, 'name': 'A', 'parent_id': 1},
            {'node_id': 3, 'name': 'B', 'parent_id': 1},
        ])
        # 3 input nodes, root skipped (full-tenant mode) → 2 creates → 2 paces.
        self.assertEqual(len(getattr(restore, '_sleeps', [])), 2)


class ResolveBuiltinRoleCollisionTests(unittest.TestCase):
    def test_known_builtins_get_migrated_suffix(self):
        self.assertEqual(resolve_builtin_role_collision('Administrator'),
                         'Administrator (Migrated)')
        self.assertEqual(resolve_builtin_role_collision('Keeper Administrator'),
                         'Keeper Administrator (Migrated)')

    def test_unknown_names_pass_through(self):
        self.assertEqual(resolve_builtin_role_collision('MIGTEST-Admin'),
                         'MIGTEST-Admin')


class DedupeRoleNamesTests(unittest.TestCase):
    def test_duplicate_suffix_plus_default_flag(self):
        roles = [
            {'name': 'Viewer', 'node': 'My company\\NodeA', 'default_role': True},
            {'name': 'Viewer', 'node': 'My company\\NodeB'},
            {'name': 'Unique', 'node': 'My company'},
        ]
        rows, renames = dedupe_role_names(roles, source_root='My company', target_root='Root')
        names = {r['create_name']: r for r in rows}
        self.assertIn('Viewer (NodeA)', names)
        self.assertIn('Viewer (NodeB)', names)
        self.assertEqual(names['Viewer (NodeA)']['new_user'], 'on')
        self.assertEqual(names['Viewer (NodeB)']['new_user'], 'off')
        self.assertEqual(names['Unique']['node'], 'Root')  # source_root → target_root
        self.assertEqual(len(renames), 2)

    def test_builtin_collision_resolved_after_dedup(self):
        roles = [{'name': 'Administrator', 'node': 'My company'}]
        rows, _ = dedupe_role_names(roles, source_root='My company', target_root='Root')
        self.assertEqual(rows[0]['create_name'], 'Administrator (Migrated)')

    def test_builtin_collision_records_rename_log_entry(self):
        """Bug 78 — when builtin-collision adds the ' (Migrated)' suffix,
        the rename must land in rename_log so verify can pair the source
        role with the renamed target role through rename_map.json. Key
        is raw source-side `node` so it matches validate.py's
        `role.get('node', '')` lookup verbatim."""
        roles = [
            {'name': 'Keeper Administrator', 'node': 'My company'},
            {'name': 'Administrator', 'node': 'My company\\HQ'},
        ]
        rows, renames = dedupe_role_names(
            roles, source_root='My company', target_root='Keeperdemo')
        # Both source roles match BUILTIN_ROLE_NAMES → both get suffixed.
        rename_by_orig = {orig: (src_node, renamed)
                          for orig, src_node, renamed in renames}
        self.assertIn('Keeper Administrator', rename_by_orig)
        src_node, renamed = rename_by_orig['Keeper Administrator']
        # src_node is the SOURCE-side .node verbatim (not target-remapped).
        self.assertEqual(src_node, 'My company')
        self.assertEqual(renamed, 'Keeper Administrator (Migrated)')
        # Nested-source case: still the source-side path, not the leaf.
        self.assertIn('Administrator', rename_by_orig)
        src_node2, renamed2 = rename_by_orig['Administrator']
        self.assertEqual(src_node2, 'My company\\HQ')
        self.assertEqual(renamed2, 'Administrator (Migrated)')

    def test_no_builtin_collision_no_extra_rename_log_entry(self):
        """Non-builtin names must not add to rename_log via the new
        builtin-collision branch."""
        roles = [{'name': 'MIGTEST-Admin', 'node': 'My company'}]
        rows, renames = dedupe_role_names(
            roles, source_root='My company', target_root='Keeperdemo')
        self.assertEqual(rows[0]['create_name'], 'MIGTEST-Admin')
        self.assertEqual(renames, [])

    def test_dedup_rename_log_key_is_raw_source_node(self):
        """Bug 61 fix — `rename_log` second tuple element must be the
        RAW source-side `.node` value (full path verbatim), not the
        post-remap `node` (target_root or leaf). Validate.py looks up
        through `role.get('node', '')` which is the source value
        verbatim. The pre-fix shape stored post-remap node which broke
        the lookup contract: every dedup-renamed role hit NOT FOUND in
        verify even though it was correctly created on target.

        Rehearsal-15 evidence: 7+ false-positive 'NOT FOUND on target'
        FAILs across `Departaments - *` roles — all eliminated by
        making the rename_log key shape consistent with the lookup."""
        roles = [
            # Two source roles colliding on root — dedup adds suffix.
            {'name': 'Auditors', 'node': 'My company'},
            {'name': 'Auditors', 'node': 'My company\\HQ'},
            # Two more colliding deep in tree.
            {'name': 'Departaments - Sales',
             'node': 'My company\\Master Company - Azure'},
            {'name': 'Departaments - Sales', 'node': 'My company\\Alan Demo'},
        ]
        _, renames = dedupe_role_names(
            roles, source_root='My company', target_root='Keeperdemo')
        rename_by_orig_node = {(orig, src_node): renamed
                               for orig, src_node, renamed in renames}
        # Source-root case: src_node verbatim is 'My company',
        # not target_root 'Keeperdemo'.
        self.assertIn(('Auditors', 'My company'), rename_by_orig_node)
        # Nested case: full source path verbatim, not just leaf.
        self.assertIn(('Auditors', 'My company\\HQ'), rename_by_orig_node)
        self.assertIn(
            ('Departaments - Sales', 'My company\\Master Company - Azure'),
            rename_by_orig_node)
        self.assertIn(
            ('Departaments - Sales', 'My company\\Alan Demo'),
            rename_by_orig_node)


class PlanManagedNodesTests(unittest.TestCase):
    def test_emits_one_row_per_managed_node(self):
        roles = [{
            'name': 'MIGTEST-Admin',
            'managed_nodes': [
                {'node_name': 'My company\\Sub', 'cascade': True,
                 'privileges': ['MANAGE_USER', 'MANAGE_ROLES']},
                {'node_name': 'My company\\Other', 'cascade': False,
                 'privileges': []},
            ],
        }]
        plan = plan_managed_nodes(roles, source_root='My company', target_root='Keeperdemo')
        self.assertEqual(len(plan), 2)
        name, node, cascade, privs = plan[0]
        self.assertEqual(name, 'MIGTEST-Admin')
        self.assertEqual(node, 'Keeperdemo\\Sub')  # full-path remap, not leaf
        self.assertEqual(cascade, 'on')
        self.assertEqual(privs, ['MANAGE_USER', 'MANAGE_ROLES'])
        # Second row has empty privs
        self.assertEqual(plan[1][3], [])

    def test_builtin_role_renamed(self):
        roles = [{
            'name': 'Administrator',
            'managed_nodes': [{'node_name': 'My company', 'cascade': False, 'privileges': []}],
        }]
        plan = plan_managed_nodes(roles, source_root='My company', target_root='Root')
        self.assertEqual(plan[0][0], 'Administrator (Migrated)')


class BuildIdToRoleNameTests(unittest.TestCase):
    def test_handles_role_id_or_id_field(self):
        roles = [
            {'role_id': '42', 'name': 'A'},
            {'id': 43, 'name': 'B'},
            {'role_id': '', 'name': 'Skipped'},
        ]
        m = build_id_to_role_name(roles)
        self.assertEqual(m['42'], 'A')
        self.assertEqual(m['43'], 'B')
        self.assertNotIn('', m)


class ClassifyEnforcementTests(unittest.TestCase):
    def test_simple_boolean_becomes_lowercase_string(self):
        d = classify_enforcement('R', 'two_factor_required', True, {})
        self.assertEqual(d, {'phase': 'SIMPLE', 'role': 'R',
                             'key': 'two_factor_required', 'value': 'true'})

    def test_simple_int_becomes_string(self):
        d = classify_enforcement('R', 'min_pw_length', 12, {})
        self.assertEqual(d['value'], '12')

    def test_account_share_resolves_id_to_name(self):
        d = classify_enforcement('R', 'require_account_share', '99',
                                 id_to_name={'99': 'MIGTEST-Admin'})
        self.assertEqual(d['phase'], 'ACCOUNT_SHARE')
        self.assertEqual(d['value'], 'MIGTEST-Admin')

    def test_account_share_builtin_collision_applied(self):
        d = classify_enforcement('R', 'require_account_share', '1',
                                 id_to_name={'1': 'Administrator'})
        self.assertEqual(d['value'], 'Administrator (Migrated)')

    def test_account_share_unresolved_is_skipped(self):
        d = classify_enforcement('R', 'require_account_share', '999', id_to_name={})
        self.assertEqual(d['phase'], 'SKIP')

    def test_account_share_self_reference_is_skipped(self):
        """Bug 47: when the resolved target name equals the role being
        modified, self-reference cannot be applied cross-tenant —
        Commander rejects with a generic 'cannot update enforcement'.
        Skip rather than send to Commander.

        v1.7: opt-in flag used to bypass the more-conservative
        lockout-risk SKIP and exercise the Bug 47 path specifically.
        """
        d = classify_enforcement(
            'Keeper Administrator (Migrated)',
            'require_account_share',
            '34574486732804',
            id_to_name={'34574486732804': 'Keeper Administrator'},
            apply_admin_lockout_risk_enforcements=True,
        )
        self.assertEqual(d['phase'], 'SKIP')
        self.assertIn('self-reference', d['reason'])

    def test_account_share_self_reference_after_collision(self):
        """Bug 47: self-reference detection runs after the built-in-
        collision rename, since the source name 'Administrator'
        becomes 'Administrator (Migrated)' on target.

        v1.7: opt-in flag used to bypass the lockout-risk SKIP."""
        d = classify_enforcement(
            'Administrator (Migrated)',
            'require_account_share', '1',
            id_to_name={'1': 'Administrator'},
            apply_admin_lockout_risk_enforcements=True,
        )
        self.assertEqual(d['phase'], 'SKIP')
        self.assertIn('self-reference', d['reason'])

    def test_bug64_role_without_transfer_account_skipped(self):
        """Bug 64 (Upstream-3 reclassified): require_account_share on
        a non-admin role (lacks TRANSFER_ACCOUNT) is invalid source
        config. Target's stricter validation rejects with generic
        'bad_inputs_enforcement'. Pre-flight SKIP avoids the wasted
        API call and gives a clearer operator-facing reason."""
        meta = {'Departaments - Finance Interns':
                {'has_transfer_account': False}}
        d = classify_enforcement(
            'Departaments - Finance Interns',
            'require_account_share', '99',
            id_to_name={'99': 'Admin - Exclusive Account Transfer'},
            source_role_meta=meta,
        )
        self.assertEqual(d['phase'], 'SKIP')
        self.assertIn('TRANSFER_ACCOUNT', d['reason'])
        self.assertIn('Bug 64', d['reason'])

    def test_bug64_role_with_transfer_account_proceeds_to_account_share(self):
        meta = {'MIGTEST-Admin': {'has_transfer_account': True}}
        d = classify_enforcement(
            'MIGTEST-Admin', 'require_account_share', '99',
            id_to_name={'99': 'Other-Admin'},
            source_role_meta=meta,
        )
        self.assertEqual(d['phase'], 'ACCOUNT_SHARE')
        self.assertEqual(d['value'], 'Other-Admin')

    def test_bug64_meta_optional_back_compat(self):
        """When source_role_meta is None, classify behaves like pre-fix
        (proceeds to id_to_name resolution). Keeps tests + pipelines
        that don't pass meta unchanged."""
        d = classify_enforcement(
            'Some Role', 'require_account_share', '99',
            id_to_name={'99': 'Admin'},
        )
        self.assertEqual(d['phase'], 'ACCOUNT_SHARE')

    def test_bug64_meta_lookup_handles_builtin_suffix(self):
        """classify sees the SUFFIX'd target name (e.g. 'Keeper
        Administrator (Migrated)') but build_source_role_meta indexes
        BOTH spellings, so the privilege check still fires.

        v1.7: opt-in flag used to bypass the lockout-risk SKIP, which
        otherwise short-circuits before the meta-lookup runs."""
        meta = build_source_role_meta([{
            'name': 'Keeper Administrator',
            'managed_nodes': [{'privileges': ['TRANSFER_ACCOUNT']}],
        }])
        d = classify_enforcement(
            'Keeper Administrator (Migrated)',
            'require_account_share', '99',
            id_to_name={'99': 'Other-Admin'},
            source_role_meta=meta,
            apply_admin_lockout_risk_enforcements=True,
        )
        # Has transfer_account → not pre-flight skipped (proceeds).
        self.assertEqual(d['phase'], 'ACCOUNT_SHARE')


class LockoutRiskEnforcementSkipTests(unittest.TestCase):
    """v1.7 — lockout-risk enforcements default-skip on builtin-admin
    roles. The 2026-04-26 `jlima+demo2` lockout incident
    (`restrict_ip_addresses` mis-applied) demonstrated that cross-tenant
    drift on these enforcements can lock the operator out of the target
    before they can fix it. Default behavior: SKIP with operator-handoff
    reason. Opt back in via `apply_admin_lockout_risk_enforcements=True`.
    """

    def test_require_account_share_on_builtin_admin_skipped_by_default(self):
        d = classify_enforcement(
            'Administrator', 'require_account_share', '99',
            id_to_name={'99': 'Other-Admin'})
        self.assertEqual(d['phase'], 'SKIP')
        self.assertIn('lockout-risk', d['reason'])
        self.assertIn('Administrator', d['reason'])
        self.assertIn('--apply-admin-lockout-risk-enforcements',
                      d['reason'])

    def test_restrict_ip_addresses_on_builtin_admin_skipped_by_default(self):
        """The 2026-04-26 incident vector — default-skip blocks the
        repeat. `restrict_ip_addresses` is CLI-supported (string-typed
        in Commander), so it routes through classify_enforcement."""
        d = classify_enforcement(
            'Keeper Administrator', 'restrict_ip_addresses',
            '10.0.0.0/8,192.168.1.0/24', id_to_name={})
        self.assertEqual(d['phase'], 'SKIP')
        self.assertIn('lockout-risk', d['reason'])

    def test_master_password_reentry_on_builtin_admin_skipped_by_default(self):
        """FILE-typed lockout-risk key — guard fires before the FILE
        phase routing."""
        d = classify_enforcement(
            'Enterprise Admin', 'master_password_reentry',
            '{"interval_minutes": 30}', id_to_name={})
        self.assertEqual(d['phase'], 'SKIP')
        self.assertIn('lockout-risk', d['reason'])

    def test_two_factor_by_ip_on_builtin_admin_skipped_by_default(self):
        d = classify_enforcement(
            'Admin', 'two_factor_by_ip',
            '{"allowed": ["10.0.0.0/8"]}', id_to_name={})
        self.assertEqual(d['phase'], 'SKIP')

    def test_lockout_risk_on_non_builtin_role_proceeds_normally(self):
        """Non-builtin roles still get lockout-risk enforcements
        applied. The narrow-scope guard intentionally trusts that
        operators migrating IP-locked technician roles know what
        they're doing for non-admin roles."""
        d = classify_enforcement(
            'My Custom Role', 'restrict_ip_addresses',
            '10.0.0.0/8', id_to_name={})
        self.assertEqual(d['phase'], 'SIMPLE')
        self.assertEqual(d['value'], '10.0.0.0/8')

    def test_lockout_risk_with_opt_in_flag_proceeds(self):
        """When `apply_admin_lockout_risk_enforcements=True`, restore
        pre-v1.7 behavior — apply the enforcement on the builtin-admin
        role (assuming the operator has audited the value)."""
        d = classify_enforcement(
            'Administrator', 'restrict_ip_addresses',
            '10.0.0.0/8', id_to_name={},
            apply_admin_lockout_risk_enforcements=True)
        self.assertEqual(d['phase'], 'SIMPLE')

    def test_lockout_risk_check_handles_migrated_suffix(self):
        """A builtin-admin source role gets renamed to 'X (Migrated)'
        on target. The guard must see through the suffix."""
        d = classify_enforcement(
            'Keeper Administrator (Migrated)', 'restrict_ip_addresses',
            '10.0.0.0/8', id_to_name={})
        self.assertEqual(d['phase'], 'SKIP')

    def test_non_lockout_risk_key_on_builtin_admin_proceeds(self):
        """Only the 4 LOCKOUT_RISK_ENFORCEMENTS keys are guarded.
        Other enforcements on builtin-admin roles apply normally."""
        d = classify_enforcement(
            'Administrator', 'two_factor_required', True, id_to_name={})
        self.assertEqual(d['phase'], 'SIMPLE')
        self.assertEqual(d['value'], 'true')

    def test_default_kwarg_preserves_back_compat(self):
        """Existing callers that don't pass
        `apply_admin_lockout_risk_enforcements` get the new default
        (False) → lockout-risk keys SKIP on builtin-admin roles. This
        is the intentional behavior change in v1.7."""
        d = classify_enforcement(
            'Executive', 'require_account_share', '99',
            id_to_name={'99': 'Other-Admin'})
        self.assertEqual(d['phase'], 'SKIP')


class PlanManagedNodesRenameAwareTests(unittest.TestCase):
    """Bug 67 (rehearsal-11) — when source roles get dedup-renamed by
    step_roles (duplicate-name disambiguation by source-node suffix),
    plan_managed_nodes must emit the RENAMED target name so the
    caller's `role_name in created_roles` gate finds them. Pre-fix:
    every renamed role's managed_node grants got SKIPed as 'role
    never created on target'."""

    def test_rename_lookup_replaces_role_name(self):
        # Bug 67 v2 — lookup key uses POST-REMAP target node, matching
        # dedupe_role_names. role.node='My company\\X' resolves to
        # leaf 'X' for the rename key.
        roles = [{
            'name': 'Departaments - Finance Interns',
            'node': 'My company\\Master Company - Azure SSO Cloud Connector',
            'managed_nodes': [{
                'node_name': 'Subsidiary 1', 'cascade': True,
                'privileges': ['MANAGE_USER'],
            }],
        }]
        rename_lookup = {
            # KEY: leaf_of(role.node) when role.node != source_root.
            ('Departaments - Finance Interns',
             'Master Company - Azure SSO Cloud Connector'):
                'Departaments - Finance Interns (Master Company - Azure SSO Cloud Connector)',
        }
        out = plan_managed_nodes(roles, source_root='My company',
                                  target_root='Keeperdemo',
                                  role_rename_lookup=rename_lookup)
        self.assertEqual(len(out), 1)
        # Emits RENAMED target name, not the original 'Departaments -
        # Finance Interns'.
        self.assertEqual(
            out[0][0],
            'Departaments - Finance Interns (Master Company - Azure SSO Cloud Connector)')

    def test_rename_lookup_uses_target_root_for_root_scoped_role(self):
        # Bug 67 v2 — when role.node == source_root, key uses target_root.
        roles = [{
            'name': 'Departaments - Staging admin',
            'node': 'My company',
            'managed_nodes': [{'node_name': 'Y', 'privileges': []}],
        }]
        rename_lookup = {
            ('Departaments - Staging admin', 'Keeperdemo'):
                'Departaments - Staging admin (Keeperdemo)',
        }
        out = plan_managed_nodes(roles, source_root='My company',
                                  target_root='Keeperdemo',
                                  role_rename_lookup=rename_lookup)
        self.assertEqual(out[0][0],
                          'Departaments - Staging admin (Keeperdemo)')

    def test_no_rename_falls_back_to_builtin_collision(self):
        # When the (name, node) pair isn't in the rename map, fall
        # back to the existing builtin-collision rename.
        roles = [{
            'name': 'Keeper Administrator',
            'node': 'My company',
            'managed_nodes': [{'node_name': 'X', 'privileges': []}],
        }]
        out = plan_managed_nodes(roles, source_root='My company',
                                  target_root='Keeperdemo')
        # Builtin collision still applies.
        self.assertEqual(out[0][0], 'Keeper Administrator (Migrated)')

    def test_empty_rename_lookup_is_back_compat(self):
        # Pre-Bug-67 callers pass no rename_lookup → behavior unchanged.
        roles = [{
            'name': 'Plain-Role', 'node': 'X',
            'managed_nodes': [{'node_name': 'Y', 'privileges': []}],
        }]
        out = plan_managed_nodes(roles)
        self.assertEqual(out[0][0], 'Plain-Role')


class BuildSourceRoleMetaTests(unittest.TestCase):
    """Bug 64 — index source roles by privilege metadata for the
    require_account_share pre-flight check."""

    def test_role_with_transfer_account_recorded(self):
        meta = build_source_role_meta([{
            'name': 'MIGTEST-Admin',
            'managed_nodes': [
                {'privileges': ['MANAGE_USER', 'TRANSFER_ACCOUNT']},
            ],
        }])
        self.assertTrue(meta['MIGTEST-Admin']['has_transfer_account'])

    def test_role_without_managed_nodes_lacks_transfer_account(self):
        meta = build_source_role_meta([{
            'name': 'Departaments - Finance Interns',
            'managed_nodes': [],
        }])
        self.assertFalse(
            meta['Departaments - Finance Interns']['has_transfer_account'])

    def test_builtin_collision_indexed_under_both_names(self):
        meta = build_source_role_meta([{
            'name': 'Keeper Administrator',
            'managed_nodes': [{'privileges': ['TRANSFER_ACCOUNT']}],
        }])
        self.assertIn('Keeper Administrator', meta)
        self.assertIn('Keeper Administrator (Migrated)', meta)
        # Both spellings carry the same privilege snapshot.
        self.assertTrue(
            meta['Keeper Administrator (Migrated)']['has_transfer_account'])

    def test_case_insensitive_privilege_match(self):
        # Source data sometimes carries lowercase privilege names; the
        # check normalizes case.
        meta = build_source_role_meta([{
            'name': 'X',
            'managed_nodes': [{'privileges': ['transfer_account']}],
        }])
        self.assertTrue(meta['X']['has_transfer_account'])

    def test_account_share_cross_reference_passes_through(self):
        """Bug 47: non-self references still produce ACCOUNT_SHARE
        phase unchanged — only same-name cases are skipped."""
        d = classify_enforcement(
            'Some Other Role',
            'require_account_share', '99',
            id_to_name={'99': 'Keeper Administrator'},
        )
        self.assertEqual(d['phase'], 'ACCOUNT_SHARE')
        self.assertEqual(d['value'], 'Keeper Administrator (Migrated)')

    def test_file_enforcement_serializes_dict_to_json(self):
        d = classify_enforcement('R', 'generated_password_complexity',
                                 {'minLength': 12, 'requireDigits': True}, {})
        self.assertEqual(d['phase'], 'FILE')
        self.assertIn('"minLength":', d['body'])

    def test_file_enforcement_preserves_string_body(self):
        raw = '{"some": "json"}'
        d = classify_enforcement('R', 'master_password_reentry', raw, {})
        self.assertEqual(d['body'], raw)

    def test_file_enforcement_empty_value_skipped(self):
        self.assertEqual(classify_enforcement('R', 'two_factor_by_ip', None, {})['phase'], 'SKIP')


class ParseStepRangeTests(unittest.TestCase):
    """Regression: a typo like '0_5' used to silently run the whole 0-12
    pipeline (destructive). Must raise instead."""

    def setUp(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import StructureCommand
        self.cmd = StructureCommand()

    def test_valid_range(self):
        self.assertEqual(self.cmd._parse_step_range('0-12'), (0, 12))
        self.assertEqual(self.cmd._parse_step_range('4-6'), (4, 6))

    def test_typo_raises(self):
        with self.assertRaises(ValueError):
            self.cmd._parse_step_range('0_5')

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            self.cmd._parse_step_range('')

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            self.cmd._parse_step_range('0-99')  # hi > 12
        with self.assertRaises(ValueError):
            self.cmd._parse_step_range('-1-5')  # lo < 0
        with self.assertRaises(ValueError):
            self.cmd._parse_step_range('5-3')   # lo > hi


class StructureRestoreStep4Tests(unittest.TestCase):
    def test_step_roles_creates_with_new_user_flag(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company',
                                   target_root='Keeperdemo')
        restore.step_roles([
            {'name': 'MIGTEST-Default', 'node': 'My company\\MIGRATION-TEST-NODE',
             'default_role': True},
            {'name': 'MIGTEST-Basic', 'node': 'My company\\MIGRATION-TEST-NODE'},
        ])
        role_calls = [c for c in client.calls if c[0] == 'create_role']
        self.assertEqual(role_calls[0][1],
                         ('MIGTEST-Default', 'MIGRATION-TEST-NODE', 'on'))
        self.assertEqual(role_calls[1][1],
                         ('MIGTEST-Basic', 'MIGRATION-TEST-NODE', 'off'))

    def test_step_roles_resolves_builtin_collision(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        restore.step_roles([{'name': 'Administrator', 'node': 'My company'}])
        self.assertEqual(client.calls[0][1][0], 'Administrator (Migrated)')


class StructureRestoreStep5Tests(unittest.TestCase):
    def test_adds_managed_node_then_each_privilege(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        restore.step_managed_nodes([{
            'name': 'MIGTEST-Admin',
            'managed_nodes': [{
                'node_name': 'My company\\Sub', 'cascade': True,
                'privileges': ['MANAGE_USER', 'MANAGE_ROLES'],
            }],
        }])
        kinds = [c[0] for c in client.calls]
        self.assertEqual(kinds, ['add_role_managed_node',
                                 'add_role_privilege',
                                 'add_role_privilege'])
        self.assertEqual(client.calls[0][1], ('MIGTEST-Admin', 'Root\\Sub', 'on'))
        self.assertEqual(client.calls[1][1], ('MIGTEST-Admin', 'MANAGE_USER', 'Root\\Sub'))


class StructureRestoreStep6Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dispatches_simple_file_and_skip_phases(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        # Bug 47 (rehearsal-4): require_account_share='42' resolves to
        # 'MIGTEST-Admin' which equals the role being modified — self-
        # reference. classify_enforcement now returns phase=SKIP for
        # self-ref instead of ACCOUNT_SHARE (which the old test
        # counted as SIMPLE). Updated counts:
        #   require_two_factor=True            → SIMPLE
        #   master_password_minimum_length=12  → SIMPLE
        #   require_account_share='42' (self)  → SKIP   (was: ACCOUNT_SHARE)
        #   generated_password_complexity      → FILE
        roles = [
            {'role_id': '42', 'name': 'MIGTEST-Admin', 'enforcements': {
                'require_two_factor': True,
                'generated_password_complexity': {'minLength': 12},
                'require_account_share': '42',      # resolves to MIGTEST-Admin → self-ref
                # Use an in-dict key whose type would still go SIMPLE
                'master_password_minimum_length': 12,
            }},
        ]
        summary = restore.step_enforcements(roles, complexity_dir=self.tmp)
        self.assertEqual(summary['simple'], 2)   # boolean + integer
        self.assertEqual(summary['file'], 1)     # complexity dict
        self.assertEqual(summary['skipped'], 1)  # self-ref account_share
        files = os.listdir(self.tmp)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].startswith('MIGTEST-Admin_generated_password_complexity'))

    def test_unresolved_account_share_is_skipped(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        roles = [{
            'role_id': '42', 'name': 'MIGTEST-Admin',
            'enforcements': {'require_account_share': '999'},
        }]
        summary = restore.step_enforcements(roles, complexity_dir=self.tmp)
        self.assertEqual(summary['skipped'], 1)
        # No calls made for this enforcement
        self.assertEqual(len(client.calls), 0)

    def test_direct_api_fallback_invoked_for_unsupported_types(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        # 'some_unknown_json_type' is not in Commander's ENFORCEMENTS dict,
        # so is_cli_unsupported → routes to direct_api_fn.
        captured = {}

        def fake_direct(role_name, direct_enfs):
            captured['role'] = role_name
            captured['enfs'] = direct_enfs
            return {k: (True, 'OK') for k in direct_enfs}

        roles = [{
            'role_id': '42', 'name': 'MIGTEST-Admin',
            'enforcements': {
                'require_two_factor': True,           # CLI-supported → SIMPLE
                'some_unknown_json_type': {'a': 1},   # unsupported → direct API
            },
        }]
        summary = restore.step_enforcements(
            roles, complexity_dir=self.tmp, direct_api_fn=fake_direct,
        )
        self.assertEqual(summary['simple'], 1)       # require_two_factor
        self.assertEqual(summary['direct'], 1)       # some_unknown_json_type
        self.assertEqual(summary['failed'], 0)
        self.assertEqual(captured['role'], 'MIGTEST-Admin')
        self.assertEqual(captured['enfs'],
                         {'some_unknown_json_type': {'a': 1}})

    def test_direct_api_unsupported_skipped_when_fn_missing(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        roles = [{
            'role_id': '42', 'name': 'MIGTEST-Admin',
            'enforcements': {'some_unknown_json_type': {'a': 1}},
        }]
        # No direct_api_fn → skipped gracefully rather than failing
        summary = restore.step_enforcements(roles, complexity_dir=self.tmp)
        self.assertEqual(summary['skipped'], 1)
        self.assertEqual(summary['failed'], 0)

    def test_lockout_risk_direct_api_keys_skipped_pre_partition(self):
        """v1.7 critical: `master_password_reentry` (json) and
        `two_factor_by_ip` (jsonarray) route through direct_api_fn,
        not classify_enforcement. The default-skip rule must hoist
        ABOVE the cli/direct partition to cover them. Pre-fix
        (rev1) put the guard inside classify_enforcement only —
        these two keys silently bypassed and got written to target.
        Code-reviewer caught the gap before live rehearsal.

        Test asserts: on a builtin-admin role, the direct-API keys
        in `LOCKOUT_RISK_ENFORCEMENTS` are SKIPPED at structure-time
        — `direct_api_fn` is never called for them — and a per-key
        SKIP audit row is emitted."""
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company',
                                    target_root='Root')
        captured_calls = []

        def fake_direct(role_name, direct_enfs):
            captured_calls.append((role_name, dict(direct_enfs)))
            return {k: (True, 'OK') for k in direct_enfs}

        roles = [{
            'role_id': '1', 'name': 'Administrator',
            'enforcements': {
                'master_password_reentry': '{"interval": 30}',  # json
                'two_factor_by_ip': '[{"cidr": "10.0.0.0/8"}]',  # jsonarray
                'require_two_factor': True,                      # SIMPLE — should still apply
            },
        }]
        summary = restore.step_enforcements(
            roles, complexity_dir=self.tmp, direct_api_fn=fake_direct,
        )
        # Direct-API was called only for non-lockout-risk keys (or
        # not at all if the only direct-typed keys were lockout-risk).
        called_keys = set()
        for _, enfs in captured_calls:
            called_keys.update(enfs.keys())
        self.assertNotIn('master_password_reentry', called_keys,
                         'master_password_reentry must NOT reach the '
                         'direct-API path on a builtin-admin role with '
                         'apply_admin_lockout_risk_enforcements=False')
        self.assertNotIn('two_factor_by_ip', called_keys,
                         'two_factor_by_ip must NOT reach the '
                         'direct-API path on a builtin-admin role with '
                         'apply_admin_lockout_risk_enforcements=False')
        # The non-lockout-risk SIMPLE enforcement still applied.
        self.assertEqual(summary['simple'], 1)
        # Both lockout-risk keys count as skipped at structure-time.
        self.assertGreaterEqual(summary['skipped'], 2)
        # Per-key SKIP audit rows emitted (T2.2 verify-side
        # consumption depends on these).
        skip_rows = [r for r in restore.results
                     if r.category == 'enforcement'
                     and r.action == 'classify-skip']
        skip_keys = {r.name.rsplit('.', 1)[1] for r in skip_rows}
        self.assertIn('master_password_reentry', skip_keys)
        self.assertIn('two_factor_by_ip', skip_keys)

    def test_lockout_risk_direct_api_keys_applied_with_opt_in(self):
        """When `apply_admin_lockout_risk_enforcements=True`, the
        direct-API keys flow through the direct-API path normally.
        Mirrors the CLI-path opt-in test, validating that the new
        top-level filter respects the flag."""
        client = FakeClient()
        restore = StructureRestore(
            client, source_root='My company', target_root='Root',
            apply_admin_lockout_risk_enforcements=True)
        captured_calls = []

        def fake_direct(role_name, direct_enfs):
            captured_calls.append((role_name, dict(direct_enfs)))
            return {k: (True, 'OK') for k in direct_enfs}

        roles = [{
            'role_id': '1', 'name': 'Administrator',
            'enforcements': {
                'master_password_reentry': '{"interval": 30}',
                'two_factor_by_ip': '[{"cidr": "10.0.0.0/8"}]',
            },
        }]
        restore.step_enforcements(
            roles, complexity_dir=self.tmp, direct_api_fn=fake_direct,
        )
        called_keys = set()
        for _, enfs in captured_calls:
            called_keys.update(enfs.keys())
        self.assertIn('master_password_reentry', called_keys)
        self.assertIn('two_factor_by_ip', called_keys)

    def test_lockout_risk_on_non_builtin_role_reaches_direct_api(self):
        """The default-skip rule is scoped to builtin-admin roles. A
        non-builtin role with `master_password_reentry` set still
        routes to direct-API normally (operators migrating IP-locked
        technician roles know what they're doing for non-admin)."""
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company',
                                    target_root='Root')
        captured_calls = []

        def fake_direct(role_name, direct_enfs):
            captured_calls.append((role_name, dict(direct_enfs)))
            return {k: (True, 'OK') for k in direct_enfs}

        roles = [{
            'role_id': '50', 'name': 'Engineering Lead',
            'enforcements': {'master_password_reentry': '{"a": 1}'},
        }]
        restore.step_enforcements(
            roles, complexity_dir=self.tmp, direct_api_fn=fake_direct,
        )
        called_keys = set()
        for _, enfs in captured_calls:
            called_keys.update(enfs.keys())
        self.assertIn('master_password_reentry', called_keys)


class TargetNodeForUserTests(unittest.TestCase):
    def test_source_root_user_is_skipped(self):
        # Users sitting on the root need no --node flag; bash script skips them.
        self.assertEqual(
            target_node_for_user('My company', 'My company', 'Keeperdemo'),
            '',
        )

    def test_leaf_returned_for_normal_subtree(self):
        self.assertEqual(
            target_node_for_user('My company\\Sub', 'My company', 'Keeperdemo'),
            'Sub',
        )

    def test_leaf_matching_source_root_is_skipped(self):
        # Edge case: src_node leaf happens to equal source root string
        self.assertEqual(
            target_node_for_user('Thing\\My company', 'My company', 'Keeperdemo'),
            '',
        )

    def test_leaf_matching_target_root_is_skipped(self):
        self.assertEqual(
            target_node_for_user('A\\Keeperdemo', 'My company', 'Keeperdemo'),
            '',
        )

    def test_empty_returns_empty(self):
        self.assertEqual(target_node_for_user('', 'My company', 'Keeperdemo'), '')


class PlanUserNodeAssignmentsTests(unittest.TestCase):
    def test_skips_root_users_and_emits_leaf_for_others(self):
        users = [
            {'email': 'root@x', 'node': 'My company'},  # root → mapped to target root, skipped
            {'email': 'sub@x', 'node': 'My company\\Team'},
            {'email': '', 'node': 'My company\\Team'},  # no email
        ]
        pairs = list(plan_user_node_assignments(users, 'My company', 'My company'))
        # sub@x goes to 'Team'; root@x target is 'My company' which equals target root → skipped
        self.assertEqual(pairs, [('sub@x', 'Team')])


class PlanUserTeamAssignmentsTests(unittest.TestCase):
    def test_flattens_per_team(self):
        users = [
            {'email': 'a@x', 'teams': ['T1', 'T2']},
            {'email': 'b@x', 'teams': ['T1']},
            {'email': 'c@x', 'teams': []},
            {'email': '', 'teams': ['Ignored']},
        ]
        pairs = list(plan_user_team_assignments(users))
        self.assertEqual(pairs, [('a@x', 'T1'), ('a@x', 'T2'), ('b@x', 'T1')])


class PlanRoleUserAssignmentsTests(unittest.TestCase):
    def test_builtin_collision_applied_to_role_name(self):
        roles = [
            {'name': 'Administrator', 'users': [{'username': 'a@x'}]},
            {'name': 'MIGTEST-Admin', 'users': [
                {'username': 'b@x'}, {'email': 'c@x'},  # tolerates either key
            ]},
        ]
        pairs = list(plan_role_user_assignments(roles))
        self.assertIn(('Administrator (Migrated)', 'a@x'), pairs)
        self.assertIn(('MIGTEST-Admin', 'b@x'), pairs)
        self.assertIn(('MIGTEST-Admin', 'c@x'), pairs)


class PlanRoleTeamAssignmentsTests(unittest.TestCase):
    def test_admin_flag_reflects_managed_nodes(self):
        roles = [
            {'name': 'Admin-Role', 'managed_nodes': [{'node_name': 'N'}],
             'teams': [{'team_name': 'T1'}]},
            {'name': 'Team-Role', 'teams': [{'name': 'T2'}]},
        ]
        plan = list(plan_role_team_assignments(roles))
        self.assertEqual(plan, [('Admin-Role', 'T1', True),
                                ('Team-Role', 'T2', False)])

    def test_string_team_format_from_live_inventory(self):
        """Bug 11 regression: live_inventory.py emits role.teams as a
        list of plain strings; older/alternative producers emit dicts.
        Both must yield assignments — previously the string path was
        silently dropped (every team-role link missed)."""
        roles = [
            {'name': 'Basic', 'teams': ['Team-Alpha', 'Team-Beta']},
            {'name': 'Mixed', 'teams': ['Team-Gamma', {'name': 'Team-Delta'}]},
        ]
        plan = list(plan_role_team_assignments(roles))
        self.assertEqual(plan, [
            ('Basic', 'Team-Alpha', False),
            ('Basic', 'Team-Beta', False),
            ('Mixed', 'Team-Gamma', False),
            ('Mixed', 'Team-Delta', False),
        ])

    def test_unknown_team_format_silently_skipped(self):
        """Defensive: anything that's not a dict or string (e.g. int)
        yields no assignment, doesn't crash."""
        roles = [{'name': 'Weird', 'teams': [42, None, '', 'Real-Team']}]
        plan = list(plan_role_team_assignments(roles))
        self.assertEqual(plan, [('Weird', 'Real-Team', False)])

    def test_strings_with_whitespace_stripped(self):
        roles = [{'name': 'Trim', 'teams': ['  Team-Pad  ']}]
        plan = list(plan_role_team_assignments(roles))
        self.assertEqual(plan, [('Trim', 'Team-Pad', False)])

    def test_bug83_role_rename_lookup_resolves_dedup_renamed_role(self):
        """Bug 83 — when a source role got dedup-renamed (e.g.
        'Departaments - Sales' at two source nodes → '...(Master
        Company)' and '...(Alan Demo)' on target), team assignments
        must route to the renamed target role. Pre-fix, every
        dedup-renamed role's team-membership got SKIPped at the
        gate ('target role never created — call suppressed')."""
        roles = [
            {'name': 'Sales', 'node': 'My company\\HQ',
             'teams': ['Marketing']},
        ]
        # Source role got dedup-renamed.
        role_rename_lookup = {
            ('Sales', 'My company\\HQ'): 'Sales (HQ)',
        }
        plan = list(plan_role_team_assignments(
            roles, role_rename_lookup=role_rename_lookup))
        self.assertEqual(plan, [('Sales (HQ)', 'Marketing', False)])

    def test_bug83_team_rename_lookup_emits_one_per_candidate(self):
        """Bug 83 — source role.teams carries only team NAMES (no
        node), so when team got dedup-renamed at multiple source
        nodes, plan emits one tuple per candidate. The caller's
        gate then picks the one that matches a created team."""
        roles = [{'name': 'R', 'teams': ['DBA Team']}]
        team_rename_by_name = {
            'DBA Team': ['DBA Team (Master Company)', 'DBA Team (Alan Demo)'],
        }
        plan = list(plan_role_team_assignments(
            roles, team_rename_lookup_by_name=team_rename_by_name))
        self.assertEqual(set(plan), {
            ('R', 'DBA Team (Master Company)', False),
            ('R', 'DBA Team (Alan Demo)', False),
        })

    def test_bug83_unrenamed_team_passes_through(self):
        """No rename lookup entry → use source name verbatim
        (preserves behavior for un-renamed teams)."""
        roles = [{'name': 'R', 'teams': ['Plain Team']}]
        team_rename_by_name = {'OtherTeam': ['OtherTeam (X)']}
        plan = list(plan_role_team_assignments(
            roles, team_rename_lookup_by_name=team_rename_by_name))
        self.assertEqual(plan, [('R', 'Plain Team', False)])

    def test_bug83_user_plan_resolves_dedup_renamed_role(self):
        """Bug 83 companion — plan_role_user_assignments resolves
        dedup-renamed source roles too."""
        roles = [
            {'name': 'Auditors', 'node': 'My company\\Sub1',
             'users': [{'username': 'a@x'}]},
            {'name': 'Auditors', 'node': 'My company\\Sub2',
             'users': [{'email': 'b@x'}]},
        ]
        role_rename_lookup = {
            ('Auditors', 'My company\\Sub1'): 'Auditors (Sub1)',
            ('Auditors', 'My company\\Sub2'): 'Auditors (Sub2)',
        }
        pairs = list(plan_role_user_assignments(
            roles, role_rename_lookup=role_rename_lookup))
        self.assertEqual(set(pairs), {
            ('Auditors (Sub1)', 'a@x'),
            ('Auditors (Sub2)', 'b@x'),
        })


class StructureRestoreStep7To9Tests(unittest.TestCase):
    def _restore(self, **kwargs):
        client = FakeClient(**kwargs)
        return client, StructureRestore(
            client, source_root='My company', target_root='Keeperdemo')

    def test_step_user_nodes_uses_leaf_name(self):
        client, restore = self._restore()
        restore.step_user_nodes([
            {'email': 'a@x', 'node': 'My company\\Dept\\Team'},
        ])
        self.assertEqual(client.calls[0][1], ('a@x', 'Team'))

    def test_step_user_nodes_gates_on_created_nodes(self):
        """When step_nodes ran and only 'Good' landed on target,
        step_user_nodes should suppress the user→missing-node call as
        SKIPPED instead of letting Commander cascade through."""
        client, restore = self._restore()
        restore.created_nodes = {'Good'}
        restore.step_user_nodes([
            {'email': 'a@x', 'node': 'My company\\Dept\\Good'},
            {'email': 'b@x', 'node': 'My company\\Dept\\Missing'},
        ])
        self.assertEqual(len(client.calls), 1)
        skipped = [r for r in restore.results
                    if r.status == StepResult.SKIPPED and 'Missing' in r.name]
        self.assertEqual(len(skipped), 1)
        self.assertIn('suppressed', skipped[0].notes)

    def test_step_user_nodes_gate_off_when_set_empty(self):
        """Backwards compat: empty created_nodes means caller didn't run
        step_nodes (plan-dir path); every assignment proceeds."""
        client, restore = self._restore()
        restore.step_user_nodes([
            {'email': 'a@x', 'node': 'My company\\Dept\\Anything'},
        ])
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(restore.counters['SKIPPED'], 0)

    def test_step_user_teams_iterates_teams(self):
        client, restore = self._restore()
        restore.step_user_teams([{'email': 'a@x', 'teams': ['T1', 'T2']}])
        self.assertEqual(len(client.calls), 2)

    def test_step_user_teams_gates_on_created_teams(self):
        """Mirror of node gate: suppress user→missing-team cascades."""
        client, restore = self._restore()
        restore.created_teams = {'T1'}
        restore.step_user_teams([
            {'email': 'a@x', 'teams': ['T1', 'T2']},
        ])
        self.assertEqual(len(client.calls), 1)
        skipped = [r for r in restore.results
                    if r.status == StepResult.SKIPPED and 'T2' in r.name]
        self.assertEqual(len(skipped), 1)
        self.assertIn('suppressed', skipped[0].notes)

    def test_step_role_users_records_successes_and_failures(self):
        client = FakeClient(fail_on={'add_user_to_role'})
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        restore.step_role_users([
            {'name': 'MIGTEST-R', 'users': [{'username': 'a@x'}]},
        ])
        self.assertEqual(restore.counters['FAILED'], 1)

    def test_step_role_users_gates_on_created_roles(self):
        """When step_roles failed to create a role, role→user adds
        targeting that role suppress to one SKIPPED per (user,role)
        pair."""
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company',
                                    target_root='Root')
        restore.created_roles = {'Good-Role'}
        restore.step_role_users([
            {'name': 'Good-Role',
             'users': [{'username': 'a@x'}]},
            {'name': 'Missing-Role',
             'users': [{'username': 'b@x'}, {'username': 'c@x'}]},
        ])
        # Good gets through (1 call); Missing's two users both suppress.
        self.assertEqual(len(client.calls), 1)
        suppressed = [r for r in restore.results
                       if r.status == StepResult.SKIPPED
                       and 'Missing-Role' in r.name]
        self.assertEqual(len(suppressed), 2)
        self.assertIn('suppressed', suppressed[0].notes)


class StructureRestoreStep10Tests(unittest.TestCase):
    def test_admin_roles_are_skipped_not_attempted(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        restore.step_role_teams([
            {'name': 'Admin-Role', 'managed_nodes': [{'node_name': 'X'}],
             'teams': [{'team_name': 'T1'}]},
            {'name': 'Plain-Role', 'teams': [{'team_name': 'T2'}]},
        ])
        # One SKIPPED for the admin role, one SUCCESS for the non-admin
        self.assertEqual(restore.counters['SKIPPED'], 1)
        self.assertEqual(restore.counters['SUCCESS'], 1)
        # Only the non-admin call made it to the client
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0][1], ('Plain-Role', 'T2'))

    def test_step_role_teams_gates_on_created_teams(self):
        """Mirror of step_managed_nodes gate: when step_teams left a team
        uncreated, downstream role→team adds for that team should be
        recorded SKIPPED, not pushed through to Commander."""
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company',
                                    target_root='Root')
        restore.created_roles = {'Plain-Role'}
        restore.created_teams = {'T1'}
        restore.step_role_teams([
            {'name': 'Plain-Role',
             'teams': [{'team_name': 'T1'}, {'team_name': 'T2'}]},
        ])
        # T1 succeeds, T2 suppressed
        self.assertEqual(len(client.calls), 1)
        suppressed = [r for r in restore.results
                       if r.status == StepResult.SKIPPED
                       and 'T2' in r.name and 'suppressed' in r.notes]
        self.assertEqual(len(suppressed), 1)

    def test_step_role_teams_gates_on_created_roles(self):
        """When step_roles failed to create a role, role→team adds
        targeting that role should suppress to one SKIPPED per pair."""
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company',
                                    target_root='Root')
        restore.created_roles = {'Good-Role'}
        restore.created_teams = {'T1'}
        restore.step_role_teams([
            {'name': 'Missing-Role', 'teams': [{'team_name': 'T1'}]},
        ])
        self.assertEqual(len(client.calls), 0)
        suppressed = [r for r in restore.results
                       if r.status == StepResult.SKIPPED
                       and 'Missing-Role' in r.name]
        self.assertEqual(len(suppressed), 1)
        self.assertIn('role never created', suppressed[0].notes)


class StructureRestoreStep11Tests(unittest.TestCase):
    def test_success_on_first_try(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        restore.step_sf_membership('/path/full.json', '/path/flat.json')
        self.assertEqual(restore.counters['SUCCESS'], 1)
        self.assertEqual(len(client.calls), 1)

    def test_fallback_to_flat_when_primary_fails(self):
        class OneFailClient(FakeClient):
            def __init__(self):
                super().__init__()
                self.call_count = 0

            def apply_membership(self, path):
                self.call_count += 1
                ok = self.call_count > 1  # first call fails, second succeeds
                self.calls.append(('apply_membership', (path,)))
                return ok

        client = OneFailClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        restore.step_sf_membership('/primary.json', '/fallback.json')
        self.assertEqual(restore.counters['SUCCESS'], 1)
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(restore.results[0].notes, 'Flattened fallback')

    def test_missing_path_records_skipped(self):
        client = FakeClient()
        restore = StructureRestore(client, source_root='My company', target_root='Root')
        restore.step_sf_membership(None)
        self.assertEqual(restore.counters['SKIPPED'], 1)


class StructureRestoreStep12Tests(unittest.TestCase):
    def test_validate_reports_match_per_entity(self):
        class CountingClient(FakeClient):
            def count_nodes(self, scope_node=''):
                return 5
            def count_teams(self, scope_node=''):
                return 3
            def count_roles(self, scope_node=''):
                return 2
            def count_users(self, scope_node=''):
                return 10

        client = CountingClient()
        restore = StructureRestore(client, source_root='My company',
                                   target_root='Root', scope_node='Sub')
        # Bump counters to exercise summary passthrough
        restore.counters['SUCCESS'] = 7
        report = restore.step_validate({'nodes': 5, 'teams': 3, 'roles': 3})
        self.assertEqual(report['observed']['nodes'], 5)
        self.assertEqual(report['observed']['users'], 10)
        self.assertEqual(report['match'],
                         {'nodes': True, 'teams': True, 'roles': False})
        self.assertEqual(report['summary']['SUCCESS'], 7)


class DedupeRoleNamesEdgeCases(unittest.TestCase):
    """Cover the empty-name skip in dedupe_role_names (line 218)."""

    def test_role_with_blank_name_skipped(self):
        rows, _ = dedupe_role_names([
            {'name': '', 'node': 'X'},
            {'name': '   ', 'node': 'Y'},
            {'name': 'Real', 'node': 'Z'},
        ])
        self.assertEqual([r['original_name'] for r in rows], ['Real'])


class PlanManagedNodesEdgeCases(unittest.TestCase):
    """Cover blank-role-name + blank-managed-node-name skip (lines 257, 263)."""

    def test_blank_role_skipped(self):
        out = plan_managed_nodes([
            {'name': '', 'managed_nodes': [{'node_name': 'X'}]},
            {'name': 'Real', 'managed_nodes': [{'node_name': 'Z'}]},
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][0], 'Real')

    def test_managed_node_with_blank_node_name_skipped(self):
        """Empty/missing node_name on a managed_nodes entry is skipped."""
        out = plan_managed_nodes([
            {'name': 'R', 'managed_nodes': [
                {'node_name': '', 'cascade': True},
                {'node_name': 'Y', 'cascade': False},
            ]},
        ])
        # Only 'Y' survives.
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][1], 'Y')


class Bug80NodeRenameLookupTests(unittest.TestCase):
    """Bug 80 — when source has duplicate-leaf node siblings (Bug 73
    territory) and target underwent rename-with-suffix disambiguation,
    plan_managed_nodes must resolve each binding through the
    `(source_node_id, source_parent_path)` disambiguation context to
    pick the right post-rename target name. Pre-fix:
    `Permissions -  Share` bound to source `Finance` got migrated as
    `Finance` on target — which didn't exist (Bug 73 had renamed
    target to `Finance (Subsidiary X)` per parent), and Commander
    silently SUCCESS-returned without persisting."""

    def test_node_rename_lookup_resolves_duplicate_leaf(self):
        roles = [{
            'name': 'Permissions -  Share',
            'managed_nodes': [{
                'node_name': 'Finance',
                'source_node_id': '12345',
                'source_parent_path': 'My company\\Subsidiary 2 - Jumpcloud\\Finance',
                'cascade': True,
                'privileges': ['sharing_administrator'],
            }],
        }]
        node_lookup = {
            ('12345', 'My company\\Subsidiary 2 - Jumpcloud\\Finance'):
                'Finance (Subsidiary 2 - Jumpcloud)',
        }
        out = plan_managed_nodes(roles, source_root='My company',
                                  target_root='Keeperdemo',
                                  node_rename_lookup=node_lookup)
        self.assertEqual(len(out), 1)
        # Should emit the disambiguated target name, not raw 'Finance'.
        self.assertEqual(out[0][1], 'Finance (Subsidiary 2 - Jumpcloud)')

    def test_node_rename_lookup_falls_through_when_no_context(self):
        """Pre-Bug-80 inventories don't carry source_node_id /
        source_parent_path on managed_nodes entries. Plan must still
        work via name-only remapping (backwards-compatible)."""
        roles = [{
            'name': 'R',
            'managed_nodes': [{
                'node_name': 'Finance', 'cascade': True, 'privileges': []
            }],
        }]
        node_lookup = {
            ('12345', 'My company\\Sub\\Finance'):
                'Finance (Sub)',
        }
        out = plan_managed_nodes(roles, source_root='My company',
                                  target_root='Keeperdemo',
                                  node_rename_lookup=node_lookup)
        # Falls through; emits raw 'Finance'.
        self.assertEqual(out[0][1], 'Finance')

    def test_node_rename_lookup_picks_correct_sibling(self):
        """Three source `Finance` siblings under different parents.
        Each binding has its own disambiguation context. plan emits
        the correctly-renamed target for each."""
        roles = [{
            'name': 'Role-A',
            'managed_nodes': [{
                'node_name': 'Finance', 'source_node_id': '111',
                'source_parent_path': 'My company\\Sub1\\Finance',
                'cascade': True, 'privileges': [],
            }],
        }, {
            'name': 'Role-B',
            'managed_nodes': [{
                'node_name': 'Finance', 'source_node_id': '222',
                'source_parent_path': 'My company\\Sub2\\Finance',
                'cascade': True, 'privileges': [],
            }],
        }]
        node_lookup = {
            ('111', 'My company\\Sub1\\Finance'): 'Finance (Sub1)',
            ('222', 'My company\\Sub2\\Finance'): 'Finance (Sub2)',
        }
        out = plan_managed_nodes(roles, source_root='My company',
                                  target_root='Keeperdemo',
                                  node_rename_lookup=node_lookup)
        targets = sorted(t for _, t, _, _ in out)
        self.assertEqual(targets, ['Finance (Sub1)', 'Finance (Sub2)'])


class Bug80LiveInventoryCaptureContextTests(unittest.TestCase):
    """Bug 80 layer 1 — `live_inventory._build_role_managed_nodes`
    captures `source_node_id` + `source_parent_path` on each
    managed_nodes entry so the migration side can disambiguate
    duplicate-leaf source siblings."""

    def test_managed_nodes_capture_disambiguation_context(self):
        from keepercommander.commands.keeper_tenant_migrate.live_inventory import build_role_pivots
        ent = {
            'enterprise_name': 'My company',
            'nodes': [
                {'node_id': 1, 'parent_id': None, 'data': {}},  # root
                {'node_id': 2, 'parent_id': 1,
                 'data': {'displayname': 'Sub1'}},
                {'node_id': 3, 'parent_id': 2,
                 'data': {'displayname': 'Finance'}},
                {'node_id': 4, 'parent_id': 1,
                 'data': {'displayname': 'Sub2'}},
                {'node_id': 5, 'parent_id': 4,
                 'data': {'displayname': 'Finance'}},  # duplicate leaf
            ],
            'managed_nodes': [
                {'role_id': 100, 'managed_node_id': 3,
                 'cascade_node_management': True},
                {'role_id': 101, 'managed_node_id': 5,
                 'cascade_node_management': False},
            ],
            'role_privileges': [],
        }
        managed, _enfs, _users, _teams = build_role_pivots(ent)
        # Both bindings captured with disambiguating context.
        r100 = managed[100][0]
        r101 = managed[101][0]
        self.assertEqual(r100['node_name'], 'Finance')
        self.assertEqual(r100['source_node_id'], '3')
        self.assertIn('Sub1', r100['source_parent_path'])
        self.assertIn('Finance', r100['source_parent_path'])
        self.assertEqual(r101['node_name'], 'Finance')
        self.assertEqual(r101['source_node_id'], '5')
        self.assertIn('Sub2', r101['source_parent_path'])
        # IDs differ even though the leaf names are identical — Bug 80
        # disambiguator is preserved.
        self.assertNotEqual(r100['source_node_id'], r101['source_node_id'])
        self.assertNotEqual(
            r100['source_parent_path'], r101['source_parent_path'])


class PlanRoleAssignmentsEdgeCases(unittest.TestCase):
    """Cover blank role-name skip in plan_role_user/team_assignments
    (lines 368, 385)."""

    def test_role_user_with_blank_role_skipped(self):
        out = list(plan_role_user_assignments([
            {'name': '', 'users': [{'username': 'a@x'}]},
            {'name': 'R', 'users': [{'username': 'b@x'}]},
        ]))
        self.assertEqual(out, [('R', 'b@x')])

    def test_role_team_with_blank_role_skipped(self):
        out = list(plan_role_team_assignments([
            {'name': '', 'teams': [{'team_name': 'T'}]},
            {'name': 'R', 'teams': [{'team_name': 'T2'}]},
        ]))
        self.assertEqual(out, [('R', 'T2', False)])


class DedupeTeamNamesEdgeCases(unittest.TestCase):
    """Cover the empty-name skip in dedupe_team_names (line 420)."""

    def test_team_with_blank_name_skipped(self):
        rows, _ = dedupe_team_names([
            {'name': '', 'node': 'X'},
            {'name': 'Real', 'node': 'Y'},
        ])
        self.assertEqual([r['original_name'] for r in rows], ['Real'])


class StructureClientDefaultBatchTests(unittest.TestCase):
    """Cover the default StructureClient.set_role_enforcements_simple_batch
    iteration path (lines 495-501)."""

    def test_default_batch_iterates_per_pair(self):
        from keepercommander.commands.keeper_tenant_migrate.structure import StructureClient

        class _ConcreteClient(StructureClient):
            def __init__(self):
                self.simple_calls = []
                # Fail the second pair.
                self._next = iter([True, False, True])

            def set_role_enforcement_simple(self, role_name, key, value):
                self.simple_calls.append((role_name, key, value))
                return next(self._next)

        c = _ConcreteClient()
        ok = c.set_role_enforcements_simple_batch(
            'R', [('a', '1'), ('b', '2'), ('c', '3')])
        self.assertFalse(ok)  # one pair returned False → batch False
        self.assertEqual(len(c.simple_calls), 3)

    def test_default_batch_empty_pairs_returns_true_without_iterating(self):
        from keepercommander.commands.keeper_tenant_migrate.structure import StructureClient

        class _ConcreteClient(StructureClient):
            def set_role_enforcement_simple(self, *a, **kw):  # pragma: no cover
                raise AssertionError('should not be called')

        ok = _ConcreteClient().set_role_enforcements_simple_batch('R', [])
        self.assertTrue(ok)


class FakeClientFailurePathsTests(unittest.TestCase):
    """Cover FakeClient fail_on branches for folder operations + count_*."""

    def test_add_user_folder_fail_on_returns_empty(self):
        c = FakeClient(fail_on={'add_user_folder'})
        out = c.add_user_folder('X', parent_uid='p')
        self.assertEqual(out, '')
        self.assertEqual(c.calls[-1][0], 'add_user_folder')

    def test_add_shared_folder_fail_on_returns_empty(self):
        c = FakeClient(fail_on={'add_shared_folder'})
        out = c.add_shared_folder('X')
        self.assertEqual(out, '')

    def test_add_subfolder_fail_on_returns_empty(self):
        c = FakeClient(fail_on={'add_subfolder'})
        out = c.add_subfolder('X', parent_sf_folder_uid='p')
        self.assertEqual(out, '')

    def test_count_helpers_default_to_zero(self):
        c = FakeClient()
        # count_nodes returns len(calls) — initially 0
        self.assertEqual(c.count_nodes('any'), 0)
        self.assertEqual(c.count_teams('any'), 0)
        self.assertEqual(c.count_roles('any'), 0)
        self.assertEqual(c.count_users('any'), 0)


class StepResultAsRowTests(unittest.TestCase):
    """Cover StepResult.as_row()."""

    def test_as_row_returns_all_fields(self):
        r = StepResult('cat', 'name', 'create', StepResult.SUCCESS, 'note')
        self.assertEqual(r.as_row(),
                          ['cat', 'name', 'create',
                           StepResult.SUCCESS, 'note'])


class LastErrorFallbackTests(unittest.TestCase):
    """Cover the _last_error fallback when commander_clients import fails
    (lines 741-742)."""

    def test_last_error_returns_empty_when_module_unimportable(self):
        """The except-Exception path silently returns ''."""
        from unittest.mock import patch

        restore = StructureRestore(FakeClient())
        # Simulate a failure inside the try block.
        with patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.'
                    'get_last_call_error',
                    side_effect=RuntimeError('boom')):
            self.assertEqual(restore._last_error(), '')


class StepTeamsRolesFailureNotesTests(unittest.TestCase):
    """Cover the FAILED branch with rename note in step_teams + step_roles
    (lines 918-919, 942-943)."""

    def test_step_teams_failed_branch_records_rename_note(self):
        client = FakeClient(fail_on={'create_team'})
        restore = StructureRestore(client, source_root='SRC',
                                     target_root='TGT')
        # Two teams with the same name — duplicate-suffix path triggers
        # base_notes; the create_team failure flips into the failure
        # branch which keeps that note.
        teams = [
            {'name': 'Eng', 'node': 'A'},
            {'name': 'Eng', 'node': 'B'},
        ]
        restore.step_teams(teams)
        failed = [r for r in restore.results if r.status == StepResult.FAILED]
        self.assertGreaterEqual(len(failed), 1)
        # The base "renamed from" note is preserved on the FAILED record.
        self.assertTrue(any('renamed from' in r.notes for r in failed))

    def test_step_roles_failed_branch_records_rename_note(self):
        client = FakeClient(fail_on={'create_role'})
        restore = StructureRestore(client, source_root='SRC',
                                     target_root='TGT')
        roles = [
            {'name': 'Manager', 'node': 'X', 'new_user': True},
            {'name': 'Manager', 'node': 'Y', 'new_user': False},
        ]
        restore.step_roles(roles)
        failed = [r for r in restore.results if r.status == StepResult.FAILED]
        self.assertGreaterEqual(len(failed), 1)


class ManagedNodesFailureBranchTests(unittest.TestCase):
    """Cover the SKIPPED/FAILED classifier branches in step_managed_nodes
    (lines 978-979 admin failure + 996-1004 priv failure)."""

    def test_managed_node_admin_call_fails_records_failure(self):
        client = FakeClient(fail_on={'add_role_managed_node'})
        restore = StructureRestore(client, source_root='SRC',
                                     target_root='TGT')
        # Pre-populate created_roles so the gate doesn't suppress.
        restore.created_roles.add('R')
        roles = [{
            'name': 'R',
            'managed_nodes': [
                {'node_name': 'N', 'cascade': True, 'privileges': ['p1']},
            ],
        }]
        restore.step_managed_nodes(roles)
        admin_recs = [r for r in restore.results if r.action == 'add-admin']
        self.assertEqual(admin_recs[0].status, StepResult.FAILED)

    def test_managed_node_privilege_call_fails_records_failure(self):
        client = FakeClient(fail_on={'add_role_privilege'})
        restore = StructureRestore(client, source_root='SRC',
                                     target_root='TGT')
        restore.created_roles.add('R')
        roles = [{
            'name': 'R',
            'managed_nodes': [
                {'node_name': 'N', 'cascade': False, 'privileges': ['p1']},
            ],
        }]
        restore.step_managed_nodes(roles)
        priv_recs = [r for r in restore.results
                       if r.action == 'add-privilege']
        self.assertEqual(priv_recs[0].status, StepResult.FAILED)


class StepEnforcementsBranchesTests:
    pass  # Holder for next group


class EnforcementsBlankAndGateTests(unittest.TestCase):
    """Cover step_enforcements: blank role name (1049), gate suppression
    (1061-1066), non-dict enforcements skip (1070), provided complexity_dir
    (1029)."""

    def test_blank_role_skipped(self):
        restore = StructureRestore(FakeClient())
        out = restore.step_enforcements([
            {'name': '', 'enforcements': {'k': 'v'}},
            {'name': 'R', 'enforcements': {}},
        ])
        # No fails, no simples — just the wrap-up record.
        self.assertEqual(out['failed'], 0)
        self.assertEqual(out['simple'], 0)

    def test_gate_skips_uncreated_role(self):
        """When created_roles is populated and a role isn't in it, every
        enforcement on that role is suppressed via a single SKIPPED record."""
        restore = StructureRestore(FakeClient())
        restore.created_roles.add('Kept')
        restore.step_enforcements([
            {'name': 'Missing', 'enforcements': {'a': 1, 'b': 2}},
        ])
        skipped = [r for r in restore.results
                     if r.action == 'skip-missing']
        self.assertEqual(len(skipped), 1)
        self.assertIn('2 enforcement', skipped[0].notes)

    def test_non_dict_enforcements_block_skipped(self):
        """A role with a list-typed enforcements payload is silently skipped."""
        restore = StructureRestore(FakeClient())
        out = restore.step_enforcements([
            {'name': 'R', 'enforcements': ['not-a-dict']},
        ])
        self.assertEqual(out['simple'], 0)

    def test_caller_provided_complexity_dir_is_reused(self):
        """When complexity_dir is explicitly passed, it's reused (not deleted)."""
        with tempfile.TemporaryDirectory() as base:
            cdir = os.path.join(base, 'enf')
            restore = StructureRestore(FakeClient())
            restore.step_enforcements(
                [{'name': 'R',
                   'enforcements': {'master_password_reentry': 'thirty'}}],
                complexity_dir=cdir)
            # Caller-provided dir survives the call.
            self.assertTrue(os.path.isdir(cdir))


class EnforcementsDirectAndFailureTests(unittest.TestCase):
    """Cover direct-API success + per-key failure tally, FILE write path
    failure, and SIMPLE-batch failure tally (lines 1096-1097, 1135,
    1159-1160)."""

    def test_direct_api_per_key_failure_increments_fail_count(self):
        from unittest.mock import patch

        # Make the direct-API path fire by claiming one key is unsupported.
        def fake_unsupported(key):
            return key == 'json_key'

        def direct_fn(role, mapping):
            return {k: (False, 'rejected') for k in mapping}

        restore = StructureRestore(FakeClient())
        with patch('keepercommander.commands.keeper_tenant_migrate.enforcement_direct.is_cli_unsupported',
                    side_effect=fake_unsupported):
            out = restore.step_enforcements(
                [{'name': 'R', 'enforcements': {'json_key': {'x': 1}}}],
                direct_api_fn=direct_fn)
        self.assertEqual(out['direct'], 0)
        self.assertGreaterEqual(out['failed'], 1)

    def test_direct_api_upstream4_rejection_counts_as_skipped(self):
        # Bug 53 (v1.5.6) — direct-API path now routes failures
        # through `_classify_error`. Upstream-4 (environment-
        # restricted BOOLEAN, e.g. ALLOW_CAN_EDIT_EXTERNAL_SHARES on
        # MSP target) returns the same generic envelope as Upstream-3
        # but with valueType=BOOLEAN. Plugin-side workaround is
        # SKIP-with-audit so the pipeline proceeds; operator can
        # apply manually if/when target tenant config changes.
        from unittest.mock import patch

        def fake_unsupported(key):
            return key == 'allow_can_edit_external_shares'

        def direct_fn(role, mapping):
            err = (
                'communicate raised: cannot update enforcement: '
                'roleId=12058/51788715655757, '
                'enforcement=ALLOW_CAN_EDIT_EXTERNAL_SHARES, '
                'enforcementId=247, valueType=BOOLEAN, '
                'category=ACCOUNT_ENFORCEMENTS, value=null'
            )
            return {k: (False, err) for k in mapping}

        restore = StructureRestore(FakeClient())
        with patch('keepercommander.commands.keeper_tenant_migrate.enforcement_direct.is_cli_unsupported',
                    side_effect=fake_unsupported):
            out = restore.step_enforcements([
                {'name': 'R', 'enforcements':
                    {'allow_can_edit_external_shares': True}}
            ], direct_api_fn=direct_fn)
        self.assertEqual(out['failed'], 0)
        self.assertGreaterEqual(out['skipped'], 1)

    def test_simple_batch_failure_counts_every_pair_as_fail(self):
        client = FakeClient(fail_on={'set_role_enforcements_simple_batch'})
        restore = StructureRestore(client)
        out = restore.step_enforcements([
            {'name': 'R', 'enforcements': {'minimum_pbkdf2_iterations': '1000',
                                              'master_password_minimum_length': '14'}},
        ])
        # Two pairs → both counted as failures since whole batch failed.
        self.assertEqual(out['failed'], 2)
        self.assertEqual(out['simple'], 0)

    def test_simple_batch_upstream3_rejection_counts_as_skipped(self):
        # Bug 51 — when batch fails because Commander rejects a
        # cross-tenant REQUIRE_ACCOUNT_SHARE (Upstream-3), the whole
        # batch is classified SKIPPED so structure proceeds. The
        # alternative was FAILED (halts auto-migrate); the marker
        # gives operators a clean continuation point with a clear
        # post-migration manual-action note in logs.
        client = FakeClient(fail_on={'set_role_enforcements_simple_batch'})
        restore = StructureRestore(client)
        upstream3_err = (
            'cannot update enforcement: roleId=12058/51788715655777, '
            'enforcement=REQUIRE_ACCOUNT_SHARE, enforcementId=34, '
            'valueType=ACCOUNT_SHARE, value=12058/51788715655757'
        )
        with patch.object(restore, '_last_error',
                           return_value=upstream3_err):
            out = restore.step_enforcements([
                {'name': 'R',
                 'enforcements': {'master_password_minimum_length': '14'}},
            ])
        self.assertEqual(out['failed'], 0)
        self.assertGreaterEqual(out['skipped'], 1)

    def test_file_enforcement_write_failure_counts_as_fail(self):
        # generated_password_complexity is a FILE-phase key that's NOT
        # cli-unsupported, so it routes through the FILE path where the
        # client's set_role_enforcement_file is called.
        client = FakeClient(fail_on={'set_role_enforcement_file'})
        restore = StructureRestore(client)
        out = restore.step_enforcements([
            {'name': 'R',
             'enforcements': {'generated_password_complexity':
                                {'min_length': 14, 'min_special': 2}}},
        ])
        self.assertEqual(out['file'], 0)
        self.assertEqual(out['failed'], 1)

    def test_file_enforcement_classifier_skips_known_upstream(self):
        # Bug 57 (v1.5.7): FILE-phase failures now route through
        # `_classify_error` like the direct-API and CLI batch paths.
        # When `_last_error()` returns a known-upstream marker (e.g.
        # the dependency-cascade `'is not found: Skipping'` idiom),
        # the failure becomes SKIPPED, not FAILED.
        client = FakeClient(fail_on={'set_role_enforcement_file'})
        restore = StructureRestore(client)
        with patch.object(restore, '_last_error',
                           return_value='Role X is not found: Skipping'):
            out = restore.step_enforcements([
                {'name': 'R',
                 'enforcements': {'generated_password_complexity':
                                    {'min_length': 14}}},
            ])
        self.assertEqual(out['file'], 0)
        self.assertEqual(out['failed'], 0)
        self.assertGreaterEqual(out['skipped'], 1)


class StepVaultFoldersUnknownTypeAndIncompleteTests(unittest.TestCase):
    """Cover unknown ftype, incomplete entry, exception inside client call
    (lines 1270-1273, 1325-1332)."""

    def test_incomplete_entry_marked_failed(self):
        restore = StructureRestore(FakeClient())
        # name is empty → incomplete
        restore.step_vault_folders([
            {'name': '', 'type': 'shared_folder', 'uid': 'x'},
        ])
        recs = [r for r in restore.results
                  if r.category == 'vault_folders']
        self.assertEqual(recs[0].status, StepResult.FAILED)
        self.assertIn('incomplete', recs[0].notes)

    def test_unknown_folder_type_marked_failed(self):
        restore = StructureRestore(FakeClient())
        restore.step_vault_folders([
            {'name': 'X', 'type': 'mystery_folder', 'uid': 'u', 'parent_uid': ''},
        ])
        recs = [r for r in restore.results
                  if r.category == 'vault_folders']
        self.assertEqual(recs[0].status, StepResult.FAILED)
        self.assertIn('unknown folder type', recs[0].notes)

    def test_client_exception_during_create_marks_failed(self):
        """An unexpected exception inside the client's add_user_folder is
        caught and recorded as a per-folder FAILED entry."""
        from keepercommander.commands.keeper_tenant_migrate.structure import StructureClient

        class _BoomClient(StructureClient):
            def add_user_folder(self, name, parent_uid=''):
                raise ValueError(f'boom-{name}')

            def count_nodes(self, scope_node=''):  # pragma: no cover
                return 0

            def count_teams(self, scope_node=''):  # pragma: no cover
                return 0

            def count_roles(self, scope_node=''):  # pragma: no cover
                return 0

            def count_users(self, scope_node=''):  # pragma: no cover
                return 0

        restore = StructureRestore(_BoomClient())
        restore.step_vault_folders([
            {'name': 'X', 'type': 'user_folder',
             'uid': 'u', 'parent_uid': ''},
        ])
        recs = [r for r in restore.results
                  if r.category == 'vault_folders']
        self.assertEqual(recs[0].status, StepResult.FAILED)
        self.assertIn('ValueError', recs[0].notes)
        self.assertIn('boom-X', recs[0].notes)


class StepSfMembershipFailureTests(unittest.TestCase):
    """Cover step_sf_membership failure branches (line 1364)."""

    def test_no_flat_fallback_failed_message(self):
        """Native fails, no flat fallback → FAILED with 'No flat fallback'."""
        client = FakeClient(fail_on={'apply_membership'})
        restore = StructureRestore(client)
        restore.step_sf_membership('/path/to/membership.json')
        rec = restore.results[-1]
        self.assertEqual(rec.status, StepResult.FAILED)
        self.assertIn('No flat fallback', rec.notes)

    def test_both_paths_fail_message(self):
        """Both native and flat fallback fail → FAILED with combined message."""
        client = FakeClient(fail_on={'apply_membership'})
        restore = StructureRestore(client)
        restore.step_sf_membership('/p/native.json',
                                     flat_fallback_path='/p/flat.json')
        rec = restore.results[-1]
        self.assertEqual(rec.status, StepResult.FAILED)
        self.assertIn('Both full and flat failed', rec.notes)

    def test_flat_fallback_succeeds_after_native_fails(self):
        """Native fails but flat fallback works → SUCCESS with 'Flattened'."""
        # Custom client: first apply_membership call fails, second succeeds.
        class _Toggle(FakeClient):
            def __init__(self):
                super().__init__()
                self._next = iter([False, True])

            def apply_membership(self, path):
                self.calls.append(('apply_membership', (path,)))
                return next(self._next)

        restore = StructureRestore(_Toggle())
        restore.step_sf_membership('/native.json',
                                     flat_fallback_path='/flat.json')
        rec = restore.results[-1]
        self.assertEqual(rec.status, StepResult.SUCCESS)
        self.assertIn('Flattened', rec.notes)


class TopologicalNodeOrderEdgeCases(unittest.TestCase):
    """Cover the unreachable-via-fixture branches in topological_node_order
    (lines 153, 161)."""

    def test_node_with_unresolvable_parent_is_skipped(self):
        """If a node's parent_id can't be resolved AND it doesn't match
        the scope-root remap rule, the node is dropped (line 153)."""
        nodes = [
            {'id': '1', 'name': 'Real', 'parent': '', 'isolated': False},
            {'id': '2', 'name': 'Orphan', 'parent': 'Ghost',
             'isolated': False},
        ]
        out = topological_node_order(nodes,
                                       scope_node_name='SomeScope',
                                       target_root='Tgt')
        names = [n[0] for n in out]
        self.assertNotIn('Orphan', names)

    def test_full_tenant_root_node_itself_not_emitted(self):
        """The source root with parent='' is captured in
        root_nids_full_tenant and skipped (line 161)."""
        nodes = [
            {'id': '1', 'name': 'My company', 'parent': '',
             'isolated': False},
            {'id': '2', 'name': 'Child', 'parent': 'My company',
             'isolated': False},
        ]
        out = topological_node_order(nodes, scope_node_name='',
                                       target_root='TgtRoot')
        names = [n[0] for n in out]
        self.assertNotIn('My company', names)
        self.assertIn('Child', names)


if __name__ == '__main__':
    unittest.main()
