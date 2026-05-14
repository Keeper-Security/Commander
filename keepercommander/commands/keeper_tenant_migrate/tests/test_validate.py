import unittest

from keepercommander.commands.keeper_tenant_migrate.validate import (
    Check,
    Severity,
    ValidationContext,
    Validator,
    phase_entity_counts,
    phase_nodes,
    phase_pre_flight,
    phase_record_types,
    phase_records,
    phase_roles,
    phase_shared_folders,
    phase_teams,
    phase_users,
    phase_vault_health,
    summarize,
)


def _inv(**overrides):
    base = {
        'source_user': 'admin@src',
        'entities': {'nodes': [], 'teams': [], 'roles': [],
                     'users': [], 'shared_folders': [], 'records': []},
    }
    base.update(overrides)
    return base


class ChecksDataTypeTests(unittest.TestCase):
    def test_check_as_row_matches_fields(self):
        c = Check('nodes', Severity.PASS, 'ok', 'detail')
        self.assertEqual(c.as_row(), ['nodes', 'PASS', 'ok', 'detail'])


class PhasePreFlightTests(unittest.TestCase):
    def test_both_populated_emits_pass(self):
        ctx = ValidationContext(_inv(), {'nodes': []})
        checks = list(phase_pre_flight(ctx))
        self.assertEqual(checks[0].severity, Severity.PASS)

    def test_missing_inventory_is_fail(self):
        ctx = ValidationContext(None, {'nodes': []})
        self.assertEqual(list(phase_pre_flight(ctx))[0].severity, Severity.FAIL)

    def test_missing_target_state_is_fail(self):
        ctx = ValidationContext(_inv(), None)
        self.assertEqual(list(phase_pre_flight(ctx))[0].severity, Severity.FAIL)


class PhaseNodesTests(unittest.TestCase):
    def test_exact_match_is_pass(self):
        inv = _inv(entities={'nodes': [{'name': 'A', 'isolated': True}],
                             'teams': [], 'roles': [], 'users': [],
                             'shared_folders': [], 'records': []})
        target = {'nodes': [{'name': 'A', 'isolated': True}]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        self.assertEqual(checks[0].severity, Severity.PASS)

    def test_missing_node_is_fail(self):
        inv = _inv(entities={'nodes': [{'name': 'A'}, {'name': 'B'}],
                             'teams': [], 'roles': [], 'users': [],
                             'shared_folders': [], 'records': []})
        target = {'nodes': [{'name': 'A'}]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        missing = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(missing), 1)
        self.assertIn('B', missing[0].message)

    def test_isolated_mismatch_is_fail(self):
        inv = _inv(entities={'nodes': [{'name': 'A', 'isolated': True}],
                             'teams': [], 'roles': [], 'users': [],
                             'shared_folders': [], 'records': []})
        target = {'nodes': [{'name': 'A', 'isolated': False}]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        self.assertEqual(checks[0].severity, Severity.FAIL)
        self.assertIn('isolated flag mismatch', checks[0].message)

    def test_no_source_yields_skip(self):
        checks = list(phase_nodes(ValidationContext(_inv(), {'nodes': []})))
        self.assertEqual(checks[0].severity, Severity.SKIP)

    def test_parent_path_mismatch_is_fail(self):
        """Bug 16 follow-up: when target has the node but at the wrong
        parent (e.g., scope-node remap flattened the subtree), verify
        should FAIL with a topology-divergence message instead of
        silently passing."""
        inv = _inv(
            source_root='My company',
            scope_node='MIGRATION-TEST-NODE',
            entities={'nodes': [
                {'name': 'MIGTEST-Child', 'parent': 'MIGRATION-TEST-NODE',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        # Target has the node but parent is wrong (sibling under root,
        # not under the scope node) — pre-Bug-16 behavior.
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'MIGTEST-Child', 'parent': 'Keeperdemo',
             'isolated': False},
        ]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(fails), 1)
        self.assertIn('parent mismatch', fails[0].message)
        self.assertIn('MIGRATION-TEST-NODE', fails[0].message)

    def test_parent_path_match_is_pass(self):
        """Bug 16 fixed scenario: target node lives under the scope node
        on target — leaf names match."""
        inv = _inv(
            source_root='My company',
            scope_node='MIGRATION-TEST-NODE',
            entities={'nodes': [
                {'name': 'MIGTEST-Child', 'parent': 'MIGRATION-TEST-NODE',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'MIGTEST-Child', 'parent': 'MIGRATION-TEST-NODE',
             'isolated': False},
        ]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        self.assertEqual(checks[0].severity, Severity.PASS)

    def test_parent_path_check_skipped_for_old_captures(self):
        """Backwards compat: target captures predating the parent field
        don't carry one — verify must not FAIL. Skips the parent check
        and falls through to the existing isolated-flag pass."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'A', 'parent': 'My company', 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'nodes': [{'name': 'A', 'isolated': False}]}  # no 'parent' key
        checks = list(phase_nodes(ValidationContext(inv, target)))
        self.assertEqual(checks[0].severity, Severity.PASS)

    def test_parent_path_source_root_remapped_to_target_root(self):
        """Direct children of the source enterprise root remap to the
        target enterprise root — full-tenant migration case."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'TopLevel-A', 'parent': 'My company',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'TopLevel-A', 'parent': 'Keeperdemo',
             'isolated': False},
        ]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        self.assertEqual(checks[0].severity, Severity.PASS)

    def test_duplicate_leaf_names_under_distinct_parents_pass(self):
        """Bug 73: two Finance nodes under distinct Subsidiary parents
        must each match their own (name, parent) pair — not collapse
        onto a single name-keyed entry."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'Finance', 'parent': 'Subsidiary A',
                 'isolated': False},
                {'name': 'Finance', 'parent': 'Subsidiary B',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'Finance', 'parent': 'Subsidiary A',
             'isolated': False},
            {'name': 'Finance', 'parent': 'Subsidiary B',
             'isolated': False},
        ]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        passes = [c for c in checks if c.severity == Severity.PASS]
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(passes), 2)
        self.assertEqual(len(fails), 0)

    def test_rename_map_translates_source_to_renamed_target(self):
        """Bug 73 α: structure stage renamed duplicate-leaf source
        Finance to 'Finance (Subsidiary B)' on target. phase_nodes
        translates the source name through rename_map and PASSes
        against the renamed target entry."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'Finance', 'parent': 'Subsidiary A',
                 'isolated': False},
                {'name': 'Finance', 'parent': 'Subsidiary B',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'Finance (Subsidiary A)', 'parent': 'Subsidiary A',
             'isolated': False},
            {'name': 'Finance (Subsidiary B)', 'parent': 'Subsidiary B',
             'isolated': False},
        ]}
        rename_map = {
            'roles': {}, 'teams': {},
            'nodes': {
                ('Finance', 'Subsidiary A'): 'Finance (Subsidiary A)',
                ('Finance', 'Subsidiary B'): 'Finance (Subsidiary B)',
            },
        }
        ctx = ValidationContext(inv, target, rename_map=rename_map)
        checks = list(phase_nodes(ctx))
        passes = [c for c in checks if c.severity == Severity.PASS]
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(passes), 2)
        self.assertEqual(len(fails), 0)

    def test_rename_map_missing_renamed_target_is_fail(self):
        """Bug 73 α: when rename_map says Finance→Finance (SubB) but
        target only has Finance (SubA), phase_nodes correctly reports
        the missing renamed target."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'Finance', 'parent': 'Subsidiary A',
                 'isolated': False},
                {'name': 'Finance', 'parent': 'Subsidiary B',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'Finance (Subsidiary A)', 'parent': 'Subsidiary A',
             'isolated': False},
        ]}
        rename_map = {
            'roles': {}, 'teams': {},
            'nodes': {
                ('Finance', 'Subsidiary A'): 'Finance (Subsidiary A)',
                ('Finance', 'Subsidiary B'): 'Finance (Subsidiary B)',
            },
        }
        ctx = ValidationContext(inv, target, rename_map=rename_map)
        checks = list(phase_nodes(ctx))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(fails), 1)
        self.assertIn('Finance (Subsidiary B)', fails[0].message)

    def test_duplicate_leaf_name_missing_one_parent_is_fail(self):
        """Bug 73 regression — when only ONE Finance landed on target
        but source has TWO under different parents, the missing parent
        must produce a FAIL, not a silent collapse to PASS."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'Finance', 'parent': 'Subsidiary A',
                 'isolated': False},
                {'name': 'Finance', 'parent': 'Subsidiary B',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        # Only one Finance on target — the Subsidiary B copy is
        # missing (the Commander dedup symptom this fixes).
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'Finance', 'parent': 'Subsidiary A',
             'isolated': False},
        ]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(fails), 1)
        self.assertIn("'Subsidiary B'", fails[0].message)


class PhaseNodesSourceRootSkipTests(unittest.TestCase):
    """Bug 75 — the source enterprise root is not migrated by design;
    phase_nodes used to emit a FAIL ("Node missing on target: My
    company") on every rehearsal because it iterated the source root
    alongside other entities and looked it up unconditionally. Now
    yields SKIP with an explicit "not migrated by design" note when
    the row is the source root with empty/self parent."""

    def test_source_root_yields_skip_not_fail(self):
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'My company', 'parent': '', 'isolated': False},
                {'name': 'Subsidiary A', 'parent': 'My company',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'Subsidiary A', 'parent': 'Keeperdemo',
             'isolated': False},
        ]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        skips = [c for c in checks if c.severity == Severity.SKIP]
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(skips), 1, f'expected 1 SKIP, got {skips}')
        self.assertIn("'My company'", skips[0].message)
        self.assertIn('not migrated by design', skips[0].message)
        self.assertEqual(fails, [], f'no FAIL expected, got {fails}')

    def test_source_root_with_self_parent_also_skipped(self):
        """Edge case: some inventories carry source-root with parent==
        source_root (self-reference). Still skip."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'My company', 'parent': 'My company',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': []}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        skips = [c for c in checks if c.severity == Severity.SKIP]
        self.assertEqual(len(skips), 1)

    def test_node_named_like_source_root_under_real_parent_NOT_skipped(self):
        """Defensive: if a tenant legitimately has a node named the
        same as its source enterprise root (rare but possible) UNDER
        a non-root parent, that node SHOULD verify normally — not
        get the source-root SKIP. The skip rule requires empty or
        self parent."""
        inv = _inv(
            source_root='My company',
            entities={'nodes': [
                {'name': 'My company', 'parent': 'Subsidiary A',
                 'isolated': False},
            ], 'teams': [], 'roles': [], 'users': [],
                'shared_folders': [], 'records': []})
        target = {'enterprise_name': 'Keeperdemo', 'nodes': [
            {'name': 'My company', 'parent': 'Subsidiary A',
             'isolated': False},
        ]}
        checks = list(phase_nodes(ValidationContext(inv, target)))
        passes = [c for c in checks if c.severity == Severity.PASS]
        skips = [c for c in checks if c.severity == Severity.SKIP]
        self.assertEqual(len(passes), 1)
        self.assertEqual(skips, [], 'should not skip — has a real parent')


class PhaseNodesCaptureProjectionTests(unittest.TestCase):
    """Bug 73 — `_params_enterprise_to_target_state` must preserve the
    parent of every source node, even when leaf names collide. The
    pre-fix name-keyed dict overwrote with the last-seen parent, so
    duplicate-named nodes all claimed the same parent on capture."""

    def _project(self, ent):
        from types import SimpleNamespace
        from keepercommander.commands.keeper_tenant_migrate.commands import (
            _params_enterprise_to_target_state,
        )
        return _params_enterprise_to_target_state(
            SimpleNamespace(enterprise=ent))

    def test_capture_preserves_distinct_parents(self):
        ent = {
            'enterprise_name': 'ACME',
            'nodes': [
                {'node_id': 1, 'parent_id': 0, 'data': {}},  # root
                {'node_id': 10, 'parent_id': 1,
                 'data': {'displayname': 'Subsidiary A'}},
                {'node_id': 11, 'parent_id': 1,
                 'data': {'displayname': 'Subsidiary B'}},
                {'node_id': 100, 'parent_id': 10,
                 'data': {'displayname': 'Finance'}},
                {'node_id': 101, 'parent_id': 11,
                 'data': {'displayname': 'Finance'}},
            ],
            'teams': [], 'roles': [], 'users': [],
            'shared_folders': [],
        }
        target = self._project(ent)
        finance = [n for n in target['nodes'] if n['name'] == 'Finance']
        self.assertEqual(len(finance), 2)
        parents = sorted(n['parent'] for n in finance)
        self.assertEqual(parents, ['Subsidiary A', 'Subsidiary B'])


class PhaseTeamsTests(unittest.TestCase):
    def test_restricts_mismatch_is_fail(self):
        inv = _inv(entities={'nodes': [], 'teams': [{'name': 'T', 'restricts': 'R W'}],
                             'roles': [], 'users': [], 'shared_folders': [], 'records': []})
        target = {'teams': [{'name': 'T', 'restricts': 'R'}]}
        checks = list(phase_teams(ValidationContext(inv, target)))
        fail = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(fail), 1)
        self.assertIn('restricts mismatch', fail[0].message)

    def test_restricts_normalized_for_comparison(self):
        inv = _inv(entities={'nodes': [], 'teams': [{'name': 'T', 'restricts': 'r w'}],
                             'roles': [], 'users': [], 'shared_folders': [], 'records': []})
        target = {'teams': [{'name': 'T', 'restricts': 'R W'}]}
        checks = list(phase_teams(ValidationContext(inv, target)))
        self.assertEqual(checks[0].severity, Severity.PASS)

    def test_node_leaf_mismatch_is_warn(self):
        """Bug 44 — team placed in a different leaf node on target should WARN."""
        inv = _inv(entities={'nodes': [],
                             'teams': [{'name': 'T', 'restricts': '',
                                        'node': 'My company\\Eng'}],
                             'roles': [], 'users': [], 'shared_folders': [],
                             'records': []})
        target = {'teams': [{'name': 'T', 'restricts': '',
                             'node': 'Keeperdemo\\Sales'}]}
        checks = list(phase_teams(ValidationContext(inv, target)))
        self.assertTrue(any(c.severity == Severity.WARN
                            and 'node leaf' in c.message for c in checks))

    def test_node_leaf_match_passes_across_root_remap(self):
        """Bug 44 — leaf matches, root differs (cross-tenant remap) → PASS."""
        inv = _inv(entities={'nodes': [],
                             'teams': [{'name': 'T', 'restricts': '',
                                        'node': 'My company\\Eng'}],
                             'roles': [], 'users': [], 'shared_folders': [],
                             'records': []})
        target = {'teams': [{'name': 'T', 'restricts': '',
                             'node': 'Keeperdemo\\Eng'}]}
        checks = list(phase_teams(ValidationContext(inv, target)))
        self.assertTrue(any(c.severity == Severity.PASS
                            and 'node leaf=Eng' in c.message for c in checks))


class PhaseSkipAuditTests(unittest.TestCase):
    """Bug 63 — surface unknown SKIPs as FAIL (likely new plugin
    bugs); known categories pass through with severity matching the
    operator action required."""

    def _ctx_with_audit(self, csv_rows):
        import csv as _csv
        import os as _os
        import tempfile
        fd, path = tempfile.mkstemp(suffix='.csv')
        _os.close(fd)
        with open(path, 'w', newline='') as f:
            w = _csv.writer(f)
            w.writerow(['category', 'name', 'action', 'status', 'notes'])
            for r in csv_rows:
                w.writerow(r)
        self.addCleanup(_os.unlink, path)
        return ValidationContext(_inv(), {'_skip_audit_path': path})

    def test_unknown_skip_surfaces_as_fail(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import phase_skip_audit
        ctx = self._ctx_with_audit([
            ['e', 'X', 'apply', 'SKIPPED', 'something completely new'],
        ])
        checks = list(phase_skip_audit(ctx))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(len(fails), 1)
        self.assertIn('UNKNOWN', fails[0].message)

    def test_target_capability_passes(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import phase_skip_audit
        ctx = self._ctx_with_audit([
            ['rp', 'X', 'add', 'SKIPPED',
             'target does not support this (invalid privilege: '
             'manage_billing)'],
        ])
        checks = list(phase_skip_audit(ctx))
        # No FAIL — target-capability is a genuine gap, not a bug.
        self.assertFalse(any(c.severity == Severity.FAIL for c in checks))

    def test_no_audit_csv_returns_skip(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import phase_skip_audit
        ctx = ValidationContext(_inv(), {})
        checks = list(phase_skip_audit(ctx))
        self.assertEqual(checks[0].severity, Severity.SKIP)

    def test_zero_skips_passes_clean(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import phase_skip_audit
        ctx = self._ctx_with_audit([
            ['role', 'A', 'create', 'SUCCESS', ''],
        ])
        checks = list(phase_skip_audit(ctx))
        self.assertTrue(any(c.severity == Severity.PASS
                            and 'Zero SKIPs' in c.message for c in checks))


class RenameMapResolutionTests(unittest.TestCase):
    """Bug 61 — verify must look up renamed roles/teams via the
    rename_map persisted by the structure stage. Without this, source
    roles whose names collide across nodes (and got node-suffix renames
    on target) report NOT FOUND in verify even though they exist."""

    def test_phase_roles_finds_renamed_role(self):
        # Source has 'Finance Interns' on node 'A'; target has the
        # disambiguated 'Finance Interns (A)' because of a duplicate
        # name on another node.
        src = {'name': 'Finance Interns', 'node': 'A',
               'managed_nodes': [], 'enforcements': {}, 'teams': []}
        tgt = {'name': 'Finance Interns (A)',
               'managed_nodes': [], 'enforcements': {}, 'teams': []}
        rename_map = {'roles': {('Finance Interns', 'A'): 'Finance Interns (A)'},
                      'teams': {}}
        ctx = ValidationContext(
            _inv(entities={'nodes': [], 'teams': [], 'users': [],
                           'shared_folders': [], 'records': [],
                           'roles': [src]}),
            {'roles': [tgt]}, rename_map=rename_map)
        checks = list(phase_roles(ctx))
        # Was FAIL pre-fix; now PASSes via rename_map lookup.
        self.assertTrue(any(c.severity == Severity.PASS
                            and 'exists on target' in c.message for c in checks))
        self.assertFalse(any(c.severity == Severity.FAIL
                             and 'NOT FOUND' in c.message for c in checks))

    def test_phase_roles_falls_back_to_source_name_without_rename(self):
        # No rename for this (name, node) pair — verify uses source name.
        src = {'name': 'R', 'node': 'A',
               'managed_nodes': [], 'enforcements': {}, 'teams': []}
        tgt = {'name': 'R', 'managed_nodes': [], 'enforcements': {}, 'teams': []}
        ctx = ValidationContext(
            _inv(entities={'nodes': [], 'teams': [], 'users': [],
                           'shared_folders': [], 'records': [],
                           'roles': [src]}),
            {'roles': [tgt]},
            rename_map={'roles': {}, 'teams': {}})
        checks = list(phase_roles(ctx))
        self.assertTrue(any(c.severity == Severity.PASS
                            and 'exists on target' in c.message for c in checks))

    def test_phase_teams_finds_renamed_team(self):
        src = {'name': 'Sales', 'node': 'A', 'restricts': ''}
        tgt = {'name': 'Sales (A)', 'restricts': ''}
        rename_map = {'roles': {},
                      'teams': {('Sales', 'A'): 'Sales (A)'}}
        ctx = ValidationContext(
            _inv(entities={'nodes': [], 'teams': [src], 'users': [],
                           'shared_folders': [], 'records': [], 'roles': []}),
            {'teams': [tgt]}, rename_map=rename_map)
        checks = list(phase_teams(ctx))
        self.assertFalse(any(c.severity == Severity.FAIL
                             and 'missing on target' in c.message for c in checks))

    def test_target_name_for_returns_source_when_unmapped(self):
        ctx = ValidationContext(_inv(), {})
        # Empty rename_map default — passthrough.
        self.assertEqual(ctx.target_name_for('roles', 'X', 'Y'), 'X')


class PhaseRolesTests(unittest.TestCase):
    def _ctx(self, src_role, tgt_role):
        entities = {'nodes': [], 'teams': [], 'users': [], 'shared_folders': [],
                    'records': [], 'roles': [src_role]}
        return ValidationContext(_inv(entities=entities), {'roles': [tgt_role]})

    def test_exact_match_all_pass(self):
        src = {'name': 'R', 'default_role': False,
               'managed_nodes': [{'privileges': ['MANAGE_USER'], 'cascade': True}],
               'enforcements': {'two_factor_required': True},
               'teams': [{'name': 'T1'}]}
        checks = list(phase_roles(self._ctx(src, src)))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(fails, [])

    def test_missing_privilege_is_fail(self):
        src = {'name': 'R', 'managed_nodes': [{'privileges': ['A', 'B']}]}
        tgt = {'name': 'R', 'managed_nodes': [{'privileges': ['A']}]}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL and 'privilege B' in c.message]
        self.assertEqual(len(fails), 1)

    def test_extra_privilege_is_warn(self):
        src = {'name': 'R', 'managed_nodes': [{'privileges': []}]}
        tgt = {'name': 'R', 'managed_nodes': [{'privileges': ['EXTRA']}]}
        checks = list(phase_roles(self._ctx(src, tgt)))
        warns = [c for c in checks if c.severity == Severity.WARN]
        self.assertTrue(any('EXTRA' in c.message for c in warns))

    def test_cascade_mismatch_is_fail(self):
        src = {'name': 'R', 'managed_nodes': [{'privileges': [], 'cascade': True}]}
        tgt = {'name': 'R', 'managed_nodes': [{'privileges': [], 'cascade': False}]}
        checks = list(phase_roles(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.FAIL and 'cascade' in c.message for c in checks))

    def test_enforcement_missing_is_fail(self):
        src = {'name': 'R', 'enforcements': {'k': 'v'}}
        tgt = {'name': 'R', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.FAIL and 'enforcement k' in c.message for c in checks))

    def test_account_share_id_drift_is_pass(self):
        src = {'name': 'R', 'enforcements': {'require_account_share': '42'}}
        tgt = {'name': 'R', 'enforcements': {'require_account_share': '999'}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        pass_msgs = [c.message for c in checks if c.severity == Severity.PASS]
        self.assertTrue(any('require_account_share' in m for m in pass_msgs))

    def test_missing_role_entirely_is_fail(self):
        src = {'name': 'R'}
        ctx = ValidationContext(_inv(entities={'nodes': [], 'teams': [],
                                                'users': [], 'shared_folders': [],
                                                'records': [], 'roles': [src]}),
                                 {'roles': []})
        checks = list(phase_roles(ctx))
        self.assertEqual(len([c for c in checks if c.severity == Severity.FAIL]), 1)

    def test_teams_missing_is_fail(self):
        src = {'name': 'R', 'teams': [{'name': 'T1'}, 'T2']}
        tgt = {'name': 'R', 'teams': [{'name': 'T1'}]}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL and 'team T2' in c.message]
        self.assertEqual(len(fails), 1)

    def test_node_leaf_mismatch_is_warn(self):
        """Bug 44 — role placed in a different leaf node on target should WARN,
        not FAIL (cross-tenant root remap is legit)."""
        src = {'name': 'R', 'node': 'My company\\Eng'}
        tgt = {'name': 'R', 'node': 'Keeperdemo\\Sales'}
        checks = list(phase_roles(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.WARN
                            and 'node leaf' in c.message for c in checks))

    def test_node_leaf_match_passes(self):
        """Bug 44 — leaf names match, root differs (cross-tenant remap) → PASS."""
        src = {'name': 'R', 'node': 'My company\\Eng'}
        tgt = {'name': 'R', 'node': 'Keeperdemo\\Eng'}
        checks = list(phase_roles(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.PASS
                            and 'node leaf=Eng' in c.message for c in checks))

    def test_visible_below_mismatch_is_fail(self):
        """Bug 44 — flipping visible_below silently breaks scope-down
        enforcement, so it's a hard FAIL not a WARN."""
        src = {'name': 'R', 'visible_below': True}
        tgt = {'name': 'R', 'visible_below': False}
        checks = list(phase_roles(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.FAIL
                            and 'visible_below' in c.message for c in checks))


class RestrictRecordTypesNormalizeTests(unittest.TestCase):
    """Bug 77 — verify must compare `restrict_record_types` as name-sets.
    Source emits portable name-strings post-Bug-60; target captures the
    raw `{"std":[..],"ent":[..]}` shape from `params.enterprise.roles`.
    Both must flatten to a name-set before set-compare."""

    def _ctx(self, src_role, tgt_role, target_record_types=None):
        entities = {'nodes': [], 'teams': [], 'users': [], 'shared_folders': [],
                    'records': [], 'roles': [src_role]}
        target_state = {'roles': [tgt_role]}
        if target_record_types is not None:
            target_state['record_types'] = target_record_types
        return ValidationContext(_inv(entities=entities), target_state)

    def test_std_id_dict_matches_name_string(self):
        """MIGTEST-Role-Golden case: source 'login,databaseCredentials',
        target '{"std":[12,6],"ent":[]}' should PASS — login=12,
        databaseCredentials=6 per stable-UID guarantee."""
        src = {'name': 'R', 'enforcements':
               {'restrict_record_types': 'login,databaseCredentials'}}
        tgt = {'name': 'R', 'enforcements':
               {'restrict_record_types': '{"std":[12,6],"ent":[]}'}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rrt = [c for c in checks if 'restrict_record_types' in c.message]
        self.assertTrue(any(c.severity == Severity.PASS for c in rrt),
                         f'expected PASS for shape-asymmetric match, got {rrt!r}')
        self.assertFalse(any(c.severity == Severity.FAIL for c in rrt),
                          f'expected no FAIL, got {rrt!r}')

    def test_set_difference_surfaces_missing_and_extra_names(self):
        """Genuine divergence — source asks for {login, sshKeys}, target
        only carries login (id=12). FAIL must list the missing name."""
        src = {'name': 'R', 'enforcements':
               {'restrict_record_types': 'login,sshKeys'}}
        tgt = {'name': 'R', 'enforcements':
               {'restrict_record_types': '{"std":[12],"ent":[]}'}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'restrict_record_types' in c.message]
        self.assertEqual(len(fails), 1)
        self.assertIn('sshKeys', fails[0].message)

    def test_ent_id_resolves_through_target_record_types(self):
        """Custom enterprise types resolve via target_state['record_types']
        snapshot. Source 'CustomCard', target '{"std":[],"ent":[22246]}'
        with record_types map {22246: 'CustomCard'} should PASS."""
        src = {'name': 'R', 'enforcements':
               {'restrict_record_types': 'CustomCard'}}
        tgt = {'name': 'R', 'enforcements':
               {'restrict_record_types': '{"std":[],"ent":[22246]}'}}
        record_types = [{'id': 22246,
                          'content': {'$id': 'CustomCard'}}]
        checks = list(phase_roles(self._ctx(src, tgt, record_types)))
        rrt = [c for c in checks if 'restrict_record_types' in c.message]
        self.assertTrue(any(c.severity == Severity.PASS for c in rrt),
                         f'expected PASS, got {rrt!r}')

    def test_ent_id_unresolved_surfaces_as_marker(self):
        """When target_state lacks record_types, ent IDs become explicit
        `<ent:NNN>` markers — never silently dropped."""
        src = {'name': 'R', 'enforcements':
               {'restrict_record_types': 'CustomCard'}}
        tgt = {'name': 'R', 'enforcements':
               {'restrict_record_types': '{"std":[],"ent":[22246]}'}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'restrict_record_types' in c.message]
        self.assertEqual(len(fails), 1)
        self.assertIn('<ent:22246>', fails[0].message)

    def test_both_name_strings_pass(self):
        """Pre-Bug-60 inventories captured both sides as name strings;
        regression case must still PASS."""
        src = {'name': 'R', 'enforcements':
               {'restrict_record_types': 'login,databaseCredentials'}}
        tgt = {'name': 'R', 'enforcements':
               {'restrict_record_types': 'databaseCredentials,login'}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rrt = [c for c in checks if 'restrict_record_types' in c.message]
        self.assertTrue(any(c.severity == Severity.PASS for c in rrt))
        self.assertFalse(any(c.severity == Severity.FAIL for c in rrt))


class FalseEnforcementCanonicalAbsentTests(unittest.TestCase):
    """Bug 76.1 — `false` on a BOOLEAN enforcement is canonically absent
    on target. enforcement_direct._build_request maps False →
    role_enforcement_remove (no-op against a role that didn't already
    have the key), so target's enforcement table genuinely lacks the
    entry. Verify must treat that as a successful round-trip, not FAIL."""

    def _ctx(self, src_role, tgt_role):
        entities = {'nodes': [], 'teams': [], 'users': [], 'shared_folders': [],
                    'records': [], 'roles': [src_role]}
        return ValidationContext(_inv(entities=entities), {'roles': [tgt_role]})

    def test_source_false_target_absent_is_pass(self):
        """rehearsal-15 case: Keeper Administrator role's
        `restrict_can_edit_external_shares=false` correctly absent on
        target → PASS, not FAIL."""
        src = {'name': 'R', 'enforcements':
               {'restrict_can_edit_external_shares': False}}
        tgt = {'name': 'R', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rel = [c for c in checks if 'restrict_can_edit_external_shares' in c.message]
        self.assertEqual(len(rel), 1)
        self.assertEqual(rel[0].severity, Severity.PASS)
        self.assertIn('canonical absent', rel[0].message)

    def test_source_string_false_target_absent_is_pass(self):
        """Some inventories normalize bools to lowercase strings; same
        canonical-absent rule applies."""
        src = {'name': 'R', 'enforcements':
               {'restrict_can_edit_external_shares': 'false'}}
        tgt = {'name': 'R', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rel = [c for c in checks if 'restrict_can_edit_external_shares' in c.message]
        self.assertEqual(rel[0].severity, Severity.PASS)

    def test_source_true_target_absent_still_fails(self):
        """A `true` enforcement that didn't land is a real bug — must
        still FAIL. Don't broaden the canonical-absent rule beyond
        false."""
        src = {'name': 'R', 'enforcements':
               {'restrict_can_edit_external_shares': True}}
        tgt = {'name': 'R', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'restrict_can_edit_external_shares' in c.message]
        self.assertEqual(len(fails), 1)
        self.assertIn('MISSING', fails[0].message)

    def test_source_non_bool_target_absent_still_fails(self):
        """Non-boolean keys (string/int) absent on target are real
        FAILs — canonical-absent rule applies only to bool false."""
        src = {'name': 'R', 'enforcements': {'some_key': 'expected_value'}}
        tgt = {'name': 'R', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'some_key' in c.message]
        self.assertEqual(len(fails), 1)

    def test_bug84_empty_string_source_target_absent_is_pass(self):
        """Bug 84 — empty-string source value with no target key is
        canonical-absent. Common for JSON-typed enforcements like
        `generated_password_complexity` / `master_password_reentry`
        when the source operator created the role but never
        configured the rule. Source `--enforcement KEY:` (empty) is a
        no-op against an absent target key — correct round-trip."""
        src = {'name': 'R', 'enforcements':
               {'generated_password_complexity': ''}}
        tgt = {'name': 'R', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rel = [c for c in checks
               if 'generated_password_complexity' in c.message]
        self.assertEqual(len(rel), 1)
        self.assertEqual(rel[0].severity, Severity.PASS)
        self.assertIn('canonical absent', rel[0].message)

    def test_bug84_whitespace_only_source_is_canonical_absent(self):
        """Defensive: whitespace-only source value treated same as
        empty for canonical-absent purposes."""
        src = {'name': 'R', 'enforcements':
               {'master_password_reentry': '   '}}
        tgt = {'name': 'R', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rel = [c for c in checks
               if 'master_password_reentry' in c.message
               and 'canonical absent' in c.message]
        self.assertEqual(len(rel), 1)


class RequireAccountShareMissingSkipTests(unittest.TestCase):
    """Bug 76.2 — `require_account_share` absent on target is the
    expected outcome of multiple structure-time SKIP paths (Bug 47
    self-ref / Bug 64 missing TRANSFER_ACCOUNT / Bug 51 cross-tenant
    rejection / unresolved role_id) and also carries lockout risk.
    Verify reports SKIP with operator-handoff guidance, not FAIL."""

    def _ctx(self, src_role, tgt_role):
        entities = {'nodes': [], 'teams': [], 'users': [], 'shared_folders': [],
                    'records': [], 'roles': [src_role]}
        return ValidationContext(_inv(entities=entities), {'roles': [tgt_role]})

    def test_require_account_share_missing_is_skip_not_fail(self):
        src = {'name': 'Admin', 'enforcements': {'require_account_share': 12345}}
        tgt = {'name': 'Admin', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rel = [c for c in checks if 'require_account_share' in c.message]
        self.assertEqual(len(rel), 1)
        self.assertEqual(rel[0].severity, Severity.SKIP)
        self.assertIn('lockout-risk', rel[0].message)
        self.assertIn('apply manually post-migration', rel[0].message)

    def test_require_account_share_missing_emits_no_fail(self):
        """Sanity guard: no other check accidentally FAILs the same row."""
        src = {'name': 'Admin', 'enforcements': {'require_account_share': 12345}}
        tgt = {'name': 'Admin', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'require_account_share' in c.message]
        self.assertEqual(fails, [])

    def test_other_missing_enforcements_still_fail(self):
        """The SKIP-on-missing rule is scoped to LOCKOUT_RISK_ENFORCEMENTS
        — non-lockout-risk truthy enforcements absent on target must
        still FAIL."""
        src = {'name': 'Admin', 'enforcements': {
            'require_account_share': 12345,
            'two_factor_required': True,
        }}
        tgt = {'name': 'Admin', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        ras_skip = [c for c in checks if c.severity == Severity.SKIP
                    and 'require_account_share' in c.message]
        tfa_fail = [c for c in checks if c.severity == Severity.FAIL
                    and 'two_factor_required' in c.message]
        self.assertEqual(len(ras_skip), 1)
        self.assertEqual(len(tfa_fail), 1)

    def test_all_lockout_risk_keys_skip_when_missing_on_target(self):
        """v1.7 — verify SKIPs all 4 LOCKOUT_RISK_ENFORCEMENTS uniformly
        when missing on target. This mirrors structure-side
        default-skip on builtin-admin roles (and Bug 47/64/51 SKIPs
        for require_account_share specifically). Each missing-on-target
        row should yield SKIP, not FAIL."""
        src = {'name': 'Administrator', 'enforcements': {
            'require_account_share': 12345,
            'restrict_ip_addresses': '10.0.0.0/8',
            'master_password_reentry': '{"interval_minutes": 30}',
            'two_factor_by_ip': '{"allowed": ["10.0.0.0/8"]}',
        }}
        tgt = {'name': 'Administrator', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        for key in ('require_account_share', 'restrict_ip_addresses',
                    'master_password_reentry', 'two_factor_by_ip'):
            rel = [c for c in checks if key in c.message]
            self.assertEqual(len(rel), 1, f'expected 1 row for {key}')
            self.assertEqual(rel[0].severity, Severity.SKIP,
                             f'{key} should SKIP not {rel[0].severity.name}')
            self.assertIn('lockout-risk', rel[0].message)
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and any(k in c.message for k in (
                     'require_account_share', 'restrict_ip_addresses',
                     'master_password_reentry', 'two_factor_by_ip'))]
        self.assertEqual(fails, [])


class StructureSkippedEnforcementsConsumptionTests(unittest.TestCase):
    """v1.7 / T2.2 — verify consults `structure_skipped_enforcements`
    (loaded from structure_results.csv) and sharpens the lockout-risk
    SKIP message accordingly. Pre-v1.7 artifact dirs (no per-key audit
    rows) fall back to the generic "no structure-stage SKIP recorded"
    tag, but still SKIP rather than FAIL — the safety stays the same;
    only the diagnostic changes."""

    def _ctx(self, src_role, tgt_role, skip_map):
        from keepercommander.commands.keeper_tenant_migrate.validate import ValidationContext
        entities = {'nodes': [], 'teams': [], 'users': [],
                    'shared_folders': [], 'records': [], 'roles': [src_role]}
        return ValidationContext(
            _inv(entities=entities), {'roles': [tgt_role]},
            structure_skipped_enforcements=skip_map)

    def test_skip_reason_quoted_when_audit_present(self):
        src = {'name': 'Administrator',
               'enforcements': {'require_account_share': 12345}}
        tgt = {'name': 'Administrator', 'enforcements': {}}
        skip_map = {('Administrator', 'require_account_share'):
                    'self-reference (Bug 47)'}
        checks = list(phase_roles(self._ctx(src, tgt, skip_map)))
        rel = [c for c in checks
               if 'require_account_share' in c.message]
        self.assertEqual(rel[0].severity, Severity.SKIP)
        self.assertIn('structure SKIP recorded', rel[0].message)
        self.assertIn('self-reference (Bug 47)', rel[0].message)

    def test_skip_falls_back_to_generic_when_audit_missing(self):
        """No audit row for this (role, key) pair → emit SKIP with
        "no structure-stage SKIP recorded" tag so the operator knows
        the absence wasn't recorded by structure (could be pre-v1.7
        artifact or a write-path regression)."""
        src = {'name': 'Administrator',
               'enforcements': {'require_account_share': 12345}}
        tgt = {'name': 'Administrator', 'enforcements': {}}
        checks = list(phase_roles(self._ctx(src, tgt, {})))
        rel = [c for c in checks
               if 'require_account_share' in c.message]
        self.assertEqual(rel[0].severity, Severity.SKIP)
        self.assertIn('no structure-stage SKIP recorded',
                      rel[0].message)

    def test_loader_parses_per_key_skip_rows(self):
        """`load_structure_skipped_enforcements` extracts only the
        v1.7 classify-skip rows; SUCCESS rows + non-enforcement
        categories are ignored."""
        import csv
        import os
        import tempfile

        from keepercommander.commands.keeper_tenant_migrate.validate import (
            load_structure_skipped_enforcements)

        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.csv', delete=False, newline='')
        try:
            writer = csv.writer(tmp)
            writer.writerow(['category', 'name', 'action', 'status', 'notes'])
            writer.writerow(['enforcement', 'Administrator.require_account_share',
                             'classify-skip', 'SKIPPED', 'Bug 47 self-ref'])
            writer.writerow(['enforcement', 'Admin.restrict_ip_addresses',
                             'classify-skip', 'SKIPPED', 'lockout-risk'])
            # Aggregate row should be ignored.
            writer.writerow(['enforcements', 'All roles', 'set', 'SUCCESS',
                             '600 simple; 5 skipped'])
            # Non-enforcement category should be ignored.
            writer.writerow(['role_priv', 'Admin: foo on Root',
                             'add-privilege', 'SKIPPED', 'invalid'])
            tmp.close()
            result = load_structure_skipped_enforcements(tmp.name)
            self.assertEqual(result, {
                ('Administrator', 'require_account_share'):
                    'Bug 47 self-ref',
                ('Admin', 'restrict_ip_addresses'): 'lockout-risk',
            })
        finally:
            os.unlink(tmp.name)

    def test_loader_handles_missing_file(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import (
            load_structure_skipped_enforcements)
        self.assertEqual(
            load_structure_skipped_enforcements('/nonexistent.csv'), {})
        self.assertEqual(load_structure_skipped_enforcements(''), {})


class Bug79CountAggregatorAdjustmentTests(unittest.TestCase):
    """Bug 79 — count-aggregator must subtract structure-time SKIPs +
    canonical-absent values before comparing parity. Pre-fix: source
    has 9 enforcements, structure SKIPs 1 (Bug 47/64/51 or v1.7
    lockout-risk), target has 8 → false FAIL. Post-fix: src 9 - 1
    skipped = 8 effective vs target 8 → PASS."""

    def _ctx(self, src_role, tgt_role, skip_map=None, priv_skipped=None):
        from keepercommander.commands.keeper_tenant_migrate.validate import ValidationContext
        entities = {'nodes': [], 'teams': [], 'users': [],
                    'shared_folders': [], 'records': [], 'roles': [src_role]}
        return ValidationContext(
            _inv(entities=entities), {'roles': [tgt_role]},
            structure_skipped_enforcements=skip_map or {},
            structure_skipped_privileges=priv_skipped or {})

    def test_enforcement_count_pass_when_skipped_keys_subtracted(self):
        """rehearsal-16 case: MIGTEST-Role-Admin source has 9
        enforcements, 1 SKIPed at classify-time (require_account_share
        self-ref Bug 47), target has 8 enforcements. Adjusted source
        count = 9 - 1 = 8 → no FAIL."""
        src = {'name': 'R', 'enforcements': {
            f'key{i}': True for i in range(8)
        }}
        src['enforcements']['require_account_share'] = '12345'
        tgt = {'name': 'R', 'enforcements': {
            f'key{i}': True for i in range(8)
        }}
        skip_map = {('R', 'require_account_share'):
                    'self-reference (Bug 47)'}
        checks = list(phase_roles(self._ctx(src, tgt, skip_map=skip_map)))
        count_fails = [c for c in checks if c.severity == Severity.FAIL
                       and 'enforcements count' in c.message]
        self.assertEqual(count_fails, [],
                         f'expected no count FAIL; got {[c.message for c in count_fails]}')

    def test_enforcement_count_fails_when_unexplained_drift(self):
        """Without a structure-time SKIP record, count drift is still
        a real FAIL — the safety-net behavior pre-Bug-79 is
        preserved for genuine divergence."""
        src = {'name': 'R', 'enforcements': {
            'key1': True, 'key2': True, 'key3': True
        }}
        tgt = {'name': 'R', 'enforcements': {'key1': True}}
        checks = list(phase_roles(self._ctx(src, tgt, skip_map={})))
        count_fails = [c for c in checks if c.severity == Severity.FAIL
                       and 'enforcements count' in c.message]
        self.assertEqual(len(count_fails), 1)

    def test_enforcement_count_pass_when_canonical_absent(self):
        """Bug 76.1 — `false` boolean enforcements canonically absent
        on target. Source count includes them; target count doesn't.
        Adjustment subtracts the canonical-absent count."""
        src = {'name': 'R', 'enforcements': {
            'truthy_enf': True,
            'falsy_enf_1': False,
            'falsy_enf_2': False,
        }}
        tgt = {'name': 'R', 'enforcements': {'truthy_enf': True}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        count_fails = [c for c in checks if c.severity == Severity.FAIL
                       and 'enforcements count' in c.message]
        self.assertEqual(count_fails, [])

    def test_enforcement_count_pass_when_cross_tenant_id_absent(self):
        """rehearsal-17 Tier 6 case: MIGTEST-Role-Admin source has 9
        enforcements including `require_account_share` whose value is
        the SOURCE role's own server-assigned ID (self-reference per
        Bug 47 / Upstream-1). Plugin-side classify_enforcement skips
        the write; structure_results.csv may or may not record the
        skip depending on the code path. Either way, target has 8
        enforcements (missing `require_account_share`). Verify must
        recognise that cross-tenant-ID enforcements absent from target
        are an EXPECTED count-diff (the value couldn't survive the
        cross-tenant remap by design) and not flag the count as FAIL.
        This is the verify-emit precision improvement that closes the
        Tier 6 verify FAIL without depending on structure_results.csv
        having the right skip row."""
        src = {'name': 'MIGTEST-Role-Admin', 'enforcements': {
            f'key{i}': True for i in range(8)
        }}
        src['enforcements']['require_account_share'] = '12058/51788715655757'
        # Target is missing require_account_share entirely (the
        # rehearsal-17 ground truth from c3po:/tmp/rehearsal-17-tier6-real/).
        tgt = {'name': 'MIGTEST-Role-Admin', 'enforcements': {
            f'key{i}': True for i in range(8)
        }}
        # Critically: skip_map is EMPTY — the rehearsal didn't have
        # the structure_results.csv skip row, but cross-tenant-ID
        # detection should kick in regardless.
        checks = list(phase_roles(self._ctx(src, tgt, skip_map={})))
        count_fails = [c for c in checks if c.severity == Severity.FAIL
                       and 'enforcements count' in c.message]
        self.assertEqual(count_fails, [],
                         f'expected no count FAIL; got {[c.message for c in count_fails]}')

    def test_cross_tenant_id_filter_no_double_count_with_skip_map(self):
        """Defensive: when a cross-tenant-ID key is ALSO in
        structure_skipped_enforcements (the canonical path), the
        union-based adjustment must NOT double-subtract."""
        src = {'name': 'R', 'enforcements': {
            'key1': True, 'key2': True,
            'require_account_share': '12058/51788715655757',
        }}
        # Source has 3 enforcements; require_account_share is in BOTH
        # skip_map AND _CROSS_TENANT_ID_ENFORCEMENTS. Target has 2.
        # Union adjustment = {require_account_share} → adj=1 →
        # effective_src = 3 - 1 = 2 → matches target. If the previous
        # `enf_skipped + enf_canonical_absent + cross_tenant_id` sum
        # had been kept, adj would be 1+0+1=2, effective_src=1, target=2,
        # 1 != 2 → spurious FAIL.
        tgt = {'name': 'R', 'enforcements': {'key1': True, 'key2': True}}
        skip_map = {('R', 'require_account_share'):
                    'self-reference (Bug 47)'}
        checks = list(phase_roles(self._ctx(src, tgt, skip_map=skip_map)))
        count_fails = [c for c in checks if c.severity == Severity.FAIL
                       and 'enforcements count' in c.message]
        self.assertEqual(count_fails, [],
                         f'union-adjustment should not double-count; '
                         f'got {[c.message for c in count_fails]}')

    def test_privilege_count_pass_when_target_edition_skipped(self):
        """Elevation approval case: source has 2 privileges, structure
        SKIPped 1 as `'invalid privilege: privilege_access'` (target-
        edition-unsupported). Adjusted source count = 2 - 1 = 1 →
        no count FAIL."""
        src = {'name': 'Elevation approval', 'managed_nodes': [{
            'node_name': 'Root', 'cascade': True,
            'privileges': ['approve_device', 'privilege_access'],
        }], 'enforcements': {}}
        tgt = {'name': 'Elevation approval', 'managed_nodes': [{
            'node_name': 'Root', 'cascade': True,
            'privileges': ['approve_device'],
        }], 'enforcements': {}}
        priv_skipped = {'Elevation approval': 1}
        checks = list(phase_roles(
            self._ctx(src, tgt, priv_skipped=priv_skipped)))
        count_fails = [c for c in checks if c.severity == Severity.FAIL
                       and 'privileges count' in c.message]
        self.assertEqual(count_fails, [])

    def test_count_fail_message_includes_adjustment_detail(self):
        """When an adjustment is applied AND counts still differ,
        the FAIL message tells the operator how much was adjusted —
        prevents head-scratching during diagnosis."""
        src = {'name': 'R', 'enforcements': {
            'key1': True, 'key2': True, 'key3': True, 'key4': True
        }}
        tgt = {'name': 'R', 'enforcements': {'key1': True}}
        skip_map = {('R', 'key2'): 'self-ref'}
        checks = list(phase_roles(self._ctx(src, tgt, skip_map=skip_map)))
        count_fails = [c for c in checks if c.severity == Severity.FAIL
                       and 'enforcements count' in c.message]
        self.assertEqual(len(count_fails), 1)
        self.assertIn('adjusted', count_fails[0].message)


class Bug78PasswordComplexityDiagnosticTests(unittest.TestCase):
    """Bug 78 — verify-side specific diagnosis of
    `generated_password_complexity` divergence. Three categories:
    multi-domain truncation, length mutation, generic value diff.
    Source-side data captured as JSON-list-of-dicts; target captures
    the same after Commander's CLI write."""

    def _ctx(self, src_role, tgt_role):
        from keepercommander.commands.keeper_tenant_migrate.validate import ValidationContext
        entities = {'nodes': [], 'teams': [], 'users': [],
                    'shared_folders': [], 'records': [], 'roles': [src_role]}
        return ValidationContext(_inv(entities=entities), {'roles': [tgt_role]})

    def test_multi_domain_truncation_emits_specific_fail(self):
        """rehearsal-15 case: source captures list[2] (default + domain-
        scoped), target shows list[1] (only first rule landed)."""
        import json
        src_value = json.dumps([
            {'domains': ['_default_'], 'length': 12},
            {'domains': ['youtube.com'], 'length': 16},
        ])
        tgt_value = json.dumps([{'domains': ['_default_'], 'length': 12}])
        src = {'name': 'R',
               'enforcements': {'generated_password_complexity': src_value}}
        tgt = {'name': 'R',
               'enforcements': {'generated_password_complexity': tgt_value}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rel = [c for c in checks if 'generated_password_complexity' in c.message]
        self.assertEqual(len(rel), 1)
        self.assertEqual(rel[0].severity, Severity.FAIL)
        self.assertIn('multi-domain truncation', rel[0].message)
        self.assertIn('Bug 78', rel[0].message)
        self.assertIn('source has 2', rel[0].message)
        self.assertIn('target has 1', rel[0].message)

    def test_length_mutation_emits_specific_fail(self):
        """Length-mutation symptom: source has length=12, target shows
        length=20 (same rule count, different value)."""
        import json
        src_value = json.dumps([{'domains': ['_default_'], 'length': 12}])
        tgt_value = json.dumps([{'domains': ['_default_'], 'length': 20}])
        src = {'name': 'R',
               'enforcements': {'generated_password_complexity': src_value}}
        tgt = {'name': 'R',
               'enforcements': {'generated_password_complexity': tgt_value}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        rel = [c for c in checks if 'generated_password_complexity' in c.message]
        self.assertEqual(len(rel), 1)
        self.assertEqual(rel[0].severity, Severity.FAIL)
        self.assertIn('length-mutation', rel[0].message)
        self.assertIn('Bug 78', rel[0].message)
        self.assertIn('src=12', rel[0].message)
        self.assertIn('target=20', rel[0].message)

    def test_matching_complexity_passes(self):
        """When source and target have identical complexity values,
        emit PASS — the diagnostic only fires on divergence."""
        import json
        v = json.dumps([{'domains': ['_default_'], 'length': 12}])
        src = {'name': 'R',
               'enforcements': {'generated_password_complexity': v}}
        tgt = {'name': 'R',
               'enforcements': {'generated_password_complexity': v}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        passes = [c for c in checks
                  if 'generated_password_complexity' in c.message
                  and c.severity == Severity.PASS]
        self.assertEqual(len(passes), 1)

    def test_non_parseable_value_falls_back_to_generic(self):
        """When the value can't parse as JSON, fall back to the
        generic `expected/actual` shape — verify still produces an
        actionable FAIL."""
        src = {'name': 'R',
               'enforcements': {'generated_password_complexity': 'not-json'}}
        tgt = {'name': 'R',
               'enforcements': {'generated_password_complexity': 'also-not-json'}}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks
                 if 'generated_password_complexity' in c.message
                 and c.severity == Severity.FAIL]
        self.assertEqual(len(fails), 1)
        self.assertIn('expected=', fails[0].message)


class Bug81MspAutoProvisionedRolesTests(unittest.TestCase):
    """Bug 81 — MSP-edition target tenants auto-bind managed_nodes to
    specific built-in roles (e.g. `MSP Subscription Manager` gets a
    managed_node binding the source had no equivalent for). Verify
    can't predict tenant-edition auto-bindings, so the count diff
    on these specific roles downgrades from FAIL to WARN."""

    def _ctx(self, src_role, tgt_role):
        from keepercommander.commands.keeper_tenant_migrate.validate import ValidationContext
        entities = {'nodes': [], 'teams': [], 'users': [],
                    'shared_folders': [], 'records': [], 'roles': [src_role]}
        return ValidationContext(_inv(entities=entities), {'roles': [tgt_role]})

    def test_msp_subscription_manager_extra_managed_node_is_warn(self):
        """rehearsal-16 case: source has 0 managed_nodes on this role,
        target (MSP Keeperdemo) has 1 (auto-bound to MSP root).
        Should WARN, not FAIL."""
        src = {'name': 'MSP Subscription Manager', 'managed_nodes': []}
        tgt = {'name': 'MSP Subscription Manager', 'managed_nodes': [{
            'node_name': 'Root', 'cascade': True, 'privileges': []
        }]}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'managed_nodes' in c.message]
        warns = [c for c in checks if c.severity == Severity.WARN
                 and 'MSP-edition' in c.message]
        self.assertEqual(fails, [],
                         f'expected no FAIL; got {[c.message for c in fails]}')
        self.assertEqual(len(warns), 1)

    def test_non_msp_role_with_extra_managed_node_still_fails(self):
        """The MSP downgrade is scoped to the allowlist. A custom role
        with target-extra managed_nodes still FAILs."""
        src = {'name': 'Custom Role', 'managed_nodes': []}
        tgt = {'name': 'Custom Role', 'managed_nodes': [{
            'node_name': 'Root', 'cascade': True, 'privileges': []
        }]}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'managed_nodes count' in c.message]
        self.assertEqual(len(fails), 1)

    def test_msp_role_handles_migrated_suffix(self):
        """MSP role surfaced post-rename (`MSP Subscription Manager
        (Migrated)`) should still match the allowlist."""
        src = {'name': 'MSP Subscription Manager', 'managed_nodes': []}
        tgt = {'name': 'MSP Subscription Manager (Migrated)',
               'managed_nodes': [{
                   'node_name': 'Root', 'cascade': True, 'privileges': []
               }]}
        # Test via bare_for_msp path; needs rename_map to align names.
        # Easier: just verify the suffix-stripping logic by passing the
        # suffixed name as both src and tgt.
        from keepercommander.commands.keeper_tenant_migrate.validate import ValidationContext
        entities = {'nodes': [], 'teams': [], 'users': [],
                    'shared_folders': [], 'records': [],
                    'roles': [{'name': 'MSP Subscription Manager (Migrated)',
                               'managed_nodes': []}]}
        ctx = ValidationContext(_inv(entities=entities),
                                 {'roles': [tgt]})
        checks = list(phase_roles(ctx))
        warns = [c for c in checks if c.severity == Severity.WARN
                 and 'MSP-edition' in c.message]
        self.assertEqual(len(warns), 1)

    def test_msp_role_with_LESS_managed_nodes_on_target_still_fails(self):
        """The downgrade only applies when target has MORE bindings
        (the auto-provisioning vector). If source has more than
        target, that's a real migration drop and should FAIL."""
        src = {'name': 'MSP Subscription Manager', 'managed_nodes': [{
            'node_name': 'Root', 'cascade': True, 'privileges': []
        }, {'node_name': 'Sub', 'cascade': False, 'privileges': []}]}
        tgt = {'name': 'MSP Subscription Manager', 'managed_nodes': [{
            'node_name': 'Root', 'cascade': True, 'privileges': []
        }]}
        checks = list(phase_roles(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'managed_nodes count' in c.message]
        self.assertEqual(len(fails), 1)


class Bug79LoaderTests(unittest.TestCase):
    """Loader for `role_priv` SKIPPED rows in structure_results.csv —
    name shape is `<role>: <privilege> on <node>`. Loader handles role
    names containing colons (e.g. `Access Level: Read-Only`) by
    anchoring on the rightmost ` on ` boundary."""

    def _write_csv(self, rows):
        import csv
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.csv', delete=False, newline='')
        try:
            writer = csv.writer(tmp)
            writer.writerow(['category', 'name', 'action', 'status', 'notes'])
            for r in rows:
                writer.writerow(r)
            tmp.close()
            return tmp.name
        except Exception:
            os.unlink(tmp.name)
            raise

    def test_loader_counts_role_priv_skipped_rows(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import (
            load_structure_skipped_privileges)
        path = self._write_csv([
            ['role_priv', 'Elevation approval: privilege_access on Root',
             'add-privilege', 'SKIPPED', 'invalid'],
            ['role_priv', 'Elevation approval: manage_billing on Root',
             'add-privilege', 'SKIPPED', 'invalid'],
            ['role_priv', 'Other Role: foo on Root',
             'add-privilege', 'SUCCESS', ''],
            ['enforcement', 'X.y', 'classify-skip', 'SKIPPED', 'reason'],
        ])
        try:
            counts = load_structure_skipped_privileges(path)
            self.assertEqual(counts, {'Elevation approval': 2})
        finally:
            import os
            os.unlink(path)

    def test_loader_handles_role_name_with_colon(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import (
            load_structure_skipped_privileges)
        path = self._write_csv([
            ['role_priv', 'Access Level: Read-Only: priv_x on Some Node',
             'add-privilege', 'SKIPPED', 'invalid'],
        ])
        try:
            counts = load_structure_skipped_privileges(path)
            self.assertEqual(counts, {'Access Level: Read-Only': 1})
        finally:
            import os
            os.unlink(path)

    def test_loader_missing_file_returns_empty(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import (
            load_structure_skipped_privileges)
        self.assertEqual(
            load_structure_skipped_privileges('/nonexistent.csv'), {})


class Bug78PrivilegeSkipSetTests(unittest.TestCase):
    """Bug 78 derivative — `_compare_role_privileges` consults a
    per-(role, priv) skip set so target-edition-unsupported privileges
    (manage_billing / privilege_access on a non-MSP target) are SKIP
    instead of FAIL. Companion to Bug 79's count adjust."""

    def _write_csv(self, rows):
        import csv
        import tempfile
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.csv', delete=False, newline='')
        writer = csv.writer(tmp)
        writer.writerow(['category', 'name', 'action', 'status', 'notes'])
        for r in rows:
            writer.writerow(r)
        tmp.close()
        return tmp.name

    def test_skip_set_loader_returns_per_role_priv_pairs(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import (
            load_structure_skipped_privileges_set)
        path = self._write_csv([
            ['role_priv', 'KA (Migrated): privilege_access on Root',
             'add-privilege', 'SKIPPED', 'invalid'],
            ['role_priv', 'KA (Migrated): manage_billing on Root',
             'add-privilege', 'SKIPPED', 'invalid'],
            ['role_priv', 'Other: ok on Root',
             'add-privilege', 'SUCCESS', ''],
        ])
        try:
            skip_set = load_structure_skipped_privileges_set(path)
            self.assertEqual(skip_set, {
                ('KA (Migrated)', 'privilege_access'),
                ('KA (Migrated)', 'manage_billing'),
            })
        finally:
            import os
            os.unlink(path)

    def test_skip_set_lowercases_privilege_name(self):
        """Compare against `_compare_role_privileges` which iterates
        privileges as-stored (lowercase per Commander's API). Loader
        normalizes to lowercase so the lookup matches."""
        from keepercommander.commands.keeper_tenant_migrate.validate import (
            load_structure_skipped_privileges_set)
        path = self._write_csv([
            ['role_priv', 'R: PRIVILEGE_ACCESS on Root',
             'add-privilege', 'SKIPPED', 'invalid'],
        ])
        try:
            skip_set = load_structure_skipped_privileges_set(path)
            self.assertIn(('R', 'privilege_access'), skip_set)
        finally:
            import os
            os.unlink(path)

    def test_compare_role_privileges_skip_with_matching_set(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import _compare_role_privileges
        src = {'privileges': ['manage_user', 'privilege_access']}
        tgt = {'privileges': ['manage_user']}
        # Without skip_privs: privilege_access → FAIL
        no_skip = list(_compare_role_privileges('roles', 'R', src, tgt))
        self.assertTrue(any(
            c.severity == Severity.FAIL and 'privilege_access' in c.message
            for c in no_skip))
        # With skip_privs containing the priv: → SKIP
        with_skip = list(_compare_role_privileges(
            'roles', 'R', src, tgt, skip_privs={'privilege_access'}))
        self.assertFalse(any(
            c.severity == Severity.FAIL and 'privilege_access' in c.message
            for c in with_skip))
        self.assertTrue(any(
            c.severity == Severity.SKIP and 'privilege_access' in c.message
            for c in with_skip))


class UsersStageStatusDetectionTests(unittest.TestCase):
    """Detect whether auto-migrate's `users` stage was run, so verify
    can downgrade source-user-not-on-target NOT FOUND from FAIL to
    SKIP when the operator hasn't yet invited users."""

    def _write_audit_log(self, lines):
        import tempfile
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.log', delete=False)
        for line in lines:
            tmp.write(line + '\n')
        tmp.close()
        return tmp.name

    def test_returns_skipped_when_other_subcommands_present(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import detect_users_stage_status
        path = self._write_audit_log([
            '{"subcommand": "structure", "summary": {}}',
            '{"subcommand": "verify", "summary": {}}',
        ])
        try:
            self.assertEqual(detect_users_stage_status(path), 'skipped')
        finally:
            import os; os.unlink(path)

    def test_returns_ran_when_users_subcommand_present(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import detect_users_stage_status
        path = self._write_audit_log([
            '{"subcommand": "structure", "summary": {}}',
            '{"subcommand": "users", "summary": {"counters": {"INVITED": 5}}}',
        ])
        try:
            self.assertEqual(detect_users_stage_status(path), 'ran')
        finally:
            import os; os.unlink(path)

    def test_returns_unknown_when_audit_log_missing(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import detect_users_stage_status
        self.assertEqual(detect_users_stage_status('/nonexistent.log'),
                         'unknown')
        self.assertEqual(detect_users_stage_status(None), 'unknown')

    def test_phase_users_emits_skip_when_stage_skipped(self):
        """User missing on target + users-stage-skipped → SKIP, not FAIL."""
        src = [{'email': 'u@x', 'teams': [], 'roles': []}]
        ctx = ValidationContext(_inv(entities={
            'nodes': [], 'teams': [], 'roles': [], 'shared_folders': [],
            'records': [], 'users': src,
        }), {'users': []}, users_stage_status='skipped')
        checks = list(phase_users(ctx))
        skips = [c for c in checks
                 if c.severity == Severity.SKIP and 'u@x' in c.message]
        self.assertEqual(len(skips), 1)
        self.assertIn('not yet invited', skips[0].message)
        # No FAIL on the same user
        fails = [c for c in checks
                 if c.severity == Severity.FAIL and 'u@x' in c.message]
        self.assertEqual(len(fails), 0)

    def test_phase_users_keeps_fail_when_stage_status_unknown(self):
        """Pre-v1.7 behavior preserved when no audit.log signal:
        missing source user is still FAIL."""
        src = [{'email': 'u@x', 'teams': [], 'roles': []}]
        ctx = ValidationContext(_inv(entities={
            'nodes': [], 'teams': [], 'roles': [], 'shared_folders': [],
            'records': [], 'users': src,
        }), {'users': []})  # default users_stage_status='unknown'
        checks = list(phase_users(ctx))
        self.assertTrue(any(c.severity == Severity.FAIL
                            and 'NOT FOUND' in c.message for c in checks))


class PhaseSharedFoldersTests(unittest.TestCase):
    def test_missing_sf_is_fail(self):
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                             'records': [],
                             'shared_folders': [{'name': 'SF1'}]})
        checks = list(phase_shared_folders(ValidationContext(inv, {'shared_folders': []})))
        self.assertTrue(any(c.severity == Severity.FAIL for c in checks))

    def test_default_flag_drift_is_warn(self):
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                             'records': [],
                             'shared_folders': [{'name': 'SF1', 'default_can_edit': True}]})
        tgt = {'shared_folders': [{'name': 'SF1', 'default_can_edit': False}]}
        checks = list(phase_shared_folders(ValidationContext(inv, tgt)))
        warns = [c for c in checks if c.severity == Severity.WARN]
        self.assertTrue(any('default_can_edit' in c.message for c in warns))

    def test_per_user_perm_drift_is_warn(self):
        src_sf = {'name': 'SF1', 'users': [
            {'username': 'a@x', 'can_edit': True, 'can_share': True,
             'manage_users': False, 'manage_records': False},
        ]}
        tgt_sf = {'name': 'SF1', 'users': [
            {'username': 'a@x', 'can_edit': False, 'can_share': True,
             'manage_users': False, 'manage_records': False},
        ]}
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                             'records': [],
                             'shared_folders': [src_sf]})
        tgt = {'shared_folders': [tgt_sf]}
        checks = list(phase_shared_folders(ValidationContext(inv, tgt)))
        warns = [c for c in checks if c.severity == Severity.WARN]
        self.assertTrue(
            any('a@x' in c.message and 'can_edit' in c.message for c in warns))

    def test_missing_user_in_target_is_warn(self):
        src_sf = {'name': 'SF1', 'users': [{'username': 'a@x', 'can_edit': True}]}
        tgt_sf = {'name': 'SF1', 'users': []}
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                             'records': [],
                             'shared_folders': [src_sf]})
        checks = list(phase_shared_folders(
            ValidationContext(inv, {'shared_folders': [tgt_sf]})))
        warns = [c for c in checks if c.severity == Severity.WARN]
        self.assertTrue(
            any('a@x' in c.message and 'MISSING' in c.message for c in warns))

    def test_extra_user_on_target_is_warn(self):
        src_sf = {'name': 'SF1', 'users': []}
        tgt_sf = {'name': 'SF1', 'users': [{'username': 'extra@x'}]}
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                             'records': [],
                             'shared_folders': [src_sf]})
        checks = list(phase_shared_folders(
            ValidationContext(inv, {'shared_folders': [tgt_sf]})))
        self.assertTrue(any('EXTRA' in c.message and 'extra@x' in c.message
                             for c in checks))

    def test_team_perm_drift_is_warn(self):
        src_sf = {'name': 'SF1', 'teams': [
            {'name': 'T1', 'manage_users': True, 'manage_records': False},
        ]}
        tgt_sf = {'name': 'SF1', 'teams': [
            {'name': 'T1', 'manage_users': False, 'manage_records': False},
        ]}
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                             'records': [],
                             'shared_folders': [src_sf]})
        checks = list(phase_shared_folders(
            ValidationContext(inv, {'shared_folders': [tgt_sf]})))
        warns = [c for c in checks if c.severity == Severity.WARN]
        self.assertTrue(any('T1' in c.message and 'manage_users' in c.message
                             for c in warns))


class PhaseRecordsTests(unittest.TestCase):
    def _ctx(self, src_rec, tgt_rec):
        return ValidationContext(
            _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                           'shared_folders': [], 'records': [src_rec]}),
            {'records': [tgt_rec]} if tgt_rec else {'records': []},
        )

    def test_missing_record_is_fail(self):
        checks = list(phase_records(self._ctx({'title': 'R'}, None)))
        self.assertTrue(any(c.severity == Severity.FAIL for c in checks))

    def test_attachment_count_drift_is_warn(self):
        src = {'title': 'R', 'attachment_count': 2}
        tgt = {'title': 'R', 'attachment_count': 1}
        checks = list(phase_records(self._ctx(src, tgt)))
        warns = [c for c in checks if c.severity == Severity.WARN]
        self.assertTrue(any('attachment_count' in c.message for c in warns))

    def test_totp_drift_is_warn(self):
        src = {'title': 'R', 'has_totp': True}
        tgt = {'title': 'R', 'has_totp': False}
        checks = list(phase_records(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.WARN and 'has_totp' in c.message for c in checks))

    def test_record_type_mismatch_is_fail(self):
        """Bug 41 — pre-fix phase_records didn't compare record `type`,
        which is how Bug 34 (every non-login record imported as `login`)
        evaded detection. The check now FAILs when src_type !=
        target_type so the operator catches type degradation in verify.
        """
        src = {'title': 'Notes', 'type': 'encryptedNotes'}
        tgt = {'title': 'Notes', 'type': 'login'}
        checks = list(phase_records(self._ctx(src, tgt)))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertTrue(any('type src=' in c.message for c in fails),
                        f'expected a type FAIL, got: {[str(c) for c in checks]}')

    def test_record_type_match_is_pass(self):
        src = {'title': 'Notes', 'type': 'encryptedNotes'}
        tgt = {'title': 'Notes', 'type': 'encryptedNotes'}
        checks = list(phase_records(self._ctx(src, tgt)))
        passes = [c for c in checks if c.severity == Severity.PASS]
        self.assertTrue(any('type=encryptedNotes' in c.message for c in passes))

    def test_record_type_skipped_when_either_side_missing(self):
        """Older inventories may not have `type` populated. The check
        skips silently rather than flagging false positives."""
        # src has type, tgt doesn't
        checks = list(phase_records(self._ctx(
            {'title': 'R', 'type': 'login'}, {'title': 'R'})))
        type_fails = [c for c in checks
                      if c.severity == Severity.FAIL
                      and 'type src=' in c.message]
        self.assertEqual(type_fails, [])


class PhaseRecordsFieldLevelTests(unittest.TestCase):
    """Exercises the --include-fields path: login/password/url/notes/custom diff."""

    def _ctx(self, src_rec, tgt_rec):
        return ValidationContext(
            _inv(entities={'nodes': [], 'teams': [], 'roles': [], 'users': [],
                           'shared_folders': [], 'records': [src_rec]}),
            {'records': [tgt_rec]},
        )

    def test_all_fields_match(self):
        shared = {
            'title': 'R', 'login': 'a@x', 'password': 'pw',
            'login_url': 'http://x', 'notes': 'n', 'totp_secret': '',
            'custom_fields': {'Env': 'prod'},
        }
        checks = list(phase_records(self._ctx(shared.copy(), shared.copy())))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(fails, [])

    def test_password_mismatch_is_fail(self):
        src = {'title': 'R', 'login': 'a@x', 'password': 'original'}
        tgt = {'title': 'R', 'login': 'a@x', 'password': 'DIFFERENT'}
        checks = list(phase_records(self._ctx(src, tgt)))
        pw_fails = [c for c in checks if c.severity == Severity.FAIL and 'password' in c.message]
        self.assertEqual(len(pw_fails), 1)

    def test_missing_custom_field_is_fail(self):
        src = {'title': 'R', 'login': 'a@x', 'custom_fields': {'Env': 'prod'}}
        tgt = {'title': 'R', 'login': 'a@x', 'custom_fields': {}}
        checks = list(phase_records(self._ctx(src, tgt)))
        env_missing = [c for c in checks
                       if c.severity == Severity.FAIL and 'Env' in c.message]
        self.assertEqual(len(env_missing), 1)

    def test_extra_custom_field_is_warn(self):
        src = {'title': 'R', 'login': 'a@x', 'custom_fields': {}}
        tgt = {'title': 'R', 'login': 'a@x', 'custom_fields': {'Extra': 'y'}}
        checks = list(phase_records(self._ctx(src, tgt)))
        warns = [c for c in checks
                 if c.severity == Severity.WARN and 'Extra' in c.message]
        self.assertEqual(len(warns), 1)

    def test_no_field_data_skips_field_level_checks(self):
        """Backwards-compat: inventories without --include-fields still work."""
        src = {'title': 'R', 'attachment_count': 1}
        tgt = {'title': 'R', 'attachment_count': 1}
        checks = list(phase_records(self._ctx(src, tgt)))
        # Only the "exists" PASS — no field-level comparisons
        self.assertEqual(len([c for c in checks if 'matches' in c.message]), 0)


class PhaseRecordTypesTests(unittest.TestCase):
    def test_missing_custom_type_is_fail(self):
        inv = _inv(record_types=[{'content': {'$id': 'myType'}}])
        target = {'record_types': []}
        checks = list(phase_record_types(ValidationContext(inv, target)))
        self.assertTrue(any(c.severity == Severity.FAIL for c in checks))

    def test_present_type_is_pass(self):
        inv = _inv(record_types=[{'content': {'$id': 'myType'}}])
        target = {'record_types': [{'content': {'$id': 'myType'}}]}
        checks = list(phase_record_types(ValidationContext(inv, target)))
        self.assertTrue(any(c.severity == Severity.PASS for c in checks))

    def test_no_source_types_yields_skip(self):
        checks = list(phase_record_types(ValidationContext(_inv(), {})))
        self.assertEqual(checks[0].severity, Severity.SKIP)


class PhaseUsersTests(unittest.TestCase):
    """Bug 42 — phase_users compares email match, status, node, team/role
    membership. Status policy: invited/pending => WARN (mid-flight),
    missing on target => FAIL, extra on target => WARN."""

    def _ctx(self, src_users=None, tgt_users=None):
        entities = {'nodes': [], 'teams': [], 'roles': [],
                    'shared_folders': [], 'records': [],
                    'users': src_users or []}
        return ValidationContext(_inv(entities=entities),
                                 {'users': tgt_users or []})

    def test_no_source_yields_skip(self):
        checks = list(phase_users(self._ctx()))
        self.assertEqual(checks[0].severity, Severity.SKIP)

    def test_missing_source_user_is_fail(self):
        src = [{'email': 'u@x', 'teams': [], 'roles': []}]
        checks = list(phase_users(self._ctx(src, [])))
        self.assertTrue(any(c.severity == Severity.FAIL
                            and 'NOT FOUND' in c.message for c in checks))

    def test_invited_status_is_warn(self):
        src = [{'email': 'u@x'}]
        tgt = [{'email': 'u@x', 'status': 'invited'}]
        checks = list(phase_users(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.WARN
                            and 'invited' in c.message for c in checks))

    def test_active_status_is_pass(self):
        src = [{'email': 'u@x'}]
        tgt = [{'email': 'u@x', 'status': 'active'}]
        checks = list(phase_users(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.PASS
                            and 'status=active' in c.message for c in checks))

    def test_team_missing_is_fail(self):
        src = [{'email': 'u@x', 'teams': ['T1', 'T2']}]
        tgt = [{'email': 'u@x', 'status': 'active', 'teams': ['T1']}]
        checks = list(phase_users(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.FAIL
                            and 'team T2 MISSING' in c.message for c in checks))

    def test_role_missing_is_fail(self):
        src = [{'email': 'u@x', 'roles': ['Admin']}]
        tgt = [{'email': 'u@x', 'status': 'active', 'roles': []}]
        checks = list(phase_users(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.FAIL
                            and 'role Admin MISSING' in c.message for c in checks))

    def test_extra_target_user_is_warn(self):
        src = [{'email': 'u@x'}]
        tgt = [{'email': 'u@x', 'status': 'active'},
               {'email': 'extra@y', 'status': 'active'}]
        checks = list(phase_users(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.WARN
                            and 'EXTRA on target: extra@y' in c.message
                            for c in checks))

    def test_node_leaf_mismatch_is_warn(self):
        src = [{'email': 'u@x', 'node': 'My company\\Eng'}]
        tgt = [{'email': 'u@x', 'status': 'active', 'node': 'Keeperdemo\\Engineering'}]
        checks = list(phase_users(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.WARN
                            and 'node leaf' in c.message for c in checks))

    def test_node_leaf_match_passes(self):
        # Cross-tenant root remap: leaf names match, root differs — still PASS.
        src = [{'email': 'u@x', 'node': 'My company\\Eng'}]
        tgt = [{'email': 'u@x', 'status': 'active', 'node': 'Keeperdemo\\Eng'}]
        checks = list(phase_users(self._ctx(src, tgt)))
        self.assertTrue(any(c.severity == Severity.PASS
                            and 'node leaf=Eng' in c.message for c in checks))

    def test_email_case_insensitive(self):
        src = [{'email': 'U@X'}]
        tgt = [{'email': 'u@x', 'status': 'active'}]
        checks = list(phase_users(self._ctx(src, tgt)))
        # No FAIL on missing-user despite case mismatch.
        self.assertFalse(any(c.severity == Severity.FAIL for c in checks))


class PhaseEntityCountsTests(unittest.TestCase):
    def _inv_counts(self, **counts):
        base = {'nodes': 0, 'teams': 0, 'roles': 0, 'shared_folders': 0,
                'users': 0, 'records': 0}
        base.update(counts)
        return _inv(counts=base)

    def test_all_match_all_pass(self):
        inv = self._inv_counts(nodes=1, teams=1, roles=0, shared_folders=0)
        target = {'nodes': [{'name': 'A'}], 'teams': [{'name': 'T'}],
                  'roles': [], 'shared_folders': []}
        checks = list(phase_entity_counts(ValidationContext(inv, target)))
        self.assertTrue(all(c.severity in (Severity.PASS, Severity.SKIP) for c in checks))

    def test_fewer_than_expected_is_fail(self):
        inv = self._inv_counts(nodes=5)
        target = {'nodes': [{'name': 'A'}], 'teams': [], 'roles': [], 'shared_folders': []}
        checks = list(phase_entity_counts(ValidationContext(inv, target)))
        fail = [c for c in checks if c.severity == Severity.FAIL and c.message.startswith('nodes')]
        self.assertEqual(len(fail), 1)

    def test_more_than_expected_is_warn(self):
        inv = self._inv_counts(nodes=1)
        target = {'nodes': [{'name': 'A'}, {'name': 'B'}], 'teams': [],
                  'roles': [], 'shared_folders': []}
        checks = list(phase_entity_counts(ValidationContext(inv, target)))
        warn = [c for c in checks if c.severity == Severity.WARN and c.message.startswith('nodes')]
        self.assertEqual(len(warn), 1)


class PhaseCountParityTests(unittest.TestCase):
    """Consistency guarantee: source/target count mismatches on records/
    roles/teams are FAIL severity so a silent structure-restore drop
    gets surfaced. User-count drift is WARN (invite acceptance lag)."""

    def test_record_field_count_drift_is_fail(self):
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [],
                              'users': [], 'shared_folders': [],
                              'records': [{'title': 'R',
                                           'standard_field_count': 4,
                                           'custom_field_count': 2,
                                           'total_field_count': 6}]})
        target = {'records': [{'title': 'R',
                                'standard_field_count': 3,
                                'custom_field_count': 2,
                                'total_field_count': 5}]}
        checks = list(phase_records(ValidationContext(inv, target)))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertTrue(any('standard_field_count' in c.message for c in fails))
        self.assertTrue(any('total_field_count' in c.message for c in fails))

    def test_record_field_count_match_is_pass(self):
        shared = {'title': 'R',
                  'standard_field_count': 3, 'custom_field_count': 1,
                  'total_field_count': 4}
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [],
                              'users': [], 'shared_folders': [],
                              'records': [shared]})
        target = {'records': [shared.copy()]}
        checks = list(phase_records(ValidationContext(inv, target)))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(fails, [])

    def test_role_managed_node_count_drift_is_fail(self):
        src = {'name': 'R',
               'managed_nodes': [{'privileges': ['a']}, {'privileges': ['b']}],
               'enforcements': {}, 'teams': [], 'users': []}
        tgt = {'name': 'R',
               'managed_nodes': [{'privileges': ['a']}],
               'enforcements': {}, 'teams': [], 'users': []}
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [src],
                              'users': [], 'shared_folders': [], 'records': []})
        checks = list(phase_roles(ValidationContext(inv, {'roles': [tgt]})))
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertTrue(any('managed_nodes count' in c.message for c in fails))

    def test_role_user_count_drift_is_warn(self):
        """Invitation-acceptance delay legitimately moves the user-count —
        WARN instead of FAIL."""
        src = {'name': 'R', 'managed_nodes': [], 'enforcements': {},
               'teams': [], 'users': [{'username': 'a'}, {'username': 'b'}]}
        tgt = {'name': 'R', 'managed_nodes': [], 'enforcements': {},
               'teams': [], 'users': [{'username': 'a'}]}
        inv = _inv(entities={'nodes': [], 'teams': [], 'roles': [src],
                              'users': [], 'shared_folders': [], 'records': []})
        checks = list(phase_roles(ValidationContext(inv, {'roles': [tgt]})))
        warns = [c for c in checks if c.severity == Severity.WARN]
        self.assertTrue(any('users count' in c.message for c in warns))

    def test_team_role_count_drift_is_fail(self):
        inv = _inv(entities={'nodes': [], 'teams': [{'name': 'T', 'restricts': '',
                                                     'user_count': 0, 'role_count': 3}],
                              'roles': [], 'users': [], 'shared_folders': [],
                              'records': []})
        target = {'teams': [{'name': 'T', 'restricts': '',
                              'user_count': 0, 'role_count': 2}]}
        checks = list(phase_teams(ValidationContext(inv, target)))
        fails = [c for c in checks if c.severity == Severity.FAIL
                 and 'role_count' in c.message]
        self.assertEqual(len(fails), 1)


class PhaseVaultHealthTests(unittest.TestCase):
    def test_skip_when_no_params(self):
        ctx = ValidationContext(_inv(), {})
        checks = list(phase_vault_health(ctx))
        self.assertEqual(checks[0].severity, Severity.SKIP)
        self.assertIn('offline', checks[0].message.lower())

    def test_each_probe_catches_exception_as_skip(self):
        """When a Commander command raises, the phase returns SKIP for that
        probe rather than FAIL — we don't want a missing command to block
        the whole run."""
        class FakeParams:
            pass

        ctx = ValidationContext(_inv(), {}, params=FakeParams())
        # Each Commander command is invoked with minimal kwargs that may or
        # may not match the real parser. We expect SKIPs if Commander errors
        # out — just that we don't raise.
        checks = list(phase_vault_health(ctx))
        # Exactly 3 probes, each yields either PASS/WARN/SKIP
        self.assertEqual(len(checks), 3)
        for c in checks:
            self.assertIn(c.severity, (Severity.PASS, Severity.WARN, Severity.SKIP))


class ValidatorIntegrationTests(unittest.TestCase):
    def test_runs_all_phases_and_summarizes(self):
        inv = _inv(entities={'nodes': [{'name': 'A'}],
                             'teams': [{'name': 'T'}],
                             'roles': [], 'users': [], 'shared_folders': [], 'records': []})
        target = {'nodes': [{'name': 'A'}], 'teams': [{'name': 'T'}]}
        ctx = ValidationContext(inv, target)
        checks = Validator(ctx).run()
        counts = summarize(checks)
        self.assertGreaterEqual(counts['PASS'], 3)  # pre_flight + node + team
        self.assertEqual(counts['FAIL'], 0)


class CheckReprTests(unittest.TestCase):
    def test_repr_renders_severity_phase_message(self):
        c = Check('nodes', Severity.FAIL, 'Missing on target: X',
                   'source 3, target 2')
        r = repr(c)
        self.assertIn('FAIL', r)
        self.assertIn('nodes', r)
        self.assertIn('Missing on target: X', r)
        self.assertIn('source 3, target 2', r)
        self.assertNotIn('object at 0x', r)

    def test_repr_without_detail(self):
        r = repr(Check('pre_flight', Severity.PASS, 'loaded'))
        self.assertIn('PASS', r)
        self.assertIn('pre_flight', r)
        self.assertIn('loaded', r)


if __name__ == '__main__':
    unittest.main()
