"""Tests for `--resume` state-reconciliation in StructureRestore (G7)."""

import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.structure import (
    FakeClient,
    StepResult,
    StructureClient,
    StructureRestore,
)


def _ops(client, op):
    return [c[1] for c in client.calls if c[0] == op]


def _statuses(restore, category):
    return [(r.name, r.status, r.notes)
            for r in restore.results if r.category == category]


class StructureClientProtocolDefaultsTests(unittest.TestCase):
    """The base protocol returns empty projections so any backend
    that doesn't implement them sees a cold-start (resume = no-op
    versus a from-scratch run)."""

    def test_default_projections_return_empty(self):
        proto = StructureClient()
        self.assertEqual(proto.list_node_names(), set())
        self.assertEqual(proto.list_team_names(), set())
        self.assertEqual(proto.list_role_names(), set())
        self.assertEqual(proto.list_isolated_node_names(), set())
        self.assertEqual(proto.list_role_managed_nodes('R'), set())
        self.assertEqual(proto.list_role_privileges('R'), set())
        self.assertEqual(proto.list_role_enforcements('R'), {})
        self.assertEqual(proto.list_user_node_assignments(), {})
        self.assertEqual(proto.list_user_team_memberships(), {})
        self.assertEqual(proto.list_role_user_memberships(), {})
        self.assertEqual(proto.list_role_team_memberships(), {})
        self.assertEqual(proto.list_shared_folder_names(), set())
        self.assertEqual(proto.find_folder_uid('x', ''), '')


class FakeClientProjectionTests(unittest.TestCase):
    """FakeClient seeds let tests simulate target-side state at
    the moment the operator types `--resume`."""

    def test_seeded_state_returned_by_projections(self):
        c = FakeClient()
        c.existing_nodes = {'A', 'B'}
        c.existing_teams = {'T1'}
        c.existing_roles = {'Role-X'}
        c.existing_isolated_nodes = {'A'}
        c.existing_managed_nodes = {'Role-X': {('B', 'on')}}
        c.existing_role_privileges = {'Role-X': {('manage_users', 'B')}}
        c.existing_role_enforcements = {'Role-X': {'k': 'v'}}
        c.existing_user_nodes = {'a@x.com': 'B'}
        c.existing_user_teams = {'a@x.com': {'T1'}}
        c.existing_role_users = {'Role-X': {'a@x.com'}}
        c.existing_role_teams = {'Role-X': {'T1'}}
        c.existing_shared_folders = {'SF-1'}
        c.existing_folder_uids = {('Top', ''): 'uf-existing'}
        self.assertEqual(c.list_node_names(), {'A', 'B'})
        self.assertEqual(c.list_team_names(), {'T1'})
        self.assertEqual(c.list_role_names(), {'Role-X'})
        self.assertEqual(c.list_isolated_node_names(), {'A'})
        self.assertEqual(c.list_role_managed_nodes('Role-X'),
                         {('B', 'on')})
        self.assertEqual(c.list_role_privileges('Role-X'),
                         {('manage_users', 'B')})
        self.assertEqual(c.list_role_enforcements('Role-X'),
                         {'k': 'v'})
        self.assertEqual(c.list_user_node_assignments(),
                         {'a@x.com': 'B'})
        self.assertEqual(c.list_user_team_memberships(),
                         {'a@x.com': {'T1'}})
        self.assertEqual(c.list_role_user_memberships(),
                         {'Role-X': {'a@x.com'}})
        self.assertEqual(c.list_role_team_memberships(),
                         {'Role-X': {'T1'}})
        self.assertEqual(c.list_shared_folder_names(), {'SF-1'})
        self.assertEqual(c.find_folder_uid('Top', ''), 'uf-existing')
        self.assertEqual(c.find_folder_uid('Missing', ''), '')

    def test_unseeded_returns_empty_defaults(self):
        c = FakeClient()
        # Same shape as the protocol: every projection empty when no
        # state has been pre-loaded.
        self.assertEqual(c.list_node_names(), set())
        self.assertEqual(c.list_team_names(), set())
        self.assertEqual(c.list_role_names(), set())
        self.assertEqual(c.list_isolated_node_names(), set())
        self.assertEqual(c.list_role_managed_nodes('R'), set())
        self.assertEqual(c.list_role_privileges('R'), set())
        self.assertEqual(c.list_role_enforcements('R'), {})
        self.assertEqual(c.find_folder_uid('x', ''), '')

    def test_find_folder_uid_returns_empty_when_no_existing_dict(self):
        c = FakeClient()
        # The attribute defaults to absent — projection returns ''.
        self.assertFalse(hasattr(c, 'existing_folder_uids'))
        self.assertEqual(c.find_folder_uid('x', 'p'), '')


class ResumeFlagDefaultOffTests(unittest.TestCase):
    """Regression guard: every code path must default to resume=False
    so existing operators see no behavior change."""

    def test_default_resume_false(self):
        r = StructureRestore(FakeClient())
        self.assertFalse(r.resume)
        self.assertEqual(r.resume_skipped, 0)
        self.assertEqual(r.resume_reconciled, 0)

    def test_resume_keyword_only(self):
        # resume must be keyword-only — passing positionally would
        # accidentally turn it on if any future caller adds a
        # positional after target_root.
        with self.assertRaises(TypeError):
            StructureRestore(FakeClient(), 'src', 'tgt', '', 0.0,
                              0.0, 0, 2.0, True)

    def test_explicit_false_stays_off(self):
        r = StructureRestore(FakeClient(), resume=False)
        self.assertFalse(r.resume)


class ResumeNodesTests(unittest.TestCase):
    def test_node_already_present_is_skipped(self):
        c = FakeClient()
        c.existing_nodes = {'Child'}
        r = StructureRestore(c, source_root='Root', target_root='Root',
                              resume=True)
        nodes = [
            {'id': '1', 'name': 'Root', 'parent': '', 'isolated': False},
            {'id': '2', 'name': 'Child', 'parent': 'Root',
             'isolated': False},
            {'id': '3', 'name': 'New', 'parent': 'Root',
             'isolated': False},
        ]
        r.step_nodes(nodes)
        # Child existed → skipped. New didn't → created.
        statuses = _statuses(r, 'node')
        by_name = {n: (s, notes) for n, s, notes in statuses}
        self.assertEqual(by_name['Child'][0], StepResult.SKIPPED)
        self.assertIn('already present (resume)', by_name['Child'][1])
        self.assertEqual(by_name['New'][0], StepResult.SUCCESS)
        self.assertIn('created — was missing on resume',
                       by_name['New'][1])
        self.assertEqual(r.resume_skipped, 1)
        # Only one create_node call (for "New").
        created = [args[0] for args in _ops(c, 'create_node')]
        self.assertEqual(created, ['New'])

    def test_resume_off_creates_everything(self):
        c = FakeClient()
        c.existing_nodes = {'Child'}
        r = StructureRestore(c, source_root='Root', target_root='Root',
                              resume=False)
        r.step_nodes([
            {'id': '1', 'name': 'Root', 'parent': '', 'isolated': False},
            {'id': '2', 'name': 'Child', 'parent': 'Root',
             'isolated': False},
        ])
        # Resume off → projection ignored, every node is attempted.
        self.assertEqual(len(_ops(c, 'create_node')), 1)
        self.assertEqual(r.resume_skipped, 0)


class ResumeIsolatedFlagsTests(unittest.TestCase):
    def test_already_isolated_skipped(self):
        c = FakeClient()
        c.existing_isolated_nodes = {'A'}
        r = StructureRestore(c, resume=True)
        r.step_isolated_flags([
            {'name': 'A', 'isolated': True},
            {'name': 'B', 'isolated': True},
        ])
        # A skipped, B toggled.
        self.assertEqual(len(_ops(c, 'toggle_node_isolated')), 1)
        self.assertEqual(_ops(c, 'toggle_node_isolated')[0], ('B',))
        statuses = _statuses(r, 'node')
        by_name = {n: (s, notes) for n, s, notes in statuses}
        self.assertEqual(by_name['A'][0], StepResult.SKIPPED)
        self.assertIn('already isolated (resume)', by_name['A'][1])
        self.assertEqual(by_name['B'][0], StepResult.SUCCESS)


class ResumeTeamsTests(unittest.TestCase):
    def test_existing_team_skipped(self):
        c = FakeClient()
        c.existing_teams = {'Alpha'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        teams = [
            {'name': 'Alpha', 'node': 'My company\\NodeA', 'restricts': ''},
            {'name': 'Beta', 'node': 'My company\\NodeB', 'restricts': 'R'},
        ]
        r.step_teams(teams)
        # Alpha skipped, Beta created.
        statuses = _statuses(r, 'team')
        by_name = {n: (s, notes) for n, s, notes in statuses}
        self.assertEqual(by_name['Alpha'][0], StepResult.SKIPPED)
        self.assertIn('already present (resume)', by_name['Alpha'][1])
        self.assertEqual(by_name['Beta'][0], StepResult.SUCCESS)
        self.assertIn('created — was missing on resume',
                       by_name['Beta'][1])
        self.assertEqual([a[0] for a in _ops(c, 'create_team')], ['Beta'])

    def test_dedupe_renamed_team_check_uses_create_name(self):
        # Duplicate names get suffixed to '<name> (<node-leaf>)'. The
        # resume check must compare against `create_name`, not the
        # original source name.
        c = FakeClient()
        c.existing_teams = {'Shared (NodeA)'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        teams = [
            {'name': 'Shared', 'node': 'My company\\NodeA', 'restricts': ''},
            {'name': 'Shared', 'node': 'My company\\NodeB', 'restricts': ''},
        ]
        r.step_teams(teams)
        by_name = {r2.name: r2.status for r2 in r.results
                   if r2.category == 'team'}
        self.assertEqual(by_name['Shared (NodeA)'], StepResult.SKIPPED)
        self.assertEqual(by_name['Shared (NodeB)'], StepResult.SUCCESS)


class ResumeRolesTests(unittest.TestCase):
    def test_existing_role_skipped(self):
        c = FakeClient()
        c.existing_roles = {'Manager'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        roles = [
            {'name': 'Manager', 'node': 'My company\\NodeA',
             'new_user': True},
            {'name': 'NewRole', 'node': 'My company\\NodeB',
             'new_user': False},
        ]
        r.step_roles(roles)
        statuses = _statuses(r, 'role')
        by_name = {n: (s, notes) for n, s, notes in statuses}
        self.assertEqual(by_name['Manager'][0], StepResult.SKIPPED)
        self.assertIn('already present (resume)', by_name['Manager'][1])
        self.assertEqual(by_name['NewRole'][0], StepResult.SUCCESS)
        self.assertEqual([a[0] for a in _ops(c, 'create_role')],
                         ['NewRole'])
        # Tracked into created_roles either way so downstream gates
        # don't suppress assignments against an already-present role.
        self.assertIn('Manager', r.created_roles)
        self.assertIn('NewRole', r.created_roles)

    def test_resume_role_dedup_with_builtin_collision(self):
        c = FakeClient()
        c.existing_roles = {'Administrator (Migrated)'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        roles = [{'name': 'Administrator', 'node': 'My company\\NodeA',
                  'new_user': False}]
        r.step_roles(roles)
        # The built-in collision resolver renamed to 'Administrator
        # (Migrated)' which already exists → skipped.
        self.assertEqual(r.results[-1].status, StepResult.SKIPPED)
        self.assertEqual(r.results[-1].name, 'Administrator (Migrated)')


class ResumeManagedNodesTests(unittest.TestCase):
    def test_existing_managed_node_skipped(self):
        c = FakeClient()
        c.existing_roles = {'AdminRole'}
        c.existing_managed_nodes = {'AdminRole': {('NodeA', 'on')}}
        c.existing_role_privileges = {
            'AdminRole': {('manage_users', 'NodeA')},
        }
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        # Pre-create the role into created_roles (gate satisfied)
        r.created_roles.add('AdminRole')
        roles_complete = [{
            'name': 'AdminRole',
            'managed_nodes': [{
                'node_name': 'NodeA', 'cascade': True,
                'privileges': ['manage_users', 'manage_records'],
            }],
        }]
        r.step_managed_nodes(roles_complete)
        # No new managed-node call, no manage_users priv call,
        # but manage_records IS called (was missing).
        self.assertEqual(_ops(c, 'add_role_managed_node'), [])
        priv_calls = [args for args in _ops(c, 'add_role_privilege')]
        # Only manage_records hits the wire; manage_users was already there.
        self.assertEqual(priv_calls,
                         [('AdminRole', 'manage_records', 'NodeA')])
        # Skipped count: 1 admin row + 1 priv = 2.
        self.assertEqual(r.resume_skipped, 2)

    def test_missing_managed_node_creates(self):
        c = FakeClient()
        c.existing_roles = {'AdminRole'}
        # No managed_nodes existing → both admin row + priv created.
        r = StructureRestore(c, resume=True)
        r.created_roles.add('AdminRole')
        roles_complete = [{
            'name': 'AdminRole',
            'managed_nodes': [{
                'node_name': 'NodeA', 'cascade': False,
                'privileges': ['manage_users'],
            }],
        }]
        r.step_managed_nodes(roles_complete)
        self.assertEqual(len(_ops(c, 'add_role_managed_node')), 1)
        self.assertEqual(len(_ops(c, 'add_role_privilege')), 1)
        success = [r2.notes for r2 in r.results
                   if r2.status == StepResult.SUCCESS]
        # At least one success line carries the resume marker.
        self.assertTrue(any('was missing on resume' in n for n in success))


class ResumeEnforcementsTests(unittest.TestCase):
    def test_already_applied_enforcements_dropped(self):
        c = FakeClient()
        c.existing_role_enforcements = {
            'RoleA': {'require_two_factor': True,
                      'restrict_export': True},
        }
        r = StructureRestore(c, resume=True)
        r.created_roles.add('RoleA')
        roles_complete = [{
            'name': 'RoleA',
            'enforcements': {
                'require_two_factor': True,
                'restrict_export': True,
                'restrict_import': True,         # missing on target
            },
        }]
        result = r.step_enforcements(roles_complete)
        # Only restrict_import should land — the other two were
        # identical to target and pre-filtered.
        batch_calls = _ops(c, 'set_role_enforcements_simple_batch')
        self.assertEqual(len(batch_calls), 1)
        role_name, pairs = batch_calls[0]
        self.assertEqual(role_name, 'RoleA')
        keys = [k for k, _ in pairs]
        self.assertEqual(keys, ['restrict_import'])
        self.assertEqual(result['simple'], 1)
        # Skipped count tracks the 2 already-applied keys.
        self.assertGreaterEqual(r.resume_skipped, 2)

    def test_all_already_applied_role_skipped_entirely(self):
        c = FakeClient()
        c.existing_role_enforcements = {
            'Done': {'require_two_factor': True},
        }
        r = StructureRestore(c, resume=True)
        r.created_roles.add('Done')
        roles_complete = [{
            'name': 'Done',
            'enforcements': {'require_two_factor': True},
        }]
        result = r.step_enforcements(roles_complete)
        # No batch sent — every key matched target.
        self.assertEqual(_ops(c, 'set_role_enforcements_simple_batch'),
                         [])
        self.assertEqual(result['simple'], 0)
        # Audit-log line for the role should explicitly report the skip.
        skip_records = [r2 for r2 in r.results
                        if r2.status == StepResult.SKIPPED
                        and r2.action == 'skip-already-set']
        self.assertEqual(len(skip_records), 1)
        self.assertEqual(skip_records[0].name, 'Done')

    def test_resume_off_does_not_consult_target_enforcements(self):
        c = FakeClient()
        c.existing_role_enforcements = {
            'RoleA': {'require_two_factor': True},
        }
        r = StructureRestore(c, resume=False)
        r.created_roles.add('RoleA')
        roles_complete = [{
            'name': 'RoleA',
            'enforcements': {'require_two_factor': True},
        }]
        r.step_enforcements(roles_complete)
        # Resume off → the same enforcement DOES land on target
        # (idempotent at the Commander layer; no pre-filtering here).
        self.assertEqual(len(_ops(c, 'set_role_enforcements_simple_batch')),
                         1)
        self.assertEqual(r.resume_skipped, 0)


class ResumeUserNodesTests(unittest.TestCase):
    def test_existing_user_node_assignment_skipped(self):
        c = FakeClient()
        c.existing_user_nodes = {'a@x.com': 'NodeA'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        users = [
            {'email': 'a@x.com', 'node': 'My company\\NodeA'},
            {'email': 'b@x.com', 'node': 'My company\\NodeB'},
        ]
        r.step_user_nodes(users)
        assignments = _ops(c, 'assign_user_to_node')
        # Only b@x is assigned; a@x already on NodeA.
        self.assertEqual(assignments, [('b@x.com', 'NodeB')])
        self.assertEqual(r.resume_skipped, 1)

    def test_user_on_different_node_gets_reassigned(self):
        c = FakeClient()
        c.existing_user_nodes = {'a@x.com': 'OtherNode'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        users = [{'email': 'a@x.com', 'node': 'My company\\NodeA'}]
        r.step_user_nodes(users)
        # User is on a DIFFERENT node — re-assignment lands.
        self.assertEqual(_ops(c, 'assign_user_to_node'),
                         [('a@x.com', 'NodeA')])


class ResumeUserTeamsTests(unittest.TestCase):
    def test_existing_membership_skipped(self):
        c = FakeClient()
        c.existing_user_teams = {'a@x.com': {'T1'}}
        r = StructureRestore(c, resume=True)
        users = [
            {'email': 'a@x.com', 'teams': ['T1', 'T2']},
        ]
        r.step_user_teams(users)
        # Only T2 added; T1 already there.
        self.assertEqual(_ops(c, 'add_user_to_team'),
                         [('a@x.com', 'T2')])
        self.assertEqual(r.resume_skipped, 1)


class ResumeRoleUsersTests(unittest.TestCase):
    def test_existing_role_user_skipped(self):
        c = FakeClient()
        c.existing_role_users = {'RoleA': {'a@x.com'}}
        r = StructureRestore(c, resume=True)
        roles_complete = [{
            'name': 'RoleA',
            'users': [{'username': 'a@x.com'},
                       {'username': 'b@x.com'}],
        }]
        r.step_role_users(roles_complete)
        adds = _ops(c, 'add_user_to_role')
        # Only b@x added.
        self.assertEqual(adds, [('RoleA', 'b@x.com')])
        self.assertEqual(r.resume_skipped, 1)


class ResumeRoleTeamsTests(unittest.TestCase):
    def test_existing_role_team_skipped(self):
        c = FakeClient()
        c.existing_role_teams = {'RoleA': {'TeamX'}}
        r = StructureRestore(c, resume=True)
        roles_complete = [{
            'name': 'RoleA',
            # Non-admin role — no managed_nodes
            'managed_nodes': [],
            'teams': [{'team_name': 'TeamX'}, {'team_name': 'TeamY'}],
        }]
        r.step_role_teams(roles_complete)
        adds = _ops(c, 'add_team_to_role')
        self.assertEqual(adds, [('RoleA', 'TeamY')])
        self.assertEqual(r.resume_skipped, 1)

    def test_admin_role_still_skipped_independently_of_resume(self):
        c = FakeClient()
        r = StructureRestore(c, resume=True)
        roles_complete = [{
            'name': 'AdminRole',
            'managed_nodes': [{'node_name': 'X', 'cascade': False,
                                'privileges': []}],
            'teams': [{'team_name': 'T'}],
        }]
        r.step_role_teams(roles_complete)
        # Admin-rejection path runs before resume logic.
        self.assertEqual(_ops(c, 'add_team_to_role'), [])
        self.assertEqual(r.results[-1].status, StepResult.SKIPPED)
        self.assertIn('Admin role rejects', r.results[-1].notes)


class ResumeVaultFoldersTests(unittest.TestCase):
    def test_existing_user_folder_uid_recovered(self):
        c = FakeClient()
        c.existing_folder_uids = {('Top', ''): 'uf-existing-1'}
        r = StructureRestore(c, resume=True)
        vault_folders = [{
            'name': 'Top', 'type': 'user_folder',
            'uid': 'src-Top', 'parent_uid': '',
        }]
        uid_map = r.step_vault_folders(vault_folders)
        # No add_user_folder call — UID recovered from projection.
        self.assertEqual(_ops(c, 'add_user_folder'), [])
        self.assertEqual(uid_map['src-Top'], 'uf-existing-1')
        self.assertEqual(r.results[-1].status, StepResult.SKIPPED)
        self.assertIn('already present (resume)', r.results[-1].notes)

    def test_existing_subfolder_uid_recovered_via_parent_chain(self):
        c = FakeClient()
        c.existing_folder_uids = {
            ('Parent SF', ''): 'sf-existing',
            ('Child', 'sf-existing'): 'sff-existing-child',
        }
        r = StructureRestore(c, resume=True)
        vault_folders = [
            {'name': 'Parent SF', 'type': 'shared_folder',
             'uid': 'src-parent', 'parent_uid': ''},
            {'name': 'Child', 'type': 'shared_folder_folder',
             'uid': 'src-child', 'parent_uid': 'src-parent'},
        ]
        uid_map = r.step_vault_folders(vault_folders)
        # Both recovered without create calls.
        self.assertEqual(_ops(c, 'add_shared_folder'), [])
        self.assertEqual(_ops(c, 'add_subfolder'), [])
        self.assertEqual(uid_map['src-parent'], 'sf-existing')
        self.assertEqual(uid_map['src-child'], 'sff-existing-child')
        self.assertEqual(r.resume_skipped, 2)

    def test_partial_state_creates_only_missing_folders(self):
        c = FakeClient()
        # Parent already on target; child is missing → child gets
        # created, parent skipped.
        c.existing_folder_uids = {('Parent SF', ''): 'sf-existing'}
        r = StructureRestore(c, resume=True)
        vault_folders = [
            {'name': 'Parent SF', 'type': 'shared_folder',
             'uid': 'src-parent', 'parent_uid': ''},
            {'name': 'Child', 'type': 'shared_folder_folder',
             'uid': 'src-child', 'parent_uid': 'src-parent'},
        ]
        uid_map = r.step_vault_folders(vault_folders)
        # Parent skipped → no add_shared_folder.
        self.assertEqual(_ops(c, 'add_shared_folder'), [])
        # Child created against the recovered parent UID.
        sub_calls = _ops(c, 'add_subfolder')
        self.assertEqual(len(sub_calls), 1)
        self.assertEqual(sub_calls[0][0], 'Child')
        self.assertEqual(sub_calls[0][1], 'sf-existing')
        self.assertIn('src-child', uid_map)
        # Skip count = 1 (parent only).
        self.assertEqual(r.resume_skipped, 1)

    def test_existing_promotion_target_recovered(self):
        c = FakeClient()
        c.existing_folder_uids = {('Parent - Child', ''): 'sf-promoted'}
        promotion_plan = {
            'src-child': {'proposed_promoted_name': 'Parent - Child'},
        }
        r = StructureRestore(c, resume=True)
        vault_folders = [{
            'name': 'Child', 'type': 'shared_folder_folder',
            'uid': 'src-child', 'parent_uid': 'src-parent',
        }]
        uid_map = r.step_vault_folders(
            vault_folders,
            uid_map={'src-parent': 'sf-existing-parent'},
            promotion_plan=promotion_plan,
        )
        # No promotion call — already on target.
        self.assertEqual(_ops(c, 'add_shared_folder'), [])
        self.assertEqual(uid_map['src-child'], 'sf-promoted')


class ResumeIdempotencyTests(unittest.TestCase):
    """A second consecutive `--resume` run must be a clean no-op."""

    def test_double_resume_run_is_no_op(self):
        # Cycle 1: cold start. Cycle 2: --resume. Cycle 3: --resume again.
        nodes = [
            {'id': '1', 'name': 'Root', 'parent': '',
             'isolated': False},
            {'id': '2', 'name': 'A', 'parent': 'Root',
             'isolated': False},
            {'id': '3', 'name': 'B', 'parent': 'Root',
             'isolated': True},
        ]
        teams = [{'name': 'T1', 'node': 'Root\\A', 'restricts': ''}]
        roles = [{'name': 'R1', 'node': 'Root\\A', 'new_user': False}]
        users = [{'email': 'u@x.com', 'node': 'Root\\A',
                  'teams': ['T1'], 'roles': ['R1']}]
        roles_complete = [{
            'name': 'R1',
            'managed_nodes': [],
            'enforcements': {'audit_user_login': True},
            'users': [{'username': 'u@x.com'}],
            'teams': [],
        }]

        # ── Cycle 1 — cold start, no resume.
        c1 = FakeClient()
        r1 = StructureRestore(c1, source_root='Root',
                               target_root='Root', resume=False)
        r1.step_nodes(nodes)
        r1.step_isolated_flags(nodes)
        r1.step_teams(teams)
        r1.step_roles(roles)
        r1.step_managed_nodes(roles_complete)
        r1.step_enforcements(roles_complete)
        r1.step_user_nodes(users)
        r1.step_user_teams(users)
        r1.step_role_users(roles_complete)
        cold_total_calls = len(c1.calls)
        self.assertGreater(cold_total_calls, 0)

        # ── Cycle 2 — replay with resume=True against full target.
        c2 = FakeClient()
        c2.existing_nodes = {'A', 'B'}
        c2.existing_isolated_nodes = {'B'}
        c2.existing_teams = {'T1'}
        c2.existing_roles = {'R1'}
        c2.existing_role_enforcements = {'R1': {'audit_user_login': True}}
        c2.existing_user_nodes = {'u@x.com': 'A'}
        c2.existing_user_teams = {'u@x.com': {'T1'}}
        c2.existing_role_users = {'R1': {'u@x.com'}}
        r2 = StructureRestore(c2, source_root='Root',
                               target_root='Root', resume=True)
        r2.step_nodes(nodes)
        r2.step_isolated_flags(nodes)
        r2.step_teams(teams)
        r2.step_roles(roles)
        r2.step_managed_nodes(roles_complete)
        r2.step_enforcements(roles_complete)
        r2.step_user_nodes(users)
        r2.step_user_teams(users)
        r2.step_role_users(roles_complete)
        # NO mutating calls landed — every entity already on target.
        mutating = [op for op, _ in c2.calls
                    if op.startswith(('create_', 'add_', 'assign_',
                                      'set_', 'toggle_'))]
        self.assertEqual(mutating, [],
                          msg=f'cycle-2 unexpected ops: {mutating}')
        # The only SUCCESS record allowed is step_enforcements'
        # summary line — every entity was skipped, summary tally
        # had 0 fails, so the rolled-up record reads SUCCESS.
        success_records = [r for r in r2.results
                           if r.status == StepResult.SUCCESS]
        self.assertTrue(all(r.category == 'enforcements'
                             and r.name == 'All roles'
                             for r in success_records),
                         msg=f'unexpected SUCCESS lines: '
                              f'{[(r.category, r.name) for r in success_records]}')
        self.assertGreater(r2.counters['SKIPPED'], 0)
        # Cycle-3 sanity: same projection state, run again, still no-op.
        c3 = FakeClient()
        c3.existing_nodes = c2.existing_nodes
        c3.existing_isolated_nodes = c2.existing_isolated_nodes
        c3.existing_teams = c2.existing_teams
        c3.existing_roles = c2.existing_roles
        c3.existing_role_enforcements = c2.existing_role_enforcements
        c3.existing_user_nodes = c2.existing_user_nodes
        c3.existing_user_teams = c2.existing_user_teams
        c3.existing_role_users = c2.existing_role_users
        r3 = StructureRestore(c3, source_root='Root',
                               target_root='Root', resume=True)
        r3.step_nodes(nodes)
        r3.step_isolated_flags(nodes)
        r3.step_teams(teams)
        r3.step_roles(roles)
        r3.step_managed_nodes(roles_complete)
        r3.step_enforcements(roles_complete)
        r3.step_user_nodes(users)
        r3.step_user_teams(users)
        r3.step_role_users(roles_complete)
        success_r3 = [r for r in r3.results
                      if r.status == StepResult.SUCCESS]
        self.assertTrue(all(r.category == 'enforcements'
                             for r in success_r3))


class ResumePartialStateRecoveryTests(unittest.TestCase):
    """Mid-stage crash scenario: some entities created, others
    missing. --resume creates only the missing ones."""

    def test_mid_stage_died_during_teams(self):
        c = FakeClient()
        # Pretend cycle-1 created nodes + Alpha team but died before
        # Beta or Gamma. Resume should pick up Beta + Gamma only.
        c.existing_nodes = {'A', 'B', 'C'}
        c.existing_teams = {'Alpha'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root', resume=True)
        # Step 1
        r.step_nodes([
            {'id': '1', 'name': 'My company', 'parent': '',
             'isolated': False},
            {'id': '2', 'name': 'A', 'parent': 'My company',
             'isolated': False},
            {'id': '3', 'name': 'B', 'parent': 'My company',
             'isolated': False},
            {'id': '4', 'name': 'C', 'parent': 'My company',
             'isolated': False},
        ])
        # Step 3
        r.step_teams([
            {'name': 'Alpha', 'node': 'My company\\A', 'restricts': ''},
            {'name': 'Beta', 'node': 'My company\\B', 'restricts': ''},
            {'name': 'Gamma', 'node': 'My company\\C', 'restricts': ''},
        ])
        # Three nodes already present → 0 create_node calls.
        self.assertEqual(len(_ops(c, 'create_node')), 0)
        # One team already present (Alpha) → 2 create_team calls.
        team_names_created = sorted(
            args[0] for args in _ops(c, 'create_team'))
        self.assertEqual(team_names_created, ['Beta', 'Gamma'])

    def test_audit_log_distinguishes_three_outcomes(self):
        # On a single resume run there can be entries with all three
        # distinct notes: skipped/created/reconciled (enforcements).
        c = FakeClient()
        # Scope_node is set so AlreadyHere is NOT the source root,
        # and topological_node_order emits it as the scoped root.
        c.existing_nodes = {'AlreadyHere'}
        c.existing_role_enforcements = {
            'R1': {'require_two_factor': True},
        }
        c.existing_roles = {'R1'}
        r = StructureRestore(c, source_root='My company',
                              target_root='Root',
                              scope_node='AlreadyHere', resume=True)
        r.step_nodes([
            {'id': '1', 'name': 'AlreadyHere', 'parent': '',
             'isolated': False},
            {'id': '2', 'name': 'NewlyMissing',
             'parent': 'AlreadyHere', 'isolated': False},
        ])
        r.created_roles.add('R1')
        r.step_enforcements([{
            'name': 'R1',
            'enforcements': {'require_two_factor': True,
                              'restrict_export': True},
        }])
        notes = ' '.join(r2.notes for r2 in r.results)
        self.assertIn('already present (resume)', notes)
        self.assertIn('created — was missing on resume', notes)
        self.assertIn('already applied (resume)', notes)


class ResumeParserDefaultOffTests(unittest.TestCase):
    """Regression test: existing operators see no behavior change
    from G7 — `--resume` is opt-in only."""

    def test_parser_default_off(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import structure_parser
        # Parse with no --resume flag, only required args.
        ns = structure_parser.parse_args(['--inventory', '/tmp/foo.json'])
        self.assertFalse(ns.resume)

    def test_parser_resume_set_when_flag_present(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import structure_parser
        ns = structure_parser.parse_args(
            ['--inventory', '/tmp/foo.json', '--resume'])
        self.assertTrue(ns.resume)


class ResumeAuditTelemetryTests(unittest.TestCase):
    """The `structure` audit-log event under --resume must include
    a `resume` block summarizing skipped + reconciled counts."""

    def test_resume_audit_telemetry(self):
        # Simulate a resume run: pre-seed target, run minimal steps,
        # verify audit payload includes the resume block.
        from keepercommander.commands.keeper_tenant_migrate.commands import StructureCommand
        cmd = StructureCommand()
        with tempfile.TemporaryDirectory() as run_dir:
            inv_path = os.path.join(run_dir, 'inventory.json')
            with open(inv_path, 'w') as f:
                json.dump({
                    'source_root': 'My company',
                    'target_root': 'Root',
                    'entities': {
                        'nodes': [],
                        'teams': [],
                        'roles': [],
                        'users': [],
                        'vault_folders': [],
                    },
                }, f)
            audit_path = os.path.join(run_dir, 'audit.log')

            class _Params:
                def __init__(self):
                    self.enterprise = {
                        'enterprise_name': 'Root',
                        'nodes': [{'node_id': 1,
                                    'data': {'displayname': 'Root'},
                                    'parent_id': None}],
                        'teams': [],
                        'roles': [],
                        'users': [],
                    }

            class _FakeStructureClient:
                def __init__(self, params):
                    self.params = params
                    # Minimal protocol — no methods called by empty
                    # inventory step pipeline.
                def __getattr__(self, name):
                    return lambda *a, **kw: True

            # Monkeypatch the imports inside _run.
            import keepercommander.commands.keeper_tenant_migrate.commander_clients as cc
            real_client_cls = cc.CommanderStructureClient
            real_sync = cc.sync_down
            cc.CommanderStructureClient = _FakeStructureClient
            cc.sync_down = lambda p: True
            try:
                cmd._run(_Params(), {
                    'inventory': inv_path,
                    'steps': '0-12',
                    'source_root': 'My company',
                    'target_root': 'Root',
                    'resume': True,
                    'audit_log': audit_path,
                })
            finally:
                cc.CommanderStructureClient = real_client_cls
                cc.sync_down = real_sync
            with open(audit_path) as f:
                last = json.loads([ln for ln in f if ln.strip()][-1])
            self.assertIn('resume', last['summary'])
            self.assertTrue(last['summary']['resume']['enabled'])
            self.assertEqual(
                last['summary']['resume']['skipped_already_present'], 0)


if __name__ == '__main__':
    unittest.main()
