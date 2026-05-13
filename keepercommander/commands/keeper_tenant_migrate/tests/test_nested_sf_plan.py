"""Tests for nested_sf_plan.py — subfolder classification + plan IO."""

import argparse
import json
import os
import tempfile
import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate import nested_sf_plan
from keepercommander.commands.keeper_tenant_migrate.commands import (
    NestedSfPlanCommand,
    StructureCommand,
    TenantMigrateCommand,
    nested_sf_plan_parser,
    structure_parser,
)


PARENT_SF = {
    'uid': 'sf-parent-uid',
    'name': 'ParentSF',
    'default_manage_users': False,
    'default_manage_records': True,
    'default_can_edit': True,
    'default_can_share': False,
    'users': [
        {'username': 'alice@x.com', 'manage_users': False,
         'manage_records': True, 'can_edit': True, 'can_share': False},
        {'username': 'bob@x.com', 'manage_users': False,
         'manage_records': True, 'can_edit': True, 'can_share': False},
    ],
    'teams': [
        {'name': 'TeamA', 'manage_users': False, 'manage_records': True},
    ],
    'records': [],
}


def _vault_folder(uid='sff-uid', name='ChildA',
                   sf_uid='sf-parent-uid',
                   sf_view=None,
                   parent_uid=None,
                   parent_chain=None,
                   ftype='shared_folder_folder'):
    entry = {
        'uid': uid, 'name': name, 'type': ftype,
        'parent_uid': parent_uid if parent_uid is not None else sf_uid,
        'parent_chain': parent_chain
            if parent_chain is not None else [sf_uid],
        'shared_folder_uid': sf_uid,
    }
    if sf_view is not None:
        entry['sf_view'] = sf_view
    return entry


def _inventory(vault_folders, shared_folders=None):
    return {
        'source_root': 'My company',
        'source_user': 'admin@src',
        'scope_node': 'MIGRATION-TEST-NODE',
        'prefix_filter': 'MIGTEST-',
        'entities': {
            'vault_folders': vault_folders,
            'shared_folders': shared_folders
                if shared_folders is not None else [PARENT_SF],
        },
    }


class ClassifyHelpersTests(unittest.TestCase):
    def test_norm_perm_passthrough(self):
        self.assertIsNone(nested_sf_plan._norm_perm(None))
        self.assertTrue(nested_sf_plan._norm_perm(1))
        self.assertFalse(nested_sf_plan._norm_perm(0))

    def test_user_signature_skips_blank(self):
        out = nested_sf_plan._user_signature([
            {'username': '', 'can_edit': True},
            {'email': 'A@X.com'},
            'not-a-dict',
            None,
        ])
        self.assertEqual(list(out.keys()), ['a@x.com'])

    def test_team_signature_handles_aliases(self):
        out = nested_sf_plan._team_signature([
            {'team_name': 'T', 'manage_records': True},
            {'name': '   '},
            None,
        ])
        self.assertEqual(list(out.keys()), ['T'])
        self.assertTrue(out['T']['manage_records'])

    def test_perm_signature_includes_all_keys(self):
        sig = nested_sf_plan._perm_signature(PARENT_SF)
        self.assertEqual(set(sig), set(nested_sf_plan._PERM_KEYS))

    def test_diff_users_extra_missing_differing(self):
        parent = {'a@x': {'can_edit': True},
                  'b@x': {'can_edit': True}}
        child = {'a@x': {'can_edit': False},
                 'c@x': {'can_edit': True}}
        extra, missing, diff = nested_sf_plan._diff_users(parent, child)
        self.assertEqual(extra, ['c@x'])
        self.assertEqual(missing, ['b@x'])
        self.assertEqual(diff, ['a@x'])

    def test_diff_teams_basic(self):
        e, m, d = nested_sf_plan._diff_teams(
            {'A': {'manage_records': True}},
            {'A': {'manage_records': False}, 'B': {'manage_records': True}},
        )
        self.assertEqual(e, ['B'])
        self.assertEqual(m, [])
        self.assertEqual(d, ['A'])

    def test_diff_perms_only_when_both_set(self):
        parent = {'default_manage_users': False, 'default_manage_records': True,
                  'default_can_edit': None, 'default_can_share': True}
        child = {'default_manage_users': True, 'default_manage_records': True,
                 'default_can_edit': True, 'default_can_share': None}
        diff = nested_sf_plan._diff_perms(parent, child)
        self.assertEqual(diff, ['default_manage_users'])

    def test_qualified_name(self):
        self.assertEqual(nested_sf_plan._qualified_name('A', 'B'), 'A - B')

    def test_build_sf_index_skips_uidless(self):
        idx = nested_sf_plan._build_sf_index([
            {'uid': 'a', 'name': 'A'},
            {'name': 'no-uid'},
            {'shared_folder_uid': 'b', 'name': 'B'},
        ])
        self.assertEqual(set(idx), {'a', 'b'})

    def test_has_membership(self):
        self.assertFalse(nested_sf_plan._has_membership({}))
        self.assertTrue(nested_sf_plan._has_membership({'users': [{}]}))
        self.assertTrue(nested_sf_plan._has_membership({'teams': [{}]}))


class ResolveParentTests(unittest.TestCase):
    def test_direct_shared_folder_uid_match(self):
        idx = {'sf-1': PARENT_SF}
        vf = {'shared_folder_uid': 'sf-1', 'parent_chain': []}
        self.assertEqual(nested_sf_plan._resolve_parent_sf_uid(vf, idx), 'sf-1')

    def test_walks_parent_chain(self):
        idx = {'sf-2': PARENT_SF}
        vf = {'shared_folder_uid': '', 'parent_chain': ['inter', 'sf-2']}
        self.assertEqual(nested_sf_plan._resolve_parent_sf_uid(vf, idx), 'sf-2')

    def test_no_match_returns_empty(self):
        self.assertEqual(
            nested_sf_plan._resolve_parent_sf_uid({}, {'a': {}}), '')

    def test_subfolder_path_walks_until_shared_folder(self):
        folder_index = {
            'inter': {'name': 'Mid', 'type': 'shared_folder_folder',
                      'parent_chain': ['sf-2']},
            'sf-2': {'name': 'Top', 'type': 'shared_folder',
                      'parent_chain': []},
        }
        vf = {'name': 'Leaf', 'parent_chain': ['inter', 'sf-2']}
        self.assertEqual(
            nested_sf_plan._subfolder_path(vf, folder_index),
            'Top/Mid/Leaf',
        )

    def test_subfolder_path_breaks_on_missing_ancestor(self):
        vf = {'name': 'Leaf', 'parent_chain': ['gone']}
        self.assertEqual(nested_sf_plan._subfolder_path(vf, {}), 'Leaf')


class InheritClassificationTests(unittest.TestCase):
    def test_no_subfolder_data_defaults_to_inherit(self):
        vf = _vault_folder()
        cls, action, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.INHERIT)
        self.assertEqual(action, nested_sf_plan.ACTION_PRESERVE)
        self.assertIn('default inherit', reason)
        self.assertEqual(diff, {})

    def test_empty_view_inherits(self):
        vf = _vault_folder(sf_view={'users': [], 'teams': []})
        cls, action, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.INHERIT)
        self.assertEqual(diff, {})

    def test_membership_matches_parent(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [{'name': 'TeamA', 'manage_users': False,
                        'manage_records': True}],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.INHERIT)
        self.assertIn('match parent', reason)
        self.assertEqual(diff, {})


class PromotionClassificationTests(unittest.TestCase):
    def test_extra_member_promotes(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'charlie@x.com', 'can_edit': True},
            ],
            'teams': [{'name': 'TeamA', 'manage_records': True}],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, action, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertEqual(action, nested_sf_plan.ACTION_PROMOTE)
        self.assertIn('charlie@x.com', reason)
        self.assertIn('charlie@x.com', diff['users']['extra'])

    def test_missing_member_promotes(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [{'name': 'TeamA', 'manage_records': True}],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertIn('omits parent users', reason)
        self.assertEqual(diff['users']['missing'], ['bob@x.com'])

    def test_differing_user_perm_promotes(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': True,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [{'name': 'TeamA', 'manage_records': True}],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertIn('differing per-user', reason)
        self.assertIn('alice@x.com', diff['users']['differing'])

    def test_extra_team_promotes(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [
                {'name': 'TeamA', 'manage_records': True},
                {'name': 'TeamB', 'manage_records': True},
            ],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, _, diff = nested_sf_plan._classify_subfolder(PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertEqual(diff['teams']['extra'], ['TeamB'])

    def test_missing_team_promotes(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertIn('omits parent teams', reason)
        self.assertEqual(diff['teams']['missing'], ['TeamA'])

    def test_differing_team_perm_promotes(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [{'name': 'TeamA', 'manage_users': True,
                        'manage_records': True}],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertIn('differing per-team', reason)
        self.assertEqual(diff['teams']['differing'], ['TeamA'])

    def test_stricter_perms_promotes(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [{'name': 'TeamA', 'manage_records': True}],
            'default_manage_users': False, 'default_manage_records': False,
            'default_can_edit': False, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, reason, diff = nested_sf_plan._classify_subfolder(
            PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertIn('default permissions', reason)
        self.assertIn('default_manage_records', diff['permissions'])
        self.assertIn('default_can_edit', diff['permissions'])

    def test_both_member_and_perm_diff_populates_both(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'dave@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [{'name': 'TeamA', 'manage_records': True}],
            'default_manage_users': True, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(sf_view=view)
        cls, _, _, diff = nested_sf_plan._classify_subfolder(PARENT_SF, vf)
        self.assertEqual(cls, nested_sf_plan.PROMOTE)
        self.assertIn('users', diff)
        self.assertIn('permissions', diff)
        self.assertEqual(diff['users']['extra'], ['dave@x.com'])


class CannotClassifyTests(unittest.TestCase):
    def test_missing_parent_marks_unknown(self):
        vf = _vault_folder(sf_uid='sf-orphan',
                            parent_chain=['sf-orphan'],
                            sf_view={'users': [{'username': 'a@x'}]})
        cls, action, reason, _ = nested_sf_plan._classify_subfolder(None, vf)
        self.assertEqual(cls, nested_sf_plan.UNKNOWN)
        self.assertEqual(action, nested_sf_plan.ACTION_REVIEW)
        self.assertIn('parent shared_folder', reason)


class ClassifyInventoryTests(unittest.TestCase):
    def test_inherit_subfolder_in_full_inventory(self):
        vf = _vault_folder()
        plan = nested_sf_plan.classify_inventory(_inventory([vf]))
        self.assertEqual(len(plan['decisions']), 1)
        d = plan['decisions'][0]
        self.assertEqual(d['classification'], nested_sf_plan.INHERIT)
        self.assertEqual(d['parent_sf_uid'], 'sf-parent-uid')
        self.assertEqual(d['parent_sf_name'], 'ParentSF')
        self.assertEqual(d['proposed_promoted_name'], '')
        self.assertEqual(plan['summary'][nested_sf_plan.INHERIT], 1)
        self.assertEqual(plan['source_tenant'], 'My company')

    def test_promotion_includes_qualified_name(self):
        view = {
            'users': [
                {'username': 'alice@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'bob@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
                {'username': 'extra@x.com', 'manage_users': False,
                 'manage_records': True, 'can_edit': True, 'can_share': False},
            ],
            'teams': [{'name': 'TeamA', 'manage_records': True}],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
        }
        vf = _vault_folder(name='Sensitive', sf_view=view)
        plan = nested_sf_plan.classify_inventory(_inventory([vf]))
        d = plan['decisions'][0]
        self.assertEqual(d['classification'], nested_sf_plan.PROMOTE)
        self.assertEqual(d['proposed_promoted_name'], 'ParentSF - Sensitive')
        self.assertIn('membership_diff', d)
        self.assertEqual(plan['summary'][nested_sf_plan.PROMOTE], 1)

    def test_orphan_subfolder_falls_through_to_unknown(self):
        view = {'users': [{'username': 'x@x.com'}]}
        vf = _vault_folder(uid='orphan-sff',
                            sf_uid='absent-sf',
                            parent_chain=['absent-sf'],
                            sf_view=view)
        plan = nested_sf_plan.classify_inventory(
            _inventory([vf], shared_folders=[]))
        d = plan['decisions'][0]
        self.assertEqual(d['classification'], nested_sf_plan.UNKNOWN)
        self.assertEqual(d['proposed_target_action'],
                         nested_sf_plan.ACTION_REVIEW)
        self.assertEqual(d['parent_sf_name'], '')
        self.assertEqual(plan['summary'][nested_sf_plan.UNKNOWN], 1)

    def test_non_subfolder_entries_skipped(self):
        plan = nested_sf_plan.classify_inventory({
            'entities': {
                'vault_folders': [
                    {'uid': 'u1', 'name': 'PrivateF', 'type': 'user_folder',
                     'parent_uid': '', 'parent_chain': []},
                    {'uid': 'sf1', 'name': 'TopSF', 'type': 'shared_folder',
                     'parent_uid': '', 'parent_chain': []},
                ],
                'shared_folders': [],
            },
        })
        self.assertEqual(plan['decisions'], [])
        self.assertEqual(plan['summary'], {
            nested_sf_plan.INHERIT: 0,
            nested_sf_plan.PROMOTE: 0,
            nested_sf_plan.UNKNOWN: 0,
        })

    def test_empty_inventory_returns_empty_plan(self):
        plan = nested_sf_plan.classify_inventory({})
        self.assertEqual(plan['decisions'], [])
        self.assertIn('scanned_at', plan)

    def test_source_tenant_falls_back_to_user(self):
        plan = nested_sf_plan.classify_inventory({
            'source_user': 'admin@x',
            'entities': {'vault_folders': [], 'shared_folders': []},
        })
        self.assertEqual(plan['source_tenant'], 'admin@x')


class WriteAndLoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_plan_is_chmod_0600(self):
        path = os.path.join(self.tmp, 'plan.json')
        plan = {'decisions': [], 'summary': {}}
        checksum = nested_sf_plan.write_plan(plan, path)
        st = os.stat(path)
        self.assertEqual(st.st_mode & 0o777, 0o600)
        with open(path) as f:
            self.assertEqual(json.load(f), plan)
        sidecar = path + '.sha256'
        self.assertTrue(os.path.exists(sidecar))
        with open(sidecar) as f:
            self.assertEqual(f.read().strip(), checksum)

    def test_load_inventory_round_trip(self):
        path = os.path.join(self.tmp, 'inv.json')
        with open(path, 'w') as f:
            json.dump({'a': 1}, f)
        self.assertEqual(nested_sf_plan.load_inventory(path), {'a': 1})

    def test_load_plan_round_trip(self):
        path = os.path.join(self.tmp, 'plan.json')
        with open(path, 'w') as f:
            json.dump({'decisions': []}, f)
        self.assertEqual(nested_sf_plan.load_plan(path), {'decisions': []})

    def test_promotion_lookup_filters_to_promote(self):
        plan = {'decisions': [
            {'subfolder_uid': 'a', 'proposed_target_action':
              nested_sf_plan.ACTION_PROMOTE},
            {'subfolder_uid': 'b', 'proposed_target_action':
              nested_sf_plan.ACTION_PRESERVE},
            {'proposed_target_action': nested_sf_plan.ACTION_PROMOTE},
        ]}
        out = nested_sf_plan.promotion_lookup(plan)
        self.assertEqual(set(out), {'a'})

    def test_promotion_lookup_empty_plan(self):
        self.assertEqual(nested_sf_plan.promotion_lookup({}), {})


class CommandIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parser_argparse_contract(self):
        ns = nested_sf_plan_parser.parse_args(
            ['--inventory', '/x', '--output', '/y'])
        self.assertEqual(ns.inventory, '/x')
        self.assertEqual(ns.output, '/y')

    def test_parser_requires_inventory(self):
        with self.assertRaises(SystemExit):
            nested_sf_plan_parser.parse_args(['--output', '/y'])

    def test_parser_requires_output(self):
        with self.assertRaises(SystemExit):
            nested_sf_plan_parser.parse_args(['--inventory', '/x'])

    def test_subcommand_registered_in_group(self):
        group = TenantMigrateCommand()
        self.assertIn('nested-sf-plan', group.subcommands)
        self.assertIsInstance(group.subcommands['nested-sf-plan'],
                               NestedSfPlanCommand)

    def test_execute_writes_plan_and_returns_summary(self):
        inv_path = os.path.join(self.tmp, 'inv.json')
        with open(inv_path, 'w') as f:
            json.dump(_inventory([_vault_folder()]), f)
        out_path = os.path.join(self.tmp, 'plan.json')
        cmd = NestedSfPlanCommand()
        result = cmd.execute(None, inventory=inv_path, output=out_path)
        self.assertIn('summary', result)
        self.assertEqual(result['summary'][nested_sf_plan.INHERIT], 1)
        self.assertTrue(os.path.exists(out_path))
        self.assertEqual(result['_output_path'], out_path)

    def test_execute_handles_missing_inventory(self):
        cmd = NestedSfPlanCommand()
        result = cmd.execute(None, inventory='/no/such',
                              output=os.path.join(self.tmp, 'p.json'))
        self.assertEqual(result['error'], 'inventory_missing')

    def test_get_parser_returns_module_parser(self):
        cmd = NestedSfPlanCommand()
        self.assertIs(cmd.get_parser(), nested_sf_plan_parser)


class StructureFlagDefaultOffTests(unittest.TestCase):
    def test_structure_parser_accepts_nested_sf_plan_flag(self):
        ns = structure_parser.parse_args(
            ['--inventory', '/x', '--nested-sf-plan', '/p'])
        self.assertEqual(ns.nested_sf_plan, '/p')

    def test_structure_parser_default_off(self):
        ns = structure_parser.parse_args(['--inventory', '/x'])
        self.assertEqual(ns.nested_sf_plan, '')


class StepVaultFoldersPromotionTests(unittest.TestCase):
    def test_promotion_creates_top_level_sf(self):
        from keepercommander.commands.keeper_tenant_migrate.structure import (
            FakeClient, StructureRestore,
        )
        client = FakeClient()
        restore = StructureRestore(client)
        vault_folders = [
            {'uid': 'sf-1', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': [],
             'default_manage_users': False, 'default_manage_records': True,
             'default_can_edit': True, 'default_can_share': False},
            {'uid': 'sff-1', 'name': 'ChildA',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-1', 'parent_chain': ['sf-1'],
             'default_manage_users': False, 'default_manage_records': True,
             'default_can_edit': True, 'default_can_share': False},
        ]
        promotion_plan = {
            'sff-1': {'proposed_promoted_name': 'TopSF - ChildA'},
        }
        uid_map = restore.step_vault_folders(
            vault_folders, promotion_plan=promotion_plan)
        self.assertIn('sff-1', uid_map)
        self.assertIn('sf-1', uid_map)
        op_kinds = [c[0] for c in client.calls]
        self.assertEqual(op_kinds.count('add_shared_folder'), 2)
        self.assertNotIn('add_subfolder', op_kinds)
        promoted_call = [c for c in client.calls
                          if c[0] == 'add_shared_folder'
                          and c[1][0] == 'TopSF - ChildA'][0]
        self.assertEqual(promoted_call[1][1], '')

    def test_promotion_falls_back_to_subfolder_name_if_no_proposed(self):
        from keepercommander.commands.keeper_tenant_migrate.structure import (
            FakeClient, StructureRestore,
        )
        client = FakeClient()
        restore = StructureRestore(client)
        vault_folders = [
            {'uid': 'sf-1', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'sff-1', 'name': 'ChildA',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-1', 'parent_chain': ['sf-1']},
        ]
        promotion_plan = {'sff-1': {}}
        restore.step_vault_folders(vault_folders,
                                    promotion_plan=promotion_plan)
        promoted = [c for c in client.calls
                     if c[0] == 'add_shared_folder'
                     and c[1][0] == 'ChildA']
        self.assertEqual(len(promoted), 1)

    def test_no_promotion_plan_preserves_subfolder_behavior(self):
        from keepercommander.commands.keeper_tenant_migrate.structure import (
            FakeClient, StructureRestore,
        )
        client = FakeClient()
        restore = StructureRestore(client)
        vault_folders = [
            {'uid': 'sf-1', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'sff-1', 'name': 'ChildA',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-1', 'parent_chain': ['sf-1']},
        ]
        restore.step_vault_folders(vault_folders)
        op_kinds = [c[0] for c in client.calls]
        self.assertIn('add_subfolder', op_kinds)

    def test_promotion_propagates_client_failure(self):
        from keepercommander.commands.keeper_tenant_migrate.structure import (
            FakeClient, StructureRestore,
        )
        client = FakeClient(fail_on={'add_shared_folder'})
        restore = StructureRestore(client)
        vault_folders = [
            {'uid': 'sff-1', 'name': 'ChildA',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-parent',
             'parent_chain': ['sf-parent']},
        ]
        promotion_plan = {'sff-1': {'proposed_promoted_name': 'TopSF - ChildA'}}
        uid_map = restore.step_vault_folders(
            vault_folders, promotion_plan=promotion_plan)
        self.assertNotIn('sff-1', uid_map)

    def test_step_skips_when_no_vault_folders(self):
        from keepercommander.commands.keeper_tenant_migrate.structure import (
            FakeClient, StructureRestore,
        )
        client = FakeClient()
        restore = StructureRestore(client)
        out = restore.step_vault_folders([])
        self.assertEqual(out, {})
        self.assertEqual(client.calls, [])


class StructureCommandConsumptionTests(unittest.TestCase):
    """Verify structure consumes a nested-sf-plan when --nested-sf-plan flag set,
    and skips it otherwise. We patch the StructureRestore so we don't need a
    real Commander session."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_inventory(self, vault_folders):
        path = os.path.join(self.tmp, 'inv.json')
        with open(path, 'w') as f:
            json.dump({
                'entities': {
                    'nodes': [], 'teams': [], 'roles': [], 'users': [],
                    'shared_folders': [],
                    'vault_folders': vault_folders,
                    'records': [],
                },
            }, f)
        return path

    def _patch_step_capture(self, captured):
        from keepercommander.commands.keeper_tenant_migrate import structure as struct_mod

        original = struct_mod.StructureRestore.step_vault_folders

        def fake(self, vfs, *, uid_map=None, promotion_plan=None,
                  action_plan=None, existing_target_names=None):
            # Capture both the legacy promotion_plan and the new
            # action_plan so older tests continue to work and newer
            # ones can verify per-row dispatch.
            captured['promotion_plan'] = promotion_plan
            captured['action_plan'] = action_plan
            captured['vault_folders'] = vfs
            return uid_map or {}

        return mock.patch.object(
            struct_mod.StructureRestore, 'step_vault_folders', fake)

    def _common_patches(self):
        # _run lazy-imports CommanderStructureClient + sync_down from
        # the underlying modules — patch those source modules.
        return [
            mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commander_clients.'
                'CommanderStructureClient',
                return_value=mock.MagicMock()),
            mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'),
            mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands._detect_target_root',
                return_value='Keeperdemo'),
            mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.audit.append_audit_event'),
        ]

    def test_structure_with_plan_passes_promotion_plan(self):
        inv_path = self._write_inventory([
            {'uid': 'sf-x', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'sff-x', 'name': 'ChildA',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-x', 'parent_chain': ['sf-x']},
        ])
        plan_path = os.path.join(self.tmp, 'plan.json')
        with open(plan_path, 'w') as f:
            json.dump({'decisions': [
                {'subfolder_uid': 'sff-x',
                 'proposed_target_action':
                  nested_sf_plan.ACTION_PROMOTE,
                 'proposed_promoted_name': 'TopSF - ChildA'},
            ]}, f)

        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                cmd._run(mock.MagicMock(),
                          {'inventory': inv_path,
                           'plan': '',
                           'steps': '11-11',
                           'nested_sf_plan': plan_path,
                           'scope_node': '',
                           'dry_run': False})
            finally:
                for p in patches:
                    p.stop()

        # New consumption hook routes through `action_plan`; legacy
        # `promotion_plan` is no longer populated by `_run`.
        self.assertIn('sff-x', captured['action_plan'])

    def _stub_vfs(self):
        return [
            {'uid': 'sf-a', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
        ]

    def test_structure_without_plan_passes_empty(self):
        inv_path = self._write_inventory(self._stub_vfs())
        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                cmd._run(mock.MagicMock(),
                          {'inventory': inv_path,
                           'plan': '',
                           'steps': '11-11',
                           'nested_sf_plan': '',
                           'scope_node': '',
                           'dry_run': False})
            finally:
                for p in patches:
                    p.stop()
        self.assertEqual(captured.get('action_plan'), {})

    def test_structure_with_missing_plan_path_continues(self):
        inv_path = self._write_inventory(self._stub_vfs())
        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                cmd._run(mock.MagicMock(),
                          {'inventory': inv_path,
                           'plan': '',
                           'steps': '11-11',
                           'nested_sf_plan': '/no/such/plan.json',
                           'scope_node': '',
                           'dry_run': False})
            finally:
                for p in patches:
                    p.stop()
        self.assertEqual(captured.get('action_plan'), {})

    def test_structure_with_corrupt_plan_continues(self):
        inv_path = self._write_inventory(self._stub_vfs())
        bad_path = os.path.join(self.tmp, 'bad.json')
        with open(bad_path, 'w') as f:
            f.write('not-json{')
        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                cmd._run(mock.MagicMock(),
                          {'inventory': inv_path,
                           'plan': '',
                           'steps': '11-11',
                           'nested_sf_plan': bad_path,
                           'scope_node': '',
                           'dry_run': False})
            finally:
                for p in patches:
                    p.stop()
        self.assertEqual(captured.get('action_plan'), {})


if __name__ == '__main__':
    unittest.main()
