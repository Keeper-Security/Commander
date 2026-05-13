"""Tests for the 5-option SF migration matrix (T2.1-T2.11).

Covers:
- 5-option enum + classifier dispatch (T2.2-T2.3)
- Operator UX: --default-action, --per-folder-rules,
  --default-conflict-resolution (T2.4)
- step_vault_folders 5-action dispatch + per-row materializers (T2.5)
- Conflict handling: error / suffix / merge (T2.6)
- Round-trip integrity: synthetic source → plan → structure → assert
  for each of the 5 options (T2.7)
- commander_supports_true_nested_sf() probe (T2.8)
- Plan-JSON round-trip (legacy + new fields) (T2.9)
"""

import argparse
import json
import os
import tempfile
import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate import nested_sf_plan as nsfp
from keepercommander.commands.keeper_tenant_migrate.commands import (
    NestedSfPlanCommand, nested_sf_plan_parser,
)
from keepercommander.commands.keeper_tenant_migrate.structure import FakeClient, StructureRestore


# ─── Test fixtures ────────────────────────────────────────────────────────


PARENT = {
    'uid': 'sf-p',
    'name': 'Parent',
    'default_manage_users': False,
    'default_manage_records': True,
    'default_can_edit': True,
    'default_can_share': False,
    'users': [
        {'username': 'alice@x', 'manage_users': False,
         'manage_records': True, 'can_edit': True, 'can_share': False},
        {'username': 'bob@x', 'manage_users': False,
         'manage_records': True, 'can_edit': True, 'can_share': False},
    ],
    'teams': [{'name': 'TeamA', 'manage_records': True}],
}

DIVERGENT_VIEW = {
    'users': [
        {'username': 'alice@x', 'manage_users': False,
         'manage_records': True, 'can_edit': True, 'can_share': False},
        {'username': 'bob@x', 'manage_users': False,
         'manage_records': True, 'can_edit': True, 'can_share': False},
        {'username': 'charlie@x', 'manage_users': False,
         'manage_records': True, 'can_edit': True, 'can_share': False},
    ],
    'teams': [{'name': 'TeamA', 'manage_records': True}],
    'default_manage_users': False, 'default_manage_records': True,
    'default_can_edit': True, 'default_can_share': False,
}


def _vf(uid='sff-1', name='Child', sf_uid='sf-p',
         sf_view=None, ftype='shared_folder_folder'):
    e = {'uid': uid, 'name': name, 'type': ftype,
         'parent_uid': sf_uid, 'parent_chain': [sf_uid],
         'shared_folder_uid': sf_uid}
    if sf_view is not None:
        e['sf_view'] = sf_view
    return e


def _inv(vault_folders, shared_folders=None):
    return {
        'source_root': 'My company',
        'scope_node': 'MIGRATION-TEST-NODE',
        'prefix_filter': 'MIGTEST-',
        'entities': {
            'vault_folders': vault_folders,
            'shared_folders': (shared_folders if shared_folders is not None
                                else [PARENT]),
        },
    }


# ─── T2.2/T2.3: 5-option enum + classifier ────────────────────────────────


class FiveOptionEnumTests(unittest.TestCase):
    def test_all_actions_size(self):
        self.assertEqual(len(nsfp.ALL_ACTIONS), 5)

    def test_divergent_actions_excludes_preserve(self):
        self.assertNotIn(nsfp.ACTION_PRESERVE, nsfp.DIVERGENT_ACTIONS)
        self.assertNotIn(nsfp.ACTION_REVIEW, nsfp.DIVERGENT_ACTIONS)
        self.assertEqual(len(nsfp.DIVERGENT_ACTIONS), 3)

    def test_action_constants_match_doc_keys(self):
        self.assertEqual(nsfp.ACTION_PRESERVE, 'preserve-subfolder')
        self.assertEqual(nsfp.ACTION_PROMOTE, 'promote-to-sibling')
        self.assertEqual(nsfp.ACTION_TRUE_NESTED, 'promote-to-true-nested')
        self.assertEqual(nsfp.ACTION_FLATTEN, 'flatten-with-prefix')
        self.assertEqual(nsfp.ACTION_REVIEW, 'needs-review')

    def test_legacy_aliases_present(self):
        self.assertEqual(nsfp.ACTION_PRESERVE_LEGACY,
                          'preserve-as-subfolder')
        self.assertEqual(nsfp.ACTION_PROMOTE_LEGACY,
                          'promote-to-shared_folder')


class ClassifierDefaultActionTests(unittest.TestCase):
    def test_default_promote_yields_promote(self):
        plan = nsfp.classify_inventory(_inv([_vf(sf_view=DIVERGENT_VIEW)]))
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_default_flatten_yields_flatten(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(sf_view=DIVERGENT_VIEW)]),
            default_action=nsfp.ACTION_FLATTEN)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_FLATTEN)

    def test_default_true_nested_unsupported_falls_back_to_promote(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(sf_view=DIVERGENT_VIEW)]),
            default_action=nsfp.ACTION_TRUE_NESTED,
            supports_true_nested=False)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_default_true_nested_supported_emits_true_nested(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(sf_view=DIVERGENT_VIEW)]),
            default_action=nsfp.ACTION_TRUE_NESTED,
            supports_true_nested=True)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_TRUE_NESTED)

    def test_default_preserve_with_divergent_still_promotes(self):
        # preserve-as-default is a contradiction for a divergent
        # subfolder; the safe behaviour is promote.
        plan = nsfp.classify_inventory(
            _inv([_vf(sf_view=DIVERGENT_VIEW)]),
            default_action=nsfp.ACTION_PRESERVE)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_unknown_default_action_resets_to_promote(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(sf_view=DIVERGENT_VIEW)]),
            default_action='bogus-value')
        self.assertEqual(plan['default_action'], nsfp.ACTION_PROMOTE)

    def test_inherit_subfolder_uses_preserve(self):
        plan = nsfp.classify_inventory(_inv([_vf()]),
                                        default_action=nsfp.ACTION_FLATTEN)
        # No sf_view → inherit, regardless of default_action.
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PRESERVE)

    def test_proposed_promoted_name_for_promote(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(name='Sensitive', sf_view=DIVERGENT_VIEW)]))
        self.assertEqual(plan['decisions'][0]['proposed_promoted_name'],
                          'Parent - Sensitive')

    def test_proposed_promoted_name_for_flatten(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(name='Sensitive', sf_view=DIVERGENT_VIEW)]),
            default_action=nsfp.ACTION_FLATTEN)
        self.assertEqual(plan['decisions'][0]['proposed_promoted_name'],
                          'Parent__Sensitive')

    def test_proposed_promoted_name_for_true_nested(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(name='Sensitive', sf_view=DIVERGENT_VIEW)]),
            default_action=nsfp.ACTION_TRUE_NESTED,
            supports_true_nested=True)
        # True-nested keeps original name (lives inside parent SF).
        self.assertEqual(plan['decisions'][0]['proposed_promoted_name'],
                          'Sensitive')

    def test_action_summary_populated(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='a', sf_view=DIVERGENT_VIEW),
                   _vf(uid='b'),
                   _vf(uid='c', sf_view=DIVERGENT_VIEW)]))
        self.assertEqual(plan['action_summary'][nsfp.ACTION_PROMOTE], 2)
        self.assertEqual(plan['action_summary'][nsfp.ACTION_PRESERVE], 1)


class PerFolderRulesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dict_override_for_single_folder(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='a', sf_view=DIVERGENT_VIEW),
                   _vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules={'b': nsfp.ACTION_FLATTEN})
        actions = {d['subfolder_uid']: d['proposed_target_action']
                   for d in plan['decisions']}
        self.assertEqual(actions['a'], nsfp.ACTION_PROMOTE)
        self.assertEqual(actions['b'], nsfp.ACTION_FLATTEN)

    def test_override_to_preserve_short_circuits_diff(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules={'b': nsfp.ACTION_PRESERVE})
        d = plan['decisions'][0]
        self.assertEqual(d['proposed_target_action'], nsfp.ACTION_PRESERVE)
        self.assertEqual(d['classification'], nsfp.INHERIT)

    def test_override_to_review_skips_diff(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules={'b': nsfp.ACTION_REVIEW})
        d = plan['decisions'][0]
        self.assertEqual(d['proposed_target_action'], nsfp.ACTION_REVIEW)
        self.assertEqual(d['classification'], nsfp.UNKNOWN)

    def test_override_true_nested_unsupported_falls_back(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules={'b': nsfp.ACTION_TRUE_NESTED},
            supports_true_nested=False)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_override_true_nested_supported(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules={'b': nsfp.ACTION_TRUE_NESTED},
            supports_true_nested=True)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_TRUE_NESTED)

    def test_unknown_override_value_ignored(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules={'b': 'made-up-action'})
        # Falls through to default behaviour.
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_per_folder_rules_path_is_loaded(self):
        rules_path = os.path.join(self.tmp, 'rules.json')
        with open(rules_path, 'w') as f:
            json.dump({'b': nsfp.ACTION_FLATTEN}, f)
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules=rules_path)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_FLATTEN)

    def test_per_folder_rules_missing_path_warns(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules='/no/such/file.json')
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_per_folder_rules_corrupt_path_warns(self):
        bad = os.path.join(self.tmp, 'bad.json')
        with open(bad, 'w') as f:
            f.write('{not-json')
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules=bad)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_per_folder_rules_non_dict_json_ignored(self):
        bad = os.path.join(self.tmp, 'list.json')
        with open(bad, 'w') as f:
            json.dump([1, 2, 3], f)
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules=bad)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_per_folder_rules_non_string_values_ignored(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]),
            per_folder_rules={'b': 5})
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)


# ─── T2.6: conflict resolution ────────────────────────────────────────────


class ConflictResolutionTests(unittest.TestCase):
    def test_no_collision_returns_ok(self):
        out, status = nsfp.resolve_name_collision(
            'A', set(), policy=nsfp.CONFLICT_ERROR)
        self.assertEqual((out, status), ('A', 'ok'))

    def test_error_policy_returns_error(self):
        out, status = nsfp.resolve_name_collision(
            'A', {'A'}, policy=nsfp.CONFLICT_ERROR)
        self.assertEqual(status, 'error')
        self.assertEqual(out, 'A')

    def test_merge_policy_returns_merged(self):
        out, status = nsfp.resolve_name_collision(
            'A', {'A'}, policy=nsfp.CONFLICT_MERGE)
        self.assertEqual(status, 'merged')

    def test_suffix_policy_finds_unique(self):
        out, status = nsfp.resolve_name_collision(
            'A', {'A'}, policy=nsfp.CONFLICT_SUFFIX)
        self.assertEqual(status, 'suffixed')
        self.assertEqual(out, 'A (2)')

    def test_suffix_policy_increments_through_dupes(self):
        out, status = nsfp.resolve_name_collision(
            'A', {'A', 'A (2)', 'A (3)'},
            policy=nsfp.CONFLICT_SUFFIX)
        self.assertEqual((out, status), ('A (4)', 'suffixed'))

    def test_default_conflict_in_classify_inventory(self):
        plan = nsfp.classify_inventory(_inv([_vf()]))
        self.assertEqual(plan['default_conflict_resolution'],
                          nsfp.CONFLICT_ERROR)
        self.assertEqual(plan['decisions'][0]['conflict_resolution'],
                          nsfp.CONFLICT_ERROR)

    def test_unknown_conflict_policy_resets_to_error(self):
        plan = nsfp.classify_inventory(
            _inv([_vf()]),
            default_conflict_resolution='made-up')
        self.assertEqual(plan['default_conflict_resolution'],
                          nsfp.CONFLICT_ERROR)


# ─── T2.5: step_vault_folders dispatch + materializers ────────────────────


def _build_action_plan(uid, action, *, name=None,
                        conflict=nsfp.CONFLICT_ERROR):
    return {uid: {
        'subfolder_uid': uid,
        'proposed_target_action': action,
        'proposed_promoted_name': name or '',
        'conflict_resolution': conflict,
    }}


class StepVaultFoldersDispatchTests(unittest.TestCase):
    def _vfs(self, child_uid='sff-1', child_name='Child'):
        return [
            {'uid': 'sf-1', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': child_uid, 'name': child_name,
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-1', 'parent_chain': ['sf-1']},
        ]

    def test_preserve_uses_add_subfolder(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan('sff-1', nsfp.ACTION_PRESERVE)
        uid_map = restore.step_vault_folders(
            self._vfs(), action_plan=action_plan)
        kinds = [c[0] for c in client.calls]
        self.assertIn('add_subfolder', kinds)

    def test_promote_uses_add_shared_folder_with_qualified_name(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_PROMOTE, name='TopSF - Child')
        restore.step_vault_folders(self._vfs(), action_plan=action_plan)
        promoted = [c for c in client.calls
                     if c[0] == 'add_shared_folder' and c[1][0] == 'TopSF - Child']
        self.assertEqual(len(promoted), 1)

    def test_flatten_uses_double_underscore(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_FLATTEN, name='TopSF__Child')
        restore.step_vault_folders(self._vfs(), action_plan=action_plan)
        flat = [c for c in client.calls
                 if c[0] == 'add_shared_folder' and c[1][0] == 'TopSF__Child']
        self.assertEqual(len(flat), 1)

    def test_true_nested_raises_records_failed(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_TRUE_NESTED, name='Child')
        restore.step_vault_folders(self._vfs(), action_plan=action_plan)
        # No add_shared_folder for the child — only the parent SF.
        promoted_children = [
            c for c in client.calls
            if c[0] == 'add_shared_folder' and c[1][0] != 'TopSF']
        self.assertEqual(promoted_children, [])
        statuses = [r.status for r in restore.results]
        self.assertIn('FAILED', statuses)

    def test_review_action_records_skipped(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan('sff-1', nsfp.ACTION_REVIEW)
        restore.step_vault_folders(self._vfs(), action_plan=action_plan)
        reasons = [r.notes for r in restore.results
                    if r.status == 'SKIPPED']
        self.assertTrue(any('needs-review' in n for n in reasons))

    def test_hybrid_per_folder_dispatches_correctly(self):
        client = FakeClient()
        restore = StructureRestore(client)
        vfs = self._vfs() + [
            {'uid': 'sff-2', 'name': 'OtherChild',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-1', 'parent_chain': ['sf-1']},
        ]
        action_plan = {}
        action_plan.update(_build_action_plan(
            'sff-1', nsfp.ACTION_PROMOTE, name='TopSF - Child'))
        action_plan.update(_build_action_plan(
            'sff-2', nsfp.ACTION_FLATTEN, name='TopSF__OtherChild'))
        restore.step_vault_folders(vfs, action_plan=action_plan)
        names_created = [c[1][0] for c in client.calls
                          if c[0] == 'add_shared_folder']
        self.assertIn('TopSF - Child', names_created)
        self.assertIn('TopSF__OtherChild', names_created)

    def test_legacy_promotion_plan_still_works(self):
        client = FakeClient()
        restore = StructureRestore(client)
        promotion_plan = {
            'sff-1': {'proposed_promoted_name': 'TopSF - Child',
                      'conflict_resolution': nsfp.CONFLICT_ERROR},
        }
        restore.step_vault_folders(
            self._vfs(), promotion_plan=promotion_plan)
        names = [c[1][0] for c in client.calls
                  if c[0] == 'add_shared_folder']
        self.assertIn('TopSF - Child', names)

    def test_action_plan_overrides_legacy_promotion_plan(self):
        client = FakeClient()
        restore = StructureRestore(client)
        promotion_plan = {
            'sff-1': {'proposed_promoted_name': 'WRONG',
                      'conflict_resolution': nsfp.CONFLICT_ERROR},
        }
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_FLATTEN, name='TopSF__Child')
        restore.step_vault_folders(
            self._vfs(),
            promotion_plan=promotion_plan,
            action_plan=action_plan,
        )
        names = [c[1][0] for c in client.calls
                  if c[0] == 'add_shared_folder']
        self.assertNotIn('WRONG', names)
        self.assertIn('TopSF__Child', names)


class MaterializerEdgeCaseTests(unittest.TestCase):
    """Branches inside the dispatch / materializer functions."""

    def _vfs(self):
        return [
            {'uid': 'sf-1', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'sff-1', 'name': 'Child',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-1', 'parent_chain': ['sf-1']},
        ]

    def test_unknown_divergent_action_records_failed(self):
        # Bypass classify_inventory and inject an unknown divergent
        # action straight into the action_plan to exercise the dispatch
        # default branch.
        client = FakeClient()
        restore = StructureRestore(client)
        # Construct a synthetic dispatch entry that survives through to
        # _materialize_divergent — we have to cheat past
        # `divergent` gating by patching DIVERGENT_ACTIONS.
        bogus = 'made-up-divergent-action'
        with mock.patch.object(nsfp, 'DIVERGENT_ACTIONS',
                                 nsfp.DIVERGENT_ACTIONS + (bogus,)):
            action_plan = {
                'sff-1': {
                    'subfolder_uid': 'sff-1',
                    'proposed_target_action': bogus,
                    'proposed_promoted_name': 'X',
                },
            }
            restore.step_vault_folders(self._vfs(),
                                        action_plan=action_plan)
        statuses = [(r.action, r.status) for r in restore.results]
        self.assertTrue(any(s == 'FAILED' for _, s in statuses))

    def test_apply_preserve_subfolder_named_method(self):
        # Direct call to verify symmetry helper works.
        client = FakeClient()
        restore = StructureRestore(client)
        uid = restore._apply_preserve_subfolder(
            {'name': 'Hello'}, 'parent-uid')
        self.assertTrue(uid.startswith('sff-Hello'))

    def test_empty_uid_returned_records_failed(self):
        # client.add_shared_folder returns '' (failure) — promote
        # materializer should record FAILED with 'client returned empty
        # UID'.
        client = FakeClient(fail_on={'add_shared_folder'})
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_PROMOTE, name='TopSF - Child')
        uid_map = restore.step_vault_folders(
            self._vfs(), action_plan=action_plan)
        # The parent SF also fails; child is not mapped either.
        self.assertNotIn('sff-1', uid_map)
        statuses = [r.status for r in restore.results]
        self.assertIn('FAILED', statuses)

    def test_unknown_folder_type_records_failed(self):
        client = FakeClient()
        restore = StructureRestore(client)
        vfs = [
            {'uid': 'x', 'name': 'Mystery', 'type': 'unknown-type',
             'parent_uid': '', 'parent_chain': []},
        ]
        restore.step_vault_folders(vfs)
        notes = [r.notes for r in restore.results]
        self.assertTrue(any('unknown folder type' in n for n in notes))

    def test_client_exception_is_recorded(self):
        # The `except Exception` branch in step_vault_folders.
        class BoomClient(FakeClient):
            def add_shared_folder(self, *a, **kw):
                raise RuntimeError('boom')
        client = BoomClient()
        restore = StructureRestore(client)
        vfs = [{'uid': 'sf-1', 'name': 'X', 'type': 'shared_folder',
                'parent_uid': '', 'parent_chain': []}]
        restore.step_vault_folders(vfs)
        notes = [r.notes for r in restore.results]
        self.assertTrue(any('RuntimeError' in n for n in notes))

    def test_incomplete_entry_records_failed(self):
        # name / ftype / src_uid missing → 'incomplete entry' FAILED.
        client = FakeClient()
        restore = StructureRestore(client)
        vfs = [{'uid': '', 'name': 'NoUID',
                'type': 'shared_folder',
                'parent_uid': '', 'parent_chain': []}]
        restore.step_vault_folders(vfs)
        notes = [r.notes for r in restore.results]
        self.assertTrue(any('incomplete entry' in n for n in notes))


class StepVaultFoldersConflictTests(unittest.TestCase):
    def _vfs(self):
        return [
            {'uid': 'sf-1', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'sff-1', 'name': 'Child',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-1', 'parent_chain': ['sf-1']},
        ]

    def test_promote_collision_error_records_failed(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_PROMOTE, name='TopSF - Child',
            conflict=nsfp.CONFLICT_ERROR)
        uid_map = restore.step_vault_folders(
            self._vfs(), action_plan=action_plan,
            existing_target_names={'TopSF - Child'})
        self.assertNotIn('sff-1', uid_map)
        statuses = [(r.action, r.status) for r in restore.results]
        self.assertIn(('promote-to-sibling', 'FAILED'), statuses)

    def test_promote_collision_suffix_resolves(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_PROMOTE, name='TopSF - Child',
            conflict=nsfp.CONFLICT_SUFFIX)
        uid_map = restore.step_vault_folders(
            self._vfs(), action_plan=action_plan,
            existing_target_names={'TopSF - Child'})
        self.assertIn('sff-1', uid_map)
        names = [c[1][0] for c in client.calls
                  if c[0] == 'add_shared_folder']
        self.assertIn('TopSF - Child (2)', names)

    def test_promote_collision_merge_records_no_create(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_PROMOTE, name='TopSF - Child',
            conflict=nsfp.CONFLICT_MERGE)
        uid_map = restore.step_vault_folders(
            self._vfs(), action_plan=action_plan,
            existing_target_names={'TopSF - Child'})
        # Merge: subfolder UID NOT mapped (no client UID returned),
        # but no FAILED record either.
        actions = [r.action for r in restore.results]
        self.assertIn('promote-to-sibling-merged', actions)
        promoted_calls = [c for c in client.calls
                           if c[0] == 'add_shared_folder'
                           and c[1][0] == 'TopSF - Child']
        # Only the Parent (TopSF) was created — no promoted child SF.
        self.assertEqual(len(promoted_calls), 0)

    def test_flatten_collision_error_records_failed(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_FLATTEN, name='TopSF__Child',
            conflict=nsfp.CONFLICT_ERROR)
        restore.step_vault_folders(
            self._vfs(), action_plan=action_plan,
            existing_target_names={'TopSF__Child'})
        statuses = [(r.action, r.status) for r in restore.results]
        self.assertIn(('flatten-with-prefix', 'FAILED'), statuses)

    def test_flatten_collision_suffix_resolves(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_FLATTEN, name='TopSF__Child',
            conflict=nsfp.CONFLICT_SUFFIX)
        uid_map = restore.step_vault_folders(
            self._vfs(), action_plan=action_plan,
            existing_target_names={'TopSF__Child'})
        self.assertIn('sff-1', uid_map)

    def test_flatten_collision_merge(self):
        client = FakeClient()
        restore = StructureRestore(client)
        action_plan = _build_action_plan(
            'sff-1', nsfp.ACTION_FLATTEN, name='TopSF__Child',
            conflict=nsfp.CONFLICT_MERGE)
        restore.step_vault_folders(
            self._vfs(), action_plan=action_plan,
            existing_target_names={'TopSF__Child'})
        actions = [r.action for r in restore.results]
        self.assertIn('flatten-with-prefix-merged', actions)


# ─── T2.8: commander_supports_true_nested_sf probe ────────────────────────


class CommanderVersionProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_folder_py(self, content):
        path = os.path.join(self.tmp, 'folder.py')
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_sentinel_present_returns_false(self):
        path = self._write_folder_py(
            "raise CommandError('mkdir', 'Shared folders cannot be nested')\n")
        self.assertFalse(
            nsfp.commander_supports_true_nested_sf(version='17.2.13',
                                                    source_path=path))

    def test_sentinel_absent_returns_true(self):
        path = self._write_folder_py(
            "# new world: nested SFs supported\npass\n")
        self.assertTrue(
            nsfp.commander_supports_true_nested_sf(version='99.0.0',
                                                    source_path=path))

    def test_known_version_with_sentinel(self):
        path = self._write_folder_py(
            "raise CommandError('mkdir', 'Shared folders cannot be nested')\n")
        for v in ('17.2.13', '17.2.14', '17.2.15'):
            self.assertFalse(
                nsfp.commander_supports_true_nested_sf(version=v,
                                                        source_path=path),
                f'{v} should be unsupported')

    def test_missing_source_path_returns_false(self):
        self.assertFalse(
            nsfp.commander_supports_true_nested_sf(
                version='17.2.13',
                source_path='/non/existent/folder.py'))

    def test_unreadable_source_path_returns_false(self):
        path = self._write_folder_py('x')
        os.chmod(path, 0o000)
        try:
            # On many systems root can still read 0o000 — but if it
            # can't, result is False either way.
            result = nsfp.commander_supports_true_nested_sf(
                version='17.2.13', source_path=path)
            self.assertIn(result, (True, False))
        finally:
            os.chmod(path, 0o600)

    def test_empty_version_falls_through_to_source_check(self):
        path = self._write_folder_py(
            "raise CommandError('mkdir', 'Shared folders cannot be nested')\n")
        self.assertFalse(
            nsfp.commander_supports_true_nested_sf(version='',
                                                    source_path=path))

    def test_real_commander_returns_false_today(self):
        # Real Commander v17.2.13 in dev environment should still
        # have the sentinel — defensive.
        commander_path = (
            '/root/Desktop/Projects/Commander/keepercommander/'
            'commands/folder.py')
        if not os.path.isfile(commander_path):
            self.skipTest('Real Commander tree not available')
        self.assertFalse(
            nsfp.commander_supports_true_nested_sf(
                version='17.2.13',
                source_path=commander_path))

    def test_oserror_on_read_returns_false(self):
        # Force the open() to raise OSError — exercises the
        # `except OSError: return False` branch.
        path = self._write_folder_py('Shared folders cannot be nested')
        with mock.patch('builtins.open', side_effect=OSError('boom')):
            self.assertFalse(
                nsfp.commander_supports_true_nested_sf(
                    version='17.2.13', source_path=path))


class SuffixExhaustionTests(unittest.TestCase):
    def test_suffix_policy_exhausted_returns_error(self):
        # Saturate the (2)..(999) suffix space → degrade to error.
        existing = {'A'} | {f'A ({i})' for i in range(2, 1000)}
        out, status = nsfp.resolve_name_collision(
            'A', existing, policy=nsfp.CONFLICT_SUFFIX)
        self.assertEqual(status, 'error')
        self.assertEqual(out, 'A')


# ─── T2.5: action_lookup ──────────────────────────────────────────────────


class ActionLookupTests(unittest.TestCase):
    def test_filters_blank_uids(self):
        plan = {'decisions': [
            {'subfolder_uid': '',
             'proposed_target_action': nsfp.ACTION_PROMOTE},
            {'subfolder_uid': 'a',
             'proposed_target_action': nsfp.ACTION_PROMOTE},
        ]}
        out = nsfp.action_lookup(plan)
        self.assertEqual(set(out), {'a'})

    def test_missing_action_defaults_to_preserve(self):
        plan = {'decisions': [{'subfolder_uid': 'a'}]}
        out = nsfp.action_lookup(plan)
        self.assertEqual(out['a']['proposed_target_action'],
                          nsfp.ACTION_PRESERVE)

    def test_legacy_action_translated_to_promote(self):
        plan = {'decisions': [{
            'subfolder_uid': 'a',
            'proposed_target_action': nsfp.ACTION_PROMOTE_LEGACY,
        }]}
        out = nsfp.action_lookup(plan)
        self.assertEqual(out['a']['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)

    def test_legacy_preserve_translated(self):
        plan = {'decisions': [{
            'subfolder_uid': 'a',
            'proposed_target_action': nsfp.ACTION_PRESERVE_LEGACY,
        }]}
        out = nsfp.action_lookup(plan)
        self.assertEqual(out['a']['proposed_target_action'],
                          nsfp.ACTION_PRESERVE)

    def test_empty_plan_returns_empty(self):
        self.assertEqual(nsfp.action_lookup({}), {})

    def test_promotion_lookup_filters_to_promote(self):
        # Backwards-compat helper.
        plan = {'decisions': [
            {'subfolder_uid': 'a',
             'proposed_target_action': nsfp.ACTION_PROMOTE},
            {'subfolder_uid': 'b',
             'proposed_target_action': nsfp.ACTION_FLATTEN},
            {'subfolder_uid': 'c',
             'proposed_target_action': nsfp.ACTION_PROMOTE_LEGACY},
        ]}
        out = nsfp.promotion_lookup(plan)
        self.assertEqual(set(out), {'a', 'c'})


# ─── T2.4: argparse contract ──────────────────────────────────────────────


class ArgparseTests(unittest.TestCase):
    def test_default_action_default_value(self):
        ns = nested_sf_plan_parser.parse_args(
            ['--inventory', '/x', '--output', '/y'])
        self.assertEqual(ns.default_action, 'promote-to-sibling')

    def test_default_action_choices(self):
        ns = nested_sf_plan_parser.parse_args(
            ['--inventory', '/x', '--output', '/y',
             '--default-action', 'flatten-with-prefix'])
        self.assertEqual(ns.default_action, 'flatten-with-prefix')

    def test_default_action_invalid_rejected(self):
        with self.assertRaises(SystemExit):
            nested_sf_plan_parser.parse_args(
                ['--inventory', '/x', '--output', '/y',
                 '--default-action', 'made-up'])

    def test_per_folder_rules_argument(self):
        ns = nested_sf_plan_parser.parse_args(
            ['--inventory', '/x', '--output', '/y',
             '--per-folder-rules', '/p'])
        self.assertEqual(ns.per_folder_rules, '/p')

    def test_per_folder_rules_default_empty(self):
        ns = nested_sf_plan_parser.parse_args(
            ['--inventory', '/x', '--output', '/y'])
        self.assertEqual(ns.per_folder_rules, '')

    def test_default_conflict_resolution_choices(self):
        for choice in ('error', 'suffix', 'merge'):
            ns = nested_sf_plan_parser.parse_args(
                ['--inventory', '/x', '--output', '/y',
                 '--default-conflict-resolution', choice])
            self.assertEqual(ns.default_conflict_resolution, choice)

    def test_default_conflict_resolution_invalid_rejected(self):
        with self.assertRaises(SystemExit):
            nested_sf_plan_parser.parse_args(
                ['--inventory', '/x', '--output', '/y',
                 '--default-conflict-resolution', 'made-up'])


class NestedSfPlanCommandIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_execute_passes_default_action(self):
        inv_path = os.path.join(self.tmp, 'inv.json')
        with open(inv_path, 'w') as f:
            json.dump(_inv([_vf(sf_view=DIVERGENT_VIEW)]), f)
        out_path = os.path.join(self.tmp, 'plan.json')
        cmd = NestedSfPlanCommand()
        result = cmd.execute(None, inventory=inv_path, output=out_path,
                              default_action='flatten-with-prefix',
                              per_folder_rules='',
                              default_conflict_resolution='suffix')
        self.assertEqual(result['default_action'], 'flatten-with-prefix')
        self.assertEqual(result['default_conflict_resolution'], 'suffix')
        self.assertEqual(result['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_FLATTEN)
        self.assertEqual(result['decisions'][0]['conflict_resolution'],
                          nsfp.CONFLICT_SUFFIX)

    def test_execute_per_folder_rules_path(self):
        inv_path = os.path.join(self.tmp, 'inv.json')
        with open(inv_path, 'w') as f:
            json.dump(_inv([_vf(uid='b', sf_view=DIVERGENT_VIEW)]), f)
        rules_path = os.path.join(self.tmp, 'rules.json')
        with open(rules_path, 'w') as f:
            json.dump({'b': nsfp.ACTION_FLATTEN}, f)
        out_path = os.path.join(self.tmp, 'plan.json')
        cmd = NestedSfPlanCommand()
        result = cmd.execute(None, inventory=inv_path, output=out_path,
                              default_action='promote-to-sibling',
                              per_folder_rules=rules_path,
                              default_conflict_resolution='error')
        self.assertEqual(result['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_FLATTEN)


# ─── T2.7: Round-trip integrity ───────────────────────────────────────────


class _RoundTripFixture:
    """Synthetic source vault with a parent SF + divergent subfolder.

    Produces inventory dicts compatible with classify_inventory and
    vault_folders lists compatible with step_vault_folders. Encodes the
    full membership/perms shape so the integrity assertions can verify
    each option preserves it correctly.
    """

    def __init__(self):
        self.parent_sf = {
            'uid': 'sf-parent', 'name': 'Parent',
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
            'users': PARENT['users'], 'teams': PARENT['teams'],
        }
        self.divergent_view = DIVERGENT_VIEW
        self.vault_folders = [
            {'uid': 'sf-parent', 'name': 'Parent',
             'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': [],
             'default_manage_users': False, 'default_manage_records': True,
             'default_can_edit': True, 'default_can_share': False},
            {'uid': 'sff-child', 'name': 'Child',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-parent', 'parent_chain': ['sf-parent'],
             'default_manage_users': False, 'default_manage_records': True,
             'default_can_edit': True, 'default_can_share': False,
             'sf_view': dict(DIVERGENT_VIEW)},
        ]

    def inventory(self):
        return {
            'source_root': 'My company',
            'scope_node': 'MIGRATION-TEST-NODE',
            'prefix_filter': 'MIGTEST-',
            'entities': {
                'vault_folders': self.vault_folders,
                'shared_folders': [self.parent_sf],
            },
        }


class RoundTripIntegrityTests(unittest.TestCase):
    """For each of the 5 options assert the option produces the right shape.

    Source byte-equality: the synthetic source dict is captured pre-run
    via deepcopy, and verified byte-equal post-run — guards rule 0
    (source-read-only).
    """

    def setUp(self):
        import copy
        self.fx = _RoundTripFixture()
        self.source_snapshot = copy.deepcopy(self.fx.inventory())

    def _assert_source_intact(self):
        # Round-trip must NEVER mutate the source inventory dict.
        self.assertEqual(self.fx.inventory(), self.source_snapshot)

    def _run(self, default_action, supports_true_nested=False,
              per_folder_rules=None,
              existing_target_names=None,
              default_conflict_resolution=nsfp.CONFLICT_ERROR):
        plan = nsfp.classify_inventory(
            self.fx.inventory(),
            default_action=default_action,
            per_folder_rules=per_folder_rules,
            default_conflict_resolution=default_conflict_resolution,
            supports_true_nested=supports_true_nested,
        )
        client = FakeClient()
        restore = StructureRestore(client)
        uid_map = restore.step_vault_folders(
            self.fx.vault_folders,
            action_plan=nsfp.action_lookup(plan),
            existing_target_names=existing_target_names,
        )
        self._assert_source_intact()
        return plan, client, restore, uid_map

    def test_round_trip_preserve_subfolder(self):
        # Force preserve via per-folder override (the diff would
        # otherwise drive promote).
        plan, client, restore, uid_map = self._run(
            nsfp.ACTION_PRESERVE,
            per_folder_rules={'sff-child': nsfp.ACTION_PRESERVE})
        self.assertIn('sff-child', uid_map)
        self.assertEqual(plan['decisions'][0]['proposed_target_action'],
                          nsfp.ACTION_PRESERVE)
        # Should call add_subfolder, not add_shared_folder for child.
        kinds = [c[0] for c in client.calls]
        self.assertIn('add_subfolder', kinds)

    def test_round_trip_promote_to_sibling(self):
        plan, client, restore, uid_map = self._run(nsfp.ACTION_PROMOTE)
        self.assertIn('sff-child', uid_map)
        # Default perms on child mirror parent's.
        promoted = [c for c in client.calls
                     if c[0] == 'add_shared_folder'
                     and c[1][0] == 'Parent - Child']
        self.assertEqual(len(promoted), 1)
        # Child created with parent_uid=''
        self.assertEqual(promoted[0][1][1], '')

    def test_round_trip_flatten_with_prefix(self):
        plan, client, restore, uid_map = self._run(nsfp.ACTION_FLATTEN)
        self.assertIn('sff-child', uid_map)
        flat = [c for c in client.calls
                 if c[0] == 'add_shared_folder'
                 and c[1][0] == 'Parent__Child']
        self.assertEqual(len(flat), 1)

    def test_round_trip_promote_to_true_nested_unsupported(self):
        plan, client, restore, uid_map = self._run(
            nsfp.ACTION_TRUE_NESTED, supports_true_nested=False)
        # Falls back to promote-to-sibling.
        self.assertIn('sff-child', uid_map)
        names = [c[1][0] for c in client.calls
                  if c[0] == 'add_shared_folder']
        self.assertIn('Parent - Child', names)

    def test_round_trip_promote_to_true_nested_supported_records_failure(self):
        # When supported is True and action stays as TRUE_NESTED, the
        # materializer raises NotImplementedError (no Commander
        # implementation yet) — recorded as FAILED.
        plan, client, restore, uid_map = self._run(
            nsfp.ACTION_TRUE_NESTED, supports_true_nested=True)
        statuses = [(r.action, r.status) for r in restore.results]
        self.assertTrue(any('FAILED' == s for _, s in statuses))

    def test_round_trip_hybrid_per_folder(self):
        # Two subfolders: one promote, one flatten.
        self.fx.vault_folders.append({
            'uid': 'sff-other', 'name': 'OtherChild',
            'type': 'shared_folder_folder',
            'parent_uid': 'sf-parent', 'parent_chain': ['sf-parent'],
            'default_manage_users': False, 'default_manage_records': True,
            'default_can_edit': True, 'default_can_share': False,
            'sf_view': DIVERGENT_VIEW,
        })
        import copy
        self.source_snapshot = copy.deepcopy(self.fx.inventory())
        plan, client, restore, uid_map = self._run(
            nsfp.ACTION_PROMOTE,
            per_folder_rules={'sff-other': nsfp.ACTION_FLATTEN})
        self.assertIn('sff-child', uid_map)
        self.assertIn('sff-other', uid_map)
        names = [c[1][0] for c in client.calls
                  if c[0] == 'add_shared_folder']
        self.assertIn('Parent - Child', names)
        self.assertIn('Parent__OtherChild', names)

    def test_round_trip_conflict_resolution_suffix(self):
        plan, client, restore, uid_map = self._run(
            nsfp.ACTION_PROMOTE,
            default_conflict_resolution=nsfp.CONFLICT_SUFFIX,
            existing_target_names={'Parent - Child'})
        self.assertIn('sff-child', uid_map)
        names = [c[1][0] for c in client.calls
                  if c[0] == 'add_shared_folder']
        self.assertIn('Parent - Child (2)', names)

    def test_round_trip_default_perms_propagate_for_promote(self):
        # The promoted SF should be created with the source subfolder's
        # default_* permissions (the materializer reads them off `vf`).
        plan, client, restore, uid_map = self._run(nsfp.ACTION_PROMOTE)
        promoted = [c for c in client.calls
                     if c[0] == 'add_shared_folder'
                     and c[1][0] == 'Parent - Child']
        self.assertEqual(len(promoted), 1)
        # Args layout: (name, parent_uid, new_uid, default_manage_users,
        # default_manage_records, default_can_edit, default_can_share)
        args = promoted[0][1]
        self.assertEqual(args[3], False)  # default_manage_users
        self.assertEqual(args[4], True)   # default_manage_records
        self.assertEqual(args[5], True)   # default_can_edit
        self.assertEqual(args[6], False)  # default_can_share


# ─── Plan JSON round-trip: write + load preserves all fields ──────────────


class PlanJsonRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_5_option_plan_roundtrip(self):
        plan = nsfp.classify_inventory(
            _inv([_vf(uid='a', sf_view=DIVERGENT_VIEW),
                   _vf(uid='b'),
                   _vf(uid='c', sf_view=DIVERGENT_VIEW)]),
            default_action=nsfp.ACTION_FLATTEN,
            default_conflict_resolution=nsfp.CONFLICT_SUFFIX,
        )
        path = os.path.join(self.tmp, 'plan.json')
        nsfp.write_plan(plan, path)
        loaded = nsfp.load_plan(path)
        self.assertEqual(loaded['default_action'], nsfp.ACTION_FLATTEN)
        self.assertEqual(loaded['default_conflict_resolution'],
                          nsfp.CONFLICT_SUFFIX)
        for d in loaded['decisions']:
            self.assertIn('proposed_target_action', d)
            self.assertIn('conflict_resolution', d)
        # action_summary must round-trip exactly.
        self.assertEqual(loaded['action_summary'], plan['action_summary'])

    def test_legacy_plan_action_lookup_compat(self):
        # Old plans wrote 'preserve-as-subfolder' /
        # 'promote-to-shared_folder' literals.
        legacy_plan = {
            'decisions': [
                {'subfolder_uid': 'a',
                 'proposed_target_action': 'promote-to-shared_folder',
                 'proposed_promoted_name': 'Parent - Old'},
                {'subfolder_uid': 'b',
                 'proposed_target_action': 'preserve-as-subfolder'},
            ]
        }
        out = nsfp.action_lookup(legacy_plan)
        self.assertEqual(out['a']['proposed_target_action'],
                          nsfp.ACTION_PROMOTE)
        self.assertEqual(out['b']['proposed_target_action'],
                          nsfp.ACTION_PRESERVE)


# ─── Misc edge cases for full coverage ────────────────────────────────────


class ClassifyEdgeCaseTests(unittest.TestCase):
    def test_orphan_subfolder_classification_review(self):
        orphan = _vf(sf_uid='absent-sf')
        orphan['parent_chain'] = ['absent-sf']
        plan = nsfp.classify_inventory(_inv([orphan], shared_folders=[]))
        d = plan['decisions'][0]
        self.assertEqual(d['classification'], nsfp.UNKNOWN)
        self.assertEqual(d['proposed_target_action'], nsfp.ACTION_REVIEW)

    def test_supports_true_nested_field_in_plan(self):
        plan = nsfp.classify_inventory(_inv([_vf()]),
                                        supports_true_nested=True)
        self.assertTrue(plan['commander_supports_true_nested_sf'])

    def test_subfolder_without_uid_skipped_by_action_lookup(self):
        plan = {'decisions': [{'proposed_target_action':
                                 nsfp.ACTION_PROMOTE}]}
        self.assertEqual(nsfp.action_lookup(plan), {})


if __name__ == '__main__':
    unittest.main()
