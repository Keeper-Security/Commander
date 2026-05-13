"""Unit tests for keepercommander.commands.keeper_tenant_migrate.overrides — 100% coverage target."""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate import overrides as overrides_mod
from keepercommander.commands.keeper_tenant_migrate.overrides import (
    OverridesValidationError,
    apply_overrides,
    format_validation_errors,
    load_overrides,
    load_validate_apply,
    validate_overrides,
)


def _make_plan(*, decisions=None, supports_true_nested=False, tier='medium'):
    """Stub plan dict matching nested_sf_plan / T1 migration-plan.json shape."""
    return {
        'decisions': list(decisions or []),
        'commander_supports_true_nested_sf': supports_true_nested,
        'tier': tier,
    }


def _decision(uid, *, action='preserve-subfolder', conflict='error'):
    return {
        'subfolder_uid': uid,
        'subfolder_name': f'name-{uid}',
        'proposed_target_action': action,
        'conflict_resolution': conflict,
    }


# ─── Loader tests ───────────────────────────────────────────────────────────

class LoadOverridesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, body):
        path = os.path.join(self.tmp, name)
        with open(path, 'w') as f:
            f.write(body)
        return path

    def test_empty_file_returns_empty_dict(self):
        path = self._write('o.yaml', '')
        self.assertEqual(load_overrides(path), {})

    def test_valid_yaml_returns_dict(self):
        path = self._write('o.yaml', 'subfolders:\n  abc: promote-to-sibling\n')
        out = load_overrides(path)
        self.assertEqual(out, {'subfolders': {'abc': 'promote-to-sibling'}})

    def test_valid_json_loads_when_yaml_unavailable(self):
        path = self._write('o.json', json.dumps({'tier': 'large'}))
        # Force ImportError on yaml to exercise the JSON fallback branch.
        with mock.patch.dict('sys.modules', {'yaml': None}):
            self.assertEqual(load_overrides(path), {'tier': 'large'})

    def test_missing_path_raises(self):
        with self.assertRaises(OverridesValidationError) as cm:
            load_overrides(os.path.join(self.tmp, 'nope.yaml'))
        self.assertTrue(any('not found' in e for e in cm.exception.errors))

    def test_empty_path_string_raises(self):
        with self.assertRaises(OverridesValidationError) as cm:
            load_overrides('')
        self.assertTrue(any('no overrides path' in e for e in cm.exception.errors))

    def test_unreadable_file_raises(self):
        path = self._write('locked.yaml', 'subfolders: {}')
        with mock.patch('builtins.open', side_effect=OSError('boom')):
            with self.assertRaises(OverridesValidationError) as cm:
                load_overrides(path)
        self.assertTrue(any('unreadable' in e for e in cm.exception.errors))

    def test_malformed_yaml_raises_friendly_error(self):
        # Unclosed bracket — both yaml.safe_load and json.loads choke.
        path = self._write('bad.yaml', 'subfolders: [unclosed\n')
        with self.assertRaises(OverridesValidationError) as cm:
            load_overrides(path)
        self.assertTrue(any('not valid YAML/JSON' in e
                              for e in cm.exception.errors))

    def test_top_level_must_be_mapping(self):
        path = self._write('list.yaml', '- a\n- b\n')
        with self.assertRaises(OverridesValidationError) as cm:
            load_overrides(path)
        self.assertTrue(any('top-level must be a mapping' in e
                              for e in cm.exception.errors))

    def test_explicit_null_yaml_returns_empty_dict(self):
        path = self._write('null.yaml', '~\n')
        # safe_load('~') = None — branch coverage for the `data is None`
        # guard.
        self.assertEqual(load_overrides(path), {})

    def test_close_match_suffix_branch(self):
        # Force the suffix-match arm of _close_match: plan UID ends
        # with the typo'd UID. Validation surfaces the close-match.
        plan = _make_plan(decisions=[_decision('xyzABCDE')])
        errs = validate_overrides(
            {'subfolders': {'ABCDE': 'promote-to-sibling'}}, plan)
        self.assertTrue(any("did you mean 'xyzABCDE'" in e for e in errs))

    def test_close_match_no_candidates(self):
        # Empty plan → no candidates → no close-match hint.
        plan = _make_plan()
        errs = validate_overrides(
            {'subfolders': {'abc': 'promote-to-sibling'}}, plan)
        self.assertTrue(any('no subfolder with this UID' in e
                              for e in errs))


# ─── Validation tests ──────────────────────────────────────────────────────

class ValidateOverridesTests(unittest.TestCase):
    def test_empty_overrides_against_empty_plan(self):
        self.assertEqual(validate_overrides({}, {}), [])

    def test_non_dict_overrides_returns_error(self):
        errs = validate_overrides([], {})
        self.assertTrue(any('must be a mapping' in e for e in errs))

    def test_unknown_top_level_key(self):
        errs = validate_overrides({'foo': {}}, _make_plan())
        self.assertTrue(any('not a recognised top-level key' in e
                              for e in errs))

    # ── subfolders ────────────────────────────────────────────────────────

    def test_unknown_subfolder_uid(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides(
            {'subfolders': {'xyz': 'promote-to-sibling'}}, plan)
        self.assertTrue(any('unknown UID' in e for e in errs))

    def test_unknown_subfolder_uid_close_match_hint(self):
        plan = _make_plan(decisions=[_decision('abc12345xyz')])
        errs = validate_overrides(
            {'subfolders': {'abc12345': 'promote-to-sibling'}}, plan)
        self.assertTrue(any('did you mean' in e for e in errs))

    def test_invalid_action_value(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides(
            {'subfolders': {'abc': 'flatten-and-burn'}}, plan)
        self.assertTrue(any('invalid' in e and 'flatten-and-burn' in e
                              for e in errs))

    def test_non_string_action_value(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides(
            {'subfolders': {'abc': 42}}, plan)
        self.assertTrue(any('not a string' in e for e in errs))

    def test_non_string_subfolder_key(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides(
            {'subfolders': {123: 'promote-to-sibling'}}, plan)
        self.assertTrue(any('non-string key' in e for e in errs))

    def test_subfolders_block_not_mapping(self):
        errs = validate_overrides({'subfolders': 'oops'}, _make_plan())
        self.assertTrue(any('subfolders must be a mapping' in e
                              for e in errs))

    def test_true_nested_blocked_when_unsupported(self):
        plan = _make_plan(decisions=[_decision('abc')],
                           supports_true_nested=False)
        errs = validate_overrides(
            {'subfolders': {'abc': 'promote-to-true-nested'}}, plan)
        self.assertTrue(any('true-nested' in e and 'requires' in e
                              for e in errs))

    def test_true_nested_allowed_when_supported(self):
        plan = _make_plan(decisions=[_decision('abc')],
                           supports_true_nested=True)
        errs = validate_overrides(
            {'subfolders': {'abc': 'promote-to-true-nested'}}, plan)
        self.assertEqual(errs, [])

    def test_legacy_action_normalized(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides(
            {'subfolders': {'abc': 'promote-to-shared_folder'}}, plan)
        self.assertEqual(errs, [])

    # ── conflicts ─────────────────────────────────────────────────────────

    def test_unknown_conflict_uid(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides({'conflicts': {'xyz': 'merge'}}, plan)
        self.assertTrue(any('unknown UID' in e for e in errs))

    def test_unknown_conflict_uid_close_match(self):
        plan = _make_plan(decisions=[_decision('abc12345xyz',
                                                action='promote-to-sibling')])
        errs = validate_overrides({'conflicts': {'abc12345': 'merge'}}, plan)
        self.assertTrue(any('did you mean' in e for e in errs))

    def test_invalid_conflict_policy(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides({'conflicts': {'abc': 'overwrite'}}, plan)
        self.assertTrue(any('invalid' in e and 'overwrite' in e
                              for e in errs))

    def test_non_string_conflict_value(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides({'conflicts': {'abc': 7}}, plan)
        self.assertTrue(any('not a string' in e for e in errs))

    def test_non_string_conflict_key(self):
        plan = _make_plan(decisions=[_decision('abc')])
        errs = validate_overrides({'conflicts': {None: 'merge'}}, plan)
        self.assertTrue(any('non-string key' in e for e in errs))

    def test_conflicts_block_not_mapping(self):
        errs = validate_overrides({'conflicts': 'merge'}, _make_plan())
        self.assertTrue(any('conflicts must be a mapping' in e
                              for e in errs))

    def test_merge_invalid_for_preserve_action(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='preserve-subfolder')])
        errs = validate_overrides({'conflicts': {'abc': 'merge'}}, plan)
        self.assertTrue(any('merge' in e and 'preserve-subfolder' in e
                              for e in errs))

    def test_merge_valid_when_subfolder_overridden_to_promote(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='preserve-subfolder')])
        ovr = {'subfolders': {'abc': 'promote-to-sibling'},
               'conflicts': {'abc': 'merge'}}
        self.assertEqual(validate_overrides(ovr, plan), [])

    def test_merge_invalid_subblock_not_mapping(self):
        # subfolders block is a string; merge falls through preserve.
        plan = _make_plan(decisions=[_decision('abc',
                                                action='preserve-subfolder')])
        ovr = {'subfolders': 'oops', 'conflicts': {'abc': 'merge'}}
        errs = validate_overrides(ovr, plan)
        # Two errors: subfolders type, and merge-invalid-for-preserve
        self.assertTrue(any('subfolders must be a mapping' in e
                              for e in errs))
        self.assertTrue(any("merge" in e and "preserve" in e for e in errs))

    def test_merge_valid_for_promote_action_already(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='promote-to-sibling')])
        self.assertEqual(
            validate_overrides({'conflicts': {'abc': 'merge'}}, plan), [])

    def test_merge_valid_for_flatten_action(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='flatten-with-prefix')])
        self.assertEqual(
            validate_overrides({'conflicts': {'abc': 'merge'}}, plan), [])

    # ── tier ──────────────────────────────────────────────────────────────

    def test_tier_override_without_accept_risk(self):
        plan = _make_plan(tier='medium')
        errs = validate_overrides({'tier': 'large'}, plan, accept_risk=False)
        self.assertTrue(any('--accept-risk' in e for e in errs))

    def test_tier_override_with_accept_risk(self):
        plan = _make_plan(tier='medium')
        self.assertEqual(
            validate_overrides({'tier': 'large'}, plan, accept_risk=True),
            [])

    def test_tier_value_not_string(self):
        errs = validate_overrides({'tier': 7}, _make_plan(),
                                    accept_risk=True)
        self.assertTrue(any('not a string' in e for e in errs))

    def test_tier_value_invalid_enum(self):
        errs = validate_overrides({'tier': 'huge'}, _make_plan(),
                                    accept_risk=True)
        self.assertTrue(any('invalid' in e and 'huge' in e for e in errs))

    def test_tier_value_auto_skips_risk_gate(self):
        # `auto` is the same as omitting → no risk gate.
        self.assertEqual(
            validate_overrides({'tier': 'auto'}, _make_plan(),
                                accept_risk=False), [])

    def test_tier_empty_string_treated_as_omitted(self):
        self.assertEqual(
            validate_overrides({'tier': ''}, _make_plan(),
                                accept_risk=False), [])

    def test_tier_missing_in_plan_surfaces_unknown_in_msg(self):
        plan = {'decisions': [], 'commander_supports_true_nested_sf': False}
        errs = validate_overrides({'tier': 'large'}, plan,
                                    accept_risk=False)
        self.assertTrue(any('unknown' in e for e in errs))

    # ── notes ─────────────────────────────────────────────────────────────

    def test_notes_block_not_mapping(self):
        errs = validate_overrides({'notes': 'hi'}, _make_plan())
        self.assertTrue(any('notes must be a mapping' in e for e in errs))

    def test_notes_value_not_string(self):
        errs = validate_overrides({'notes': {'abc': 42}}, _make_plan())
        self.assertTrue(any('must be a string' in e for e in errs))

    def test_notes_non_string_key(self):
        errs = validate_overrides({'notes': {None: 'hi'}}, _make_plan())
        self.assertTrue(any('non-string key' in e for e in errs))

    def test_notes_uid_not_required_in_plan(self):
        # Notes can reference orphan UIDs — that's a feature, not a bug.
        plan = _make_plan()
        self.assertEqual(
            validate_overrides({'notes': {'orphan-uid': 'remember'}}, plan),
            [])


# ─── Application tests ──────────────────────────────────────────────────────

class ApplyOverridesTests(unittest.TestCase):
    def test_empty_overrides_returns_copy_no_audit(self):
        plan = _make_plan(decisions=[_decision('abc')])
        new_plan, audit = apply_overrides(plan, {})
        self.assertEqual(new_plan, plan)
        self.assertIsNot(new_plan, plan)
        self.assertEqual(audit, [])

    def test_input_plan_never_mutated(self):
        original = _make_plan(decisions=[_decision('abc',
                                                     action='preserve-subfolder')])
        snapshot = json.dumps(original, sort_keys=True)
        ovr = {'subfolders': {'abc': 'promote-to-sibling'},
               'tier': 'large',
               'notes': {'abc': 'why'}}
        apply_overrides(original, ovr)
        self.assertEqual(json.dumps(original, sort_keys=True), snapshot)

    def test_subfolder_override_creates_audit_entry(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='preserve-subfolder')])
        new_plan, audit = apply_overrides(
            plan, {'subfolders': {'abc': 'promote-to-sibling'}})
        self.assertEqual(new_plan['decisions'][0]['proposed_target_action'],
                         'promote-to-sibling')
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['kind'], 'subfolder')
        self.assertEqual(audit[0]['before'], 'preserve-subfolder')
        self.assertEqual(audit[0]['after'], 'promote-to-sibling')

    def test_subfolder_override_matching_default_no_audit(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='promote-to-sibling')])
        _, audit = apply_overrides(
            plan, {'subfolders': {'abc': 'promote-to-sibling'}})
        self.assertEqual(audit, [])

    def test_legacy_action_in_plan_normalized_for_audit(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='promote-to-shared_folder')])
        _, audit = apply_overrides(
            plan, {'subfolders': {'abc': 'promote-to-sibling'}})
        # Legacy action normalises to promote-to-sibling, so this is a
        # no-op delta.
        self.assertEqual(audit, [])

    def test_legacy_action_input_in_overrides_normalized(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='preserve-subfolder')])
        new_plan, audit = apply_overrides(
            plan, {'subfolders': {'abc': 'promote-to-shared_folder'}})
        self.assertEqual(new_plan['decisions'][0]['proposed_target_action'],
                         'promote-to-sibling')
        self.assertEqual(audit[0]['after'], 'promote-to-sibling')

    def test_conflict_override_creates_audit_entry(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='promote-to-sibling',
                                                conflict='error')])
        new_plan, audit = apply_overrides(
            plan, {'conflicts': {'abc': 'merge'}})
        self.assertEqual(new_plan['decisions'][0]['conflict_resolution'],
                         'merge')
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['kind'], 'conflict')
        self.assertEqual(audit[0]['before'], 'error')
        self.assertEqual(audit[0]['after'], 'merge')

    def test_conflict_override_matching_default_no_audit(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='promote-to-sibling',
                                                conflict='merge')])
        _, audit = apply_overrides(
            plan, {'conflicts': {'abc': 'merge'}})
        self.assertEqual(audit, [])

    def test_tier_override_creates_audit_entry(self):
        plan = _make_plan(tier='medium')
        new_plan, audit = apply_overrides(plan, {'tier': 'large'})
        self.assertEqual(new_plan['tier'], 'large')
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['kind'], 'tier')
        self.assertEqual(audit[0]['uid'], '_global')
        self.assertEqual(audit[0]['before'], 'medium')
        self.assertEqual(audit[0]['after'], 'large')

    def test_tier_override_matching_no_audit(self):
        plan = _make_plan(tier='large')
        _, audit = apply_overrides(plan, {'tier': 'large'})
        self.assertEqual(audit, [])

    def test_tier_override_auto_no_op(self):
        plan = _make_plan(tier='medium')
        new_plan, audit = apply_overrides(plan, {'tier': 'auto'})
        self.assertEqual(new_plan['tier'], 'medium')
        self.assertEqual(audit, [])

    def test_tier_note_via_underscore_tier_key(self):
        plan = _make_plan(tier='medium')
        _, audit = apply_overrides(
            plan, {'tier': 'large', 'notes': {'_tier': 'we run hot'}})
        self.assertEqual(audit[0]['note'], 'we run hot')

    def test_subfolder_note_attaches_to_audit_entry(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='preserve-subfolder')])
        ovr = {'subfolders': {'abc': 'promote-to-sibling'},
               'notes': {'abc': 'engineering owns this'}}
        _, audit = apply_overrides(plan, ovr)
        self.assertEqual(audit[0]['note'], 'engineering owns this')

    def test_orphan_note_in_plan_uid(self):
        # Note attached to a plan UID without an actual override.
        plan = _make_plan(decisions=[_decision('abc')])
        _, audit = apply_overrides(
            plan, {'notes': {'abc': 'flag for follow-up'}})
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['kind'], 'note')
        self.assertTrue(audit[0]['in_plan'])

    def test_orphan_note_outside_plan(self):
        plan = _make_plan(decisions=[_decision('abc')])
        _, audit = apply_overrides(
            plan, {'notes': {'unknown-uid': 'pre-existing target SF'}})
        self.assertEqual(audit[0]['in_plan'], False)

    def test_orphan_note_skipped_when_blank(self):
        plan = _make_plan(decisions=[_decision('abc')])
        _, audit = apply_overrides(plan, {'notes': {'abc': ''}})
        self.assertEqual(audit, [])

    def test_orphan_note_skipped_when_non_string(self):
        plan = _make_plan(decisions=[_decision('abc')])
        _, audit = apply_overrides(plan, {'notes': {'abc': 42}})
        self.assertEqual(audit, [])

    def test_decisions_without_uid_skipped(self):
        plan = _make_plan(decisions=[{'subfolder_name': 'no-uid'}])
        new_plan, audit = apply_overrides(
            plan, {'subfolders': {'abc': 'promote-to-sibling'}})
        self.assertEqual(audit, [])
        self.assertEqual(new_plan['decisions'], [{'subfolder_name': 'no-uid'}])

    def test_non_dict_decision_skipped(self):
        # Mix a junk decision in with a real one and supply non-empty
        # overrides so apply_overrides actually walks the list.
        plan = _make_plan(decisions=['not-a-dict',
                                       _decision('abc',
                                                 action='preserve-subfolder')])
        new_plan, audit = apply_overrides(
            plan, {'subfolders': {'abc': 'promote-to-sibling'}})
        # The string entry survives untouched; only `abc` is overridden.
        self.assertEqual(new_plan['decisions'][0], 'not-a-dict')
        self.assertEqual(new_plan['decisions'][1]['proposed_target_action'],
                         'promote-to-sibling')
        self.assertEqual(len(audit), 1)

    def test_decisions_list_replaced_when_not_list(self):
        plan = {'decisions': 'oops'}
        new_plan, audit = apply_overrides(plan, {})
        self.assertEqual(new_plan, {'decisions': 'oops'})
        self.assertEqual(audit, [])

    def test_subfolders_block_not_mapping_no_op(self):
        plan = _make_plan(decisions=[_decision('abc')])
        new_plan, audit = apply_overrides(plan, {'subfolders': 'oops'})
        self.assertEqual(audit, [])
        self.assertEqual(new_plan['decisions'][0]['proposed_target_action'],
                         'preserve-subfolder')

    def test_conflicts_block_not_mapping_no_op(self):
        plan = _make_plan(decisions=[_decision('abc')])
        new_plan, audit = apply_overrides(plan, {'conflicts': 'oops'})
        self.assertEqual(audit, [])

    def test_notes_block_not_mapping_no_op(self):
        plan = _make_plan(decisions=[_decision('abc')])
        new_plan, audit = apply_overrides(plan, {'notes': 'oops'})
        self.assertEqual(audit, [])

    def test_tier_with_non_string_value_no_op(self):
        plan = _make_plan(tier='medium')
        new_plan, audit = apply_overrides(plan, {'tier': 5})
        self.assertEqual(new_plan['tier'], 'medium')
        self.assertEqual(audit, [])

    def test_default_action_preserve_when_decision_missing(self):
        # Branch: decision has no `proposed_target_action` key — falls
        # back to ACTION_PRESERVE for the diff.
        plan = _make_plan(decisions=[{'subfolder_uid': 'abc'}])
        new_plan, audit = apply_overrides(
            plan, {'subfolders': {'abc': 'promote-to-sibling'}})
        self.assertEqual(audit[0]['before'], 'preserve-subfolder')
        self.assertEqual(audit[0]['after'], 'promote-to-sibling')


# ─── Friendly error formatter ──────────────────────────────────────────────

class FormatErrorsTests(unittest.TestCase):
    def test_empty_returns_empty_string(self):
        self.assertEqual(format_validation_errors([]), '')

    def test_formats_with_path(self):
        msg = format_validation_errors(['oops', 'bad'], path='/tmp/o.yaml')
        self.assertIn('/tmp/o.yaml', msg)
        self.assertIn('  - oops', msg)
        self.assertIn('  - bad', msg)
        self.assertIn('No changes were applied', msg)

    def test_formats_without_path(self):
        msg = format_validation_errors(['oops'])
        self.assertIn('<overrides>', msg)


# ─── load_validate_apply convenience ───────────────────────────────────────

class LoadValidateApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, body):
        path = os.path.join(self.tmp, name)
        with open(path, 'w') as f:
            f.write(body)
        return path

    def test_round_trip(self):
        plan = _make_plan(decisions=[_decision('abc',
                                                action='preserve-subfolder')],
                           tier='medium')
        path = self._write('o.yaml',
                             'subfolders:\n  abc: promote-to-sibling\n')
        new_plan, audit = load_validate_apply(path, plan)
        self.assertEqual(new_plan['decisions'][0]['proposed_target_action'],
                         'promote-to-sibling')
        self.assertEqual(len(audit), 1)

    def test_validation_error_raises_with_friendly_messages(self):
        plan = _make_plan(decisions=[_decision('abc')])
        path = self._write('o.yaml',
                             'subfolders:\n  unknown: promote-to-sibling\n')
        with self.assertRaises(OverridesValidationError) as cm:
            load_validate_apply(path, plan)
        self.assertTrue(any('unknown' in e for e in cm.exception.errors))

    def test_tier_override_without_accept_risk_raises(self):
        plan = _make_plan(tier='medium')
        path = self._write('o.yaml', 'tier: large\n')
        with self.assertRaises(OverridesValidationError) as cm:
            load_validate_apply(path, plan, accept_risk=False)
        self.assertTrue(any('--accept-risk' in e
                              for e in cm.exception.errors))


# ─── Round-trip integration: plan → overrides → apply → audit ─────────────

class RoundTripIntegrationTests(unittest.TestCase):
    """T2.8 — end-to-end: a synthetic plan is overridden + the resulting
    plan is what `nested_sf_plan.action_lookup` would dispatch on. Source
    plan bytes are asserted unchanged after the round trip (Rule 0
    in-memory invariant).
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, body):
        path = os.path.join(self.tmp, name)
        with open(path, 'w') as f:
            f.write(body)
        return path

    def test_user_choices_drive_action_lookup(self):
        from keepercommander.commands.keeper_tenant_migrate.nested_sf_plan import action_lookup

        plan = _make_plan(
            decisions=[
                _decision('eng001', action='preserve-subfolder',
                           conflict='error'),
                _decision('fin001', action='preserve-subfolder',
                           conflict='error'),
                _decision('hr001', action='promote-to-sibling',
                           conflict='error'),
            ],
            tier='medium',
        )
        plan_snapshot = json.dumps(plan, sort_keys=True)

        ovr_path = self._write('overrides.yaml', '''
subfolders:
  eng001: promote-to-sibling
  fin001: flatten-with-prefix
  hr001: needs-review

conflicts:
  eng001: merge

notes:
  eng001: "engineering owns this on target"
  fin001: "match existing flat naming on target"

tier: large
''')

        new_plan, audit = load_validate_apply(ovr_path, plan,
                                                accept_risk=True)

        # Source plan untouched (Rule 0 in-memory invariant).
        self.assertEqual(json.dumps(plan, sort_keys=True), plan_snapshot)

        # User's per-folder choices drive dispatch.
        lookup = action_lookup(new_plan)
        self.assertEqual(lookup['eng001']['proposed_target_action'],
                         'promote-to-sibling')
        self.assertEqual(lookup['eng001']['conflict_resolution'], 'merge')
        self.assertEqual(lookup['fin001']['proposed_target_action'],
                         'flatten-with-prefix')
        self.assertEqual(lookup['hr001']['proposed_target_action'],
                         'needs-review')

        # Tier delta lands too.
        self.assertEqual(new_plan['tier'], 'large')

        # Every applied override sits in the audit list.
        kinds = [a['kind'] for a in audit]
        self.assertIn('subfolder', kinds)
        self.assertIn('conflict', kinds)
        self.assertIn('tier', kinds)
        # Notes attached to overridden rows ride along.
        eng_audit = [a for a in audit
                     if a['kind'] == 'subfolder' and a['uid'] == 'eng001']
        self.assertEqual(eng_audit[0]['note'],
                         'engineering owns this on target')


if __name__ == '__main__':
    unittest.main()
