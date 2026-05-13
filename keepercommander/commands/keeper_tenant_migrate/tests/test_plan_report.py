"""Tests for plan_report.py — markdown + JSON mirror generation."""

import json
import os
import stat
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate import plan_report
from keepercommander.commands.keeper_tenant_migrate.commands import (
    PlanReportCommand,
    TenantMigrateCommand,
    plan_report_parser,
)


# ── Fixture builders ─────────────────────────────────────────────────


def _inventory(**overrides):
    """Return a minimal, fully-populated inventory."""
    base = {
        'source_user': 'admin@acme-source',
        'source_root': 'My company',
        'scope_node': 'MIGRATION-TEST-NODE',
        'prefix_filter': 'MIGTEST-',
        'counts': {
            'nodes': 42, 'teams': 18, 'roles': 25, 'users': 340,
            'shared_folders': 45, 'records': 1378,
            'attachments': 22, 'direct_shares': 67,
        },
    }
    base.update(overrides)
    return base


def _decision(uid, name, action, *, parent='ParentSF', path=None,
              reason='', conflict='error', promoted_name=''):
    return {
        'subfolder_uid': uid,
        'subfolder_name': name,
        'subfolder_path': path or f'{parent}/{name}',
        'parent_sf_name': parent,
        'proposed_target_action': action,
        'proposed_promoted_name': promoted_name or f'{parent} - {name}',
        'reason': reason,
        'conflict_resolution': conflict,
    }


def _plan_meta(decisions=None, supports_true_nested=False):
    return {
        'commander_supports_true_nested_sf': supports_true_nested,
        'decisions': decisions or [],
    }


def _estimate(tier='medium (51-500)', delay=1.0, batch=25,
               calls=1247, duration='14m 23s'):
    return {
        'throttle': {'tier': tier, 'delay': delay, 'batch_size': batch},
        'totals': {'calls': calls, 'seconds': float(calls) * 0.6,
                   'duration_human': duration},
    }


def _write(tmpdir, name, payload):
    p = os.path.join(tmpdir, name)
    with open(p, 'w') as f:
        json.dump(payload, f)
    return p


# ── Pure helpers ─────────────────────────────────────────────────────


class HelpersTests(unittest.TestCase):
    def test_load_json_missing_path_returns_none(self):
        self.assertIsNone(plan_report._load_json(''))
        self.assertIsNone(plan_report._load_json('/no/such/file.json'))

    def test_load_json_invalid_returns_none(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as f:
            f.write('not json {{{')
            p = f.name
        try:
            self.assertIsNone(plan_report._load_json(p))
        finally:
            os.unlink(p)

    def test_load_json_unreadable_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, 'unreadable.json')
            with open(p, 'w') as f:
                json.dump({'k': 1}, f)
            os.chmod(p, 0)
            try:
                # Root may still read; skip the assertion if so.
                result = plan_report._load_json(p)
                if os.geteuid() != 0:
                    self.assertIsNone(result)
            finally:
                os.chmod(p, 0o600)

    def test_safe_get_walks_nested(self):
        d = {'a': {'b': {'c': 7}}}
        self.assertEqual(plan_report._safe_get(d, 'a', 'b', 'c'), 7)
        self.assertIsNone(plan_report._safe_get(d, 'a', 'x'))
        self.assertEqual(plan_report._safe_get(d, 'a', 'x', default='fallback'),
                         'fallback')

    def test_safe_get_handles_non_dict_link(self):
        d = {'a': [1, 2]}
        self.assertEqual(plan_report._safe_get(d, 'a', 'b', default='X'), 'X')

    def test_alternatives_excludes_chosen(self):
        alts = plan_report._alternatives_for_action(
            'promote-to-sibling', supports_true_nested=False)
        self.assertNotIn('promote-to-sibling', alts)
        self.assertIn('preserve-subfolder', alts)
        self.assertNotIn('promote-to-true-nested', alts)

    def test_alternatives_includes_true_nested_when_supported(self):
        alts = plan_report._alternatives_for_action(
            'preserve-subfolder', supports_true_nested=True)
        self.assertIn('promote-to-true-nested', alts)

    def test_companion_json_path_replaces_md_extension(self):
        self.assertEqual(plan_report._companion_json_path('/a/b/foo.md'),
                         '/a/b/foo.json')

    def test_companion_json_path_appends_when_no_md(self):
        self.assertEqual(plan_report._companion_json_path('/a/b/foo.txt'),
                         '/a/b/foo.txt.json')

    def test_split_decisions_splits_review_and_conflicts(self):
        d_inherit = _decision('u1', 'A', 'preserve-subfolder')
        d_review = _decision('u2', 'B', 'promote-to-sibling')
        d_conflict = _decision('u3', 'C', 'preserve-subfolder',
                                conflict='suffix')
        review, conflicts = plan_report._split_decisions(
            _plan_meta([d_inherit, d_review, d_conflict]))
        review_uids = [d['subfolder_uid'] for d in review]
        conflict_uids = [d['subfolder_uid'] for d in conflicts]
        self.assertEqual(review_uids, ['u2'])
        self.assertEqual(conflict_uids, ['u3'])

    def test_split_decisions_handles_missing_decisions_key(self):
        review, conflicts = plan_report._split_decisions({})
        self.assertEqual(review, [])
        self.assertEqual(conflicts, [])


# ── Section renderers ────────────────────────────────────────────────


class HeaderTests(unittest.TestCase):
    def test_includes_source_user_root_scope_prefix(self):
        out = '\n'.join(plan_report._render_header(
            _inventory(), _estimate(),
            _plan_meta(supports_true_nested=False)))
        self.assertIn('admin@acme-source (My company)', out)
        self.assertIn('MIGRATION-TEST-NODE / prefix `MIGTEST-`', out)
        self.assertIn('14m 23s', out)
        self.assertIn('1,247 API calls', out)
        self.assertIn('NOT supported', out)

    def test_supports_true_nested_message(self):
        out = '\n'.join(plan_report._render_header(
            _inventory(), _estimate(),
            _plan_meta(supports_true_nested=True)))
        self.assertIn('true-nested SFs supported', out)

    def test_capability_silent_when_meta_absent(self):
        out = '\n'.join(plan_report._render_header(
            _inventory(), _estimate(), {}))
        self.assertNotIn('Commander capability', out)

    def test_blank_inventory_falls_back_gracefully(self):
        out = '\n'.join(plan_report._render_header({}, {}, {}))
        self.assertIn('_unknown_', out)
        self.assertIn('_full tenant_', out)


class SummaryTests(unittest.TestCase):
    def test_summary_lists_all_count_buckets(self):
        out = '\n'.join(plan_report._render_summary(
            _inventory(), _plan_meta([_decision('u1', 'A', 'preserve-subfolder')]),
            [], []))
        self.assertIn('42 nodes', out)
        self.assertIn('340 users', out)
        self.assertIn('1,378 records', out)

    def test_summary_handles_missing_counts(self):
        out = '\n'.join(plan_report._render_summary({}, {}, [], []))
        self.assertIn('Inventory data missing', out)


class DecisionsTableTests(unittest.TestCase):
    def test_no_decisions_emits_empty_state(self):
        out = '\n'.join(plan_report._render_decisions([], [], False))
        self.assertIn('_No decisions need review', out)

    def test_decisions_table_has_per_row_override_key(self):
        d = _decision('uid42', 'SecOps', 'promote-to-sibling',
                       parent='Engineering',
                       reason='adds users not in parent')
        out = '\n'.join(plan_report._render_decisions([d], [], False))
        self.assertIn('`subfolders.uid42`', out)
        self.assertIn('Engineering/SecOps', out)
        self.assertIn('adds users not in parent', out)

    def test_decisions_row_no_uid_falls_back(self):
        d = _decision('', 'X', 'promote-to-sibling')
        out = '\n'.join(plan_report._render_decisions([d], [], False))
        self.assertIn('_(no UID)_', out)

    def test_conflict_row_includes_proposed_name(self):
        d = _decision('cfx', 'Y', 'preserve-subfolder',
                       conflict='suffix',
                       promoted_name='Acme - Y')
        out = '\n'.join(plan_report._render_decisions([], [d], False))
        self.assertIn('`Acme - Y`', out)
        self.assertIn('`conflicts.cfx`', out)
        self.assertIn('append', out)

    def test_conflict_row_no_uid(self):
        d = _decision('', 'Y', 'preserve-subfolder', conflict='merge')
        out = '\n'.join(plan_report._render_decisions([], [d], False))
        self.assertIn('_(no UID)_', out)


class DefaultsBucketTests(unittest.TestCase):
    def test_no_decisions_at_all(self):
        out = '\n'.join(plan_report._render_defaults({}))
        self.assertIn('no nested shared folders', out)

    def test_no_inherit_rows(self):
        d = _decision('u1', 'A', 'promote-to-sibling')
        out = '\n'.join(plan_report._render_defaults(_plan_meta([d])))
        self.assertIn('No defaults applied', out)

    def test_inherit_rows_collapsed_into_summary(self):
        ds = [
            _decision('u1', 'A', 'preserve-subfolder',
                      parent='SF1',
                      reason='no independent membership'),
            _decision('u2', 'B', 'preserve-subfolder',
                      parent='SF2',
                      reason='matches parent'),
            _decision('u3', 'C', 'promote-to-sibling',
                      parent='SF3'),
        ]
        out = '\n'.join(plan_report._render_defaults(_plan_meta(ds)))
        self.assertIn('<details>', out)
        self.assertIn('2 subfolder(s)', out)
        self.assertIn('SF1/A', out)
        self.assertIn('SF2/B', out)
        self.assertNotIn('SF3/C', out)

    def test_inherit_row_with_unresolved_parent(self):
        d = _decision('u1', 'A', 'preserve-subfolder', parent='')
        out = '\n'.join(plan_report._render_defaults(_plan_meta([d])))
        self.assertIn('_(unresolved)_', out)


class PhasesTests(unittest.TestCase):
    def test_phases_are_plain_language(self):
        out = '\n'.join(plan_report._render_phases(_inventory(), _estimate()))
        self.assertIn('Step 5', out)
        self.assertIn('recreate 42 node(s)', out)
        self.assertIn('340 user(s)', out)

    def test_phases_handles_missing_counts(self):
        out = '\n'.join(plan_report._render_phases({}, {}))
        self.assertIn('re-run `plan`', out)


class NotTouchTests(unittest.TestCase):
    def test_not_touch_calls_out_rule_zero(self):
        out = '\n'.join(plan_report._render_not_touch())
        self.assertIn('Source tenant is read-only forever', out)
        self.assertIn('Rule 0', out)
        self.assertIn('decommission', out)


class SignoffTests(unittest.TestCase):
    def test_signoff_includes_review_count(self):
        d = _decision('u1', 'A', 'promote-to-sibling')
        out = '\n'.join(plan_report._render_signoff([d], []))
        self.assertIn('**1** subfolder decision(s)', out)
        self.assertIn('[ ]', out)

    def test_signoff_includes_conflict_count(self):
        d = _decision('u1', 'A', 'preserve-subfolder', conflict='suffix')
        out = '\n'.join(plan_report._render_signoff([], [d]))
        self.assertIn('**1** name-conflict policy choice(s)', out)

    def test_signoff_omits_review_lines_when_no_review(self):
        out = '\n'.join(plan_report._render_signoff([], []))
        self.assertNotIn('subfolder decision(s)', out)
        self.assertNotIn('name-conflict policy choice(s)', out)


class CheatsheetTests(unittest.TestCase):
    def test_cheatsheet_shows_yaml_structure(self):
        out = '\n'.join(plan_report._render_overrides_cheatsheet())
        self.assertIn('subfolders:', out)
        self.assertIn('conflicts:', out)
        self.assertIn('notes:', out)
        self.assertIn('--accept-risk', out)


# ── End-to-end render_migration_plan ─────────────────────────────────


class RenderPlanTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)

    def _paths(self, inventory=None, plan=None, estimate=None):
        ip = pp = ep = ''
        if inventory is not None:
            ip = _write(self.td.name, 'inv.json', inventory)
        if plan is not None:
            pp = _write(self.td.name, 'plan.json', plan)
        if estimate is not None:
            ep = _write(self.td.name, 'est.json', estimate)
        return ip, pp, ep

    def test_empty_inputs_still_renders_all_sections(self):
        out = plan_report.render_migration_plan('', '', '')
        self.assertIn('# Migration plan', out)
        self.assertIn('## Summary', out)
        self.assertIn('## Decisions awaiting your review', out)
        self.assertIn('## What this migration will NOT touch', out)
        self.assertIn('## Sign-off', out)

    def test_inventory_only_inheritances(self):
        ip, pp, ep = self._paths(
            inventory=_inventory(),
            plan=_plan_meta([
                _decision('u1', 'A', 'preserve-subfolder'),
                _decision('u2', 'B', 'preserve-subfolder'),
            ]),
            estimate=_estimate())
        out = plan_report.render_migration_plan(ip, pp, ep)
        self.assertIn('_No decisions need review', out)
        self.assertIn('2 subfolder(s)', out)

    def test_mixed_actions_render_all(self):
        ip, pp, ep = self._paths(
            inventory=_inventory(),
            plan=_plan_meta([
                _decision('u1', 'A', 'preserve-subfolder'),
                _decision('u2', 'B', 'promote-to-sibling',
                          reason='adds users'),
                _decision('u3', 'C', 'flatten-with-prefix',
                          reason='legacy target'),
                _decision('u4', 'D', 'needs-review',
                          reason='parent missing', parent=''),
            ]),
            estimate=_estimate())
        out = plan_report.render_migration_plan(ip, pp, ep)
        self.assertIn('promote-to-sibling', out) # alternatives line
        self.assertIn('flatten-with-prefix', out)
        self.assertIn('needs-review', out)
        self.assertIn('`subfolders.u2`', out)

    def test_plan_with_conflicts(self):
        ip, pp, ep = self._paths(
            inventory=_inventory(),
            plan=_plan_meta([
                _decision('u1', 'A', 'promote-to-sibling',
                          conflict='suffix'),
                _decision('u2', 'B', 'promote-to-sibling',
                          conflict='merge'),
            ]),
            estimate=_estimate())
        out = plan_report.render_migration_plan(ip, pp, ep)
        self.assertIn('`conflicts.u1`', out)
        self.assertIn('`conflicts.u2`', out)
        self.assertIn('append', out)
        self.assertIn('reuse the existing', out)

    def test_tier_outlier_xlarge(self):
        ip, pp, ep = self._paths(
            inventory=_inventory(),
            plan=_plan_meta([]),
            estimate=_estimate(tier='xlarge (5k+)', delay=3.0, batch=100,
                                calls=98000, duration='4h 15m'))
        out = plan_report.render_migration_plan(ip, pp, ep)
        self.assertIn('xlarge', out)
        self.assertIn('4h 15m', out)
        self.assertIn('98,000 API calls', out)

    def test_degraded_inventory_only(self):
        ip = _write(self.td.name, 'inv.json', _inventory())
        out = plan_report.render_migration_plan(ip, '', '')
        self.assertIn('# Migration plan', out)
        # No decisions to render — section still emitted
        self.assertIn('_No decisions need review', out)
        # Counts present, so phases get plain-language entries
        self.assertIn('340 user(s)', out)

    def test_degraded_plan_only(self):
        pp = _write(self.td.name, 'plan.json',
                    _plan_meta([_decision('u1', 'A', 'promote-to-sibling')],
                                supports_true_nested=False))
        out = plan_report.render_migration_plan('', pp, '')
        self.assertIn('Inventory data missing', out)
        self.assertIn('`subfolders.u1`', out)

    def test_supports_true_nested_alters_alternatives_column(self):
        ip, pp, ep = self._paths(
            inventory=_inventory(),
            plan=_plan_meta(
                [_decision('u1', 'A', 'promote-to-sibling')],
                supports_true_nested=True),
            estimate=_estimate())
        out = plan_report.render_migration_plan(ip, pp, ep)
        self.assertIn('promote-to-true-nested', out)


# ── Machine-mirror JSON ──────────────────────────────────────────────


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)

    def _write_inputs(self, **kwargs):
        ip = _write(self.td.name, 'inv.json', kwargs.get('inventory', _inventory()))
        pp = _write(self.td.name, 'plan.json', kwargs.get('plan'))
        ep = _write(self.td.name, 'est.json', kwargs.get('estimate', _estimate()))
        return ip, pp, ep

    def test_mirror_carries_decision_rows(self):
        ip, pp, ep = self._write_inputs(plan=_plan_meta([
            _decision('u1', 'A', 'promote-to-sibling',
                      reason='adds users'),
            _decision('u2', 'B', 'preserve-subfolder'),
        ]))
        m = plan_report.build_machine_mirror(ip, pp, ep)
        self.assertEqual(len(m['decisions']), 1)
        self.assertEqual(m['decisions'][0]['override_key'],
                         'subfolders.u1')
        self.assertEqual(m['decisions'][0]['operator_recommends'],
                         'promote-to-sibling')
        self.assertIn('preserve-subfolder', m['decisions'][0]['alternatives'])
        self.assertEqual(m['defaults_bucket']['preserve-subfolder'], 1)

    def test_mirror_carries_conflict_rows(self):
        ip, pp, ep = self._write_inputs(plan=_plan_meta([
            _decision('u1', 'A', 'promote-to-sibling',
                      conflict='suffix',
                      promoted_name='X - A'),
        ]))
        m = plan_report.build_machine_mirror(ip, pp, ep)
        self.assertEqual(len(m['conflicts']), 1)
        self.assertEqual(m['conflicts'][0]['override_key'],
                         'conflicts.u1')
        self.assertEqual(m['conflicts'][0]['proposed_promoted_name'],
                         'X - A')
        self.assertEqual(m['conflicts'][0]['operator_recommends'],
                         'suffix')

    def test_mirror_input_paths_recorded(self):
        ip, pp, ep = self._write_inputs(plan=_plan_meta([]))
        m = plan_report.build_machine_mirror(ip, pp, ep)
        self.assertEqual(m['inputs']['inventory'], ip)
        self.assertEqual(m['inputs']['nested_sf_plan'], pp)
        self.assertEqual(m['inputs']['estimate'], ep)

    def test_mirror_is_json_serialisable(self):
        ip, pp, ep = self._write_inputs(plan=_plan_meta([
            _decision('u1', 'A', 'promote-to-sibling'),
        ]))
        m = plan_report.build_machine_mirror(ip, pp, ep)
        self.assertEqual(json.loads(json.dumps(m)), m)

    def test_mirror_summary_carries_throttle_and_totals(self):
        ip, pp, ep = self._write_inputs(plan=_plan_meta([]),
                                         estimate=_estimate(tier='large',
                                                             calls=4242))
        m = plan_report.build_machine_mirror(ip, pp, ep)
        self.assertEqual(m['summary']['throttle']['tier'], 'large')
        self.assertEqual(m['summary']['totals']['calls'], 4242)

    def test_mirror_handles_all_inputs_missing(self):
        m = plan_report.build_machine_mirror('', '', '')
        self.assertEqual(m['decisions'], [])
        self.assertEqual(m['conflicts'], [])
        self.assertEqual(m['inputs']['inventory'], '')


# ── write_report (filesystem) ────────────────────────────────────────


class WriteReportTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)

    def _full_inputs(self):
        ip = _write(self.td.name, 'inv.json', _inventory())
        pp = _write(self.td.name, 'plan.json', _plan_meta([
            _decision('u1', 'A', 'promote-to-sibling'),
        ]))
        ep = _write(self.td.name, 'est.json', _estimate())
        return ip, pp, ep

    def test_write_report_emits_md_and_json(self):
        ip, pp, ep = self._full_inputs()
        out_md = os.path.join(self.td.name, 'plan.md')
        md_path, json_path = plan_report.write_report(
            out_md, inventory_path=ip,
            nested_sf_plan_path=pp, estimate_path=ep)
        self.assertEqual(md_path, out_md)
        self.assertEqual(json_path, os.path.join(self.td.name, 'plan.json'))
        self.assertTrue(os.path.isfile(md_path))
        self.assertTrue(os.path.isfile(json_path))

    def test_write_report_files_are_0644(self):
        ip, pp, ep = self._full_inputs()
        out_md = os.path.join(self.td.name, 'plan.md')
        md_path, json_path = plan_report.write_report(
            out_md, inventory_path=ip,
            nested_sf_plan_path=pp, estimate_path=ep)
        for p in (md_path, json_path):
            mode = stat.S_IMODE(os.stat(p).st_mode)
            self.assertEqual(mode, 0o644,
                             f'{p} mode={oct(mode)} (expected 0o644)')

    def test_write_report_requires_at_least_one_input(self):
        with self.assertRaises(ValueError):
            plan_report.write_report(
                os.path.join(self.td.name, 'plan.md'))

    def test_write_report_with_non_md_extension(self):
        ip, _pp, _ep = self._full_inputs()
        out = os.path.join(self.td.name, 'report.txt')
        md_path, json_path = plan_report.write_report(
            out, inventory_path=ip)
        self.assertEqual(md_path, out)
        self.assertEqual(json_path, out + '.json')
        self.assertTrue(os.path.isfile(json_path))

    def test_write_report_json_mirror_loads_back(self):
        ip, pp, ep = self._full_inputs()
        out_md = os.path.join(self.td.name, 'plan.md')
        _, json_path = plan_report.write_report(
            out_md, inventory_path=ip,
            nested_sf_plan_path=pp, estimate_path=ep)
        with open(json_path) as f:
            mirror = json.load(f)
        self.assertEqual(len(mirror['decisions']), 1)
        self.assertEqual(mirror['decisions'][0]['override_key'],
                         'subfolders.u1')


# ── Subcommand wiring ────────────────────────────────────────────────


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)

    def test_registered_in_tenant_migrate_group(self):
        group = TenantMigrateCommand()
        self.assertIn('plan-report', group.subcommands)

    def test_parser_accepts_all_inputs(self):
        ns = plan_report_parser.parse_args([
            '--inventory', 'i.json',
            '--nested-sf-plan', 'n.json',
            '--estimate', 'e.json',
            '--output', 'o.md',
        ])
        self.assertEqual(ns.inventory, 'i.json')
        self.assertEqual(ns.nested_sf_plan, 'n.json')
        self.assertEqual(ns.estimate, 'e.json')
        self.assertEqual(ns.output, 'o.md')

    def test_parser_requires_output(self):
        with self.assertRaises(SystemExit):
            plan_report_parser.parse_args([])

    def test_execute_no_inputs_returns_error(self):
        cmd = PlanReportCommand()
        out = os.path.join(self.td.name, 'plan.md')
        result = cmd.execute(None, output=out)
        self.assertEqual(result, {'error': 'no_inputs'})
        self.assertFalse(os.path.exists(out))

    def test_execute_with_inventory_only(self):
        cmd = PlanReportCommand()
        ip = _write(self.td.name, 'inv.json', _inventory())
        out = os.path.join(self.td.name, 'plan.md')
        result = cmd.execute(None, inventory=ip,
                              nested_sf_plan='', estimate='',
                              output=out)
        self.assertEqual(result['report_path'], out)
        self.assertTrue(os.path.isfile(result['mirror_path']))

    def test_execute_with_all_inputs(self):
        cmd = PlanReportCommand()
        ip = _write(self.td.name, 'inv.json', _inventory())
        pp = _write(self.td.name, 'plan.json', _plan_meta([
            _decision('u1', 'A', 'promote-to-sibling',
                      conflict='suffix')]))
        ep = _write(self.td.name, 'est.json', _estimate())
        out = os.path.join(self.td.name, 'plan.md')
        result = cmd.execute(None, inventory=ip,
                              nested_sf_plan=pp, estimate=ep,
                              output=out)
        self.assertTrue(os.path.isfile(result['report_path']))
        with open(result['report_path']) as f:
            md = f.read()
        self.assertIn('subfolders.u1', md)
        self.assertIn('conflicts.u1', md)


if __name__ == '__main__':
    unittest.main()
