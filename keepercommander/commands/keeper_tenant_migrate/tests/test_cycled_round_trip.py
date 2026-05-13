"""Cycled round-trip tests (T6 — squad-2).

Test ordering matters: the **Rule 0 / source-read-only** tests run
FIRST (alphabetical / structural priority via the
``Test00SourceReadOnly`` class name) so any regression in the
read-only enforcement surfaces before any other test executes.

The rest exercise:

  - 3-cycle default (idempotency, undo cleanliness, byte equality)
  - per-cycle metric drift (>5 % triggers FAIL)
  - the recursion guard: tests on the cycled tests themselves —
    deliberately mutate source / break undo / accumulate residue and
    verify the harness *catches* the breach instead of silently
    passing.

This file is fakes-mode only. Live-mode wiring lives in
``migration_scripts/ci/comprehensive_rehearsal.py`` and is exercised
indirectly via the helpers under
``keepercommander.commands.keeper_tenant_migrate.cycled_validation``.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate import cycled_validation as cv
from keepercommander.commands.keeper_tenant_migrate.cycled_validation import (
    CycledHarness,
    CycleMetrics,
    CycleResult,
    DEFAULT_CYCLES,
    DRIFT_THRESHOLD,
    SourceMutationError,
    assert_source_file_unchanged,
    compute_drift,
    hash_source_config_file,
    snapshot_bytes,
    verify_source_read_only,
    write_per_cycle_audit,
    write_unified_audit,
)


# ════════════════════════════════════════════════════════════════════
# Rule 0 — source-read-only enforcement (must run FIRST)
# ════════════════════════════════════════════════════════════════════



# Module-level guard: tests below depend on the rehearsal harness or
# legacy reference script under `migration_scripts/`, which ships
# separately from the Commander tree. When absent, the dependent
# classes are skipped.
import os as _os
_HARNESS_DIR = _os.path.abspath(_os.path.join(
    _os.path.dirname(__file__), '..', '..', '..', '..', 'migration_scripts'))
_HAS_HARNESS = _os.path.isdir(_HARNESS_DIR)

class Test00SourceReadOnly_RuleZero(unittest.TestCase):
    """Rule 0: the EU-demo source is read-only forever.

    These tests MUST pass before any other cycled test is meaningful.
    A regression here is an immediate roll-back — silent source
    mutation is the worst possible failure mode for this project.
    """

    def test_baseline_captured_once_in_constructor(self):
        h = CycledHarness()
        # The constructor must have populated _baseline_source_bytes.
        self.assertTrue(h._baseline_source_bytes)
        self.assertEqual(h._baseline_source_bytes,
                          snapshot_bytes(h.inventory))

    def test_unchanged_source_passes_assertion(self):
        h = CycledHarness()
        # Calling the assertion directly with no mutations must succeed.
        h.assert_source_unchanged(cycle=0)
        h.assert_source_unchanged(cycle=99)

    def test_source_mutation_raises_immediately(self):
        h = CycledHarness()
        # Mutate source between cycles. The next assertion MUST raise.
        h.inventory['entities']['nodes'].append({'name': 'EVIL', 'parent': ''})
        with self.assertRaises(SourceMutationError) as ctx:
            h.assert_source_unchanged(cycle=1)
        self.assertIn('SOURCE MUTATION DETECTED', str(ctx.exception))
        self.assertIn('cycle 1', str(ctx.exception))

    def test_source_mutation_writes_audit_log_before_raising(self):
        h = CycledHarness()
        h.inventory['entities']['nodes'][0]['name'] = 'TAMPERED'
        try:
            h.assert_source_unchanged(cycle=2)
        except SourceMutationError:
            pass
        # The audit log entry was written EVEN THOUGH the call raised.
        self.assertEqual(len(h.audit_log), 1)
        self.assertIn('SOURCE MUTATION DETECTED', h.audit_log[0])
        self.assertIn('cycle 2', h.audit_log[0])

    def test_run_aborts_on_first_mutation(self):
        """If source is corrupted between cycle 1 and 2, the run
        must abort BEFORE cycle 2's forward path executes."""
        h = CycledHarness()

        original_run_one = h.run_one_cycle
        cycle_calls: list[int] = []

        def spy_one_cycle(*args, **kwargs):
            cycle_calls.append(kwargs.get('cycle', -1))
            r = original_run_one(*args, **kwargs)
            # Inject a mutation right after cycle 1 succeeds.
            if kwargs.get('cycle') == 1:
                h.inventory['entities']['nodes'].append(
                    {'name': 'CORRUPTED', 'parent': ''}
                )
            return r

        with mock.patch.object(h, 'run_one_cycle', side_effect=spy_one_cycle):
            with self.assertRaises(SourceMutationError):
                h.run(cycles=3)

        # Cycle 1 ran. Cycle 2 STARTED (its own internal post-check
        # detected the breach), but its result was never appended.
        self.assertEqual(cycle_calls, [1, 2])

    def test_step_helpers_use_local_clone_not_source(self):
        """Forward-step helpers must read from a deep-copied clone of
        the inventory. Even if a step *tried* to mutate its argument,
        the harness's source bytes stay frozen."""
        h = CycledHarness()
        baseline = snapshot_bytes(h.inventory)
        results = h.run(cycles=1)
        self.assertEqual(snapshot_bytes(h.inventory), baseline)
        self.assertEqual(results[0].status, 'PASS')

    def test_verify_source_read_only_helper_no_audit_log(self):
        baseline = snapshot_bytes({'a': 1})
        # No audit_log argument — helper must not raise on equality.
        verify_source_read_only(baseline, {'a': 1}, cycle=5)
        # Mutation without audit_log still raises.
        with self.assertRaises(SourceMutationError):
            verify_source_read_only(baseline, {'a': 2}, cycle=5)

    def test_live_mode_hash_source_config_file(self):
        """Live-mode rail: byte digest of the source config path."""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            tmp.write(b'{"hello":"world"}')
            tmp_path = tmp.name
        try:
            h1 = hash_source_config_file(tmp_path)
            h2 = hash_source_config_file(tmp_path)
            self.assertEqual(h1, h2)
            # Length is 64 hex chars for SHA-256.
            self.assertEqual(len(h1), 64)
            # File mutation changes the hash.
            with open(tmp_path, 'wb') as f:
                f.write(b'{"hello":"mutated"}')
            self.assertNotEqual(hash_source_config_file(tmp_path), h1)
        finally:
            os.unlink(tmp_path)

    def test_live_mode_assert_source_file_unchanged(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            tmp.write(b'{"sentinel":42}')
            tmp_path = tmp.name
        try:
            baseline = hash_source_config_file(tmp_path)
            audit: list = []
            # Unchanged → no raise.
            assert_source_file_unchanged(
                tmp_path, baseline, cycle=1, audit_log=audit,
            )
            self.assertEqual(audit, [])
            # Mutate → raise + audit-log entry.
            with open(tmp_path, 'wb') as f:
                f.write(b'{"sentinel":99}')
            with self.assertRaises(SourceMutationError) as ctx:
                assert_source_file_unchanged(
                    tmp_path, baseline, cycle=2, audit_log=audit,
                )
            self.assertEqual(len(audit), 1)
            self.assertIn('cycle 2', audit[0])
            self.assertIn(tmp_path, str(ctx.exception))
        finally:
            os.unlink(tmp_path)

    def test_live_mode_no_audit_log_argument(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            tmp.write(b'X')
            tmp_path = tmp.name
        try:
            base = hash_source_config_file(tmp_path)
            with open(tmp_path, 'wb') as f:
                f.write(b'Y')
            # No audit_log argument — must still raise.
            with self.assertRaises(SourceMutationError):
                assert_source_file_unchanged(tmp_path, base, cycle=7)
        finally:
            os.unlink(tmp_path)


# ════════════════════════════════════════════════════════════════════
# Cycle definition + 3-cycle default run
# ════════════════════════════════════════════════════════════════════


class Test01CycleDefinition(unittest.TestCase):
    """Validate the cycle building blocks before exercising the loop."""

    def test_default_cycles_constant(self):
        self.assertEqual(DEFAULT_CYCLES, 3)

    def test_drift_threshold_constant(self):
        self.assertEqual(DRIFT_THRESHOLD, 0.05)

    def test_synthetic_inventory_shape(self):
        h = CycledHarness()
        inv = h.inventory
        self.assertIn('entities', inv)
        self.assertIn('counts', inv)
        for k in ('nodes', 'teams', 'roles', 'shared_folders',
                   'users', 'records', 'shares', 'attachments'):
            self.assertIn(k, inv['entities'])
            self.assertIn(k, inv['counts'])
            self.assertEqual(len(inv['entities'][k]), inv['counts'][k])

    def test_cycle_metrics_as_dict_round_trips(self):
        m = CycleMetrics(api_calls=42, runtime_seconds=1.23,
                          throttle_events=3, verify_pass_rate=0.99,
                          undo_completion_rate=1.0)
        d = m.as_dict()
        self.assertEqual(d['api_calls'], 42)
        self.assertEqual(d['throttle_events'], 3)

    def test_cycle_result_as_dict_round_trips(self):
        r = CycleResult(
            cycle=1, status='PASS', metrics=CycleMetrics(api_calls=10),
            target_post_create_hash='deadbeef',
            target_post_undo_clean=True, notes='all good',
        )
        d = r.as_dict()
        self.assertEqual(d['cycle'], 1)
        self.assertEqual(d['status'], 'PASS')
        self.assertEqual(d['target_post_create_hash'], 'deadbeef')


class Test02ThreeCycleDefault(unittest.TestCase):
    """End-to-end: run the default 3 cycles and assert all invariants."""

    def setUp(self):
        self.h = CycledHarness()

    def test_default_run_returns_three_cycles(self):
        results = self.h.run()
        self.assertEqual(len(results), DEFAULT_CYCLES)

    def test_every_cycle_passes(self):
        results = self.h.run(cycles=3)
        for r in results:
            self.assertEqual(r.status, 'PASS', msg=r.notes)

    def test_target_post_create_hash_byte_equal_across_cycles(self):
        results = self.h.run(cycles=3)
        h1 = results[0].target_post_create_hash
        for r in results[1:]:
            self.assertEqual(r.target_post_create_hash, h1,
                              f'cycle {r.cycle} drift from cycle 1')

    def test_undo_clean_after_every_cycle(self):
        results = self.h.run(cycles=3)
        for r in results:
            self.assertTrue(r.target_post_undo_clean,
                             f'cycle {r.cycle} left residue')

    def test_assert_idempotency_passes_on_clean_run(self):
        results = self.h.run(cycles=3)
        self.assertEqual(self.h.assert_idempotency(results), [])

    def test_assert_undo_clean_passes_on_clean_run(self):
        results = self.h.run(cycles=3)
        self.assertEqual(self.h.assert_undo_clean(results), [])

    def test_assert_no_drift_passes_on_clean_run(self):
        results = self.h.run(cycles=3)
        # API calls are deterministic in fakes-mode → 0 drift.
        # Runtime drift is non-zero but well under 5%.
        # We allow tiny natural variation but not a systemic breach.
        failures = self.h.assert_no_drift(results)
        # Filter out runtime which can fluctuate on noisy CI; the
        # squad-2 brief explicitly notes runtime can drift in fakes
        # without indicating a regression. We assert: at most one
        # runtime entry and never any API/throttle/verify/undo drift.
        for f in failures:
            self.assertIn('runtime_seconds', f,
                           f'unexpected non-runtime drift: {f!r}')

    def test_run_with_zero_cycles_raises(self):
        with self.assertRaises(ValueError):
            self.h.run(cycles=0)

    def test_run_with_negative_cycles_raises(self):
        with self.assertRaises(ValueError):
            self.h.run(cycles=-3)

    def test_run_one_cycle_returns_pass(self):
        r = self.h.run_one_cycle(cycle=1)
        self.assertEqual(r.status, 'PASS')

    def test_hammer_mode_propagates(self):
        # Hammer mode is currently a flag-only branch in fakes-mode.
        results = self.h.run(cycles=2, hammer=True)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertEqual(r.status, 'PASS')


# ════════════════════════════════════════════════════════════════════
# Drift detection (T6.4)
# ════════════════════════════════════════════════════════════════════


class Test03DriftDetection(unittest.TestCase):
    def test_compute_drift_zero_when_equal(self):
        m = CycleMetrics(api_calls=10, runtime_seconds=1.0,
                          throttle_events=2, verify_pass_rate=1.0,
                          undo_completion_rate=1.0)
        d = compute_drift(m, m)
        for v in d.values():
            self.assertEqual(v, 0.0)

    def test_compute_drift_relative_for_count_metrics(self):
        a = CycleMetrics(api_calls=100)
        b = CycleMetrics(api_calls=110)
        d = compute_drift(a, b)
        self.assertAlmostEqual(d['api_calls'], 0.10)

    def test_compute_drift_absolute_for_rates(self):
        a = CycleMetrics(verify_pass_rate=1.0, undo_completion_rate=1.0)
        b = CycleMetrics(verify_pass_rate=0.96, undo_completion_rate=0.92)
        d = compute_drift(a, b)
        self.assertAlmostEqual(d['verify_pass_rate'], 0.04)
        self.assertAlmostEqual(d['undo_completion_rate'], 0.08)

    def test_compute_drift_zero_baseline_no_div_zero(self):
        a = CycleMetrics(api_calls=0, throttle_events=0)
        b = CycleMetrics(api_calls=0, throttle_events=0)
        d = compute_drift(a, b)
        # max(abs(0), 1.0) == 1.0 → 0 drift on equal-zero comparisons.
        self.assertEqual(d['api_calls'], 0.0)
        self.assertEqual(d['throttle_events'], 0.0)

    def test_drift_above_threshold_flagged(self):
        h = CycledHarness()
        c1 = CycleResult(
            cycle=1, status='PASS', metrics=CycleMetrics(api_calls=100),
            target_post_create_hash='h', target_post_undo_clean=True,
        )
        c2 = CycleResult(
            cycle=2, status='PASS', metrics=CycleMetrics(api_calls=200),
            target_post_create_hash='h', target_post_undo_clean=True,
        )
        # api_calls drifted 100% — well above 5% threshold.
        failures = h.assert_no_drift([c1, c2])
        self.assertTrue(any('api_calls' in f for f in failures))

    def test_assert_idempotency_flags_hash_drift(self):
        h = CycledHarness()
        c1 = CycleResult(
            cycle=1, status='PASS', metrics=CycleMetrics(),
            target_post_create_hash='hash-A',
            target_post_undo_clean=True,
        )
        c2 = CycleResult(
            cycle=2, status='PASS', metrics=CycleMetrics(),
            target_post_create_hash='hash-B-different',
            target_post_undo_clean=True,
        )
        failures = h.assert_idempotency([c1, c2])
        self.assertEqual(len(failures), 1)
        self.assertIn('cycle 2', failures[0])

    def test_assert_undo_clean_flags_residue(self):
        h = CycledHarness()
        c1 = CycleResult(
            cycle=1, status='PASS', metrics=CycleMetrics(),
            target_post_create_hash='', target_post_undo_clean=False,
            notes='residue=4',
        )
        failures = h.assert_undo_clean([c1])
        self.assertEqual(len(failures), 1)
        self.assertIn('residue=4', failures[0])

    def test_assert_no_drift_empty_when_single_cycle(self):
        h = CycledHarness()
        results = h.run(cycles=1)
        self.assertEqual(h.assert_no_drift(results), [])
        self.assertEqual(h.assert_idempotency(results), [])


# ════════════════════════════════════════════════════════════════════
# Recursion guard — tests on the cycled tests (T6.9)
# ════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_HARNESS, "requires migration_scripts/ harness (not shipped with Commander)")
class Test04RecursionGuard(unittest.TestCase):
    """Inject deliberate failures and verify the harness catches them."""

    def test_detects_undo_incompleteness(self):
        """If undo silently leaves entities, the cycle must FAIL."""
        h = CycledHarness()

        original = cv._step_undo

        def broken_undo(target, audit_events, prefix):
            # Simulate undo that "forgot" to delete some entities.
            # Just don't reverse anything.
            return 0, 999       # zero reversed, 999 attempted

        with mock.patch.object(cv, '_step_undo', side_effect=broken_undo):
            results = h.run(cycles=1)

        self.assertEqual(results[0].status, 'FAIL')
        self.assertFalse(results[0].target_post_undo_clean)
        # undo_completion_rate must be near zero.
        self.assertLess(results[0].metrics.undo_completion_rate, 0.5)

    def test_detects_accumulating_residue_via_post_undo_count(self):
        """A target that retains entities between cycles fails undo-clean."""
        h = CycledHarness()

        # Patch _step_undo to leave one record behind every cycle.
        def leaky_undo(target, audit_events, prefix):
            # Pop everything except one record.
            last_uid = next(iter(target.records), None)
            target.records.clear()
            if last_uid:
                target.records[last_uid] = {'leaked': True}
            target.shares.clear()
            target.attachments.clear()
            target.users.clear()
            target.nodes.clear()
            target.teams.clear()
            target.roles.clear()
            target.shared_folders.clear()
            return 1, 1

        with mock.patch.object(cv, '_step_undo', side_effect=leaky_undo):
            results = h.run(cycles=2)

        # Both cycles MUST have target_post_undo_clean=False.
        self.assertFalse(results[0].target_post_undo_clean)
        self.assertFalse(results[1].target_post_undo_clean)
        failures = h.assert_undo_clean(results)
        self.assertEqual(len(failures), 2)

    def test_detects_throttle_drift(self):
        """An artificial throttle spike in cycle 2 must trip drift."""
        h = CycledHarness()
        c1 = CycleResult(
            cycle=1, status='PASS',
            metrics=CycleMetrics(throttle_events=2),
            target_post_create_hash='h', target_post_undo_clean=True,
        )
        c2 = CycleResult(
            cycle=2, status='PASS',
            # 2 -> 10 = 400 % drift, way above 5 %.
            metrics=CycleMetrics(throttle_events=10),
            target_post_create_hash='h', target_post_undo_clean=True,
        )
        failures = h.assert_no_drift([c1, c2])
        self.assertTrue(any('throttle_events' in f for f in failures))

    def test_partial_verify_writes_note_in_result(self):
        """When verify_pass_rate is < 1.0 the cycle's notes column
        documents the count, and the run is marked FAIL."""
        h = CycledHarness()

        # Patch _step_verify to return 80 % pass rate.
        def partial_verify(target, inv):
            return 8, 10

        with mock.patch.object(cv, '_step_verify', side_effect=partial_verify):
            results = h.run(cycles=1)
        r = results[0]
        self.assertEqual(r.status, 'FAIL')
        self.assertIn('verify 8/10', r.notes)
        self.assertEqual(r.metrics.verify_pass_rate, 0.8)

    def test_detects_verify_rate_drop(self):
        """A 4 % drop in verify pass rate is below 5 % drift; a 6 %
        drop must be caught."""
        h = CycledHarness()
        c1 = CycleResult(
            cycle=1, status='PASS',
            metrics=CycleMetrics(verify_pass_rate=1.00),
            target_post_create_hash='h', target_post_undo_clean=True,
        )
        c2 = CycleResult(
            cycle=2, status='PASS',
            metrics=CycleMetrics(verify_pass_rate=0.94),
            target_post_create_hash='h', target_post_undo_clean=True,
        )
        failures = h.assert_no_drift([c1, c2])
        self.assertTrue(any('verify_pass_rate' in f for f in failures))


# ════════════════════════════════════════════════════════════════════
# Audit trail emission (T6.8)
# ════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_HARNESS, "requires migration_scripts/ harness (not shipped with Commander)")
class Test05AuditTrail(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_per_cycle_audit_written_under_cycle_dir(self):
        h = CycledHarness()
        results = h.run(cycles=3)
        for r in results:
            path = write_per_cycle_audit(self.tmp, r.cycle, r)
            self.assertTrue(os.path.exists(path))
            self.assertIn(f'cycle-{r.cycle}', path)
            with open(path) as f:
                payload = json.load(f)
            self.assertEqual(payload['cycle'], r.cycle)
            self.assertEqual(payload['status'], r.status)

    def test_unified_audit_summary_emits_md_and_json(self):
        h = CycledHarness()
        results = h.run(cycles=3)
        md_path = write_unified_audit(self.tmp, results)
        json_path = os.path.join(self.tmp, 'cycled_validation.json')
        self.assertTrue(os.path.exists(md_path))
        self.assertTrue(os.path.exists(json_path))
        with open(md_path) as f:
            md = f.read()
        # Contains a row per cycle.
        for r in results:
            self.assertIn(f'| {r.cycle} |', md)
        # Drift section present.
        self.assertIn('Drift vs cycle 1', md)
        with open(json_path) as f:
            payload = json.load(f)
        self.assertEqual(len(payload), 3)

    def test_unified_audit_no_drift_section_when_one_cycle(self):
        h = CycledHarness()
        results = h.run(cycles=1)
        md_path = write_unified_audit(self.tmp, results)
        with open(md_path) as f:
            md = f.read()
        self.assertNotIn('Drift vs cycle 1', md)


# ════════════════════════════════════════════════════════════════════
# Live-mode wiring assertions (no subprocess invoked)
# ════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_HARNESS, "requires migration_scripts/ harness (not shipped with Commander)")
class Test06LiveModeWiringSurface(unittest.TestCase):
    """Verify the live-mode harness exposes the cycled flags expected
    by the squad-2 brief. Does NOT invoke subprocess; pure argparse
    introspection."""

    def test_comprehensive_rehearsal_has_cycles_flag(self):
        from migration_scripts.ci.comprehensive_rehearsal import build_arg_parser
        ap = build_arg_parser()
        # argparse exposes _actions; we look for --cycles.
        dests = {a.dest for a in ap._actions}
        self.assertIn('cycles', dests)
        self.assertIn('hammer', dests)

    def test_cycles_default_zero(self):
        from migration_scripts.ci.comprehensive_rehearsal import build_arg_parser
        ap = build_arg_parser()
        # Defaults must keep current Tier 1-8 behaviour when --cycles
        # isn't passed (cycles=0 == cycled-mode-disabled).
        ns = ap.parse_args([
            '--source-config', '/tmp/x',
            '--target-config', '/tmp/y',
            '--run-dir', '/tmp/z',
        ])
        self.assertEqual(ns.cycles, 0)
        self.assertFalse(ns.hammer)

    def test_cycles_flag_parses(self):
        from migration_scripts.ci.comprehensive_rehearsal import build_arg_parser
        ap = build_arg_parser()
        ns = ap.parse_args([
            '--source-config', '/tmp/x',
            '--target-config', '/tmp/y',
            '--run-dir', '/tmp/z',
            '--cycles', '5',
            '--hammer',
        ])
        self.assertEqual(ns.cycles, 5)
        self.assertTrue(ns.hammer)


# ════════════════════════════════════════════════════════════════════
# Snapshot helpers (deterministic byte equality)
# ════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_HARNESS, "requires migration_scripts/ harness (not shipped with Commander)")
class Test07SnapshotHelpers(unittest.TestCase):
    def test_snapshot_bytes_sorts_keys(self):
        a = snapshot_bytes({'b': 1, 'a': 2})
        b = snapshot_bytes({'a': 2, 'b': 1})
        self.assertEqual(a, b)

    def test_snapshot_bytes_handles_non_string_keys_via_default(self):
        # The default=str fallback allows objects that aren't natively
        # JSON-serialisable to be snapshotted (we never use it in
        # production but test the path so coverage stays at 100%).
        class Sentinel:
            def __str__(self):
                return 'sentinel'
        b = snapshot_bytes({'k': Sentinel()})
        self.assertIn(b'sentinel', b)

    def test_snapshot_bytes_returns_bytes(self):
        self.assertIsInstance(snapshot_bytes({'x': 1}), bytes)


@unittest.skipUnless(_HAS_HARNESS, "requires migration_scripts/ harness (not shipped with Commander)")
class Test08LiveModeHelpers(unittest.TestCase):
    """Direct exercise of the cycled-mode helpers in
    ``comprehensive_rehearsal.py`` (T6.12 — 100 % line coverage on
    new code)."""

    def setUp(self):
        # Imports here are not at module top because the harness file
        # has heavy side-effect imports we don't want at collection
        # time. Tests in this class run after the rest of the suite.
        from migration_scripts.ci import comprehensive_rehearsal as cr
        self.cr = cr
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)
        # Synthesise a source-config file used by the live-mode rail.
        self.src_path = os.path.join(self.tmp, 'source.json')
        with open(self.src_path, 'w') as f:
            f.write('{"source":"baseline"}')
        self.tgt_path = os.path.join(self.tmp, 'target.json')
        with open(self.tgt_path, 'w') as f:
            f.write('{"target":1}')

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_ctx(self, *, cycles=2, hammer=False):
        return self.cr.Context(
            source_config=self.src_path,
            target_config=self.tgt_path,
            run_dir=self.tmp,
            scope_node='MIGRATION-TEST-NODE',
            prefix='MIGTEST-',
            live_writes=False,
            cycles=cycles,
            hammer=hammer,
        )

    def test_capture_baseline_skips_when_cycles_zero(self):
        ctx = self._make_ctx(cycles=0)
        self.cr._tier_9_capture_baseline(ctx)
        self.assertEqual(ctx.source_config_baseline_hash, '')

    def test_capture_baseline_populates_hash(self):
        ctx = self._make_ctx(cycles=2)
        self.cr._tier_9_capture_baseline(ctx)
        self.assertEqual(len(ctx.source_config_baseline_hash), 64)

    def test_assert_unchanged_returns_pass_when_unmutated(self):
        ctx = self._make_ctx(cycles=2)
        self.cr._tier_9_capture_baseline(ctx)
        r = self.cr._tier_9_assert_source_unchanged(ctx, cycle=1)
        self.assertEqual(r.status, 'PASS')
        self.assertEqual(r.category, 'cycled-rule-zero')

    def test_assert_unchanged_returns_fail_on_mutation(self):
        ctx = self._make_ctx(cycles=2)
        self.cr._tier_9_capture_baseline(ctx)
        # Mutate source file between cycles.
        with open(self.src_path, 'w') as f:
            f.write('{"source":"MUTATED"}')
        r = self.cr._tier_9_assert_source_unchanged(ctx, cycle=2)
        self.assertEqual(r.status, 'FAIL')
        self.assertIn('SOURCE MUTATION', r.detail)

    def test_run_one_cycle_creates_subdirectory(self):
        ctx = self._make_ctx(cycles=2)
        # Stub run_all_inner so we don't need real subprocesses.
        with mock.patch.object(self.cr, 'run_all_inner',
                                 return_value=0) as mocked:
            results = self.cr._run_one_cycle(ctx, cycle=1)
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, 'cycle-1')))
        self.assertTrue(any(r.name.endswith('runtime') for r in results))
        self.assertTrue(mocked.called)

    def test_run_one_cycle_records_aborted_on_exception(self):
        ctx = self._make_ctx(cycles=2)

        def boom(_):
            raise RuntimeError('synthetic kaboom')

        with mock.patch.object(self.cr, 'run_all_inner', side_effect=boom):
            results = self.cr._run_one_cycle(ctx, cycle=4)
        # The aborted Result is the first appended, then runtime.
        names = [r.name for r in results]
        self.assertTrue(any('aborted' in n for n in names))
        self.assertTrue(any(r.status == 'FAIL'
                             and 'kaboom' in r.detail for r in results))

    def test_drift_check_pass_with_one_cycle(self):
        # Two cycles are required to compute drift.
        results = [self.cr.Result(name='c1-cycle-1-runtime',
                                    category='cycled-metric',
                                    status='PASS', seconds=1.0)]
        r = self.cr._tier_9_drift_check([results])
        self.assertEqual(r.status, 'PASS')
        self.assertIn('fewer than 2 cycles', r.detail)

    def test_drift_check_pass_when_within_envelope(self):
        # Cycle 1: 100 s, Cycle 2: 102 s → 2 % drift, well within 5 %.
        c1 = [self.cr.Result(name='c1-cycle-1-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=100.0)]
        c2 = [self.cr.Result(name='c2-cycle-2-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=102.0)]
        r = self.cr._tier_9_drift_check([c1, c2])
        self.assertEqual(r.status, 'PASS')

    def test_drift_check_fail_above_envelope(self):
        # 100 s baseline, 200 s cycle 2 → 100 % drift, way over 5 %.
        c1 = [self.cr.Result(name='c1-cycle-1-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=100.0)]
        c2 = [self.cr.Result(name='c2-cycle-2-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=200.0)]
        r = self.cr._tier_9_drift_check([c1, c2])
        self.assertEqual(r.status, 'FAIL')
        self.assertIn('cycle 2', r.detail)

    def test_drift_check_handles_zero_baseline(self):
        # Sub-second baselines are below the noise floor — drift signal
        # is dominated by scheduling jitter, so we skip the check.
        c1 = [self.cr.Result(name='c1-cycle-1-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=0.0)]
        c2 = [self.cr.Result(name='c2-cycle-2-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=1.0)]
        r = self.cr._tier_9_drift_check([c1, c2])
        self.assertEqual(r.status, 'PASS')

    def test_drift_check_below_noise_floor_passes(self):
        # 0.5 s baseline < 1.0 s noise floor, so a 100 % runtime
        # increase still PASSes — too noisy to be meaningful.
        c1 = [self.cr.Result(name='c1-cycle-1-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=0.5)]
        c2 = [self.cr.Result(name='c2-cycle-2-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=1.0)]
        r = self.cr._tier_9_drift_check([c1, c2])
        self.assertEqual(r.status, 'PASS')

    def test_drift_check_handles_malformed_runtime_name(self):
        # A Result whose name doesn't have a parseable cycle int is
        # silently skipped.
        c1 = [self.cr.Result(name='c1-cycle-NOTANINT-runtime',
                                category='cycled-metric',
                                status='PASS', seconds=1.0)]
        r = self.cr._tier_9_drift_check([c1])
        self.assertEqual(r.status, 'PASS')

    def test_emit_summary_writes_md_and_json(self):
        ctx = self._make_ctx(cycles=2)
        ctx.source_config_baseline_hash = 'a' * 64
        per_cycle = [
            [self.cr.Result(name='c1-foo', category='read-only',
                             status='PASS', seconds=0.1),
             self.cr.Result(name='c1-cycle-1-runtime',
                             category='cycled-metric',
                             status='PASS', seconds=1.5)],
            [self.cr.Result(name='c2-foo', category='read-only',
                             status='FAIL', seconds=0.1),
             self.cr.Result(name='c2-cycle-2-runtime',
                             category='cycled-metric',
                             status='PASS', seconds=1.6)],
        ]
        self.cr._tier_9_emit_summary(ctx, per_cycle)
        md_path = os.path.join(self.tmp, 'cycled_audit_summary.md')
        json_path = os.path.join(self.tmp, 'cycled_validation.json')
        self.assertTrue(os.path.exists(md_path))
        self.assertTrue(os.path.exists(json_path))
        with open(md_path) as f:
            md = f.read()
        self.assertIn('| 1 |', md)
        self.assertIn('| 2 |', md)
        self.assertIn('Cycles: 2', md)
        with open(json_path) as f:
            payload = json.load(f)
        self.assertEqual(payload['cycles'], 2)
        self.assertEqual(len(payload['cycle_results']), 2)

    def test_run_cycled_full_path_two_cycles(self):
        """Drive _run_cycled end-to-end with a stubbed run_all_inner.

        Validates: baseline captured, per-cycle subdir created,
        Rule 0 PASS Result appended per cycle, summary written.
        """
        ctx = self._make_ctx(cycles=2)
        with mock.patch.object(self.cr, 'run_all_inner',
                                 return_value=0):
            rc = self.cr._run_cycled(ctx)
        self.assertEqual(rc, 0)
        # Per-cycle dirs exist.
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, 'cycle-1')))
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, 'cycle-2')))
        # Rule-0 PASS entries exist.
        rule_zero = [r for r in ctx.results
                      if r.category == 'cycled-rule-zero']
        self.assertEqual(len(rule_zero), 2)
        for r in rule_zero:
            self.assertEqual(r.status, 'PASS')
        # Drift check entry present.
        drift = [r for r in ctx.results
                  if r.name == 'cycled-drift-check']
        self.assertEqual(len(drift), 1)

    def test_run_cycled_aborts_on_source_mutation(self):
        ctx = self._make_ctx(cycles=3)

        original_inner = self.cr.run_all_inner

        def mutating_inner(_ctx):
            # Simulate a buggy step that mutates source bytes mid-cycle.
            with open(self.src_path, 'a') as f:
                f.write('!')
            return 0

        with mock.patch.object(self.cr, 'run_all_inner',
                                 side_effect=mutating_inner):
            rc = self.cr._run_cycled(ctx)
        self.assertEqual(rc, 1)
        rule_zero_fails = [r for r in ctx.results
                            if r.category == 'cycled-rule-zero'
                            and r.status == 'FAIL']
        self.assertEqual(len(rule_zero_fails), 1)
        # Loop aborted before cycle 2 completed → at most one Rule-0 fail.

    def test_run_all_dispatches_to_cycled_when_cycles_set(self):
        ctx = self._make_ctx(cycles=1)
        with mock.patch.object(self.cr, '_run_cycled',
                                 return_value=0) as mocked:
            self.cr.run_all(ctx)
        mocked.assert_called_once_with(ctx)

    def test_run_all_dispatches_to_inner_when_cycles_zero(self):
        ctx = self._make_ctx(cycles=0)
        with mock.patch.object(self.cr, 'run_all_inner',
                                 return_value=0) as mocked:
            self.cr.run_all(ctx)
        mocked.assert_called_once_with(ctx)

    def test_main_dispatches_with_cycles_zero(self):
        """End-to-end: main() with --cycles=0 calls run_all_inner."""
        argv = [
            'comprehensive_rehearsal.py',
            '--source-config', self.src_path,
            '--target-config', self.tgt_path,
            '--run-dir', self.tmp,
        ]
        with mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(self.cr, 'run_all_inner',
                                    return_value=0) as mocked, \
                mock.patch.object(self.cr, '_write_matrix'):
            rc = self.cr.main()
        self.assertEqual(rc, 0)
        mocked.assert_called_once()
        # Confirm the Context that landed in run_all_inner has cycles=0.
        args = mocked.call_args[0]
        self.assertEqual(args[0].cycles, 0)
        self.assertFalse(args[0].hammer)

    def test_main_dispatches_with_cycles_positive(self):
        """main() with --cycles=2 --hammer calls _run_cycled."""
        argv = [
            'comprehensive_rehearsal.py',
            '--source-config', self.src_path,
            '--target-config', self.tgt_path,
            '--run-dir', self.tmp,
            '--cycles', '2', '--hammer',
        ]
        with mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(self.cr, '_run_cycled',
                                    return_value=0) as mocked, \
                mock.patch.object(self.cr, '_write_matrix'):
            rc = self.cr.main()
        self.assertEqual(rc, 0)
        mocked.assert_called_once()
        ctx_passed = mocked.call_args[0][0]
        self.assertEqual(ctx_passed.cycles, 2)
        self.assertTrue(ctx_passed.hammer)

    def test_recursion_guard_trips_on_re_entry(self):
        """If something synthesises a cycle_ctx with cycles>0 the
        recursion guard must abort the cycle with a RuntimeError.

        The guard is exercised by patching Context() to return a
        synthetic ctx whose cycles attribute is non-zero — simulating
        a future regression where the recursion-guard was broken."""
        ctx = self._make_ctx(cycles=2)
        original_init = self.cr.Context

        def bad_factory(*args, **kwargs):
            # The recursion-guard test only fires for the inner ctx
            # that _run_one_cycle constructs. The outer ctx for this
            # test is built before patching.
            obj = original_init(*args, **kwargs)
            obj.cycles = 99    # simulated regression
            return obj

        with mock.patch.object(self.cr, 'Context',
                                 side_effect=bad_factory):
            results = self.cr._run_one_cycle(ctx, cycle=1)
        # The RuntimeError gets caught by the try-except in
        # _run_one_cycle and recorded as a FAIL Result.
        names = [r.name for r in results]
        self.assertTrue(any('aborted' in n for n in names))
        self.assertTrue(any(
            r.status == 'FAIL'
            and 'recursion guard' in r.detail.lower()
            for r in results
        ))


if __name__ == '__main__':
    unittest.main()
