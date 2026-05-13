"""Unit tests for the adaptive-throttle module.

Covers:
  - Delay growth on log-record events + transient exceptions
  - Decay after SUCCESS_RESET clean calls
  - Cap at max_delay (no unbounded growth)
  - Floor at base_delay (no shrinking below)
  - Per-tenant registry isolation
  - Integration with ThrottleLogCapture installing/removing handler
  - Throttle exception detector

No network, no Commander SDK. A trivial fake `params` object carries the
identity tuple used by the registry.
"""

import logging
import unittest

from keepercommander.commands.keeper_tenant_migrate.throttle import (
    AdaptiveThrottle,
    ThrottleLogCapture,
    is_throttle_exception,
)


def _make_params(server='src.keepersecurity.eu', user='admin@src'):
    class _P:
        pass
    p = _P()
    p.server = server
    p.user = user
    return p


class AdaptiveThrottleTests(unittest.TestCase):

    def setUp(self):
        AdaptiveThrottle.reset_registry()

    def tearDown(self):
        AdaptiveThrottle.reset_registry()

    # ─── Growth on hits ────────────────────────────────────────────

    def test_grows_on_transient_hit(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=20,
                              cluster_window=30.0)
        self.assertEqual(t.current_delay, 2.0)
        # Space hits beyond the cluster window so growth is linear.
        # Clustered hits double (see test_throttle_burst.py).
        t.begin_call()
        t.end_call(hit=True, now=0.0)
        self.assertEqual(t.current_delay, 3.0)
        t.begin_call()
        t.end_call(hit=True, now=100.0)
        self.assertEqual(t.current_delay, 4.0)
        self.assertEqual(t.throttle_events, 2)

    def test_grows_on_log_event(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=20)
        t.begin_call()
        t.record_log_event('Throttled (attempt 1/3), retrying in 60s')
        t.end_call(hit=False)
        self.assertEqual(t.current_delay, 3.0)
        self.assertEqual(t.throttle_events, 1)

    def test_caps_at_max(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=5.0, step=1.0,
                              jitter=0.0, success_reset=20)
        for _ in range(20):
            t.begin_call()
            t.end_call(hit=True)
        self.assertEqual(t.current_delay, 5.0)

    # ─── Decay on clean runs ───────────────────────────────────────

    def test_decays_after_success_reset(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=3,
                              cluster_window=30.0,
                              decay_cooldown=0.0)
        # Push delay up to 5s via 3 isolated (non-clustered) hits.
        for i in range(3):
            t.begin_call()
            t.end_call(hit=True, now=i * 100.0)
        self.assertEqual(t.current_delay, 5.0)

        # Clock source must match the hit phase — monotonic() on a
        # fresh runner can be < the test fake _last_hit_time=200.0,
        # failing the cooldown gate even with decay_cooldown=0.
        for i in range(3):
            t.begin_call()
            t.end_call(hit=False, now=300.0 + i)
        self.assertEqual(t.current_delay, 4.0)

        for i in range(3):
            t.begin_call()
            t.end_call(hit=False, now=400.0 + i)
        self.assertEqual(t.current_delay, 3.0)

    def test_decay_floors_at_base(self):
        # decay_cooldown=0 so the test exercises the floor-at-base
        # invariant without having to inject clock time. Production
        # uses decay_cooldown to prevent oscillation — see
        # test_throttle_burst.py::test_decay_respects_cooldown.
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=2,
                              decay_cooldown=0.0)
        t.begin_call()
        t.end_call(hit=True)   # 3.0
        for _ in range(10):
            t.begin_call()
            t.end_call(hit=False)
        self.assertEqual(t.current_delay, 2.0)

    def test_success_counter_resets_on_hit(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=5)
        # 4 clean — not enough to decay
        for _ in range(4):
            t.begin_call()
            t.end_call(hit=False)
        self.assertEqual(t.consecutive_ok, 4)
        # 1 hit → counter resets, delay grows
        t.begin_call()
        t.end_call(hit=True)
        self.assertEqual(t.consecutive_ok, 0)
        self.assertEqual(t.current_delay, 3.0)

    # ─── sleep() ───────────────────────────────────────────────────

    def test_sleep_uses_current_delay(self):
        t = AdaptiveThrottle(base_delay=1.5, max_delay=10.0, jitter=0.0)
        waits = []
        t.sleep(sleeper=waits.append)
        self.assertEqual(waits, [1.5])

    def test_sleep_jitter_within_range(self):
        t = AdaptiveThrottle(base_delay=1.0, max_delay=10.0, jitter=0.3)
        waits = []
        for _ in range(20):
            t.sleep(sleeper=waits.append)
        # Every sample must be in [base, base+jitter]
        for w in waits:
            self.assertGreaterEqual(w, 1.0)
            self.assertLessEqual(w, 1.3 + 1e-9)

    def test_sleep_disabled_returns_zero(self):
        t = AdaptiveThrottle(base_delay=5.0, enabled=False)
        waits = []
        t.sleep(sleeper=waits.append)
        self.assertEqual(waits, [])

    def test_total_sleep_accumulates(self):
        t = AdaptiveThrottle(base_delay=0.5, jitter=0.0)
        dummy_sleeper = lambda _s: None
        for _ in range(4):
            t.sleep(sleeper=dummy_sleeper)
        self.assertAlmostEqual(t.total_sleep, 2.0, places=3)

    # ─── Per-tenant registry ───────────────────────────────────────

    def test_registry_keys_by_server_and_user(self):
        AdaptiveThrottle.configure_defaults(
            base_delay=2.0, max_delay=10.0, step=1.0, jitter=0.0,
            success_reset=20, enabled=True)
        src = _make_params(server='src.eu', user='a@x')
        tgt = _make_params(server='msp.eu', user='b@y')

        t_src = AdaptiveThrottle.for_params(src)
        t_tgt = AdaptiveThrottle.for_params(tgt)
        self.assertIsNot(t_src, t_tgt)

        t_src.begin_call()
        t_src.end_call(hit=True)
        # Target untouched
        self.assertEqual(t_tgt.current_delay, 2.0)
        self.assertEqual(t_src.current_delay, 3.0)

    def test_registry_returns_same_instance_for_same_key(self):
        p = _make_params()
        a = AdaptiveThrottle.for_params(p)
        b = AdaptiveThrottle.for_params(p)
        self.assertIs(a, b)

    def test_registry_snapshot_includes_tenant_labels(self):
        src = _make_params(server='src.eu', user='a@x')
        AdaptiveThrottle.for_params(src).begin_call()
        AdaptiveThrottle.for_params(src).end_call(hit=True)
        snap = AdaptiveThrottle.registry_snapshot()
        self.assertIn('a@x@src.eu', snap)
        self.assertEqual(snap['a@x@src.eu']['throttle_events'], 1)

    def test_reset_registry_clears_all(self):
        _ = AdaptiveThrottle.for_params(_make_params())
        self.assertTrue(AdaptiveThrottle._registry)
        AdaptiveThrottle.reset_registry()
        self.assertFalse(AdaptiveThrottle._registry)

    # ─── Config validation ─────────────────────────────────────────

    def test_rejects_negative_base(self):
        with self.assertRaises(ValueError):
            AdaptiveThrottle(base_delay=-1.0)

    def test_rejects_max_below_base(self):
        with self.assertRaises(ValueError):
            AdaptiveThrottle(base_delay=5.0, max_delay=1.0)

    def test_rejects_zero_success_reset(self):
        with self.assertRaises(ValueError):
            AdaptiveThrottle(success_reset=0)

    def test_configure_defaults_rejects_unknown(self):
        with self.assertRaises(KeyError):
            AdaptiveThrottle.configure_defaults(invalid_key=1)

    # ─── Logging capture ───────────────────────────────────────────

    def test_logging_capture_feeds_throttle(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=20)
        t.begin_call()
        with ThrottleLogCapture(t):
            logging.warning(
                'Throttled (attempt %d/%d), retrying in %d seconds',
                1, 3, 30,
            )
        t.end_call(hit=False)
        self.assertEqual(t.current_delay, 3.0)
        self.assertEqual(t.throttle_events, 1)

    def test_logging_capture_ignores_unrelated_warnings(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=20)
        t.begin_call()
        with ThrottleLogCapture(t):
            logging.warning('Some unrelated warning')
        t.end_call(hit=False)
        self.assertEqual(t.current_delay, 2.0)
        self.assertEqual(t.throttle_events, 0)

    def test_logging_capture_removes_handler(self):
        t = AdaptiveThrottle(base_delay=2.0)
        before = list(logging.getLogger().handlers)
        with ThrottleLogCapture(t):
            mid = list(logging.getLogger().handlers)
            self.assertGreater(len(mid), len(before))
        after = list(logging.getLogger().handlers)
        self.assertEqual(after, before)

    def test_multiple_log_events_in_one_call(self):
        t = AdaptiveThrottle(base_delay=2.0, max_delay=10.0, step=1.0,
                              jitter=0.0, success_reset=20)
        t.begin_call()
        with ThrottleLogCapture(t):
            logging.warning('Throttled (attempt 1/3), retrying in 30 seconds')
            logging.warning('Throttled (attempt 2/3), retrying in 60 seconds')
        t.end_call(hit=False)
        # One-call grows by ONE step regardless of how many events
        # fired within the call — growth is per-call, not per-event.
        self.assertEqual(t.current_delay, 3.0)
        # But event counter reflects every record
        self.assertEqual(t.throttle_events, 2)


class SilentFailureCaptureTests(unittest.TestCase):
    """Commander-side silent skip detection. When Commander emits a
    warning like `Add/Remove managed node privilege: invalid privilege:
    X` and then returns success anyway, the plugin needs to see the
    warning so the call result gets converted to False and the
    classifier can route it to SKIPPED/FAILED.
    """

    def test_captures_invalid_privilege(self):
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture()
        with cap:
            logging.warning('Add/Remove managed node privilege: '
                             'invalid privilege: privilege_access')
        self.assertIn('invalid privilege', cap.message)

    def test_captures_is_not_found_skipping(self):
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture()
        with cap:
            logging.warning('User finance@example.com is not found: Skipping')
        self.assertIn('is not found', cap.message)

    def test_captures_does_not_manage_node(self):
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture()
        with cap:
            logging.warning('Role "5" does not manage node "42"')
        self.assertIn('does not manage node', cap.message)

    def test_captures_bug13_schema_markers(self):
        """Bug 13 — admin/team mutual-exclusion rejections must be
        captured so the plugin's success return gets flipped to a real
        failure and the classifier names the actual constraint."""
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture()
        with cap:
            logging.warning('Teams cannot be assigned to roles with '
                             'administrative permissions.')
        self.assertIn('teams cannot be assigned', cap.message.lower())

    def test_ignores_unrelated_warnings(self):
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture()
        with cap:
            logging.warning('Some unrelated warning about the weather')
        self.assertEqual(cap.message, '')

    def test_only_first_message_kept(self):
        # Multiple matches during one call — we keep the first one
        # to avoid noisy diagnostics. Classifier needs only one sample.
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture()
        with cap:
            logging.warning('invalid privilege: one')
            logging.warning('invalid privilege: two')
        self.assertIn('one', cap.message)
        self.assertNotIn('two', cap.message)

    def test_handler_is_removed_after_context(self):
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        before = list(logging.getLogger().handlers)
        with SilentFailureCapture():
            pass
        after = list(logging.getLogger().handlers)
        self.assertEqual(after, before)


class EmbeddingContractTests(unittest.TestCase):
    """B1 — `ThrottleLogCapture` and `SilentFailureCapture` accept
    consumer-supplied marker strings so embedding contexts (Commander
    team adopting the throttle, downstream tooling) don't have to
    inherit the plugin's migration-flow vocabulary."""

    def test_throttle_log_capture_custom_marker(self):
        """Custom log_marker overrides the default detection phrase."""
        from keepercommander.commands.keeper_tenant_migrate.throttle import (
            AdaptiveThrottle, ThrottleLogCapture,
        )
        AdaptiveThrottle.reset_registry()
        t = AdaptiveThrottle(base_delay=2.0, jitter=0.0,
                             cluster_window=30.0)
        with ThrottleLogCapture(t, log_marker='RateLimited('):
            logging.warning('Throttled (attempt 1/5)')   # ignored — not the marker
            self.assertEqual(t._in_call_events, 0)
            logging.warning('RateLimited(call=42)')      # matches custom marker
            self.assertEqual(t._in_call_events, 1)

    def test_throttle_log_capture_default_unchanged(self):
        """Default behavior preserved when no log_marker passed."""
        from keepercommander.commands.keeper_tenant_migrate.throttle import (
            AdaptiveThrottle, ThrottleLogCapture, THROTTLE_LOG_MARKER,
        )
        self.assertEqual(THROTTLE_LOG_MARKER, 'Throttled (attempt')
        AdaptiveThrottle.reset_registry()
        t = AdaptiveThrottle(base_delay=2.0, jitter=0.0,
                             cluster_window=30.0)
        with ThrottleLogCapture(t):
            logging.warning('Throttled (attempt 1/5)')
            self.assertEqual(t._in_call_events, 1)

    def test_silent_failure_capture_custom_markers(self):
        """Custom markers tuple replaces the default migration vocabulary."""
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture(markers=(
            'svc-foo: permission denied',
            'svc-foo: entity not found',
        ))
        with cap:
            # Default plugin marker — should NOT match the custom set.
            logging.warning('User finance@example.com is not found: Skipping')
            # Custom marker — should match.
            logging.warning('svc-foo: permission denied for op=create')
        self.assertIn('svc-foo: permission denied', cap.message)
        # And the default-set phrase did NOT short-circuit the custom check.
        self.assertNotIn('finance@example.com', cap.message)

    def test_silent_failure_capture_default_markers_module_constant(self):
        """`SILENT_FAILURE_MARKERS` is a stable public-facing tuple
        consumers can inspect."""
        from keepercommander.commands.keeper_tenant_migrate.throttle import SILENT_FAILURE_MARKERS
        self.assertIsInstance(SILENT_FAILURE_MARKERS, tuple)
        # All entries are lowercase per the substring-match contract.
        for m in SILENT_FAILURE_MARKERS:
            self.assertEqual(m, m.lower())

    def test_silent_failure_capture_markers_lowercased_at_construction(self):
        """Custom markers passed in mixed-case are lowered once at
        ctor; per-record loop never re-cases."""
        from keepercommander.commands.keeper_tenant_migrate.throttle import SilentFailureCapture
        cap = SilentFailureCapture(markers=('PERMISSION DENIED',))
        with cap:
            logging.warning('the operation hit Permission Denied at parse time')
        self.assertIn('Permission Denied', cap.message)

    def test_backwards_compat_private_alias_present(self):
        """Old name `_SILENT_FAILURE_MARKERS` aliases the new one for
        any downstream that referenced it."""
        from keepercommander.commands.keeper_tenant_migrate.throttle import (
            SILENT_FAILURE_MARKERS, _SILENT_FAILURE_MARKERS,
        )
        self.assertIs(_SILENT_FAILURE_MARKERS, SILENT_FAILURE_MARKERS)


class ThrottleExceptionDetectorTests(unittest.TestCase):

    def test_result_code_throttled(self):
        class E(Exception):
            result_code = 'throttled'
        self.assertTrue(is_throttle_exception(E('boom')))

    def test_result_code_too_many_requests(self):
        class E(Exception):
            result_code = 'too_many_requests'
        self.assertTrue(is_throttle_exception(E('boom')))

    def test_message_throttled(self):
        self.assertTrue(is_throttle_exception(Exception('Throttled on op')))

    def test_message_429(self):
        self.assertTrue(is_throttle_exception(Exception('HTTP 429 bla')))

    def test_unrelated_not_throttle(self):
        self.assertFalse(is_throttle_exception(Exception('connection reset')))
        self.assertFalse(is_throttle_exception(Exception('invalid input')))
        self.assertFalse(is_throttle_exception(None))


if __name__ == '__main__':
    unittest.main()
