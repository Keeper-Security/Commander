"""Tests for the burst-bound token bucket + clustered-hit exponential
growth added to AdaptiveThrottle.

Diagnosis (2026-04-22): per-call average pacing doesn't stop the
plugin's Python loops from firing N sequential `_call`s per role
(enforcements, managed-node privileges) in tight sequence. Token
bucket gates those bursts; clustered-hit detection converges the
adaptive delay fast when the tenant is actively throttling.
"""

import unittest

from keepercommander.commands.keeper_tenant_migrate.throttle import (
    AdaptiveThrottle,
    TokenBucket,
)


class _FakeClock:
    def __init__(self, start: float = 0.0):
        self.t = float(start)

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += max(0.0, float(seconds))


class TokenBucketTests(unittest.TestCase):

    def setUp(self):
        self.clock = _FakeClock()

    def _bucket(self, **kw):
        defaults = dict(capacity=3, refill_per_sec=0.5,
                        min_refill_per_sec=0.1, label='test')
        defaults.update(kw)
        return TokenBucket(**defaults)

    # ─── Acquire ───────────────────────────────────────────────────

    def test_capacity_allows_burst(self):
        b = self._bucket(capacity=3, refill_per_sec=0.5)
        for _ in range(3):
            w = b.acquire(sleeper=self.clock.sleep, now_fn=self.clock.now)
            self.assertEqual(w, 0.0, 'first 3 calls should not wait')

    def test_fourth_call_waits_for_refill(self):
        b = self._bucket(capacity=3, refill_per_sec=0.5)
        for _ in range(3):
            b.acquire(sleeper=self.clock.sleep, now_fn=self.clock.now)
        # 4th call: bucket empty, refill 0.5 tok/s → need to wait 2s
        w = b.acquire(sleeper=self.clock.sleep, now_fn=self.clock.now)
        self.assertAlmostEqual(w, 2.0, places=3)

    def test_sustained_rate_matches_refill(self):
        b = self._bucket(capacity=3, refill_per_sec=1.0)
        # Burn capacity
        for _ in range(3):
            b.acquire(sleeper=self.clock.sleep, now_fn=self.clock.now)
        # Steady state: each subsequent call waits 1s
        for _ in range(5):
            w = b.acquire(sleeper=self.clock.sleep, now_fn=self.clock.now)
            self.assertAlmostEqual(w, 1.0, places=3)

    def test_gap_restores_budget(self):
        b = self._bucket(capacity=3, refill_per_sec=1.0)
        for _ in range(3):
            b.acquire(sleeper=self.clock.sleep, now_fn=self.clock.now)
        # Wait 10 real seconds without acquiring
        self.clock.t += 10.0
        # Next 3 calls should all fit in the refilled capacity
        for _ in range(3):
            w = b.acquire(sleeper=self.clock.sleep, now_fn=self.clock.now)
            self.assertEqual(w, 0.0, 'budget should refill during gap')

    # ─── on_hit ────────────────────────────────────────────────────

    def test_clustered_hit_halves_refill(self):
        b = self._bucket(refill_per_sec=1.0, min_refill_per_sec=0.1)
        b.on_hit(clustered=True)
        self.assertEqual(b.refill_per_sec, 0.5)
        b.on_hit(clustered=True)
        self.assertEqual(b.refill_per_sec, 0.25)

    def test_isolated_hit_cuts_refill_10_percent(self):
        b = self._bucket(refill_per_sec=1.0, min_refill_per_sec=0.1)
        b.on_hit(clustered=False)
        self.assertAlmostEqual(b.refill_per_sec, 0.9, places=4)

    def test_refill_never_below_min(self):
        b = self._bucket(refill_per_sec=1.0, min_refill_per_sec=0.2)
        for _ in range(20):
            b.on_hit(clustered=True)
        self.assertGreaterEqual(b.refill_per_sec, 0.2)

    # ─── on_clean_window ───────────────────────────────────────────

    def test_clean_window_restores_gradually(self):
        b = self._bucket(refill_per_sec=1.0, min_refill_per_sec=0.1)
        b.on_hit(clustered=True)
        self.assertEqual(b.refill_per_sec, 0.5)
        b.on_clean_window()
        self.assertAlmostEqual(b.refill_per_sec, 0.55, places=4)
        b.on_clean_window()
        self.assertAlmostEqual(b.refill_per_sec, 0.605, places=4)

    def test_clean_window_never_exceeds_initial(self):
        b = self._bucket(refill_per_sec=1.0, min_refill_per_sec=0.1)
        # Already at initial; clean window is no-op
        for _ in range(10):
            b.on_clean_window()
        self.assertEqual(b.refill_per_sec, 1.0)

    # ─── Config validation ─────────────────────────────────────────

    def test_rejects_zero_capacity(self):
        with self.assertRaises(ValueError):
            TokenBucket(capacity=0, refill_per_sec=1.0, min_refill_per_sec=0.1)

    def test_rejects_nonpositive_refill(self):
        with self.assertRaises(ValueError):
            TokenBucket(capacity=3, refill_per_sec=0.0, min_refill_per_sec=0.1)

    def test_rejects_min_above_refill(self):
        with self.assertRaises(ValueError):
            TokenBucket(capacity=3, refill_per_sec=0.5, min_refill_per_sec=1.0)


class ClusteredHitTests(unittest.TestCase):
    """AdaptiveThrottle: clustered hits should switch from linear
    +step growth to exponential (double current). This makes the
    feedback loop converge in O(log N) instead of O(N) during
    burst-limit scenarios.
    """

    def setUp(self):
        AdaptiveThrottle.reset_registry()

    def tearDown(self):
        AdaptiveThrottle.reset_registry()

    def _throttle(self, **kw):
        defaults = dict(base_delay=2.0, max_delay=60.0, step=1.0,
                        jitter=0.0, success_reset=20, cluster_window=30.0,
                        bucket_capacity=3, bucket_refill_per_sec=0.5,
                        bucket_min_refill_per_sec=0.1)
        defaults.update(kw)
        return AdaptiveThrottle(**defaults)

    def test_isolated_hits_grow_linearly(self):
        t = self._throttle()
        # Two hits 100s apart (outside cluster_window) → +1s each
        t.begin_call(); t.end_call(hit=True, now=0.0)
        self.assertEqual(t.current_delay, 3.0)
        t.begin_call(); t.end_call(hit=True, now=100.0)
        self.assertEqual(t.current_delay, 4.0)
        self.assertEqual(t.clustered_events, 0)

    def test_clustered_hits_grow_exponentially(self):
        t = self._throttle()
        # First hit: +step (no prior hit to cluster against)
        t.begin_call(); t.end_call(hit=True, now=0.0)
        self.assertEqual(t.current_delay, 3.0)
        # 10s later (within cluster_window): double
        t.begin_call(); t.end_call(hit=True, now=10.0)
        self.assertEqual(t.current_delay, 6.0)
        # 5s later (still clustered): double again
        t.begin_call(); t.end_call(hit=True, now=15.0)
        self.assertEqual(t.current_delay, 12.0)
        self.assertEqual(t.clustered_events, 2)

    def test_cluster_window_boundary(self):
        t = self._throttle(cluster_window=30.0)
        t.begin_call(); t.end_call(hit=True, now=0.0)       # base: 3.0
        # Exactly at window boundary: still clustered
        t.begin_call(); t.end_call(hit=True, now=30.0)      # doubles → 6.0
        self.assertEqual(t.current_delay, 6.0)
        # Well beyond: linear
        t.begin_call(); t.end_call(hit=True, now=100.0)     # +step → 7.0
        self.assertEqual(t.current_delay, 7.0)

    def test_clustered_growth_caps_at_max(self):
        t = self._throttle(max_delay=10.0)
        for i in range(10):
            t.begin_call(); t.end_call(hit=True, now=i * 1.0)
        self.assertEqual(t.current_delay, 10.0)

    def test_clean_call_breaks_cluster_chain(self):
        t = self._throttle()
        t.begin_call(); t.end_call(hit=True, now=0.0)  # 3.0
        # A clean call doesn't clear _last_hit_time, but a hit 100s
        # later is still beyond the window so it's isolated.
        for i in range(20):
            t.begin_call(); t.end_call(hit=False, now=1.0 + i * 0.1)
        # 100s later, fresh hit: isolated
        t.begin_call(); t.end_call(hit=True, now=120.0)
        # Should be +step from whatever decay left us at (or base)
        self.assertLess(t.current_delay, 6.0)

    def test_clustered_hit_also_slows_bucket(self):
        t = self._throttle(bucket_refill_per_sec=1.0,
                            bucket_min_refill_per_sec=0.1)
        initial = t.bucket.refill_per_sec
        t.begin_call(); t.end_call(hit=True, now=0.0)
        t.begin_call(); t.end_call(hit=True, now=5.0)   # clustered
        # Isolated hit: 10% cut. Clustered hit: halved.
        # So bucket refill went 1.0 → 0.9 → 0.45
        self.assertAlmostEqual(t.bucket.refill_per_sec, 0.45, places=3)


class DecayCooldownTests(unittest.TestCase):
    """Decay must NOT fire within decay_cooldown seconds of the last
    throttle hit. Prevents the 2026-04-22 oscillation:
        throttle → +step → 20 clean → decay → throttle → +step → …
    forever with no net progress.
    """

    def setUp(self):
        AdaptiveThrottle.reset_registry()

    def tearDown(self):
        AdaptiveThrottle.reset_registry()

    def _throttle(self, **kw):
        defaults = dict(base_delay=2.0, max_delay=30.0, step=1.0,
                        jitter=0.0, success_reset=3,
                        cluster_window=30.0, decay_cooldown=60.0,
                        bucket_capacity=3, bucket_refill_per_sec=0.5,
                        bucket_min_refill_per_sec=0.1,
                        bucket_decay_every_n_windows=1)
        defaults.update(kw)
        return AdaptiveThrottle(**defaults)

    def test_cooldown_blocks_early_decay(self):
        t = self._throttle(decay_cooldown=60.0, success_reset=3)
        t.begin_call(); t.end_call(hit=True, now=0.0)   # 3.0
        # 3 clean calls at t=1,2,3 — within 60s cooldown
        for i in range(3):
            t.begin_call(); t.end_call(hit=False, now=1.0 + i)
        # Decay suppressed
        self.assertEqual(t.current_delay, 3.0)

    def test_cooldown_allows_decay_after_window(self):
        t = self._throttle(decay_cooldown=60.0, success_reset=3)
        t.begin_call(); t.end_call(hit=True, now=0.0)   # 3.0
        # 3 clean calls >60s later
        for i in range(3):
            t.begin_call(); t.end_call(hit=False, now=100.0 + i)
        self.assertEqual(t.current_delay, 2.0)   # decayed one step

    def test_oscillation_does_not_form(self):
        # The 2026-04-22 scenario: throttle, 20 clean, decay, throttle,
        # 20 clean, decay, … The cooldown should keep delay growing
        # monotonically when hits keep coming within the cooldown.
        t = self._throttle(decay_cooldown=60.0, success_reset=3,
                            cluster_window=1.0)
        # Simulate: hit every 70 seconds (outside cluster but inside
        # decay cooldown of 60s-ish if we interleave cleanly). Actually
        # across 70s we have cooldown_ok=True by then, so the test
        # demonstrates progressive linear growth.
        t_now = 0.0
        for _ in range(4):
            t.begin_call(); t.end_call(hit=True, now=t_now)
            # 3 clean calls RIGHT after — cooldown should block decay
            for _ in range(3):
                t_now += 1.0
                t.begin_call(); t.end_call(hit=False, now=t_now)
            t_now += 65.0
        # Expect delay grew 4 times (4 hits, cooldown blocked decay)
        # 2.0 + 4*1 = 6.0
        self.assertEqual(t.current_delay, 6.0)

    def test_bucket_decays_every_n_windows(self):
        # Bucket should NOT relax on every success window — only every
        # Nth window. Keeps burst cap sticky.
        t = self._throttle(
            success_reset=2, decay_cooldown=0.0,
            bucket_refill_per_sec=1.0,
            bucket_min_refill_per_sec=0.1,
            bucket_decay_every_n_windows=3,
        )
        t.begin_call(); t.end_call(hit=True, now=0.0)
        bucket_after_hit = t.bucket.refill_per_sec   # 0.9 (isolated)

        # Window 1 (2 clean calls) — bucket unchanged
        for i in range(2):
            t.begin_call(); t.end_call(hit=False, now=1.0 + i)
        self.assertEqual(t.bucket.refill_per_sec, bucket_after_hit)

        # Window 2 (2 more) — still unchanged
        for i in range(2):
            t.begin_call(); t.end_call(hit=False, now=3.0 + i)
        self.assertEqual(t.bucket.refill_per_sec, bucket_after_hit)

        # Window 3 — NOW bucket ticks up
        for i in range(2):
            t.begin_call(); t.end_call(hit=False, now=5.0 + i)
        self.assertGreater(t.bucket.refill_per_sec, bucket_after_hit)


class AdaptiveThrottleAcquireTests(unittest.TestCase):
    """AdaptiveThrottle.acquire() delegates to the bucket."""

    def setUp(self):
        AdaptiveThrottle.reset_registry()

    def tearDown(self):
        AdaptiveThrottle.reset_registry()

    def test_acquire_uses_bucket(self):
        clock = _FakeClock()
        t = AdaptiveThrottle(
            base_delay=2.0, max_delay=30.0,
            bucket_capacity=2, bucket_refill_per_sec=1.0,
            bucket_min_refill_per_sec=0.1, jitter=0.0,
        )
        # First 2 fit in capacity
        self.assertEqual(t.acquire(sleeper=clock.sleep, now_fn=clock.now), 0.0)
        self.assertEqual(t.acquire(sleeper=clock.sleep, now_fn=clock.now), 0.0)
        # 3rd waits 1s for refill
        self.assertAlmostEqual(
            t.acquire(sleeper=clock.sleep, now_fn=clock.now),
            1.0, places=3,
        )

    def test_acquire_disabled_is_noop(self):
        t = AdaptiveThrottle(enabled=False, base_delay=2.0,
                              bucket_capacity=1,
                              bucket_refill_per_sec=0.01,
                              bucket_min_refill_per_sec=0.005)
        clock = _FakeClock()
        # Exhaust capacity, then prove disabled = no wait
        t.bucket.tokens = 0
        self.assertEqual(t.acquire(sleeper=clock.sleep, now_fn=clock.now), 0.0)

    def test_acquire_accumulates_total_sleep(self):
        clock = _FakeClock()
        t = AdaptiveThrottle(
            bucket_capacity=1, bucket_refill_per_sec=0.5,
            bucket_min_refill_per_sec=0.1, jitter=0.0,
        )
        t.acquire(sleeper=clock.sleep, now_fn=clock.now)  # capacity=1 free
        t.acquire(sleeper=clock.sleep, now_fn=clock.now)  # waits 2s
        self.assertGreater(t.total_sleep, 0)


if __name__ == '__main__':
    unittest.main()
