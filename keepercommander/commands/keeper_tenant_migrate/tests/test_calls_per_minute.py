"""Tests for --calls-per-minute behavior in the estimate + run config.

The flag is the operator-facing knob: "limit this run to N API calls per
minute". Internally it maps to adaptive throttle base_delay and feeds
the estimator so the banner ETA is honest.
"""

import unittest

from keepercommander.commands.keeper_tenant_migrate.estimate import (
    AVG_CALL_LATENCY_SEC,
    estimate_from_counts,
)


class CallsPerMinuteEstimateTests(unittest.TestCase):

    def _counts(self, **kw):
        base = {'nodes': 10, 'teams': 10, 'roles': 10, 'users': 500,
                'shared_folders': 5, 'records': 500, 'attachments': 10,
                'direct_shares': 0, 'total_enforcements': 50,
                'total_privileges': 20, 'vault_folders': 50}
        base.update(kw)
        return base

    def test_cpm_overrides_tier_delay(self):
        est_default = estimate_from_counts(self._counts())
        est_cpm = estimate_from_counts(self._counts(), calls_per_minute=30)
        # 30 cpm → 2.0s/call → 2.0 - 0.3 latency = 1.7s delay
        self.assertAlmostEqual(est_cpm.delay, 2.0 - AVG_CALL_LATENCY_SEC,
                                places=3)
        # Different from whatever the tier gave us
        self.assertNotEqual(est_cpm.delay, est_default.delay)

    def test_cpm_60_gives_1_second_delay(self):
        est = estimate_from_counts(self._counts(), calls_per_minute=60)
        # 60 cpm → 1.0s/call → 0.7s delay
        self.assertAlmostEqual(est.delay, 1.0 - AVG_CALL_LATENCY_SEC,
                                places=3)

    def test_cpm_very_high_floors_at_zero(self):
        # 200 cpm → 0.3s/call, minus 0.3 latency → 0.0 delay
        est = estimate_from_counts(self._counts(), calls_per_minute=200)
        self.assertEqual(est.delay, 0.0)

    def test_cpm_disables_throttle_penalty(self):
        # Compare at the same call-density: include_throttle=True with
        # no cpm should estimate longer than with cpm (because cpm
        # replaces the penalty, it doesn't stack).
        without_cpm = estimate_from_counts(
            self._counts(records=2000, users=2000))
        with_cpm = estimate_from_counts(
            self._counts(records=2000, users=2000),
            calls_per_minute=60)
        # With cpm, no separate throttle penalty layered on top
        self.assertLess(with_cpm.total_seconds, without_cpm.total_seconds)

    def test_cpm_zero_is_passthrough(self):
        a = estimate_from_counts(self._counts())
        b = estimate_from_counts(self._counts(), calls_per_minute=0)
        self.assertEqual(a.delay, b.delay)
        self.assertEqual(a.tier_label, b.tier_label)

    def test_cpm_label_annotation(self):
        est = estimate_from_counts(self._counts(), calls_per_minute=30)
        self.assertIn('cpm=30', est.tier_label)

    def test_cpm_runtime_reflects_rate(self):
        counts = self._counts()
        # At 60 cpm, runtime should roughly equal total_calls / cpm minutes
        est = estimate_from_counts(counts, calls_per_minute=60)
        # Rough upper bound: calls/cpm * 60 seconds, plus attachment overhead
        expected_max = (est.total_calls / 60) * 60 + 200
        self.assertLess(est.total_seconds, expected_max * 1.5)


class RunConfigCpmTests(unittest.TestCase):

    def test_runconfig_accepts_calls_per_minute(self):
        from keepercommander.commands.keeper_tenant_migrate.auto_migrate import RunConfig
        cfg = RunConfig(run_dir='/tmp/x', calls_per_minute=30)
        self.assertEqual(cfg.calls_per_minute, 30)

    def test_runconfig_default_is_zero(self):
        from keepercommander.commands.keeper_tenant_migrate.auto_migrate import RunConfig
        cfg = RunConfig(run_dir='/tmp/x')
        self.assertEqual(cfg.calls_per_minute, 0.0)


if __name__ == '__main__':
    unittest.main()
