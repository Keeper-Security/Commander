"""Tests for the tenant-size estimate module."""

import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate import estimate


SMALL = {
    'nodes': 5, 'teams': 2, 'roles': 3, 'users': 10,
    'shared_folders': 4, 'records': 40, 'attachments': 0,
    'direct_shares': 0, 'total_enforcements': 12, 'total_privileges': 8,
}

MEDIUM = {
    'nodes': 42, 'teams': 18, 'roles': 25, 'users': 340,
    'shared_folders': 45, 'records': 1378, 'attachments': 22,
    'direct_shares': 67, 'total_enforcements': 137, 'total_privileges': 32,
}

LARGE = {
    'nodes': 150, 'teams': 60, 'roles': 80, 'users': 2500,
    'shared_folders': 200, 'records': 3500, 'attachments': 120,
    'direct_shares': 400, 'total_enforcements': 900, 'total_privileges': 160,
}

XLARGE = {
    'nodes': 500, 'teams': 200, 'roles': 300, 'users': 15000,
    'shared_folders': 800, 'records': 40000, 'attachments': 2000,
    'direct_shares': 5000, 'total_enforcements': 5000, 'total_privileges': 800,
}


class TestTier(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(estimate.tier_for(0), (0.0, 0, 'empty'))

    def test_small(self):
        delay, batch, label = estimate.tier_for(30)
        self.assertEqual((delay, batch), (0.5, 0))
        self.assertIn('small', label)

    def test_medium_at_boundary(self):
        self.assertEqual(estimate.tier_for(500)[:2], (1.0, 25))

    def test_large(self):
        self.assertEqual(estimate.tier_for(2000)[:2], (2.0, 50))

    def test_xlarge(self):
        self.assertEqual(estimate.tier_for(10_000)[:2], (3.0, 100))


class TestBudget(unittest.TestCase):
    def test_empty_inventory_produces_zero_calls(self):
        est = estimate.estimate_from_counts({})
        self.assertEqual(est.total_calls, 0)
        self.assertEqual(est.total_seconds, 0.0)

    def test_small_budget(self):
        est = estimate.estimate_from_counts(SMALL)
        # structure: 5 + 2*2 + 3*2 + 8 = 23
        # users:     10 * 2 = 20
        # imports:   5 (record-types estimate)
        # attach:    0
        # shares:    0
        self.assertEqual(est.total_calls, 23 + 20 + 5)

    def test_medium_budget_stages_are_named(self):
        est = estimate.estimate_from_counts(MEDIUM)
        names = [s.name for s in est.stages]
        self.assertEqual(names, [
            'structure', 'users', 'records-import',
            'records-attachments', 'records-shares',
        ])

    def test_medium_has_attachment_duration_premium(self):
        """Attachments should dominate runtime per record vs. plain calls.

        With throttle-awareness (v1.3+) the runtime now includes the
        expected-throttle penalty: 44 calls / 3 calls-per-throttle = ~14
        pauses × 60s = ~880s on top of the base 134s (101 call +
        33 attachment) → ~1014s total. Bounds widened accordingly.
        """
        est = estimate.estimate_from_counts(MEDIUM)
        stage_by_name = {s.name: s for s in est.stages}
        attach = stage_by_name['records-attachments']
        # 22 attachments * 2 calls = 44 calls
        self.assertEqual(attach.calls, 44)
        # MEDIUM has records=1378 → large tier (delay=2.0).
        # Throttle penalty applies (tier is medium+).
        # base = 44 * (0.3 + 2.0) = 101.2; extra = 22 * 1.5 = 33
        # throttle = (44/3) * 60 = 880
        # total ≈ 1014s
        self.assertGreater(attach.seconds_at_throttle, 900)
        self.assertLess(attach.seconds_at_throttle, 1100)

    def test_small_tier_does_not_include_throttle_penalty(self):
        """Small tier: Commander rarely throttles on cold sessions at
        low burst rate. No penalty so the estimate is realistic for
        a dev-rehearsal MIGTEST-sized run."""
        est = estimate.estimate_from_counts(SMALL)
        # Ensure tier is 'small' so throttle is off.
        self.assertIn('small', est.tier_label)
        # Sum of per-call latency should be close to total_seconds
        # (no 60s penalties). SMALL total ≈ sum of (calls × 0.3-0.8s).
        # We check an upper bound: with 0 throttles applied, total must
        # be well under 100s for the SMALL fixture.
        self.assertLess(est.total_seconds, 100)

    def test_medium_tier_does_include_throttle_penalty(self):
        """Medium+ tier should add throttle pauses — observed in
        rehearsal, built into the model."""
        est = estimate.estimate_from_counts(MEDIUM)
        # Sanity: at least some stages reflect the throttle penalty.
        # Compare total_seconds with a no-throttle synthesis.
        no_throttle_total = 0
        for s in est.stages:
            # Base + attach extra, NO throttle.
            calls = s.calls
            base = calls * (0.3 + est.delay)
            attach_calls = calls if s.name == 'records-attachments' else 0
            extra = (attach_calls / 2) * 1.5
            no_throttle_total += base + extra
        # Real total must be substantially larger (>= 1.5x) because
        # of the added throttle pauses.
        self.assertGreater(est.total_seconds, no_throttle_total * 1.5)

    def test_tier_driver_auto_picks_max(self):
        counts = dict(MEDIUM)  # users=340, records=1378 → records tier
        est = estimate.estimate_from_counts(counts, tier_driver='auto')
        self.assertEqual(est.delay, 2.0)  # records>500 → large tier

    def test_tier_driver_users_forces_users_axis(self):
        est = estimate.estimate_from_counts(MEDIUM, tier_driver='users')
        # users=340 → medium tier
        self.assertEqual(est.delay, 1.0)
        self.assertEqual(est.batch_size, 25)

    def test_tier_driver_records_forces_records_axis(self):
        est = estimate.estimate_from_counts(MEDIUM, tier_driver='records')
        # records=1378 → large tier
        self.assertEqual(est.delay, 2.0)
        self.assertEqual(est.batch_size, 50)

    def test_xlarge_stays_bounded(self):
        est = estimate.estimate_from_counts(XLARGE)
        # Should not explode — just confirm totals are computed
        self.assertGreater(est.total_calls, 30_000)
        self.assertEqual(est.delay, 3.0)
        self.assertEqual(est.batch_size, 100)


class TestFormatting(unittest.TestCase):
    def test_fmt_duration_seconds(self):
        self.assertEqual(estimate._fmt_duration(45), '45s')

    def test_fmt_duration_minutes(self):
        self.assertEqual(estimate._fmt_duration(125), '2m 5s')

    def test_fmt_duration_hours(self):
        self.assertEqual(estimate._fmt_duration(3725), '1h 2m')

    def test_markdown_has_all_sections(self):
        est = estimate.estimate_from_counts(MEDIUM)
        md = estimate.render_markdown(est, enterprise_name='Acme Sandbox')
        self.assertIn('Acme Sandbox', md)
        self.assertIn('### Counts', md)
        self.assertIn('### API call budget', md)
        self.assertIn('### Throttle recommendation', md)
        self.assertIn('### Warnings', md)  # has attachments + shares
        self.assertIn('--delay=2.0', md)

    def test_markdown_no_warnings_section_for_small(self):
        est = estimate.estimate_from_counts(SMALL)
        md = estimate.render_markdown(est)
        self.assertNotIn('### Warnings', md)

    def test_markdown_warns_on_long_runtime(self):
        est = estimate.estimate_from_counts(XLARGE)
        md = estimate.render_markdown(est)
        self.assertIn('1 h', md.replace('1h', '1 h'))


class TestInventoryLoad(unittest.TestCase):
    def test_load_counts_from_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'inventory.json')
            with open(path, 'w') as f:
                json.dump({'counts': MEDIUM, 'entities': {}}, f)
            counts = estimate.load_inventory_counts(path)
            self.assertEqual(counts, MEDIUM)

    def test_load_counts_raises_on_missing_counts(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'inventory.json')
            with open(path, 'w') as f:
                json.dump({'entities': {}}, f)
            with self.assertRaises(ValueError):
                estimate.load_inventory_counts(path)


class TestAsJson(unittest.TestCase):
    def test_json_shape(self):
        est = estimate.estimate_from_counts(MEDIUM)
        j = est.as_json()
        self.assertIn('counts', j)
        self.assertIn('stages', j)
        self.assertIn('throttle', j)
        self.assertIn('totals', j)
        self.assertEqual(j['throttle']['delay'], est.delay)
        self.assertEqual(j['throttle']['batch_size'], est.batch_size)
        self.assertEqual(len(j['stages']), 5)


class TestWizardTierParity(unittest.TestCase):
    """The wizard and the estimator must agree on throttle tiers."""

    def test_wizard_tiers_come_from_estimate(self):
        from keepercommander.commands.keeper_tenant_migrate import wizard

        wiz = wizard.Wizard.__new__(wizard.Wizard)
        wiz.auto_adjust = True
        tiers = list(wiz._SCALE_TIERS)
        # Every (upper, delay, batch) must match estimate.SCALE_TIERS
        est_tiers = [(u, d, b) for u, d, b, _ in estimate.SCALE_TIERS]
        self.assertEqual(tiers, est_tiers)


if __name__ == '__main__':
    unittest.main()
