import unittest

from keepercommander.commands.keeper_tenant_migrate.compliance import (
    ALLOW,
    BLOCKED,
    OVERRIDE,
    WARN,
    evaluate,
    format_decision,
)
from keepercommander.commands.keeper_tenant_migrate.tenant_profile import TenantProfile


def _p(name='p', region='', residency='', tags=()):
    return TenantProfile(
        name=name, region=region, data_residency=residency,
        compliance_tags=list(tags),
    )


class EvaluateTests(unittest.TestCase):
    def test_same_region_no_residency_allow(self):
        d = evaluate(_p(region='EU'), _p(region='EU'))
        self.assertEqual(d.verdict, ALLOW)
        self.assertFalse(d.cross_region)

    def test_cross_region_no_residency_warn(self):
        d = evaluate(_p(region='EU'), _p(region='US'))
        self.assertEqual(d.verdict, WARN)
        self.assertTrue(d.cross_region)
        self.assertTrue(any('cross-region' in r for r in d.reasons))

    def test_source_residency_blocks_foreign_target(self):
        d = evaluate(_p(region='EU', residency='EU'), _p(region='US'))
        self.assertEqual(d.verdict, BLOCKED)
        self.assertTrue(any('data_residency=EU' in r for r in d.reasons))

    def test_target_residency_blocks_foreign_source(self):
        d = evaluate(_p(region='US'), _p(region='EU', residency='EU'))
        self.assertEqual(d.verdict, BLOCKED)

    def test_matching_residency_both_sides_allow(self):
        d = evaluate(_p(region='EU', residency='EU'),
                      _p(region='EU', residency='EU'))
        self.assertEqual(d.verdict, ALLOW)

    def test_override_converts_blocked_to_override(self):
        d = evaluate(_p(region='EU', residency='EU'),
                      _p(region='US'),
                      override=True)
        self.assertEqual(d.verdict, OVERRIDE)
        self.assertTrue(any('OVERRIDE' in r for r in d.reasons))

    def test_tags_union_preserved(self):
        d = evaluate(_p(region='EU', tags=['gdpr']),
                      _p(region='EU', tags=['soc2']))
        self.assertEqual(d.audit_tags, ['gdpr', 'soc2'])

    def test_missing_regions_allow(self):
        """If neither side has a region, we can't assert cross-region; ALLOW."""
        d = evaluate(_p(), _p())
        self.assertEqual(d.verdict, ALLOW)


class FormatDecisionTests(unittest.TestCase):
    def test_renders_verdict_and_reasons(self):
        d = evaluate(_p(region='EU', residency='EU'), _p(region='US'))
        text = format_decision(d)
        self.assertIn('BLOCKED', text)
        self.assertIn('EU', text)
        self.assertIn('US', text)


if __name__ == '__main__':
    unittest.main()
