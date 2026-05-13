import unittest

from keepercommander.commands.keeper_tenant_migrate.source_quality import (
    CATEGORIES,
    scan,
    scan_roles,
    scan_whitespace,
    summarize,
)


def _inv(roles=None, teams=None, shared_folders=None, records=None):
    return {
        'entities': {
            'roles': roles or [],
            'teams': teams or [],
            'shared_folders': shared_folders or [],
            'records': records or [],
        },
    }


class ScanRolesTests(unittest.TestCase):
    def test_require_account_share_without_transfer_account_flagged(self):
        inv = _inv(roles=[{
            'name': 'Departaments - Finance Interns',
            'managed_nodes': [],  # no admin → no TRANSFER_ACCOUNT
            'enforcements': {'require_account_share': '12345'},
        }])
        findings = list(scan_roles(inv))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['category'], 'source-data-quality')
        self.assertIn('TRANSFER_ACCOUNT', findings[0]['issue'])

    def test_require_account_share_on_admin_role_passes(self):
        inv = _inv(roles=[{
            'name': 'Admin',
            'managed_nodes': [
                {'privileges': ['TRANSFER_ACCOUNT', 'MANAGE_USER']},
            ],
            'enforcements': {'require_account_share': '12345'},
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'source-data-quality']
        self.assertEqual(findings, [])

    def test_deprecated_alias_flagged(self):
        inv = _inv(roles=[{
            'name': 'Keeper Administrator',
            'enforcements': {'allow_can_edit_external_shares': 'true'},
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'deprecated-alias']
        self.assertEqual(len(findings), 1)
        self.assertIn('restrict_can_edit_external_shares',
                       findings[0]['issue'])

    def test_admin_with_teams_is_schema_violation(self):
        inv = _inv(roles=[{
            'name': 'Bad-Admin',
            'managed_nodes': [{'privileges': ['MANAGE_USER']}],
            'teams': [{'name': 'T1'}],
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'schema-violation']
        self.assertEqual(len(findings), 1)
        self.assertIn('managed_nodes', findings[0]['issue'])
        self.assertIn('teams', findings[0]['issue'])


class LockoutRiskScanRolesTests(unittest.TestCase):
    """v1.7 — pre-flight surfacing of lockout-risk enforcements on
    builtin-admin roles, so the operator sees the decision they're
    making before structure runs."""

    def test_lockout_risk_on_builtin_admin_flagged(self):
        inv = _inv(roles=[{
            'name': 'Administrator',
            'managed_nodes': [{'privileges': ['TRANSFER_ACCOUNT']}],
            'enforcements': {'restrict_ip_addresses': '10.0.0.0/8'},
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'lockout-risk']
        self.assertEqual(len(findings), 1)
        self.assertIn('Administrator', findings[0]['issue'])
        self.assertIn('restrict_ip_addresses', findings[0]['issue'])
        self.assertIn('--apply-admin-lockout-risk-enforcements',
                      findings[0]['suggested_action'])

    def test_multiple_lockout_keys_yield_separate_findings(self):
        inv = _inv(roles=[{
            'name': 'Keeper Administrator',
            'managed_nodes': [{'privileges': ['TRANSFER_ACCOUNT']}],
            'enforcements': {
                'restrict_ip_addresses': '10.0.0.0/8',
                'two_factor_by_ip': '{"allowed": []}',
            },
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'lockout-risk']
        self.assertEqual(len(findings), 2)
        # Match against the quoted-key marker that's specific to the
        # finding's primary key — `{key!r}` renders as 'key' in the
        # issue text — so the worked-example reference doesn't bleed
        # across findings.
        flagged_keys = {f['issue'].split("'")[1] for f in findings}
        self.assertEqual(flagged_keys,
                         {'restrict_ip_addresses', 'two_factor_by_ip'})

    def test_lockout_risk_on_non_builtin_role_not_flagged(self):
        inv = _inv(roles=[{
            'name': 'Custom Engineer Role',
            'enforcements': {'restrict_ip_addresses': '10.0.0.0/8'},
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'lockout-risk']
        self.assertEqual(findings, [])

    def test_lockout_risk_handles_migrated_suffix(self):
        """A builtin-admin source role observed post-rename collision
        carries the (Migrated) suffix on target inventory captures.
        The pre-flight scanner should still flag it."""
        inv = _inv(roles=[{
            'name': 'Keeper Administrator (Migrated)',
            'enforcements': {'require_account_share': '99'},
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'lockout-risk']
        self.assertEqual(len(findings), 1)
        self.assertIn('Keeper Administrator', findings[0]['issue'])

    def test_non_lockout_enforcement_on_builtin_admin_not_flagged(self):
        """Only the 4 LOCKOUT_RISK_ENFORCEMENTS keys trigger this
        scanner. A regular `two_factor_required` enforcement on
        Administrator does not."""
        inv = _inv(roles=[{
            'name': 'Administrator',
            'enforcements': {'two_factor_required': True},
        }])
        findings = [f for f in scan_roles(inv)
                    if f['category'] == 'lockout-risk']
        self.assertEqual(findings, [])


class ScanWhitespaceTests(unittest.TestCase):
    def test_trailing_space_in_sf_name_flagged(self):
        inv = _inv(shared_folders=[
            {'name': 'Keeper Demo Console users '},
        ])
        findings = list(scan_whitespace(inv))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['entity_kind'], 'shared_folder')

    def test_clean_names_pass(self):
        inv = _inv(
            shared_folders=[{'name': 'Clean SF'}],
            teams=[{'name': 'Clean Team'}],
            roles=[{'name': 'Clean Role'}],
        )
        self.assertEqual(list(scan_whitespace(inv)), [])

    def test_leading_space_in_team_flagged(self):
        inv = _inv(teams=[{'name': ' Team-A'}])
        findings = list(scan_whitespace(inv))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['entity_kind'], 'team')


class ScanIntegrationTests(unittest.TestCase):
    def test_summarize_groups_by_category(self):
        inv = _inv(
            roles=[
                {'name': 'R1', 'enforcements': {
                    'require_account_share': '1',
                    'allow_can_edit_external_shares': 'true',
                }},
            ],
            shared_folders=[{'name': 'SF '}],
        )
        findings = scan(inv)
        counts = summarize(findings)
        self.assertEqual(counts['source-data-quality'], 1)
        self.assertEqual(counts['deprecated-alias'], 1)
        self.assertEqual(counts['whitespace-padding'], 1)
        self.assertEqual(counts['total'], 3)

    def test_clean_inventory_returns_empty(self):
        """v1.7: 'clean' now requires no lockout-risk findings either.
        Use a non-builtin role so the lockout-risk scanner doesn't
        trip; TRANSFER_ACCOUNT presence still mutes the Bug-64 path."""
        inv = _inv(roles=[
            {'name': 'Custom-Admin',
             'managed_nodes': [{'privileges': ['TRANSFER_ACCOUNT']}],
             'enforcements': {'require_account_share': '1'}},
        ])
        self.assertEqual(scan(inv), [])

    def test_categories_export_matches_scanners(self):
        # Defensive — every category we emit must be in the exported
        # CATEGORIES tuple so consumers (CSV writers, reports) stay
        # in sync.
        inv = _inv(
            roles=[{'name': 'R',
                    'managed_nodes': [{'privileges': ['MANAGE_USER']}],
                    'teams': [{'name': 'T'}],
                    'enforcements': {
                        'require_account_share': '1',
                        'allow_can_edit_external_shares': 'true',
                    }}],
            shared_folders=[{'name': 'SF '}],
        )
        for f in scan(inv):
            self.assertIn(f['category'], CATEGORIES)


if __name__ == '__main__':
    unittest.main()
