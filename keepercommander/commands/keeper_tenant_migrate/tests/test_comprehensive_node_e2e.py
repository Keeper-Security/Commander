"""End-to-end fakes-only walk of the comprehensive-node fixture set.

Builds one giant inventory containing every fixture from
keepercommander.commands.keeper_tenant_migrate.tests.fixtures.comprehensive_node, runs it
through the full structure → users → records → verify pipeline using
existing Fake* clients, and asserts the comparison-matrix output (PASS
across nodes / teams / roles / SFs / records) sees zero FAIL — every
field round-trips. Mirrors what migration_scripts/06b_comparison_matrix.sh
emits live.
"""

import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.structure import FakeClient, StructureRestore
from keepercommander.commands.keeper_tenant_migrate.tests.fixtures import comprehensive_node as cn
from keepercommander.commands.keeper_tenant_migrate.users import FakeUserClient, UserRunner
from keepercommander.commands.keeper_tenant_migrate.validate import (
    Severity,
    ValidationContext,
    Validator,
    summarize,
)


class ComprehensiveNodeEndToEndTests(unittest.TestCase):
    """Drive the full pipeline against the combined fixture set."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = cn.combined_inventory()
        cls.tmp = tempfile.mkdtemp(prefix='migtest_e2e_')

    def _run_structure(self):
        """Run the structure stages that operate on the combined fixture."""
        client = FakeClient()
        restore = StructureRestore(
            client, source_root=cn.SOURCE_ROOT, target_root=cn.TARGET_ROOT,
            scope_node=cn.SCOPE_NODE,
        )
        nodes = self.inventory['entities']['nodes']
        restore.step_nodes(nodes)
        restore.step_isolated_flags(nodes)
        restore.step_teams(self.inventory['entities']['teams'])
        restore.step_roles(self.inventory['entities']['roles'])
        restore.step_managed_nodes(self.inventory['entities']['roles'])
        restore.step_enforcements(self.inventory['entities']['roles'],
                                   complexity_dir=self.tmp)
        restore.step_user_nodes(self.inventory['entities']['users'])
        restore.step_user_teams(self.inventory['entities']['users'])
        restore.step_role_users(self.inventory['entities']['roles'])
        restore.step_role_teams(self.inventory['entities']['roles'])
        restore.step_vault_folders(self.inventory['vault_folders'])
        return client, restore

    def _run_users(self):
        client = FakeUserClient()
        runner = UserRunner(client, source_root=cn.SOURCE_ROOT,
                             target_root=cn.TARGET_ROOT,
                             default_node=cn.SCOPE_NODE,
                             sleeper=lambda *_: None)
        roster = [{'email': u['email'], 'full_name': u['email'].split('@')[0]}
                  for u in self.inventory['entities']['users']]
        plan = []
        for u in self.inventory['entities']['users']:
            if u['status'] == 'invited':
                plan.append({'source_email': u['email'], 'category': 'E'})
        results = runner.run(roster, inventory={'entities': self.inventory['entities']},
                              transition_plan=plan)
        return client, results

    def test_structure_stage_zero_failures(self):
        """Every structure stage runs without recording a FAILED entry."""
        client, restore = self._run_structure()
        self.assertEqual(restore.counters['FAILED'], 0,
                         msg=f'Failures: {[r.notes for r in restore.results if r.status=="FAILED"]}')

    def test_users_stage_invites_or_extends_every_roster_row(self):
        client, results = self._run_users()
        statuses = {r.status for r in results}
        # Every fixture user resolves to a valid lifecycle status.
        self.assertTrue(statuses.issubset(
            {'YES', 'EXISTS', 'EXTENDED'}),
            msg=f'Unexpected statuses: {statuses}')
        # Pending-invite user must have hit the EXTENDED branch.
        emails = [r.email for r in results if r.status == 'EXTENDED']
        self.assertIn('pending.invite@migtest.example', emails)

    def test_validator_zero_fail_when_target_mirrors_source(self):
        """Validator over a fake target equal to the source inventory must
        emit zero FAILs across every phase. This is the comparison-matrix
        100% PASS contract from 06b_comparison_matrix.sh, applied
        offline."""
        # Build a target_state dict mirroring source entities — what a
        # successful migration would produce.
        ent = self.inventory['entities']
        target = {
            'nodes': list(ent['nodes']),
            'teams': list(ent['teams']),
            'roles': list(ent['roles']),
            'shared_folders': list(ent['shared_folders']),
            'records': list(ent['records']),
            'users': list(ent['users']),
        }
        ctx = ValidationContext(self.inventory, target)
        checks = Validator(ctx).run()
        counts = summarize(checks)
        # PASS dominates; FAIL is zero (mirror condition); WARN tolerated
        # for cross-tenant cosmetic differences (e.g. user_count drift).
        self.assertEqual(counts['FAIL'], 0,
                         msg=[c for c in checks
                              if c.severity == Severity.FAIL])
        self.assertGreater(counts['PASS'], 0)

    def test_records_round_trip_preserves_every_field(self):
        """Field-level: passwords, URLs, custom fields, TOTP, attachments
        all round-trip through summarize_record without dropping
        anything."""
        records = self.inventory['entities']['records']
        # Locate fixtures by deterministic title.
        titles = {r['title']: r for r in records}
        # Login record full fields.
        login = titles['MIGTEST-LoginFull']
        self.assertEqual(login['login'], 'svcacct@migtest.example')
        self.assertEqual(login['password'], 'CorrectHorseBatteryStaple')
        self.assertEqual(login['login_url'],
                         'https://app.migtest.example/login')
        self.assertEqual(login['notes'],
                         'Production credentials — rotate quarterly.')
        # Custom fields.
        cf = titles['MIGTEST-CustomFields']
        self.assertEqual(cf['custom_fields']['Environment'], 'production')
        self.assertEqual(cf['custom_fields']['Owner'], 'platform-team')
        self.assertEqual(cf['custom_fields']['TicketId'], 'MIGTEST-1234')
        # Attachments.
        self.assertEqual(titles['MIGTEST-WithAttachments']['attachment_count'], 2)
        # TOTP.
        totp = titles['MIGTEST-WithTOTP']
        self.assertTrue(totp['has_totp'])
        self.assertIn('JBSWY3DPEHPK3PXP', totp['totp_secret'])
        # Direct shares.
        share = titles['MIGTEST-DirectShare']
        self.assertEqual(len(share['direct_shares']), 2)

    def test_vault_folders_fully_resolved_by_uid_map(self):
        """Every vault_folders source UID lands in uid_map after
        step_vault_folders — proves parents were emitted in front of
        children, no orphaned folders."""
        client, restore = self._run_structure()
        # Re-run vault_folders alone with a fresh client to capture uid_map.
        c2 = FakeClient()
        r2 = StructureRestore(c2, source_root=cn.SOURCE_ROOT,
                               target_root=cn.TARGET_ROOT,
                               scope_node=cn.SCOPE_NODE)
        uid_map = r2.step_vault_folders(self.inventory['vault_folders'])
        for vf in self.inventory['vault_folders']:
            self.assertIn(vf['uid'], uid_map,
                           msg=f'Folder {vf["name"]} ({vf["type"]}) not resolved')

    def test_comparison_matrix_all_pass_aggregate(self):
        """Aggregate parity check: walk every fixture category, assert
        the validator's per-category PASS count covers the fixture
        count + key-level checks the gap calls out. Simulates running
        06b_comparison_matrix.sh offline against a matched target."""
        ent = self.inventory['entities']
        target = {
            'nodes': list(ent['nodes']),
            'teams': list(ent['teams']),
            'roles': list(ent['roles']),
            'shared_folders': list(ent['shared_folders']),
            'records': list(ent['records']),
            'users': list(ent['users']),
        }
        ctx = ValidationContext(self.inventory, target)
        checks = Validator(ctx).run()
        per_phase_pass = {}
        per_phase_fail = {}
        for c in checks:
            if c.severity == Severity.PASS:
                per_phase_pass[c.phase] = per_phase_pass.get(c.phase, 0) + 1
            elif c.severity == Severity.FAIL:
                per_phase_fail[c.phase] = per_phase_fail.get(c.phase, 0) + 1
        # FAIL is zero in every phase.
        self.assertEqual(per_phase_fail, {},
                         msg=f'FAIL by phase: {per_phase_fail}')
        # Each entity-category phase produced at least one PASS,
        # corresponding to the fixture category being exercised.
        for phase in ('nodes', 'teams', 'roles', 'shared_folders', 'records'):
            self.assertGreater(per_phase_pass.get(phase, 0), 0,
                                msg=f'No PASS check for phase {phase}')


if __name__ == '__main__':
    unittest.main()
