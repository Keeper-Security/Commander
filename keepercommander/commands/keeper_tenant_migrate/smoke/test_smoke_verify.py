"""Smoke: tenant-migrate verify — reports PASS on a synthetic round-trip."""

import json
import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import (
    CaptureTargetStateCommand, PlanCommand, VerifyCommand,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import (
    seed_record, writeable_run_dir,
)


class VerifyRoundTripSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('verify')
        self.inv = os.path.join(self.run_dir, 'inventory.json')
        self.target_state = os.path.join(self.run_dir, 'target-state.json')
        self.checks = os.path.join(self.run_dir, 'checks.csv')
        self.audit = os.path.join(self.run_dir, 'audit.log')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_verify_passes_on_identical_source_and_target(self):
        # Build a minimal source with one team + one user + one record.
        src = build_smoke_params(enterprise_name='Co')
        src.enterprise['teams'].append({
            'team_uid': 't-1', 'name': 'MIGTEST-Smoke',
            'node_id': 2, 'restrict_share': False, 'restrict_edit': False,
            'restrict_view': False, 'restrict_sharing': False,
            'users': [], 'records': [],
        })
        src.enterprise['users'].append({
            'enterprise_user_id': 7777,
            'username': 'migtest-rt@co.example', 'node_id': 2,
            'status': 'active', 'two_factor_enabled': False,
            'job_title': '', 'teams': [], 'roles': [],
        })
        seed_record(src, uid='UID-RT', title='MIGTEST-RT-Login')

        with StubCommander():
            PlanCommand().execute(
                src, output=self.inv, scope_node='MIGRATION-TEST-NODE',
                prefix='MIGTEST-', target_user='', target_root='',
                include_fields=False, skip_hsf_scrape=True,
            )
            # Capture the SAME params as if it were the target — synthetic
            # round-trip means source == target.
            CaptureTargetStateCommand().execute(
                src, output=self.target_state, include_fields=False,
                prefix='MIGTEST-', mc=None,
            )
            VerifyCommand().execute(
                src, inventory=self.inv, target_state=self.target_state,
                output=self.checks, audit_log=self.audit,
            )
        self.assertTrue(os.path.exists(self.checks))
        # Read back checks.csv — every row should be PASS or INFO; no FAILs.
        import csv
        with open(self.checks) as f:
            rows = list(csv.DictReader(f))
        # Severity column lives in the second position; our DictReader
        # keys come from the header.
        fails = [r for r in rows
                 if (r.get('severity') or '').upper() == 'FAIL']
        self.assertEqual(fails, [],
                          f'verify reported FAIL on round-trip: {fails}')


if __name__ == '__main__':
    unittest.main()
