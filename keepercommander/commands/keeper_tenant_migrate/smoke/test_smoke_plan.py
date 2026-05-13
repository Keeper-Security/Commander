"""Smoke: tenant-migrate plan — produces inventory.json from current session."""

import json
import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import PlanCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import (
    seed_record, writeable_run_dir,
)


class PlanSmokeTests(unittest.TestCase):
    """Plan should write a valid inventory JSON with non-zero counts."""

    def setUp(self):
        self.run_dir = writeable_run_dir('plan')
        self.out = os.path.join(self.run_dir, 'inventory.json')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_plan_emits_inventory_with_expected_counts(self):
        params = build_smoke_params()
        # Seed a single MIGTEST record so the inventory has non-zero records.
        seed_record(params, uid='UID-001', title='MIGTEST-Login-1')
        with StubCommander():
            PlanCommand().execute(
                params, output=self.out,
                scope_node='MIGRATION-TEST-NODE',
                prefix='MIGTEST-',
                target_user='', target_root='',
                include_fields=False, skip_hsf_scrape=True,
            )
        self.assertTrue(os.path.exists(self.out),
                        'plan must emit inventory file')
        with open(self.out) as f:
            inv = json.load(f)
        self.assertIn('counts', inv)
        self.assertIn('entities', inv)
        # Counts schema is enforced by live_inventory: nodes/teams/roles/users keys.
        for key in ('nodes', 'teams', 'roles', 'users'):
            self.assertIn(key, inv['counts'],
                          f'counts missing required key {key}')


if __name__ == '__main__':
    unittest.main()
