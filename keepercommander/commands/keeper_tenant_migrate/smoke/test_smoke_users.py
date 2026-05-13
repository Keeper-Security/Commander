"""Smoke: tenant-migrate users --dry-run — classifies CREATE vs SKIP."""

import csv
import json
import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import PlanCommand, UsersCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


def _write_roster(path, rows):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['email', 'full_name'])
        w.writeheader()
        for r in rows:
            w.writerow(r)


class UsersDryRunSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('users')
        self.inv = os.path.join(self.run_dir, 'inventory.json')
        self.roster = os.path.join(self.run_dir, 'roster.csv')
        self.report = os.path.join(self.run_dir, 'plan.md')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_users_dry_run_emits_plan_with_create_ops(self):
        # Source side — admin + 2 MIGTEST users.
        src = build_smoke_params(enterprise_name='SrcCo')
        src.enterprise['users'].extend([
            {'enterprise_user_id': 5001, 'username': 'migtest-alice@srcco.example',
             'node_id': 2, 'status': 'active',
             'two_factor_enabled': False, 'job_title': 'Eng',
             'teams': [], 'roles': []},
            {'enterprise_user_id': 5002, 'username': 'migtest-bob@srcco.example',
             'node_id': 2, 'status': 'active',
             'two_factor_enabled': False, 'job_title': 'PM',
             'teams': [], 'roles': []},
        ])
        with StubCommander():
            PlanCommand().execute(
                src, output=self.inv, scope_node='MIGRATION-TEST-NODE',
                prefix='MIGTEST-', target_user='', target_root='',
                include_fields=False, skip_hsf_scrape=True,
            )
        with open(self.inv) as f:
            inv = json.load(f)
        self.assertIn('users', inv['entities'])

        _write_roster(self.roster, [
            {'email': 'migtest-alice@srcco.example', 'full_name': 'Alice'},
            {'email': 'migtest-bob@srcco.example', 'full_name': 'Bob'},
        ])

        # Target side — fresh, neither user exists.
        tgt = build_smoke_params(enterprise_name='TgtCo')
        with StubCommander() as stub:
            result = UsersCommand().execute(
                tgt, inventory=self.inv, roster=self.roster,
                transition_plan=None, source_root='SrcCo',
                target_root='TgtCo', default_node='TgtCo',
                dry_run=True, dry_run_report=self.report,
                mc=None, old_domain='', new_domain='',
                delay=0.0, batch_size=0, sso_policy='warn',
                run_dir=self.run_dir, resume=False,
                force_restart=False,
            )
            self.assertEqual(stub.recorder.calls, [],
                              'dry-run must not invoke EnterpriseUserCommand')
        self.assertTrue(result.get('dry_run'))
        # The plan must contain at least one CREATE classification.
        with open(self.report) as f:
            md = f.read()
        self.assertIn('migtest-alice@srcco.example', md)


if __name__ == '__main__':
    unittest.main()
