"""Smoke: tenant-migrate decommission --plan-only — emits Markdown plan."""

import csv
import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import DecommissionCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


class DecommissionPlanOnlySmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('decom')
        self.roster = os.path.join(self.run_dir, 'roster.csv')
        with open(self.roster, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['email'])
            w.writeheader()
            w.writerow({'email': 'migtest-alice@srcco.example'})
            w.writerow({'email': 'migtest-bob@srcco.example'})
        self.plan = os.path.join(self.run_dir, 'decom-plan.md')
        # Anchor the session as TARGET so the SEC-1 destructive guard
        # (commit 8b16e46) classifies the role and skips the source-mode
        # interlock — without a target side, detect_session_role returns
        # 'unknown' and the fail-closed path triggers even on plan-only.
        from keepercommander.commands.keeper_tenant_migrate.wizard import save_migration_yaml
        save_migration_yaml(self.run_dir, {
            'source': {'enterprise_name': 'SrcCo',
                       'user': 'admin@srcco.example',
                       'server': 'https://srcco.keepersecurity.eu'},
            'target': {'enterprise_name': 'SmokeCo',
                       'user': 'admin@smokeco.example',
                       'server': 'https://keepersecurity.eu'},
        })

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_decommission_plan_only_emits_markdown(self):
        params = build_smoke_params()
        with StubCommander() as stub:
            result = DecommissionCommand().execute(
                params, roster=self.roster, plan_only=True,
                plan_output=self.plan, checkpoint='', report_output='',
                confirm_manual_completion=False, audit_log='',
                operator='', delay=0.0, max_age_hours=72,
                dry_run=False, dry_run_report='',
                expected_tenant_name='',
                skip_tenant_check=True,
                run_dir=self.run_dir,
                confirm_source_destructive=False,
            )
            # Plan-only never invokes Commander.
            self.assertEqual(stub.recorder.calls, [])
        self.assertTrue(result.get('plan_only'))
        self.assertEqual(result['users'], 2)
        self.assertTrue(os.path.exists(self.plan))
        with open(self.plan) as f:
            md = f.read()
        # Both source emails must appear in the plan.
        self.assertIn('migtest-alice@srcco.example', md)
        self.assertIn('migtest-bob@srcco.example', md)


if __name__ == '__main__':
    unittest.main()
