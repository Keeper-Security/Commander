"""Smoke: tenant-migrate transfer-user --dry-run — classifies READY_TRANSFER rows.

Exercises the Path-B vault-transfer subcommand against the kwarg-strict
stub. Dry-run mode bypasses the destructive-source-mode interlock and
the live-only safeguards (tenant-name + batch-cap), so the smoke driver
runs end-to-end without simulating an interactive operator.
"""

import csv
import os
import shutil
import unittest

from keepercommander.commands.enterprise import EnterpriseUserCommand

from keepercommander.commands.keeper_tenant_migrate.commander_clients import CommanderUserClient
from keepercommander.commands.keeper_tenant_migrate.commands import TransferUserCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import (
    StubAssertionError, StubCommander, build_smoke_params,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


def _write_readiness(path, rows):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(
            f, fieldnames=['email', 'name', 'migration_path', 'transfer_status'])
        w.writeheader()
        for r in rows:
            w.writerow(r)


class TransferUserDryRunSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('transfer-user')
        self.readiness = os.path.join(self.run_dir, 'readiness.csv')
        self.report = os.path.join(self.run_dir, 'transfer-user-report.csv')
        self.dry_md = os.path.join(self.run_dir, 'transfer-user-plan.md')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_transfer_user_dry_run_classifies_ready_rows(self):
        _write_readiness(self.readiness, [
            {'email': 'migtest-tu1@srcco.example', 'name': 'TU One',
             'migration_path': 'READY_TRANSFER', 'transfer_status': 'eligible'},
            {'email': 'migtest-tu2@srcco.example', 'name': 'TU Two',
             'migration_path': 'READY_TRANSFER', 'transfer_status': 'eligible'},
            # A non-READY row to make sure the loader filters it out.
            {'email': 'migtest-other@srcco.example', 'name': 'Other',
             'migration_path': 'READY_OWNERSHIP', 'transfer_status': ''},
        ])

        params = build_smoke_params(enterprise_name='SrcCo')
        with StubCommander() as stub:
            result = TransferUserCommand().execute(
                params, readiness_report=self.readiness,
                report_output=self.report, admin_email='admin@srcco.example',
                delay=0.0, dry_run=True, dry_run_report=self.dry_md,
                yes=True, expected_tenant_name='', skip_tenant_check=True,
                batch_cap=50, override_batch_cap=False,
                run_dir=self.run_dir,
                confirm_source_destructive=False,
                resume=False, force_restart=False,
            )
            # Dry-run never invokes EnterpriseTransferUserCommand on the
            # SDK boundary — the DryRun wrapper records the calls but
            # short-circuits before .execute().
            for cmd_name, _kw in stub.recorder.calls:
                self.assertNotEqual(cmd_name, 'EnterpriseTransferUserCommand',
                                    'dry-run leaked a real transfer call')
        self.assertTrue(result.get('dry_run'))
        # Dry-run summary carries per-row counts; classify_plan + summarize
        # roll those into a CREATE/SKIP/UNCHECKED histogram in `counts`.
        self.assertEqual(result['summary']['total'], 2,
                          'expected 2 READY_TRANSFER rows after CSV filter')
        self.assertEqual(result['counts'].get('UNCHECKED', 0), 2,
                          'transfer_user_vault classifies as UNCHECKED in dry-run')
        self.assertTrue(os.path.exists(self.dry_md))
        with open(self.dry_md) as f:
            md = f.read()
        # Plan renders an UNCHECKED bucket per transfer_user_vault op.
        self.assertIn('transfer_user_vault', md)
        self.assertIn('UNCHECKED (2)', md)
        # 0600 on the dry-run plan because it is a destructive-op artifact.
        mode = os.stat(self.dry_md).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_transfer_user_kwarg_strict_drift_is_caught(self):
        """Per-subcommand kwarg-strict claim: a bogus kwarg sent through
        any command class the transfer-user path uses must surface as a
        StubAssertionError, mirroring how live argparse would reject it.

        Use CommanderUserClient.invite_user as the kwarg-strict probe — it
        runs through the same EnterpriseUserCommand class that the smoke
        layer's enterprise-user patch covers, exactly the way live drift
        would manifest if Commander dropped a dest the plugin still sends.
        """
        params = build_smoke_params(enterprise_name='SrcCo')
        with StubCommander(extra_strict_drift={
                EnterpriseUserCommand: {'displayname'}}):
            client = CommanderUserClient(params)
            with self.assertRaises(StubAssertionError):
                client.invite_user(
                    'migtest-drift@srcco.example', 'Drift Probe',
                    'MIGRATION-TEST-NODE', '',
                )


if __name__ == '__main__':
    unittest.main()
