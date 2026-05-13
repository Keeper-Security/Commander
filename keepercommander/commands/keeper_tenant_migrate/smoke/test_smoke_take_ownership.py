"""Smoke: tenant-migrate take-ownership --dry-run — Path-A folder transfer.

Exercises the verification-report → backup + ownership-transfer driver
against the kwarg-strict stub. Dry-run skips the destructive-source
interlock and the live-only safeguards while still walking the full
loop through the DryRun-wrapped client.
"""

import csv
import os
import shutil
import unittest

from keepercommander.commands.register import ShareRecordCommand

from keepercommander.commands.keeper_tenant_migrate.commands import TakeOwnershipCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import (
    StubAssertionError, StubCommander, build_smoke_params,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


def _write_verification(path, rows):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=[
            'email', 'full_name', 'expected_folder', 'record_count', 'status'])
        w.writeheader()
        for r in rows:
            w.writerow(r)


class TakeOwnershipDryRunSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('take-ownership')
        self.verification = os.path.join(self.run_dir, 'verification.csv')
        self.backup_dir = os.path.join(self.run_dir, 'backups')
        self.report = os.path.join(self.run_dir, 'ownership-report.csv')
        self.dry_md = os.path.join(self.run_dir, 'ownership-plan.md')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_take_ownership_dry_run_classifies_ready_rows(self):
        _write_verification(self.verification, [
            {'email': 'migtest-own1@srcco.example', 'full_name': 'Owner One',
             'expected_folder': 'MIGRATION-Owner-One', 'record_count': '4',
             'status': 'READY'},
            {'email': 'migtest-own2@srcco.example', 'full_name': 'Owner Two',
             'expected_folder': 'MIGRATION-Owner-Two', 'record_count': '2',
             'status': 'READY'},
            # Non-READY row must be filtered out.
            {'email': 'migtest-skip@srcco.example', 'full_name': 'Skip',
             'expected_folder': 'MIGRATION-Skip', 'record_count': '0',
             'status': 'PENDING'},
        ])
        os.makedirs(self.backup_dir, exist_ok=True)

        params = build_smoke_params(enterprise_name='SrcCo')
        with StubCommander() as stub:
            result = TakeOwnershipCommand().execute(
                params, verification_report=self.verification,
                backup_dir=self.backup_dir, report_output=self.report,
                admin_email='admin@srcco.example', delay=0.0,
                dry_run=True, dry_run_report=self.dry_md, yes=True,
                expected_tenant_name='', skip_tenant_check=True,
                old_domain='', new_domain='', batch_size=0,
                run_dir=self.run_dir,
                confirm_source_destructive=False,
                resume=False, force_restart=False,
            )
            # Dry-run never invokes the SDK ShareRecordCommand. The
            # stub has it patched, so any leak would be visible in
            # recorder.calls — assert none surfaced.
            for cmd_name, _kw in stub.recorder.calls:
                self.assertNotEqual(cmd_name, 'ShareRecordCommand',
                                    'dry-run leaked a real ownership transfer')
        self.assertTrue(result.get('dry_run'))
        # 2 READY rows × (export_folder_json + take_folder_ownership) = 4 ops.
        self.assertEqual(result['summary']['total'], 2,
                          'expected 2 READY rows after CSV filter')
        self.assertTrue(os.path.exists(self.dry_md))
        with open(self.dry_md) as f:
            md = f.read()
        # Plan lists the two op kinds; the DryRun classifier records
        # each call against an UNCHECKED bucket because we have no
        # target-state probe for path-A operations.
        self.assertIn('export_folder_json', md)
        self.assertIn('take_folder_ownership', md)
        # 0600 on the dry-run plan (destructive-op artifact).
        mode = os.stat(self.dry_md).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_take_ownership_kwarg_strict_drift_is_caught(self):
        """Probe the kwarg-strict claim against ShareRecordCommand —
        the SDK boundary the live take-ownership flow drives. Mark
        `recursive` as drifted and observe StubAssertionError when the
        plugin sends it through CommanderOwnershipClient.
        """
        from keepercommander.commands.keeper_tenant_migrate.commander_clients import (
            CommanderOwnershipClient,
        )
        params = build_smoke_params(enterprise_name='SrcCo')
        with StubCommander(extra_strict_drift={
                ShareRecordCommand: {'recursive'}}):
            client = CommanderOwnershipClient(params)
            with self.assertRaises(StubAssertionError):
                client.take_folder_ownership(
                    'MIGRATION-Probe', 'admin@srcco.example')


if __name__ == '__main__':
    unittest.main()
