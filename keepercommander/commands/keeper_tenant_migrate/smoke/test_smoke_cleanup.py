"""Smoke: tenant-migrate cleanup --dry-run — produces a delete-plan."""

import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import CleanupCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


class CleanupDryRunSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('cleanup')
        self.report = os.path.join(self.run_dir, 'cleanup-plan.md')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_cleanup_dry_run_produces_delete_plan(self):
        params = build_smoke_params()
        # Prime the tenant with MIGTEST entities to be cleaned.
        params.enterprise['teams'].append({
            'team_uid': 'tu-001', 'name': 'MIGTEST-Team-1', 'node_id': 2,
            'restrict_share': False, 'restrict_edit': False,
            'restrict_view': False, 'restrict_sharing': False,
        })
        params.enterprise['roles'].append({
            'role_id': 5001, 'data': {'displayname': 'MIGTEST-Role-1'},
            'node_id': 2,
        })
        with StubCommander() as stub:
            result = CleanupCommand().execute(
                params, prefix='MIGTEST-', dry_run=True,
                dry_run_report=self.report, confirm=False,
                yes=False,
                expected_tenant_name=params.enterprise['enterprise_name'],
                skip_tenant_check=False,
                batch_cap=50, override_batch_cap=False,
                run_dir=self.run_dir,
                confirm_source_destructive=False, mc=None,
                include_records=False,
            )
            self.assertEqual(stub.recorder.calls, [],
                              'dry-run cleanup must not delete anything')
        self.assertTrue(result.get('dry_run'))
        self.assertIn('counts', result)
        self.assertTrue(os.path.exists(self.report))


if __name__ == '__main__':
    unittest.main()
