"""Smoke: tenant-migrate structure --dry-run — produces a CREATE/SKIP plan."""

import json
import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import PlanCommand, StructureCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


class StructureDryRunSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('structure')
        self.inv = os.path.join(self.run_dir, 'inventory.json')
        self.report = os.path.join(self.run_dir, 'plan.md')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_structure_dry_run_against_fresh_target_classifies_creates(self):
        # Stage 1: capture a tiny inventory off a synthetic source.
        src = build_smoke_params(enterprise_name='SrcCo')
        # Add one team + one role under MIGRATION-TEST-NODE so the
        # inventory has a non-trivial structure.
        src.enterprise['teams'].append({
            'team_uid': 't-001', 'name': 'MIGTEST-Smoke-Team',
            'node_id': 2,
            'restrict_share': False, 'restrict_edit': False,
            'restrict_view': False, 'restrict_sharing': False,
            'users': [], 'records': [],
        })
        src.enterprise['roles'].append({
            'role_id': 1001, 'data': {'displayname': 'MIGTEST-Smoke-Role'},
            'node_id': 2, 'enforcements': {},
            'users': [], 'teams': [],
            'managed_nodes': [], 'role_privileges': [],
        })
        with StubCommander():
            PlanCommand().execute(
                src, output=self.inv, scope_node='MIGRATION-TEST-NODE',
                prefix='MIGTEST-', target_user='', target_root='',
                include_fields=False, skip_hsf_scrape=True,
            )
        self.assertTrue(os.path.exists(self.inv))

        # Stage 2: dry-run structure on a fresh target tenant.
        tgt = build_smoke_params(enterprise_name='TgtCo')
        with StubCommander() as stub:
            StructureCommand().execute(
                tgt, inventory=self.inv,
                source_root='SrcCo', target_root='TgtCo',
                scope_node='', steps='0-12', dry_run=True,
                dry_run_report=self.report, mc=None,
            )
            # Dry-run must not touch the SDK — recorder stays empty.
            self.assertEqual(stub.recorder.calls, [],
                              'dry-run must not call any Commander commands')
        self.assertTrue(os.path.exists(self.report),
                        'dry-run report not emitted')
        # Report is Markdown with a CREATE classification for our seed entities.
        with open(self.report) as f:
            md = f.read()
        self.assertIn('MIGTEST-Smoke-Team', md)
        self.assertIn('MIGTEST-Smoke-Role', md)


if __name__ == '__main__':
    unittest.main()
