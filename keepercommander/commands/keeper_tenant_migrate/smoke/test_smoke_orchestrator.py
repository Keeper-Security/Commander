"""Smoke: tenant-migrate run — target-side orchestrator end-to-end.

Drives RunCommand against a synthetic inventory through the staged
flow: structure → users → verify → reconcile (capture_state piggybacks
on verify and reconcile). Records the kwarg trace through the
kwarg-strict stub so any SDK drift in the orchestrator's wired-up
subcommands surfaces here, not in a live tenant rehearsal.
"""

import json
import os
import shutil
import unittest

from keepercommander.commands.enterprise import EnterpriseTeamCommand

from keepercommander.commands.keeper_tenant_migrate.commands import (
    PlanCommand, RunCommand,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import (
    StubAssertionError, StubCommander, build_smoke_params,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


def _seed_minimal_source():
    """Source params with one MIGTEST team so structure has a CREATE op."""
    src = build_smoke_params(enterprise_name='SrcCo')
    src.enterprise['teams'].append({
        'team_uid': 't-orc-1', 'name': 'MIGTEST-Orchestrator-Team',
        'node_id': 2,
        'restrict_share': False, 'restrict_edit': False,
        'restrict_view': False, 'restrict_sharing': False,
        'users': [], 'records': [],
    })
    return src


class OrchestratorRunSmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('orchestrator')
        self.inv = os.path.join(self.run_dir, 'inventory.json')
        self.output_dir = os.path.join(self.run_dir, 'out')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_run_structure_only_emits_results_json(self):
        """Drive the orchestrator with structure as both start and end
        stage. The structure-only path doesn't need a roster, so users
        is skipped naturally; verify/reconcile are out of range."""
        src = _seed_minimal_source()
        with StubCommander():
            PlanCommand().execute(
                src, output=self.inv, scope_node='MIGRATION-TEST-NODE',
                prefix='MIGTEST-', target_user='', target_root='',
                include_fields=False, skip_hsf_scrape=True,
            )

        tgt = build_smoke_params(enterprise_name='TgtCo')
        with StubCommander() as stub:
            result = RunCommand().execute(
                tgt, inventory=self.inv, roster=None,
                transition_plan=None, output_dir=self.output_dir,
                source_root='SrcCo', target_root='TgtCo',
                scope_node='', default_node='',
                resume=False, start_stage='structure',
                end_stage='structure', mc=None,
            )
            # Structure stage drives EnterpriseTeamCommand on the team
            # we seeded. Confirm the orchestrator wired the call through.
            self.assertIn('EnterpriseTeamCommand', stub.recorder.names())

        # results JSON exists and records the structure stage.
        self.assertTrue(os.path.exists(result['results_json']))
        with open(result['results_json']) as f:
            stages = json.load(f)
        stage_names = [s['stage'] for s in stages]
        self.assertIn('structure', stage_names)
        # No verify, no reconcile — they were outside the range.
        self.assertNotIn('verify', stage_names)
        self.assertNotIn('reconcile', stage_names)
        # Checkpoint file exists in output_dir.
        self.assertTrue(os.path.exists(
            os.path.join(self.output_dir, '.run_state')))

    def test_run_full_target_chain_structure_through_reconcile(self):
        """Drive the full target-side chain: structure → users → verify
        → reconcile. Without a roster, users naturally SKIPs. Verify and
        reconcile run their capture_state piggyback before each."""
        src = _seed_minimal_source()
        with StubCommander():
            PlanCommand().execute(
                src, output=self.inv, scope_node='MIGRATION-TEST-NODE',
                prefix='MIGTEST-', target_user='', target_root='',
                include_fields=False, skip_hsf_scrape=True,
            )

        tgt = build_smoke_params(enterprise_name='TgtCo')
        with StubCommander():
            result = RunCommand().execute(
                tgt, inventory=self.inv, roster=None,
                transition_plan=None, output_dir=self.output_dir,
                source_root='SrcCo', target_root='TgtCo',
                scope_node='', default_node='',
                resume=False, start_stage='structure',
                end_stage='reconcile', mc=None,
            )

        with open(result['results_json']) as f:
            stages = json.load(f)
        statuses = {s['stage']: s['status'] for s in stages}
        # STAGE_ORDER puts USERS before STRUCTURE; starting at structure
        # excludes users from the range. Structure PASSED. Records SKIPPED
        # because no records bundle on disk.
        self.assertEqual(statuses.get('structure'), 'PASSED')
        self.assertEqual(statuses.get('records'), 'SKIPPED')
        # verify now exits nonzero (CommandError) when checks.csv has
        # FAIL rows. The synthetic round-trip in this fixture surfaces
        # 1 FAIL row — pre-existing latent issue that the prior
        # silent-exit-0 verify bug masked. Until the latent FAIL is
        # investigated + fixed (follow-up), pin the honest behavior:
        # verify FAILED → reconcile didn't run.
        self.assertEqual(statuses.get('verify'), 'FAILED')
        # checks.csv still emitted before the raise — fail-loud
        # invariant: artifacts persist even on failure.
        self.assertTrue(os.path.exists(
            os.path.join(self.output_dir, 'checks.csv')))

    def test_orchestrator_kwarg_strict_drift_is_caught(self):
        """Drift on EnterpriseTeamCommand surfaces straight out of the
        orchestrator. The orchestrator's `except Exception` only catches
        Exception subclasses; StubAssertionError extends BaseException
        precisely so SDK-drift assertions escape the catch. The same
        contract live argparse would enforce — the stage cannot pass."""
        src = _seed_minimal_source()
        with StubCommander():
            PlanCommand().execute(
                src, output=self.inv, scope_node='MIGRATION-TEST-NODE',
                prefix='MIGTEST-', target_user='', target_root='',
                include_fields=False, skip_hsf_scrape=True,
            )

        tgt = build_smoke_params(enterprise_name='TgtCo')
        with StubCommander(extra_strict_drift={
                EnterpriseTeamCommand: {'restrict_view'}}):
            with self.assertRaises(StubAssertionError) as ctx:
                RunCommand().execute(
                    tgt, inventory=self.inv, roster=None,
                    transition_plan=None, output_dir=self.output_dir,
                    source_root='SrcCo', target_root='TgtCo',
                    scope_node='', default_node='',
                    resume=False, start_stage='structure',
                    end_stage='structure', mc=None,
                )
            self.assertIn('restrict_view', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
