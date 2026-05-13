"""Smoke: tenant-migrate undo --plan-only — produces a rollback plan."""

import os
import shutil
import unittest

from keepercommander.commands.keeper_tenant_migrate.audit import append_audit_event
from keepercommander.commands.keeper_tenant_migrate.commands import UndoCommand
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import StubCommander, build_smoke_params
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import writeable_run_dir


class UndoPlanOnlySmokeTests(unittest.TestCase):

    def setUp(self):
        self.run_dir = writeable_run_dir('undo')
        self.audit = os.path.join(self.run_dir, 'audit.log')

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def _seed_audit(self):
        # Seed a structure event + a users event so the planner has
        # something to rewind. The audit chain hashes prev → next, so
        # we rely on append_audit_event for chain integrity.
        append_audit_event(self.audit, {
            'subcommand': 'structure',
            'inputs': {'inventory': '/tmp/inv.json'},
            'outputs': {},
            'summary': {'created_nodes': ['MIGTEST-Smoke-Node']},
        })
        append_audit_event(self.audit, {
            'subcommand': 'users',
            'inputs': {'inventory': '/tmp/inv.json',
                        'roster': '/tmp/roster.csv'},
            'outputs': {},
            'summary': {
                'invited_emails': ['migtest-rollback@co.example'],
                'counts': {'total': 1, 'invited': 1, 'extended': 0,
                            'existing': 0, 'blocked': 0, 'failed': 0},
            },
        })

    def test_undo_plan_only_returns_plans_without_executing(self):
        self._seed_audit()
        params = build_smoke_params()
        with StubCommander() as stub:
            result = UndoCommand().execute(
                params, audit_log=self.audit,
                up_to=None, execute=False, hard=False, yes=True,
            )
            self.assertEqual(stub.recorder.calls, [],
                              'plan-only undo must not invoke Commander')
        self.assertTrue(result.get('ok'))
        self.assertFalse(result.get('executed'))
        self.assertGreaterEqual(result.get('count', 0), 1,
                                 'undo must surface at least one plan entry')


if __name__ == '__main__':
    unittest.main()
