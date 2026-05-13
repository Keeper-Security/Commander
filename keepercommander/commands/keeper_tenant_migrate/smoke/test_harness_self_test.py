"""Harness self-test: prove the smoke layer can catch SDK kwarg drift.

This is the meta-test described in ROADMAP Phase D. Two cases:
   1. Without drift, a smoke-style call through commander_clients passes.
   2. With drift injected (SDK suddenly rejects a kwarg the plugin sends),
      the same call fails with StubAssertionError.

When this test ever flips (case 2 stops failing), the harness has lost
its teeth and the next live regression will surface as a runtime bug.
"""

import unittest

from keepercommander.commands.enterprise import EnterpriseUserCommand

from keepercommander.commands.keeper_tenant_migrate.commander_clients import CommanderUserClient
from keepercommander.commands.keeper_tenant_migrate.smoke._stub import (
    StubAssertionError, StubCommander, build_smoke_params,
)
from keepercommander.commands.keeper_tenant_migrate.smoke._stub.runtime import (
    get_last_unknown_kwarg,
)


class HarnessSelfTest(unittest.TestCase):
    """The harness must catch what it's designed to catch."""

    def test_baseline_invite_user_succeeds(self):
        """Without drift, the plugin's invite_user passes through cleanly."""
        params = build_smoke_params(enterprise_name='SelfTestCo')
        with StubCommander() as stub:
            client = CommanderUserClient(params)
            ok, _err = client.invite_user(
                'migtest-self@selftestco.example', 'Self Test',
                'MIGRATION-TEST-NODE', 'QA',
            )
            self.assertTrue(ok)
            self.assertIn('EnterpriseUserCommand', stub.recorder.names())

    def test_drift_on_displayname_makes_invite_fail(self):
        """Simulate the SDK removing the `displayname` dest. The smoke
        harness must surface that as a hard failure — same way live
        Commander would reject the call."""
        params = build_smoke_params(enterprise_name='SelfTestCo')
        # Drift: pretend Commander removed the `displayname` dest.
        with StubCommander(extra_strict_drift={
                EnterpriseUserCommand: {'displayname'}}):
            client = CommanderUserClient(params)
            with self.assertRaises(StubAssertionError) as ctx:
                client.invite_user(
                    'migtest-self@selftestco.example', 'Self Test',
                    'MIGRATION-TEST-NODE', 'QA',
                )
            self.assertIn('displayname', str(ctx.exception))
            recorded = get_last_unknown_kwarg()
            self.assertEqual(recorded[0], 'EnterpriseUserCommand')
            self.assertIn('displayname', recorded[1])

    def test_drift_then_restore_returns_to_baseline(self):
        """After exiting the drift context, the harness goes back to passing.
        Confirms the patch cleanly tears down — important so ordering of
        smoke tests doesn't bleed drift state across tests."""
        params = build_smoke_params(enterprise_name='SelfTestCo')
        # Exercise drift first.
        with StubCommander(extra_strict_drift={
                EnterpriseUserCommand: {'displayname'}}):
            with self.assertRaises(StubAssertionError):
                CommanderUserClient(params).invite_user(
                    'migtest-x@selftestco.example', 'X', 'MIGRATION-TEST-NODE',
                    '',
                )
        # Now a fresh stub (no drift) must pass.
        with StubCommander():
            ok, _err = CommanderUserClient(params).invite_user(
                'migtest-y@selftestco.example', 'Y', 'MIGRATION-TEST-NODE', '',
            )
            self.assertTrue(ok)


if __name__ == '__main__':
    unittest.main()
