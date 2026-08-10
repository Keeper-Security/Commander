#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""Tests for PAM workflow settings enforcement gating."""

import io
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.error import CommandError
from keepercommander.commands.workflow.helpers import (
    WORKFLOW_SETTINGS_ENFORCEMENT_KEY,
    can_configure_workflow_settings,
    ensure_can_configure_workflow_settings,
)
from keepercommander.commands.workflow.registry import PAMWorkflowCommand
from keepercommander.commands.workflow.config_commands import WorkflowDeleteCommand


def _params_with_enforcement(allowed):
    params = MagicMock()
    if allowed is None:
        params.enforcements = None
        return params
    params.enforcements = {
        'booleans': (
            [{'key': WORKFLOW_SETTINGS_ENFORCEMENT_KEY, 'value': True}]
            if allowed else
            [{'key': 'some_other_key', 'value': True}]
        )
    }
    return params


class TestCanConfigureWorkflowSettings(unittest.TestCase):

    def test_allowed_when_enforcement_true(self):
        self.assertTrue(can_configure_workflow_settings(_params_with_enforcement(True)))

    def test_denied_when_enforcement_absent(self):
        # Revoke removes the key from booleans (Commander parser drops :false).
        self.assertFalse(can_configure_workflow_settings(_params_with_enforcement(False)))

    def test_denied_when_no_enforcements(self):
        self.assertFalse(can_configure_workflow_settings(_params_with_enforcement(None)))

    def test_refresh_reloads_revoked_policy(self):
        params = _params_with_enforcement(True)

        def _revoke(_params):
            _params.enforcements = {'booleans': []}

        with patch(
            'keepercommander.loginv3.LoginV3Flow.populateAccountSummary',
            side_effect=_revoke,
        ) as mock_refresh:
            self.assertFalse(can_configure_workflow_settings(params, refresh=True))
            mock_refresh.assert_called_once_with(params)

    def test_ensure_raises_when_denied(self):
        with self.assertRaises(CommandError) as ctx:
            ensure_can_configure_workflow_settings(
                _params_with_enforcement(False), refresh=False, action='delete',
            )
        self.assertIn('workflow settings', str(ctx.exception).lower())
        self.assertIn('delete', str(ctx.exception).lower())


class TestWorkflowAdminGateRefresh(unittest.TestCase):

    def test_delete_blocked_after_refresh_shows_revoke(self):
        """Repro: stale allow in session, revoke mid-session — delete must not reach Router."""
        params = _params_with_enforcement(True)

        def _revoke(_params):
            _params.enforcements = {'booleans': []}

        cmd = PAMWorkflowCommand()
        with patch(
            'keepercommander.loginv3.LoginV3Flow.populateAccountSummary',
            side_effect=_revoke,
        ), patch('sys.stdout', new_callable=io.StringIO) as stdout:
            result = cmd.execute_args(params, 'delete qWRT4eqVWubL9xJbub4rfA')

        self.assertIsNone(result)
        out = stdout.getvalue()
        self.assertIn('do not have permission', out.lower())
        self.assertIn('delete', out.lower())

    def test_delete_command_raises_when_policy_revoked(self):
        params = _params_with_enforcement(False)
        with patch(
            'keepercommander.loginv3.LoginV3Flow.populateAccountSummary',
        ), self.assertRaises(CommandError) as ctx:
            WorkflowDeleteCommand().execute(params, record='qWRT4eqVWubL9xJbub4rfA')
        self.assertIn('workflow settings', str(ctx.exception).lower())


if __name__ == '__main__':
    unittest.main()
