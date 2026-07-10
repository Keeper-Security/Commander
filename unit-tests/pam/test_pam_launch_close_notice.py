"""
Unit tests for ``_print_close_reason_notice`` — the user-facing notice shown when a
``pam launch`` guac session is closed by the remote end.

Regression: a normal logout (user types ``exit`` / ``logout``) is reported by the
gateway as ``guacd_error`` (CloseConnectionReason code 14) or ``server_disconnect``.
The notice must NOT print the misleading "Session ended (guacd_error)." line once the
session was actually live, while still surfacing a genuine connect-time guacd fault
(``guacd_error`` before any data flowed).
"""
import importlib
import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

skip_tests = False
skip_reason = ""
try:
    importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')
    from keepercommander.commands.pam_launch import launch as launch_mod
    from keepercommander.commands.pam_launch.launch import (
        _print_close_reason_notice,
        _approve_pam_launch_if_needed,
        _is_tube_terminal_state,
        EXIT_CODE_AI_TERMINATED,
        EXIT_CODE_ADMIN_TERMINATED,
    )
    from keepercommander.error import CommandError
except ImportError as e:  # pragma: no cover
    skip_tests = True
    skip_reason = f"Cannot import pam_launch.launch: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestPrintCloseReasonNotice(unittest.TestCase):

    def _notice(self, reason, *, session_established=False, pending_exit_code=None):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = _print_close_reason_notice(
                reason,
                pending_exit_code=pending_exit_code,
                session_established=session_established,
            )
        return rc, buf.getvalue()

    # --- the regression: clean logout must be silent -----------------------

    def test_guacd_error_after_established_session_is_silent(self):
        rc, out = self._notice('guacd_error', session_established=True)
        self.assertEqual(out, '')
        self.assertIsNone(rc)

    def test_server_disconnect_is_silent_regardless_of_state(self):
        for established in (True, False):
            rc, out = self._notice('server_disconnect', session_established=established)
            self.assertEqual(out, '')
            self.assertIsNone(rc)

    # --- genuine faults still surface --------------------------------------

    def test_guacd_error_before_session_established_is_shown(self):
        rc, out = self._notice('guacd_error', session_established=False)
        self.assertIn('Session ended (guacd_error).', out)
        self.assertIsNone(rc)

    # --- unchanged behaviour for the other reasons -------------------------

    def test_normal_and_client_are_silent(self):
        for reason in ('normal', 'client', None):
            rc, out = self._notice(reason, session_established=True)
            self.assertEqual(out, '')

    def test_ai_closed_returns_ai_exit_code(self):
        rc, out = self._notice('ai_closed', session_established=True)
        self.assertEqual(rc, EXIT_CODE_AI_TERMINATED)
        self.assertIn('KeeperAI', out)

    def test_admin_closed_returns_admin_exit_code(self):
        rc, out = self._notice('admin_closed', session_established=True)
        self.assertEqual(rc, EXIT_CODE_ADMIN_TERMINATED)
        self.assertIn('administrator', out)

    def test_other_reason_prints_generic_notice(self):
        rc, out = self._notice('timeout', session_established=True)
        self.assertIn('Session ended (timeout).', out)

    def test_pending_exit_code_preserved_on_silent_close(self):
        rc, out = self._notice('guacd_error', session_established=True, pending_exit_code=7)
        self.assertEqual(out, '')
        self.assertEqual(rc, 7)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamLaunchDesktopApproval(unittest.TestCase):

    def test_plain_commander_launch_does_not_request_desktop_approval(self):
        params = type('Params', (), {'via_desktop_login': False})()
        with mock.patch.object(launch_mod.pam_state_bridge, 'request_start_tunnel_approval') as approval:
            _approve_pam_launch_if_needed(params, 'record-1', 'Record 1')

        approval.assert_not_called()

    def test_via_desktop_launch_requests_approval(self):
        params = type('Params', (), {'via_desktop_login': True})()
        with mock.patch.object(
            launch_mod.pam_state_bridge,
            'request_start_tunnel_approval',
            return_value=(True, 'allow'),
        ) as approval:
            _approve_pam_launch_if_needed(params, 'record-1', 'Record 1')

        approval.assert_called_once_with(
            params=params,
            action='pam_launch',
            resource_handle='record-1',
            resource_title='Record 1',
            purpose='Open PAM launch session',
        )

    def test_via_desktop_launch_denial_fails_closed(self):
        params = type('Params', (), {'via_desktop_login': True})()
        with mock.patch.object(
            launch_mod.pam_state_bridge,
            'request_start_tunnel_approval',
            return_value=(False, 'denied'),
        ):
            with self.assertRaises(CommandError) as cm:
                _approve_pam_launch_if_needed(params, 'record-1', 'Record 1')

        self.assertIn('Desktop approval denied or unavailable: denied', str(cm.exception))

    def test_via_desktop_launch_duplicate_session_is_user_friendly(self):
        params = type('Params', (), {'via_desktop_login': True})()
        with mock.patch.object(
            launch_mod.pam_state_bridge,
            'request_start_tunnel_approval',
            return_value=(
                False,
                'duplicate_active_session: A PAM launch session is already active for record record-1.',
            ),
        ):
            with self.assertRaises(CommandError) as cm:
                _approve_pam_launch_if_needed(params, 'record-1', 'Record 1')

        self.assertEqual('', cm.exception.command)
        self.assertIn('PAM launch session is already active', cm.exception.message)
        self.assertNotIn('Desktop approval denied or unavailable', cm.exception.message)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamLaunchTubeState(unittest.TestCase):

    def test_terminal_states_are_closed(self):
        class Registry:
            def __init__(self, state):
                self.state = state

            def get_connection_state(self, tube_id):
                return self.state

        for state in ('closed', 'disconnected', 'failed', 'not_found'):
            self.assertTrue(_is_tube_terminal_state(Registry(state), 'tube-1'))

    def test_connected_state_is_not_closed(self):
        class Registry:
            def get_connection_state(self, tube_id):
                return 'connected'

        self.assertFalse(_is_tube_terminal_state(Registry(), 'tube-1'))

    def test_missing_tube_is_terminal(self):
        class Registry:
            def get_connection_state(self, tube_id):
                raise RuntimeError('Tube not found')

        self.assertTrue(_is_tube_terminal_state(Registry(), 'tube-1'))

    def test_unknown_state_error_is_not_terminal(self):
        class Registry:
            def get_connection_state(self, tube_id):
                raise RuntimeError('temporary registry failure')

        self.assertFalse(_is_tube_terminal_state(Registry(), 'tube-1'))


if __name__ == '__main__':
    unittest.main()
