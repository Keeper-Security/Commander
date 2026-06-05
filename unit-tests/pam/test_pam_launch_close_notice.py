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

sys.path.insert(0, os.path.dirname(__file__))

skip_tests = False
skip_reason = ""
try:
    importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')
    from keepercommander.commands.pam_launch import launch as launch_mod
    from keepercommander.commands.pam_launch.launch import (
        _print_close_reason_notice,
        EXIT_CODE_AI_TERMINATED,
        EXIT_CODE_ADMIN_TERMINATED,
    )
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


if __name__ == '__main__':
    unittest.main()
