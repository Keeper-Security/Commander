"""A failing workflow must not stop the rest of a resource's Step 2, and the user must not see a stack trace."""
import io
import logging
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import MagicMock, patch

import keepercommander.commands.record  # noqa: F401

from keepercommander.commands.pam_import import batch_step2, workflow_apply
from keepercommander.commands.pam_import.base import PamMachineObject, PamWorkflowOptions
from keepercommander.commands.pam_import.batch_pipeline import _Step2DotProgress
from keepercommander.error import CommandError

MACH = 'MMMMMMMMMMMMMMMMMMMMMA'
ADMIN = 'AAAAAAAAAAAAAAAAAAAAAA'
STEP2 = 'keepercommander.commands.pam_import.batch_step2.'


def machine_with_workflow():
    mach = PamMachineObject.load({'type': 'pamMachine', 'title': 'M1', 'host': 'h', 'pam_settings': {
        'options': {'workflow': {'approvals_needed': 1, 'approvers': [
            {'principal': {'type': 'user', 'email': 'nobody@example.com'}}]}}}})
    mach.uid = MACH
    mach._extend_tag = 'new'
    return mach


def fail(*_args, **_kwargs):
    raise CommandError('', 'workflow apply failed for "M1": User nobody@example.com does not exist')


class Quiet(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.NOTSET)


class TestWorkflowFailureDoesNotStopTheResource(Quiet):
    def run_full(self, errors_out):
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        with patch(STEP2 + 'apply_workflow', side_effect=fail), \
                patch('keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch'), \
                patch(STEP2 + 'get_admin_credential', return_value=ADMIN), \
                patch(STEP2 + 'get_launch_credential', return_value=ADMIN), \
                patch(STEP2 + 'is_admin_external', return_value=False):
            batch_step2.run_step2_full(MagicMock(), tdag, machine_with_workflow(), 'cfg', MagicMock(), 'sfu', 'sfr',
                                       errors_out=errors_out)
        return tdag

    def test_the_credentials_are_still_set_and_the_failure_is_recorded(self):
        errors = []
        with self.assertLogs(level='ERROR') as cm:
            tdag = self.run_full(errors)
        tdag.set_launch_credentials.assert_called_once()          # the part AFTER the workflow still ran
        self.assertEqual(len(errors), 1)
        self.assertIn('workflow of M1: workflow apply failed for "M1": User nobody@example.com does not exist', errors[0])
        self.assertEqual(len(cm.records), 1)
        self.assertIsNone(cm.records[0].exc_info)                 # no stack trace for the user
        self.assertIn('Batch Step 2: workflow of "M1" was not applied', cm.output[0])

    def test_the_traceback_is_still_available_at_debug_level(self):
        with self.assertLogs(level='DEBUG') as cm:
            self.run_full([])
        assert any(r.levelno == logging.DEBUG and r.exc_info for r in cm.records)

    def test_without_an_error_list_the_old_behaviour_remains(self):
        with self.assertRaises(CommandError):
            self.run_full(None)


class TestProgressLine(Quiet):
    def finish(self, **kw):
        out = io.StringIO()
        with redirect_stderr(out):
            progress = _Step2DotProgress(total=7)
            progress.start()
            for _ in range(7):
                progress.tick()
            progress.finish(**kw)
        return out.getvalue()

    def test_errors_are_reported_as_errors_not_as_a_failed_run(self):
        text = self.finish(ok=False, errors=1)
        self.assertTrue(text.rstrip().endswith('7 done with 1 error(s) (7 resource(s) processed)'))
        self.assertNotIn('failed', text)

    def test_the_clean_and_the_failed_lines_are_unchanged(self):
        self.assertTrue(self.finish(ok=True).rstrip().endswith('7 done (7 resource(s))'))
        self.assertTrue(self.finish(ok=False).rstrip().endswith('7 failed (7 resource(s))'))


class TestApproverPreflight(Quiet):
    def lookup(self, error_codes):
        rs = MagicMock()
        rs.keyResponses = [MagicMock(username=u, errorCode=c) for u, c in error_codes.items()]
        return patch('keepercommander.api.communicate_rest', return_value=rs)

    def test_users_without_a_key_are_found_in_one_call(self):
        # the server answers a missing user and an existing user of another enterprise with the SAME code
        with self.lookup({'a@x.com': 'success', 'nobody@example.com': 'no_active_share_exist',
                          'elsewhere@y.com': 'no_active_share_exist'}) as rest:
            found = workflow_apply.unknown_users(MagicMock(), ['A@x.com', 'nobody@example.com', 'elsewhere@y.com'])
        self.assertEqual(found, ['elsewhere@y.com', 'nobody@example.com'])
        self.assertEqual(rest.call_count, 1)
        self.assertEqual(sorted(rest.call_args.args[1].usernames),
                         ['a@x.com', 'elsewhere@y.com', 'nobody@example.com'])

    def test_other_answers_are_not_a_not_found(self):
        # restricted sharing answers not_allowed_to_share_to_group for everybody
        with self.lookup({'a@x.com': 'not_allowed_to_share_to_group', 'b@x.com': 'some_new_code'}):
            self.assertEqual(workflow_apply.unknown_users(MagicMock(), ['a@x.com', 'b@x.com']), [])
            found, unverified, failure = workflow_apply.lookup_users(MagicMock(), ['a@x.com', 'b@x.com'])
        self.assertEqual((found, failure), ([], ''))
        self.assertEqual(unverified, {'a@x.com': 'not_allowed_to_share_to_group', 'b@x.com': 'some_new_code'})

    def test_other_answers_give_a_neutral_note_with_the_server_code(self):
        mach = machine_with_workflow()
        with self.lookup({'nobody@example.com': 'not_allowed_to_share_to_group'}):
            lines = workflow_apply.approver_warnings(MagicMock(), [mach])
        self.assertEqual(lines, ['NOTE: Resource "M1": workflow approver "nobody@example.com" could not be verified '
                                 '(server answered "not_allowed_to_share_to_group")'])

    def test_a_failed_lookup_gives_one_note_with_the_error_code(self):
        from keepercommander.error import KeeperApiError
        mach = machine_with_workflow()
        with patch('keepercommander.api.communicate_rest', side_effect=KeeperApiError('throttled', 'slow down')):
            lines = workflow_apply.approver_warnings(MagicMock(), [mach])
        self.assertEqual(lines, ['NOTE: workflow approvers could not be verified (lookup failed: throttled)'])
        with patch('keepercommander.api.communicate_rest', side_effect=RuntimeError('network')):
            lines = workflow_apply.approver_warnings(MagicMock(), [mach])
        self.assertEqual(lines, ['NOTE: workflow approvers could not be verified (lookup failed: RuntimeError)'])

    def test_a_mix_gives_the_warning_for_one_and_the_note_for_the_other(self):
        raw = {'type': 'pamMachine', 'title': 'M2', 'host': 'h', 'pam_settings': {'options': {'workflow': {
            'approvals_needed': 1, 'approvers': [{'principal': {'type': 'user', 'email': 'gone@x.com'}},
                                                 {'principal': {'type': 'user', 'email': 'odd@x.com'}},
                                                 {'principal': {'type': 'user', 'email': 'ok@x.com'}}]}}}}
        from keepercommander.commands.pam_import.base import PamMachineObject
        mach = PamMachineObject.load(raw)
        with self.lookup({'gone@x.com': 'no_active_share_exist', 'odd@x.com': 'new_code', 'ok@x.com': 'success'}):
            lines = workflow_apply.approver_warnings(MagicMock(), [mach])
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith('Resource "M2": workflow approver "gone@x.com" was not found'))
        self.assertEqual(lines[1], 'NOTE: Resource "M2": workflow approver "odd@x.com" could not be verified '
                                   '(server answered "new_code")')

    def test_a_failed_lookup_blocks_nothing(self):
        with patch('keepercommander.api.communicate_rest', side_effect=RuntimeError('network')):
            self.assertEqual(workflow_apply.unknown_users(MagicMock(), ['a@x.com']), [])
        self.assertEqual(workflow_apply.unknown_users(MagicMock(), []), [])
        self.assertEqual(workflow_apply.lookup_users(MagicMock(), []), ([], {}, ''))

    def test_the_warning_names_the_resource_and_the_approver(self):
        with self.lookup({'nobody@example.com': 'no_active_share_exist'}):
            lines = workflow_apply.approver_warnings(MagicMock(), [machine_with_workflow()])
        self.assertEqual(lines, ['Resource "M1": workflow approver "nobody@example.com" was not found among the '
                                 'users of your enterprise - if this user does not exist at all, the workflow of '
                                 'this resource will fail'])

    def test_validate_principals_logs_the_warning_and_does_not_raise(self):
        mach = machine_with_workflow()
        with self.lookup({'nobody@example.com': 'no_active_share_exist'}), self.assertLogs(level='WARNING') as cm:
            workflow_apply.validate_workflow_principals(MagicMock(), [mach])
        self.assertTrue(any('was not found among the users of your enterprise' in line for line in cm.output))

    def test_resources_without_a_workflow_make_no_call(self):
        plain = PamMachineObject.load({'type': 'pamMachine', 'title': 'P', 'host': 'h'})
        with patch('keepercommander.api.communicate_rest') as rest:
            workflow_apply.validate_workflow_principals(MagicMock(), [plain])
        rest.assert_not_called()


if __name__ == '__main__':
    unittest.main()
