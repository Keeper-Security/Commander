"""``workflow_apply._reconcile_approvers``: an approver whose escalation changed is replaced (QA 2026-11-19)."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import utils
from keepercommander.commands.pam_import import workflow_apply as wa
from keepercommander.proto import workflow_pb2

RECORD = utils.base64_url_decode(utils.generate_uid())


def existing(email, escalation=False, after_ms=0):
    approver = workflow_pb2.WorkflowApprover()
    approver.user = email
    approver.escalation = escalation
    if after_ms:
        approver.escalationAfterMs = after_ms
    return approver


def wanted(email, escalation=False, after_ms=0):
    return {'principal_type': 'user', 'email': email, 'team_uid_b64': None, 'escalation': escalation,
            'escalation_after_ms': after_ms}


class TestReconcileApprovers(unittest.TestCase):
    def run_reconcile(self, have, want):
        calls = []

        def post(_params, endpoint, rq_proto=None, **_kw):
            calls.append((endpoint, [(a.user, a.escalation, a.escalationAfterMs) for a in rq_proto.approvers]))

        with patch.object(wa, '_post_with_throttle_retry', side_effect=post):
            wa._reconcile_approvers(MagicMock(), RECORD, 'M1', have, want)
        return calls

    def test_an_unchanged_approver_makes_no_call(self):
        self.assertEqual(self.run_reconcile([existing('a@x.com', True, 7200000)], [wanted('a@x.com', True, 7200000)]), [])

    def test_a_changed_escalation_is_replaced(self):
        calls = self.run_reconcile([existing('a@x.com')], [wanted('a@x.com', True, 7200000)])
        self.assertEqual(calls, [('delete_workflow_approvers', [('a@x.com', False, 0)]),
                                 ('add_workflow_approvers', [('a@x.com', True, 7200000)])])

    def test_a_changed_delay_is_replaced_and_the_delay_of_an_off_escalation_is_ignored(self):
        calls = self.run_reconcile([existing('a@x.com', True, 3600000)], [wanted('a@x.com', True, 7200000)])
        self.assertEqual([c[0] for c in calls], ['delete_workflow_approvers', 'add_workflow_approvers'])
        self.assertEqual(self.run_reconcile([existing('a@x.com', False, 5)], [wanted('a@x.com', False, 0)]), [])

    def test_new_and_removed_approvers_still_work(self):
        calls = self.run_reconcile([existing('old@x.com')], [wanted('new@x.com')])
        self.assertEqual(calls, [('delete_workflow_approvers', [('old@x.com', False, 0)]),
                                 ('add_workflow_approvers', [('new@x.com', False, 0)])])


if __name__ == '__main__':
    unittest.main()
