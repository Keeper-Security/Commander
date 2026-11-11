import contextlib
import io
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from keepercommander.commands.workflow.approver_commands import WorkflowGetApprovalRequestsCommand
from keepercommander.proto import enterprise_pb2, workflow_pb2
from keepercommander import utils


class TestWorkflowPendingApprovers(unittest.TestCase):
    def setUp(self):
        self.params = SimpleNamespace(
            user='current.approver@example.com',
            enterprise_ec_key=b'enterprise-key',
            enterprise=None,
            record_cache={},
        )
        self.approval_requests = workflow_pb2.ApprovalRequests()
        workflow = self.approval_requests.workflows.add()
        workflow.flowUid = b'flow-uid'
        workflow.user = 'requester@example.com'
        workflow.resource.value = b'record-uid'
        workflow.resource.name = 'PAM Record'
        workflow.startedOn = 1000

        self.workflow_state = workflow_pb2.WorkflowState()
        self.workflow_state.flowUid = b'flow-uid'
        self.workflow_state.status.approvedBy.add(user='other.approver@example.com')

        self.workflow_config = workflow_pb2.WorkflowConfig()
        self.workflow_config.parameters.approvalsNeeded = 2
        user_approver = self.workflow_config.approvers.add()
        user_approver.user = 'user.approver@example.com'
        team_approver = self.workflow_config.approvers.add()
        team_approver.teamUid = b'team-uid'
        team_approver.escalation = True
        team_approver.escalationAfterMs = 3600000

    def _run_pending(self, *, include_approvers):
        team_members = enterprise_pb2.GetTeamMemberResponse()
        team_members.enterpriseUser.add(email='team.member@example.com')
        router_responses = {
            'get_approval_requests': self.approval_requests,
            'get_workflow_state': self.workflow_state,
            'read_workflow_config': self.workflow_config,
        }

        def router_call(_params, endpoint, **_kwargs):
            return router_responses[endpoint]

        output = io.StringIO()
        with mock.patch(
            'keepercommander.commands.workflow.approver_commands._post_request_to_router',
            side_effect=router_call,
        ), mock.patch(
            'keepercommander.commands.workflow.approver_commands.api.communicate_rest',
            return_value=team_members,
        ) as team_lookup, mock.patch.object(
            WorkflowGetApprovalRequestsCommand,
            '_decrypt_param',
            return_value=None,
        ), mock.patch.object(
            WorkflowGetApprovalRequestsCommand,
            '_print_table',
        ), mock.patch(
            'keepercommander.commands.workflow.approver_commands.RecordResolver.resolve_name',
            return_value='PAM Record',
        ), contextlib.redirect_stdout(output):
            WorkflowGetApprovalRequestsCommand().execute(
                self.params,
                format='json',
                include_approvers=include_approvers,
            )
        return json.loads(output.getvalue()), team_lookup

    def test_json_includes_approval_counts_and_approver_members_when_requested(self):
        result, team_lookup = self._run_pending(include_approvers=True)
        request = result['requests'][0]

        self.assertEqual(request['requested_by'], 'requester@example.com')
        self.assertEqual(request['approvals_needed'], 2)
        self.assertEqual(request['approvals_received'], 1)
        self.assertEqual(
            request['approvers'][0],
            {
                'type': 'user',
                'email': 'user.approver@example.com',
                'escalation': False,
            },
        )
        self.assertEqual(request['approvers'][1]['type'], 'team')
        self.assertEqual(request['approvers'][1]['team_uid'], utils.base64_url_encode(b'team-uid'))
        self.assertEqual(
            request['approvers'][1]['members'],
            ['team.member@example.com'],
        )
        self.assertTrue(request['approvers'][1]['escalation'])
        self.assertIn('escalation_after', request['approvers'][1])
        self.assertNotIn('source', request)
        team_lookup.assert_called_once()

    def test_json_omits_approver_details_without_flag_but_keeps_counts(self):
        result, team_lookup = self._run_pending(include_approvers=False)
        request = result['requests'][0]

        self.assertEqual(request['approvals_needed'], 2)
        self.assertEqual(request['approvals_received'], 1)
        self.assertNotIn('approvers', request)
        team_lookup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
