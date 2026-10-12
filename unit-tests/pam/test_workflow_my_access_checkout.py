#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
#

"""Tests for checked-out owner enrichment in PAM workflow my-access."""

import io
import json
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.workflow.state_commands import WorkflowGetUserAccessStateCommand
from keepercommander.proto import GraphSync_pb2, workflow_pb2


def _workflow(flow_uid=b'flow-uid', checked_out_by=''):
    workflow = workflow_pb2.WorkflowState()
    workflow.flowUid = flow_uid
    workflow.resource.type = GraphSync_pb2.RFT_REC
    workflow.resource.value = b'record-uid'
    workflow.status.checkedOutBy = checked_out_by
    return workflow


def _state(checked_out_by=''):
    state = workflow_pb2.WorkflowState()
    state.flowUid = b'flow-uid'
    if checked_out_by:
        state.status.checkedOutBy = checked_out_by
    return state


class TestWorkflowMyAccessCheckout(unittest.TestCase):

    def setUp(self):
        self.params = MagicMock()
        self.params.user = 'approver@example.com'

    def test_returns_checkout_owner_from_full_state(self):
        with patch(
            'keepercommander.commands.workflow.state_commands._post_request_to_router',
            return_value=_state('requester@example.com'),
        ) as post:
            checked_out_by = WorkflowGetUserAccessStateCommand._get_checked_out_by(
                self.params, _workflow(),
            )

        self.assertEqual('requester@example.com', checked_out_by)
        post.assert_called_once()
        self.assertEqual('get_workflow_state', post.call_args_list[0].args[1])

    def test_returns_current_user_when_they_checked_out(self):
        with patch(
            'keepercommander.commands.workflow.state_commands._post_request_to_router',
            return_value=_state('APPROVER@example.com'),
        ):
            checked_out_by = WorkflowGetUserAccessStateCommand._get_checked_out_by(
                self.params, _workflow(),
            )

        self.assertEqual('APPROVER@example.com', checked_out_by)

    def test_returns_none_when_checkout_owner_is_missing(self):
        with patch(
            'keepercommander.commands.workflow.state_commands._post_request_to_router',
            return_value=_state(),
        ):
            checked_out_by = WorkflowGetUserAccessStateCommand._get_checked_out_by(
                self.params, _workflow(),
            )

        self.assertIsNone(checked_out_by)

    def test_table_leaves_checkout_owner_blank_when_not_available(self):
        response = workflow_pb2.UserAccessState()
        workflow = response.workflows.add()
        workflow.flowUid = b'flow-uid'
        workflow.resource.value = b'record-uid'

        with patch(
            'keepercommander.commands.workflow.state_commands.RecordResolver.resolve_name',
            return_value='Test record',
        ), patch('sys.stdout', new_callable=io.StringIO) as stdout:
            WorkflowGetUserAccessStateCommand._print_table(self.params, response)

        self.assertNotIn('None', stdout.getvalue())

    def test_execute_prefers_bulk_value_and_falls_back_only_for_missing_values(self):
        response = workflow_pb2.UserAccessState()
        response.workflows.add().CopyFrom(_workflow(b'bulk-flow', 'alice@example.com'))
        response.workflows.add().CopyFrom(_workflow(b'fallback-flow'))
        response.workflows.add().CopyFrom(_workflow(b'failed-flow'))

        fallback_state = _state('bob@example.com')
        mock_router = patch(
            'keepercommander.commands.workflow.state_commands._post_request_to_router',
            side_effect=[response, fallback_state, RuntimeError('router unavailable')],
        )

        with mock_router as post, patch(
            'keepercommander.commands.workflow.state_commands.RecordResolver.resolve_name',
            return_value='Test record',
        ), patch('sys.stdout', new_callable=io.StringIO) as stdout:
            with self.assertLogs(level='WARNING') as logs:
                WorkflowGetUserAccessStateCommand().execute(self.params, format='json')

        result = json.loads(stdout.getvalue())
        owners = {
            workflow['flow_uid']: workflow['checked_out_by']
            for workflow in result['workflows']
        }
        self.assertEqual('alice@example.com', owners['YnVsay1mbG93'])
        self.assertEqual('bob@example.com', owners['ZmFsbGJhY2stZmxvdw'])
        self.assertIsNone(owners['ZmFpbGVkLWZsb3c'])
        self.assertEqual(3, post.call_count)  # bulk fetch plus only two needed fallbacks
        self.assertEqual('get_user_access_state', post.call_args_list[0].args[1])
        self.assertEqual('get_workflow_state', post.call_args_list[1].args[1])
        self.assertEqual('get_workflow_state', post.call_args_list[2].args[1])
        self.assertEqual(1, len(logs.records))
        self.assertIn('1 workflow', logs.output[0])


if __name__ == '__main__':
    unittest.main()
