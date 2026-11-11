import unittest
from unittest import mock

from keepercommander.service.commands.integrations.slack_app_setup import SlackAppSetupCommand
from keepercommander.service.commands.integrations.teams_app_setup import TeamsAppSetupCommand
from keepercommander.service.docker import (
    ApprovalsConfig,
    SlackConfig,
    TeamsConfig,
    WorkflowApprovalConstants,
)


class TestChatWorkflowSetup(unittest.TestCase):
    def test_prompt_skips_interval_when_workflow_approval_is_disabled(self):
        command = SlackAppSetupCommand()
        with mock.patch.object(command, '_prompt_yes_no', return_value=False) as yes_no, \
                mock.patch('builtins.input') as prompt:
            enabled, interval = command._collect_workflow_approval_config()

        self.assertFalse(enabled)
        self.assertEqual(interval, 120)
        yes_no.assert_called_once_with(
            'Do you want to set up PAM Workflow approval?',
            default=False,
        )
        prompt.assert_not_called()

    def test_prompt_collects_positive_interval_when_enabled(self):
        command = TeamsAppSetupCommand()
        with mock.patch.object(command, '_prompt_yes_no', return_value=True), \
                mock.patch('builtins.input', side_effect=['0', 'not-a-number', '45']):
            enabled, interval = command._collect_workflow_approval_config()

        self.assertTrue(enabled)
        self.assertEqual(interval, 45)

    def test_slack_persists_workflow_approval_config(self):
        command = SlackAppSetupCommand()
        config = SlackConfig(
            slack_app_token='app-token',
            slack_bot_token='bot-token',
            slack_signing_secret='signing-secret',
            approvals=ApprovalsConfig(multi_channel_enabled=False),
            workflow_approval_enabled=True,
            workflow_approval_polling_interval=45,
        )
        fields = {
            field.label: field.get_default_value()
            for field in command.build_record_custom_fields(config)
        }
        self.assertEqual(fields[WorkflowApprovalConstants.FIELD_ENABLED], 'true')
        self.assertEqual(fields[WorkflowApprovalConstants.FIELD_POLLING_INTERVAL], '45')

    def test_teams_persists_workflow_approval_config(self):
        command = TeamsAppSetupCommand()
        config = TeamsConfig(
            client_id='client-id',
            client_secret='client-secret',
            tenant_id='tenant-id',
            approvals_channel_id='channel-id',
            approvals_team_id='team-id',
            workflow_approval_enabled=True,
            workflow_approval_polling_interval=60,
        )
        fields = {
            field.label: field.get_default_value()
            for field in command.build_record_custom_fields(config)
        }
        self.assertEqual(fields[WorkflowApprovalConstants.FIELD_ENABLED], 'true')
        self.assertEqual(fields[WorkflowApprovalConstants.FIELD_POLLING_INTERVAL], '60')

    def test_pam_command_is_only_allowed_when_enabled(self):
        for command in (SlackAppSetupCommand(), TeamsAppSetupCommand()):
            with self.subTest(integration=command.get_integration_name()):
                self.assertNotIn('pam', command.get_allowed_service_commands().split(','))
                self.assertIn('pam', command.get_allowed_service_commands(True).split(','))
                self.assertNotIn(
                    'pam',
                    command.sanitize_service_commands('pam,search').split(','),
                )
                self.assertIn(
                    'pam',
                    command.sanitize_service_commands(
                        'search',
                        workflow_approval_enabled=True,
                    ).split(','),
                )


if __name__ == '__main__':
    unittest.main()
