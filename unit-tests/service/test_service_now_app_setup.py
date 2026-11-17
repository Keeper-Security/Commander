from contextlib import ExitStack
from unittest import TestCase, mock

from keepercommander.cli import aliases, commands, enterprise_commands, msp_commands
from keepercommander.commands.start_service import register_command_info, register_commands
from keepercommander.error import CommandError
from keepercommander.service.commands.service_now_app_setup import (
    ServiceNowAppSetupCommand,
    ServiceNowSetupConstants,
)
from keepercommander.service.commands.integrations.runtime_policy import apply_runtime_command_policy
from keepercommander.service.decorators.min_commander_version import (
    TERRAFORM_DOCKER_ENV,
    TERRAFORM_DOCKER_ENV_LEGACY,
)
from keepercommander.service.docker.models import ServiceConfig
from keepercommander.service.util.exceptions import ValidationError


class TestServiceNowAppSetupCommand(TestCase):
    def test_parser_prog_and_defaults(self):
        parser = ServiceNowAppSetupCommand().get_parser()
        self.assertEqual(parser.prog, 'service-now-app-setup')
        args = parser.parse_args([])
        self.assertEqual(args.folder_name, ServiceNowSetupConstants.DEFAULT_FOLDER_NAME)
        self.assertEqual(args.app_name, ServiceNowSetupConstants.DEFAULT_APP_NAME)
        self.assertEqual(args.record_name, ServiceNowSetupConstants.DEFAULT_RECORD_NAME)

    def test_queue_config_always_enabled(self):
        self.assertTrue(ServiceNowAppSetupCommand()._get_queue_config())

    def test_service_configuration_uses_fixed_commands_and_queue_mode(self):
        cmd = ServiceNowAppSetupCommand()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(cmd, '_get_port_config', return_value=8900))
            stack.enter_context(mock.patch.object(
                cmd, '_get_commands_config', return_value=ServiceNowSetupConstants.SERVICE_COMMANDS
            ))
            ngrok_prompt = stack.enter_context(mock.patch.object(cmd, '_get_ngrok_config'))
            cloudflare_prompt = stack.enter_context(mock.patch.object(cmd, '_get_cloudflare_config'))
            tailscale_prompt = stack.enter_context(mock.patch.object(cmd, '_get_tailscale_config'))
            stack.enter_context(mock.patch.object(cmd, '_get_advanced_security_config', return_value={
                'allowed_ip': '0.0.0.0/0,::/0', 'denied_ip': '', 'rate_limit': '',
                'encryption_enabled': False, 'encryption_key': '', 'token_expiration': '',
            }))
            config = cmd.get_service_configuration(mock.Mock())

        self.assertEqual(config.port, 8900)
        self.assertEqual(config.commands, ServiceNowSetupConstants.SERVICE_COMMANDS)
        self.assertTrue(config.queue_enabled)
        self.assertFalse(config.ngrok_enabled)
        self.assertFalse(config.cloudflare_enabled)
        self.assertFalse(config.tailscale_enabled)
        ngrok_prompt.assert_not_called()
        cloudflare_prompt.assert_not_called()
        tailscale_prompt.assert_not_called()

    @mock.patch('keepercommander.service.commands.service_now_app_setup.RuntimeServiceConfig')
    def test_commands_config_validates_and_sanitizes_against_fixed_allowlist(self, mock_config):
        mock_config.return_value.validate_command_list.return_value = (
            ServiceNowSetupConstants.SERVICE_COMMANDS + ',clipboard-copy'
        )

        params = mock.Mock()
        result = ServiceNowAppSetupCommand()._get_commands_config(params)

        self.assertEqual(result, ServiceNowSetupConstants.SERVICE_COMMANDS)
        mock_config.return_value.validate_command_list.assert_called_once_with(
            ServiceNowSetupConstants.SERVICE_COMMANDS, params
        )

    @mock.patch('keepercommander.service.commands.service_now_app_setup.RuntimeServiceConfig')
    def test_commands_config_wraps_validation_error(self, mock_config):
        mock_config.return_value.validate_command_list.side_effect = ValidationError('bad command')

        with self.assertRaises(CommandError) as ctx:
            ServiceNowAppSetupCommand()._get_commands_config(mock.Mock())

        self.assertEqual(ctx.exception.command, 'service-now-app-setup')
        self.assertIn('bad command', ctx.exception.message)

    @mock.patch('keepercommander.service.commands.service_now_app_setup.RuntimeServiceConfig')
    @mock.patch.object(ServiceNowAppSetupCommand, 'run_setup_steps')
    def test_execute_validates_allowlist_before_setup(self, mock_setup, mock_config):
        mock_config.return_value.validate_command_list.side_effect = ValidationError('bad allowlist')
        with self.assertRaises(CommandError):
            ServiceNowAppSetupCommand().execute(mock.Mock())
        mock_setup.assert_not_called()

    def test_compose_uses_servicenow_service_names_and_not_terraform_marker(self):
        setup_result = mock.Mock(
            folder_uid='f', folder_name='folder', app_uid='a', app_name='app',
            record_uid='record-uid', b64_config='cfg',
        )
        config = ServiceConfig(
            port=8900,
            commands=ServiceNowSetupConstants.SERVICE_COMMANDS,
            queue_enabled=True,
            ngrok_enabled=False,
            ngrok_auth_token='',
            ngrok_custom_domain='',
            cloudflare_enabled=False,
            cloudflare_tunnel_token='',
            cloudflare_custom_domain='',
        )

        yaml_content = ServiceNowAppSetupCommand().generate_docker_compose_yaml(
            setup_result, config
        )

        self.assertIn('commander-servicenow:', yaml_content)
        self.assertIn('container_name: keeper-service-servicenow', yaml_content)
        self.assertIn(f'{ServiceNowSetupConstants.SERVICENOW_RECORD_ENV}:', yaml_content)
        self.assertIn(
            f"{ServiceNowSetupConstants.SERVICENOW_RECORD_ENV}: {setup_result.record_uid}",
            yaml_content,
        )
        self.assertNotIn(TERRAFORM_DOCKER_ENV, yaml_content)
        self.assertNotIn(TERRAFORM_DOCKER_ENV_LEGACY, yaml_content)
        self.assertIn(f"-c '{ServiceNowSetupConstants.SERVICE_COMMANDS}'", yaml_content)
        self.assertNotIn('-ng ', yaml_content)
        self.assertNotIn('-cf ', yaml_content)
        self.assertNotIn('tailscale:', yaml_content)

    def test_runtime_policy_strips_commands_outside_servicenow_allowlist(self):
        class Args:
            commands = ServiceNowSetupConstants.SERVICE_COMMANDS + ',clipboard-copy'

        with mock.patch.dict(
            'os.environ',
            {ServiceNowSetupConstants.SERVICENOW_RECORD_ENV: 'record-uid'},
            clear=True,
        ):
            args = Args()
            apply_runtime_command_policy(args)

        self.assertEqual(args.commands, ServiceNowSetupConstants.SERVICE_COMMANDS)


class TestServiceNowSetupConstants(TestCase):
    def test_allowlist_matches_the_required_commands(self):
        self.assertEqual(
            ServiceNowSetupConstants.SERVICE_COMMANDS_LIST,
            (
                'ls', 'get', 'search', 'sync-down', 'list-sf', 'record-add', 'record-update',
                'nsf-record-add', 'nsf-record-update', 'nsf-share-record', 'nsf-share-folder',
                'share-folder', 'share-record', 'one-time-share', 'epm',
            ),
        )

    def test_allowlist_entries_are_registered_commands(self):
        known = set(commands) | set(enterprise_commands) | set(msp_commands) | set(aliases)
        missing = [
            name for name in ServiceNowSetupConstants.SERVICE_COMMANDS_LIST if name not in known
        ]
        self.assertEqual(missing, [])

    def test_allowlist_has_no_duplicates(self):
        allowed = ServiceNowSetupConstants.SERVICE_COMMANDS_LIST
        self.assertEqual(len(allowed), len(set(allowed)))
        self.assertEqual(ServiceNowSetupConstants.SERVICE_COMMANDS, ','.join(allowed))

    def test_setup_command_is_registered_and_discoverable(self):
        registered = {}
        register_commands(registered)
        self.assertIn('service-now-app-setup', registered)

        descriptions = {}
        register_command_info({}, descriptions)
        self.assertIn('service-now-app-setup', descriptions)
