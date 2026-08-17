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

from unittest import TestCase, mock

from keepercommander.cli import aliases, commands, enterprise_commands, msp_commands
from keepercommander.error import CommandError
from keepercommander.service.commands.terraform_app_setup import (
    TerraformAppSetupCommand,
    TerraformSetupConstants,
)
from keepercommander.service.docker.models import ServiceConfig
from keepercommander.service.util.exceptions import ValidationError


class TestTerraformAppSetupCommand(TestCase):
    def test_parser_prog_and_defaults(self):
        cmd = TerraformAppSetupCommand()
        parser = cmd.get_parser()
        self.assertEqual(parser.prog, 'terraform-app-setup')
        args = parser.parse_args([])
        self.assertEqual(args.folder_name, TerraformSetupConstants.DEFAULT_FOLDER_NAME)
        self.assertEqual(args.app_name, TerraformSetupConstants.DEFAULT_APP_NAME)
        self.assertEqual(args.record_name, TerraformSetupConstants.DEFAULT_RECORD_NAME)

    def test_queue_config_always_enabled(self):
        self.assertTrue(TerraformAppSetupCommand()._get_queue_config())

    @mock.patch(
        'keepercommander.service.commands.terraform_app_setup.RuntimeServiceConfig'
    )
    def test_commands_config_uses_fixed_allowlist(self, mock_runtime_config):
        mock_runtime_config.return_value.validate_command_list.return_value = (
            TerraformSetupConstants.SERVICE_COMMANDS
        )
        cmd = TerraformAppSetupCommand()
        params = mock.Mock()
        result = cmd._get_commands_config(params)
        self.assertEqual(result, TerraformSetupConstants.SERVICE_COMMANDS)
        mock_runtime_config.return_value.validate_command_list.assert_called_once_with(
            TerraformSetupConstants.SERVICE_COMMANDS, params
        )

    @mock.patch(
        'keepercommander.service.commands.terraform_app_setup.RuntimeServiceConfig'
    )
    def test_commands_config_wraps_validation_error(self, mock_runtime_config):
        mock_runtime_config.return_value.validate_command_list.side_effect = ValidationError(
            'bad command'
        )
        with self.assertRaises(CommandError) as ctx:
            TerraformAppSetupCommand()._get_commands_config(mock.Mock())
        self.assertEqual(ctx.exception.command, 'terraform-app-setup')
        self.assertIn('bad command', ctx.exception.message)

    @mock.patch.object(TerraformAppSetupCommand, 'run_setup_steps')
    @mock.patch.object(
        TerraformAppSetupCommand,
        '_validate_terraform_commands',
        side_effect=CommandError('terraform-app-setup', 'bad allowlist'),
    )
    def test_execute_validates_allowlist_before_setup(self, _mock_validate, mock_setup):
        with self.assertRaises(CommandError):
            TerraformAppSetupCommand().execute(mock.Mock())
        mock_setup.assert_not_called()

    @mock.patch.object(TerraformAppSetupCommand, '_get_advanced_security_config')
    @mock.patch.object(TerraformAppSetupCommand, '_get_cloudflare_config')
    @mock.patch.object(TerraformAppSetupCommand, '_get_ngrok_config')
    @mock.patch.object(TerraformAppSetupCommand, '_get_port_config', return_value=8900)
    @mock.patch.object(
        TerraformAppSetupCommand,
        '_get_commands_config',
        return_value=TerraformSetupConstants.SERVICE_COMMANDS,
    )
    def test_service_configuration_always_enables_queue(
        self,
        _mock_commands,
        _mock_port,
        mock_ngrok,
        mock_cf,
        mock_security,
    ):
        mock_ngrok.return_value = {
            'ngrok_enabled': False,
            'ngrok_auth_token': '',
            'ngrok_custom_domain': '',
            'ngrok_public_url': '',
        }
        mock_cf.return_value = {
            'cloudflare_enabled': False,
            'cloudflare_tunnel_token': '',
            'cloudflare_custom_domain': '',
            'cloudflare_public_url': '',
        }
        mock_security.return_value = {
            'allowed_ip': '0.0.0.0/0,::/0',
            'denied_ip': '',
            'rate_limit': '',
            'encryption_enabled': False,
            'encryption_key': '',
            'token_expiration': '',
        }

        cmd = TerraformAppSetupCommand()
        config = cmd.get_service_configuration(params=mock.Mock())

        self.assertIsInstance(config, ServiceConfig)
        self.assertTrue(config.queue_enabled)
        self.assertEqual(config.commands, TerraformSetupConstants.SERVICE_COMMANDS)
        self.assertEqual(config.port, 8900)
        mock_security.assert_called_once()


class TestTerraformSetupConstants(TestCase):
    def test_allowlist_entries_are_registered_commands(self):
        known = set(commands) | set(enterprise_commands) | set(msp_commands) | set(aliases)
        missing = [
            name for name in TerraformSetupConstants.SERVICE_COMMANDS_LIST
            if name not in known
        ]
        self.assertEqual(missing, [])

    def test_allowlist_has_no_duplicate_entries(self):
        parts = TerraformSetupConstants.SERVICE_COMMANDS_LIST
        self.assertEqual(len(parts), len(set(parts)))
        self.assertEqual(
            TerraformSetupConstants.SERVICE_COMMANDS,
            ','.join(TerraformSetupConstants.SERVICE_COMMANDS_LIST),
        )
