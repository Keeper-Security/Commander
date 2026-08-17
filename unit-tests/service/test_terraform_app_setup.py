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

from keepercommander.service.commands.terraform_app_setup import (
    TerraformAppSetupCommand,
    TerraformSetupConstants,
)
from keepercommander.service.docker.models import ServiceConfig


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
    def test_allowlist_includes_core_commands(self):
        commands = {
            c.strip()
            for c in TerraformSetupConstants.SERVICE_COMMANDS.split(',')
            if c.strip()
        }
        for expected in (
            'this-device',
            'sync-down',
            'enterprise-user',
            'record-add',
            'nsf-share-record',
            'pam',
            'secrets-manager',
        ):
            self.assertIn(expected, commands)

    def test_allowlist_has_no_duplicate_entries(self):
        parts = [
            c.strip()
            for c in TerraformSetupConstants.SERVICE_COMMANDS.split(',')
            if c.strip()
        ]
        self.assertEqual(len(parts), len(set(parts)))
