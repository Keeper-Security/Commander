import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from keepercommander.commands.start_service import register_commands, register_command_info
from keepercommander.service.commands.integrations.integration_setup_base import IntegrationSetupCommand
from keepercommander.service.commands.integrations.zoom_app_setup import (
    ZoomAppSetupCommand,
    is_valid_public_endpoint_url,
)
from keepercommander.service.docker import ServiceConfig, SetupResult, ZoomConfig, ZoomConstants


class TestZoomAppSetupCommand(unittest.TestCase):

    def setUp(self):
        self.command = ZoomAppSetupCommand()

    def _config(self):
        return ZoomConfig(
            client_id='client-id',
            client_secret='client-secret',
            bot_jid='bot@example.com',
            secret_token='secret-token',
            approvals_channel_jid='approvals@example.com',
            public_endpoint_url='https://abc123.ngrok.app/zoom/webhook',
        )

    def test_command_is_registered_and_has_description(self):
        commands = {}
        register_commands(commands)
        self.assertIsInstance(commands['zoom-app-setup'], ZoomAppSetupCommand)

        command_info = {}
        register_command_info({}, command_info)
        self.assertIn('zoom-app-setup', command_info)

    def test_command_uses_integration_setup_flow_and_zoom_defaults(self):
        self.assertIsInstance(self.command, IntegrationSetupCommand)
        self.assertEqual(self.command.get_integration_name(), 'Zoom')
        self.assertEqual(self.command.get_integration_display_name(), 'Zoom Chat')
        self.assertEqual(self.command.get_command_name(), 'zoom-app-setup')
        self.assertEqual(self.command.get_docker_service_name(), 'zoom-app')
        self.assertEqual(self.command.get_docker_container_name(), 'keeper-zoom-app')
        self.assertEqual(self.command.get_docker_image(), 'keeper/zoom-app:latest')
        self.assertEqual(self.command.get_record_env_key(), 'ZOOM_RECORD')
        self.assertEqual(
            self.command.get_default_folder_name(),
            'Commander Service Mode - Zoom Chat App',
        )
        self.assertEqual(self.command.get_parser().prog, 'zoom-app-setup')

    def test_parser_inherits_common_setup_options(self):
        args = self.command.get_parser().parse_args([
            '--config-path', '/tmp/config.json',
            '--zoom-record-name', 'Zoom Config',
            '--skip-device-setup',
        ])
        self.assertEqual(args.config_path, '/tmp/config.json')
        self.assertEqual(args.integration_record_name, 'Zoom Config')
        self.assertTrue(args.skip_device_setup)

    def test_public_endpoint_validation(self):
        self.assertTrue(is_valid_public_endpoint_url('https://xyz.ngrok.app'))
        self.assertTrue(
            is_valid_public_endpoint_url('https://keeper.example.com:8443/zoom/webhook')
        )
        self.assertFalse(is_valid_public_endpoint_url('http://keeper.example.com'))
        self.assertFalse(is_valid_public_endpoint_url('https://localhost:3000'))
        self.assertFalse(is_valid_public_endpoint_url('https://192.168.1.2'))
        self.assertFalse(is_valid_public_endpoint_url('https://not-a-domain'))
        self.assertFalse(is_valid_public_endpoint_url('https://example.com:bad'))
        self.assertFalse(is_valid_public_endpoint_url('https://example.com:'))
        self.assertFalse(is_valid_public_endpoint_url('https://user:password@example.com'))
        self.assertFalse(is_valid_public_endpoint_url('https://example.com/path#fragment'))

    def test_collects_required_zoom_values_and_retries_empty_values(self):
        responses = [
            '', 'client-id',
            'bot@example.com',
            'approvals@example.com',
            'https://abc123.ngrok.app/zoom/webhook',
        ]
        with mock.patch('builtins.input', side_effect=responses) as input_prompt, \
                mock.patch(
                    'getpass.getpass',
                    side_effect=['client-secret', 'secret-token'],
                ) as secret_prompt:
            config = self.command.collect_integration_config(None)
        self.assertEqual(config, self._config())
        self.assertEqual(input_prompt.call_count, len(responses))
        self.assertEqual(secret_prompt.call_count, 2)
        self.assertIn('Client Secret:', secret_prompt.call_args_list[0].args[0])
        self.assertIn('Secret Token:', secret_prompt.call_args_list[1].args[0])

    def test_builds_vault_record_fields_with_secrets_protected(self):
        fields = {
            field.label: field.get_default_value()
            for field in self.command.build_record_custom_fields(self._config())
        }
        self.assertEqual(fields[ZoomConstants.FIELD_CLIENT_ID], 'client-id')
        self.assertEqual(fields[ZoomConstants.FIELD_CLIENT_SECRET], 'client-secret')
        self.assertEqual(fields[ZoomConstants.FIELD_BOT_JID], 'bot@example.com')
        self.assertEqual(fields[ZoomConstants.FIELD_SECRET_TOKEN], 'secret-token')
        self.assertEqual(
            fields[ZoomConstants.FIELD_APPROVALS_CHANNEL_JID],
            'approvals@example.com',
        )
        self.assertEqual(
            fields[ZoomConstants.FIELD_PUBLIC_ENDPOINT_URL],
            'https://abc123.ngrok.app/zoom/webhook',
        )

    def test_compose_contains_zoom_and_commander_services(self):
        setup_result = SetupResult(
            folder_uid='folder-uid',
            folder_name='folder',
            app_uid='app-uid',
            app_name='app',
            record_uid='commander-record-uid',
            b64_config='base64-config',
        )
        service_config = ServiceConfig(
            port=8900,
            commands=self.command.get_service_commands(),
            queue_enabled=True,
            ngrok_enabled=False,
            ngrok_auth_token='',
            ngrok_custom_domain='',
            cloudflare_enabled=False,
            cloudflare_tunnel_token='',
            cloudflare_custom_domain='',
        )

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.chdir(tmp_dir)
            try:
                self.command._update_docker_compose(
                    setup_result, service_config, 'zoom-record-uid', self._config()
                )
                compose = yaml.safe_load(Path('docker-compose.yml').read_text(encoding='utf-8'))
            finally:
                os.chdir(cwd)

        services = compose['services']
        self.assertIn('commander-zoom', services)
        zoom_service = services['zoom-app']
        self.assertEqual(zoom_service['image'], 'keeper/zoom-app:latest')
        self.assertEqual(zoom_service['ports'], ['3000:3000'])
        self.assertEqual(zoom_service['environment']['ZOOM_RECORD'], 'zoom-record-uid')
        self.assertEqual(
            services['commander-zoom']['environment']['ZOOM_RECORD'],
            'zoom-record-uid',
        )


if __name__ == '__main__':
    unittest.main()
