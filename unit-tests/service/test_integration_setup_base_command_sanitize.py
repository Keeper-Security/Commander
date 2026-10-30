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

import os
import re
import tempfile
import unittest

from keepercommander.service.commands.integrations.gchat_app_setup import GChatAppSetupCommand
from keepercommander.service.docker.models import ServiceConfig, SetupResult

_COMMAND_LIST_RE = re.compile(r"-c '([^']*)'")


class TestIntegrationSetupBaseCommandSanitize(unittest.TestCase):
    """A tampered/injected commands string must be confined to the integration's own get_service_commands() list."""

    def _make_service_config(self, commands):
        return ServiceConfig(
            port=8900,
            commands=commands,
            queue_enabled=True,
            ngrok_enabled=False,
            ngrok_auth_token='',
            ngrok_custom_domain='',
            cloudflare_enabled=False,
            cloudflare_tunnel_token='',
            cloudflare_custom_domain='',
        )

    def test_update_docker_compose_strips_commands_outside_allowlist(self):
        cmd = GChatAppSetupCommand()
        allowed = set(cmd.get_service_commands().split(','))

        setup_result = SetupResult(
            folder_uid='folder-uid', folder_name='folder', app_uid='app-uid',
            app_name='app', record_uid='setup-record-uid', b64_config='cfg',
        )
        tampered_commands = cmd.get_service_commands() + ',malicious-command,rm'
        service_config = self._make_service_config(tampered_commands)

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.chdir(tmp_dir)
            try:
                cmd._update_docker_compose(setup_result, service_config, 'integration-record-uid')
                with open(os.path.join(tmp_dir, 'docker-compose.yml')) as f:
                    yaml_content = f.read()
            finally:
                os.chdir(cwd)

        match = _COMMAND_LIST_RE.search(yaml_content)
        self.assertIsNotNone(match)
        written_commands = set(match.group(1).split(','))

        self.assertNotIn('malicious-command', written_commands)
        self.assertNotIn('rm', written_commands)
        self.assertEqual(written_commands, allowed)

    def test_update_docker_compose_adds_ca_to_both_services_when_requested(self):
        cmd = GChatAppSetupCommand()
        setup_result = SetupResult(
            folder_uid='folder-uid', folder_name='folder', app_uid='app-uid',
            app_name='app', record_uid='setup-record-uid', b64_config='cfg',
        )
        ca_path = '/home/ec2-user/smk/ca-bundle.pem'

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.chdir(tmp_dir)
            try:
                cmd._update_docker_compose(
                    setup_result,
                    self._make_service_config(cmd.get_service_commands()),
                    'integration-record-uid',
                    ca_bundle_path=ca_path,
                )
                with open(os.path.join(tmp_dir, 'docker-compose.yml')) as f:
                    yaml_content = f.read()
            finally:
                os.chdir(cwd)

        self.assertEqual(yaml_content.count(f'source: {ca_path}'), 2)
        self.assertEqual(yaml_content.count('KEEPER_SSL_CERT_FILE: /certs/keeper-ca-bundle.pem'), 2)
        self.assertEqual(yaml_content.count('REQUESTS_CA_BUNDLE: /certs/keeper-ca-bundle.pem'), 2)
        self.assertEqual(yaml_content.count('NODE_EXTRA_CA_CERTS: /certs/keeper-ca-bundle.pem'), 2)


if __name__ == '__main__':
    unittest.main()
