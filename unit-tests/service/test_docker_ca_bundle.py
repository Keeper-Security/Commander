import os
import tempfile
import unittest
from unittest import mock

from keepercommander.service.docker import DockerComposeBuilder, DockerSetupBase


class TestDockerCaBundle(unittest.TestCase):
    def _builder(self, ca_bundle_path=None):
        setup_result = mock.Mock(b64_config='test-ksm-config', record_uid='commander-record-uid')
        return DockerComposeBuilder(
            setup_result,
            {'port': 8900, 'commands': 'whoami'},
            ca_bundle_path=ca_bundle_path,
        )

    def test_no_ca_path_leaves_default_compose_unchanged(self):
        compose = self._builder().build_dict()
        commander = compose['services']['commander']

        self.assertNotIn('environment', commander)
        self.assertNotIn('volumes', commander)
        self.assertEqual(commander['image'], 'keeper/commander:latest')

    def test_ca_bundle_is_mounted_for_commander_and_integration_service(self):
        with tempfile.NamedTemporaryFile() as ca_file:
            builder = self._builder(ca_file.name)
            builder.add_integration_service(
                service_name='slack-app',
                container_name='keeper-slack-app',
                image='keeper/slack-app:latest',
                record_uid='slack-record-uid',
                record_env_key='SLACK_RECORD',
            )
            compose = builder.build_dict()
            source = os.path.abspath(ca_file.name)

        expected_volume = {
            'type': 'bind',
            'source': source,
            'target': '/certs/keeper-ca-bundle.pem',
            'read_only': True,
        }
        for name in ('commander', 'slack-app'):
            service = compose['services'][name]
            self.assertIn(expected_volume, service['volumes'])
            self.assertEqual(
                service['environment']['KEEPER_SSL_CERT_FILE'],
                '/certs/keeper-ca-bundle.pem',
            )
            self.assertEqual(
                service['environment']['REQUESTS_CA_BUNDLE'],
                '/certs/keeper-ca-bundle.pem',
            )

    def test_prompt_defaults_to_no(self):
        with mock.patch('builtins.input', return_value='') as input_mock:
            self.assertIsNone(DockerSetupBase._prompt_for_docker_ca_bundle())
        input_mock.assert_called_once()

    def test_prompt_collects_and_resolves_ca_path(self):
        with tempfile.NamedTemporaryFile() as ca_file:
            with mock.patch('builtins.input', side_effect=['yes', ca_file.name]):
                result = DockerSetupBase._prompt_for_docker_ca_bundle()

        self.assertEqual(result, os.path.abspath(ca_file.name))

    def test_prompt_allows_path_that_exists_only_on_remote_docker_host(self):
        remote_host_path = '/home/ec2-user/.local/state/keeper/smk-public-endpoint/tls/ca.crt'
        with mock.patch('builtins.input', side_effect=['y', remote_host_path]):
            result = DockerSetupBase._prompt_for_docker_ca_bundle()

        self.assertEqual(result, remote_host_path)

    def test_prompt_retries_when_yes_is_followed_by_blank_path(self):
        with mock.patch('builtins.input', side_effect=['y', '', './ca-bundle.pem']) as input_mock:
            result = DockerSetupBase._prompt_for_docker_ca_bundle()

        self.assertEqual(result, 'ca-bundle.pem')
        self.assertEqual(input_mock.call_count, 3)


if __name__ == '__main__':
    unittest.main()
