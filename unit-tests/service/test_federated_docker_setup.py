import base64
import json
import os
import stat
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest import mock

import docker_ksm_utility
from keepercommander.error import CommandError
from keepercommander.display import bcolors
from keepercommander.proto import APIRequest_pb2, enterprise_pb2
from keepercommander.service.core.globals import FEDERATED_LOGIN_COMMANDS
from keepercommander.service.docker.compose_builder import DockerComposeBuilder
from keepercommander.service.docker.federated_setup import (
    FederatedSetupOptions,
    create_federated_config,
    keeper_token_audience,
    remove_managed_federated_client,
    remove_managed_federated_clients,
    read_jwt_claims,
)
from keepercommander.service.docker.models import (
    DockerLoginMode,
    DockerSetupConstants,
    ServiceConfig,
    SetupResult,
)
from keepercommander.service.docker.printer import DockerSetupPrinter
from keepercommander.service.docker.setup_base import DockerSetupBase


def _jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return f'header.{payload}.signature'


class TestFederatedSetup(unittest.TestCase):
    def test_keeper_token_audience_matches_registered_client_audience(self):
        self.assertEqual(
            keeper_token_audience('keepersecurity.com'),
            'https://keepersecurity.com',
        )
        self.assertEqual(
            keeper_token_audience('https://vault.example.test:8443'),
            'https://vault.example.test:8443',
        )

    @mock.patch('keepercommander.service.core.globals.init_globals')
    @mock.patch('keepercommander.service.core.globals.get_current_params', return_value=None)
    @mock.patch('keepercommander.__main__.get_params_from_config')
    def test_service_params_load_respects_config_env_and_initializes_federated_login(
        self, mock_get_params, _get_current_params, _init_globals
    ):
        from keepercommander.service.core.globals import ensure_params_loaded

        params = mock.Mock()
        params.federated_login = None
        mock_get_params.return_value = params
        with mock.patch.dict(os.environ, {
            'KEEPER_CONFIG_FILE': '/tmp/oidc-runtime-config.json',
            'KEEPER_FEDERATED_CONFIG': '/home/commander/.keeper/federated-config.json',
            'KEEPER_OIDC_TOKEN_FILE': '/home/commander/.keeper/oidc-token.jwt',
        }):
            loaded_params = ensure_params_loaded()

        self.assertIs(loaded_params, params)
        mock_get_params.assert_called_once_with('/tmp/oidc-runtime-config.json')
        self.assertIsNotNone(params.federated_login)
        self.assertEqual(
            params.federated_login.federated_config,
            '/home/commander/.keeper/federated-config.json',
        )

    def test_setup_command_parsers_expose_shared_oidc_options(self):
        from keepercommander.service.commands.integrations.gchat_app_setup import GChatAppSetupCommand
        from keepercommander.service.commands.integrations.sailpoint_app_setup import SailPointAppSetupCommand
        from keepercommander.service.commands.integrations.slack_app_setup import SlackAppSetupCommand
        from keepercommander.service.commands.integrations.teams_app_setup import TeamsAppSetupCommand
        from keepercommander.service.commands.service_docker_setup import ServiceDockerSetupCommand
        from keepercommander.service.commands.service_now_app_setup import ServiceNowAppSetupCommand
        from keepercommander.service.commands.terraform_app_setup import TerraformAppSetupCommand

        for command in (
            ServiceDockerSetupCommand(),
            SlackAppSetupCommand(),
            TeamsAppSetupCommand(),
            GChatAppSetupCommand(),
            SailPointAppSetupCommand(),
            TerraformAppSetupCommand(),
            ServiceNowAppSetupCommand(),
        ):
            with self.subTest(command=command.get_parser().prog):
                args = command.get_parser().parse_args([
                    '--login-flow', 'oidc',
                    '--oidc-token-file', '/tmp/provider.jwt',
                    '--oidc-issuer', 'https://id.example.test/',
                    '--oidc-subject', 'client-123@clients',
                ])
                self.assertEqual(args.login_flow, 'oidc')
                self.assertEqual(args.oidc_token_file, '/tmp/provider.jwt')
                self.assertEqual(args.oidc_issuer, 'https://id.example.test/')
                self.assertEqual(args.oidc_subject, 'client-123@clients')

    def test_read_jwt_claims_extracts_issuer_and_subject_without_echoing_token(self):
        token = _jwt({
            'iss': 'https://id.example.test/',
            'sub': 'client-123@clients',
            'exp': int(time.time()) + 3600,
        })
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as token_file:
            token_file.write(token)
            token_path = token_file.name
        try:
            with redirect_stdout(StringIO()):
                claims = read_jwt_claims(token_path, 'test-setup')
        finally:
            os.unlink(token_path)

        self.assertEqual(claims['iss'], 'https://id.example.test/')
        self.assertEqual(claims['sub'], 'client-123@clients')

    def test_read_jwt_claims_rejects_expired_token(self):
        token = _jwt({
            'iss': 'https://id.example.test/',
            'sub': 'client-123@clients',
            'exp': int(time.time()) - 1,
        })
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as token_file:
            token_file.write(token)
            token_path = token_file.name
        try:
            with self.assertRaisesRegex(CommandError, 'already expired'):
                read_jwt_claims(token_path, 'test-setup')
        finally:
            os.unlink(token_path)

    def test_read_jwt_claims_rejects_non_numeric_expiration(self):
        for exp in ('123', True, float('nan')):
            with self.subTest(exp=exp), tempfile.NamedTemporaryFile(
                mode='w', delete=False
            ) as token_file:
                token_file.write(_jwt({
                    'iss': 'https://id.example.test/',
                    'sub': 'client-123@clients',
                    'exp': exp,
                }))
                token_path = token_file.name
            try:
                with self.assertRaisesRegex(CommandError, 'invalid exp claim'):
                    read_jwt_claims(token_path, 'test-setup')
            finally:
                os.unlink(token_path)

    def test_read_jwt_claims_checks_expected_audience(self):
        token = _jwt({
            'iss': 'https://id.example.test/',
            'sub': 'client-123@clients',
            'aud': ['https://other.example.test', 'https://keepersecurity.com'],
        })
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as token_file:
            token_file.write(token)
            token_path = token_file.name
        try:
            output = StringIO()
            with redirect_stdout(output):
                claims = read_jwt_claims(
                    token_path, 'test-setup', 'https://keepersecurity.com'
                )
            self.assertEqual(claims['aud'][-1], 'https://keepersecurity.com')
            self.assertIn('Required JWT audience: https://keepersecurity.com', output.getvalue())

            with self.assertRaisesRegex(CommandError, 'does not include the required Keeper audience'):
                read_jwt_claims(token_path, 'test-setup', 'https://wrong.example.test')
        finally:
            os.unlink(token_path)

    def test_oidc_setup_checks_keeper_audience_before_provisioning(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as token_file:
            token_file.write(_jwt({
                'iss': 'https://id.example.test/',
                'sub': 'client-123@clients',
                'aud': 'https://wrong.example.test',
            }))
            token_path = token_file.name
        try:
            with self.assertRaisesRegex(CommandError, 'required Keeper audience'):
                DockerSetupBase.collect_login_options(
                    login_flow='oidc',
                    oidc_token_file=token_path,
                    keeper_server='keepersecurity.com',
                    command_name='test-setup',
                )
        finally:
            os.unlink(token_path)

    def test_read_jwt_claims_rejects_missing_or_invalid_audience(self):
        for audience in (None, 42, ['https://keepersecurity.com', 42]):
            claims = {
                'iss': 'https://id.example.test/',
                'sub': 'client-123@clients',
            }
            if audience is not None:
                claims['aud'] = audience
            with self.subTest(audience=audience), tempfile.NamedTemporaryFile(
                mode='w', delete=False
            ) as token_file:
                token_file.write(_jwt(claims))
                token_path = token_file.name
            try:
                with self.assertRaisesRegex(CommandError, 'missing or invalid aud claim'):
                    read_jwt_claims(
                        token_path, 'test-setup', 'https://keepersecurity.com'
                    )
            finally:
                os.unlink(token_path)

    def test_read_jwt_claims_rejects_future_or_invalid_not_before(self):
        for nbf in (time.time() + 60, '123', True, float('nan')):
            with self.subTest(nbf=nbf), tempfile.NamedTemporaryFile(
                mode='w', delete=False
            ) as token_file:
                token_file.write(_jwt({
                    'iss': 'https://id.example.test/',
                    'sub': 'client-123@clients',
                    'nbf': nbf,
                }))
                token_path = token_file.name
            try:
                expected_error = 'not valid yet' if isinstance(nbf, float) and nbf > time.time() else 'invalid nbf'
                with self.assertRaisesRegex(CommandError, expected_error):
                    read_jwt_claims(token_path, 'test-setup')
            finally:
                os.unlink(token_path)

    def test_read_jwt_claims_warns_with_chmod_command_for_insecure_permissions(self):
        token = _jwt({'iss': 'https://id.example.test/', 'sub': 'client-123@clients'})
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as token_file:
            token_file.write(token)
            token_path = token_file.name
        try:
            os.chmod(token_path, 0o644)
            output = StringIO()
            with redirect_stdout(output):
                read_jwt_claims(token_path, 'test-setup')
        finally:
            os.unlink(token_path)

        self.assertIn(f'chmod 600 {token_path}', output.getvalue())
        self.assertNotIn('before continuing', output.getvalue())

    @mock.patch('keepercommander.service.docker.federated_setup.KSMCommand.add_federated_client')
    @mock.patch('keepercommander.service.docker.federated_setup.KSMCommand.get_app_info',
                return_value=[mock.Mock(clients=[])])
    def test_federated_client_is_registered_for_vault_session_with_data_key(
        self, _get_app_info, mock_add_client
    ):
        def write_config(**kwargs):
            with open(kwargs['config_file'], 'w', encoding='utf-8') as config_file:
                config_file.write('{"authType":"oauth","dataKey":"secret"}')

        mock_add_client.side_effect = write_config
        with tempfile.TemporaryDirectory() as config_dir:
            with mock.patch(
                'keepercommander.service.docker.federated_setup.utils.get_default_path',
                return_value=config_dir,
            ):
                config_path, client_name = create_federated_config(
                    mock.Mock(),
                    'app-uid',
                    FederatedSetupOptions(
                        token_path='/tmp/provider.jwt',
                        issuer='https://id.example.test/',
                        subject='client-123@clients',
                        jwks_uri='https://id.example.test/.well-known/jwks.json',
                    ),
                    'test-setup',
                )
            try:
                call_kwargs = mock_add_client.call_args.kwargs
                self.assertEqual(call_kwargs['access_type'], 'vault-session')
                self.assertTrue(call_kwargs['include_data_key'])
                self.assertEqual(call_kwargs['issuer'], 'https://id.example.test/')
                self.assertEqual(call_kwargs['subject'], 'client-123@clients')
                self.assertEqual(
                    call_kwargs['jwks_uri'],
                    'https://id.example.test/.well-known/jwks.json',
                )
                self.assertEqual(os.path.dirname(config_path), config_dir)
                self.assertTrue(os.path.basename(config_path).startswith('federated-config-'))
                self.assertEqual(client_name, 'Commander Service Mode - Federated Client')
                self.assertEqual(stat.S_IMODE(os.stat(config_path).st_mode), 0o600)
            finally:
                os.unlink(config_path)

    @mock.patch('keepercommander.service.docker.federated_setup.KSMCommand.remove_client')
    @mock.patch('keepercommander.service.docker.federated_setup.KSMCommand.get_app_info')
    def test_removes_only_setup_managed_vault_session_clients(
        self, mock_get_app_info, mock_remove_client
    ):
        def client(name, auth_type=APIRequest_pb2.APP_CLIENT_AUTH_OAUTH,
                   access_type=APIRequest_pb2.APP_CLIENT_ACCESS_VAULT_SESSION,
                   client_type=enterprise_pb2.GENERAL):
            return SimpleNamespace(
                id=name,
                authType=auth_type,
                allowedAccessType=access_type,
                appClientType=client_type,
            )

        managed_name = DockerSetupConstants.DEFAULT_FEDERATED_CLIENT_NAME
        suffixed_name = f'{managed_name} a1b2c3d4'
        mock_get_app_info.return_value = [SimpleNamespace(clients=[
            client(managed_name),
            client(suffixed_name),
            client('User-created client'),
            client(f'{managed_name} not-a-hex-suffix'),
            client(f'{managed_name} deadbeef', access_type=APIRequest_pb2.APP_CLIENT_ACCESS_SECRETS_MANAGER),
        ])]

        remove_managed_federated_clients(
            mock.Mock(), 'app-uid', keep_client_name=suffixed_name
        )

        mock_remove_client.assert_called_once_with(
            mock.ANY, 'app-uid', [managed_name], force=True
        )

    @mock.patch('keepercommander.service.docker.federated_setup.KSMCommand.remove_client')
    @mock.patch('keepercommander.service.docker.federated_setup.KSMCommand.get_app_info')
    def test_failed_setup_can_revoke_only_its_new_managed_client(
        self, mock_get_app_info, mock_remove_client
    ):
        name = f'{DockerSetupConstants.DEFAULT_FEDERATED_CLIENT_NAME} a1b2c3d4'
        mock_get_app_info.return_value = [SimpleNamespace(clients=[SimpleNamespace(
            id=name,
            authType=APIRequest_pb2.APP_CLIENT_AUTH_OAUTH,
            allowedAccessType=APIRequest_pb2.APP_CLIENT_ACCESS_VAULT_SESSION,
            appClientType=enterprise_pb2.GENERAL,
        )])]

        remove_managed_federated_client(mock.Mock(), 'app-uid', name)

        mock_remove_client.assert_called_once_with(mock.ANY, 'app-uid', [name], force=True)

    @mock.patch('builtins.input', return_value='1')
    def test_config_setup_prompt_explains_both_login_paths(self, mock_input):
        output = StringIO()
        with redirect_stdout(output):
            mode = DockerSetupBase._select_login_mode(None, 'test-setup')

        rendered = output.getvalue()
        self.assertEqual(mode, DockerLoginMode.KSM)
        self.assertIn('Config Setup', rendered)
        self.assertIn('1. Commander config.json', rendered)
        self.assertIn('2. Federated OIDC', rendered)
        prompt = mock_input.call_args.args[0]
        self.assertIn('[Press Enter for 1] (1/2):', prompt)
        self.assertIn(bcolors.OKBLUE, prompt)
        self.assertNotIn('(y/n)', prompt)
        self.assertNotIn('KSM config.json (existing flow)', rendered)
        self.assertNotIn('existing flow', rendered)

    @mock.patch('builtins.input', return_value='2')
    def test_config_setup_prompt_selects_federated_oidc(self, _input):
        with redirect_stdout(StringIO()):
            self.assertEqual(
                DockerSetupBase._select_login_mode(None, 'test-setup'),
                DockerLoginMode.OIDC,
            )

    def test_oidc_jwt_prompt_explains_provider_token_and_expiry(self):
        token = _jwt({
            'iss': 'https://id.example.test/',
            'sub': 'client-123@clients',
            'exp': int(time.time()) + 3600,
        })
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as token_file:
            token_file.write(token)
            token_path = token_file.name
        try:
            output = StringIO()
            with mock.patch('builtins.input', return_value='') as mock_input, redirect_stdout(output):
                mode, options = DockerSetupBase.collect_login_options(
                    login_flow='oidc',
                    oidc_token_file=token_path,
                    command_name='test-setup',
                    default_oidc_token_file='/tmp/.keeper/oidc-token.jwt',
                )
            rendered = output.getvalue()
        finally:
            os.unlink(token_path)

        self.assertEqual(mode, DockerLoginMode.OIDC)
        self.assertEqual(options.token_path, os.path.abspath(token_path))
        self.assertIn('provider-issued JWT', rendered)
        self.assertIn('expires within 24 hours', rendered)
        self.assertNotIn('not refreshed automatically', rendered)
        self.assertEqual(mock_input.call_count, 1)  # JWKS only; iss/sub came from the JWT.
        jwks_prompt = mock_input.call_args.args[0]
        self.assertIn('JWKS URI?', jwks_prompt)
        self.assertIn(bcolors.OKBLUE, jwks_prompt)
        self.assertIn('OIDC JWKS URI (optional)', rendered)

    def test_oidc_jwt_path_defaults_to_current_config_directory(self):
        token = _jwt({
            'iss': 'https://id.example.test/',
            'sub': 'client-123@clients',
        })
        with tempfile.TemporaryDirectory() as config_dir:
            default_token_path = os.path.join(config_dir, 'oidc-token.jwt')
            with open(default_token_path, 'w', encoding='utf-8') as token_file:
                token_file.write(token)
            os.chmod(default_token_path, 0o600)
            output = StringIO()
            with mock.patch('builtins.input', side_effect=['', '']) as mock_input, redirect_stdout(output):
                mode, options = DockerSetupBase.collect_login_options(
                    login_flow='oidc',
                    command_name='test-setup',
                    default_oidc_token_file=default_token_path,
                )

        self.assertEqual(mode, DockerLoginMode.OIDC)
        self.assertEqual(options.token_path, default_token_path)
        self.assertIn(default_token_path, mock_input.call_args_list[0].args[0])
        self.assertIn(bcolors.OKBLUE, mock_input.call_args_list[0].args[0])
        self.assertEqual(mock_input.call_count, 2)  # JWT path and JWKS URI; iss/sub came from JWT.

    def test_oidc_prompts_for_issuer_and_subject_only_when_claims_are_missing(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as token_file:
            token_file.write(_jwt({'aud': 'https://keepersecurity.com'}))
            token_path = token_file.name
        try:
            os.chmod(token_path, 0o600)
            with mock.patch(
                'builtins.input',
                side_effect=['https://id.example.test/', 'client-123@clients', ''],
            ) as mock_input, redirect_stdout(StringIO()):
                mode, options = DockerSetupBase.collect_login_options(
                    login_flow='oidc',
                    oidc_token_file=token_path,
                    command_name='test-setup',
                )
        finally:
            os.unlink(token_path)

        self.assertEqual(mode, DockerLoginMode.OIDC)
        self.assertEqual(options.issuer, 'https://id.example.test/')
        self.assertEqual(options.subject, 'client-123@clients')
        self.assertEqual(mock_input.call_count, 3)
        self.assertTrue(all(bcolors.OKBLUE in call.args[0] for call in mock_input.call_args_list))

    @mock.patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    @mock.patch('keepercommander.service.docker.setup_base.upload_federated_artifacts')
    @mock.patch('keepercommander.service.docker.setup_base.remove_managed_federated_clients')
    @mock.patch('keepercommander.service.docker.setup_base.create_federated_config')
    @mock.patch('keepercommander.service.docker.setup_base.RecordHandler.has_file_storage',
                return_value=True)
    def test_setup_steps_provision_oidc_files_instead_of_config_json(
        self, _has_storage, _create_config, mock_remove_clients, mock_upload, _printer
    ):
        setup = DockerSetupBase()
        options = FederatedSetupOptions(
            token_path='/tmp/provider.jwt',
            issuer='https://id.example.test/',
            subject='client-123@clients',
        )
        with tempfile.TemporaryDirectory() as config_dir:
            federated_config_path = os.path.join(config_dir, 'federated-config.json')
            with open(federated_config_path, 'w', encoding='utf-8') as config_file:
                config_file.write('{"dataKey":"secret"}')
            _create_config.return_value = (
                federated_config_path,
                'Commander Service Mode - Federated Client',
            )
            with (
                mock.patch.object(setup, '_setup_device') as mock_setup_device,
                mock.patch.object(setup, '_create_shared_folder', return_value='folder-uid'),
                mock.patch.object(setup, '_create_config_record', return_value='record-uid'),
                mock.patch.object(setup, '_create_ksm_app', return_value='app-uid'),
                mock.patch.object(setup, '_share_folder_with_app'),
                mock.patch.object(setup, '_create_client_device', return_value='ksm-b64'),
                mock.patch.object(setup, '_upload_config_file') as mock_upload_config,
            ):
                result = setup.run_setup_steps(
                    params=mock.Mock(),
                    folder_name='folder',
                    app_name='app',
                    record_name='record',
                    config_path=os.path.join(config_dir, 'config.json'),
                    timeout='30d',
                    skip_device_setup=True,
                    login_mode=DockerLoginMode.OIDC,
                    federated_options=options,
                    command_name='test-setup',
                )

        mock_setup_device.assert_not_called()
        mock_upload_config.assert_not_called()
        self.assertEqual(
            _create_config.call_args.kwargs['output_dir'],
            config_dir,
        )
        mock_upload.assert_called_once_with(
            mock.ANY, 'record-uid', federated_config_path, '/tmp/provider.jwt', 'test-setup'
        )
        mock_remove_clients.assert_called_once_with(
            mock.ANY, 'app-uid',
            keep_client_name='Commander Service Mode - Federated Client',
        )
        self.assertEqual(result.login_mode, DockerLoginMode.OIDC)
        self.assertEqual(result.cleanup_paths, ['/tmp/provider.jwt'])
        self.assertFalse(os.path.exists(federated_config_path))
        self.assertEqual(result.b64_config, 'ksm-b64')

    @mock.patch('keepercommander.service.docker.setup_base.upload_federated_artifacts',
                side_effect=CommandError('test-setup', 'upload failed'))
    @mock.patch('keepercommander.service.docker.setup_base.remove_managed_federated_client')
    @mock.patch('keepercommander.service.docker.setup_base.create_federated_config')
    @mock.patch('keepercommander.service.docker.setup_base.RecordHandler.has_file_storage',
                return_value=True)
    def test_failed_oidc_upload_removes_local_federated_config(
        self, _has_storage, mock_create_config, mock_remove_client, _upload
    ):
        setup = DockerSetupBase()
        options = FederatedSetupOptions(
            token_path='/tmp/provider.jwt',
            issuer='https://id.example.test/',
            subject='client-123@clients',
        )
        with tempfile.TemporaryDirectory() as config_dir:
            federated_config_path = os.path.join(config_dir, 'federated-config.json')
            with open(federated_config_path, 'w', encoding='utf-8') as config_file:
                config_file.write('{"dataKey":"sensitive"}')
            mock_create_config.return_value = (
                federated_config_path,
                'Commander Service Mode - Federated Client',
            )

            with (
                mock.patch.object(setup, '_setup_device'),
                mock.patch.object(setup, '_create_shared_folder', return_value='folder-uid'),
                mock.patch.object(setup, '_create_config_record', return_value='record-uid'),
                mock.patch.object(setup, '_create_ksm_app', return_value='app-uid'),
                mock.patch.object(setup, '_share_folder_with_app'),
                mock.patch.object(setup, '_create_client_device', return_value='ksm-b64'),
            ):
                with redirect_stdout(StringIO()), self.assertRaisesRegex(
                    CommandError, 'upload failed'
                ):
                    setup.run_setup_steps(
                        params=mock.Mock(),
                        folder_name='folder',
                        app_name='app',
                        record_name='record',
                        config_path=os.path.join(config_dir, 'config.json'),
                        timeout='30d',
                        login_mode=DockerLoginMode.OIDC,
                        federated_options=options,
                        command_name='test-setup',
                    )

            self.assertFalse(os.path.exists(federated_config_path))
            mock_remove_client.assert_called_once_with(
                mock.ANY, 'app-uid', 'Commander Service Mode - Federated Client'
            )

    @mock.patch('keepercommander.service.docker.setup_base.RecordHandler.has_file_storage',
                return_value=True)
    def test_config_flow_removes_old_managed_federated_clients_after_upload(
        self, _has_storage
    ):
        setup = DockerSetupBase()
        events = []
        with (
            mock.patch.object(setup, '_create_shared_folder', return_value='folder-uid'),
            mock.patch.object(setup, '_create_config_record', return_value='record-uid'),
            mock.patch.object(setup, '_create_ksm_app', return_value='app-uid'),
            mock.patch.object(setup, '_share_folder_with_app'),
            mock.patch.object(setup, '_create_client_device', return_value='ksm-b64'),
            mock.patch.object(setup, '_upload_config_file', side_effect=lambda *args: events.append('upload')),
            mock.patch(
                'keepercommander.service.docker.setup_base.remove_managed_federated_clients',
                side_effect=lambda *args, **kwargs: events.append('revoke'),
            ),
        ):
            setup.run_setup_steps(
                params=mock.Mock(),
                folder_name='folder',
                app_name='app',
                record_name='record',
                config_path='/tmp/config.json',
                timeout='30d',
                skip_device_setup=True,
                login_mode=DockerLoginMode.KSM,
                command_name='test-setup',
            )

        self.assertEqual(events, ['upload', 'revoke'])


class TestFederatedDockerCompose(unittest.TestCase):
    def _config(self):
        return {
            'port': 8900,
            'commands': 'tree,ls',
            'queue_enabled': True,
            'ngrok_enabled': False,
            'ngrok_auth_token': '',
            'ngrok_custom_domain': '',
            'cloudflare_enabled': False,
            'cloudflare_tunnel_token': '',
            'cloudflare_custom_domain': '',
        }

    def _setup_result(self, login_mode):
        return SetupResult(
            folder_uid='folder-uid',
            folder_name='folder',
            app_uid='app-uid',
            app_name='app',
            record_uid='docker-record',
            b64_config='ksm-b64',
            login_mode=login_mode,
        )

    def test_oidc_environment_is_only_added_to_commander_service(self):
        setup_result = self._setup_result(DockerLoginMode.OIDC)
        builder = DockerComposeBuilder(
            setup_result,
            self._config(),
            commander_environment={'SLACK_RECORD': 'slack-record'},
        )
        result = builder.add_integration_service(
            service_name='slack-app',
            container_name='keeper-slack-app',
            image='keeper/slack-app:latest',
            record_uid='slack-record',
            record_env_key='SLACK_RECORD',
        ).build_dict()

        commander_env = result['services']['commander']['environment']
        sidecar_env = result['services']['slack-app']['environment']
        self.assertEqual(
            commander_env[DockerSetupConstants.FEDERATED_CONFIG_ENV],
            DockerSetupConstants.FEDERATED_CONFIG_CONTAINER_PATH,
        )
        self.assertEqual(
            commander_env[DockerSetupConstants.OIDC_TOKEN_ENV],
            DockerSetupConstants.OIDC_TOKEN_CONTAINER_PATH,
        )
        self.assertEqual(sidecar_env['KSM_CONFIG'], 'ksm-b64')
        self.assertEqual(sidecar_env['COMMANDER_RECORD'], 'docker-record')
        self.assertNotIn(DockerSetupConstants.FEDERATED_CONFIG_ENV, sidecar_env)
        self.assertNotIn(DockerSetupConstants.OIDC_TOKEN_ENV, sidecar_env)

    def test_ksm_environment_remains_unchanged_for_existing_flow(self):
        setup_result = self._setup_result(DockerLoginMode.KSM)
        result = DockerComposeBuilder(setup_result, self._config()).build_dict()
        environment = result['services']['commander'].get('environment', {})
        self.assertNotIn(DockerSetupConstants.FEDERATED_CONFIG_ENV, environment)
        self.assertNotIn(DockerSetupConstants.OIDC_TOKEN_ENV, environment)
        self.assertIn('--ksm-config ksm-b64', result['services']['commander']['command'])

    def test_specialized_compose_builders_keep_oidc_on_commander(self):
        from keepercommander.service.commands.service_now_app_setup import ServiceNowAppSetupCommand
        from keepercommander.service.commands.terraform_app_setup import TerraformAppSetupCommand

        setup_result = self._setup_result(DockerLoginMode.OIDC)
        config = ServiceConfig(
            port=8900,
            commands='tree,ls',
            queue_enabled=True,
            ngrok_enabled=False,
            ngrok_auth_token='',
            ngrok_custom_domain='',
            cloudflare_enabled=False,
            cloudflare_tunnel_token='',
            cloudflare_custom_domain='',
        )

        for command in (ServiceNowAppSetupCommand(), TerraformAppSetupCommand()):
            with self.subTest(command=type(command).__name__):
                compose = command.generate_docker_compose_yaml(setup_result, config)
                self.assertIn(
                    f'{DockerSetupConstants.FEDERATED_CONFIG_ENV}: '
                    f'{DockerSetupConstants.FEDERATED_CONFIG_CONTAINER_PATH}',
                    compose,
                )
                self.assertIn(
                    f'{DockerSetupConstants.OIDC_TOKEN_ENV}: '
                    f'{DockerSetupConstants.OIDC_TOKEN_CONTAINER_PATH}',
                    compose,
                )

    def test_oidc_cleanup_keeps_local_commander_config(self):
        output = StringIO()
        with redirect_stdout(output):
            DockerSetupPrinter.print_common_deployment_steps(
                '8900',
                '/home/user/.keeper/config.json',
                login_mode=DockerLoginMode.OIDC,
                cleanup_paths=['/tmp/provider.jwt'],
            )

        rendered = output.getvalue()
        self.assertIn('Step 2: Remove the local JWT file', rendered)
        self.assertIn('rm /tmp/provider.jwt', rendered)
        self.assertNotIn('federated-config.json', rendered)
        self.assertIn('Keep your local config.json for normal Commander login', rendered)
        self.assertNotIn('rm /home/user/.keeper/config.json', rendered)

    def test_ksm_cleanup_instruction_is_unchanged(self):
        output = StringIO()
        with redirect_stdout(output):
            DockerSetupPrinter.print_common_deployment_steps(
                '8900',
                '/home/user/.keeper/config.json',
                login_mode=DockerLoginMode.KSM,
            )
        rendered = output.getvalue()
        self.assertIn('rm /home/user/.keeper/config.json', rendered)
        self.assertNotIn('federated login files', rendered)

    def test_service_status_is_in_federated_login_command_allowlist(self):
        self.assertIn('service-status', FEDERATED_LOGIN_COMMANDS)


class TestDockerKsmOidcAttachmentDownload(unittest.TestCase):
    @mock.patch('docker_ksm_utility.validate_file_path')
    @mock.patch('docker_ksm_utility._get_secret_by_uid_or_title')
    @mock.patch('docker_ksm_utility._initialize_secrets_manager')
    @mock.patch('docker_ksm_utility.check_ksm_dependency', return_value=True)
    def test_downloads_exact_attachment_with_private_permissions(
        self, _dependency, mock_initialize, mock_get_secret, mock_validate
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, 'oidc-token.jwt')
            permissions_during_save = []

            class FakeFile:
                name = 'oidc-token.jwt'

                @staticmethod
                def save_file(path, _force):
                    with open(path, 'w', encoding='utf-8') as token_file:
                        token_file.write('header.payload.signature')
                    permissions_during_save.append(
                        stat.S_IMODE(os.stat(path).st_mode)
                    )

            mock_validate.side_effect = [(True, 'ksm-config.json'), (True, output_path)]
            mock_initialize.return_value = object()
            mock_get_secret.return_value = mock.Mock(files=[FakeFile()])

            self.assertTrue(docker_ksm_utility.download_attachment(
                'ksm-config.json',
                None,
                'record-uid',
                'oidc-token.jwt',
                output_path,
            ))
            self.assertEqual(
                stat.S_IMODE(os.stat(output_path).st_mode),
                0o600,
            )
            self.assertEqual(permissions_during_save, [0o600])
            mock_initialize.assert_called_once_with('ksm-config.json', None)
            self.assertEqual(mock_validate.call_count, 2)

    @mock.patch('docker_ksm_utility.validate_file_path', return_value=(True, '/tmp/token.jwt'))
    @mock.patch('docker_ksm_utility._initialize_secrets_manager')
    @mock.patch('docker_ksm_utility.check_ksm_dependency', return_value=True)
    def test_rejects_ambiguous_duplicate_attachment_names(
        self, _dependency, mock_initialize, _validate
    ):
        mock_initialize.return_value = object()
        fake_file = mock.Mock(name='oidc-token.jwt')
        fake_file.name = 'oidc-token.jwt'
        mock_secret = mock.Mock(files=[fake_file, fake_file])
        with mock.patch(
            'docker_ksm_utility._get_secret_by_uid_or_title',
            return_value=mock_secret,
        ):
            with redirect_stdout(StringIO()):
                self.assertFalse(docker_ksm_utility.download_attachment(
                    'ksm-config.json',
                    None,
                    'record-uid',
                    'oidc-token.jwt',
                    '/tmp/token.jwt',
                ))

    @mock.patch('docker_ksm_utility.validate_file_path')
    @mock.patch('docker_ksm_utility._initialize_secrets_manager')
    @mock.patch('docker_ksm_utility.check_ksm_dependency', return_value=True)
    def test_rejects_and_removes_empty_oidc_attachment(
        self, _dependency, mock_initialize, mock_validate
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, 'oidc-token.jwt')

            class EmptyFile:
                name = 'oidc-token.jwt'

                @staticmethod
                def save_file(path, _force):
                    with open(path, 'wb'):
                        pass

            mock_validate.side_effect = [
                (True, 'ksm-config.json'),
                (True, output_path),
            ]
            mock_initialize.return_value = object()
            with mock.patch(
                'docker_ksm_utility._get_secret_by_uid_or_title',
                return_value=mock.Mock(files=[EmptyFile()]),
            ), redirect_stdout(StringIO()):
                self.assertFalse(docker_ksm_utility.download_attachment(
                    'ksm-config.json',
                    None,
                    'record-uid',
                    'oidc-token.jwt',
                    output_path,
                ))

            self.assertFalse(os.path.exists(output_path))


if __name__ == '__main__':
    unittest.main()
