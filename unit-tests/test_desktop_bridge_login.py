import sys
import types
import base64
from unittest import TestCase, mock


def _install_test_import_stubs():
    zxcvbn_module = types.ModuleType('zxcvbn')
    zxcvbn_module.zxcvbn = lambda _: {'score': 0}
    sys.modules.setdefault('zxcvbn', zxcvbn_module)

    try:
        import google
        from google.protobuf import descriptor_pb2, descriptor_pool
    except Exception:
        return

    pool = descriptor_pool.Default()

    def has_file(name):
        try:
            pool.FindFileByName(name)
            return True
        except Exception:
            return False

    if not has_file('google/api/http.proto'):
        http_proto = descriptor_pb2.FileDescriptorProto()
        http_proto.name = 'google/api/http.proto'
        http_proto.package = 'google.api'
        http_proto.syntax = 'proto3'
        http_rule = http_proto.message_type.add()
        http_rule.name = 'HttpRule'

        def add_http_rule_field(name, number, field_type):
            field = http_rule.field.add()
            field.name = name
            field.number = number
            field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
            field.type = field_type
            return field

        add_http_rule_field('selector', 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        add_http_rule_field('get', 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        add_http_rule_field('put', 3, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        add_http_rule_field('post', 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        add_http_rule_field('delete', 5, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        add_http_rule_field('patch', 6, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        add_http_rule_field('body', 7, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        additional_bindings = add_http_rule_field(
            'additional_bindings',
            11,
            descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        )
        additional_bindings.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
        additional_bindings.type_name = '.google.api.HttpRule'
        add_http_rule_field('response_body', 12, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        pool.AddSerializedFile(http_proto.SerializeToString())

    if not has_file('google/api/annotations.proto'):
        annotations_proto = descriptor_pb2.FileDescriptorProto()
        annotations_proto.name = 'google/api/annotations.proto'
        annotations_proto.package = 'google.api'
        annotations_proto.syntax = 'proto3'
        annotations_proto.dependency.extend(['google/protobuf/descriptor.proto', 'google/api/http.proto'])
        http_extension = annotations_proto.extension.add()
        http_extension.name = 'http'
        http_extension.number = 72295728
        http_extension.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
        http_extension.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
        http_extension.type_name = '.google.api.HttpRule'
        http_extension.extendee = '.google.protobuf.MethodOptions'
        pool.AddSerializedFile(annotations_proto.SerializeToString())

    api_module = sys.modules.setdefault('google.api', types.ModuleType('google.api'))
    setattr(google, 'api', api_module)
    annotations_module = types.ModuleType('google.api.annotations_pb2')
    annotations_module.DESCRIPTOR = pool.FindFileByName('google/api/annotations.proto')
    setattr(api_module, 'annotations_pb2', annotations_module)
    sys.modules.setdefault('google.api.annotations_pb2', annotations_module)


_install_test_import_stubs()

from keepercommander import __main__ as keeper_main
from keepercommander import cli, crypto, rest_api, utils
from keepercommander.auth import desktop_bridge
from keepercommander.commands import utils as command_utils
from keepercommander.commands.base import ParseError
from keepercommander.commands.pam_launch import launch_cache
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams


class _VaultAccountBinding:
    def __init__(self, vault_account_uid, username=None, email=None):
        self.vault_account_uid = vault_account_uid
        self.username = username
        self.email = email


class _VaultBootstrapResult:
    def __init__(self, vault_session_token, server=None, expires_in_ms=None, request_id=None,
                 vault_account_binding=None, ka_server=None):
        self.vault_session_token = vault_session_token
        self.server = server
        self.ka_server = ka_server
        self.expires_in_ms = expires_in_ms
        self.request_id = request_id or 'test-request-id'
        if vault_account_binding is not None:
            self.vault_account_binding = vault_account_binding


class _FakeBridgeClient:
    module = None

    def exchange_vault_token(self, request):
        self.module.last_request = request
        if self.module.error:
            raise self.module.error
        return self.module.vault_result


class _FakeBridgeError(Exception):
    def __init__(self):
        super().__init__('vault is locked')
        self.kind = 'vault_locked'
        self.code = 'KDBC_VAULT_LOCKED'
        self.retryable = True
        self.actor = 'vault'
        self.message = 'vault is locked'
        self.request_id = 'request-1'


def _make_bridge_module(vault_result=None, error=None):
    module = types.SimpleNamespace()
    module.last_request = None
    module.vault_result = vault_result
    module.error = error
    module.store_load_result = None
    module.store_load_error = None
    module.store_init_error = None
    module.store_save_error = None
    module.store_prepare_error = None
    module.store_prepare_unavailable_after_registrar = False
    module.store_prepare_result = None
    module.store_prepare_calls = []
    module.store_saved = []
    module.store_deleted = []
    coordinator_private_key, coordinator_public_key = crypto.generate_ec_key()
    module.coordinator_device_private_key = crypto.unload_ec_private_key(coordinator_private_key)
    module.coordinator_device_public_key = crypto.unload_ec_public_key(coordinator_public_key)

    class ClientIdentity:
        def __init__(self, name, version, kind, ka_client_version=None):
            self.name = name
            self.version = version
            self.kind = kind
            self.ka_client_version = ka_client_version

    class DeviceCredentials:
        def __init__(self, encrypted_device_token, device_private_key, device_public_key=None):
            self.encrypted_device_token = encrypted_device_token
            self.device_private_key = device_private_key
            self.device_public_key = device_public_key

    class DeviceCredentialStoreUnavailableError(Exception):
        def __init__(self, message='store unavailable'):
            super().__init__(message)
            self.kind = 'device_credential_store_unavailable'
            self.code = 'KDBC_DEVICE_CREDENTIAL_STORE_UNAVAILABLE'
            self.actor = 'leaf'
            self.retryable = False

    class DeviceCredentialStoreAuthFailedError(Exception):
        def __init__(self, message='store authentication denied'):
            super().__init__(message)
            self.kind = 'device_credential_store_auth_failed'
            self.code = 'KDBC_DEVICE_CREDENTIAL_STORE_AUTH_FAILED'
            self.actor = 'leaf'
            self.retryable = False

    class KARegistrationFailedError(Exception):
        def __init__(self, message='KA registration failed'):
            super().__init__(message)
            self.message = message
            self.kind = 'ka_registration_failed'
            self.code = 'KDBC_KA_REGISTRATION_FAILED'
            self.actor = 'ka'
            self.retryable = False

    class BootstrapDeviceNotForThisAccountError(Exception):
        def __init__(self, message='device is not for this account'):
            super().__init__(message)
            self.message = message
            self.kind = 'bootstrap_device_not_for_this_account'
            self.code = 'KDBC_BOOTSTRAP_DEVICE_NOT_FOR_THIS_ACCOUNT'
            self.actor = 'vault'
            self.retryable = False

    class DeviceCredentialStore:
        def __init__(self):
            if module.store_init_error:
                raise module.store_init_error

        def load(self, env_host):
            module.store_loaded = env_host
            if module.store_load_error:
                raise module.store_load_error
            return module.store_load_result

        def save(self, env_host, creds):
            if module.store_save_error:
                raise module.store_save_error
            module.store_saved.append((env_host, creds))

        def delete(self, env_host):
            module.store_deleted.append(env_host)

        def list(self):
            return []

        def prepare_via_desktop_device_credentials(self, env_host, registrar, client_identity=None):
            module.store_prepare_calls.append((env_host, client_identity))
            if module.store_prepare_error:
                raise module.store_prepare_error
            if module.store_prepare_result is not None:
                return module.store_prepare_result
            encrypted_device_token = registrar(env_host, module.coordinator_device_public_key, client_identity)
            return DeviceCredentials(
                encrypted_device_token,
                module.coordinator_device_private_key,
                module.coordinator_device_public_key,
            )

        def prepare_via_desktop_login_context(self, request, registrar, client=None):
            env_host = request.config.server if request.config else None
            module.store_prepare_calls.append((env_host, client))
            if module.store_prepare_unavailable_after_registrar:
                registrar(env_host, module.coordinator_device_public_key, client)
                raise DeviceCredentialStoreUnavailableError()
            if module.store_prepare_error:
                raise module.store_prepare_error
            if module.store_prepare_result is not None:
                creds = module.store_prepare_result
            else:
                encrypted_device_token = registrar(env_host, module.coordinator_device_public_key, client)
                creds = DeviceCredentials(
                    encrypted_device_token,
                    module.coordinator_device_private_key,
                    module.coordinator_device_public_key,
                )
            request.device = creds
            module.last_request = request
            if module.error:
                raise module.error
            context = types.SimpleNamespace()
            context.env_host = env_host
            context.device = creds
            context.vault_bootstrap = module.vault_result
            context.used_cached_device = module.store_prepare_result is not None
            context.attempted_env_hosts = [env_host] if env_host else []
            return context

    class BridgeClientConfig:
        def __init__(self, server=None, region=None, socket_override=None, timeout_millis=None,
                     verification_policy=None):
            self.server = server
            self.region = region
            self.socket_override = socket_override
            self.timeout_millis = timeout_millis
            self.verification_policy = verification_policy

    class BootstrapRequest:
        def __init__(self, client, device, flow=None, request_id=None, message_session_uid=None,
                     host_attestation=None, config=None):
            self.client = client
            self.device = device
            self.flow = flow
            self.request_id = request_id
            self.message_session_uid = message_session_uid
            self.host_attestation = host_attestation
            self.config = config

    class BridgeClient(_FakeBridgeClient):
        pass

    BridgeClient.module = module
    module.ClientIdentity = ClientIdentity
    module.DeviceCredentials = DeviceCredentials
    module.DeviceCredentialStore = DeviceCredentialStore
    module.DeviceCredentialStoreUnavailableError = DeviceCredentialStoreUnavailableError
    module.DeviceCredentialStoreAuthFailedError = DeviceCredentialStoreAuthFailedError
    module.KARegistrationFailedError = KARegistrationFailedError
    module.BootstrapDeviceNotForThisAccountError = BootstrapDeviceNotForThisAccountError
    module.BridgeClientConfig = BridgeClientConfig
    module.BootstrapRequest = BootstrapRequest
    module.BridgeClient = BridgeClient
    return module


def _set_coordinator_device(bridge_module, private_key):
    bridge_module.coordinator_device_private_key = crypto.unload_ec_private_key(private_key)
    bridge_module.coordinator_device_public_key = crypto.unload_ec_public_key(private_key.public_key())


def _make_enrolled_params():
    device_private_key, _ = crypto.generate_ec_key()
    device_private_key_bytes = crypto.unload_ec_private_key(device_private_key)
    device_public_key = device_private_key.public_key()
    params = KeeperParams(server='keepersecurity.com')
    params.device_token = utils.base64_url_encode(b'encrypted-device-token')
    params.device_private_key = utils.base64_url_encode(device_private_key_bytes)
    params.data_key = None
    return params, device_public_key


def _make_ka_proto_response(device_public_key, data_key, primary_username='ka.user@example.com',
                            account_uid=b'\x01' * 16):
    from keepercommander.proto import APIRequest_pb2
    login_resp = APIRequest_pb2.LoginResponse()
    login_resp.loginState = APIRequest_pb2.LoginState.Value('LOGGED_IN')
    login_resp.encryptedSessionToken = b'ka-session-token'
    login_resp.encryptedDataKey = crypto.encrypt_ec(data_key, device_public_key)
    login_resp.primaryUsername = primary_username
    login_resp.accountUid = account_uid
    return login_resp.SerializeToString()


def _make_device_proto_response(encrypted_device_token=b'ephemeral-device-token'):
    from keepercommander.proto import APIRequest_pb2
    device = APIRequest_pb2.Device()
    device.encryptedDeviceToken = encrypted_device_token
    return device.SerializeToString()


class TestDesktopBridgeLogin(TestCase):

    def test_login_parser_accepts_via_desktop_and_new_login_together(self):
        opts = command_utils.login_parser.parse_args(['--via-desktop'])
        self.assertTrue(opts.via_desktop)
        self.assertFalse(opts.no_via_desktop)
        self.assertFalse(opts.new_login)

        opts = command_utils.login_parser.parse_args(['--via-desktop', '--new-login'])
        self.assertTrue(opts.via_desktop)
        self.assertTrue(opts.new_login)

        opts = command_utils.login_parser.parse_args(['--no-via-desktop'])
        self.assertFalse(opts.via_desktop)
        self.assertTrue(opts.no_via_desktop)

        opts = command_utils.login_parser.parse_args(['--force'])
        self.assertTrue(opts.force)

    def test_command_uses_bridge_adapter_without_normal_login_fallback(self):
        params = KeeperParams()
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login:
            bridge_login.side_effect = lambda p: setattr(p, 'session_token', 'SESSION')
            cmd.execute(params, via_desktop=True, skip_sync=True)

        bridge_login.assert_called_once_with(params)
        api_login.assert_not_called()
        self.assertTrue(params.via_desktop_login)

    def test_via_desktop_login_clears_stale_pam_launch_cache_after_sync(self):
        params = KeeperParams()
        cmd = command_utils.LoginCommand()
        launch_cache.put('record-1', {
            'dag_linked_uid': None,
            'config_uid': 'stale-config',
            'gateway_uid': 'stale-gateway',
            'gateway_name': 'Stale Gateway',
        })

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login, \
                mock.patch('keepercommander.commands.utils.SyncDownCommand.execute') as sync_down, \
                mock.patch('keepercommander.loginv3.LoginV3API.register_encrypted_data_key_for_device'):
            bridge_login.side_effect = lambda p: setattr(p, 'session_token', 'SESSION')
            cmd.execute(params, via_desktop=True)

        bridge_login.assert_called_once_with(params)
        api_login.assert_not_called()
        sync_down.assert_called_once_with(params, force=True)
        self.assertIsNone(launch_cache.get('record-1'))

    def test_via_desktop_login_clears_stale_vault_cache_before_desktop_auth(self):
        params = KeeperParams()
        params.session_token = 'OLD_SESSION'
        params.user = 'old-user@example.com'
        params.record_cache['stale-record'] = {'record_uid': 'stale-record'}
        params.subfolder_record_cache[''] = {'stale-record'}
        cmd = command_utils.LoginCommand()

        def bridge_login(p):
            self.assertEqual({}, p.record_cache)
            self.assertEqual({}, p.subfolder_record_cache)
            self.assertIsNone(p.session_token)
            p.user = 'vault-user@example.com'
            p.session_token = 'NEW_SESSION'

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login_mock, \
                mock.patch('keepercommander.api.login') as api_login, \
                mock.patch('keepercommander.commands.utils.SyncDownCommand.execute') as sync_down, \
                mock.patch('keepercommander.loginv3.LoginV3API.register_encrypted_data_key_for_device'):
            bridge_login_mock.side_effect = bridge_login
            cmd.execute(params, via_desktop=True)

        bridge_login_mock.assert_called_once_with(params)
        api_login.assert_not_called()
        sync_down.assert_called_once_with(params, force=True)
        self.assertEqual('vault-user@example.com', params.user)

    def test_via_desktop_rejects_explicit_email(self):
        params = KeeperParams()
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login:
            with self.assertRaises(CommandError):
                cmd.execute(params, email='user@example.com', via_desktop=True, skip_sync=True)

        bridge_login.assert_not_called()
        api_login.assert_not_called()

    def test_no_via_desktop_bypasses_session_wide_desktop_login(self):
        params = KeeperParams()
        params.via_desktop_login = True
        params.user = 'user@example.com'
        params.desktop_account_uid = 'desktop-account'
        params.desktop_user = 'desktop@example.com'
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login:
            api_login.side_effect = lambda p, new_login=False: setattr(p, 'session_token', 'SESSION')
            cmd.execute(params, email='user@example.com', no_via_desktop=True, skip_sync=True)

        bridge_login.assert_not_called()
        api_login.assert_called_once_with(params, new_login=False)
        self.assertFalse(params.via_desktop_login)
        self.assertIsNone(params.desktop_account_uid)
        self.assertEqual('', params.desktop_user)

    def test_plain_email_login_bypasses_stale_session_wide_desktop_login(self):
        params = KeeperParams()
        params.via_desktop_login = True
        params.desktop_account_uid = 'desktop-account'
        params.desktop_user = 'desktop@example.com'
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login:
            api_login.side_effect = lambda p, new_login=False: setattr(p, 'session_token', 'SESSION')
            cmd.execute(params, email='user@example.com', skip_sync=True)

        bridge_login.assert_not_called()
        api_login.assert_called_once_with(params, new_login=False)
        self.assertEqual('user@example.com', params.user)
        self.assertIsNone(params.desktop_account_uid)
        self.assertEqual('', params.desktop_user)

    def test_plain_email_login_prompts_before_stopping_active_via_desktop_tunnels(self):
        params = KeeperParams()
        params.session_token = 'SESSION'
        params.via_desktop_login = True
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login, \
                mock.patch(
                    'keepercommander.commands.tunnel.tunnel_lifecycle.describe_active_pam_tunnels_on_logout',
                    return_value=['record-1 (local 127.0.0.1:49153 -> remote host:22)'],
                ), \
                mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.close_pam_tunnels_on_logout') as close_tunnels, \
                mock.patch('keepercommander.commands.utils.user_choice', return_value='n') as choice:
            cmd.execute(params, email='user@example.com', skip_sync=True)

        bridge_login.assert_not_called()
        api_login.assert_not_called()
        close_tunnels.assert_not_called()
        choice.assert_called_once()
        self.assertEqual('SESSION', params.session_token)
        self.assertTrue(params.via_desktop_login)

    def test_plain_email_login_force_stops_active_via_desktop_tunnels(self):
        params = KeeperParams()
        params.session_token = 'SESSION'
        params.via_desktop_login = True
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login, \
                mock.patch(
                    'keepercommander.commands.tunnel.tunnel_lifecycle.describe_active_pam_tunnels_on_logout',
                    return_value=['record-1 (local 127.0.0.1:49153 -> remote host:22)'],
                ), \
                mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.close_pam_tunnels_on_logout') as close_tunnels, \
                mock.patch('keepercommander.commands.utils.user_choice') as choice:
            api_login.side_effect = lambda p, new_login=False: setattr(p, 'session_token', 'NEW_SESSION')
            cmd.execute(params, email='user@example.com', force=True, skip_sync=True)

        bridge_login.assert_not_called()
        choice.assert_not_called()
        close_tunnels.assert_called_once_with(params)
        api_login.assert_called_once_with(params, new_login=False)
        self.assertFalse(params.via_desktop_login)
        self.assertEqual('user@example.com', params.user)

    def test_via_desktop_login_tears_down_replaced_session_before_bridge_auth(self):
        params = KeeperParams()
        params.session_token = 'SESSION'
        params.via_desktop_login = True
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login, \
                mock.patch(
                    'keepercommander.commands.tunnel.tunnel_lifecycle.describe_active_pam_tunnels_on_logout',
                    return_value=[],
                ), \
                mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.close_pam_tunnels_on_logout') as close_tunnels:
            bridge_login.side_effect = lambda p: setattr(p, 'session_token', 'DESKTOP_SESSION')
            cmd.execute(params, via_desktop=True, skip_sync=True)

        close_tunnels.assert_called_once_with(params)
        bridge_login.assert_called_once_with(params)
        api_login.assert_not_called()
        self.assertTrue(params.via_desktop_login)

    def test_failed_desktop_login_clears_session_wide_desktop_mode(self):
        params = KeeperParams()
        params.via_desktop_login = True
        cmd = command_utils.LoginCommand()

        with mock.patch('keepercommander.auth.desktop_bridge.login_via_desktop') as bridge_login, \
                mock.patch('keepercommander.api.login') as api_login:
            bridge_login.side_effect = desktop_bridge.DesktopBridgeLoginError('failed')
            cmd.execute(params, skip_sync=True)

        bridge_login.assert_called_once_with(params)
        api_login.assert_not_called()
        self.assertFalse(params.via_desktop_login)

    def test_clear_session_resets_session_wide_desktop_mode(self):
        params = KeeperParams()
        params.via_desktop_login = True
        params.via_desktop_session_terminated = True
        params.desktop_account_uid = 'desktop-account'
        params.desktop_user = 'desktop@example.com'

        params.clear_session()

        self.assertFalse(params.via_desktop_login)
        self.assertFalse(params.via_desktop_session_terminated)
        self.assertIsNone(params.desktop_account_uid)
        self.assertEqual('', params.desktop_user)

    def test_login_replacement_detaches_tube_registry_after_pam_teardown(self):
        params = KeeperParams()
        params.session_token = 'SESSION'
        params.commands = ['queued-command']
        tube_registry = mock.Mock()
        tube_registry.cleanup_all.side_effect = AssertionError('cleanup_all should not run after PAM teardown')
        params.tube_registry = tube_registry

        with mock.patch(
            'keepercommander.commands.tunnel.tunnel_lifecycle.describe_active_pam_tunnels_on_logout',
            return_value=['record-1'],
        ), mock.patch(
            'keepercommander.commands.tunnel.tunnel_lifecycle.close_pam_tunnels_on_logout',
        ) as close_tunnels, mock.patch(
            'keepercommander.commands.tunnel.pam_state_bridge.suspend_desktop_bridge_state',
        ) as suspend_state:
            ok = command_utils._prepare_login_session_replacement(
                params,
                target_user='other@example.com',
                force=True,
            )

        self.assertTrue(ok)
        close_tunnels.assert_called_once_with(params)
        suspend_state.assert_called_once_with(params, clear_binding=True)
        tube_registry.cleanup_all.assert_not_called()
        self.assertIsNone(params.tube_registry)
        self.assertEqual(['queued-command'], params.commands)

    def test_terminal_desktop_disconnect_consumes_next_authenticated_command(self):
        params = KeeperParams()
        params.via_desktop_session_terminated = True

        with self.assertLogs(level='WARNING') as logs:
            consumed = cli._consume_via_desktop_terminal_command(params, 'pam tunnel list')

        self.assertTrue(consumed)
        self.assertFalse(params.via_desktop_session_terminated)
        self.assertTrue(any('Vault Desktop disconnected; please login again.' in line for line in logs.output))

    def test_terminal_desktop_disconnect_allows_explicit_login(self):
        params = KeeperParams()
        params.via_desktop_session_terminated = True

        consumed = cli._consume_via_desktop_terminal_command(params, 'login --via-desktop')

        self.assertFalse(consumed)
        self.assertFalse(params.via_desktop_session_terminated)

    def test_queued_shell_login_suppresses_startup_auto_login(self):
        params = KeeperParams()
        params.user = 'configured.user@example.com'
        params.commands = ['login --via-desktop', 'q']

        with mock.patch('keepercommander.cli.display.welcome'), \
                mock.patch('keepercommander.cli.versioning.welcome_print_version'), \
                mock.patch('keepercommander.cli.LoginCommand.execute') as login_execute:
            cli.loop(params)

        login_execute.assert_called_once()
        self.assertTrue(login_execute.call_args.kwargs.get('via_desktop'))

    def test_shell_startup_uses_session_wide_via_desktop_without_login_command(self):
        params = KeeperParams()
        params.via_desktop_login = True
        params.user = 'configured.user@example.com'
        params.commands = ['q']

        with mock.patch('keepercommander.cli.display.welcome'), \
                mock.patch('keepercommander.cli.versioning.welcome_print_version'), \
                mock.patch('keepercommander.commands.tunnel.pam_state_bridge.start_state_sync_worker') as start_sync, \
                mock.patch('keepercommander.cli.LoginCommand.execute') as login_execute:
            login_execute.side_effect = lambda p, **_: setattr(p, 'session_token', 'SESSION')
            cli.loop(params)

        login_execute.assert_called_once_with(params, via_desktop=True, show_help=False)
        start_sync.assert_called_once_with(params)

    def test_keeper_server_env_preserves_full_dev_hostname(self):
        params = KeeperParams(server='keepersecurity.com')

        with mock.patch.dict('os.environ', {'KEEPER_SERVER': 'dev.keepersecurity.com'}):
            keeper_main.apply_keeper_server_env(params)

        self.assertEqual('dev.keepersecurity.com', params.server)

    def test_keeper_server_env_accepts_dev_region_code(self):
        params = KeeperParams(server='keepersecurity.com')

        with mock.patch.dict('os.environ', {'KEEPER_SERVER': 'US_DEV'}):
            keeper_main.apply_keeper_server_env(params)

        self.assertEqual('dev.keepersecurity.com', params.server)

    def test_bridge_exchange_populates_in_memory_session_via_ka(self):
        params, device_public_key = _make_enrolled_params()
        params.server = 'dev.keepersecurity.com'
        data_key = utils.generate_aes_key()
        account_uid = utils.base64_url_encode(b'\x01' * 16)
        enrolled_device_token = utils.base64_url_decode(params.device_token)
        ephemeral_private_key, ephemeral_public_key = crypto.generate_ec_key()
        ephemeral_device_token = b'ephemeral-device-token'
        vault_token_bytes = b'vault-session-token'
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(vault_token_bytes),
            server='stale-legacy.keepersecurity.com',
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(
                account_uid,
                username='ka.user@example.com',
                email='ka.user@example.com',
            ),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.coordinator_device_private_key = crypto.unload_ec_private_key(ephemeral_private_key)
        bridge_module.coordinator_device_public_key = crypto.unload_ec_public_key(ephemeral_public_key)
        ka_proto = _make_ka_proto_response(ephemeral_public_key, data_key)
        captured_ka = {}
        captured_register = {}
        endpoints = []

        def fake_execute_rest(context, endpoint, payload, timeout=None):
            from keepercommander.proto import APIRequest_pb2
            endpoints.append(endpoint)
            if endpoint == 'authentication/register_device':
                captured_register['server_base'] = context.server_base
                rq = APIRequest_pb2.DeviceRegistrationRequest()
                rq.ParseFromString(payload.payload)
                captured_register['device_public_key'] = rq.devicePublicKey
                captured_register['client_version'] = rq.clientVersion
                return _make_device_proto_response(ephemeral_device_token)
            captured_ka['endpoint'] = endpoint
            captured_ka['server_base'] = context.server_base
            rq = APIRequest_pb2.StartLoginRequest()
            rq.ParseFromString(payload.payload)
            captured_ka['encrypted_device_token'] = rq.encryptedDeviceToken
            captured_ka['message_session_uid'] = rq.messageSessionUid
            captured_ka['account_uid'] = rq.accountUid
            captured_ka['from_session_token'] = rq.fromSessionToken
            captured_ka['username'] = rq.username
            captured_ka['payload_session_token'] = payload.encryptedSessionToken
            return ka_proto

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary') as populate_summary, \
                mock.patch('keepercommander.config_storage.loader.store_config_properties') as store_config, \
                mock.patch('keepercommander.rest_api.execute_rest', side_effect=fake_execute_rest):
            desktop_bridge.login_via_desktop(
                params,
                bridge_module=bridge_module,
                bridge_socket='/tmp/keeper-bridge-leaf.sock',
                timeout_ms=1234,
                verification_policy='log_only',
            )

        request = bridge_module.last_request
        self.assertEqual('already_enrolled', request.flow)
        self.assertEqual('Keeper Commander', request.client.name)
        self.assertEqual('commander', request.client.kind)
        self.assertEqual(rest_api.CLIENT_VERSION, request.client.ka_client_version)
        self.assertEqual('/tmp/keeper-bridge-leaf.sock', request.config.socket_override)
        self.assertEqual(1234, request.config.timeout_millis)
        self.assertEqual('log_only', request.config.verification_policy)
        self.assertEqual(ephemeral_device_token, request.device.encrypted_device_token)
        self.assertEqual(b'ka-session-token', params.session_token_bytes)
        self.assertEqual(utils.base64_url_encode(b'ka-session-token'), params.session_token)
        self.assertEqual(data_key, params.data_key)
        self.assertIsNone(params.clone_code)
        self.assertEqual('ka.user@example.com', params.user)
        self.assertEqual(account_uid, params.desktop_account_uid)
        self.assertEqual('ka.user@example.com', params.desktop_user)
        self.assertEqual(['authentication/register_device', 'authentication/login_from_existing_session_token'], endpoints)
        self.assertIn('dev.keepersecurity.com', captured_register['server_base'])
        self.assertEqual(crypto.unload_ec_public_key(ephemeral_public_key), captured_register['device_public_key'])
        self.assertEqual(rest_api.CLIENT_VERSION, captured_register['client_version'])
        self.assertEqual('authentication/login_from_existing_session_token', captured_ka['endpoint'])
        self.assertIn('dev.keepersecurity.com', captured_ka['server_base'])
        self.assertEqual('dev.keepersecurity.com', params.server)
        self.assertEqual(ephemeral_device_token, captured_ka['encrypted_device_token'])
        self.assertEqual(utils.base64_url_encode(enrolled_device_token), params.device_token)
        self.assertTrue(captured_ka['message_session_uid'])
        self.assertEqual(b'', captured_ka['account_uid'])
        self.assertEqual(b'', captured_ka['from_session_token'])
        self.assertEqual('', captured_ka['username'])
        self.assertEqual(vault_token_bytes, captured_ka['payload_session_token'])
        populate_summary.assert_called_once_with(params)
        store_config.assert_not_called()
        self.assertEqual(1, len(bridge_module.store_prepare_calls))
        self.assertEqual('dev.keepersecurity.com', bridge_module.store_prepare_calls[0][0])
        self.assertEqual([], bridge_module.store_saved)

    def test_bridge_exchange_uses_cached_device_credentials(self):
        params, cached_public_key = _make_enrolled_params()
        data_key = utils.generate_aes_key()
        account_uid = utils.base64_url_encode(b'\x01' * 16)
        cached_private_key_bytes = utils.base64_url_decode(params.device_private_key)
        cached_device_token = b'cached-device-token'
        vault_token_bytes = b'vault-session-token'
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(vault_token_bytes),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(account_uid, email='ka.user@example.com'),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.store_prepare_result = bridge_module.DeviceCredentials(
            cached_device_token,
            cached_private_key_bytes,
            crypto.unload_ec_public_key(cached_public_key),
        )
        ka_proto = _make_ka_proto_response(cached_public_key, data_key)
        captured = {}

        def fake_execute_rest(context, endpoint, payload, timeout=None):
            captured['endpoint'] = endpoint
            from keepercommander.proto import APIRequest_pb2
            rq = APIRequest_pb2.StartLoginRequest()
            rq.ParseFromString(payload.payload)
            captured['encrypted_device_token'] = rq.encryptedDeviceToken
            return ka_proto

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.auth.desktop_bridge._register_ephemeral_device') as register_ephemeral, \
                mock.patch('keepercommander.rest_api.execute_rest', side_effect=fake_execute_rest):
            desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        register_ephemeral.assert_not_called()
        self.assertEqual(1, len(bridge_module.store_prepare_calls))
        self.assertEqual([], bridge_module.store_saved)
        self.assertEqual('authentication/login_from_existing_session_token', captured['endpoint'])
        self.assertEqual(cached_device_token, captured['encrypted_device_token'])

    def test_bridge_exchange_falls_back_when_device_store_unavailable(self):
        params, device_public_key = _make_enrolled_params()
        data_key = utils.generate_aes_key()
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(b'vault-session-token'),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(utils.base64_url_encode(b'\x01' * 16), email='ka.user@example.com'),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.store_init_error = bridge_module.DeviceCredentialStoreUnavailableError()
        ka_proto = _make_ka_proto_response(device_public_key, data_key)

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.auth.desktop_bridge._register_ephemeral_device',
                           return_value=(
                               utils.base64_url_decode(params.device_token),
                               utils.base64_url_decode(params.device_private_key),
                           )) as register_ephemeral, \
                mock.patch('keepercommander.rest_api.execute_rest', return_value=ka_proto):
            desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        register_ephemeral.assert_called_once_with(params)
        self.assertEqual([], bridge_module.store_saved)

    def test_prepare_login_context_does_not_ephemeral_fallback_after_registrar_when_store_unavailable(self):
        params, _ = _make_enrolled_params()
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(b'vault-session-token'),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(utils.base64_url_encode(b'\x01' * 16), email='ka.user@example.com'),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.store_prepare_unavailable_after_registrar = True

        with mock.patch('keepercommander.auth.desktop_bridge._register_ephemeral_device') as register_ephemeral, \
                mock.patch(
                    'keepercommander.auth.desktop_bridge._register_device_for_public_key',
                    return_value=b'kdbc-device-token',
                ) as register_device:
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        register_device.assert_called_once()
        register_ephemeral.assert_not_called()
        self.assertEqual('KDBC_DEVICE_CREDENTIAL_STORE_UNAVAILABLE', ctx.exception.code)
        self.assertEqual('device_credential_store_unavailable', ctx.exception.kind)

    def test_bridge_exchange_surfaces_device_store_auth_failure_on_prepare(self):
        params, _ = _make_enrolled_params()
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(b'vault-session-token'),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(utils.base64_url_encode(b'\x01' * 16), email='ka.user@example.com'),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.store_prepare_error = bridge_module.DeviceCredentialStoreAuthFailedError()

        with mock.patch('keepercommander.auth.desktop_bridge._register_ephemeral_device') as register_ephemeral:
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        register_ephemeral.assert_not_called()
        self.assertEqual('KDBC_DEVICE_CREDENTIAL_STORE_AUTH_FAILED', ctx.exception.code)
        self.assertEqual('device_credential_store_auth_failed', ctx.exception.kind)
        self.assertIn('Device credential store authentication was denied', str(ctx.exception))

    def test_bridge_exchange_surfaces_device_store_auth_failure_without_ephemeral_fallback(self):
        params, device_public_key = _make_enrolled_params()
        data_key = utils.generate_aes_key()
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(b'vault-session-token'),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(utils.base64_url_encode(b'\x01' * 16), email='ka.user@example.com'),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.store_prepare_error = bridge_module.DeviceCredentialStoreAuthFailedError()
        ka_proto = _make_ka_proto_response(device_public_key, data_key)

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.auth.desktop_bridge._register_ephemeral_device') as register_ephemeral, \
                mock.patch('keepercommander.rest_api.execute_rest', return_value=ka_proto):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        register_ephemeral.assert_not_called()
        self.assertEqual('KDBC_DEVICE_CREDENTIAL_STORE_AUTH_FAILED', ctx.exception.code)
        self.assertEqual('device_credential_store_auth_failed', ctx.exception.kind)
        self.assertIn('Device credential store authentication was denied', str(ctx.exception))

    def test_bridge_exchange_surfaces_bootstrap_device_not_for_account(self):
        params, _ = _make_enrolled_params()
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(b'vault-session-token'),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(utils.base64_url_encode(b'\x01' * 16), email='ka.user@example.com'),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.store_prepare_error = bridge_module.BootstrapDeviceNotForThisAccountError()

        with mock.patch('keepercommander.auth.desktop_bridge._register_ephemeral_device') as register_ephemeral:
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        register_ephemeral.assert_not_called()
        self.assertEqual('KDBC_BOOTSTRAP_DEVICE_NOT_FOR_THIS_ACCOUNT', ctx.exception.code)
        self.assertEqual('bootstrap_device_not_for_this_account', ctx.exception.kind)
        self.assertEqual('vault', ctx.exception.actor)

    def test_bridge_exchange_adopts_vault_account_binding_over_stale_commander_user(self):
        params, device_public_key = _make_enrolled_params()
        params.user = 'stale.commander@example.com'
        params.account_uid_bytes = b'\x03' * 16
        data_key = utils.generate_aes_key()
        account_uid_bytes = b'\x02' * 16
        account_uid = utils.base64_url_encode(account_uid_bytes)
        vault_result = _VaultBootstrapResult(
            vault_session_token=b'vault-session-token',
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(
                account_uid,
                username='vault.user@example.com',
                email='vault.user@example.com',
            ),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        _set_coordinator_device(bridge_module, crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key)))
        ka_proto = _make_ka_proto_response(
            device_public_key,
            data_key,
            primary_username='ka.user@example.com',
            account_uid=account_uid_bytes,
        )

        def fake_execute_rest(context, endpoint, payload, timeout=None):
            if endpoint == 'authentication/register_device':
                return _make_device_proto_response(utils.base64_url_decode(params.device_token))
            return ka_proto

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.config_storage.loader.store_config_properties'), \
                mock.patch('keepercommander.rest_api.execute_rest', side_effect=fake_execute_rest):
            desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertEqual(account_uid_bytes, params.account_uid_bytes)
        self.assertEqual(account_uid, params.desktop_account_uid)
        self.assertEqual('vault.user@example.com', params.user)
        self.assertEqual('vault.user@example.com', params.desktop_user)

    def test_bridge_exchange_rejects_ka_account_uid_that_disagrees_with_vault_binding(self):
        params, device_public_key = _make_enrolled_params()
        data_key = utils.generate_aes_key()
        vault_result = _VaultBootstrapResult(
            vault_session_token=b'vault-session-token',
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(
                utils.base64_url_encode(b'\x02' * 16),
                email='vault.user@example.com',
            ),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        _set_coordinator_device(bridge_module, crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key)))
        ka_proto = _make_ka_proto_response(device_public_key, data_key, account_uid=b'\x01' * 16)

        def fake_execute_rest(context, endpoint, payload, timeout=None):
            if endpoint == 'authentication/register_device':
                return _make_device_proto_response(utils.base64_url_decode(params.device_token))
            return ka_proto

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.config_storage.loader.store_config_properties'), \
                mock.patch('keepercommander.rest_api.execute_rest', side_effect=fake_execute_rest):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertEqual('account_mismatch', ctx.exception.kind)
        self.assertIn('Desktop account does not match Vault account', str(ctx.exception))

    def test_bridge_exchange_requires_vault_ka_server(self):
        params, device_public_key = _make_enrolled_params()
        data_key = utils.generate_aes_key()
        vault_result = _VaultBootstrapResult(
            vault_session_token=b'vault-session-token',
            vault_account_binding=_VaultAccountBinding(
                utils.base64_url_encode(b'\x01' * 16),
                email='vault.user@example.com',
            ),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        bridge_module.store_prepare_result = bridge_module.DeviceCredentials(
            utils.base64_url_decode(params.device_token),
            utils.base64_url_decode(params.device_private_key),
            crypto.unload_ec_public_key(device_public_key),
        )
        ka_proto = _make_ka_proto_response(device_public_key, data_key)

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.rest_api.execute_rest', return_value=ka_proto):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertEqual('ka_server_binding_missing', ctx.exception.kind)
        self.assertIn('Vault KA server', str(ctx.exception))

    def test_bridge_exchange_registers_ephemeral_device_in_vault_region(self):
        params, device_public_key = _make_enrolled_params()
        params.server = 'dev.keepersecurity.com'
        account_uid = utils.base64_url_encode(b'\x01' * 16)
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(b'vault-session-token'),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(
                account_uid,
                email='ka.user@example.com',
            ),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        ephemeral_private_key, ephemeral_public_key = crypto.generate_ec_key()
        ephemeral_private_key_bytes = crypto.unload_ec_private_key(ephemeral_private_key)
        ephemeral_device_token = b'ephemeral-device-token'
        captured = {}

        def fake_execute_rest(context, endpoint, payload, timeout=None):
            captured['endpoint'] = endpoint
            captured['server_base'] = context.server_base
            from keepercommander.proto import APIRequest_pb2
            rq = APIRequest_pb2.DeviceRegistrationRequest()
            rq.ParseFromString(payload.payload)
            captured['device_public_key'] = rq.devicePublicKey
            return _make_device_proto_response(ephemeral_device_token)

        with mock.patch('keepercommander.auth.desktop_bridge.crypto.generate_ec_key',
                        return_value=(ephemeral_private_key, ephemeral_public_key)), \
                mock.patch('keepercommander.rest_api.execute_rest', side_effect=fake_execute_rest):
            token, private_key = desktop_bridge._register_ephemeral_device(params)

        self.assertEqual('authentication/register_device', captured['endpoint'])
        self.assertIn('keepersecurity.com', captured['server_base'])
        self.assertEqual(crypto.unload_ec_public_key(ephemeral_public_key), captured['device_public_key'])
        self.assertEqual(ephemeral_device_token, token)
        self.assertEqual(ephemeral_private_key_bytes, private_key)
        self.assertEqual('dev.keepersecurity.com', params.server)

    def test_bridge_exchange_surfaces_ephemeral_registration_failure(self):
        params, _ = _make_enrolled_params()
        vault_result = _VaultBootstrapResult(
            vault_session_token=base64.b64encode(b'vault-session-token'),
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(
                utils.base64_url_encode(b'\x01' * 16),
                email='ka.user@example.com',
            ),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.rest_api.execute_rest',
                           return_value={
                               'error': 'registration_failed',
                               'message': 'register device failed',
                           }):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertEqual('ka_device_registration_failed', ctx.exception.kind)
        self.assertIn('register device failed', str(ctx.exception))

    def test_bridge_error_mapping_preserves_kdbc_fields(self):
        params, _ = _make_enrolled_params()

        with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as context:
            desktop_bridge.login_via_desktop(params, bridge_module=_make_bridge_module(error=_FakeBridgeError()))

        self.assertEqual('KDBC_VAULT_LOCKED', context.exception.code)
        self.assertEqual('vault_locked', context.exception.kind)
        self.assertTrue(context.exception.retryable)
        self.assertEqual('vault', context.exception.actor)
        self.assertEqual('request-1', context.exception.request_id)
        self.assertIn('code=KDBC_VAULT_LOCKED', str(context.exception))
        self.assertIn('kind=vault_locked', str(context.exception))
        self.assertIn('actor=vault', str(context.exception))
        self.assertIn('retryable=True', str(context.exception))

    def test_desktop_login_timeout_defaults_to_no_deadline(self):
        params, _ = _make_enrolled_params()
        bridge_module = _make_bridge_module(error=_FakeBridgeError())

        with self.assertRaises(desktop_bridge.DesktopBridgeLoginError):
            desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertIsNone(bridge_module.last_request.config.timeout_millis)

    def test_desktop_login_timeout_can_be_overridden_by_environment(self):
        params, _ = _make_enrolled_params()
        bridge_module = _make_bridge_module(error=_FakeBridgeError())

        with mock.patch.dict('os.environ', {'KDBC_LOGIN_TIMEOUT_MS': '45000'}):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError):
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertEqual(45000, bridge_module.last_request.config.timeout_millis)

    def test_desktop_login_timeout_zero_means_no_deadline(self):
        params, _ = _make_enrolled_params()
        bridge_module = _make_bridge_module(error=_FakeBridgeError())

        with mock.patch.dict('os.environ', {'KDBC_LOGIN_TIMEOUT_MS': '0'}):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError):
                desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertIsNone(bridge_module.last_request.config.timeout_millis)

    def test_desktop_login_keyboard_interrupt_cancels(self):
        params, _ = _make_enrolled_params()
        bridge_module = _make_bridge_module(error=KeyboardInterrupt())

        with self.assertRaises(KeyboardInterrupt):
            desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

    def test_login_command_cancels_via_desktop_on_keyboard_interrupt(self):
        params = KeeperParams()
        params.via_desktop_login = True
        cmd = command_utils.LoginCommand()

        with mock.patch(
            'keepercommander.auth.desktop_bridge.login_via_desktop',
            side_effect=KeyboardInterrupt(),
        ), mock.patch('keepercommander.api.login') as api_login:
            result = cmd.execute(params, via_desktop=True, skip_sync=True)

        self.assertIsNone(result)
        self.assertFalse(params.via_desktop_login)
        api_login.assert_not_called()

    def test_bridge_config_uses_verification_policy_from_environment(self):
        params, _ = _make_enrolled_params()
        bridge_module = _make_bridge_module(vault_result=_VaultBootstrapResult(b'vault-session-token'))

        with mock.patch.dict('os.environ', {'KDBC_VERIFICATION_POLICY': 'log_only'}):
            request = desktop_bridge._build_bootstrap_request(
                bridge_module,
                params,
                utils.base64_url_decode(params.device_token),
                utils.base64_url_decode(params.device_private_key),
                None,
                1234,
                None,
            )

        self.assertEqual('log_only', request.config.verification_policy)

    def test_bridge_config_defaults_dev_hosts_to_log_only(self):
        params = KeeperParams(server='dev.keepersecurity.com')
        bridge_module = _make_bridge_module(vault_result=_VaultBootstrapResult(b'vault-session-token'))

        with mock.patch.dict('os.environ', {}, clear=True):
            config = desktop_bridge._build_bridge_config(
                bridge_module, params, None, 1234, None,
            )

        self.assertEqual('log_only', config.verification_policy)

    def test_bridge_config_leaves_production_policy_to_kdbc_default(self):
        params = KeeperParams(server='keepersecurity.com')
        bridge_module = _make_bridge_module(vault_result=_VaultBootstrapResult(b'vault-session-token'))

        with mock.patch.dict('os.environ', {}, clear=True):
            config = desktop_bridge._build_bridge_config(
                bridge_module, params, None, 1234, None,
            )

        self.assertIsNone(config.verification_policy)

    def test_bridge_config_environment_overrides_dev_default(self):
        params = KeeperParams(server='dev.keepersecurity.com')
        bridge_module = _make_bridge_module(vault_result=_VaultBootstrapResult(b'vault-session-token'))

        with mock.patch.dict('os.environ', {'KDBC_VERIFICATION_POLICY': 'enforce'}, clear=True):
            config = desktop_bridge._build_bridge_config(
                bridge_module, params, None, 1234, None,
            )

        self.assertEqual('enforce', config.verification_policy)


class TestAutoEnrollment(TestCase):

    def test_fresh_install_auto_registers_device_then_proceeds(self):
        """No config.json — KDBC coordinator should register a process credential."""
        params = KeeperParams(server='keepersecurity.com')
        # no device_token, no device_private_key

        data_key = utils.generate_aes_key()

        vault_result = _VaultBootstrapResult(
            vault_session_token=b'vault-session-token',
            ka_server='dev.keepersecurity.com',
            vault_account_binding=_VaultAccountBinding(utils.base64_url_encode(b'\x01' * 16)),
        )
        bridge_module = _make_bridge_module(vault_result=vault_result)
        device_private_key = crypto.load_ec_private_key(bridge_module.coordinator_device_private_key)
        ka_proto = _make_ka_proto_response(device_private_key.public_key(), data_key)
        endpoints = []

        def fake_execute_rest(context, endpoint, payload, timeout=None):
            endpoints.append(endpoint)
            if endpoint == 'authentication/register_device':
                return _make_device_proto_response(b'new-device-token')
            return ka_proto

        with mock.patch('keepercommander.loginv3.LoginV3API.get_device_id') as get_device_id, \
                mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.rest_api.execute_rest', side_effect=fake_execute_rest):
            desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        get_device_id.assert_not_called()
        self.assertEqual(['authentication/register_device', 'authentication/login_from_existing_session_token'], endpoints)
        self.assertEqual(data_key, params.data_key)
        self.assertEqual(b'ka-session-token', params.session_token_bytes)

    def test_fresh_install_registration_failure_raises_ka_registration_failed(self):
        params = KeeperParams(server='keepersecurity.com')

        with mock.patch('keepercommander.rest_api.execute_rest',
                        side_effect=Exception('network error')):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=_make_bridge_module())

        self.assertEqual(desktop_bridge.KDBC_KA_LOGIN_FAILED, ctx.exception.code)
        self.assertEqual('ka_device_registration_failed', ctx.exception.kind)
        self.assertIn('network error', str(ctx.exception))


class TestKaTransport(TestCase):

    def test_ka_login_happy_path_returns_credential_tuple(self):
        device_private_key, _ = crypto.generate_ec_key()
        device_public_key = device_private_key.public_key()
        data_key = utils.generate_aes_key()
        params = KeeperParams(server='keepersecurity.com')

        proto_bytes = _make_ka_proto_response(device_public_key, data_key)
        with mock.patch('keepercommander.rest_api.execute_rest', return_value=proto_bytes):
            result = desktop_bridge._ka_login_from_existing_session_token(
                params,
                encrypted_device_token=b'device-token',
                message_session_uid=b'msg-uid',
                vault_session_token=b'vault-session',
            )

        encrypted_session_token, encrypted_data_key, primary_username, account_uid = result
        self.assertEqual(b'ka-session-token', encrypted_session_token)
        self.assertEqual('ka.user@example.com', primary_username)
        decrypted = crypto.decrypt_ec(encrypted_data_key, device_private_key)
        self.assertEqual(data_key, decrypted)

    def test_ka_login_propagates_request_fields(self):
        params = KeeperParams(server='keepersecurity.com')
        captured = {}

        def fake_execute_rest(context, endpoint, payload, timeout=None):
            captured['endpoint'] = endpoint
            captured['encrypted_session_token'] = payload.encryptedSessionToken
            from keepercommander.proto import APIRequest_pb2
            rq = APIRequest_pb2.StartLoginRequest()
            rq.ParseFromString(payload.payload)
            captured['encrypted_device_token'] = rq.encryptedDeviceToken
            captured['message_session_uid'] = rq.messageSessionUid
            return {'error': 'test_stop', 'message': 'test_stop'}

        with self.assertRaises(desktop_bridge.DesktopBridgeLoginError):
            with mock.patch('keepercommander.rest_api.execute_rest', side_effect=fake_execute_rest):
                desktop_bridge._ka_login_from_existing_session_token(
                    params,
                    encrypted_device_token=b'my-device-token',
                    message_session_uid=b'my-msg-uid',
                    vault_session_token=b'my-vault-session',
                )

        self.assertEqual('authentication/login_from_existing_session_token', captured['endpoint'])
        self.assertEqual(b'my-device-token', captured['encrypted_device_token'])
        self.assertEqual(b'my-msg-uid', captured['message_session_uid'])
        self.assertEqual(b'my-vault-session', captured['encrypted_session_token'])

    def test_ka_login_raises_on_dict_error_response(self):
        params = KeeperParams(server='keepersecurity.com')
        with mock.patch('keepercommander.rest_api.execute_rest',
                        return_value={'error': 'invalid_device', 'message': 'device rejected'}):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge._ka_login_from_existing_session_token(
                    params, b'tok', b'uid', b'vsession',
                )
        self.assertEqual(desktop_bridge.KDBC_KA_LOGIN_FAILED, ctx.exception.code)
        self.assertIn('device rejected', str(ctx.exception))

    def test_ka_login_raises_on_unexpected_login_state(self):
        from keepercommander.proto import APIRequest_pb2
        login_resp = APIRequest_pb2.LoginResponse()
        login_resp.loginState = APIRequest_pb2.LoginState.Value('REQUIRES_2FA')
        params = KeeperParams(server='keepersecurity.com')
        with mock.patch('keepercommander.rest_api.execute_rest',
                        return_value=login_resp.SerializeToString()):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge._ka_login_from_existing_session_token(
                    params, b'tok', b'uid', b'vsession',
                )
        self.assertEqual(desktop_bridge.KDBC_KA_LOGIN_FAILED, ctx.exception.code)
