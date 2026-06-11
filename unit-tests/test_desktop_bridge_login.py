import sys
import types
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

from keepercommander import cli, crypto, rest_api, utils
from keepercommander.auth import desktop_bridge
from keepercommander.commands import utils as command_utils
from keepercommander.commands.base import ParseError
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams


class _VaultBootstrapResult:
    def __init__(self, vault_session_token, server=None, expires_in_ms=None, request_id=None):
        self.vault_session_token = vault_session_token
        self.server = server
        self.expires_in_ms = expires_in_ms
        self.request_id = request_id or 'test-request-id'


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

    class BridgeClientConfig:
        def __init__(self, server=None, region=None, socket_override=None, timeout_millis=None):
            self.server = server
            self.region = region
            self.socket_override = socket_override
            self.timeout_millis = timeout_millis

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
    module.BridgeClientConfig = BridgeClientConfig
    module.BootstrapRequest = BootstrapRequest
    module.BridgeClient = BridgeClient
    return module


def _make_enrolled_params():
    device_private_key, _ = crypto.generate_ec_key()
    device_private_key_bytes = crypto.unload_ec_private_key(device_private_key)
    device_public_key = device_private_key.public_key()
    params = KeeperParams(server='keepersecurity.com')
    params.device_token = utils.base64_url_encode(b'encrypted-device-token')
    params.device_private_key = utils.base64_url_encode(device_private_key_bytes)
    params.data_key = None
    return params, device_public_key


def _make_ka_proto_response(device_public_key, data_key):
    from keepercommander.proto import APIRequest_pb2
    login_resp = APIRequest_pb2.LoginResponse()
    login_resp.loginState = APIRequest_pb2.LoginState.Value('LOGGED_IN')
    login_resp.encryptedSessionToken = b'ka-session-token'
    login_resp.encryptedDataKey = crypto.encrypt_ec(data_key, device_public_key)
    login_resp.primaryUsername = 'ka.user@example.com'
    login_resp.accountUid = b'\x01' * 16
    return login_resp.SerializeToString()


class TestDesktopBridgeLogin(TestCase):

    def test_login_parser_accepts_via_desktop_and_rejects_new_login_conflict(self):
        opts = command_utils.login_parser.parse_args(['--via-desktop'])
        self.assertTrue(opts.via_desktop)
        self.assertFalse(opts.new_login)

        with self.assertRaises(ParseError):
            command_utils.login_parser.parse_args(['--via-desktop', '--new-login'])

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

    def test_command_rejects_cross_level_new_login_conflict(self):
        params = KeeperParams()
        params.top_level_new_login = True

        with self.assertRaises(CommandError):
            command_utils.LoginCommand().execute(params, via_desktop=True, skip_sync=True)

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

    def test_bridge_exchange_populates_in_memory_session_via_ka(self):
        params, device_public_key = _make_enrolled_params()
        data_key = utils.generate_aes_key()
        vault_result = _VaultBootstrapResult(vault_session_token=b'vault-session-token')
        bridge_module = _make_bridge_module(vault_result=vault_result)
        ka_proto = _make_ka_proto_response(device_public_key, data_key)

        with mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary') as populate_summary, \
                mock.patch('keepercommander.config_storage.loader.store_config_properties') as store_config, \
                mock.patch('keepercommander.rest_api.execute_rest', return_value=ka_proto):
            desktop_bridge.login_via_desktop(
                params,
                bridge_module=bridge_module,
                bridge_socket='/tmp/keeper-bridge-leaf.sock',
                timeout_ms=1234,
            )

        request = bridge_module.last_request
        self.assertEqual('already_enrolled', request.flow)
        self.assertEqual('Keeper Commander', request.client.name)
        self.assertEqual('commander', request.client.kind)
        self.assertEqual(rest_api.CLIENT_VERSION, request.client.ka_client_version)
        self.assertEqual('/tmp/keeper-bridge-leaf.sock', request.config.socket_override)
        self.assertEqual(1234, request.config.timeout_millis)
        self.assertEqual(utils.base64_url_decode(params.device_token), request.device.encrypted_device_token)
        self.assertEqual(b'ka-session-token', params.session_token_bytes)
        self.assertEqual(utils.base64_url_encode(b'ka-session-token'), params.session_token)
        self.assertEqual(data_key, params.data_key)
        self.assertIsNone(params.clone_code)
        self.assertEqual('ka.user@example.com', params.user)
        populate_summary.assert_called_once_with(params)
        store_config.assert_not_called()

    def test_bridge_error_mapping_preserves_kdbc_fields(self):
        params, _ = _make_enrolled_params()

        with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as context:
            desktop_bridge.login_via_desktop(params, bridge_module=_make_bridge_module(error=_FakeBridgeError()))

        self.assertEqual('KDBC_VAULT_LOCKED', context.exception.code)
        self.assertEqual('vault_locked', context.exception.kind)
        self.assertTrue(context.exception.retryable)
        self.assertEqual('vault', context.exception.actor)
        self.assertEqual('request-1', context.exception.request_id)


class TestAutoEnrollment(TestCase):

    def test_fresh_install_auto_registers_device_then_proceeds(self):
        """No config.json — device token absent — bridge login should auto-register."""
        params = KeeperParams(server='keepersecurity.com')
        # no device_token, no device_private_key

        device_private_key_obj, _ = crypto.generate_ec_key()
        device_private_key_bytes = crypto.unload_ec_private_key(device_private_key_obj)
        device_public_key = device_private_key_obj.public_key()
        data_key = utils.generate_aes_key()

        def fake_get_device_id(p):
            p.device_token = utils.base64_url_encode(b'new-device-token')
            p.device_private_key = utils.base64_url_encode(device_private_key_bytes)

        vault_result = _VaultBootstrapResult(vault_session_token=b'vault-session-token')
        bridge_module = _make_bridge_module(vault_result=vault_result)
        ka_proto = _make_ka_proto_response(device_public_key, data_key)

        with mock.patch('keepercommander.loginv3.LoginV3API.get_device_id', side_effect=fake_get_device_id), \
                mock.patch('keepercommander.loginv3.LoginV3Flow.populateAccountSummary'), \
                mock.patch('keepercommander.rest_api.execute_rest', return_value=ka_proto):
            desktop_bridge.login_via_desktop(params, bridge_module=bridge_module)

        self.assertEqual(data_key, params.data_key)
        self.assertEqual(b'ka-session-token', params.session_token_bytes)

    def test_fresh_install_registration_failure_raises_not_enrolled(self):
        params = KeeperParams(server='keepersecurity.com')

        with mock.patch('keepercommander.loginv3.LoginV3API.get_device_id',
                        side_effect=Exception('network error')):
            with self.assertRaises(desktop_bridge.DesktopBridgeLoginError) as ctx:
                desktop_bridge.login_via_desktop(params, bridge_module=_make_bridge_module())

        self.assertEqual(desktop_bridge.KDBC_CLIENT_NOT_ENROLLED, ctx.exception.code)
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
