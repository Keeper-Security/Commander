import base64

from unittest import TestCase, mock

from keepercommander.api import login, auth_verifier
from keepercommander.APIRequest_pb2 import PreLoginResponse, DeviceStatus
from keepercommander.error import KeeperApiError, AuthenticationError

from data_vault import get_user_params, VaultEnvironment, get_connected_params

vault_env = VaultEnvironment()

class TestLogin(TestCase):
    has2fa = False
    dataKeyAsEncParam = False
    enterpriseInvite = False
    enterpriseInviteCode = '987654321'

    def setUp(self):
        self.pre_login_mock = mock.patch('keepercommander.rest_api.pre_login').start()
        self.pre_login_mock.side_effect = TestLogin.process_pre_login

        self.v2_execute_mock = mock.patch('keepercommander.rest_api.v2_execute').start()
        self.v2_execute_mock.side_effect = TestLogin.process_login_command

        self.ctrl_c = KeyboardInterrupt()
        self.getpass_mock = mock.patch('getpass.getpass').start()
        self.getpass_mock.side_effect = self.ctrl_c

        self.store_config_mock = mock.patch('builtins.open', mock.mock_open()).start()
        self.store_config_mock.side_effect = Exception()

        self.input_mock = mock.patch('builtins.input').start()
        self.input_mock.side_effect = Exception()

        self.print_mock = mock.patch('builtins.print').start()

        self.comm_mock = mock.patch('keepercommander.api.communicate').start()
        self.input_mock.side_effect = Exception()

        TestLogin.has2fa = False
        TestLogin.dataKeyAsEncParam = False
        TestLogin.enterpriseInvite = False

    def tearDown(self):
        mock.patch.stopall()

    def test_login_success(self):
        params = get_user_params()
        login(params)
        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    def test_refresh_session_token(self):
        params = get_connected_params()
        login(params)
        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    def test_login_success_params(self):
        TestLogin.dataKeyAsEncParam = True
        params = get_user_params()
        login(params)
        self.assertEqual(params.data_key, vault_env.data_key)
        self.assertEqual(params.session_token, vault_env.session_token)

    def test_login_success_2fa_device_token(self):
        TestLogin.has2fa = True
        params = get_user_params()
        params.mfa_token = vault_env.device_token
        params.mfa_type = 'device_token'
        login(params)
        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    def test_login_success_2fa_one_time(self):
        TestLogin.has2fa = True
        self.getpass_mock.side_effect = [vault_env.one_time_token, self.ctrl_c]
        self.store_config_mock.side_effect = None
        params = get_user_params()
        login(params)
        self.store_config_mock.assert_called_once_with(params.config_filename, 'w')
        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    def test_login_success_2fa_cancel(self):
        TestLogin.has2fa = True
        params = get_user_params()
        login(params)
        self.assertFalse(params.session_token)

    def test_login_failed(self):
        params = get_user_params()
        params.password = '123456'
        with self.assertRaises(AuthenticationError):
            login(params)

    def test_login_invalid_user(self):
        TestLogin.has2fa = False
        params = get_user_params()
        params.user = 'wrong.user@keepersecurity.com'
        with self.assertRaises(AuthenticationError):
            login(params)

    def test_accept_invite(self):
        TestLogin.enterpriseInvite = True
        params = get_user_params()
        self.input_mock.side_effect = ['accept', TestLogin.enterpriseInviteCode, self.ctrl_c]
        self.comm_mock.side_effect = TestLogin.process_invite
        login(params)
        self.assertEqual(self.comm_mock.call_count, 1)
        self.assertEqual(self.input_mock.call_count, 2)
        self.assertEqual(self.print_mock.call_count, 1)
        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    def test_decline_invite(self):
        TestLogin.enterpriseInvite = True
        params = get_user_params()
        self.input_mock.side_effect = ['decline', self.ctrl_c]
        self.comm_mock.side_effect = TestLogin.process_invite
        login(params)
        self.assertEqual(self.comm_mock.call_count, 1)
        self.assertEqual(self.input_mock.call_count, 1)
        self.assertEqual(self.print_mock.call_count, 1)
        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    def test_ignore_invite(self):
        TestLogin.enterpriseInvite = True
        params = get_user_params()
        self.input_mock.side_effect = ['ignore', self.ctrl_c]
        login(params)
        self.assertEqual(self.input_mock.call_count, 1)
        self.assertEqual(self.print_mock.call_count, 1)
        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    @staticmethod
    def process_invite(context, rq):
        if rq['command'] == 'accept_enterprise_invite':
            if rq['verification_code'] == TestLogin.enterpriseInviteCode:
                return { 'result': 'success', 'result_code': ''}
            else:
                return { 'result': 'fail', 'result_code': 'bad_input_verification_code'}
        elif rq['command'] == 'decline_enterprise_invite':
            return { 'result': 'success', 'result_code': ''}
        return { 'result': 'fail', 'result_code': 'invalid_command'}

    @staticmethod
    def process_pre_login(context, user):
        # type: (any, str) -> PreLoginResponse
        if user == vault_env.user:
            rs = PreLoginResponse()
            rs.status = DeviceStatus.Value('OK')
            salt = rs.salt.add()
            salt.iterations = vault_env.iterations
            salt.salt = vault_env.salt
            salt.algorithm = 2
            salt.name = 'Master password'
            return rs

        raise KeeperApiError('user_does_not_exist', 'user_does_not_exist')

    @staticmethod
    def process_login_command(context, request):
        # type: (any, dict) -> dict
        if request['username'] == vault_env.user:
            auth1 = auth_verifier(vault_env.password, vault_env.salt, vault_env.iterations)
            if auth1 == request['auth_response']:
                device_token = None
                if TestLogin.has2fa:
                    method = request.get('2fa_type') or ''
                    token = request.get('2fa_token') or ''
                    if method == 'one_time':
                        if token != vault_env.one_time_token:
                            return {
                                'result' : 'fail',
                                'result_code': 'invalid_totp'
                            }
                        device_token = vault_env.device_token
                    elif method == 'device_token':
                        if token != vault_env.device_token:
                            return {
                                'result' : 'fail',
                                'result_code': 'invalid_device_token'
                            }
                    else:
                        return {
                            'result' : 'fail',
                            'result_code': 'need_totp'
                        }

                rs = {
                    'result': 'success',
                    'result_code': 'auth_success',
                    'session_token': vault_env.session_token
                }
                if TestLogin.enterpriseInvite:
                    rs['enforcements'] = {
                        'enterprise_invited': 'Test Enterprise'
                    }
                if TestLogin.has2fa and device_token:
                    rs['device_token'] = device_token

                if 'include' in request:
                    include = request['include']
                    if 'keys' in include:
                        keys = {
                            'encrypted_private_key': vault_env.encrypted_private_key
                        }
                        if TestLogin.dataKeyAsEncParam:
                            keys['encryption_params'] = vault_env.encryption_params
                        else:
                            keys['encrypted_data_key'] = vault_env.encrypted_data_key
                        rs['keys'] = keys

                    if 'is_enterprise_admin' in include:
                        rs['is_enterprise_admin'] = False

                return rs

            return {
                'result' : 'failure',
                'result_code': 'auth_failed',
                'salt': base64.urlsafe_b64encode(vault_env.salt).decode('utf-8').strip('='),
                'iterations': vault_env.iterations
            }

        return {
            'result' : 'failure',
            'result_code': 'Failed_to_find_user'
        }

