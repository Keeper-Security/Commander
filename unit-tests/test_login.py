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

        TestLogin.has2fa = False
        TestLogin.dataKeyAsEncParam = False

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
        params = get_user_params()
        params.user = 'wrong.user@keepersecurity.com'
        with self.assertRaises(AuthenticationError):
            login(params)

    def test_login_auth_expired(self):
        params = get_user_params()

        call_no = 0
        def return_auth_expired(context, rq):
            nonlocal call_no
            call_no += 1
            rs = TestLogin.process_login_command(context, rq)
            if call_no == 1:
                rs['result'] = 'fail'
                rs['result_code'] = 'auth_expired'
                rs['message'] = 'Auth expired'
            elif call_no == 2:
                pass
            else:
                raise Exception()
            return rs

        self.v2_execute_mock.side_effect = return_auth_expired

        with mock.patch('keepercommander.api.change_master_password') as m_passwd:
            def password_changed(params):
                params.password = vault_env.password
                return True

            m_passwd.side_effect = password_changed
            with self.assertLogs():
                login(params)
            m_passwd.assert_called()

        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

    def test_account_transfer_expired(self):
        params = get_user_params()

        call_no = 0

        def return_auth_expired(context, rq):
            nonlocal call_no
            call_no += 1
            rs = TestLogin.process_login_command(context, rq)
            if call_no == 1:
                rs['result'] = 'fail'
                rs['result_code'] = 'auth_expired_transfer'
                rs['message'] = 'Auth Transfer expired'
                rs['settings'] = {
                    'share_account_to': [{
                        'role_id': 123456789,
                        'public_key': vault_env.encoded_public_key
                    }]
                }
            elif call_no == 2:
                pass
            else:
                raise Exception()
            return rs

        self.v2_execute_mock.side_effect = return_auth_expired

        with mock.patch('keepercommander.api.accept_account_transfer_consent') as m_transfer:
            m_transfer.return_value = True
            with self.assertLogs():
                login(params)
            m_transfer.assert_called()

        self.assertEqual(params.session_token, vault_env.session_token)
        self.assertEqual(params.data_key, vault_env.data_key)

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
                if TestLogin.has2fa and device_token:
                    rs['device_token'] = device_token
                    rs['dt_scope'] = 'expiration'

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

