"""LoginV3Flow must keep the login type when it restarts login after device approval.

An SSO user who chooses "SSO User with a Master Password" logs in with loginType=ALTERNATE.
On a new device the server first asks for device approval; once the device is verified, the
flow calls start_login again. If that call drops back to NORMAL, the server answers with the
SSO redirect instead of the master password prompt.
"""
from unittest import TestCase, mock

from keepercommander.auth import login_steps
from keepercommander.loginv3 import LoginV3Flow, LoginV3API
from keepercommander.params import KeeperParams
from keepercommander.proto import APIRequest_pb2


def _response(state, url=''):
    rs = APIRequest_pb2.LoginResponse()
    rs.loginState = state
    rs.encryptedLoginToken = b'login-token'
    if url:
        rs.url = url
    return rs


class _ScriptedLoginUi(login_steps.LoginUi):
    """Chooses the master password at the SSO prompt and approves the device by email code."""

    def __init__(self):
        self.sso_redirects = 0

    def on_device_approval(self, step):
        step.send_code(login_steps.DeviceApprovalChannel.Email, '12345678')

    def on_two_factor(self, step):
        raise AssertionError('unexpected 2FA prompt')

    def on_password(self, step):
        raise AssertionError('unexpected password prompt')

    def on_sso_redirect(self, step):
        self.sso_redirects += 1
        step.login_with_password()

    def on_sso_data_key(self, step):
        raise AssertionError('unexpected SSO data key prompt')


class TestLoginTypeAfterDeviceApproval(TestCase):
    def setUp(self):
        self.params = KeeperParams()
        self.params.user = 'sso.user@example.com'
        self.params.config = {}
        self.ui = _ScriptedLoginUi()
        self.flow = LoginV3Flow(login_ui=self.ui)

        patches = [
            mock.patch('keepercommander.biometric.check_biometric_previously_used', return_value=False),
            mock.patch.object(LoginV3API, 'get_device_id', return_value=b'device-token'),
            mock.patch.object(LoginV3API, 'validateDeviceVerificationCodeMessage'),
            mock.patch.object(LoginV3Flow, 'post_login_processing'),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _login(self, responses):
        with mock.patch.object(LoginV3API, 'startLoginMessage', side_effect=responses) as start_login:
            self.flow.login(self.params)
        return [c.kwargs.get('loginType', 'NORMAL') for c in start_login.call_args_list]

    def test_sso_master_password_choice_survives_device_approval(self):
        login_types = self._login([
            _response(APIRequest_pb2.REDIRECT_ONSITE_SSO, url='https://sso.example.com/login'),
            _response(APIRequest_pb2.DEVICE_APPROVAL_REQUIRED),
            _response(APIRequest_pb2.LOGGED_IN),
        ])
        self.assertEqual(login_types, ['NORMAL', 'ALTERNATE', 'ALTERNATE'])
        self.assertEqual(self.ui.sso_redirects, 1)

    def test_sso_master_password_config_survives_device_approval(self):
        self.params.config = {'sso_master_password': True}
        login_types = self._login([
            _response(APIRequest_pb2.DEVICE_APPROVAL_REQUIRED),
            _response(APIRequest_pb2.LOGGED_IN),
        ])
        self.assertEqual(login_types, ['ALTERNATE', 'ALTERNATE'])
        self.assertEqual(self.ui.sso_redirects, 0)

    def test_normal_login_stays_normal_after_device_approval(self):
        login_types = self._login([
            _response(APIRequest_pb2.DEVICE_APPROVAL_REQUIRED),
            _response(APIRequest_pb2.LOGGED_IN),
        ])
        self.assertEqual(login_types, ['NORMAL', 'NORMAL'])
