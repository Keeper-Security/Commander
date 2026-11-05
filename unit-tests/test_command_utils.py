from unittest import TestCase, mock, skip

import datetime

import pytest

from data_enterprise import EnterpriseEnvironment
from data_vault import get_synced_params, get_user_params, get_connected_params, VaultEnvironment
from helper import KeeperApiHelper
from keepercommander import constants, utils as core_utils
from keepercommander.commands import utils
from keepercommander.params import KeeperParams
from keepercommander.proto import APIRequest_pb2


vault_env = VaultEnvironment()
ent_env = EnterpriseEnvironment()


class TestRegister(TestCase):
    enterpriseInviteCode = '987654321'

    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command

    def tearDown(self):
        mock.patch.stopall()

    def test_whoami(self):
        params = get_synced_params()

        cmd = utils.WhoamiCommand()
        with mock.patch('builtins.print'):
            cmd.execute(params, verbose=True)

    def test_login(self):
        params = get_user_params()
        cmd = utils.LoginCommand()
        with mock.patch('builtins.input') as mock_input, \
                mock.patch('getpass.getpass') as mock_getpass, \
                mock.patch('keepercommander.api.login') as mock_login:
            mock_input.return_value = 'user3@keepersecurity.com'
            mock_getpass.return_value = '123456'
            cmd.execute(params)
            mock_login.assert_called()

            mock_login.reset_mock()
            mock_input.return_value = KeyboardInterrupt()
            mock_getpass.return_value = '123456'
            cmd.execute(params, email='user3@keepersecurity.com')
            mock_login.assert_called()

            mock_login.reset_mock()
            mock_input.return_value = KeyboardInterrupt()
            mock_getpass.return_value = KeyboardInterrupt()
            cmd.execute(params, email='user3@keepersecurity.com', password='123456')
            mock_login.assert_called()

            mock_login.reset_mock()
            mock_input.return_value = ''
            mock_getpass.return_value = ''
            cmd.execute(params)
            mock_login.assert_not_called()

    def test_logout(self):
        params = get_synced_params()
        cmd = utils.LogoutCommand()
        cmd.execute(params)
        self.assertIsNone(params.session_token)

    def test_enterprise_invite(self):
        params = get_connected_params()
        params.enforcements = {
            'enterprise_invited': 'Test Enterprise'
        }

        cmd = utils.CheckEnforcementsCommand()
        with mock.patch('builtins.print'), mock.patch('keepercommander.commands.utils.user_choice') as m_choice, mock.patch('builtins.input') as m_input:

            # accept, enter invite code
            def accept_enterprise_invite(rq):
                self.assertEqual(rq['command'], 'accept_enterprise_invite')
                self.assertEqual(rq['verification_code'], TestRegister.enterpriseInviteCode)
            m_choice.return_value = 'Accept'
            m_input.return_value = TestRegister.enterpriseInviteCode
            KeeperApiHelper.communicate_expect([accept_enterprise_invite])
            cmd.execute(params)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            # accept, skip invite code
            m_choice.return_value = 'Accept'
            m_input.return_value = ''
            cmd.execute(params)

            # decline
            m_choice.return_value = 'Decline'
            m_input.side_effect = KeyboardInterrupt()
            KeeperApiHelper.communicate_expect(['decline_enterprise_invite'])
            cmd.execute(params)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            # ignore
            m_choice.return_value = 'Ignore'
            cmd.execute(params)

    def test_account_transfer_consent(self):
        params = get_connected_params()
        params.settings = {
            'share_account_to': [{
                'role_id': ent_env.role1_id,
                'public_key': vault_env.encoded_public_key
            }],
            'must_perform_account_share_by': int(datetime.datetime.now().timestamp())
        }

        cmd = utils.CheckEnforcementsCommand()
        with mock.patch('builtins.print'), mock.patch('keepercommander.api.accept_account_transfer_consent') as m_transfer:

            m_transfer.return_value = True
            cmd.execute(params)
            m_transfer.assert_called()
            self.assertNotIn('share_account_to', params.settings)
            self.assertNotIn('must_perform_account_share_by', params.settings)

            m_transfer.reset()
            m_transfer.return_value = False
            cmd.execute(params)
            m_transfer.assert_called()
            self.assertNotIn('share_account_to', params.settings)
            self.assertNotIn('must_perform_account_share_by', params.settings)


def test_password_change_rejects_weak_current_parameters(monkeypatch):
    params = KeeperParams()
    params.user = 'user@example.com'
    params.settings = {}
    params.enforcements = None
    endpoints = []

    def fake_communicate_rest(_params, _request, endpoint, **_kwargs):
        endpoints.append(endpoint)
        salt = APIRequest_pb2.Salt()
        salt.salt = bytes(16)
        salt.iterations = 1
        return salt

    monkeypatch.setattr('keepercommander.commands.utils.api.communicate_rest', fake_communicate_rest)

    with pytest.raises(ValueError, match='below the required minimum'):
        utils.ResetPasswordCommand().execute(params, current_password='test-password')
    assert endpoints == ['authentication/get_salt_and_iterations']


def test_password_change_upgrades_legacy_iteration_count(monkeypatch):
    params = KeeperParams()
    params.user = 'legacy@example.com'
    params.settings = {}
    params.enforcements = None
    params.config = {}
    params.data_key = bytes(range(32))
    endpoints = []
    requests = []

    def fake_communicate_rest(_params, _request, endpoint, **_kwargs):
        endpoints.append(endpoint)
        if endpoint == 'authentication/get_salt_and_iterations':
            salt = APIRequest_pb2.Salt()
            salt.salt = b'0123456789abcdef'
            salt.iterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS
            return salt
        if endpoint == 'authentication/validate_master_password':
            response = APIRequest_pb2.MasterPasswordReentryResponse()
            response.status = APIRequest_pb2.MP_SUCCESS
            return response
        if endpoint == 'authentication/get_domain_password_rules':
            response = APIRequest_pb2.NewUserMinimumParams()
            response.minimumIterations = constants.PBKDF2_LEGACY_MIN_ITERATIONS
            return response
        pytest.fail(f'Unexpected endpoint: {endpoint}')

    monkeypatch.setattr('keepercommander.commands.utils.api.communicate_rest', fake_communicate_rest)
    monkeypatch.setattr('keepercommander.commands.utils.api.communicate',
                        lambda _params, request: requests.append(request))

    utils.ResetPasswordCommand().execute(
        params, current_password='old-password', new_password='new-password')

    assert endpoints == [
        'authentication/get_salt_and_iterations',
        'authentication/validate_master_password',
        'authentication/get_domain_password_rules',
    ]
    assert len(requests) == 1
    auth_verifier = core_utils.base64_url_decode(requests[0]['auth_verifier'])
    assert int.from_bytes(auth_verifier[1:4], byteorder='big') == constants.PBKDF2_ITERATIONS
    assert params.iterations == constants.PBKDF2_ITERATIONS
    assert core_utils.get_stored_pbkdf2_iterations(
        params.config, params.user, 'master') == constants.PBKDF2_ITERATIONS
