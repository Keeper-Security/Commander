from unittest import TestCase, mock, skip

import datetime

from data_enterprise import EnterpriseEnvironment
from data_vault import get_synced_params, get_user_params, get_connected_params, VaultEnvironment
from helper import KeeperApiHelper
from keepercommander.commands import utils


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
            'must_perform_account_share_by': datetime.datetime.now().timestamp()
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
