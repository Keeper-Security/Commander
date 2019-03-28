from unittest import TestCase, mock

from data_vault import get_synced_params, get_user_params
from keepercommander.commands import utils


class TestRegister(TestCase):
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
