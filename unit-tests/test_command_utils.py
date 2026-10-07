from unittest import TestCase, mock, skip

import datetime

from data_enterprise import EnterpriseEnvironment
from data_vault import get_synced_params, get_user_params, get_connected_params, VaultEnvironment
from helper import KeeperApiHelper
from keepercommander.commands import utils
from keepercommander import __main__ as keeper_main
from keepercommander.__main__ import parser as keeper_parser


vault_env = VaultEnvironment()
ent_env = EnterpriseEnvironment()


class TestSkipScanCLI(TestCase):
    def test_skip_scan_flag_before_or_after_command(self):
        for argv in (['--skip-scan', 'list'], ['list', '--skip-scan']):
            with self.subTest(argv=argv):
                opts, remaining = keeper_parser.parse_known_args(argv)
                self.assertEqual(opts.command, 'list')
                self.assertTrue(opts.skip_scan)
                self.assertEqual(remaining, [])

    def test_login_command_flag_is_parsed(self):
        opts = utils.LoginCommand().get_parser().parse_args([
            '--skip-scan', 'user@example.com'
        ])
        self.assertTrue(opts.skip_scan)

    def test_global_flag_survives_login_command_reconstruction(self):
        command_lines = (
            (['keeper', '--skip-scan', 'login', 'user@example.com'],
             ['login user@example.com', 'q']),
            (['keeper', '--skip-scan', 'shell', 'login', 'user@example.com'],
             ['login user@example.com']),
            (['keeper', 'shell', '--skip-scan', 'login', 'user@example.com'],
             ['login user@example.com']),
        )
        for argv, expected_commands in command_lines:
            with self.subTest(argv=argv):
                params = get_user_params()
                with mock.patch('sys.argv', argv), \
                        mock.patch.object(keeper_main, 'get_params_from_config', return_value=params), \
                        mock.patch.object(keeper_main.cli, 'loop', return_value=0) as loop, \
                        mock.patch('sys.exit'):
                    keeper_main.main()

                self.assertTrue(params.skip_scan)
                loop.assert_called_once()
                self.assertEqual(loop.call_args.args[0].commands, expected_commands)


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

    def test_login_skip_scan_keeps_vault_and_enterprise_sync(self):
        params = get_user_params()
        params.config['config_storage'] = 'file'
        params.skip_scan = True

        def sync_down_effect(p, **kwargs):
            p.sync_data = False

        with mock.patch('keepercommander.api.login', side_effect=lambda p, **kwargs: setattr(p, 'session_token', 'token')), \
                mock.patch.object(utils.SyncDownCommand, 'execute', side_effect=sync_down_effect) as sync_down, \
                mock.patch('keepercommander.api.query_enterprise') as query_enterprise, \
                mock.patch.object(utils.BreachWatchScanCommand, 'execute') as breachwatch_scan, \
                mock.patch.object(utils.SyncSecurityDataCommand, 'execute') as sync_security_data, \
                mock.patch('keepercommander.loginv3.LoginV3API.register_encrypted_data_key_for_device') as register_device:
            params.is_enterprise_admin = True
            params.breach_watch = True
            params.enterprise_ec_key = b'enterprise-key'
            utils.LoginCommand().execute(
                params,
                email=params.user,
                password=params.password,
                show_help=False
            )

        sync_down.assert_called_once_with(params, force=True)
        query_enterprise.assert_called_once_with(params, True)
        breachwatch_scan.assert_not_called()
        sync_security_data.assert_not_called()
        register_device.assert_not_called()
        # Normal vault sync leaves the command-dispatch post-sync hook idle.
        self.assertFalse(params.sync_data)

    def test_login_command_skip_scan_flag_uses_kwargs(self):
        params = get_user_params()
        params.config['config_storage'] = 'file'

        def sync_down_effect(p, **kwargs):
            p.sync_data = False

        with mock.patch('keepercommander.api.login', side_effect=lambda p, **kwargs: setattr(p, 'session_token', 'token')), \
                mock.patch.object(utils.SyncDownCommand, 'execute', side_effect=sync_down_effect) as sync_down, \
                mock.patch.object(utils.BreachWatchScanCommand, 'execute') as breachwatch_scan, \
                mock.patch.object(utils.SyncSecurityDataCommand, 'execute') as sync_security_data, \
                mock.patch('keepercommander.loginv3.LoginV3API.register_encrypted_data_key_for_device') as register_device:
            params.breach_watch = True
            params.enterprise_ec_key = b'enterprise-key'
            utils.LoginCommand().execute_args(
                params,
                f'--skip-scan {params.user}',
                show_help=False
            )

        sync_down.assert_called_once_with(params, force=True)
        breachwatch_scan.assert_not_called()
        sync_security_data.assert_not_called()
        register_device.assert_not_called()

    def test_login_without_skip_scan_and_registration_keeps_post_login_work(self):
        params = get_user_params()
        params.config['config_storage'] = 'file'
        params.is_enterprise_admin = True
        params.breach_watch = True
        params.enterprise_ec_key = b'enterprise-key'

        with mock.patch('keepercommander.api.login', side_effect=lambda p, **kwargs: setattr(p, 'session_token', 'token')), \
                mock.patch.object(utils.SyncDownCommand, 'execute') as sync_down, \
                mock.patch('keepercommander.api.query_enterprise') as query_enterprise, \
                mock.patch.object(utils.BreachWatchScanCommand, 'execute') as breachwatch_scan, \
                mock.patch.object(utils.SyncSecurityDataCommand, 'execute') as sync_security_data, \
                mock.patch('keepercommander.loginv3.LoginV3API.register_encrypted_data_key_for_device') as register_device:
            utils.LoginCommand().execute(
                params,
                email=params.user,
                password=params.password,
                show_help=False
            )

        sync_down.assert_called_once_with(params, force=True)
        query_enterprise.assert_called_once_with(params, True)
        breachwatch_scan.assert_called_once_with(params, suppress_no_op=True)
        sync_security_data.assert_called_once_with(params, record='@all', suppress_no_op=True)
        register_device.assert_called_once_with(params)

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
