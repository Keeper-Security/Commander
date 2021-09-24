from unittest import TestCase, mock

from data_vault import VaultEnvironment, get_synced_params, get_connected_params
from helper import KeeperApiHelper
from keepercommander import api
from keepercommander import APIRequest_pb2 as proto

vault_env = VaultEnvironment()


class TestSearch(TestCase):
    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command

    def tearDown(self):
        mock.patch.stopall()

    def test_search_records(self):
        params = get_synced_params()

        records = api.search_records(params, '')
        self.assertEqual(len(records), len(params.record_cache))

        records = api.search_records(params, 'RECORD')
        self.assertEqual(len(records), len(params.record_cache))

        records = api.search_records(params, 'Record 1')
        self.assertEqual(len(records), 1)

        records = api.search_records(params, 'INVALID')
        self.assertEqual(len(records), 0)

    def test_search_shared_folders(self):
        params = get_synced_params()

        sfs = api.search_shared_folders(params, '')
        self.assertEqual(len(sfs), len(params.shared_folder_cache))

        sfs = api.search_shared_folders(params, 'folder')
        self.assertEqual(len(sfs), len(params.shared_folder_cache))

        sfs = api.search_shared_folders(params, '1')
        self.assertEqual(len(sfs), 1)

        sfs = api.search_shared_folders(params, 'INVALID')
        self.assertEqual(len(sfs), 0)

    def test_search_teams(self):
        params = get_synced_params()

        teams = api.search_teams(params, '')
        self.assertEqual(len(teams), len(params.team_cache))

        teams = api.search_shared_folders(params, 'team')
        self.assertEqual(len(teams), len(params.shared_folder_cache))

        teams = api.search_shared_folders(params, '1')
        self.assertEqual(len(teams), 1)

        teams = api.search_shared_folders(params, 'INVALID')
        self.assertEqual(len(teams), 0)

    def test_change_password(self):
        params = get_connected_params()

        with mock.patch('keepercommander.rest_api.get_new_user_params') as m_params, mock.patch('builtins.print'), mock.patch('getpass.getpass') as m_getpass:
            user_params = proto.NewUserMinimumParams()
            user_params.minimumIterations = 1000
            user_params.passwordMatchRegex.extend(['^(?=(.*[A-Z]){1,}).*$', '^(?=(.*[0-9]){2,}).*$', '.{6,}'])
            user_params.passwordMatchDescription.extend(['Contains at least 1 uppercase character(s)', 'Contains at least 2 digit(s)', 'At least 6 character(s)'])
            m_params.return_value = user_params

            m_getpass.return_value = '1New2Password3'

            KeeperApiHelper.communicate_expect(['change_master_password'])
            self.assertTrue(api.change_master_password(params))
            self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_change_weak_password(self):
        params = get_connected_params()

        with mock.patch('keepercommander.rest_api.get_new_user_params') as m_params, mock.patch('builtins.print'), mock.patch('getpass.getpass') as m_getpass:
            user_params = proto.NewUserMinimumParams()
            user_params.minimumIterations = 1000
            user_params.passwordMatchRegex.extend(['^(?=(.*[A-Z]){1,}).*$', '^(?=(.*[0-9]){2,}).*$', '.{6,}'])
            user_params.passwordMatchDescription.extend(['Contains at least 1 uppercase character(s)', 'Contains at least 2 digit(s)', 'At least 6 character(s)'])
            m_params.return_value = user_params

            m_getpass.side_effect = ['NewPassword', 'NewPassword', '', Exception()]

            with self.assertLogs():
                self.assertFalse(api.change_master_password(params))

    def test_change_different_password(self):
        params = get_connected_params()

        with mock.patch('keepercommander.rest_api.get_new_user_params') as m_params, mock.patch('builtins.print'), mock.patch('getpass.getpass') as m_getpass:
            user_params = proto.NewUserMinimumParams()
            user_params.minimumIterations = 1000
            user_params.passwordMatchRegex.extend(['^(?=(.*[A-Z]){1,}).*$', '^(?=(.*[0-9]){2,}).*$', '.{6,}'])
            user_params.passwordMatchDescription.extend(['Contains at least 1 uppercase character(s)', 'Contains at least 2 digit(s)', 'At least 6 character(s)'])
            m_params.return_value = user_params

            m_getpass.side_effect = ['0New1Password2', '2New1Password0', '', Exception()]

            with self.assertLogs():
                self.assertFalse(api.change_master_password(params))

    def test_accept_account_transfer_consent(self):
        params = get_connected_params()
        params.settings = {
            'must_perform_account_share_by': '1632370067000',
            'share_account_to': [{
                'role_id': 123456789,
                'public_key': vault_env.encoded_public_key
            }]
        }
        with mock.patch('builtins.print'), mock.patch('builtins.input', return_value='accept'):

            KeeperApiHelper.communicate_expect(['share_account'])
            self.assertTrue(api.accept_account_transfer_consent(params))
            self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_decline_account_transfer_consent(self):
        params = get_connected_params()
        params.settings = {
            'must_perform_account_share_by': '1632370067000',
            'share_account_to': [{
                'role_id': 123456789,
                'public_key': vault_env.encoded_public_key
            }]
        }
        with mock.patch('builtins.print'), mock.patch('builtins.input', return_value='decline'):
            self.assertFalse(api.accept_account_transfer_consent(params))
