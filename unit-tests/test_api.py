from unittest import TestCase, mock
from collections import namedtuple

from data_vault import VaultEnvironment, get_synced_params, get_connected_params
from helper import KeeperApiHelper
from keepercommander import api, generator

vault_env = VaultEnvironment()


class TestPasswordGenerator(TestCase):
    def test_generator_exclude(self):
        gen = generator.KeeperPasswordGenerator(length=20, caps=-2, lower=-2, digits=-2, symbols=0)
        self.assertEqual(gen.category_map[4][0], 14)
        password = gen.generate()
        strength = generator.get_password_strength(password)
        self.assertEqual(strength.length, 20)
        self.assertEqual(strength.symbols, 0)

    def test_generator_fail(self):
        with self.assertRaises(Exception):
            generator.KeeperPasswordGenerator(length=20, caps=0, lower=0, digits=0, symbols=0)


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
