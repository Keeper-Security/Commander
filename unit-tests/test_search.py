from unittest import TestCase, mock

from data_vault import VaultEnvironment, get_synced_params, get_user_params
from keepercommander import api

vault_env = VaultEnvironment()


class TestSearch(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

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
