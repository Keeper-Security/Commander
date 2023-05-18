from unittest import TestCase, mock

from data_vault import VaultEnvironment, get_synced_params
from keepercommander.api import sync_down, crypto, utils
from keepercommander.proto import SyncDown_pb2

vault_env = VaultEnvironment()


class TestSyncDown(TestCase):
    def test_full_sync(self):
        params = get_synced_params()

        self.assertEqual(len(params.record_cache), 3)
        self.assertEqual(len(params.shared_folder_cache), 1)
        self.assertEqual(len(params.team_cache), 1)
        self.assert_key_unencrypted(params)

    def test_sync_remove_owned_records(self):
        params = get_synced_params()
        len_before = len(params.record_cache)

        records_to_delete = [x for x, md in params.meta_data_cache.items() if md.get('owner') is True]

        with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
            rs = SyncDown_pb2.SyncDownResponse()
            rs.continuationToken = crypto.get_random_bytes(64)
            rs.removedRecords.extend((utils.base64_url_decode(x) for x in records_to_delete))
            mock_comm.return_value = rs
            sync_down(params)

        self.assertEqual(len(params.record_cache), len_before - len(records_to_delete))
        self.assert_key_unencrypted(params)

    def test_sync_remove_team(self):
        params = get_synced_params()
        teams_to_delete = [x['team_uid'] for x in params.team_cache.values()]

        with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
            rs = SyncDown_pb2.SyncDownResponse()
            rs.continuationToken = crypto.get_random_bytes(64)
            rs.removedTeams.extend((utils.base64_url_decode(x) for x in teams_to_delete))
            mock_comm.return_value = rs
            sync_down(params)

        self.assertEqual(len(params.record_cache), 3)
        self.assertEqual(len(params.team_cache), 0)
        self.assert_key_unencrypted(params)

    def test_sync_remove_shared_folder_then_team(self):
        params = get_synced_params()
        sf_to_delete = [x['shared_folder_uid'] for x in params.shared_folder_cache.values()]

        with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
            rs = SyncDown_pb2.SyncDownResponse()
            rs.continuationToken = crypto.get_random_bytes(64)
            rs.removedSharedFolders.extend((utils.base64_url_decode(x) for x in sf_to_delete))
            mock_comm.return_value = rs
            sync_down(params)

        self.assertEqual(len(params.record_cache), 3)
        self.assertEqual(len(params.shared_folder_cache), 1)
        self.assertEqual(len(params.team_cache), 1)
        self.assert_key_unencrypted(params)

        teams_to_delete = [x['team_uid'] for x in params.team_cache.values()]

        with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
            rs = SyncDown_pb2.SyncDownResponse()
            rs.continuationToken = crypto.get_random_bytes(64)
            rs.removedTeams.extend((utils.base64_url_decode(x) for x in teams_to_delete))
            mock_comm.return_value = rs
            sync_down(params)

        self.assertEqual(len(params.record_cache), 2)
        self.assertEqual(len(params.shared_folder_cache), 0)
        self.assertEqual(len(params.team_cache), 0)
        self.assert_key_unencrypted(params)

    def test_sync_remove_team_shared_folder(self):
        params = get_synced_params()
        teams_to_delete = [x['team_uid'] for x in params.team_cache.values()]
        sf_to_delete = [x['shared_folder_uid'] for x in params.shared_folder_cache.values()]

        with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
            rs = SyncDown_pb2.SyncDownResponse()
            rs.continuationToken = crypto.get_random_bytes(64)
            rs.removedTeams.extend((utils.base64_url_decode(x) for x in teams_to_delete))
            rs.removedSharedFolders.extend((utils.base64_url_decode(x) for x in sf_to_delete))
            mock_comm.return_value = rs
            sync_down(params)

        self.assertEqual(len(params.record_cache), 2)
        self.assertEqual(len(params.shared_folder_cache), 0)
        self.assertEqual(len(params.team_cache), 0)
        self.assert_key_unencrypted(params)

    def assert_key_unencrypted(self, params):
        for r in params.record_cache.values():
            self.assertTrue('record_key_unencrypted' in r)
        for sf in params.shared_folder_cache.values():
            self.assertTrue('shared_folder_key_unencrypted' in sf)
        for t in params.team_cache.values():
            self.assertTrue('team_key_unencrypted' in t)
