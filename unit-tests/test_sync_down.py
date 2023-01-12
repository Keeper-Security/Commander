from unittest import TestCase, mock

from data_vault import VaultEnvironment, get_connected_params, get_sync_down_response, get_synced_params
from helper import KeeperApiHelper
from keepercommander.api import sync_down
from keepercommander.proto import record_pb2

vault_env = VaultEnvironment()


class TestSyncDown(TestCase):

    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command
        self.communicate_rest = mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        mock.patch.stopall()

    def test_full_sync(self):
        params = get_connected_params()
        self.communicate_mock.side_effect = None
        self.communicate_mock.return_value = get_sync_down_response()
        self.communicate_rest.return_value = record_pb2.RecordTypesResponse()

        sync_down(params)

        self.assertEqual(len(params.record_cache), 3)
        self.assertEqual(len(params.shared_folder_cache), 1)
        self.assertEqual(len(params.team_cache), 1)
        self.assert_key_unencrypted(params)

    def test_sync_remove_owned_records(self):
        params = get_synced_params()
        len_before = len(params.record_cache)

        records_to_delete = [x['record_uid'] for x in params.meta_data_cache.values() if x['owner']]

        def sync_down_removed_records(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_records': records_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_records])
        sync_down(params)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(len(params.record_cache), len_before - len(records_to_delete))
        self.assert_key_unencrypted(params)

    def test_sync_remove_team(self):
        params = get_synced_params()
        teams_to_delete = [x['team_uid'] for x in params.team_cache.values()]

        def sync_down_removed_teams(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_teams': teams_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_teams])
        sync_down(params)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(len(params.record_cache), 3)
        self.assertEqual(len(params.team_cache), 0)
        self.assert_key_unencrypted(params)

    def test_sync_remove_shared_folder_then_team(self):
        params = get_synced_params()
        sf_to_delete = [x['shared_folder_uid'] for x in params.shared_folder_cache.values()]

        def sync_down_removed_shared_folders(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_shared_folders': sf_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_shared_folders])
        sync_down(params)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(len(params.record_cache), 3)
        self.assertEqual(len(params.shared_folder_cache), 1)
        self.assertEqual(len(params.team_cache), 1)
        self.assert_key_unencrypted(params)

        teams_to_delete = [x['team_uid'] for x in params.team_cache.values()]

        def sync_down_removed_teams(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_teams': teams_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_teams])
        sync_down(params)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(len(params.record_cache), 2)
        self.assertEqual(len(params.shared_folder_cache), 0)
        self.assertEqual(len(params.team_cache), 0)
        self.assert_key_unencrypted(params)

    def test_sync_remove_team_shared_folder(self):
        params = get_synced_params()
        teams_to_delete = [x['team_uid'] for x in params.team_cache.values()]
        sf_to_delete = [x['shared_folder_uid'] for x in params.shared_folder_cache.values()]

        def sync_down_removed_teams_and_shared_folders(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_shared_folders': sf_to_delete,
                'removed_teams': teams_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_teams_and_shared_folders])
        sync_down(params)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

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
