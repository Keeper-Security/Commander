import json
from unittest import TestCase, mock

from data_vault import VaultEnvironment, get_synced_params
from keepercommander.api import sync_down, crypto, utils
from keepercommander.proto import SyncDown_pb2, record_pb2

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

        self.assertEqual(len(params.record_cache), 2)
        self.assertEqual(len(params.shared_folder_cache), 0)
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

    def test_classic_records_update_nested_share_revision(self):
        """Classic response.records must refresh nested_share_records.revision when present."""
        params = get_synced_params()
        record_uid = next(iter(params.record_cache))
        params.nested_share_records = {
            record_uid: {
                'record_uid': record_uid,
                'revision': 1,
                'version': 3,
                'shared': False,
                'client_modified_time': 0,
            }
        }
        new_revision = 42

        with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
            rs = SyncDown_pb2.SyncDownResponse()
            rs.continuationToken = crypto.get_random_bytes(64)
            rec = rs.records.add()
            rec.recordUid = utils.base64_url_decode(record_uid)
            rec.revision = new_revision
            rec.version = 3
            rec.shared = True
            rec.clientModifiedTime = 123456
            rec.data = b'\x00' * 16
            mock_comm.return_value = rs
            sync_down(params)

        self.assertEqual(params.record_cache[record_uid]['revision'], new_revision)
        self.assertEqual(params.nested_share_records[record_uid]['revision'], new_revision)
        self.assertEqual(params.nested_share_records[record_uid]['shared'], True)
        self.assertEqual(params.nested_share_records[record_uid]['client_modified_time'], 123456)

    def test_classic_records_does_not_downgrade_nsf_revision(self):
        """Deferred classic sync must not roll back a fresher NSF revision."""
        params = get_synced_params()
        record_uid = next(iter(params.record_cache))
        params.nested_share_records = {
            record_uid: {
                'record_uid': record_uid,
                'revision': 99,
                'version': 3,
                'shared': False,
                'client_modified_time': 0,
            }
        }
        stale_revision = 42

        with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
            rs = SyncDown_pb2.SyncDownResponse()
            rs.continuationToken = crypto.get_random_bytes(64)
            rec = rs.records.add()
            rec.recordUid = utils.base64_url_decode(record_uid)
            rec.revision = stale_revision
            rec.version = 3
            rec.shared = True
            rec.clientModifiedTime = 123456
            rec.data = b'\x00' * 16
            mock_comm.return_value = rs
            sync_down(params)

        self.assertEqual(params.record_cache[record_uid]['revision'], stale_revision)
        self.assertEqual(params.nested_share_records[record_uid]['revision'], 99)

    def assert_key_unencrypted(self, params):
        for r in params.record_cache.values():
            self.assertTrue('record_key_unencrypted' in r)
        for sf in params.shared_folder_cache.values():
            self.assertTrue('shared_folder_key_unencrypted' in sf)
        for t in params.team_cache.values():
            self.assertTrue('team_key_unencrypted' in t)


class TestSyncDownKsmAppMembership(TestCase):
    """KSM App Sharing v2: ksm_app_users / ksm_app_teams caches built from the sync-down response."""

    def setUp(self):
        self.app_uid_bytes = crypto.get_random_bytes(16)
        self.app_uid = utils.base64_url_encode(self.app_uid_bytes)
        self.team_uid_bytes = crypto.get_random_bytes(16)
        self.team_uid = utils.base64_url_encode(self.team_uid_bytes)

    def _sync(self, params, fill):
        rs = SyncDown_pb2.SyncDownResponse()
        rs.continuationToken = crypto.get_random_bytes(64)
        fill(rs)

        def respond(p, request, endpoint, **kwargs):
            # a full sync also asks for the record types
            if endpoint == 'vault/get_record_types':
                return record_pb2.RecordTypesResponse()
            return rs

        with mock.patch('keepercommander.api.communicate_rest', side_effect=respond):
            sync_down(params)

    def _add_user(self, rs, username='member@example.com', manage_users=True, manage_shares=False,
                  manage_devices=False, removed=False, record_key=None, key_type=None):
        change = rs.ksmAppUsers.add()
        change.appRecordUid = self.app_uid_bytes
        change.username = username
        change.canManageUsers = manage_users
        change.canManageShares = manage_shares
        change.canManageDevices = manage_devices
        change.removed = removed
        if record_key is not None:
            change.recordKey = record_key
            change.recordKeyType = key_type

    def _add_team(self, rs, manage_users=True, manage_shares=False, manage_devices=False, removed=False):
        change = rs.ksmAppTeams.add()
        change.appRecordUid = self.app_uid_bytes
        change.teamUid = self.team_uid_bytes
        change.canManageUsers = manage_users
        change.canManageShares = manage_shares
        change.canManageDevices = manage_devices
        change.removed = removed

    def test_app_user_is_cached_with_permission_bits(self):
        params = get_synced_params()
        self._sync(params, lambda rs: self._add_user(rs, manage_users=True, manage_shares=False, manage_devices=True))

        entry = params.ksm_app_users[self.app_uid]['member@example.com']
        self.assertTrue(entry['can_manage_users'])
        self.assertFalse(entry['can_manage_shares'])
        self.assertTrue(entry['can_manage_devices'])
        self.assertNotIn('record_key', entry, 'no key was sent, so none is cached')

    def test_app_user_update_replaces_the_bits(self):
        params = get_synced_params()
        self._sync(params, lambda rs: self._add_user(rs, manage_users=True, manage_shares=False))
        self._sync(params, lambda rs: self._add_user(rs, manage_users=False, manage_shares=True))

        entry = params.ksm_app_users[self.app_uid]['member@example.com']
        self.assertFalse(entry['can_manage_users'])
        self.assertTrue(entry['can_manage_shares'])

    def test_removed_app_user_is_dropped_and_others_stay(self):
        params = get_synced_params()

        def add_two(rs):
            self._add_user(rs, username='a@example.com')
            self._add_user(rs, username='b@example.com')

        self._sync(params, add_two)
        self._sync(params, lambda rs: self._add_user(rs, username='a@example.com', removed=True))

        self.assertNotIn('a@example.com', params.ksm_app_users[self.app_uid])
        self.assertIn('b@example.com', params.ksm_app_users[self.app_uid])

    def test_app_user_record_key_is_decrypted(self):
        params = get_synced_params()
        record_key = crypto.get_random_bytes(32)
        encrypted = crypto.encrypt_aes_v1(record_key, params.data_key)
        self._sync(params, lambda rs: self._add_user(
            rs, record_key=encrypted, key_type=record_pb2.ENCRYPTED_BY_DATA_KEY))

        entry = params.ksm_app_users[self.app_uid]['member@example.com']
        self.assertEqual(record_key, entry['record_key_unencrypted'])

    def test_app_user_with_undecryptable_key_is_cached_without_the_key(self):
        params = get_synced_params()
        self._sync(params, lambda rs: self._add_user(
            rs, record_key=crypto.get_random_bytes(48), key_type=record_pb2.ENCRYPTED_BY_DATA_KEY))

        entry = params.ksm_app_users[self.app_uid]['member@example.com']
        self.assertIn('record_key', entry)
        self.assertNotIn('record_key_unencrypted', entry, 'a bad key must not break the sync')

    def test_app_team_is_cached_then_removed(self):
        params = get_synced_params()
        self._sync(params, lambda rs: self._add_team(rs, manage_users=False, manage_devices=True))

        entry = params.ksm_app_teams[self.app_uid][self.team_uid]
        self.assertFalse(entry['can_manage_users'])
        self.assertTrue(entry['can_manage_devices'])

        self._sync(params, lambda rs: self._add_team(rs, removed=True))
        self.assertNotIn(self.team_uid, params.ksm_app_teams[self.app_uid])

    def test_removed_app_record_drops_its_membership_caches(self):
        params = get_synced_params()

        def add_both(rs):
            self._add_user(rs)
            self._add_team(rs)

        self._sync(params, add_both)
        self._sync(params, lambda rs: rs.removedRecords.append(self.app_uid_bytes))

        self.assertNotIn(self.app_uid, params.ksm_app_users)
        self.assertNotIn(self.app_uid, params.ksm_app_teams)

    def test_removed_team_is_pruned_from_every_app(self):
        params = get_synced_params()
        self._sync(params, lambda rs: self._add_team(rs))
        self._sync(params, lambda rs: rs.removedTeams.append(self.team_uid_bytes))

        self.assertNotIn(self.team_uid, params.ksm_app_teams[self.app_uid])

    def test_full_resync_clears_the_membership_caches(self):
        params = get_synced_params()

        def add_both(rs):
            self._add_user(rs)
            self._add_team(rs)

        self._sync(params, add_both)
        self.assertTrue(params.ksm_app_users)

        def full_sync(rs):
            rs.cacheStatus = SyncDown_pb2.CLEAR

        self._sync(params, full_sync)

        self.assertEqual({}, params.ksm_app_users)
        self.assertEqual({}, params.ksm_app_teams)

    def test_member_gets_the_app_record_key_from_their_membership(self):
        """A member who does not own the app has no record key of their own; it comes from the membership row."""
        params = get_synced_params()
        record_key = crypto.get_random_bytes(32)

        def fill(rs):
            record = rs.records.add()
            record.recordUid = self.app_uid_bytes
            record.revision = 1
            record.version = 3
            record.shared = True
            record.clientModifiedTime = utils.current_milli_time()
            record.data = crypto.encrypt_aes_v2(json.dumps({'title': 'Shared App'}).encode('utf-8'), record_key)
            self._add_user(rs, username=params.user, record_key=crypto.encrypt_aes_v1(record_key, params.data_key),
                           key_type=record_pb2.ENCRYPTED_BY_DATA_KEY)

        self._sync(params, fill)

        self.assertIn(self.app_uid, params.record_cache, 'the app record must survive the sync')
        self.assertEqual(record_key, params.record_cache[self.app_uid]['record_key_unencrypted'])
