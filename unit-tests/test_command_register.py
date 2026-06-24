import datetime
import json
from contextlib import contextmanager
from unittest import TestCase, mock

from data_vault import get_synced_params, VaultEnvironment
from keepercommander.commands import register
from keepercommander.error import CommandError
from keepercommander.proto import APIRequest_pb2, record_pb2
from keepercommander import utils
from keepercommander.subfolder import NestedShareFolderNode

vault_env = VaultEnvironment()


class TestRegister(TestCase):
    expected_commands = []

    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.run_command').start()
        self.communicate_mock.side_effect = TestRegister.communicate_success
        self.communicate_mock = mock.patch('keepercommander.api.communicate_rest').start()
        self.communicate_mock.side_effect = TestRegister.communicate_rest_success
        TestRegister.expected_commands.clear()

    def tearDown(self):
        mock.patch.stopall()

    def test_share_record(self):
        params = get_synced_params()

        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))
        cmd = register.ShareRecordCommand()

        def not_shared(params, record_uids, is_share_admin):
            pass
        self.record_share_mock = mock.patch('keepercommander.api.get_record_shares').start()
        self.record_share_mock.side_effect = not_shared

        TestRegister.expected_commands.extend(['records_share_update'])
        cmd.execute(params, email=['user2@keepersecurity.com'], action='grant', can_share=False, can_edit=True, record=record_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

        TestRegister.expected_commands.extend(['records_share_update'])
        cmd.execute(params, email=['user2@keepersecurity.com'], action='owner', can_share=False, can_edit=True, record=record_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

        def shared(params, record_uids, is_share_admin):
            return [{
                'shares': {
                    'user_permissions': [
                        {
                            'username': params.user,
                            'owner': True,
                        },
                        {
                            'username': 'user2@keepersecurity.com',
                            'owner': False,
                            'shareable': False,
                            'editable': False
                        }
                    ]
                }
            }]
        self.record_share_mock.side_effect = shared

        TestRegister.expected_commands.extend(['records_share_update'])
        cmd.execute(params, email=['user2@keepersecurity.com'], action='revoke', record=record_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

    @contextmanager
    def _make_record_rotation_eligible(self, params, target_uid):
        """Present the record as a pamUser with rotation configured (ROE-eligible)."""
        from keepercommander import vault
        params.record_rotation_cache[target_uid] = {'record_uid': target_uid, 'revision': 1}
        real_load = vault.KeeperRecord.load

        def fake_load(p, uid, *args, **kwargs):
            loaded = real_load(p, uid, *args, **kwargs)
            if uid == target_uid and loaded is not None:
                loaded.get_record_type = lambda: 'pamUser'
            return loaded

        with mock.patch.object(vault.KeeperRecord, 'load', side_effect=fake_load):
            yield

    def _capture_shared_record_requests(self):
        """Patch the response-builder so we can assert on outbound SharedRecord protos."""
        captured = []

        def capture(rq):
            status = record_pb2.SharedRecordStatus()
            status.recordUid = rq.recordUid
            status.status = 'success'
            status.username = rq.toUsername
            captured.append(rq)
            return status

        original = TestRegister.record_share_rq_rs
        TestRegister.record_share_rq_rs = staticmethod(capture)
        return captured, original

    @staticmethod
    def _existing_share_response(target_email, *, editable=False, shareable=False):
        def _impl(params, record_uids, *_args, **_kw):
            return [{
                'record_uid': next(iter(record_uids)),
                'shares': {
                    'user_permissions': [
                        {'username': params.user, 'owner': True},
                        {'username': target_email, 'owner': False,
                         'shareable': shareable, 'editable': editable},
                    ]
                }
            }]
        return _impl

    def test_share_record_rotate_on_expiration_sets_flag(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        captured, original = self._capture_shared_record_requests()
        try:
            mock.patch('keepercommander.api.get_record_shares',
                       side_effect=lambda *_args, **_kw: None).start()

            cmd = register.ShareRecordCommand()
            TestRegister.expected_commands.extend(['records_share_update'])
            with self._make_record_rotation_eligible(params, record_uid):
                cmd.execute(params,
                            email=['user2@keepersecurity.com'],
                            action='grant',
                            can_share=False,
                            can_edit=True,
                            record=record_uid,
                            expire_in='1d',
                            rotate_on_expiration=True)
            self.assertEqual(len(TestRegister.expected_commands), 0)
            target = next((r for r in captured if r.toUsername == 'user2@keepersecurity.com'), None)
            self.assertIsNotNone(target)
            self.assertTrue(target.rotateOnExpiration)
            self.assertGreater(target.expiration, 0)
            self.assertEqual(target.timerNotificationType, record_pb2.NOTIFY_OWNER)
        finally:
            TestRegister.record_share_rq_rs = original

    def test_share_record_rotate_on_expiration_sets_flag_on_existing_share(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        captured, original = self._capture_shared_record_requests()
        try:
            mock.patch('keepercommander.api.get_record_shares',
                       side_effect=self._existing_share_response('user2@keepersecurity.com')).start()

            cmd = register.ShareRecordCommand()
            TestRegister.expected_commands.extend(['records_share_update'])
            with self._make_record_rotation_eligible(params, record_uid):
                cmd.execute(params,
                            email=['user2@keepersecurity.com'],
                            action='grant',
                            can_share=False,
                            can_edit=False,
                            record=record_uid,
                            expire_in='1d',
                            rotate_on_expiration=True)
            self.assertEqual(len(TestRegister.expected_commands), 0)
            target = next((r for r in captured if r.toUsername == 'user2@keepersecurity.com'), None)
            self.assertIsNotNone(target)
            self.assertTrue(target.rotateOnExpiration,
                            'rotateOnExpiration must travel on update path, not just add path')
            self.assertGreater(target.expiration, 0)
            self.assertEqual(target.timerNotificationType, record_pb2.NOTIFY_OWNER)
        finally:
            TestRegister.record_share_rq_rs = original

    def test_share_record_update_expiration_without_roe(self):
        """Existing share must accept --expire-in updates, matching Vault UX."""
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        captured, original = self._capture_shared_record_requests()
        try:
            mock.patch('keepercommander.api.get_record_shares',
                       side_effect=self._existing_share_response('user2@keepersecurity.com', editable=True)).start()

            cmd = register.ShareRecordCommand()
            TestRegister.expected_commands.extend(['records_share_update'])
            cmd.execute(params,
                        email=['user2@keepersecurity.com'],
                        action='grant',
                        can_share=False,
                        can_edit=False,
                        record=record_uid,
                        expire_in='1d')
            target = next((r for r in captured if r.toUsername == 'user2@keepersecurity.com'), None)
            self.assertIsNotNone(target)
            self.assertGreater(target.expiration, 0)
            self.assertEqual(target.timerNotificationType, record_pb2.NOTIFY_OWNER)
            self.assertFalse(target.rotateOnExpiration)
        finally:
            TestRegister.record_share_rq_rs = original

    def test_share_record_update_clears_expiration_with_never(self):
        """--expire-at never on an existing share must clear the timer (expiration = -1)."""
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        captured, original = self._capture_shared_record_requests()
        try:
            mock.patch('keepercommander.api.get_record_shares',
                       side_effect=self._existing_share_response('user2@keepersecurity.com', editable=True)).start()

            cmd = register.ShareRecordCommand()
            TestRegister.expected_commands.extend(['records_share_update'])
            cmd.execute(params,
                        email=['user2@keepersecurity.com'],
                        action='grant',
                        can_share=False,
                        can_edit=False,
                        record=record_uid,
                        expire_at='never')
            target = next((r for r in captured if r.toUsername == 'user2@keepersecurity.com'), None)
            self.assertIsNotNone(target)
            self.assertEqual(target.expiration, -1)
            self.assertFalse(target.rotateOnExpiration)
        finally:
            TestRegister.record_share_rq_rs = original

    def test_share_record_rotate_on_expiration_requires_expiration(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        cmd = register.ShareRecordCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.prep_request(params, dict(
                email=['user2@keepersecurity.com'],
                action='grant',
                can_share=False,
                can_edit=False,
                record=record_uid,
                rotate_on_expiration=True,
            ))
        self.assertIn('--rotate-on-expiration', str(ctx.exception))

    def test_share_record_rotate_on_expiration_rejects_never(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        cmd = register.ShareRecordCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.prep_request(params, dict(
                email=['user2@keepersecurity.com'],
                action='grant',
                record=record_uid,
                expire_at='never',
                rotate_on_expiration=True,
            ))
        self.assertIn('--rotate-on-expiration', str(ctx.exception))

    def test_share_record_rotate_on_expiration_rejects_non_pam_user(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))
        # Intentionally do NOT mark as pamUser; keep the fixture's default type.
        cmd = register.ShareRecordCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.prep_request(params, dict(
                email=['user2@keepersecurity.com'],
                action='grant',
                record=record_uid,
                expire_in='1d',
                rotate_on_expiration=True,
            ))
        self.assertIn('pamUser', str(ctx.exception))

    def test_share_record_rotate_on_expiration_rejects_non_grant_action(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        cmd = register.ShareRecordCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.prep_request(params, dict(
                email=['user2@keepersecurity.com'],
                action='revoke',
                record=record_uid,
                expire_in='1d',
                rotate_on_expiration=True,
            ))
        self.assertIn('--rotate-on-expiration', str(ctx.exception))

    def test_share_folder(self):
        params = get_synced_params()
        shared_folder_uid = next(iter([x['shared_folder_uid'] for x in params.shared_folder_cache.values()]))
        cmd = register.ShareFolderCommand()

        TestRegister.expected_commands.extend(['shared_folder_update_v3'])
        cmd.execute(params, action='grant', user=['user2@keepersecurity.com'], manage_records=True, manage_users=False, folder=shared_folder_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

        TestRegister.expected_commands.extend(['shared_folder_update_v3'])
        cmd.execute(params, action='revoke', user=['user2@keepersecurity.com'], folder=shared_folder_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

    def test_share_folder_prepare_request_sets_rotate_on_expiration(self):
        """Folder-wide expiration/ROE applies to user/team protos, not record protos."""
        params = get_synced_params()
        shared_folder_uid = next(iter(params.shared_folder_cache.keys()))
        team_uid = utils.base64_url_encode(b'a' * 16)

        curr_sf = dict(params.shared_folder_cache[shared_folder_uid])
        curr_sf.setdefault('users', [])
        curr_sf['teams'] = [{'team_uid': team_uid, 'manage_records': True, 'manage_users': True}]
        curr_sf.setdefault('records', [])

        future_ts = int(datetime.datetime.now().timestamp()) + 86_400

        params.key_cache['user2@keepersecurity.com'] = mock.MagicMock(
            rsa=utils.base64_url_decode(vault_env.encoded_public_key), ec=None)

        rq = register.ShareFolderCommand.prepare_request(
            params,
            kwargs={'action': 'grant'},
            curr_sf=curr_sf,
            users=['user2@keepersecurity.com'],
            teams=[team_uid],
            rec_uids=[],
            share_expiration=future_ts,
            rotate_on_expiration=True,
        )

        user_msgs = list(rq.sharedFolderAddUser) + list(rq.sharedFolderUpdateUser)
        team_msgs = list(rq.sharedFolderAddTeam) + list(rq.sharedFolderUpdateTeam)
        record_msgs = list(rq.sharedFolderAddRecord) + list(rq.sharedFolderUpdateRecord)

        for msgs, label in [(user_msgs, 'user'), (team_msgs, 'team')]:
            self.assertTrue(msgs, f'expected at least one {label} proto on the wire')
            for m in msgs:
                self.assertTrue(m.rotateOnExpiration,
                                f'rotateOnExpiration must be set on every {label} proto')
                self.assertGreater(m.expiration, 0)
                self.assertEqual(m.timerNotificationType, record_pb2.NOTIFY_OWNER)

        self.assertFalse(record_msgs, 'record protos must not carry folder-wide expiration')

    def test_share_folder_prepare_request_sets_folder_and_record_expiration_when_records_specified(self):
        """With -r and --expire-in, folder user and record share both get timers; not SharedFolderUpdateRecord."""
        params = get_synced_params()
        shared_folder_uid = next(iter(params.shared_folder_cache.keys()))
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        curr_sf = dict(params.shared_folder_cache[shared_folder_uid])
        curr_sf.setdefault('users', [])
        curr_sf.setdefault('records', [{'record_uid': record_uid, 'can_edit': True, 'can_share': True}])
        future_ts = int(datetime.datetime.now().timestamp()) + 86_400

        params.key_cache['user2@keepersecurity.com'] = mock.MagicMock(
            rsa=utils.base64_url_decode(vault_env.encoded_public_key), ec=None)

        rq = register.ShareFolderCommand.prepare_request(
            params,
            kwargs={'action': 'grant', 'can_edit': 'on', 'can_share': 'on'},
            curr_sf=curr_sf,
            users=['user2@keepersecurity.com'],
            teams=[],
            rec_uids=[record_uid],
            share_expiration=future_ts,
            rotate_on_expiration=True,
        )

        user_msgs = list(rq.sharedFolderAddUser) + list(rq.sharedFolderUpdateUser)
        record_msgs = list(rq.sharedFolderAddRecord) + list(rq.sharedFolderUpdateRecord)

        self.assertTrue(user_msgs, 'expected folder user share with expiration')
        for m in user_msgs:
            self.assertGreater(m.expiration, 0)
            self.assertTrue(m.rotateOnExpiration)
            self.assertEqual(m.timerNotificationType, record_pb2.NOTIFY_OWNER)

        self.assertTrue(record_msgs, 'expected record permission update')
        for m in record_msgs:
            self.assertEqual(m.expiration, 0)
            self.assertFalse(m.rotateOnExpiration)

    def test_share_folder_prepare_record_share_request_sets_expiration(self):
        params = get_synced_params()
        shared_folder_uid = next(iter(params.shared_folder_cache.keys()))
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))
        curr_sf = dict(params.shared_folder_cache[shared_folder_uid])
        future_ts = int(datetime.datetime.now().timestamp()) + 86_400

        params.key_cache['user2@keepersecurity.com'] = mock.MagicMock(
            rsa=utils.base64_url_decode(vault_env.encoded_public_key), ec=None)

        rq = register.ShareFolderCommand.prepare_record_share_request(
            params,
            kwargs={'action': 'grant', 'can_edit': 'on', 'can_share': 'on'},
            shared_folder_uid=shared_folder_uid,
            users=['user2@keepersecurity.com'],
            rec_uids=[record_uid],
            curr_sf=curr_sf,
            share_expiration=future_ts,
            rotate_on_expiration=True,
        )

        self.assertIsNotNone(rq)
        self.assertEqual(len(rq), 2, 'positive expiration must revoke then re-grant')
        self.assertTrue(rq[0].removeSharedRecord)
        self.assertTrue(rq[1].addSharedRecord)
        shared_records = list(rq[1].addSharedRecord)
        self.assertTrue(shared_records)
        for sr in shared_records:
            self.assertGreater(sr.expiration, 0)
            self.assertTrue(sr.rotateOnExpiration)
            self.assertEqual(sr.timerNotificationType, record_pb2.NOTIFY_OWNER)
            self.assertEqual(utils.base64_url_encode(sr.sharedFolderUid), shared_folder_uid)

    def test_share_folder_prepare_request_skips_redundant_user_update_for_record_only(self):
        """When sharing another record without expiration, skip redundant folder user update."""
        params = get_synced_params()
        shared_folder_uid = next(iter(params.shared_folder_cache.keys()))
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))

        curr_sf = dict(params.shared_folder_cache[shared_folder_uid])
        curr_sf['users'] = [{
            'username': 'user2@keepersecurity.com',
            'manage_records': True,
            'manage_users': True,
        }]
        curr_sf.setdefault('records', [{'record_uid': record_uid, 'can_edit': True, 'can_share': True}])

        rq = register.ShareFolderCommand.prepare_request(
            params,
            kwargs={'action': 'grant', 'manage_records': 'on', 'manage_users': 'on',
                    'can_edit': 'on', 'can_share': 'on'},
            curr_sf=curr_sf,
            users=['user2@keepersecurity.com'],
            teams=[],
            rec_uids=[record_uid],
            share_expiration=None,
        )

        self.assertFalse(list(rq.sharedFolderUpdateUser))
        self.assertTrue(list(rq.sharedFolderAddRecord),
                        'new record grant should update folder record permissions via add')
        self.assertFalse(list(rq.sharedFolderUpdateRecord))

    def test_share_folder_prepare_request_updates_user_when_folder_wide_expiration(self):
        """Folder-wide --expire-in (no -r) sets expiration on the folder user share."""
        params = get_synced_params()
        shared_folder_uid = next(iter(params.shared_folder_cache.keys()))
        future_ts = int(datetime.datetime.now().timestamp()) + 86_400

        curr_sf = dict(params.shared_folder_cache[shared_folder_uid])
        curr_sf['users'] = [{
            'username': 'user2@keepersecurity.com',
            'manage_records': True,
            'manage_users': True,
        }]

        rq = register.ShareFolderCommand.prepare_request(
            params,
            kwargs={'action': 'grant', 'manage_records': 'on', 'manage_users': 'on'},
            curr_sf=curr_sf,
            users=['user2@keepersecurity.com'],
            teams=[],
            rec_uids=[],
            share_expiration=future_ts,
        )

        user_msgs = list(rq.sharedFolderUpdateUser)
        self.assertTrue(user_msgs)
        self.assertGreater(user_msgs[0].expiration, 0)

    def test_share_folder_rotate_on_expiration_rejects_folder_without_pam_user(self):
        params = get_synced_params()
        shared_folder_uid = next(iter(params.shared_folder_cache.keys()))
        cmd = register.ShareFolderCommand()
        with mock.patch('keepercommander.commands.register.SyncDownCommand.execute'):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params, action='grant', user=['user2@keepersecurity.com'],
                            folder=shared_folder_uid, expire_in='1d', rotate_on_expiration=True)
        self.assertIn('pamUser', str(ctx.exception))

    @staticmethod
    def _attach_nested_share_folder(params, record_uid, folder_name='Drive'):
        folder_uid = utils.generate_uid()
        folder_node = NestedShareFolderNode()
        folder_node.uid = folder_uid
        folder_node.name = folder_name
        folder_node.parent_uid = None
        params.folder_cache[folder_uid] = folder_node
        params.root_folder.subfolders.append(folder_uid)

        params.nested_share_folders[folder_uid] = {
            'folder_uid': folder_uid,
            'name': folder_name,
            'owner_username': params.user,
        }
        params.nested_share_folder_records[folder_uid] = {record_uid}
        params.nested_share_records[record_uid] = {
            'record_uid': record_uid,
            'shared': True,
        }
        params.subfolder_cache[folder_uid] = {
            'folder_uid': folder_uid,
            'type': 'user_folder',
            'name': folder_name,
            'source': 'nested_share_folder',
        }
        for record_uids in params.subfolder_record_cache.values():
            record_uids.discard(record_uid)
        params.subfolder_record_cache[folder_uid] = {record_uid}
        params.record_cache[record_uid]['shared'] = True
        params.record_cache[record_uid].pop('shares', None)
        return folder_uid

    def test_share_report_owner_supports_nested_share_records(self):
        params = get_synced_params()
        record_uid = next(uid for uid, rec in params.record_cache.items() if not rec.get('shared'))
        folder_uid = self._attach_nested_share_folder(params, record_uid)

        access_result = {
            'record_accesses': [
                {
                    'record_uid': record_uid,
                    'accessor_name': params.user,
                    'access_type': 'AT_USER',
                    'access_type_uid': utils.generate_uid(),
                    'owner': True,
                    'inherited': False,
                    'can_view': True,
                    'can_edit': True,
                    'can_update_access': True,
                    'can_approve_access': True,
                },
                {
                    'record_uid': record_uid,
                    'accessor_name': 'user2@keepersecurity.com',
                    'access_type': 'AT_USER',
                    'access_type_uid': utils.generate_uid(),
                    'owner': False,
                    'inherited': True,
                    'can_view': True,
                    'can_edit': True,
                    'can_update_access': True,
                    'can_approve_access': True,
                }
            ]
        }

        with mock.patch('keepercommander.api.get_record_shares', return_value=None), \
                mock.patch('keepercommander.nested_share_folder.record_api.get_record_accesses_v3',
                           return_value=access_result):
            cmd = register.ShareReportCommand()
            report = cmd.execute(params, format='json', owner=True, verbose=True, container=[folder_uid])

        data = json.loads(report)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['record_uid'], record_uid)
        self.assertEqual(data[0]['record_owner'], params.user)
        self.assertEqual(data[0]['folder_path'], 'Drive')
        self.assertIn('user2@keepersecurity.com', data[0]['shared_with'])

    def test_share_report_folders_supports_nested_share_folders(self):
        params = get_synced_params()
        record_uid = next(uid for uid in params.record_cache)
        folder_uid = self._attach_nested_share_folder(params, record_uid)
        params.nested_share_folder_sharing_states[folder_uid] = {
            'shared': True,
            'count': 1,
        }
        access_result = {
            'results': [{
                'folder_uid': folder_uid,
                'success': True,
                'accessors': [{
                    'username': 'user2@keepersecurity.com',
                    'accessor_uid': utils.generate_uid(),
                    'access_type': 'AT_USER',
                    'role': 'CONTENT_SHARE_MANAGER',
                }]
            }]
        }

        with mock.patch('keepercommander.nested_share_folder.folder_api.get_folder_access_v3',
                        return_value=access_result):
            cmd = register.ShareReportCommand()
            report = cmd.execute(params, format='json', folders=True)

        data = json.loads(report)
        row = next((x for x in data if x['Folder UID'] == folder_uid), None)
        self.assertIsNotNone(row)
        self.assertEqual(row['Folder Name'], 'Drive')
        self.assertEqual(row['Type'], 'Nested Share Folder')
        self.assertEqual(row['Shared To'], 'user2@keepersecurity.com')
        self.assertEqual(row['Folder Path'], 'Drive')
        self.assertEqual(row['Permissions'], 'Content and Share Manager')

    @staticmethod
    def record_share_rq_rs(rq):
        status = record_pb2.SharedRecordStatus()
        status.recordUid = rq.recordUid
        status.status = 'success'
        status.username = rq.toUsername
        return status

    @staticmethod
    def communicate_rest_success(params, request, endpoint, **kwargs):
        if 'rs_type' in kwargs:
            rs = kwargs['rs_type']()
        else:
            rs = None

        _, _, command = endpoint.rpartition('/')

        if command == 'get_public_keys':
            for x in request.usernames:
                key_response = APIRequest_pb2.PublicKeyResponse()
                key_response.username = x
                key_response.publicKey = utils.base64_url_decode(vault_env.encoded_public_key)
                rs.keyResponses.append(key_response)
            return rs
        if command == 'records_share_update':
            rs.addSharedRecordStatus.extend((TestRegister.record_share_rq_rs(x) for x in request.addSharedRecord))
            rs.addSharedRecordStatus.extend((TestRegister.record_share_rq_rs(x) for x in request.updateSharedRecord))
            rs.removeSharedRecordStatus.extend((TestRegister.record_share_rq_rs(x) for x in request.removeSharedRecord))

        cmd = TestRegister.expected_commands.pop(0)
        if cmd == command:
            return rs

        raise Exception()

    @staticmethod
    def communicate_success(params, request):
        rs = {
            'result': 'success',
            'result_code': '',
            'message': ''
        }
        raise Exception()
