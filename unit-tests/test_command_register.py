import json
from unittest import TestCase, mock

from data_vault import get_synced_params, VaultEnvironment
from keepercommander.commands import register
from keepercommander.error import CommandError
from keepercommander.proto import APIRequest_pb2, record_pb2
from keepercommander import utils

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

    def _mark_record_as_pam_user(self, params, record_uid):
        rec = params.record_cache[record_uid]
        try:
            existing = rec.get('data_unencrypted')
            data = json.loads(existing.decode() if isinstance(existing, (bytes, bytearray)) else (existing or '{}'))
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data['type'] = 'pamUser'
        rec['data_unencrypted'] = json.dumps(data).encode()

    def test_share_record_rotate_on_expiration_sets_flag(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))
        self._mark_record_as_pam_user(params, record_uid)

        captured = {}

        def capture_record_share(rq):
            status = record_pb2.SharedRecordStatus()
            status.recordUid = rq.recordUid
            status.status = 'success'
            status.username = rq.toUsername
            captured.setdefault('rqs', []).append(rq)
            return status

        original = TestRegister.record_share_rq_rs
        TestRegister.record_share_rq_rs = staticmethod(capture_record_share)
        try:
            self.record_share_mock = mock.patch('keepercommander.api.get_record_shares').start()
            self.record_share_mock.side_effect = lambda *_args, **_kw: None

            cmd = register.ShareRecordCommand()
            TestRegister.expected_commands.extend(['records_share_update'])
            cmd.execute(params,
                        email=['user2@keepersecurity.com'],
                        action='grant',
                        can_share=False,
                        can_edit=True,
                        record=record_uid,
                        expire_in='1d',
                        rotate_on_expiration=True)
            self.assertEqual(len(TestRegister.expected_commands), 0)
            rqs = captured.get('rqs', [])
            self.assertTrue(rqs, 'Expected at least one SharedRecord on the wire')
            # The new add/update entry must carry the rotateOnExpiration bit and a positive expiration.
            target = next((r for r in rqs if r.toUsername == 'user2@keepersecurity.com'), None)
            self.assertIsNotNone(target, 'Expected SharedRecord for the target email')
            self.assertTrue(target.rotateOnExpiration,
                            'rotateOnExpiration should be set when --rotate-on-expiration is passed')
            self.assertGreater(target.expiration, 0)
            self.assertEqual(target.timerNotificationType, record_pb2.NOTIFY_OWNER)
        finally:
            TestRegister.record_share_rq_rs = original

    def test_share_record_rotate_on_expiration_requires_expiration(self):
        params = get_synced_params()
        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))
        self._mark_record_as_pam_user(params, record_uid)

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
        self._mark_record_as_pam_user(params, record_uid)

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
        self._mark_record_as_pam_user(params, record_uid)

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

    def test_share_record_parser_accepts_rotate_on_expiration(self):
        ns = register.share_record_parser.parse_args(
            ['-e', 'user2@example.com', '--expire-in', '1d', '--rotate-on-expiration', 'rec-uid'])
        self.assertTrue(ns.rotate_on_expiration)
        self.assertEqual(ns.expire_in, '1d')

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
