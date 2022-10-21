from unittest import TestCase, mock

from data_vault import get_synced_params, VaultEnvironment
from keepercommander.commands import register
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

        self.record_share_mock = mock.patch('keepercommander.api.get_record_shares').start()

        def not_shared(params, record_uids, is_share_admin):
            pass
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
