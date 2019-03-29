from unittest import TestCase, mock

from data_vault import get_synced_params, VaultEnvironment, get_user_params
from keepercommander.commands import register

vault_env = VaultEnvironment()


class TestRegister(TestCase):
    expected_commands = []

    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.run_command').start()
        self.communicate_mock.side_effect = TestRegister.communicate_success
        TestRegister.expected_commands.clear()

    def tearDown(self):
        mock.patch.stopall()

    def test_share_record(self):
        params = get_synced_params()

        record_uid = next(iter([x['record_uid'] for x in params.meta_data_cache.values() if x['can_share']]))
        cmd = register.ShareRecordCommand()

        TestRegister.expected_commands.extend(['record_share_update'])
        cmd.execute(params, email=['user2@keepersecurity.com'], action='grant', can_share=False, can_edit=True, record=record_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

        TestRegister.expected_commands.extend(['record_share_update'])
        cmd.execute(params, email=['user2@keepersecurity.com'], action='owner', can_share=False, can_edit=True, record=record_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

        TestRegister.expected_commands.extend(['record_share_update'])
        cmd.execute(params, email=['user2@keepersecurity.com'], action='revoke', record=record_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

    def test_share_folder(self):
        params = get_synced_params()
        shared_folder_uid = next(iter([x['shared_folder_uid'] for x in params.shared_folder_cache.values()]))
        cmd = register.ShareFolderCommand()

        TestRegister.expected_commands.extend(['shared_folder_update'])
        cmd.execute(params, action='grant', user=['user2@keepersecurity.com'], manage_records=True, manage_users=False, folder=shared_folder_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

        TestRegister.expected_commands.extend(['shared_folder_update'])
        cmd.execute(params, action='revoke', user=['user2@keepersecurity.com'], folder=shared_folder_uid)
        self.assertEqual(len(TestRegister.expected_commands), 0)

    def test_register(self):
        params = get_user_params()

        cmd = register.RegisterCommand()

        with mock.patch('keepercommander.commands.register.RegisterCommand.get_iterations', return_value=1000):
            TestRegister.expected_commands.extend(['register'])
            cmd.execute(params, email='user3@keepersecurity.com', password='123456')
            self.assertEqual(len(TestRegister.expected_commands), 0)

            with mock.patch('keepercommander.api.login'):
                TestRegister.expected_commands.extend(['register', 'set_data_key_backup'])
                cmd.execute(params, email='user3@keepersecurity.com', password='123456', question='What?', answer='Nothing')
                self.assertEqual(len(TestRegister.expected_commands), 0)

            with mock.patch('getpass.getpass') as getpass_mock:
                getpass_mock.side_effect = ['123456', KeyboardInterrupt()]
                TestRegister.expected_commands.extend(['register'])
                cmd.execute(params, email='user3@keepersecurity.com')
                self.assertEqual(len(TestRegister.expected_commands), 0)

    @staticmethod
    def communicate_success(params, request):
        rs = {
            'result': 'success',
            'result_code': '',
            'message': ''
        }
        if request['command'] == 'public_keys':
            rs['public_keys'] = [{
                'key_owner': x,
                'public_key': vault_env.encoded_public_key
            } for x in request['key_owners']]
            return rs

        if request['command'] == 'get_records':
            rs['records'] = [{'record_uid': x, 'user_permissions': [], 'shared_folder_permissions': []} for x in request['records']]
            return rs

        if request['command'] == 'pre_register':
            rs['result'] = 'fail'
            rs['result_code'] = 'Failed_to_find_user'
            rs['password_rules'] = []
            return rs
        cmd = TestRegister.expected_commands.pop(0)
        if cmd == request['command']:
            return rs

        raise Exception()
