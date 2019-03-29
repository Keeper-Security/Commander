import tempfile
import json

from unittest import TestCase, mock

from data_config import read_config_file
from keepercommander.params import KeeperParams
from keepercommander import cli, api
from keepercommander.subfolder import BaseFolderNode


class TestConnectedCommands(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.params = KeeperParams()
        read_config_file(cls.params)
        api.login(cls.params)
        TestConnectedCommands.wipe_out_data()

    @classmethod
    def tearDownClass(cls):
        cli.do_command(cls.params, 'logout')

    @classmethod
    def wipe_out_data(cls):
        params = cls.params # type: KeeperParams

        params.revision = 0
        api.sync_down(params)
        request = {
            'command': 'record_update',
            'delete_records': [key for key in params.record_cache.keys()]
        }
        rs = api.communicate(params, request)

        for shared_folder_uid in params.shared_folder_cache:
            request = {
                'command': 'shared_folder_update',
                'operation': 'delete',
                'shared_folder_uid': shared_folder_uid
            }
            rs = api.communicate(params, request)

        folder_uids = [x for x in params.root_folder.subfolders if params.subfolder_cache[x]['type'] == BaseFolderNode.UserFolderType]
        if folder_uids:
            request = {
                'command': 'pre_delete',
                'objects': [
                    {
                        'from_type': 'user_folder',
                        'object_uid': x,
                        'object_type': 'user_folder',
                        'delete_resolution': 'unlink'
                    } for x in folder_uids
                ]
            }
            rs = api.communicate(params, request)
            request = {
                'command': 'delete',
                'pre_delete_token': rs['pre_delete_response']['pre_delete_token']
            }
            rs = api.communicate(params, request)

        request = {
            'command': 'purge_deleted_records'
        }
        rs = api.communicate(params, request)
        params.revision = 0
        api.sync_down(params)

    def test_vault_commands(self):
        params = TestConnectedCommands.params # type: KeeperParams
        with mock.patch('builtins.input', side_effect = KeyboardInterrupt()), mock.patch('builtins.print'):
            cli.do_command(params, 'add  --login="user@keepersecurity.com" --pass=password --url="https://keepersecurity.com/" --custom="{\\"cmdr:plugin\\":\\"noop\\"}" "Record 1"')
            cli.do_command(params, 'sync-down')

            record_uid = next(iter(params.record_cache.keys()))
            rec = api.get_record(params, record_uid)

            self.assertEqual(rec.get('cmdr:plugin'), 'noop')
            old_password = rec.password
            cli.do_command(params, 'r -- {0}'.format(rec.record_uid))
            cli.do_command(params, 'sync-down')
            rec = api.get_record(params, record_uid)
            self.assertNotEqual(old_password, rec.password)

            cli.do_command(params, 'ls -l')
            cli.do_command(params, 'mkdir --user-folder "User Folder 1"')
            cli.do_command(params, 'mkdir --shared-folder --all "Shared Folder 1"')
            cli.do_command(params, 'sync-down')
            cli.do_command(params, 'cd "User Folder 1"')
            cli.do_command(params, 'mkdir --user-folder "User Folder 2"')
            cli.do_command(params, 'cd /')
            cli.do_command(params, 'ln "Record 1" "Shared Folder 1"')
            cli.do_command(params, 'mv "Record 1" "User Folder 1"')
            params.revision = 0
            cli.do_command(params, 'sync-down')
            self.assertEqual(len(params.record_cache), 1)
            self.assertEqual(len(params.shared_folder_cache), 1)

            cli.do_command(params, 'cd "Shared Folder 1"')
            cli.do_command(params, 'append-notes --notes="Additional info" "Record 1"')
            cli.do_command(params, 'sync-down')
            cli.do_command(params, 'cd "../User Folder 1"')
            cli.do_command(params, 'rmdir --force "User Folder 2"')
            cli.do_command(params, 'sync-down')

            cli.do_command(params, 'cd /')
            cli.do_command(params, 'search record')
            cli.do_command(params, 'search folder')

            with tempfile.NamedTemporaryFile() as f:
                f.write(b'data')
                f.flush()
                cli.do_command(params, 'cd "User Folder 1"')
                cli.do_command(params, 'upload-attachment --file="{0}" "Record 1"'.format(f.name))
            cli.do_command(params, 'sync-down')

            with mock.patch('builtins.open', mock.mock_open()) as m_open, mock.patch('os.path.abspath', return_value='file/path'):
                cli.do_command(params, 'download-attachment -- {0}'.format(record_uid))
                m_open.assert_called()
                m_open.return_value.write.assert_called()

            rec = api.get_record(params, record_uid)
            self.assertEqual(len(rec.attachments), 1)
            cli.do_command(params, 'delete-attachment --name={0} -- {1}'.format(rec.attachments[0]['id'], record_uid))
            cli.do_command(params, 'sync-down')
            rec = api.get_record(params, record_uid)
            self.assertEqual(len(rec.attachments), 0)

            json_text = ''
            with mock.patch('builtins.open', mock.mock_open()) as m_open, mock.patch('os.path.abspath', return_value='file/path'):
                def file_write(text):
                    nonlocal json_text
                    json_text += text

                m_open.return_value.write = file_write
                cli.do_command(params, 'export --format=json file')
            self.assertTrue(len(json_text) > 0)
            exported = json.loads(json_text)
            self.assertEqual(len(params.record_cache), len(exported['records']))
            self.assertEqual(len(params.shared_folder_cache), len(exported['shared_folders']))

            TestConnectedCommands.wipe_out_data()
            with mock.patch('builtins.open', mock.mock_open()) as m_open, mock.patch('os.path.isfile', return_value=True):
                def file_read():
                    nonlocal json_text
                    return json_text

                m_open.return_value.read = file_read
                cli.do_command(params, 'import --format=json file')

            self.assertEqual(len(params.record_cache), len(exported['records']))
            self.assertEqual(len(params.shared_folder_cache), len(exported['shared_folders']))


class TestEnterpriseCommands(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.params = KeeperParams()
        read_config_file(cls.params)
        cls.params.user = cls.params.config['enterprise']['user']
        cls.params.password = cls.params.config['enterprise']['password']
        api.login(cls.params)
        TestEnterpriseCommands.wipe_out_data()

    @classmethod
    def tearDownClass(cls):
        params = cls.params # type: KeeperParams
        api.query_enterprise(params)
        for user in params.enterprise['users']:
            if user['status'] == 'actove' and user['lock'] != 0:
                request = {
                    'command': 'enterprise_user_lock',
                    'enterprise_user_id': user['enterprise_user_id'],
                    'lock': 'unlocked'
                }
                api.communicate(params, request)

        cli.do_command(params, 'logout')

    @classmethod
    def wipe_out_data(cls):
        params = cls.params # type: KeeperParams
        managed_roles = set()
        for mn in params.enterprise['managed_nodes']:
            managed_roles.add(mn['role_id'])

        for ru in params.enterprise['role_users']:
            if ru['role_id'] not in managed_roles:
                request = {
                    'command': 'role_user_remove',
                    'role_id': ru['role_id'],
                    'enterprise_user_id': ru['enterprise_user_id']
                }
                api.communicate(params, request)

        for user in params.enterprise['users']:
            if user['status'] == 'invited':
                request = {
                    'command': 'enterprise_user_delete',
                    'enterprise_user_id': user['enterprise_user_id']
                }
                api.communicate(params, request)

            elif user['lock'] != 0:
                request = {
                    'command': 'enterprise_user_lock',
                    'enterprise_user_id': user['enterprise_user_id'],
                    'lock': 'unlocked'
                }
                api.communicate(params, request)

        for team in params.enterprise['teams']:
            request = {
                'command': 'team_delete',
                'team_uid': team['team_uid']
            }
            api.communicate(params, request)
        api.query_enterprise(params)

    def test_vault_commands(self):
        params = TestEnterpriseCommands.params # type: KeeperParams
        self.assertIsNotNone(params.enterprise)
        test_user = params.config['user']
        new_user = 'integration.user@keepersecurity.com'
        new_team = 'Test Team'
        with mock.patch('builtins.input', side_effect = KeyboardInterrupt()), mock.patch('builtins.print'):
            cli.do_command(params, 'enterprise-info --verbose')

            cli.do_command(params, 'enterprise-team --add "{0}"'.format(new_team))
            cli.do_command(params, 'enterprise-team --restrict-edit=on --restrict-share=on --restrict-view=off "{0}"'.format(new_team))

            cli.do_command(params, 'enterprise-user --add --name="Test User" {0}'.format(new_user))
            cli.do_command(params, 'enterprise-user --lock "{0}"'.format(test_user))
            cli.do_command(params, 'enterprise-user --unlock "{0}"'.format(test_user))

            cli.do_command(params, 'enterprise-team --add-user="{0}" "{1}"'.format(test_user, new_team))
            cli.do_command(params, 'enterprise-team --remove-user="{0}" "{1}"'.format(test_user, new_team))
            cli.do_command(params, 'enterprise-user --add-team="{0}" "{1}"'.format(new_team, test_user))
            cli.do_command(params, 'enterprise-user --remove-team="{0}" "{1}"'.format(new_team, test_user))

            role_id = None
            managed_roles = set()
            for mn in params.enterprise['managed_nodes']:
                managed_roles.add(mn['role_id'])

            for role in params.enterprise['roles']:
                if role['role_id'] not in managed_roles:
                    role_id = role['role_id']
                    break
            if role_id:
                cli.do_command(params, 'enterprise-role --add-user="{0}" "{1}"'.format(new_user, role_id))


