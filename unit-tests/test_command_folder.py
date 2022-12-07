from unittest import TestCase, mock
import logging

from data_vault import get_synced_params
from helper import KeeperApiHelper
from keepercommander.commands import folder
from keepercommander.error import CommandError


class TestFolder(TestCase):
    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command

    def tearDown(self):
        mock.patch.stopall()

    def test_list(self):
        params = get_synced_params()

        cmd = folder.FolderListCommand()
        with mock.patch('builtins.print'), mock.patch('keepercommander.api.get_record_shares'):
            cmd.execute(params)
            cmd.execute(params, detail=True)

    def test_change_directory(self):
        params = get_synced_params()

        cmd = folder.FolderCdCommand()
        folder_name = next(iter([x['name_unencrypted'] for x in params.shared_folder_cache.values()]))
        owd = params.current_folder
        cmd.execute(params, folder=folder_name)
        self.assertNotEqual(owd, params.current_folder)

    def test_tree(self):
        params = get_synced_params()
        cmd = folder.FolderTreeCommand()

        with mock.patch('builtins.print'):
            cmd.execute(params)
        with self.assertRaises(CommandError):
            cmd.execute(params, folder='Invalid')

    def test_make_folder(self):
        params = get_synced_params()
        cmd = folder.FolderMakeCommand()

        def is_user_folder(rq):
            self.assertEqual(rq['command'], 'folder_add')
            self.assertEqual(rq['folder_type'], 'user_folder')

        def is_shared_folder(rq):
            self.assertEqual(rq['command'], 'folder_add')
            self.assertEqual(rq['folder_type'], 'shared_folder')

        def is_shared_folder_folder(rq):
            self.assertEqual(rq['command'], 'folder_add')
            self.assertEqual(rq['folder_type'], 'shared_folder_folder')

        KeeperApiHelper.communicate_expect([is_user_folder])
        cmd.execute(params, user_folder=True, folder='New Folder')

        KeeperApiHelper.communicate_expect([is_shared_folder])
        cmd.execute(params, shared_folder=True, folder='New Shared Folder')

        with mock.patch('keepercommander.commands.folder.user_choice') as mock_choice:
            mock_choice.return_value = 'n'
            KeeperApiHelper.communicate_expect([is_user_folder])
            cmd.execute(params, folder='New Folder')
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            mock_choice.return_value = 'y'
            KeeperApiHelper.communicate_expect([is_shared_folder])
            cmd.execute(params, folder='New Shared Folder')
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            with mock.patch('builtins.input') as mock_input:
                mock_choice.return_value = 'n'
                mock_input.return_value = 'New Personal Folder'
                KeeperApiHelper.communicate_expect([is_user_folder])
                cmd.execute(params)
                self.assertTrue(KeeperApiHelper.is_expect_empty())

        shared_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'shared_folder']))
        with self.assertLogs(level=logging.WARNING):
            cmd.execute(params, folder=shared_folder.name)

        params.current_folder = shared_folder.uid
        KeeperApiHelper.communicate_expect([is_shared_folder_folder])
        cmd.execute(params, folder='New SubFolder')
        self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_remove_non_existing_folder(self):
        params = get_synced_params()
        cmd = folder.FolderRemoveCommand()

        with self.assertRaises(CommandError):
            cmd.execute(params, folder='Invalid Name')

    def test_delete_folders(self):
        params = get_synced_params()
        cmd = folder.FolderRemoveCommand()
        all_folders = [x for x in params.folder_cache.values() if not x.parent_uid]

        def pre_delete(rq):
            self.assertEqual(rq['command'], 'pre_delete')
            return {
                'pre_delete_response': {
                    'would_delete': {
                        'deletion_summary': ['All root folders']
                    },
                    'pre_delete_token': 'token'
                }
            }

        with mock.patch('builtins.print'), mock.patch('keepercommander.commands.folder.user_choice') as mock_choice:
            mock_choice.return_value = 'n'
            KeeperApiHelper.communicate_expect([pre_delete])
            cmd.execute(params, pattern=[x.name for x in all_folders])
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            mock_choice.return_value = 'y'
            KeeperApiHelper.communicate_expect([pre_delete, 'delete'])
            cmd.execute(params, pattern=[x.name for x in all_folders])
            self.assertTrue(KeeperApiHelper.is_expect_empty())


    def test_move_success(self):
        params = get_synced_params()
        cmd = folder.FolderMoveCommand()

        user_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'user_folder']))
        shared_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'shared_folder']))

        root_record_uid = next(iter(params.subfolder_record_cache['']))
        sf_record_uid = next(iter(params.subfolder_record_cache[shared_folder.uid]))

        KeeperApiHelper.communicate_expect(['move'])
        cmd.execute(params, src=root_record_uid, dst=user_folder.uid)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        KeeperApiHelper.communicate_expect(['move'])
        cmd.execute(params, src=sf_record_uid, dst=user_folder.name)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        KeeperApiHelper.communicate_expect(['move'])
        cmd.execute(params, src=root_record_uid, dst=user_folder.uid)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_move_invalid_input(self):
        params = get_synced_params()
        cmd = folder.FolderMoveCommand()

        user_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'user_folder']))
        # shared_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'shared_folder']))

        root_record_uid = next(iter(params.subfolder_record_cache['']))

        with self.assertRaises(CommandError):
            cmd.execute(params, src='Invalid Record', dst=user_folder.uid)
        with self.assertRaises(CommandError):
            cmd.execute(params, src=root_record_uid, dst='Invalid Folder')
        with self.assertRaises(CommandError):
            cmd.execute(params, src=user_folder.uid, dst=user_folder.uid)
