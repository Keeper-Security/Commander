import logging

from unittest import TestCase, mock

from data_vault import get_synced_params
from helper import KeeperApiHelper
from keepercommander.commands import folder


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
        with self.assertLogs(level=logging.WARNING):
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

        with self.assertLogs(level=logging.WARNING):
            cmd.execute(params, folder='Invalid Name')

    def test_delete_user_folder(self):
        params = get_synced_params()
        cmd = folder.FolderRemoveCommand()
        user_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'user_folder']))

        def pre_delete(rq):
            self.assertEqual(rq['command'], 'pre_delete')
            return {
                'pre_delete_response': {
                    'would_delete': {
                        'deletion_summary': ['1 Personal Folder']
                    },
                    'pre_delete_token': 'token'
                }
            }

        with mock.patch('builtins.print'), mock.patch('keepercommander.commands.folder.user_choice') as mock_choice:
            mock_choice.return_value = 'n'
            KeeperApiHelper.communicate_expect([pre_delete])
            cmd.execute(params, folder=user_folder.name)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            mock_choice.return_value = 'y'
            KeeperApiHelper.communicate_expect([pre_delete, 'delete'])
            cmd.execute(params, folder=user_folder.name)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_delete_shared_folder(self):
        params = get_synced_params()
        cmd = folder.FolderRemoveCommand()
        shared_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'shared_folder']))

        def shared_folder_update(rq):
            self.assertEqual(rq['command'], 'shared_folder_update')
            self.assertEqual(rq['operation'], 'delete')
            self.assertEqual(rq['shared_folder_uid'], shared_folder.uid)

        KeeperApiHelper.communicate_expect([shared_folder_update])
        cmd.execute(params, force=True, folder=shared_folder.name)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        with mock.patch('keepercommander.commands.folder.user_choice') as mock_choice:
            mock_choice.return_value = 'y'

            KeeperApiHelper.communicate_expect([shared_folder_update])
            cmd.execute(params, folder=shared_folder.name)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            mock_choice.return_value = 'n'
            cmd.execute(params, folder=shared_folder.name)

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
        shared_folder = next(iter([x for x in params.folder_cache.values() if x.type == 'shared_folder']))

        root_record_uid = next(iter(params.subfolder_record_cache['']))

        with self.assertLogs(level=logging.WARNING):
            cmd.execute(params, src='Invalid Record', dst=user_folder.uid)
            cmd.execute(params, src=root_record_uid, dst='Invalid Folder')
            cmd.execute(params, src=user_folder.uid, dst=user_folder.uid)

