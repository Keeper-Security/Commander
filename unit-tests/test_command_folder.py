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
            
    def test_list_json_no_ansi_colors(self):
        """Test that ls command with JSON format doesn't include ANSI color codes."""
        params = get_synced_params()
        cmd = folder.FolderListCommand()
        
        # Execute with JSON format - this should not include ANSI color codes
        with mock.patch('keepercommander.api.get_record_shares'):
            result = cmd.execute(params, detail=True, format='json')
            
            # If result is returned (JSON/CSV format), check it doesn't contain ANSI codes
            if result:
                import json
                # Convert to JSON string to check for ANSI escape sequences
                json_str = json.dumps(result)
                # Check that no ANSI escape sequences are present
                self.assertNotIn('\u001b[', json_str, "JSON output should not contain ANSI escape sequences")
                self.assertNotIn('\\u001b[', json_str, "JSON output should not contain ANSI escape sequences")

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
        with mock.patch('keepercommander.commands.folder.user_choice', return_value='n'):
            KeeperApiHelper.communicate_expect([is_user_folder])
            cmd.execute(params, folder=shared_folder.name)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

        params.current_folder = shared_folder.uid
        KeeperApiHelper.communicate_expect([is_shared_folder_folder])
        cmd.execute(params, folder='New SubFolder')
        self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_make_folder_allows_duplicate_root_name(self):
        from keepercommander.subfolder import UserFolderNode

        params = get_synced_params()
        existing = UserFolderNode()
        existing.uid = 'c' * 22
        existing.name = 'Duplicate Root'
        existing.parent_uid = None
        existing.subfolders = []
        second = UserFolderNode()
        second.uid = 'h' * 22
        second.name = 'Duplicate Root'
        second.parent_uid = None
        second.subfolders = []
        params.folder_cache[existing.uid] = existing
        params.folder_cache[second.uid] = second
        params.root_folder.subfolders.extend([existing.uid, second.uid])

        def is_user_folder(rq):
            self.assertEqual(rq['command'], 'folder_add')
            self.assertEqual(rq['folder_type'], 'user_folder')

        KeeperApiHelper.communicate_expect([is_user_folder])
        folder.FolderMakeCommand().execute(
            params, user_folder=True, folder='Duplicate Root')
        self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_make_folder_rejects_duplicate_parent_name(self):
        from keepercommander.subfolder import UserFolderNode

        params = get_synced_params()
        first = UserFolderNode()
        first.uid = 'd' * 22
        first.name = 'Duplicate Parent'
        first.parent_uid = None
        first.subfolders = []
        second = UserFolderNode()
        second.uid = 'e' * 22
        second.name = 'Duplicate Parent'
        second.parent_uid = None
        second.subfolders = []
        params.folder_cache[first.uid] = first
        params.folder_cache[second.uid] = second
        params.root_folder.subfolders.extend([first.uid, second.uid])

        with self.assertRaises(CommandError):
            folder.FolderMakeCommand().execute(
                params, user_folder=True, folder='Duplicate Parent/Child')

    def test_make_folder_keeps_child_name_unique_under_current_folder(self):
        from keepercommander.subfolder import UserFolderNode

        params = get_synced_params()
        parent = UserFolderNode()
        parent.uid = 'f' * 22
        parent.name = 'Parent'
        parent.parent_uid = None
        parent.subfolders = []
        child = UserFolderNode()
        child.uid = 'g' * 22
        child.name = 'Child'
        child.parent_uid = parent.uid
        child.subfolders = []
        parent.subfolders.append(child.uid)
        params.folder_cache[parent.uid] = parent
        params.folder_cache[child.uid] = child
        params.root_folder.subfolders.append(parent.uid)
        params.current_folder = parent.uid

        with self.assertLogs(level=logging.WARNING):
            folder.FolderMakeCommand().execute(
                params, user_folder=True, folder='Child')

    def test_remove_non_existing_folder(self):
        params = get_synced_params()
        cmd = folder.FolderRemoveCommand()

        with self.assertRaises(CommandError):
            cmd.execute(params, folder='Invalid Name')

    def test_remove_rejects_ambiguous_folder_path(self):
        from keepercommander.subfolder import UserFolderNode

        params = get_synced_params()
        first = UserFolderNode()
        first.uid = 'a' * 22
        first.name = 'Ambiguous'
        first.parent_uid = None
        first.subfolders = []
        second = UserFolderNode()
        second.uid = 'b' * 22
        second.name = 'Ambiguous'
        second.parent_uid = None
        second.subfolders = []
        params.folder_cache[first.uid] = first
        params.folder_cache[second.uid] = second
        params.root_folder.subfolders.extend([first.uid, second.uid])

        cmd = folder.FolderRemoveCommand()
        with mock.patch(
                'keepercommander.enforcement.MasterPasswordReentryEnforcer.check_and_enforce',
                return_value=True):
            with self.assertRaises(CommandError) as ctx:
                cmd.execute(params, pattern=['Ambiguous'], force=True, quiet=True)
        self.assertIn('Multiple folders match', str(ctx.exception))

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
