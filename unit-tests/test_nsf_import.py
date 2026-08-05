from unittest import TestCase, mock
import json
import os
import tempfile

from keepercommander.importer import nsf_import
from keepercommander.importer.importer import Folder, Record, SharedFolder, Permission
from keepercommander.importer.json.json import KeeperJsonImporter
from keepercommander.subfolder import NestedShareFolderNode


class TestNsfImportHelpers(TestCase):
    def test_classic_perms_to_nsf_role(self):
        self.assertEqual(nsf_import.classic_perms_to_nsf_role(True, True), 'full-manager')
        self.assertEqual(nsf_import.classic_perms_to_nsf_role(False, True, can_share=True),
                         'content-share-manager')
        self.assertEqual(nsf_import.classic_perms_to_nsf_role(False, True), 'content-manager')
        self.assertEqual(nsf_import.classic_perms_to_nsf_role(False, False, can_edit=True),
                         'content-manager')
        self.assertEqual(nsf_import.classic_perms_to_nsf_role(False, False, can_share=True),
                         'share-manager')
        self.assertEqual(nsf_import.classic_perms_to_nsf_role(), 'viewer')

    def test_flatten_record_folder_paths(self):
        rec = Record()
        fol = Folder()
        fol.domain = 'Shared'
        fol.path = 'Team\\Apps'
        rec.folders = [fol]
        nsf_import.flatten_record_folder_paths([rec])
        self.assertEqual(fol.domain, '')
        self.assertEqual(fol.path, 'Shared\\Team\\Apps')

    def test_is_nsf_folder(self):
        params = mock.MagicMock()
        params.nested_share_folders = {'nsf1': {'name': 'Root'}}
        params.subfolder_cache = {
            'nsf2': {'source': 'nested_share_folder', 'name': 'Child'},
        }
        node = NestedShareFolderNode()
        node.uid = 'nsf3'
        params.folder_cache = {'nsf3': node}

        self.assertTrue(nsf_import.is_nsf_folder(params, 'nsf1'))
        self.assertTrue(nsf_import.is_nsf_folder(params, 'nsf2'))
        self.assertTrue(nsf_import.is_nsf_folder(params, 'nsf3'))
        self.assertFalse(nsf_import.is_nsf_folder(params, ''))
        self.assertFalse(nsf_import.is_nsf_folder(params, 'missing'))

    def test_find_nsf_child(self):
        params = mock.MagicMock()
        params.nested_share_folders = {
            'root1': {'name': 'Migration', 'parent_uid': ''},
            'child1': {'name': 'Apps', 'parent_uid': 'root1'},
        }
        self.assertEqual(nsf_import.find_nsf_child(params, 'Migration', ''), 'root1')
        self.assertEqual(nsf_import.find_nsf_child(params, 'Apps', 'root1'), 'child1')
        self.assertIsNone(nsf_import.find_nsf_child(params, 'Missing', 'root1'))

    def test_prepare_nsf_folders_reuses_existing(self):
        params = mock.MagicMock()
        params.nested_share_folders = {
            'root1': {'name': 'Migration', 'parent_uid': ''},
            'child1': {'name': 'Apps', 'parent_uid': 'root1'},
        }
        params.subfolder_cache = {}
        params.folder_cache = {}

        rec = Record()
        fol = Folder()
        fol.path = 'Migration\\Apps'
        rec.folders = [fol]

        created = nsf_import.prepare_nsf_folders(params, [], [rec], '')
        self.assertEqual(created, 0)
        self.assertEqual(fol.uid, 'child1')

    def test_prepare_nsf_folders_creates_missing(self):
        params = mock.MagicMock()
        params.nested_share_folders = {
            'root1': {'name': 'Migration', 'parent_uid': ''},
        }
        params.subfolder_cache = {}
        params.folder_cache = {}

        rec = Record()
        fol = Folder()
        fol.path = 'Migration\\NewChild'
        rec.folders = [fol]

        with mock.patch('keepercommander.importer.nsf_import.create_nsf_folders_batch',
                        return_value=['new1']) as create_mock:
            nsf_import.prepare_nsf_folders(params, [], [rec], '')
            create_mock.assert_called_once_with(params, [('NewChild', 'root1')])
            self.assertEqual(fol.uid, 'new1')

    def test_prepare_nsf_folders_with_base_parent(self):
        params = mock.MagicMock()
        params.nested_share_folders = {
            'base': {'name': 'Base', 'parent_uid': ''},
        }
        params.subfolder_cache = {}
        params.folder_cache = {}

        sf = SharedFolder()
        sf.path = 'ProjectA'

        with mock.patch('keepercommander.importer.nsf_import.create_nsf_folders_batch',
                        return_value=['proj1']) as create_mock:
            nsf_import.prepare_nsf_folders(params, [sf], [], 'base')
            create_mock.assert_called_once_with(params, [('ProjectA', 'base')])
            self.assertEqual(sf.uid, 'proj1')

    def test_prepare_nsf_folders_batches_same_depth(self):
        params = mock.MagicMock()
        params.nested_share_folders = {
            'root': {'name': 'Root', 'parent_uid': ''},
        }
        params.subfolder_cache = {}
        params.folder_cache = {}

        rec1 = Record()
        fol1 = Folder()
        fol1.path = 'Root\\A'
        rec1.folders = [fol1]
        rec2 = Record()
        fol2 = Folder()
        fol2.path = 'Root\\B'
        rec2.folders = [fol2]

        with mock.patch('keepercommander.importer.nsf_import.create_nsf_folders_batch',
                        return_value=['uidA', 'uidB']) as create_mock:
            nsf_import.prepare_nsf_folders(params, [], [rec1, rec2], '')
            create_mock.assert_called_once_with(
                params, [('A', 'root'), ('B', 'root')])
            self.assertEqual(fol1.uid, 'uidA')
            self.assertEqual(fol2.uid, 'uidB')

    def test_throttle_retry_retries_then_succeeds(self):
        from keepercommander.error import KeeperApiError

        calls = {'n': 0}

        def flaky():
            calls['n'] += 1
            if calls['n'] < 3:
                raise KeeperApiError('throttled', 'Due to repeated attempts, your request has been throttled')
            return 'ok'

        with mock.patch('keepercommander.importer.nsf_import.time.sleep') as sleep_mock:
            result = nsf_import._call_with_throttle_retry('test', flaky)
        self.assertEqual(result, 'ok')
        self.assertEqual(calls['n'], 3)
        self.assertEqual(sleep_mock.call_count, 2)

    def test_apply_nsf_folder_permissions(self):
        params = mock.MagicMock()
        params.nested_share_folders = {
            'f1': {'name': 'Team', 'parent_uid': ''},
        }

        sf = SharedFolder()
        sf.uid = 'f1'
        sf.path = 'Team'
        perm = Permission()
        perm.name = 'user@example.com'
        perm.manage_records = True
        sf.permissions = [perm]

        with mock.patch(
            'keepercommander.nested_share_folder.folder_api.grant_folder_access_v3',
            return_value={'success': True},
        ) as grant_mock:
            nsf_import.apply_nsf_folder_permissions(params, [sf])
            grant_mock.assert_called_once()
            args, kwargs = grant_mock.call_args
            self.assertEqual(args[1], 'f1')
            self.assertEqual(args[2], 'user@example.com')
            self.assertEqual(kwargs.get('role'), 'content-manager')
            self.assertFalse(kwargs.get('as_team'))

    def test_apply_nsf_folder_permissions_multiple_users_and_roles(self):
        params = mock.MagicMock()
        params.nested_share_folders = {
            'f1': {'name': 'Team', 'parent_uid': ''},
        }

        sf = SharedFolder()
        sf.uid = 'f1'
        sf.path = 'Team'
        sf.manage_users = True
        sf.manage_records = True

        viewer = Permission()
        viewer.name = 'viewer@example.com'
        viewer.manage_users = False
        viewer.manage_records = False

        manager = Permission()
        manager.name = 'manager@example.com'
        manager.manage_users = True
        manager.manage_records = True

        team = Permission()
        team.uid = 'teamUid12345678901234'
        team.manage_records = True
        team.manage_users = False

        sf.permissions = [viewer, manager, team]

        with mock.patch(
            'keepercommander.nested_share_folder.folder_api.grant_folder_access_v3',
            return_value={'success': True},
        ) as grant_mock:
            nsf_import.apply_nsf_folder_permissions(
                params, [sf], manage_users=True, manage_records=True)
            self.assertEqual(grant_mock.call_count, 3)
            calls = grant_mock.call_args_list
            # viewer with CLI defaults elevates to folder/default role
            self.assertEqual(calls[0].args[2], 'viewer@example.com')
            self.assertEqual(calls[0].kwargs.get('role'), 'full-manager')
            self.assertFalse(calls[0].kwargs.get('as_team'))
            # explicit full manager
            self.assertEqual(calls[1].args[2], 'manager@example.com')
            self.assertEqual(calls[1].kwargs.get('role'), 'full-manager')
            # team UID treated as team
            self.assertEqual(calls[2].args[2], 'teamUid12345678901234')
            self.assertEqual(calls[2].kwargs.get('role'), 'content-manager')
            self.assertTrue(calls[2].kwargs.get('as_team'))


class TestJsonNsfPermissions(TestCase):
    def test_json_loads_permissions_without_users_only(self):
        """NSF import needs permissions on shared folders even without --users."""
        payload = {
            'shared_folders': [
                {
                    'path': 'NSF Demo\\Partners',
                    'manage_users': True,
                    'manage_records': True,
                    'can_edit': True,
                    'can_share': True,
                    'permissions': [
                        {
                            'name': 'partner@example.com',
                            'manage_users': False,
                            'manage_records': True,
                        },
                        {
                            'uid': 'teamUidABCDEFG0123456',
                            'name': 'Engineering',
                            'manage_users': True,
                            'manage_records': True,
                        },
                    ],
                }
            ],
            'records': [
                {
                    'title': 'Portal',
                    'login': 'admin',
                    'password': 'secret',
                    'folders': [{'shared_folder': 'NSF Demo\\Partners'}],
                }
            ],
        }
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as tf:
            json.dump(payload, tf)
            path = tf.name
        try:
            importer = KeeperJsonImporter()
            items = list(importer.do_import(path, users_only=False))
        finally:
            os.unlink(path)

        folders = [x for x in items if isinstance(x, SharedFolder)]
        records = [x for x in items if isinstance(x, Record)]
        self.assertEqual(len(folders), 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(folders[0].path, 'NSF Demo\\Partners')
        self.assertIsNotNone(folders[0].permissions)
        self.assertEqual(len(folders[0].permissions), 2)
        self.assertEqual(folders[0].permissions[0].name, 'partner@example.com')
        self.assertTrue(folders[0].permissions[0].manage_records)
        self.assertFalse(folders[0].permissions[0].manage_users)
        self.assertEqual(folders[0].permissions[1].uid, 'teamUidABCDEFG0123456')
        self.assertTrue(folders[0].permissions[1].manage_users)

    def test_sample_nsf_json_includes_permissions(self):
        sample = os.path.join(
            os.path.dirname(__file__), '..', 'sample_data', 'import_nsf.json.txt')
        if not os.path.isfile(sample):
            self.skipTest('sample_data/import_nsf.json.txt missing')
        importer = KeeperJsonImporter()
        folders = [x for x in importer.do_import(sample) if isinstance(x, SharedFolder)]
        with_perms = [f for f in folders if f.permissions]
        self.assertGreaterEqual(len(with_perms), 1)
        names = {p.name for f in with_perms for p in f.permissions if p.name}
        self.assertIn('user@mycompany.com', names)


class TestImportNsfCliFlag(TestCase):
    def test_import_parser_has_nsf_flag(self):
        from keepercommander.importer import commands
        action = None
        for a in commands.import_parser._actions:
            if '--nsf' in (a.option_strings or []):
                action = a
                break
        self.assertIsNotNone(action)
        self.assertEqual(action.dest, 'use_nsf')


class TestFilePathResolution(TestCase):
    def test_resolves_json_txt_sample_from_stem(self):
        importer = KeeperJsonImporter()
        # sample_data/import.json.txt exists in the repo
        resolved = importer.resolve_file_path(
            os.path.join(os.path.dirname(__file__), '..', 'sample_data', 'import'))
        self.assertTrue(resolved.endswith('import.json.txt'))
        self.assertTrue(os.path.isfile(resolved))

    def test_resolves_json_txt_when_json_requested(self):
        importer = KeeperJsonImporter()
        sample_json = os.path.join(
            os.path.dirname(__file__), '..', 'sample_data', 'import_nsf.json')
        # File is stored as import_nsf.json.txt; requesting .json should find it
        if not os.path.isfile(sample_json):
            resolved = importer.resolve_file_path(sample_json)
            self.assertTrue(resolved.endswith('import_nsf.json.txt'))
            self.assertTrue(os.path.isfile(resolved))

    def test_resolves_csv_exactly(self):
        from keepercommander.importer.csv.csv import KeeperCsvImporter
        importer = KeeperCsvImporter()
        csv_path = os.path.join(
            os.path.dirname(__file__), '..', 'sample_data', 'import_nsf.csv')
        resolved = importer.resolve_file_path(csv_path)
        self.assertEqual(os.path.abspath(resolved), os.path.abspath(csv_path))
