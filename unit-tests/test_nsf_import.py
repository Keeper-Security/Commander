import json
import os
import tempfile
from unittest import TestCase, mock

from keepercommander.error import KeeperApiError
from keepercommander.importer import nsf_import
from keepercommander.importer.commands import RecordImportCommand, import_parser
from keepercommander.importer.csv.csv import KeeperCsvImporter
from keepercommander.importer.importer import Folder, Record, SharedFolder, Permission
from keepercommander.importer.json.json import KeeperJsonImporter
from keepercommander.subfolder import NestedShareFolderNode

SAMPLE = os.path.join(os.path.dirname(__file__), '..', 'sample_data')
GRANT = 'keepercommander.nested_share_folder.folder_api.grant_folder_access_v3'
CREATE = 'keepercommander.importer.nsf_import.create_nsf_folders_batch'


def _params(folders=None):
    p = mock.MagicMock()
    p.nested_share_folders = folders or {}
    p.subfolder_cache = {}
    p.folder_cache = {}
    p.enforcements = None
    return p


def _record(path):
    rec = Record()
    fol = Folder()
    fol.path = path
    rec.folders = [fol]
    return rec, fol


def _perm(name=None, uid=None, role=None, manage_records=False, manage_users=False):
    p = Permission()
    p.name = name
    p.uid = uid
    p.role = role
    p.manage_records = manage_records
    p.manage_users = manage_users
    return p


class TestNsfImport(TestCase):
    def test_classic_perms_to_nsf_role(self):
        cases = [
            ((True, True), 'full-manager'),
            ((False, True), 'content-manager'),
            ((False, False), 'viewer'),
        ]
        for args, role in cases:
            self.assertEqual(nsf_import.classic_perms_to_nsf_role(*args), role)
        self.assertEqual(
            nsf_import.classic_perms_to_nsf_role(False, True, can_share=True),
            'content-share-manager')
        self.assertEqual(
            nsf_import.classic_perms_to_nsf_role(False, False, can_share=True),
            'share-manager')

    def test_flatten_and_find(self):
        rec, fol = _record('')
        fol.domain = 'Shared'
        fol.path = 'Team\\Apps'
        nsf_import.flatten_record_folder_paths([rec])
        self.assertEqual((fol.domain, fol.path), ('', 'Shared\\Team\\Apps'))

        params = _params({
            'root1': {'name': 'Migration', 'parent_uid': ''},
            'child1': {'name': 'Apps', 'parent_uid': 'root1'},
        })
        self.assertEqual(nsf_import.find_nsf_child(params, 'Migration', ''), 'root1')
        self.assertEqual(nsf_import.find_nsf_child(params, 'Apps', 'root1'), 'child1')
        self.assertIsNone(nsf_import.find_nsf_child(params, 'Missing', 'root1'))

    def test_is_nsf_folder(self):
        params = _params({'nsf1': {'name': 'Root'}})
        params.subfolder_cache = {'nsf2': {'source': 'nested_share_folder'}}
        node = NestedShareFolderNode()
        node.uid = 'nsf3'
        params.folder_cache = {'nsf3': node}
        self.assertTrue(nsf_import.is_nsf_folder(params, 'nsf1'))
        self.assertTrue(nsf_import.is_nsf_folder(params, 'nsf2'))
        self.assertTrue(nsf_import.is_nsf_folder(params, 'nsf3'))
        self.assertFalse(nsf_import.is_nsf_folder(params, 'missing'))

    def test_prepare_nsf_folders(self):
        params = _params({
            'root1': {'name': 'Migration', 'parent_uid': ''},
            'child1': {'name': 'Apps', 'parent_uid': 'root1'},
        })
        rec, fol = _record('Migration\\Apps')
        self.assertEqual(nsf_import.prepare_nsf_folders(params, [], [rec]), 0)
        self.assertEqual(fol.uid, 'child1')

        rec, fol = _record('Migration\\New')
        with mock.patch(CREATE, return_value=['new1']) as m:
            nsf_import.prepare_nsf_folders(params, [], [rec])
            m.assert_called_once_with(params, [('New', 'root1')])
            self.assertEqual(fol.uid, 'new1')

        sf = SharedFolder()
        sf.path = 'ProjectA'
        with mock.patch(CREATE, return_value=['proj1']) as m:
            nsf_import.prepare_nsf_folders(_params({'base': {'name': 'Base', 'parent_uid': ''}}),
                                          [sf], [], 'base')
            m.assert_called_once_with(mock.ANY, [('ProjectA', 'base')])
            self.assertEqual(sf.uid, 'proj1')

    def test_prepare_nsf_folders_batches_same_depth(self):
        params = _params({'root': {'name': 'Root', 'parent_uid': ''}})
        rec_a, fol_a = _record('Root\\A')
        rec_b, fol_b = _record('Root\\B')
        with mock.patch(CREATE, return_value=['uidA', 'uidB']) as m:
            nsf_import.prepare_nsf_folders(params, [], [rec_a, rec_b])
            m.assert_called_once_with(params, [('A', 'root'), ('B', 'root')])
            self.assertEqual((fol_a.uid, fol_b.uid), ('uidA', 'uidB'))

    def test_throttle_retry(self):
        n = {'c': 0}

        def flaky():
            n['c'] += 1
            if n['c'] < 3:
                raise KeeperApiError('throttled', 'throttled')
            return 'ok'

        with mock.patch('keepercommander.importer.nsf_import.time.sleep') as sleep:
            self.assertEqual(nsf_import._call_with_throttle_retry('t', flaky), 'ok')
        self.assertEqual((n['c'], sleep.call_count), (3, 2))

    def test_apply_permissions_classic_and_role(self):
        params = _params({'f1': {'name': 'Team', 'parent_uid': ''}})
        sf = SharedFolder()
        sf.uid = 'f1'
        sf.path = 'Team'
        sf.permissions = [
            _perm(name='user@example.com', manage_records=True),
            _perm(name='viewer@example.com', role='viewer'),
            _perm(name='admin@example.com', role='full-manager'),
            _perm(name='editor@example.com', role='content_manager'),
            _perm(name='bad@example.com', role='superuser'),
        ]
        with mock.patch(GRANT, return_value={'success': True}) as grant:
            nsf_import.apply_nsf_folder_permissions(params, [sf])
            roles = [c.kwargs.get('role') for c in grant.call_args_list]
            self.assertEqual(roles, ['content-manager', 'viewer', 'full-manager', 'content-manager'])
            self.assertEqual(grant.call_args_list[0].args[2], 'user@example.com')

    def test_json_loads_permissions_and_roles(self):
        payload = {
            'shared_folders': [{
                'path': 'NSF\\Team',
                'permissions': [
                    {'name': 'u@ex.com', 'manage_records': True},
                    {'name': 'a@ex.com', 'role': 'full-manager'},
                    {'uid': 'teamUid12345678901234', 'role': 'viewer'},
                ],
            }],
            'records': [{'title': 'R', 'login': 'u', 'password': 'p',
                         'folders': [{'folder': 'NSF\\Team'}]}],
        }
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8') as tf:
            json.dump(payload, tf)
            path = tf.name
        try:
            items = list(KeeperJsonImporter().do_import(path))
        finally:
            os.unlink(path)

        folders = [x for x in items if isinstance(x, SharedFolder)]
        self.assertEqual(len(folders), 1)
        perms = folders[0].permissions
        self.assertEqual(len(perms), 3)
        self.assertEqual(perms[0].name, 'u@ex.com')
        self.assertTrue(perms[0].manage_records)
        self.assertEqual(perms[1].role, 'full-manager')
        self.assertEqual(perms[2].uid, 'teamUid12345678901234')

    def test_sample_files(self):
        for name, check in (
            ('import_nsf.txt', lambda fs: any(p.name == 'user@mycompany.com'
                                             for f in fs for p in (f.permissions or []))),
            ('import_nsf_permissions.txt', lambda fs: {
                p.role for f in fs for p in (f.permissions or []) if p.role
            } >= {'viewer', 'full-manager', 'content-manager'}),
        ):
            path = os.path.join(SAMPLE, name)
            if not os.path.isfile(path):
                self.skipTest(f'{name} missing')
            folders = [x for x in KeeperJsonImporter().do_import(path) if isinstance(x, SharedFolder)]
            self.assertTrue(check(folders), name)

    def test_cli_nsf_skips_classic_prompt(self):
        cmd = RecordImportCommand()
        with mock.patch('keepercommander.importer.commands.user_choice') as choice, \
             mock.patch('keepercommander.importer.commands.imp_exp._import') as imp:
            cmd.execute(_params(), format='json', name='sample_data/import_nsf.txt',
                        use_nsf=True, users_only=True)
            choice.assert_not_called()
            self.assertTrue(all(not imp.call_args.kwargs.get(k)
                                for k in ('manage_users', 'manage_records', 'can_edit', 'can_share')))

            # classic --shared still prompts (name is unused; import is mocked)
            choice.reset_mock()
            choice.return_value = 'a'
            cmd.execute(_params(), format='json', name='sample_data/import_nsf.txt', shared=True)
            choice.assert_called_once()
            self.assertTrue(all(imp.call_args.kwargs.get(k)
                                for k in ('manage_users', 'manage_records', 'can_edit', 'can_share')))

    def test_parser_and_path_resolve(self):
        self.assertTrue(any('--nsf' in (a.option_strings or []) for a in import_parser._actions))

        nsf_txt = os.path.join(SAMPLE, 'import_nsf.txt')
        if not os.path.isfile(nsf_txt):
            self.skipTest('sample_data/import_nsf.txt missing')

        json_imp = KeeperJsonImporter()
        # stem → import_nsf.txt
        self.assertTrue(
            json_imp.resolve_file_path(os.path.join(SAMPLE, 'import_nsf')).endswith('import_nsf.txt'))
        # exact .txt path
        self.assertEqual(
            os.path.abspath(json_imp.resolve_file_path(nsf_txt)),
            os.path.abspath(nsf_txt))

        csv_path = os.path.join(SAMPLE, 'import_nsf.csv')
        if os.path.isfile(csv_path):
            self.assertEqual(
                os.path.abspath(KeeperCsvImporter().resolve_file_path(csv_path)),
                os.path.abspath(csv_path))
