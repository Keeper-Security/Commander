"""``pam project delinea-import``: folder selection, dry run / --output, redaction, and import flow."""

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

from keepercommander.error import CommandError
from keepercommander.importer.thycotic.pam import Crosswalk
from keepercommander.commands.pam_import.delinea_import import (
    DEFAULT_IMPORT_JSON,
    DelineaImportOptions,
    DelineaImportOrchestrator,
    DelineaMappedImport,
    DelineaPAMImportCommand,
    select_folders,
)

sys.path.insert(0, os.path.dirname(__file__))
from _delinea_fixtures import by_title, items, resources, secret  # noqa: E402

DELINEA_IMPORT = 'keepercommander.commands.pam_import.delinea_import'

SSH = {'passwordTypeId': 9, 'passwordTypeName': 'Unix Account (SSH)'}


class FakeClient:
    """``DelineaPamClient`` double: two top-level folders, one SSH secret in each."""

    def __init__(self):
        self.folders_by_id = {
            5: {'id': 5, 'folderName': 'Servers', 'folderPath': '\\Servers'},
            6: {'id': 6, 'folderName': 'Other', 'folderPath': '\\Other'},
        }
        self.secrets = {
            1: secret(1, 'root', 6007, folderId=5, autoChangeEnabled=False,
                      items=items(machine='web01', username='root', password='secret-pw', private_key='PEM')),
            2: secret(2, 'svc', 6007, folderId=6, autoChangeEnabled=False,
                      items=items(machine='web02', username='svc', password='pw2')),
        }
        self.folder_permission_rows = {}
        self.secret_permission_rows = {}
        self.folder_permissions = mock.Mock(side_effect=lambda fid: self.folder_permission_rows.get(fid, []))

    def folders(self):
        return self.folders_by_id

    def users(self):
        return {10: {'userName': 'alice', 'emailAddress': 'alice@example.com'}}

    def groups(self):
        return {}

    def secret_ids(self, folder_ids):
        return [sid for sid, row in self.secrets.items() if row['folderId'] in folder_ids]

    def secret(self, secret_id):
        return self.secrets.get(secret_id)

    def secret_permissions(self, secret_id):
        return self.secret_permission_rows.get(secret_id, [])

    def secret_rpc(self, _secret_id):
        return dict(SSH)

    def sites(self):
        return {}

    def __getattr__(self, _name):
        # secret_settings, secret_policy, folder, secret_template, password_type, password_requirement
        return lambda *_args: None


class TestSelectFolders(unittest.TestCase):
    FOLDERS = [
        {'folderName': 'Servers', 'folderPath': '\\Servers'},
        {'folderName': 'Linux', 'folderPath': '\\Servers\\Linux'},
        {'folderName': 'ServersOld', 'folderPath': '\\ServersOld'},
        {'folderName': 'Databases', 'folderPath': ''},
        {'folderName': '', 'folderPath': ''},
    ]

    def test_no_prefixes_returns_copy_of_all(self):
        for prefixes in ([], ['', '  ']):
            with self.subTest(prefixes=prefixes):
                result = select_folders(self.FOLDERS, prefixes)
                self.assertEqual(result, self.FOLDERS)
                self.assertIsNot(result, self.FOLDERS)

    def test_prefixes(self):
        cases = [
            (['Servers'], ['Servers', 'Linux']),          # subfolders, not siblings
            (['Servers\\Linux'], ['Linux']),
            (['/servers/linux/'], ['Linux']),             # forward slashes, case, trailing separator
            (['\\SERVERS'], ['Servers', 'Linux']),
            (['linux'], ['Linux']),                       # bare folder name
            (['Databases'], ['Databases']),               # path missing, name used
            (['Databases', 'ServersOld'], ['ServersOld', 'Databases']),
            (['Nope'], []),
        ]
        for prefixes, expected in cases:
            with self.subTest(prefixes=prefixes):
                self.assertEqual([f['folderName'] for f in select_folders(self.FOLDERS, prefixes)], expected)

    def test_malformed_folder_entries_are_skipped(self):
        folders = [None, 'Servers', self.FOLDERS[0]]
        self.assertEqual(select_folders(folders, ['Servers']), [self.FOLDERS[0]])


class TestDelineaImportOrchestrator(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(tmp.name)
        self.client = FakeClient()
        self.params = mock.Mock(enterprise={'users': [{'username': 'alice@example.com'}]}, available_team_cache=[])

    def orchestrator(self, **options):
        return DelineaImportOrchestrator(self.params, self.client, DelineaImportOptions(server='ss', **options))

    @staticmethod
    def run_quiet(orchestrator):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            orchestrator.run()
        return out.getvalue()

    @staticmethod
    def read(path):
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)

    def test_privileged_account_is_added_to_the_resource_users(self):
        self.client.secrets[3] = secret(
            3, 'monthly', 6007, folderId=5, autoChangeEnabled=True,
            items=items(machine='monthlyRPC', username='svc', password='pw'))
        self.client.secrets[20] = secret(
            20, 'AdminUserRPC', 6007, folderId=99,
            items=items(machine='admin-host', username='domadm', password='admin-pw'))
        original = self.client.secret_rpc

        def secret_rpc(secret_id):
            rpc = dict(original(secret_id))
            if secret_id in (1, 3):
                rpc['privilegedAccountSecretId'] = 20
            return rpc

        self.client.secret_rpc = secret_rpc
        mapped = self.orchestrator(folders=['Servers']).map(Crosswalk())
        by_host = {resource['title']: resource for resource in mapped.resources}
        self.assertEqual(set(by_host), {'web01', 'monthlyRPC'})
        self.assertEqual(mapped.users, [])
        for host, account in (('web01', 'root'), ('monthlyRPC', 'monthly')):
            users = by_host[host]['users']
            self.assertEqual([user['title'] for user in users], [account, 'AdminUserRPC'])
            admin = users[1]
            self.assertEqual((admin['login'], admin['password'], admin['folder_path']),
                             ('domadm', 'admin-pw', 'Servers/Servers - Users'))
            connection = by_host[host]['pam_settings']['connection']
            self.assertEqual(connection['launch_credentials'], account)
            self.assertEqual(connection['administrative_credentials'], 'AdminUserRPC')
        self.assertIsNot(by_host['web01']['users'][1], by_host['monthlyRPC']['users'][1])

    def test_map(self):
        orchestrator = self.orchestrator(project_name='Proj', gateway='GW1', folders=['Servers'])
        mapped = orchestrator.map(Crosswalk())
        self.assertEqual([r['title'] for r in mapped.resources], ['web01'])
        self.assertEqual(list(mapped.folder_grants), ['Servers'])
        self.assertEqual(mapped.resources[0]['type'], 'pamMachine')
        document = orchestrator.build_import_json(mapped, False)
        self.assertEqual(document['project'], 'Proj')
        self.assertEqual(document['pam_configuration']['gateway_name'], 'GW1')
        # Same content, but a copy: build_import_json() is called once per import attempt.
        self.assertEqual(document['pam_data']['resources'], mapped.resources)
        self.assertIsNot(document['pam_data']['resources'], mapped.resources)
        document['pam_data']['resources'][0]['users'][0]['password'] = 'changed'
        self.assertEqual(mapped.resources[0]['users'][0]['password'], 'secret-pw')

        orchestrator = self.orchestrator()
        document = orchestrator.build_import_json(orchestrator.map(Crosswalk()), False)
        self.assertNotIn('gateway_name', document['pam_configuration'])
        self.assertEqual(len(resources(document)), 2)

    def test_map_warns_when_no_folder_matches(self):
        orchestrator = self.orchestrator(folders=['Nope', 'Nada'])
        with self.assertLogs(level='WARNING') as logs:
            self.assertEqual(orchestrator.map(Crosswalk()).resources, [])
        self.assertIn('Nope, Nada', logs.output[0])

    def test_nested_inheriting_folder_keeps_its_own_shared_folder(self):
        """A secret stays in its own folder even when that folder inherits permissions."""
        self.client.folders_by_id = {
            1: {'id': 1, 'folderName': 'Level1', 'folderPath': '\\Level1'},
            2: {'id': 2, 'folderName': 'Level2', 'folderPath': '\\Level1\\Level2',
                'parentFolderId': 1, 'inheritPermissions': True},
            3: {'id': 3, 'folderName': 'Level3', 'folderPath': '\\Level1\\Level2\\Level3',
                'parentFolderId': 2, 'inheritPermissions': False},
            4: {'id': 4, 'folderName': 'Level4', 'folderPath': '\\Level1\\Level2\\Level3\\Level4',
                'parentFolderId': 3, 'inheritPermissions': True},
            5: {'id': 5, 'folderName': 'Level5', 'folderPath': '\\Level1\\Level2\\Level3\\Level4\\Level5',
                'parentFolderId': 4, 'inheritPermissions': True},
        }
        self.client.secrets = {
            1: secret(1, 'Account1', 6007, folderId=3, autoChangeEnabled=False,
                      items=items(machine='res1', username='user1', password='p1')),
            2: secret(2, 'Account2', 6007, folderId=3, autoChangeEnabled=False,
                      items=items(machine='res2', username='user2', password='p2')),
            3: secret(3, 'Account3', 6007, folderId=5, autoChangeEnabled=False,
                      items=items(machine='res3', username='user3', password='p3')),
        }
        mapped = self.orchestrator().map(Crosswalk())
        self.assertEqual(sorted(r['folder_path'] for r in mapped.resources), [
            'Level3/Level3 - Resources',
            'Level3/Level3 - Resources',
            'Level5/Level5 - Resources',
        ])
        self.assertEqual(sorted(user['folder_path'] for resource in mapped.resources for user in resource['users']), [
            'Level3/Level3 - Users',
            'Level3/Level3 - Users',
            'Level5/Level5 - Users',
        ])
        self.assertEqual(sorted(mapped.folder_grants), ['Level3', 'Level5'])
        self.assertEqual(sorted(c.args[0] for c in self.client.folder_permissions.call_args_list), [3, 5])

    def test_same_name_folders_with_different_ids_stay_separate(self):
        """Two folders named alike under different parents get distinct shared folders and grants."""
        self.client.folders_by_id = {
            1: {'id': 1, 'folderName': 'Prod', 'folderPath': '\\TeamA\\Prod'},
            2: {'id': 2, 'folderName': 'Prod', 'folderPath': '\\TeamB\\Prod'},
        }
        self.client.secrets = {
            1: secret(1, 'Account1', 6007, folderId=1, autoChangeEnabled=False,
                      items=items(machine='res1', username='user1', password='p1')),
            2: secret(2, 'Account2', 6007, folderId=2, autoChangeEnabled=False,
                      items=items(machine='res2', username='user2', password='p2')),
            3: secret(3, 'Account3', 6007, folderId=1, autoChangeEnabled=False,
                      items=items(machine='res3', username='user3', password='p3')),
        }
        mapped = self.orchestrator().map(Crosswalk())
        paths = {r['title']: r['folder_path'] for r in mapped.resources}
        self.assertEqual(paths['res1'], 'Prod/Prod - Resources')
        self.assertEqual(paths['res3'], 'Prod/Prod - Resources')
        self.assertEqual(paths['res2'], 'Prod #2/Prod #2 - Resources')
        self.assertEqual(sorted(mapped.folder_grants), ['Prod', 'Prod #2'])
        self.assertEqual(sorted(c.args[0] for c in self.client.folder_permissions.call_args_list), [1, 2])

    def test_folder_permissions_read_once_per_folder(self):
        self.client.secrets[3] = secret(3, 'root2', 6007, folderId=5, autoChangeEnabled=False,
                                        items=items(machine='web03', username='r', password='p'))
        row = {'userId': 10, 'folderAccessRoleName': 'View', 'secretAccessRoleName': 'View'}
        self.client.folder_permission_rows = {5: [row]}
        self.client.secret_permission_rows = {1: [dict(row, secretAccessRoleName='Owner')], 3: [row]}
        mapped = self.orchestrator().map(Crosswalk())
        self.assertEqual(sorted(c.args[0] for c in self.client.folder_permissions.call_args_list), [5, 6])
        self.assertEqual([t.secret_id for t in mapped.secret_grants], [1])
        self.assertEqual(len(mapped.folder_grants['Servers']), 1)

    def test_skip_permissions_reads_no_permissions(self):
        mapped = self.orchestrator(skip_permissions=True).map(Crosswalk())
        self.client.folder_permissions.assert_not_called()
        self.assertEqual(mapped.folder_grants, {'Servers': [], 'Other': []})

    def test_dry_run_writes_redacted_file_prints_and_never_imports(self):
        with mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback') as fallback:
            output = self.run_quiet(self.orchestrator(dry_run=True, yes=True))
        fallback.assert_not_called()
        self.assertIn('[DRY RUN COMPLETE] 2 resources, 2 users would be imported.', output)
        self.assertNotIn('secret-pw', output)
        self.assertNotIn('PEM', output)
        user = by_title(self.read(DEFAULT_IMPORT_JSON), 'web01')['users'][0]
        self.assertEqual((user['password'], user['private_pem_key']), ('***', '***'))

    def test_dry_run_with_output_writes_only_that_file(self):
        self.run_quiet(self.orchestrator(dry_run=True, output_file='review.json'))
        self.assertTrue(os.path.exists('review.json'))
        self.assertFalse(os.path.exists(DEFAULT_IMPORT_JSON))

    def test_output_writes_owner_only_file_and_exits(self):
        with open('review.json', 'w', encoding='utf-8') as fh:
            fh.write('x' * 10000)
        with mock.patch(f'{DELINEA_IMPORT}.user_choice') as prompt, \
                mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback') as fallback:
            output = self.run_quiet(self.orchestrator(output_file='review.json'))
        prompt.assert_not_called()
        fallback.assert_not_called()
        self.assertIn('Import JSON saved to: review.json', output)
        self.assertEqual(len(resources(self.read('review.json'))), 2)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(os.stat('review.json').st_mode), 0o600)

    def test_include_credentials_keeps_secrets(self):
        self.run_quiet(self.orchestrator(output_file='review.json', include_credentials=True))
        user = by_title(self.read('review.json'), 'web01')['users'][0]
        self.assertEqual((user['password'], user['private_pem_key']), ('secret-pw', 'PEM'))

    def test_redacted_document(self):
        orchestrator = self.orchestrator()
        document = orchestrator.build_import_json(orchestrator.map(Crosswalk()), False)
        redacted = orchestrator.redacted_document(document)
        self.assertEqual(by_title(redacted, 'web01')['users'][0]['password'], '***')
        self.assertEqual(by_title(document, 'web01')['users'][0]['password'], 'secret-pw')
        self.assertEqual(orchestrator.redacted_document({}), {})
        sparse = {'pam_data': {'users': [{'private_pem_key': 'k', 'password': 'p'}], 'resources': [{}]}}
        self.assertEqual(orchestrator.redacted_document(sparse)['pam_data']['users'][0],
                         {'private_pem_key': '***', 'password': '***'})

    def test_declined_prompt_does_not_import(self):
        with mock.patch(f'{DELINEA_IMPORT}.user_choice', return_value='n') as prompt, \
                mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback') as fallback:
            self.run_quiet(self.orchestrator())
        self.assertIn('2 resources and 2 users', prompt.call_args[0][0])
        fallback.assert_not_called()
        # File is not written when user declines (no --dry-run or --output-file flag)
        self.assertFalse(os.path.exists(DEFAULT_IMPORT_JSON))

    def test_declined_prompt_does_not_create_users_or_teams(self):
        self.client.auth = mock.Mock()
        with mock.patch(f'{DELINEA_IMPORT}.ThycoticImporter') as importer_cls, \
                mock.patch(f'{DELINEA_IMPORT}.user_choice', return_value='n') as prompt, \
                mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback') as fallback:
            self.run_quiet(self.orchestrator(add_users=True, add_teams=True))
        self.assertIn('create Keeper users and Keeper teams', prompt.call_args[0][0])
        fallback.assert_not_called()
        importer_cls.return_value._migrate_thycotic_users.assert_not_called()
        importer_cls.return_value._migrate_thycotic_teams.assert_not_called()

    def test_import_uses_unredacted_document(self):
        orchestrator = self.orchestrator(yes=True, use_nsf=True)
        with mock.patch(f'{DELINEA_IMPORT}.choose_nsf', return_value=True), \
                mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback',
                           side_effect=lambda params, project, nsf, run, findings: run(nsf) or nsf), \
                mock.patch.object(orchestrator, 'import_project') as import_project:
            output = self.run_quiet(orchestrator)
        document, nsf = import_project.call_args[0]
        self.assertTrue(nsf)
        self.assertEqual(by_title(document, 'web01')['users'][0]['password'], 'secret-pw')
        self.assertIn('Delinea import (Nested Share Folders): 2 resources, 2 users', output)
        self.assertIn('Rotation: disabled 2, inherited 0', output)

    def test_failed_import_raises_and_skips_secret_grants(self):
        row = {'userId': 10, 'folderAccessRoleName': 'View', 'secretAccessRoleName': 'Owner'}
        self.client.secret_permission_rows = {1: [row]}
        with mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback', side_effect=RuntimeError('boom')), \
                mock.patch(f'{DELINEA_IMPORT}.apply_secret_grants') as grants:
            with self.assertRaises(RuntimeError):
                self.run_quiet(self.orchestrator(yes=True))
        grants.assert_not_called()

    def test_crosswalk_options(self):
        with open('cw.csv', 'w', encoding='utf-8') as fh:
            fh.write('changer_name,record_type,protocol,port\nUnix Account (SSH),login,,\n')
        mapped = []
        orchestrator = self.orchestrator(dry_run=True, crosswalk_file='cw.csv')
        with mock.patch.object(orchestrator, 'map', side_effect=lambda cw: mapped.append(cw) or
                               DelineaMappedImport()):
            self.run_quiet(orchestrator)
        self.assertEqual(mapped[0].resolve('unix account (ssh)').record_type, 'login')

        with self.assertRaises(CommandError):
            self.orchestrator(crosswalk_file='missing.csv').run()

        os.remove(DEFAULT_IMPORT_JSON)
        orchestrator = self.orchestrator(crosswalk_out='cw.csv')
        with mock.patch.object(orchestrator, 'run_crosswalk') as run_crosswalk, \
                mock.patch.object(orchestrator, 'map') as map_:
            orchestrator.run()
        run_crosswalk.assert_called_once()
        map_.assert_not_called()
        self.assertFalse(os.path.exists(DEFAULT_IMPORT_JSON))

    def test_add_users_and_teams_use_thycotic_importer(self):
        auth = mock.Mock()
        self.client.auth = auth
        cases = (
            ({'add_users': True, 'dry_run': True}, '_preview_thycotic_users', (auth,)),
            ({'add_users': True, 'yes': True}, '_migrate_thycotic_users', (auth, self.params)),
            ({'add_teams': True, 'dry_run': True}, '_preview_thycotic_teams', (auth,)),
            ({'add_teams': True, 'yes': True}, '_migrate_thycotic_teams', (auth, self.params)),
        )
        for options, called, args in cases:
            with self.subTest(options=options):
                with mock.patch(f'{DELINEA_IMPORT}.ThycoticImporter') as importer_cls, \
                        mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback', return_value=False):
                    self.run_quiet(self.orchestrator(**options))
                getattr(importer_cls.return_value, called).assert_called_once_with(*args)
                for name in (
                    '_preview_thycotic_users', '_migrate_thycotic_users',
                    '_preview_thycotic_teams', '_migrate_thycotic_teams',
                ):
                    if name != called:
                        getattr(importer_cls.return_value, name).assert_not_called()

    def test_user_and_team_flags_default_off(self):
        options = DelineaImportOptions.from_kwargs({'server': 'ss.example.com'})
        self.assertFalse(options.add_users)
        self.assertFalse(options.add_teams)
        enabled = DelineaImportOptions.from_kwargs({
            'server': 'ss.example.com', 'add_users': True, 'add_teams': True,
        })
        self.assertTrue(enabled.add_users)
        self.assertTrue(enabled.add_teams)
        parsed = DelineaPAMImportCommand.parser.parse_args([
            'ss.example.com', '--add-users', '--add-teams', '--dry-run',
        ])
        self.assertTrue(parsed.add_users)
        self.assertTrue(parsed.add_teams)

    def test_report_counts_rotation_from_users(self):
        mapped = DelineaMappedImport(resources=[{'users': [
            {'rotation_settings': {'enabled': 'on'}}, {'rotation_settings': {'enabled': 'off'}}, {}]}],
            users=[{'title': 'standalone'}])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.orchestrator().report(mapped, used_nsf=False)
        self.assertIn('(classic shared folders): 1 resources, 4 users', out.getvalue())
        self.assertIn('Rotation: enabled 1, disabled 3', out.getvalue())


if __name__ == '__main__':
    unittest.main()
