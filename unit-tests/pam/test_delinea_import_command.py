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

from keepercommander.commands.pam_import.delinea_import import (
    DEFAULT_IMPORT_JSON,
    DelineaImportOptions,
    DelineaImportOrchestrator,
    DelineaMappedImport,
    select_folders,
)

sys.path.insert(0, os.path.dirname(__file__))
from _delinea_fixtures import by_title, items, resources, secret  # noqa: E402

DELINEA_IMPORT = 'keepercommander.commands.pam_import.delinea_import'

SAMPLE_FOLDERS = [
    {'folderName': 'Servers', 'folderPath': '\\Servers', 'secrets': [
        secret(1, 'root', 6007, items=items(machine='web01', username='root', password='secret-pw',
                                            private_key='PEM'))]},
    {'folderName': 'Other', 'folderPath': '\\Other', 'secrets': [
        secret(2, 'svc', 6007, items=items(machine='web02', username='svc', password='pw2'))]},
]


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


class TestDelineaImportOrchestrator(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(tmp.name)
        self.client = mock.Mock()
        self.client.folder_secret_details.side_effect = lambda: [dict(f) for f in SAMPLE_FOLDERS]

    def orchestrator(self, **options):
        return DelineaImportOrchestrator(mock.Mock(), self.client, DelineaImportOptions(server='ss', **options))

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

    def test_map(self):
        orchestrator = self.orchestrator(project_name='Proj', gateway='GW1', folders=['Servers'])
        mapped = orchestrator.map(mock.Mock(mappings={}))
        self.assertEqual(orchestrator.import_document['project'], 'Proj')
        self.assertEqual(orchestrator.import_document['pam_configuration']['gateway_name'], 'GW1')
        self.assertIs(mapped.resources, resources(orchestrator.import_document))
        self.assertEqual([r['title'] for r in mapped.resources], ['web01'])

        orchestrator = self.orchestrator()
        orchestrator.map(mock.Mock(mappings={}))
        self.assertNotIn('gateway_name', orchestrator.import_document['pam_configuration'])

    def test_map_warns_when_no_folder_matches(self):
        orchestrator = self.orchestrator(folders=['Nope', 'Nada'])
        with self.assertLogs(level='WARNING') as logs:
            self.assertEqual(orchestrator.map(mock.Mock(mappings={})).resources, [])
        self.assertIn('Nope, Nada', logs.output[0])

    def test_dry_run_writes_redacted_file_prints_and_never_imports(self):
        with mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback') as fallback, \
                mock.patch(f'{DELINEA_IMPORT}.choose_nsf') as choose:
            output = self.run_quiet(self.orchestrator(dry_run=True, yes=True))
        fallback.assert_not_called()
        choose.assert_not_called()
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
        orchestrator.map(mock.Mock(mappings={}))
        redacted = orchestrator.redacted_document(orchestrator.import_document)
        self.assertEqual(by_title(redacted, 'web01')['users'][0]['password'], '***')
        self.assertEqual(by_title(orchestrator.import_document, 'web01')['users'][0]['password'], 'secret-pw')
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
        self.assertTrue(os.path.exists(DEFAULT_IMPORT_JSON))

    def test_import_uses_unredacted_document(self):
        orchestrator = self.orchestrator(yes=True, use_nsf=True)
        with mock.patch(f'{DELINEA_IMPORT}.choose_nsf', return_value=True), \
                mock.patch(f'{DELINEA_IMPORT}.run_with_classic_fallback',
                           side_effect=lambda params, project, nsf, run, findings: run(nsf) or nsf), \
                mock.patch.object(orchestrator, 'import_project') as import_project:
            output = self.run_quiet(orchestrator)
        document, nsf = import_project.call_args[0]
        self.assertIs(document, orchestrator.import_document)
        self.assertTrue(nsf)
        self.assertEqual(by_title(document, 'web01')['users'][0]['password'], 'secret-pw')
        self.assertIn('Delinea import (Nested Share Folders): 2 resources, 2 users', output)
        self.assertIn('Rotation: enabled 0, disabled 2', output)

    def test_crosswalk_options(self):
        with self.assertLogs(level='WARNING') as logs:
            self.run_quiet(self.orchestrator(dry_run=True, crosswalk_file='cw.csv'))
        self.assertTrue(any('crosswalk file is not applied' in line for line in logs.output))

        os.remove(DEFAULT_IMPORT_JSON)
        self.client.folder_secret_details.reset_mock()
        orchestrator = self.orchestrator(crosswalk_out='cw.csv')
        with mock.patch.object(orchestrator, 'run_crosswalk') as run_crosswalk:
            orchestrator.run()
        run_crosswalk.assert_called_once()
        self.client.folder_secret_details.assert_not_called()
        self.assertFalse(os.path.exists(DEFAULT_IMPORT_JSON))

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
