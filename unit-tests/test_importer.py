from unittest import TestCase, mock

from data_vault import get_synced_params, get_connected_params
from helper import KeeperApiHelper
from keepercommander.importer import importer, commands


class TestImporterUtils(TestCase):
    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command

    def tearDown(self):
        mock.patch.stopall()

    def test_load_importer_format(self):
        for fmt in ['csv', 'json']:
            self.assertTrue(issubclass(importer.importer_for_format(fmt), importer.BaseImporter))
            self.assertTrue(issubclass(importer.exporter_for_format(fmt), importer.BaseExporter))

    def test_path_components(self):
        comps = list(importer.path_components('wwww\\wwww'))
        self.assertEqual(len(comps), 2)
        self.assertEqual(comps[0], 'wwww')
        self.assertEqual(comps[1], 'wwww')

        comps = list(importer.path_components('ww\\\\ww\\wwww'))
        self.assertEqual(len(comps), 2)
        self.assertEqual(comps[0], 'ww\\ww')
        self.assertEqual(comps[1], 'wwww')

        comps = list(importer.path_components('\\wwww\\'))
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0], 'wwww')

        comps = list(importer.path_components('wwww'))
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0], 'wwww')

    def test_export_import(self):
        params_export = get_synced_params()
        cmd_export = commands.RecordExportCommand()
        param_import = get_connected_params()
        cmd_import = commands.RecordImportCommand()

        json_text = ''

        def mock_write(text):
            nonlocal json_text
            json_text += text

        def mock_read():
            nonlocal json_text
            return json_text

        with mock.patch('keepercommander.api.sync_down'), mock.patch('builtins.open', mock.mock_open()) as m_open:
            m_open.return_value.write = mock_write
            cmd_export.execute(params_export, format='json', filename='json')

        with mock.patch('keepercommander.api.sync_down'), mock.patch('builtins.open', mock.mock_open()) as m_open:
            m_open.return_value.read = mock_read
            self.communicate_mock.side_effect = None
            self.communicate_mock.return_value = {
                'result': 'success',
                'result_code': '',
                'message': ''
            }
            with mock.patch('os.path.isfile', return_value=True):
                cmd_import.execute(param_import, format='json', filename='json')



