from unittest import TestCase, mock

from data_vault import get_synced_params, get_connected_params
from helper import KeeperApiHelper
from keepercommander import vault
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

        with mock.patch('keepercommander.sync_down.sync_down'), mock.patch('builtins.open', mock.mock_open()) as m_open:
            m_open.return_value.write = mock_write
            cmd_export.execute(params_export, format='json', name='json')

        with mock.patch('keepercommander.sync_down.sync_down'), \
                mock.patch('builtins.open', mock.mock_open()) as m_open, \
                mock.patch('keepercommander.importer.imp_exp.execute_import_folder_record', return_value=([], [])), \
                mock.patch('keepercommander.importer.imp_exp.execute_records_add', return_value=[]):
            m_open.return_value.read = mock_read
            self.communicate_mock.side_effect = None
            self.communicate_mock.return_value = {
                'result': 'success',
                'result_code': '',
                'message': ''
            }
            with mock.patch('os.path.isfile', return_value=True):
                cmd_import.execute(param_import, format='json', name='json')

    def test_host_serialization(self):
        host = {
            'hostName': 'keepersecurity.com',
            'port': '222'
        }
        host_str = vault.TypedField.export_host_field(host)
        self.assertIsNotNone(host_str)
        host1 = vault.TypedField.import_host_field(host_str)
        self.assertEqual(host, host1)

    def test_phone_serialization(self):
        dict_value = {
            'region': 'US',
            'number': '(555)123-4567',
            'ext': '',
            'type': 'Mobile'
        }
        str_value = vault.TypedField.export_phone_field(dict_value)
        self.assertIsNotNone(str_value)
        dict_value1 = vault.TypedField.import_phone_field(str_value)
        self.assertEqual(dict_value, dict_value1)

    def test_name_serialization(self):
        dict_value = {
            'first': 'Joe',
            'middle': 'Jr.',
            'last': 'Doe'
        }
        str_value = vault.TypedField.export_name_field(dict_value)
        self.assertIsNotNone(str_value)
        dict_value1 = vault.TypedField.import_name_field(str_value)
        self.assertEqual(dict_value, dict_value1)

    def test_address_serialization(self):
        dict_value = {
            'street1': '100 Main st.',
            'street2': '',
            'city': 'El Dorado Hills',
            'state': 'CA',
            'zip': '95762',
            'country': 'US'
        }
        str_value = vault.TypedField.export_address_field(dict_value)
        self.assertIsNotNone(str_value)
        dict_value1 = vault.TypedField.import_address_field(str_value)
        self.assertEqual(dict_value, dict_value1)

    def test_q_and_a_serialization(self):
        dict_value = {
            'question': 'What is the best password management application',
            'answer': 'keeper'
        }
        str_value = vault.TypedField.export_q_and_a_field(dict_value)
        self.assertIsNotNone(str_value)
        dict_value1 = vault.TypedField.import_q_and_a_field(str_value)
        self.assertTrue(isinstance(dict_value1, dict))
        orig_question = dict_value['question']
        if not orig_question.endswith('?'):
            orig_question += '?'
        self.assertEqual(orig_question, dict_value1['question'])
        self.assertEqual(dict_value['answer'], dict_value1['answer'])

    def test_card_serialization(self):
        dict_value = {
            'cardNumber': '4111111111111111',
            'cardExpirationDate': '05/2025',
            'cardSecurityCode': '123'
        }
        str_value = vault.TypedField.export_card_field(dict_value)
        self.assertIsNotNone(str_value)
        dict_value1 = vault.TypedField.import_card_field(str_value)
        self.assertEqual(dict_value, dict_value1)
        dict_value1 = vault.TypedField.import_card_field(
            f'{dict_value["cardNumber"]}  {dict_value["cardSecurityCode"]}  {dict_value["cardExpirationDate"]}')
        self.assertEqual(dict_value, dict_value1)

    def test_bank_account_serialization(self):
        dict_value = {
            'accountType': 'Checking',
            'routingNumber': '123456789',
            'accountNumber': '98765432109876'
        }
        str_value = vault.TypedField.export_account_field(dict_value)
        self.assertIsNotNone(str_value)
        dict_value1 = vault.TypedField.import_account_field(str_value)
        self.assertEqual(dict_value, dict_value1)

    def test_schedule_parser(self):
        sc = vault.TypedField.import_schedule_field('1 1 * * *')
        self.assertEqual(sc.get('type'), 'DAILY')

        sc = vault.TypedField.import_schedule_field('1 1 */5 * *')
        self.assertEqual(sc.get('type'), 'DAILY')
        self.assertEqual(sc.get('occurrences'), 5)

        sc = vault.TypedField.import_schedule_field('1 1 5 * *')
        self.assertEqual(sc.get('type'), 'MONTHLY_BY_DAY')
        self.assertEqual(sc.get('monthDay'), 5)

        sc = vault.TypedField.import_schedule_field('1 1 20 5 ?')
        self.assertEqual(sc.get('type'), 'YEARLY')
        self.assertEqual(sc.get('monthDay'), 20)
        self.assertEqual(sc.get('month'), 'MAY')

        sc = vault.TypedField.import_schedule_field('1 1 * * */3')
        self.assertEqual(sc.get('type'), 'DAILY')
        self.assertEqual(sc.get('occurrences'), 3)

        sc = vault.TypedField.import_schedule_field('1 1 * * 3')
        self.assertEqual(sc.get('type'), 'WEEKLY')
        self.assertEqual(sc.get('weekday'), 'WEDNESDAY')

        sc = vault.TypedField.import_schedule_field('1 1 * * 3#2')
        self.assertEqual(sc.get('type'), 'MONTHLY_BY_WEEKDAY')
        self.assertEqual(sc.get('weekday'), 'WEDNESDAY')
        self.assertEqual(sc.get('occurrence'), 'SECOND')
