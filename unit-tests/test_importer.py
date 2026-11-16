import io
import json
import os
import tempfile
from unittest import TestCase, mock, skipUnless

from data_vault import get_synced_params, get_connected_params
from helper import KeeperApiHelper
from keepercommander import params as params_module, utils, vault
from keepercommander.error import CommandError
from keepercommander.importer import importer, commands, imp_exp
from keepercommander.proto import record_pb2

try:
    from keepercommander.importer.keepass.keepass import KeepassExporter, PyKeePass
except ImportError:
    KeepassExporter = None
    PyKeePass = None


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

    def test_json_export_stdout_does_not_open_output_file(self):
        record = importer.Record()
        record.uid = 'PAM_RECORD_UID'
        record.title = 'PAM record'
        record.type = 'pamUser'
        output = io.StringIO()

        with mock.patch('sys.stdout', output), \
                mock.patch('builtins.open', side_effect=AssertionError('stdout export must not open a file')):
            importer.exporter_for_format('json')().execute(None, [record])

        exported = json.loads(output.getvalue())
        self.assertEqual(exported['records'][0]['uid'], 'PAM_RECORD_UID')

    def test_service_mode_export_defense_in_depth(self):
        params = params_module.KeeperParams()
        params.service_mode = True
        command = commands.RecordExportCommand()

        for options in (
            {'format': 'json', 'name': '/tmp/export.json'},
            {'format': 'json', 'name': None, 'zip_archive': True},
            {'format': 'json', 'name': None, 'max_size': '1M'},
            {'format': 'csv', 'name': None},
        ):
            with self.subTest(options=options), self.assertRaises(CommandError):
                command.execute(params, **options)

        with mock.patch('keepercommander.importer.commands.imp_exp.export') as export:
            command.execute(
                params, format='json', name=None, folder='FOLDER_UID',
                owned_only=True,
            )

        export.assert_called_once_with(
            params, 'json', None, folder='FOLDER_UID', owned_only=True,
            _service_mode_record_limit=imp_exp.SERVICE_MODE_EXPORT_MAX_RECORDS,
            _service_mode_input_limit=imp_exp.SERVICE_MODE_EXPORT_MAX_INPUT_BYTES,
        )

    def test_service_mode_export_restriction_is_an_explicit_command_error(self):
        params = params_module.KeeperParams()
        params.service_mode = True
        params.enforcements = {
            'booleans': [{'key': 'restrict_export', 'value': True}],
        }

        with self.assertRaisesRegex(CommandError, 'enterprise export restrictions'):
            commands.RecordExportCommand().execute(
                params,
                format='json',
                name=None,
            )

    def test_json_export_service_mode_record_limit(self):
        params = params_module.KeeperParams()
        params.record_cache = {
            uid: {
                'record_uid': uid,
                'version': 3,
                'client_modified_time': 0,
                'data_unencrypted': json.dumps({
                    'title': f'Record {uid}',
                    'type': 'login',
                    'fields': [],
                }).encode('utf-8'),
            }
            for uid in ('ONE', 'TWO')
        }

        with mock.patch('keepercommander.importer.imp_exp.sync_down.sync_down'):
            with self.assertRaisesRegex(CommandError, 'record processing limit'):
                imp_exp.export(
                    params,
                    'json',
                    None,
                    _service_mode_record_limit=1,
                )

    def test_json_export_service_mode_input_data_limit(self):
        params = params_module.KeeperParams()
        params.record_cache = {
            'ONE': {
                'record_uid': 'ONE',
                'version': 3,
                'client_modified_time': 0,
                'data_unencrypted': b'x' * 32,
            },
        }

        with mock.patch('keepercommander.importer.imp_exp.sync_down.sync_down'):
            with self.assertRaisesRegex(CommandError, 'input data processing limit'):
                imp_exp.export(
                    params,
                    'json',
                    None,
                    _service_mode_input_limit=8,
                )

    def test_owned_only_export_skips_protected_record_missing_from_record_cache(self):
        params = params_module.KeeperParams()
        visible_uid = 'VISIBLE_RECORD_UID'
        protected_uid = 'PROTECTED_CONFIG_UID'
        params.record_cache = {
            visible_uid: {
                'record_uid': visible_uid,
                'version': 3,
                'client_modified_time': 0,
                'data_unencrypted': json.dumps({
                    'title': 'Visible record',
                    'type': 'login',
                    'fields': [],
                }).encode('utf-8'),
            }
        }
        # Service Mode hides the protected record payload but its ownership
        # metadata remains available for unrelated commands.
        params.record_owner_cache = {
            visible_uid: params_module.RecordOwner(True, None),
            protected_uid: params_module.RecordOwner(True, None),
        }
        output = io.StringIO()

        with mock.patch('keepercommander.importer.imp_exp.sync_down.sync_down'), \
                mock.patch('sys.stdout', output):
            imp_exp.export(params, 'json', None, owned_only=True)

        exported = json.loads(output.getvalue())
        self.assertEqual([record['uid'] for record in exported['records']], [visible_uid])

    @skipUnless(KeepassExporter and PyKeePass, 'pykeepass is not installed')
    def test_keepass_export_sanitizes_xml_invalid_characters(self):
        record = importer.Record()
        record.title = 'bad\x10title'
        record.login = 'user\x10name'
        record.password = 'pass\x10word'
        record.login_url = 'https://example.com/\x10path'
        record.notes = 'note\x10body'

        folder = importer.Folder()
        folder.path = 'group\x10name'
        record.folders = [folder]

        record.fields.append(importer.RecordField('text', 'custom\x10label', 'value\x10data'))

        with tempfile.NamedTemporaryFile(suffix='.kdbx', delete=False) as temp_file:
            file_name = temp_file.name

        try:
            KeepassExporter().do_export(file_name, [record], file_password='password')
            with PyKeePass(file_name, password='password') as kdb:
                self.assertEqual(len(kdb.entries), 1)
                entry = kdb.entries[0]
                self.assertEqual(entry.title, 'badtitle')
                self.assertEqual(entry.username, 'username')
                self.assertEqual(entry.password, 'password')
                self.assertEqual(entry.url, 'https://example.com/path')
                self.assertEqual(entry.notes, 'notebody')
                self.assertEqual(entry.group.name, 'groupname')
                self.assertEqual(entry.custom_properties.get('$text:customlabel'), 'valuedata')
        finally:
            if os.path.exists(file_name):
                os.unlink(file_name)

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

    def test_export_schedule_field_preserves_quartz_cron_seconds(self):
        schedule = {"type": "CRON", "cron": "1 5 1 * * ?", "tz": "Etc/UTC"}
        self.assertEqual(vault.TypedField.export_schedule_field(schedule), '1 5 1 * * ?')

        schedule = {"type": "CRON", "cron": "0 5 1 * * ?"}
        self.assertEqual(vault.TypedField.export_schedule_field(schedule), '0 5 1 * * ?')

        schedule = {"type": "CRON", "cron": "5 1 * * ?"}
        self.assertEqual(vault.TypedField.export_schedule_field(schedule), '5 1 * * ?')


class TestKeeperV3AttachmentDownload(TestCase):
    def setUp(self):
        self.params = mock.MagicMock()
        self.params.rest_context.proxies = None
        self.rest_requests = []
        self.denied_uids = set()
        self.rest_mock = mock.patch.object(imp_exp.api, 'communicate_rest', side_effect=self._files_download).start()
        self.get_mock = mock.patch.object(imp_exp.requests, 'get').start()
        mock.patch.object(imp_exp.KeeperV3Attachment, 'set_stream', lambda s, raw, for_encrypt: raw).start()

    def tearDown(self):
        mock.patch.stopall()

    def _files_download(self, params, rq, endpoint, rs_type):
        self.rest_requests.append(list(rq.record_uids))
        rs = record_pb2.FilesGetResponse()
        for uid in rq.record_uids:
            f = rs.files.add()
            f.record_uid = uid
            if uid in self.denied_uids:
                f.status = record_pb2.FG_ACCESS_DENIED
            else:
                f.status = record_pb2.FG_SUCCESS
                f.url = 'https://files/' + utils.base64_url_encode(uid)
                f.success_status_code = 200
        return rs

    @staticmethod
    def _http_response(status_code):
        rs = mock.MagicMock()
        rs.status_code = status_code
        rs.raw = io.BytesIO(b'data')
        return rs

    def _attachments(self, count):
        return [imp_exp.KeeperV3Attachment(self.params, utils.generate_uid()) for _ in range(count)]

    def test_batches_files_download_requests(self):
        attachments = self._attachments(205)
        events = []
        self.rest_mock.side_effect = lambda *a, **kw: (events.append('prefetch'), self._files_download(*a, **kw))[1]
        self.get_mock.side_effect = lambda url, **kw: (events.append('download'), self._http_response(200))[1]

        ensure_url = imp_exp.KeeperV3Attachment.batch_prefetcher(attachments)
        for atta in attachments:
            ensure_url(atta)
            atta.open()

        self.assertEqual([len(x) for x in self.rest_requests], [100, 100, 5])
        self.assertEqual(events.count('download'), 205)
        first, second, third = [i for i, e in enumerate(events) if e == 'prefetch']
        self.assertEqual(second - first - 1, 100)
        self.assertEqual(third - second - 1, 100)

    def test_failed_file_falls_back_to_single_request(self):
        attachments = self._attachments(3)
        denied_uid = utils.base64_url_decode(attachments[1].file_uid)
        self.denied_uids.add(denied_uid)
        self.get_mock.side_effect = lambda url, **kw: self._http_response(200)

        imp_exp.KeeperV3Attachment.prefetch_urls(attachments)
        self.assertIsNone(attachments[1]._url)
        self.assertIsNotNone(attachments[0]._url)

        self.denied_uids.clear()
        attachments[1].open()
        self.assertEqual(self.rest_requests[-1], [denied_uid])
        self.assertIsNotNone(attachments[1]._url)

    def test_prefetch_error_does_not_abort(self):
        attachments = self._attachments(2)
        self.rest_mock.side_effect = Exception('throttled')
        imp_exp.KeeperV3Attachment.prefetch_urls(attachments)
        self.assertTrue(all(a._url is None for a in attachments))

    def test_expired_url_closes_response_and_refreshes(self):
        atta = self._attachments(1)[0]
        imp_exp.KeeperV3Attachment.prefetch_urls([atta])
        expired = self._http_response(403)
        fresh = self._http_response(200)
        self.get_mock.side_effect = [expired, fresh]

        atta.open()

        expired.close.assert_called_once()
        self.assertEqual(self.get_mock.call_count, 2)
        self.assertEqual(len(self.rest_requests), 2)
