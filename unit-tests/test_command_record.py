import json
import os
import io

from unittest import TestCase, mock

from data_vault import get_synced_params, VaultEnvironment
from helper import KeeperApiHelper

from keepercommander import api, utils, crypto, attachment, vault
from keepercommander.commands import recordv2, record, record_edit
from keepercommander.error import CommandError


class TestRecord(TestCase):
    vault_env = VaultEnvironment()

    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command

    def tearDown(self):
        mock.patch.stopall()

    def test_parse_field(self):
        prf = record_edit.RecordEditMixin.parse_field('text.aaa==bbb=ccc')
        self.assertEqual(prf.type, 'text')
        self.assertEqual(prf.label, 'aaa=bbb')
        self.assertEqual(prf.value, 'ccc')

        prf = record_edit.RecordEditMixin.parse_field('aaa==bbb==ccc=')
        self.assertEqual(prf.type, '')
        self.assertEqual(prf.label, 'aaa=bbb=ccc')
        self.assertEqual(prf.value, '')

        prf = record_edit.RecordEditMixin.parse_field('aaa====bbb= =ccc=')
        self.assertEqual(prf.type, '')
        self.assertEqual(prf.label, 'aaa==bbb')
        self.assertEqual(prf.value, '=ccc=')

    def test_create_record(self):
        params = get_synced_params()
        r = vault.KeeperRecord.create(params, 'login')

    def test_add_command(self):
        params = get_synced_params()
        cmd = recordv2.RecordAddCommand()

        with mock.patch('keepercommander.api.sync_down'):
            KeeperApiHelper.communicate_expect(['record_add'])
            cmd.execute(params, force=True, title='New Record')
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            KeeperApiHelper.communicate_expect(['record_add'])
            cmd.execute(params, login='login', password='password', url='url', custom='name1: value 1, name2: value 2', title='New Record')
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            KeeperApiHelper.communicate_expect(['record_add'])
            cmd.execute(params, login='login', password='password', url='url', custom=[{'name1': 'value 1', 'name2': 'value 2'}], title='New Record')
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            with mock.patch('builtins.input', return_value='Input Data'):
                KeeperApiHelper.communicate_expect(['record_add'])
                cmd.execute(params, force=True, title='New Record')
                self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_add_command_check_request(self):
        params = get_synced_params()
        cmd = recordv2.RecordAddCommand()

        def check_record(rq):
            rq['command'] = 'record_add'
            record_key = api.decrypt_data(rq['record_key'], self.vault_env.data_key)
            data_bytes = api.decrypt_data(rq['data'], record_key)
            data = json.loads(data_bytes.decode('utf-8'))
            self.assertEqual(data['title'], 'data')
            self.assertEqual(data['title'], data['link'])
            self.assertEqual(data['secret1'], data['secret2'])
            self.assertEqual(len(data['custom']), 2)

        with mock.patch('builtins.input', return_value='data'), mock.patch('keepercommander.api.sync_down'):
            KeeperApiHelper.communicate_expect([check_record])
            cmd.execute(params, custom='name1: value 1, name2: value 2')
            self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_remove_command_from_root(self):
        params = get_synced_params()
        cmd = recordv2.RecordRemoveCommand()

        record_uid = next(iter(params.subfolder_record_cache['']))
        rec = api.get_record(params, record_uid)

        def pre_delete_command(rq):
            self.assertEqual(rq['command'], 'pre_delete')
            return {
                'pre_delete_response': {
                    'would_delete': {
                        'deletion_summary': ['delete all']
                    },

                    'pre_delete_token': 'token'
                }
            }

        with mock.patch('keepercommander.commands.base.user_choice') as choice_mock:
            choice_mock.return_value = KeyboardInterrupt()
            KeeperApiHelper.communicate_expect([pre_delete_command, 'delete'])
            cmd.execute(params, force=True, record=rec.record_uid)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            KeeperApiHelper.communicate_expect([pre_delete_command, 'delete'])
            cmd.execute(params, force=True, record=rec.title)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            with mock.patch('builtins.print'):
                choice_mock.return_value = 'y'
                KeeperApiHelper.communicate_expect([pre_delete_command, 'delete'])
                cmd.execute(params, record=rec.record_uid)
                self.assertTrue(KeeperApiHelper.is_expect_empty())

                KeeperApiHelper.communicate_expect([pre_delete_command, 'delete'])
                cmd.execute(params, record=rec.title)
                self.assertTrue(KeeperApiHelper.is_expect_empty())

                choice_mock.return_value = 'n'
                KeeperApiHelper.communicate_expect([pre_delete_command])
                cmd.execute(params, record=rec.record_uid)
                self.assertTrue(KeeperApiHelper.is_expect_empty())

                KeeperApiHelper.communicate_expect([pre_delete_command])
                cmd.execute(params, record=rec.title)
                self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_search_command(self):
        params = get_synced_params()
        cmd = record.SearchCommand()

        with mock.patch('builtins.print'):
            cmd.execute(params, pattern='.*')
            cmd.execute(params, pattern='Non-existing-name')

    def test_record_list_command(self):
        params = get_synced_params()
        cmd = record.RecordListCommand()

        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, pattern='record')
            mock_print.assert_called()

            mock_print.reset_mock()
            cmd.execute(params, pattern='INVALID')
            mock_print.assert_not_called()

    def test_shared_list_command(self):
        params = get_synced_params()
        cmd = record.RecordListSfCommand()

        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, pattern='folder')
            mock_print.assert_called()

            mock_print.reset_mock()
            cmd.execute(params, pattern='INVALID')
            mock_print.assert_not_called()

    def test_team_list_command(self):
        params = get_synced_params()
        cmd = record.RecordListTeamCommand()

        def get_available_teams(rq):
            self.assertEqual(rq['command'], 'get_available_teams')
            return {
                'teams': [
                    {
                        'team_uid': api.generate_record_uid(),
                        'team_name': 'Team 1'
                    },
                    {
                        'team_uid': api.generate_record_uid(),
                        'team_name': 'Team 2'
                    }
                ]
            }
        KeeperApiHelper.communicate_expect([get_available_teams])
        with mock.patch('builtins.print'):
            cmd.execute(params)
        self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_get_record_uid(self):
        params = get_synced_params()
        cmd = record.RecordGetUidCommand()

        record_uid = next(iter(params.subfolder_record_cache['']))
        with mock.patch('builtins.print'), mock.patch('keepercommander.api.get_record_shares'):
            cmd.execute(params, uid=record_uid)
            cmd.execute(params, format='json', uid=record_uid)

    def test_get_shared_folder_uid(self):
        params = get_synced_params()
        cmd = record.RecordGetUidCommand()

        shared_folder_uid = next(iter(params.shared_folder_cache))
        with mock.patch('builtins.print'):
            cmd.execute(params, uid=shared_folder_uid)
            cmd.execute(params, format='json', uid=shared_folder_uid)

    def test_get_team_uid(self):
        params = get_synced_params()
        cmd = record.RecordGetUidCommand()

        team_uid = next(iter(params.team_cache))
        with mock.patch('builtins.print'):
            cmd.execute(params, uid=team_uid)
            cmd.execute(params, format='json', uid=team_uid)

    def test_get_invalid_uid(self):
        params = get_synced_params()
        cmd = record.RecordGetUidCommand()

        with self.assertRaises(CommandError):
            cmd.execute(params, uid='invalid')

    def test_append_notes_command(self):
        params = get_synced_params()
        cmd = recordv2.RecordAppendNotesCommand()

        record_uid = next(iter(params.subfolder_record_cache['']))
        with mock.patch('keepercommander.api.update_record'):
            cmd.execute(params, notes='notes', record=record_uid)

            with mock.patch('builtins.input', return_value='data'):
                cmd.execute(params, record=record_uid)

        with self.assertRaises(CommandError):
            cmd.execute(params, notes='notes', record='invalid')

    def test_download_attachment_command(self):
        params = get_synced_params()
        cmd = recordv2.RecordDownloadAttachmentCommand()

        records = [x for x in params.record_cache.values() if len(x['extra_unencrypted']) > 10]
        rec = records[0]
        record_uid = rec['record_uid']
        extra = json.loads(rec['extra_unencrypted'].decode('utf-8'))
        attachments = {}  # type: dict[any, tuple[attachment.AttachmentDownloadRequest, bytes]]
        for file in extra['files']:
            atta_id = file['id']   # type: str
            key = utils.base64_url_decode(file['key'])
            body_encoded = crypto.encrypt_aes_v1(os.urandom(file['size']), key)
            rq = attachment.AttachmentDownloadRequest()
            rq.title = 'Title'
            rq.url = f'https://keepersecurity.com/files/{atta_id}'
            rq.is_gcm_encrypted = False
            rq.encryption_key = key

            attachments[atta_id] = (rq, body_encoded)

        def prepare_download(params, record_uid):
            return (x[0] for x in attachments.values())

        def requests_get(url, **kwargs):
            body = next((x[1] for x in attachments.values() if x[0].url == url), None)
            if not body:
                raise Exception(f'URL \"{url}\" not found.')
            rs = mock.Mock()
            rs.status_code = 200
            stream = io.BytesIO(body)
            rs.raw = stream
            rs.__enter__ = mock.Mock(return_value=rs)
            rs.__exit__ = mock.Mock(return_value=None)
            return rs

        with mock.patch('keepercommander.attachment.prepare_attachment_download', side_effect=prepare_download), \
                mock.patch('requests.get', side_effect=requests_get), \
                mock.patch('builtins.open', mock.mock_open()), \
                mock.patch('os.path.abspath', return_value='/file_name'):
            cmd.execute(params, record=record_uid)

    def test_upload_attachment_command(self):
        params = get_synced_params()
        cmd = recordv2.RecordUploadAttachmentCommand()

        record_uid = next(iter([x['record_uid'] for x in params.record_cache.values() if len(x['extra_unencrypted']) > 10]))
        rec = api.get_record(params, record_uid)

        with self.assertRaises(CommandError):
            cmd.execute(params, record=rec.title)

        def request_upload(rq):
            self.assertEqual(rq['command'], 'request_upload')
            return {
                'file_uploads': [{
                    'max_size': 1000000,
                    'url': 'https://keepersecurity.com/uploads/',
                    'success_status_code': 201,
                    'file_id': 'ABCDEF%.2d' % x,
                    'file_parameter': 'file',
                    'parameters': {'a':'b'}
                } for x in range((rq.get('file_count') or 0) + (rq.get('thumbnail_count') or 0))]
            }

        def request_http_post(url, **kwargs):
            attachment = mock.Mock()
            attachment.status_code = 201
            return attachment

        with mock.patch('requests.post', side_effect=request_http_post), \
                mock.patch('builtins.open', mock.mock_open(read_data=b'data')) as m_open, \
                mock.patch('os.path.isfile', return_value=True), \
                mock.patch('os.path.getsize') as mock_getsize:

            m_open.return_value.tell = lambda: 4
            mock_getsize.return_value = 1000000000
            with self.assertRaises(CommandError):
                KeeperApiHelper.communicate_expect([request_upload])
                cmd.execute(params, file=['file.data'], record=record_uid)
                self.assertTrue(KeeperApiHelper.is_expect_empty())

            KeeperApiHelper.communicate_expect([request_upload, 'record_update'])
            m_open.return_value.tell = lambda: 4
            mock_getsize.return_value = 1000
            cmd.execute(params, file=['file.data'], record=record_uid)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

    def test_delete_attachment_command(self):
        params = get_synced_params()
        cmd = recordv2.RecordDeleteAttachmentCommand()

        record_uid = next(iter([x['record_uid'] for x in params.record_cache.values() if len(x['extra_unencrypted']) > 10]))
        rec = api.get_record(params, record_uid)

        KeeperApiHelper.communicate_expect(['record_update'])
        cmd.execute(params, name=[rec.attachments[0]['id']], record=rec.title)
        self.assertTrue(KeeperApiHelper.is_expect_empty())
