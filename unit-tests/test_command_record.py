import json
import os
import io
from typing import Union

from unittest import TestCase, mock

from data_vault import get_synced_params, VaultEnvironment
from helper import KeeperApiHelper

from keepercommander import api, utils, crypto, attachment, vault
from keepercommander.commands import record, record_edit
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
        cmd = record_edit.RecordAddCommand()

        with mock.patch('keepercommander.api.sync_down'), \
                mock.patch('keepercommander.record_management.add_record_to_folder') as ar:

            added_record = None     # type: Union[vault.PasswordRecord, vault.TypedRecord, None]
            def artf(p, r, f):
                nonlocal added_record
                added_record = r
                added_record.record_uid = utils.generate_uid()
            ar.side_effect = artf

            with self.assertRaises(CommandError):
                cmd.execute(params, force=True, title='New Record')

            added_record = None
            cmd.execute(params, force=True, title='New Record', record_type='legacy',
                        fields=['login=user@company.com', 'password=password', 'url=https://google.com/', 'AAA=BBB'])
            self.assertIsNotNone(added_record)
            self.assertEqual('New Record', added_record.title)
            self.assertIsInstance(added_record, vault.PasswordRecord)
            self.assertEqual(added_record.login, 'user@company.com')
            self.assertEqual(added_record.password, 'password')
            self.assertEqual(added_record.link, 'https://google.com/')
            self.assertEqual(len(added_record.custom), 1)
            value = added_record.get_custom_value('AAA')
            self.assertEqual(value, 'BBB')

            added_record = None
            cmd.execute(params, force=True, title='New Record', record_type='login',
                        fields=['login=user@company.com', 'password=password', 'url=https://google.com/', 'AAA=BBB'])
            self.assertIsNotNone(added_record)
            self.assertEqual('New Record', added_record.title)
            self.assertIsInstance(added_record, vault.TypedRecord)
            field = added_record.get_typed_field('login')
            self.assertIsNotNone(field)
            self.assertEqual(field.get_default_value(str), 'user@company.com')
            field = added_record.get_typed_field('password')
            self.assertIsNotNone(field)
            self.assertEqual(field.get_default_value(str), 'password')
            field = added_record.get_typed_field('url')
            self.assertIsNotNone(field)
            self.assertEqual(field.get_default_value(str), 'https://google.com/')
            field = added_record.get_typed_field('text', 'AAA')
            self.assertIsNotNone(field)
            self.assertEqual(field.get_default_value(str), 'BBB')

    def test_remove_command_from_root(self):
        params = get_synced_params()
        cmd = record.RecordRemoveCommand()

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
            cmd.execute(params, force=True, records=[rec.record_uid])
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            KeeperApiHelper.communicate_expect([pre_delete_command, 'delete'])
            cmd.execute(params, force=True, record=rec.title)
            self.assertTrue(KeeperApiHelper.is_expect_empty())

            with mock.patch('builtins.print'):
                choice_mock.return_value = 'y'
                KeeperApiHelper.communicate_expect([pre_delete_command, 'delete'])
                cmd.execute(params, records=[rec.record_uid])
                self.assertTrue(KeeperApiHelper.is_expect_empty())

                KeeperApiHelper.communicate_expect([pre_delete_command, 'delete'])
                cmd.execute(params, records=[rec.title])
                self.assertTrue(KeeperApiHelper.is_expect_empty())

                choice_mock.return_value = 'n'
                KeeperApiHelper.communicate_expect([pre_delete_command])
                cmd.execute(params, records=[rec.record_uid])
                self.assertTrue(KeeperApiHelper.is_expect_empty())

                KeeperApiHelper.communicate_expect([pre_delete_command])
                cmd.execute(params, records=[rec.title])
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
        cmd = record_edit.RecordAppendNotesCommand()

        record_uid = next(iter(params.subfolder_record_cache['']))
        with mock.patch('keepercommander.record_management.update_record'):
            cmd.execute(params, notes='notes', record=record_uid)

            with mock.patch('builtins.input', return_value='data'):
                cmd.execute(params, record=record_uid)

        with self.assertRaises(CommandError):
            cmd.execute(params, notes='notes', record='invalid')

    def test_download_attachment_command(self):
        params = get_synced_params()
        cmd = record_edit.RecordDownloadAttachmentCommand()

        records = [x for x in params.record_cache.values() if 'extra_unencrypted' in x and len(x['extra_unencrypted']) > 10]
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

    def test_delete_attachment_command(self):
        params = get_synced_params()
        record_uid = next((x['record_uid'] for x in params.record_cache.values()
                           if 'extra_unencrypted' in x and len(x['extra_unencrypted']) > 10), None)

        rec = vault.KeeperRecord.load(params, record_uid)
        self.assertIsNotNone(rec)
        self.assertIsInstance(rec, vault.PasswordRecord)
        self.assertGreater(len(rec.attachments), 0)

        KeeperApiHelper.communicate_expect(['record_update'])
        cmd = record_edit.RecordDeleteAttachmentCommand()
        cmd.execute(params, name=[rec.attachments[0].id], record=rec.title)
        self.assertTrue(KeeperApiHelper.is_expect_empty())
