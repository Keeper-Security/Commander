import json
import os
import io
from typing import Union

from unittest import TestCase, mock

from data_vault import get_synced_params, VaultEnvironment
from helper import KeeperApiHelper

from keepercommander import api, utils, crypto, attachment, vault, vault_extensions
from keepercommander.commands import record, record_edit
from keepercommander.error import CommandError


class TestRecord(TestCase):
    vault_env = VaultEnvironment()
    expected_commands = []

    def setUp(self):
        self.communicate_mock = mock.patch('keepercommander.api.communicate').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command
        self.communicate_mock = mock.patch('keepercommander.api.communicate_rest').start()
        self.communicate_mock.side_effect = TestRecord.communicate_rest_success
        TestRecord.expected_commands.clear()

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
            self.assertRaises(CommandError, cmd.execute, params, force=True, title='New Record')
            # cmd.execute(params, force=True, title='New Record', record_type='legacy',
            #             fields=['login=user@company.com', 'password=password', 'url=https://google.com/', 'AAA=BBB'])
            # self.assertIsNotNone(added_record)
            # self.assertEqual('New Record', added_record.title)
            # self.assertIsInstance(added_record, vault.PasswordRecord)
            # self.assertEqual(added_record.login, 'user@company.com')
            # self.assertEqual(added_record.password, 'password')
            # self.assertEqual(added_record.link, 'https://google.com/')
            # self.assertEqual(len(added_record.custom), 1)
            # value = added_record.get_custom_value('AAA')
            # self.assertEqual(value, 'BBB')

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

    def _run_add(self, params, **kwargs):
        """Run record-add with the API mocked; return the TypedRecord that would be saved."""
        cmd = record_edit.RecordAddCommand()
        captured = {}
        with mock.patch('keepercommander.api.sync_down'), \
                mock.patch('keepercommander.record_management.add_record_to_folder') as ar:
            def artf(p, r, f):
                captured['record'] = r
                r.record_uid = utils.generate_uid()
            ar.side_effect = artf
            cmd.execute(params, **kwargs)
        return captured.get('record')

    # RT schema with a label-less field (synthesized fallback) and one with a real definition label.
    _RT_SCHEMA = [
        {"$ref": "login"},                                  # no label in RT definition
        {"$ref": "password"},                               # no label in RT definition
        {"$ref": "script", "label": "rotationScripts"},     # real RT-definition label
    ]

    def test_add_command_labels_default_is_legacy(self):
        # No --labels (and explicit --labels=on): fields with no label in the RT definition fall
        # back to the field type as the label; real definition labels are kept.
        params = get_synced_params()
        for labels in (None, 'on'):
            kwargs = dict(force=True, title='L', record_type='login',
                          fields=['login=user@company.com', 'password=secret'])
            if labels is not None:
                kwargs['labels'] = labels
            with mock.patch.object(record_edit.RecordAddCommand, 'get_record_type_fields',
                                   return_value=list(self._RT_SCHEMA)):
                record = self._run_add(params, **kwargs)
            self.assertIsInstance(record, vault.TypedRecord)
            self.assertEqual(record.get_typed_field('login').label, 'login')            # synthesized
            self.assertEqual(record.get_typed_field('password').label, 'password')      # synthesized
            self.assertEqual(record.get_typed_field('script').label, 'rotationScripts')  # real, kept
            data = vault_extensions.extract_typed_record_data(record)
            login_data = next(x for x in data['fields'] if x['type'] == 'login')
            self.assertEqual(login_data.get('label'), 'login')

    def test_add_command_labels_off_matches_vault(self):
        # --labels=off: omit the synthesized type-name labels (login, password) but KEEP real
        # RT-definition labels (script->rotationScripts), matching the Vault UI; an explicitly
        # provided cmdline label is always preserved.
        params = get_synced_params()
        with mock.patch.object(record_edit.RecordAddCommand, 'get_record_type_fields',
                               return_value=list(self._RT_SCHEMA)):
            record = self._run_add(params, force=True, title='L', record_type='login', labels='off',
                                   fields=['login=user@company.com', 'text.MyLabel=val'])
        self.assertIsInstance(record, vault.TypedRecord)
        self.assertFalse(record.get_typed_field('login').label)                        # synthesized -> dropped
        self.assertFalse(record.get_typed_field('password').label)                     # synthesized -> dropped
        self.assertEqual(record.get_typed_field('script').label, 'rotationScripts')    # real -> kept
        self.assertEqual(record.get_typed_field('text', 'MyLabel').label, 'MyLabel')   # explicit -> kept

        data = vault_extensions.extract_typed_record_data(record)
        login_d = next(x for x in data['fields'] if x['type'] == 'login')
        script_d = next(x for x in data['fields'] if x['type'] == 'script')
        self.assertNotIn('label', login_d)                          # synthesized label omitted
        self.assertEqual(script_d.get('label'), 'rotationScripts')  # real label serialized
        custom_d = next(x for x in data['custom'] if x.get('label') == 'MyLabel')
        self.assertEqual(custom_d['label'], 'MyLabel')

    def test_extract_typed_field_omits_empty_label(self):
        # Serializer omits the label key when falsy; keeps it when present.
        self.assertNotIn('label', vault_extensions.extract_typed_field(
            vault.TypedField.new_field('login', 'admin', '')))
        self.assertNotIn('label', vault_extensions.extract_typed_field(
            vault.TypedField.new_field('login', 'admin', None)))
        kept = vault_extensions.extract_typed_field(vault.TypedField.new_field('text', 'v', 'MyLabel'))
        self.assertEqual(kept.get('label'), 'MyLabel')

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

    def test_shared_list_filters_by_roe_eligible(self):
        params = get_synced_params()
        cmd = record.RecordListSfCommand()

        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, roe_eligible=True)
            mock_print.assert_not_called()

        with mock.patch(
                'keepercommander.vault_extensions.shared_folder_has_pam_user_with_rotation',
                return_value=True):
            with mock.patch('builtins.print') as mock_print:
                cmd.execute(params, roe_eligible=True)
                mock_print.assert_called()

    def test_team_list_command(self):
        params = get_synced_params()
        cmd = record.RecordListTeamCommand()

        TestRecord.expected_commands.extend(['get_share_objects'])
        with mock.patch('builtins.print'):
            cmd.execute(params)
        self.assertTrue(len(TestRecord.expected_commands) == 0)

    def test_get_record_uid(self):
        params = get_synced_params()
        cmd = record.RecordGetUidCommand()

        record_uid = next(iter(params.subfolder_record_cache['']))
        with mock.patch('builtins.print'), mock.patch('keepercommander.api.get_record_shares'):
            cmd.execute(params, uid=record_uid)
            cmd.execute(params, format='json', uid=record_uid)

    def test_record_list_command_with_fields(self):
        params = get_synced_params()
        cmd = record.RecordListCommand()

        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, field=['title'], pattern='Record 3')
            printed_args = mock_print.call_args[0][0] if mock_print.call_args else ''
            self.assertIn('Record 3', printed_args)

        with mock.patch('builtins.print') as mock_print:
            cmd.execute(params, field=['title'], pattern='NonExistentRecordName')
            mock_print.assert_not_called()

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

    def test_get_rejects_shell_metacharacters_in_lookup_token(self):
        params = get_synced_params()
        cmd = record.RecordGetUidCommand()

        with self.assertRaises(CommandError) as context:
            cmd.execute(params, uid='x;cd $HOME && id > pwned_keeper_rce.txt;#"unclosed')
        self.assertIn('forbidden characters', context.exception.message)

    def test_append_notes_command(self):
        params = get_synced_params()
        cmd = record_edit.RecordAppendNotesCommand()

        # Fixture mixes legacy (Record 1) and typed login (Record 2) in root; append-notes
        # uses RecordUpdateCommand, which rejects legacy PasswordRecord.
        record_uid = None
        for uid in params.subfolder_record_cache['']:
            rec = vault.KeeperRecord.load(params, uid)
            if isinstance(rec, vault.TypedRecord):
                record_uid = uid
                break
        self.assertIsNotNone(record_uid)
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


    @staticmethod
    def communicate_rest_success(params, request, endpoint, **kwargs):
        if 'rs_type' in kwargs:
            rs = kwargs['rs_type']()
        else:
            rs = None

        _, _, command = endpoint.rpartition('/')

        cmd = TestRecord.expected_commands.pop(0)
        if cmd == command:
            return rs

        raise Exception()


class TestGetCommandMasking(TestCase):
    """Sensitive fields are masked in detail/fields output; --unmask reveals them."""

    def setUp(self):
        mock.patch('keepercommander.api.communicate').start()
        mock.patch('keepercommander.api.communicate_rest').start()

    def tearDown(self):
        mock.patch.stopall()

    def _printed(self, mock_print):
        return ' '.join(str(a) for call in mock_print.call_args_list for a in call[0])

    # ── Record.display() (v2 / v3-via-Record.load) ─────────────────────────

    def _v2_record(self, custom_fields):
        from keepercommander.record import Record
        r = Record(utils.generate_uid())
        r.title = 'Test'
        r.custom_fields = list(custom_fields)
        return r

    def test_detail_masks_secret_type(self):
        r = self._v2_record([{'type': 'secret', 'name': 'Token', 'value': 'top-secret'}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=False)
        out = self._printed(p)
        self.assertNotIn('top-secret', out)
        self.assertIn('********', out)

    def test_detail_unmask_reveals_secret(self):
        r = self._v2_record([{'type': 'secret', 'name': 'Token', 'value': 'top-secret'}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=True)
        self.assertIn('top-secret', self._printed(p))

    def test_detail_masks_pincode_type(self):
        r = self._v2_record([{'type': 'pinCode', 'name': 'PIN', 'value': '1234'}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=False)
        out = self._printed(p)
        self.assertNotIn('1234', out)
        self.assertIn('********', out)

    def test_detail_masks_v3_secret_prefix(self):
        # v3 with label: Record.load() encodes type in name as "secret:Label"
        r = self._v2_record([{'type': 'text', 'name': 'secret:Token', 'value': 'top-secret'}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=False)
        out = self._printed(p)
        self.assertNotIn('top-secret', out)
        self.assertIn('********', out)

    def test_detail_masks_v3_secret_no_label(self):
        # v3 without label: Record.load() stores just the type as the name, no colon
        r = self._v2_record([{'type': 'text', 'name': 'secret', 'value': 'top-secret'}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=False)
        out = self._printed(p)
        self.assertNotIn('top-secret', out)
        self.assertIn('********', out)

    def test_detail_masks_v3_pincode_no_label(self):
        r = self._v2_record([{'type': 'text', 'name': 'pinCode', 'value': '9999'}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=False)
        out = self._printed(p)
        self.assertNotIn('9999', out)
        self.assertIn('********', out)

    def test_detail_does_not_mask_text_field(self):
        r = self._v2_record([{'type': 'text', 'name': 'Note', 'value': 'public info'}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=False)
        self.assertIn('public info', self._printed(p))

    def test_detail_masks_security_question_answer_only(self):
        # v3 custom field: Record.load() stores type='text', name='securityQuestion', value=dict
        r = self._v2_record([{'type': 'text', 'name': 'securityQuestion',
                               'value': {'question': 'MyQuestion', 'answer': 'MyAnswer'}}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=False)
        out = self._printed(p)
        self.assertNotIn('MyAnswer', out)
        self.assertIn('MyQuestion', out)
        self.assertIn('********', out)

    def test_detail_unmask_reveals_security_question_answer(self):
        r = self._v2_record([{'type': 'text', 'name': 'securityQuestion',
                               'value': {'question': 'MyQuestion', 'answer': 'MyAnswer'}}])
        with mock.patch('builtins.print') as p:
            r.display(unmask=True)
        out = self._printed(p)
        self.assertIn('MyQuestion', out)
        self.assertIn('MyAnswer', out)
        self.assertNotIn('********', out)

    # ── RecordV3.display() ──────────────────────────────────────────────────

    def _v3_cache_entry(self, fields=None, custom=None):
        data = json.dumps({
            'type': 'login', 'title': 'Test',
            'fields': fields or [],
            'custom': custom or [],
        }).encode()
        return {'record_uid': utils.generate_uid(), 'data_unencrypted': data}

    def test_v3_detail_masks_json_field(self):
        from keepercommander.recordv3 import RecordV3
        rec = self._v3_cache_entry(
            fields=[{'type': 'json', 'label': 'Config', 'value': ['{"k":"v"}']}])
        with mock.patch('builtins.print') as p:
            RecordV3.display(rec, unmask=False, params=None)
        out = self._printed(p)
        self.assertNotIn('"k"', out)
        self.assertIn('********', out)

    def test_v3_detail_masks_security_question_answer(self):
        from keepercommander.recordv3 import RecordV3
        rec = self._v3_cache_entry(fields=[{
            'type': 'securityQuestion', 'label': 'SQ',
            'value': [{'question': 'Mothers maiden name', 'answer': 'Smith'}],
        }])
        with mock.patch('builtins.print') as p:
            RecordV3.display(rec, unmask=False, params=None)
        out = self._printed(p)
        self.assertNotIn('Smith', out)
        self.assertIn('********', out)
        self.assertIn('Mothers maiden name', out)

    def test_v3_detail_unmask_reveals_security_answer(self):
        from keepercommander.recordv3 import RecordV3
        rec = self._v3_cache_entry(fields=[{
            'type': 'securityQuestion', 'label': 'SQ',
            'value': [{'question': 'Mothers maiden name', 'answer': 'Smith'}],
        }])
        with mock.patch('builtins.print') as p:
            RecordV3.display(rec, unmask=True, params=None)
        self.assertIn('Smith', self._printed(p))

    # ── fields format ──────────────────────────────────────────────────────

    def _run_fields(self, custom_fields, unmask=False):
        from keepercommander.record import Record as LegacyRecord
        params = get_synced_params()
        r = LegacyRecord(utils.generate_uid())
        r.title = 'Test'
        r.custom_fields = list(custom_fields)
        params.record_cache[r.record_uid] = {'version': 2, 'shared': False}
        captured = []
        cmd = record.RecordGetUidCommand()
        with mock.patch('builtins.print', side_effect=captured.append), \
             mock.patch('keepercommander.api.get_record', return_value=r), \
             mock.patch('keepercommander.api.get_record_shares'), \
             mock.patch('keepercommander.api.get_share_admins_for_record', return_value=[]):
            cmd.execute(params, uid=r.record_uid, format='fields', unmask=unmask)
        return json.loads(captured[-1])

    def test_fields_includes_secret_custom_field_masked(self):
        fields = self._run_fields([{'type': 'secret', 'name': 'Token', 'value': 'top-secret'}])
        f = next((x for x in fields if x['name'] == 'Token'), None)
        self.assertIsNotNone(f)
        self.assertEqual(f['value'], '********')

    def test_fields_masks_v3_secret_no_label(self):
        # v3 custom secret without label: type='text', name='secret'
        fields = self._run_fields([{'type': 'text', 'name': 'secret', 'value': 'top-secret'}])
        f = next((x for x in fields if x['name'] == 'secret'), None)
        self.assertIsNotNone(f)
        self.assertEqual(f['value'], '********')

    def test_fields_masks_v3_pincode_no_label(self):
        fields = self._run_fields([{'type': 'text', 'name': 'pinCode', 'value': '9999'}])
        f = next((x for x in fields if x['name'] == 'pinCode'), None)
        self.assertIsNotNone(f)
        self.assertEqual(f['value'], '********')

    def test_fields_unmask_reveals_secret(self):
        fields = self._run_fields(
            [{'type': 'secret', 'name': 'Token', 'value': 'top-secret'}], unmask=True)
        f = next((x for x in fields if x['name'] == 'Token'), None)
        self.assertIsNotNone(f)
        self.assertEqual(f['value'], 'top-secret')

    def test_fields_excludes_empty_custom_fields(self):
        fields = self._run_fields([
            {'type': 'text', 'name': 'Empty', 'value': ''},
            {'type': 'text', 'name': 'Present', 'value': 'hello'},
        ])
        names = [x['name'] for x in fields]
        self.assertNotIn('Empty', names)
        self.assertIn('Present', names)

    def test_fields_security_question_masks_answer_only(self):
        fields = self._run_fields([{
            'type': 'securityQuestion', 'name': 'securityQuestion',
            'value': [{'question': 'MyQuestion', 'answer': 'MyAnswer'}],
        }])
        f = next((x for x in fields if x['name'] == 'securityQuestion'), None)
        self.assertIsNotNone(f)
        self.assertIsInstance(f['value'], dict)
        self.assertEqual(f['value']['question'], 'MyQuestion')
        self.assertEqual(f['value']['answer'], '********')

    def test_fields_security_question_unmask_reveals_answer(self):
        fields = self._run_fields([{
            'type': 'securityQuestion', 'name': 'securityQuestion',
            'value': [{'question': 'MyQuestion', 'answer': 'MyAnswer'}],
        }], unmask=True)
        f = next((x for x in fields if x['name'] == 'securityQuestion'), None)
        self.assertIsNotNone(f)
        self.assertIsInstance(f['value'], dict)
        self.assertEqual(f['value']['question'], 'MyQuestion')
        self.assertEqual(f['value']['answer'], 'MyAnswer')

