"""Tests for Step 1c batched attachments (files_add + parallel PUTs + records_update)."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import utils
from keepercommander import vault
from keepercommander.commands.pam_import.base import (
    PamAttachmentObject,
    PamAttachmentsObject,
    PamMachineObject,
    PamScriptObject,
    PamScriptsObject,
)
from keepercommander.commands.pam_import.batch_attachments import (
    BatchAttachmentSummary,
    PendingUpload,
    _apply_uploads_to_record,
    collect_config_script_uploads,
    collect_pending_uploads,
    execute_batch_attachments,
    run_import_tail_config_scripts,
)
from keepercommander.proto import record_pb2


PARENT_UID = 'PPPPPPPPPPPPPPPPPPPPPA'
FILE_UID = 'FFFFFFFFFFFFFFFFFFFFFA'


def _write_temp_file(content: bytes = b'hello') -> str:
    fd, path = tempfile.mkstemp()
    os.close(fd)
    with open(path, 'wb') as fh:
        fh.write(content)
    return path


class TestCollectPendingUploads(unittest.TestCase):
    def test_collects_attachment_and_script(self):
        att_path = _write_temp_file(b'att-data')
        script_path = _write_temp_file(b'script-data')
        try:
            mach = PamMachineObject()
            mach.uid = PARENT_UID
            att = PamAttachmentObject()
            att.file = att_path
            mach.attachments = PamAttachmentsObject()
            mach.attachments.attachments = [att]
            script = PamScriptObject()
            script.file = script_path
            script.script_command = 'pwsh.exe'
            mach.scripts = PamScriptsObject()
            mach.scripts.scripts = [script]

            pending = collect_pending_uploads(mach)
            self.assertEqual(len(pending), 2)
            kinds = {p.kind for p in pending}
            self.assertEqual(kinds, {'attachment', 'script'})
            self.assertTrue(all(p.parent_uid == PARENT_UID for p in pending))
        finally:
            os.unlink(att_path)
            os.unlink(script_path)

    def test_skips_missing_files(self):
        mach = PamMachineObject()
        mach.uid = PARENT_UID
        att = PamAttachmentObject()
        att.file = '/nonexistent/file.bin'
        mach.attachments = PamAttachmentsObject()
        mach.attachments.attachments = [att]
        self.assertEqual(collect_pending_uploads(mach), [])


class TestCollectConfigScriptUploads(unittest.TestCase):
    def test_includes_only_scripts_with_record_refs(self):
        script_path = _write_temp_file(b'cred-script')
        no_cred_path = _write_temp_file(b'plain-script')
        try:
            with_refs = PamScriptObject()
            with_refs.file = script_path
            with_refs.record_refs = ['UUUUUUUUUUUUUUUUUUUUUA']
            with_refs.script_command = 'run.ps1'
            without_refs = PamScriptObject()
            without_refs.file = no_cred_path

            pending = collect_config_script_uploads(PARENT_UID, [with_refs, without_refs])
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].parent_uid, PARENT_UID)
            self.assertEqual(pending[0].kind, 'script')
            self.assertEqual(pending[0].script, with_refs)
        finally:
            os.unlink(script_path)
            os.unlink(no_cred_path)

    def test_run_import_tail_delegates_to_execute_batch(self):
        script_path = _write_temp_file(b'tail-script')
        try:
            script = PamScriptObject()
            script.file = script_path
            script.record_refs = ['UUUUUUUUUUUUUUUUUUUUUA']
            params = MagicMock()
            expected = BatchAttachmentSummary(uploaded_count=1)
            with patch(
                'keepercommander.commands.pam_import.batch_attachments.execute_batch_attachments',
                return_value=expected,
            ) as exec_batch:
                summary = run_import_tail_config_scripts(params, PARENT_UID, [script])
            self.assertIs(summary, expected)
            exec_batch.assert_called_once()
            pending_arg = exec_batch.call_args[0][1]
            self.assertEqual(len(pending_arg), 1)
            self.assertEqual(pending_arg[0].parent_uid, PARENT_UID)
        finally:
            os.unlink(script_path)


class TestApplyUploadsToRecord(unittest.TestCase):
    def test_patches_file_ref_and_script_fields(self):
        from keepercommander.commands.pam_import.batch_attachments import (
            PendingUpload,
            _UploadSuccess,
        )

        record = vault.TypedRecord()
        record.type_name = 'pamMachine'
        script = PamScriptObject()
        script.script_command = 'run.ps1'
        script.record_refs = ['UUUUUUUUUUUUUUUUUUUUUA']
        uploads = [
            _UploadSuccess(
                PendingUpload(PARENT_UID, '/a', 'a.bin', 5, 'attachment'),
                FILE_UID,
                b'\x00' * 32,
            ),
            _UploadSuccess(
                PendingUpload(PARENT_UID, '/b', 'b.ps1', 10, 'script', script=script),
                'SSSSSSSSSSSSSSSSSSSSSA',
                b'\x01' * 32,
            ),
        ]
        _apply_uploads_to_record(record, uploads)
        file_ref = record.get_typed_field('fileRef')
        self.assertIsNotNone(file_ref)
        self.assertEqual(file_ref.value, [FILE_UID])
        script_field = next(f for f in record.fields if f.type == 'script')
        self.assertEqual(len(script_field.value), 1)
        entry = script_field.value[0]
        self.assertEqual(entry['fileRef'], 'SSSSSSSSSSSSSSSSSSSSSA')
        self.assertEqual(entry['command'], 'run.ps1')
        self.assertEqual(entry['recordRef'], ['UUUUUUUUUUUUUUUUUUUUUA'])


class TestReplaceUploads(unittest.TestCase):
    """`pam project update`: an upload that `replaces` a file record takes its place in the record."""

    def _upload(self, kind, old, uid='NNNNNNNNNNNNNNNNNNNNNA', script=None):
        from keepercommander.commands.pam_import.batch_attachments import _UploadSuccess
        return _UploadSuccess(PendingUpload(PARENT_UID, '/a', 'a', 5, kind, script=script, replaces=old), uid, b'\x01' * 32)

    def test_an_attachment_takes_the_position_of_the_old_file(self):
        record = vault.TypedRecord()
        record.fields.append(vault.TypedField.new_field('fileRef', ['AAA', 'OLD', 'CCC'], ''))
        _apply_uploads_to_record(record, [self._upload('attachment', 'OLD')])
        self.assertEqual(record.get_typed_field('fileRef').value, ['AAA', 'NNNNNNNNNNNNNNNNNNNNNA', 'CCC'])

    def test_an_attachment_in_the_custom_section_is_replaced_there(self):
        record = vault.TypedRecord()
        record.custom.append(vault.TypedField.new_field('fileRef', ['OLD'], 'fileRef'))
        _apply_uploads_to_record(record, [self._upload('attachment', 'OLD')])
        self.assertEqual(record.custom[0].value, ['NNNNNNNNNNNNNNNNNNNNNA'])
        self.assertEqual(record.fields, [])                                      # no second field is made

    def test_a_replace_whose_old_file_is_gone_appends(self):
        record = vault.TypedRecord()
        record.fields.append(vault.TypedField.new_field('fileRef', ['AAA'], ''))
        _apply_uploads_to_record(record, [self._upload('attachment', 'OLD')])
        self.assertEqual(record.get_typed_field('fileRef').value, ['AAA', 'NNNNNNNNNNNNNNNNNNNNNA'])

    def test_a_script_entry_is_swapped_in_place_with_the_command_of_the_json(self):
        record = vault.TypedRecord()
        record.fields.append(vault.TypedField.new_field('script', [
            {'fileRef': 'KEEP', 'recordRef': [], 'command': 'sh'},
            {'fileRef': 'OLD', 'recordRef': ['U0'], 'command': 'sh'}], 'rotationScripts'))
        script = PamScriptObject()
        script.script_command = 'bash'
        script.record_refs = ['U1']
        _apply_uploads_to_record(record, [self._upload('script', 'OLD', script=script)])
        value = next(f for f in record.fields if f.type == 'script').value
        self.assertEqual(value, [{'fileRef': 'KEEP', 'recordRef': [], 'command': 'sh'},
                                 {'fileRef': 'NNNNNNNNNNNNNNNNNNNNNA', 'recordRef': ['U1'], 'command': 'bash'}])


    def test_the_record_links_follow_the_swap(self):
        """The new file record is linked to the record (KSM reaches files through the links), the replaced one is unlinked."""
        import copy
        from keepercommander.commands.pam_import.deferred_refs import _build_typed_record_update_pb
        new_uid = 'NNNNNNNNNNNNNNNNNNNNNA'
        old_uid = 'OOOOOOOOOOOOOOOOOOOOOA'
        keep_uid = 'KKKKKKKKKKKKKKKKKKKKKA'
        existing = vault.TypedRecord()
        existing.record_uid = PARENT_UID
        existing.type_name = 'pamMachine'
        existing.record_key = b'\x07' * 32
        existing.revision = 3
        existing.fields.append(vault.TypedField.new_field('fileRef', [keep_uid, old_uid], ''))
        record = copy.deepcopy(existing)
        _apply_uploads_to_record(record, [self._upload('attachment', old_uid, uid=new_uid)])
        record.linked_keys = {new_uid: b'\x05' * 32}
        params = MagicMock()
        params.enterprise_ec_key = None
        pb = _build_typed_record_update_pb(params, record, existing)
        self.assertEqual([utils.base64_url_encode(l.record_uid) for l in pb.record_links_add], [new_uid])
        self.assertEqual([utils.base64_url_encode(u) for u in pb.record_links_remove], [old_uid])


class TestPartialRun(unittest.TestCase):
    """partial=True (update): the parent whose upload failed is left out, the others are patched."""

    def test_the_other_parent_is_still_patched(self):
        from keepercommander.commands.pam_import.batch_attachments import _UploadSuccess
        mod = 'keepercommander.commands.pam_import.batch_attachments.'
        other = 'OOOOOOOOOOOOOOOOOOOOOA'
        params = MagicMock()
        params.record_cache = {PARENT_UID: MagicMock(), other: MagicMock()}
        pending = [PendingUpload(PARENT_UID, '/tmp/a.bin', 'a.bin', 5, 'attachment'),
                   PendingUpload(other, '/tmp/b.bin', 'b.bin', 5, 'attachment')]
        existing = vault.TypedRecord()
        existing.record_uid = PARENT_UID
        existing.record_key = b'\x07' * 32
        ok = record_pb2.RecordModifyStatus()
        ok.record_uid = utils.base64_url_decode(PARENT_UID)
        ok.status = record_pb2.RS_SUCCESS
        built = []

        def fake_build(_params, record, _existing):
            built.append(record)
            return record_pb2.RecordUpdate()

        puts = ([_UploadSuccess(pending[0], FILE_UID, b'\x03' * 32)], [(other, 'PUT upload failed')])
        for partial, expect_built in ((True, 1), (False, 0)):
            del built[:]
            with patch(mod + '_files_add_chunk') as files_add, patch(mod + '_parallel_puts', return_value=puts), \
                    patch('keepercommander.vault.KeeperRecord.load', return_value=existing), \
                    patch(mod + '_build_typed_record_update_pb', side_effect=fake_build), \
                    patch(mod + 'execute_records_update_with_retry', return_value=[ok]), patch(mod + 'api.sync_down'):
                files_add.return_value = record_pb2.FilesAddResponse()
                summary = execute_batch_attachments(params, pending, partial=partial)
            self.assertEqual(summary.failures, [(other, 'PUT upload failed')])
            self.assertEqual(len(built), expect_built, partial)


class TestFilesAddIsScript(unittest.TestCase):
    """A rotation script file must be flagged is_script in files_add (as the sequential import does)."""

    def test_script_flagged_attachment_not(self):
        from keepercommander.commands.pam_import import batch_attachments as ba

        slots = [
            ba._UploadSlot(PendingUpload(PARENT_UID, '/a', 'a.bin', 5, 'attachment'), b'A' * 16, b'\x01' * 32),
            ba._UploadSlot(PendingUpload(PARENT_UID, '/b', 'b.sh', 7, 'script'), b'B' * 16, b'\x02' * 32),
        ]
        params = MagicMock()
        params.data_key = b'\x03' * 32
        sent = []

        def fake_communicate(_params, rq, endpoint, rs_type=None):
            sent.append((endpoint, rq))
            return rs_type()

        with patch.object(ba.api, 'communicate_rest', side_effect=fake_communicate), \
                patch.object(ba, 'rest_fail_on_throttle', return_value=False):
            ba._files_add_chunk(params, slots)

        self.assertEqual(len(sent), 1)
        endpoint, rq = sent[0]
        self.assertEqual(endpoint, 'vault/files_add')
        self.assertEqual([f.is_script for f in rq.files], [False, True])


class TestExecuteBatchAttachments(unittest.TestCase):
    def _mock_file_add_result(self, file_uid: bytes, status=record_pb2.FA_SUCCESS):
        fres = record_pb2.FileAddStatus()
        fres.record_uid = file_uid
        fres.status = status
        fres.url = 'https://upload.example/put'
        fres.parameters = '{"success_action_status": "201"}'
        fres.success_status_code = 201
        return fres

    def test_happy_path_batches_files_add_and_records_update(self):
        params = MagicMock()
        params.record_cache = {PARENT_UID: MagicMock()}
        params.data_key = b'\x00' * 32
        params.rest_context.proxies = {}
        params.rest_context.certificate_check = True

        pending = [
            PendingUpload(PARENT_UID, '/tmp/a.bin', 'a.bin', 5, 'attachment'),
        ]
        file_uid = b'\x02' * 16
        existing = vault.TypedRecord()
        existing.record_uid = PARENT_UID
        existing.type_name = 'pamMachine'

        with patch(
            'keepercommander.commands.pam_import.batch_attachments._files_add_chunk',
        ) as files_add, \
             patch(
                 'keepercommander.commands.pam_import.batch_attachments._parallel_puts',
             ) as parallel, \
             patch('keepercommander.vault.KeeperRecord.load', return_value=existing), \
             patch(
                 'keepercommander.commands.pam_import.batch_attachments._build_typed_record_update_pb',
                 return_value=record_pb2.RecordUpdate(),
             ) as build_pb, \
             patch(
                 'keepercommander.commands.pam_import.batch_attachments.imp_exp.execute_records_update',
             ) as exec_upd, \
             patch('keepercommander.commands.pam_import.batch_attachments.api.sync_down') as sync:
            files_add.return_value = record_pb2.FilesAddResponse(
                files=[self._mock_file_add_result(file_uid)],
            )
            from keepercommander.commands.pam_import.batch_attachments import _UploadSuccess
            parallel.return_value = ([
                _UploadSuccess(pending[0], FILE_UID, b'\x03' * 32),
            ], [])
            ok = record_pb2.RecordModifyStatus()
            ok.record_uid = utils.base64_url_decode(PARENT_UID)
            ok.status = record_pb2.RS_SUCCESS
            exec_upd.return_value = [ok]

            summary = execute_batch_attachments(params, pending)
            self.assertEqual(summary.uploaded_count, 1)
            self.assertEqual(summary.failures, [])
            files_add.assert_called_once()
            parallel.assert_called_once()
            build_pb.assert_called_once()
            exec_upd.assert_called_once()
            sync.assert_called_once()

    def test_every_uploaded_file_incl_a_script_is_linked_to_the_parent(self):
        """The script file is referenced only from the `script` field: its key must still reach record_links_add."""
        from keepercommander.commands.pam_import.batch_attachments import _UploadSuccess
        script_uid = 'SSSSSSSSSSSSSSSSSSSSSA'
        params = MagicMock()
        params.record_cache = {PARENT_UID: MagicMock()}
        params.data_key = b'\x00' * 32
        pending = [PendingUpload(PARENT_UID, '/tmp/a.bin', 'a.bin', 5, 'attachment'),
                   PendingUpload(PARENT_UID, '/tmp/run.sh', 'run.sh', 7, 'script', script=PamScriptObject())]
        existing = vault.TypedRecord()
        existing.record_uid = PARENT_UID
        existing.type_name = 'pamMachine'
        existing.record_key = b'\x07' * 32
        seen = {}

        def fake_build(_params, record, _existing):
            seen['linked'] = dict(record.linked_keys or {})
            seen['refs'] = vault_extensions.extract_typed_record_refs(record)
            return record_pb2.RecordUpdate()

        from keepercommander import vault_extensions
        ok = record_pb2.RecordModifyStatus()
        ok.record_uid = utils.base64_url_decode(PARENT_UID)
        ok.status = record_pb2.RS_SUCCESS
        with patch('keepercommander.commands.pam_import.batch_attachments._files_add_chunk') as files_add, \
                patch('keepercommander.commands.pam_import.batch_attachments._parallel_puts',
                      return_value=([_UploadSuccess(pending[0], FILE_UID, b'\x03' * 32),
                                     _UploadSuccess(pending[1], script_uid, b'\x04' * 32)], [])), \
                patch('keepercommander.vault.KeeperRecord.load', return_value=existing), \
                patch('keepercommander.commands.pam_import.batch_attachments._build_typed_record_update_pb',
                      side_effect=fake_build), \
                patch('keepercommander.commands.pam_import.batch_attachments.execute_records_update_with_retry',
                      return_value=[ok]), \
                patch('keepercommander.commands.pam_import.batch_attachments.api.sync_down'):
            files_add.return_value = record_pb2.FilesAddResponse()
            summary = execute_batch_attachments(params, pending)
        self.assertEqual(summary.failures, [])
        self.assertEqual(seen['linked'], {FILE_UID: b'\x03' * 32, script_uid: b'\x04' * 32})
        self.assertEqual(seen['refs'], {FILE_UID, script_uid})

    def test_a_parent_in_a_nested_share_folder_is_patched_through_the_nsf_update(self):
        """QA 2026-11-19: the classic records_update said "success" for an NSF parent and the files were not on the record."""
        from keepercommander.commands.pam_import.batch_attachments import _UploadSuccess
        mod = 'keepercommander.commands.pam_import.batch_attachments.'
        params = MagicMock()
        params.record_cache = {PARENT_UID: MagicMock()}
        pending = [PendingUpload(PARENT_UID, '/tmp/a.bin', 'a.bin', 5, 'attachment')]
        parent = vault.TypedRecord()
        parent.record_uid = PARENT_UID
        parent.type_name = 'pamMachine'
        parent.record_key = b'' * 32
        parent.revision = 5                                    # the stale classic copy
        seen = {}

        def fake_build(_params, record, existing):
            seen['revisions'] = (record.revision, existing.revision)
            return record_pb2.RecordUpdate()

        ok = record_pb2.RecordModifyStatus()
        ok.record_uid = utils.base64_url_decode(PARENT_UID)
        ok.status = record_pb2.RS_SUCCESS
        with patch(mod + '_files_add_chunk') as files_add,                 patch(mod + '_parallel_puts', return_value=([_UploadSuccess(pending[0], FILE_UID, b'' * 32)], [])),                 patch(mod + 'is_pam_nsf_record', return_value=True),                 patch(mod + 'refresh_stale_nsf_records') as refresh,                 patch(mod + 'load_pam_record', return_value=parent),                 patch('keepercommander.nested_share_folder.common.get_record_revision', return_value=99),                 patch(mod + '_build_typed_record_update_pb', side_effect=fake_build),                 patch(mod + 'execute_nsf_records_update_with_retry', return_value=[ok]) as nsf_update,                 patch(mod + 'execute_records_update_with_retry') as classic_update,                 patch(mod + 'sync_down_preserving_nsf_keys') as nsf_sync,                 patch(mod + 'api.sync_down') as plain_sync:
            files_add.return_value = record_pb2.FilesAddResponse()
            summary = execute_batch_attachments(params, pending)
        self.assertEqual(summary.failures, [])
        refresh.assert_called_once()                                   # the stale classic copy is refreshed first
        nsf_update.assert_called_once()
        classic_update.assert_not_called()
        self.assertEqual(seen['revisions'], (99, 99))                  # sent with the revision the server has
        nsf_sync.assert_called_once()
        plain_sync.assert_not_called()

    def test_put_failure_aborts_before_records_update(self):
        params = MagicMock()
        params.record_cache = {PARENT_UID: MagicMock()}
        pending = [PendingUpload(PARENT_UID, '/tmp/a.bin', 'a.bin', 5, 'attachment')]

        with patch(
            'keepercommander.commands.pam_import.batch_attachments._files_add_chunk',
        ) as files_add, \
             patch(
                 'keepercommander.commands.pam_import.batch_attachments._parallel_puts',
                 return_value=([], [(PARENT_UID, 'PUT upload failed')]),
             ), \
             patch(
                 'keepercommander.commands.pam_import.batch_attachments.imp_exp.execute_records_update',
             ) as exec_upd:
            files_add.return_value = record_pb2.FilesAddResponse(
                files=[self._mock_file_add_result(b'\x02' * 16)],
            )
            summary = execute_batch_attachments(params, pending)
            self.assertEqual(summary.failures, [(PARENT_UID, 'PUT upload failed')])
            exec_upd.assert_not_called()

    def test_parent_missing_from_cache_warns_and_skips(self):
        params = MagicMock()
        params.record_cache = {}
        pending = [PendingUpload(PARENT_UID, '/tmp/a.bin', 'a.bin', 5, 'attachment')]
        summary = execute_batch_attachments(params, pending)
        self.assertEqual(summary.uploaded_count, 0)
        self.assertEqual(len(summary.warnings), 1)


if __name__ == '__main__':
    unittest.main()
