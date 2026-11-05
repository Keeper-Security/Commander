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
