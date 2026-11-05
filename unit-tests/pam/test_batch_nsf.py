"""NSF batch Step 1a / 1b / sync helpers."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import utils, vault
from keepercommander.commands.pam_import.batch_nsf import (
    execute_nsf_records_add_with_retry,
    execute_nsf_records_update_with_retry,
    project_uses_nsf,
    sync_down_after_batch,
    typed_record_to_nsf_record_add,
)
from keepercommander.commands.pam_import.batch_pipeline import BatchPamImportEngine
from keepercommander.commands.pam_import.base import PamUserObject
from keepercommander.commands.pam_import.deferred_refs import (
    DeferredRefUpdate,
    apply_deferred_ref_updates,
)
from keepercommander.proto import record_pb2
from keepercommander.subfolder import NestedShareFolderNode


USER_UID = 'UUUUUUUUUUUUUUUUUUUUUA'
MACH_UID = 'MMMMMMMMMMMMMMMMMMMMMA'
NSF_FOLDER = 'NSFFolderUID1111111111A'


class TestProjectUsesNsf(unittest.TestCase):
    def test_option_flag(self):
        params = MagicMock()
        params.nested_share_folders = {}
        self.assertTrue(project_uses_nsf(params, {'options': {'use_nsf': True}}))
        self.assertFalse(project_uses_nsf(params, {'options': {'use_nsf': False}}))

    def test_existing_nsf_folders(self):
        params = MagicMock()
        params.nested_share_folders = {NSF_FOLDER: {'name': 'Users'}}
        self.assertTrue(project_uses_nsf(params, {'options': {}}))


class TestSyncDownAfterBatch(unittest.TestCase):
    def test_classic_sync(self):
        params = MagicMock()
        params.nested_share_folders = {}
        with patch('keepercommander.api.sync_down') as sync, \
             patch(
                 'keepercommander.commands.pam_import.nsf_helpers.sync_down_preserving_nsf_keys',
             ) as nsf_sync:
            sync_down_after_batch(params, {'options': {'use_nsf': False}})
            sync.assert_called_once_with(params)
            nsf_sync.assert_not_called()

    def test_nsf_preserving_sync(self):
        params = MagicMock()
        params.nested_share_folders = {NSF_FOLDER: {}}
        with patch(
            'keepercommander.commands.pam_import.nsf_helpers.sync_down_preserving_nsf_keys',
        ) as nsf_sync, patch('keepercommander.api.sync_down') as sync:
            sync_down_after_batch(params)
            nsf_sync.assert_called_once_with(params)
            sync.assert_not_called()


class TestTypedRecordToNsfRecordAdd(unittest.TestCase):
    def test_builds_v3_add_with_folder_key_wrap(self):
        params = MagicMock()
        params.data_key = b'd' * 32
        params.enterprise_ec_key = None
        params.nested_share_folders = {
            NSF_FOLDER: {'folder_key_unencrypted': b'f' * 32, 'name': 'Users'},
        }
        record = vault.TypedRecord()
        record.record_uid = USER_UID
        record.record_key = b'r' * 32
        record.title = 'admin'
        record.type_name = 'pamUser'

        pb = typed_record_to_nsf_record_add(params, record, NSF_FOLDER)
        self.assertEqual(utils.base64_url_encode(pb.recordUid), USER_UID)
        self.assertEqual(utils.base64_url_encode(pb.folderUid), NSF_FOLDER)
        self.assertTrue(pb.recordKey)
        self.assertTrue(pb.data)


class TestExecuteTierUseNsfPath(unittest.TestCase):
    def test_tier_1a_routes_nsf_folder_to_v3_add(self):
        params = MagicMock()
        params.record_cache = {}
        params.nested_share_folders = {
            NSF_FOLDER: {'folder_key_unencrypted': b'f' * 32, 'name': 'Users'},
        }
        params.folder_cache = {}
        node = NestedShareFolderNode()
        node.uid = NSF_FOLDER
        node.name = 'Users'
        params.folder_cache[NSF_FOLDER] = node
        params.data_key = b'd' * 32
        params.enterprise_ec_key = None
        params.record_type_cache = {}

        user = PamUserObject()
        user.uid = USER_UID
        user.title = 'admin'
        user.login = 'admin'
        user.password = 'secret'
        user.resolved_folder_uid = NSF_FOLDER

        eng = BatchPamImportEngine(
            params, {'options': {'use_nsf': True}}, [user], [],
            users_folder_uid=NSF_FOLDER,
            resources_folder_uid=NSF_FOLDER,
            pam_cfg_uid='cfg',
        )
        eng.record_keys[USER_UID] = b'r' * 32

        success = record_pb2.RecordModifyStatus()
        success.record_uid = utils.base64_url_decode(USER_UID)
        success.status = record_pb2.RS_SUCCESS

        with patch(
            'keepercommander.commands.pam_import.batch_pipeline.pam_object_to_typed_record',
        ) as to_rec, \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.typed_record_to_nsf_record_add',
             ) as to_nsf, \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.execute_nsf_records_add_with_retry',
                 return_value=[success],
             ) as nsf_add, \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.execute_records_add_with_retry',
             ) as classic_add, \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.add_record_to_folder',
             ) as classic_pb, \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.sync_down_after_batch',
             ) as sync, \
             patch(
                 'keepercommander.commands.pam_import.batch_pipeline.is_nested_share_folder',
                 return_value=True,
             ):
            typed = vault.TypedRecord()
            typed.record_uid = USER_UID
            typed.record_key = b'r' * 32
            to_rec.return_value = typed
            to_nsf.return_value = MagicMock()

            from keepercommander.commands.pam_import.batch_pipeline import CreationTier
            ok = eng._execute_tier_1a(
                CreationTier(name='tier0_global_users', objects=[user]),
                inserted_uids=set(),
            )
            self.assertTrue(ok)
            nsf_add.assert_called_once()
            classic_add.assert_not_called()
            classic_pb.assert_not_called()
            sync.assert_called_once()
            self.assertEqual(user._batch_vault_status, 'created')


class TestNsfDeferredRefUpdates(unittest.TestCase):
    def test_nsf_record_uses_v3_update(self):
        params = MagicMock()
        params.record_cache = {}
        params.nested_share_records = {MACH_UID: {'version': 3}}
        params.nested_share_record_data = {}
        params.enterprise_ec_key = None
        record = vault.TypedRecord()
        record.record_uid = MACH_UID
        record.revision = 1
        record.record_key = b'0' * 32
        record.type_name = 'pamMachine'
        record.custom.append(vault.TypedField.new_field(
            'pamSettings',
            [{'allowSupplyHost': False, 'portForward': {}, 'connection': {}}],
            '',
        ))
        deferred = [
            DeferredRefUpdate(
                record_uid=MACH_UID,
                settings_field='pamSettings',
                json_path=('connection', 'userRecords'),
                value=[USER_UID],
            ),
        ]
        params.nested_share_records[USER_UID] = {'version': 3}
        success = record_pb2.RecordModifyStatus()
        success.record_uid = utils.base64_url_decode(MACH_UID)
        success.status = record_pb2.RS_SUCCESS

        with patch(
            'keepercommander.commands.pam_import.deferred_refs.load_pam_record',
            return_value=record,
        ), patch(
            'keepercommander.commands.pam_import.deferred_refs.is_pam_nsf_record',
            return_value=True,
        ), patch(
            'keepercommander.commands.pam_import.deferred_refs.execute_nsf_records_update_with_retry',
            return_value=[success],
        ) as nsf_upd, patch(
            'keepercommander.commands.pam_import.deferred_refs.execute_records_update_with_retry',
        ) as classic_upd, patch(
            'keepercommander.commands.pam_import.deferred_refs.sync_down_after_batch',
        ) as sync:
            summary = apply_deferred_ref_updates(params, deferred)
            self.assertEqual(summary.failures, [])
            nsf_upd.assert_called_once()
            classic_upd.assert_not_called()
            sync.assert_called_once()


class TestExecuteNsfHelpersChunking(unittest.TestCase):
    def test_add_chunks_and_reports(self):
        params = MagicMock()
        params.rest_context = None
        rs = MagicMock()
        rs.records = [MagicMock()]
        with patch(
            'keepercommander.commands.pam_import.batch_nsf.record_add_v3',
            return_value=rs,
        ) as add, patch(
            'keepercommander.commands.pam_import.batch_nsf.report_statuses',
            create=True,
        ):
            with patch(
                'keepercommander.importer.imp_exp.report_statuses',
            ), patch(
                'keepercommander.importer.imp_exp.record_status_to_str',
                return_value='success',
            ):
                ticks = []
                out = execute_nsf_records_add_with_retry(
                    params, [MagicMock()],
                    status_type=None,
                    on_chunk=lambda n: ticks.append(n),
                )
                self.assertEqual(len(out), 1)
                self.assertEqual(ticks, [1])
                add.assert_called_once()

    def test_update_chunks(self):
        params = MagicMock()
        params.rest_context = None
        rs = MagicMock()
        rs.records = [MagicMock()]
        with patch(
            'keepercommander.commands.pam_import.batch_nsf.record_update_v3',
            return_value=rs,
        ) as upd, patch(
            'keepercommander.importer.imp_exp.report_statuses',
        ), patch(
            'keepercommander.importer.imp_exp.record_status_to_str',
            return_value='success',
        ):
            out = execute_nsf_records_update_with_retry(
                params, [record_pb2.RecordUpdate()], status_type=None,
            )
            self.assertEqual(len(out), 1)
            upd.assert_called_once()


if __name__ == '__main__':
    unittest.main()
