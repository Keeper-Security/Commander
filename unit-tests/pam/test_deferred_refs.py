"""Tests for Step 1b deferred embedded-ref updates."""
import copy
import json
import unittest
from unittest.mock import MagicMock, patch

from keepercommander import vault
from keepercommander.commands.pam_import.base import (
    ConnectionSettingsRDP,
    ConnectionSettingsSSH,
    PamMachineObject,
    PamSettingsFieldData,
    PamUserObject,
    SFTPConnectionSettings,
)
from keepercommander.commands.pam_import.batch_pipeline import (
    BatchPamImportEngine,
    CreationTier,
)
from keepercommander.commands.pam_import.deferred_refs import (
    DeferredRefApplySummary,
    DeferredRefUpdate,
    _apply_deferrals_to_record,
    apply_deferred_ref_updates,
    collect_connection_deferrals,
    plan_deferred_refs_for_tiers,
)
from keepercommander.commands.pam_import.pam_record_build import pam_object_to_typed_record
from keepercommander import utils
from keepercommander.proto import record_pb2


MACH_UID = 'MMMMMMMMMMMMMMMMMMMMMA'
USER_UID = 'UUUUUUUUUUUUUUUUUUUUUA'
RES_UID = 'RRRRRRRRRRRRRRRRRRRRRA'
DIR_UID = 'DDDDDDDDDDDDDDDDDDDDDA'


def _pam_settings_connection(record: vault.TypedRecord) -> dict:
    field = record.get_typed_field('pamSettings')
    return field.value[0].get('connection', {})


def _rebuild_connection_via_1b(stripped: dict, deferred: list) -> dict:
    record = vault.TypedRecord()
    record.type_name = 'pamMachine'
    record.custom.append(vault.TypedField.new_field(
        'pamSettings',
        [{'allowSupplyHost': False, 'portForward': {}, 'connection': copy.deepcopy(stripped)}],
        '',
    ))
    _apply_deferrals_to_record(record, deferred)
    return record.get_typed_field('pamSettings').value[0]['connection']


class TestCollectConnectionDeferrals(unittest.TestCase):
    def test_user_records_deferred_when_target_missing(self):
        deferred = []
        conn = {'userRecords': [USER_UID]}
        stripped = collect_connection_deferrals(
            MACH_UID, 'pamSettings', conn, inserted_uids=set(), deferred=deferred,
        )
        self.assertNotIn('userRecords', stripped)
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0].json_path, ('connection', 'userRecords'))
        self.assertEqual(deferred[0].value, [USER_UID])

    def test_user_records_kept_when_target_present(self):
        deferred = []
        conn = {'userRecords': [USER_UID]}
        stripped = collect_connection_deferrals(
            MACH_UID, 'pamSettings', conn, inserted_uids={USER_UID}, deferred=deferred,
        )
        self.assertEqual(stripped.get('userRecords'), [USER_UID])
        self.assertEqual(deferred, [])

    def test_sftp_resource_uid_deferred(self):
        deferred = []
        conn = {'sftp': {'sftpResourceUid': RES_UID}}
        stripped = collect_connection_deferrals(
            MACH_UID, 'pamSettings', conn, inserted_uids=set(), deferred=deferred,
        )
        self.assertNotIn('sftpResourceUid', stripped.get('sftp', {}))
        self.assertEqual(deferred[0].json_path, ('connection', 'sftp', 'sftpResourceUid'))


class TestApplyDeferralsToRecord(unittest.TestCase):
    def test_patch_pam_settings_blob(self):
        record = vault.TypedRecord()
        record.type_name = 'pamMachine'
        record.custom.append(vault.TypedField.new_field(
            'pamSettings',
            [{'allowSupplyHost': False, 'portForward': {}, 'connection': {}}],
            '',
        ))
        items = [
            DeferredRefUpdate(
                record_uid='x',
                settings_field='pamSettings',
                json_path=('connection', 'userRecords'),
                value=[USER_UID],
            ),
        ]
        self.assertTrue(_apply_deferrals_to_record(record, items))
        field = record.get_typed_field('pamSettings')
        self.assertEqual(field.value[0]['connection']['userRecords'], [USER_UID])


class TestPlanDeferredRefsForTiers(unittest.TestCase):
    def test_same_tier_machine_before_user_queues_deferral(self):
        user = PamUserObject()
        user.uid = USER_UID
        user._extend_tag = 'new'
        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach._extend_tag = 'new'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsSSH(port='22')
        conn.userRecordUid = [USER_UID]
        mach.pam_settings.connection = conn
        tiers = [CreationTier('tier_resources', [mach, user])]
        deferred = plan_deferred_refs_for_tiers(tiers, set())
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0].record_uid, MACH_UID)
        self.assertEqual(deferred[0].json_path, ('connection', 'userRecords'))


class TestPamRecordBuildDeferrals(unittest.TestCase):
    def test_create_json_omits_deferred_ref(self):
        from keepercommander.commands.record_edit import RecordAddCommand

        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach.title = 'm1'
        mach.type = 'pamMachine'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsSSH(port='22')
        conn.userRecordUid = [USER_UID]
        mach.pam_settings.connection = conn
        rt_sample = RecordAddCommand().get_record_type_fields(MagicMock(), 'pamMachine')
        if not rt_sample:
            self.skipTest('pamMachine record type not available in test env')
        deferred = []
        with patch(
            'keepercommander.commands.pam_import.pam_record_build.RecordEditAddCommand.get_record_type_fields',
            return_value=rt_sample,
        ):
            record = pam_object_to_typed_record(
                MagicMock(), mach, 'folder-uid',
                inserted_uids=set(),
                deferred_out=deferred,
            )
        pam_field = record.get_typed_field('pamSettings')
        self.assertIsNotNone(pam_field)
        conn_json = pam_field.value[0].get('connection', {})
        self.assertNotIn('userRecords', conn_json)
        self.assertEqual(len(deferred), 1)


class TestSemanticParity(unittest.TestCase):
    """Strip-at-1a + patch-at-1b should match full connection JSON at create."""

    def test_user_records_and_sftp_resource_round_trip(self):
        full = {
            'protocol': 'rdp',
            'userRecords': [USER_UID],
            'sftp': {'enableSftp': True, 'sftpResourceUid': RES_UID},
        }
        deferred = []
        stripped = collect_connection_deferrals(
            MACH_UID, 'pamSettings', full, inserted_uids=set(), deferred=deferred,
        )
        rebuilt = _rebuild_connection_via_1b(stripped, deferred)
        self.assertEqual(rebuilt.get('userRecords'), full['userRecords'])
        self.assertEqual(rebuilt['sftp'].get('sftpResourceUid'), RES_UID)
        self.assertEqual(rebuilt['sftp'].get('enableSftp'), True)

    def test_pam_record_build_matches_sequential_json(self):
        from keepercommander.commands.record_edit import RecordAddCommand

        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach.title = 'm1'
        mach.type = 'pamMachine'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsRDP(port='3389')
        conn.userRecordUid = [USER_UID]
        conn.sftp = SFTPConnectionSettings(enableSftp=True)
        conn.sftp.sftpResourceUid = RES_UID
        mach.pam_settings.connection = conn
        full_conn = conn.to_record_dict()

        rt_sample = RecordAddCommand().get_record_type_fields(MagicMock(), 'pamMachine')
        if not rt_sample:
            self.skipTest('pamMachine record type not available in test env')

        deferred = []
        with patch(
            'keepercommander.commands.pam_import.pam_record_build.RecordEditAddCommand.get_record_type_fields',
            return_value=rt_sample,
        ):
            stripped_record = pam_object_to_typed_record(
                MagicMock(), mach, 'folder-uid',
                inserted_uids=set(),
                deferred_out=deferred,
            )
            immediate_record = pam_object_to_typed_record(
                MagicMock(), mach, 'folder-uid',
                inserted_uids={USER_UID, RES_UID},
                deferred_out=None,
            )

        stripped_conn = _pam_settings_connection(stripped_record)
        immediate_conn = _pam_settings_connection(immediate_record)
        rebuilt = _rebuild_connection_via_1b(stripped_conn, deferred)
        self.assertEqual(json.dumps(rebuilt, sort_keys=True), json.dumps(immediate_conn, sort_keys=True))
        self.assertEqual(json.dumps(rebuilt, sort_keys=True), json.dumps(full_conn, sort_keys=True))


class TestSftpCrossResourceDeferral(unittest.TestCase):
    def test_consumer_before_directory_resource_in_tier(self):
        consumer = PamMachineObject()
        consumer.uid = MACH_UID
        consumer._extend_tag = 'new'
        consumer.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsRDP(port='3389')
        conn.sftp = SFTPConnectionSettings(enableSftp=True)
        conn.sftp.sftpResourceUid = DIR_UID
        consumer.pam_settings.connection = conn

        directory = PamMachineObject()
        directory.uid = DIR_UID
        directory._extend_tag = 'new'

        tiers = [CreationTier('tier_resources', [consumer, directory])]
        deferred = plan_deferred_refs_for_tiers(tiers, set())
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0].json_path, ('connection', 'sftp', 'sftpResourceUid'))
        self.assertEqual(deferred[0].value, DIR_UID)


class TestUnresolvedRefWarnings(unittest.TestCase):
    def test_missing_target_skipped_not_failed(self):
        params = MagicMock()
        params.record_cache = {MACH_UID: {'record_uid': MACH_UID, 'version': 3}}
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
        with patch('keepercommander.commands.pam_import.deferred_refs.load_pam_record', return_value=record), \
             patch('keepercommander.commands.pam_import.deferred_refs.imp_exp.execute_records_update') as upd, \
             patch('keepercommander.commands.pam_import.deferred_refs.sync_down_after_batch') as sync:
            summary = apply_deferred_ref_updates(params, deferred)
            self.assertEqual(summary.failures, [])
            self.assertEqual(len(summary.warnings), 1)
            upd.assert_not_called()
            sync.assert_called_once()


class TestChannelADeferrals(unittest.TestCase):
    def test_strip_typed_record_ref_when_target_missing(self):
        record = vault.TypedRecord()
        record.record_uid = MACH_UID
        record.fields.append(vault.TypedField.new_field('recordRef', [USER_UID], 'creds'))
        deferred: list = []
        from keepercommander.commands.pam_import.deferred_refs import (
            DeferredChannelAUpdate,
            collect_channel_a_deferrals,
            extract_channel_a_refs,
        )
        collect_channel_a_deferrals(record, MACH_UID, set(), deferred)
        self.assertEqual(len(deferred), 1)
        self.assertIsInstance(deferred[0], DeferredChannelAUpdate)
        self.assertEqual(deferred[0].ref_uid, USER_UID)
        self.assertEqual(extract_channel_a_refs(record), set())

    def test_strip_script_record_ref_when_target_missing(self):
        record = vault.TypedRecord()
        record.record_uid = MACH_UID
        record.fields.append(vault.TypedField.new_field(
            'script',
            [{'fileRef': 'FILEUID1111111111111111', 'recordRef': [USER_UID], 'command': 'pwsh'}],
            'rotationScripts',
        ))
        deferred = []
        from keepercommander.commands.pam_import.deferred_refs import collect_channel_a_deferrals

        collect_channel_a_deferrals(record, MACH_UID, set(), deferred)
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0].field_type, 'script')
        script = record.fields[0].value[0]
        self.assertEqual(script.get('recordRef'), [])

    def test_apply_channel_a_adds_record_ref_and_links(self):
        from keepercommander.commands.pam_import.deferred_refs import (
            DeferredChannelAUpdate,
            _apply_channel_a_to_record,
            _build_typed_record_update_pb,
        )

        existing = vault.TypedRecord()
        existing.record_uid = MACH_UID
        existing.revision = 1
        existing.record_key = b'1' * 32
        record = vault.TypedRecord()
        record.record_uid = MACH_UID
        record.revision = 1
        record.record_key = b'1' * 32
        record.linked_keys = {USER_UID: b'2' * 32}
        items = [
            DeferredChannelAUpdate(
                record_uid=MACH_UID,
                ref_uid=USER_UID,
                field_type='recordRef',
                field_label='creds',
            ),
        ]
        self.assertTrue(_apply_channel_a_to_record(record, items))
        field = record.get_typed_field('recordRef')
        self.assertEqual(field.value, [USER_UID])
        params = MagicMock()
        params.enterprise_ec_key = None
        params.record_cache = {USER_UID: {'record_uid': USER_UID}}
        with patch('keepercommander.commands.pam_import.deferred_refs.vault.KeeperRecord.load') as load:
            target = vault.TypedRecord()
            target.record_key = b'2' * 32
            load.return_value = target
            pb = _build_typed_record_update_pb(params, record, existing)
        self.assertEqual(len(pb.record_links_add), 1)


class TestApplyDeferredRefUpdates(unittest.TestCase):
    def test_apply_batch_update_and_sync(self):
        params = MagicMock()
        params.record_cache = {
            MACH_UID: {'record_uid': MACH_UID, 'version': 3},
            USER_UID: {'record_uid': USER_UID, 'version': 3},
        }
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
        success_result = record_pb2.RecordModifyStatus()
        success_result.record_uid = utils.base64_url_decode(MACH_UID)
        success_result.status = record_pb2.RS_SUCCESS

        with patch('keepercommander.commands.pam_import.deferred_refs.load_pam_record', return_value=record), \
             patch('keepercommander.commands.pam_import.deferred_refs.imp_exp.execute_records_update', return_value=[success_result]) as upd, \
             patch('keepercommander.commands.pam_import.deferred_refs.sync_down_after_batch') as sync:
            summary = apply_deferred_ref_updates(params, deferred)
            self.assertEqual(summary.failures, [])
            upd.assert_called_once()
            sync.assert_called_once()

    def test_apply_channel_a_batch_update(self):
        from keepercommander.commands.pam_import.deferred_refs import DeferredChannelAUpdate

        params = MagicMock()
        params.record_cache = {
            MACH_UID: {'record_uid': MACH_UID, 'version': 3},
            USER_UID: {'record_uid': USER_UID, 'version': 3},
        }
        params.enterprise_ec_key = None
        record = vault.TypedRecord()
        record.record_uid = MACH_UID
        record.revision = 1
        record.record_key = b'0' * 32
        record.type_name = 'pamUser'
        deferred_links = [
            DeferredChannelAUpdate(
                record_uid=MACH_UID,
                ref_uid=USER_UID,
                field_type='recordRef',
                field_label='creds',
            ),
        ]
        success_result = record_pb2.RecordModifyStatus()
        success_result.record_uid = utils.base64_url_decode(MACH_UID)
        success_result.status = record_pb2.RS_SUCCESS
        record_keys = {MACH_UID: b'0' * 32, USER_UID: b'1' * 32}

        with patch('keepercommander.commands.pam_import.deferred_refs.load_pam_record', return_value=record), \
             patch('keepercommander.commands.pam_import.deferred_refs.imp_exp.execute_records_update', return_value=[success_result]) as upd, \
             patch('keepercommander.commands.pam_import.deferred_refs.sync_down_after_batch') as sync:
            summary = apply_deferred_ref_updates(
                params, [], deferred_links, record_keys=record_keys,
            )
            self.assertEqual(summary.failures, [])
            upd.assert_called_once()
            sync.assert_called_once()


if __name__ == '__main__':
    unittest.main()
