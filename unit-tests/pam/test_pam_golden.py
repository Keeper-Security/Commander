"""Golden tests — batch RecordAdd encrypted payload parity vs sequential create."""
from __future__ import annotations

import base64
import json
import unittest
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock, patch

from keepercommander import crypto, vault
from keepercommander.commands.pam_import.base import (
    ConnectionSettingsRDP,
    PamMachineObject,
    PamSettingsFieldData,
    PamUserObject,
    SFTPConnectionSettings,
)
from keepercommander.commands.pam_import.deferred_refs import (
    DeferredRefUpdate,
    _apply_deferrals_to_record,
    collect_connection_deferrals,
)
from keepercommander.commands.pam_import.pam_record_build import (
    _apply_pam_settings_fields,
    build_record_add_kwargs,
    pam_object_to_typed_record,
)
from keepercommander.commands.record_edit import RecordAddCommand
from keepercommander.record_management import add_record_to_folder
from keepercommander.recordv3 import RecordV3
from keepercommander.subfolder import UserFolderNode


MACH_UID = 'MMMMMMMMMMMMMMMMMMMMMA'
USER_UID = 'UUUUUUUUUUUUUUUUUUUUUA'
RES_UID = 'RRRRRRRRRRRRRRRRRRRRRA'
FOLDER_UID = 'FFFFFFFFFFFFFFFFFFFFFA'
FIXED_RECORD_KEY = b'\xab' * 32
FIXED_SEED_B64 = base64.b64encode(b'\xcd' * 32).decode()


def _make_params():
    params = MagicMock()
    params.data_key = b'\x01' * 32
    params.enterprise_ec_key = None
    params.record_cache = {}
    folder = UserFolderNode()
    folder.uid = FOLDER_UID
    folder.type = 'user_folder'
    params.folder_cache = {FOLDER_UID: folder}
    params.shared_folder_cache = {}
    return params


def _normalize_typed_record_data(record: vault.TypedRecord) -> str:
    from keepercommander import vault_extensions

    data = vault_extensions.extract_typed_record_data(record)
    return json.dumps(data, sort_keys=True)


def _decrypt_record_add_data(pb, record_key: bytes) -> str:
    plain = crypto.decrypt_aes_v2(pb.data, record_key)
    return json.dumps(json.loads(plain.decode('utf-8')), sort_keys=True)


def _pin_seed(record: vault.TypedRecord) -> None:
    field = record.get_typed_field('trafficEncryptionSeed')
    if field:
        field.value = [FIXED_SEED_B64]


def _get_rt_sample(params, record_type: str):
    cmd = RecordAddCommand()
    rt = cmd.get_record_type_fields(params, record_type)
    return rt


def _typed_record_from_add_kwargs(params, kwargs: Dict[str, Any]) -> vault.TypedRecord:
    """Build TypedRecord the way ``RecordAddCommand.execute`` does (no vault I/O)."""
    cmd = RecordAddCommand()
    record_type = kwargs['record_type']
    rt_fields = cmd.get_record_type_fields(params, record_type)
    if not rt_fields:
        raise ValueError(f'record type {record_type!r} unavailable')

    record_fields = []
    for field in kwargs.get('fields', []):
        parsed = cmd.parse_field(field.strip())
        if parsed.type != 'file':
            record_fields.append(parsed)

    record = vault.TypedRecord()
    record.type_name = record_type
    for rf in rt_fields:
        ref = rf.get('$ref')
        if not ref:
            continue
        label = rf.get('label') or ref
        default_value = rf.get('appFillerData') if ref == 'appFiller' else None
        field = vault.TypedField.new_field(ref, default_value, label)
        if rf.get('required'):
            field.required = True
        record.fields.append(field)
    cmd.assign_typed_fields(record, record_fields)

    record_uid = str(kwargs.get('record_uid', ''))
    if RecordV3.is_valid_ref_uid(record_uid):
        record.record_uid = record_uid
    record.title = kwargs.get('title') or ''
    record.notes = cmd.validate_notes(kwargs.get('notes') or '')
    return record


def _create_record_kwargs(obj, folder_uid: str) -> Dict[str, Any]:
    """Field list matching ``PamMachineObject.create_record`` / ``PamUserObject.create_record``."""
    if isinstance(obj, PamUserObject):
        args: Dict[str, Any] = {
            'force': True,
            'folder': folder_uid,
            'record_type': obj.type,
        }
        if obj.uid:
            args['record_uid'] = obj.uid
        if obj.title:
            args['title'] = obj.title
        if obj.notes:
            args['notes'] = obj.notes
        fields: List[str] = []
        if obj.login:
            fields.append(f'f.login={obj.login}')
        if obj.password:
            fields.append(f'f.password={obj.password}')
        if fields:
            args['fields'] = fields
        return args

    args = {
        'force': True,
        'folder': folder_uid,
        'record_type': obj.type,
    }
    if obj.uid:
        args['record_uid'] = obj.uid
    if obj.title:
        args['title'] = obj.title
    if obj.notes:
        args['notes'] = obj.notes

    fields = []
    hostname = obj.host.strip() if isinstance(getattr(obj, 'host', None), str) and obj.host.strip() else ''
    port = obj.port.strip() if isinstance(getattr(obj, 'port', None), str) and obj.port.strip() else ''
    if hostname or port:
        val = json.dumps({'hostName': hostname, 'port': port})
        fields.append(f'f.pamHostname=$JSON:{val}')

    ps = getattr(obj, 'pam_settings', None)
    if ps and isinstance(ps, PamSettingsFieldData):
        allow_supply = True if ps.allowSupplyHost is True else False
        port_forward = ps.portForward.to_record_dict() if ps.portForward else {}
        connection = ps.connection.to_record_dict() if ps.connection else {}
        if port_forward or connection or allow_supply:
            val = json.dumps({
                'allowSupplyHost': allow_supply,
                'portForward': port_forward or {},
                'connection': connection or {},
            })
            fields.append(f'c.pamSettings=$JSON:{val}')

    if fields:
        args['fields'] = fields
    return args


def _batch_record_add_pb(
    params,
    obj,
    *,
    inserted_uids: Set[str],
    deferred_out: Optional[list] = None,
    record_key: bytes = FIXED_RECORD_KEY,
):
    rt_sample = _get_rt_sample(params, obj.type)
    if not rt_sample:
        return None
    with patch(
        'keepercommander.commands.pam_import.pam_record_build.RecordEditAddCommand.get_record_type_fields',
        return_value=rt_sample,
    ), patch(
        'keepercommander.commands.pam_import.tunnel_setup.ensure_traffic_encryption_seed_on_typed_record',
    ) as seed_mock:
        record = pam_object_to_typed_record(
            params, obj, FOLDER_UID,
            record_key=record_key,
            inserted_uids=inserted_uids,
            deferred_out=deferred_out,
        )
        seed_mock.assert_called_once()
    _pin_seed(record)
    record.record_key = record_key
    return add_record_to_folder(params, record, FOLDER_UID, pb_only=True)


class TestPamSettingsFieldParity(unittest.TestCase):
    def test_build_record_add_kwargs_matches_create_record_fields(self):
        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach.title = 'batch-golden'
        mach.type = 'pamMachine'
        mach.host = 'host.example'
        mach.port = '3389'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsRDP(port='3389')
        conn.userRecordUid = [USER_UID]
        conn.sftp = SFTPConnectionSettings(enableSftp=True)
        conn.sftp.sftpResourceUid = RES_UID
        mach.pam_settings.connection = conn

        batch_kwargs = build_record_add_kwargs(mach, FOLDER_UID)
        _apply_pam_settings_fields(
            batch_kwargs, mach,
            inserted_uids={USER_UID, RES_UID},
            deferred_out=None,
        )
        seq_kwargs = _create_record_kwargs(mach, FOLDER_UID)

        batch_pam = next(f for f in batch_kwargs['fields'] if f.startswith('c.pamSettings'))
        seq_pam = next(f for f in seq_kwargs['fields'] if f.startswith('c.pamSettings'))
        self.assertEqual(batch_pam, seq_pam)


class TestRecordAddEncryptedGolden(unittest.TestCase):
    def _assert_encrypted_parity(self, params, obj, inserted_uids: Set[str]):
        rt_sample = _get_rt_sample(params, obj.type)
        if not rt_sample:
            self.skipTest(f'{obj.type} record type not available in test env')

        batch_pb = _batch_record_add_pb(params, obj, inserted_uids=inserted_uids)
        self.assertIsNotNone(batch_pb)

        seq_kwargs = _create_record_kwargs(obj, FOLDER_UID)
        if isinstance(obj, PamMachineObject):
            batch_kwargs = build_record_add_kwargs(obj, FOLDER_UID)
            _apply_pam_settings_fields(
                batch_kwargs, obj,
                inserted_uids=inserted_uids,
                deferred_out=None,
            )
            seq_kwargs = batch_kwargs

        seq_record = _typed_record_from_add_kwargs(params, seq_kwargs)
        _pin_seed(seq_record)
        seq_record.record_key = FIXED_RECORD_KEY
        seq_pb = add_record_to_folder(params, seq_record, FOLDER_UID, pb_only=True)

        batch_json = _decrypt_record_add_data(batch_pb, FIXED_RECORD_KEY)
        seq_json = _decrypt_record_add_data(seq_pb, FIXED_RECORD_KEY)
        self.assertEqual(batch_json, seq_json)

    def test_pam_machine_immediate_create_encrypted_parity(self):
        params = _make_params()
        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach.title = 'golden-mach'
        mach.type = 'pamMachine'
        mach.host = '10.0.0.1'
        mach.port = '3389'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsRDP(port='3389')
        conn.userRecordUid = [USER_UID]
        mach.pam_settings.connection = conn
        self._assert_encrypted_parity(params, mach, {USER_UID})

    def test_pam_user_immediate_create_encrypted_parity(self):
        params = _make_params()
        user = PamUserObject()
        user.uid = USER_UID
        user.title = 'golden-user'
        user.type = 'pamUser'
        user.login = 'admin'
        user.password = 'secret'
        self._assert_encrypted_parity(params, user, set())

    def test_strip_plus_1b_matches_immediate_encrypted_payload(self):
        params = _make_params()
        mach = PamMachineObject()
        mach.uid = MACH_UID
        mach.title = 'deferred-golden'
        mach.type = 'pamMachine'
        mach.host = '10.0.0.2'
        mach.port = '3389'
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsRDP(port='3389')
        conn.userRecordUid = [USER_UID]
        conn.sftp = SFTPConnectionSettings(enableSftp=True)
        conn.sftp.sftpResourceUid = RES_UID
        mach.pam_settings.connection = conn

        rt_sample = _get_rt_sample(params, 'pamMachine')
        if not rt_sample:
            self.skipTest('pamMachine record type not available in test env')

        deferred: list = []
        with patch(
            'keepercommander.commands.pam_import.pam_record_build.RecordEditAddCommand.get_record_type_fields',
            return_value=rt_sample,
        ), patch(
            'keepercommander.commands.pam_import.tunnel_setup.ensure_traffic_encryption_seed_on_typed_record',
        ):
            stripped = pam_object_to_typed_record(
                params, mach, FOLDER_UID,
                record_key=FIXED_RECORD_KEY,
                inserted_uids=set(),
                deferred_out=deferred,
            )
        _apply_deferrals_to_record(stripped, deferred)
        _pin_seed(stripped)
        stripped.record_key = FIXED_RECORD_KEY
        stripped_pb = add_record_to_folder(params, stripped, FOLDER_UID, pb_only=True)

        immediate_pb = _batch_record_add_pb(
            params, mach, inserted_uids={USER_UID, RES_UID},
        )
        self.assertIsNotNone(immediate_pb)

        self.assertEqual(
            _decrypt_record_add_data(stripped_pb, FIXED_RECORD_KEY),
            _decrypt_record_add_data(immediate_pb, FIXED_RECORD_KEY),
        )


class TestSetterWrapperParity(unittest.TestCase):
    def test_setters_match_object_side_to_record_dict(self):
        from keepercommander.commands.pam_import.base import set_sftp_uid
        from keepercommander.commands.pam_import.deferred_refs import (
            apply_http_credentials_uid_to_settings,
            apply_sftp_resource_uid_to_settings,
            apply_sftp_user_uid_to_settings,
            apply_user_records_to_settings,
        )

        mach = PamMachineObject()
        mach.pam_settings = PamSettingsFieldData()
        conn = ConnectionSettingsRDP(port='3389')
        conn.sftp = SFTPConnectionSettings(enableSftp=True)
        conn.userRecordUid = [USER_UID]
        mach.pam_settings.connection = conn
        set_sftp_uid(mach, 'sftpResourceUid', RES_UID)
        set_sftp_uid(mach, 'sftpUserUid', USER_UID)
        expected_conn = conn.to_record_dict()

        settings_root = {'allowSupplyHost': False, 'portForward': {}, 'connection': {}}
        apply_user_records_to_settings(settings_root, [USER_UID])
        apply_sftp_resource_uid_to_settings(settings_root, RES_UID)
        apply_sftp_user_uid_to_settings(settings_root, USER_UID)
        patched = settings_root['connection']
        self.assertEqual(patched.get('userRecords'), expected_conn.get('userRecords'))
        self.assertEqual(
            patched.get('sftp', {}).get('sftpResourceUid'),
            expected_conn.get('sftp', {}).get('sftpResourceUid'),
        )
        self.assertEqual(
            patched.get('sftp', {}).get('sftpUserUid'),
            expected_conn.get('sftp', {}).get('sftpUserUid'),
        )

        http_root = {'connection': {}}
        apply_http_credentials_uid_to_settings(http_root, USER_UID)
        self.assertEqual(http_root['connection']['httpCredentialsUid'], USER_UID)

    def test_collect_and_apply_round_trip_via_setters(self):
        full = {
            'protocol': 'rdp',
            'userRecords': [USER_UID],
            'sftp': {'enableSftp': True, 'sftpResourceUid': RES_UID},
        }
        deferred: list = []
        stripped = collect_connection_deferrals(
            MACH_UID, 'pamSettings', full, inserted_uids=set(), deferred=deferred,
        )
        record = vault.TypedRecord()
        record.type_name = 'pamMachine'
        record.custom.append(vault.TypedField.new_field(
            'pamSettings',
            [{'allowSupplyHost': False, 'portForward': {}, 'connection': stripped}],
            '',
        ))
        _apply_deferrals_to_record(record, deferred)
        conn = record.get_typed_field('pamSettings').value[0]['connection']
        self.assertEqual(conn.get('userRecords'), [USER_UID])
        self.assertEqual(conn['sftp'].get('sftpResourceUid'), RES_UID)


if __name__ == '__main__':
    unittest.main()
