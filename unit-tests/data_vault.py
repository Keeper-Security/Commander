import base64
import json
import os
from typing import List, Union, Optional, Dict
from unittest import mock

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA

from keepercommander import api, params, shared_folder, team, crypto, utils, vault, vault_extensions, record_facades
from keepercommander.proto import record_pb2, SyncDown_pb2

_USER_NAME = 'unit.test@company.com'
_USER_PASSWORD = base64.b64encode(os.urandom(8)).decode('utf-8').strip('=')
_USER_ITERATIONS = 1000
_USER_SALT = os.urandom(16)
_USER_DATA_KEY = utils.generate_aes_key()
_USER_ACCOUNT_UID = utils.generate_uid()

_SESSION_TOKEN = base64.urlsafe_b64encode(os.urandom(64)).decode('utf-8').strip('=')

_2FA_ONE_TIME_TOKEN = '123456'
_2FA_DEVICE_TOKEN = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').strip('=')

_private_key, _public_key = crypto.generate_rsa_key()

_DER_PRIVATE_KEY = crypto.unload_rsa_private_key(_private_key)
_ENCRYPTED_PRIVATE_KEY = utils.base64_url_encode(crypto.encrypt_aes_v1(_DER_PRIVATE_KEY, _USER_DATA_KEY))

_IMPORTED_PUBLIC_KEY = crypto.unload_rsa_public_key(_public_key)

_V2_DERIVED_KEY = crypto.derive_keyhash_v2('data_key', _USER_PASSWORD, _USER_SALT, _USER_ITERATIONS)
_dk = crypto.encrypt_aes_v2(_USER_DATA_KEY, _V2_DERIVED_KEY)
_ENCRYPTED_DATA_KEY = base64.urlsafe_b64encode(_dk).decode('utf-8').strip()

_V1_DERIVED_KEY = crypto.derive_keyhash_v1(_USER_PASSWORD, _USER_SALT, _USER_ITERATIONS)
_enc_iter = int.to_bytes(_USER_ITERATIONS, length=3, byteorder='big', signed=False)
_enc_iv = os.urandom(16)
_cipher = AES.new(_V1_DERIVED_KEY, AES.MODE_CBC, _enc_iv)
_enc_dk = b'\x01' + _enc_iter + _USER_SALT + _enc_iv + _cipher.encrypt(_USER_DATA_KEY + _USER_DATA_KEY)
_ENCRYPTION_PARAMS = base64.urlsafe_b64encode(_enc_dk).decode('utf-8').strip('=')


class VaultEnvironment:
    def __init__(self):
        self.user = _USER_NAME
        self.password = _USER_PASSWORD
        self.iterations = _USER_ITERATIONS
        self.salt = _USER_SALT
        self.data_key = _USER_DATA_KEY
        self.public_key = _public_key
        self.encoded_public_key = utils.base64_url_encode(_IMPORTED_PUBLIC_KEY)
        self.session_token = _SESSION_TOKEN
        self.one_time_token = _2FA_ONE_TIME_TOKEN
        self.device_token = _2FA_DEVICE_TOKEN
        self.encrypted_private_key = _ENCRYPTED_PRIVATE_KEY
        self.encrypted_data_key = _ENCRYPTED_DATA_KEY
        self.encryption_params = _ENCRYPTION_PARAMS
        self.revision = _REVISION


def get_user_params():
    p = params.KeeperParams(server='https://test.keepersecurity.com/')
    p.user = _USER_NAME
    p.password = _USER_PASSWORD
    return p


def get_connected_params():
    p = get_user_params()
    p.iterations = _USER_ITERATIONS
    p.salt = _USER_SALT
    p.data_key = _USER_DATA_KEY
    p.account_uid_bytes = utils.base64_url_decode(_USER_ACCOUNT_UID)

    p.auth_verifier = utils.base64_url_encode(utils.create_auth_verifier(_USER_PASSWORD, _USER_SALT, _USER_ITERATIONS))
    p.rsa_key = RSA.importKey(_DER_PRIVATE_KEY)
    p.rsa_key2 = crypto.load_rsa_private_key(_DER_PRIVATE_KEY)
    p.session_token = _SESSION_TOKEN
    return p


def get_sync_down_responses(p, request, endpoint, rs_type):
    if endpoint == 'vault/sync_down':
        return get_sync_down_response()
    elif endpoint == 'vault/get_record_types':
        content = json.dumps({
            "$id": "login",
            "categories": ["login"],
            "description": "Login template",
            "fields": [
                {"$ref": "login"},
                {"$ref": "password"},
                {"$ref": "url"},
                {"$ref": "fileRef"},
                {"$ref": "oneTimeCode"}
            ]
        })
        rs = record_pb2.RecordTypesResponse()
        rt = record_pb2.RecordType()
        rt.recordTypeId = 1
        rt.content = content
        rt.scope = record_pb2.RT_STANDARD
        rs.recordTypes.append(rt)
        rs.standardCounter = 1
        return rs
    raise NotImplementedError()


def get_synced_params():
    p = get_connected_params()
    with mock.patch('keepercommander.api.communicate_rest') as mock_comm:
        mock_comm.side_effect = get_sync_down_responses
        api.sync_down(p)
    return p


_REVISION = 100
_RECORDS = []                     # type: List[SyncDown_pb2.Record]
_RECORD_METADATA = []             # type: List[SyncDown_pb2.RecordMetaData]
_SHARED_FOLDERS = []              # type: List[SyncDown_pb2.SharedFolder]
_SHARED_FOLDER_USERS = []         # type: List[SyncDown_pb2.SharedFolderUser]
_SHARED_FOLDER_TEAMS = []         # type: List[SyncDown_pb2.SharedFolderTeam]
_SHARED_FOLDER_RECORDS = []       # type: List[SyncDown_pb2.SharedFolderRecord]
_USER_FOLDERS = []                # type: List[SyncDown_pb2.UserFolder]
_USER_FOLDER_RECORDS = []         # type: List[SyncDown_pb2.UserFolderRecord]
_USER_FOLDER_SHARED_FOLDER = []   # type: List[SyncDown_pb2.UserFolderSharedFolder]
_TEAMS = []                       # type: List[SyncDown_pb2.Team]


def get_sync_down_response():    # type: () -> SyncDown_pb2.SyncDownResponse
    response = SyncDown_pb2.SyncDownResponse()
    response.continuationToken = crypto.get_random_bytes(64)
    response.hasMore = False
    response.cacheStatus = SyncDown_pb2.CLEAR
    response.teams.extend(_TEAMS)
    response.userFolders.extend(_USER_FOLDERS)
    response.sharedFolders.extend(_SHARED_FOLDERS)
    response.sharedFolderUsers.extend(_SHARED_FOLDER_USERS)
    response.sharedFolderTeams.extend(_SHARED_FOLDER_TEAMS)
    response.sharedFolderRecords.extend(_SHARED_FOLDER_RECORDS)
    response.records.extend(_RECORDS)
    response.recordMetaData.extend(_RECORD_METADATA)
    response.userFolderRecords.extend(_USER_FOLDER_RECORDS)
    response.userFolderSharedFolders.extend(_USER_FOLDER_SHARED_FOLDER)

    return response


def register_record(rec, key_type=None):
    # type: (Union[vault.PasswordRecord, vault.TypedRecord], Optional[int]) -> bytes

    extra = None   # type: Optional[dict]
    udata = None   # type: Optional[dict]
    if isinstance(rec, vault.PasswordRecord):
        data = vault_extensions.extract_password_record_data(rec)
        extra = vault_extensions.extract_password_record_extras(rec, None)
        if rec.attachments:
            udata = {'file_id': [x.id for x in rec.attachments]}
    elif isinstance(rec, vault.TypedRecord):
        data = vault_extensions.extract_typed_record_data(rec)
    else:
        raise Exception('Unsupported record type')

    record_key = utils.generate_aes_key() if key_type != 0 else _USER_DATA_KEY

    rec_object = SyncDown_pb2.Record()
    rec_object.recordUid = utils.base64_url_decode(rec.record_uid)
    rec_object.revision = rec.revision if (0 < rec.revision <= _REVISION) else _REVISION
    rec_object.version = 2 if isinstance(rec, vault.PasswordRecord) else 3
    rec_object.shared = key_type not in [0, 1]
    rec_object.clientModifiedTime = utils.current_milli_time()
    if isinstance(rec, vault.PasswordRecord):
        rec_object.data = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), record_key)
        if extra:
            rec_object.extra = crypto.encrypt_aes_v1(json.dumps(extra).encode('utf-8'), record_key)
        if udata:
            rec_object.udata = json.dumps(udata)
    else:
        rec_object.data = crypto.encrypt_aes_v2(json.dumps(data).encode('utf-8'), record_key)

    _RECORDS.append(rec_object)

    if isinstance(key_type, int):
        meta_data = SyncDown_pb2.RecordMetaData()
        meta_data.recordUid = utils.base64_url_decode(rec.record_uid)
        meta_data.owner = key_type in [0, 1]
        meta_data.recordKeyType = key_type
        meta_data.canShare = key_type == 1
        meta_data.canEdit = key_type == 1

        if key_type == 0:
            pass
        if key_type == 1:
            meta_data.recordKey = crypto.encrypt_aes_v1(record_key, _USER_DATA_KEY)
        elif key_type == 2:
            meta_data.recordKey = crypto.encrypt_rsa(record_key, _public_key)

        _RECORD_METADATA.append(meta_data)

    return record_key


def register_records_to_folder(folder_uid, record_uids):    # type: (Optional[str], list) -> None
    for record_uid in record_uids:
        ufr = SyncDown_pb2.UserFolderRecord()
        ufr.recordUid = utils.base64_url_decode(record_uid)
        if folder_uid:
            ufr.folderUid = utils.base64_url_decode(folder_uid)
        _USER_FOLDER_RECORDS.append(ufr)


def register_shared_folder(shared_folder, records):  # type: (shared_folder.SharedFolder, Dict[str, bytes]) -> bytes
    shared_folder_key = utils.generate_aes_key()

    sf = SyncDown_pb2.SharedFolder()
    sf.sharedFolderUid = utils.base64_url_decode(shared_folder.shared_folder_uid)
    sf.revision = 5
    sf.sharedFolderKey = crypto.encrypt_aes_v1(shared_folder_key, _USER_DATA_KEY)
    sf.keyType = 1
    sf.data =  crypto.encrypt_aes_v1(json.dumps({'name': shared_folder.name}).encode(), shared_folder_key)
    sf.defaultManageRecords = True
    sf.defaultManageUsers = True
    sf.defaultCanEdit = True
    sf.defaultCanReshare = True
    sf.cacheStatus = SyncDown_pb2.CLEAR
    sf.name = crypto.encrypt_aes_v1(shared_folder.name.encode('utf-8'), shared_folder_key)
    _SHARED_FOLDERS.append(sf)

    sfu = SyncDown_pb2.SharedFolderUser()
    sfu.sharedFolderUid = utils.base64_url_decode(shared_folder.shared_folder_uid)
    sfu.manageRecords = True
    sfu.manageUsers = True
    sfu.accountUid = utils.base64_url_decode(_USER_ACCOUNT_UID)
    _SHARED_FOLDER_USERS.append(sfu)

    for record_uid, record_key in records.items():
        sfr = SyncDown_pb2.SharedFolderRecord()
        sfr.sharedFolderUid = utils.base64_url_decode(shared_folder.shared_folder_uid)
        sfr.recordUid = utils.base64_url_decode(record_uid)
        sfr.recordKey = crypto.encrypt_aes_v1(record_key, shared_folder_key)
        sfr.canShare = False
        sfr.canEdit = False
        sfr.ownerAccountUid = utils.base64_url_decode(_USER_ACCOUNT_UID)
        sfr.owner = True
        _SHARED_FOLDER_RECORDS.append(sfr)

    return shared_folder_key


def register_team(team, key_type, sfs=None):     # type: (team.Team, int, dict) -> bytes
    public_key = crypto.load_rsa_public_key(_IMPORTED_PUBLIC_KEY)
    team_key = utils.generate_aes_key()

    t = SyncDown_pb2.Team()
    t.teamUid = utils.base64_url_decode(team.team_uid)
    t.name = team.name
    t.teamKey = crypto.encrypt_aes_v1(team_key, _USER_DATA_KEY) \
        if key_type == 1 else crypto.encrypt_rsa(team_key, public_key)
    t.teamKeyType = key_type
    t.restrictEdit = team.restrict_edit
    t.restrictShare = team.restrict_share
    t.restrictView = team.restrict_view
    _TEAMS.append(t)

    if isinstance(sfs, dict):
        for shared_folder_uid, shared_folder_key in sfs.items():
            sfk = SyncDown_pb2.SharedFolderKey()
            sfk.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            sfk.sharedFolderKey = crypto.encrypt_aes_v1(shared_folder_key, team_key)
            t.sharedFolderKeys.append(sfk)

            sft = SyncDown_pb2.SharedFolderTeam()
            sft.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            sft.teamUid = utils.base64_url_decode(team.team_uid)
            sft.name = team.name
            sft.manageRecords = key_type == 1
            sft.manageUsers = key_type == 1
            _SHARED_FOLDER_TEAMS.append(sft)

    return team_key


def generate_data():
    r1 = vault.PasswordRecord()
    r1.record_uid = utils.generate_uid()
    r1.title = 'Record 1'
    r1.login = 'user1@keepersecurity.com'
    r1.password = 'password1'
    r1.login_url = 'https://keepersecurity.com/1'
    r1.set_custom_value('field1', 'value1')
    r1.notes = 'note1'
    atta1 = vault.AttachmentFile()
    atta1.id = 'ABCDEFGH'
    atta1.name = 'Attachment 1'
    atta1.key = utils.base64_url_encode(api.generate_aes_key())
    atta1.size = 1000
    r1.attachments = [atta1]
    r1.revision = 1
    r1_key = register_record(r1, 1)

    facade = record_facades.LoginRecordFacade()
    r2 = vault.TypedRecord()
    r2.record_uid = utils.generate_uid()
    r2.title = 'Record 2'
    r2.revision = 2
    facade.record = r2
    facade.login = 'user2@keepersecurity.com'
    facade.password = 'password2'
    facade.login_url = 'https://keepersecurity.com/2'
    facade.notes = 'note2'
    r2.custom.append(vault.TypedField.new_field('text', 'value2', 'field2'))
    r2_key = register_record(r2, 2)

    register_records_to_folder(None, [r1.record_uid, r2.record_uid])

    r3 = vault.PasswordRecord()
    r3.record_uid = utils.generate_uid()
    r3.title = 'Record 3'
    r3.login = 'user3@keepersecurity.com'
    r3.password = 'password3'
    r3.login_url = 'https://keepersecurity.com/3'
    r3.revision = 3
    r3_key = register_record(r3)

    sf1 = shared_folder.SharedFolder()
    sf1.shared_folder_uid = utils.generate_uid()
    sf1.default_manage_records = False
    sf1.default_manage_users = False
    sf1.default_can_edit = False
    sf1.default_can_share = False
    sf1.name = 'Shared Folder 1'
    sf1_key = register_shared_folder(sf1, {
        r3.record_uid: r3_key
    })
    register_records_to_folder(sf1.shared_folder_uid, [r3.record_uid])
    ufsf = SyncDown_pb2.UserFolderSharedFolder()
    ufsf.sharedFolderUid = utils.base64_url_decode(sf1.shared_folder_uid)
    _USER_FOLDER_SHARED_FOLDER.append(ufsf)

    t1 = team.Team()
    t1.team_uid = utils.generate_uid()
    t1.name = 'Team 1'
    t1.restrict_edit = True
    t1.restrict_share = True
    t1.restrict_view = False

    register_team(t1, 1, {sf1.shared_folder_uid: sf1_key})

    folder_key = utils.generate_aes_key()
    uf = SyncDown_pb2.UserFolder()
    uf.folderUid = utils.base64_url_decode(utils.generate_uid())
    uf.userFolderKey = crypto.encrypt_aes_v1(folder_key, _USER_DATA_KEY)
    uf.keyType = 1
    uf.revision = 4
    uf.data = crypto.encrypt_aes_v1(json.dumps({'name': 'User Folder 1'}).encode('utf-8'), folder_key)
    _USER_FOLDERS.append(uf)

generate_data()
