import os
import base64
import json
import copy
from typing import Optional

from unittest import mock

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from keepercommander import rest_api, api, params, record, shared_folder, team

_USER_NAME = 'unit.test@keepersecurity.com'
_USER_PASSWORD = base64.b64encode(os.urandom(8)).decode('utf-8').strip('=')
_USER_ITERATIONS = 1000
_USER_SALT = os.urandom(16)
_USER_DATA_KEY = os.urandom(32)
_USER_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7359ABCB9854B5CB781E4910662C5EF1

u1i/Mj22bT6AegV38qTsz0mK/QFbGpveS9dq4GXkYVA5JjqowcVsl1HUq2mIhDmW
wYRhkqGWD6IJkt++mDIpv74VKYYuzxTVvt4V46LS/mXn9xqO8g8Cy1qxWznRBPZe
a6/qziQpSI1R4PltIcD1gQHPIJiHINOi4Zi1GT6FTRzZwQ+08rOFfRchvP/rG8hX
KgLywsk9p44exMNJBJhOVTs6UeC4zGdMxNN++Qa+3o+6G8FVgyR4KNGqcFVoYGe6
L5K5KoJz4LwhUy3NDL9TSftxqvXsbiFtUw4BSEYjdyDYQz/ytpFkyGJIzn7vutx+
XbEIMRi6RR2qObI9TdiA5w7sOthvCiGbpzqlH6b++pIRNYiUPe+Ec8SeEbkM8wZB
IFx6xCpDKZQPyCnHngwYIw/iCXqO5UyJjDCnDHOVpMi/BbMJsKp7U+qcrUmN9gUr
VMFRlUZpps5Im3wu3gebZ6Fu41JYK2LqcgEOnh0EbeeZIvH3+uv/QIHdJPYSbsMU
Ns2KJQc+n4PsZa7kZf/CGAq926Y302o9SV2pX1GAcwoHJWkfukZhpt3ikJSrnHVD
FAIZbA0xt4XdbDMVg5T6Er+q1IO1zrZeQ/NLsRR+/JLz3+DvtIKrVMTLtGbl/VV4
rROt9l6YnF2F8CMaMz68v+19vzo1zEob/WD/8Ye3YQq66meJ/+NjwyTmMrZxsO/l
FHeDgDs1r2Nc1uC2/n1UiiZyFTaBzkj/5QUnpBm33V/P63+pN6cw0qEvjNEwdIOC
d5Ohky1d1ayhSeVHkx1ZYcSTriicgWcWTOV+zckJ+VAqvSCZV4A+NMqZGVzPhMgC
h9GWvIXfMDhXIDzBsQz2W3zseJFSzL4av8b/AxTDapOeS9M8FzsbEDJC7YfiLVWK
6bFOLr2dg5Lm41iyWmp7NK2+IUFN15DgMIbHcpfD24F+cs73hjE3E56rsb8dBifG
Q1izqwFiopK+1z9C/EWBmmY3AcyqjXEQl3DWnL2IbYnhmm/SN040BGVZKJcUBUlk
b7RPQF+uZWlM8EWLTqCZQUfl3bogxOcFryyElBPDVRq4Z/x4di2FuUbmI/Mbs1g7
PiBWKIC8CHk3sLezXgMn1thkKsRI3xN+jZcGTZ6lhTVKUAbbW8mqRzBtyjPHbjUC
9PRSeJRDc10ZYnyWhLXa2lSgY12obXNuxLi8eKg6VuBnVzh4CvjOmJY3NlA5xsUi
YLl49YLLQqBU2IwrgqYm+7n2D8PmnhwPUPj2shNoIi9gtAhx8n0pyypgzd8iTtQZ
3IxO1zaNjJOal4er299DcoBsZ5cZ7EU6ltwtUCNqGyaVWwSqjAKtiPGpjT/eEAeL
KLzX+F5r+dUUsy5m8ds+6TUWDxLaqT8PcugnUxT8f3JokODv7JHSiogB1ETeczKS
RJfJH63edAQLxl+rayIqsTuUntmMNgE3olQWexCChX9b8xW6OzVgw8jU6WX0OGOB
5qkDxT9de8CpseIymuDX8AYIpPxIHJdigTBBfYp34hPAKuBpAwDPNS1FiOZYYZSB
84VHEOeXkUpBgAGQwphDZITltMDnssSGPbCX9EHM5+mNVkmQw+SDJbcgXm0jNVtC
-----END RSA PRIVATE KEY-----
'''
_PRIVATE_KEY_PASSWORD = 'E,{-qhsm;<cq]3D(3H5K/'
_USER_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0AjmBXo371pYmvS1NM
8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HDGl3+ylAbI02vIzKue+gDbjo1wUGp2qhA
Nc1VxllLSWnkJmwbuGUTEWp4ANjusoMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx
5oBaqArrrGEg+36Vi7miA/g/UT4DKcryglD4Xx0H9t5Hav+frz2qcEsyh9FC0fNy
on/uveEdP2ac+kax8vO5EeVfBzOdw+WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm0
38JuMwHChTK29H9EOlqbOOuzYA1ENzL88hELpe+kl4RmpNS94BJDssikFFbjoiAV
fwIDAQAB
-----END PUBLIC KEY-----
'''

_SESSION_TOKEN = base64.urlsafe_b64encode(os.urandom(64)).decode('utf-8').strip('=')
_DEVICE_ID = os.urandom(64)

_2FA_ONE_TIME_TOKEN = '123456'
_2FA_DEVICE_TOKEN = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').strip('=')

_IMPORTED_PRIVATE_KEY = RSA.importKey(_USER_PRIVATE_KEY, _PRIVATE_KEY_PASSWORD)
_DER_PRIVATE_KEY = _IMPORTED_PRIVATE_KEY.export_key(format='DER')
_ENCRYPTED_PRIVATE_KEY = api.encrypt_aes(_DER_PRIVATE_KEY, _USER_DATA_KEY)

_IMPORTED_PUBLIC_KEY = RSA.importKey(_USER_PUBLIC_KEY)
_ENCODED_PUBLIC_KEY = base64.urlsafe_b64encode(_IMPORTED_PUBLIC_KEY.export_key(format='DER')).decode('utf-8').strip('=')

_V2_DERIVED_KEY = rest_api.derive_key_v2('data_key', _USER_PASSWORD, _USER_SALT, _USER_ITERATIONS)
_dk = rest_api.encrypt_aes(_USER_DATA_KEY, _V2_DERIVED_KEY)
_ENCRYPTED_DATA_KEY = base64.urlsafe_b64encode(_dk).decode('utf-8').strip()

_V1_DERIVED_KEY = api.derive_key(_USER_PASSWORD, _USER_SALT, _USER_ITERATIONS)
_enc_iter = int.to_bytes(_USER_ITERATIONS, length=3, byteorder='big', signed=False)
_enc_iv = os.urandom(16)
_cipher = AES.new(_V1_DERIVED_KEY, AES.MODE_CBC, _enc_iv)
_enc_dk = b'\x01' + _enc_iter + _USER_SALT + _enc_iv + _cipher.encrypt(_USER_DATA_KEY + _USER_DATA_KEY)
_ENCRYPTION_PARAMS = base64.urlsafe_b64encode(_enc_dk).decode('utf-8').strip()


class VaultEnvironment:
    def __init__(self):
        self.user = _USER_NAME
        self.password = _USER_PASSWORD
        self.iterations = _USER_ITERATIONS
        self.salt = _USER_SALT
        self.data_key = _USER_DATA_KEY
        self.public_key = _IMPORTED_PUBLIC_KEY
        self.encoded_public_key = _ENCODED_PUBLIC_KEY
        self.session_token = _SESSION_TOKEN
        self.device_id = _DEVICE_ID
        self.one_time_token = _2FA_ONE_TIME_TOKEN
        self.device_token = _2FA_DEVICE_TOKEN
        self.encrypted_private_key = _ENCRYPTED_PRIVATE_KEY
        self.encrypted_data_key = _ENCRYPTED_DATA_KEY
        self.encryption_params = _ENCRYPTION_PARAMS
        self.revision = _REVISION


def get_user_params():
    p = params.KeeperParams(server='https://test.keepersecurity.com/', device_id=_DEVICE_ID)
    p.config['device_id'] = base64.urlsafe_b64encode(_DEVICE_ID).decode('utf-8').rstrip('=')
    p.user = _USER_NAME
    p.password = _USER_PASSWORD
    return p


def get_connected_params():
    p = get_user_params()
    p.iterations = _USER_ITERATIONS
    p.salt = _USER_SALT
    p.data_key = _USER_DATA_KEY

    p.auth_verifier = api.auth_verifier(_USER_PASSWORD, _USER_SALT, _USER_ITERATIONS)
    p.rsa_key = _IMPORTED_PRIVATE_KEY
    p.session_token = _SESSION_TOKEN
    return p


def get_synced_params():
    p = get_connected_params()
    with mock.patch('keepercommander.api.communicate') as mock_comm:
        mock_comm.return_value = get_sync_down_response()
        api.sync_down(p)
    return p


_REVISION = 100
_RECORDS = []
_RECORD_METADATA = []
_SHARED_FOLDERS = []
_USER_FOLDERS = []
_USER_FOLDER_RECORDS = []
_USER_FOLDER_SHARED_FOLDER = []
_TEAMS = []

def get_sync_down_response():
    return {
        'result': 'success',
        'result_code': '',
        'message': '',
        'full_sync': True,
        'revision': _REVISION,
        'records': copy.deepcopy(_RECORDS),
        'record_meta_data': copy.deepcopy(_RECORD_METADATA),
        'shared_folders': copy.deepcopy(_SHARED_FOLDERS),
        'teams': copy.deepcopy(_TEAMS),
        'user_folders': copy.deepcopy(_USER_FOLDERS),
        'user_folder_records': copy.deepcopy(_USER_FOLDER_RECORDS),
        'user_folder_shared_folders': copy.deepcopy(_USER_FOLDER_SHARED_FOLDER),
    }


def register_record(record, key_type=None):
    # type: (record.Record, Optional[int]) -> bytes
    data = {
        'title': record.title or '',
        'secret1': record.login or '',
        'secret2': record.password or '',
        'link': record.login_url or '',
        'notes': record.notes or '',
        'custom': record.custom_fields or '',
        'folder': record.folder or ''
    }

    extra = None
    udata = None
    if record.attachments:
        extra = {
            'files': record.attachments
        }
        udata = {
            'file_id': [x['id'] for x in record.attachments]
        }

    record_key = api.generate_aes_key() if key_type != 0 else _USER_DATA_KEY
    rec_object = {
        'record_uid': record.record_uid,
        'revision': record.revision if (0 < record.revision <= _REVISION) else _REVISION,
        'version': 2 if key_type != 0 else 1,
        'shared': key_type not in [0, 1],
        'data': api.encrypt_aes(json.dumps(data).encode('utf-8'), record_key),
    }
    if extra:
        rec_object['extra'] = api.encrypt_aes(json.dumps(extra).encode('utf-8'), record_key)
    if udata:
        rec_object['udata'] = udata

    _RECORDS.append(rec_object)

    meta_data = {
        'record_uid': record.record_uid,
        'owner': key_type in [0, 1],
        'can_share': key_type == 1,
        'can_edit': key_type == 1,
        'record_key_type': key_type
    }

    if key_type == 0:
        _RECORD_METADATA.append(meta_data)
    if key_type == 1:
        meta_data['record_key'] = api.encrypt_aes(record_key, _USER_DATA_KEY)
        _RECORD_METADATA.append(meta_data)
    elif key_type == 2:
        meta_data['record_key'] = api.encrypt_rsa(record_key, _IMPORTED_PUBLIC_KEY)
        _RECORD_METADATA.append(meta_data)

    return record_key


def register_records_to_folder(folder_uid, record_uids):
    # type: (Optional[str], list) -> None
    for record_uid in record_uids:
        ufr = {
            'record_uid': record_uid
        }
        if folder_uid:
            ufr['folder_uid'] = folder_uid
        _USER_FOLDER_RECORDS.append(ufr)


def register_shared_folder(shared_folder, records):
    # type: (shared_folder.SharedFolder, dict) -> bytes

    shared_folder_key = api.generate_aes_key()
    sf = {
        'shared_folder_uid': shared_folder.shared_folder_uid,
        'key_type': 1,
        'shared_folder_key': api.encrypt_aes(shared_folder_key, _USER_DATA_KEY),
        'name': api.encrypt_aes(shared_folder.name.encode('utf-8'), shared_folder_key),
        'is_account_folder': False,
        'manage_records': False,
        'manage_users': False,
        'default_manage_records': True,
        'default_manage_users': True,
        'default_can_edit': True,
        'default_can_share': True,
        'full_sync': True,
        'records': [{
            'record_uid': x[0],
            'record_key': api.encrypt_aes(x[1], shared_folder_key),
            'can_share': False,
            'can_edit': False
        } for x in records.items()],
        'users': [{
            'username': _USER_NAME,
            'manage_records': True,
            'manage_users': True
        }],
        'revision': 5
    }
    _SHARED_FOLDERS.append(sf)

    return shared_folder_key


def register_team(team, key_type, sfs=None):
    # type: (team.Team, int, dict) -> bytes
    team_key = api.generate_aes_key()
    t = {
        'team_uid': team.team_uid,
        'name': team.name,
        'team_key_type': key_type,
        'team_key': api.encrypt_aes(team_key, _USER_DATA_KEY) if key_type == 1 else api.encrypt_rsa(team_key, _IMPORTED_PUBLIC_KEY),
        'team_private_key': api.encrypt_aes(_DER_PRIVATE_KEY, team_key),
        'restrict_edit': team.restrict_edit,
        'restrict_share': team.restrict_share,
        'restrict_view': team.restrict_view,
    }
    _TEAMS.append(t)

    if sfs:
        t['shared_folder_keys'] = [{
            'shared_folder_uid': x[0],
            'key_type': 1,
            'shared_folder_key': api.encrypt_aes(x[1], team_key)
        } for x in sfs.items()]

        sf_uids = set()
        for uid in sfs:
            sf_uids.add(uid)
        for sf in _SHARED_FOLDERS:
            if sf['shared_folder_uid'] in sf_uids:
                if 'teams' not in sf:
                    sf['teams'] = []
                sf['teams'].append({
                    'team_uid': team.team_uid,
                    'name': team.name,
                    'manage_records': key_type == 1,
                    'manage_users': key_type == 1
                })

    return team_key


def generate_data():
    r1 = record.Record()
    r1.record_uid = api.generate_record_uid()
    r1.folder = 'Old Folder'
    r1.title = 'Record 1'
    r1.login = 'user1@keepersecurity.com'
    r1.password = 'password1'
    r1.login_url = 'https://keepersecurity.com/1'
    r1.set_field('field1', 'value1')
    r1.notes = 'note1'
    r1.attachments = [{
        'name': 'Attachment 1',
        'key': base64.urlsafe_b64encode(api.generate_aes_key()).decode('utf-8').rstrip('='),
        'id': 'ABCDEFGH',
        'size': 1000
    }]
    r1.revision = 1
    r1_key = register_record(r1, 1)

    r2 = record.Record()
    r2.record_uid = api.generate_record_uid()
    r2.title = 'Record 2'
    r2.login = 'user2@keepersecurity.com'
    r2.password = 'password2'
    r2.login_url = 'https://keepersecurity.com/2'
    r2.set_field('field2', 'value2')
    r2.notes = 'note2'
    r2.revision = 2
    r2_key = register_record(r2, 2)

    register_records_to_folder(None, [r1.record_uid, r2.record_uid])

    r3 = record.Record()
    r3.record_uid = api.generate_record_uid()
    r3.title = 'Record 3'
    r3.login = 'user3@keepersecurity.com'
    r3.password = 'password3'
    r3.login_url = 'https://keepersecurity.com/3'
    r3.revision = 3
    r3_key = register_record(r3)

    sf1 = shared_folder.SharedFolder()
    sf1.shared_folder_uid = api.generate_record_uid()
    sf1.default_manage_records = False
    sf1.default_manage_users = False
    sf1.default_can_edit = False
    sf1.default_can_share = False
    sf1.name = 'Shared Folder 1'
    sf1_key = register_shared_folder(sf1, {
        r3.record_uid: r3_key
    })
    register_records_to_folder(sf1.shared_folder_uid, [r3.record_uid])
    _USER_FOLDER_SHARED_FOLDER.append({'shared_folder_uid': sf1.shared_folder_uid})

    t1 = team.Team()
    t1.team_uid = api.generate_record_uid()
    t1.name = 'Team 1'
    t1.restrict_edit = True
    t1.restrict_share = True
    t1.restrict_view = False

    register_team(t1, 1, {
        sf1.shared_folder_uid: sf1_key
    })

    folder_key = api.generate_aes_key()
    _USER_FOLDERS.append({
        'folder_uid': api.generate_record_uid(),
        'key_type': 1,
        'user_folder_key': api.encrypt_aes(folder_key, _USER_DATA_KEY),
        'revision': 200,
        'type': 'user_folder',
        'data': api.encrypt_aes(json.dumps({'name': 'User Folder 1'}).encode('utf-8'), folder_key)
    })


generate_data()
