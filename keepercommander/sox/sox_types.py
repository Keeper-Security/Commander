from keepercommander import crypto, utils
from keepercommander.proto import enterprise_pb2
import json

class EnterpriseUser:
    def __init__(self):
        self.user_uid = -1
        self.email = ''
        self.status = enterprise_pb2.OK
        self.records = []                    # type: List[str]

    @staticmethod
    def load(store):    # type: (sox_storage.StorageUser) -> EnterpriseUser
        user = EnterpriseUser()
        user.user_uid = store.user_uid
        user.email = store.email
        user.status = store.status
        return user


class Record:
    def __init__(self):
        self.record_uid = b''
        self.encrypted_data = b''
        self.data = {}
        self.created = 0
        self.last_pw_change = 0
        self.shared = False


    @staticmethod
    def load(store, ec_key):
        def decrypt_data(encrypted, key):   # type: (bytes) -> Dict['str', Any]
            data_json = crypto.decrypt_ec(utils.base64_url_decode(encrypted), key) if encrypted else b'{}'
            return json.loads(data_json.decode())
        record = Record()
        record.record_uid = store.record_uid
        record.encrypted_data = store.encrypted_data
        record.data = decrypt_data(store.encrypted_data, ec_key)
        record.created = store.created
        record.last_pw_change = store.last_pw_change
        record.shared = store.shared
        return record


class UserRecord():
    def __init__(self, user_uid, record):   # type: (int, Record) -> Nonw
        self.record = record
        self.user_uid = user_uid

