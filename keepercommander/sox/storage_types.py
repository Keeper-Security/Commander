from keepercommander.proto import enterprise_pb2
from keepercommander.storage.types import IUidLink, IUid

class StorageUser(IUid):
    def __init__(self):
        self.user_uid = ''
        self.email = ''
        self.status = enterprise_pb2.OK

    def uid(self):
        # -> str
        return self.user_uid

class StorageRecord(IUid):
    def __init__(self):
        self.record_uid = ''
        self.encrypted_data = b''
        self.shared = True
        self.created = 0
        self.last_pw_change = 0

    def uid(self):
        # -> str
        return self.record_uid


class StorageUserRecordLink(IUidLink):
    def __init__(self):
        self.record_uid = ''
        self.user_uid = ''

    def subject_uid(self):
        #  -> str
        return self.record_uid

    def object_uid(self):
        #  -> str
        return self.user_uid
