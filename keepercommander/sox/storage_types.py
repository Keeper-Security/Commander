from ..proto import enterprise_pb2
from ..storage.types import IUidLink, IUid


class StorageUser(IUid):
    def __init__(self):
        self.user_uid = 0
        self.email = ''
        self.status = not enterprise_pb2.OK
        self.job_title = ''
        self.full_name = ''
        self.node_id = 0

    def uid(self):
        # -> int
        return self.user_uid


class StorageRecord(IUid):
    def __init__(self):
        self.record_uid = ''
        self.record_uid_bytes = b''
        self.encrypted_data = b''
        self.shared = True
        self.in_trash = False
        self.has_attachments = False

    def uid(self):
        # -> str
        return self.record_uid


class StorageRecordAging(IUid):
    def __init__(self, record_uid=''):
        self.record_uid = record_uid
        self.created = 0
        self.last_pw_change = 0

    def uid(self):
        return self.record_uid


class StorageTeam(IUid):
    def __init__(self):
        self.team_uid = ''
        self.team_name = ''
        self.restrict_edit = True
        self.restrict_share = True

    def uid(self):
        # -> str
        return self.team_uid


class StorageRole(IUid):
    def __init__(self):
        self.role_id = 0
        self.encrypted_data = b''
        self.restrict_share_outside_enterprise = False
        self.restrict_share_all = False
        self.restrict_share_of_attachments = False
        self.restrict_mask_passwords_while_editing = False

    def uid(self):
        # -> str
        return self.role_id


class StorageTeamUserLink(IUidLink):
    def __init__(self, team_uid='', user_uid=0):
        self.team_uid = team_uid
        self.user_uid = user_uid

    def subject_uid(self):
        #  -> str
        return self.team_uid

    def object_uid(self):
        #  -> int
        return self.user_uid


class StorageUserRecordLink(IUidLink):
    def __init__(self):
        self.record_uid = ''
        self.user_uid = 0

    def subject_uid(self):
        #  -> str
        return self.record_uid

    def object_uid(self):
        #  -> int
        return self.user_uid


class StorageSharedFolderRecordLink(IUidLink):
    def __init__(self, folder_uid='', record_uid='', permissions=0):
        self.folder_uid = folder_uid
        self.record_uid = record_uid
        self.permissions = permissions

    def subject_uid(self):
        return self.folder_uid

    def object_uid(self):
        return self.record_uid


class StorageSharedFolderUserLink(IUidLink):
    def __init__(self, folder_uid='', user_uid=0):
        self.folder_uid = folder_uid
        self.user_uid = user_uid

    def subject_uid(self):
        return self.folder_uid

    def object_uid(self):
        return self.user_uid


class StorageSharedFolderTeamLink(IUidLink):
    def __init__(self, folder_uid='', team_uid=''):
        self.folder_uid = folder_uid
        self.team_uid = team_uid

    def subject_uid(self):
        return self.folder_uid

    def object_uid(self):
        return self.team_uid


class StorageRecordPermissions(IUidLink):
    def __init__(self, record_uid='', user_uid=0, permissions=0):
        self.record_uid = record_uid
        self.user_uid = user_uid
        self.permissions = permissions

    def subject_uid(self):
        return self.record_uid

    def object_uid(self):
        return self.user_uid
