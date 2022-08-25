from typing import Dict, Any, List

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .. import crypto, utils
from ..proto import enterprise_pb2
import json

from .storage_types import StorageUser, StorageRecord, StorageTeam


class EnterpriseUser:
    def __init__(self):
        self.user_uid = 0
        self.email = ''
        self.status = not enterprise_pb2.OK
        self.job_title = ''
        self.node_id = 0
        self.records = []
        self.roles = []

    @staticmethod
    def load(entity):    # type: (StorageUser) -> EnterpriseUser
        user = EnterpriseUser()
        user.user_uid = entity.user_uid
        user.email = entity.email
        user.status = entity.status
        user.job_title = entity.job_title
        user.node_id = entity.node_id
        return user


class Record:
    def __init__(self):
        self.record_uid = ''
        self.data = {}
        self.created = 0
        self.last_pw_change = 0
        self.shared = False
        self.in_trash = False
        self.has_attachments = False
        self.user_permissions = dict()

    @staticmethod
    def load(entity, ec_key):    # type: (StorageRecord, EllipticCurvePrivateKey) -> Record
        def decrypt_data(encrypted, key):   # type: (str, EllipticCurvePrivateKey) -> Dict['str', Any]
            data_json = crypto.decrypt_ec(utils.base64_url_decode(encrypted), key) if encrypted else b'{}'
            return json.loads(data_json.decode())
        record = Record()
        record.record_uid = entity.record_uid
        record.data = decrypt_data(entity.encrypted_data, ec_key)
        record.shared = entity.shared
        record.in_trash = entity.in_trash
        record.has_attachments = entity.has_attachments
        return record


class UserRecord:
    def __init__(self, user_uid, record):   # type: (int, Record) -> None
        self.record = record
        self.user_uid = user_uid


class RecordPermissions:
    def __init__(self, record_uid, permissions):    # type: (int, int) -> None
        self.record_uid = record_uid
        self.permission_bits = permissions
        self.user_uid = -1

    @property
    def permissions(self):
        return RecordPermissions.to_permissions_str(self.permission_bits)

    @staticmethod
    def to_permissions_str(permission_bits):
        # type: (int) -> str
        permission_masks = {1: 'owner',  2: 'mask', 4: 'edit', 8: 'share', 16: 'share_admin'}
        permissions = [permission for mask, permission in permission_masks.items() if (permission_bits & mask)]
        if not permissions:
            permissions.append('read-only')
        return ','.join(permissions)


class Team:
    def __init__(self):
        self.team_uid = ''
        self.team_name = ''
        self.restrict_edit = True
        self.restrict_share = True
        self.users = []

    @staticmethod
    def load(entity):   # type: (StorageTeam) -> Team
        team = Team()
        team.team_uid = entity.team_uid
        team.team_name = entity.team_name
        team.restrict_edit = entity.restrict_edit
        team.restrict_share = entity.restrict_share
        return team


class SharedFolder:
    def __init__(self):
        self.folder_uid = ''
        self.record_permissions = []    # type: List[RecordPermissions]
        self.users = []
        self.teams = []

    @staticmethod
    def load(entity):
        folder = SharedFolder()
        folder.folder_uid = entity.folder_uid
        folder.record_permissions.append(RecordPermissions(entity.record_uid, entity.permissions))
        return folder
