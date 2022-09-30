import logging
from typing import Dict, Any, List, Set

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .. import crypto
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
    def __init__(self, data_source=None, ec_key=None):
        self.record_uid = ''
        self.record_uid_bytes = b''
        self.data = {}
        self.created = 0
        self.last_pw_change = 0
        self.shared = False
        self.in_trash = False
        self.has_attachments = False
        self.user_permissions = dict()
        data_source and self.update_properties(data_source, ec_key)

    def update_properties(self, entity, ec_key):  # type: (StorageRecord, EllipticCurvePrivateKey) -> None
        def decrypt_data(encrypted, key):  # type: (bytes, EllipticCurvePrivateKey) -> Dict['str', Any]
            decrypted = {}
            try:
                data_json = crypto.decrypt_ec(encrypted, key) if encrypted else b'{}'
                decrypted = json.loads(data_json.decode())
            except:
                logging.debug('Cannot decrypt record \"%s\" info.', self.record_uid)
            return decrypted

        self.record_uid = entity.record_uid if not self.record_uid else self.record_uid
        self.record_uid_bytes = entity.record_uid_bytes if not self.record_uid_bytes else self.record_uid_bytes
        self.data = decrypt_data(entity.encrypted_data, ec_key) if not self.data else self.data
        self.shared = entity.shared
        self.in_trash = entity.in_trash
        self.has_attachments = entity.has_attachments


class UserRecord:
    def __init__(self, user_uid, record):   # type: (int, Record) -> None
        self.record = record
        self.user_uid = user_uid


class RecordPermissions:
    def __init__(self, record_uid, permissions):    # type: (str, int) -> None
        self.record_uid = record_uid
        self.permission_bits = permissions
        self.user_uid = -1

    @property
    def permissions(self):
        return RecordPermissions.to_permissions_str(self.permission_bits)

    @staticmethod
    def to_permissions_str(permission_bits):
        # type: (int) -> str
        permission_masks = {1: 'owner', 2: 'mask', 4: 'edit', 8: 'share', 16: 'share_admin'}
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
        self.users = set()              # type: Set[int]
        self.teams = set()              # type: Set[str]

    def update_record_permissions(self, permissions):  # type: (RecordPermissions) -> None
        if not any([p for p in self.record_permissions if p.record_uid == permissions.record_uid]):
            self.record_permissions.append(permissions)
