from __future__ import annotations

from typing import Dict, Any
from dataclasses import dataclass
import enum
import datetime
import hashlib
import hmac
from typing import List, Optional

from .. import utils
from ..proto import pedm_pb2, NotificationCenter_pb2

@dataclass
class DeploymentAgentInformation:
    hash_key: bytes
    peer_public_key: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            'hash_key': utils.base64_url_encode(self.hash_key),
            'peer_public_key': utils.base64_url_encode(self.peer_public_key),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DeploymentAgentInformation:
        hash_key = data['hash_key']
        peer_public_key = data.get('peer_public_key') or data['pair_public_key']
        return DeploymentAgentInformation(hash_key=utils.base64_url_decode(hash_key),
                                          peer_public_key=utils.base64_url_decode(peer_public_key))


def get_collection_uid(hash_key: bytes, collection_type: int, value: str) -> str:
    message = collection_type.to_bytes(4, byteorder='big') + value.strip().lower().encode('utf-8')
    d = hmac.new(hash_key, message, hashlib.sha256).digest()
    x1 = int.from_bytes(d[:16], byteorder='big', signed=False)
    x2 = int.from_bytes(d[16:], byteorder='big', signed=False)
    return utils.base64_url_encode((x1 ^ x2).to_bytes(length=16, byteorder='big', signed=False))


class CollectionType(int, enum.Enum):
    Other = 0,
    OsBuild = 1,
    Application = 2,
    UserAccount = 3,
    GroupAccount = 4,
    ApplicationName = 5,
    UserName = 10,
    CustomAppCollection = 102,
    CustomUserCollection = 103,
    CustomMachineCollection = 201,
    OsVersion = 202,


def collection_type_to_name(collection_type: int) -> str:
    if collection_type == CollectionType.OsBuild:
        return 'OS Build'
    if collection_type == CollectionType.Application:
        return 'Application'
    if collection_type == CollectionType.UserAccount:
        return 'User Account'
    if collection_type == CollectionType.GroupAccount:
        return 'Group Account'
    if collection_type == CollectionType.ApplicationName:
        return 'App Name'
    if collection_type == CollectionType.UserName:
        return 'User Name'
    if collection_type == CollectionType.CustomAppCollection:
        return 'App Collection'
    if collection_type == CollectionType.CustomUserCollection:
        return 'User Collection'
    if collection_type == CollectionType.CustomMachineCollection:
        return 'Machine Collection'
    if collection_type == CollectionType.OsVersion:
        return 'OS Version'
    return 'Other'

def collection_link_type_to_name(collection_link_type: int) -> str:
    if collection_link_type == pedm_pb2.CollectionLinkType.CLT_AGENT:
        return 'AGENT'
    if collection_link_type == pedm_pb2.CollectionLinkType.CLT_POLICY:
        return 'POLICY'
    if collection_link_type == pedm_pb2.CollectionLinkType.CLT_COLLECTION:
        return 'COLLECTION'
    return 'OTHER'


class EventRequestType(int, enum.Enum):
    Other = 0,
    PrivilegeElevation = 1,
    FileAccess = 2,
    CommandLine = 5,
    LeastPrivilege = 6,
    Custom = 99

def approval_type_to_name(event_type: int) -> str:
    if event_type == EventRequestType.PrivilegeElevation:
        return 'PrivilegeElevation'
    if event_type == EventRequestType.FileAccess:
        return 'FileAccess'
    if event_type == EventRequestType.CommandLine:
        return 'CommandLine'
    if event_type == EventRequestType.LeastPrivilege:
        return 'LeastPrivilege'
    if event_type == EventRequestType.Custom:
        return 'Custom'
    return 'Other'

def approval_status_to_name(approval_status: int, created: datetime.datetime, expire_in: int) -> str:
    if approval_status == NotificationCenter_pb2.NAS_APPROVED:
        return 'Approved'
    elif approval_status == NotificationCenter_pb2.NAS_DENIED:
        return 'Denied'
    elif approval_status == NotificationCenter_pb2.NAS_UNSPECIFIED:
        status = 'Pending'
        expire_time = created + datetime.timedelta(minutes=expire_in)
        if expire_time < datetime.datetime.now():
            status = 'Expired'
        return status
    else:
        return 'Unsupported'

@dataclass
class CollectionRequiredFields:
    all_fields: List[str]
    primary_key_fields: Optional[List[str]] = None


def get_collection_required_fields(collection_type: Optional[int]) -> Optional[CollectionRequiredFields]:
    if collection_type is None:
        return None
    if collection_type == CollectionType.OsBuild:
        return CollectionRequiredFields(['Name', 'Version'])
    if collection_type == CollectionType.Application:
        return CollectionRequiredFields(['FileHash', 'FileName', 'FileVersion'], ['FileHash'])
    if collection_type == CollectionType.UserAccount:
        return CollectionRequiredFields(['Domainname', 'Username', 'AccountType'])
    if collection_type == CollectionType.GroupAccount:
        return CollectionRequiredFields(['GroupName'])
    if collection_type == CollectionType.ApplicationName:
        return CollectionRequiredFields(['Name'])
    if collection_type == CollectionType.UserName:
        return CollectionRequiredFields(['Name'])
    if collection_type == CollectionType.CustomUserCollection:
        return CollectionRequiredFields(['Name'])
    if collection_type == CollectionType.OsVersion:
        return CollectionRequiredFields(['Name'])
    return None
