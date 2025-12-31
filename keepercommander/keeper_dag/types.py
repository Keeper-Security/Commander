from __future__ import annotations
from enum import Enum
from pydantic import BaseModel
from typing import List, Optional, Union


class BaseEnum(Enum):

    @classmethod
    def find_enum(cls, value: Union[Enum, str, int], default: Optional[Enum] = None):
        if value is not None:
            for e in cls:
                if e == value or e.value == value:
                    return e
            if hasattr(cls, str(value).upper()):
                return getattr(cls, value.upper())
        return default


class RefType(BaseEnum):
    # 0
    GENERAL = "general"
    # 1
    USER = "user"
    # 2
    DEVICE = "device"
    # 3
    REC = "rec"
    # 4
    FOLDER = "folder"
    # 5
    TEAM = "team"
    # 6
    ENTERPRISE = "enterprise"
    # 7
    PAM_DIRECTORY = "pam_directory"
    # 8
    PAM_MACHINE = "pam_machine"
    # 9
    PAM_DATABASE = "pam_database"
    # 10
    PAM_USER = "pam_user"
    # 11
    PAM_NETWORK = "pam_network"
    # 12
    PAM_BROWSER = "pam_browser"
    # 13
    CONNECTION = "connetion"
    # 14
    WORKFLOW = "workflow"
    # 15
    NOTIFICATION = "notification"
    # 16
    USER_INFO = "user_info"
    # 17
    TEAM_INFO = "team_info"
    # 18
    ROLE = "role"

    def __str__(self):
        return self.value


class EdgeType(BaseEnum):

    """
    DAG data type enum

    * DATA - encrypted data
    * KEY - encrypted key
    * LINK - like a key, but not encrypted
    * ACL - unencrypted set of access control flags
    * DELETION - removal of the previous edge at the same coordinates
    * DENIAL - an element that was shared through graph relationship, can be explicitly denied
    * UNDENIAL - negates the effect of denial, bringing back the share

    """
    DATA = "data"
    KEY = "key"
    LINK = "link"
    ACL = "acl"
    DELETION = "deletion"
    DENIAL = "denial"
    UNDENIAL = "undenial"

    # To store discovery, you would need data and key. To store relationships between records after the discovery
    # data was converted, you use Link.

    def __str__(self) -> str:
        return str(self.value)


class PamGraphId(BaseEnum):
    PAM = 0
    DISCOVERY_RULES = 10
    DISCOVERY_JOBS = 11
    INFRASTRUCTURE = 12
    SERVICE_LINKS = 13


class PamEndpoints(BaseEnum):
    PAM = "/graph-sync/pam"
    DISCOVERY_RULES = "/graph-sync/discovery_rules"
    DISCOVERY_JOBS = "/graph-sync/discovery_jobs"
    INFRASTRUCTURE = "/graph-sync/infrastructure"
    SERVICE_LINKS = "/graph-sync/service_links"


ENDPOINT_TO_GRAPH_ID_MAP = {
    PamEndpoints.PAM.value: PamGraphId.PAM.value,
    PamEndpoints.DISCOVERY_RULES.value: PamGraphId.DISCOVERY_RULES.value,
    PamEndpoints.DISCOVERY_JOBS.value: PamGraphId.DISCOVERY_JOBS.value,
    PamEndpoints.INFRASTRUCTURE.value: PamGraphId.INFRASTRUCTURE.value,
    PamEndpoints.SERVICE_LINKS.value: PamGraphId.SERVICE_LINKS.value,
}


class SyncQuery(BaseModel):
    streamId: Optional[str] = None    # base64 of a user's ID who is syncing.
    deviceId: Optional[str] = None
    syncPoint: Optional[int] = None
    graphId: Optional[int] = 0


class SyncDataItem(BaseModel):
    ref: Ref
    parentRef: Optional[Ref] = None
    content: Optional[str] = None
    content_is_base64: bool = True
    type: Optional[str] = None
    path: Optional[str] = None
    deletion: Optional[bool] = False


class SyncData(BaseModel):
    syncPoint: int
    data: List[SyncDataItem]
    hasMore: bool


class Ref(BaseModel):
    type: RefType
    value: str
    name: Optional[str] = None


# Translation for Key
class Key(BaseModel):
    id: Ref
    value: str


class DAGData(BaseModel):
    type: EdgeType
    ref: Ref
    parentRef: Optional[Ref] = None
    content: Optional[str] = None
    path: Optional[str] = None


class DataPayload(BaseModel):
    origin: Ref
    dataList: List
    graphId: Optional[int] = 0
