from __future__ import annotations
from .crypto import encrypt_aes
from enum import Enum
import base64
import json
from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Union, Dict


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

# Inverse map for callers that have a graph_id int and need the PamEndpoints enum
# to address the new /api/user/graph-sync/<graph>/<verb> routes.
GRAPH_ID_TO_ENDPOINT = {
    PamGraphId.PAM.value: PamEndpoints.PAM,
    PamGraphId.DISCOVERY_RULES.value: PamEndpoints.DISCOVERY_RULES,
    PamGraphId.DISCOVERY_JOBS.value: PamEndpoints.DISCOVERY_JOBS,
    PamGraphId.INFRASTRUCTURE.value: PamEndpoints.INFRASTRUCTURE,
    PamGraphId.SERVICE_LINKS.value: PamEndpoints.SERVICE_LINKS,
}

# Inverse map for callers that have a graph_id int and need the PamEndpoints enum
# to address the new /api/user/graph-sync/<graph>/<verb> routes.
GRAPH_ID_TO_ENDPOINT = {
    PamGraphId.PAM.value: PamEndpoints.PAM,
    PamGraphId.DISCOVERY_RULES.value: PamEndpoints.DISCOVERY_RULES,
    PamGraphId.DISCOVERY_JOBS.value: PamEndpoints.DISCOVERY_JOBS,
    PamGraphId.INFRASTRUCTURE.value: PamEndpoints.INFRASTRUCTURE,
    PamGraphId.SERVICE_LINKS.value: PamEndpoints.SERVICE_LINKS,
}


class SyncQuery(BaseModel):
    streamId: Optional[str] = None    # base64 of a user's ID who is syncing.
    deviceId: Optional[str] = None
    syncPoint: Optional[int] = None
    graphId: Optional[int] = 0


class SyncDataItem(BaseModel):
    ref: Ref
    parentRef: Optional[Ref] = None
    # Either a base64-encoded string (JSON wire format) or raw bytes
    # (protobuf wire format). `content_is_base64` distinguishes them so the
    # consumer can decode appropriately.
    content: Optional[Union[str, bytes]] = None
    content_is_base64: bool = True
    type: Optional[str] = None
    path: Optional[str] = None
    deletion: Optional[bool] = False


class SyncData(BaseModel):
    syncPoint: int
    data: List[SyncDataItem]
    hasMore: bool
    # Per-graph multi_sync: identifies which stream this result came from.
    # None for single-stream `sync` results (backward compatible).
    streamId: Optional[bytes] = None


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


class ConnectionProtocolEnum(BaseEnum):
    ssh = "ssh"
    rdp = "rdp"
    vnc = "vnc"
    telnet = "telnet"
    http = "http"
    sqlserver = "sqlserver"
    postgresql = "postgresql"
    mysql = "mysql"


class ConnectionSecurity(BaseEnum):
    any = "any"
    nla = "nla"
    tls = "tls"
    rdp = "rdp"


class ConnectionSettingsBase(BaseModel):
    protocol: ConnectionProtocolEnum
    port: Optional[str] = None
    allowSupplyUser: bool = False
    userRecords: List[str] = []
    recordingIncludeKeys: bool = False

    def encode(self) -> str:
        return self.model_dump_json()


class ConnectionSettingsSftp(BaseModel):
    enableSftp: bool = True
    sftpRootDirectory: Optional[str] = None
    sftpServerAliveInterval: Optional[int] = 30


class ConnectionSettingsSsh(ConnectionSettingsBase):
    protocol: ConnectionProtocolEnum = ConnectionProtocolEnum.ssh
    port: str = "22"
    allowSupplyUser: bool = True
    disableCopy: bool = False
    disablePaste: bool = False
    colorScheme: Optional[str] = "white-black"
    fontSize: Optional[int] = 12
    scrollback: Optional[int] = 2000
    hostKey: Optional[str] = None
    command: Optional[str] = None
    sftp: Optional[ConnectionSettingsSftp] = ConnectionSettingsSftp()


class ConnectionSettingsRdp(ConnectionSettingsBase):
    protocol: ConnectionProtocolEnum = ConnectionProtocolEnum.rdp
    port: str = "3389"
    disableCopy: bool = False
    disablePaste: bool = False
    security: ConnectionSecurity = ConnectionSecurity.any
    disableAuth: bool = False
    ignoreCert: bool = True
    loadBalanceInfo: Optional[str] = None
    sftp: Optional[ConnectionSettingsSftp] = ConnectionSettingsSftp()
    disableAudio: bool = False
    resizeMethod: str = "display-update"
    enableWallpaper: bool = False
    enableFullWindowDrag: bool = False


class ConnectionSettingsHttp(ConnectionSettingsBase):
    protocol: ConnectionProtocolEnum = ConnectionProtocolEnum.http
    port: str = "443"
    disableCopy: bool = False
    disablePaste: bool = False


class JitSettings(BaseModel):
    createEphemeral: bool = False
    elevate: bool = False
    elevationMethod: str = "group"
    elevationString: Optional[str] = None
    baseDistinguishedName: Optional[str] = None
    ephemeralAccountType: Optional[str] = None

    def encode(self, record_key_bytes: bytes) -> str:
        return base64.b64encode(encrypt_aes(self.model_dump_json().encode(), record_key_bytes)).decode()


class AiSettingsRiskTagItemLog(BaseModel):
    date: int
    userId: str
    action: str


class AiSettingsRiskTagItem(BaseModel):
    tag: str
    auditLog: List[AiSettingsRiskTagItemLog] = []


class AiSettingsRiskTag(BaseModel):
    allow: List[AiSettingsRiskTagItem] = []
    deny: List[AiSettingsRiskTagItem] = []


class AiSettingsRiskLevel(BaseModel):
    aiSessionTerminate: bool = False
    tags: AiSettingsRiskTag = AiSettingsRiskTag()


class AiSettingsRiskLevels(BaseModel):
    low: AiSettingsRiskLevel = AiSettingsRiskLevel()
    medium: AiSettingsRiskLevel = AiSettingsRiskLevel()
    high: AiSettingsRiskLevel = AiSettingsRiskLevel()
    critical: AiSettingsRiskLevel = AiSettingsRiskLevel()


class AiSettings(BaseModel):
    version: str = "v1.0.0"
    riskLevels: AiSettingsRiskLevels = AiSettingsRiskLevels()

    def encode(self, record_key_bytes: bytes) -> str:
        return base64.b64encode(encrypt_aes(self.model_dump_json().encode(), record_key_bytes)).decode()


class MetaAllSettings(BaseModel):
    remoteBrowserIsolation: bool = False
    rotation: bool = False
    connections: bool = False
    portForwards: bool = False
    sessionRecording: bool = False
    typescriptRecording: bool = False
    aiEnabled: bool = False
    aiSessionTerminate: bool = False


class Meta(BaseModel):
    allowedSettings: MetaAllSettings = MetaAllSettings()
    idpConfigUid: Optional[str] = None
    rotateOnTermination: bool = False
    version: int = 1
    locked: bool = False
    no_update_services: bool = False
    defaultElevationTime: int = 3600000

    def encode(self) -> str:
        return self.model_dump_json()


class PortForward(BaseModel):
    port: str
    reusePort: bool = False
    useSpecifiedLocalPort: bool = False
    localPort: Optional[str] = None

    def encode(self) -> str:
        return self.model_dump_json()


class NetworkSettings(BaseModel):
    allowedSettings: MetaAllSettings = MetaAllSettings()
    idpConfigUid: Optional[str] = None
    adminUid: Optional[str] = None

    def encode(self) -> str:
        return self.model_dump_json()


class NetworkResource(BaseModel):
    model_config = ConfigDict(extra='allow')

    recordUid: str
    adminUid: Optional[str] = None
    meta: Optional[str] = None
    connectionSettings: Optional[str] = None
    connectUsers: Optional[List[str]] = None
    domainUid: Optional[str] = None
    jitSettings: Optional[str] = None
    keeperAiSettings: Optional[str] = None
    updateServices: Optional[bool] = None


class NetworkRotation(BaseModel):
    model_config = ConfigDict(extra='allow')

    recordUid: str
    revision: int
    configurationUid: Optional[str] = None
    resourceUid:  Optional[str] = None
    schedule: Optional[str] = None
    pwdComplexity: Optional[str] = None
    disabled: Optional[bool] = None
    updateServices: Optional[bool] = None
    serviceResources: Optional[List[str]] = None
    serviceNames: Optional[List[Dict]] = None


class PasswordComplexity(BaseModel):
    length: int = 20
    caps: int = 1
    lowercase: int = 1
    digits: int = 1
    special: int = 1
    specialChars: str = """!@#$%^?();',.=+[]<>{}-_/\\*&:"`~|"""

    def encode(self, record_key_bytes: bytes) -> str:
        return base64.b64encode(encrypt_aes(self.model_dump_json().encode(), record_key_bytes)).decode()

# https://keeper.atlassian.net/wiki/spaces/EPD/pages/3970793540/Rotation+Schedule


class ScheduleDow(BaseEnum):
    SUNDAY = "SUNDAY"
    MONDAY = "MONDAY"
    TUESDAY = "TUESDAY"
    WEDNESDAY = "WEDNESDAY"
    THURSDAY = "THURSDAY"
    FRIDAY = "FRIDAY"
    SATURDAY = "SATURDAY"


class ScheduleOccurrence(BaseEnum):
    FIRST = "FIRST"
    SECOND = "SECOND"
    THIRD = "THIRD"
    FOURTH = "FOURTH"
    LAST = "LAST"


class ScheduleMonth(BaseEnum):
    JANUARY = "JANUARY"
    FEBRUARY = "FEBRUARY"
    MARCH = "MARCH"
    APRIL = "APRIL"
    MAY = "MAY"
    JUNE = "JUNE"
    JULY = "JULY"
    AUGUST = "AUGUST"
    SEPTEMBER = "SEPTEMBER"
    OCTOBER = "OCTOBER"
    NOVEMBER = "NOVEMBER"
    DECEMBER = "DECEMBER"


class Schedule(BaseModel):
    type: str = "NA"

    def encode(self) -> str:
        return json.dumps([self.model_dump(exclude_none=True)])


class ScheduleCron(Schedule):
    type: str = "CRON"
    cron: str
    tz: Optional[str] = None


class ScheduleRunOnce(Schedule):
    type: str = "RUN_ONCE"
    time: str
    tz: Optional[str] = None


class ScheduleHourly(Schedule):
    type: str = "HOURLY"
    minute: Optional[int] = None
    second: Optional[int] = None
    intervalCount: int = 1


class ScheduleDaily(Schedule):
    type: str = "DAILY"
    time: str
    tz: Optional[str] = None
    intervalCount: Optional[int] = None


class ScheduleWeekly(Schedule):
    type: str = "WEEKLY"
    weekday: ScheduleDow
    time: str
    tz: Optional[str] = None
    intervalCount: Optional[int] = None


class ScheduleMonthByDay(Schedule):
    type: str = "MONTHLY_BY_DAY"
    monthDay: int
    time: str
    tz: Optional[str] = None
    intervalCount: Optional[int] = None


class ScheduleMonthByWeekday(Schedule):
    type: str = "MONTHLY_BY_WEEKDAY"
    weekday: ScheduleDow
    occurrence: ScheduleOccurrence
    time: str
    tz: Optional[str] = None
    intervalCount: Optional[int] = None


class ScheduleYearly(Schedule):
    type: str = "YEARLY"
    month: ScheduleMonth
    monthDay: int
    time: str
    intervalCount: int = 1
    tz: Optional[str] = None

####################


class ServiceEnum(BaseEnum):
    service = "service"
    task = "task"
    iis_pool = "iis_pool"
    dcom = "dcom"
    com = "com"
    com_plus = "com_plus"
    scom = "scom"


class ServiceNameItem(BaseModel):
    name: str

    # If this was added via Discovery, this will be True
    via_discovery: bool = False


class ServiceName(BaseModel):
    type: ServiceEnum
    items: List[ServiceNameItem] = []


class ServiceResourceName(BaseModel):
    resourceUid: str
    names: List[ServiceName]

    def encode(self, record_key_bytes: bytes) -> Dict:

        names = []
        for item in self.names:
            names.append(item.model_dump(mode='json'))

        print(names)

        return {
            "resourceUid": self.resourceUid,
            "names": base64.b64encode(encrypt_aes(json.dumps(names).encode(), record_key_bytes)).decode()
        }