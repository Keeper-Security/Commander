import enterprise_pb2 as _enterprise_pb2
import record_pb2 as _record_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class WebRtcConnectionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    CONNECTION: _ClassVar[WebRtcConnectionType]
    TUNNEL: _ClassVar[WebRtcConnectionType]
    SSH: _ClassVar[WebRtcConnectionType]
    RDP: _ClassVar[WebRtcConnectionType]
    HTTP: _ClassVar[WebRtcConnectionType]
    VNC: _ClassVar[WebRtcConnectionType]
    TELNET: _ClassVar[WebRtcConnectionType]
    MYSQL: _ClassVar[WebRtcConnectionType]
    SQL_SERVER: _ClassVar[WebRtcConnectionType]
    POSTGRESQL: _ClassVar[WebRtcConnectionType]

class PAMOperationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    ADD: _ClassVar[PAMOperationType]
    UPDATE: _ClassVar[PAMOperationType]
    REPLACE: _ClassVar[PAMOperationType]
    DELETE: _ClassVar[PAMOperationType]

class PAMOperationResultType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    POT_SUCCESS: _ClassVar[PAMOperationResultType]
    POT_UNKNOWN_ERROR: _ClassVar[PAMOperationResultType]
    POT_ALREADY_EXISTS: _ClassVar[PAMOperationResultType]
    POT_DOES_NOT_EXIST: _ClassVar[PAMOperationResultType]

class ControllerMessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    CMT_GENERAL: _ClassVar[ControllerMessageType]
    CMT_ROTATE: _ClassVar[ControllerMessageType]
    CMT_DISCOVERY: _ClassVar[ControllerMessageType]
    CMT_CONNECT: _ClassVar[ControllerMessageType]

class PAMRecordingType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    PRT_SESSION: _ClassVar[PAMRecordingType]
    PRT_TYPESCRIPT: _ClassVar[PAMRecordingType]
    PRT_TIME: _ClassVar[PAMRecordingType]
CONNECTION: WebRtcConnectionType
TUNNEL: WebRtcConnectionType
SSH: WebRtcConnectionType
RDP: WebRtcConnectionType
HTTP: WebRtcConnectionType
VNC: WebRtcConnectionType
TELNET: WebRtcConnectionType
MYSQL: WebRtcConnectionType
SQL_SERVER: WebRtcConnectionType
POSTGRESQL: WebRtcConnectionType
ADD: PAMOperationType
UPDATE: PAMOperationType
REPLACE: PAMOperationType
DELETE: PAMOperationType
POT_SUCCESS: PAMOperationResultType
POT_UNKNOWN_ERROR: PAMOperationResultType
POT_ALREADY_EXISTS: PAMOperationResultType
POT_DOES_NOT_EXIST: PAMOperationResultType
CMT_GENERAL: ControllerMessageType
CMT_ROTATE: ControllerMessageType
CMT_DISCOVERY: ControllerMessageType
CMT_CONNECT: ControllerMessageType
PRT_SESSION: PAMRecordingType
PRT_TYPESCRIPT: PAMRecordingType
PRT_TIME: PAMRecordingType

class PAMRotationSchedule(_message.Message):
    __slots__ = ["recordUid", "configurationUid", "controllerUid", "scheduleData", "noSchedule"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULEDATA_FIELD_NUMBER: _ClassVar[int]
    NOSCHEDULE_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    configurationUid: bytes
    controllerUid: bytes
    scheduleData: str
    noSchedule: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., configurationUid: _Optional[bytes] = ..., controllerUid: _Optional[bytes] = ..., scheduleData: _Optional[str] = ..., noSchedule: bool = ...) -> None: ...

class PAMRotationSchedulesResponse(_message.Message):
    __slots__ = ["schedules"]
    SCHEDULES_FIELD_NUMBER: _ClassVar[int]
    schedules: _containers.RepeatedCompositeFieldContainer[PAMRotationSchedule]
    def __init__(self, schedules: _Optional[_Iterable[_Union[PAMRotationSchedule, _Mapping]]] = ...) -> None: ...

class PAMOnlineController(_message.Message):
    __slots__ = ["controllerUid", "connectedOn", "ipAddress", "version", "connections"]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    CONNECTEDON_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    controllerUid: bytes
    connectedOn: int
    ipAddress: str
    version: str
    connections: _containers.RepeatedCompositeFieldContainer[PAMWebRtcConnection]
    def __init__(self, controllerUid: _Optional[bytes] = ..., connectedOn: _Optional[int] = ..., ipAddress: _Optional[str] = ..., version: _Optional[str] = ..., connections: _Optional[_Iterable[_Union[PAMWebRtcConnection, _Mapping]]] = ...) -> None: ...

class PAMWebRtcConnection(_message.Message):
    __slots__ = ["connectionUid", "type", "recordUid", "userName", "startedOn", "configurationUid"]
    CONNECTIONUID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    STARTEDON_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    connectionUid: bytes
    type: WebRtcConnectionType
    recordUid: bytes
    userName: str
    startedOn: int
    configurationUid: bytes
    def __init__(self, connectionUid: _Optional[bytes] = ..., type: _Optional[_Union[WebRtcConnectionType, str]] = ..., recordUid: _Optional[bytes] = ..., userName: _Optional[str] = ..., startedOn: _Optional[int] = ..., configurationUid: _Optional[bytes] = ...) -> None: ...

class PAMOnlineControllers(_message.Message):
    __slots__ = ["deprecated", "controllers"]
    DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERS_FIELD_NUMBER: _ClassVar[int]
    deprecated: _containers.RepeatedScalarFieldContainer[bytes]
    controllers: _containers.RepeatedCompositeFieldContainer[PAMOnlineController]
    def __init__(self, deprecated: _Optional[_Iterable[bytes]] = ..., controllers: _Optional[_Iterable[_Union[PAMOnlineController, _Mapping]]] = ...) -> None: ...

class PAMRotateRequest(_message.Message):
    __slots__ = ["requestUid", "recordUid"]
    REQUESTUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    requestUid: bytes
    recordUid: bytes
    def __init__(self, requestUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ...) -> None: ...

class PAMControllersResponse(_message.Message):
    __slots__ = ["controllers"]
    CONTROLLERS_FIELD_NUMBER: _ClassVar[int]
    controllers: _containers.RepeatedCompositeFieldContainer[PAMController]
    def __init__(self, controllers: _Optional[_Iterable[_Union[PAMController, _Mapping]]] = ...) -> None: ...

class PAMRemoveController(_message.Message):
    __slots__ = ["controllerUid", "message"]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    controllerUid: bytes
    message: str
    def __init__(self, controllerUid: _Optional[bytes] = ..., message: _Optional[str] = ...) -> None: ...

class PAMRemoveControllerResponse(_message.Message):
    __slots__ = ["controllers"]
    CONTROLLERS_FIELD_NUMBER: _ClassVar[int]
    controllers: _containers.RepeatedCompositeFieldContainer[PAMRemoveController]
    def __init__(self, controllers: _Optional[_Iterable[_Union[PAMRemoveController, _Mapping]]] = ...) -> None: ...

class PAMModifyRequest(_message.Message):
    __slots__ = ["operations"]
    OPERATIONS_FIELD_NUMBER: _ClassVar[int]
    operations: _containers.RepeatedCompositeFieldContainer[PAMDataOperation]
    def __init__(self, operations: _Optional[_Iterable[_Union[PAMDataOperation, _Mapping]]] = ...) -> None: ...

class PAMDataOperation(_message.Message):
    __slots__ = ["operationType", "configuration", "element"]
    OPERATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    ELEMENT_FIELD_NUMBER: _ClassVar[int]
    operationType: PAMOperationType
    configuration: PAMConfigurationData
    element: PAMElementData
    def __init__(self, operationType: _Optional[_Union[PAMOperationType, str]] = ..., configuration: _Optional[_Union[PAMConfigurationData, _Mapping]] = ..., element: _Optional[_Union[PAMElementData, _Mapping]] = ...) -> None: ...

class PAMConfigurationData(_message.Message):
    __slots__ = ["configurationUid", "nodeId", "controllerUid", "data"]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    configurationUid: bytes
    nodeId: int
    controllerUid: bytes
    data: bytes
    def __init__(self, configurationUid: _Optional[bytes] = ..., nodeId: _Optional[int] = ..., controllerUid: _Optional[bytes] = ..., data: _Optional[bytes] = ...) -> None: ...

class PAMElementData(_message.Message):
    __slots__ = ["elementUid", "parentUid", "data"]
    ELEMENTUID_FIELD_NUMBER: _ClassVar[int]
    PARENTUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    elementUid: bytes
    parentUid: bytes
    data: bytes
    def __init__(self, elementUid: _Optional[bytes] = ..., parentUid: _Optional[bytes] = ..., data: _Optional[bytes] = ...) -> None: ...

class PAMElementOperationResult(_message.Message):
    __slots__ = ["elementUid", "result", "message"]
    ELEMENTUID_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    elementUid: bytes
    result: PAMOperationResultType
    message: str
    def __init__(self, elementUid: _Optional[bytes] = ..., result: _Optional[_Union[PAMOperationResultType, str]] = ..., message: _Optional[str] = ...) -> None: ...

class PAMModifyResult(_message.Message):
    __slots__ = ["results"]
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[PAMElementOperationResult]
    def __init__(self, results: _Optional[_Iterable[_Union[PAMElementOperationResult, _Mapping]]] = ...) -> None: ...

class PAMElement(_message.Message):
    __slots__ = ["elementUid", "data", "created", "lastModified", "children"]
    ELEMENTUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    elementUid: bytes
    data: bytes
    created: int
    lastModified: int
    children: _containers.RepeatedCompositeFieldContainer[PAMElement]
    def __init__(self, elementUid: _Optional[bytes] = ..., data: _Optional[bytes] = ..., created: _Optional[int] = ..., lastModified: _Optional[int] = ..., children: _Optional[_Iterable[_Union[PAMElement, _Mapping]]] = ...) -> None: ...

class PAMGenericUidRequest(_message.Message):
    __slots__ = ["uid"]
    UID_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    def __init__(self, uid: _Optional[bytes] = ...) -> None: ...

class PAMGenericUidsRequest(_message.Message):
    __slots__ = ["uids"]
    UIDS_FIELD_NUMBER: _ClassVar[int]
    uids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, uids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PAMConfiguration(_message.Message):
    __slots__ = ["configurationUid", "nodeId", "controllerUid", "data", "created", "lastModified", "children"]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    configurationUid: bytes
    nodeId: int
    controllerUid: bytes
    data: bytes
    created: int
    lastModified: int
    children: _containers.RepeatedCompositeFieldContainer[PAMElement]
    def __init__(self, configurationUid: _Optional[bytes] = ..., nodeId: _Optional[int] = ..., controllerUid: _Optional[bytes] = ..., data: _Optional[bytes] = ..., created: _Optional[int] = ..., lastModified: _Optional[int] = ..., children: _Optional[_Iterable[_Union[PAMElement, _Mapping]]] = ...) -> None: ...

class PAMConfigurations(_message.Message):
    __slots__ = ["configurations"]
    CONFIGURATIONS_FIELD_NUMBER: _ClassVar[int]
    configurations: _containers.RepeatedCompositeFieldContainer[PAMConfiguration]
    def __init__(self, configurations: _Optional[_Iterable[_Union[PAMConfiguration, _Mapping]]] = ...) -> None: ...

class PAMController(_message.Message):
    __slots__ = ["controllerUid", "controllerName", "deviceToken", "deviceName", "nodeId", "created", "lastModified", "applicationUid", "appClientType", "isInitialized"]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERNAME_FIELD_NUMBER: _ClassVar[int]
    DEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    APPLICATIONUID_FIELD_NUMBER: _ClassVar[int]
    APPCLIENTTYPE_FIELD_NUMBER: _ClassVar[int]
    ISINITIALIZED_FIELD_NUMBER: _ClassVar[int]
    controllerUid: bytes
    controllerName: str
    deviceToken: str
    deviceName: str
    nodeId: int
    created: int
    lastModified: int
    applicationUid: bytes
    appClientType: _enterprise_pb2.AppClientType
    isInitialized: bool
    def __init__(self, controllerUid: _Optional[bytes] = ..., controllerName: _Optional[str] = ..., deviceToken: _Optional[str] = ..., deviceName: _Optional[str] = ..., nodeId: _Optional[int] = ..., created: _Optional[int] = ..., lastModified: _Optional[int] = ..., applicationUid: _Optional[bytes] = ..., appClientType: _Optional[_Union[_enterprise_pb2.AppClientType, str]] = ..., isInitialized: bool = ...) -> None: ...

class ControllerResponse(_message.Message):
    __slots__ = ["payload"]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    payload: str
    def __init__(self, payload: _Optional[str] = ...) -> None: ...

class PAMConfigurationController(_message.Message):
    __slots__ = ["configurationUid", "controllerUid"]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    configurationUid: bytes
    controllerUid: bytes
    def __init__(self, configurationUid: _Optional[bytes] = ..., controllerUid: _Optional[bytes] = ...) -> None: ...

class ConfigurationAddRequest(_message.Message):
    __slots__ = ["configurationUid", "recordKey", "data", "recordLinks", "audit"]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    RECORDLINKS_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    configurationUid: bytes
    recordKey: bytes
    data: bytes
    recordLinks: _containers.RepeatedCompositeFieldContainer[_record_pb2.RecordLink]
    audit: _record_pb2.RecordAudit
    def __init__(self, configurationUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., data: _Optional[bytes] = ..., recordLinks: _Optional[_Iterable[_Union[_record_pb2.RecordLink, _Mapping]]] = ..., audit: _Optional[_Union[_record_pb2.RecordAudit, _Mapping]] = ...) -> None: ...

class RelayAccessCreds(_message.Message):
    __slots__ = ["username", "password", "serverTime"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    SERVERTIME_FIELD_NUMBER: _ClassVar[int]
    username: str
    password: str
    serverTime: int
    def __init__(self, username: _Optional[str] = ..., password: _Optional[str] = ..., serverTime: _Optional[int] = ...) -> None: ...

class PAMRecording(_message.Message):
    __slots__ = ["connectionUid", "recordingType", "recordUid", "userName", "startedOn", "length", "fileSize", "protocol"]
    CONNECTIONUID_FIELD_NUMBER: _ClassVar[int]
    RECORDINGTYPE_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    STARTEDON_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    FILESIZE_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    connectionUid: bytes
    recordingType: PAMRecordingType
    recordUid: bytes
    userName: str
    startedOn: int
    length: int
    fileSize: int
    protocol: str
    def __init__(self, connectionUid: _Optional[bytes] = ..., recordingType: _Optional[_Union[PAMRecordingType, str]] = ..., recordUid: _Optional[bytes] = ..., userName: _Optional[str] = ..., startedOn: _Optional[int] = ..., length: _Optional[int] = ..., fileSize: _Optional[int] = ..., protocol: _Optional[str] = ...) -> None: ...

class PAMRecordingsResponse(_message.Message):
    __slots__ = ["recordings"]
    RECORDINGS_FIELD_NUMBER: _ClassVar[int]
    recordings: _containers.RepeatedCompositeFieldContainer[PAMRecording]
    def __init__(self, recordings: _Optional[_Iterable[_Union[PAMRecording, _Mapping]]] = ...) -> None: ...

class PAMData(_message.Message):
    __slots__ = ["vertex", "content"]
    VERTEX_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    vertex: bytes
    content: bytes
    def __init__(self, vertex: _Optional[bytes] = ..., content: _Optional[bytes] = ...) -> None: ...

class UidList(_message.Message):
    __slots__ = ["uids"]
    UIDS_FIELD_NUMBER: _ClassVar[int]
    uids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, uids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PAMResourceConfig(_message.Message):
    __slots__ = ["recordUid", "networkUid", "adminUid", "meta", "connectionSettings", "connectUsers", "domainUid", "jitSettings"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    NETWORKUID_FIELD_NUMBER: _ClassVar[int]
    ADMINUID_FIELD_NUMBER: _ClassVar[int]
    META_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONSETTINGS_FIELD_NUMBER: _ClassVar[int]
    CONNECTUSERS_FIELD_NUMBER: _ClassVar[int]
    DOMAINUID_FIELD_NUMBER: _ClassVar[int]
    JITSETTINGS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    networkUid: bytes
    adminUid: bytes
    meta: bytes
    connectionSettings: bytes
    connectUsers: UidList
    domainUid: bytes
    jitSettings: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., networkUid: _Optional[bytes] = ..., adminUid: _Optional[bytes] = ..., meta: _Optional[bytes] = ..., connectionSettings: _Optional[bytes] = ..., connectUsers: _Optional[_Union[UidList, _Mapping]] = ..., domainUid: _Optional[bytes] = ..., jitSettings: _Optional[bytes] = ...) -> None: ...
