import pam_pb2 as _pam_pb2
import APIRequest_pb2 as _APIRequest_pb2
import folder_pb2 as _folder_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RouterResponseCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RRC_OK: _ClassVar[RouterResponseCode]
    RRC_GENERAL_ERROR: _ClassVar[RouterResponseCode]
    RRC_NOT_ALLOWED: _ClassVar[RouterResponseCode]
    RRC_BAD_REQUEST: _ClassVar[RouterResponseCode]
    RRC_TIMEOUT: _ClassVar[RouterResponseCode]
    RRC_BAD_STATE: _ClassVar[RouterResponseCode]
    RRC_CONTROLLER_DOWN: _ClassVar[RouterResponseCode]
    RRC_WRONG_INSTANCE: _ClassVar[RouterResponseCode]
    RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED: _ClassVar[RouterResponseCode]
    RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED: _ClassVar[RouterResponseCode]

class RouterRotationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RRS_ONLINE: _ClassVar[RouterRotationStatus]
    RRS_NO_ROTATION: _ClassVar[RouterRotationStatus]
    RRS_NO_CONTROLLER: _ClassVar[RouterRotationStatus]
    RRS_CONTROLLER_DOWN: _ClassVar[RouterRotationStatus]

class UserRecordAccessLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RRAL_NONE: _ClassVar[UserRecordAccessLevel]
    RRAL_READ: _ClassVar[UserRecordAccessLevel]
    RRAL_SHARE: _ClassVar[UserRecordAccessLevel]
    RRAL_EDIT: _ClassVar[UserRecordAccessLevel]
    RRAL_EDIT_AND_SHARE: _ClassVar[UserRecordAccessLevel]
    RRAL_OWNER: _ClassVar[UserRecordAccessLevel]

class ServiceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNSPECIFIED: _ClassVar[ServiceType]
    KA: _ClassVar[ServiceType]
    BI: _ClassVar[ServiceType]
RRC_OK: RouterResponseCode
RRC_GENERAL_ERROR: RouterResponseCode
RRC_NOT_ALLOWED: RouterResponseCode
RRC_BAD_REQUEST: RouterResponseCode
RRC_TIMEOUT: RouterResponseCode
RRC_BAD_STATE: RouterResponseCode
RRC_CONTROLLER_DOWN: RouterResponseCode
RRC_WRONG_INSTANCE: RouterResponseCode
RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED: RouterResponseCode
RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED: RouterResponseCode
RRS_ONLINE: RouterRotationStatus
RRS_NO_ROTATION: RouterRotationStatus
RRS_NO_CONTROLLER: RouterRotationStatus
RRS_CONTROLLER_DOWN: RouterRotationStatus
RRAL_NONE: UserRecordAccessLevel
RRAL_READ: UserRecordAccessLevel
RRAL_SHARE: UserRecordAccessLevel
RRAL_EDIT: UserRecordAccessLevel
RRAL_EDIT_AND_SHARE: UserRecordAccessLevel
RRAL_OWNER: UserRecordAccessLevel
UNSPECIFIED: ServiceType
KA: ServiceType
BI: ServiceType

class RouterResponse(_message.Message):
    __slots__ = ("responseCode", "errorMessage", "encryptedPayload")
    RESPONSECODE_FIELD_NUMBER: _ClassVar[int]
    ERRORMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    responseCode: RouterResponseCode
    errorMessage: str
    encryptedPayload: bytes
    def __init__(self, responseCode: _Optional[_Union[RouterResponseCode, str]] = ..., errorMessage: _Optional[str] = ..., encryptedPayload: _Optional[bytes] = ...) -> None: ...

class RouterControllerMessage(_message.Message):
    __slots__ = ("messageType", "messageUid", "controllerUid", "streamResponse", "payload", "timeout")
    MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGEUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    STREAMRESPONSE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    messageType: _pam_pb2.ControllerMessageType
    messageUid: bytes
    controllerUid: bytes
    streamResponse: bool
    payload: bytes
    timeout: int
    def __init__(self, messageType: _Optional[_Union[_pam_pb2.ControllerMessageType, str]] = ..., messageUid: _Optional[bytes] = ..., controllerUid: _Optional[bytes] = ..., streamResponse: bool = ..., payload: _Optional[bytes] = ..., timeout: _Optional[int] = ...) -> None: ...

class RouterUserAuth(_message.Message):
    __slots__ = ("transmissionKey", "sessionToken", "userId", "enterpriseUserId", "deviceName", "deviceToken", "clientVersionId", "needUsername", "username", "mspEnterpriseId", "isPedmAdmin", "mcEnterpriseId")
    TRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    SESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSIONID_FIELD_NUMBER: _ClassVar[int]
    NEEDUSERNAME_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    MSPENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    ISPEDMADMIN_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    transmissionKey: bytes
    sessionToken: bytes
    userId: int
    enterpriseUserId: int
    deviceName: str
    deviceToken: bytes
    clientVersionId: int
    needUsername: bool
    username: str
    mspEnterpriseId: int
    isPedmAdmin: bool
    mcEnterpriseId: int
    def __init__(self, transmissionKey: _Optional[bytes] = ..., sessionToken: _Optional[bytes] = ..., userId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ..., deviceName: _Optional[str] = ..., deviceToken: _Optional[bytes] = ..., clientVersionId: _Optional[int] = ..., needUsername: bool = ..., username: _Optional[str] = ..., mspEnterpriseId: _Optional[int] = ..., isPedmAdmin: bool = ..., mcEnterpriseId: _Optional[int] = ...) -> None: ...

class RouterDeviceAuth(_message.Message):
    __slots__ = ("clientId", "clientVersion", "signature", "enterpriseId", "nodeId", "deviceName", "deviceToken", "controllerName", "controllerUid", "ownerUser", "challenge", "ownerId", "maxInstanceCount")
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERNAME_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    OWNERUSER_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    OWNERID_FIELD_NUMBER: _ClassVar[int]
    MAXINSTANCECOUNT_FIELD_NUMBER: _ClassVar[int]
    clientId: str
    clientVersion: str
    signature: bytes
    enterpriseId: int
    nodeId: int
    deviceName: str
    deviceToken: bytes
    controllerName: str
    controllerUid: bytes
    ownerUser: str
    challenge: str
    ownerId: int
    maxInstanceCount: int
    def __init__(self, clientId: _Optional[str] = ..., clientVersion: _Optional[str] = ..., signature: _Optional[bytes] = ..., enterpriseId: _Optional[int] = ..., nodeId: _Optional[int] = ..., deviceName: _Optional[str] = ..., deviceToken: _Optional[bytes] = ..., controllerName: _Optional[str] = ..., controllerUid: _Optional[bytes] = ..., ownerUser: _Optional[str] = ..., challenge: _Optional[str] = ..., ownerId: _Optional[int] = ..., maxInstanceCount: _Optional[int] = ...) -> None: ...

class RouterRecordRotation(_message.Message):
    __slots__ = ("recordUid", "configurationUid", "controllerUid", "resourceUid", "noSchedule")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    NOSCHEDULE_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    configurationUid: bytes
    controllerUid: bytes
    resourceUid: bytes
    noSchedule: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., configurationUid: _Optional[bytes] = ..., controllerUid: _Optional[bytes] = ..., resourceUid: _Optional[bytes] = ..., noSchedule: bool = ...) -> None: ...

class RouterRecordRotationsRequest(_message.Message):
    __slots__ = ("enterpriseId", "records")
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    records: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, enterpriseId: _Optional[int] = ..., records: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RouterRecordRotationsResponse(_message.Message):
    __slots__ = ("rotations", "hasMore")
    ROTATIONS_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    rotations: _containers.RepeatedCompositeFieldContainer[RouterRecordRotation]
    hasMore: bool
    def __init__(self, rotations: _Optional[_Iterable[_Union[RouterRecordRotation, _Mapping]]] = ..., hasMore: bool = ...) -> None: ...

class RouterRotationInfo(_message.Message):
    __slots__ = ("status", "configurationUid", "resourceUid", "nodeId", "controllerUid", "controllerName", "scriptName", "pwdComplexity", "disabled")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERNAME_FIELD_NUMBER: _ClassVar[int]
    SCRIPTNAME_FIELD_NUMBER: _ClassVar[int]
    PWDCOMPLEXITY_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    status: RouterRotationStatus
    configurationUid: bytes
    resourceUid: bytes
    nodeId: int
    controllerUid: bytes
    controllerName: str
    scriptName: str
    pwdComplexity: str
    disabled: bool
    def __init__(self, status: _Optional[_Union[RouterRotationStatus, str]] = ..., configurationUid: _Optional[bytes] = ..., resourceUid: _Optional[bytes] = ..., nodeId: _Optional[int] = ..., controllerUid: _Optional[bytes] = ..., controllerName: _Optional[str] = ..., scriptName: _Optional[str] = ..., pwdComplexity: _Optional[str] = ..., disabled: bool = ...) -> None: ...

class RouterRecordRotationRequest(_message.Message):
    __slots__ = ("recordUid", "revision", "configurationUid", "resourceUid", "schedule", "enterpriseUserId", "pwdComplexity", "disabled", "remoteAddress", "clientVersionId", "noop", "saasConfiguration", "updateServices", "serviceResources")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    PWDCOMPLEXITY_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    REMOTEADDRESS_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSIONID_FIELD_NUMBER: _ClassVar[int]
    NOOP_FIELD_NUMBER: _ClassVar[int]
    SAASCONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    UPDATESERVICES_FIELD_NUMBER: _ClassVar[int]
    SERVICERESOURCES_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    revision: int
    configurationUid: bytes
    resourceUid: bytes
    schedule: str
    enterpriseUserId: int
    pwdComplexity: bytes
    disabled: bool
    remoteAddress: str
    clientVersionId: int
    noop: bool
    saasConfiguration: bytes
    updateServices: bool
    serviceResources: _pam_pb2.UidList
    def __init__(self, recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., configurationUid: _Optional[bytes] = ..., resourceUid: _Optional[bytes] = ..., schedule: _Optional[str] = ..., enterpriseUserId: _Optional[int] = ..., pwdComplexity: _Optional[bytes] = ..., disabled: bool = ..., remoteAddress: _Optional[str] = ..., clientVersionId: _Optional[int] = ..., noop: bool = ..., saasConfiguration: _Optional[bytes] = ..., updateServices: bool = ..., serviceResources: _Optional[_Union[_pam_pb2.UidList, _Mapping]] = ...) -> None: ...

class UserRecordAccessRequest(_message.Message):
    __slots__ = ("userId", "recordUid")
    USERID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    userId: int
    recordUid: bytes
    def __init__(self, userId: _Optional[int] = ..., recordUid: _Optional[bytes] = ...) -> None: ...

class UserRecordAccessResponse(_message.Message):
    __slots__ = ("recordUid", "accessLevel", "isShareAdmin")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSLEVEL_FIELD_NUMBER: _ClassVar[int]
    ISSHAREADMIN_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    accessLevel: UserRecordAccessLevel
    isShareAdmin: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., accessLevel: _Optional[_Union[UserRecordAccessLevel, str]] = ..., isShareAdmin: bool = ...) -> None: ...

class UserRecordAccessRequests(_message.Message):
    __slots__ = ("requests",)
    REQUESTS_FIELD_NUMBER: _ClassVar[int]
    requests: _containers.RepeatedCompositeFieldContainer[UserRecordAccessRequest]
    def __init__(self, requests: _Optional[_Iterable[_Union[UserRecordAccessRequest, _Mapping]]] = ...) -> None: ...

class UserRecordAccessResponses(_message.Message):
    __slots__ = ("responses",)
    RESPONSES_FIELD_NUMBER: _ClassVar[int]
    responses: _containers.RepeatedCompositeFieldContainer[UserRecordAccessResponse]
    def __init__(self, responses: _Optional[_Iterable[_Union[UserRecordAccessResponse, _Mapping]]] = ...) -> None: ...

class UserSharedFolderAccessRequest(_message.Message):
    __slots__ = ("userId", "sharedFolderUid")
    USERID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    userId: int
    sharedFolderUid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, userId: _Optional[int] = ..., sharedFolderUid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class UserSharedFolderAccessResponse(_message.Message):
    __slots__ = ("sharedFolderUid", "accessRoleType")
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSROLETYPE_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    accessRoleType: _folder_pb2.AccessRoleType
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., accessRoleType: _Optional[_Union[_folder_pb2.AccessRoleType, str]] = ...) -> None: ...

class UserSharedFolderAccessResponses(_message.Message):
    __slots__ = ("responses",)
    RESPONSES_FIELD_NUMBER: _ClassVar[int]
    responses: _containers.RepeatedCompositeFieldContainer[UserSharedFolderAccessResponse]
    def __init__(self, responses: _Optional[_Iterable[_Union[UserSharedFolderAccessResponse, _Mapping]]] = ...) -> None: ...

class UserFolderPermissionsRequest(_message.Message):
    __slots__ = ("userId", "folderUid")
    USERID_FIELD_NUMBER: _ClassVar[int]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    userId: int
    folderUid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, userId: _Optional[int] = ..., folderUid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class UserFolderPermissionsResponse(_message.Message):
    __slots__ = ("folderUid", "permissions")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    permissions: _folder_pb2.FolderPermissions
    def __init__(self, folderUid: _Optional[bytes] = ..., permissions: _Optional[_Union[_folder_pb2.FolderPermissions, _Mapping]] = ...) -> None: ...

class UserFolderPermissionsResponses(_message.Message):
    __slots__ = ("responses",)
    RESPONSES_FIELD_NUMBER: _ClassVar[int]
    responses: _containers.RepeatedCompositeFieldContainer[UserFolderPermissionsResponse]
    def __init__(self, responses: _Optional[_Iterable[_Union[UserFolderPermissionsResponse, _Mapping]]] = ...) -> None: ...

class RotationSchedule(_message.Message):
    __slots__ = ("record_uid", "schedule")
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    schedule: str
    def __init__(self, record_uid: _Optional[bytes] = ..., schedule: _Optional[str] = ...) -> None: ...

class ApiCallbackRequest(_message.Message):
    __slots__ = ("resourceUid", "schedules", "url", "serviceType")
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULES_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    SERVICETYPE_FIELD_NUMBER: _ClassVar[int]
    resourceUid: bytes
    schedules: _containers.RepeatedCompositeFieldContainer[ApiCallbackSchedule]
    url: str
    serviceType: ServiceType
    def __init__(self, resourceUid: _Optional[bytes] = ..., schedules: _Optional[_Iterable[_Union[ApiCallbackSchedule, _Mapping]]] = ..., url: _Optional[str] = ..., serviceType: _Optional[_Union[ServiceType, str]] = ...) -> None: ...

class ApiCallbackSchedule(_message.Message):
    __slots__ = ("schedule", "data")
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    schedule: str
    data: bytes
    def __init__(self, schedule: _Optional[str] = ..., data: _Optional[bytes] = ...) -> None: ...

class RouterScheduledActions(_message.Message):
    __slots__ = ("schedule", "resourceUids")
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUIDS_FIELD_NUMBER: _ClassVar[int]
    schedule: str
    resourceUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, schedule: _Optional[str] = ..., resourceUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RouterRecordsRotationRequest(_message.Message):
    __slots__ = ("rotationSchedules",)
    ROTATIONSCHEDULES_FIELD_NUMBER: _ClassVar[int]
    rotationSchedules: _containers.RepeatedCompositeFieldContainer[RouterScheduledActions]
    def __init__(self, rotationSchedules: _Optional[_Iterable[_Union[RouterScheduledActions, _Mapping]]] = ...) -> None: ...

class ConnectionParameters(_message.Message):
    __slots__ = ("connectionUid", "recordUid", "userId", "controllerUid", "credentialsRecordUid")
    CONNECTIONUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALSRECORDUID_FIELD_NUMBER: _ClassVar[int]
    connectionUid: bytes
    recordUid: bytes
    userId: int
    controllerUid: bytes
    credentialsRecordUid: bytes
    def __init__(self, connectionUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., userId: _Optional[int] = ..., controllerUid: _Optional[bytes] = ..., credentialsRecordUid: _Optional[bytes] = ...) -> None: ...

class ValidateConnectionsRequest(_message.Message):
    __slots__ = ("connections",)
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    connections: _containers.RepeatedCompositeFieldContainer[ConnectionParameters]
    def __init__(self, connections: _Optional[_Iterable[_Union[ConnectionParameters, _Mapping]]] = ...) -> None: ...

class ConnectionValidationFailure(_message.Message):
    __slots__ = ("connectionUid", "errorMessage")
    CONNECTIONUID_FIELD_NUMBER: _ClassVar[int]
    ERRORMESSAGE_FIELD_NUMBER: _ClassVar[int]
    connectionUid: bytes
    errorMessage: str
    def __init__(self, connectionUid: _Optional[bytes] = ..., errorMessage: _Optional[str] = ...) -> None: ...

class ValidateConnectionsResponse(_message.Message):
    __slots__ = ("failedConnections",)
    FAILEDCONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    failedConnections: _containers.RepeatedCompositeFieldContainer[ConnectionValidationFailure]
    def __init__(self, failedConnections: _Optional[_Iterable[_Union[ConnectionValidationFailure, _Mapping]]] = ...) -> None: ...

class GetEnforcementRequest(_message.Message):
    __slots__ = ("enterpriseUserId",)
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ...) -> None: ...

class EnforcementType(_message.Message):
    __slots__ = ("enforcementTypeId", "value")
    ENFORCEMENTTYPEID_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    enforcementTypeId: int
    value: str
    def __init__(self, enforcementTypeId: _Optional[int] = ..., value: _Optional[str] = ...) -> None: ...

class GetEnforcementResponse(_message.Message):
    __slots__ = ("enforcementTypes", "addOnIds", "isInTrial")
    ENFORCEMENTTYPES_FIELD_NUMBER: _ClassVar[int]
    ADDONIDS_FIELD_NUMBER: _ClassVar[int]
    ISINTRIAL_FIELD_NUMBER: _ClassVar[int]
    enforcementTypes: _containers.RepeatedCompositeFieldContainer[EnforcementType]
    addOnIds: _containers.RepeatedScalarFieldContainer[int]
    isInTrial: bool
    def __init__(self, enforcementTypes: _Optional[_Iterable[_Union[EnforcementType, _Mapping]]] = ..., addOnIds: _Optional[_Iterable[int]] = ..., isInTrial: bool = ...) -> None: ...

class PEDMTOTPValidateRequest(_message.Message):
    __slots__ = ("username", "enterpriseId", "code")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    username: str
    enterpriseId: int
    code: int
    def __init__(self, username: _Optional[str] = ..., enterpriseId: _Optional[int] = ..., code: _Optional[int] = ...) -> None: ...

class GetPEDMAdminInfoResponse(_message.Message):
    __slots__ = ("isPedmAdmin", "pedmAddonActive")
    ISPEDMADMIN_FIELD_NUMBER: _ClassVar[int]
    PEDMADDONACTIVE_FIELD_NUMBER: _ClassVar[int]
    isPedmAdmin: bool
    pedmAddonActive: bool
    def __init__(self, isPedmAdmin: bool = ..., pedmAddonActive: bool = ...) -> None: ...

class PAMNetworkSettings(_message.Message):
    __slots__ = ("allowedSettings", "idpConfigUid", "adminUid")
    ALLOWEDSETTINGS_FIELD_NUMBER: _ClassVar[int]
    IDPCONFIGUID_FIELD_NUMBER: _ClassVar[int]
    ADMINUID_FIELD_NUMBER: _ClassVar[int]
    allowedSettings: bytes
    idpConfigUid: bytes
    adminUid: bytes
    def __init__(self, allowedSettings: _Optional[bytes] = ..., idpConfigUid: _Optional[bytes] = ..., adminUid: _Optional[bytes] = ...) -> None: ...

class PAMNetworkConfigurationRequest(_message.Message):
    __slots__ = ("recordUid", "networkSettings", "resources", "rotations")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    NETWORKSETTINGS_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    ROTATIONS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    networkSettings: PAMNetworkSettings
    resources: _containers.RepeatedCompositeFieldContainer[_pam_pb2.PAMResourceConfig]
    rotations: _containers.RepeatedCompositeFieldContainer[RouterRecordRotationRequest]
    def __init__(self, recordUid: _Optional[bytes] = ..., networkSettings: _Optional[_Union[PAMNetworkSettings, _Mapping]] = ..., resources: _Optional[_Iterable[_Union[_pam_pb2.PAMResourceConfig, _Mapping]]] = ..., rotations: _Optional[_Iterable[_Union[RouterRecordRotationRequest, _Mapping]]] = ...) -> None: ...

class PAMDiscoveryRulesSetRequest(_message.Message):
    __slots__ = ("networkUid", "rules", "rulesKey")
    NETWORKUID_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    RULESKEY_FIELD_NUMBER: _ClassVar[int]
    networkUid: bytes
    rules: bytes
    rulesKey: bytes
    def __init__(self, networkUid: _Optional[bytes] = ..., rules: _Optional[bytes] = ..., rulesKey: _Optional[bytes] = ...) -> None: ...

class Router2FAValidateRequest(_message.Message):
    __slots__ = ("transmissionKey", "sessionToken", "value")
    TRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    SESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    transmissionKey: bytes
    sessionToken: bytes
    value: str
    def __init__(self, transmissionKey: _Optional[bytes] = ..., sessionToken: _Optional[bytes] = ..., value: _Optional[str] = ...) -> None: ...

class Router2FASendPushRequest(_message.Message):
    __slots__ = ("transmissionKey", "sessionToken", "pushType")
    TRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    SESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    PUSHTYPE_FIELD_NUMBER: _ClassVar[int]
    transmissionKey: bytes
    sessionToken: bytes
    pushType: _APIRequest_pb2.TwoFactorPushType
    def __init__(self, transmissionKey: _Optional[bytes] = ..., sessionToken: _Optional[bytes] = ..., pushType: _Optional[_Union[_APIRequest_pb2.TwoFactorPushType, str]] = ...) -> None: ...

class Router2FAGetWebAuthnChallengeRequest(_message.Message):
    __slots__ = ("transmissionKey", "sessionToken")
    TRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    SESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    transmissionKey: bytes
    sessionToken: bytes
    def __init__(self, transmissionKey: _Optional[bytes] = ..., sessionToken: _Optional[bytes] = ...) -> None: ...

class Router2FAGetWebAuthnChallengeResponse(_message.Message):
    __slots__ = ("challenge", "capabilities")
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    challenge: str
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, challenge: _Optional[str] = ..., capabilities: _Optional[_Iterable[str]] = ...) -> None: ...

class CreateEphemeralSecretRequest(_message.Message):
    __slots__ = ("encryptedSecret", "secretKeyHash", "ttl")
    ENCRYPTEDSECRET_FIELD_NUMBER: _ClassVar[int]
    SECRETKEYHASH_FIELD_NUMBER: _ClassVar[int]
    TTL_FIELD_NUMBER: _ClassVar[int]
    encryptedSecret: bytes
    secretKeyHash: bytes
    ttl: int
    def __init__(self, encryptedSecret: _Optional[bytes] = ..., secretKeyHash: _Optional[bytes] = ..., ttl: _Optional[int] = ...) -> None: ...
