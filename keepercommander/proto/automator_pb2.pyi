import ssocloud_pb2 as _ssocloud_pb2
import enterprise_pb2 as _enterprise_pb2
import version_pb2 as _version_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SsoAuthenticationProtocolType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_PROTOCOL: _ClassVar[SsoAuthenticationProtocolType]
    SAML2: _ClassVar[SsoAuthenticationProtocolType]

class CertificateFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_FORMAT: _ClassVar[CertificateFormat]
    PKCS12: _ClassVar[CertificateFormat]
    JKS: _ClassVar[CertificateFormat]

class SkillType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_SKILL_TYPE: _ClassVar[SkillType]
    DEVICE_APPROVAL: _ClassVar[SkillType]
    TEAM_APPROVAL: _ClassVar[SkillType]
    TEAM_FOR_USER_APPROVAL: _ClassVar[SkillType]

class AutomatorState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_STATE: _ClassVar[AutomatorState]
    RUNNING: _ClassVar[AutomatorState]
    ERROR: _ClassVar[AutomatorState]
    NEEDS_INITIALIZATION: _ClassVar[AutomatorState]
    NEEDS_CRYPTO_STEP_1: _ClassVar[AutomatorState]
    NEEDS_CRYPTO_STEP_2: _ClassVar[AutomatorState]
UNKNOWN_PROTOCOL: SsoAuthenticationProtocolType
SAML2: SsoAuthenticationProtocolType
UNKNOWN_FORMAT: CertificateFormat
PKCS12: CertificateFormat
JKS: CertificateFormat
UNKNOWN_SKILL_TYPE: SkillType
DEVICE_APPROVAL: SkillType
TEAM_APPROVAL: SkillType
TEAM_FOR_USER_APPROVAL: SkillType
UNKNOWN_STATE: AutomatorState
RUNNING: AutomatorState
ERROR: AutomatorState
NEEDS_INITIALIZATION: AutomatorState
NEEDS_CRYPTO_STEP_1: AutomatorState
NEEDS_CRYPTO_STEP_2: AutomatorState

class AutomatorSettingValue(_message.Message):
    __slots__ = ["settingId", "settingTypeId", "settingTag", "settingName", "settingValue", "dataType", "lastModified", "fromFile", "encrypted", "encoded", "editable", "translated", "userVisible", "required"]
    SETTINGID_FIELD_NUMBER: _ClassVar[int]
    SETTINGTYPEID_FIELD_NUMBER: _ClassVar[int]
    SETTINGTAG_FIELD_NUMBER: _ClassVar[int]
    SETTINGNAME_FIELD_NUMBER: _ClassVar[int]
    SETTINGVALUE_FIELD_NUMBER: _ClassVar[int]
    DATATYPE_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    FROMFILE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_FIELD_NUMBER: _ClassVar[int]
    ENCODED_FIELD_NUMBER: _ClassVar[int]
    EDITABLE_FIELD_NUMBER: _ClassVar[int]
    TRANSLATED_FIELD_NUMBER: _ClassVar[int]
    USERVISIBLE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    settingId: int
    settingTypeId: int
    settingTag: str
    settingName: str
    settingValue: str
    dataType: _ssocloud_pb2.DataType
    lastModified: str
    fromFile: bool
    encrypted: bool
    encoded: bool
    editable: bool
    translated: bool
    userVisible: bool
    required: bool
    def __init__(self, settingId: _Optional[int] = ..., settingTypeId: _Optional[int] = ..., settingTag: _Optional[str] = ..., settingName: _Optional[str] = ..., settingValue: _Optional[str] = ..., dataType: _Optional[_Union[_ssocloud_pb2.DataType, str]] = ..., lastModified: _Optional[str] = ..., fromFile: bool = ..., encrypted: bool = ..., encoded: bool = ..., editable: bool = ..., translated: bool = ..., userVisible: bool = ..., required: bool = ...) -> None: ...

class ApproveDeviceRequest(_message.Message):
    __slots__ = ["automatorId", "ssoAuthenticationProtocolType", "authMessage", "email", "devicePublicKey", "serverEccPublicKeyId", "userEncryptedDataKey", "userEncryptedDataKeyType", "ipAddress", "isTesting", "isEccOnly"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SSOAUTHENTICATIONPROTOCOLTYPE_FIELD_NUMBER: _ClassVar[int]
    AUTHMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDDATAKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    ISTESTING_FIELD_NUMBER: _ClassVar[int]
    ISECCONLY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    ssoAuthenticationProtocolType: SsoAuthenticationProtocolType
    authMessage: str
    email: str
    devicePublicKey: bytes
    serverEccPublicKeyId: int
    userEncryptedDataKey: bytes
    userEncryptedDataKeyType: _enterprise_pb2.EncryptedKeyType
    ipAddress: str
    isTesting: bool
    isEccOnly: bool
    def __init__(self, automatorId: _Optional[int] = ..., ssoAuthenticationProtocolType: _Optional[_Union[SsoAuthenticationProtocolType, str]] = ..., authMessage: _Optional[str] = ..., email: _Optional[str] = ..., devicePublicKey: _Optional[bytes] = ..., serverEccPublicKeyId: _Optional[int] = ..., userEncryptedDataKey: _Optional[bytes] = ..., userEncryptedDataKeyType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., ipAddress: _Optional[str] = ..., isTesting: bool = ..., isEccOnly: bool = ...) -> None: ...

class SetupRequest(_message.Message):
    __slots__ = ["automatorId", "serverEccPublicKeyId", "automatorState", "encryptedEnterprisePrivateEccKey", "encryptedEnterprisePrivateRsaKey", "automatorSkills", "encryptedTreeKey", "isEccOnly"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDENTERPRISEPRIVATEECCKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDENTERPRISEPRIVATERSAKEY_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSKILLS_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTREEKEY_FIELD_NUMBER: _ClassVar[int]
    ISECCONLY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    serverEccPublicKeyId: int
    automatorState: AutomatorState
    encryptedEnterprisePrivateEccKey: bytes
    encryptedEnterprisePrivateRsaKey: bytes
    automatorSkills: _containers.RepeatedCompositeFieldContainer[AutomatorSkill]
    encryptedTreeKey: bytes
    isEccOnly: bool
    def __init__(self, automatorId: _Optional[int] = ..., serverEccPublicKeyId: _Optional[int] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., encryptedEnterprisePrivateEccKey: _Optional[bytes] = ..., encryptedEnterprisePrivateRsaKey: _Optional[bytes] = ..., automatorSkills: _Optional[_Iterable[_Union[AutomatorSkill, _Mapping]]] = ..., encryptedTreeKey: _Optional[bytes] = ..., isEccOnly: bool = ...) -> None: ...

class StatusRequest(_message.Message):
    __slots__ = ["automatorId", "serverEccPublicKeyId", "isEccOnly"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    ISECCONLY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    serverEccPublicKeyId: int
    isEccOnly: bool
    def __init__(self, automatorId: _Optional[int] = ..., serverEccPublicKeyId: _Optional[int] = ..., isEccOnly: bool = ...) -> None: ...

class InitializeRequest(_message.Message):
    __slots__ = ["automatorId", "idpMetadata", "idpSigningCertificate", "ssoEntityId", "emailMapping", "firstnameMapping", "lastnameMapping", "disabled", "serverEccPublicKeyId", "config", "sslMode", "persistState", "disableSniCheck", "sslCertificateFilename", "sslCertificateFilePassword", "sslCertificateKeyPassword", "sslCertificateContents", "automatorHost", "automatorPort", "ipAllow", "ipDeny", "isEccOnly"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    IDPMETADATA_FIELD_NUMBER: _ClassVar[int]
    IDPSIGNINGCERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    SSOENTITYID_FIELD_NUMBER: _ClassVar[int]
    EMAILMAPPING_FIELD_NUMBER: _ClassVar[int]
    FIRSTNAMEMAPPING_FIELD_NUMBER: _ClassVar[int]
    LASTNAMEMAPPING_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    SSLMODE_FIELD_NUMBER: _ClassVar[int]
    PERSISTSTATE_FIELD_NUMBER: _ClassVar[int]
    DISABLESNICHECK_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEFILENAME_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEFILEPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEKEYPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATECONTENTS_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORHOST_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORPORT_FIELD_NUMBER: _ClassVar[int]
    IPALLOW_FIELD_NUMBER: _ClassVar[int]
    IPDENY_FIELD_NUMBER: _ClassVar[int]
    ISECCONLY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    idpMetadata: str
    idpSigningCertificate: bytes
    ssoEntityId: str
    emailMapping: str
    firstnameMapping: str
    lastnameMapping: str
    disabled: bool
    serverEccPublicKeyId: int
    config: bytes
    sslMode: str
    persistState: bool
    disableSniCheck: bool
    sslCertificateFilename: str
    sslCertificateFilePassword: str
    sslCertificateKeyPassword: str
    sslCertificateContents: bytes
    automatorHost: str
    automatorPort: str
    ipAllow: str
    ipDeny: str
    isEccOnly: bool
    def __init__(self, automatorId: _Optional[int] = ..., idpMetadata: _Optional[str] = ..., idpSigningCertificate: _Optional[bytes] = ..., ssoEntityId: _Optional[str] = ..., emailMapping: _Optional[str] = ..., firstnameMapping: _Optional[str] = ..., lastnameMapping: _Optional[str] = ..., disabled: bool = ..., serverEccPublicKeyId: _Optional[int] = ..., config: _Optional[bytes] = ..., sslMode: _Optional[str] = ..., persistState: bool = ..., disableSniCheck: bool = ..., sslCertificateFilename: _Optional[str] = ..., sslCertificateFilePassword: _Optional[str] = ..., sslCertificateKeyPassword: _Optional[str] = ..., sslCertificateContents: _Optional[bytes] = ..., automatorHost: _Optional[str] = ..., automatorPort: _Optional[str] = ..., ipAllow: _Optional[str] = ..., ipDeny: _Optional[str] = ..., isEccOnly: bool = ...) -> None: ...

class NotInitializedResponse(_message.Message):
    __slots__ = ["automatorTransmissionKey", "signingCertificate", "signingCertificateFilename", "signingCertificatePassword", "signingKeyPassword", "signingCertificateFormat", "automatorPublicKey", "config"]
    AUTOMATORTRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATEFILENAME_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATEPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SIGNINGKEYPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATEFORMAT_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    automatorTransmissionKey: bytes
    signingCertificate: bytes
    signingCertificateFilename: str
    signingCertificatePassword: str
    signingKeyPassword: str
    signingCertificateFormat: CertificateFormat
    automatorPublicKey: bytes
    config: bytes
    def __init__(self, automatorTransmissionKey: _Optional[bytes] = ..., signingCertificate: _Optional[bytes] = ..., signingCertificateFilename: _Optional[str] = ..., signingCertificatePassword: _Optional[str] = ..., signingKeyPassword: _Optional[str] = ..., signingCertificateFormat: _Optional[_Union[CertificateFormat, str]] = ..., automatorPublicKey: _Optional[bytes] = ..., config: _Optional[bytes] = ...) -> None: ...

class AutomatorResponse(_message.Message):
    __slots__ = ["automatorId", "enabled", "timestamp", "approveDevice", "status", "notInitialized", "error", "approveTeamsForUser", "approveTeams", "automatorState", "automatorPublicEccKey", "version"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    APPROVEDEVICE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    NOTINITIALIZED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    APPROVETEAMSFORUSER_FIELD_NUMBER: _ClassVar[int]
    APPROVETEAMS_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORPUBLICECCKEY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    enabled: bool
    timestamp: int
    approveDevice: ApproveDeviceResponse
    status: StatusResponse
    notInitialized: NotInitializedResponse
    error: ErrorResponse
    approveTeamsForUser: ApproveTeamsForUserResponse
    approveTeams: ApproveTeamsResponse
    automatorState: AutomatorState
    automatorPublicEccKey: bytes
    version: _version_pb2.Version
    def __init__(self, automatorId: _Optional[int] = ..., enabled: bool = ..., timestamp: _Optional[int] = ..., approveDevice: _Optional[_Union[ApproveDeviceResponse, _Mapping]] = ..., status: _Optional[_Union[StatusResponse, _Mapping]] = ..., notInitialized: _Optional[_Union[NotInitializedResponse, _Mapping]] = ..., error: _Optional[_Union[ErrorResponse, _Mapping]] = ..., approveTeamsForUser: _Optional[_Union[ApproveTeamsForUserResponse, _Mapping]] = ..., approveTeams: _Optional[_Union[ApproveTeamsResponse, _Mapping]] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., automatorPublicEccKey: _Optional[bytes] = ..., version: _Optional[_Union[_version_pb2.Version, _Mapping]] = ...) -> None: ...

class ApproveDeviceResponse(_message.Message):
    __slots__ = ["approved", "encryptedUserDataKey", "message", "encryptedUserDataKeyType"]
    APPROVED_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDUSERDATAKEY_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDUSERDATAKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    approved: bool
    encryptedUserDataKey: bytes
    message: str
    encryptedUserDataKeyType: _enterprise_pb2.EncryptedKeyType
    def __init__(self, approved: bool = ..., encryptedUserDataKey: _Optional[bytes] = ..., message: _Optional[str] = ..., encryptedUserDataKeyType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ...) -> None: ...

class StatusResponse(_message.Message):
    __slots__ = ["initialized", "enabledTimestamp", "initializedTimestamp", "updatedTimestamp", "numberOfDevicesApproved", "numberOfDevicesDenied", "numberOfErrors", "sslCertificateExpiration", "notInitializedResponse", "config", "numberOfTeamMembershipsApproved", "numberOfTeamMembershipsDenied", "numberOfTeamsApproved", "numberOfTeamsDenied"]
    INITIALIZED_FIELD_NUMBER: _ClassVar[int]
    ENABLEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    INITIALIZEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    UPDATEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFDEVICESAPPROVED_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFDEVICESDENIED_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFERRORS_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    NOTINITIALIZEDRESPONSE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFTEAMMEMBERSHIPSAPPROVED_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFTEAMMEMBERSHIPSDENIED_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFTEAMSAPPROVED_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFTEAMSDENIED_FIELD_NUMBER: _ClassVar[int]
    initialized: bool
    enabledTimestamp: int
    initializedTimestamp: int
    updatedTimestamp: int
    numberOfDevicesApproved: int
    numberOfDevicesDenied: int
    numberOfErrors: int
    sslCertificateExpiration: int
    notInitializedResponse: NotInitializedResponse
    config: bytes
    numberOfTeamMembershipsApproved: int
    numberOfTeamMembershipsDenied: int
    numberOfTeamsApproved: int
    numberOfTeamsDenied: int
    def __init__(self, initialized: bool = ..., enabledTimestamp: _Optional[int] = ..., initializedTimestamp: _Optional[int] = ..., updatedTimestamp: _Optional[int] = ..., numberOfDevicesApproved: _Optional[int] = ..., numberOfDevicesDenied: _Optional[int] = ..., numberOfErrors: _Optional[int] = ..., sslCertificateExpiration: _Optional[int] = ..., notInitializedResponse: _Optional[_Union[NotInitializedResponse, _Mapping]] = ..., config: _Optional[bytes] = ..., numberOfTeamMembershipsApproved: _Optional[int] = ..., numberOfTeamMembershipsDenied: _Optional[int] = ..., numberOfTeamsApproved: _Optional[int] = ..., numberOfTeamsDenied: _Optional[int] = ...) -> None: ...

class ErrorResponse(_message.Message):
    __slots__ = ["message"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class LogEntry(_message.Message):
    __slots__ = ["serverTime", "messageLevel", "component", "message"]
    SERVERTIME_FIELD_NUMBER: _ClassVar[int]
    MESSAGELEVEL_FIELD_NUMBER: _ClassVar[int]
    COMPONENT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    serverTime: str
    messageLevel: str
    component: str
    message: str
    def __init__(self, serverTime: _Optional[str] = ..., messageLevel: _Optional[str] = ..., component: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class AdminResponse(_message.Message):
    __slots__ = ["success", "message", "automatorInfo"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORINFO_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    automatorInfo: _containers.RepeatedCompositeFieldContainer[AutomatorInfo]
    def __init__(self, success: bool = ..., message: _Optional[str] = ..., automatorInfo: _Optional[_Iterable[_Union[AutomatorInfo, _Mapping]]] = ...) -> None: ...

class AutomatorInfo(_message.Message):
    __slots__ = ["automatorId", "nodeId", "name", "enabled", "url", "automatorSkills", "automatorSettingValues", "status", "logEntries", "automatorState", "version"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSKILLS_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSETTINGVALUES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LOGENTRIES_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    nodeId: int
    name: str
    enabled: bool
    url: str
    automatorSkills: _containers.RepeatedCompositeFieldContainer[AutomatorSkill]
    automatorSettingValues: _containers.RepeatedCompositeFieldContainer[AutomatorSettingValue]
    status: StatusResponse
    logEntries: _containers.RepeatedCompositeFieldContainer[LogEntry]
    automatorState: AutomatorState
    version: str
    def __init__(self, automatorId: _Optional[int] = ..., nodeId: _Optional[int] = ..., name: _Optional[str] = ..., enabled: bool = ..., url: _Optional[str] = ..., automatorSkills: _Optional[_Iterable[_Union[AutomatorSkill, _Mapping]]] = ..., automatorSettingValues: _Optional[_Iterable[_Union[AutomatorSettingValue, _Mapping]]] = ..., status: _Optional[_Union[StatusResponse, _Mapping]] = ..., logEntries: _Optional[_Iterable[_Union[LogEntry, _Mapping]]] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., version: _Optional[str] = ...) -> None: ...

class AdminCreateAutomatorRequest(_message.Message):
    __slots__ = ["nodeId", "name", "skill"]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SKILL_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    name: str
    skill: AutomatorSkill
    def __init__(self, nodeId: _Optional[int] = ..., name: _Optional[str] = ..., skill: _Optional[_Union[AutomatorSkill, _Mapping]] = ...) -> None: ...

class AdminDeleteAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminGetAutomatorsOnNodeRequest(_message.Message):
    __slots__ = ["nodeId"]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    def __init__(self, nodeId: _Optional[int] = ...) -> None: ...

class AdminGetAutomatorsForEnterpriseRequest(_message.Message):
    __slots__ = ["enterpriseId"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    def __init__(self, enterpriseId: _Optional[int] = ...) -> None: ...

class AdminGetAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminEnableAutomatorRequest(_message.Message):
    __slots__ = ["automatorId", "enabled"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    enabled: bool
    def __init__(self, automatorId: _Optional[int] = ..., enabled: bool = ...) -> None: ...

class AdminEditAutomatorRequest(_message.Message):
    __slots__ = ["automatorId", "name", "enabled", "url", "skillTypes", "automatorSettingValues"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    SKILLTYPES_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSETTINGVALUES_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    name: str
    enabled: bool
    url: str
    skillTypes: _containers.RepeatedScalarFieldContainer[SkillType]
    automatorSettingValues: _containers.RepeatedCompositeFieldContainer[AutomatorSettingValue]
    def __init__(self, automatorId: _Optional[int] = ..., name: _Optional[str] = ..., enabled: bool = ..., url: _Optional[str] = ..., skillTypes: _Optional[_Iterable[_Union[SkillType, str]]] = ..., automatorSettingValues: _Optional[_Iterable[_Union[AutomatorSettingValue, _Mapping]]] = ...) -> None: ...

class AdminSetupAutomatorRequest(_message.Message):
    __slots__ = ["automatorId", "automatorState", "encryptedEccEnterprisePrivateKey", "encryptedRsaEnterprisePrivateKey", "skillTypes", "encryptedTreeKey"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDECCENTERPRISEPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRSAENTERPRISEPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    SKILLTYPES_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTREEKEY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    automatorState: AutomatorState
    encryptedEccEnterprisePrivateKey: bytes
    encryptedRsaEnterprisePrivateKey: bytes
    skillTypes: _containers.RepeatedScalarFieldContainer[SkillType]
    encryptedTreeKey: bytes
    def __init__(self, automatorId: _Optional[int] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., encryptedEccEnterprisePrivateKey: _Optional[bytes] = ..., encryptedRsaEnterprisePrivateKey: _Optional[bytes] = ..., skillTypes: _Optional[_Iterable[_Union[SkillType, str]]] = ..., encryptedTreeKey: _Optional[bytes] = ...) -> None: ...

class AdminSetupAutomatorResponse(_message.Message):
    __slots__ = ["success", "message", "automatorId", "automatorState", "automatorEccPublicKey"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    automatorId: int
    automatorState: AutomatorState
    automatorEccPublicKey: bytes
    def __init__(self, success: bool = ..., message: _Optional[str] = ..., automatorId: _Optional[int] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., automatorEccPublicKey: _Optional[bytes] = ...) -> None: ...

class AdminAutomatorSkillsRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AutomatorSkill(_message.Message):
    __slots__ = ["skillType", "name", "translatedName"]
    SKILLTYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TRANSLATEDNAME_FIELD_NUMBER: _ClassVar[int]
    skillType: SkillType
    name: str
    translatedName: str
    def __init__(self, skillType: _Optional[_Union[SkillType, str]] = ..., name: _Optional[str] = ..., translatedName: _Optional[str] = ...) -> None: ...

class AdminAutomatorSkillsResponse(_message.Message):
    __slots__ = ["success", "message", "automatorSkills"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSKILLS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    automatorSkills: _containers.RepeatedCompositeFieldContainer[AutomatorSkill]
    def __init__(self, success: bool = ..., message: _Optional[str] = ..., automatorSkills: _Optional[_Iterable[_Union[AutomatorSkill, _Mapping]]] = ...) -> None: ...

class AdminResetAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminInitializeAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminAutomatorLogRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminAutomatorLogClearRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class ApproveTeamsForUserRequest(_message.Message):
    __slots__ = ["automatorId", "ssoAuthenticationProtocolType", "authMessage", "email", "serverEccPublicKeyId", "ipAddress", "userPublicKey", "teamDescription", "isTesting", "isEccOnly", "userPublicKeyEcc"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SSOAUTHENTICATIONPROTOCOLTYPE_FIELD_NUMBER: _ClassVar[int]
    AUTHMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    USERPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    TEAMDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ISTESTING_FIELD_NUMBER: _ClassVar[int]
    ISECCONLY_FIELD_NUMBER: _ClassVar[int]
    USERPUBLICKEYECC_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    ssoAuthenticationProtocolType: SsoAuthenticationProtocolType
    authMessage: str
    email: str
    serverEccPublicKeyId: int
    ipAddress: str
    userPublicKey: bytes
    teamDescription: _containers.RepeatedCompositeFieldContainer[TeamDescription]
    isTesting: bool
    isEccOnly: bool
    userPublicKeyEcc: bytes
    def __init__(self, automatorId: _Optional[int] = ..., ssoAuthenticationProtocolType: _Optional[_Union[SsoAuthenticationProtocolType, str]] = ..., authMessage: _Optional[str] = ..., email: _Optional[str] = ..., serverEccPublicKeyId: _Optional[int] = ..., ipAddress: _Optional[str] = ..., userPublicKey: _Optional[bytes] = ..., teamDescription: _Optional[_Iterable[_Union[TeamDescription, _Mapping]]] = ..., isTesting: bool = ..., isEccOnly: bool = ..., userPublicKeyEcc: _Optional[bytes] = ...) -> None: ...

class TeamDescription(_message.Message):
    __slots__ = ["teamUid", "teamName", "encryptedTeamKey", "encryptedTeamKeyType"]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    TEAMNAME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    teamName: str
    encryptedTeamKey: bytes
    encryptedTeamKeyType: _enterprise_pb2.EncryptedKeyType
    def __init__(self, teamUid: _Optional[bytes] = ..., teamName: _Optional[str] = ..., encryptedTeamKey: _Optional[bytes] = ..., encryptedTeamKeyType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ...) -> None: ...

class ApproveTeamsForUserResponse(_message.Message):
    __slots__ = ["automatorId", "email", "message", "approveTeamResponse"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    APPROVETEAMRESPONSE_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    email: str
    message: str
    approveTeamResponse: _containers.RepeatedCompositeFieldContainer[ApproveOneTeamForUserResponse]
    def __init__(self, automatorId: _Optional[int] = ..., email: _Optional[str] = ..., message: _Optional[str] = ..., approveTeamResponse: _Optional[_Iterable[_Union[ApproveOneTeamForUserResponse, _Mapping]]] = ...) -> None: ...

class ApproveOneTeamForUserResponse(_message.Message):
    __slots__ = ["approved", "message", "teamUid", "teamName", "userEncryptedTeamKey", "userEncryptedTeamKeyType", "userEncryptedTeamKeyByEcc", "userEncryptedTeamKeyByEccType"]
    APPROVED_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    TEAMNAME_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDTEAMKEY_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDTEAMKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDTEAMKEYBYECC_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDTEAMKEYBYECCTYPE_FIELD_NUMBER: _ClassVar[int]
    approved: bool
    message: str
    teamUid: bytes
    teamName: str
    userEncryptedTeamKey: bytes
    userEncryptedTeamKeyType: _enterprise_pb2.EncryptedKeyType
    userEncryptedTeamKeyByEcc: bytes
    userEncryptedTeamKeyByEccType: _enterprise_pb2.EncryptedKeyType
    def __init__(self, approved: bool = ..., message: _Optional[str] = ..., teamUid: _Optional[bytes] = ..., teamName: _Optional[str] = ..., userEncryptedTeamKey: _Optional[bytes] = ..., userEncryptedTeamKeyType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., userEncryptedTeamKeyByEcc: _Optional[bytes] = ..., userEncryptedTeamKeyByEccType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ...) -> None: ...

class ApproveTeamsRequest(_message.Message):
    __slots__ = ["automatorId", "ssoAuthenticationProtocolType", "authMessage", "email", "serverEccPublicKeyId", "ipAddress", "teamDescription", "isEccOnly", "isTesting"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SSOAUTHENTICATIONPROTOCOLTYPE_FIELD_NUMBER: _ClassVar[int]
    AUTHMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    TEAMDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ISECCONLY_FIELD_NUMBER: _ClassVar[int]
    ISTESTING_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    ssoAuthenticationProtocolType: SsoAuthenticationProtocolType
    authMessage: str
    email: str
    serverEccPublicKeyId: int
    ipAddress: str
    teamDescription: _containers.RepeatedCompositeFieldContainer[TeamDescription]
    isEccOnly: bool
    isTesting: bool
    def __init__(self, automatorId: _Optional[int] = ..., ssoAuthenticationProtocolType: _Optional[_Union[SsoAuthenticationProtocolType, str]] = ..., authMessage: _Optional[str] = ..., email: _Optional[str] = ..., serverEccPublicKeyId: _Optional[int] = ..., ipAddress: _Optional[str] = ..., teamDescription: _Optional[_Iterable[_Union[TeamDescription, _Mapping]]] = ..., isEccOnly: bool = ..., isTesting: bool = ...) -> None: ...

class ApproveTeamsResponse(_message.Message):
    __slots__ = ["automatorId", "message", "approveTeamResponse"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    APPROVETEAMRESPONSE_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    message: str
    approveTeamResponse: _containers.RepeatedCompositeFieldContainer[ApproveOneTeamResponse]
    def __init__(self, automatorId: _Optional[int] = ..., message: _Optional[str] = ..., approveTeamResponse: _Optional[_Iterable[_Union[ApproveOneTeamResponse, _Mapping]]] = ...) -> None: ...

class ApproveOneTeamResponse(_message.Message):
    __slots__ = ["approved", "message", "teamUid", "teamName", "encryptedTeamKeyCbc", "encryptedTeamKeyCbcType", "encryptedTeamKeyGcm", "encryptedTeamKeyGcmType", "teamPublicKeyRsa", "encryptedTeamPrivateKeyRsa", "encryptedTeamPrivateKeyRsaType", "teamPublicKeyEcc", "encryptedTeamPrivateKeyEcc", "encryptedTeamPrivateKeyEccType"]
    APPROVED_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    TEAMNAME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEYCBC_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEYCBCTYPE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEYGCM_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEYGCMTYPE_FIELD_NUMBER: _ClassVar[int]
    TEAMPUBLICKEYRSA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMPRIVATEKEYRSA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMPRIVATEKEYRSATYPE_FIELD_NUMBER: _ClassVar[int]
    TEAMPUBLICKEYECC_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMPRIVATEKEYECC_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMPRIVATEKEYECCTYPE_FIELD_NUMBER: _ClassVar[int]
    approved: bool
    message: str
    teamUid: bytes
    teamName: str
    encryptedTeamKeyCbc: bytes
    encryptedTeamKeyCbcType: _enterprise_pb2.EncryptedKeyType
    encryptedTeamKeyGcm: bytes
    encryptedTeamKeyGcmType: _enterprise_pb2.EncryptedKeyType
    teamPublicKeyRsa: bytes
    encryptedTeamPrivateKeyRsa: bytes
    encryptedTeamPrivateKeyRsaType: _enterprise_pb2.EncryptedKeyType
    teamPublicKeyEcc: bytes
    encryptedTeamPrivateKeyEcc: bytes
    encryptedTeamPrivateKeyEccType: _enterprise_pb2.EncryptedKeyType
    def __init__(self, approved: bool = ..., message: _Optional[str] = ..., teamUid: _Optional[bytes] = ..., teamName: _Optional[str] = ..., encryptedTeamKeyCbc: _Optional[bytes] = ..., encryptedTeamKeyCbcType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., encryptedTeamKeyGcm: _Optional[bytes] = ..., encryptedTeamKeyGcmType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., teamPublicKeyRsa: _Optional[bytes] = ..., encryptedTeamPrivateKeyRsa: _Optional[bytes] = ..., encryptedTeamPrivateKeyRsaType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., teamPublicKeyEcc: _Optional[bytes] = ..., encryptedTeamPrivateKeyEcc: _Optional[bytes] = ..., encryptedTeamPrivateKeyEccType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ...) -> None: ...
