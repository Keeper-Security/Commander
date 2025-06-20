import APIRequest_pb2 as _APIRequest_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AuthProtocolType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    SAML2: _ClassVar[AuthProtocolType]

class DataType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    ANY: _ClassVar[DataType]
    BOOLEAN: _ClassVar[DataType]
    INTEGER: _ClassVar[DataType]
    STRING: _ClassVar[DataType]
    BYTES: _ClassVar[DataType]
    URL: _ClassVar[DataType]
    com_keepersecurity_proto_SsoCloud_DataType: _ClassVar[DataType]
    com_keepersecurity_proto_SsoCloud_AuthProtocolType: _ClassVar[DataType]
    com_keepersecurity_proto_SsoCloud_SsoIdpType: _ClassVar[DataType]
    LONG: _ClassVar[DataType]
    TIMESTAMP: _ClassVar[DataType]

class SsoCloudSettingOperationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    SET: _ClassVar[SsoCloudSettingOperationType]
    GET: _ClassVar[SsoCloudSettingOperationType]
    DELETE: _ClassVar[SsoCloudSettingOperationType]
    RESET_TO_DEFAULT: _ClassVar[SsoCloudSettingOperationType]

class SsoIdpType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    XX_UNUSED: _ClassVar[SsoIdpType]
    GENERIC: _ClassVar[SsoIdpType]
    F5: _ClassVar[SsoIdpType]
    GOOGLE: _ClassVar[SsoIdpType]
    OKTA: _ClassVar[SsoIdpType]
    ADFS: _ClassVar[SsoIdpType]
    AZURE: _ClassVar[SsoIdpType]
    ONELOGIN: _ClassVar[SsoIdpType]
    AWS: _ClassVar[SsoIdpType]
    CENTRIFY: _ClassVar[SsoIdpType]
    DUO: _ClassVar[SsoIdpType]
    IBM: _ClassVar[SsoIdpType]
    JUMPCLOUD: _ClassVar[SsoIdpType]
    PING: _ClassVar[SsoIdpType]
    PINGONE: _ClassVar[SsoIdpType]
    RSA: _ClassVar[SsoIdpType]
    SECUREAUTH: _ClassVar[SsoIdpType]
    THALES: _ClassVar[SsoIdpType]
    AUTH0: _ClassVar[SsoIdpType]
    BEYOND: _ClassVar[SsoIdpType]
    HYPR: _ClassVar[SsoIdpType]
    PUREID: _ClassVar[SsoIdpType]
    SDO: _ClassVar[SsoIdpType]
    TRAIT: _ClassVar[SsoIdpType]
    TRANSMIT: _ClassVar[SsoIdpType]
    TRUSONA: _ClassVar[SsoIdpType]
    VERIDIUM: _ClassVar[SsoIdpType]
    CAS: _ClassVar[SsoIdpType]
SAML2: AuthProtocolType
ANY: DataType
BOOLEAN: DataType
INTEGER: DataType
STRING: DataType
BYTES: DataType
URL: DataType
com_keepersecurity_proto_SsoCloud_DataType: DataType
com_keepersecurity_proto_SsoCloud_AuthProtocolType: DataType
com_keepersecurity_proto_SsoCloud_SsoIdpType: DataType
LONG: DataType
TIMESTAMP: DataType
SET: SsoCloudSettingOperationType
GET: SsoCloudSettingOperationType
DELETE: SsoCloudSettingOperationType
RESET_TO_DEFAULT: SsoCloudSettingOperationType
XX_UNUSED: SsoIdpType
GENERIC: SsoIdpType
F5: SsoIdpType
GOOGLE: SsoIdpType
OKTA: SsoIdpType
ADFS: SsoIdpType
AZURE: SsoIdpType
ONELOGIN: SsoIdpType
AWS: SsoIdpType
CENTRIFY: SsoIdpType
DUO: SsoIdpType
IBM: SsoIdpType
JUMPCLOUD: SsoIdpType
PING: SsoIdpType
PINGONE: SsoIdpType
RSA: SsoIdpType
SECUREAUTH: SsoIdpType
THALES: SsoIdpType
AUTH0: SsoIdpType
BEYOND: SsoIdpType
HYPR: SsoIdpType
PUREID: SsoIdpType
SDO: SsoIdpType
TRAIT: SsoIdpType
TRANSMIT: SsoIdpType
TRUSONA: SsoIdpType
VERIDIUM: SsoIdpType
CAS: SsoIdpType

class SsoCloudSettingValue(_message.Message):
    __slots__ = ["settingId", "settingName", "label", "value", "valueType", "lastModified", "isFromFile", "isEditable", "isRequired"]
    SETTINGID_FIELD_NUMBER: _ClassVar[int]
    SETTINGNAME_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    VALUETYPE_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    ISFROMFILE_FIELD_NUMBER: _ClassVar[int]
    ISEDITABLE_FIELD_NUMBER: _ClassVar[int]
    ISREQUIRED_FIELD_NUMBER: _ClassVar[int]
    settingId: int
    settingName: str
    label: str
    value: str
    valueType: DataType
    lastModified: str
    isFromFile: bool
    isEditable: bool
    isRequired: bool
    def __init__(self, settingId: _Optional[int] = ..., settingName: _Optional[str] = ..., label: _Optional[str] = ..., value: _Optional[str] = ..., valueType: _Optional[_Union[DataType, str]] = ..., lastModified: _Optional[str] = ..., isFromFile: bool = ..., isEditable: bool = ..., isRequired: bool = ...) -> None: ...

class SsoCloudSettingAction(_message.Message):
    __slots__ = ["settingId", "settingName", "operation", "value"]
    SETTINGID_FIELD_NUMBER: _ClassVar[int]
    SETTINGNAME_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    settingId: int
    settingName: str
    operation: SsoCloudSettingOperationType
    value: str
    def __init__(self, settingId: _Optional[int] = ..., settingName: _Optional[str] = ..., operation: _Optional[_Union[SsoCloudSettingOperationType, str]] = ..., value: _Optional[str] = ...) -> None: ...

class SsoCloudConfigurationRequest(_message.Message):
    __slots__ = ["ssoServiceProviderId", "ssoSpConfigurationId", "name", "ssoAuthProtocolType", "ssoCloudSettingAction"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SSOAUTHPROTOCOLTYPE_FIELD_NUMBER: _ClassVar[int]
    SSOCLOUDSETTINGACTION_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    ssoSpConfigurationId: int
    name: str
    ssoAuthProtocolType: AuthProtocolType
    ssoCloudSettingAction: _containers.RepeatedCompositeFieldContainer[SsoCloudSettingAction]
    def __init__(self, ssoServiceProviderId: _Optional[int] = ..., ssoSpConfigurationId: _Optional[int] = ..., name: _Optional[str] = ..., ssoAuthProtocolType: _Optional[_Union[AuthProtocolType, str]] = ..., ssoCloudSettingAction: _Optional[_Iterable[_Union[SsoCloudSettingAction, _Mapping]]] = ...) -> None: ...

class SsoSharedConfigItem(_message.Message):
    __slots__ = ["ssoSpConfigurationId", "ssoServiceProviderId", "ssoNodeId"]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    SSONODEID_FIELD_NUMBER: _ClassVar[int]
    ssoSpConfigurationId: int
    ssoServiceProviderId: int
    ssoNodeId: int
    def __init__(self, ssoSpConfigurationId: _Optional[int] = ..., ssoServiceProviderId: _Optional[int] = ..., ssoNodeId: _Optional[int] = ...) -> None: ...

class SsoCloudConfigurationResponse(_message.Message):
    __slots__ = ["ssoServiceProviderId", "ssoSpConfigurationId", "enterpriseId", "name", "protocol", "lastModified", "ssoCloudSettingValue", "isShared", "sharedConfigs"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    SSOCLOUDSETTINGVALUE_FIELD_NUMBER: _ClassVar[int]
    ISSHARED_FIELD_NUMBER: _ClassVar[int]
    SHAREDCONFIGS_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    ssoSpConfigurationId: int
    enterpriseId: int
    name: str
    protocol: str
    lastModified: str
    ssoCloudSettingValue: _containers.RepeatedCompositeFieldContainer[SsoCloudSettingValue]
    isShared: bool
    sharedConfigs: _containers.RepeatedCompositeFieldContainer[SsoSharedConfigItem]
    def __init__(self, ssoServiceProviderId: _Optional[int] = ..., ssoSpConfigurationId: _Optional[int] = ..., enterpriseId: _Optional[int] = ..., name: _Optional[str] = ..., protocol: _Optional[str] = ..., lastModified: _Optional[str] = ..., ssoCloudSettingValue: _Optional[_Iterable[_Union[SsoCloudSettingValue, _Mapping]]] = ..., isShared: bool = ..., sharedConfigs: _Optional[_Iterable[_Union[SsoSharedConfigItem, _Mapping]]] = ...) -> None: ...

class SsoIdpTypeRequest(_message.Message):
    __slots__ = ["ssoIdpTypeId", "tag", "label"]
    SSOIDPTYPEID_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ssoIdpTypeId: int
    tag: str
    label: str
    def __init__(self, ssoIdpTypeId: _Optional[int] = ..., tag: _Optional[str] = ..., label: _Optional[str] = ...) -> None: ...

class SsoIdpTypeResponse(_message.Message):
    __slots__ = ["ssoIdpTypeId", "tag", "label"]
    SSOIDPTYPEID_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ssoIdpTypeId: int
    tag: int
    label: int
    def __init__(self, ssoIdpTypeId: _Optional[int] = ..., tag: _Optional[int] = ..., label: _Optional[int] = ...) -> None: ...

class SsoCloudSAMLLogRequest(_message.Message):
    __slots__ = ["ssoServiceProviderId"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    def __init__(self, ssoServiceProviderId: _Optional[int] = ...) -> None: ...

class SsoCloudSAMLLogEntry(_message.Message):
    __slots__ = ["serverTime", "direction", "messageType", "messageIssued", "fromEntityId", "samlStatus", "relayState", "samlContent", "isSigned", "isOK"]
    SERVERTIME_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGEISSUED_FIELD_NUMBER: _ClassVar[int]
    FROMENTITYID_FIELD_NUMBER: _ClassVar[int]
    SAMLSTATUS_FIELD_NUMBER: _ClassVar[int]
    RELAYSTATE_FIELD_NUMBER: _ClassVar[int]
    SAMLCONTENT_FIELD_NUMBER: _ClassVar[int]
    ISSIGNED_FIELD_NUMBER: _ClassVar[int]
    ISOK_FIELD_NUMBER: _ClassVar[int]
    serverTime: str
    direction: str
    messageType: str
    messageIssued: str
    fromEntityId: str
    samlStatus: str
    relayState: str
    samlContent: str
    isSigned: bool
    isOK: bool
    def __init__(self, serverTime: _Optional[str] = ..., direction: _Optional[str] = ..., messageType: _Optional[str] = ..., messageIssued: _Optional[str] = ..., fromEntityId: _Optional[str] = ..., samlStatus: _Optional[str] = ..., relayState: _Optional[str] = ..., samlContent: _Optional[str] = ..., isSigned: bool = ..., isOK: bool = ...) -> None: ...

class SsoCloudSAMLLogResponse(_message.Message):
    __slots__ = ["ssoServiceProviderId", "entry"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    entry: _containers.RepeatedCompositeFieldContainer[SsoCloudSAMLLogEntry]
    def __init__(self, ssoServiceProviderId: _Optional[int] = ..., entry: _Optional[_Iterable[_Union[SsoCloudSAMLLogEntry, _Mapping]]] = ...) -> None: ...

class SsoCloudServiceProviderUpdateRequest(_message.Message):
    __slots__ = ["ssoServiceProviderId", "ssoSpConfigurationId"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    ssoSpConfigurationId: int
    def __init__(self, ssoServiceProviderId: _Optional[int] = ..., ssoSpConfigurationId: _Optional[int] = ...) -> None: ...

class SsoCloudIdpMetadataRequest(_message.Message):
    __slots__ = ["ssoSpConfigurationId", "filename", "content"]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    ssoSpConfigurationId: int
    filename: str
    content: bytes
    def __init__(self, ssoSpConfigurationId: _Optional[int] = ..., filename: _Optional[str] = ..., content: _Optional[bytes] = ...) -> None: ...

class SsoCloudIdpMetadataSupportRequest(_message.Message):
    __slots__ = ["ssoServiceProviderId", "ssoSpConfigurationId", "ssoEnterpriseId", "filename", "content"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    SSOENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    ssoSpConfigurationId: int
    ssoEnterpriseId: int
    filename: str
    content: bytes
    def __init__(self, ssoServiceProviderId: _Optional[int] = ..., ssoSpConfigurationId: _Optional[int] = ..., ssoEnterpriseId: _Optional[int] = ..., filename: _Optional[str] = ..., content: _Optional[bytes] = ...) -> None: ...

class SsoCloudConfigurationValidationRequest(_message.Message):
    __slots__ = ["ssoSpConfigurationId"]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    ssoSpConfigurationId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, ssoSpConfigurationId: _Optional[_Iterable[int]] = ...) -> None: ...

class ValidationContent(_message.Message):
    __slots__ = ["ssoSpConfigurationId", "isSuccessful", "errorMessage"]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    ISSUCCESSFUL_FIELD_NUMBER: _ClassVar[int]
    ERRORMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ssoSpConfigurationId: int
    isSuccessful: bool
    errorMessage: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ssoSpConfigurationId: _Optional[int] = ..., isSuccessful: bool = ..., errorMessage: _Optional[_Iterable[str]] = ...) -> None: ...

class SsoCloudConfigurationValidationResponse(_message.Message):
    __slots__ = ["validationContent"]
    VALIDATIONCONTENT_FIELD_NUMBER: _ClassVar[int]
    validationContent: _containers.RepeatedCompositeFieldContainer[ValidationContent]
    def __init__(self, validationContent: _Optional[_Iterable[_Union[ValidationContent, _Mapping]]] = ...) -> None: ...

class SsoCloudServiceProviderConfigurationListRequest(_message.Message):
    __slots__ = ["ssoServiceProviderId"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    def __init__(self, ssoServiceProviderId: _Optional[int] = ...) -> None: ...

class ConfigurationListItem(_message.Message):
    __slots__ = ["ssoSpConfigurationId", "name", "isSelected", "ssoServiceProviderId"]
    SSOSPCONFIGURATIONID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ISSELECTED_FIELD_NUMBER: _ClassVar[int]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    ssoSpConfigurationId: int
    name: str
    isSelected: bool
    ssoServiceProviderId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, ssoSpConfigurationId: _Optional[int] = ..., name: _Optional[str] = ..., isSelected: bool = ..., ssoServiceProviderId: _Optional[_Iterable[int]] = ...) -> None: ...

class SsoCloudServiceProviderConfigurationListResponse(_message.Message):
    __slots__ = ["configurationItem"]
    CONFIGURATIONITEM_FIELD_NUMBER: _ClassVar[int]
    configurationItem: _containers.RepeatedCompositeFieldContainer[ConfigurationListItem]
    def __init__(self, configurationItem: _Optional[_Iterable[_Union[ConfigurationListItem, _Mapping]]] = ...) -> None: ...

class SsoCloudRequest(_message.Message):
    __slots__ = ["messageSessionUid", "clientVersion", "embedded", "json", "dest", "idpSessionId", "forceLogin", "username", "detached"]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    EMBEDDED_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    DEST_FIELD_NUMBER: _ClassVar[int]
    IDPSESSIONID_FIELD_NUMBER: _ClassVar[int]
    FORCELOGIN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    DETACHED_FIELD_NUMBER: _ClassVar[int]
    messageSessionUid: bytes
    clientVersion: str
    embedded: bool
    json: bool
    dest: str
    idpSessionId: str
    forceLogin: bool
    username: str
    detached: bool
    def __init__(self, messageSessionUid: _Optional[bytes] = ..., clientVersion: _Optional[str] = ..., embedded: bool = ..., json: bool = ..., dest: _Optional[str] = ..., idpSessionId: _Optional[str] = ..., forceLogin: bool = ..., username: _Optional[str] = ..., detached: bool = ...) -> None: ...

class SsoCloudResponse(_message.Message):
    __slots__ = ["command", "messageSessionUid", "email", "encryptedLoginToken", "providerName", "idpSessionId", "encryptedSessionToken", "errorToken"]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    PROVIDERNAME_FIELD_NUMBER: _ClassVar[int]
    IDPSESSIONID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    ERRORTOKEN_FIELD_NUMBER: _ClassVar[int]
    command: str
    messageSessionUid: bytes
    email: str
    encryptedLoginToken: bytes
    providerName: str
    idpSessionId: str
    encryptedSessionToken: bytes
    errorToken: str
    def __init__(self, command: _Optional[str] = ..., messageSessionUid: _Optional[bytes] = ..., email: _Optional[str] = ..., encryptedLoginToken: _Optional[bytes] = ..., providerName: _Optional[str] = ..., idpSessionId: _Optional[str] = ..., encryptedSessionToken: _Optional[bytes] = ..., errorToken: _Optional[str] = ...) -> None: ...

class SsoCloudLogRequest(_message.Message):
    __slots__ = ["ssoServiceProviderId", "serviceName", "serviceId"]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    SERVICENAME_FIELD_NUMBER: _ClassVar[int]
    SERVICEID_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    serviceName: str
    serviceId: int
    def __init__(self, ssoServiceProviderId: _Optional[int] = ..., serviceName: _Optional[str] = ..., serviceId: _Optional[int] = ...) -> None: ...

class SamlRelayState(_message.Message):
    __slots__ = ["messageSessionUid", "username", "embedded", "json", "destId", "keyId", "supportedLanguage", "checksum", "isGeneratedUid", "deviceId", "detached"]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    EMBEDDED_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    DESTID_FIELD_NUMBER: _ClassVar[int]
    KEYID_FIELD_NUMBER: _ClassVar[int]
    SUPPORTEDLANGUAGE_FIELD_NUMBER: _ClassVar[int]
    CHECKSUM_FIELD_NUMBER: _ClassVar[int]
    ISGENERATEDUID_FIELD_NUMBER: _ClassVar[int]
    DEVICEID_FIELD_NUMBER: _ClassVar[int]
    DETACHED_FIELD_NUMBER: _ClassVar[int]
    messageSessionUid: bytes
    username: str
    embedded: bool
    json: bool
    destId: int
    keyId: int
    supportedLanguage: _APIRequest_pb2.SupportedLanguage
    checksum: int
    isGeneratedUid: bool
    deviceId: int
    detached: bool
    def __init__(self, messageSessionUid: _Optional[bytes] = ..., username: _Optional[str] = ..., embedded: bool = ..., json: bool = ..., destId: _Optional[int] = ..., keyId: _Optional[int] = ..., supportedLanguage: _Optional[_Union[_APIRequest_pb2.SupportedLanguage, str]] = ..., checksum: _Optional[int] = ..., isGeneratedUid: bool = ..., deviceId: _Optional[int] = ..., detached: bool = ...) -> None: ...

class SsoCloudMigrationStatusRequest(_message.Message):
    __slots__ = ["nodeId", "fullStatus", "includeMigratedUsers", "limit"]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    FULLSTATUS_FIELD_NUMBER: _ClassVar[int]
    INCLUDEMIGRATEDUSERS_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    fullStatus: bool
    includeMigratedUsers: bool
    limit: int
    def __init__(self, nodeId: _Optional[int] = ..., fullStatus: bool = ..., includeMigratedUsers: bool = ..., limit: _Optional[int] = ...) -> None: ...

class SsoCloudMigrationStatusResponse(_message.Message):
    __slots__ = ["success", "message", "nodeId", "ssoConnectId", "ssoConnectName", "ssoConnectCloudId", "ssoConnectCloudName", "totalUsersCount", "usersMigratedCount", "migratedUsers", "unmigratedUsers"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    SSOCONNECTID_FIELD_NUMBER: _ClassVar[int]
    SSOCONNECTNAME_FIELD_NUMBER: _ClassVar[int]
    SSOCONNECTCLOUDID_FIELD_NUMBER: _ClassVar[int]
    SSOCONNECTCLOUDNAME_FIELD_NUMBER: _ClassVar[int]
    TOTALUSERSCOUNT_FIELD_NUMBER: _ClassVar[int]
    USERSMIGRATEDCOUNT_FIELD_NUMBER: _ClassVar[int]
    MIGRATEDUSERS_FIELD_NUMBER: _ClassVar[int]
    UNMIGRATEDUSERS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    nodeId: int
    ssoConnectId: int
    ssoConnectName: str
    ssoConnectCloudId: int
    ssoConnectCloudName: str
    totalUsersCount: int
    usersMigratedCount: int
    migratedUsers: _containers.RepeatedCompositeFieldContainer[SsoCloudMigrationUserInfo]
    unmigratedUsers: _containers.RepeatedCompositeFieldContainer[SsoCloudMigrationUserInfo]
    def __init__(self, success: bool = ..., message: _Optional[str] = ..., nodeId: _Optional[int] = ..., ssoConnectId: _Optional[int] = ..., ssoConnectName: _Optional[str] = ..., ssoConnectCloudId: _Optional[int] = ..., ssoConnectCloudName: _Optional[str] = ..., totalUsersCount: _Optional[int] = ..., usersMigratedCount: _Optional[int] = ..., migratedUsers: _Optional[_Iterable[_Union[SsoCloudMigrationUserInfo, _Mapping]]] = ..., unmigratedUsers: _Optional[_Iterable[_Union[SsoCloudMigrationUserInfo, _Mapping]]] = ...) -> None: ...

class SsoCloudMigrationUserInfo(_message.Message):
    __slots__ = ["userId", "email", "fullName", "isMigrated"]
    USERID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    ISMIGRATED_FIELD_NUMBER: _ClassVar[int]
    userId: int
    email: str
    fullName: str
    isMigrated: bool
    def __init__(self, userId: _Optional[int] = ..., email: _Optional[str] = ..., fullName: _Optional[str] = ..., isMigrated: bool = ...) -> None: ...
