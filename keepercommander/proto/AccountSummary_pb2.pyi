import APIRequest_pb2 as _APIRequest_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AccountSummaryRequest(_message.Message):
    __slots__ = ["summaryVersion", "includeRecentActivity"]
    SUMMARYVERSION_FIELD_NUMBER: _ClassVar[int]
    INCLUDERECENTACTIVITY_FIELD_NUMBER: _ClassVar[int]
    summaryVersion: int
    includeRecentActivity: bool
    def __init__(self, summaryVersion: _Optional[int] = ..., includeRecentActivity: bool = ...) -> None: ...

class AccountSummaryElements(_message.Message):
    __slots__ = ["clientKey", "settings", "keysInfo", "syncLogs", "isEnterpriseAdmin", "license", "group", "Enforcements", "Images", "personalLicense", "fixSharedFolderRecords", "usernames", "devices", "isShareAdmin", "accountRecovery", "accountRecoveryPrompt", "minMasterPasswordLengthNoPrompt", "forbidKeyType2"]
    CLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    KEYSINFO_FIELD_NUMBER: _ClassVar[int]
    SYNCLOGS_FIELD_NUMBER: _ClassVar[int]
    ISENTERPRISEADMIN_FIELD_NUMBER: _ClassVar[int]
    LICENSE_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    ENFORCEMENTS_FIELD_NUMBER: _ClassVar[int]
    IMAGES_FIELD_NUMBER: _ClassVar[int]
    PERSONALLICENSE_FIELD_NUMBER: _ClassVar[int]
    FIXSHAREDFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    USERNAMES_FIELD_NUMBER: _ClassVar[int]
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    ISSHAREADMIN_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTRECOVERY_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTRECOVERYPROMPT_FIELD_NUMBER: _ClassVar[int]
    MINMASTERPASSWORDLENGTHNOPROMPT_FIELD_NUMBER: _ClassVar[int]
    FORBIDKEYTYPE2_FIELD_NUMBER: _ClassVar[int]
    clientKey: bytes
    settings: Settings
    keysInfo: KeysInfo
    syncLogs: _containers.RepeatedCompositeFieldContainer[SyncLog]
    isEnterpriseAdmin: bool
    license: License
    group: Group
    Enforcements: Enforcements
    Images: _containers.RepeatedCompositeFieldContainer[KeyValue]
    personalLicense: License
    fixSharedFolderRecords: bool
    usernames: _containers.RepeatedScalarFieldContainer[str]
    devices: _containers.RepeatedCompositeFieldContainer[DeviceInfo]
    isShareAdmin: bool
    accountRecovery: bool
    accountRecoveryPrompt: bool
    minMasterPasswordLengthNoPrompt: int
    forbidKeyType2: bool
    def __init__(self, clientKey: _Optional[bytes] = ..., settings: _Optional[_Union[Settings, _Mapping]] = ..., keysInfo: _Optional[_Union[KeysInfo, _Mapping]] = ..., syncLogs: _Optional[_Iterable[_Union[SyncLog, _Mapping]]] = ..., isEnterpriseAdmin: bool = ..., license: _Optional[_Union[License, _Mapping]] = ..., group: _Optional[_Union[Group, _Mapping]] = ..., Enforcements: _Optional[_Union[Enforcements, _Mapping]] = ..., Images: _Optional[_Iterable[_Union[KeyValue, _Mapping]]] = ..., personalLicense: _Optional[_Union[License, _Mapping]] = ..., fixSharedFolderRecords: bool = ..., usernames: _Optional[_Iterable[str]] = ..., devices: _Optional[_Iterable[_Union[DeviceInfo, _Mapping]]] = ..., isShareAdmin: bool = ..., accountRecovery: bool = ..., accountRecoveryPrompt: bool = ..., minMasterPasswordLengthNoPrompt: _Optional[int] = ..., forbidKeyType2: bool = ...) -> None: ...

class DeviceInfo(_message.Message):
    __slots__ = ["encryptedDeviceToken", "deviceName", "deviceStatus", "devicePublicKey", "encryptedDataKeyDoNotUse", "clientVersion", "username", "ipAddress", "approveRequestTime", "encryptedDataKeyPresent", "groupId", "devicePlatform", "clientFormFactor"]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICESTATUS_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEYDONOTUSE_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    APPROVEREQUESTTIME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEYPRESENT_FIELD_NUMBER: _ClassVar[int]
    GROUPID_FIELD_NUMBER: _ClassVar[int]
    DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
    CLIENTFORMFACTOR_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    deviceName: str
    deviceStatus: _APIRequest_pb2.DeviceStatus
    devicePublicKey: bytes
    encryptedDataKeyDoNotUse: bytes
    clientVersion: str
    username: str
    ipAddress: str
    approveRequestTime: int
    encryptedDataKeyPresent: bool
    groupId: int
    devicePlatform: str
    clientFormFactor: _APIRequest_pb2.ClientFormFactor
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., deviceName: _Optional[str] = ..., deviceStatus: _Optional[_Union[_APIRequest_pb2.DeviceStatus, str]] = ..., devicePublicKey: _Optional[bytes] = ..., encryptedDataKeyDoNotUse: _Optional[bytes] = ..., clientVersion: _Optional[str] = ..., username: _Optional[str] = ..., ipAddress: _Optional[str] = ..., approveRequestTime: _Optional[int] = ..., encryptedDataKeyPresent: bool = ..., groupId: _Optional[int] = ..., devicePlatform: _Optional[str] = ..., clientFormFactor: _Optional[_Union[_APIRequest_pb2.ClientFormFactor, str]] = ...) -> None: ...

class KeysInfo(_message.Message):
    __slots__ = ["encryptionParams", "encryptedDataKey", "dataKeyBackupDate", "userAuthUid", "encryptedPrivateKey", "encryptedEccPrivateKey", "eccPublicKey"]
    ENCRYPTIONPARAMS_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    DATAKEYBACKUPDATE_FIELD_NUMBER: _ClassVar[int]
    USERAUTHUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDECCPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    encryptionParams: bytes
    encryptedDataKey: bytes
    dataKeyBackupDate: float
    userAuthUid: bytes
    encryptedPrivateKey: bytes
    encryptedEccPrivateKey: bytes
    eccPublicKey: bytes
    def __init__(self, encryptionParams: _Optional[bytes] = ..., encryptedDataKey: _Optional[bytes] = ..., dataKeyBackupDate: _Optional[float] = ..., userAuthUid: _Optional[bytes] = ..., encryptedPrivateKey: _Optional[bytes] = ..., encryptedEccPrivateKey: _Optional[bytes] = ..., eccPublicKey: _Optional[bytes] = ...) -> None: ...

class SyncLog(_message.Message):
    __slots__ = ["countryName", "secondsAgo", "deviceName", "countryCode", "deviceUID", "ipAddress"]
    COUNTRYNAME_FIELD_NUMBER: _ClassVar[int]
    SECONDSAGO_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    COUNTRYCODE_FIELD_NUMBER: _ClassVar[int]
    DEVICEUID_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    countryName: str
    secondsAgo: int
    deviceName: str
    countryCode: str
    deviceUID: bytes
    ipAddress: str
    def __init__(self, countryName: _Optional[str] = ..., secondsAgo: _Optional[int] = ..., deviceName: _Optional[str] = ..., countryCode: _Optional[str] = ..., deviceUID: _Optional[bytes] = ..., ipAddress: _Optional[str] = ...) -> None: ...

class License(_message.Message):
    __slots__ = ["subscriptionCode", "productTypeId", "productTypeName", "expirationDate", "secondsUntilExpiration", "maxDevices", "filePlanType", "bytesUsed", "bytesTotal", "secondsUntilStorageExpiration", "storageExpirationDate", "hasAutoRenewableAppstoreSubscription", "accountType", "uploadsRemaining", "enterpriseId", "chatEnabled", "auditAndReportingEnabled", "breachWatchFeatureDisable", "accountUid", "allowPersonalLicense", "licensedBy", "email", "breachWatchEnabled", "breachWatchScanned", "breachWatchExpiration", "breachWatchDateCreated", "error", "expiration", "storageExpiration", "uploadsCount", "units", "pendingEnterprise", "isPamEnabled"]
    SUBSCRIPTIONCODE_FIELD_NUMBER: _ClassVar[int]
    PRODUCTTYPEID_FIELD_NUMBER: _ClassVar[int]
    PRODUCTTYPENAME_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    SECONDSUNTILEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    MAXDEVICES_FIELD_NUMBER: _ClassVar[int]
    FILEPLANTYPE_FIELD_NUMBER: _ClassVar[int]
    BYTESUSED_FIELD_NUMBER: _ClassVar[int]
    BYTESTOTAL_FIELD_NUMBER: _ClassVar[int]
    SECONDSUNTILSTORAGEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    STORAGEEXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    HASAUTORENEWABLEAPPSTORESUBSCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    UPLOADSREMAINING_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    CHATENABLED_FIELD_NUMBER: _ClassVar[int]
    AUDITANDREPORTINGENABLED_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHFEATUREDISABLE_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    ALLOWPERSONALLICENSE_FIELD_NUMBER: _ClassVar[int]
    LICENSEDBY_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHENABLED_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHSCANNED_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHDATECREATED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    STORAGEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    UPLOADSCOUNT_FIELD_NUMBER: _ClassVar[int]
    UNITS_FIELD_NUMBER: _ClassVar[int]
    PENDINGENTERPRISE_FIELD_NUMBER: _ClassVar[int]
    ISPAMENABLED_FIELD_NUMBER: _ClassVar[int]
    subscriptionCode: str
    productTypeId: int
    productTypeName: str
    expirationDate: str
    secondsUntilExpiration: int
    maxDevices: int
    filePlanType: int
    bytesUsed: int
    bytesTotal: int
    secondsUntilStorageExpiration: int
    storageExpirationDate: str
    hasAutoRenewableAppstoreSubscription: bool
    accountType: int
    uploadsRemaining: int
    enterpriseId: int
    chatEnabled: bool
    auditAndReportingEnabled: bool
    breachWatchFeatureDisable: bool
    accountUid: bytes
    allowPersonalLicense: bool
    licensedBy: str
    email: str
    breachWatchEnabled: bool
    breachWatchScanned: bool
    breachWatchExpiration: int
    breachWatchDateCreated: int
    error: Result
    expiration: int
    storageExpiration: int
    uploadsCount: int
    units: int
    pendingEnterprise: bool
    isPamEnabled: bool
    def __init__(self, subscriptionCode: _Optional[str] = ..., productTypeId: _Optional[int] = ..., productTypeName: _Optional[str] = ..., expirationDate: _Optional[str] = ..., secondsUntilExpiration: _Optional[int] = ..., maxDevices: _Optional[int] = ..., filePlanType: _Optional[int] = ..., bytesUsed: _Optional[int] = ..., bytesTotal: _Optional[int] = ..., secondsUntilStorageExpiration: _Optional[int] = ..., storageExpirationDate: _Optional[str] = ..., hasAutoRenewableAppstoreSubscription: bool = ..., accountType: _Optional[int] = ..., uploadsRemaining: _Optional[int] = ..., enterpriseId: _Optional[int] = ..., chatEnabled: bool = ..., auditAndReportingEnabled: bool = ..., breachWatchFeatureDisable: bool = ..., accountUid: _Optional[bytes] = ..., allowPersonalLicense: bool = ..., licensedBy: _Optional[str] = ..., email: _Optional[str] = ..., breachWatchEnabled: bool = ..., breachWatchScanned: bool = ..., breachWatchExpiration: _Optional[int] = ..., breachWatchDateCreated: _Optional[int] = ..., error: _Optional[_Union[Result, _Mapping]] = ..., expiration: _Optional[int] = ..., storageExpiration: _Optional[int] = ..., uploadsCount: _Optional[int] = ..., units: _Optional[int] = ..., pendingEnterprise: bool = ..., isPamEnabled: bool = ...) -> None: ...

class AddOn(_message.Message):
    __slots__ = ["licenseKeyId", "name", "expirationDate", "createdDate", "isTrial", "enabled", "scanned", "featureDisable"]
    LICENSEKEYID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    CREATEDDATE_FIELD_NUMBER: _ClassVar[int]
    ISTRIAL_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    SCANNED_FIELD_NUMBER: _ClassVar[int]
    FEATUREDISABLE_FIELD_NUMBER: _ClassVar[int]
    licenseKeyId: int
    name: str
    expirationDate: int
    createdDate: int
    isTrial: bool
    enabled: bool
    scanned: bool
    featureDisable: bool
    def __init__(self, licenseKeyId: _Optional[int] = ..., name: _Optional[str] = ..., expirationDate: _Optional[int] = ..., createdDate: _Optional[int] = ..., isTrial: bool = ..., enabled: bool = ..., scanned: bool = ..., featureDisable: bool = ...) -> None: ...

class Settings(_message.Message):
    __slots__ = ["audit", "mustPerformAccountShareBy", "shareAccountTo", "rules", "passwordRulesIntro", "autoBackupDays", "theme", "channel", "channelValue", "rsaConfigured", "emailVerified", "masterPasswordLastModified", "accountFolderKey", "securityKeys", "keyValues", "ssoUser", "onlineAccessOnly", "masterPasswordExpiry", "twoFactorRequired", "disallowExport", "restrictFiles", "restrictAllSharing", "restrictSharing", "restrictSharingIncomingAll", "restrictSharingIncomingEnterprise", "logoutTimer", "persistentLogin", "ipDisableAutoApprove", "shareDataKeyWithEccPublicKey", "shareDataKeyWithDevicePublicKey", "RecordTypesCounter", "RecordTypesEnterpriseCounter", "recordTypesEnabled", "canManageRecordTypes", "recordTypesPAMCounter", "logoutTimerMinutes", "securityKeysNoUserVerify", "channels", "personalUsernames"]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    MUSTPERFORMACCOUNTSHAREBY_FIELD_NUMBER: _ClassVar[int]
    SHAREACCOUNTTO_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    PASSWORDRULESINTRO_FIELD_NUMBER: _ClassVar[int]
    AUTOBACKUPDAYS_FIELD_NUMBER: _ClassVar[int]
    THEME_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    CHANNELVALUE_FIELD_NUMBER: _ClassVar[int]
    RSACONFIGURED_FIELD_NUMBER: _ClassVar[int]
    EMAILVERIFIED_FIELD_NUMBER: _ClassVar[int]
    MASTERPASSWORDLASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    SECURITYKEYS_FIELD_NUMBER: _ClassVar[int]
    KEYVALUES_FIELD_NUMBER: _ClassVar[int]
    SSOUSER_FIELD_NUMBER: _ClassVar[int]
    ONLINEACCESSONLY_FIELD_NUMBER: _ClassVar[int]
    MASTERPASSWORDEXPIRY_FIELD_NUMBER: _ClassVar[int]
    TWOFACTORREQUIRED_FIELD_NUMBER: _ClassVar[int]
    DISALLOWEXPORT_FIELD_NUMBER: _ClassVar[int]
    RESTRICTFILES_FIELD_NUMBER: _ClassVar[int]
    RESTRICTALLSHARING_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHARING_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHARINGINCOMINGALL_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHARINGINCOMINGENTERPRISE_FIELD_NUMBER: _ClassVar[int]
    LOGOUTTIMER_FIELD_NUMBER: _ClassVar[int]
    PERSISTENTLOGIN_FIELD_NUMBER: _ClassVar[int]
    IPDISABLEAUTOAPPROVE_FIELD_NUMBER: _ClassVar[int]
    SHAREDATAKEYWITHECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    SHAREDATAKEYWITHDEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    RECORDTYPESCOUNTER_FIELD_NUMBER: _ClassVar[int]
    RECORDTYPESENTERPRISECOUNTER_FIELD_NUMBER: _ClassVar[int]
    RECORDTYPESENABLED_FIELD_NUMBER: _ClassVar[int]
    CANMANAGERECORDTYPES_FIELD_NUMBER: _ClassVar[int]
    RECORDTYPESPAMCOUNTER_FIELD_NUMBER: _ClassVar[int]
    LOGOUTTIMERMINUTES_FIELD_NUMBER: _ClassVar[int]
    SECURITYKEYSNOUSERVERIFY_FIELD_NUMBER: _ClassVar[int]
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    PERSONALUSERNAMES_FIELD_NUMBER: _ClassVar[int]
    audit: bool
    mustPerformAccountShareBy: int
    shareAccountTo: _containers.RepeatedCompositeFieldContainer[MissingAccountShareKey]
    rules: _containers.RepeatedCompositeFieldContainer[PasswordRule]
    passwordRulesIntro: str
    autoBackupDays: int
    theme: str
    channel: str
    channelValue: str
    rsaConfigured: bool
    emailVerified: bool
    masterPasswordLastModified: float
    accountFolderKey: bytes
    securityKeys: _containers.RepeatedCompositeFieldContainer[SecurityKey]
    keyValues: _containers.RepeatedCompositeFieldContainer[KeyValue]
    ssoUser: bool
    onlineAccessOnly: bool
    masterPasswordExpiry: int
    twoFactorRequired: bool
    disallowExport: bool
    restrictFiles: bool
    restrictAllSharing: bool
    restrictSharing: bool
    restrictSharingIncomingAll: bool
    restrictSharingIncomingEnterprise: bool
    logoutTimer: int
    persistentLogin: bool
    ipDisableAutoApprove: bool
    shareDataKeyWithEccPublicKey: bool
    shareDataKeyWithDevicePublicKey: bool
    RecordTypesCounter: int
    RecordTypesEnterpriseCounter: int
    recordTypesEnabled: bool
    canManageRecordTypes: bool
    recordTypesPAMCounter: int
    logoutTimerMinutes: int
    securityKeysNoUserVerify: bool
    channels: _containers.RepeatedScalarFieldContainer[_APIRequest_pb2.TwoFactorChannelType]
    personalUsernames: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, audit: bool = ..., mustPerformAccountShareBy: _Optional[int] = ..., shareAccountTo: _Optional[_Iterable[_Union[MissingAccountShareKey, _Mapping]]] = ..., rules: _Optional[_Iterable[_Union[PasswordRule, _Mapping]]] = ..., passwordRulesIntro: _Optional[str] = ..., autoBackupDays: _Optional[int] = ..., theme: _Optional[str] = ..., channel: _Optional[str] = ..., channelValue: _Optional[str] = ..., rsaConfigured: bool = ..., emailVerified: bool = ..., masterPasswordLastModified: _Optional[float] = ..., accountFolderKey: _Optional[bytes] = ..., securityKeys: _Optional[_Iterable[_Union[SecurityKey, _Mapping]]] = ..., keyValues: _Optional[_Iterable[_Union[KeyValue, _Mapping]]] = ..., ssoUser: bool = ..., onlineAccessOnly: bool = ..., masterPasswordExpiry: _Optional[int] = ..., twoFactorRequired: bool = ..., disallowExport: bool = ..., restrictFiles: bool = ..., restrictAllSharing: bool = ..., restrictSharing: bool = ..., restrictSharingIncomingAll: bool = ..., restrictSharingIncomingEnterprise: bool = ..., logoutTimer: _Optional[int] = ..., persistentLogin: bool = ..., ipDisableAutoApprove: bool = ..., shareDataKeyWithEccPublicKey: bool = ..., shareDataKeyWithDevicePublicKey: bool = ..., RecordTypesCounter: _Optional[int] = ..., RecordTypesEnterpriseCounter: _Optional[int] = ..., recordTypesEnabled: bool = ..., canManageRecordTypes: bool = ..., recordTypesPAMCounter: _Optional[int] = ..., logoutTimerMinutes: _Optional[int] = ..., securityKeysNoUserVerify: bool = ..., channels: _Optional[_Iterable[_Union[_APIRequest_pb2.TwoFactorChannelType, str]]] = ..., personalUsernames: _Optional[_Iterable[str]] = ...) -> None: ...

class KeyValue(_message.Message):
    __slots__ = ["key", "value"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class KeyValueBoolean(_message.Message):
    __slots__ = ["key", "value"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: bool
    def __init__(self, key: _Optional[str] = ..., value: bool = ...) -> None: ...

class KeyValueLong(_message.Message):
    __slots__ = ["key", "value"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: int
    def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...

class Result(_message.Message):
    __slots__ = ["resultCode", "message", "result"]
    RESULTCODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    resultCode: str
    message: str
    result: str
    def __init__(self, resultCode: _Optional[str] = ..., message: _Optional[str] = ..., result: _Optional[str] = ...) -> None: ...

class Enforcements(_message.Message):
    __slots__ = ["strings", "booleans", "longs", "jsons"]
    STRINGS_FIELD_NUMBER: _ClassVar[int]
    BOOLEANS_FIELD_NUMBER: _ClassVar[int]
    LONGS_FIELD_NUMBER: _ClassVar[int]
    JSONS_FIELD_NUMBER: _ClassVar[int]
    strings: _containers.RepeatedCompositeFieldContainer[KeyValue]
    booleans: _containers.RepeatedCompositeFieldContainer[KeyValueBoolean]
    longs: _containers.RepeatedCompositeFieldContainer[KeyValueLong]
    jsons: _containers.RepeatedCompositeFieldContainer[KeyValue]
    def __init__(self, strings: _Optional[_Iterable[_Union[KeyValue, _Mapping]]] = ..., booleans: _Optional[_Iterable[_Union[KeyValueBoolean, _Mapping]]] = ..., longs: _Optional[_Iterable[_Union[KeyValueLong, _Mapping]]] = ..., jsons: _Optional[_Iterable[_Union[KeyValue, _Mapping]]] = ...) -> None: ...

class MissingAccountShareKey(_message.Message):
    __slots__ = ["role_id", "publicKey"]
    ROLE_ID_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    role_id: int
    publicKey: bytes
    def __init__(self, role_id: _Optional[int] = ..., publicKey: _Optional[bytes] = ...) -> None: ...

class PasswordRule(_message.Message):
    __slots__ = ["ruleType", "pattern", "match", "minimum", "description", "value"]
    RULETYPE_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ruleType: str
    pattern: str
    match: bool
    minimum: int
    description: str
    value: str
    def __init__(self, ruleType: _Optional[str] = ..., pattern: _Optional[str] = ..., match: bool = ..., minimum: _Optional[int] = ..., description: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class SecurityKey(_message.Message):
    __slots__ = ["deviceId", "deviceName", "dateAdded", "isValid", "deviceRegistration"]
    DEVICEID_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DATEADDED_FIELD_NUMBER: _ClassVar[int]
    ISVALID_FIELD_NUMBER: _ClassVar[int]
    DEVICEREGISTRATION_FIELD_NUMBER: _ClassVar[int]
    deviceId: int
    deviceName: str
    dateAdded: int
    isValid: bool
    deviceRegistration: DeviceRegistration
    def __init__(self, deviceId: _Optional[int] = ..., deviceName: _Optional[str] = ..., dateAdded: _Optional[int] = ..., isValid: bool = ..., deviceRegistration: _Optional[_Union[DeviceRegistration, _Mapping]] = ...) -> None: ...

class DeviceRegistration(_message.Message):
    __slots__ = ["keyHandle", "publicKey", "attestationCert", "counter", "compromised"]
    KEYHANDLE_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ATTESTATIONCERT_FIELD_NUMBER: _ClassVar[int]
    COUNTER_FIELD_NUMBER: _ClassVar[int]
    COMPROMISED_FIELD_NUMBER: _ClassVar[int]
    keyHandle: str
    publicKey: bytes
    attestationCert: str
    counter: int
    compromised: bool
    def __init__(self, keyHandle: _Optional[str] = ..., publicKey: _Optional[bytes] = ..., attestationCert: _Optional[str] = ..., counter: _Optional[int] = ..., compromised: bool = ...) -> None: ...

class Group(_message.Message):
    __slots__ = ["admin", "groupVerificationCode", "administrator"]
    ADMIN_FIELD_NUMBER: _ClassVar[int]
    GROUPVERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    ADMINISTRATOR_FIELD_NUMBER: _ClassVar[int]
    admin: bool
    groupVerificationCode: str
    administrator: Administrator
    def __init__(self, admin: bool = ..., groupVerificationCode: _Optional[str] = ..., administrator: _Optional[_Union[Administrator, _Mapping]] = ...) -> None: ...

class Administrator(_message.Message):
    __slots__ = ["firstName", "lastName", "email", "currentNumberOfUsers", "numberOfUsers", "subscriptionCode", "expirationDate", "purchaseDate"]
    FIRSTNAME_FIELD_NUMBER: _ClassVar[int]
    LASTNAME_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    CURRENTNUMBEROFUSERS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFUSERS_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTIONCODE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    PURCHASEDATE_FIELD_NUMBER: _ClassVar[int]
    firstName: str
    lastName: str
    email: str
    currentNumberOfUsers: int
    numberOfUsers: int
    subscriptionCode: str
    expirationDate: str
    purchaseDate: str
    def __init__(self, firstName: _Optional[str] = ..., lastName: _Optional[str] = ..., email: _Optional[str] = ..., currentNumberOfUsers: _Optional[int] = ..., numberOfUsers: _Optional[int] = ..., subscriptionCode: _Optional[str] = ..., expirationDate: _Optional[str] = ..., purchaseDate: _Optional[str] = ...) -> None: ...
