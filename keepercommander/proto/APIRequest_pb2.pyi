import enterprise_pb2 as _enterprise_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SupportedLanguage(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENGLISH: _ClassVar[SupportedLanguage]
    ARABIC: _ClassVar[SupportedLanguage]
    BRITISH: _ClassVar[SupportedLanguage]
    CHINESE: _ClassVar[SupportedLanguage]
    CHINESE_HONG_KONG: _ClassVar[SupportedLanguage]
    CHINESE_TAIWAN: _ClassVar[SupportedLanguage]
    DUTCH: _ClassVar[SupportedLanguage]
    FRENCH: _ClassVar[SupportedLanguage]
    GERMAN: _ClassVar[SupportedLanguage]
    GREEK: _ClassVar[SupportedLanguage]
    HEBREW: _ClassVar[SupportedLanguage]
    ITALIAN: _ClassVar[SupportedLanguage]
    JAPANESE: _ClassVar[SupportedLanguage]
    KOREAN: _ClassVar[SupportedLanguage]
    POLISH: _ClassVar[SupportedLanguage]
    PORTUGUESE: _ClassVar[SupportedLanguage]
    PORTUGUESE_BRAZIL: _ClassVar[SupportedLanguage]
    ROMANIAN: _ClassVar[SupportedLanguage]
    RUSSIAN: _ClassVar[SupportedLanguage]
    SLOVAK: _ClassVar[SupportedLanguage]
    SPANISH: _ClassVar[SupportedLanguage]
    FINNISH: _ClassVar[SupportedLanguage]
    SWEDISH: _ClassVar[SupportedLanguage]

class LoginType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NORMAL: _ClassVar[LoginType]
    SSO: _ClassVar[LoginType]
    BIO: _ClassVar[LoginType]
    ALTERNATE: _ClassVar[LoginType]
    OFFLINE: _ClassVar[LoginType]
    FORGOT_PASSWORD: _ClassVar[LoginType]
    PASSKEY_BIO: _ClassVar[LoginType]

class DeviceStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEVICE_NEEDS_APPROVAL: _ClassVar[DeviceStatus]
    DEVICE_OK: _ClassVar[DeviceStatus]
    DEVICE_DISABLED_BY_USER: _ClassVar[DeviceStatus]
    DEVICE_LOCKED_BY_ADMIN: _ClassVar[DeviceStatus]

class LicenseStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OTHER: _ClassVar[LicenseStatus]
    ACTIVE: _ClassVar[LicenseStatus]
    EXPIRED: _ClassVar[LicenseStatus]
    DISABLED: _ClassVar[LicenseStatus]

class AccountType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONSUMER: _ClassVar[AccountType]
    FAMILY: _ClassVar[AccountType]
    ENTERPRISE: _ClassVar[AccountType]

class SessionTokenType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NO_RESTRICTION: _ClassVar[SessionTokenType]
    ACCOUNT_RECOVERY: _ClassVar[SessionTokenType]
    SHARE_ACCOUNT: _ClassVar[SessionTokenType]
    PURCHASE: _ClassVar[SessionTokenType]
    RESTRICT: _ClassVar[SessionTokenType]
    ACCEPT_INVITE: _ClassVar[SessionTokenType]
    SUPPORT_SERVER: _ClassVar[SessionTokenType]
    ENTERPRISE_CREATION: _ClassVar[SessionTokenType]
    EXPIRED_BUT_ALLOWED_TO_SYNC: _ClassVar[SessionTokenType]
    ACCEPT_FAMILY_INVITE: _ClassVar[SessionTokenType]
    ENTERPRISE_CREATION_PURCHASED: _ClassVar[SessionTokenType]
    EMERGENCY_ACCESS: _ClassVar[SessionTokenType]

class Version(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    invalid_version: _ClassVar[Version]
    default_version: _ClassVar[Version]
    second_version: _ClassVar[Version]

class MasterPasswordReentryActionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNMASK: _ClassVar[MasterPasswordReentryActionType]
    COPY: _ClassVar[MasterPasswordReentryActionType]

class LoginMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INVALID_LOGINMETHOD: _ClassVar[LoginMethod]
    EXISTING_ACCOUNT: _ClassVar[LoginMethod]
    SSO_DOMAIN: _ClassVar[LoginMethod]
    AFTER_SSO: _ClassVar[LoginMethod]
    NEW_ACCOUNT: _ClassVar[LoginMethod]

class LoginState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INVALID_LOGINSTATE: _ClassVar[LoginState]
    LOGGED_OUT: _ClassVar[LoginState]
    DEVICE_APPROVAL_REQUIRED: _ClassVar[LoginState]
    DEVICE_LOCKED: _ClassVar[LoginState]
    ACCOUNT_LOCKED: _ClassVar[LoginState]
    DEVICE_ACCOUNT_LOCKED: _ClassVar[LoginState]
    UPGRADE: _ClassVar[LoginState]
    LICENSE_EXPIRED: _ClassVar[LoginState]
    REGION_REDIRECT: _ClassVar[LoginState]
    REDIRECT_CLOUD_SSO: _ClassVar[LoginState]
    REDIRECT_ONSITE_SSO: _ClassVar[LoginState]
    REQUIRES_2FA: _ClassVar[LoginState]
    REQUIRES_AUTH_HASH: _ClassVar[LoginState]
    REQUIRES_USERNAME: _ClassVar[LoginState]
    AFTER_CLOUD_SSO_LOGIN: _ClassVar[LoginState]
    REQUIRES_ACCOUNT_CREATION: _ClassVar[LoginState]
    REQUIRES_DEVICE_ENCRYPTED_DATA_KEY: _ClassVar[LoginState]
    LOGIN_TOKEN_EXPIRED: _ClassVar[LoginState]
    PASSKEY_INITIATE_CHALLENGE: _ClassVar[LoginState]
    PASSKEY_AUTH_REQUIRED: _ClassVar[LoginState]
    PASSKEY_VERIFY_AUTHENTICATION: _ClassVar[LoginState]
    AFTER_PASSKEY_LOGIN: _ClassVar[LoginState]
    LOGGED_IN: _ClassVar[LoginState]

class EncryptedDataKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NO_KEY: _ClassVar[EncryptedDataKeyType]
    BY_DEVICE_PUBLIC_KEY: _ClassVar[EncryptedDataKeyType]
    BY_PASSWORD: _ClassVar[EncryptedDataKeyType]
    BY_ALTERNATE: _ClassVar[EncryptedDataKeyType]
    BY_BIO: _ClassVar[EncryptedDataKeyType]

class PasswordMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENTERED: _ClassVar[PasswordMethod]
    BIOMETRICS: _ClassVar[PasswordMethod]

class TwoFactorPushType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TWO_FA_PUSH_NONE: _ClassVar[TwoFactorPushType]
    TWO_FA_PUSH_SMS: _ClassVar[TwoFactorPushType]
    TWO_FA_PUSH_KEEPER: _ClassVar[TwoFactorPushType]
    TWO_FA_PUSH_DUO_PUSH: _ClassVar[TwoFactorPushType]
    TWO_FA_PUSH_DUO_TEXT: _ClassVar[TwoFactorPushType]
    TWO_FA_PUSH_DUO_CALL: _ClassVar[TwoFactorPushType]
    TWO_FA_PUSH_DNA: _ClassVar[TwoFactorPushType]

class TwoFactorValueType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TWO_FA_CODE_NONE: _ClassVar[TwoFactorValueType]
    TWO_FA_CODE_TOTP: _ClassVar[TwoFactorValueType]
    TWO_FA_CODE_SMS: _ClassVar[TwoFactorValueType]
    TWO_FA_CODE_DUO: _ClassVar[TwoFactorValueType]
    TWO_FA_CODE_RSA: _ClassVar[TwoFactorValueType]
    TWO_FA_RESP_U2F: _ClassVar[TwoFactorValueType]
    TWO_FA_RESP_WEBAUTHN: _ClassVar[TwoFactorValueType]
    TWO_FA_CODE_DNA: _ClassVar[TwoFactorValueType]

class TwoFactorChannelType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TWO_FA_CT_NONE: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_TOTP: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_SMS: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_DUO: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_RSA: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_BACKUP: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_U2F: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_WEBAUTHN: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_KEEPER: _ClassVar[TwoFactorChannelType]
    TWO_FA_CT_DNA: _ClassVar[TwoFactorChannelType]

class TwoFactorExpiration(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TWO_FA_EXP_IMMEDIATELY: _ClassVar[TwoFactorExpiration]
    TWO_FA_EXP_5_MINUTES: _ClassVar[TwoFactorExpiration]
    TWO_FA_EXP_12_HOURS: _ClassVar[TwoFactorExpiration]
    TWO_FA_EXP_24_HOURS: _ClassVar[TwoFactorExpiration]
    TWO_FA_EXP_30_DAYS: _ClassVar[TwoFactorExpiration]
    TWO_FA_EXP_NEVER: _ClassVar[TwoFactorExpiration]

class LicenseType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VAULT: _ClassVar[LicenseType]
    CHAT: _ClassVar[LicenseType]
    STORAGE: _ClassVar[LicenseType]
    BREACHWATCH: _ClassVar[LicenseType]

class ObjectTypes(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECORD: _ClassVar[ObjectTypes]
    SHARED_FOLDER_USER: _ClassVar[ObjectTypes]
    SHARED_FOLDER_TEAM: _ClassVar[ObjectTypes]
    USER_FOLDER: _ClassVar[ObjectTypes]
    TEAM_USER: _ClassVar[ObjectTypes]

class EncryptedObjectType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EOT_UNSPECIFIED: _ClassVar[EncryptedObjectType]
    EOT_RECORD_KEY: _ClassVar[EncryptedObjectType]
    EOT_SHARED_FOLDER_USER_KEY: _ClassVar[EncryptedObjectType]
    EOT_SHARED_FOLDER_TEAM_KEY: _ClassVar[EncryptedObjectType]
    EOT_TEAM_USER_KEY: _ClassVar[EncryptedObjectType]
    EOT_USER_FOLDER_KEY: _ClassVar[EncryptedObjectType]
    EOT_SECURITY_DATA: _ClassVar[EncryptedObjectType]
    EOT_SECURITY_DATA_MASTER_PASSWORD: _ClassVar[EncryptedObjectType]
    EOT_EMERGENCY_ACCESS_KEY: _ClassVar[EncryptedObjectType]
    EOT_V2_RECORD_KEY: _ClassVar[EncryptedObjectType]

class MasterPasswordReentryStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MP_UNKNOWN: _ClassVar[MasterPasswordReentryStatus]
    MP_SUCCESS: _ClassVar[MasterPasswordReentryStatus]
    MP_FAILURE: _ClassVar[MasterPasswordReentryStatus]

class AlternateAuthenticationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ALTERNATE_MASTER_PASSWORD: _ClassVar[AlternateAuthenticationType]
    BIOMETRIC: _ClassVar[AlternateAuthenticationType]
    ACCOUNT_RECOVER: _ClassVar[AlternateAuthenticationType]

class ThrottleType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PASSWORD_RETRY_THROTTLE: _ClassVar[ThrottleType]
    PASSWORD_RETRY_LEGACY_THROTTLE: _ClassVar[ThrottleType]
    TWO_FA_THROTTLE: _ClassVar[ThrottleType]
    TWO_FA_LEGACY_THROTTLE: _ClassVar[ThrottleType]
    QA_RETRY_THROTTLE: _ClassVar[ThrottleType]
    ACCOUNT_RECOVER_THROTTLE: _ClassVar[ThrottleType]
    VALIDATE_DEVICE_VERIFICATION_CODE_THROTTLE: _ClassVar[ThrottleType]
    VALIDATE_CREATE_USER_VERIFICATION_CODE_THROTTLE: _ClassVar[ThrottleType]

class Region(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[Region]
    eu: _ClassVar[Region]
    us: _ClassVar[Region]
    usgov: _ClassVar[Region]
    au: _ClassVar[Region]
    jp: _ClassVar[Region]
    ca: _ClassVar[Region]

class ApplicationShareType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SHARE_TYPE_RECORD: _ClassVar[ApplicationShareType]
    SHARE_TYPE_FOLDER: _ClassVar[ApplicationShareType]

class TimeLimitedAccessType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INVALID_TIME_LIMITED_ACCESS_TYPE: _ClassVar[TimeLimitedAccessType]
    USER_ACCESS_TO_RECORD: _ClassVar[TimeLimitedAccessType]
    USER_OR_TEAM_ACCESS_TO_SHAREDFOLDER: _ClassVar[TimeLimitedAccessType]
    RECORD_ACCESS_TO_SHAREDFOLDER: _ClassVar[TimeLimitedAccessType]

class BackupKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BKT_SEC_ANSWER: _ClassVar[BackupKeyType]
    BKT_PASSPHRASE_HASH: _ClassVar[BackupKeyType]

class GenericStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SUCCESS: _ClassVar[GenericStatus]
    INVALID_OBJECT: _ClassVar[GenericStatus]
    ALREADY_EXISTS: _ClassVar[GenericStatus]
    ACCESS_DENIED: _ClassVar[GenericStatus]

class AuthenticatorAttachment(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CROSS_PLATFORM: _ClassVar[AuthenticatorAttachment]
    PLATFORM: _ClassVar[AuthenticatorAttachment]
    ALL_SUPPORTED: _ClassVar[AuthenticatorAttachment]

class PasskeyPurpose(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PK_LOGIN: _ClassVar[PasskeyPurpose]
    PK_REAUTH: _ClassVar[PasskeyPurpose]

class ClientFormFactor(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FF_EMPTY: _ClassVar[ClientFormFactor]
    FF_PHONE: _ClassVar[ClientFormFactor]
    FF_TABLET: _ClassVar[ClientFormFactor]
    FF_WATCH: _ClassVar[ClientFormFactor]
ENGLISH: SupportedLanguage
ARABIC: SupportedLanguage
BRITISH: SupportedLanguage
CHINESE: SupportedLanguage
CHINESE_HONG_KONG: SupportedLanguage
CHINESE_TAIWAN: SupportedLanguage
DUTCH: SupportedLanguage
FRENCH: SupportedLanguage
GERMAN: SupportedLanguage
GREEK: SupportedLanguage
HEBREW: SupportedLanguage
ITALIAN: SupportedLanguage
JAPANESE: SupportedLanguage
KOREAN: SupportedLanguage
POLISH: SupportedLanguage
PORTUGUESE: SupportedLanguage
PORTUGUESE_BRAZIL: SupportedLanguage
ROMANIAN: SupportedLanguage
RUSSIAN: SupportedLanguage
SLOVAK: SupportedLanguage
SPANISH: SupportedLanguage
FINNISH: SupportedLanguage
SWEDISH: SupportedLanguage
NORMAL: LoginType
SSO: LoginType
BIO: LoginType
ALTERNATE: LoginType
OFFLINE: LoginType
FORGOT_PASSWORD: LoginType
PASSKEY_BIO: LoginType
DEVICE_NEEDS_APPROVAL: DeviceStatus
DEVICE_OK: DeviceStatus
DEVICE_DISABLED_BY_USER: DeviceStatus
DEVICE_LOCKED_BY_ADMIN: DeviceStatus
OTHER: LicenseStatus
ACTIVE: LicenseStatus
EXPIRED: LicenseStatus
DISABLED: LicenseStatus
CONSUMER: AccountType
FAMILY: AccountType
ENTERPRISE: AccountType
NO_RESTRICTION: SessionTokenType
ACCOUNT_RECOVERY: SessionTokenType
SHARE_ACCOUNT: SessionTokenType
PURCHASE: SessionTokenType
RESTRICT: SessionTokenType
ACCEPT_INVITE: SessionTokenType
SUPPORT_SERVER: SessionTokenType
ENTERPRISE_CREATION: SessionTokenType
EXPIRED_BUT_ALLOWED_TO_SYNC: SessionTokenType
ACCEPT_FAMILY_INVITE: SessionTokenType
ENTERPRISE_CREATION_PURCHASED: SessionTokenType
EMERGENCY_ACCESS: SessionTokenType
invalid_version: Version
default_version: Version
second_version: Version
UNMASK: MasterPasswordReentryActionType
COPY: MasterPasswordReentryActionType
INVALID_LOGINMETHOD: LoginMethod
EXISTING_ACCOUNT: LoginMethod
SSO_DOMAIN: LoginMethod
AFTER_SSO: LoginMethod
NEW_ACCOUNT: LoginMethod
INVALID_LOGINSTATE: LoginState
LOGGED_OUT: LoginState
DEVICE_APPROVAL_REQUIRED: LoginState
DEVICE_LOCKED: LoginState
ACCOUNT_LOCKED: LoginState
DEVICE_ACCOUNT_LOCKED: LoginState
UPGRADE: LoginState
LICENSE_EXPIRED: LoginState
REGION_REDIRECT: LoginState
REDIRECT_CLOUD_SSO: LoginState
REDIRECT_ONSITE_SSO: LoginState
REQUIRES_2FA: LoginState
REQUIRES_AUTH_HASH: LoginState
REQUIRES_USERNAME: LoginState
AFTER_CLOUD_SSO_LOGIN: LoginState
REQUIRES_ACCOUNT_CREATION: LoginState
REQUIRES_DEVICE_ENCRYPTED_DATA_KEY: LoginState
LOGIN_TOKEN_EXPIRED: LoginState
PASSKEY_INITIATE_CHALLENGE: LoginState
PASSKEY_AUTH_REQUIRED: LoginState
PASSKEY_VERIFY_AUTHENTICATION: LoginState
AFTER_PASSKEY_LOGIN: LoginState
LOGGED_IN: LoginState
NO_KEY: EncryptedDataKeyType
BY_DEVICE_PUBLIC_KEY: EncryptedDataKeyType
BY_PASSWORD: EncryptedDataKeyType
BY_ALTERNATE: EncryptedDataKeyType
BY_BIO: EncryptedDataKeyType
ENTERED: PasswordMethod
BIOMETRICS: PasswordMethod
TWO_FA_PUSH_NONE: TwoFactorPushType
TWO_FA_PUSH_SMS: TwoFactorPushType
TWO_FA_PUSH_KEEPER: TwoFactorPushType
TWO_FA_PUSH_DUO_PUSH: TwoFactorPushType
TWO_FA_PUSH_DUO_TEXT: TwoFactorPushType
TWO_FA_PUSH_DUO_CALL: TwoFactorPushType
TWO_FA_PUSH_DNA: TwoFactorPushType
TWO_FA_CODE_NONE: TwoFactorValueType
TWO_FA_CODE_TOTP: TwoFactorValueType
TWO_FA_CODE_SMS: TwoFactorValueType
TWO_FA_CODE_DUO: TwoFactorValueType
TWO_FA_CODE_RSA: TwoFactorValueType
TWO_FA_RESP_U2F: TwoFactorValueType
TWO_FA_RESP_WEBAUTHN: TwoFactorValueType
TWO_FA_CODE_DNA: TwoFactorValueType
TWO_FA_CT_NONE: TwoFactorChannelType
TWO_FA_CT_TOTP: TwoFactorChannelType
TWO_FA_CT_SMS: TwoFactorChannelType
TWO_FA_CT_DUO: TwoFactorChannelType
TWO_FA_CT_RSA: TwoFactorChannelType
TWO_FA_CT_BACKUP: TwoFactorChannelType
TWO_FA_CT_U2F: TwoFactorChannelType
TWO_FA_CT_WEBAUTHN: TwoFactorChannelType
TWO_FA_CT_KEEPER: TwoFactorChannelType
TWO_FA_CT_DNA: TwoFactorChannelType
TWO_FA_EXP_IMMEDIATELY: TwoFactorExpiration
TWO_FA_EXP_5_MINUTES: TwoFactorExpiration
TWO_FA_EXP_12_HOURS: TwoFactorExpiration
TWO_FA_EXP_24_HOURS: TwoFactorExpiration
TWO_FA_EXP_30_DAYS: TwoFactorExpiration
TWO_FA_EXP_NEVER: TwoFactorExpiration
VAULT: LicenseType
CHAT: LicenseType
STORAGE: LicenseType
BREACHWATCH: LicenseType
RECORD: ObjectTypes
SHARED_FOLDER_USER: ObjectTypes
SHARED_FOLDER_TEAM: ObjectTypes
USER_FOLDER: ObjectTypes
TEAM_USER: ObjectTypes
EOT_UNSPECIFIED: EncryptedObjectType
EOT_RECORD_KEY: EncryptedObjectType
EOT_SHARED_FOLDER_USER_KEY: EncryptedObjectType
EOT_SHARED_FOLDER_TEAM_KEY: EncryptedObjectType
EOT_TEAM_USER_KEY: EncryptedObjectType
EOT_USER_FOLDER_KEY: EncryptedObjectType
EOT_SECURITY_DATA: EncryptedObjectType
EOT_SECURITY_DATA_MASTER_PASSWORD: EncryptedObjectType
EOT_EMERGENCY_ACCESS_KEY: EncryptedObjectType
EOT_V2_RECORD_KEY: EncryptedObjectType
MP_UNKNOWN: MasterPasswordReentryStatus
MP_SUCCESS: MasterPasswordReentryStatus
MP_FAILURE: MasterPasswordReentryStatus
ALTERNATE_MASTER_PASSWORD: AlternateAuthenticationType
BIOMETRIC: AlternateAuthenticationType
ACCOUNT_RECOVER: AlternateAuthenticationType
PASSWORD_RETRY_THROTTLE: ThrottleType
PASSWORD_RETRY_LEGACY_THROTTLE: ThrottleType
TWO_FA_THROTTLE: ThrottleType
TWO_FA_LEGACY_THROTTLE: ThrottleType
QA_RETRY_THROTTLE: ThrottleType
ACCOUNT_RECOVER_THROTTLE: ThrottleType
VALIDATE_DEVICE_VERIFICATION_CODE_THROTTLE: ThrottleType
VALIDATE_CREATE_USER_VERIFICATION_CODE_THROTTLE: ThrottleType
UNKNOWN: Region
eu: Region
us: Region
usgov: Region
au: Region
jp: Region
ca: Region
SHARE_TYPE_RECORD: ApplicationShareType
SHARE_TYPE_FOLDER: ApplicationShareType
INVALID_TIME_LIMITED_ACCESS_TYPE: TimeLimitedAccessType
USER_ACCESS_TO_RECORD: TimeLimitedAccessType
USER_OR_TEAM_ACCESS_TO_SHAREDFOLDER: TimeLimitedAccessType
RECORD_ACCESS_TO_SHAREDFOLDER: TimeLimitedAccessType
BKT_SEC_ANSWER: BackupKeyType
BKT_PASSPHRASE_HASH: BackupKeyType
SUCCESS: GenericStatus
INVALID_OBJECT: GenericStatus
ALREADY_EXISTS: GenericStatus
ACCESS_DENIED: GenericStatus
CROSS_PLATFORM: AuthenticatorAttachment
PLATFORM: AuthenticatorAttachment
ALL_SUPPORTED: AuthenticatorAttachment
PK_LOGIN: PasskeyPurpose
PK_REAUTH: PasskeyPurpose
FF_EMPTY: ClientFormFactor
FF_PHONE: ClientFormFactor
FF_TABLET: ClientFormFactor
FF_WATCH: ClientFormFactor

class QrcMessageKey(_message.Message):
    __slots__ = ("clientEcPublicKey", "mlKemEncapsulatedKey", "data", "msgVersion", "ecKeyId")
    CLIENTECPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    MLKEMENCAPSULATEDKEY_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    MSGVERSION_FIELD_NUMBER: _ClassVar[int]
    ECKEYID_FIELD_NUMBER: _ClassVar[int]
    clientEcPublicKey: bytes
    mlKemEncapsulatedKey: bytes
    data: bytes
    msgVersion: int
    ecKeyId: int
    def __init__(self, clientEcPublicKey: _Optional[bytes] = ..., mlKemEncapsulatedKey: _Optional[bytes] = ..., data: _Optional[bytes] = ..., msgVersion: _Optional[int] = ..., ecKeyId: _Optional[int] = ...) -> None: ...

class ApiRequest(_message.Message):
    __slots__ = ("encryptedTransmissionKey", "publicKeyId", "locale", "encryptedPayload", "encryptionType", "recaptcha", "subEnvironment", "qrcMessageKey")
    ENCRYPTEDTRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    RECAPTCHA_FIELD_NUMBER: _ClassVar[int]
    SUBENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    QRCMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    encryptedTransmissionKey: bytes
    publicKeyId: int
    locale: str
    encryptedPayload: bytes
    encryptionType: int
    recaptcha: str
    subEnvironment: str
    qrcMessageKey: QrcMessageKey
    def __init__(self, encryptedTransmissionKey: _Optional[bytes] = ..., publicKeyId: _Optional[int] = ..., locale: _Optional[str] = ..., encryptedPayload: _Optional[bytes] = ..., encryptionType: _Optional[int] = ..., recaptcha: _Optional[str] = ..., subEnvironment: _Optional[str] = ..., qrcMessageKey: _Optional[_Union[QrcMessageKey, _Mapping]] = ...) -> None: ...

class ApiRequestPayload(_message.Message):
    __slots__ = ("payload", "encryptedSessionToken", "timeToken", "apiVersion")
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    TIMETOKEN_FIELD_NUMBER: _ClassVar[int]
    APIVERSION_FIELD_NUMBER: _ClassVar[int]
    payload: bytes
    encryptedSessionToken: bytes
    timeToken: bytes
    apiVersion: int
    def __init__(self, payload: _Optional[bytes] = ..., encryptedSessionToken: _Optional[bytes] = ..., timeToken: _Optional[bytes] = ..., apiVersion: _Optional[int] = ...) -> None: ...

class Transform(_message.Message):
    __slots__ = ("key", "encryptedDeviceToken")
    KEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    encryptedDeviceToken: bytes
    def __init__(self, key: _Optional[bytes] = ..., encryptedDeviceToken: _Optional[bytes] = ...) -> None: ...

class DeviceRequest(_message.Message):
    __slots__ = ("clientVersion", "deviceName", "devicePlatform", "clientFormFactor", "username")
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
    CLIENTFORMFACTOR_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    clientVersion: str
    deviceName: str
    devicePlatform: str
    clientFormFactor: ClientFormFactor
    username: str
    def __init__(self, clientVersion: _Optional[str] = ..., deviceName: _Optional[str] = ..., devicePlatform: _Optional[str] = ..., clientFormFactor: _Optional[_Union[ClientFormFactor, str]] = ..., username: _Optional[str] = ...) -> None: ...

class AuthRequest(_message.Message):
    __slots__ = ("clientVersion", "username", "encryptedDeviceToken")
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    clientVersion: str
    username: str
    encryptedDeviceToken: bytes
    def __init__(self, clientVersion: _Optional[str] = ..., username: _Optional[str] = ..., encryptedDeviceToken: _Optional[bytes] = ...) -> None: ...

class NewUserMinimumParams(_message.Message):
    __slots__ = ("minimumIterations", "passwordMatchRegex", "passwordMatchDescription", "isEnterpriseDomain", "enterpriseEccPublicKey", "forbidKeyType2")
    MINIMUMITERATIONS_FIELD_NUMBER: _ClassVar[int]
    PASSWORDMATCHREGEX_FIELD_NUMBER: _ClassVar[int]
    PASSWORDMATCHDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ISENTERPRISEDOMAIN_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    FORBIDKEYTYPE2_FIELD_NUMBER: _ClassVar[int]
    minimumIterations: int
    passwordMatchRegex: _containers.RepeatedScalarFieldContainer[str]
    passwordMatchDescription: _containers.RepeatedScalarFieldContainer[str]
    isEnterpriseDomain: bool
    enterpriseEccPublicKey: bytes
    forbidKeyType2: bool
    def __init__(self, minimumIterations: _Optional[int] = ..., passwordMatchRegex: _Optional[_Iterable[str]] = ..., passwordMatchDescription: _Optional[_Iterable[str]] = ..., isEnterpriseDomain: _Optional[bool] = ..., enterpriseEccPublicKey: _Optional[bytes] = ..., forbidKeyType2: _Optional[bool] = ...) -> None: ...

class PreLoginRequest(_message.Message):
    __slots__ = ("authRequest", "loginType", "twoFactorToken")
    AUTHREQUEST_FIELD_NUMBER: _ClassVar[int]
    LOGINTYPE_FIELD_NUMBER: _ClassVar[int]
    TWOFACTORTOKEN_FIELD_NUMBER: _ClassVar[int]
    authRequest: AuthRequest
    loginType: LoginType
    twoFactorToken: bytes
    def __init__(self, authRequest: _Optional[_Union[AuthRequest, _Mapping]] = ..., loginType: _Optional[_Union[LoginType, str]] = ..., twoFactorToken: _Optional[bytes] = ...) -> None: ...

class LoginRequest(_message.Message):
    __slots__ = ("authRequest", "loginType", "authenticationHashPrime", "encryptedLoginToken", "authResponse", "mcEnterpriseId", "push_token", "platform")
    AUTHREQUEST_FIELD_NUMBER: _ClassVar[int]
    LOGINTYPE_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATIONHASHPRIME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    AUTHRESPONSE_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    PUSH_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    authRequest: AuthRequest
    loginType: LoginType
    authenticationHashPrime: bytes
    encryptedLoginToken: bytes
    authResponse: bytes
    mcEnterpriseId: int
    push_token: str
    platform: str
    def __init__(self, authRequest: _Optional[_Union[AuthRequest, _Mapping]] = ..., loginType: _Optional[_Union[LoginType, str]] = ..., authenticationHashPrime: _Optional[bytes] = ..., encryptedLoginToken: _Optional[bytes] = ..., authResponse: _Optional[bytes] = ..., mcEnterpriseId: _Optional[int] = ..., push_token: _Optional[str] = ..., platform: _Optional[str] = ...) -> None: ...

class DeviceResponse(_message.Message):
    __slots__ = ("encryptedDeviceToken", "status")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    status: DeviceStatus
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., status: _Optional[_Union[DeviceStatus, str]] = ...) -> None: ...

class Salt(_message.Message):
    __slots__ = ("iterations", "salt", "algorithm", "uid", "name")
    ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    iterations: int
    salt: bytes
    algorithm: int
    uid: bytes
    name: str
    def __init__(self, iterations: _Optional[int] = ..., salt: _Optional[bytes] = ..., algorithm: _Optional[int] = ..., uid: _Optional[bytes] = ..., name: _Optional[str] = ...) -> None: ...

class TwoFactorChannel(_message.Message):
    __slots__ = ("type",)
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: int
    def __init__(self, type: _Optional[int] = ...) -> None: ...

class StartLoginRequest(_message.Message):
    __slots__ = ("encryptedDeviceToken", "username", "clientVersion", "messageSessionUid", "encryptedLoginToken", "loginType", "mcEnterpriseId", "loginMethod", "forceNewLogin", "cloneCode", "v2TwoFactorToken", "accountUid", "fromSessionToken")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    LOGINTYPE_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    LOGINMETHOD_FIELD_NUMBER: _ClassVar[int]
    FORCENEWLOGIN_FIELD_NUMBER: _ClassVar[int]
    CLONECODE_FIELD_NUMBER: _ClassVar[int]
    V2TWOFACTORTOKEN_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    FROMSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    username: str
    clientVersion: str
    messageSessionUid: bytes
    encryptedLoginToken: bytes
    loginType: LoginType
    mcEnterpriseId: int
    loginMethod: LoginMethod
    forceNewLogin: bool
    cloneCode: bytes
    v2TwoFactorToken: str
    accountUid: bytes
    fromSessionToken: bytes
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., username: _Optional[str] = ..., clientVersion: _Optional[str] = ..., messageSessionUid: _Optional[bytes] = ..., encryptedLoginToken: _Optional[bytes] = ..., loginType: _Optional[_Union[LoginType, str]] = ..., mcEnterpriseId: _Optional[int] = ..., loginMethod: _Optional[_Union[LoginMethod, str]] = ..., forceNewLogin: _Optional[bool] = ..., cloneCode: _Optional[bytes] = ..., v2TwoFactorToken: _Optional[str] = ..., accountUid: _Optional[bytes] = ..., fromSessionToken: _Optional[bytes] = ...) -> None: ...

class LoginResponse(_message.Message):
    __slots__ = ("loginState", "accountUid", "primaryUsername", "encryptedDataKey", "encryptedDataKeyType", "encryptedLoginToken", "encryptedSessionToken", "sessionTokenType", "message", "url", "channels", "salt", "cloneCode", "stateSpecificValue", "ssoClientVersion", "sessionTokenTypeModifier")
    LOGINSTATE_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    PRIMARYUSERNAME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    SESSIONTOKENTYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    CLONECODE_FIELD_NUMBER: _ClassVar[int]
    STATESPECIFICVALUE_FIELD_NUMBER: _ClassVar[int]
    SSOCLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    SESSIONTOKENTYPEMODIFIER_FIELD_NUMBER: _ClassVar[int]
    loginState: LoginState
    accountUid: bytes
    primaryUsername: str
    encryptedDataKey: bytes
    encryptedDataKeyType: EncryptedDataKeyType
    encryptedLoginToken: bytes
    encryptedSessionToken: bytes
    sessionTokenType: SessionTokenType
    message: str
    url: str
    channels: _containers.RepeatedCompositeFieldContainer[TwoFactorChannelInfo]
    salt: _containers.RepeatedCompositeFieldContainer[Salt]
    cloneCode: bytes
    stateSpecificValue: str
    ssoClientVersion: str
    sessionTokenTypeModifier: str
    def __init__(self, loginState: _Optional[_Union[LoginState, str]] = ..., accountUid: _Optional[bytes] = ..., primaryUsername: _Optional[str] = ..., encryptedDataKey: _Optional[bytes] = ..., encryptedDataKeyType: _Optional[_Union[EncryptedDataKeyType, str]] = ..., encryptedLoginToken: _Optional[bytes] = ..., encryptedSessionToken: _Optional[bytes] = ..., sessionTokenType: _Optional[_Union[SessionTokenType, str]] = ..., message: _Optional[str] = ..., url: _Optional[str] = ..., channels: _Optional[_Iterable[_Union[TwoFactorChannelInfo, _Mapping]]] = ..., salt: _Optional[_Iterable[_Union[Salt, _Mapping]]] = ..., cloneCode: _Optional[bytes] = ..., stateSpecificValue: _Optional[str] = ..., ssoClientVersion: _Optional[str] = ..., sessionTokenTypeModifier: _Optional[str] = ...) -> None: ...

class SwitchListElement(_message.Message):
    __slots__ = ("username", "fullName", "authRequired", "isLinked", "profilePicUrl")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    AUTHREQUIRED_FIELD_NUMBER: _ClassVar[int]
    ISLINKED_FIELD_NUMBER: _ClassVar[int]
    PROFILEPICURL_FIELD_NUMBER: _ClassVar[int]
    username: str
    fullName: str
    authRequired: bool
    isLinked: bool
    profilePicUrl: str
    def __init__(self, username: _Optional[str] = ..., fullName: _Optional[str] = ..., authRequired: _Optional[bool] = ..., isLinked: _Optional[bool] = ..., profilePicUrl: _Optional[str] = ...) -> None: ...

class SwitchListResponse(_message.Message):
    __slots__ = ("elements",)
    ELEMENTS_FIELD_NUMBER: _ClassVar[int]
    elements: _containers.RepeatedCompositeFieldContainer[SwitchListElement]
    def __init__(self, elements: _Optional[_Iterable[_Union[SwitchListElement, _Mapping]]] = ...) -> None: ...

class SsoUserInfo(_message.Message):
    __slots__ = ("companyName", "samlRequest", "samlRequestType", "ssoDomainName", "loginUrl", "logoutUrl")
    COMPANYNAME_FIELD_NUMBER: _ClassVar[int]
    SAMLREQUEST_FIELD_NUMBER: _ClassVar[int]
    SAMLREQUESTTYPE_FIELD_NUMBER: _ClassVar[int]
    SSODOMAINNAME_FIELD_NUMBER: _ClassVar[int]
    LOGINURL_FIELD_NUMBER: _ClassVar[int]
    LOGOUTURL_FIELD_NUMBER: _ClassVar[int]
    companyName: str
    samlRequest: str
    samlRequestType: str
    ssoDomainName: str
    loginUrl: str
    logoutUrl: str
    def __init__(self, companyName: _Optional[str] = ..., samlRequest: _Optional[str] = ..., samlRequestType: _Optional[str] = ..., ssoDomainName: _Optional[str] = ..., loginUrl: _Optional[str] = ..., logoutUrl: _Optional[str] = ...) -> None: ...

class PreLoginResponse(_message.Message):
    __slots__ = ("deviceStatus", "salt", "OBSOLETE_FIELD", "ssoUserInfo")
    DEVICESTATUS_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    OBSOLETE_FIELD_FIELD_NUMBER: _ClassVar[int]
    SSOUSERINFO_FIELD_NUMBER: _ClassVar[int]
    deviceStatus: DeviceStatus
    salt: _containers.RepeatedCompositeFieldContainer[Salt]
    OBSOLETE_FIELD: _containers.RepeatedCompositeFieldContainer[TwoFactorChannel]
    ssoUserInfo: SsoUserInfo
    def __init__(self, deviceStatus: _Optional[_Union[DeviceStatus, str]] = ..., salt: _Optional[_Iterable[_Union[Salt, _Mapping]]] = ..., OBSOLETE_FIELD: _Optional[_Iterable[_Union[TwoFactorChannel, _Mapping]]] = ..., ssoUserInfo: _Optional[_Union[SsoUserInfo, _Mapping]] = ...) -> None: ...

class LoginAsUserRequest(_message.Message):
    __slots__ = ("username",)
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    def __init__(self, username: _Optional[str] = ...) -> None: ...

class LoginAsUserResponse(_message.Message):
    __slots__ = ("encryptedSessionToken", "encryptedSharedAccountKey")
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSHAREDACCOUNTKEY_FIELD_NUMBER: _ClassVar[int]
    encryptedSessionToken: bytes
    encryptedSharedAccountKey: bytes
    def __init__(self, encryptedSessionToken: _Optional[bytes] = ..., encryptedSharedAccountKey: _Optional[bytes] = ...) -> None: ...

class ValidateAuthHashRequest(_message.Message):
    __slots__ = ("passwordMethod", "authResponse", "encryptedLoginToken")
    PASSWORDMETHOD_FIELD_NUMBER: _ClassVar[int]
    AUTHRESPONSE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    passwordMethod: PasswordMethod
    authResponse: bytes
    encryptedLoginToken: bytes
    def __init__(self, passwordMethod: _Optional[_Union[PasswordMethod, str]] = ..., authResponse: _Optional[bytes] = ..., encryptedLoginToken: _Optional[bytes] = ...) -> None: ...

class TwoFactorChannelInfo(_message.Message):
    __slots__ = ("channelType", "channel_uid", "channelName", "challenge", "capabilities", "phoneNumber", "maxExpiration", "createdOn", "lastFrequency")
    CHANNELTYPE_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_UID_FIELD_NUMBER: _ClassVar[int]
    CHANNELNAME_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    PHONENUMBER_FIELD_NUMBER: _ClassVar[int]
    MAXEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    CREATEDON_FIELD_NUMBER: _ClassVar[int]
    LASTFREQUENCY_FIELD_NUMBER: _ClassVar[int]
    channelType: TwoFactorChannelType
    channel_uid: bytes
    channelName: str
    challenge: str
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    phoneNumber: str
    maxExpiration: TwoFactorExpiration
    createdOn: int
    lastFrequency: TwoFactorExpiration
    def __init__(self, channelType: _Optional[_Union[TwoFactorChannelType, str]] = ..., channel_uid: _Optional[bytes] = ..., channelName: _Optional[str] = ..., challenge: _Optional[str] = ..., capabilities: _Optional[_Iterable[str]] = ..., phoneNumber: _Optional[str] = ..., maxExpiration: _Optional[_Union[TwoFactorExpiration, str]] = ..., createdOn: _Optional[int] = ..., lastFrequency: _Optional[_Union[TwoFactorExpiration, str]] = ...) -> None: ...

class TwoFactorDuoStatus(_message.Message):
    __slots__ = ("capabilities", "phoneNumber", "enroll_url", "message")
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    PHONENUMBER_FIELD_NUMBER: _ClassVar[int]
    ENROLL_URL_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    phoneNumber: str
    enroll_url: str
    message: str
    def __init__(self, capabilities: _Optional[_Iterable[str]] = ..., phoneNumber: _Optional[str] = ..., enroll_url: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class TwoFactorAddRequest(_message.Message):
    __slots__ = ("channelType", "channel_uid", "channelName", "phoneNumber", "duoPushType")
    CHANNELTYPE_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_UID_FIELD_NUMBER: _ClassVar[int]
    CHANNELNAME_FIELD_NUMBER: _ClassVar[int]
    PHONENUMBER_FIELD_NUMBER: _ClassVar[int]
    DUOPUSHTYPE_FIELD_NUMBER: _ClassVar[int]
    channelType: TwoFactorChannelType
    channel_uid: bytes
    channelName: str
    phoneNumber: str
    duoPushType: TwoFactorPushType
    def __init__(self, channelType: _Optional[_Union[TwoFactorChannelType, str]] = ..., channel_uid: _Optional[bytes] = ..., channelName: _Optional[str] = ..., phoneNumber: _Optional[str] = ..., duoPushType: _Optional[_Union[TwoFactorPushType, str]] = ...) -> None: ...

class TwoFactorRenameRequest(_message.Message):
    __slots__ = ("channel_uid", "channelName")
    CHANNEL_UID_FIELD_NUMBER: _ClassVar[int]
    CHANNELNAME_FIELD_NUMBER: _ClassVar[int]
    channel_uid: bytes
    channelName: str
    def __init__(self, channel_uid: _Optional[bytes] = ..., channelName: _Optional[str] = ...) -> None: ...

class TwoFactorAddResponse(_message.Message):
    __slots__ = ("challenge", "backupKeys")
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    BACKUPKEYS_FIELD_NUMBER: _ClassVar[int]
    challenge: str
    backupKeys: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, challenge: _Optional[str] = ..., backupKeys: _Optional[_Iterable[str]] = ...) -> None: ...

class TwoFactorDeleteRequest(_message.Message):
    __slots__ = ("channel_uid",)
    CHANNEL_UID_FIELD_NUMBER: _ClassVar[int]
    channel_uid: bytes
    def __init__(self, channel_uid: _Optional[bytes] = ...) -> None: ...

class TwoFactorListResponse(_message.Message):
    __slots__ = ("channels", "expireOn")
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    EXPIREON_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedCompositeFieldContainer[TwoFactorChannelInfo]
    expireOn: int
    def __init__(self, channels: _Optional[_Iterable[_Union[TwoFactorChannelInfo, _Mapping]]] = ..., expireOn: _Optional[int] = ...) -> None: ...

class TwoFactorUpdateExpirationRequest(_message.Message):
    __slots__ = ("expireIn",)
    EXPIREIN_FIELD_NUMBER: _ClassVar[int]
    expireIn: TwoFactorExpiration
    def __init__(self, expireIn: _Optional[_Union[TwoFactorExpiration, str]] = ...) -> None: ...

class TwoFactorValidateRequest(_message.Message):
    __slots__ = ("encryptedLoginToken", "valueType", "value", "channel_uid", "expireIn")
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    VALUETYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_UID_FIELD_NUMBER: _ClassVar[int]
    EXPIREIN_FIELD_NUMBER: _ClassVar[int]
    encryptedLoginToken: bytes
    valueType: TwoFactorValueType
    value: str
    channel_uid: bytes
    expireIn: TwoFactorExpiration
    def __init__(self, encryptedLoginToken: _Optional[bytes] = ..., valueType: _Optional[_Union[TwoFactorValueType, str]] = ..., value: _Optional[str] = ..., channel_uid: _Optional[bytes] = ..., expireIn: _Optional[_Union[TwoFactorExpiration, str]] = ...) -> None: ...

class TwoFactorValidateResponse(_message.Message):
    __slots__ = ("encryptedLoginToken",)
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedLoginToken: bytes
    def __init__(self, encryptedLoginToken: _Optional[bytes] = ...) -> None: ...

class TwoFactorSendPushRequest(_message.Message):
    __slots__ = ("encryptedLoginToken", "pushType", "channel_uid", "expireIn")
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    PUSHTYPE_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_UID_FIELD_NUMBER: _ClassVar[int]
    EXPIREIN_FIELD_NUMBER: _ClassVar[int]
    encryptedLoginToken: bytes
    pushType: TwoFactorPushType
    channel_uid: bytes
    expireIn: TwoFactorExpiration
    def __init__(self, encryptedLoginToken: _Optional[bytes] = ..., pushType: _Optional[_Union[TwoFactorPushType, str]] = ..., channel_uid: _Optional[bytes] = ..., expireIn: _Optional[_Union[TwoFactorExpiration, str]] = ...) -> None: ...

class License(_message.Message):
    __slots__ = ("created", "expiration", "licenseStatus", "paid", "message")
    CREATED_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    LICENSESTATUS_FIELD_NUMBER: _ClassVar[int]
    PAID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    created: int
    expiration: int
    licenseStatus: LicenseStatus
    paid: bool
    message: str
    def __init__(self, created: _Optional[int] = ..., expiration: _Optional[int] = ..., licenseStatus: _Optional[_Union[LicenseStatus, str]] = ..., paid: _Optional[bool] = ..., message: _Optional[str] = ...) -> None: ...

class OwnerlessRecord(_message.Message):
    __slots__ = ("recordUid", "recordKey", "status")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    recordKey: bytes
    status: int
    def __init__(self, recordUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., status: _Optional[int] = ...) -> None: ...

class OwnerlessRecords(_message.Message):
    __slots__ = ("ownerlessRecord",)
    OWNERLESSRECORD_FIELD_NUMBER: _ClassVar[int]
    ownerlessRecord: _containers.RepeatedCompositeFieldContainer[OwnerlessRecord]
    def __init__(self, ownerlessRecord: _Optional[_Iterable[_Union[OwnerlessRecord, _Mapping]]] = ...) -> None: ...

class UserAuthRequest(_message.Message):
    __slots__ = ("uid", "salt", "iterations", "encryptedClientKey", "authHash", "encryptedDataKey", "loginType", "name", "algorithm")
    UID_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDCLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    AUTHHASH_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    LOGINTYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    salt: bytes
    iterations: int
    encryptedClientKey: bytes
    authHash: bytes
    encryptedDataKey: bytes
    loginType: LoginType
    name: str
    algorithm: int
    def __init__(self, uid: _Optional[bytes] = ..., salt: _Optional[bytes] = ..., iterations: _Optional[int] = ..., encryptedClientKey: _Optional[bytes] = ..., authHash: _Optional[bytes] = ..., encryptedDataKey: _Optional[bytes] = ..., loginType: _Optional[_Union[LoginType, str]] = ..., name: _Optional[str] = ..., algorithm: _Optional[int] = ...) -> None: ...

class UidRequest(_message.Message):
    __slots__ = ("uid",)
    UID_FIELD_NUMBER: _ClassVar[int]
    uid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, uid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class DeviceUpdateRequest(_message.Message):
    __slots__ = ("encryptedDeviceToken", "clientVersion", "deviceName", "devicePublicKey", "deviceStatus", "devicePlatform", "clientFormFactor")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    DEVICESTATUS_FIELD_NUMBER: _ClassVar[int]
    DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
    CLIENTFORMFACTOR_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    clientVersion: str
    deviceName: str
    devicePublicKey: bytes
    deviceStatus: DeviceStatus
    devicePlatform: str
    clientFormFactor: ClientFormFactor
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., clientVersion: _Optional[str] = ..., deviceName: _Optional[str] = ..., devicePublicKey: _Optional[bytes] = ..., deviceStatus: _Optional[_Union[DeviceStatus, str]] = ..., devicePlatform: _Optional[str] = ..., clientFormFactor: _Optional[_Union[ClientFormFactor, str]] = ...) -> None: ...

class DeviceUpdateResponse(_message.Message):
    __slots__ = ("encryptedDeviceToken", "clientVersion", "deviceName", "devicePublicKey", "deviceStatus", "devicePlatform", "clientFormFactor")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    DEVICESTATUS_FIELD_NUMBER: _ClassVar[int]
    DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
    CLIENTFORMFACTOR_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    clientVersion: str
    deviceName: str
    devicePublicKey: bytes
    deviceStatus: DeviceStatus
    devicePlatform: str
    clientFormFactor: ClientFormFactor
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., clientVersion: _Optional[str] = ..., deviceName: _Optional[str] = ..., devicePublicKey: _Optional[bytes] = ..., deviceStatus: _Optional[_Union[DeviceStatus, str]] = ..., devicePlatform: _Optional[str] = ..., clientFormFactor: _Optional[_Union[ClientFormFactor, str]] = ...) -> None: ...

class RegisterDeviceInRegionRequest(_message.Message):
    __slots__ = ("encryptedDeviceToken", "clientVersion", "deviceName", "devicePublicKey", "devicePlatform", "clientFormFactor")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
    CLIENTFORMFACTOR_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    clientVersion: str
    deviceName: str
    devicePublicKey: bytes
    devicePlatform: str
    clientFormFactor: ClientFormFactor
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., clientVersion: _Optional[str] = ..., deviceName: _Optional[str] = ..., devicePublicKey: _Optional[bytes] = ..., devicePlatform: _Optional[str] = ..., clientFormFactor: _Optional[_Union[ClientFormFactor, str]] = ...) -> None: ...

class RegistrationRequest(_message.Message):
    __slots__ = ("authRequest", "userAuthRequest", "encryptedClientKey", "encryptedPrivateKey", "publicKey", "verificationCode", "deprecatedAuthHashHash", "deprecatedEncryptedClientKey", "deprecatedEncryptedPrivateKey", "deprecatedEncryptionParams")
    AUTHREQUEST_FIELD_NUMBER: _ClassVar[int]
    USERAUTHREQUEST_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDCLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    DEPRECATEDAUTHHASHHASH_FIELD_NUMBER: _ClassVar[int]
    DEPRECATEDENCRYPTEDCLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    DEPRECATEDENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    DEPRECATEDENCRYPTIONPARAMS_FIELD_NUMBER: _ClassVar[int]
    authRequest: AuthRequest
    userAuthRequest: UserAuthRequest
    encryptedClientKey: bytes
    encryptedPrivateKey: bytes
    publicKey: bytes
    verificationCode: str
    deprecatedAuthHashHash: bytes
    deprecatedEncryptedClientKey: bytes
    deprecatedEncryptedPrivateKey: bytes
    deprecatedEncryptionParams: bytes
    def __init__(self, authRequest: _Optional[_Union[AuthRequest, _Mapping]] = ..., userAuthRequest: _Optional[_Union[UserAuthRequest, _Mapping]] = ..., encryptedClientKey: _Optional[bytes] = ..., encryptedPrivateKey: _Optional[bytes] = ..., publicKey: _Optional[bytes] = ..., verificationCode: _Optional[str] = ..., deprecatedAuthHashHash: _Optional[bytes] = ..., deprecatedEncryptedClientKey: _Optional[bytes] = ..., deprecatedEncryptedPrivateKey: _Optional[bytes] = ..., deprecatedEncryptionParams: _Optional[bytes] = ...) -> None: ...

class ConvertUserToV3Request(_message.Message):
    __slots__ = ("authRequest", "userAuthRequest", "encryptedClientKey", "encryptedPrivateKey", "publicKey")
    AUTHREQUEST_FIELD_NUMBER: _ClassVar[int]
    USERAUTHREQUEST_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDCLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    authRequest: AuthRequest
    userAuthRequest: UserAuthRequest
    encryptedClientKey: bytes
    encryptedPrivateKey: bytes
    publicKey: bytes
    def __init__(self, authRequest: _Optional[_Union[AuthRequest, _Mapping]] = ..., userAuthRequest: _Optional[_Union[UserAuthRequest, _Mapping]] = ..., encryptedClientKey: _Optional[bytes] = ..., encryptedPrivateKey: _Optional[bytes] = ..., publicKey: _Optional[bytes] = ...) -> None: ...

class RevisionResponse(_message.Message):
    __slots__ = ("revision",)
    REVISION_FIELD_NUMBER: _ClassVar[int]
    revision: int
    def __init__(self, revision: _Optional[int] = ...) -> None: ...

class ChangeEmailRequest(_message.Message):
    __slots__ = ("newEmail",)
    NEWEMAIL_FIELD_NUMBER: _ClassVar[int]
    newEmail: str
    def __init__(self, newEmail: _Optional[str] = ...) -> None: ...

class ChangeEmailResponse(_message.Message):
    __slots__ = ("encryptedChangeEmailToken",)
    ENCRYPTEDCHANGEEMAILTOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedChangeEmailToken: bytes
    def __init__(self, encryptedChangeEmailToken: _Optional[bytes] = ...) -> None: ...

class EmailVerificationLinkResponse(_message.Message):
    __slots__ = ("emailVerified",)
    EMAILVERIFIED_FIELD_NUMBER: _ClassVar[int]
    emailVerified: bool
    def __init__(self, emailVerified: _Optional[bool] = ...) -> None: ...

class SecurityData(_message.Message):
    __slots__ = ("uid", "data")
    UID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    data: bytes
    def __init__(self, uid: _Optional[bytes] = ..., data: _Optional[bytes] = ...) -> None: ...

class SecurityScoreData(_message.Message):
    __slots__ = ("uid", "data", "revision")
    UID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    data: bytes
    revision: int
    def __init__(self, uid: _Optional[bytes] = ..., data: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class SecurityDataRequest(_message.Message):
    __slots__ = ("recordSecurityData", "masterPasswordSecurityData", "encryptionType", "recordSecurityScoreData")
    RECORDSECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    MASTERPASSWORDSECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    RECORDSECURITYSCOREDATA_FIELD_NUMBER: _ClassVar[int]
    recordSecurityData: _containers.RepeatedCompositeFieldContainer[SecurityData]
    masterPasswordSecurityData: _containers.RepeatedCompositeFieldContainer[SecurityData]
    encryptionType: _enterprise_pb2.EncryptedKeyType
    recordSecurityScoreData: _containers.RepeatedCompositeFieldContainer[SecurityScoreData]
    def __init__(self, recordSecurityData: _Optional[_Iterable[_Union[SecurityData, _Mapping]]] = ..., masterPasswordSecurityData: _Optional[_Iterable[_Union[SecurityData, _Mapping]]] = ..., encryptionType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., recordSecurityScoreData: _Optional[_Iterable[_Union[SecurityScoreData, _Mapping]]] = ...) -> None: ...

class SecurityReportIncrementalData(_message.Message):
    __slots__ = ("enterpriseUserId", "currentSecurityData", "currentSecurityDataRevision", "oldSecurityData", "oldSecurityDataRevision", "currentDataEncryptionType", "oldDataEncryptionType", "recordUid")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    CURRENTSECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    CURRENTSECURITYDATAREVISION_FIELD_NUMBER: _ClassVar[int]
    OLDSECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    OLDSECURITYDATAREVISION_FIELD_NUMBER: _ClassVar[int]
    CURRENTDATAENCRYPTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    OLDDATAENCRYPTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    currentSecurityData: bytes
    currentSecurityDataRevision: int
    oldSecurityData: bytes
    oldSecurityDataRevision: int
    currentDataEncryptionType: _enterprise_pb2.EncryptedKeyType
    oldDataEncryptionType: _enterprise_pb2.EncryptedKeyType
    recordUid: bytes
    def __init__(self, enterpriseUserId: _Optional[int] = ..., currentSecurityData: _Optional[bytes] = ..., currentSecurityDataRevision: _Optional[int] = ..., oldSecurityData: _Optional[bytes] = ..., oldSecurityDataRevision: _Optional[int] = ..., currentDataEncryptionType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., oldDataEncryptionType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., recordUid: _Optional[bytes] = ...) -> None: ...

class SecurityReport(_message.Message):
    __slots__ = ("enterpriseUserId", "encryptedReportData", "revision", "twoFactor", "lastLogin", "numberOfReusedPassword", "securityReportIncrementalData", "userId", "hasOldEncryption")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDREPORTDATA_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    TWOFACTOR_FIELD_NUMBER: _ClassVar[int]
    LASTLOGIN_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFREUSEDPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SECURITYREPORTINCREMENTALDATA_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    HASOLDENCRYPTION_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    encryptedReportData: bytes
    revision: int
    twoFactor: str
    lastLogin: int
    numberOfReusedPassword: int
    securityReportIncrementalData: _containers.RepeatedCompositeFieldContainer[SecurityReportIncrementalData]
    userId: int
    hasOldEncryption: bool
    def __init__(self, enterpriseUserId: _Optional[int] = ..., encryptedReportData: _Optional[bytes] = ..., revision: _Optional[int] = ..., twoFactor: _Optional[str] = ..., lastLogin: _Optional[int] = ..., numberOfReusedPassword: _Optional[int] = ..., securityReportIncrementalData: _Optional[_Iterable[_Union[SecurityReportIncrementalData, _Mapping]]] = ..., userId: _Optional[int] = ..., hasOldEncryption: _Optional[bool] = ...) -> None: ...

class SecurityReportSaveRequest(_message.Message):
    __slots__ = ("securityReport", "continuationToken")
    SECURITYREPORT_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    securityReport: _containers.RepeatedCompositeFieldContainer[SecurityReport]
    continuationToken: bytes
    def __init__(self, securityReport: _Optional[_Iterable[_Union[SecurityReport, _Mapping]]] = ..., continuationToken: _Optional[bytes] = ...) -> None: ...

class SecurityReportRequest(_message.Message):
    __slots__ = ("fromPage",)
    FROMPAGE_FIELD_NUMBER: _ClassVar[int]
    fromPage: int
    def __init__(self, fromPage: _Optional[int] = ...) -> None: ...

class SecurityReportResponse(_message.Message):
    __slots__ = ("enterprisePrivateKey", "securityReport", "asOfRevision", "fromPage", "toPage", "complete", "enterpriseEccPrivateKey", "hasIncrementalData")
    ENTERPRISEPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    SECURITYREPORT_FIELD_NUMBER: _ClassVar[int]
    ASOFREVISION_FIELD_NUMBER: _ClassVar[int]
    FROMPAGE_FIELD_NUMBER: _ClassVar[int]
    TOPAGE_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEECCPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    HASINCREMENTALDATA_FIELD_NUMBER: _ClassVar[int]
    enterprisePrivateKey: bytes
    securityReport: _containers.RepeatedCompositeFieldContainer[SecurityReport]
    asOfRevision: int
    fromPage: int
    toPage: int
    complete: bool
    enterpriseEccPrivateKey: bytes
    hasIncrementalData: bool
    def __init__(self, enterprisePrivateKey: _Optional[bytes] = ..., securityReport: _Optional[_Iterable[_Union[SecurityReport, _Mapping]]] = ..., asOfRevision: _Optional[int] = ..., fromPage: _Optional[int] = ..., toPage: _Optional[int] = ..., complete: _Optional[bool] = ..., enterpriseEccPrivateKey: _Optional[bytes] = ..., hasIncrementalData: _Optional[bool] = ...) -> None: ...

class IncrementalSecurityDataRequest(_message.Message):
    __slots__ = ("continuationToken",)
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    def __init__(self, continuationToken: _Optional[bytes] = ...) -> None: ...

class IncrementalSecurityDataResponse(_message.Message):
    __slots__ = ("securityReportIncrementalData", "continuationToken")
    SECURITYREPORTINCREMENTALDATA_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    securityReportIncrementalData: _containers.RepeatedCompositeFieldContainer[SecurityReportIncrementalData]
    continuationToken: bytes
    def __init__(self, securityReportIncrementalData: _Optional[_Iterable[_Union[SecurityReportIncrementalData, _Mapping]]] = ..., continuationToken: _Optional[bytes] = ...) -> None: ...

class ReusedPasswordsRequest(_message.Message):
    __slots__ = ("count",)
    COUNT_FIELD_NUMBER: _ClassVar[int]
    count: int
    def __init__(self, count: _Optional[int] = ...) -> None: ...

class SummaryConsoleReport(_message.Message):
    __slots__ = ("reportType", "reportData")
    REPORTTYPE_FIELD_NUMBER: _ClassVar[int]
    REPORTDATA_FIELD_NUMBER: _ClassVar[int]
    reportType: int
    reportData: bytes
    def __init__(self, reportType: _Optional[int] = ..., reportData: _Optional[bytes] = ...) -> None: ...

class ChangeToKeyTypeOne(_message.Message):
    __slots__ = ("objectType", "primaryUid", "secondaryUid", "key")
    OBJECTTYPE_FIELD_NUMBER: _ClassVar[int]
    PRIMARYUID_FIELD_NUMBER: _ClassVar[int]
    SECONDARYUID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    objectType: ObjectTypes
    primaryUid: bytes
    secondaryUid: bytes
    key: bytes
    def __init__(self, objectType: _Optional[_Union[ObjectTypes, str]] = ..., primaryUid: _Optional[bytes] = ..., secondaryUid: _Optional[bytes] = ..., key: _Optional[bytes] = ...) -> None: ...

class ChangeToKeyTypeOneRequest(_message.Message):
    __slots__ = ("changeToKeyTypeOne",)
    CHANGETOKEYTYPEONE_FIELD_NUMBER: _ClassVar[int]
    changeToKeyTypeOne: _containers.RepeatedCompositeFieldContainer[ChangeToKeyTypeOne]
    def __init__(self, changeToKeyTypeOne: _Optional[_Iterable[_Union[ChangeToKeyTypeOne, _Mapping]]] = ...) -> None: ...

class ChangeToKeyTypeOneStatus(_message.Message):
    __slots__ = ("uid", "type", "status", "reason")
    UID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    type: str
    status: str
    reason: str
    def __init__(self, uid: _Optional[bytes] = ..., type: _Optional[str] = ..., status: _Optional[str] = ..., reason: _Optional[str] = ...) -> None: ...

class ChangeToKeyTypeOneResponse(_message.Message):
    __slots__ = ("changeToKeyTypeOneStatus",)
    CHANGETOKEYTYPEONESTATUS_FIELD_NUMBER: _ClassVar[int]
    changeToKeyTypeOneStatus: _containers.RepeatedCompositeFieldContainer[ChangeToKeyTypeOneStatus]
    def __init__(self, changeToKeyTypeOneStatus: _Optional[_Iterable[_Union[ChangeToKeyTypeOneStatus, _Mapping]]] = ...) -> None: ...

class GetChangeKeyTypesRequest(_message.Message):
    __slots__ = ("onlyTheseObjects", "limit", "includeRecommended", "includeKeys", "includeAllowedKeyTypes")
    ONLYTHESEOBJECTS_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    INCLUDERECOMMENDED_FIELD_NUMBER: _ClassVar[int]
    INCLUDEKEYS_FIELD_NUMBER: _ClassVar[int]
    INCLUDEALLOWEDKEYTYPES_FIELD_NUMBER: _ClassVar[int]
    onlyTheseObjects: _containers.RepeatedScalarFieldContainer[EncryptedObjectType]
    limit: int
    includeRecommended: bool
    includeKeys: bool
    includeAllowedKeyTypes: bool
    def __init__(self, onlyTheseObjects: _Optional[_Iterable[_Union[EncryptedObjectType, str]]] = ..., limit: _Optional[int] = ..., includeRecommended: _Optional[bool] = ..., includeKeys: _Optional[bool] = ..., includeAllowedKeyTypes: _Optional[bool] = ...) -> None: ...

class GetChangeKeyTypesResponse(_message.Message):
    __slots__ = ("keys", "allowedKeyTypes")
    KEYS_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDKEYTYPES_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[ChangeKeyType]
    allowedKeyTypes: _containers.RepeatedCompositeFieldContainer[AllowedKeyTypes]
    def __init__(self, keys: _Optional[_Iterable[_Union[ChangeKeyType, _Mapping]]] = ..., allowedKeyTypes: _Optional[_Iterable[_Union[AllowedKeyTypes, _Mapping]]] = ...) -> None: ...

class AllowedKeyTypes(_message.Message):
    __slots__ = ("objectType", "allowedKeyTypes")
    OBJECTTYPE_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDKEYTYPES_FIELD_NUMBER: _ClassVar[int]
    objectType: EncryptedObjectType
    allowedKeyTypes: _containers.RepeatedScalarFieldContainer[_enterprise_pb2.EncryptedKeyType]
    def __init__(self, objectType: _Optional[_Union[EncryptedObjectType, str]] = ..., allowedKeyTypes: _Optional[_Iterable[_Union[_enterprise_pb2.EncryptedKeyType, str]]] = ...) -> None: ...

class ChangeKeyTypes(_message.Message):
    __slots__ = ("keys",)
    KEYS_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[ChangeKeyType]
    def __init__(self, keys: _Optional[_Iterable[_Union[ChangeKeyType, _Mapping]]] = ...) -> None: ...

class ChangeKeyType(_message.Message):
    __slots__ = ("objectType", "uid", "secondaryUid", "key", "keyType", "status")
    OBJECTTYPE_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    SECONDARYUID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    objectType: EncryptedObjectType
    uid: bytes
    secondaryUid: bytes
    key: bytes
    keyType: _enterprise_pb2.EncryptedKeyType
    status: GenericStatus
    def __init__(self, objectType: _Optional[_Union[EncryptedObjectType, str]] = ..., uid: _Optional[bytes] = ..., secondaryUid: _Optional[bytes] = ..., key: _Optional[bytes] = ..., keyType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., status: _Optional[_Union[GenericStatus, str]] = ...) -> None: ...

class SetKey(_message.Message):
    __slots__ = ("id", "key")
    ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    id: int
    key: bytes
    def __init__(self, id: _Optional[int] = ..., key: _Optional[bytes] = ...) -> None: ...

class SetKeyRequest(_message.Message):
    __slots__ = ("keys",)
    KEYS_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[SetKey]
    def __init__(self, keys: _Optional[_Iterable[_Union[SetKey, _Mapping]]] = ...) -> None: ...

class CreateUserRequest(_message.Message):
    __slots__ = ("username", "authVerifier", "encryptionParams", "rsaPublicKey", "rsaEncryptedPrivateKey", "eccPublicKey", "eccEncryptedPrivateKey", "encryptedDeviceToken", "encryptedClientKey", "clientVersion", "encryptedDeviceDataKey", "encryptedLoginToken", "messageSessionUid", "installReferrer", "mccMNC", "mfg", "model", "brand", "product", "device", "carrier", "verificationCode", "enterpriseRegistration", "encryptedVerificationToken", "enterpriseUsersDataKey")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    AUTHVERIFIER_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTIONPARAMS_FIELD_NUMBER: _ClassVar[int]
    RSAPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    RSAENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ECCENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDCLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICEDATAKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    INSTALLREFERRER_FIELD_NUMBER: _ClassVar[int]
    MCCMNC_FIELD_NUMBER: _ClassVar[int]
    MFG_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    BRAND_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    CARRIER_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEREGISTRATION_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDVERIFICATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERSDATAKEY_FIELD_NUMBER: _ClassVar[int]
    username: str
    authVerifier: bytes
    encryptionParams: bytes
    rsaPublicKey: bytes
    rsaEncryptedPrivateKey: bytes
    eccPublicKey: bytes
    eccEncryptedPrivateKey: bytes
    encryptedDeviceToken: bytes
    encryptedClientKey: bytes
    clientVersion: str
    encryptedDeviceDataKey: bytes
    encryptedLoginToken: bytes
    messageSessionUid: bytes
    installReferrer: str
    mccMNC: int
    mfg: str
    model: str
    brand: str
    product: str
    device: str
    carrier: str
    verificationCode: str
    enterpriseRegistration: _enterprise_pb2.EnterpriseRegistration
    encryptedVerificationToken: bytes
    enterpriseUsersDataKey: bytes
    def __init__(self, username: _Optional[str] = ..., authVerifier: _Optional[bytes] = ..., encryptionParams: _Optional[bytes] = ..., rsaPublicKey: _Optional[bytes] = ..., rsaEncryptedPrivateKey: _Optional[bytes] = ..., eccPublicKey: _Optional[bytes] = ..., eccEncryptedPrivateKey: _Optional[bytes] = ..., encryptedDeviceToken: _Optional[bytes] = ..., encryptedClientKey: _Optional[bytes] = ..., clientVersion: _Optional[str] = ..., encryptedDeviceDataKey: _Optional[bytes] = ..., encryptedLoginToken: _Optional[bytes] = ..., messageSessionUid: _Optional[bytes] = ..., installReferrer: _Optional[str] = ..., mccMNC: _Optional[int] = ..., mfg: _Optional[str] = ..., model: _Optional[str] = ..., brand: _Optional[str] = ..., product: _Optional[str] = ..., device: _Optional[str] = ..., carrier: _Optional[str] = ..., verificationCode: _Optional[str] = ..., enterpriseRegistration: _Optional[_Union[_enterprise_pb2.EnterpriseRegistration, _Mapping]] = ..., encryptedVerificationToken: _Optional[bytes] = ..., enterpriseUsersDataKey: _Optional[bytes] = ...) -> None: ...

class NodeEnforcementAddOrUpdateRequest(_message.Message):
    __slots__ = ("nodeId", "enforcement", "value")
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENFORCEMENT_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    enforcement: str
    value: str
    def __init__(self, nodeId: _Optional[int] = ..., enforcement: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class NodeEnforcementRemoveRequest(_message.Message):
    __slots__ = ("nodeId", "enforcement")
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENFORCEMENT_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    enforcement: str
    def __init__(self, nodeId: _Optional[int] = ..., enforcement: _Optional[str] = ...) -> None: ...

class ApiRequestByKey(_message.Message):
    __slots__ = ("keyId", "payload", "username", "locale", "supportedLanguage", "type")
    KEYID_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    SUPPORTEDLANGUAGE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    keyId: int
    payload: bytes
    username: str
    locale: str
    supportedLanguage: SupportedLanguage
    type: int
    def __init__(self, keyId: _Optional[int] = ..., payload: _Optional[bytes] = ..., username: _Optional[str] = ..., locale: _Optional[str] = ..., supportedLanguage: _Optional[_Union[SupportedLanguage, str]] = ..., type: _Optional[int] = ...) -> None: ...

class ApiRequestByKAtoKAKey(_message.Message):
    __slots__ = ("sourceRegion", "payload", "supportedLanguage", "destinationRegion")
    SOURCEREGION_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    SUPPORTEDLANGUAGE_FIELD_NUMBER: _ClassVar[int]
    DESTINATIONREGION_FIELD_NUMBER: _ClassVar[int]
    sourceRegion: Region
    payload: bytes
    supportedLanguage: SupportedLanguage
    destinationRegion: Region
    def __init__(self, sourceRegion: _Optional[_Union[Region, str]] = ..., payload: _Optional[bytes] = ..., supportedLanguage: _Optional[_Union[SupportedLanguage, str]] = ..., destinationRegion: _Optional[_Union[Region, str]] = ...) -> None: ...

class MemcacheRequest(_message.Message):
    __slots__ = ("key", "userId")
    KEY_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    key: str
    userId: int
    def __init__(self, key: _Optional[str] = ..., userId: _Optional[int] = ...) -> None: ...

class MemcacheResponse(_message.Message):
    __slots__ = ("key", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class MasterPasswordReentryRequest(_message.Message):
    __slots__ = ("pbkdf2Password", "action")
    PBKDF2PASSWORD_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    pbkdf2Password: str
    action: MasterPasswordReentryActionType
    def __init__(self, pbkdf2Password: _Optional[str] = ..., action: _Optional[_Union[MasterPasswordReentryActionType, str]] = ...) -> None: ...

class MasterPasswordReentryResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: MasterPasswordReentryStatus
    def __init__(self, status: _Optional[_Union[MasterPasswordReentryStatus, str]] = ...) -> None: ...

class DeviceRegistrationRequest(_message.Message):
    __slots__ = ("clientVersion", "deviceName", "devicePublicKey", "devicePlatform", "clientFormFactor", "username")
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
    CLIENTFORMFACTOR_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    clientVersion: str
    deviceName: str
    devicePublicKey: bytes
    devicePlatform: str
    clientFormFactor: ClientFormFactor
    username: str
    def __init__(self, clientVersion: _Optional[str] = ..., deviceName: _Optional[str] = ..., devicePublicKey: _Optional[bytes] = ..., devicePlatform: _Optional[str] = ..., clientFormFactor: _Optional[_Union[ClientFormFactor, str]] = ..., username: _Optional[str] = ...) -> None: ...

class DeviceVerificationRequest(_message.Message):
    __slots__ = ("encryptedDeviceToken", "username", "verificationChannel", "messageSessionUid", "clientVersion")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCHANNEL_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    username: str
    verificationChannel: str
    messageSessionUid: bytes
    clientVersion: str
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., username: _Optional[str] = ..., verificationChannel: _Optional[str] = ..., messageSessionUid: _Optional[bytes] = ..., clientVersion: _Optional[str] = ...) -> None: ...

class DeviceVerificationResponse(_message.Message):
    __slots__ = ("encryptedDeviceToken", "username", "messageSessionUid", "clientVersion", "deviceStatus")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICESTATUS_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    username: str
    messageSessionUid: bytes
    clientVersion: str
    deviceStatus: DeviceStatus
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., username: _Optional[str] = ..., messageSessionUid: _Optional[bytes] = ..., clientVersion: _Optional[str] = ..., deviceStatus: _Optional[_Union[DeviceStatus, str]] = ...) -> None: ...

class DeviceApprovalRequest(_message.Message):
    __slots__ = ("email", "twoFactorChannel", "clientVersion", "locale", "encryptedDeviceToken", "totpCode", "deviceIp", "deviceTokenExpireDays")
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    TWOFACTORCHANNEL_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    TOTPCODE_FIELD_NUMBER: _ClassVar[int]
    DEVICEIP_FIELD_NUMBER: _ClassVar[int]
    DEVICETOKENEXPIREDAYS_FIELD_NUMBER: _ClassVar[int]
    email: str
    twoFactorChannel: str
    clientVersion: str
    locale: str
    encryptedDeviceToken: bytes
    totpCode: str
    deviceIp: str
    deviceTokenExpireDays: str
    def __init__(self, email: _Optional[str] = ..., twoFactorChannel: _Optional[str] = ..., clientVersion: _Optional[str] = ..., locale: _Optional[str] = ..., encryptedDeviceToken: _Optional[bytes] = ..., totpCode: _Optional[str] = ..., deviceIp: _Optional[str] = ..., deviceTokenExpireDays: _Optional[str] = ...) -> None: ...

class DeviceApprovalResponse(_message.Message):
    __slots__ = ("encryptedTwoFactorToken",)
    ENCRYPTEDTWOFACTORTOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedTwoFactorToken: bytes
    def __init__(self, encryptedTwoFactorToken: _Optional[bytes] = ...) -> None: ...

class ApproveDeviceRequest(_message.Message):
    __slots__ = ("encryptedDeviceToken", "encryptedDeviceDataKey", "denyApproval", "linkDevice")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICEDATAKEY_FIELD_NUMBER: _ClassVar[int]
    DENYAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    LINKDEVICE_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    encryptedDeviceDataKey: bytes
    denyApproval: bool
    linkDevice: bool
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., encryptedDeviceDataKey: _Optional[bytes] = ..., denyApproval: _Optional[bool] = ..., linkDevice: _Optional[bool] = ...) -> None: ...

class EnterpriseUserAliasRequest(_message.Message):
    __slots__ = ("enterpriseUserId", "alias")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    alias: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., alias: _Optional[str] = ...) -> None: ...

class EnterpriseUserAddAliasRequest(_message.Message):
    __slots__ = ("enterpriseUserId", "alias", "primary")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    PRIMARY_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    alias: str
    primary: bool
    def __init__(self, enterpriseUserId: _Optional[int] = ..., alias: _Optional[str] = ..., primary: _Optional[bool] = ...) -> None: ...

class EnterpriseUserAddAliasRequestV2(_message.Message):
    __slots__ = ("enterpriseUserAddAliasRequest",)
    ENTERPRISEUSERADDALIASREQUEST_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserAddAliasRequest: _containers.RepeatedCompositeFieldContainer[EnterpriseUserAddAliasRequest]
    def __init__(self, enterpriseUserAddAliasRequest: _Optional[_Iterable[_Union[EnterpriseUserAddAliasRequest, _Mapping]]] = ...) -> None: ...

class EnterpriseUserAddAliasStatus(_message.Message):
    __slots__ = ("enterpriseUserId", "status")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    status: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., status: _Optional[str] = ...) -> None: ...

class EnterpriseUserAddAliasResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: _containers.RepeatedCompositeFieldContainer[EnterpriseUserAddAliasStatus]
    def __init__(self, status: _Optional[_Iterable[_Union[EnterpriseUserAddAliasStatus, _Mapping]]] = ...) -> None: ...

class Device(_message.Message):
    __slots__ = ("encryptedDeviceToken",)
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ...) -> None: ...

class RegisterDeviceDataKeyRequest(_message.Message):
    __slots__ = ("encryptedDeviceToken", "encryptedDeviceDataKey")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICEDATAKEY_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    encryptedDeviceDataKey: bytes
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., encryptedDeviceDataKey: _Optional[bytes] = ...) -> None: ...

class ValidateCreateUserVerificationCodeRequest(_message.Message):
    __slots__ = ("username", "clientVersion", "verificationCode")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    username: str
    clientVersion: str
    verificationCode: str
    def __init__(self, username: _Optional[str] = ..., clientVersion: _Optional[str] = ..., verificationCode: _Optional[str] = ...) -> None: ...

class ValidateDeviceVerificationCodeRequest(_message.Message):
    __slots__ = ("username", "clientVersion", "verificationCode", "messageSessionUid", "encryptedDeviceToken")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    username: str
    clientVersion: str
    verificationCode: str
    messageSessionUid: bytes
    encryptedDeviceToken: bytes
    def __init__(self, username: _Optional[str] = ..., clientVersion: _Optional[str] = ..., verificationCode: _Optional[str] = ..., messageSessionUid: _Optional[bytes] = ..., encryptedDeviceToken: _Optional[bytes] = ...) -> None: ...

class SendSessionMessageRequest(_message.Message):
    __slots__ = ("messageSessionUid", "command", "username")
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    messageSessionUid: bytes
    command: str
    username: str
    def __init__(self, messageSessionUid: _Optional[bytes] = ..., command: _Optional[str] = ..., username: _Optional[str] = ...) -> None: ...

class GlobalUserAccount(_message.Message):
    __slots__ = ("username", "accountUid", "regionName")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    REGIONNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    accountUid: bytes
    regionName: str
    def __init__(self, username: _Optional[str] = ..., accountUid: _Optional[bytes] = ..., regionName: _Optional[str] = ...) -> None: ...

class AccountUsername(_message.Message):
    __slots__ = ("username", "dateActive")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    DATEACTIVE_FIELD_NUMBER: _ClassVar[int]
    username: str
    dateActive: str
    def __init__(self, username: _Optional[str] = ..., dateActive: _Optional[str] = ...) -> None: ...

class SsoServiceProviderRequest(_message.Message):
    __slots__ = ("name", "clientVersion", "locale")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    name: str
    clientVersion: str
    locale: str
    def __init__(self, name: _Optional[str] = ..., clientVersion: _Optional[str] = ..., locale: _Optional[str] = ...) -> None: ...

class SsoServiceProviderResponse(_message.Message):
    __slots__ = ("name", "spUrl", "isCloud", "clientVersion")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SPURL_FIELD_NUMBER: _ClassVar[int]
    ISCLOUD_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    name: str
    spUrl: str
    isCloud: bool
    clientVersion: str
    def __init__(self, name: _Optional[str] = ..., spUrl: _Optional[str] = ..., isCloud: _Optional[bool] = ..., clientVersion: _Optional[str] = ...) -> None: ...

class UserSettingRequest(_message.Message):
    __slots__ = ("setting", "value")
    SETTING_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    setting: str
    value: str
    def __init__(self, setting: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class ThrottleState(_message.Message):
    __slots__ = ("type", "key", "value", "state")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    type: ThrottleType
    key: str
    value: str
    state: bool
    def __init__(self, type: _Optional[_Union[ThrottleType, str]] = ..., key: _Optional[str] = ..., value: _Optional[str] = ..., state: _Optional[bool] = ...) -> None: ...

class ThrottleState2(_message.Message):
    __slots__ = ("key", "keyDescription", "value", "valueDescription", "identifier", "locked", "includedInAllClear", "expireSeconds")
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEYDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    VALUEDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    LOCKED_FIELD_NUMBER: _ClassVar[int]
    INCLUDEDINALLCLEAR_FIELD_NUMBER: _ClassVar[int]
    EXPIRESECONDS_FIELD_NUMBER: _ClassVar[int]
    key: str
    keyDescription: str
    value: str
    valueDescription: str
    identifier: str
    locked: bool
    includedInAllClear: bool
    expireSeconds: int
    def __init__(self, key: _Optional[str] = ..., keyDescription: _Optional[str] = ..., value: _Optional[str] = ..., valueDescription: _Optional[str] = ..., identifier: _Optional[str] = ..., locked: _Optional[bool] = ..., includedInAllClear: _Optional[bool] = ..., expireSeconds: _Optional[int] = ...) -> None: ...

class DeviceInformation(_message.Message):
    __slots__ = ("deviceId", "deviceName", "clientVersion", "lastLogin", "deviceStatus")
    DEVICEID_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    LASTLOGIN_FIELD_NUMBER: _ClassVar[int]
    DEVICESTATUS_FIELD_NUMBER: _ClassVar[int]
    deviceId: int
    deviceName: str
    clientVersion: str
    lastLogin: int
    deviceStatus: DeviceStatus
    def __init__(self, deviceId: _Optional[int] = ..., deviceName: _Optional[str] = ..., clientVersion: _Optional[str] = ..., lastLogin: _Optional[int] = ..., deviceStatus: _Optional[_Union[DeviceStatus, str]] = ...) -> None: ...

class UserSetting(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: bool
    def __init__(self, name: _Optional[str] = ..., value: _Optional[bool] = ...) -> None: ...

class UserDataKeyRequest(_message.Message):
    __slots__ = ("enterpriseUserId",)
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, enterpriseUserId: _Optional[_Iterable[int]] = ...) -> None: ...

class UserDataKeyByNodeRequest(_message.Message):
    __slots__ = ("nodeIds",)
    NODEIDS_FIELD_NUMBER: _ClassVar[int]
    nodeIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, nodeIds: _Optional[_Iterable[int]] = ...) -> None: ...

class EnterpriseUserIdDataKeyPair(_message.Message):
    __slots__ = ("enterpriseUserId", "encryptedDataKey", "keyType")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    encryptedDataKey: bytes
    keyType: _enterprise_pb2.EncryptedKeyType
    def __init__(self, enterpriseUserId: _Optional[int] = ..., encryptedDataKey: _Optional[bytes] = ..., keyType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ...) -> None: ...

class UserDataKey(_message.Message):
    __slots__ = ("roleId", "roleKey", "privateKey", "enterpriseUserIdDataKeyPairs")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ROLEKEY_FIELD_NUMBER: _ClassVar[int]
    PRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERIDDATAKEYPAIRS_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    roleKey: bytes
    privateKey: str
    enterpriseUserIdDataKeyPairs: _containers.RepeatedCompositeFieldContainer[EnterpriseUserIdDataKeyPair]
    def __init__(self, roleId: _Optional[int] = ..., roleKey: _Optional[bytes] = ..., privateKey: _Optional[str] = ..., enterpriseUserIdDataKeyPairs: _Optional[_Iterable[_Union[EnterpriseUserIdDataKeyPair, _Mapping]]] = ...) -> None: ...

class UserDataKeyResponse(_message.Message):
    __slots__ = ("userDataKeys", "accessDenied", "noEncryptedDataKey")
    USERDATAKEYS_FIELD_NUMBER: _ClassVar[int]
    ACCESSDENIED_FIELD_NUMBER: _ClassVar[int]
    NOENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    userDataKeys: _containers.RepeatedCompositeFieldContainer[UserDataKey]
    accessDenied: _containers.RepeatedScalarFieldContainer[int]
    noEncryptedDataKey: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, userDataKeys: _Optional[_Iterable[_Union[UserDataKey, _Mapping]]] = ..., accessDenied: _Optional[_Iterable[int]] = ..., noEncryptedDataKey: _Optional[_Iterable[int]] = ...) -> None: ...

class MasterPasswordRecoveryVerificationRequest(_message.Message):
    __slots__ = ("encryptedLoginToken",)
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedLoginToken: bytes
    def __init__(self, encryptedLoginToken: _Optional[bytes] = ...) -> None: ...

class GetSecurityQuestionV3Request(_message.Message):
    __slots__ = ("encryptedLoginToken", "verificationCode")
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    encryptedLoginToken: bytes
    verificationCode: str
    def __init__(self, encryptedLoginToken: _Optional[bytes] = ..., verificationCode: _Optional[str] = ...) -> None: ...

class GetSecurityQuestionV3Response(_message.Message):
    __slots__ = ("securityQuestion", "backupKeyDate", "salt", "iterations")
    SECURITYQUESTION_FIELD_NUMBER: _ClassVar[int]
    BACKUPKEYDATE_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    securityQuestion: str
    backupKeyDate: int
    salt: bytes
    iterations: int
    def __init__(self, securityQuestion: _Optional[str] = ..., backupKeyDate: _Optional[int] = ..., salt: _Optional[bytes] = ..., iterations: _Optional[int] = ...) -> None: ...

class GetDataKeyBackupV3Request(_message.Message):
    __slots__ = ("encryptedLoginToken", "verificationCode", "securityAnswerHash")
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    SECURITYANSWERHASH_FIELD_NUMBER: _ClassVar[int]
    encryptedLoginToken: bytes
    verificationCode: str
    securityAnswerHash: bytes
    def __init__(self, encryptedLoginToken: _Optional[bytes] = ..., verificationCode: _Optional[str] = ..., securityAnswerHash: _Optional[bytes] = ...) -> None: ...

class PasswordRules(_message.Message):
    __slots__ = ("ruleType", "match", "pattern", "description", "minimum", "value")
    RULETYPE_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ruleType: str
    match: bool
    pattern: str
    description: str
    minimum: int
    value: str
    def __init__(self, ruleType: _Optional[str] = ..., match: _Optional[bool] = ..., pattern: _Optional[str] = ..., description: _Optional[str] = ..., minimum: _Optional[int] = ..., value: _Optional[str] = ...) -> None: ...

class GetDataKeyBackupV3Response(_message.Message):
    __slots__ = ("dataKeyBackup", "dataKeyBackupDate", "publicKey", "encryptedPrivateKey", "clientKey", "encryptedSessionToken", "passwordRules", "passwordRulesIntro", "minimumPbkdf2Iterations", "keyType")
    DATAKEYBACKUP_FIELD_NUMBER: _ClassVar[int]
    DATAKEYBACKUPDATE_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    CLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    PASSWORDRULES_FIELD_NUMBER: _ClassVar[int]
    PASSWORDRULESINTRO_FIELD_NUMBER: _ClassVar[int]
    MINIMUMPBKDF2ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    dataKeyBackup: bytes
    dataKeyBackupDate: int
    publicKey: bytes
    encryptedPrivateKey: bytes
    clientKey: bytes
    encryptedSessionToken: bytes
    passwordRules: _containers.RepeatedCompositeFieldContainer[PasswordRules]
    passwordRulesIntro: str
    minimumPbkdf2Iterations: int
    keyType: _enterprise_pb2.KeyType
    def __init__(self, dataKeyBackup: _Optional[bytes] = ..., dataKeyBackupDate: _Optional[int] = ..., publicKey: _Optional[bytes] = ..., encryptedPrivateKey: _Optional[bytes] = ..., clientKey: _Optional[bytes] = ..., encryptedSessionToken: _Optional[bytes] = ..., passwordRules: _Optional[_Iterable[_Union[PasswordRules, _Mapping]]] = ..., passwordRulesIntro: _Optional[str] = ..., minimumPbkdf2Iterations: _Optional[int] = ..., keyType: _Optional[_Union[_enterprise_pb2.KeyType, str]] = ...) -> None: ...

class GetPublicKeysRequest(_message.Message):
    __slots__ = ("usernames",)
    USERNAMES_FIELD_NUMBER: _ClassVar[int]
    usernames: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, usernames: _Optional[_Iterable[str]] = ...) -> None: ...

class PublicKeyResponse(_message.Message):
    __slots__ = ("username", "publicKey", "publicEccKey", "message", "errorCode")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    PUBLICECCKEY_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ERRORCODE_FIELD_NUMBER: _ClassVar[int]
    username: str
    publicKey: bytes
    publicEccKey: bytes
    message: str
    errorCode: str
    def __init__(self, username: _Optional[str] = ..., publicKey: _Optional[bytes] = ..., publicEccKey: _Optional[bytes] = ..., message: _Optional[str] = ..., errorCode: _Optional[str] = ...) -> None: ...

class GetPublicKeysResponse(_message.Message):
    __slots__ = ("keyResponses",)
    KEYRESPONSES_FIELD_NUMBER: _ClassVar[int]
    keyResponses: _containers.RepeatedCompositeFieldContainer[PublicKeyResponse]
    def __init__(self, keyResponses: _Optional[_Iterable[_Union[PublicKeyResponse, _Mapping]]] = ...) -> None: ...

class SetEccKeyPairRequest(_message.Message):
    __slots__ = ("publicKey", "encryptedPrivateKey")
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    publicKey: bytes
    encryptedPrivateKey: bytes
    def __init__(self, publicKey: _Optional[bytes] = ..., encryptedPrivateKey: _Optional[bytes] = ...) -> None: ...

class SetEccKeyPairsRequest(_message.Message):
    __slots__ = ("teamKeys",)
    TEAMKEYS_FIELD_NUMBER: _ClassVar[int]
    teamKeys: _containers.RepeatedCompositeFieldContainer[TeamEccKeyPair]
    def __init__(self, teamKeys: _Optional[_Iterable[_Union[TeamEccKeyPair, _Mapping]]] = ...) -> None: ...

class SetEccKeyPairsResponse(_message.Message):
    __slots__ = ("teamKeys",)
    TEAMKEYS_FIELD_NUMBER: _ClassVar[int]
    teamKeys: _containers.RepeatedCompositeFieldContainer[TeamEccKeyPairResponse]
    def __init__(self, teamKeys: _Optional[_Iterable[_Union[TeamEccKeyPairResponse, _Mapping]]] = ...) -> None: ...

class TeamEccKeyPair(_message.Message):
    __slots__ = ("teamUid", "publicKey", "encryptedPrivateKey")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    publicKey: bytes
    encryptedPrivateKey: bytes
    def __init__(self, teamUid: _Optional[bytes] = ..., publicKey: _Optional[bytes] = ..., encryptedPrivateKey: _Optional[bytes] = ...) -> None: ...

class TeamEccKeyPairResponse(_message.Message):
    __slots__ = ("teamUid", "status")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    status: GenericStatus
    def __init__(self, teamUid: _Optional[bytes] = ..., status: _Optional[_Union[GenericStatus, str]] = ...) -> None: ...

class GetKsmPublicKeysRequest(_message.Message):
    __slots__ = ("clientIds", "controllerUids")
    CLIENTIDS_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUIDS_FIELD_NUMBER: _ClassVar[int]
    clientIds: _containers.RepeatedScalarFieldContainer[bytes]
    controllerUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, clientIds: _Optional[_Iterable[bytes]] = ..., controllerUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class DevicePublicKeyResponse(_message.Message):
    __slots__ = ("clientId", "publicKey", "controllerUid")
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    clientId: bytes
    publicKey: bytes
    controllerUid: bytes
    def __init__(self, clientId: _Optional[bytes] = ..., publicKey: _Optional[bytes] = ..., controllerUid: _Optional[bytes] = ...) -> None: ...

class GetKsmPublicKeysResponse(_message.Message):
    __slots__ = ("keyResponses",)
    KEYRESPONSES_FIELD_NUMBER: _ClassVar[int]
    keyResponses: _containers.RepeatedCompositeFieldContainer[DevicePublicKeyResponse]
    def __init__(self, keyResponses: _Optional[_Iterable[_Union[DevicePublicKeyResponse, _Mapping]]] = ...) -> None: ...

class AddAppSharesRequest(_message.Message):
    __slots__ = ("appRecordUid", "shares")
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHARES_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: bytes
    shares: _containers.RepeatedCompositeFieldContainer[AppShareAdd]
    def __init__(self, appRecordUid: _Optional[bytes] = ..., shares: _Optional[_Iterable[_Union[AppShareAdd, _Mapping]]] = ...) -> None: ...

class RemoveAppSharesRequest(_message.Message):
    __slots__ = ("appRecordUid", "shares")
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHARES_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: bytes
    shares: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, appRecordUid: _Optional[bytes] = ..., shares: _Optional[_Iterable[bytes]] = ...) -> None: ...

class AppShareAdd(_message.Message):
    __slots__ = ("secretUid", "shareType", "encryptedSecretKey", "editable")
    SECRETUID_FIELD_NUMBER: _ClassVar[int]
    SHARETYPE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSECRETKEY_FIELD_NUMBER: _ClassVar[int]
    EDITABLE_FIELD_NUMBER: _ClassVar[int]
    secretUid: bytes
    shareType: ApplicationShareType
    encryptedSecretKey: bytes
    editable: bool
    def __init__(self, secretUid: _Optional[bytes] = ..., shareType: _Optional[_Union[ApplicationShareType, str]] = ..., encryptedSecretKey: _Optional[bytes] = ..., editable: _Optional[bool] = ...) -> None: ...

class AppShare(_message.Message):
    __slots__ = ("secretUid", "shareType", "editable", "createdOn", "data")
    SECRETUID_FIELD_NUMBER: _ClassVar[int]
    SHARETYPE_FIELD_NUMBER: _ClassVar[int]
    EDITABLE_FIELD_NUMBER: _ClassVar[int]
    CREATEDON_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    secretUid: bytes
    shareType: ApplicationShareType
    editable: bool
    createdOn: int
    data: bytes
    def __init__(self, secretUid: _Optional[bytes] = ..., shareType: _Optional[_Union[ApplicationShareType, str]] = ..., editable: _Optional[bool] = ..., createdOn: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class AddAppClientRequest(_message.Message):
    __slots__ = ("appRecordUid", "encryptedAppKey", "clientId", "lockIp", "firstAccessExpireOn", "accessExpireOn", "id", "appClientType")
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDAPPKEY_FIELD_NUMBER: _ClassVar[int]
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    LOCKIP_FIELD_NUMBER: _ClassVar[int]
    FIRSTACCESSEXPIREON_FIELD_NUMBER: _ClassVar[int]
    ACCESSEXPIREON_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    APPCLIENTTYPE_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: bytes
    encryptedAppKey: bytes
    clientId: bytes
    lockIp: bool
    firstAccessExpireOn: int
    accessExpireOn: int
    id: str
    appClientType: _enterprise_pb2.AppClientType
    def __init__(self, appRecordUid: _Optional[bytes] = ..., encryptedAppKey: _Optional[bytes] = ..., clientId: _Optional[bytes] = ..., lockIp: _Optional[bool] = ..., firstAccessExpireOn: _Optional[int] = ..., accessExpireOn: _Optional[int] = ..., id: _Optional[str] = ..., appClientType: _Optional[_Union[_enterprise_pb2.AppClientType, str]] = ...) -> None: ...

class RemoveAppClientsRequest(_message.Message):
    __slots__ = ("appRecordUid", "clients")
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    CLIENTS_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: bytes
    clients: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, appRecordUid: _Optional[bytes] = ..., clients: _Optional[_Iterable[bytes]] = ...) -> None: ...

class AddExternalShareRequest(_message.Message):
    __slots__ = ("recordUid", "encryptedRecordKey", "clientId", "accessExpireOn", "id", "isSelfDestruct", "isEditable")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDKEY_FIELD_NUMBER: _ClassVar[int]
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    ACCESSEXPIREON_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    ISSELFDESTRUCT_FIELD_NUMBER: _ClassVar[int]
    ISEDITABLE_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    encryptedRecordKey: bytes
    clientId: bytes
    accessExpireOn: int
    id: str
    isSelfDestruct: bool
    isEditable: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., encryptedRecordKey: _Optional[bytes] = ..., clientId: _Optional[bytes] = ..., accessExpireOn: _Optional[int] = ..., id: _Optional[str] = ..., isSelfDestruct: _Optional[bool] = ..., isEditable: _Optional[bool] = ...) -> None: ...

class AppClient(_message.Message):
    __slots__ = ("id", "clientId", "createdOn", "firstAccess", "lastAccess", "publicKey", "lockIp", "ipAddress", "firstAccessExpireOn", "accessExpireOn", "appClientType", "canEdit")
    ID_FIELD_NUMBER: _ClassVar[int]
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    CREATEDON_FIELD_NUMBER: _ClassVar[int]
    FIRSTACCESS_FIELD_NUMBER: _ClassVar[int]
    LASTACCESS_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    LOCKIP_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    FIRSTACCESSEXPIREON_FIELD_NUMBER: _ClassVar[int]
    ACCESSEXPIREON_FIELD_NUMBER: _ClassVar[int]
    APPCLIENTTYPE_FIELD_NUMBER: _ClassVar[int]
    CANEDIT_FIELD_NUMBER: _ClassVar[int]
    id: str
    clientId: bytes
    createdOn: int
    firstAccess: int
    lastAccess: int
    publicKey: bytes
    lockIp: bool
    ipAddress: str
    firstAccessExpireOn: int
    accessExpireOn: int
    appClientType: _enterprise_pb2.AppClientType
    canEdit: bool
    def __init__(self, id: _Optional[str] = ..., clientId: _Optional[bytes] = ..., createdOn: _Optional[int] = ..., firstAccess: _Optional[int] = ..., lastAccess: _Optional[int] = ..., publicKey: _Optional[bytes] = ..., lockIp: _Optional[bool] = ..., ipAddress: _Optional[str] = ..., firstAccessExpireOn: _Optional[int] = ..., accessExpireOn: _Optional[int] = ..., appClientType: _Optional[_Union[_enterprise_pb2.AppClientType, str]] = ..., canEdit: _Optional[bool] = ...) -> None: ...

class GetAppInfoRequest(_message.Message):
    __slots__ = ("appRecordUid",)
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, appRecordUid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class AppInfo(_message.Message):
    __slots__ = ("appRecordUid", "shares", "clients", "isExternalShare")
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHARES_FIELD_NUMBER: _ClassVar[int]
    CLIENTS_FIELD_NUMBER: _ClassVar[int]
    ISEXTERNALSHARE_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: bytes
    shares: _containers.RepeatedCompositeFieldContainer[AppShare]
    clients: _containers.RepeatedCompositeFieldContainer[AppClient]
    isExternalShare: bool
    def __init__(self, appRecordUid: _Optional[bytes] = ..., shares: _Optional[_Iterable[_Union[AppShare, _Mapping]]] = ..., clients: _Optional[_Iterable[_Union[AppClient, _Mapping]]] = ..., isExternalShare: _Optional[bool] = ...) -> None: ...

class GetAppInfoResponse(_message.Message):
    __slots__ = ("appInfo",)
    APPINFO_FIELD_NUMBER: _ClassVar[int]
    appInfo: _containers.RepeatedCompositeFieldContainer[AppInfo]
    def __init__(self, appInfo: _Optional[_Iterable[_Union[AppInfo, _Mapping]]] = ...) -> None: ...

class ApplicationSummary(_message.Message):
    __slots__ = ("appRecordUid", "lastAccess", "recordShares", "folderShares", "folderRecords", "clientCount", "expiredClientCount", "username", "appData")
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    LASTACCESS_FIELD_NUMBER: _ClassVar[int]
    RECORDSHARES_FIELD_NUMBER: _ClassVar[int]
    FOLDERSHARES_FIELD_NUMBER: _ClassVar[int]
    FOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    CLIENTCOUNT_FIELD_NUMBER: _ClassVar[int]
    EXPIREDCLIENTCOUNT_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    APPDATA_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: bytes
    lastAccess: int
    recordShares: int
    folderShares: int
    folderRecords: int
    clientCount: int
    expiredClientCount: int
    username: str
    appData: bytes
    def __init__(self, appRecordUid: _Optional[bytes] = ..., lastAccess: _Optional[int] = ..., recordShares: _Optional[int] = ..., folderShares: _Optional[int] = ..., folderRecords: _Optional[int] = ..., clientCount: _Optional[int] = ..., expiredClientCount: _Optional[int] = ..., username: _Optional[str] = ..., appData: _Optional[bytes] = ...) -> None: ...

class GetApplicationsSummaryResponse(_message.Message):
    __slots__ = ("applicationSummary",)
    APPLICATIONSUMMARY_FIELD_NUMBER: _ClassVar[int]
    applicationSummary: _containers.RepeatedCompositeFieldContainer[ApplicationSummary]
    def __init__(self, applicationSummary: _Optional[_Iterable[_Union[ApplicationSummary, _Mapping]]] = ...) -> None: ...

class GetVerificationTokenRequest(_message.Message):
    __slots__ = ("username",)
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    def __init__(self, username: _Optional[str] = ...) -> None: ...

class GetVerificationTokenResponse(_message.Message):
    __slots__ = ("encryptedVerificationToken",)
    ENCRYPTEDVERIFICATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedVerificationToken: bytes
    def __init__(self, encryptedVerificationToken: _Optional[bytes] = ...) -> None: ...

class SendShareInviteRequest(_message.Message):
    __slots__ = ("email",)
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    email: str
    def __init__(self, email: _Optional[str] = ...) -> None: ...

class TimeLimitedAccessRequest(_message.Message):
    __slots__ = ("accountUid", "teamUid", "recordUid", "sharedObjectUid", "timeLimitedAccessType", "expiration")
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDOBJECTUID_FIELD_NUMBER: _ClassVar[int]
    TIMELIMITEDACCESSTYPE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    accountUid: _containers.RepeatedScalarFieldContainer[bytes]
    teamUid: _containers.RepeatedScalarFieldContainer[bytes]
    recordUid: _containers.RepeatedScalarFieldContainer[bytes]
    sharedObjectUid: bytes
    timeLimitedAccessType: TimeLimitedAccessType
    expiration: int
    def __init__(self, accountUid: _Optional[_Iterable[bytes]] = ..., teamUid: _Optional[_Iterable[bytes]] = ..., recordUid: _Optional[_Iterable[bytes]] = ..., sharedObjectUid: _Optional[bytes] = ..., timeLimitedAccessType: _Optional[_Union[TimeLimitedAccessType, str]] = ..., expiration: _Optional[int] = ...) -> None: ...

class TimeLimitedAccessStatus(_message.Message):
    __slots__ = ("uid", "message")
    UID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    message: str
    def __init__(self, uid: _Optional[bytes] = ..., message: _Optional[str] = ...) -> None: ...

class TimeLimitedAccessResponse(_message.Message):
    __slots__ = ("revision", "userAccessStatus", "teamAccessStatus", "recordAccessStatus")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    USERACCESSSTATUS_FIELD_NUMBER: _ClassVar[int]
    TEAMACCESSSTATUS_FIELD_NUMBER: _ClassVar[int]
    RECORDACCESSSTATUS_FIELD_NUMBER: _ClassVar[int]
    revision: int
    userAccessStatus: _containers.RepeatedCompositeFieldContainer[TimeLimitedAccessStatus]
    teamAccessStatus: _containers.RepeatedCompositeFieldContainer[TimeLimitedAccessStatus]
    recordAccessStatus: _containers.RepeatedCompositeFieldContainer[TimeLimitedAccessStatus]
    def __init__(self, revision: _Optional[int] = ..., userAccessStatus: _Optional[_Iterable[_Union[TimeLimitedAccessStatus, _Mapping]]] = ..., teamAccessStatus: _Optional[_Iterable[_Union[TimeLimitedAccessStatus, _Mapping]]] = ..., recordAccessStatus: _Optional[_Iterable[_Union[TimeLimitedAccessStatus, _Mapping]]] = ...) -> None: ...

class RequestDownloadRequest(_message.Message):
    __slots__ = ("fileNames",)
    FILENAMES_FIELD_NUMBER: _ClassVar[int]
    fileNames: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, fileNames: _Optional[_Iterable[str]] = ...) -> None: ...

class RequestDownloadResponse(_message.Message):
    __slots__ = ("result", "message", "downloads")
    RESULT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADS_FIELD_NUMBER: _ClassVar[int]
    result: str
    message: str
    downloads: _containers.RepeatedCompositeFieldContainer[Download]
    def __init__(self, result: _Optional[str] = ..., message: _Optional[str] = ..., downloads: _Optional[_Iterable[_Union[Download, _Mapping]]] = ...) -> None: ...

class Download(_message.Message):
    __slots__ = ("fileName", "url", "successStatusCode")
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    SUCCESSSTATUSCODE_FIELD_NUMBER: _ClassVar[int]
    fileName: str
    url: str
    successStatusCode: int
    def __init__(self, fileName: _Optional[str] = ..., url: _Optional[str] = ..., successStatusCode: _Optional[int] = ...) -> None: ...

class DeleteUserRequest(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: str
    def __init__(self, reason: _Optional[str] = ...) -> None: ...

class ChangeMasterPasswordRequest(_message.Message):
    __slots__ = ("authVerifier", "encryptionParams", "fromServiceProvider", "iterationsChange")
    AUTHVERIFIER_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTIONPARAMS_FIELD_NUMBER: _ClassVar[int]
    FROMSERVICEPROVIDER_FIELD_NUMBER: _ClassVar[int]
    ITERATIONSCHANGE_FIELD_NUMBER: _ClassVar[int]
    authVerifier: bytes
    encryptionParams: bytes
    fromServiceProvider: bool
    iterationsChange: bool
    def __init__(self, authVerifier: _Optional[bytes] = ..., encryptionParams: _Optional[bytes] = ..., fromServiceProvider: _Optional[bool] = ..., iterationsChange: _Optional[bool] = ...) -> None: ...

class ChangeMasterPasswordResponse(_message.Message):
    __slots__ = ("encryptedSessionToken",)
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    encryptedSessionToken: bytes
    def __init__(self, encryptedSessionToken: _Optional[bytes] = ...) -> None: ...

class AccountRecoverySetupRequest(_message.Message):
    __slots__ = ("recoveryEncryptedDataKey", "recoveryAuthHash")
    RECOVERYENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    RECOVERYAUTHHASH_FIELD_NUMBER: _ClassVar[int]
    recoveryEncryptedDataKey: bytes
    recoveryAuthHash: bytes
    def __init__(self, recoveryEncryptedDataKey: _Optional[bytes] = ..., recoveryAuthHash: _Optional[bytes] = ...) -> None: ...

class AccountRecoveryVerifyCodeResponse(_message.Message):
    __slots__ = ("backupKeyType", "backupKeyDate", "securityQuestion", "salt", "iterations")
    BACKUPKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    BACKUPKEYDATE_FIELD_NUMBER: _ClassVar[int]
    SECURITYQUESTION_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    backupKeyType: BackupKeyType
    backupKeyDate: int
    securityQuestion: str
    salt: bytes
    iterations: int
    def __init__(self, backupKeyType: _Optional[_Union[BackupKeyType, str]] = ..., backupKeyDate: _Optional[int] = ..., securityQuestion: _Optional[str] = ..., salt: _Optional[bytes] = ..., iterations: _Optional[int] = ...) -> None: ...

class EmergencyAccessLoginRequest(_message.Message):
    __slots__ = ("owner",)
    OWNER_FIELD_NUMBER: _ClassVar[int]
    owner: str
    def __init__(self, owner: _Optional[str] = ...) -> None: ...

class EmergencyAccessLoginResponse(_message.Message):
    __slots__ = ("sessionToken", "dataKey", "rsaPrivateKey", "eccPrivateKey")
    SESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    DATAKEY_FIELD_NUMBER: _ClassVar[int]
    RSAPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ECCPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    sessionToken: bytes
    dataKey: _enterprise_pb2.TypedKey
    rsaPrivateKey: _enterprise_pb2.TypedKey
    eccPrivateKey: _enterprise_pb2.TypedKey
    def __init__(self, sessionToken: _Optional[bytes] = ..., dataKey: _Optional[_Union[_enterprise_pb2.TypedKey, _Mapping]] = ..., rsaPrivateKey: _Optional[_Union[_enterprise_pb2.TypedKey, _Mapping]] = ..., eccPrivateKey: _Optional[_Union[_enterprise_pb2.TypedKey, _Mapping]] = ...) -> None: ...

class UserTeamKey(_message.Message):
    __slots__ = ("teamUid", "username", "enterpriseUserId", "encryptedTeamKeyRSA", "encryptedTeamKeyEC", "status")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEYRSA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEYEC_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    username: str
    enterpriseUserId: int
    encryptedTeamKeyRSA: bytes
    encryptedTeamKeyEC: bytes
    status: GenericStatus
    def __init__(self, teamUid: _Optional[bytes] = ..., username: _Optional[str] = ..., enterpriseUserId: _Optional[int] = ..., encryptedTeamKeyRSA: _Optional[bytes] = ..., encryptedTeamKeyEC: _Optional[bytes] = ..., status: _Optional[_Union[GenericStatus, str]] = ...) -> None: ...

class GenericRequestResponse(_message.Message):
    __slots__ = ("request",)
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    request: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, request: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PasskeyRegistrationRequest(_message.Message):
    __slots__ = ("authenticatorAttachment",)
    AUTHENTICATORATTACHMENT_FIELD_NUMBER: _ClassVar[int]
    authenticatorAttachment: AuthenticatorAttachment
    def __init__(self, authenticatorAttachment: _Optional[_Union[AuthenticatorAttachment, str]] = ...) -> None: ...

class PasskeyRegistrationResponse(_message.Message):
    __slots__ = ("challengeToken", "pkCreationOptions")
    CHALLENGETOKEN_FIELD_NUMBER: _ClassVar[int]
    PKCREATIONOPTIONS_FIELD_NUMBER: _ClassVar[int]
    challengeToken: bytes
    pkCreationOptions: str
    def __init__(self, challengeToken: _Optional[bytes] = ..., pkCreationOptions: _Optional[str] = ...) -> None: ...

class PasskeyRegistrationFinalization(_message.Message):
    __slots__ = ("challengeToken", "authenticatorResponse", "friendlyName")
    CHALLENGETOKEN_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATORRESPONSE_FIELD_NUMBER: _ClassVar[int]
    FRIENDLYNAME_FIELD_NUMBER: _ClassVar[int]
    challengeToken: bytes
    authenticatorResponse: str
    friendlyName: str
    def __init__(self, challengeToken: _Optional[bytes] = ..., authenticatorResponse: _Optional[str] = ..., friendlyName: _Optional[str] = ...) -> None: ...

class PasskeyAuthenticationRequest(_message.Message):
    __slots__ = ("authenticatorAttachment", "passkeyPurpose", "clientVersion", "encryptedDeviceToken", "username", "encryptedLoginToken")
    AUTHENTICATORATTACHMENT_FIELD_NUMBER: _ClassVar[int]
    PASSKEYPURPOSE_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    authenticatorAttachment: AuthenticatorAttachment
    passkeyPurpose: PasskeyPurpose
    clientVersion: str
    encryptedDeviceToken: bytes
    username: str
    encryptedLoginToken: bytes
    def __init__(self, authenticatorAttachment: _Optional[_Union[AuthenticatorAttachment, str]] = ..., passkeyPurpose: _Optional[_Union[PasskeyPurpose, str]] = ..., clientVersion: _Optional[str] = ..., encryptedDeviceToken: _Optional[bytes] = ..., username: _Optional[str] = ..., encryptedLoginToken: _Optional[bytes] = ...) -> None: ...

class PasskeyAuthenticationResponse(_message.Message):
    __slots__ = ("pkRequestOptions", "challengeToken", "encryptedLoginToken")
    PKREQUESTOPTIONS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGETOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    pkRequestOptions: str
    challengeToken: bytes
    encryptedLoginToken: bytes
    def __init__(self, pkRequestOptions: _Optional[str] = ..., challengeToken: _Optional[bytes] = ..., encryptedLoginToken: _Optional[bytes] = ...) -> None: ...

class PasskeyValidationRequest(_message.Message):
    __slots__ = ("challengeToken", "assertionResponse", "passkeyPurpose", "encryptedLoginToken")
    CHALLENGETOKEN_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONRESPONSE_FIELD_NUMBER: _ClassVar[int]
    PASSKEYPURPOSE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    challengeToken: bytes
    assertionResponse: bytes
    passkeyPurpose: PasskeyPurpose
    encryptedLoginToken: bytes
    def __init__(self, challengeToken: _Optional[bytes] = ..., assertionResponse: _Optional[bytes] = ..., passkeyPurpose: _Optional[_Union[PasskeyPurpose, str]] = ..., encryptedLoginToken: _Optional[bytes] = ...) -> None: ...

class PasskeyValidationResponse(_message.Message):
    __slots__ = ("isValid", "encryptedLoginToken")
    ISVALID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDLOGINTOKEN_FIELD_NUMBER: _ClassVar[int]
    isValid: bool
    encryptedLoginToken: bytes
    def __init__(self, isValid: _Optional[bool] = ..., encryptedLoginToken: _Optional[bytes] = ...) -> None: ...

class UpdatePasskeyRequest(_message.Message):
    __slots__ = ("userId", "credentialId", "friendlyName")
    USERID_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALID_FIELD_NUMBER: _ClassVar[int]
    FRIENDLYNAME_FIELD_NUMBER: _ClassVar[int]
    userId: int
    credentialId: bytes
    friendlyName: str
    def __init__(self, userId: _Optional[int] = ..., credentialId: _Optional[bytes] = ..., friendlyName: _Optional[str] = ...) -> None: ...

class PasskeyListRequest(_message.Message):
    __slots__ = ("includeDisabled",)
    INCLUDEDISABLED_FIELD_NUMBER: _ClassVar[int]
    includeDisabled: bool
    def __init__(self, includeDisabled: _Optional[bool] = ...) -> None: ...

class PasskeyInfo(_message.Message):
    __slots__ = ("userId", "credentialId", "friendlyName", "AAGUID", "createdAtMillis", "lastUsedMillis", "disabledAtMillis")
    USERID_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALID_FIELD_NUMBER: _ClassVar[int]
    FRIENDLYNAME_FIELD_NUMBER: _ClassVar[int]
    AAGUID_FIELD_NUMBER: _ClassVar[int]
    CREATEDATMILLIS_FIELD_NUMBER: _ClassVar[int]
    LASTUSEDMILLIS_FIELD_NUMBER: _ClassVar[int]
    DISABLEDATMILLIS_FIELD_NUMBER: _ClassVar[int]
    userId: int
    credentialId: bytes
    friendlyName: str
    AAGUID: str
    createdAtMillis: int
    lastUsedMillis: int
    disabledAtMillis: int
    def __init__(self, userId: _Optional[int] = ..., credentialId: _Optional[bytes] = ..., friendlyName: _Optional[str] = ..., AAGUID: _Optional[str] = ..., createdAtMillis: _Optional[int] = ..., lastUsedMillis: _Optional[int] = ..., disabledAtMillis: _Optional[int] = ...) -> None: ...

class PasskeyListResponse(_message.Message):
    __slots__ = ("passkeyInfo",)
    PASSKEYINFO_FIELD_NUMBER: _ClassVar[int]
    passkeyInfo: _containers.RepeatedCompositeFieldContainer[PasskeyInfo]
    def __init__(self, passkeyInfo: _Optional[_Iterable[_Union[PasskeyInfo, _Mapping]]] = ...) -> None: ...

class TranslationInfo(_message.Message):
    __slots__ = ("translationKey", "translationValue")
    TRANSLATIONKEY_FIELD_NUMBER: _ClassVar[int]
    TRANSLATIONVALUE_FIELD_NUMBER: _ClassVar[int]
    translationKey: str
    translationValue: str
    def __init__(self, translationKey: _Optional[str] = ..., translationValue: _Optional[str] = ...) -> None: ...

class TranslationRequest(_message.Message):
    __slots__ = ("translationKey",)
    TRANSLATIONKEY_FIELD_NUMBER: _ClassVar[int]
    translationKey: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, translationKey: _Optional[_Iterable[str]] = ...) -> None: ...

class TranslationResponse(_message.Message):
    __slots__ = ("translationInfo",)
    TRANSLATIONINFO_FIELD_NUMBER: _ClassVar[int]
    translationInfo: _containers.RepeatedCompositeFieldContainer[TranslationInfo]
    def __init__(self, translationInfo: _Optional[_Iterable[_Union[TranslationInfo, _Mapping]]] = ...) -> None: ...
