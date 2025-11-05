import record_pb2 as _record_pb2
import tla_pb2 as _tla_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RecordType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    password: _ClassVar[RecordType]

class FolderType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    default_folder: _ClassVar[FolderType]
    user_folder: _ClassVar[FolderType]
    shared_folder: _ClassVar[FolderType]
    shared_folder_folder: _ClassVar[FolderType]

class EncryptedKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    no_key: _ClassVar[EncryptedKeyType]
    encrypted_by_data_key: _ClassVar[EncryptedKeyType]
    encrypted_by_public_key: _ClassVar[EncryptedKeyType]
    encrypted_by_data_key_gcm: _ClassVar[EncryptedKeyType]
    encrypted_by_public_key_ecc: _ClassVar[EncryptedKeyType]

class SetBooleanValue(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BOOLEAN_NO_CHANGE: _ClassVar[SetBooleanValue]
    BOOLEAN_TRUE: _ClassVar[SetBooleanValue]
    BOOLEAN_FALSE: _ClassVar[SetBooleanValue]

class FolderUsageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UT_UNKNOWN: _ClassVar[FolderUsageType]
    UT_NORMAL: _ClassVar[FolderUsageType]
    UT_WORKFLOW: _ClassVar[FolderUsageType]

class FolderKeyEncryptionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENCRYPTED_BY_USER_KEY: _ClassVar[FolderKeyEncryptionType]
    ENCRYPTED_BY_PARENT_KEY: _ClassVar[FolderKeyEncryptionType]

class FolderModifyStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SUCCESS: _ClassVar[FolderModifyStatus]
    BAD_REQUEST: _ClassVar[FolderModifyStatus]
    ACCESS_DENIED: _ClassVar[FolderModifyStatus]
    NOT_FOUND: _ClassVar[FolderModifyStatus]

class FolderPermissionBits(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    noBits: _ClassVar[FolderPermissionBits]
    canAddUsers: _ClassVar[FolderPermissionBits]
    canRemoveUsers: _ClassVar[FolderPermissionBits]
    canAddRecords: _ClassVar[FolderPermissionBits]
    canRemoveRecords: _ClassVar[FolderPermissionBits]
    canDeleteRecords: _ClassVar[FolderPermissionBits]
    canCreateFolders: _ClassVar[FolderPermissionBits]
    canDeleteFolders: _ClassVar[FolderPermissionBits]
    canChangeUserPermissions: _ClassVar[FolderPermissionBits]
    canChangeRecordPermissions: _ClassVar[FolderPermissionBits]
    canChangeFolderOwnership: _ClassVar[FolderPermissionBits]
    canChangeRecordOwnership: _ClassVar[FolderPermissionBits]
    canEditRecords: _ClassVar[FolderPermissionBits]
    canViewRecords: _ClassVar[FolderPermissionBits]
    canReshareRecords: _ClassVar[FolderPermissionBits]
    canApproveAccess: _ClassVar[FolderPermissionBits]
    canRequestAccess: _ClassVar[FolderPermissionBits]
    canUpdateSetting: _ClassVar[FolderPermissionBits]

class AccessRoleType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NO_ROLE: _ClassVar[AccessRoleType]
    VIEWER: _ClassVar[AccessRoleType]
    SHARED_MANAGER: _ClassVar[AccessRoleType]
    CONTRIBUTOR: _ClassVar[AccessRoleType]
    CONTENT_MANAGER: _ClassVar[AccessRoleType]
    MANAGER: _ClassVar[AccessRoleType]

class AccessType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AT_UNKNOWN: _ClassVar[AccessType]
    AT_OWNER: _ClassVar[AccessType]
    AT_USER: _ClassVar[AccessType]
    AT_TEAM: _ClassVar[AccessType]
    AT_ENTERPRISE: _ClassVar[AccessType]
    AT_FOLDER: _ClassVar[AccessType]
    AT_APPLICATION: _ClassVar[AccessType]

class ObjectType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OT_UNKNOWN: _ClassVar[ObjectType]
    OT_RECORD: _ClassVar[ObjectType]
    OT_FOLDER: _ClassVar[ObjectType]
password: RecordType
default_folder: FolderType
user_folder: FolderType
shared_folder: FolderType
shared_folder_folder: FolderType
no_key: EncryptedKeyType
encrypted_by_data_key: EncryptedKeyType
encrypted_by_public_key: EncryptedKeyType
encrypted_by_data_key_gcm: EncryptedKeyType
encrypted_by_public_key_ecc: EncryptedKeyType
BOOLEAN_NO_CHANGE: SetBooleanValue
BOOLEAN_TRUE: SetBooleanValue
BOOLEAN_FALSE: SetBooleanValue
UT_UNKNOWN: FolderUsageType
UT_NORMAL: FolderUsageType
UT_WORKFLOW: FolderUsageType
ENCRYPTED_BY_USER_KEY: FolderKeyEncryptionType
ENCRYPTED_BY_PARENT_KEY: FolderKeyEncryptionType
SUCCESS: FolderModifyStatus
BAD_REQUEST: FolderModifyStatus
ACCESS_DENIED: FolderModifyStatus
NOT_FOUND: FolderModifyStatus
noBits: FolderPermissionBits
canAddUsers: FolderPermissionBits
canRemoveUsers: FolderPermissionBits
canAddRecords: FolderPermissionBits
canRemoveRecords: FolderPermissionBits
canDeleteRecords: FolderPermissionBits
canCreateFolders: FolderPermissionBits
canDeleteFolders: FolderPermissionBits
canChangeUserPermissions: FolderPermissionBits
canChangeRecordPermissions: FolderPermissionBits
canChangeFolderOwnership: FolderPermissionBits
canChangeRecordOwnership: FolderPermissionBits
canEditRecords: FolderPermissionBits
canViewRecords: FolderPermissionBits
canReshareRecords: FolderPermissionBits
canApproveAccess: FolderPermissionBits
canRequestAccess: FolderPermissionBits
canUpdateSetting: FolderPermissionBits
NO_ROLE: AccessRoleType
VIEWER: AccessRoleType
SHARED_MANAGER: AccessRoleType
CONTRIBUTOR: AccessRoleType
CONTENT_MANAGER: AccessRoleType
MANAGER: AccessRoleType
AT_UNKNOWN: AccessType
AT_OWNER: AccessType
AT_USER: AccessType
AT_TEAM: AccessType
AT_ENTERPRISE: AccessType
AT_FOLDER: AccessType
AT_APPLICATION: AccessType
OT_UNKNOWN: ObjectType
OT_RECORD: ObjectType
OT_FOLDER: ObjectType

class EncryptedDataKey(_message.Message):
    __slots__ = ("encryptedKey", "encryptedKeyType")
    ENCRYPTEDKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    encryptedKey: bytes
    encryptedKeyType: EncryptedKeyType
    def __init__(self, encryptedKey: _Optional[bytes] = ..., encryptedKeyType: _Optional[_Union[EncryptedKeyType, str]] = ...) -> None: ...

class SharedFolderRecordData(_message.Message):
    __slots__ = ("folderUid", "recordUid", "userId", "encryptedDataKey")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordUid: bytes
    userId: int
    encryptedDataKey: _containers.RepeatedCompositeFieldContainer[EncryptedDataKey]
    def __init__(self, folderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., userId: _Optional[int] = ..., encryptedDataKey: _Optional[_Iterable[_Union[EncryptedDataKey, _Mapping]]] = ...) -> None: ...

class SharedFolderRecordDataList(_message.Message):
    __slots__ = ("sharedFolderRecordData",)
    SHAREDFOLDERRECORDDATA_FIELD_NUMBER: _ClassVar[int]
    sharedFolderRecordData: _containers.RepeatedCompositeFieldContainer[SharedFolderRecordData]
    def __init__(self, sharedFolderRecordData: _Optional[_Iterable[_Union[SharedFolderRecordData, _Mapping]]] = ...) -> None: ...

class SharedFolderRecordFix(_message.Message):
    __slots__ = ("folderUid", "recordUid", "encryptedRecordFolderKey")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordUid: bytes
    encryptedRecordFolderKey: bytes
    def __init__(self, folderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., encryptedRecordFolderKey: _Optional[bytes] = ...) -> None: ...

class SharedFolderRecordFixList(_message.Message):
    __slots__ = ("sharedFolderRecordFix",)
    SHAREDFOLDERRECORDFIX_FIELD_NUMBER: _ClassVar[int]
    sharedFolderRecordFix: _containers.RepeatedCompositeFieldContainer[SharedFolderRecordFix]
    def __init__(self, sharedFolderRecordFix: _Optional[_Iterable[_Union[SharedFolderRecordFix, _Mapping]]] = ...) -> None: ...

class RecordRequest(_message.Message):
    __slots__ = ("recordUid", "recordType", "recordData", "encryptedRecordKey", "folderType", "howLongAgo", "folderUid", "encryptedRecordFolderKey", "extra", "nonSharedData", "fileIds")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDTYPE_FIELD_NUMBER: _ClassVar[int]
    RECORDDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDKEY_FIELD_NUMBER: _ClassVar[int]
    FOLDERTYPE_FIELD_NUMBER: _ClassVar[int]
    HOWLONGAGO_FIELD_NUMBER: _ClassVar[int]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    EXTRA_FIELD_NUMBER: _ClassVar[int]
    NONSHAREDDATA_FIELD_NUMBER: _ClassVar[int]
    FILEIDS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    recordType: RecordType
    recordData: bytes
    encryptedRecordKey: bytes
    folderType: FolderType
    howLongAgo: int
    folderUid: bytes
    encryptedRecordFolderKey: bytes
    extra: bytes
    nonSharedData: bytes
    fileIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, recordUid: _Optional[bytes] = ..., recordType: _Optional[_Union[RecordType, str]] = ..., recordData: _Optional[bytes] = ..., encryptedRecordKey: _Optional[bytes] = ..., folderType: _Optional[_Union[FolderType, str]] = ..., howLongAgo: _Optional[int] = ..., folderUid: _Optional[bytes] = ..., encryptedRecordFolderKey: _Optional[bytes] = ..., extra: _Optional[bytes] = ..., nonSharedData: _Optional[bytes] = ..., fileIds: _Optional[_Iterable[int]] = ...) -> None: ...

class RecordResponse(_message.Message):
    __slots__ = ("recordUid", "revision", "status")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    revision: int
    status: str
    def __init__(self, recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderFields(_message.Message):
    __slots__ = ("encryptedFolderName", "manageUsers", "manageRecords", "canEdit", "canShare")
    ENCRYPTEDFOLDERNAME_FIELD_NUMBER: _ClassVar[int]
    MANAGEUSERS_FIELD_NUMBER: _ClassVar[int]
    MANAGERECORDS_FIELD_NUMBER: _ClassVar[int]
    CANEDIT_FIELD_NUMBER: _ClassVar[int]
    CANSHARE_FIELD_NUMBER: _ClassVar[int]
    encryptedFolderName: bytes
    manageUsers: bool
    manageRecords: bool
    canEdit: bool
    canShare: bool
    def __init__(self, encryptedFolderName: _Optional[bytes] = ..., manageUsers: bool = ..., manageRecords: bool = ..., canEdit: bool = ..., canShare: bool = ...) -> None: ...

class SharedFolderFolderFields(_message.Message):
    __slots__ = ("sharedFolderUid",)
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    def __init__(self, sharedFolderUid: _Optional[bytes] = ...) -> None: ...

class FolderRequest(_message.Message):
    __slots__ = ("folderUid", "folderType", "parentFolderUid", "folderData", "encryptedFolderKey", "sharedFolderFields", "sharedFolderFolderFields")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERTYPE_FIELD_NUMBER: _ClassVar[int]
    PARENTFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERFIELDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERFOLDERFIELDS_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    folderType: FolderType
    parentFolderUid: bytes
    folderData: bytes
    encryptedFolderKey: bytes
    sharedFolderFields: SharedFolderFields
    sharedFolderFolderFields: SharedFolderFolderFields
    def __init__(self, folderUid: _Optional[bytes] = ..., folderType: _Optional[_Union[FolderType, str]] = ..., parentFolderUid: _Optional[bytes] = ..., folderData: _Optional[bytes] = ..., encryptedFolderKey: _Optional[bytes] = ..., sharedFolderFields: _Optional[_Union[SharedFolderFields, _Mapping]] = ..., sharedFolderFolderFields: _Optional[_Union[SharedFolderFolderFields, _Mapping]] = ...) -> None: ...

class FolderResponse(_message.Message):
    __slots__ = ("folderUid", "revision", "status")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    revision: int
    status: str
    def __init__(self, folderUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., status: _Optional[str] = ...) -> None: ...

class ImportFolderRecordRequest(_message.Message):
    __slots__ = ("folderRequest", "recordRequest")
    FOLDERREQUEST_FIELD_NUMBER: _ClassVar[int]
    RECORDREQUEST_FIELD_NUMBER: _ClassVar[int]
    folderRequest: _containers.RepeatedCompositeFieldContainer[FolderRequest]
    recordRequest: _containers.RepeatedCompositeFieldContainer[RecordRequest]
    def __init__(self, folderRequest: _Optional[_Iterable[_Union[FolderRequest, _Mapping]]] = ..., recordRequest: _Optional[_Iterable[_Union[RecordRequest, _Mapping]]] = ...) -> None: ...

class ImportFolderRecordResponse(_message.Message):
    __slots__ = ("folderResponse", "recordResponse")
    FOLDERRESPONSE_FIELD_NUMBER: _ClassVar[int]
    RECORDRESPONSE_FIELD_NUMBER: _ClassVar[int]
    folderResponse: _containers.RepeatedCompositeFieldContainer[FolderResponse]
    recordResponse: _containers.RepeatedCompositeFieldContainer[RecordResponse]
    def __init__(self, folderResponse: _Optional[_Iterable[_Union[FolderResponse, _Mapping]]] = ..., recordResponse: _Optional[_Iterable[_Union[RecordResponse, _Mapping]]] = ...) -> None: ...

class SharedFolderUpdateRecord(_message.Message):
    __slots__ = ("recordUid", "sharedFolderUid", "teamUid", "canEdit", "canShare", "encryptedRecordKey", "revision", "expiration", "timerNotificationType", "rotateOnExpiration")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    CANEDIT_FIELD_NUMBER: _ClassVar[int]
    CANSHARE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDKEY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    sharedFolderUid: bytes
    teamUid: bytes
    canEdit: SetBooleanValue
    canShare: SetBooleanValue
    encryptedRecordKey: bytes
    revision: int
    expiration: int
    timerNotificationType: _record_pb2.TimerNotificationType
    rotateOnExpiration: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., sharedFolderUid: _Optional[bytes] = ..., teamUid: _Optional[bytes] = ..., canEdit: _Optional[_Union[SetBooleanValue, str]] = ..., canShare: _Optional[_Union[SetBooleanValue, str]] = ..., encryptedRecordKey: _Optional[bytes] = ..., revision: _Optional[int] = ..., expiration: _Optional[int] = ..., timerNotificationType: _Optional[_Union[_record_pb2.TimerNotificationType, str]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class SharedFolderUpdateUser(_message.Message):
    __slots__ = ("username", "manageUsers", "manageRecords", "sharedFolderKey", "expiration", "timerNotificationType", "typedSharedFolderKey", "rotateOnExpiration")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    MANAGEUSERS_FIELD_NUMBER: _ClassVar[int]
    MANAGERECORDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    TYPEDSHAREDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    username: str
    manageUsers: SetBooleanValue
    manageRecords: SetBooleanValue
    sharedFolderKey: bytes
    expiration: int
    timerNotificationType: _record_pb2.TimerNotificationType
    typedSharedFolderKey: EncryptedDataKey
    rotateOnExpiration: bool
    def __init__(self, username: _Optional[str] = ..., manageUsers: _Optional[_Union[SetBooleanValue, str]] = ..., manageRecords: _Optional[_Union[SetBooleanValue, str]] = ..., sharedFolderKey: _Optional[bytes] = ..., expiration: _Optional[int] = ..., timerNotificationType: _Optional[_Union[_record_pb2.TimerNotificationType, str]] = ..., typedSharedFolderKey: _Optional[_Union[EncryptedDataKey, _Mapping]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class SharedFolderUpdateTeam(_message.Message):
    __slots__ = ("teamUid", "manageUsers", "manageRecords", "sharedFolderKey", "expiration", "timerNotificationType", "typedSharedFolderKey", "rotateOnExpiration")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    MANAGEUSERS_FIELD_NUMBER: _ClassVar[int]
    MANAGERECORDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    TYPEDSHAREDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    manageUsers: bool
    manageRecords: bool
    sharedFolderKey: bytes
    expiration: int
    timerNotificationType: _record_pb2.TimerNotificationType
    typedSharedFolderKey: EncryptedDataKey
    rotateOnExpiration: bool
    def __init__(self, teamUid: _Optional[bytes] = ..., manageUsers: bool = ..., manageRecords: bool = ..., sharedFolderKey: _Optional[bytes] = ..., expiration: _Optional[int] = ..., timerNotificationType: _Optional[_Union[_record_pb2.TimerNotificationType, str]] = ..., typedSharedFolderKey: _Optional[_Union[EncryptedDataKey, _Mapping]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class SharedFolderUpdateV3Request(_message.Message):
    __slots__ = ("sharedFolderUpdateOperation_dont_use", "sharedFolderUid", "encryptedSharedFolderName", "revision", "forceUpdate", "fromTeamUid", "defaultManageUsers", "defaultManageRecords", "defaultCanEdit", "defaultCanShare", "sharedFolderAddRecord", "sharedFolderAddUser", "sharedFolderAddTeam", "sharedFolderUpdateRecord", "sharedFolderUpdateUser", "sharedFolderUpdateTeam", "sharedFolderRemoveRecord", "sharedFolderRemoveUser", "sharedFolderRemoveTeam", "sharedFolderOwner")
    SHAREDFOLDERUPDATEOPERATION_DONT_USE_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSHAREDFOLDERNAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    FORCEUPDATE_FIELD_NUMBER: _ClassVar[int]
    FROMTEAMUID_FIELD_NUMBER: _ClassVar[int]
    DEFAULTMANAGEUSERS_FIELD_NUMBER: _ClassVar[int]
    DEFAULTMANAGERECORDS_FIELD_NUMBER: _ClassVar[int]
    DEFAULTCANEDIT_FIELD_NUMBER: _ClassVar[int]
    DEFAULTCANSHARE_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERADDRECORD_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERADDUSER_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERADDTEAM_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUPDATERECORD_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUPDATEUSER_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUPDATETEAM_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERREMOVERECORD_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERREMOVEUSER_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERREMOVETEAM_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDEROWNER_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUpdateOperation_dont_use: int
    sharedFolderUid: bytes
    encryptedSharedFolderName: bytes
    revision: int
    forceUpdate: bool
    fromTeamUid: bytes
    defaultManageUsers: SetBooleanValue
    defaultManageRecords: SetBooleanValue
    defaultCanEdit: SetBooleanValue
    defaultCanShare: SetBooleanValue
    sharedFolderAddRecord: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateRecord]
    sharedFolderAddUser: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateUser]
    sharedFolderAddTeam: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateTeam]
    sharedFolderUpdateRecord: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateRecord]
    sharedFolderUpdateUser: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateUser]
    sharedFolderUpdateTeam: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateTeam]
    sharedFolderRemoveRecord: _containers.RepeatedScalarFieldContainer[bytes]
    sharedFolderRemoveUser: _containers.RepeatedScalarFieldContainer[str]
    sharedFolderRemoveTeam: _containers.RepeatedScalarFieldContainer[bytes]
    sharedFolderOwner: str
    def __init__(self, sharedFolderUpdateOperation_dont_use: _Optional[int] = ..., sharedFolderUid: _Optional[bytes] = ..., encryptedSharedFolderName: _Optional[bytes] = ..., revision: _Optional[int] = ..., forceUpdate: bool = ..., fromTeamUid: _Optional[bytes] = ..., defaultManageUsers: _Optional[_Union[SetBooleanValue, str]] = ..., defaultManageRecords: _Optional[_Union[SetBooleanValue, str]] = ..., defaultCanEdit: _Optional[_Union[SetBooleanValue, str]] = ..., defaultCanShare: _Optional[_Union[SetBooleanValue, str]] = ..., sharedFolderAddRecord: _Optional[_Iterable[_Union[SharedFolderUpdateRecord, _Mapping]]] = ..., sharedFolderAddUser: _Optional[_Iterable[_Union[SharedFolderUpdateUser, _Mapping]]] = ..., sharedFolderAddTeam: _Optional[_Iterable[_Union[SharedFolderUpdateTeam, _Mapping]]] = ..., sharedFolderUpdateRecord: _Optional[_Iterable[_Union[SharedFolderUpdateRecord, _Mapping]]] = ..., sharedFolderUpdateUser: _Optional[_Iterable[_Union[SharedFolderUpdateUser, _Mapping]]] = ..., sharedFolderUpdateTeam: _Optional[_Iterable[_Union[SharedFolderUpdateTeam, _Mapping]]] = ..., sharedFolderRemoveRecord: _Optional[_Iterable[bytes]] = ..., sharedFolderRemoveUser: _Optional[_Iterable[str]] = ..., sharedFolderRemoveTeam: _Optional[_Iterable[bytes]] = ..., sharedFolderOwner: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateV3RequestV2(_message.Message):
    __slots__ = ("sharedFoldersUpdateV3",)
    SHAREDFOLDERSUPDATEV3_FIELD_NUMBER: _ClassVar[int]
    sharedFoldersUpdateV3: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateV3Request]
    def __init__(self, sharedFoldersUpdateV3: _Optional[_Iterable[_Union[SharedFolderUpdateV3Request, _Mapping]]] = ...) -> None: ...

class SharedFolderUpdateRecordStatus(_message.Message):
    __slots__ = ("recordUid", "status")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    status: str
    def __init__(self, recordUid: _Optional[bytes] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateUserStatus(_message.Message):
    __slots__ = ("username", "status")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    username: str
    status: str
    def __init__(self, username: _Optional[str] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateTeamStatus(_message.Message):
    __slots__ = ("teamUid", "status")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    status: str
    def __init__(self, teamUid: _Optional[bytes] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateV3Response(_message.Message):
    __slots__ = ("revision", "sharedFolderAddRecordStatus", "sharedFolderAddUserStatus", "sharedFolderAddTeamStatus", "sharedFolderUpdateRecordStatus", "sharedFolderUpdateUserStatus", "sharedFolderUpdateTeamStatus", "sharedFolderRemoveRecordStatus", "sharedFolderRemoveUserStatus", "sharedFolderRemoveTeamStatus", "sharedFolderUid", "status")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERADDRECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERADDUSERSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERADDTEAMSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUPDATERECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUPDATEUSERSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUPDATETEAMSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERREMOVERECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERREMOVEUSERSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERREMOVETEAMSTATUS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    revision: int
    sharedFolderAddRecordStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateRecordStatus]
    sharedFolderAddUserStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateUserStatus]
    sharedFolderAddTeamStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateTeamStatus]
    sharedFolderUpdateRecordStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateRecordStatus]
    sharedFolderUpdateUserStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateUserStatus]
    sharedFolderUpdateTeamStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateTeamStatus]
    sharedFolderRemoveRecordStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateRecordStatus]
    sharedFolderRemoveUserStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateUserStatus]
    sharedFolderRemoveTeamStatus: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateTeamStatus]
    sharedFolderUid: bytes
    status: str
    def __init__(self, revision: _Optional[int] = ..., sharedFolderAddRecordStatus: _Optional[_Iterable[_Union[SharedFolderUpdateRecordStatus, _Mapping]]] = ..., sharedFolderAddUserStatus: _Optional[_Iterable[_Union[SharedFolderUpdateUserStatus, _Mapping]]] = ..., sharedFolderAddTeamStatus: _Optional[_Iterable[_Union[SharedFolderUpdateTeamStatus, _Mapping]]] = ..., sharedFolderUpdateRecordStatus: _Optional[_Iterable[_Union[SharedFolderUpdateRecordStatus, _Mapping]]] = ..., sharedFolderUpdateUserStatus: _Optional[_Iterable[_Union[SharedFolderUpdateUserStatus, _Mapping]]] = ..., sharedFolderUpdateTeamStatus: _Optional[_Iterable[_Union[SharedFolderUpdateTeamStatus, _Mapping]]] = ..., sharedFolderRemoveRecordStatus: _Optional[_Iterable[_Union[SharedFolderUpdateRecordStatus, _Mapping]]] = ..., sharedFolderRemoveUserStatus: _Optional[_Iterable[_Union[SharedFolderUpdateUserStatus, _Mapping]]] = ..., sharedFolderRemoveTeamStatus: _Optional[_Iterable[_Union[SharedFolderUpdateTeamStatus, _Mapping]]] = ..., sharedFolderUid: _Optional[bytes] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateV3ResponseV2(_message.Message):
    __slots__ = ("sharedFoldersUpdateV3Response",)
    SHAREDFOLDERSUPDATEV3RESPONSE_FIELD_NUMBER: _ClassVar[int]
    sharedFoldersUpdateV3Response: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateV3Response]
    def __init__(self, sharedFoldersUpdateV3Response: _Optional[_Iterable[_Union[SharedFolderUpdateV3Response, _Mapping]]] = ...) -> None: ...

class GetDeletedSharedFoldersAndRecordsResponse(_message.Message):
    __slots__ = ("sharedFolders", "sharedFolderRecords", "deletedRecordData", "usernames")
    SHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    DELETEDRECORDDATA_FIELD_NUMBER: _ClassVar[int]
    USERNAMES_FIELD_NUMBER: _ClassVar[int]
    sharedFolders: _containers.RepeatedCompositeFieldContainer[DeletedSharedFolder]
    sharedFolderRecords: _containers.RepeatedCompositeFieldContainer[DeletedSharedFolderRecord]
    deletedRecordData: _containers.RepeatedCompositeFieldContainer[DeletedRecordData]
    usernames: _containers.RepeatedCompositeFieldContainer[Username]
    def __init__(self, sharedFolders: _Optional[_Iterable[_Union[DeletedSharedFolder, _Mapping]]] = ..., sharedFolderRecords: _Optional[_Iterable[_Union[DeletedSharedFolderRecord, _Mapping]]] = ..., deletedRecordData: _Optional[_Iterable[_Union[DeletedRecordData, _Mapping]]] = ..., usernames: _Optional[_Iterable[_Union[Username, _Mapping]]] = ...) -> None: ...

class DeletedSharedFolder(_message.Message):
    __slots__ = ("sharedFolderUid", "folderUid", "parentUid", "sharedFolderKey", "folderKeyType", "data", "dateDeleted", "revision")
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    PARENTUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    FOLDERKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    DATEDELETED_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    folderUid: bytes
    parentUid: bytes
    sharedFolderKey: bytes
    folderKeyType: _record_pb2.RecordKeyType
    data: bytes
    dateDeleted: int
    revision: int
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., folderUid: _Optional[bytes] = ..., parentUid: _Optional[bytes] = ..., sharedFolderKey: _Optional[bytes] = ..., folderKeyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ..., data: _Optional[bytes] = ..., dateDeleted: _Optional[int] = ..., revision: _Optional[int] = ...) -> None: ...

class DeletedSharedFolderRecord(_message.Message):
    __slots__ = ("folderUid", "recordUid", "sharedRecordKey", "dateDeleted", "revision")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDRECORDKEY_FIELD_NUMBER: _ClassVar[int]
    DATEDELETED_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordUid: bytes
    sharedRecordKey: bytes
    dateDeleted: int
    revision: int
    def __init__(self, folderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., sharedRecordKey: _Optional[bytes] = ..., dateDeleted: _Optional[int] = ..., revision: _Optional[int] = ...) -> None: ...

class DeletedRecordData(_message.Message):
    __slots__ = ("recordUid", "ownerUid", "revision", "clientModifiedTime", "data", "version")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    OWNERUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CLIENTMODIFIEDTIME_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    ownerUid: bytes
    revision: int
    clientModifiedTime: int
    data: bytes
    version: int
    def __init__(self, recordUid: _Optional[bytes] = ..., ownerUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., clientModifiedTime: _Optional[int] = ..., data: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...

class Username(_message.Message):
    __slots__ = ("accountUid", "username")
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    accountUid: bytes
    username: str
    def __init__(self, accountUid: _Optional[bytes] = ..., username: _Optional[str] = ...) -> None: ...

class RestoreDeletedSharedFoldersAndRecordsRequest(_message.Message):
    __slots__ = ("folders", "records")
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    folders: _containers.RepeatedCompositeFieldContainer[RestoreSharedObject]
    records: _containers.RepeatedCompositeFieldContainer[RestoreSharedObject]
    def __init__(self, folders: _Optional[_Iterable[_Union[RestoreSharedObject, _Mapping]]] = ..., records: _Optional[_Iterable[_Union[RestoreSharedObject, _Mapping]]] = ...) -> None: ...

class RestoreSharedObject(_message.Message):
    __slots__ = ("folderUid", "recordUids")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, folderUid: _Optional[bytes] = ..., recordUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class FolderData(_message.Message):
    __slots__ = ("folderUid", "parentUid", "data", "type", "inheritUserPermissions", "folderKey", "ownerInfo", "dateCreated", "lastModified")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    PARENTUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    INHERITUSERPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    FOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    OWNERINFO_FIELD_NUMBER: _ClassVar[int]
    DATECREATED_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    parentUid: bytes
    data: bytes
    type: FolderUsageType
    inheritUserPermissions: SetBooleanValue
    folderKey: bytes
    ownerInfo: UserInfo
    dateCreated: int
    lastModified: int
    def __init__(self, folderUid: _Optional[bytes] = ..., parentUid: _Optional[bytes] = ..., data: _Optional[bytes] = ..., type: _Optional[_Union[FolderUsageType, str]] = ..., inheritUserPermissions: _Optional[_Union[SetBooleanValue, str]] = ..., folderKey: _Optional[bytes] = ..., ownerInfo: _Optional[_Union[UserInfo, _Mapping]] = ..., dateCreated: _Optional[int] = ..., lastModified: _Optional[int] = ...) -> None: ...

class FolderKey(_message.Message):
    __slots__ = ("folderUid", "parentUid", "folderKey", "encryptedBy")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    PARENTUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDBY_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    parentUid: bytes
    folderKey: bytes
    encryptedBy: FolderKeyEncryptionType
    def __init__(self, folderUid: _Optional[bytes] = ..., parentUid: _Optional[bytes] = ..., folderKey: _Optional[bytes] = ..., encryptedBy: _Optional[_Union[FolderKeyEncryptionType, str]] = ...) -> None: ...

class FolderAddRequest(_message.Message):
    __slots__ = ("folderData",)
    FOLDERDATA_FIELD_NUMBER: _ClassVar[int]
    folderData: _containers.RepeatedCompositeFieldContainer[FolderData]
    def __init__(self, folderData: _Optional[_Iterable[_Union[FolderData, _Mapping]]] = ...) -> None: ...

class FolderModifyResult(_message.Message):
    __slots__ = ("folderUid", "status", "message")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    status: FolderModifyStatus
    message: str
    def __init__(self, folderUid: _Optional[bytes] = ..., status: _Optional[_Union[FolderModifyStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class FolderAddResponse(_message.Message):
    __slots__ = ("folderAddResults",)
    FOLDERADDRESULTS_FIELD_NUMBER: _ClassVar[int]
    folderAddResults: _containers.RepeatedCompositeFieldContainer[FolderModifyResult]
    def __init__(self, folderAddResults: _Optional[_Iterable[_Union[FolderModifyResult, _Mapping]]] = ...) -> None: ...

class FolderUpdateRequest(_message.Message):
    __slots__ = ("folderData",)
    FOLDERDATA_FIELD_NUMBER: _ClassVar[int]
    folderData: _containers.RepeatedCompositeFieldContainer[FolderData]
    def __init__(self, folderData: _Optional[_Iterable[_Union[FolderData, _Mapping]]] = ...) -> None: ...

class FolderUpdateResponse(_message.Message):
    __slots__ = ("folderUpdateResults",)
    FOLDERUPDATERESULTS_FIELD_NUMBER: _ClassVar[int]
    folderUpdateResults: _containers.RepeatedCompositeFieldContainer[FolderModifyResult]
    def __init__(self, folderUpdateResults: _Optional[_Iterable[_Union[FolderModifyResult, _Mapping]]] = ...) -> None: ...

class FolderPermissions(_message.Message):
    __slots__ = ("canAddUsers", "canRemoveUsers", "canAddRecords", "canRemoveRecords", "canDeleteRecords", "canCreateFolders", "canDeleteFolders", "canChangeUserPermissions", "canChangeRecordPermissions", "canChangeFolderOwnership", "canChangeRecordOwnership", "canEditRecords", "canViewRecords", "canReshareRecords", "canApproveAccess", "canRequestAccess", "canUpdateSetting")
    CANADDUSERS_FIELD_NUMBER: _ClassVar[int]
    CANREMOVEUSERS_FIELD_NUMBER: _ClassVar[int]
    CANADDRECORDS_FIELD_NUMBER: _ClassVar[int]
    CANREMOVERECORDS_FIELD_NUMBER: _ClassVar[int]
    CANDELETERECORDS_FIELD_NUMBER: _ClassVar[int]
    CANCREATEFOLDERS_FIELD_NUMBER: _ClassVar[int]
    CANDELETEFOLDERS_FIELD_NUMBER: _ClassVar[int]
    CANCHANGEUSERPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    CANCHANGERECORDPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    CANCHANGEFOLDEROWNERSHIP_FIELD_NUMBER: _ClassVar[int]
    CANCHANGERECORDOWNERSHIP_FIELD_NUMBER: _ClassVar[int]
    CANEDITRECORDS_FIELD_NUMBER: _ClassVar[int]
    CANVIEWRECORDS_FIELD_NUMBER: _ClassVar[int]
    CANRESHARERECORDS_FIELD_NUMBER: _ClassVar[int]
    CANAPPROVEACCESS_FIELD_NUMBER: _ClassVar[int]
    CANREQUESTACCESS_FIELD_NUMBER: _ClassVar[int]
    CANUPDATESETTING_FIELD_NUMBER: _ClassVar[int]
    canAddUsers: bool
    canRemoveUsers: bool
    canAddRecords: bool
    canRemoveRecords: bool
    canDeleteRecords: bool
    canCreateFolders: bool
    canDeleteFolders: bool
    canChangeUserPermissions: bool
    canChangeRecordPermissions: bool
    canChangeFolderOwnership: bool
    canChangeRecordOwnership: bool
    canEditRecords: bool
    canViewRecords: bool
    canReshareRecords: bool
    canApproveAccess: bool
    canRequestAccess: bool
    canUpdateSetting: bool
    def __init__(self, canAddUsers: bool = ..., canRemoveUsers: bool = ..., canAddRecords: bool = ..., canRemoveRecords: bool = ..., canDeleteRecords: bool = ..., canCreateFolders: bool = ..., canDeleteFolders: bool = ..., canChangeUserPermissions: bool = ..., canChangeRecordPermissions: bool = ..., canChangeFolderOwnership: bool = ..., canChangeRecordOwnership: bool = ..., canEditRecords: bool = ..., canViewRecords: bool = ..., canReshareRecords: bool = ..., canApproveAccess: bool = ..., canRequestAccess: bool = ..., canUpdateSetting: bool = ...) -> None: ...

class Capabilities(_message.Message):
    __slots__ = ("canAddUsers", "canRemoveUsers", "canAddRecords", "canRemoveRecords", "canDeleteRecords", "canCreateFolders", "canDeleteFolders", "canChangeUserPermissions", "canChangeRecordPermissions", "canChangeFolderOwnership", "canChangeRecordOwnership", "canEditRecords", "canViewRecords", "canReshareRecords", "canApproveAccess", "canRequestAccess", "canUpdateSetting")
    CANADDUSERS_FIELD_NUMBER: _ClassVar[int]
    CANREMOVEUSERS_FIELD_NUMBER: _ClassVar[int]
    CANADDRECORDS_FIELD_NUMBER: _ClassVar[int]
    CANREMOVERECORDS_FIELD_NUMBER: _ClassVar[int]
    CANDELETERECORDS_FIELD_NUMBER: _ClassVar[int]
    CANCREATEFOLDERS_FIELD_NUMBER: _ClassVar[int]
    CANDELETEFOLDERS_FIELD_NUMBER: _ClassVar[int]
    CANCHANGEUSERPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    CANCHANGERECORDPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    CANCHANGEFOLDEROWNERSHIP_FIELD_NUMBER: _ClassVar[int]
    CANCHANGERECORDOWNERSHIP_FIELD_NUMBER: _ClassVar[int]
    CANEDITRECORDS_FIELD_NUMBER: _ClassVar[int]
    CANVIEWRECORDS_FIELD_NUMBER: _ClassVar[int]
    CANRESHARERECORDS_FIELD_NUMBER: _ClassVar[int]
    CANAPPROVEACCESS_FIELD_NUMBER: _ClassVar[int]
    CANREQUESTACCESS_FIELD_NUMBER: _ClassVar[int]
    CANUPDATESETTING_FIELD_NUMBER: _ClassVar[int]
    canAddUsers: SetBooleanValue
    canRemoveUsers: SetBooleanValue
    canAddRecords: SetBooleanValue
    canRemoveRecords: SetBooleanValue
    canDeleteRecords: SetBooleanValue
    canCreateFolders: SetBooleanValue
    canDeleteFolders: SetBooleanValue
    canChangeUserPermissions: SetBooleanValue
    canChangeRecordPermissions: SetBooleanValue
    canChangeFolderOwnership: SetBooleanValue
    canChangeRecordOwnership: SetBooleanValue
    canEditRecords: SetBooleanValue
    canViewRecords: SetBooleanValue
    canReshareRecords: SetBooleanValue
    canApproveAccess: SetBooleanValue
    canRequestAccess: SetBooleanValue
    canUpdateSetting: SetBooleanValue
    def __init__(self, canAddUsers: _Optional[_Union[SetBooleanValue, str]] = ..., canRemoveUsers: _Optional[_Union[SetBooleanValue, str]] = ..., canAddRecords: _Optional[_Union[SetBooleanValue, str]] = ..., canRemoveRecords: _Optional[_Union[SetBooleanValue, str]] = ..., canDeleteRecords: _Optional[_Union[SetBooleanValue, str]] = ..., canCreateFolders: _Optional[_Union[SetBooleanValue, str]] = ..., canDeleteFolders: _Optional[_Union[SetBooleanValue, str]] = ..., canChangeUserPermissions: _Optional[_Union[SetBooleanValue, str]] = ..., canChangeRecordPermissions: _Optional[_Union[SetBooleanValue, str]] = ..., canChangeFolderOwnership: _Optional[_Union[SetBooleanValue, str]] = ..., canChangeRecordOwnership: _Optional[_Union[SetBooleanValue, str]] = ..., canEditRecords: _Optional[_Union[SetBooleanValue, str]] = ..., canViewRecords: _Optional[_Union[SetBooleanValue, str]] = ..., canReshareRecords: _Optional[_Union[SetBooleanValue, str]] = ..., canApproveAccess: _Optional[_Union[SetBooleanValue, str]] = ..., canRequestAccess: _Optional[_Union[SetBooleanValue, str]] = ..., canUpdateSetting: _Optional[_Union[SetBooleanValue, str]] = ...) -> None: ...

class FolderRecordUpdateRequest(_message.Message):
    __slots__ = ("folderUid", "addRecords", "updateRecords", "removeRecords")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ADDRECORDS_FIELD_NUMBER: _ClassVar[int]
    UPDATERECORDS_FIELD_NUMBER: _ClassVar[int]
    REMOVERECORDS_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    addRecords: _containers.RepeatedCompositeFieldContainer[RecordMetadata]
    updateRecords: _containers.RepeatedCompositeFieldContainer[RecordMetadata]
    removeRecords: _containers.RepeatedCompositeFieldContainer[RecordMetadata]
    def __init__(self, folderUid: _Optional[bytes] = ..., addRecords: _Optional[_Iterable[_Union[RecordMetadata, _Mapping]]] = ..., updateRecords: _Optional[_Iterable[_Union[RecordMetadata, _Mapping]]] = ..., removeRecords: _Optional[_Iterable[_Union[RecordMetadata, _Mapping]]] = ...) -> None: ...

class RecordMetadata(_message.Message):
    __slots__ = ("recordUid", "encryptedRecordKey", "encryptedRecordKeyType", "tlaProperties")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    TLAPROPERTIES_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    encryptedRecordKey: bytes
    encryptedRecordKeyType: EncryptedKeyType
    tlaProperties: _tla_pb2.TLAProperties
    def __init__(self, recordUid: _Optional[bytes] = ..., encryptedRecordKey: _Optional[bytes] = ..., encryptedRecordKeyType: _Optional[_Union[EncryptedKeyType, str]] = ..., tlaProperties: _Optional[_Union[_tla_pb2.TLAProperties, _Mapping]] = ...) -> None: ...

class FolderRecord(_message.Message):
    __slots__ = ("folderUid", "recordMetadata")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDMETADATA_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordMetadata: RecordMetadata
    def __init__(self, folderUid: _Optional[bytes] = ..., recordMetadata: _Optional[_Union[RecordMetadata, _Mapping]] = ...) -> None: ...

class FolderRecordUpdateResponse(_message.Message):
    __slots__ = ("folderUid", "folderRecordUpdateResult")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERRECORDUPDATERESULT_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    folderRecordUpdateResult: _containers.RepeatedCompositeFieldContainer[FolderRecordUpdateResult]
    def __init__(self, folderUid: _Optional[bytes] = ..., folderRecordUpdateResult: _Optional[_Iterable[_Union[FolderRecordUpdateResult, _Mapping]]] = ...) -> None: ...

class FolderRecordUpdateResult(_message.Message):
    __slots__ = ("recordUid", "status", "message")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    status: FolderModifyStatus
    message: str
    def __init__(self, recordUid: _Optional[bytes] = ..., status: _Optional[_Union[FolderModifyStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class FolderAccessData(_message.Message):
    __slots__ = ("folderUid", "accessTypeUid", "accessType", "accessRoleType", "folderKey", "inherited", "hidden", "permissions", "tlaProperties", "dateCreated", "lastModified")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSTYPEUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSTYPE_FIELD_NUMBER: _ClassVar[int]
    ACCESSROLETYPE_FIELD_NUMBER: _ClassVar[int]
    FOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    INHERITED_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    TLAPROPERTIES_FIELD_NUMBER: _ClassVar[int]
    DATECREATED_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    accessTypeUid: bytes
    accessType: AccessType
    accessRoleType: AccessRoleType
    folderKey: EncryptedDataKey
    inherited: bool
    hidden: bool
    permissions: FolderPermissions
    tlaProperties: _tla_pb2.TLAProperties
    dateCreated: int
    lastModified: int
    def __init__(self, folderUid: _Optional[bytes] = ..., accessTypeUid: _Optional[bytes] = ..., accessType: _Optional[_Union[AccessType, str]] = ..., accessRoleType: _Optional[_Union[AccessRoleType, str]] = ..., folderKey: _Optional[_Union[EncryptedDataKey, _Mapping]] = ..., inherited: bool = ..., hidden: bool = ..., permissions: _Optional[_Union[FolderPermissions, _Mapping]] = ..., tlaProperties: _Optional[_Union[_tla_pb2.TLAProperties, _Mapping]] = ..., dateCreated: _Optional[int] = ..., lastModified: _Optional[int] = ...) -> None: ...

class RevokedAccess(_message.Message):
    __slots__ = ("folderUid", "actorUid", "accessType")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ACTORUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSTYPE_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    actorUid: bytes
    accessType: AccessType
    def __init__(self, folderUid: _Optional[bytes] = ..., actorUid: _Optional[bytes] = ..., accessType: _Optional[_Union[AccessType, str]] = ...) -> None: ...

class RecordAccessData(_message.Message):
    __slots__ = ("accessTypeUid", "accessType", "recordUid", "accessRoleType", "owner", "inherited", "hidden", "deniedAccess", "can_edit", "can_view", "can_share", "can_delete", "can_request_access", "can_approve_access", "dateCreated", "lastModified", "tlaProperties")
    ACCESSTYPEUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSTYPE_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSROLETYPE_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    INHERITED_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_FIELD_NUMBER: _ClassVar[int]
    DENIEDACCESS_FIELD_NUMBER: _ClassVar[int]
    CAN_EDIT_FIELD_NUMBER: _ClassVar[int]
    CAN_VIEW_FIELD_NUMBER: _ClassVar[int]
    CAN_SHARE_FIELD_NUMBER: _ClassVar[int]
    CAN_DELETE_FIELD_NUMBER: _ClassVar[int]
    CAN_REQUEST_ACCESS_FIELD_NUMBER: _ClassVar[int]
    CAN_APPROVE_ACCESS_FIELD_NUMBER: _ClassVar[int]
    DATECREATED_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    TLAPROPERTIES_FIELD_NUMBER: _ClassVar[int]
    accessTypeUid: bytes
    accessType: AccessType
    recordUid: bytes
    accessRoleType: AccessRoleType
    owner: bool
    inherited: bool
    hidden: bool
    deniedAccess: bool
    can_edit: bool
    can_view: bool
    can_share: bool
    can_delete: bool
    can_request_access: bool
    can_approve_access: bool
    dateCreated: int
    lastModified: int
    tlaProperties: _tla_pb2.TLAProperties
    def __init__(self, accessTypeUid: _Optional[bytes] = ..., accessType: _Optional[_Union[AccessType, str]] = ..., recordUid: _Optional[bytes] = ..., accessRoleType: _Optional[_Union[AccessRoleType, str]] = ..., owner: bool = ..., inherited: bool = ..., hidden: bool = ..., deniedAccess: bool = ..., can_edit: bool = ..., can_view: bool = ..., can_share: bool = ..., can_delete: bool = ..., can_request_access: bool = ..., can_approve_access: bool = ..., dateCreated: _Optional[int] = ..., lastModified: _Optional[int] = ..., tlaProperties: _Optional[_Union[_tla_pb2.TLAProperties, _Mapping]] = ...) -> None: ...

class AccessData(_message.Message):
    __slots__ = ("accessTypeUid", "accessRoleType", "deniedAccess", "inherited", "hidden", "capabilities")
    ACCESSTYPEUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSROLETYPE_FIELD_NUMBER: _ClassVar[int]
    DENIEDACCESS_FIELD_NUMBER: _ClassVar[int]
    INHERITED_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    accessTypeUid: bytes
    accessRoleType: AccessRoleType
    deniedAccess: bool
    inherited: bool
    hidden: bool
    capabilities: Capabilities
    def __init__(self, accessTypeUid: _Optional[bytes] = ..., accessRoleType: _Optional[_Union[AccessRoleType, str]] = ..., deniedAccess: bool = ..., inherited: bool = ..., hidden: bool = ..., capabilities: _Optional[_Union[Capabilities, _Mapping]] = ...) -> None: ...

class FolderAccessRequest(_message.Message):
    __slots__ = ("folderAccessAdds", "folderAccessUpdates", "folderAccessRemoves")
    FOLDERACCESSADDS_FIELD_NUMBER: _ClassVar[int]
    FOLDERACCESSUPDATES_FIELD_NUMBER: _ClassVar[int]
    FOLDERACCESSREMOVES_FIELD_NUMBER: _ClassVar[int]
    folderAccessAdds: _containers.RepeatedCompositeFieldContainer[FolderAccessData]
    folderAccessUpdates: _containers.RepeatedCompositeFieldContainer[FolderAccessData]
    folderAccessRemoves: _containers.RepeatedCompositeFieldContainer[FolderAccessData]
    def __init__(self, folderAccessAdds: _Optional[_Iterable[_Union[FolderAccessData, _Mapping]]] = ..., folderAccessUpdates: _Optional[_Iterable[_Union[FolderAccessData, _Mapping]]] = ..., folderAccessRemoves: _Optional[_Iterable[_Union[FolderAccessData, _Mapping]]] = ...) -> None: ...

class FolderAccessResult(_message.Message):
    __slots__ = ("folderUid", "accessUid", "accessType", "status", "message")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSTYPE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    accessUid: bytes
    accessType: AccessType
    status: FolderModifyStatus
    message: str
    def __init__(self, folderUid: _Optional[bytes] = ..., accessUid: _Optional[bytes] = ..., accessType: _Optional[_Union[AccessType, str]] = ..., status: _Optional[_Union[FolderModifyStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class FolderAccessResponse(_message.Message):
    __slots__ = ("folderAccessResults",)
    FOLDERACCESSRESULTS_FIELD_NUMBER: _ClassVar[int]
    folderAccessResults: _containers.RepeatedCompositeFieldContainer[FolderAccessResult]
    def __init__(self, folderAccessResults: _Optional[_Iterable[_Union[FolderAccessResult, _Mapping]]] = ...) -> None: ...

class UserInfo(_message.Message):
    __slots__ = ("accountUid", "username")
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    accountUid: bytes
    username: str
    def __init__(self, accountUid: _Optional[bytes] = ..., username: _Optional[str] = ...) -> None: ...

class RecordData(_message.Message):
    __slots__ = ("user", "data", "recordUid")
    USER_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    user: UserInfo
    data: bytes
    recordUid: bytes
    def __init__(self, user: _Optional[_Union[UserInfo, _Mapping]] = ..., data: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ...) -> None: ...

class RecordKey(_message.Message):
    __slots__ = ("user_uid", "record_uid", "record_key", "encrypted_key_type")
    USER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    user_uid: bytes
    record_uid: bytes
    record_key: bytes
    encrypted_key_type: EncryptedKeyType
    def __init__(self, user_uid: _Optional[bytes] = ..., record_uid: _Optional[bytes] = ..., record_key: _Optional[bytes] = ..., encrypted_key_type: _Optional[_Union[EncryptedKeyType, str]] = ...) -> None: ...
