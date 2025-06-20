import record_pb2 as _record_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RecordType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    password: _ClassVar[RecordType]

class FolderType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    default_folder: _ClassVar[FolderType]
    user_folder: _ClassVar[FolderType]
    shared_folder: _ClassVar[FolderType]
    shared_folder_folder: _ClassVar[FolderType]

class EncryptedKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    no_key: _ClassVar[EncryptedKeyType]
    encrypted_by_data_key: _ClassVar[EncryptedKeyType]
    encrypted_by_public_key: _ClassVar[EncryptedKeyType]
    encrypted_by_data_key_gcm: _ClassVar[EncryptedKeyType]
    encrypted_by_public_key_ecc: _ClassVar[EncryptedKeyType]

class SetBooleanValue(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    BOOLEAN_NO_CHANGE: _ClassVar[SetBooleanValue]
    BOOLEAN_TRUE: _ClassVar[SetBooleanValue]
    BOOLEAN_FALSE: _ClassVar[SetBooleanValue]
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

class EncryptedDataKey(_message.Message):
    __slots__ = ["encryptedKey", "encryptedKeyType"]
    ENCRYPTEDKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    encryptedKey: bytes
    encryptedKeyType: EncryptedKeyType
    def __init__(self, encryptedKey: _Optional[bytes] = ..., encryptedKeyType: _Optional[_Union[EncryptedKeyType, str]] = ...) -> None: ...

class SharedFolderRecordData(_message.Message):
    __slots__ = ["folderUid", "recordUid", "userId", "encryptedDataKey"]
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
    __slots__ = ["sharedFolderRecordData"]
    SHAREDFOLDERRECORDDATA_FIELD_NUMBER: _ClassVar[int]
    sharedFolderRecordData: _containers.RepeatedCompositeFieldContainer[SharedFolderRecordData]
    def __init__(self, sharedFolderRecordData: _Optional[_Iterable[_Union[SharedFolderRecordData, _Mapping]]] = ...) -> None: ...

class SharedFolderRecordFix(_message.Message):
    __slots__ = ["folderUid", "recordUid", "encryptedRecordFolderKey"]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordUid: bytes
    encryptedRecordFolderKey: bytes
    def __init__(self, folderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., encryptedRecordFolderKey: _Optional[bytes] = ...) -> None: ...

class SharedFolderRecordFixList(_message.Message):
    __slots__ = ["sharedFolderRecordFix"]
    SHAREDFOLDERRECORDFIX_FIELD_NUMBER: _ClassVar[int]
    sharedFolderRecordFix: _containers.RepeatedCompositeFieldContainer[SharedFolderRecordFix]
    def __init__(self, sharedFolderRecordFix: _Optional[_Iterable[_Union[SharedFolderRecordFix, _Mapping]]] = ...) -> None: ...

class RecordRequest(_message.Message):
    __slots__ = ["recordUid", "recordType", "recordData", "encryptedRecordKey", "folderType", "howLongAgo", "folderUid", "encryptedRecordFolderKey", "extra", "nonSharedData", "fileIds"]
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
    __slots__ = ["recordUid", "revision", "status"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    revision: int
    status: str
    def __init__(self, recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderFields(_message.Message):
    __slots__ = ["encryptedFolderName", "manageUsers", "manageRecords", "canEdit", "canShare"]
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
    __slots__ = ["sharedFolderUid"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    def __init__(self, sharedFolderUid: _Optional[bytes] = ...) -> None: ...

class FolderRequest(_message.Message):
    __slots__ = ["folderUid", "folderType", "parentFolderUid", "folderData", "encryptedFolderKey", "sharedFolderFields", "sharedFolderFolderFields"]
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
    __slots__ = ["folderUid", "revision", "status"]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    revision: int
    status: str
    def __init__(self, folderUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., status: _Optional[str] = ...) -> None: ...

class ImportFolderRecordRequest(_message.Message):
    __slots__ = ["folderRequest", "recordRequest"]
    FOLDERREQUEST_FIELD_NUMBER: _ClassVar[int]
    RECORDREQUEST_FIELD_NUMBER: _ClassVar[int]
    folderRequest: _containers.RepeatedCompositeFieldContainer[FolderRequest]
    recordRequest: _containers.RepeatedCompositeFieldContainer[RecordRequest]
    def __init__(self, folderRequest: _Optional[_Iterable[_Union[FolderRequest, _Mapping]]] = ..., recordRequest: _Optional[_Iterable[_Union[RecordRequest, _Mapping]]] = ...) -> None: ...

class ImportFolderRecordResponse(_message.Message):
    __slots__ = ["folderResponse", "recordResponse"]
    FOLDERRESPONSE_FIELD_NUMBER: _ClassVar[int]
    RECORDRESPONSE_FIELD_NUMBER: _ClassVar[int]
    folderResponse: _containers.RepeatedCompositeFieldContainer[FolderResponse]
    recordResponse: _containers.RepeatedCompositeFieldContainer[RecordResponse]
    def __init__(self, folderResponse: _Optional[_Iterable[_Union[FolderResponse, _Mapping]]] = ..., recordResponse: _Optional[_Iterable[_Union[RecordResponse, _Mapping]]] = ...) -> None: ...

class SharedFolderUpdateRecord(_message.Message):
    __slots__ = ["recordUid", "sharedFolderUid", "teamUid", "canEdit", "canShare", "encryptedRecordKey", "revision", "expiration", "timerNotificationType", "rotateOnExpiration"]
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
    __slots__ = ["username", "manageUsers", "manageRecords", "sharedFolderKey", "expiration", "timerNotificationType", "typedSharedFolderKey", "rotateOnExpiration"]
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
    __slots__ = ["teamUid", "manageUsers", "manageRecords", "sharedFolderKey", "expiration", "timerNotificationType", "typedSharedFolderKey", "rotateOnExpiration"]
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
    __slots__ = ["sharedFolderUpdateOperation_dont_use", "sharedFolderUid", "encryptedSharedFolderName", "revision", "forceUpdate", "fromTeamUid", "defaultManageUsers", "defaultManageRecords", "defaultCanEdit", "defaultCanShare", "sharedFolderAddRecord", "sharedFolderAddUser", "sharedFolderAddTeam", "sharedFolderUpdateRecord", "sharedFolderUpdateUser", "sharedFolderUpdateTeam", "sharedFolderRemoveRecord", "sharedFolderRemoveUser", "sharedFolderRemoveTeam", "sharedFolderOwner"]
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
    __slots__ = ["sharedFoldersUpdateV3"]
    SHAREDFOLDERSUPDATEV3_FIELD_NUMBER: _ClassVar[int]
    sharedFoldersUpdateV3: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateV3Request]
    def __init__(self, sharedFoldersUpdateV3: _Optional[_Iterable[_Union[SharedFolderUpdateV3Request, _Mapping]]] = ...) -> None: ...

class SharedFolderUpdateRecordStatus(_message.Message):
    __slots__ = ["recordUid", "status"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    status: str
    def __init__(self, recordUid: _Optional[bytes] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateUserStatus(_message.Message):
    __slots__ = ["username", "status"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    username: str
    status: str
    def __init__(self, username: _Optional[str] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateTeamStatus(_message.Message):
    __slots__ = ["teamUid", "status"]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    status: str
    def __init__(self, teamUid: _Optional[bytes] = ..., status: _Optional[str] = ...) -> None: ...

class SharedFolderUpdateV3Response(_message.Message):
    __slots__ = ["revision", "sharedFolderAddRecordStatus", "sharedFolderAddUserStatus", "sharedFolderAddTeamStatus", "sharedFolderUpdateRecordStatus", "sharedFolderUpdateUserStatus", "sharedFolderUpdateTeamStatus", "sharedFolderRemoveRecordStatus", "sharedFolderRemoveUserStatus", "sharedFolderRemoveTeamStatus", "sharedFolderUid", "status"]
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
    __slots__ = ["sharedFoldersUpdateV3Response"]
    SHAREDFOLDERSUPDATEV3RESPONSE_FIELD_NUMBER: _ClassVar[int]
    sharedFoldersUpdateV3Response: _containers.RepeatedCompositeFieldContainer[SharedFolderUpdateV3Response]
    def __init__(self, sharedFoldersUpdateV3Response: _Optional[_Iterable[_Union[SharedFolderUpdateV3Response, _Mapping]]] = ...) -> None: ...

class GetDeletedSharedFoldersAndRecordsResponse(_message.Message):
    __slots__ = ["sharedFolders", "sharedFolderRecords", "deletedRecordData", "usernames"]
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
    __slots__ = ["sharedFolderUid", "folderUid", "parentUid", "sharedFolderKey", "folderKeyType", "data", "dateDeleted", "revision"]
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
    __slots__ = ["folderUid", "recordUid", "sharedRecordKey", "dateDeleted", "revision"]
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
    __slots__ = ["recordUid", "ownerUid", "revision", "clientModifiedTime", "data", "version"]
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
    __slots__ = ["accountUid", "username"]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    accountUid: bytes
    username: str
    def __init__(self, accountUid: _Optional[bytes] = ..., username: _Optional[str] = ...) -> None: ...

class RestoreDeletedSharedFoldersAndRecordsRequest(_message.Message):
    __slots__ = ["folders", "records"]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    folders: _containers.RepeatedCompositeFieldContainer[RestoreSharedObject]
    records: _containers.RepeatedCompositeFieldContainer[RestoreSharedObject]
    def __init__(self, folders: _Optional[_Iterable[_Union[RestoreSharedObject, _Mapping]]] = ..., records: _Optional[_Iterable[_Union[RestoreSharedObject, _Mapping]]] = ...) -> None: ...

class RestoreSharedObject(_message.Message):
    __slots__ = ["folderUid", "recordUids"]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, folderUid: _Optional[bytes] = ..., recordUids: _Optional[_Iterable[bytes]] = ...) -> None: ...
