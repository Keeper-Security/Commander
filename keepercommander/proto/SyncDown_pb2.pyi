import record_pb2 as _record_pb2
import breachwatch_pb2 as _breachwatch_pb2
import APIRequest_pb2 as _APIRequest_pb2
import enterprise_pb2 as _enterprise_pb2
import NotificationCenter_pb2 as _NotificationCenter_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CacheStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    KEEP: _ClassVar[CacheStatus]
    CLEAR: _ClassVar[CacheStatus]

class RecordRotationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RRST_NOT_ROTATED: _ClassVar[RecordRotationStatus]
    RRST_IN_PROGRESS: _ClassVar[RecordRotationStatus]
    RRST_SUCCESS: _ClassVar[RecordRotationStatus]
    RRST_FAILURE: _ClassVar[RecordRotationStatus]
KEEP: CacheStatus
CLEAR: CacheStatus
RRST_NOT_ROTATED: RecordRotationStatus
RRST_IN_PROGRESS: RecordRotationStatus
RRST_SUCCESS: RecordRotationStatus
RRST_FAILURE: RecordRotationStatus

class SyncDownRequest(_message.Message):
    __slots__ = ["continuationToken", "dataVersion"]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    DATAVERSION_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    dataVersion: int
    def __init__(self, continuationToken: _Optional[bytes] = ..., dataVersion: _Optional[int] = ...) -> None: ...

class SyncDownResponse(_message.Message):
    __slots__ = ["continuationToken", "hasMore", "cacheStatus", "userFolders", "sharedFolders", "userFolderSharedFolders", "sharedFolderFolders", "records", "recordMetaData", "nonSharedData", "recordLinks", "userFolderRecords", "sharedFolderRecords", "sharedFolderFolderRecords", "sharedFolderUsers", "sharedFolderTeams", "recordAddAuditData", "teams", "sharingChanges", "profile", "profilePic", "pendingTeamMembers", "breachWatchRecords", "userAuths", "breachWatchSecurityData", "reusedPasswords", "removedUserFolders", "removedSharedFolders", "removedUserFolderSharedFolders", "removedSharedFolderFolders", "removedRecords", "removedRecordLinks", "removedUserFolderRecords", "removedSharedFolderRecords", "removedSharedFolderFolderRecords", "removedSharedFolderUsers", "removedSharedFolderTeams", "removedTeams", "ksmAppShares", "ksmAppClients", "shareInvitations", "diagnostics", "recordRotations", "users", "removedUsers", "securityScoreData", "notificationSync"]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    CACHESTATUS_FIELD_NUMBER: _ClassVar[int]
    USERFOLDERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    USERFOLDERSHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERFOLDERS_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    RECORDMETADATA_FIELD_NUMBER: _ClassVar[int]
    NONSHAREDDATA_FIELD_NUMBER: _ClassVar[int]
    RECORDLINKS_FIELD_NUMBER: _ClassVar[int]
    USERFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUSERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERTEAMS_FIELD_NUMBER: _ClassVar[int]
    RECORDADDAUDITDATA_FIELD_NUMBER: _ClassVar[int]
    TEAMS_FIELD_NUMBER: _ClassVar[int]
    SHARINGCHANGES_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    PROFILEPIC_FIELD_NUMBER: _ClassVar[int]
    PENDINGTEAMMEMBERS_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHRECORDS_FIELD_NUMBER: _ClassVar[int]
    USERAUTHS_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHSECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    REUSEDPASSWORDS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDUSERFOLDERS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDSHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDUSERFOLDERSHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDSHAREDFOLDERFOLDERS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDRECORDS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDRECORDLINKS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDUSERFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDSHAREDFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDSHAREDFOLDERFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDSHAREDFOLDERUSERS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDSHAREDFOLDERTEAMS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDTEAMS_FIELD_NUMBER: _ClassVar[int]
    KSMAPPSHARES_FIELD_NUMBER: _ClassVar[int]
    KSMAPPCLIENTS_FIELD_NUMBER: _ClassVar[int]
    SHAREINVITATIONS_FIELD_NUMBER: _ClassVar[int]
    DIAGNOSTICS_FIELD_NUMBER: _ClassVar[int]
    RECORDROTATIONS_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDUSERS_FIELD_NUMBER: _ClassVar[int]
    SECURITYSCOREDATA_FIELD_NUMBER: _ClassVar[int]
    NOTIFICATIONSYNC_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    hasMore: bool
    cacheStatus: CacheStatus
    userFolders: _containers.RepeatedCompositeFieldContainer[UserFolder]
    sharedFolders: _containers.RepeatedCompositeFieldContainer[SharedFolder]
    userFolderSharedFolders: _containers.RepeatedCompositeFieldContainer[UserFolderSharedFolder]
    sharedFolderFolders: _containers.RepeatedCompositeFieldContainer[SharedFolderFolder]
    records: _containers.RepeatedCompositeFieldContainer[Record]
    recordMetaData: _containers.RepeatedCompositeFieldContainer[RecordMetaData]
    nonSharedData: _containers.RepeatedCompositeFieldContainer[NonSharedData]
    recordLinks: _containers.RepeatedCompositeFieldContainer[RecordLink]
    userFolderRecords: _containers.RepeatedCompositeFieldContainer[UserFolderRecord]
    sharedFolderRecords: _containers.RepeatedCompositeFieldContainer[SharedFolderRecord]
    sharedFolderFolderRecords: _containers.RepeatedCompositeFieldContainer[SharedFolderFolderRecord]
    sharedFolderUsers: _containers.RepeatedCompositeFieldContainer[SharedFolderUser]
    sharedFolderTeams: _containers.RepeatedCompositeFieldContainer[SharedFolderTeam]
    recordAddAuditData: _containers.RepeatedScalarFieldContainer[bytes]
    teams: _containers.RepeatedCompositeFieldContainer[Team]
    sharingChanges: _containers.RepeatedCompositeFieldContainer[SharingChange]
    profile: Profile
    profilePic: ProfilePic
    pendingTeamMembers: _containers.RepeatedCompositeFieldContainer[PendingTeamMember]
    breachWatchRecords: _containers.RepeatedCompositeFieldContainer[BreachWatchRecord]
    userAuths: _containers.RepeatedCompositeFieldContainer[UserAuth]
    breachWatchSecurityData: _containers.RepeatedCompositeFieldContainer[BreachWatchSecurityData]
    reusedPasswords: ReusedPasswords
    removedUserFolders: _containers.RepeatedScalarFieldContainer[bytes]
    removedSharedFolders: _containers.RepeatedScalarFieldContainer[bytes]
    removedUserFolderSharedFolders: _containers.RepeatedCompositeFieldContainer[UserFolderSharedFolder]
    removedSharedFolderFolders: _containers.RepeatedCompositeFieldContainer[SharedFolderFolder]
    removedRecords: _containers.RepeatedScalarFieldContainer[bytes]
    removedRecordLinks: _containers.RepeatedCompositeFieldContainer[RecordLink]
    removedUserFolderRecords: _containers.RepeatedCompositeFieldContainer[UserFolderRecord]
    removedSharedFolderRecords: _containers.RepeatedCompositeFieldContainer[SharedFolderRecord]
    removedSharedFolderFolderRecords: _containers.RepeatedCompositeFieldContainer[SharedFolderFolderRecord]
    removedSharedFolderUsers: _containers.RepeatedCompositeFieldContainer[SharedFolderUser]
    removedSharedFolderTeams: _containers.RepeatedCompositeFieldContainer[SharedFolderTeam]
    removedTeams: _containers.RepeatedScalarFieldContainer[bytes]
    ksmAppShares: _containers.RepeatedCompositeFieldContainer[KsmChange]
    ksmAppClients: _containers.RepeatedCompositeFieldContainer[KsmChange]
    shareInvitations: _containers.RepeatedCompositeFieldContainer[ShareInvitation]
    diagnostics: SyncDiagnostics
    recordRotations: _containers.RepeatedCompositeFieldContainer[RecordRotation]
    users: _containers.RepeatedCompositeFieldContainer[User]
    removedUsers: _containers.RepeatedScalarFieldContainer[bytes]
    securityScoreData: _containers.RepeatedCompositeFieldContainer[SecurityScoreData]
    notificationSync: _containers.RepeatedCompositeFieldContainer[_NotificationCenter_pb2.NotificationWrapper]
    def __init__(self, continuationToken: _Optional[bytes] = ..., hasMore: bool = ..., cacheStatus: _Optional[_Union[CacheStatus, str]] = ..., userFolders: _Optional[_Iterable[_Union[UserFolder, _Mapping]]] = ..., sharedFolders: _Optional[_Iterable[_Union[SharedFolder, _Mapping]]] = ..., userFolderSharedFolders: _Optional[_Iterable[_Union[UserFolderSharedFolder, _Mapping]]] = ..., sharedFolderFolders: _Optional[_Iterable[_Union[SharedFolderFolder, _Mapping]]] = ..., records: _Optional[_Iterable[_Union[Record, _Mapping]]] = ..., recordMetaData: _Optional[_Iterable[_Union[RecordMetaData, _Mapping]]] = ..., nonSharedData: _Optional[_Iterable[_Union[NonSharedData, _Mapping]]] = ..., recordLinks: _Optional[_Iterable[_Union[RecordLink, _Mapping]]] = ..., userFolderRecords: _Optional[_Iterable[_Union[UserFolderRecord, _Mapping]]] = ..., sharedFolderRecords: _Optional[_Iterable[_Union[SharedFolderRecord, _Mapping]]] = ..., sharedFolderFolderRecords: _Optional[_Iterable[_Union[SharedFolderFolderRecord, _Mapping]]] = ..., sharedFolderUsers: _Optional[_Iterable[_Union[SharedFolderUser, _Mapping]]] = ..., sharedFolderTeams: _Optional[_Iterable[_Union[SharedFolderTeam, _Mapping]]] = ..., recordAddAuditData: _Optional[_Iterable[bytes]] = ..., teams: _Optional[_Iterable[_Union[Team, _Mapping]]] = ..., sharingChanges: _Optional[_Iterable[_Union[SharingChange, _Mapping]]] = ..., profile: _Optional[_Union[Profile, _Mapping]] = ..., profilePic: _Optional[_Union[ProfilePic, _Mapping]] = ..., pendingTeamMembers: _Optional[_Iterable[_Union[PendingTeamMember, _Mapping]]] = ..., breachWatchRecords: _Optional[_Iterable[_Union[BreachWatchRecord, _Mapping]]] = ..., userAuths: _Optional[_Iterable[_Union[UserAuth, _Mapping]]] = ..., breachWatchSecurityData: _Optional[_Iterable[_Union[BreachWatchSecurityData, _Mapping]]] = ..., reusedPasswords: _Optional[_Union[ReusedPasswords, _Mapping]] = ..., removedUserFolders: _Optional[_Iterable[bytes]] = ..., removedSharedFolders: _Optional[_Iterable[bytes]] = ..., removedUserFolderSharedFolders: _Optional[_Iterable[_Union[UserFolderSharedFolder, _Mapping]]] = ..., removedSharedFolderFolders: _Optional[_Iterable[_Union[SharedFolderFolder, _Mapping]]] = ..., removedRecords: _Optional[_Iterable[bytes]] = ..., removedRecordLinks: _Optional[_Iterable[_Union[RecordLink, _Mapping]]] = ..., removedUserFolderRecords: _Optional[_Iterable[_Union[UserFolderRecord, _Mapping]]] = ..., removedSharedFolderRecords: _Optional[_Iterable[_Union[SharedFolderRecord, _Mapping]]] = ..., removedSharedFolderFolderRecords: _Optional[_Iterable[_Union[SharedFolderFolderRecord, _Mapping]]] = ..., removedSharedFolderUsers: _Optional[_Iterable[_Union[SharedFolderUser, _Mapping]]] = ..., removedSharedFolderTeams: _Optional[_Iterable[_Union[SharedFolderTeam, _Mapping]]] = ..., removedTeams: _Optional[_Iterable[bytes]] = ..., ksmAppShares: _Optional[_Iterable[_Union[KsmChange, _Mapping]]] = ..., ksmAppClients: _Optional[_Iterable[_Union[KsmChange, _Mapping]]] = ..., shareInvitations: _Optional[_Iterable[_Union[ShareInvitation, _Mapping]]] = ..., diagnostics: _Optional[_Union[SyncDiagnostics, _Mapping]] = ..., recordRotations: _Optional[_Iterable[_Union[RecordRotation, _Mapping]]] = ..., users: _Optional[_Iterable[_Union[User, _Mapping]]] = ..., removedUsers: _Optional[_Iterable[bytes]] = ..., securityScoreData: _Optional[_Iterable[_Union[SecurityScoreData, _Mapping]]] = ..., notificationSync: _Optional[_Iterable[_Union[_NotificationCenter_pb2.NotificationWrapper, _Mapping]]] = ...) -> None: ...

class UserFolder(_message.Message):
    __slots__ = ["folderUid", "parentUid", "userFolderKey", "keyType", "revision", "data"]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    PARENTUID_FIELD_NUMBER: _ClassVar[int]
    USERFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    parentUid: bytes
    userFolderKey: bytes
    keyType: _record_pb2.RecordKeyType
    revision: int
    data: bytes
    def __init__(self, folderUid: _Optional[bytes] = ..., parentUid: _Optional[bytes] = ..., userFolderKey: _Optional[bytes] = ..., keyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ..., revision: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class SharedFolder(_message.Message):
    __slots__ = ["sharedFolderUid", "revision", "sharedFolderKey", "keyType", "data", "defaultManageRecords", "defaultManageUsers", "defaultCanEdit", "defaultCanReshare", "cacheStatus", "owner", "ownerAccountUid", "name"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    DEFAULTMANAGERECORDS_FIELD_NUMBER: _ClassVar[int]
    DEFAULTMANAGEUSERS_FIELD_NUMBER: _ClassVar[int]
    DEFAULTCANEDIT_FIELD_NUMBER: _ClassVar[int]
    DEFAULTCANRESHARE_FIELD_NUMBER: _ClassVar[int]
    CACHESTATUS_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    OWNERACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    revision: int
    sharedFolderKey: bytes
    keyType: _record_pb2.RecordKeyType
    data: bytes
    defaultManageRecords: bool
    defaultManageUsers: bool
    defaultCanEdit: bool
    defaultCanReshare: bool
    cacheStatus: CacheStatus
    owner: str
    ownerAccountUid: bytes
    name: bytes
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., sharedFolderKey: _Optional[bytes] = ..., keyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ..., data: _Optional[bytes] = ..., defaultManageRecords: bool = ..., defaultManageUsers: bool = ..., defaultCanEdit: bool = ..., defaultCanReshare: bool = ..., cacheStatus: _Optional[_Union[CacheStatus, str]] = ..., owner: _Optional[str] = ..., ownerAccountUid: _Optional[bytes] = ..., name: _Optional[bytes] = ...) -> None: ...

class UserFolderSharedFolder(_message.Message):
    __slots__ = ["folderUid", "sharedFolderUid", "revision"]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    sharedFolderUid: bytes
    revision: int
    def __init__(self, folderUid: _Optional[bytes] = ..., sharedFolderUid: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class SharedFolderFolder(_message.Message):
    __slots__ = ["sharedFolderUid", "folderUid", "parentUid", "sharedFolderFolderKey", "keyType", "revision", "data"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    PARENTUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    folderUid: bytes
    parentUid: bytes
    sharedFolderFolderKey: bytes
    keyType: _record_pb2.RecordKeyType
    revision: int
    data: bytes
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., folderUid: _Optional[bytes] = ..., parentUid: _Optional[bytes] = ..., sharedFolderFolderKey: _Optional[bytes] = ..., keyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ..., revision: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class SharedFolderKey(_message.Message):
    __slots__ = ["sharedFolderUid", "sharedFolderKey", "keyType"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    sharedFolderKey: bytes
    keyType: _record_pb2.RecordKeyType
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., sharedFolderKey: _Optional[bytes] = ..., keyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ...) -> None: ...

class Team(_message.Message):
    __slots__ = ["teamUid", "name", "teamKey", "teamKeyType", "teamPrivateKey", "restrictEdit", "restrictShare", "restrictView", "removedSharedFolders", "sharedFolderKeys", "teamEccPrivateKey", "teamEccPublicKey"]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TEAMKEY_FIELD_NUMBER: _ClassVar[int]
    TEAMKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    TEAMPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    RESTRICTEDIT_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHARE_FIELD_NUMBER: _ClassVar[int]
    RESTRICTVIEW_FIELD_NUMBER: _ClassVar[int]
    REMOVEDSHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERKEYS_FIELD_NUMBER: _ClassVar[int]
    TEAMECCPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    TEAMECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    name: str
    teamKey: bytes
    teamKeyType: _record_pb2.RecordKeyType
    teamPrivateKey: bytes
    restrictEdit: bool
    restrictShare: bool
    restrictView: bool
    removedSharedFolders: _containers.RepeatedScalarFieldContainer[bytes]
    sharedFolderKeys: _containers.RepeatedCompositeFieldContainer[SharedFolderKey]
    teamEccPrivateKey: bytes
    teamEccPublicKey: bytes
    def __init__(self, teamUid: _Optional[bytes] = ..., name: _Optional[str] = ..., teamKey: _Optional[bytes] = ..., teamKeyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ..., teamPrivateKey: _Optional[bytes] = ..., restrictEdit: bool = ..., restrictShare: bool = ..., restrictView: bool = ..., removedSharedFolders: _Optional[_Iterable[bytes]] = ..., sharedFolderKeys: _Optional[_Iterable[_Union[SharedFolderKey, _Mapping]]] = ..., teamEccPrivateKey: _Optional[bytes] = ..., teamEccPublicKey: _Optional[bytes] = ...) -> None: ...

class Record(_message.Message):
    __slots__ = ["recordUid", "revision", "version", "shared", "clientModifiedTime", "data", "extra", "udata", "fileSize", "thumbnailSize"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SHARED_FIELD_NUMBER: _ClassVar[int]
    CLIENTMODIFIEDTIME_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    EXTRA_FIELD_NUMBER: _ClassVar[int]
    UDATA_FIELD_NUMBER: _ClassVar[int]
    FILESIZE_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSIZE_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    revision: int
    version: int
    shared: bool
    clientModifiedTime: int
    data: bytes
    extra: bytes
    udata: str
    fileSize: int
    thumbnailSize: int
    def __init__(self, recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., version: _Optional[int] = ..., shared: bool = ..., clientModifiedTime: _Optional[int] = ..., data: _Optional[bytes] = ..., extra: _Optional[bytes] = ..., udata: _Optional[str] = ..., fileSize: _Optional[int] = ..., thumbnailSize: _Optional[int] = ...) -> None: ...

class RecordLink(_message.Message):
    __slots__ = ["parentRecordUid", "childRecordUid", "recordKey", "revision"]
    PARENTRECORDUID_FIELD_NUMBER: _ClassVar[int]
    CHILDRECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    parentRecordUid: bytes
    childRecordUid: bytes
    recordKey: bytes
    revision: int
    def __init__(self, parentRecordUid: _Optional[bytes] = ..., childRecordUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class UserFolderRecord(_message.Message):
    __slots__ = ["folderUid", "recordUid", "revision"]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    recordUid: bytes
    revision: int
    def __init__(self, folderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class SharedFolderFolderRecord(_message.Message):
    __slots__ = ["sharedFolderUid", "folderUid", "recordUid", "revision"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    folderUid: bytes
    recordUid: bytes
    revision: int
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., folderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class NonSharedData(_message.Message):
    __slots__ = ["recordUid", "data"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    data: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., data: _Optional[bytes] = ...) -> None: ...

class RecordMetaData(_message.Message):
    __slots__ = ["recordUid", "owner", "recordKey", "recordKeyType", "canShare", "canEdit", "ownerAccountUid", "expiration", "expirationNotificationType", "ownerUsername"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    RECORDKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    CANSHARE_FIELD_NUMBER: _ClassVar[int]
    CANEDIT_FIELD_NUMBER: _ClassVar[int]
    OWNERACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    OWNERUSERNAME_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    owner: bool
    recordKey: bytes
    recordKeyType: _record_pb2.RecordKeyType
    canShare: bool
    canEdit: bool
    ownerAccountUid: bytes
    expiration: int
    expirationNotificationType: _record_pb2.TimerNotificationType
    ownerUsername: str
    def __init__(self, recordUid: _Optional[bytes] = ..., owner: bool = ..., recordKey: _Optional[bytes] = ..., recordKeyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ..., canShare: bool = ..., canEdit: bool = ..., ownerAccountUid: _Optional[bytes] = ..., expiration: _Optional[int] = ..., expirationNotificationType: _Optional[_Union[_record_pb2.TimerNotificationType, str]] = ..., ownerUsername: _Optional[str] = ...) -> None: ...

class SharingChange(_message.Message):
    __slots__ = ["recordUid", "shared"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHARED_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    shared: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., shared: bool = ...) -> None: ...

class Profile(_message.Message):
    __slots__ = ["data", "profileName", "revision"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    PROFILENAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    profileName: str
    revision: int
    def __init__(self, data: _Optional[bytes] = ..., profileName: _Optional[str] = ..., revision: _Optional[int] = ...) -> None: ...

class ProfilePic(_message.Message):
    __slots__ = ["url", "revision"]
    URL_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    url: str
    revision: int
    def __init__(self, url: _Optional[str] = ..., revision: _Optional[int] = ...) -> None: ...

class PendingTeamMember(_message.Message):
    __slots__ = ["enterpriseUserId", "userPublicKey", "teamUids", "userEccPublicKey"]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    TEAMUIDS_FIELD_NUMBER: _ClassVar[int]
    USERECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    userPublicKey: bytes
    teamUids: _containers.RepeatedScalarFieldContainer[bytes]
    userEccPublicKey: bytes
    def __init__(self, enterpriseUserId: _Optional[int] = ..., userPublicKey: _Optional[bytes] = ..., teamUids: _Optional[_Iterable[bytes]] = ..., userEccPublicKey: _Optional[bytes] = ...) -> None: ...

class BreachWatchRecord(_message.Message):
    __slots__ = ["recordUid", "data", "type", "scannedBy", "revision", "scannedByAccountUid"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SCANNEDBY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SCANNEDBYACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    data: bytes
    type: _breachwatch_pb2.BreachWatchInfoType
    scannedBy: str
    revision: int
    scannedByAccountUid: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., data: _Optional[bytes] = ..., type: _Optional[_Union[_breachwatch_pb2.BreachWatchInfoType, str]] = ..., scannedBy: _Optional[str] = ..., revision: _Optional[int] = ..., scannedByAccountUid: _Optional[bytes] = ...) -> None: ...

class UserAuth(_message.Message):
    __slots__ = ["uid", "loginType", "deleted", "iterations", "salt", "encryptedClientKey", "revision", "name"]
    UID_FIELD_NUMBER: _ClassVar[int]
    LOGINTYPE_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDCLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    loginType: _APIRequest_pb2.LoginType
    deleted: bool
    iterations: int
    salt: bytes
    encryptedClientKey: bytes
    revision: int
    name: str
    def __init__(self, uid: _Optional[bytes] = ..., loginType: _Optional[_Union[_APIRequest_pb2.LoginType, str]] = ..., deleted: bool = ..., iterations: _Optional[int] = ..., salt: _Optional[bytes] = ..., encryptedClientKey: _Optional[bytes] = ..., revision: _Optional[int] = ..., name: _Optional[str] = ...) -> None: ...

class BreachWatchSecurityData(_message.Message):
    __slots__ = ["recordUid", "revision"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    revision: int
    def __init__(self, recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class ReusedPasswords(_message.Message):
    __slots__ = ["count", "revision"]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    count: int
    revision: int
    def __init__(self, count: _Optional[int] = ..., revision: _Optional[int] = ...) -> None: ...

class SharedFolderRecord(_message.Message):
    __slots__ = ["sharedFolderUid", "recordUid", "recordKey", "canShare", "canEdit", "ownerAccountUid", "expiration", "owner", "expirationNotificationType", "ownerUsername", "rotateOnExpiration"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    CANSHARE_FIELD_NUMBER: _ClassVar[int]
    CANEDIT_FIELD_NUMBER: _ClassVar[int]
    OWNERACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    OWNERUSERNAME_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    recordUid: bytes
    recordKey: bytes
    canShare: bool
    canEdit: bool
    ownerAccountUid: bytes
    expiration: int
    owner: bool
    expirationNotificationType: _record_pb2.TimerNotificationType
    ownerUsername: str
    rotateOnExpiration: bool
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., canShare: bool = ..., canEdit: bool = ..., ownerAccountUid: _Optional[bytes] = ..., expiration: _Optional[int] = ..., owner: bool = ..., expirationNotificationType: _Optional[_Union[_record_pb2.TimerNotificationType, str]] = ..., ownerUsername: _Optional[str] = ..., rotateOnExpiration: bool = ...) -> None: ...

class SharedFolderUser(_message.Message):
    __slots__ = ["sharedFolderUid", "username", "manageRecords", "manageUsers", "accountUid", "expiration", "expirationNotificationType", "rotateOnExpiration"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    MANAGERECORDS_FIELD_NUMBER: _ClassVar[int]
    MANAGEUSERS_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    username: str
    manageRecords: bool
    manageUsers: bool
    accountUid: bytes
    expiration: int
    expirationNotificationType: _record_pb2.TimerNotificationType
    rotateOnExpiration: bool
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., username: _Optional[str] = ..., manageRecords: bool = ..., manageUsers: bool = ..., accountUid: _Optional[bytes] = ..., expiration: _Optional[int] = ..., expirationNotificationType: _Optional[_Union[_record_pb2.TimerNotificationType, str]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class SharedFolderTeam(_message.Message):
    __slots__ = ["sharedFolderUid", "teamUid", "name", "manageRecords", "manageUsers", "expiration", "expirationNotificationType", "rotateOnExpiration"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    MANAGERECORDS_FIELD_NUMBER: _ClassVar[int]
    MANAGEUSERS_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    teamUid: bytes
    name: str
    manageRecords: bool
    manageUsers: bool
    expiration: int
    expirationNotificationType: _record_pb2.TimerNotificationType
    rotateOnExpiration: bool
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., teamUid: _Optional[bytes] = ..., name: _Optional[str] = ..., manageRecords: bool = ..., manageUsers: bool = ..., expiration: _Optional[int] = ..., expirationNotificationType: _Optional[_Union[_record_pb2.TimerNotificationType, str]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class KsmChange(_message.Message):
    __slots__ = ["appRecordUid", "detailId", "removed", "appClientType", "expiration"]
    APPRECORDUID_FIELD_NUMBER: _ClassVar[int]
    DETAILID_FIELD_NUMBER: _ClassVar[int]
    REMOVED_FIELD_NUMBER: _ClassVar[int]
    APPCLIENTTYPE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    appRecordUid: bytes
    detailId: bytes
    removed: bool
    appClientType: _enterprise_pb2.AppClientType
    expiration: int
    def __init__(self, appRecordUid: _Optional[bytes] = ..., detailId: _Optional[bytes] = ..., removed: bool = ..., appClientType: _Optional[_Union[_enterprise_pb2.AppClientType, str]] = ..., expiration: _Optional[int] = ...) -> None: ...

class ShareInvitation(_message.Message):
    __slots__ = ["username"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    def __init__(self, username: _Optional[str] = ...) -> None: ...

class User(_message.Message):
    __slots__ = ["accountUid", "username"]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    accountUid: bytes
    username: str
    def __init__(self, accountUid: _Optional[bytes] = ..., username: _Optional[str] = ...) -> None: ...

class SyncDiagnostics(_message.Message):
    __slots__ = ["continuationToken", "userId", "enterpriseUserId", "syncedTo", "syncingTo"]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    SYNCEDTO_FIELD_NUMBER: _ClassVar[int]
    SYNCINGTO_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    userId: int
    enterpriseUserId: int
    syncedTo: int
    syncingTo: int
    def __init__(self, continuationToken: _Optional[bytes] = ..., userId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ..., syncedTo: _Optional[int] = ..., syncingTo: _Optional[int] = ...) -> None: ...

class RecordRotation(_message.Message):
    __slots__ = ["recordUid", "revision", "configurationUid", "schedule", "pwdComplexity", "disabled", "resourceUid", "lastRotation", "lastRotationStatus"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    PWDCOMPLEXITY_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    LASTROTATION_FIELD_NUMBER: _ClassVar[int]
    LASTROTATIONSTATUS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    revision: int
    configurationUid: bytes
    schedule: str
    pwdComplexity: bytes
    disabled: bool
    resourceUid: bytes
    lastRotation: int
    lastRotationStatus: RecordRotationStatus
    def __init__(self, recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., configurationUid: _Optional[bytes] = ..., schedule: _Optional[str] = ..., pwdComplexity: _Optional[bytes] = ..., disabled: bool = ..., resourceUid: _Optional[bytes] = ..., lastRotation: _Optional[int] = ..., lastRotationStatus: _Optional[_Union[RecordRotationStatus, str]] = ...) -> None: ...

class SecurityScoreData(_message.Message):
    __slots__ = ["recordUid", "data", "revision"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    data: bytes
    revision: int
    def __init__(self, recordUid: _Optional[bytes] = ..., data: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class BreachWatchGetSyncDataRequest(_message.Message):
    __slots__ = ["recordUids"]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, recordUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class BreachWatchGetSyncDataResponse(_message.Message):
    __slots__ = ["breachWatchRecords", "breachWatchSecurityData", "users"]
    BREACHWATCHRECORDS_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHSECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    breachWatchRecords: _containers.RepeatedCompositeFieldContainer[BreachWatchRecord]
    breachWatchSecurityData: _containers.RepeatedCompositeFieldContainer[BreachWatchSecurityData]
    users: _containers.RepeatedCompositeFieldContainer[User]
    def __init__(self, breachWatchRecords: _Optional[_Iterable[_Union[BreachWatchRecord, _Mapping]]] = ..., breachWatchSecurityData: _Optional[_Iterable[_Union[BreachWatchSecurityData, _Mapping]]] = ..., users: _Optional[_Iterable[_Union[User, _Mapping]]] = ...) -> None: ...

class GetAccountUidMapResponse(_message.Message):
    __slots__ = ["users"]
    USERS_FIELD_NUMBER: _ClassVar[int]
    users: _containers.RepeatedCompositeFieldContainer[User]
    def __init__(self, users: _Optional[_Iterable[_Union[User, _Mapping]]] = ...) -> None: ...
