from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RecordTypeScope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RT_STANDARD: _ClassVar[RecordTypeScope]
    RT_USER: _ClassVar[RecordTypeScope]
    RT_ENTERPRISE: _ClassVar[RecordTypeScope]
    RT_PAM: _ClassVar[RecordTypeScope]
    RT_PAM_CONFIGURATION: _ClassVar[RecordTypeScope]

class RecordKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    NO_KEY: _ClassVar[RecordKeyType]
    ENCRYPTED_BY_DATA_KEY: _ClassVar[RecordKeyType]
    ENCRYPTED_BY_PUBLIC_KEY: _ClassVar[RecordKeyType]
    ENCRYPTED_BY_DATA_KEY_GCM: _ClassVar[RecordKeyType]
    ENCRYPTED_BY_PUBLIC_KEY_ECC: _ClassVar[RecordKeyType]
    ENCRYPTED_BY_ROOT_KEY_CBC: _ClassVar[RecordKeyType]
    ENCRYPTED_BY_ROOT_KEY_GCM: _ClassVar[RecordKeyType]

class RecordFolderType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    user_folder: _ClassVar[RecordFolderType]
    shared_folder: _ClassVar[RecordFolderType]
    shared_folder_folder: _ClassVar[RecordFolderType]

class RecordModifyResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RS_SUCCESS: _ClassVar[RecordModifyResult]
    RS_OUT_OF_SYNC: _ClassVar[RecordModifyResult]
    RS_ACCESS_DENIED: _ClassVar[RecordModifyResult]
    RS_SHARE_DENIED: _ClassVar[RecordModifyResult]
    RS_RECORD_EXISTS: _ClassVar[RecordModifyResult]
    RS_OLD_RECORD_VERSION_TYPE: _ClassVar[RecordModifyResult]
    RS_NEW_RECORD_VERSION_TYPE: _ClassVar[RecordModifyResult]
    RS_FILES_NOT_MATCH: _ClassVar[RecordModifyResult]
    RS_RECORD_NOT_SHAREABLE: _ClassVar[RecordModifyResult]
    RS_ATTACHMENT_NOT_SHAREABLE: _ClassVar[RecordModifyResult]
    RS_FILE_LIMIT_REACHED: _ClassVar[RecordModifyResult]
    RS_SIZE_EXCEEDED_LIMIT: _ClassVar[RecordModifyResult]
    RS_ONLY_OWNER_CAN_MODIFY_SCRIPTS: _ClassVar[RecordModifyResult]

class FileAddResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    FA_SUCCESS: _ClassVar[FileAddResult]
    FA_ERROR: _ClassVar[FileAddResult]

class FileGetResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    FG_SUCCESS: _ClassVar[FileGetResult]
    FG_ERROR: _ClassVar[FileGetResult]
    FG_ACCESS_DENIED: _ClassVar[FileGetResult]

class RecordDetailsInclude(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    DATA_PLUS_SHARE: _ClassVar[RecordDetailsInclude]
    DATA_ONLY: _ClassVar[RecordDetailsInclude]
    SHARE_ONLY: _ClassVar[RecordDetailsInclude]

class CheckShareAdminObjectType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    CHECK_SA_INVALID_TYPE: _ClassVar[CheckShareAdminObjectType]
    CHECK_SA_ON_SF: _ClassVar[CheckShareAdminObjectType]
    CHECK_SA_ON_RECORD: _ClassVar[CheckShareAdminObjectType]

class ShareStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    ACTIVE: _ClassVar[ShareStatus]
    BLOCK: _ClassVar[ShareStatus]
    INVITED: _ClassVar[ShareStatus]

class RecordTransactionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RTT_GENERAL: _ClassVar[RecordTransactionType]
    RTT_ROTATION: _ClassVar[RecordTransactionType]

class TimeLimitedAccessType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    INVALID_TIME_LIMITED_ACCESS_TYPE: _ClassVar[TimeLimitedAccessType]
    USER_ACCESS_TO_RECORD: _ClassVar[TimeLimitedAccessType]
    USER_OR_TEAM_ACCESS_TO_SHAREDFOLDER: _ClassVar[TimeLimitedAccessType]
    RECORD_ACCESS_TO_SHAREDFOLDER: _ClassVar[TimeLimitedAccessType]
    USER_ACCESS_TO_SHAREDFOLDER: _ClassVar[TimeLimitedAccessType]
    TEAM_ACCESS_TO_SHAREDFOLDER: _ClassVar[TimeLimitedAccessType]

class TimerNotificationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    NOTIFICATION_OFF: _ClassVar[TimerNotificationType]
    NOTIFY_OWNER: _ClassVar[TimerNotificationType]
    NOTIFY_PRIVILEGED_USERS: _ClassVar[TimerNotificationType]
RT_STANDARD: RecordTypeScope
RT_USER: RecordTypeScope
RT_ENTERPRISE: RecordTypeScope
RT_PAM: RecordTypeScope
RT_PAM_CONFIGURATION: RecordTypeScope
NO_KEY: RecordKeyType
ENCRYPTED_BY_DATA_KEY: RecordKeyType
ENCRYPTED_BY_PUBLIC_KEY: RecordKeyType
ENCRYPTED_BY_DATA_KEY_GCM: RecordKeyType
ENCRYPTED_BY_PUBLIC_KEY_ECC: RecordKeyType
ENCRYPTED_BY_ROOT_KEY_CBC: RecordKeyType
ENCRYPTED_BY_ROOT_KEY_GCM: RecordKeyType
user_folder: RecordFolderType
shared_folder: RecordFolderType
shared_folder_folder: RecordFolderType
RS_SUCCESS: RecordModifyResult
RS_OUT_OF_SYNC: RecordModifyResult
RS_ACCESS_DENIED: RecordModifyResult
RS_SHARE_DENIED: RecordModifyResult
RS_RECORD_EXISTS: RecordModifyResult
RS_OLD_RECORD_VERSION_TYPE: RecordModifyResult
RS_NEW_RECORD_VERSION_TYPE: RecordModifyResult
RS_FILES_NOT_MATCH: RecordModifyResult
RS_RECORD_NOT_SHAREABLE: RecordModifyResult
RS_ATTACHMENT_NOT_SHAREABLE: RecordModifyResult
RS_FILE_LIMIT_REACHED: RecordModifyResult
RS_SIZE_EXCEEDED_LIMIT: RecordModifyResult
RS_ONLY_OWNER_CAN_MODIFY_SCRIPTS: RecordModifyResult
FA_SUCCESS: FileAddResult
FA_ERROR: FileAddResult
FG_SUCCESS: FileGetResult
FG_ERROR: FileGetResult
FG_ACCESS_DENIED: FileGetResult
DATA_PLUS_SHARE: RecordDetailsInclude
DATA_ONLY: RecordDetailsInclude
SHARE_ONLY: RecordDetailsInclude
CHECK_SA_INVALID_TYPE: CheckShareAdminObjectType
CHECK_SA_ON_SF: CheckShareAdminObjectType
CHECK_SA_ON_RECORD: CheckShareAdminObjectType
ACTIVE: ShareStatus
BLOCK: ShareStatus
INVITED: ShareStatus
RTT_GENERAL: RecordTransactionType
RTT_ROTATION: RecordTransactionType
INVALID_TIME_LIMITED_ACCESS_TYPE: TimeLimitedAccessType
USER_ACCESS_TO_RECORD: TimeLimitedAccessType
USER_OR_TEAM_ACCESS_TO_SHAREDFOLDER: TimeLimitedAccessType
RECORD_ACCESS_TO_SHAREDFOLDER: TimeLimitedAccessType
USER_ACCESS_TO_SHAREDFOLDER: TimeLimitedAccessType
TEAM_ACCESS_TO_SHAREDFOLDER: TimeLimitedAccessType
NOTIFICATION_OFF: TimerNotificationType
NOTIFY_OWNER: TimerNotificationType
NOTIFY_PRIVILEGED_USERS: TimerNotificationType

class RecordType(_message.Message):
    __slots__ = ["recordTypeId", "content", "scope"]
    RECORDTYPEID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    recordTypeId: int
    content: str
    scope: RecordTypeScope
    def __init__(self, recordTypeId: _Optional[int] = ..., content: _Optional[str] = ..., scope: _Optional[_Union[RecordTypeScope, str]] = ...) -> None: ...

class RecordTypesRequest(_message.Message):
    __slots__ = ["standard", "user", "enterprise", "pam"]
    STANDARD_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISE_FIELD_NUMBER: _ClassVar[int]
    PAM_FIELD_NUMBER: _ClassVar[int]
    standard: bool
    user: bool
    enterprise: bool
    pam: bool
    def __init__(self, standard: bool = ..., user: bool = ..., enterprise: bool = ..., pam: bool = ...) -> None: ...

class RecordTypesResponse(_message.Message):
    __slots__ = ["recordTypes", "standardCounter", "userCounter", "enterpriseCounter", "pamCounter"]
    RECORDTYPES_FIELD_NUMBER: _ClassVar[int]
    STANDARDCOUNTER_FIELD_NUMBER: _ClassVar[int]
    USERCOUNTER_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISECOUNTER_FIELD_NUMBER: _ClassVar[int]
    PAMCOUNTER_FIELD_NUMBER: _ClassVar[int]
    recordTypes: _containers.RepeatedCompositeFieldContainer[RecordType]
    standardCounter: int
    userCounter: int
    enterpriseCounter: int
    pamCounter: int
    def __init__(self, recordTypes: _Optional[_Iterable[_Union[RecordType, _Mapping]]] = ..., standardCounter: _Optional[int] = ..., userCounter: _Optional[int] = ..., enterpriseCounter: _Optional[int] = ..., pamCounter: _Optional[int] = ...) -> None: ...

class RecordTypeModifyResponse(_message.Message):
    __slots__ = ["recordTypeId", "counter"]
    RECORDTYPEID_FIELD_NUMBER: _ClassVar[int]
    COUNTER_FIELD_NUMBER: _ClassVar[int]
    recordTypeId: int
    counter: int
    def __init__(self, recordTypeId: _Optional[int] = ..., counter: _Optional[int] = ...) -> None: ...

class RecordsGetRequest(_message.Message):
    __slots__ = ["record_uids", "client_time"]
    RECORD_UIDS_FIELD_NUMBER: _ClassVar[int]
    CLIENT_TIME_FIELD_NUMBER: _ClassVar[int]
    record_uids: _containers.RepeatedScalarFieldContainer[bytes]
    client_time: int
    def __init__(self, record_uids: _Optional[_Iterable[bytes]] = ..., client_time: _Optional[int] = ...) -> None: ...

class Record(_message.Message):
    __slots__ = ["record_uid", "record_key", "record_key_type", "data", "extra", "version", "client_modified_time", "revision", "file_ids"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    EXTRA_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    CLIENT_MODIFIED_TIME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    FILE_IDS_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    record_key: bytes
    record_key_type: RecordKeyType
    data: bytes
    extra: bytes
    version: int
    client_modified_time: int
    revision: int
    file_ids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, record_uid: _Optional[bytes] = ..., record_key: _Optional[bytes] = ..., record_key_type: _Optional[_Union[RecordKeyType, str]] = ..., data: _Optional[bytes] = ..., extra: _Optional[bytes] = ..., version: _Optional[int] = ..., client_modified_time: _Optional[int] = ..., revision: _Optional[int] = ..., file_ids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class FolderRecordKey(_message.Message):
    __slots__ = ["folder_uid", "record_uid", "record_key"]
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    record_uid: bytes
    record_key: bytes
    def __init__(self, folder_uid: _Optional[bytes] = ..., record_uid: _Optional[bytes] = ..., record_key: _Optional[bytes] = ...) -> None: ...

class Folder(_message.Message):
    __slots__ = ["folder_uid", "folder_key", "folder_key_type"]
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    FOLDER_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    folder_key: bytes
    folder_key_type: RecordKeyType
    def __init__(self, folder_uid: _Optional[bytes] = ..., folder_key: _Optional[bytes] = ..., folder_key_type: _Optional[_Union[RecordKeyType, str]] = ...) -> None: ...

class Team(_message.Message):
    __slots__ = ["team_uid", "team_key", "team_private_key", "team_key_type", "folders"]
    TEAM_UID_FIELD_NUMBER: _ClassVar[int]
    TEAM_KEY_FIELD_NUMBER: _ClassVar[int]
    TEAM_PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    TEAM_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    team_uid: bytes
    team_key: bytes
    team_private_key: bytes
    team_key_type: RecordKeyType
    folders: _containers.RepeatedCompositeFieldContainer[Folder]
    def __init__(self, team_uid: _Optional[bytes] = ..., team_key: _Optional[bytes] = ..., team_private_key: _Optional[bytes] = ..., team_key_type: _Optional[_Union[RecordKeyType, str]] = ..., folders: _Optional[_Iterable[_Union[Folder, _Mapping]]] = ...) -> None: ...

class RecordsGetResponse(_message.Message):
    __slots__ = ["records", "folder_record_keys", "folders", "teams"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    FOLDER_RECORD_KEYS_FIELD_NUMBER: _ClassVar[int]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    TEAMS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[Record]
    folder_record_keys: _containers.RepeatedCompositeFieldContainer[FolderRecordKey]
    folders: _containers.RepeatedCompositeFieldContainer[Folder]
    teams: _containers.RepeatedCompositeFieldContainer[Team]
    def __init__(self, records: _Optional[_Iterable[_Union[Record, _Mapping]]] = ..., folder_record_keys: _Optional[_Iterable[_Union[FolderRecordKey, _Mapping]]] = ..., folders: _Optional[_Iterable[_Union[Folder, _Mapping]]] = ..., teams: _Optional[_Iterable[_Union[Team, _Mapping]]] = ...) -> None: ...

class RecordLink(_message.Message):
    __slots__ = ["record_uid", "record_key"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    record_key: bytes
    def __init__(self, record_uid: _Optional[bytes] = ..., record_key: _Optional[bytes] = ...) -> None: ...

class RecordAudit(_message.Message):
    __slots__ = ["version", "data"]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    version: int
    data: bytes
    def __init__(self, version: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class SecurityData(_message.Message):
    __slots__ = ["data"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class SecurityScoreData(_message.Message):
    __slots__ = ["data"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class RecordAdd(_message.Message):
    __slots__ = ["record_uid", "record_key", "client_modified_time", "data", "non_shared_data", "folder_type", "folder_uid", "folder_key", "record_links", "audit", "securityData", "securityScoreData"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    CLIENT_MODIFIED_TIME_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    NON_SHARED_DATA_FIELD_NUMBER: _ClassVar[int]
    FOLDER_TYPE_FIELD_NUMBER: _ClassVar[int]
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    RECORD_LINKS_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    SECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    SECURITYSCOREDATA_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    record_key: bytes
    client_modified_time: int
    data: bytes
    non_shared_data: bytes
    folder_type: RecordFolderType
    folder_uid: bytes
    folder_key: bytes
    record_links: _containers.RepeatedCompositeFieldContainer[RecordLink]
    audit: RecordAudit
    securityData: SecurityData
    securityScoreData: SecurityScoreData
    def __init__(self, record_uid: _Optional[bytes] = ..., record_key: _Optional[bytes] = ..., client_modified_time: _Optional[int] = ..., data: _Optional[bytes] = ..., non_shared_data: _Optional[bytes] = ..., folder_type: _Optional[_Union[RecordFolderType, str]] = ..., folder_uid: _Optional[bytes] = ..., folder_key: _Optional[bytes] = ..., record_links: _Optional[_Iterable[_Union[RecordLink, _Mapping]]] = ..., audit: _Optional[_Union[RecordAudit, _Mapping]] = ..., securityData: _Optional[_Union[SecurityData, _Mapping]] = ..., securityScoreData: _Optional[_Union[SecurityScoreData, _Mapping]] = ...) -> None: ...

class RecordsAddRequest(_message.Message):
    __slots__ = ["records", "client_time", "security_data_key_type"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    CLIENT_TIME_FIELD_NUMBER: _ClassVar[int]
    SECURITY_DATA_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RecordAdd]
    client_time: int
    security_data_key_type: RecordKeyType
    def __init__(self, records: _Optional[_Iterable[_Union[RecordAdd, _Mapping]]] = ..., client_time: _Optional[int] = ..., security_data_key_type: _Optional[_Union[RecordKeyType, str]] = ...) -> None: ...

class RecordUpdate(_message.Message):
    __slots__ = ["record_uid", "client_modified_time", "revision", "data", "non_shared_data", "record_links_add", "record_links_remove", "audit", "securityData", "securityScoreData"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_MODIFIED_TIME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    NON_SHARED_DATA_FIELD_NUMBER: _ClassVar[int]
    RECORD_LINKS_ADD_FIELD_NUMBER: _ClassVar[int]
    RECORD_LINKS_REMOVE_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    SECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    SECURITYSCOREDATA_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    client_modified_time: int
    revision: int
    data: bytes
    non_shared_data: bytes
    record_links_add: _containers.RepeatedCompositeFieldContainer[RecordLink]
    record_links_remove: _containers.RepeatedScalarFieldContainer[bytes]
    audit: RecordAudit
    securityData: SecurityData
    securityScoreData: SecurityScoreData
    def __init__(self, record_uid: _Optional[bytes] = ..., client_modified_time: _Optional[int] = ..., revision: _Optional[int] = ..., data: _Optional[bytes] = ..., non_shared_data: _Optional[bytes] = ..., record_links_add: _Optional[_Iterable[_Union[RecordLink, _Mapping]]] = ..., record_links_remove: _Optional[_Iterable[bytes]] = ..., audit: _Optional[_Union[RecordAudit, _Mapping]] = ..., securityData: _Optional[_Union[SecurityData, _Mapping]] = ..., securityScoreData: _Optional[_Union[SecurityScoreData, _Mapping]] = ...) -> None: ...

class RecordsUpdateRequest(_message.Message):
    __slots__ = ["records", "client_time", "security_data_key_type"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    CLIENT_TIME_FIELD_NUMBER: _ClassVar[int]
    SECURITY_DATA_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RecordUpdate]
    client_time: int
    security_data_key_type: RecordKeyType
    def __init__(self, records: _Optional[_Iterable[_Union[RecordUpdate, _Mapping]]] = ..., client_time: _Optional[int] = ..., security_data_key_type: _Optional[_Union[RecordKeyType, str]] = ...) -> None: ...

class RecordFileForConversion(_message.Message):
    __slots__ = ["record_uid", "file_file_id", "thumb_file_id", "data", "record_key", "link_key"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    FILE_FILE_ID_FIELD_NUMBER: _ClassVar[int]
    THUMB_FILE_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    LINK_KEY_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    file_file_id: str
    thumb_file_id: str
    data: bytes
    record_key: bytes
    link_key: bytes
    def __init__(self, record_uid: _Optional[bytes] = ..., file_file_id: _Optional[str] = ..., thumb_file_id: _Optional[str] = ..., data: _Optional[bytes] = ..., record_key: _Optional[bytes] = ..., link_key: _Optional[bytes] = ...) -> None: ...

class RecordFolderForConversion(_message.Message):
    __slots__ = ["folder_uid", "record_folder_key"]
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    record_folder_key: bytes
    def __init__(self, folder_uid: _Optional[bytes] = ..., record_folder_key: _Optional[bytes] = ...) -> None: ...

class RecordConvertToV3(_message.Message):
    __slots__ = ["record_uid", "client_modified_time", "revision", "data", "non_shared_data", "audit", "record_file", "folder_key"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_MODIFIED_TIME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    NON_SHARED_DATA_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    RECORD_FILE_FIELD_NUMBER: _ClassVar[int]
    FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    client_modified_time: int
    revision: int
    data: bytes
    non_shared_data: bytes
    audit: RecordAudit
    record_file: _containers.RepeatedCompositeFieldContainer[RecordFileForConversion]
    folder_key: _containers.RepeatedCompositeFieldContainer[RecordFolderForConversion]
    def __init__(self, record_uid: _Optional[bytes] = ..., client_modified_time: _Optional[int] = ..., revision: _Optional[int] = ..., data: _Optional[bytes] = ..., non_shared_data: _Optional[bytes] = ..., audit: _Optional[_Union[RecordAudit, _Mapping]] = ..., record_file: _Optional[_Iterable[_Union[RecordFileForConversion, _Mapping]]] = ..., folder_key: _Optional[_Iterable[_Union[RecordFolderForConversion, _Mapping]]] = ...) -> None: ...

class RecordsConvertToV3Request(_message.Message):
    __slots__ = ["records", "client_time"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    CLIENT_TIME_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RecordConvertToV3]
    client_time: int
    def __init__(self, records: _Optional[_Iterable[_Union[RecordConvertToV3, _Mapping]]] = ..., client_time: _Optional[int] = ...) -> None: ...

class RecordsRemoveRequest(_message.Message):
    __slots__ = ["records"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, records: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RecordRevert(_message.Message):
    __slots__ = ["record_uid", "revert_to_revision"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    REVERT_TO_REVISION_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    revert_to_revision: int
    def __init__(self, record_uid: _Optional[bytes] = ..., revert_to_revision: _Optional[int] = ...) -> None: ...

class RecordsRevertRequest(_message.Message):
    __slots__ = ["records"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RecordRevert]
    def __init__(self, records: _Optional[_Iterable[_Union[RecordRevert, _Mapping]]] = ...) -> None: ...

class RecordLinkError(_message.Message):
    __slots__ = ["record_uid", "status", "message"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    status: RecordModifyResult
    message: str
    def __init__(self, record_uid: _Optional[bytes] = ..., status: _Optional[_Union[RecordModifyResult, str]] = ..., message: _Optional[str] = ...) -> None: ...

class RecordModifyStatus(_message.Message):
    __slots__ = ["record_uid", "status", "message", "link_errors"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    LINK_ERRORS_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    status: RecordModifyResult
    message: str
    link_errors: _containers.RepeatedCompositeFieldContainer[RecordLinkError]
    def __init__(self, record_uid: _Optional[bytes] = ..., status: _Optional[_Union[RecordModifyResult, str]] = ..., message: _Optional[str] = ..., link_errors: _Optional[_Iterable[_Union[RecordLinkError, _Mapping]]] = ...) -> None: ...

class RecordsModifyResponse(_message.Message):
    __slots__ = ["records", "revision"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RecordModifyStatus]
    revision: int
    def __init__(self, records: _Optional[_Iterable[_Union[RecordModifyStatus, _Mapping]]] = ..., revision: _Optional[int] = ...) -> None: ...

class RecordAddAuditData(_message.Message):
    __slots__ = ["record_uid", "revision", "data", "version"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    revision: int
    data: bytes
    version: int
    def __init__(self, record_uid: _Optional[bytes] = ..., revision: _Optional[int] = ..., data: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...

class AddAuditDataRequest(_message.Message):
    __slots__ = ["records"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RecordAddAuditData]
    def __init__(self, records: _Optional[_Iterable[_Union[RecordAddAuditData, _Mapping]]] = ...) -> None: ...

class File(_message.Message):
    __slots__ = ["record_uid", "record_key", "data", "fileSize", "thumbSize", "is_script"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    FILESIZE_FIELD_NUMBER: _ClassVar[int]
    THUMBSIZE_FIELD_NUMBER: _ClassVar[int]
    IS_SCRIPT_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    record_key: bytes
    data: bytes
    fileSize: int
    thumbSize: int
    is_script: bool
    def __init__(self, record_uid: _Optional[bytes] = ..., record_key: _Optional[bytes] = ..., data: _Optional[bytes] = ..., fileSize: _Optional[int] = ..., thumbSize: _Optional[int] = ..., is_script: bool = ...) -> None: ...

class FilesAddRequest(_message.Message):
    __slots__ = ["files", "client_time"]
    FILES_FIELD_NUMBER: _ClassVar[int]
    CLIENT_TIME_FIELD_NUMBER: _ClassVar[int]
    files: _containers.RepeatedCompositeFieldContainer[File]
    client_time: int
    def __init__(self, files: _Optional[_Iterable[_Union[File, _Mapping]]] = ..., client_time: _Optional[int] = ...) -> None: ...

class FileAddStatus(_message.Message):
    __slots__ = ["record_uid", "status", "url", "parameters", "thumbnail_parameters", "success_status_code"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    THUMBNAIL_PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    status: FileAddResult
    url: str
    parameters: str
    thumbnail_parameters: str
    success_status_code: int
    def __init__(self, record_uid: _Optional[bytes] = ..., status: _Optional[_Union[FileAddResult, str]] = ..., url: _Optional[str] = ..., parameters: _Optional[str] = ..., thumbnail_parameters: _Optional[str] = ..., success_status_code: _Optional[int] = ...) -> None: ...

class FilesAddResponse(_message.Message):
    __slots__ = ["files", "revision"]
    FILES_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    files: _containers.RepeatedCompositeFieldContainer[FileAddStatus]
    revision: int
    def __init__(self, files: _Optional[_Iterable[_Union[FileAddStatus, _Mapping]]] = ..., revision: _Optional[int] = ...) -> None: ...

class FilesGetRequest(_message.Message):
    __slots__ = ["record_uids", "for_thumbnails", "emergency_access_account_owner"]
    RECORD_UIDS_FIELD_NUMBER: _ClassVar[int]
    FOR_THUMBNAILS_FIELD_NUMBER: _ClassVar[int]
    EMERGENCY_ACCESS_ACCOUNT_OWNER_FIELD_NUMBER: _ClassVar[int]
    record_uids: _containers.RepeatedScalarFieldContainer[bytes]
    for_thumbnails: bool
    emergency_access_account_owner: str
    def __init__(self, record_uids: _Optional[_Iterable[bytes]] = ..., for_thumbnails: bool = ..., emergency_access_account_owner: _Optional[str] = ...) -> None: ...

class FileGetStatus(_message.Message):
    __slots__ = ["record_uid", "status", "url", "success_status_code", "fileKeyType"]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    FILEKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    status: FileGetResult
    url: str
    success_status_code: int
    fileKeyType: RecordKeyType
    def __init__(self, record_uid: _Optional[bytes] = ..., status: _Optional[_Union[FileGetResult, str]] = ..., url: _Optional[str] = ..., success_status_code: _Optional[int] = ..., fileKeyType: _Optional[_Union[RecordKeyType, str]] = ...) -> None: ...

class FilesGetResponse(_message.Message):
    __slots__ = ["files"]
    FILES_FIELD_NUMBER: _ClassVar[int]
    files: _containers.RepeatedCompositeFieldContainer[FileGetStatus]
    def __init__(self, files: _Optional[_Iterable[_Union[FileGetStatus, _Mapping]]] = ...) -> None: ...

class ApplicationAddRequest(_message.Message):
    __slots__ = ["app_uid", "record_key", "client_modified_time", "data", "audit"]
    APP_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    CLIENT_MODIFIED_TIME_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    app_uid: bytes
    record_key: bytes
    client_modified_time: int
    data: bytes
    audit: RecordAudit
    def __init__(self, app_uid: _Optional[bytes] = ..., record_key: _Optional[bytes] = ..., client_modified_time: _Optional[int] = ..., data: _Optional[bytes] = ..., audit: _Optional[_Union[RecordAudit, _Mapping]] = ...) -> None: ...

class GetRecordDataWithAccessInfoRequest(_message.Message):
    __slots__ = ["clientTime", "recordUid", "recordDetailsInclude"]
    CLIENTTIME_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDDETAILSINCLUDE_FIELD_NUMBER: _ClassVar[int]
    clientTime: int
    recordUid: _containers.RepeatedScalarFieldContainer[bytes]
    recordDetailsInclude: RecordDetailsInclude
    def __init__(self, clientTime: _Optional[int] = ..., recordUid: _Optional[_Iterable[bytes]] = ..., recordDetailsInclude: _Optional[_Union[RecordDetailsInclude, str]] = ...) -> None: ...

class UserPermission(_message.Message):
    __slots__ = ["username", "owner", "shareAdmin", "sharable", "editable", "awaitingApproval", "expiration", "accountUid", "timerNotificationType", "rotateOnExpiration"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    SHAREADMIN_FIELD_NUMBER: _ClassVar[int]
    SHARABLE_FIELD_NUMBER: _ClassVar[int]
    EDITABLE_FIELD_NUMBER: _ClassVar[int]
    AWAITINGAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    username: str
    owner: bool
    shareAdmin: bool
    sharable: bool
    editable: bool
    awaitingApproval: bool
    expiration: int
    accountUid: bytes
    timerNotificationType: TimerNotificationType
    rotateOnExpiration: bool
    def __init__(self, username: _Optional[str] = ..., owner: bool = ..., shareAdmin: bool = ..., sharable: bool = ..., editable: bool = ..., awaitingApproval: bool = ..., expiration: _Optional[int] = ..., accountUid: _Optional[bytes] = ..., timerNotificationType: _Optional[_Union[TimerNotificationType, str]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class SharedFolderPermission(_message.Message):
    __slots__ = ["sharedFolderUid", "resharable", "editable", "revision", "expiration", "timerNotificationType", "rotateOnExpiration"]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RESHARABLE_FIELD_NUMBER: _ClassVar[int]
    EDITABLE_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    resharable: bool
    editable: bool
    revision: int
    expiration: int
    timerNotificationType: TimerNotificationType
    rotateOnExpiration: bool
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., resharable: bool = ..., editable: bool = ..., revision: _Optional[int] = ..., expiration: _Optional[int] = ..., timerNotificationType: _Optional[_Union[TimerNotificationType, str]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class RecordData(_message.Message):
    __slots__ = ["revision", "version", "shared", "encryptedRecordData", "encryptedExtraData", "clientModifiedTime", "nonSharedData", "linkedRecordData", "fileId", "fileSize", "thumbnailSize", "recordKeyType", "recordKey", "recordUid"]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SHARED_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRECORDDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDEXTRADATA_FIELD_NUMBER: _ClassVar[int]
    CLIENTMODIFIEDTIME_FIELD_NUMBER: _ClassVar[int]
    NONSHAREDDATA_FIELD_NUMBER: _ClassVar[int]
    LINKEDRECORDDATA_FIELD_NUMBER: _ClassVar[int]
    FILEID_FIELD_NUMBER: _ClassVar[int]
    FILESIZE_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSIZE_FIELD_NUMBER: _ClassVar[int]
    RECORDKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    revision: int
    version: int
    shared: bool
    encryptedRecordData: str
    encryptedExtraData: str
    clientModifiedTime: int
    nonSharedData: str
    linkedRecordData: _containers.RepeatedCompositeFieldContainer[RecordData]
    fileId: _containers.RepeatedScalarFieldContainer[bytes]
    fileSize: int
    thumbnailSize: int
    recordKeyType: RecordKeyType
    recordKey: bytes
    recordUid: bytes
    def __init__(self, revision: _Optional[int] = ..., version: _Optional[int] = ..., shared: bool = ..., encryptedRecordData: _Optional[str] = ..., encryptedExtraData: _Optional[str] = ..., clientModifiedTime: _Optional[int] = ..., nonSharedData: _Optional[str] = ..., linkedRecordData: _Optional[_Iterable[_Union[RecordData, _Mapping]]] = ..., fileId: _Optional[_Iterable[bytes]] = ..., fileSize: _Optional[int] = ..., thumbnailSize: _Optional[int] = ..., recordKeyType: _Optional[_Union[RecordKeyType, str]] = ..., recordKey: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ...) -> None: ...

class RecordDataWithAccessInfo(_message.Message):
    __slots__ = ["recordUid", "recordData", "userPermission", "sharedFolderPermission"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDDATA_FIELD_NUMBER: _ClassVar[int]
    USERPERMISSION_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERPERMISSION_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    recordData: RecordData
    userPermission: _containers.RepeatedCompositeFieldContainer[UserPermission]
    sharedFolderPermission: _containers.RepeatedCompositeFieldContainer[SharedFolderPermission]
    def __init__(self, recordUid: _Optional[bytes] = ..., recordData: _Optional[_Union[RecordData, _Mapping]] = ..., userPermission: _Optional[_Iterable[_Union[UserPermission, _Mapping]]] = ..., sharedFolderPermission: _Optional[_Iterable[_Union[SharedFolderPermission, _Mapping]]] = ...) -> None: ...

class GetRecordDataWithAccessInfoResponse(_message.Message):
    __slots__ = ["recordDataWithAccessInfo", "noPermissionRecordUid"]
    RECORDDATAWITHACCESSINFO_FIELD_NUMBER: _ClassVar[int]
    NOPERMISSIONRECORDUID_FIELD_NUMBER: _ClassVar[int]
    recordDataWithAccessInfo: _containers.RepeatedCompositeFieldContainer[RecordDataWithAccessInfo]
    noPermissionRecordUid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, recordDataWithAccessInfo: _Optional[_Iterable[_Union[RecordDataWithAccessInfo, _Mapping]]] = ..., noPermissionRecordUid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class IsObjectShareAdmin(_message.Message):
    __slots__ = ["uid", "isAdmin", "objectType"]
    UID_FIELD_NUMBER: _ClassVar[int]
    ISADMIN_FIELD_NUMBER: _ClassVar[int]
    OBJECTTYPE_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    isAdmin: bool
    objectType: CheckShareAdminObjectType
    def __init__(self, uid: _Optional[bytes] = ..., isAdmin: bool = ..., objectType: _Optional[_Union[CheckShareAdminObjectType, str]] = ...) -> None: ...

class AmIShareAdmin(_message.Message):
    __slots__ = ["isObjectShareAdmin"]
    ISOBJECTSHAREADMIN_FIELD_NUMBER: _ClassVar[int]
    isObjectShareAdmin: _containers.RepeatedCompositeFieldContainer[IsObjectShareAdmin]
    def __init__(self, isObjectShareAdmin: _Optional[_Iterable[_Union[IsObjectShareAdmin, _Mapping]]] = ...) -> None: ...

class RecordShareUpdateRequest(_message.Message):
    __slots__ = ["addSharedRecord", "updateSharedRecord", "removeSharedRecord", "pt"]
    ADDSHAREDRECORD_FIELD_NUMBER: _ClassVar[int]
    UPDATESHAREDRECORD_FIELD_NUMBER: _ClassVar[int]
    REMOVESHAREDRECORD_FIELD_NUMBER: _ClassVar[int]
    PT_FIELD_NUMBER: _ClassVar[int]
    addSharedRecord: _containers.RepeatedCompositeFieldContainer[SharedRecord]
    updateSharedRecord: _containers.RepeatedCompositeFieldContainer[SharedRecord]
    removeSharedRecord: _containers.RepeatedCompositeFieldContainer[SharedRecord]
    pt: str
    def __init__(self, addSharedRecord: _Optional[_Iterable[_Union[SharedRecord, _Mapping]]] = ..., updateSharedRecord: _Optional[_Iterable[_Union[SharedRecord, _Mapping]]] = ..., removeSharedRecord: _Optional[_Iterable[_Union[SharedRecord, _Mapping]]] = ..., pt: _Optional[str] = ...) -> None: ...

class SharedRecord(_message.Message):
    __slots__ = ["toUsername", "recordUid", "recordKey", "sharedFolderUid", "teamUid", "editable", "shareable", "transfer", "useEccKey", "removeVaultData", "expiration", "timerNotificationType", "rotateOnExpiration"]
    TOUSERNAME_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    EDITABLE_FIELD_NUMBER: _ClassVar[int]
    SHAREABLE_FIELD_NUMBER: _ClassVar[int]
    TRANSFER_FIELD_NUMBER: _ClassVar[int]
    USEECCKEY_FIELD_NUMBER: _ClassVar[int]
    REMOVEVAULTDATA_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    toUsername: str
    recordUid: bytes
    recordKey: bytes
    sharedFolderUid: bytes
    teamUid: bytes
    editable: bool
    shareable: bool
    transfer: bool
    useEccKey: bool
    removeVaultData: bool
    expiration: int
    timerNotificationType: TimerNotificationType
    rotateOnExpiration: bool
    def __init__(self, toUsername: _Optional[str] = ..., recordUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., sharedFolderUid: _Optional[bytes] = ..., teamUid: _Optional[bytes] = ..., editable: bool = ..., shareable: bool = ..., transfer: bool = ..., useEccKey: bool = ..., removeVaultData: bool = ..., expiration: _Optional[int] = ..., timerNotificationType: _Optional[_Union[TimerNotificationType, str]] = ..., rotateOnExpiration: bool = ...) -> None: ...

class RecordShareUpdateResponse(_message.Message):
    __slots__ = ["addSharedRecordStatus", "updateSharedRecordStatus", "removeSharedRecordStatus"]
    ADDSHAREDRECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    UPDATESHAREDRECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    REMOVESHAREDRECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    addSharedRecordStatus: _containers.RepeatedCompositeFieldContainer[SharedRecordStatus]
    updateSharedRecordStatus: _containers.RepeatedCompositeFieldContainer[SharedRecordStatus]
    removeSharedRecordStatus: _containers.RepeatedCompositeFieldContainer[SharedRecordStatus]
    def __init__(self, addSharedRecordStatus: _Optional[_Iterable[_Union[SharedRecordStatus, _Mapping]]] = ..., updateSharedRecordStatus: _Optional[_Iterable[_Union[SharedRecordStatus, _Mapping]]] = ..., removeSharedRecordStatus: _Optional[_Iterable[_Union[SharedRecordStatus, _Mapping]]] = ...) -> None: ...

class SharedRecordStatus(_message.Message):
    __slots__ = ["recordUid", "status", "message", "username"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    status: str
    message: str
    username: str
    def __init__(self, recordUid: _Optional[bytes] = ..., status: _Optional[str] = ..., message: _Optional[str] = ..., username: _Optional[str] = ...) -> None: ...

class GetRecordPermissionsRequest(_message.Message):
    __slots__ = ["recordUids", "isShareAdmin"]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    ISSHAREADMIN_FIELD_NUMBER: _ClassVar[int]
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    isShareAdmin: bool
    def __init__(self, recordUids: _Optional[_Iterable[bytes]] = ..., isShareAdmin: bool = ...) -> None: ...

class GetRecordPermissionsResponse(_message.Message):
    __slots__ = ["recordPermissions"]
    RECORDPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    recordPermissions: _containers.RepeatedCompositeFieldContainer[RecordPermission]
    def __init__(self, recordPermissions: _Optional[_Iterable[_Union[RecordPermission, _Mapping]]] = ...) -> None: ...

class RecordPermission(_message.Message):
    __slots__ = ["recordUid", "owner", "canEdit", "canShare", "canTransfer"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    CANEDIT_FIELD_NUMBER: _ClassVar[int]
    CANSHARE_FIELD_NUMBER: _ClassVar[int]
    CANTRANSFER_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    owner: bool
    canEdit: bool
    canShare: bool
    canTransfer: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., owner: bool = ..., canEdit: bool = ..., canShare: bool = ..., canTransfer: bool = ...) -> None: ...

class GetShareObjectsRequest(_message.Message):
    __slots__ = ["startWith", "contains", "filtered", "sharedFolderUid"]
    STARTWITH_FIELD_NUMBER: _ClassVar[int]
    CONTAINS_FIELD_NUMBER: _ClassVar[int]
    FILTERED_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    startWith: str
    contains: str
    filtered: bool
    sharedFolderUid: bytes
    def __init__(self, startWith: _Optional[str] = ..., contains: _Optional[str] = ..., filtered: bool = ..., sharedFolderUid: _Optional[bytes] = ...) -> None: ...

class GetShareObjectsResponse(_message.Message):
    __slots__ = ["shareRelationships", "shareFamilyUsers", "shareEnterpriseUsers", "shareTeams", "shareMCTeams", "shareMCEnterpriseUsers", "shareEnterpriseNames"]
    SHARERELATIONSHIPS_FIELD_NUMBER: _ClassVar[int]
    SHAREFAMILYUSERS_FIELD_NUMBER: _ClassVar[int]
    SHAREENTERPRISEUSERS_FIELD_NUMBER: _ClassVar[int]
    SHARETEAMS_FIELD_NUMBER: _ClassVar[int]
    SHAREMCTEAMS_FIELD_NUMBER: _ClassVar[int]
    SHAREMCENTERPRISEUSERS_FIELD_NUMBER: _ClassVar[int]
    SHAREENTERPRISENAMES_FIELD_NUMBER: _ClassVar[int]
    shareRelationships: _containers.RepeatedCompositeFieldContainer[ShareUser]
    shareFamilyUsers: _containers.RepeatedCompositeFieldContainer[ShareUser]
    shareEnterpriseUsers: _containers.RepeatedCompositeFieldContainer[ShareUser]
    shareTeams: _containers.RepeatedCompositeFieldContainer[ShareTeam]
    shareMCTeams: _containers.RepeatedCompositeFieldContainer[ShareTeam]
    shareMCEnterpriseUsers: _containers.RepeatedCompositeFieldContainer[ShareUser]
    shareEnterpriseNames: _containers.RepeatedCompositeFieldContainer[ShareEnterprise]
    def __init__(self, shareRelationships: _Optional[_Iterable[_Union[ShareUser, _Mapping]]] = ..., shareFamilyUsers: _Optional[_Iterable[_Union[ShareUser, _Mapping]]] = ..., shareEnterpriseUsers: _Optional[_Iterable[_Union[ShareUser, _Mapping]]] = ..., shareTeams: _Optional[_Iterable[_Union[ShareTeam, _Mapping]]] = ..., shareMCTeams: _Optional[_Iterable[_Union[ShareTeam, _Mapping]]] = ..., shareMCEnterpriseUsers: _Optional[_Iterable[_Union[ShareUser, _Mapping]]] = ..., shareEnterpriseNames: _Optional[_Iterable[_Union[ShareEnterprise, _Mapping]]] = ...) -> None: ...

class ShareUser(_message.Message):
    __slots__ = ["username", "fullname", "enterpriseId", "status", "isShareAdmin", "isAdminOfSharedFolderOwner"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ISSHAREADMIN_FIELD_NUMBER: _ClassVar[int]
    ISADMINOFSHAREDFOLDEROWNER_FIELD_NUMBER: _ClassVar[int]
    username: str
    fullname: str
    enterpriseId: int
    status: ShareStatus
    isShareAdmin: bool
    isAdminOfSharedFolderOwner: bool
    def __init__(self, username: _Optional[str] = ..., fullname: _Optional[str] = ..., enterpriseId: _Optional[int] = ..., status: _Optional[_Union[ShareStatus, str]] = ..., isShareAdmin: bool = ..., isAdminOfSharedFolderOwner: bool = ...) -> None: ...

class ShareTeam(_message.Message):
    __slots__ = ["teamname", "enterpriseId", "teamUid"]
    TEAMNAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    teamname: str
    enterpriseId: int
    teamUid: bytes
    def __init__(self, teamname: _Optional[str] = ..., enterpriseId: _Optional[int] = ..., teamUid: _Optional[bytes] = ...) -> None: ...

class ShareEnterprise(_message.Message):
    __slots__ = ["enterprisename", "enterpriseId"]
    ENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    enterprisename: str
    enterpriseId: int
    def __init__(self, enterprisename: _Optional[str] = ..., enterpriseId: _Optional[int] = ...) -> None: ...

class RecordsOnwershipTransferRequest(_message.Message):
    __slots__ = ["transferRecords"]
    TRANSFERRECORDS_FIELD_NUMBER: _ClassVar[int]
    transferRecords: _containers.RepeatedCompositeFieldContainer[TransferRecord]
    def __init__(self, transferRecords: _Optional[_Iterable[_Union[TransferRecord, _Mapping]]] = ...) -> None: ...

class TransferRecord(_message.Message):
    __slots__ = ["username", "recordUid", "recordKey", "useEccKey"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    USEECCKEY_FIELD_NUMBER: _ClassVar[int]
    username: str
    recordUid: bytes
    recordKey: bytes
    useEccKey: bool
    def __init__(self, username: _Optional[str] = ..., recordUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., useEccKey: bool = ...) -> None: ...

class RecordsOnwershipTransferResponse(_message.Message):
    __slots__ = ["transferRecordStatus"]
    TRANSFERRECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    transferRecordStatus: _containers.RepeatedCompositeFieldContainer[TransferRecordStatus]
    def __init__(self, transferRecordStatus: _Optional[_Iterable[_Union[TransferRecordStatus, _Mapping]]] = ...) -> None: ...

class TransferRecordStatus(_message.Message):
    __slots__ = ["username", "recordUid", "status", "message"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    username: str
    recordUid: bytes
    status: str
    message: str
    def __init__(self, username: _Optional[str] = ..., recordUid: _Optional[bytes] = ..., status: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class RecordsUnshareRequest(_message.Message):
    __slots__ = ["sharedFolders", "users"]
    SHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    sharedFolders: _containers.RepeatedCompositeFieldContainer[RecordsUnshareFolder]
    users: _containers.RepeatedCompositeFieldContainer[RecordsUnshareUser]
    def __init__(self, sharedFolders: _Optional[_Iterable[_Union[RecordsUnshareFolder, _Mapping]]] = ..., users: _Optional[_Iterable[_Union[RecordsUnshareUser, _Mapping]]] = ...) -> None: ...

class RecordsUnshareResponse(_message.Message):
    __slots__ = ["sharedFolders", "users"]
    SHAREDFOLDERS_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    sharedFolders: _containers.RepeatedCompositeFieldContainer[RecordsUnshareFolderStatus]
    users: _containers.RepeatedCompositeFieldContainer[RecordsUnshareUserStatus]
    def __init__(self, sharedFolders: _Optional[_Iterable[_Union[RecordsUnshareFolderStatus, _Mapping]]] = ..., users: _Optional[_Iterable[_Union[RecordsUnshareUserStatus, _Mapping]]] = ...) -> None: ...

class RecordsUnshareFolder(_message.Message):
    __slots__ = ["recordUid", "sharedFolderUid"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    sharedFolderUid: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., sharedFolderUid: _Optional[bytes] = ...) -> None: ...

class RecordsUnshareUser(_message.Message):
    __slots__ = ["recordUid", "accountUid"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    accountUid: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., accountUid: _Optional[bytes] = ...) -> None: ...

class RecordsUnshareFolderStatus(_message.Message):
    __slots__ = ["recordUid", "sharedFolderUid"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    sharedFolderUid: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., sharedFolderUid: _Optional[bytes] = ...) -> None: ...

class RecordsUnshareUserStatus(_message.Message):
    __slots__ = ["recordUid", "accountUid"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    accountUid: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., accountUid: _Optional[bytes] = ...) -> None: ...

class TimedAccessCallbackPayload(_message.Message):
    __slots__ = ["timeLimitedAccessType"]
    TIMELIMITEDACCESSTYPE_FIELD_NUMBER: _ClassVar[int]
    timeLimitedAccessType: TimeLimitedAccessType
    def __init__(self, timeLimitedAccessType: _Optional[_Union[TimeLimitedAccessType, str]] = ...) -> None: ...

class TimeLimitedAccessRequest(_message.Message):
    __slots__ = ["accountUid", "teamUid", "recordUid", "sharedObjectUid", "timeLimitedAccessType", "expiration", "timerNotificationType"]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    SHAREDOBJECTUID_FIELD_NUMBER: _ClassVar[int]
    TIMELIMITEDACCESSTYPE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    accountUid: _containers.RepeatedScalarFieldContainer[bytes]
    teamUid: _containers.RepeatedScalarFieldContainer[bytes]
    recordUid: _containers.RepeatedScalarFieldContainer[bytes]
    sharedObjectUid: bytes
    timeLimitedAccessType: TimeLimitedAccessType
    expiration: int
    timerNotificationType: TimerNotificationType
    def __init__(self, accountUid: _Optional[_Iterable[bytes]] = ..., teamUid: _Optional[_Iterable[bytes]] = ..., recordUid: _Optional[_Iterable[bytes]] = ..., sharedObjectUid: _Optional[bytes] = ..., timeLimitedAccessType: _Optional[_Union[TimeLimitedAccessType, str]] = ..., expiration: _Optional[int] = ..., timerNotificationType: _Optional[_Union[TimerNotificationType, str]] = ...) -> None: ...

class TimeLimitedAccessStatus(_message.Message):
    __slots__ = ["uid", "message"]
    UID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    message: str
    def __init__(self, uid: _Optional[bytes] = ..., message: _Optional[str] = ...) -> None: ...

class TimeLimitedAccessResponse(_message.Message):
    __slots__ = ["revision", "userAccessStatus", "teamAccessStatus", "recordAccessStatus"]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    USERACCESSSTATUS_FIELD_NUMBER: _ClassVar[int]
    TEAMACCESSSTATUS_FIELD_NUMBER: _ClassVar[int]
    RECORDACCESSSTATUS_FIELD_NUMBER: _ClassVar[int]
    revision: int
    userAccessStatus: _containers.RepeatedCompositeFieldContainer[TimeLimitedAccessStatus]
    teamAccessStatus: _containers.RepeatedCompositeFieldContainer[TimeLimitedAccessStatus]
    recordAccessStatus: _containers.RepeatedCompositeFieldContainer[TimeLimitedAccessStatus]
    def __init__(self, revision: _Optional[int] = ..., userAccessStatus: _Optional[_Iterable[_Union[TimeLimitedAccessStatus, _Mapping]]] = ..., teamAccessStatus: _Optional[_Iterable[_Union[TimeLimitedAccessStatus, _Mapping]]] = ..., recordAccessStatus: _Optional[_Iterable[_Union[TimeLimitedAccessStatus, _Mapping]]] = ...) -> None: ...
