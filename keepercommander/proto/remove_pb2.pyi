from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RemoveAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REMOVE_ACTION_PREVIEW: _ClassVar[RemoveAction]
    REMOVE_ACTION_CONFIRM: _ClassVar[RemoveAction]

class RecordOperationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECORD_OPERATION_UNKNOWN: _ClassVar[RecordOperationType]
    UNLINK_FROM_FOLDER: _ClassVar[RecordOperationType]
    MOVE_TO_FOLDER_TRASH: _ClassVar[RecordOperationType]
    MOVE_TO_OWNER_TRASH: _ClassVar[RecordOperationType]

class FolderOperationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FOLDER_OPERATION_UNKNOWN: _ClassVar[FolderOperationType]
    FOLDER_MOVE_TO_FOLDER_TRASH: _ClassVar[FolderOperationType]
    FOLDER_MOVE_TO_OWNER_TRASH: _ClassVar[FolderOperationType]
    FOLDER_DELETE_PERMANENT: _ClassVar[FolderOperationType]

class RemoveErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REMOVE_ERROR_UNKNOWN: _ClassVar[RemoveErrorCode]
    REMOVE_ERROR_NOT_FOUND: _ClassVar[RemoveErrorCode]
    REMOVE_ERROR_ACCESS_DENIED: _ClassVar[RemoveErrorCode]
    REMOVE_ERROR_TRASHCAN_FOLDER: _ClassVar[RemoveErrorCode]
    REMOVE_ERROR_ROOT_FOLDER: _ClassVar[RemoveErrorCode]
    REMOVE_ERROR_DESCENDANT_DENIED: _ClassVar[RemoveErrorCode]

class RemoveStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REMOVE_STATUS_UNKNOWN: _ClassVar[RemoveStatus]
    REMOVE_STATUS_SUCCESS: _ClassVar[RemoveStatus]
    REMOVE_STATUS_STALE_PREVIEW: _ClassVar[RemoveStatus]
    REMOVE_STATUS_TOKEN_EXPIRED: _ClassVar[RemoveStatus]
    REMOVE_STATUS_TOKEN_INVALID: _ClassVar[RemoveStatus]
    REMOVE_STATUS_ACCESS_DENIED: _ClassVar[RemoveStatus]
    REMOVE_STATUS_VALIDATION_ERROR: _ClassVar[RemoveStatus]

class RestoreStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESTORE_STATUS_UNKNOWN: _ClassVar[RestoreStatus]
    RS_SUCCESS: _ClassVar[RestoreStatus]
    RS_NOT_IN_TRASHCAN: _ClassVar[RestoreStatus]
    RS_ACCESS_DENIED: _ClassVar[RestoreStatus]
    RS_TARGET_FOLDER_NOT_FOUND: _ClassVar[RestoreStatus]
    RS_ALREADY_EXISTS_IN_TARGET: _ClassVar[RestoreStatus]
    RS_FAIL: _ClassVar[RestoreStatus]

class RestoreItemType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESTORE_ITEM_UNKNOWN: _ClassVar[RestoreItemType]
    RESTORE_ITEM_RECORD: _ClassVar[RestoreItemType]
    RESTORE_ITEM_FOLDER: _ClassVar[RestoreItemType]
REMOVE_ACTION_PREVIEW: RemoveAction
REMOVE_ACTION_CONFIRM: RemoveAction
RECORD_OPERATION_UNKNOWN: RecordOperationType
UNLINK_FROM_FOLDER: RecordOperationType
MOVE_TO_FOLDER_TRASH: RecordOperationType
MOVE_TO_OWNER_TRASH: RecordOperationType
FOLDER_OPERATION_UNKNOWN: FolderOperationType
FOLDER_MOVE_TO_FOLDER_TRASH: FolderOperationType
FOLDER_MOVE_TO_OWNER_TRASH: FolderOperationType
FOLDER_DELETE_PERMANENT: FolderOperationType
REMOVE_ERROR_UNKNOWN: RemoveErrorCode
REMOVE_ERROR_NOT_FOUND: RemoveErrorCode
REMOVE_ERROR_ACCESS_DENIED: RemoveErrorCode
REMOVE_ERROR_TRASHCAN_FOLDER: RemoveErrorCode
REMOVE_ERROR_ROOT_FOLDER: RemoveErrorCode
REMOVE_ERROR_DESCENDANT_DENIED: RemoveErrorCode
REMOVE_STATUS_UNKNOWN: RemoveStatus
REMOVE_STATUS_SUCCESS: RemoveStatus
REMOVE_STATUS_STALE_PREVIEW: RemoveStatus
REMOVE_STATUS_TOKEN_EXPIRED: RemoveStatus
REMOVE_STATUS_TOKEN_INVALID: RemoveStatus
REMOVE_STATUS_ACCESS_DENIED: RemoveStatus
REMOVE_STATUS_VALIDATION_ERROR: RemoveStatus
RESTORE_STATUS_UNKNOWN: RestoreStatus
RS_SUCCESS: RestoreStatus
RS_NOT_IN_TRASHCAN: RestoreStatus
RS_ACCESS_DENIED: RestoreStatus
RS_TARGET_FOLDER_NOT_FOUND: RestoreStatus
RS_ALREADY_EXISTS_IN_TARGET: RestoreStatus
RS_FAIL: RestoreStatus
RESTORE_ITEM_UNKNOWN: RestoreItemType
RESTORE_ITEM_RECORD: RestoreItemType
RESTORE_ITEM_FOLDER: RestoreItemType

class RecordRemoval(_message.Message):
    __slots__ = ("folder_uid", "record_uid", "operation_type")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    record_uid: bytes
    operation_type: RecordOperationType
    def __init__(self, folder_uid: _Optional[bytes] = ..., record_uid: _Optional[bytes] = ..., operation_type: _Optional[_Union[RecordOperationType, str]] = ...) -> None: ...

class FolderRemoval(_message.Message):
    __slots__ = ("folder_uid", "operation_type")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    operation_type: FolderOperationType
    def __init__(self, folder_uid: _Optional[bytes] = ..., operation_type: _Optional[_Union[FolderOperationType, str]] = ...) -> None: ...

class RemoveRecordRequest(_message.Message):
    __slots__ = ("action", "records", "confirmation_token")
    ACTION_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    action: RemoveAction
    records: _containers.RepeatedCompositeFieldContainer[RecordRemoval]
    confirmation_token: bytes
    def __init__(self, action: _Optional[_Union[RemoveAction, str]] = ..., records: _Optional[_Iterable[_Union[RecordRemoval, _Mapping]]] = ..., confirmation_token: _Optional[bytes] = ...) -> None: ...

class RemoveFolderRequest(_message.Message):
    __slots__ = ("action", "folders", "confirmation_token")
    ACTION_FIELD_NUMBER: _ClassVar[int]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    action: RemoveAction
    folders: _containers.RepeatedCompositeFieldContainer[FolderRemoval]
    confirmation_token: bytes
    def __init__(self, action: _Optional[_Union[RemoveAction, str]] = ..., folders: _Optional[_Iterable[_Union[FolderRemoval, _Mapping]]] = ..., confirmation_token: _Optional[bytes] = ...) -> None: ...

class RemoveResponse(_message.Message):
    __slots__ = ("confirmation_token", "token_expires_at", "results", "error_message")
    CONFIRMATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    TOKEN_EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    confirmation_token: bytes
    token_expires_at: int
    results: _containers.RepeatedCompositeFieldContainer[RemoveResult]
    error_message: str
    def __init__(self, confirmation_token: _Optional[bytes] = ..., token_expires_at: _Optional[int] = ..., results: _Optional[_Iterable[_Union[RemoveResult, _Mapping]]] = ..., error_message: _Optional[str] = ...) -> None: ...

class RemoveResult(_message.Message):
    __slots__ = ("item_uid", "folder_uid", "status", "impact", "error")
    ITEM_UID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    IMPACT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    item_uid: bytes
    folder_uid: bytes
    status: RemoveStatus
    impact: Impact
    error: ItemError
    def __init__(self, item_uid: _Optional[bytes] = ..., folder_uid: _Optional[bytes] = ..., status: _Optional[_Union[RemoveStatus, str]] = ..., impact: _Optional[_Union[Impact, _Mapping]] = ..., error: _Optional[_Union[ItemError, _Mapping]] = ...) -> None: ...

class Impact(_message.Message):
    __slots__ = ("folders_count", "records_count", "affected_users_count", "affected_teams_count", "record_info", "warnings")
    FOLDERS_COUNT_FIELD_NUMBER: _ClassVar[int]
    RECORDS_COUNT_FIELD_NUMBER: _ClassVar[int]
    AFFECTED_USERS_COUNT_FIELD_NUMBER: _ClassVar[int]
    AFFECTED_TEAMS_COUNT_FIELD_NUMBER: _ClassVar[int]
    RECORD_INFO_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    folders_count: int
    records_count: int
    affected_users_count: int
    affected_teams_count: int
    record_info: _containers.RepeatedCompositeFieldContainer[RecordInfo]
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, folders_count: _Optional[int] = ..., records_count: _Optional[int] = ..., affected_users_count: _Optional[int] = ..., affected_teams_count: _Optional[int] = ..., record_info: _Optional[_Iterable[_Union[RecordInfo, _Mapping]]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class RecordInfo(_message.Message):
    __slots__ = ("record_uid", "locations_count")
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    LOCATIONS_COUNT_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    locations_count: int
    def __init__(self, record_uid: _Optional[bytes] = ..., locations_count: _Optional[int] = ...) -> None: ...

class ItemError(_message.Message):
    __slots__ = ("code", "message")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    code: RemoveErrorCode
    message: str
    def __init__(self, code: _Optional[_Union[RemoveErrorCode, str]] = ..., message: _Optional[str] = ...) -> None: ...

class RemovalTokenPayload(_message.Message):
    __slots__ = ("item_fingerprints", "user_id", "device_id", "session_uid", "expires_at_millis")
    ITEM_FINGERPRINTS_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_UID_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MILLIS_FIELD_NUMBER: _ClassVar[int]
    item_fingerprints: _containers.RepeatedCompositeFieldContainer[ItemFingerprint]
    user_id: int
    device_id: int
    session_uid: bytes
    expires_at_millis: int
    def __init__(self, item_fingerprints: _Optional[_Iterable[_Union[ItemFingerprint, _Mapping]]] = ..., user_id: _Optional[int] = ..., device_id: _Optional[int] = ..., session_uid: _Optional[bytes] = ..., expires_at_millis: _Optional[int] = ...) -> None: ...

class ItemFingerprint(_message.Message):
    __slots__ = ("record", "folder", "fingerprint")
    RECORD_FIELD_NUMBER: _ClassVar[int]
    FOLDER_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    record: RecordTarget
    folder: FolderTarget
    fingerprint: bytes
    def __init__(self, record: _Optional[_Union[RecordTarget, _Mapping]] = ..., folder: _Optional[_Union[FolderTarget, _Mapping]] = ..., fingerprint: _Optional[bytes] = ...) -> None: ...

class RecordTarget(_message.Message):
    __slots__ = ("folder_uid", "record_uid", "operation_type")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    record_uid: bytes
    operation_type: RecordOperationType
    def __init__(self, folder_uid: _Optional[bytes] = ..., record_uid: _Optional[bytes] = ..., operation_type: _Optional[_Union[RecordOperationType, str]] = ...) -> None: ...

class FolderTarget(_message.Message):
    __slots__ = ("folder_uid", "operation_type")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    operation_type: FolderOperationType
    def __init__(self, folder_uid: _Optional[bytes] = ..., operation_type: _Optional[_Union[FolderOperationType, str]] = ...) -> None: ...

class RestoreResult(_message.Message):
    __slots__ = ("item_uid", "item_type", "status", "error_message")
    ITEM_UID_FIELD_NUMBER: _ClassVar[int]
    ITEM_TYPE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    item_uid: bytes
    item_type: RestoreItemType
    status: RestoreStatus
    error_message: str
    def __init__(self, item_uid: _Optional[bytes] = ..., item_type: _Optional[_Union[RestoreItemType, str]] = ..., status: _Optional[_Union[RestoreStatus, str]] = ..., error_message: _Optional[str] = ...) -> None: ...

class TrashcanRestoreResponse(_message.Message):
    __slots__ = ("results", "error_message")
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[RestoreResult]
    error_message: str
    def __init__(self, results: _Optional[_Iterable[_Union[RestoreResult, _Mapping]]] = ..., error_message: _Optional[str] = ...) -> None: ...

class RestoreRecord(_message.Message):
    __slots__ = ("record_uid", "encrypted_record_key", "source_folder_uid")
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    encrypted_record_key: bytes
    source_folder_uid: bytes
    def __init__(self, record_uid: _Optional[bytes] = ..., encrypted_record_key: _Optional[bytes] = ..., source_folder_uid: _Optional[bytes] = ...) -> None: ...

class RestoreFolder(_message.Message):
    __slots__ = ("folder_uid", "encrypted_folder_key")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    encrypted_folder_key: bytes
    def __init__(self, folder_uid: _Optional[bytes] = ..., encrypted_folder_key: _Optional[bytes] = ...) -> None: ...

class TrashcanRestoreRequest(_message.Message):
    __slots__ = ("records", "folders", "target_folder_uid")
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    TARGET_FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RestoreRecord]
    folders: _containers.RepeatedCompositeFieldContainer[RestoreFolder]
    target_folder_uid: bytes
    def __init__(self, records: _Optional[_Iterable[_Union[RestoreRecord, _Mapping]]] = ..., folders: _Optional[_Iterable[_Union[RestoreFolder, _Mapping]]] = ..., target_folder_uid: _Optional[bytes] = ...) -> None: ...
