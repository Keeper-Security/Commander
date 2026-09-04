import record_pb2 as _record_pb2
from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TrashcanContinuationToken(_message.Message):
    __slots__ = ("sync_point", "syncedToSyncOrder")
    SYNC_POINT_FIELD_NUMBER: _ClassVar[int]
    SYNCEDTOSYNCORDER_FIELD_NUMBER: _ClassVar[int]
    sync_point: int
    syncedToSyncOrder: int
    def __init__(self, sync_point: _Optional[int] = ..., syncedToSyncOrder: _Optional[int] = ...) -> None: ...

class TrashcanSyncRequest(_message.Message):
    __slots__ = ("sync_point", "max_count", "continuationToken")
    SYNC_POINT_FIELD_NUMBER: _ClassVar[int]
    MAX_COUNT_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    sync_point: int
    max_count: int
    continuationToken: bytes
    def __init__(self, sync_point: _Optional[int] = ..., max_count: _Optional[int] = ..., continuationToken: _Optional[bytes] = ...) -> None: ...

class TrashcanSyncResponse(_message.Message):
    __slots__ = ("trashcan_data", "sync_point", "has_more", "continuationToken")
    TRASHCAN_DATA_FIELD_NUMBER: _ClassVar[int]
    SYNC_POINT_FIELD_NUMBER: _ClassVar[int]
    HAS_MORE_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    trashcan_data: TrashcanSyncData
    sync_point: int
    has_more: bool
    continuationToken: bytes
    def __init__(self, trashcan_data: _Optional[_Union[TrashcanSyncData, _Mapping]] = ..., sync_point: _Optional[int] = ..., has_more: _Optional[bool] = ..., continuationToken: _Optional[bytes] = ...) -> None: ...

class TrashcanSyncData(_message.Message):
    __slots__ = ("trashcan_records", "trashcan_folders", "removed_trashcan_records", "removed_trashcan_folders")
    TRASHCAN_RECORDS_FIELD_NUMBER: _ClassVar[int]
    TRASHCAN_FOLDERS_FIELD_NUMBER: _ClassVar[int]
    REMOVED_TRASHCAN_RECORDS_FIELD_NUMBER: _ClassVar[int]
    REMOVED_TRASHCAN_FOLDERS_FIELD_NUMBER: _ClassVar[int]
    trashcan_records: _containers.RepeatedCompositeFieldContainer[TrashcanRecord]
    trashcan_folders: _containers.RepeatedCompositeFieldContainer[TrashcanFolder]
    removed_trashcan_records: _containers.RepeatedCompositeFieldContainer[TrashcanRecord]
    removed_trashcan_folders: _containers.RepeatedCompositeFieldContainer[TrashcanFolder]
    def __init__(self, trashcan_records: _Optional[_Iterable[_Union[TrashcanRecord, _Mapping]]] = ..., trashcan_folders: _Optional[_Iterable[_Union[TrashcanFolder, _Mapping]]] = ..., removed_trashcan_records: _Optional[_Iterable[_Union[TrashcanRecord, _Mapping]]] = ..., removed_trashcan_folders: _Optional[_Iterable[_Union[TrashcanFolder, _Mapping]]] = ...) -> None: ...

class TrashcanRecord(_message.Message):
    __slots__ = ("record_uid", "trashcan_uid", "folder_record_key", "date_deleted")
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    TRASHCAN_UID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    DATE_DELETED_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    trashcan_uid: bytes
    folder_record_key: _record_pb2.FolderRecordKey
    date_deleted: int
    def __init__(self, record_uid: _Optional[bytes] = ..., trashcan_uid: _Optional[bytes] = ..., folder_record_key: _Optional[_Union[_record_pb2.FolderRecordKey, _Mapping]] = ..., date_deleted: _Optional[int] = ...) -> None: ...

class TrashcanFolder(_message.Message):
    __slots__ = ("folder_uid", "trashcan_uid", "folder_key", "folder_key_type", "date_deleted", "parent_uid")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    TRASHCAN_UID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    FOLDER_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    DATE_DELETED_FIELD_NUMBER: _ClassVar[int]
    PARENT_UID_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    trashcan_uid: bytes
    folder_key: bytes
    folder_key_type: _record_pb2.RecordKeyType
    date_deleted: int
    parent_uid: bytes
    def __init__(self, folder_uid: _Optional[bytes] = ..., trashcan_uid: _Optional[bytes] = ..., folder_key: _Optional[bytes] = ..., folder_key_type: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ..., date_deleted: _Optional[int] = ..., parent_uid: _Optional[bytes] = ...) -> None: ...
