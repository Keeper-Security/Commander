from google.api import annotations_pb2 as _annotations_pb2
import folder_pb2 as _folder_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MoveResultStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MOVE_RESULT_STATUS_UNSPECIFIED: _ClassVar[MoveResultStatus]
    MOVED: _ClassVar[MoveResultStatus]
    TARGET_ALREADY_PRESENT_SOURCE_REMOVED: _ClassVar[MoveResultStatus]
    SOURCE_NOT_FOUND: _ClassVar[MoveResultStatus]
    INVALID_MOVE: _ClassVar[MoveResultStatus]
    CYCLE_DETECTED: _ClassVar[MoveResultStatus]
MOVE_RESULT_STATUS_UNSPECIFIED: MoveResultStatus
MOVED: MoveResultStatus
TARGET_ALREADY_PRESENT_SOURCE_REMOVED: MoveResultStatus
SOURCE_NOT_FOUND: MoveResultStatus
INVALID_MOVE: MoveResultStatus
CYCLE_DETECTED: MoveResultStatus

class FolderRecordMoveRequest(_message.Message):
    __slots__ = ("moves",)
    MOVES_FIELD_NUMBER: _ClassVar[int]
    moves: _containers.RepeatedCompositeFieldContainer[FolderRecordMove]
    def __init__(self, moves: _Optional[_Iterable[_Union[FolderRecordMove, _Mapping]]] = ...) -> None: ...

class FolderRecordMove(_message.Message):
    __slots__ = ("source_folder_uid", "target_folder_uid", "record_uid", "encrypted_record_key")
    SOURCE_FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    TARGET_FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_RECORD_KEY_FIELD_NUMBER: _ClassVar[int]
    source_folder_uid: bytes
    target_folder_uid: bytes
    record_uid: bytes
    encrypted_record_key: bytes
    def __init__(self, source_folder_uid: _Optional[bytes] = ..., target_folder_uid: _Optional[bytes] = ..., record_uid: _Optional[bytes] = ..., encrypted_record_key: _Optional[bytes] = ...) -> None: ...

class FolderRecordMoveResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[FolderRecordMoveResult]
    def __init__(self, results: _Optional[_Iterable[_Union[FolderRecordMoveResult, _Mapping]]] = ...) -> None: ...

class FolderRecordMoveResult(_message.Message):
    __slots__ = ("source_folder_uid", "target_folder_uid", "record_uid", "status", "message", "move_result_status")
    SOURCE_FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    TARGET_FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MOVE_RESULT_STATUS_FIELD_NUMBER: _ClassVar[int]
    source_folder_uid: bytes
    target_folder_uid: bytes
    record_uid: bytes
    status: _folder_pb2.FolderModifyStatus
    message: str
    move_result_status: MoveResultStatus
    def __init__(self, source_folder_uid: _Optional[bytes] = ..., target_folder_uid: _Optional[bytes] = ..., record_uid: _Optional[bytes] = ..., status: _Optional[_Union[_folder_pb2.FolderModifyStatus, str]] = ..., message: _Optional[str] = ..., move_result_status: _Optional[_Union[MoveResultStatus, str]] = ...) -> None: ...

class FolderMoveRequest(_message.Message):
    __slots__ = ("moves",)
    MOVES_FIELD_NUMBER: _ClassVar[int]
    moves: _containers.RepeatedCompositeFieldContainer[FolderMove]
    def __init__(self, moves: _Optional[_Iterable[_Union[FolderMove, _Mapping]]] = ...) -> None: ...

class FolderMove(_message.Message):
    __slots__ = ("folder_uid", "target_parent_uid", "encrypted_folder_key")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    TARGET_PARENT_UID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    target_parent_uid: bytes
    encrypted_folder_key: bytes
    def __init__(self, folder_uid: _Optional[bytes] = ..., target_parent_uid: _Optional[bytes] = ..., encrypted_folder_key: _Optional[bytes] = ...) -> None: ...

class FolderMoveResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[FolderMoveResult]
    def __init__(self, results: _Optional[_Iterable[_Union[FolderMoveResult, _Mapping]]] = ...) -> None: ...

class FolderMoveResult(_message.Message):
    __slots__ = ("folder_uid", "target_parent_uid", "status", "message", "move_result_status")
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    TARGET_PARENT_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MOVE_RESULT_STATUS_FIELD_NUMBER: _ClassVar[int]
    folder_uid: bytes
    target_parent_uid: bytes
    status: _folder_pb2.FolderModifyStatus
    message: str
    move_result_status: MoveResultStatus
    def __init__(self, folder_uid: _Optional[bytes] = ..., target_parent_uid: _Optional[bytes] = ..., status: _Optional[_Union[_folder_pb2.FolderModifyStatus, str]] = ..., message: _Optional[str] = ..., move_result_status: _Optional[_Union[MoveResultStatus, str]] = ...) -> None: ...
