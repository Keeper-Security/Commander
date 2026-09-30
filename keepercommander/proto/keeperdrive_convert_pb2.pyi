from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ConvertRecordStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONVERT_RECORD_STATUS_UNSPECIFIED: _ClassVar[ConvertRecordStatus]
    OK: _ClassVar[ConvertRecordStatus]
    ENTERPRISE_NOT_KEEPER_DRIVE_ENABLED: _ClassVar[ConvertRecordStatus]
    NOT_RECORD_OWNER: _ClassVar[ConvertRecordStatus]
    RECORD_NOT_FOUND: _ClassVar[ConvertRecordStatus]
    RECORD_ALREADY_CONVERTED: _ClassVar[ConvertRecordStatus]
    FOLDER_ACCESS_DENIED: _ClassVar[ConvertRecordStatus]
    INVALID_FOLDER_KEY: _ClassVar[ConvertRecordStatus]
    INVALID_OWNER_KEY: _ClassVar[ConvertRecordStatus]
    RECORD_NOT_LEGACY: _ClassVar[ConvertRecordStatus]
    TARGET_NOT_DRIVE_FOLDER: _ClassVar[ConvertRecordStatus]
    RECORD_LINK_CHILD_NOT_OWNED: _ClassVar[ConvertRecordStatus]
    RECORD_LINK_PARENT_NOT_OWNED: _ClassVar[ConvertRecordStatus]
    RECORD_LINK_RECORD_IN_TRASH: _ClassVar[ConvertRecordStatus]
    INTERNAL_ERROR: _ClassVar[ConvertRecordStatus]
    RECORD_LINK_CHILD_NOT_INCLUDED: _ClassVar[ConvertRecordStatus]
    RECORD_LINK_FILE_PROMOTION_FAILED: _ClassVar[ConvertRecordStatus]
    RECORD_LINK_COMPONENT_FAILED: _ClassVar[ConvertRecordStatus]
    RECORD_VERSION_NOT_CONVERTIBLE: _ClassVar[ConvertRecordStatus]
CONVERT_RECORD_STATUS_UNSPECIFIED: ConvertRecordStatus
OK: ConvertRecordStatus
ENTERPRISE_NOT_KEEPER_DRIVE_ENABLED: ConvertRecordStatus
NOT_RECORD_OWNER: ConvertRecordStatus
RECORD_NOT_FOUND: ConvertRecordStatus
RECORD_ALREADY_CONVERTED: ConvertRecordStatus
FOLDER_ACCESS_DENIED: ConvertRecordStatus
INVALID_FOLDER_KEY: ConvertRecordStatus
INVALID_OWNER_KEY: ConvertRecordStatus
RECORD_NOT_LEGACY: ConvertRecordStatus
TARGET_NOT_DRIVE_FOLDER: ConvertRecordStatus
RECORD_LINK_CHILD_NOT_OWNED: ConvertRecordStatus
RECORD_LINK_PARENT_NOT_OWNED: ConvertRecordStatus
RECORD_LINK_RECORD_IN_TRASH: ConvertRecordStatus
INTERNAL_ERROR: ConvertRecordStatus
RECORD_LINK_CHILD_NOT_INCLUDED: ConvertRecordStatus
RECORD_LINK_FILE_PROMOTION_FAILED: ConvertRecordStatus
RECORD_LINK_COMPONENT_FAILED: ConvertRecordStatus
RECORD_VERSION_NOT_CONVERTIBLE: ConvertRecordStatus

class ConvertRecordRequest(_message.Message):
    __slots__ = ("records",)
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[ConvertRecord]
    def __init__(self, records: _Optional[_Iterable[_Union[ConvertRecord, _Mapping]]] = ...) -> None: ...

class ConvertRecord(_message.Message):
    __slots__ = ("record_uid", "folder_uid", "record_key_encrypted_by_folder_key", "record_key_encrypted_by_owner_key")
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_UID_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_ENCRYPTED_BY_FOLDER_KEY_FIELD_NUMBER: _ClassVar[int]
    RECORD_KEY_ENCRYPTED_BY_OWNER_KEY_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    folder_uid: bytes
    record_key_encrypted_by_folder_key: bytes
    record_key_encrypted_by_owner_key: bytes
    def __init__(self, record_uid: _Optional[bytes] = ..., folder_uid: _Optional[bytes] = ..., record_key_encrypted_by_folder_key: _Optional[bytes] = ..., record_key_encrypted_by_owner_key: _Optional[bytes] = ...) -> None: ...

class ConvertRecordResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[ConvertRecordResult]
    def __init__(self, results: _Optional[_Iterable[_Union[ConvertRecordResult, _Mapping]]] = ...) -> None: ...

class ConvertRecordResult(_message.Message):
    __slots__ = ("record_uid", "status")
    RECORD_UID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    record_uid: bytes
    status: ConvertRecordStatus
    def __init__(self, record_uid: _Optional[bytes] = ..., status: _Optional[_Union[ConvertRecordStatus, str]] = ...) -> None: ...
