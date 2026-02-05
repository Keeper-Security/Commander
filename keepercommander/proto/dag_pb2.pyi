from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RefType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GENERAL: _ClassVar[RefType]
    USER: _ClassVar[RefType]
    DEVICE: _ClassVar[RefType]
    REC: _ClassVar[RefType]
    FOLDER: _ClassVar[RefType]
    TEAM: _ClassVar[RefType]
    ENTERPRISE: _ClassVar[RefType]
    PAM_DIRECTORY: _ClassVar[RefType]
    PAM_MACHINE: _ClassVar[RefType]
    PAM_USER: _ClassVar[RefType]

class DataType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DATA: _ClassVar[DataType]
    KEY: _ClassVar[DataType]
    LINK: _ClassVar[DataType]
    ACL: _ClassVar[DataType]
    DELETION: _ClassVar[DataType]
    DENIAL: _ClassVar[DataType]
    UNDENIAL: _ClassVar[DataType]
GENERAL: RefType
USER: RefType
DEVICE: RefType
REC: RefType
FOLDER: RefType
TEAM: RefType
ENTERPRISE: RefType
PAM_DIRECTORY: RefType
PAM_MACHINE: RefType
PAM_USER: RefType
DATA: DataType
KEY: DataType
LINK: DataType
ACL: DataType
DELETION: DataType
DENIAL: DataType
UNDENIAL: DataType

class Ref(_message.Message):
    __slots__ = ("type", "value", "name")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    type: RefType
    value: bytes
    name: str
    def __init__(self, type: _Optional[_Union[RefType, str]] = ..., value: _Optional[bytes] = ..., name: _Optional[str] = ...) -> None: ...

class Data(_message.Message):
    __slots__ = ("dataType", "ref", "parentRef", "content", "path")
    DATATYPE_FIELD_NUMBER: _ClassVar[int]
    REF_FIELD_NUMBER: _ClassVar[int]
    PARENTREF_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    dataType: DataType
    ref: Ref
    parentRef: Ref
    content: bytes
    path: str
    def __init__(self, dataType: _Optional[_Union[DataType, str]] = ..., ref: _Optional[_Union[Ref, _Mapping]] = ..., parentRef: _Optional[_Union[Ref, _Mapping]] = ..., content: _Optional[bytes] = ..., path: _Optional[str] = ...) -> None: ...

class SyncData(_message.Message):
    __slots__ = ("data", "syncPoint", "hasMore")
    DATA_FIELD_NUMBER: _ClassVar[int]
    SYNCPOINT_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedCompositeFieldContainer[Data]
    syncPoint: int
    hasMore: bool
    def __init__(self, data: _Optional[_Iterable[_Union[Data, _Mapping]]] = ..., syncPoint: _Optional[int] = ..., hasMore: _Optional[bool] = ...) -> None: ...

class DebugData(_message.Message):
    __slots__ = ("dataType", "path", "ref", "parentRef")
    DATATYPE_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    REF_FIELD_NUMBER: _ClassVar[int]
    PARENTREF_FIELD_NUMBER: _ClassVar[int]
    dataType: str
    path: str
    ref: DebugRefInfo
    parentRef: DebugRefInfo
    def __init__(self, dataType: _Optional[str] = ..., path: _Optional[str] = ..., ref: _Optional[_Union[DebugRefInfo, _Mapping]] = ..., parentRef: _Optional[_Union[DebugRefInfo, _Mapping]] = ...) -> None: ...

class DebugRefInfo(_message.Message):
    __slots__ = ("refType", "value")
    REFTYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    refType: str
    value: bytes
    def __init__(self, refType: _Optional[str] = ..., value: _Optional[bytes] = ...) -> None: ...
