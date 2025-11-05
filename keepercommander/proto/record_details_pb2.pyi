from google.api import annotations_pb2 as _annotations_pb2
import folder_pb2 as _folder_pb2
import record_pb2 as _record_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RecordDataRequest(_message.Message):
    __slots__ = ("clientTime", "recordUids")
    CLIENTTIME_FIELD_NUMBER: _ClassVar[int]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    clientTime: int
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, clientTime: _Optional[int] = ..., recordUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RecordDataResponse(_message.Message):
    __slots__ = ("data", "forbiddenRecords")
    DATA_FIELD_NUMBER: _ClassVar[int]
    FORBIDDENRECORDS_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedCompositeFieldContainer[_record_pb2.RecordData]
    forbiddenRecords: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, data: _Optional[_Iterable[_Union[_record_pb2.RecordData, _Mapping]]] = ..., forbiddenRecords: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RecordAccessRequest(_message.Message):
    __slots__ = ("recordUids",)
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, recordUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RecordAccessResponse(_message.Message):
    __slots__ = ("recordAccesses", "forbiddenRecords")
    RECORDACCESSES_FIELD_NUMBER: _ClassVar[int]
    FORBIDDENRECORDS_FIELD_NUMBER: _ClassVar[int]
    recordAccesses: _containers.RepeatedCompositeFieldContainer[RecordAccess]
    forbiddenRecords: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, recordAccesses: _Optional[_Iterable[_Union[RecordAccess, _Mapping]]] = ..., forbiddenRecords: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RecordAccess(_message.Message):
    __slots__ = ("data", "accessorInfo")
    DATA_FIELD_NUMBER: _ClassVar[int]
    ACCESSORINFO_FIELD_NUMBER: _ClassVar[int]
    data: _folder_pb2.RecordAccessData
    accessorInfo: AccessorInfo
    def __init__(self, data: _Optional[_Union[_folder_pb2.RecordAccessData, _Mapping]] = ..., accessorInfo: _Optional[_Union[AccessorInfo, _Mapping]] = ...) -> None: ...

class AccessorInfo(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...
