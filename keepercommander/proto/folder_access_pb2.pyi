import folder_pb2 as _folder_pb2
from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetFolderAccessRequest(_message.Message):
    __slots__ = ("folderUid", "continuationToken", "pageSize")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    PAGESIZE_FIELD_NUMBER: _ClassVar[int]
    folderUid: _containers.RepeatedScalarFieldContainer[bytes]
    continuationToken: ContinuationToken
    pageSize: int
    def __init__(self, folderUid: _Optional[_Iterable[bytes]] = ..., continuationToken: _Optional[_Union[ContinuationToken, _Mapping]] = ..., pageSize: _Optional[int] = ...) -> None: ...

class GetFolderAccessResponse(_message.Message):
    __slots__ = ("folderAccessResults", "continuationToken", "hasMore")
    FOLDERACCESSRESULTS_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    folderAccessResults: _containers.RepeatedCompositeFieldContainer[GetFolderAccessResult]
    continuationToken: ContinuationToken
    hasMore: bool
    def __init__(self, folderAccessResults: _Optional[_Iterable[_Union[GetFolderAccessResult, _Mapping]]] = ..., continuationToken: _Optional[_Union[ContinuationToken, _Mapping]] = ..., hasMore: bool = ...) -> None: ...

class ContinuationToken(_message.Message):
    __slots__ = ("lastModified",)
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    lastModified: int
    def __init__(self, lastModified: _Optional[int] = ...) -> None: ...

class GetFolderAccessResult(_message.Message):
    __slots__ = ("folderUid", "accessors", "error")
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ACCESSORS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    folderUid: bytes
    accessors: _containers.RepeatedCompositeFieldContainer[_folder_pb2.FolderAccessData]
    error: FolderAccessError
    def __init__(self, folderUid: _Optional[bytes] = ..., accessors: _Optional[_Iterable[_Union[_folder_pb2.FolderAccessData, _Mapping]]] = ..., error: _Optional[_Union[FolderAccessError, _Mapping]] = ...) -> None: ...

class FolderAccessError(_message.Message):
    __slots__ = ("status", "message")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    status: _folder_pb2.FolderModifyStatus
    message: str
    def __init__(self, status: _Optional[_Union[_folder_pb2.FolderModifyStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...
