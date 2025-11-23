from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class Page(_message.Message):
    __slots__ = ("pageNumber", "pageSize", "cursorToken")
    PAGENUMBER_FIELD_NUMBER: _ClassVar[int]
    PAGESIZE_FIELD_NUMBER: _ClassVar[int]
    CURSORTOKEN_FIELD_NUMBER: _ClassVar[int]
    pageNumber: int
    pageSize: int
    cursorToken: str
    def __init__(self, pageNumber: _Optional[int] = ..., pageSize: _Optional[int] = ..., cursorToken: _Optional[str] = ...) -> None: ...

class PageInfo(_message.Message):
    __slots__ = ("pageNumber", "pageSize", "totalCount", "hasMore", "cursorToken")
    PAGENUMBER_FIELD_NUMBER: _ClassVar[int]
    PAGESIZE_FIELD_NUMBER: _ClassVar[int]
    TOTALCOUNT_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    CURSORTOKEN_FIELD_NUMBER: _ClassVar[int]
    pageNumber: int
    pageSize: int
    totalCount: int
    hasMore: bool
    cursorToken: str
    def __init__(self, pageNumber: _Optional[int] = ..., pageSize: _Optional[int] = ..., totalCount: _Optional[int] = ..., hasMore: bool = ..., cursorToken: _Optional[str] = ...) -> None: ...
