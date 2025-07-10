from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RefType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RFT_GENERAL: _ClassVar[RefType]
    RFT_USER: _ClassVar[RefType]
    RFT_DEVICE: _ClassVar[RefType]
    RFT_REC: _ClassVar[RefType]
    RFT_FOLDER: _ClassVar[RefType]
    RFT_TEAM: _ClassVar[RefType]
    RFT_ENTERPRISE: _ClassVar[RefType]
    RFT_PAM_DIRECTORY: _ClassVar[RefType]
    RFT_PAM_MACHINE: _ClassVar[RefType]
    RFT_PAM_DATABASE: _ClassVar[RefType]
    RFT_PAM_USER: _ClassVar[RefType]
    RFT_PAM_NETWORK: _ClassVar[RefType]
    RFT_PAM_BROWSER: _ClassVar[RefType]
    RFT_CONNECTION: _ClassVar[RefType]
    RFT_WORKFLOW: _ClassVar[RefType]
    RFT_NOTIFICATION: _ClassVar[RefType]
    RFT_USER_INFO: _ClassVar[RefType]
    RFT_TEAM_INFO: _ClassVar[RefType]
    RFT_ROLE: _ClassVar[RefType]

class GraphSyncDataType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    GSE_DATA: _ClassVar[GraphSyncDataType]
    GSE_KEY: _ClassVar[GraphSyncDataType]
    GSE_LINK: _ClassVar[GraphSyncDataType]
    GSE_ACL: _ClassVar[GraphSyncDataType]
    GSE_DELETION: _ClassVar[GraphSyncDataType]

class GraphSyncActorType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    GSA_USER: _ClassVar[GraphSyncActorType]
    GSA_SERVICE: _ClassVar[GraphSyncActorType]
    GSA_PAM_GATEWAY: _ClassVar[GraphSyncActorType]
RFT_GENERAL: RefType
RFT_USER: RefType
RFT_DEVICE: RefType
RFT_REC: RefType
RFT_FOLDER: RefType
RFT_TEAM: RefType
RFT_ENTERPRISE: RefType
RFT_PAM_DIRECTORY: RefType
RFT_PAM_MACHINE: RefType
RFT_PAM_DATABASE: RefType
RFT_PAM_USER: RefType
RFT_PAM_NETWORK: RefType
RFT_PAM_BROWSER: RefType
RFT_CONNECTION: RefType
RFT_WORKFLOW: RefType
RFT_NOTIFICATION: RefType
RFT_USER_INFO: RefType
RFT_TEAM_INFO: RefType
RFT_ROLE: RefType
GSE_DATA: GraphSyncDataType
GSE_KEY: GraphSyncDataType
GSE_LINK: GraphSyncDataType
GSE_ACL: GraphSyncDataType
GSE_DELETION: GraphSyncDataType
GSA_USER: GraphSyncActorType
GSA_SERVICE: GraphSyncActorType
GSA_PAM_GATEWAY: GraphSyncActorType

class GraphSyncRef(_message.Message):
    __slots__ = ["type", "value", "name"]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    type: RefType
    value: bytes
    name: str
    def __init__(self, type: _Optional[_Union[RefType, str]] = ..., value: _Optional[bytes] = ..., name: _Optional[str] = ...) -> None: ...

class GraphSyncActor(_message.Message):
    __slots__ = ["type", "id", "name", "effectiveUserId"]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    EFFECTIVEUSERID_FIELD_NUMBER: _ClassVar[int]
    type: GraphSyncActorType
    id: bytes
    name: str
    effectiveUserId: bytes
    def __init__(self, type: _Optional[_Union[GraphSyncActorType, str]] = ..., id: _Optional[bytes] = ..., name: _Optional[str] = ..., effectiveUserId: _Optional[bytes] = ...) -> None: ...

class GraphSyncData(_message.Message):
    __slots__ = ["type", "ref", "parentRef", "content", "path"]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REF_FIELD_NUMBER: _ClassVar[int]
    PARENTREF_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    type: GraphSyncDataType
    ref: GraphSyncRef
    parentRef: GraphSyncRef
    content: bytes
    path: str
    def __init__(self, type: _Optional[_Union[GraphSyncDataType, str]] = ..., ref: _Optional[_Union[GraphSyncRef, _Mapping]] = ..., parentRef: _Optional[_Union[GraphSyncRef, _Mapping]] = ..., content: _Optional[bytes] = ..., path: _Optional[str] = ...) -> None: ...

class GraphSyncDataPlus(_message.Message):
    __slots__ = ["data", "timestamp", "actor"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    data: GraphSyncData
    timestamp: int
    actor: GraphSyncActor
    def __init__(self, data: _Optional[_Union[GraphSyncData, _Mapping]] = ..., timestamp: _Optional[int] = ..., actor: _Optional[_Union[GraphSyncActor, _Mapping]] = ...) -> None: ...

class GraphSyncQuery(_message.Message):
    __slots__ = ["streamId", "origin", "syncPoint", "maxCount"]
    STREAMID_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    SYNCPOINT_FIELD_NUMBER: _ClassVar[int]
    MAXCOUNT_FIELD_NUMBER: _ClassVar[int]
    streamId: bytes
    origin: bytes
    syncPoint: int
    maxCount: int
    def __init__(self, streamId: _Optional[bytes] = ..., origin: _Optional[bytes] = ..., syncPoint: _Optional[int] = ..., maxCount: _Optional[int] = ...) -> None: ...

class GraphSyncResult(_message.Message):
    __slots__ = ["streamId", "syncPoint", "data", "hasMore"]
    STREAMID_FIELD_NUMBER: _ClassVar[int]
    SYNCPOINT_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    streamId: bytes
    syncPoint: int
    data: _containers.RepeatedCompositeFieldContainer[GraphSyncDataPlus]
    hasMore: bool
    def __init__(self, streamId: _Optional[bytes] = ..., syncPoint: _Optional[int] = ..., data: _Optional[_Iterable[_Union[GraphSyncDataPlus, _Mapping]]] = ..., hasMore: bool = ...) -> None: ...

class GraphSyncMultiQuery(_message.Message):
    __slots__ = ["queries"]
    QUERIES_FIELD_NUMBER: _ClassVar[int]
    queries: _containers.RepeatedCompositeFieldContainer[GraphSyncQuery]
    def __init__(self, queries: _Optional[_Iterable[_Union[GraphSyncQuery, _Mapping]]] = ...) -> None: ...

class GraphSyncMultiResult(_message.Message):
    __slots__ = ["results"]
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[GraphSyncResult]
    def __init__(self, results: _Optional[_Iterable[_Union[GraphSyncResult, _Mapping]]] = ...) -> None: ...

class GraphSyncAddDataRequest(_message.Message):
    __slots__ = ["origin", "data"]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    origin: GraphSyncRef
    data: _containers.RepeatedCompositeFieldContainer[GraphSyncData]
    def __init__(self, origin: _Optional[_Union[GraphSyncRef, _Mapping]] = ..., data: _Optional[_Iterable[_Union[GraphSyncData, _Mapping]]] = ...) -> None: ...

class GraphSyncLeafsQuery(_message.Message):
    __slots__ = ["vertices"]
    VERTICES_FIELD_NUMBER: _ClassVar[int]
    vertices: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, vertices: _Optional[_Iterable[bytes]] = ...) -> None: ...

class GraphSyncRefsResult(_message.Message):
    __slots__ = ["refs"]
    REFS_FIELD_NUMBER: _ClassVar[int]
    refs: _containers.RepeatedCompositeFieldContainer[GraphSyncRef]
    def __init__(self, refs: _Optional[_Iterable[_Union[GraphSyncRef, _Mapping]]] = ...) -> None: ...
