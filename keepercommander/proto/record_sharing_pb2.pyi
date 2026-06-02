import folder_pb2 as _folder_pb2
import tla_pb2 as _tla_pb2
from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SharingStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SUCCESS: _ClassVar[SharingStatus]
    PENDING_ACCEPT: _ClassVar[SharingStatus]
    USER_NOT_FOUND: _ClassVar[SharingStatus]
    ALREADY_SHARED: _ClassVar[SharingStatus]
    NOT_ALLOWED_TO_SHARE: _ClassVar[SharingStatus]
    ACCESS_DENIED: _ClassVar[SharingStatus]
    NOT_ALLOWED_TO_SET_PERMISSIONS: _ClassVar[SharingStatus]
SUCCESS: SharingStatus
PENDING_ACCEPT: SharingStatus
USER_NOT_FOUND: SharingStatus
ALREADY_SHARED: SharingStatus
NOT_ALLOWED_TO_SHARE: SharingStatus
ACCESS_DENIED: SharingStatus
NOT_ALLOWED_TO_SET_PERMISSIONS: SharingStatus

class Request(_message.Message):
    __slots__ = ("createSharingPermissions", "updateSharingPermissions", "revokeSharingPermissions", "echo")
    CREATESHARINGPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    UPDATESHARINGPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    REVOKESHARINGPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    ECHO_FIELD_NUMBER: _ClassVar[int]
    createSharingPermissions: _containers.RepeatedCompositeFieldContainer[Permissions]
    updateSharingPermissions: _containers.RepeatedCompositeFieldContainer[Permissions]
    revokeSharingPermissions: _containers.RepeatedCompositeFieldContainer[Permissions]
    echo: str
    def __init__(self, createSharingPermissions: _Optional[_Iterable[_Union[Permissions, _Mapping]]] = ..., updateSharingPermissions: _Optional[_Iterable[_Union[Permissions, _Mapping]]] = ..., revokeSharingPermissions: _Optional[_Iterable[_Union[Permissions, _Mapping]]] = ..., echo: _Optional[str] = ...) -> None: ...

class Permissions(_message.Message):
    __slots__ = ("recipientUid", "recordUid", "recordKey", "useEccKey", "rules")
    RECIPIENTUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    USEECCKEY_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    recipientUid: bytes
    recordUid: bytes
    recordKey: bytes
    useEccKey: bool
    rules: _folder_pb2.RecordAccessData
    def __init__(self, recipientUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., useEccKey: bool = ..., rules: _Optional[_Union[_folder_pb2.RecordAccessData, _Mapping]] = ...) -> None: ...

class Response(_message.Message):
    __slots__ = ("createdSharingStatus", "updatedSharingStatus", "revokedSharingStatus")
    CREATEDSHARINGSTATUS_FIELD_NUMBER: _ClassVar[int]
    UPDATEDSHARINGSTATUS_FIELD_NUMBER: _ClassVar[int]
    REVOKEDSHARINGSTATUS_FIELD_NUMBER: _ClassVar[int]
    createdSharingStatus: _containers.RepeatedCompositeFieldContainer[Status]
    updatedSharingStatus: _containers.RepeatedCompositeFieldContainer[Status]
    revokedSharingStatus: _containers.RepeatedCompositeFieldContainer[Status]
    def __init__(self, createdSharingStatus: _Optional[_Iterable[_Union[Status, _Mapping]]] = ..., updatedSharingStatus: _Optional[_Iterable[_Union[Status, _Mapping]]] = ..., revokedSharingStatus: _Optional[_Iterable[_Union[Status, _Mapping]]] = ...) -> None: ...

class Status(_message.Message):
    __slots__ = ("recordUid", "status", "message", "recipientUid")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTUID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    status: SharingStatus
    message: str
    recipientUid: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., status: _Optional[_Union[SharingStatus, str]] = ..., message: _Optional[str] = ..., recipientUid: _Optional[bytes] = ...) -> None: ...

class RevokedAccess(_message.Message):
    __slots__ = ("recordUid", "actorUid")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ACTORUID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    actorUid: bytes
    def __init__(self, recordUid: _Optional[bytes] = ..., actorUid: _Optional[bytes] = ...) -> None: ...

class RecordSharingState(_message.Message):
    __slots__ = ("recordUid", "isDirectlyShared", "isIndirectlyShared", "isShared")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ISDIRECTLYSHARED_FIELD_NUMBER: _ClassVar[int]
    ISINDIRECTLYSHARED_FIELD_NUMBER: _ClassVar[int]
    ISSHARED_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    isDirectlyShared: bool
    isIndirectlyShared: bool
    isShared: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., isDirectlyShared: bool = ..., isIndirectlyShared: bool = ..., isShared: bool = ...) -> None: ...
