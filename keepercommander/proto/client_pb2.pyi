from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class BreachWatchInfoType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RECORD: _ClassVar[BreachWatchInfoType]
    ALTERNATE_PASSWORD: _ClassVar[BreachWatchInfoType]

class BWStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    GOOD: _ClassVar[BWStatus]
    CHANGED: _ClassVar[BWStatus]
    WEAK: _ClassVar[BWStatus]
    BREACHED: _ClassVar[BWStatus]
    IGNORE: _ClassVar[BWStatus]
RECORD: BreachWatchInfoType
ALTERNATE_PASSWORD: BreachWatchInfoType
GOOD: BWStatus
CHANGED: BWStatus
WEAK: BWStatus
BREACHED: BWStatus
IGNORE: BWStatus

class BreachWatchUpdateRequest(_message.Message):
    __slots__ = ["breachWatchRecordRequest", "encryptedData"]
    BREACHWATCHRECORDREQUEST_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    breachWatchRecordRequest: _containers.RepeatedCompositeFieldContainer[BreachWatchRecordRequest]
    encryptedData: bytes
    def __init__(self, breachWatchRecordRequest: _Optional[_Iterable[_Union[BreachWatchRecordRequest, _Mapping]]] = ..., encryptedData: _Optional[bytes] = ...) -> None: ...

class BreachWatchRecordRequest(_message.Message):
    __slots__ = ["recordUid", "encryptedData", "breachWatchInfoType", "updateUserWhoScanned"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCHINFOTYPE_FIELD_NUMBER: _ClassVar[int]
    UPDATEUSERWHOSCANNED_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    encryptedData: bytes
    breachWatchInfoType: BreachWatchInfoType
    updateUserWhoScanned: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., breachWatchInfoType: _Optional[_Union[BreachWatchInfoType, str]] = ..., updateUserWhoScanned: bool = ...) -> None: ...

class BreachWatchData(_message.Message):
    __slots__ = ["passwords", "emails", "domains"]
    PASSWORDS_FIELD_NUMBER: _ClassVar[int]
    EMAILS_FIELD_NUMBER: _ClassVar[int]
    DOMAINS_FIELD_NUMBER: _ClassVar[int]
    passwords: _containers.RepeatedCompositeFieldContainer[BWPassword]
    emails: _containers.RepeatedCompositeFieldContainer[BWPassword]
    domains: _containers.RepeatedCompositeFieldContainer[BWPassword]
    def __init__(self, passwords: _Optional[_Iterable[_Union[BWPassword, _Mapping]]] = ..., emails: _Optional[_Iterable[_Union[BWPassword, _Mapping]]] = ..., domains: _Optional[_Iterable[_Union[BWPassword, _Mapping]]] = ...) -> None: ...

class BWPassword(_message.Message):
    __slots__ = ["value", "resolved", "status", "euid"]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EUID_FIELD_NUMBER: _ClassVar[int]
    value: str
    resolved: int
    status: BWStatus
    euid: bytes
    def __init__(self, value: _Optional[str] = ..., resolved: _Optional[int] = ..., status: _Optional[_Union[BWStatus, str]] = ..., euid: _Optional[bytes] = ...) -> None: ...
