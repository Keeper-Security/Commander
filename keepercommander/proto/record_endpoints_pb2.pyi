import record_pb2 as _record_pb2
import folder_pb2 as _folder_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RecordsAddRequest(_message.Message):
    __slots__ = ("records", "clientTime", "securityDataKeyType")
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    CLIENTTIME_FIELD_NUMBER: _ClassVar[int]
    SECURITYDATAKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[RecordAdd]
    clientTime: int
    securityDataKeyType: _record_pb2.RecordKeyType
    def __init__(self, records: _Optional[_Iterable[_Union[RecordAdd, _Mapping]]] = ..., clientTime: _Optional[int] = ..., securityDataKeyType: _Optional[_Union[_record_pb2.RecordKeyType, str]] = ...) -> None: ...

class RecordAdd(_message.Message):
    __slots__ = ("recordUid", "recordKey", "recordKeyType", "clientModifiedTime", "data", "nonSharedData", "folderUid", "folderKey", "recordLinks", "audit", "securityData", "securityScoreData")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    RECORDKEY_FIELD_NUMBER: _ClassVar[int]
    RECORDKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    CLIENTMODIFIEDTIME_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    NONSHAREDDATA_FIELD_NUMBER: _ClassVar[int]
    FOLDERUID_FIELD_NUMBER: _ClassVar[int]
    FOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    RECORDLINKS_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    SECURITYDATA_FIELD_NUMBER: _ClassVar[int]
    SECURITYSCOREDATA_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    recordKey: bytes
    recordKeyType: _folder_pb2.EncryptedKeyType
    clientModifiedTime: int
    data: bytes
    nonSharedData: bytes
    folderUid: bytes
    folderKey: bytes
    recordLinks: _containers.RepeatedCompositeFieldContainer[_record_pb2.RecordLink]
    audit: _record_pb2.RecordAudit
    securityData: _record_pb2.SecurityData
    securityScoreData: _record_pb2.SecurityScoreData
    def __init__(self, recordUid: _Optional[bytes] = ..., recordKey: _Optional[bytes] = ..., recordKeyType: _Optional[_Union[_folder_pb2.EncryptedKeyType, str]] = ..., clientModifiedTime: _Optional[int] = ..., data: _Optional[bytes] = ..., nonSharedData: _Optional[bytes] = ..., folderUid: _Optional[bytes] = ..., folderKey: _Optional[bytes] = ..., recordLinks: _Optional[_Iterable[_Union[_record_pb2.RecordLink, _Mapping]]] = ..., audit: _Optional[_Union[_record_pb2.RecordAudit, _Mapping]] = ..., securityData: _Optional[_Union[_record_pb2.SecurityData, _Mapping]] = ..., securityScoreData: _Optional[_Union[_record_pb2.SecurityScoreData, _Mapping]] = ...) -> None: ...
