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
RECORD: BreachWatchInfoType
ALTERNATE_PASSWORD: BreachWatchInfoType

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

class BreachWatchUpdateRequest(_message.Message):
    __slots__ = ["breachWatchRecordRequest", "encryptedData"]
    BREACHWATCHRECORDREQUEST_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    breachWatchRecordRequest: _containers.RepeatedCompositeFieldContainer[BreachWatchRecordRequest]
    encryptedData: bytes
    def __init__(self, breachWatchRecordRequest: _Optional[_Iterable[_Union[BreachWatchRecordRequest, _Mapping]]] = ..., encryptedData: _Optional[bytes] = ...) -> None: ...

class BreachWatchRecordStatus(_message.Message):
    __slots__ = ["recordUid", "status", "reason"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    status: str
    reason: str
    def __init__(self, recordUid: _Optional[bytes] = ..., status: _Optional[str] = ..., reason: _Optional[str] = ...) -> None: ...

class BreachWatchUpdateResponse(_message.Message):
    __slots__ = ["breachWatchRecordStatus"]
    BREACHWATCHRECORDSTATUS_FIELD_NUMBER: _ClassVar[int]
    breachWatchRecordStatus: _containers.RepeatedCompositeFieldContainer[BreachWatchRecordStatus]
    def __init__(self, breachWatchRecordStatus: _Optional[_Iterable[_Union[BreachWatchRecordStatus, _Mapping]]] = ...) -> None: ...

class BreachWatchTokenRequest(_message.Message):
    __slots__ = ["breachWatchToken"]
    BREACHWATCHTOKEN_FIELD_NUMBER: _ClassVar[int]
    breachWatchToken: bytes
    def __init__(self, breachWatchToken: _Optional[bytes] = ...) -> None: ...

class BreachWatchTokenResponse(_message.Message):
    __slots__ = ["breachWatchToken", "clientEncrypted"]
    BREACHWATCHTOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENTENCRYPTED_FIELD_NUMBER: _ClassVar[int]
    breachWatchToken: bytes
    clientEncrypted: bool
    def __init__(self, breachWatchToken: _Optional[bytes] = ..., clientEncrypted: bool = ...) -> None: ...

class AnonymizedTokenResponse(_message.Message):
    __slots__ = ["domainToken", "emailToken", "passwordToken"]
    DOMAINTOKEN_FIELD_NUMBER: _ClassVar[int]
    EMAILTOKEN_FIELD_NUMBER: _ClassVar[int]
    PASSWORDTOKEN_FIELD_NUMBER: _ClassVar[int]
    domainToken: bytes
    emailToken: bytes
    passwordToken: bytes
    def __init__(self, domainToken: _Optional[bytes] = ..., emailToken: _Optional[bytes] = ..., passwordToken: _Optional[bytes] = ...) -> None: ...

class HashCheck(_message.Message):
    __slots__ = ["hash1", "euid"]
    HASH1_FIELD_NUMBER: _ClassVar[int]
    EUID_FIELD_NUMBER: _ClassVar[int]
    hash1: bytes
    euid: bytes
    def __init__(self, hash1: _Optional[bytes] = ..., euid: _Optional[bytes] = ...) -> None: ...

class BreachWatchStatusRequest(_message.Message):
    __slots__ = ["anonymizedToken", "hashCheck", "removedEuid"]
    ANONYMIZEDTOKEN_FIELD_NUMBER: _ClassVar[int]
    HASHCHECK_FIELD_NUMBER: _ClassVar[int]
    REMOVEDEUID_FIELD_NUMBER: _ClassVar[int]
    anonymizedToken: bytes
    hashCheck: _containers.RepeatedCompositeFieldContainer[HashCheck]
    removedEuid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, anonymizedToken: _Optional[bytes] = ..., hashCheck: _Optional[_Iterable[_Union[HashCheck, _Mapping]]] = ..., removedEuid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class HashStatus(_message.Message):
    __slots__ = ["hash1", "euid", "breachDetected"]
    HASH1_FIELD_NUMBER: _ClassVar[int]
    EUID_FIELD_NUMBER: _ClassVar[int]
    BREACHDETECTED_FIELD_NUMBER: _ClassVar[int]
    hash1: bytes
    euid: bytes
    breachDetected: bool
    def __init__(self, hash1: _Optional[bytes] = ..., euid: _Optional[bytes] = ..., breachDetected: bool = ...) -> None: ...

class BreachWatchStatusResponse(_message.Message):
    __slots__ = ["hashStatus"]
    HASHSTATUS_FIELD_NUMBER: _ClassVar[int]
    hashStatus: _containers.RepeatedCompositeFieldContainer[HashStatus]
    def __init__(self, hashStatus: _Optional[_Iterable[_Union[HashStatus, _Mapping]]] = ...) -> None: ...

class EnterprisePublicKeyResponse(_message.Message):
    __slots__ = ["enterprisePublicKey", "enterpriseECCPublicKey"]
    ENTERPRISEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    enterprisePublicKey: bytes
    enterpriseECCPublicKey: bytes
    def __init__(self, enterprisePublicKey: _Optional[bytes] = ..., enterpriseECCPublicKey: _Optional[bytes] = ...) -> None: ...

class FreeScanRequest(_message.Message):
    __slots__ = ["hashedEmail"]
    HASHEDEMAIL_FIELD_NUMBER: _ClassVar[int]
    hashedEmail: bytes
    def __init__(self, hashedEmail: _Optional[bytes] = ...) -> None: ...

class FreeScanResponse(_message.Message):
    __slots__ = ["emailBreaches", "passwordBreaches"]
    EMAILBREACHES_FIELD_NUMBER: _ClassVar[int]
    PASSWORDBREACHES_FIELD_NUMBER: _ClassVar[int]
    emailBreaches: int
    passwordBreaches: int
    def __init__(self, emailBreaches: _Optional[int] = ..., passwordBreaches: _Optional[int] = ...) -> None: ...

class PaidUserRequest(_message.Message):
    __slots__ = ["email"]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    email: str
    def __init__(self, email: _Optional[str] = ...) -> None: ...

class PaidUserResponse(_message.Message):
    __slots__ = ["paidUser"]
    PAIDUSER_FIELD_NUMBER: _ClassVar[int]
    paidUser: bool
    def __init__(self, paidUser: bool = ...) -> None: ...

class DetailedScanRequest(_message.Message):
    __slots__ = ["email"]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    email: str
    def __init__(self, email: _Optional[str] = ...) -> None: ...

class UseOneTimeTokenRequest(_message.Message):
    __slots__ = ["token"]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: bytes
    def __init__(self, token: _Optional[bytes] = ...) -> None: ...

class BreachEvent(_message.Message):
    __slots__ = ["site", "email", "passwordInBreach", "date", "description"]
    SITE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    PASSWORDINBREACH_FIELD_NUMBER: _ClassVar[int]
    DATE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    site: str
    email: str
    passwordInBreach: bool
    date: str
    description: str
    def __init__(self, site: _Optional[str] = ..., email: _Optional[str] = ..., passwordInBreach: bool = ..., date: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class UseOneTimeTokenResponse(_message.Message):
    __slots__ = ["emailBreaches", "passwordBreaches", "breachEvents", "email"]
    EMAILBREACHES_FIELD_NUMBER: _ClassVar[int]
    PASSWORDBREACHES_FIELD_NUMBER: _ClassVar[int]
    BREACHEVENTS_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    emailBreaches: int
    passwordBreaches: int
    breachEvents: _containers.RepeatedCompositeFieldContainer[BreachEvent]
    email: str
    def __init__(self, emailBreaches: _Optional[int] = ..., passwordBreaches: _Optional[int] = ..., breachEvents: _Optional[_Iterable[_Union[BreachEvent, _Mapping]]] = ..., email: _Optional[str] = ...) -> None: ...

class OneTimeUseToken(_message.Message):
    __slots__ = ["email", "pad"]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    PAD_FIELD_NUMBER: _ClassVar[int]
    email: str
    pad: str
    def __init__(self, email: _Optional[str] = ..., pad: _Optional[str] = ...) -> None: ...

class FreePasswordScanRequest(_message.Message):
    __slots__ = ["hashedPassword"]
    HASHEDPASSWORD_FIELD_NUMBER: _ClassVar[int]
    hashedPassword: bytes
    def __init__(self, hashedPassword: _Optional[bytes] = ...) -> None: ...

class FreePasswordScanResponse(_message.Message):
    __slots__ = ["passwordBreaches"]
    PASSWORDBREACHES_FIELD_NUMBER: _ClassVar[int]
    passwordBreaches: int
    def __init__(self, passwordBreaches: _Optional[int] = ...) -> None: ...
