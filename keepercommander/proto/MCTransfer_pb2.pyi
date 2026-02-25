from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MCTransferStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    STATUS_INVALID: _ClassVar[MCTransferStatus]
    STATUS_REQUESTED: _ClassVar[MCTransferStatus]
    STATUS_ACCEPTED: _ClassVar[MCTransferStatus]
    STATUS_PENDING_APPROVAL: _ClassVar[MCTransferStatus]
    STATUS_APPROVED: _ClassVar[MCTransferStatus]
    STATUS_DENIED: _ClassVar[MCTransferStatus]
    STATUS_READY: _ClassVar[MCTransferStatus]
STATUS_INVALID: MCTransferStatus
STATUS_REQUESTED: MCTransferStatus
STATUS_ACCEPTED: MCTransferStatus
STATUS_PENDING_APPROVAL: MCTransferStatus
STATUS_APPROVED: MCTransferStatus
STATUS_DENIED: MCTransferStatus
STATUS_READY: MCTransferStatus

class MCTransferRequest(_message.Message):
    __slots__ = ["enterpriseName", "enterpriseContactEmail", "mcTransferTreeKeys"]
    ENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISECONTACTEMAIL_FIELD_NUMBER: _ClassVar[int]
    MCTRANSFERTREEKEYS_FIELD_NUMBER: _ClassVar[int]
    enterpriseName: str
    enterpriseContactEmail: str
    mcTransferTreeKeys: _containers.RepeatedCompositeFieldContainer[MCTransferTreeKey]
    def __init__(self, enterpriseName: _Optional[str] = ..., enterpriseContactEmail: _Optional[str] = ..., mcTransferTreeKeys: _Optional[_Iterable[_Union[MCTransferTreeKey, _Mapping]]] = ...) -> None: ...

class MCTransferTreeKey(_message.Message):
    __slots__ = ["enterpriseId", "treeKey"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    TREEKEY_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    treeKey: bytes
    def __init__(self, enterpriseId: _Optional[int] = ..., treeKey: _Optional[bytes] = ...) -> None: ...

class MCTransferApproveDenyRequest(_message.Message):
    __slots__ = ["enterpriseId", "message", "transferDate"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TRANSFERDATE_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    message: str
    transferDate: int
    def __init__(self, enterpriseId: _Optional[int] = ..., message: _Optional[str] = ..., transferDate: _Optional[int] = ...) -> None: ...

class MCTransferApproveDenyResponse(_message.Message):
    __slots__ = ["mcTransferState"]
    MCTRANSFERSTATE_FIELD_NUMBER: _ClassVar[int]
    mcTransferState: MCTransferState
    def __init__(self, mcTransferState: _Optional[_Union[MCTransferState, _Mapping]] = ...) -> None: ...

class MCTransferListResponse(_message.Message):
    __slots__ = ["mcTransferStates"]
    MCTRANSFERSTATES_FIELD_NUMBER: _ClassVar[int]
    mcTransferStates: _containers.RepeatedCompositeFieldContainer[MCTransferState]
    def __init__(self, mcTransferStates: _Optional[_Iterable[_Union[MCTransferState, _Mapping]]] = ...) -> None: ...

class MCTransferEnterprise(_message.Message):
    __slots__ = ["enterpriseId", "enterpriseName"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    enterpriseName: str
    def __init__(self, enterpriseId: _Optional[int] = ..., enterpriseName: _Optional[str] = ...) -> None: ...

class MCTransferState(_message.Message):
    __slots__ = ["movingEnterpriseId", "movingEnterpriseName", "movingEnterpriseAdminEmail", "receivingEnterpriseName", "receivingEnterpriseAdminEmail", "transferStatus", "comments", "transferDate", "mcTransferEnterprises"]
    MOVINGENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MOVINGENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    MOVINGENTERPRISEADMINEMAIL_FIELD_NUMBER: _ClassVar[int]
    RECEIVINGENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    RECEIVINGENTERPRISEADMINEMAIL_FIELD_NUMBER: _ClassVar[int]
    TRANSFERSTATUS_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    TRANSFERDATE_FIELD_NUMBER: _ClassVar[int]
    MCTRANSFERENTERPRISES_FIELD_NUMBER: _ClassVar[int]
    movingEnterpriseId: int
    movingEnterpriseName: str
    movingEnterpriseAdminEmail: str
    receivingEnterpriseName: str
    receivingEnterpriseAdminEmail: str
    transferStatus: MCTransferStatus
    comments: str
    transferDate: int
    mcTransferEnterprises: _containers.RepeatedCompositeFieldContainer[MCTransferEnterprise]
    def __init__(self, movingEnterpriseId: _Optional[int] = ..., movingEnterpriseName: _Optional[str] = ..., movingEnterpriseAdminEmail: _Optional[str] = ..., receivingEnterpriseName: _Optional[str] = ..., receivingEnterpriseAdminEmail: _Optional[str] = ..., transferStatus: _Optional[_Union[MCTransferStatus, str]] = ..., comments: _Optional[str] = ..., transferDate: _Optional[int] = ..., mcTransferEnterprises: _Optional[_Iterable[_Union[MCTransferEnterprise, _Mapping]]] = ...) -> None: ...
