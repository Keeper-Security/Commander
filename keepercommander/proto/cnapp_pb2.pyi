from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CnappProvider(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CNAPP_PROVIDER_UNSPECIFIED: _ClassVar[CnappProvider]
    CNAPP_PROVIDER_WIZ: _ClassVar[CnappProvider]

class CnappRemediationAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNSPECIFIED: _ClassVar[CnappRemediationAction]
    ROTATE_CREDENTIALS: _ClassVar[CnappRemediationAction]
    MANAGE_ACCESS: _ClassVar[CnappRemediationAction]
    JIT_ACCESS: _ClassVar[CnappRemediationAction]
    REMOVE_STANDING_PRIVILEGE: _ClassVar[CnappRemediationAction]
CNAPP_PROVIDER_UNSPECIFIED: CnappProvider
CNAPP_PROVIDER_WIZ: CnappProvider
UNSPECIFIED: CnappRemediationAction
ROTATE_CREDENTIALS: CnappRemediationAction
MANAGE_ACCESS: CnappRemediationAction
JIT_ACCESS: CnappRemediationAction
REMOVE_STANDING_PRIVILEGE: CnappRemediationAction

class CnappQueueListRequest(_message.Message):
    __slots__ = ("networkUid", "statusFilter")
    NETWORKUID_FIELD_NUMBER: _ClassVar[int]
    STATUSFILTER_FIELD_NUMBER: _ClassVar[int]
    networkUid: bytes
    statusFilter: int
    def __init__(self, networkUid: _Optional[bytes] = ..., statusFilter: _Optional[int] = ...) -> None: ...

class CnappQueueListResponse(_message.Message):
    __slots__ = ("items", "hasMore")
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    items: _containers.RepeatedCompositeFieldContainer[CnappQueueItem]
    hasMore: bool
    def __init__(self, items: _Optional[_Iterable[_Union[CnappQueueItem, _Mapping]]] = ..., hasMore: _Optional[bool] = ...) -> None: ...

class CnappQueueItem(_message.Message):
    __slots__ = ("cnappQueueId", "cnappProviderId", "cnappQueueStatusId", "receivedAt", "resolvedAt", "networkId", "payload", "recordUid", "controlHash")
    CNAPPQUEUEID_FIELD_NUMBER: _ClassVar[int]
    CNAPPPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    CNAPPQUEUESTATUSID_FIELD_NUMBER: _ClassVar[int]
    RECEIVEDAT_FIELD_NUMBER: _ClassVar[int]
    RESOLVEDAT_FIELD_NUMBER: _ClassVar[int]
    NETWORKID_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLHASH_FIELD_NUMBER: _ClassVar[int]
    cnappQueueId: int
    cnappProviderId: CnappProvider
    cnappQueueStatusId: int
    receivedAt: int
    resolvedAt: int
    networkId: bytes
    payload: bytes
    recordUid: bytes
    controlHash: str
    def __init__(self, cnappQueueId: _Optional[int] = ..., cnappProviderId: _Optional[_Union[CnappProvider, str]] = ..., cnappQueueStatusId: _Optional[int] = ..., receivedAt: _Optional[int] = ..., resolvedAt: _Optional[int] = ..., networkId: _Optional[bytes] = ..., payload: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., controlHash: _Optional[str] = ...) -> None: ...

class CnappAssociateRequest(_message.Message):
    __slots__ = ("recordUid", "cnappQueueId")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    CNAPPQUEUEID_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    cnappQueueId: int
    def __init__(self, recordUid: _Optional[bytes] = ..., cnappQueueId: _Optional[int] = ...) -> None: ...

class CnappAssociateResponse(_message.Message):
    __slots__ = ("cnappQueueStatusId",)
    CNAPPQUEUESTATUSID_FIELD_NUMBER: _ClassVar[int]
    cnappQueueStatusId: int
    def __init__(self, cnappQueueStatusId: _Optional[int] = ...) -> None: ...

class CnappRemediateRequest(_message.Message):
    __slots__ = ("cnappQueueId", "actionType", "cnappConfigurationRecordUid", "pwdComplexity", "resourceRef", "provider", "controllerUid", "messageUid", "encryptedRemediations", "autoRemediateInFuture")
    CNAPPQUEUEID_FIELD_NUMBER: _ClassVar[int]
    ACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    CNAPPCONFIGURATIONRECORDUID_FIELD_NUMBER: _ClassVar[int]
    PWDCOMPLEXITY_FIELD_NUMBER: _ClassVar[int]
    RESOURCEREF_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    MESSAGEUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDREMEDIATIONS_FIELD_NUMBER: _ClassVar[int]
    AUTOREMEDIATEINFUTURE_FIELD_NUMBER: _ClassVar[int]
    cnappQueueId: int
    actionType: CnappRemediationAction
    cnappConfigurationRecordUid: bytes
    pwdComplexity: str
    resourceRef: bytes
    provider: CnappProvider
    controllerUid: str
    messageUid: bytes
    encryptedRemediations: bytes
    autoRemediateInFuture: bool
    def __init__(self, cnappQueueId: _Optional[int] = ..., actionType: _Optional[_Union[CnappRemediationAction, str]] = ..., cnappConfigurationRecordUid: _Optional[bytes] = ..., pwdComplexity: _Optional[str] = ..., resourceRef: _Optional[bytes] = ..., provider: _Optional[_Union[CnappProvider, str]] = ..., controllerUid: _Optional[str] = ..., messageUid: _Optional[bytes] = ..., encryptedRemediations: _Optional[bytes] = ..., autoRemediateInFuture: _Optional[bool] = ...) -> None: ...

class CnappRemediateResponse(_message.Message):
    __slots__ = ("actionType", "result", "cnappQueueStatusId")
    ACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    CNAPPQUEUESTATUSID_FIELD_NUMBER: _ClassVar[int]
    actionType: CnappRemediationAction
    result: str
    cnappQueueStatusId: int
    def __init__(self, actionType: _Optional[_Union[CnappRemediationAction, str]] = ..., result: _Optional[str] = ..., cnappQueueStatusId: _Optional[int] = ...) -> None: ...

class CnappSetStatusRequest(_message.Message):
    __slots__ = ("cnappQueueId", "cnappQueueStatusId", "reason")
    CNAPPQUEUEID_FIELD_NUMBER: _ClassVar[int]
    CNAPPQUEUESTATUSID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    cnappQueueId: int
    cnappQueueStatusId: int
    reason: str
    def __init__(self, cnappQueueId: _Optional[int] = ..., cnappQueueStatusId: _Optional[int] = ..., reason: _Optional[str] = ...) -> None: ...

class CnappSetStatusResponse(_message.Message):
    __slots__ = ("cnappQueueStatusId",)
    CNAPPQUEUESTATUSID_FIELD_NUMBER: _ClassVar[int]
    cnappQueueStatusId: int
    def __init__(self, cnappQueueStatusId: _Optional[int] = ...) -> None: ...

class CnappDeleteQueueItemRequest(_message.Message):
    __slots__ = ("cnappQueueId",)
    CNAPPQUEUEID_FIELD_NUMBER: _ClassVar[int]
    cnappQueueId: int
    def __init__(self, cnappQueueId: _Optional[int] = ...) -> None: ...

class CnappDeleteQueueItemResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CnappConfiguration(_message.Message):
    __slots__ = ("networkUid", "provider", "clientId", "clientSecret", "apiEndpointUrl", "cnappConfigRecordUid", "authEndpointUrl")
    NETWORKUID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    CLIENTSECRET_FIELD_NUMBER: _ClassVar[int]
    APIENDPOINTURL_FIELD_NUMBER: _ClassVar[int]
    CNAPPCONFIGRECORDUID_FIELD_NUMBER: _ClassVar[int]
    AUTHENDPOINTURL_FIELD_NUMBER: _ClassVar[int]
    networkUid: bytes
    provider: CnappProvider
    clientId: str
    clientSecret: str
    apiEndpointUrl: str
    cnappConfigRecordUid: bytes
    authEndpointUrl: str
    def __init__(self, networkUid: _Optional[bytes] = ..., provider: _Optional[_Union[CnappProvider, str]] = ..., clientId: _Optional[str] = ..., clientSecret: _Optional[str] = ..., apiEndpointUrl: _Optional[str] = ..., cnappConfigRecordUid: _Optional[bytes] = ..., authEndpointUrl: _Optional[str] = ...) -> None: ...

class CnappDeleteConfigurationRequest(_message.Message):
    __slots__ = ("networkUid",)
    NETWORKUID_FIELD_NUMBER: _ClassVar[int]
    networkUid: bytes
    def __init__(self, networkUid: _Optional[bytes] = ...) -> None: ...

class CnappTestEncrypterRequest(_message.Message):
    __slots__ = ("urlBaseEncrypter",)
    URLBASEENCRYPTER_FIELD_NUMBER: _ClassVar[int]
    urlBaseEncrypter: str
    def __init__(self, urlBaseEncrypter: _Optional[str] = ...) -> None: ...
