import GraphSync_pb2 as _GraphSync_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class NotificationCategory(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    NC_UNSPECIFIED: _ClassVar[NotificationCategory]
    NC_ACCOUNT: _ClassVar[NotificationCategory]
    NC_SHARING: _ClassVar[NotificationCategory]
    NC_ENTERPRISE: _ClassVar[NotificationCategory]
    NC_SECURITY: _ClassVar[NotificationCategory]
    NC_REQUEST: _ClassVar[NotificationCategory]
    NC_SYSTEM: _ClassVar[NotificationCategory]
    NC_PROMOTION: _ClassVar[NotificationCategory]

class NotificationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    NT_UNSPECIFIED: _ClassVar[NotificationType]
    NT_ALERT: _ClassVar[NotificationType]
    NT_DEVICE_APPROVAL: _ClassVar[NotificationType]
    NT_MASTER_PASS_UPDATED: _ClassVar[NotificationType]
    NT_SHARE_APPROVAL: _ClassVar[NotificationType]
    NT_SHARE_APPROVAL_APPROVED: _ClassVar[NotificationType]
    NT_SHARED: _ClassVar[NotificationType]
    NT_TRANSFERRED: _ClassVar[NotificationType]
    NT_LICENSE_LIMIT_REACHED: _ClassVar[NotificationType]
    NT_APPROVAL_REQUEST: _ClassVar[NotificationType]
    NT_APPROVED_RESPONSE: _ClassVar[NotificationType]
    NT_DENIED_RESPONSE: _ClassVar[NotificationType]
    NT_2FA_CONFIGURED: _ClassVar[NotificationType]

class NotificationReadStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    NRS_UNSPECIFIED: _ClassVar[NotificationReadStatus]
    NRS_LAST: _ClassVar[NotificationReadStatus]
    NRS_READ: _ClassVar[NotificationReadStatus]
    NRS_UNREAD: _ClassVar[NotificationReadStatus]

class NotificationApprovalStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    NAS_UNSPECIFIED: _ClassVar[NotificationApprovalStatus]
    NAS_APPROVED: _ClassVar[NotificationApprovalStatus]
    NAS_DENIED: _ClassVar[NotificationApprovalStatus]
    NAS_LOST_APPROVAL_RIGHTS: _ClassVar[NotificationApprovalStatus]
    NAS_LOST_ACCESS: _ClassVar[NotificationApprovalStatus]
NC_UNSPECIFIED: NotificationCategory
NC_ACCOUNT: NotificationCategory
NC_SHARING: NotificationCategory
NC_ENTERPRISE: NotificationCategory
NC_SECURITY: NotificationCategory
NC_REQUEST: NotificationCategory
NC_SYSTEM: NotificationCategory
NC_PROMOTION: NotificationCategory
NT_UNSPECIFIED: NotificationType
NT_ALERT: NotificationType
NT_DEVICE_APPROVAL: NotificationType
NT_MASTER_PASS_UPDATED: NotificationType
NT_SHARE_APPROVAL: NotificationType
NT_SHARE_APPROVAL_APPROVED: NotificationType
NT_SHARED: NotificationType
NT_TRANSFERRED: NotificationType
NT_LICENSE_LIMIT_REACHED: NotificationType
NT_APPROVAL_REQUEST: NotificationType
NT_APPROVED_RESPONSE: NotificationType
NT_DENIED_RESPONSE: NotificationType
NT_2FA_CONFIGURED: NotificationType
NRS_UNSPECIFIED: NotificationReadStatus
NRS_LAST: NotificationReadStatus
NRS_READ: NotificationReadStatus
NRS_UNREAD: NotificationReadStatus
NAS_UNSPECIFIED: NotificationApprovalStatus
NAS_APPROVED: NotificationApprovalStatus
NAS_DENIED: NotificationApprovalStatus
NAS_LOST_APPROVAL_RIGHTS: NotificationApprovalStatus
NAS_LOST_ACCESS: NotificationApprovalStatus

class EncryptedData(_message.Message):
    __slots__ = ["version", "data"]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    version: int
    data: bytes
    def __init__(self, version: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class Notification(_message.Message):
    __slots__ = ["type", "category", "sender", "senderFullName", "encryptedData", "refs", "categories"]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    SENDERFULLNAME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    REFS_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    type: NotificationType
    category: NotificationCategory
    sender: _GraphSync_pb2.GraphSyncRef
    senderFullName: str
    encryptedData: EncryptedData
    refs: _containers.RepeatedCompositeFieldContainer[_GraphSync_pb2.GraphSyncRef]
    categories: _containers.RepeatedScalarFieldContainer[NotificationCategory]
    def __init__(self, type: _Optional[_Union[NotificationType, str]] = ..., category: _Optional[_Union[NotificationCategory, str]] = ..., sender: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., senderFullName: _Optional[str] = ..., encryptedData: _Optional[_Union[EncryptedData, _Mapping]] = ..., refs: _Optional[_Iterable[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]]] = ..., categories: _Optional[_Iterable[_Union[NotificationCategory, str]]] = ...) -> None: ...

class NotificationReadMark(_message.Message):
    __slots__ = ["uid", "notification_edge_id", "mark_edge_id", "readStatus"]
    UID_FIELD_NUMBER: _ClassVar[int]
    NOTIFICATION_EDGE_ID_FIELD_NUMBER: _ClassVar[int]
    MARK_EDGE_ID_FIELD_NUMBER: _ClassVar[int]
    READSTATUS_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    notification_edge_id: int
    mark_edge_id: int
    readStatus: NotificationReadStatus
    def __init__(self, uid: _Optional[bytes] = ..., notification_edge_id: _Optional[int] = ..., mark_edge_id: _Optional[int] = ..., readStatus: _Optional[_Union[NotificationReadStatus, str]] = ...) -> None: ...

class NotificationContent(_message.Message):
    __slots__ = ["notification", "readStatus", "approvalStatus", "clientTypeIDs", "deviceIDs"]
    NOTIFICATION_FIELD_NUMBER: _ClassVar[int]
    READSTATUS_FIELD_NUMBER: _ClassVar[int]
    APPROVALSTATUS_FIELD_NUMBER: _ClassVar[int]
    CLIENTTYPEIDS_FIELD_NUMBER: _ClassVar[int]
    DEVICEIDS_FIELD_NUMBER: _ClassVar[int]
    notification: Notification
    readStatus: NotificationReadStatus
    approvalStatus: NotificationApprovalStatus
    clientTypeIDs: _containers.RepeatedScalarFieldContainer[int]
    deviceIDs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, notification: _Optional[_Union[Notification, _Mapping]] = ..., readStatus: _Optional[_Union[NotificationReadStatus, str]] = ..., approvalStatus: _Optional[_Union[NotificationApprovalStatus, str]] = ..., clientTypeIDs: _Optional[_Iterable[int]] = ..., deviceIDs: _Optional[_Iterable[int]] = ...) -> None: ...

class NotificationWrapper(_message.Message):
    __slots__ = ["uid", "content", "timestamp"]
    UID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    uid: bytes
    content: NotificationContent
    timestamp: int
    def __init__(self, uid: _Optional[bytes] = ..., content: _Optional[_Union[NotificationContent, _Mapping]] = ..., timestamp: _Optional[int] = ...) -> None: ...

class NotificationSync(_message.Message):
    __slots__ = ["data", "syncPoint", "hasMore"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    SYNCPOINT_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedCompositeFieldContainer[NotificationWrapper]
    syncPoint: int
    hasMore: bool
    def __init__(self, data: _Optional[_Iterable[_Union[NotificationWrapper, _Mapping]]] = ..., syncPoint: _Optional[int] = ..., hasMore: bool = ...) -> None: ...

class ReadStatusUpdate(_message.Message):
    __slots__ = ["notificationUid", "status"]
    NOTIFICATIONUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    notificationUid: bytes
    status: NotificationReadStatus
    def __init__(self, notificationUid: _Optional[bytes] = ..., status: _Optional[_Union[NotificationReadStatus, str]] = ...) -> None: ...

class ApprovalStatusUpdate(_message.Message):
    __slots__ = ["notificationUid", "status"]
    NOTIFICATIONUID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    notificationUid: bytes
    status: NotificationApprovalStatus
    def __init__(self, notificationUid: _Optional[bytes] = ..., status: _Optional[_Union[NotificationApprovalStatus, str]] = ...) -> None: ...

class ProcessMarkReadEventsRequest(_message.Message):
    __slots__ = ["readStatusUpdate"]
    READSTATUSUPDATE_FIELD_NUMBER: _ClassVar[int]
    readStatusUpdate: _containers.RepeatedCompositeFieldContainer[ReadStatusUpdate]
    def __init__(self, readStatusUpdate: _Optional[_Iterable[_Union[ReadStatusUpdate, _Mapping]]] = ...) -> None: ...

class NotificationSendRequest(_message.Message):
    __slots__ = ["recipients", "notification", "clientTypeIDs", "deviceIDs"]
    RECIPIENTS_FIELD_NUMBER: _ClassVar[int]
    NOTIFICATION_FIELD_NUMBER: _ClassVar[int]
    CLIENTTYPEIDS_FIELD_NUMBER: _ClassVar[int]
    DEVICEIDS_FIELD_NUMBER: _ClassVar[int]
    recipients: _containers.RepeatedCompositeFieldContainer[_GraphSync_pb2.GraphSyncRef]
    notification: Notification
    clientTypeIDs: _containers.RepeatedScalarFieldContainer[int]
    deviceIDs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, recipients: _Optional[_Iterable[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]]] = ..., notification: _Optional[_Union[Notification, _Mapping]] = ..., clientTypeIDs: _Optional[_Iterable[int]] = ..., deviceIDs: _Optional[_Iterable[int]] = ...) -> None: ...

class NotificationsSendRequest(_message.Message):
    __slots__ = ["notifications"]
    NOTIFICATIONS_FIELD_NUMBER: _ClassVar[int]
    notifications: _containers.RepeatedCompositeFieldContainer[NotificationSendRequest]
    def __init__(self, notifications: _Optional[_Iterable[_Union[NotificationSendRequest, _Mapping]]] = ...) -> None: ...

class NotificationSyncRequest(_message.Message):
    __slots__ = ["syncPoint"]
    SYNCPOINT_FIELD_NUMBER: _ClassVar[int]
    syncPoint: int
    def __init__(self, syncPoint: _Optional[int] = ...) -> None: ...
