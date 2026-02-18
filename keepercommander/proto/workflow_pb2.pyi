import GraphSync_pb2 as _GraphSync_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class WorkflowStage(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    WS_READY_TO_START: _ClassVar[WorkflowStage]
    WS_STARTED: _ClassVar[WorkflowStage]
    WS_NEEDS_ACTION: _ClassVar[WorkflowStage]
    WS_WAITING: _ClassVar[WorkflowStage]

class AccessCondition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AC_APPROVAL: _ClassVar[AccessCondition]
    AC_CHECKIN: _ClassVar[AccessCondition]
    AC_MFA: _ClassVar[AccessCondition]
    AC_TIME: _ClassVar[AccessCondition]
    AC_REASON: _ClassVar[AccessCondition]
    AC_TICKET: _ClassVar[AccessCondition]

class DayOfWeek(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DAY_OF_WEEK_UNSPECIFIED: _ClassVar[DayOfWeek]
    MONDAY: _ClassVar[DayOfWeek]
    TUESDAY: _ClassVar[DayOfWeek]
    WEDNESDAY: _ClassVar[DayOfWeek]
    THURSDAY: _ClassVar[DayOfWeek]
    FRIDAY: _ClassVar[DayOfWeek]
    SATURDAY: _ClassVar[DayOfWeek]
    SUNDAY: _ClassVar[DayOfWeek]

class ApprovalQueueKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AQK_APPROVAL: _ClassVar[ApprovalQueueKind]
    AQK_ESCALATION: _ClassVar[ApprovalQueueKind]
WS_READY_TO_START: WorkflowStage
WS_STARTED: WorkflowStage
WS_NEEDS_ACTION: WorkflowStage
WS_WAITING: WorkflowStage
AC_APPROVAL: AccessCondition
AC_CHECKIN: AccessCondition
AC_MFA: AccessCondition
AC_TIME: AccessCondition
AC_REASON: AccessCondition
AC_TICKET: AccessCondition
DAY_OF_WEEK_UNSPECIFIED: DayOfWeek
MONDAY: DayOfWeek
TUESDAY: DayOfWeek
WEDNESDAY: DayOfWeek
THURSDAY: DayOfWeek
FRIDAY: DayOfWeek
SATURDAY: DayOfWeek
SUNDAY: DayOfWeek
AQK_APPROVAL: ApprovalQueueKind
AQK_ESCALATION: ApprovalQueueKind

class WorkflowApprover(_message.Message):
    __slots__ = ("user", "userId", "teamUid", "escalation", "escalationAfterMs")
    USER_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    ESCALATION_FIELD_NUMBER: _ClassVar[int]
    ESCALATIONAFTERMS_FIELD_NUMBER: _ClassVar[int]
    user: str
    userId: int
    teamUid: bytes
    escalation: bool
    escalationAfterMs: int
    def __init__(self, user: _Optional[str] = ..., userId: _Optional[int] = ..., teamUid: _Optional[bytes] = ..., escalation: _Optional[bool] = ..., escalationAfterMs: _Optional[int] = ...) -> None: ...

class WorkflowParameters(_message.Message):
    __slots__ = ("resource", "approvalsNeeded", "checkoutNeeded", "startAccessOnApproval", "requireReason", "requireTicket", "requireMFA", "accessLength", "allowedTimes")
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    APPROVALSNEEDED_FIELD_NUMBER: _ClassVar[int]
    CHECKOUTNEEDED_FIELD_NUMBER: _ClassVar[int]
    STARTACCESSONAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    REQUIREREASON_FIELD_NUMBER: _ClassVar[int]
    REQUIRETICKET_FIELD_NUMBER: _ClassVar[int]
    REQUIREMFA_FIELD_NUMBER: _ClassVar[int]
    ACCESSLENGTH_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDTIMES_FIELD_NUMBER: _ClassVar[int]
    resource: _GraphSync_pb2.GraphSyncRef
    approvalsNeeded: int
    checkoutNeeded: bool
    startAccessOnApproval: bool
    requireReason: bool
    requireTicket: bool
    requireMFA: bool
    accessLength: int
    allowedTimes: TemporalAccessFilter
    def __init__(self, resource: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., approvalsNeeded: _Optional[int] = ..., checkoutNeeded: _Optional[bool] = ..., startAccessOnApproval: _Optional[bool] = ..., requireReason: _Optional[bool] = ..., requireTicket: _Optional[bool] = ..., requireMFA: _Optional[bool] = ..., accessLength: _Optional[int] = ..., allowedTimes: _Optional[_Union[TemporalAccessFilter, _Mapping]] = ...) -> None: ...

class WorkflowConfig(_message.Message):
    __slots__ = ("parameters", "approvers", "createdOn")
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    APPROVERS_FIELD_NUMBER: _ClassVar[int]
    CREATEDON_FIELD_NUMBER: _ClassVar[int]
    parameters: WorkflowParameters
    approvers: _containers.RepeatedCompositeFieldContainer[WorkflowApprover]
    createdOn: int
    def __init__(self, parameters: _Optional[_Union[WorkflowParameters, _Mapping]] = ..., approvers: _Optional[_Iterable[_Union[WorkflowApprover, _Mapping]]] = ..., createdOn: _Optional[int] = ...) -> None: ...

class WorkflowStatus(_message.Message):
    __slots__ = ("stage", "conditions", "approvedBy", "startedOn", "expiresOn", "escalated")
    STAGE_FIELD_NUMBER: _ClassVar[int]
    CONDITIONS_FIELD_NUMBER: _ClassVar[int]
    APPROVEDBY_FIELD_NUMBER: _ClassVar[int]
    STARTEDON_FIELD_NUMBER: _ClassVar[int]
    EXPIRESON_FIELD_NUMBER: _ClassVar[int]
    ESCALATED_FIELD_NUMBER: _ClassVar[int]
    stage: WorkflowStage
    conditions: _containers.RepeatedScalarFieldContainer[AccessCondition]
    approvedBy: _containers.RepeatedCompositeFieldContainer[WorkflowApproval]
    startedOn: int
    expiresOn: int
    escalated: bool
    def __init__(self, stage: _Optional[_Union[WorkflowStage, str]] = ..., conditions: _Optional[_Iterable[_Union[AccessCondition, str]]] = ..., approvedBy: _Optional[_Iterable[_Union[WorkflowApproval, _Mapping]]] = ..., startedOn: _Optional[int] = ..., expiresOn: _Optional[int] = ..., escalated: _Optional[bool] = ...) -> None: ...

class WorkflowProcess(_message.Message):
    __slots__ = ("flowUid", "userId", "resource", "startedOn", "expiresOn", "reason", "mfaVerified", "externalRef")
    FLOWUID_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    STARTEDON_FIELD_NUMBER: _ClassVar[int]
    EXPIRESON_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    MFAVERIFIED_FIELD_NUMBER: _ClassVar[int]
    EXTERNALREF_FIELD_NUMBER: _ClassVar[int]
    flowUid: bytes
    userId: int
    resource: _GraphSync_pb2.GraphSyncRef
    startedOn: int
    expiresOn: int
    reason: bytes
    mfaVerified: bool
    externalRef: bytes
    def __init__(self, flowUid: _Optional[bytes] = ..., userId: _Optional[int] = ..., resource: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., startedOn: _Optional[int] = ..., expiresOn: _Optional[int] = ..., reason: _Optional[bytes] = ..., mfaVerified: _Optional[bool] = ..., externalRef: _Optional[bytes] = ...) -> None: ...

class WorkflowApproval(_message.Message):
    __slots__ = ("userId", "user", "flowUid", "approvedOn")
    USERID_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    FLOWUID_FIELD_NUMBER: _ClassVar[int]
    APPROVEDON_FIELD_NUMBER: _ClassVar[int]
    userId: int
    user: str
    flowUid: bytes
    approvedOn: int
    def __init__(self, userId: _Optional[int] = ..., user: _Optional[str] = ..., flowUid: _Optional[bytes] = ..., approvedOn: _Optional[int] = ...) -> None: ...

class WorkflowContext(_message.Message):
    __slots__ = ("workflowConfig", "workflow", "approvals", "blocker")
    WORKFLOWCONFIG_FIELD_NUMBER: _ClassVar[int]
    WORKFLOW_FIELD_NUMBER: _ClassVar[int]
    APPROVALS_FIELD_NUMBER: _ClassVar[int]
    BLOCKER_FIELD_NUMBER: _ClassVar[int]
    workflowConfig: WorkflowConfig
    workflow: WorkflowProcess
    approvals: _containers.RepeatedCompositeFieldContainer[WorkflowApproval]
    blocker: WorkflowProcess
    def __init__(self, workflowConfig: _Optional[_Union[WorkflowConfig, _Mapping]] = ..., workflow: _Optional[_Union[WorkflowProcess, _Mapping]] = ..., approvals: _Optional[_Iterable[_Union[WorkflowApproval, _Mapping]]] = ..., blocker: _Optional[_Union[WorkflowProcess, _Mapping]] = ...) -> None: ...

class WorkflowState(_message.Message):
    __slots__ = ("flowUid", "resource", "status")
    FLOWUID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    flowUid: bytes
    resource: _GraphSync_pb2.GraphSyncRef
    status: WorkflowStatus
    def __init__(self, flowUid: _Optional[bytes] = ..., resource: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., status: _Optional[_Union[WorkflowStatus, _Mapping]] = ...) -> None: ...

class WorkflowAccessRequest(_message.Message):
    __slots__ = ("resource", "reason", "ticket")
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    TICKET_FIELD_NUMBER: _ClassVar[int]
    resource: _GraphSync_pb2.GraphSyncRef
    reason: bytes
    ticket: bytes
    def __init__(self, resource: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., reason: _Optional[bytes] = ..., ticket: _Optional[bytes] = ...) -> None: ...

class WorkflowApprovalOrDenial(_message.Message):
    __slots__ = ("resource", "deny", "denialReason")
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    DENY_FIELD_NUMBER: _ClassVar[int]
    DENIALREASON_FIELD_NUMBER: _ClassVar[int]
    resource: _GraphSync_pb2.GraphSyncRef
    deny: bool
    denialReason: str
    def __init__(self, resource: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., deny: _Optional[bool] = ..., denialReason: _Optional[str] = ...) -> None: ...

class UserAccessState(_message.Message):
    __slots__ = ("workflows",)
    WORKFLOWS_FIELD_NUMBER: _ClassVar[int]
    workflows: _containers.RepeatedCompositeFieldContainer[WorkflowState]
    def __init__(self, workflows: _Optional[_Iterable[_Union[WorkflowState, _Mapping]]] = ...) -> None: ...

class ApprovalRequests(_message.Message):
    __slots__ = ("workflows",)
    WORKFLOWS_FIELD_NUMBER: _ClassVar[int]
    workflows: _containers.RepeatedCompositeFieldContainer[WorkflowProcess]
    def __init__(self, workflows: _Optional[_Iterable[_Union[WorkflowProcess, _Mapping]]] = ...) -> None: ...

class TimeOfDayRange(_message.Message):
    __slots__ = ("startTime", "endTime")
    STARTTIME_FIELD_NUMBER: _ClassVar[int]
    ENDTIME_FIELD_NUMBER: _ClassVar[int]
    startTime: int
    endTime: int
    def __init__(self, startTime: _Optional[int] = ..., endTime: _Optional[int] = ...) -> None: ...

class ApprovalQueueEntry(_message.Message):
    __slots__ = ("flowRef", "approverRef", "kind", "notifyAtMs", "requesterUserId")
    FLOWREF_FIELD_NUMBER: _ClassVar[int]
    APPROVERREF_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    NOTIFYATMS_FIELD_NUMBER: _ClassVar[int]
    REQUESTERUSERID_FIELD_NUMBER: _ClassVar[int]
    flowRef: _GraphSync_pb2.GraphSyncRef
    approverRef: _GraphSync_pb2.GraphSyncRef
    kind: ApprovalQueueKind
    notifyAtMs: int
    requesterUserId: int
    def __init__(self, flowRef: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., approverRef: _Optional[_Union[_GraphSync_pb2.GraphSyncRef, _Mapping]] = ..., kind: _Optional[_Union[ApprovalQueueKind, str]] = ..., notifyAtMs: _Optional[int] = ..., requesterUserId: _Optional[int] = ...) -> None: ...

class TemporalAccessFilter(_message.Message):
    __slots__ = ("timeRanges", "allowedDays", "timeZone")
    TIMERANGES_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDDAYS_FIELD_NUMBER: _ClassVar[int]
    TIMEZONE_FIELD_NUMBER: _ClassVar[int]
    timeRanges: _containers.RepeatedCompositeFieldContainer[TimeOfDayRange]
    allowedDays: _containers.RepeatedScalarFieldContainer[DayOfWeek]
    timeZone: str
    def __init__(self, timeRanges: _Optional[_Iterable[_Union[TimeOfDayRange, _Mapping]]] = ..., allowedDays: _Optional[_Iterable[_Union[DayOfWeek, str]]] = ..., timeZone: _Optional[str] = ...) -> None: ...

class AuthorizedUsers(_message.Message):
    __slots__ = ("username",)
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, username: _Optional[_Iterable[str]] = ...) -> None: ...
