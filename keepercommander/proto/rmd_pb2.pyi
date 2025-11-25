from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SecurityBenchmark(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    SB_INVALID: _ClassVar[SecurityBenchmark]
    SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION: _ClassVar[SecurityBenchmark]
    SB_PREVENT_INSTALLATION_OF_UNTRUSTED_EXTENSIONS: _ClassVar[SecurityBenchmark]
    SB_ENABLE_ACCOUNT_TRANSFER_POLICY: _ClassVar[SecurityBenchmark]
    SB_REDUCE_ADMINISTRATOR_PRIVILEGE: _ClassVar[SecurityBenchmark]
    SB_ENSURE_OUTSIDE_SSO_ADMINISTRATOR_EXISTS: _ClassVar[SecurityBenchmark]
    SB_LOCK_DOWN_SSO_PROVIDER: _ClassVar[SecurityBenchmark]
    SB_CREATE_AT_LEAST_TWO_KEEPER_ADMINISTRATORS: _ClassVar[SecurityBenchmark]
    SB_ENSURE_TWO_FACTOR_AUTHENTICATION_ADMIN_USERS: _ClassVar[SecurityBenchmark]
    SB_ENFORCE_STRONG_MASTER_PASSWORD: _ClassVar[SecurityBenchmark]
    SB_ENSURE_TWO_FACTOR_AUTHENTICATION_FOR_END_USERS: _ClassVar[SecurityBenchmark]
    SB_CONFIGURE_IP_ALLOWLISTING: _ClassVar[SecurityBenchmark]
    SB_CREATE_ALERTS: _ClassVar[SecurityBenchmark]
    SB_DISABLE_BROWSER_PASSWORD_MANAGERS: _ClassVar[SecurityBenchmark]
    SB_DISABLE_ACCOUNT_RECOVERY: _ClassVar[SecurityBenchmark]
    SB_ENFORCE_LEAST_PRIVILEGE_POLICY: _ClassVar[SecurityBenchmark]

class SecurityBenchmarkStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    INVALID: _ClassVar[SecurityBenchmarkStatus]
    RESOLVED: _ClassVar[SecurityBenchmarkStatus]
    IGNORED: _ClassVar[SecurityBenchmarkStatus]
    UNRESOLVED: _ClassVar[SecurityBenchmarkStatus]
SB_INVALID: SecurityBenchmark
SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION: SecurityBenchmark
SB_PREVENT_INSTALLATION_OF_UNTRUSTED_EXTENSIONS: SecurityBenchmark
SB_ENABLE_ACCOUNT_TRANSFER_POLICY: SecurityBenchmark
SB_REDUCE_ADMINISTRATOR_PRIVILEGE: SecurityBenchmark
SB_ENSURE_OUTSIDE_SSO_ADMINISTRATOR_EXISTS: SecurityBenchmark
SB_LOCK_DOWN_SSO_PROVIDER: SecurityBenchmark
SB_CREATE_AT_LEAST_TWO_KEEPER_ADMINISTRATORS: SecurityBenchmark
SB_ENSURE_TWO_FACTOR_AUTHENTICATION_ADMIN_USERS: SecurityBenchmark
SB_ENFORCE_STRONG_MASTER_PASSWORD: SecurityBenchmark
SB_ENSURE_TWO_FACTOR_AUTHENTICATION_FOR_END_USERS: SecurityBenchmark
SB_CONFIGURE_IP_ALLOWLISTING: SecurityBenchmark
SB_CREATE_ALERTS: SecurityBenchmark
SB_DISABLE_BROWSER_PASSWORD_MANAGERS: SecurityBenchmark
SB_DISABLE_ACCOUNT_RECOVERY: SecurityBenchmark
SB_ENFORCE_LEAST_PRIVILEGE_POLICY: SecurityBenchmark
INVALID: SecurityBenchmarkStatus
RESOLVED: SecurityBenchmarkStatus
IGNORED: SecurityBenchmarkStatus
UNRESOLVED: SecurityBenchmarkStatus

class EnterpriseStat(_message.Message):
    __slots__ = ["usersLoggedRecent", "usersHasRecords"]
    USERSLOGGEDRECENT_FIELD_NUMBER: _ClassVar[int]
    USERSHASRECORDS_FIELD_NUMBER: _ClassVar[int]
    usersLoggedRecent: int
    usersHasRecords: int
    def __init__(self, usersLoggedRecent: _Optional[int] = ..., usersHasRecords: _Optional[int] = ...) -> None: ...

class EnterpriseStatDetail(_message.Message):
    __slots__ = ["enterpriseUserId", "lastLoggedIn", "hasRecords"]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    LASTLOGGEDIN_FIELD_NUMBER: _ClassVar[int]
    HASRECORDS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    lastLoggedIn: int
    hasRecords: bool
    def __init__(self, enterpriseUserId: _Optional[int] = ..., lastLoggedIn: _Optional[int] = ..., hasRecords: bool = ...) -> None: ...

class EnterpriseStatContinuationToken(_message.Message):
    __slots__ = ["lastUpdated", "enterpriseUserId"]
    LASTUPDATED_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    lastUpdated: int
    enterpriseUserId: int
    def __init__(self, lastUpdated: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ...) -> None: ...

class EnterpriseStatDetailsRequest(_message.Message):
    __slots__ = ["lastUpdated", "continuationToken"]
    LASTUPDATED_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    lastUpdated: int
    continuationToken: EnterpriseStatContinuationToken
    def __init__(self, lastUpdated: _Optional[int] = ..., continuationToken: _Optional[_Union[EnterpriseStatContinuationToken, _Mapping]] = ...) -> None: ...

class EnterpriseStatDetailsResponse(_message.Message):
    __slots__ = ["enterpriseStatDetails", "lastUpdated", "continuationToken", "hasMore"]
    ENTERPRISESTATDETAILS_FIELD_NUMBER: _ClassVar[int]
    LASTUPDATED_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    enterpriseStatDetails: _containers.RepeatedCompositeFieldContainer[EnterpriseStatDetail]
    lastUpdated: int
    continuationToken: EnterpriseStatContinuationToken
    hasMore: bool
    def __init__(self, enterpriseStatDetails: _Optional[_Iterable[_Union[EnterpriseStatDetail, _Mapping]]] = ..., lastUpdated: _Optional[int] = ..., continuationToken: _Optional[_Union[EnterpriseStatContinuationToken, _Mapping]] = ..., hasMore: bool = ...) -> None: ...

class SecurityAlertsSummary(_message.Message):
    __slots__ = ["auditEventTypeId", "currentCount", "currentUserCount", "previousCount", "previousUserCount"]
    AUDITEVENTTYPEID_FIELD_NUMBER: _ClassVar[int]
    CURRENTCOUNT_FIELD_NUMBER: _ClassVar[int]
    CURRENTUSERCOUNT_FIELD_NUMBER: _ClassVar[int]
    PREVIOUSCOUNT_FIELD_NUMBER: _ClassVar[int]
    PREVIOUSUSERCOUNT_FIELD_NUMBER: _ClassVar[int]
    auditEventTypeId: int
    currentCount: int
    currentUserCount: int
    previousCount: int
    previousUserCount: int
    def __init__(self, auditEventTypeId: _Optional[int] = ..., currentCount: _Optional[int] = ..., currentUserCount: _Optional[int] = ..., previousCount: _Optional[int] = ..., previousUserCount: _Optional[int] = ...) -> None: ...

class SecurityAlertsSummaryResponse(_message.Message):
    __slots__ = ["securityAlertsSummary"]
    SECURITYALERTSSUMMARY_FIELD_NUMBER: _ClassVar[int]
    securityAlertsSummary: _containers.RepeatedCompositeFieldContainer[SecurityAlertsSummary]
    def __init__(self, securityAlertsSummary: _Optional[_Iterable[_Union[SecurityAlertsSummary, _Mapping]]] = ...) -> None: ...

class SecurityAlertsDetailRequest(_message.Message):
    __slots__ = ["auditEventTypeId", "continuationToken"]
    AUDITEVENTTYPEID_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    auditEventTypeId: int
    continuationToken: int
    def __init__(self, auditEventTypeId: _Optional[int] = ..., continuationToken: _Optional[int] = ...) -> None: ...

class SecurityAlertsDetail(_message.Message):
    __slots__ = ["enterpriseUserId", "currentCount", "previousCount", "lastOccurrence"]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    CURRENTCOUNT_FIELD_NUMBER: _ClassVar[int]
    PREVIOUSCOUNT_FIELD_NUMBER: _ClassVar[int]
    LASTOCCURRENCE_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    currentCount: int
    previousCount: int
    lastOccurrence: int
    def __init__(self, enterpriseUserId: _Optional[int] = ..., currentCount: _Optional[int] = ..., previousCount: _Optional[int] = ..., lastOccurrence: _Optional[int] = ...) -> None: ...

class SecurityAlertsDetailResponse(_message.Message):
    __slots__ = ["securityAlertDetails", "hasMore", "continuationToken"]
    SECURITYALERTDETAILS_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    securityAlertDetails: _containers.RepeatedCompositeFieldContainer[SecurityAlertsDetail]
    hasMore: bool
    continuationToken: int
    def __init__(self, securityAlertDetails: _Optional[_Iterable[_Union[SecurityAlertsDetail, _Mapping]]] = ..., hasMore: bool = ..., continuationToken: _Optional[int] = ...) -> None: ...

class EnterpriseSecurityBenchmark(_message.Message):
    __slots__ = ["securityBenchmark", "securityBenchmarkStatus", "lastUpdated", "autoResolve"]
    SECURITYBENCHMARK_FIELD_NUMBER: _ClassVar[int]
    SECURITYBENCHMARKSTATUS_FIELD_NUMBER: _ClassVar[int]
    LASTUPDATED_FIELD_NUMBER: _ClassVar[int]
    AUTORESOLVE_FIELD_NUMBER: _ClassVar[int]
    securityBenchmark: SecurityBenchmark
    securityBenchmarkStatus: SecurityBenchmarkStatus
    lastUpdated: int
    autoResolve: bool
    def __init__(self, securityBenchmark: _Optional[_Union[SecurityBenchmark, str]] = ..., securityBenchmarkStatus: _Optional[_Union[SecurityBenchmarkStatus, str]] = ..., lastUpdated: _Optional[int] = ..., autoResolve: bool = ...) -> None: ...

class SetSecurityBenchmarksRequest(_message.Message):
    __slots__ = ["enterpriseSecurityBenchmarks"]
    ENTERPRISESECURITYBENCHMARKS_FIELD_NUMBER: _ClassVar[int]
    enterpriseSecurityBenchmarks: _containers.RepeatedCompositeFieldContainer[EnterpriseSecurityBenchmark]
    def __init__(self, enterpriseSecurityBenchmarks: _Optional[_Iterable[_Union[EnterpriseSecurityBenchmark, _Mapping]]] = ...) -> None: ...

class GetSecurityBenchmarksResponse(_message.Message):
    __slots__ = ["enterpriseSecurityBenchmarks"]
    ENTERPRISESECURITYBENCHMARKS_FIELD_NUMBER: _ClassVar[int]
    enterpriseSecurityBenchmarks: _containers.RepeatedCompositeFieldContainer[EnterpriseSecurityBenchmark]
    def __init__(self, enterpriseSecurityBenchmarks: _Optional[_Iterable[_Union[EnterpriseSecurityBenchmark, _Mapping]]] = ...) -> None: ...
