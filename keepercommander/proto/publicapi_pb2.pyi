from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ActionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NONE: _ClassVar[ActionType]
    READ: _ClassVar[ActionType]
    READ_WRITE: _ClassVar[ActionType]

class StatusFilter(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ACTIVE: _ClassVar[StatusFilter]
    INACTIVE: _ClassVar[StatusFilter]
    ALL: _ClassVar[StatusFilter]
NONE: ActionType
READ: ActionType
READ_WRITE: ActionType
ACTIVE: StatusFilter
INACTIVE: StatusFilter
ALL: StatusFilter

class Role(_message.Message):
    __slots__ = ("roleId", "actionType")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    actionType: ActionType
    def __init__(self, roleId: _Optional[int] = ..., actionType: _Optional[_Union[ActionType, str]] = ...) -> None: ...

class IntegrationRequest(_message.Message):
    __slots__ = ("apiIntegrationTypeId", "actionType")
    APIINTEGRATIONTYPEID_FIELD_NUMBER: _ClassVar[int]
    ACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    apiIntegrationTypeId: int
    actionType: ActionType
    def __init__(self, apiIntegrationTypeId: _Optional[int] = ..., actionType: _Optional[_Union[ActionType, str]] = ...) -> None: ...

class GenerateTokenRequest(_message.Message):
    __slots__ = ("roles", "tokenName", "issuedDate", "expirationDate", "integrationRequests")
    ROLES_FIELD_NUMBER: _ClassVar[int]
    TOKENNAME_FIELD_NUMBER: _ClassVar[int]
    ISSUEDDATE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    INTEGRATIONREQUESTS_FIELD_NUMBER: _ClassVar[int]
    roles: _containers.RepeatedCompositeFieldContainer[Role]
    tokenName: str
    issuedDate: int
    expirationDate: int
    integrationRequests: _containers.RepeatedCompositeFieldContainer[IntegrationRequest]
    def __init__(self, roles: _Optional[_Iterable[_Union[Role, _Mapping]]] = ..., tokenName: _Optional[str] = ..., issuedDate: _Optional[int] = ..., expirationDate: _Optional[int] = ..., integrationRequests: _Optional[_Iterable[_Union[IntegrationRequest, _Mapping]]] = ...) -> None: ...

class Integrations(_message.Message):
    __slots__ = ("roleName", "apiIntegrationTypeId", "actionType", "apiIntegrationTypeName")
    ROLENAME_FIELD_NUMBER: _ClassVar[int]
    APIINTEGRATIONTYPEID_FIELD_NUMBER: _ClassVar[int]
    ACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    APIINTEGRATIONTYPENAME_FIELD_NUMBER: _ClassVar[int]
    roleName: str
    apiIntegrationTypeId: int
    actionType: ActionType
    apiIntegrationTypeName: str
    def __init__(self, roleName: _Optional[str] = ..., apiIntegrationTypeId: _Optional[int] = ..., actionType: _Optional[_Union[ActionType, str]] = ..., apiIntegrationTypeName: _Optional[str] = ...) -> None: ...

class PublicApiToken(_message.Message):
    __slots__ = ("enterprisePublicApiTokenId", "enterprise_id", "name", "token", "active", "issuedDate", "expirationDate", "integrations")
    ENTERPRISEPUBLICAPITOKENID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISE_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    ISSUEDDATE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    INTEGRATIONS_FIELD_NUMBER: _ClassVar[int]
    enterprisePublicApiTokenId: int
    enterprise_id: int
    name: str
    token: str
    active: bool
    issuedDate: int
    expirationDate: int
    integrations: _containers.RepeatedCompositeFieldContainer[Integrations]
    def __init__(self, enterprisePublicApiTokenId: _Optional[int] = ..., enterprise_id: _Optional[int] = ..., name: _Optional[str] = ..., token: _Optional[str] = ..., active: bool = ..., issuedDate: _Optional[int] = ..., expirationDate: _Optional[int] = ..., integrations: _Optional[_Iterable[_Union[Integrations, _Mapping]]] = ...) -> None: ...

class PublicApiTokenResponse(_message.Message):
    __slots__ = ("enterprise_id", "name", "token", "active", "issuedDate", "expirationDate", "integrations")
    ENTERPRISE_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    ISSUEDDATE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    INTEGRATIONS_FIELD_NUMBER: _ClassVar[int]
    enterprise_id: int
    name: str
    token: str
    active: bool
    issuedDate: int
    expirationDate: int
    integrations: _containers.RepeatedCompositeFieldContainer[Integrations]
    def __init__(self, enterprise_id: _Optional[int] = ..., name: _Optional[str] = ..., token: _Optional[str] = ..., active: bool = ..., issuedDate: _Optional[int] = ..., expirationDate: _Optional[int] = ..., integrations: _Optional[_Iterable[_Union[Integrations, _Mapping]]] = ...) -> None: ...

class PublicApiTokenResponseList(_message.Message):
    __slots__ = ("tokens",)
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    tokens: _containers.RepeatedCompositeFieldContainer[PublicApiTokenResponse]
    def __init__(self, tokens: _Optional[_Iterable[_Union[PublicApiTokenResponse, _Mapping]]] = ...) -> None: ...

class PublicApiTokens(_message.Message):
    __slots__ = ("tokens",)
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    tokens: _containers.RepeatedCompositeFieldContainer[PublicApiToken]
    def __init__(self, tokens: _Optional[_Iterable[_Union[PublicApiToken, _Mapping]]] = ...) -> None: ...

class RevokeTokenRequest(_message.Message):
    __slots__ = ("name", "token")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    name: str
    token: str
    def __init__(self, name: _Optional[str] = ..., token: _Optional[str] = ...) -> None: ...

class RevokeTokenResponse(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class ApiIntegrationType(_message.Message):
    __slots__ = ("apiIntegrationTypeId", "roleName")
    APIINTEGRATIONTYPEID_FIELD_NUMBER: _ClassVar[int]
    ROLENAME_FIELD_NUMBER: _ClassVar[int]
    apiIntegrationTypeId: int
    roleName: str
    def __init__(self, apiIntegrationTypeId: _Optional[int] = ..., roleName: _Optional[str] = ...) -> None: ...

class ApiIntegrationTypes(_message.Message):
    __slots__ = ("apiIntegrationTypes",)
    APIINTEGRATIONTYPES_FIELD_NUMBER: _ClassVar[int]
    apiIntegrationTypes: _containers.RepeatedCompositeFieldContainer[ApiIntegrationType]
    def __init__(self, apiIntegrationTypes: _Optional[_Iterable[_Union[ApiIntegrationType, _Mapping]]] = ...) -> None: ...

class Token(_message.Message):
    __slots__ = ("enterprisePublicApiTokenId",)
    ENTERPRISEPUBLICAPITOKENID_FIELD_NUMBER: _ClassVar[int]
    enterprisePublicApiTokenId: int
    def __init__(self, enterprisePublicApiTokenId: _Optional[int] = ...) -> None: ...

class ListPublicApiTokenRequest(_message.Message):
    __slots__ = ("statusFilter", "sortByName", "nameFilter")
    STATUSFILTER_FIELD_NUMBER: _ClassVar[int]
    SORTBYNAME_FIELD_NUMBER: _ClassVar[int]
    NAMEFILTER_FIELD_NUMBER: _ClassVar[int]
    statusFilter: StatusFilter
    sortByName: str
    nameFilter: str
    def __init__(self, statusFilter: _Optional[_Union[StatusFilter, str]] = ..., sortByName: _Optional[str] = ..., nameFilter: _Optional[str] = ...) -> None: ...
