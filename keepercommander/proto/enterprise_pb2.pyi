from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class KeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RSA: _ClassVar[KeyType]
    ECC: _ClassVar[KeyType]

class RoleUserModifyStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ROLE_EXISTS: _ClassVar[RoleUserModifyStatus]
    MISSING_TREE_KEY: _ClassVar[RoleUserModifyStatus]
    MISSING_ROLE_KEY: _ClassVar[RoleUserModifyStatus]
    INVALID_ENTERPRISE_USER_ID: _ClassVar[RoleUserModifyStatus]
    PENDING_ENTERPRISE_USER: _ClassVar[RoleUserModifyStatus]
    INVALID_NODE_ID: _ClassVar[RoleUserModifyStatus]
    MAY_NOT_REMOVE_SELF_FROM_ROLE: _ClassVar[RoleUserModifyStatus]
    MUST_HAVE_ONE_USER_ADMIN: _ClassVar[RoleUserModifyStatus]
    INVALID_ROLE_ID: _ClassVar[RoleUserModifyStatus]
    PAM_LICENSE_SEAT_EXCEEDED: _ClassVar[RoleUserModifyStatus]

class EnterpriseType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENTERPRISE_STANDARD: _ClassVar[EnterpriseType]
    ENTERPRISE_MSP: _ClassVar[EnterpriseType]

class TransferAcceptanceStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNDEFINED: _ClassVar[TransferAcceptanceStatus]
    NOT_REQUIRED: _ClassVar[TransferAcceptanceStatus]
    NOT_ACCEPTED: _ClassVar[TransferAcceptanceStatus]
    PARTIALLY_ACCEPTED: _ClassVar[TransferAcceptanceStatus]
    ACCEPTED: _ClassVar[TransferAcceptanceStatus]

class EnterpriseDataEntity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[EnterpriseDataEntity]
    NODES: _ClassVar[EnterpriseDataEntity]
    ROLES: _ClassVar[EnterpriseDataEntity]
    USERS: _ClassVar[EnterpriseDataEntity]
    TEAMS: _ClassVar[EnterpriseDataEntity]
    TEAM_USERS: _ClassVar[EnterpriseDataEntity]
    ROLE_USERS: _ClassVar[EnterpriseDataEntity]
    ROLE_PRIVILEGES: _ClassVar[EnterpriseDataEntity]
    ROLE_ENFORCEMENTS: _ClassVar[EnterpriseDataEntity]
    ROLE_TEAMS: _ClassVar[EnterpriseDataEntity]
    LICENSES: _ClassVar[EnterpriseDataEntity]
    MANAGED_NODES: _ClassVar[EnterpriseDataEntity]
    MANAGED_COMPANIES: _ClassVar[EnterpriseDataEntity]
    BRIDGES: _ClassVar[EnterpriseDataEntity]
    SCIMS: _ClassVar[EnterpriseDataEntity]
    EMAIL_PROVISION: _ClassVar[EnterpriseDataEntity]
    QUEUED_TEAMS: _ClassVar[EnterpriseDataEntity]
    QUEUED_TEAM_USERS: _ClassVar[EnterpriseDataEntity]
    SSO_SERVICES: _ClassVar[EnterpriseDataEntity]
    REPORT_FILTER_USERS: _ClassVar[EnterpriseDataEntity]
    DEVICES_REQUEST_FOR_ADMIN_APPROVAL: _ClassVar[EnterpriseDataEntity]
    USER_ALIASES: _ClassVar[EnterpriseDataEntity]
    COMPLIANCE_REPORT_CRITERIA_AND_FILTER: _ClassVar[EnterpriseDataEntity]
    COMPLIANCE_REPORTS: _ClassVar[EnterpriseDataEntity]

class CacheStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    KEEP: _ClassVar[CacheStatus]
    CLEAR: _ClassVar[CacheStatus]

class BackupKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NO_KEY: _ClassVar[BackupKeyType]
    ENCRYPTED_BY_DATA_KEY: _ClassVar[BackupKeyType]
    ENCRYPTED_BY_PUBLIC_KEY: _ClassVar[BackupKeyType]
    ENCRYPTED_BY_DATA_KEY_GCM: _ClassVar[BackupKeyType]
    ENCRYPTED_BY_PUBLIC_KEY_ECC: _ClassVar[BackupKeyType]

class BackupUserDataKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OWN: _ClassVar[BackupUserDataKeyType]
    SHARED_TO_ENTERPRISE: _ClassVar[BackupUserDataKeyType]

class EncryptedKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    KT_NO_KEY: _ClassVar[EncryptedKeyType]
    KT_ENCRYPTED_BY_DATA_KEY: _ClassVar[EncryptedKeyType]
    KT_ENCRYPTED_BY_PUBLIC_KEY: _ClassVar[EncryptedKeyType]
    KT_ENCRYPTED_BY_DATA_KEY_GCM: _ClassVar[EncryptedKeyType]
    KT_ENCRYPTED_BY_PUBLIC_KEY_ECC: _ClassVar[EncryptedKeyType]

class EnterpriseFlagType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INVALID: _ClassVar[EnterpriseFlagType]
    ALLOW_PERSONAL_LICENSE: _ClassVar[EnterpriseFlagType]
    SPECIAL_PROVISIONING: _ClassVar[EnterpriseFlagType]
    RECORD_TYPES: _ClassVar[EnterpriseFlagType]
    SECRETS_MANAGER: _ClassVar[EnterpriseFlagType]
    ENTERPRISE_LOCKED: _ClassVar[EnterpriseFlagType]
    FORBID_KEY_TYPE_2: _ClassVar[EnterpriseFlagType]
    CONSOLE_ONBOARDED: _ClassVar[EnterpriseFlagType]
    FORBID_ACCOUNT_TRANSFER: _ClassVar[EnterpriseFlagType]
    NPS_POPUP_OPT_OUT: _ClassVar[EnterpriseFlagType]
    SHOW_USER_ONBOARD: _ClassVar[EnterpriseFlagType]

class UserUpdateStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    USER_UPDATE_OK: _ClassVar[UserUpdateStatus]
    USER_UPDATE_ACCESS_DENIED: _ClassVar[UserUpdateStatus]

class AuditUserStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OK: _ClassVar[AuditUserStatus]
    ACCESS_DENIED: _ClassVar[AuditUserStatus]
    NO_LONGER_IN_ENTERPRISE: _ClassVar[AuditUserStatus]

class TeamUserType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    USER: _ClassVar[TeamUserType]
    ADMIN: _ClassVar[TeamUserType]
    ADMIN_ONLY: _ClassVar[TeamUserType]

class AppClientType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NOT_USED: _ClassVar[AppClientType]
    GENERAL: _ClassVar[AppClientType]
    DISCOVERY_AND_ROTATION_CONTROLLER: _ClassVar[AppClientType]
    KCM_CONTROLLER: _ClassVar[AppClientType]
    SELF_DESTRUCT: _ClassVar[AppClientType]

class DeleteEnterpriseUsersResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SUCCESS: _ClassVar[DeleteEnterpriseUsersResult]
    NOT_AN_ENTERPRISE_USER: _ClassVar[DeleteEnterpriseUsersResult]
    CANNOT_DELETE_SELF: _ClassVar[DeleteEnterpriseUsersResult]
    BRIDGE_CANNOT_DELETE_ACTIVE_USER: _ClassVar[DeleteEnterpriseUsersResult]
    ERROR: _ClassVar[DeleteEnterpriseUsersResult]

class ClearSecurityDataType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECALCULATE_SUMMARY_REPORT: _ClassVar[ClearSecurityDataType]
    FORCE_CLIENT_CHECK_FOR_MISSING_DATA: _ClassVar[ClearSecurityDataType]
    FORCE_CLIENT_RESEND_SECURITY_DATA: _ClassVar[ClearSecurityDataType]

class ReserveDomainAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DOMAIN_TOKEN: _ClassVar[ReserveDomainAction]
    DOMAIN_ADD: _ClassVar[ReserveDomainAction]
    DOMAIN_DELETE: _ClassVar[ReserveDomainAction]
RSA: KeyType
ECC: KeyType
ROLE_EXISTS: RoleUserModifyStatus
MISSING_TREE_KEY: RoleUserModifyStatus
MISSING_ROLE_KEY: RoleUserModifyStatus
INVALID_ENTERPRISE_USER_ID: RoleUserModifyStatus
PENDING_ENTERPRISE_USER: RoleUserModifyStatus
INVALID_NODE_ID: RoleUserModifyStatus
MAY_NOT_REMOVE_SELF_FROM_ROLE: RoleUserModifyStatus
MUST_HAVE_ONE_USER_ADMIN: RoleUserModifyStatus
INVALID_ROLE_ID: RoleUserModifyStatus
PAM_LICENSE_SEAT_EXCEEDED: RoleUserModifyStatus
ENTERPRISE_STANDARD: EnterpriseType
ENTERPRISE_MSP: EnterpriseType
UNDEFINED: TransferAcceptanceStatus
NOT_REQUIRED: TransferAcceptanceStatus
NOT_ACCEPTED: TransferAcceptanceStatus
PARTIALLY_ACCEPTED: TransferAcceptanceStatus
ACCEPTED: TransferAcceptanceStatus
UNKNOWN: EnterpriseDataEntity
NODES: EnterpriseDataEntity
ROLES: EnterpriseDataEntity
USERS: EnterpriseDataEntity
TEAMS: EnterpriseDataEntity
TEAM_USERS: EnterpriseDataEntity
ROLE_USERS: EnterpriseDataEntity
ROLE_PRIVILEGES: EnterpriseDataEntity
ROLE_ENFORCEMENTS: EnterpriseDataEntity
ROLE_TEAMS: EnterpriseDataEntity
LICENSES: EnterpriseDataEntity
MANAGED_NODES: EnterpriseDataEntity
MANAGED_COMPANIES: EnterpriseDataEntity
BRIDGES: EnterpriseDataEntity
SCIMS: EnterpriseDataEntity
EMAIL_PROVISION: EnterpriseDataEntity
QUEUED_TEAMS: EnterpriseDataEntity
QUEUED_TEAM_USERS: EnterpriseDataEntity
SSO_SERVICES: EnterpriseDataEntity
REPORT_FILTER_USERS: EnterpriseDataEntity
DEVICES_REQUEST_FOR_ADMIN_APPROVAL: EnterpriseDataEntity
USER_ALIASES: EnterpriseDataEntity
COMPLIANCE_REPORT_CRITERIA_AND_FILTER: EnterpriseDataEntity
COMPLIANCE_REPORTS: EnterpriseDataEntity
KEEP: CacheStatus
CLEAR: CacheStatus
NO_KEY: BackupKeyType
ENCRYPTED_BY_DATA_KEY: BackupKeyType
ENCRYPTED_BY_PUBLIC_KEY: BackupKeyType
ENCRYPTED_BY_DATA_KEY_GCM: BackupKeyType
ENCRYPTED_BY_PUBLIC_KEY_ECC: BackupKeyType
OWN: BackupUserDataKeyType
SHARED_TO_ENTERPRISE: BackupUserDataKeyType
KT_NO_KEY: EncryptedKeyType
KT_ENCRYPTED_BY_DATA_KEY: EncryptedKeyType
KT_ENCRYPTED_BY_PUBLIC_KEY: EncryptedKeyType
KT_ENCRYPTED_BY_DATA_KEY_GCM: EncryptedKeyType
KT_ENCRYPTED_BY_PUBLIC_KEY_ECC: EncryptedKeyType
INVALID: EnterpriseFlagType
ALLOW_PERSONAL_LICENSE: EnterpriseFlagType
SPECIAL_PROVISIONING: EnterpriseFlagType
RECORD_TYPES: EnterpriseFlagType
SECRETS_MANAGER: EnterpriseFlagType
ENTERPRISE_LOCKED: EnterpriseFlagType
FORBID_KEY_TYPE_2: EnterpriseFlagType
CONSOLE_ONBOARDED: EnterpriseFlagType
FORBID_ACCOUNT_TRANSFER: EnterpriseFlagType
NPS_POPUP_OPT_OUT: EnterpriseFlagType
SHOW_USER_ONBOARD: EnterpriseFlagType
USER_UPDATE_OK: UserUpdateStatus
USER_UPDATE_ACCESS_DENIED: UserUpdateStatus
OK: AuditUserStatus
ACCESS_DENIED: AuditUserStatus
NO_LONGER_IN_ENTERPRISE: AuditUserStatus
USER: TeamUserType
ADMIN: TeamUserType
ADMIN_ONLY: TeamUserType
NOT_USED: AppClientType
GENERAL: AppClientType
DISCOVERY_AND_ROTATION_CONTROLLER: AppClientType
KCM_CONTROLLER: AppClientType
SELF_DESTRUCT: AppClientType
SUCCESS: DeleteEnterpriseUsersResult
NOT_AN_ENTERPRISE_USER: DeleteEnterpriseUsersResult
CANNOT_DELETE_SELF: DeleteEnterpriseUsersResult
BRIDGE_CANNOT_DELETE_ACTIVE_USER: DeleteEnterpriseUsersResult
ERROR: DeleteEnterpriseUsersResult
RECALCULATE_SUMMARY_REPORT: ClearSecurityDataType
FORCE_CLIENT_CHECK_FOR_MISSING_DATA: ClearSecurityDataType
FORCE_CLIENT_RESEND_SECURITY_DATA: ClearSecurityDataType
DOMAIN_TOKEN: ReserveDomainAction
DOMAIN_ADD: ReserveDomainAction
DOMAIN_DELETE: ReserveDomainAction

class EnterpriseKeyPairRequest(_message.Message):
    __slots__ = ("enterprisePublicKey", "encryptedEnterprisePrivateKey", "keyType")
    ENTERPRISEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDENTERPRISEPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    enterprisePublicKey: bytes
    encryptedEnterprisePrivateKey: bytes
    keyType: KeyType
    def __init__(self, enterprisePublicKey: _Optional[bytes] = ..., encryptedEnterprisePrivateKey: _Optional[bytes] = ..., keyType: _Optional[_Union[KeyType, str]] = ...) -> None: ...

class GetTeamMemberRequest(_message.Message):
    __slots__ = ("teamUid",)
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    def __init__(self, teamUid: _Optional[bytes] = ...) -> None: ...

class EnterpriseUser(_message.Message):
    __slots__ = ("enterpriseUserId", "email", "enterpriseUsername", "isShareAdmin", "username")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERNAME_FIELD_NUMBER: _ClassVar[int]
    ISSHAREADMIN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    email: str
    enterpriseUsername: str
    isShareAdmin: bool
    username: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., email: _Optional[str] = ..., enterpriseUsername: _Optional[str] = ..., isShareAdmin: bool = ..., username: _Optional[str] = ...) -> None: ...

class GetTeamMemberResponse(_message.Message):
    __slots__ = ("enterpriseUser",)
    ENTERPRISEUSER_FIELD_NUMBER: _ClassVar[int]
    enterpriseUser: _containers.RepeatedCompositeFieldContainer[EnterpriseUser]
    def __init__(self, enterpriseUser: _Optional[_Iterable[_Union[EnterpriseUser, _Mapping]]] = ...) -> None: ...

class EnterpriseUserIds(_message.Message):
    __slots__ = ("enterpriseUserId",)
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, enterpriseUserId: _Optional[_Iterable[int]] = ...) -> None: ...

class EnterprisePersonalAccount(_message.Message):
    __slots__ = ("email", "OBSOLETE_FIELD")
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    OBSOLETE_FIELD_FIELD_NUMBER: _ClassVar[int]
    email: str
    OBSOLETE_FIELD: bytes
    def __init__(self, email: _Optional[str] = ..., OBSOLETE_FIELD: _Optional[bytes] = ...) -> None: ...

class EncryptedTeamKeyRequest(_message.Message):
    __slots__ = ("teamUid", "encryptedTeamKey", "force")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEY_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    encryptedTeamKey: bytes
    force: bool
    def __init__(self, teamUid: _Optional[bytes] = ..., encryptedTeamKey: _Optional[bytes] = ..., force: bool = ...) -> None: ...

class ReEncryptedData(_message.Message):
    __slots__ = ("id", "data")
    ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    id: int
    data: str
    def __init__(self, id: _Optional[int] = ..., data: _Optional[str] = ...) -> None: ...

class ReEncryptedRoleKey(_message.Message):
    __slots__ = ("role_id", "encryptedRoleKey")
    ROLE_ID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDROLEKEY_FIELD_NUMBER: _ClassVar[int]
    role_id: int
    encryptedRoleKey: bytes
    def __init__(self, role_id: _Optional[int] = ..., encryptedRoleKey: _Optional[bytes] = ...) -> None: ...

class ReEncryptedUserDataKey(_message.Message):
    __slots__ = ("enterpriseUserId", "userEncryptedDataKey")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    userEncryptedDataKey: bytes
    def __init__(self, enterpriseUserId: _Optional[int] = ..., userEncryptedDataKey: _Optional[bytes] = ...) -> None: ...

class NodeToManagedCompanyRequest(_message.Message):
    __slots__ = ("companyId", "nodes", "roles", "users", "roleKeys", "teamKeys", "usersDataKeys")
    COMPANYID_FIELD_NUMBER: _ClassVar[int]
    NODES_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    ROLEKEYS_FIELD_NUMBER: _ClassVar[int]
    TEAMKEYS_FIELD_NUMBER: _ClassVar[int]
    USERSDATAKEYS_FIELD_NUMBER: _ClassVar[int]
    companyId: int
    nodes: _containers.RepeatedCompositeFieldContainer[ReEncryptedData]
    roles: _containers.RepeatedCompositeFieldContainer[ReEncryptedData]
    users: _containers.RepeatedCompositeFieldContainer[ReEncryptedData]
    roleKeys: _containers.RepeatedCompositeFieldContainer[ReEncryptedRoleKey]
    teamKeys: _containers.RepeatedCompositeFieldContainer[EncryptedTeamKeyRequest]
    usersDataKeys: _containers.RepeatedCompositeFieldContainer[ReEncryptedUserDataKey]
    def __init__(self, companyId: _Optional[int] = ..., nodes: _Optional[_Iterable[_Union[ReEncryptedData, _Mapping]]] = ..., roles: _Optional[_Iterable[_Union[ReEncryptedData, _Mapping]]] = ..., users: _Optional[_Iterable[_Union[ReEncryptedData, _Mapping]]] = ..., roleKeys: _Optional[_Iterable[_Union[ReEncryptedRoleKey, _Mapping]]] = ..., teamKeys: _Optional[_Iterable[_Union[EncryptedTeamKeyRequest, _Mapping]]] = ..., usersDataKeys: _Optional[_Iterable[_Union[ReEncryptedUserDataKey, _Mapping]]] = ...) -> None: ...

class RoleTeam(_message.Message):
    __slots__ = ("role_id", "teamUid")
    ROLE_ID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    role_id: int
    teamUid: bytes
    def __init__(self, role_id: _Optional[int] = ..., teamUid: _Optional[bytes] = ...) -> None: ...

class RoleTeams(_message.Message):
    __slots__ = ("role_team",)
    ROLE_TEAM_FIELD_NUMBER: _ClassVar[int]
    role_team: _containers.RepeatedCompositeFieldContainer[RoleTeam]
    def __init__(self, role_team: _Optional[_Iterable[_Union[RoleTeam, _Mapping]]] = ...) -> None: ...

class TeamsByRole(_message.Message):
    __slots__ = ("role_id", "teamUid")
    ROLE_ID_FIELD_NUMBER: _ClassVar[int]
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    role_id: int
    teamUid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, role_id: _Optional[int] = ..., teamUid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class ManagedNodesByRole(_message.Message):
    __slots__ = ("role_id", "managedNodeId")
    ROLE_ID_FIELD_NUMBER: _ClassVar[int]
    MANAGEDNODEID_FIELD_NUMBER: _ClassVar[int]
    role_id: int
    managedNodeId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, role_id: _Optional[int] = ..., managedNodeId: _Optional[_Iterable[int]] = ...) -> None: ...

class RoleUserAddKeys(_message.Message):
    __slots__ = ("enterpriseUserId", "treeKey", "roleAdminKey")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    TREEKEY_FIELD_NUMBER: _ClassVar[int]
    ROLEADMINKEY_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    treeKey: str
    roleAdminKey: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., treeKey: _Optional[str] = ..., roleAdminKey: _Optional[str] = ...) -> None: ...

class RoleUserAdd(_message.Message):
    __slots__ = ("role_id", "roleUserAddKeys")
    ROLE_ID_FIELD_NUMBER: _ClassVar[int]
    ROLEUSERADDKEYS_FIELD_NUMBER: _ClassVar[int]
    role_id: int
    roleUserAddKeys: _containers.RepeatedCompositeFieldContainer[RoleUserAddKeys]
    def __init__(self, role_id: _Optional[int] = ..., roleUserAddKeys: _Optional[_Iterable[_Union[RoleUserAddKeys, _Mapping]]] = ...) -> None: ...

class RoleUsersAddRequest(_message.Message):
    __slots__ = ("roleUserAdds",)
    ROLEUSERADDS_FIELD_NUMBER: _ClassVar[int]
    roleUserAdds: _containers.RepeatedCompositeFieldContainer[RoleUserAdd]
    def __init__(self, roleUserAdds: _Optional[_Iterable[_Union[RoleUserAdd, _Mapping]]] = ...) -> None: ...

class RoleUserAddResult(_message.Message):
    __slots__ = ("roleId", "enterpriseUserId", "status", "message")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    enterpriseUserId: int
    status: RoleUserModifyStatus
    message: str
    def __init__(self, roleId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ..., status: _Optional[_Union[RoleUserModifyStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class RoleUsersAddResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[RoleUserAddResult]
    def __init__(self, results: _Optional[_Iterable[_Union[RoleUserAddResult, _Mapping]]] = ...) -> None: ...

class RoleUserRemove(_message.Message):
    __slots__ = ("role_id", "enterpriseUserIds")
    ROLE_ID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    role_id: int
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, role_id: _Optional[int] = ..., enterpriseUserIds: _Optional[_Iterable[int]] = ...) -> None: ...

class RoleUsersRemoveRequest(_message.Message):
    __slots__ = ("roleUserRemoves",)
    ROLEUSERREMOVES_FIELD_NUMBER: _ClassVar[int]
    roleUserRemoves: _containers.RepeatedCompositeFieldContainer[RoleUserRemove]
    def __init__(self, roleUserRemoves: _Optional[_Iterable[_Union[RoleUserRemove, _Mapping]]] = ...) -> None: ...

class RoleUserRemoveResult(_message.Message):
    __slots__ = ("roleId", "enterpriseUserId", "status", "message")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    enterpriseUserId: int
    status: RoleUserModifyStatus
    message: str
    def __init__(self, roleId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ..., status: _Optional[_Union[RoleUserModifyStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class RoleUsersRemoveResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[RoleUserRemoveResult]
    def __init__(self, results: _Optional[_Iterable[_Union[RoleUserRemoveResult, _Mapping]]] = ...) -> None: ...

class EnterpriseRegistration(_message.Message):
    __slots__ = ("encryptedTreeKey", "enterpriseName", "rootNodeData", "adminUserData", "adminName", "roleData", "rsaKeyPair", "numberSeats", "enterpriseType", "rolePublicKey", "rolePrivateKeyEncryptedWithRoleKey", "roleKeyEncryptedWithTreeKey", "eccKeyPair", "allUsersRoleData", "roleKeyEncryptedWithUserPublicKey", "approverRoleData")
    ENCRYPTEDTREEKEY_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    ROOTNODEDATA_FIELD_NUMBER: _ClassVar[int]
    ADMINUSERDATA_FIELD_NUMBER: _ClassVar[int]
    ADMINNAME_FIELD_NUMBER: _ClassVar[int]
    ROLEDATA_FIELD_NUMBER: _ClassVar[int]
    RSAKEYPAIR_FIELD_NUMBER: _ClassVar[int]
    NUMBERSEATS_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISETYPE_FIELD_NUMBER: _ClassVar[int]
    ROLEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ROLEPRIVATEKEYENCRYPTEDWITHROLEKEY_FIELD_NUMBER: _ClassVar[int]
    ROLEKEYENCRYPTEDWITHTREEKEY_FIELD_NUMBER: _ClassVar[int]
    ECCKEYPAIR_FIELD_NUMBER: _ClassVar[int]
    ALLUSERSROLEDATA_FIELD_NUMBER: _ClassVar[int]
    ROLEKEYENCRYPTEDWITHUSERPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    APPROVERROLEDATA_FIELD_NUMBER: _ClassVar[int]
    encryptedTreeKey: bytes
    enterpriseName: str
    rootNodeData: bytes
    adminUserData: bytes
    adminName: str
    roleData: bytes
    rsaKeyPair: EnterpriseKeyPairRequest
    numberSeats: int
    enterpriseType: EnterpriseType
    rolePublicKey: bytes
    rolePrivateKeyEncryptedWithRoleKey: bytes
    roleKeyEncryptedWithTreeKey: bytes
    eccKeyPair: EnterpriseKeyPairRequest
    allUsersRoleData: bytes
    roleKeyEncryptedWithUserPublicKey: bytes
    approverRoleData: bytes
    def __init__(self, encryptedTreeKey: _Optional[bytes] = ..., enterpriseName: _Optional[str] = ..., rootNodeData: _Optional[bytes] = ..., adminUserData: _Optional[bytes] = ..., adminName: _Optional[str] = ..., roleData: _Optional[bytes] = ..., rsaKeyPair: _Optional[_Union[EnterpriseKeyPairRequest, _Mapping]] = ..., numberSeats: _Optional[int] = ..., enterpriseType: _Optional[_Union[EnterpriseType, str]] = ..., rolePublicKey: _Optional[bytes] = ..., rolePrivateKeyEncryptedWithRoleKey: _Optional[bytes] = ..., roleKeyEncryptedWithTreeKey: _Optional[bytes] = ..., eccKeyPair: _Optional[_Union[EnterpriseKeyPairRequest, _Mapping]] = ..., allUsersRoleData: _Optional[bytes] = ..., roleKeyEncryptedWithUserPublicKey: _Optional[bytes] = ..., approverRoleData: _Optional[bytes] = ...) -> None: ...

class DomainPasswordRulesRequest(_message.Message):
    __slots__ = ("username", "verificationCode")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    username: str
    verificationCode: str
    def __init__(self, username: _Optional[str] = ..., verificationCode: _Optional[str] = ...) -> None: ...

class DomainPasswordRulesFields(_message.Message):
    __slots__ = ("type", "minimum", "maximum", "allowed")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_FIELD_NUMBER: _ClassVar[int]
    MAXIMUM_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_FIELD_NUMBER: _ClassVar[int]
    type: str
    minimum: int
    maximum: int
    allowed: bool
    def __init__(self, type: _Optional[str] = ..., minimum: _Optional[int] = ..., maximum: _Optional[int] = ..., allowed: bool = ...) -> None: ...

class LoginToMcRequest(_message.Message):
    __slots__ = ("mcEnterpriseId", "messageSessionUid")
    MCENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    mcEnterpriseId: int
    messageSessionUid: bytes
    def __init__(self, mcEnterpriseId: _Optional[int] = ..., messageSessionUid: _Optional[bytes] = ...) -> None: ...

class LoginToMcResponse(_message.Message):
    __slots__ = ("encryptedSessionToken", "encryptedTreeKey")
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTREEKEY_FIELD_NUMBER: _ClassVar[int]
    encryptedSessionToken: bytes
    encryptedTreeKey: str
    def __init__(self, encryptedSessionToken: _Optional[bytes] = ..., encryptedTreeKey: _Optional[str] = ...) -> None: ...

class DomainPasswordRulesResponse(_message.Message):
    __slots__ = ("domainPasswordRulesFields",)
    DOMAINPASSWORDRULESFIELDS_FIELD_NUMBER: _ClassVar[int]
    domainPasswordRulesFields: _containers.RepeatedCompositeFieldContainer[DomainPasswordRulesFields]
    def __init__(self, domainPasswordRulesFields: _Optional[_Iterable[_Union[DomainPasswordRulesFields, _Mapping]]] = ...) -> None: ...

class ApproveUserDeviceRequest(_message.Message):
    __slots__ = ("enterpriseUserId", "encryptedDeviceToken", "encryptedDeviceDataKey", "denyApproval")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICEDATAKEY_FIELD_NUMBER: _ClassVar[int]
    DENYAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    encryptedDeviceToken: bytes
    encryptedDeviceDataKey: bytes
    denyApproval: bool
    def __init__(self, enterpriseUserId: _Optional[int] = ..., encryptedDeviceToken: _Optional[bytes] = ..., encryptedDeviceDataKey: _Optional[bytes] = ..., denyApproval: bool = ...) -> None: ...

class ApproveUserDeviceResponse(_message.Message):
    __slots__ = ("enterpriseUserId", "encryptedDeviceToken", "failed", "message")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    FAILED_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    encryptedDeviceToken: bytes
    failed: bool
    message: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., encryptedDeviceToken: _Optional[bytes] = ..., failed: bool = ..., message: _Optional[str] = ...) -> None: ...

class ApproveUserDevicesRequest(_message.Message):
    __slots__ = ("deviceRequests",)
    DEVICEREQUESTS_FIELD_NUMBER: _ClassVar[int]
    deviceRequests: _containers.RepeatedCompositeFieldContainer[ApproveUserDeviceRequest]
    def __init__(self, deviceRequests: _Optional[_Iterable[_Union[ApproveUserDeviceRequest, _Mapping]]] = ...) -> None: ...

class ApproveUserDevicesResponse(_message.Message):
    __slots__ = ("deviceResponses",)
    DEVICERESPONSES_FIELD_NUMBER: _ClassVar[int]
    deviceResponses: _containers.RepeatedCompositeFieldContainer[ApproveUserDeviceResponse]
    def __init__(self, deviceResponses: _Optional[_Iterable[_Union[ApproveUserDeviceResponse, _Mapping]]] = ...) -> None: ...

class EnterpriseUserDataKey(_message.Message):
    __slots__ = ("enterpriseUserId", "userEncryptedDataKey", "keyTypeId", "roleKey", "privateKey")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPEID_FIELD_NUMBER: _ClassVar[int]
    ROLEKEY_FIELD_NUMBER: _ClassVar[int]
    PRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    userEncryptedDataKey: bytes
    keyTypeId: int
    roleKey: bytes
    privateKey: bytes
    def __init__(self, enterpriseUserId: _Optional[int] = ..., userEncryptedDataKey: _Optional[bytes] = ..., keyTypeId: _Optional[int] = ..., roleKey: _Optional[bytes] = ..., privateKey: _Optional[bytes] = ...) -> None: ...

class EnterpriseUserDataKeys(_message.Message):
    __slots__ = ("keys",)
    KEYS_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[EnterpriseUserDataKey]
    def __init__(self, keys: _Optional[_Iterable[_Union[EnterpriseUserDataKey, _Mapping]]] = ...) -> None: ...

class EnterpriseUserDataKeyLight(_message.Message):
    __slots__ = ("enterpriseUserId", "userEncryptedDataKey", "keyTypeId")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPEID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    userEncryptedDataKey: bytes
    keyTypeId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ..., userEncryptedDataKey: _Optional[bytes] = ..., keyTypeId: _Optional[int] = ...) -> None: ...

class EnterpriseUserDataKeysByNode(_message.Message):
    __slots__ = ("nodeId", "keys")
    NODEID_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    keys: _containers.RepeatedCompositeFieldContainer[EnterpriseUserDataKeyLight]
    def __init__(self, nodeId: _Optional[int] = ..., keys: _Optional[_Iterable[_Union[EnterpriseUserDataKeyLight, _Mapping]]] = ...) -> None: ...

class EnterpriseUserDataKeysByNodeResponse(_message.Message):
    __slots__ = ("keys",)
    KEYS_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[EnterpriseUserDataKeysByNode]
    def __init__(self, keys: _Optional[_Iterable[_Union[EnterpriseUserDataKeysByNode, _Mapping]]] = ...) -> None: ...

class EnterpriseDataRequest(_message.Message):
    __slots__ = ("continuationToken",)
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    def __init__(self, continuationToken: _Optional[bytes] = ...) -> None: ...

class SpecialProvisioning(_message.Message):
    __slots__ = ("url", "name")
    URL_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    url: str
    name: str
    def __init__(self, url: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class GeneralDataEntity(_message.Message):
    __slots__ = ("enterpriseName", "restrictVisibility", "specialProvisioning", "userPrivilege", "distributor", "forbidAccountTransfer", "showUserOnboard")
    ENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    RESTRICTVISIBILITY_FIELD_NUMBER: _ClassVar[int]
    SPECIALPROVISIONING_FIELD_NUMBER: _ClassVar[int]
    USERPRIVILEGE_FIELD_NUMBER: _ClassVar[int]
    DISTRIBUTOR_FIELD_NUMBER: _ClassVar[int]
    FORBIDACCOUNTTRANSFER_FIELD_NUMBER: _ClassVar[int]
    SHOWUSERONBOARD_FIELD_NUMBER: _ClassVar[int]
    enterpriseName: str
    restrictVisibility: bool
    specialProvisioning: SpecialProvisioning
    userPrivilege: UserPrivilege
    distributor: bool
    forbidAccountTransfer: bool
    showUserOnboard: bool
    def __init__(self, enterpriseName: _Optional[str] = ..., restrictVisibility: bool = ..., specialProvisioning: _Optional[_Union[SpecialProvisioning, _Mapping]] = ..., userPrivilege: _Optional[_Union[UserPrivilege, _Mapping]] = ..., distributor: bool = ..., forbidAccountTransfer: bool = ..., showUserOnboard: bool = ...) -> None: ...

class Node(_message.Message):
    __slots__ = ("nodeId", "parentId", "bridgeId", "scimId", "licenseId", "encryptedData", "duoEnabled", "rsaEnabled", "ssoServiceProviderId", "restrictVisibility", "ssoServiceProviderIds")
    NODEID_FIELD_NUMBER: _ClassVar[int]
    PARENTID_FIELD_NUMBER: _ClassVar[int]
    BRIDGEID_FIELD_NUMBER: _ClassVar[int]
    SCIMID_FIELD_NUMBER: _ClassVar[int]
    LICENSEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    DUOENABLED_FIELD_NUMBER: _ClassVar[int]
    RSAENABLED_FIELD_NUMBER: _ClassVar[int]
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    RESTRICTVISIBILITY_FIELD_NUMBER: _ClassVar[int]
    SSOSERVICEPROVIDERIDS_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    parentId: int
    bridgeId: int
    scimId: int
    licenseId: int
    encryptedData: str
    duoEnabled: bool
    rsaEnabled: bool
    ssoServiceProviderId: int
    restrictVisibility: bool
    ssoServiceProviderIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, nodeId: _Optional[int] = ..., parentId: _Optional[int] = ..., bridgeId: _Optional[int] = ..., scimId: _Optional[int] = ..., licenseId: _Optional[int] = ..., encryptedData: _Optional[str] = ..., duoEnabled: bool = ..., rsaEnabled: bool = ..., ssoServiceProviderId: _Optional[int] = ..., restrictVisibility: bool = ..., ssoServiceProviderIds: _Optional[_Iterable[int]] = ...) -> None: ...

class Role(_message.Message):
    __slots__ = ("roleId", "nodeId", "encryptedData", "keyType", "visibleBelow", "newUserInherit", "roleType")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    VISIBLEBELOW_FIELD_NUMBER: _ClassVar[int]
    NEWUSERINHERIT_FIELD_NUMBER: _ClassVar[int]
    ROLETYPE_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    nodeId: int
    encryptedData: str
    keyType: str
    visibleBelow: bool
    newUserInherit: bool
    roleType: str
    def __init__(self, roleId: _Optional[int] = ..., nodeId: _Optional[int] = ..., encryptedData: _Optional[str] = ..., keyType: _Optional[str] = ..., visibleBelow: bool = ..., newUserInherit: bool = ..., roleType: _Optional[str] = ...) -> None: ...

class User(_message.Message):
    __slots__ = ("enterpriseUserId", "nodeId", "encryptedData", "keyType", "username", "status", "lock", "userId", "accountShareExpiration", "fullName", "jobTitle", "tfaEnabled", "transferAcceptanceStatus")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LOCK_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTSHAREEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    JOBTITLE_FIELD_NUMBER: _ClassVar[int]
    TFAENABLED_FIELD_NUMBER: _ClassVar[int]
    TRANSFERACCEPTANCESTATUS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    nodeId: int
    encryptedData: str
    keyType: str
    username: str
    status: str
    lock: int
    userId: int
    accountShareExpiration: int
    fullName: str
    jobTitle: str
    tfaEnabled: bool
    transferAcceptanceStatus: TransferAcceptanceStatus
    def __init__(self, enterpriseUserId: _Optional[int] = ..., nodeId: _Optional[int] = ..., encryptedData: _Optional[str] = ..., keyType: _Optional[str] = ..., username: _Optional[str] = ..., status: _Optional[str] = ..., lock: _Optional[int] = ..., userId: _Optional[int] = ..., accountShareExpiration: _Optional[int] = ..., fullName: _Optional[str] = ..., jobTitle: _Optional[str] = ..., tfaEnabled: bool = ..., transferAcceptanceStatus: _Optional[_Union[TransferAcceptanceStatus, str]] = ...) -> None: ...

class UserAlias(_message.Message):
    __slots__ = ("enterpriseUserId", "username")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    username: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., username: _Optional[str] = ...) -> None: ...

class ComplianceReportMetaData(_message.Message):
    __slots__ = ("reportUid", "nodeId", "reportName", "dateGenerated", "runByName", "numberOfOwners", "numberOfRecords")
    REPORTUID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    REPORTNAME_FIELD_NUMBER: _ClassVar[int]
    DATEGENERATED_FIELD_NUMBER: _ClassVar[int]
    RUNBYNAME_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFOWNERS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFRECORDS_FIELD_NUMBER: _ClassVar[int]
    reportUid: bytes
    nodeId: int
    reportName: str
    dateGenerated: int
    runByName: str
    numberOfOwners: int
    numberOfRecords: int
    def __init__(self, reportUid: _Optional[bytes] = ..., nodeId: _Optional[int] = ..., reportName: _Optional[str] = ..., dateGenerated: _Optional[int] = ..., runByName: _Optional[str] = ..., numberOfOwners: _Optional[int] = ..., numberOfRecords: _Optional[int] = ...) -> None: ...

class ManagedNode(_message.Message):
    __slots__ = ("roleId", "managedNodeId", "cascadeNodeManagement")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    MANAGEDNODEID_FIELD_NUMBER: _ClassVar[int]
    CASCADENODEMANAGEMENT_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    managedNodeId: int
    cascadeNodeManagement: bool
    def __init__(self, roleId: _Optional[int] = ..., managedNodeId: _Optional[int] = ..., cascadeNodeManagement: bool = ...) -> None: ...

class UserManagedNode(_message.Message):
    __slots__ = ("nodeId", "cascadeNodeManagement", "privileges")
    NODEID_FIELD_NUMBER: _ClassVar[int]
    CASCADENODEMANAGEMENT_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGES_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    cascadeNodeManagement: bool
    privileges: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, nodeId: _Optional[int] = ..., cascadeNodeManagement: bool = ..., privileges: _Optional[_Iterable[str]] = ...) -> None: ...

class UserPrivilege(_message.Message):
    __slots__ = ("userManagedNodes", "enterpriseUserId", "encryptedData")
    USERMANAGEDNODES_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    userManagedNodes: _containers.RepeatedCompositeFieldContainer[UserManagedNode]
    enterpriseUserId: int
    encryptedData: str
    def __init__(self, userManagedNodes: _Optional[_Iterable[_Union[UserManagedNode, _Mapping]]] = ..., enterpriseUserId: _Optional[int] = ..., encryptedData: _Optional[str] = ...) -> None: ...

class RoleUser(_message.Message):
    __slots__ = ("roleId", "enterpriseUserId")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    enterpriseUserId: int
    def __init__(self, roleId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ...) -> None: ...

class RolePrivilege(_message.Message):
    __slots__ = ("managedNodeId", "roleId", "privilegeType")
    MANAGEDNODEID_FIELD_NUMBER: _ClassVar[int]
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGETYPE_FIELD_NUMBER: _ClassVar[int]
    managedNodeId: int
    roleId: int
    privilegeType: str
    def __init__(self, managedNodeId: _Optional[int] = ..., roleId: _Optional[int] = ..., privilegeType: _Optional[str] = ...) -> None: ...

class RoleEnforcement(_message.Message):
    __slots__ = ("roleId", "enforcementType", "value")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ENFORCEMENTTYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    enforcementType: str
    value: str
    def __init__(self, roleId: _Optional[int] = ..., enforcementType: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class Team(_message.Message):
    __slots__ = ("teamUid", "name", "nodeId", "restrictEdit", "restrictShare", "restrictView", "encryptedData", "encryptedTeamKey")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    RESTRICTEDIT_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHARE_FIELD_NUMBER: _ClassVar[int]
    RESTRICTVIEW_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTEAMKEY_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    name: str
    nodeId: int
    restrictEdit: bool
    restrictShare: bool
    restrictView: bool
    encryptedData: str
    encryptedTeamKey: str
    def __init__(self, teamUid: _Optional[bytes] = ..., name: _Optional[str] = ..., nodeId: _Optional[int] = ..., restrictEdit: bool = ..., restrictShare: bool = ..., restrictView: bool = ..., encryptedData: _Optional[str] = ..., encryptedTeamKey: _Optional[str] = ...) -> None: ...

class TeamUser(_message.Message):
    __slots__ = ("teamUid", "enterpriseUserId", "userType")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERTYPE_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    enterpriseUserId: int
    userType: str
    def __init__(self, teamUid: _Optional[bytes] = ..., enterpriseUserId: _Optional[int] = ..., userType: _Optional[str] = ...) -> None: ...

class GetDistributorInfoResponse(_message.Message):
    __slots__ = ("distributors",)
    DISTRIBUTORS_FIELD_NUMBER: _ClassVar[int]
    distributors: _containers.RepeatedCompositeFieldContainer[Distributor]
    def __init__(self, distributors: _Optional[_Iterable[_Union[Distributor, _Mapping]]] = ...) -> None: ...

class Distributor(_message.Message):
    __slots__ = ("name", "mspInfos")
    NAME_FIELD_NUMBER: _ClassVar[int]
    MSPINFOS_FIELD_NUMBER: _ClassVar[int]
    name: str
    mspInfos: _containers.RepeatedCompositeFieldContainer[MspInfo]
    def __init__(self, name: _Optional[str] = ..., mspInfos: _Optional[_Iterable[_Union[MspInfo, _Mapping]]] = ...) -> None: ...

class MspInfo(_message.Message):
    __slots__ = ("enterpriseId", "enterpriseName", "allocatedLicenses", "allowedMcProducts", "allowedAddOns", "maxFilePlanType", "managedCompanies", "allowUnlimitedLicenses", "addOns")
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    ALLOCATEDLICENSES_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDMCPRODUCTS_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDADDONS_FIELD_NUMBER: _ClassVar[int]
    MAXFILEPLANTYPE_FIELD_NUMBER: _ClassVar[int]
    MANAGEDCOMPANIES_FIELD_NUMBER: _ClassVar[int]
    ALLOWUNLIMITEDLICENSES_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    enterpriseName: str
    allocatedLicenses: int
    allowedMcProducts: _containers.RepeatedScalarFieldContainer[str]
    allowedAddOns: _containers.RepeatedScalarFieldContainer[str]
    maxFilePlanType: str
    managedCompanies: _containers.RepeatedCompositeFieldContainer[ManagedCompany]
    allowUnlimitedLicenses: bool
    addOns: _containers.RepeatedCompositeFieldContainer[LicenseAddOn]
    def __init__(self, enterpriseId: _Optional[int] = ..., enterpriseName: _Optional[str] = ..., allocatedLicenses: _Optional[int] = ..., allowedMcProducts: _Optional[_Iterable[str]] = ..., allowedAddOns: _Optional[_Iterable[str]] = ..., maxFilePlanType: _Optional[str] = ..., managedCompanies: _Optional[_Iterable[_Union[ManagedCompany, _Mapping]]] = ..., allowUnlimitedLicenses: bool = ..., addOns: _Optional[_Iterable[_Union[LicenseAddOn, _Mapping]]] = ...) -> None: ...

class ManagedCompany(_message.Message):
    __slots__ = ("mcEnterpriseId", "mcEnterpriseName", "mspNodeId", "numberOfSeats", "numberOfUsers", "productId", "isExpired", "treeKey", "tree_key_role", "filePlanType", "addOns")
    MCENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    MSPNODEID_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSEATS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFUSERS_FIELD_NUMBER: _ClassVar[int]
    PRODUCTID_FIELD_NUMBER: _ClassVar[int]
    ISEXPIRED_FIELD_NUMBER: _ClassVar[int]
    TREEKEY_FIELD_NUMBER: _ClassVar[int]
    TREE_KEY_ROLE_FIELD_NUMBER: _ClassVar[int]
    FILEPLANTYPE_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    mcEnterpriseId: int
    mcEnterpriseName: str
    mspNodeId: int
    numberOfSeats: int
    numberOfUsers: int
    productId: str
    isExpired: bool
    treeKey: str
    tree_key_role: int
    filePlanType: str
    addOns: _containers.RepeatedCompositeFieldContainer[LicenseAddOn]
    def __init__(self, mcEnterpriseId: _Optional[int] = ..., mcEnterpriseName: _Optional[str] = ..., mspNodeId: _Optional[int] = ..., numberOfSeats: _Optional[int] = ..., numberOfUsers: _Optional[int] = ..., productId: _Optional[str] = ..., isExpired: bool = ..., treeKey: _Optional[str] = ..., tree_key_role: _Optional[int] = ..., filePlanType: _Optional[str] = ..., addOns: _Optional[_Iterable[_Union[LicenseAddOn, _Mapping]]] = ...) -> None: ...

class MSPPool(_message.Message):
    __slots__ = ("productId", "seats", "availableSeats", "stash")
    PRODUCTID_FIELD_NUMBER: _ClassVar[int]
    SEATS_FIELD_NUMBER: _ClassVar[int]
    AVAILABLESEATS_FIELD_NUMBER: _ClassVar[int]
    STASH_FIELD_NUMBER: _ClassVar[int]
    productId: str
    seats: int
    availableSeats: int
    stash: int
    def __init__(self, productId: _Optional[str] = ..., seats: _Optional[int] = ..., availableSeats: _Optional[int] = ..., stash: _Optional[int] = ...) -> None: ...

class MSPContact(_message.Message):
    __slots__ = ("enterpriseId", "enterpriseName")
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISENAME_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    enterpriseName: str
    def __init__(self, enterpriseId: _Optional[int] = ..., enterpriseName: _Optional[str] = ...) -> None: ...

class LicenseAddOn(_message.Message):
    __slots__ = ("name", "enabled", "isTrial", "expiration", "created", "seats", "activationTime", "includedInProduct", "apiCallCount", "tierDescription", "seatsAllocated")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    ISTRIAL_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    SEATS_FIELD_NUMBER: _ClassVar[int]
    ACTIVATIONTIME_FIELD_NUMBER: _ClassVar[int]
    INCLUDEDINPRODUCT_FIELD_NUMBER: _ClassVar[int]
    APICALLCOUNT_FIELD_NUMBER: _ClassVar[int]
    TIERDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SEATSALLOCATED_FIELD_NUMBER: _ClassVar[int]
    name: str
    enabled: bool
    isTrial: bool
    expiration: int
    created: int
    seats: int
    activationTime: int
    includedInProduct: bool
    apiCallCount: int
    tierDescription: str
    seatsAllocated: int
    def __init__(self, name: _Optional[str] = ..., enabled: bool = ..., isTrial: bool = ..., expiration: _Optional[int] = ..., created: _Optional[int] = ..., seats: _Optional[int] = ..., activationTime: _Optional[int] = ..., includedInProduct: bool = ..., apiCallCount: _Optional[int] = ..., tierDescription: _Optional[str] = ..., seatsAllocated: _Optional[int] = ...) -> None: ...

class MCDefault(_message.Message):
    __slots__ = ("mcProduct", "addOns", "filePlanType", "maxLicenses", "fixedMaxLicenses")
    MCPRODUCT_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANTYPE_FIELD_NUMBER: _ClassVar[int]
    MAXLICENSES_FIELD_NUMBER: _ClassVar[int]
    FIXEDMAXLICENSES_FIELD_NUMBER: _ClassVar[int]
    mcProduct: str
    addOns: _containers.RepeatedScalarFieldContainer[str]
    filePlanType: str
    maxLicenses: int
    fixedMaxLicenses: bool
    def __init__(self, mcProduct: _Optional[str] = ..., addOns: _Optional[_Iterable[str]] = ..., filePlanType: _Optional[str] = ..., maxLicenses: _Optional[int] = ..., fixedMaxLicenses: bool = ...) -> None: ...

class MSPPermits(_message.Message):
    __slots__ = ("restricted", "maxAllowedLicenses", "allowedMcProducts", "allowedAddOns", "maxFilePlanType", "allowUnlimitedLicenses", "mcDefaults")
    RESTRICTED_FIELD_NUMBER: _ClassVar[int]
    MAXALLOWEDLICENSES_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDMCPRODUCTS_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDADDONS_FIELD_NUMBER: _ClassVar[int]
    MAXFILEPLANTYPE_FIELD_NUMBER: _ClassVar[int]
    ALLOWUNLIMITEDLICENSES_FIELD_NUMBER: _ClassVar[int]
    MCDEFAULTS_FIELD_NUMBER: _ClassVar[int]
    restricted: bool
    maxAllowedLicenses: int
    allowedMcProducts: _containers.RepeatedScalarFieldContainer[str]
    allowedAddOns: _containers.RepeatedScalarFieldContainer[str]
    maxFilePlanType: str
    allowUnlimitedLicenses: bool
    mcDefaults: _containers.RepeatedCompositeFieldContainer[MCDefault]
    def __init__(self, restricted: bool = ..., maxAllowedLicenses: _Optional[int] = ..., allowedMcProducts: _Optional[_Iterable[str]] = ..., allowedAddOns: _Optional[_Iterable[str]] = ..., maxFilePlanType: _Optional[str] = ..., allowUnlimitedLicenses: bool = ..., mcDefaults: _Optional[_Iterable[_Union[MCDefault, _Mapping]]] = ...) -> None: ...

class License(_message.Message):
    __slots__ = ("paid", "numberOfSeats", "expiration", "licenseKeyId", "productTypeId", "name", "enterpriseLicenseId", "seatsAllocated", "seatsPending", "tier", "filePlanTypeId", "maxBytes", "storageExpiration", "licenseStatus", "mspPool", "managedBy", "addOns", "nextBillingDate", "hasMSPLegacyLog", "mspPermits", "distributor")
    PAID_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSEATS_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    LICENSEKEYID_FIELD_NUMBER: _ClassVar[int]
    PRODUCTTYPEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISELICENSEID_FIELD_NUMBER: _ClassVar[int]
    SEATSALLOCATED_FIELD_NUMBER: _ClassVar[int]
    SEATSPENDING_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    FILEPLANTYPEID_FIELD_NUMBER: _ClassVar[int]
    MAXBYTES_FIELD_NUMBER: _ClassVar[int]
    STORAGEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    LICENSESTATUS_FIELD_NUMBER: _ClassVar[int]
    MSPPOOL_FIELD_NUMBER: _ClassVar[int]
    MANAGEDBY_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    NEXTBILLINGDATE_FIELD_NUMBER: _ClassVar[int]
    HASMSPLEGACYLOG_FIELD_NUMBER: _ClassVar[int]
    MSPPERMITS_FIELD_NUMBER: _ClassVar[int]
    DISTRIBUTOR_FIELD_NUMBER: _ClassVar[int]
    paid: bool
    numberOfSeats: int
    expiration: int
    licenseKeyId: int
    productTypeId: int
    name: str
    enterpriseLicenseId: int
    seatsAllocated: int
    seatsPending: int
    tier: int
    filePlanTypeId: int
    maxBytes: int
    storageExpiration: int
    licenseStatus: str
    mspPool: _containers.RepeatedCompositeFieldContainer[MSPPool]
    managedBy: MSPContact
    addOns: _containers.RepeatedCompositeFieldContainer[LicenseAddOn]
    nextBillingDate: int
    hasMSPLegacyLog: bool
    mspPermits: MSPPermits
    distributor: bool
    def __init__(self, paid: bool = ..., numberOfSeats: _Optional[int] = ..., expiration: _Optional[int] = ..., licenseKeyId: _Optional[int] = ..., productTypeId: _Optional[int] = ..., name: _Optional[str] = ..., enterpriseLicenseId: _Optional[int] = ..., seatsAllocated: _Optional[int] = ..., seatsPending: _Optional[int] = ..., tier: _Optional[int] = ..., filePlanTypeId: _Optional[int] = ..., maxBytes: _Optional[int] = ..., storageExpiration: _Optional[int] = ..., licenseStatus: _Optional[str] = ..., mspPool: _Optional[_Iterable[_Union[MSPPool, _Mapping]]] = ..., managedBy: _Optional[_Union[MSPContact, _Mapping]] = ..., addOns: _Optional[_Iterable[_Union[LicenseAddOn, _Mapping]]] = ..., nextBillingDate: _Optional[int] = ..., hasMSPLegacyLog: bool = ..., mspPermits: _Optional[_Union[MSPPermits, _Mapping]] = ..., distributor: bool = ...) -> None: ...

class Bridge(_message.Message):
    __slots__ = ("bridgeId", "nodeId", "wanIpEnforcement", "lanIpEnforcement", "status")
    BRIDGEID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    WANIPENFORCEMENT_FIELD_NUMBER: _ClassVar[int]
    LANIPENFORCEMENT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    bridgeId: int
    nodeId: int
    wanIpEnforcement: str
    lanIpEnforcement: str
    status: str
    def __init__(self, bridgeId: _Optional[int] = ..., nodeId: _Optional[int] = ..., wanIpEnforcement: _Optional[str] = ..., lanIpEnforcement: _Optional[str] = ..., status: _Optional[str] = ...) -> None: ...

class Scim(_message.Message):
    __slots__ = ("scimId", "nodeId", "status", "lastSynced", "rolePrefix", "uniqueGroups")
    SCIMID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LASTSYNCED_FIELD_NUMBER: _ClassVar[int]
    ROLEPREFIX_FIELD_NUMBER: _ClassVar[int]
    UNIQUEGROUPS_FIELD_NUMBER: _ClassVar[int]
    scimId: int
    nodeId: int
    status: str
    lastSynced: int
    rolePrefix: str
    uniqueGroups: bool
    def __init__(self, scimId: _Optional[int] = ..., nodeId: _Optional[int] = ..., status: _Optional[str] = ..., lastSynced: _Optional[int] = ..., rolePrefix: _Optional[str] = ..., uniqueGroups: bool = ...) -> None: ...

class EmailProvision(_message.Message):
    __slots__ = ("id", "nodeId", "domain", "method")
    ID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    id: int
    nodeId: int
    domain: str
    method: str
    def __init__(self, id: _Optional[int] = ..., nodeId: _Optional[int] = ..., domain: _Optional[str] = ..., method: _Optional[str] = ...) -> None: ...

class QueuedTeam(_message.Message):
    __slots__ = ("teamUid", "name", "nodeId", "encryptedData")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    name: str
    nodeId: int
    encryptedData: str
    def __init__(self, teamUid: _Optional[bytes] = ..., name: _Optional[str] = ..., nodeId: _Optional[int] = ..., encryptedData: _Optional[str] = ...) -> None: ...

class QueuedTeamUser(_message.Message):
    __slots__ = ("teamUid", "users")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    users: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, teamUid: _Optional[bytes] = ..., users: _Optional[_Iterable[int]] = ...) -> None: ...

class TeamsAddResult(_message.Message):
    __slots__ = ("successfulTeamAdd", "unsuccessfulTeamAdd", "result", "errorMessage")
    SUCCESSFULTEAMADD_FIELD_NUMBER: _ClassVar[int]
    UNSUCCESSFULTEAMADD_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    ERRORMESSAGE_FIELD_NUMBER: _ClassVar[int]
    successfulTeamAdd: _containers.RepeatedCompositeFieldContainer[TeamAddResult]
    unsuccessfulTeamAdd: _containers.RepeatedCompositeFieldContainer[TeamAddResult]
    result: str
    errorMessage: str
    def __init__(self, successfulTeamAdd: _Optional[_Iterable[_Union[TeamAddResult, _Mapping]]] = ..., unsuccessfulTeamAdd: _Optional[_Iterable[_Union[TeamAddResult, _Mapping]]] = ..., result: _Optional[str] = ..., errorMessage: _Optional[str] = ...) -> None: ...

class TeamAddResult(_message.Message):
    __slots__ = ("team", "result", "errorMessage")
    TEAM_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    ERRORMESSAGE_FIELD_NUMBER: _ClassVar[int]
    team: Team
    result: str
    errorMessage: str
    def __init__(self, team: _Optional[_Union[Team, _Mapping]] = ..., result: _Optional[str] = ..., errorMessage: _Optional[str] = ...) -> None: ...

class SsoService(_message.Message):
    __slots__ = ("ssoServiceProviderId", "nodeId", "name", "sp_url", "inviteNewUsers", "active", "isCloud")
    SSOSERVICEPROVIDERID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SP_URL_FIELD_NUMBER: _ClassVar[int]
    INVITENEWUSERS_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    ISCLOUD_FIELD_NUMBER: _ClassVar[int]
    ssoServiceProviderId: int
    nodeId: int
    name: str
    sp_url: str
    inviteNewUsers: bool
    active: bool
    isCloud: bool
    def __init__(self, ssoServiceProviderId: _Optional[int] = ..., nodeId: _Optional[int] = ..., name: _Optional[str] = ..., sp_url: _Optional[str] = ..., inviteNewUsers: bool = ..., active: bool = ..., isCloud: bool = ...) -> None: ...

class ReportFilterUser(_message.Message):
    __slots__ = ("userId", "email")
    USERID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    userId: int
    email: str
    def __init__(self, userId: _Optional[int] = ..., email: _Optional[str] = ...) -> None: ...

class DeviceRequestForAdminApproval(_message.Message):
    __slots__ = ("deviceId", "enterpriseUserId", "encryptedDeviceToken", "devicePublicKey", "deviceName", "clientVersion", "deviceType", "date", "ipAddress", "location", "email", "accountUid")
    DEVICEID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICETYPE_FIELD_NUMBER: _ClassVar[int]
    DATE_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTUID_FIELD_NUMBER: _ClassVar[int]
    deviceId: int
    enterpriseUserId: int
    encryptedDeviceToken: bytes
    devicePublicKey: bytes
    deviceName: str
    clientVersion: str
    deviceType: str
    date: int
    ipAddress: str
    location: str
    email: str
    accountUid: bytes
    def __init__(self, deviceId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ..., encryptedDeviceToken: _Optional[bytes] = ..., devicePublicKey: _Optional[bytes] = ..., deviceName: _Optional[str] = ..., clientVersion: _Optional[str] = ..., deviceType: _Optional[str] = ..., date: _Optional[int] = ..., ipAddress: _Optional[str] = ..., location: _Optional[str] = ..., email: _Optional[str] = ..., accountUid: _Optional[bytes] = ...) -> None: ...

class EnterpriseData(_message.Message):
    __slots__ = ("entity", "delete", "data")
    ENTITY_FIELD_NUMBER: _ClassVar[int]
    DELETE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    entity: EnterpriseDataEntity
    delete: bool
    data: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, entity: _Optional[_Union[EnterpriseDataEntity, str]] = ..., delete: bool = ..., data: _Optional[_Iterable[bytes]] = ...) -> None: ...

class EnterpriseDataResponse(_message.Message):
    __slots__ = ("continuationToken", "hasMore", "cacheStatus", "data", "generalData")
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    CACHESTATUS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    GENERALDATA_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    hasMore: bool
    cacheStatus: CacheStatus
    data: _containers.RepeatedCompositeFieldContainer[EnterpriseData]
    generalData: GeneralDataEntity
    def __init__(self, continuationToken: _Optional[bytes] = ..., hasMore: bool = ..., cacheStatus: _Optional[_Union[CacheStatus, str]] = ..., data: _Optional[_Iterable[_Union[EnterpriseData, _Mapping]]] = ..., generalData: _Optional[_Union[GeneralDataEntity, _Mapping]] = ...) -> None: ...

class BackupRequest(_message.Message):
    __slots__ = ("continuationToken",)
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    def __init__(self, continuationToken: _Optional[bytes] = ...) -> None: ...

class BackupRecord(_message.Message):
    __slots__ = ("userId", "recordUid", "key", "keyType", "version", "data", "extra")
    USERID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    EXTRA_FIELD_NUMBER: _ClassVar[int]
    userId: int
    recordUid: bytes
    key: bytes
    keyType: BackupKeyType
    version: int
    data: bytes
    extra: bytes
    def __init__(self, userId: _Optional[int] = ..., recordUid: _Optional[bytes] = ..., key: _Optional[bytes] = ..., keyType: _Optional[_Union[BackupKeyType, str]] = ..., version: _Optional[int] = ..., data: _Optional[bytes] = ..., extra: _Optional[bytes] = ...) -> None: ...

class BackupKey(_message.Message):
    __slots__ = ("userId", "backupKey")
    USERID_FIELD_NUMBER: _ClassVar[int]
    BACKUPKEY_FIELD_NUMBER: _ClassVar[int]
    userId: int
    backupKey: bytes
    def __init__(self, userId: _Optional[int] = ..., backupKey: _Optional[bytes] = ...) -> None: ...

class BackupUser(_message.Message):
    __slots__ = ("userId", "userName", "dataKey", "dataKeyType", "privateKey", "treeKey", "treeKeyType", "backupKeys", "privateECKey")
    USERID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    DATAKEY_FIELD_NUMBER: _ClassVar[int]
    DATAKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    PRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    TREEKEY_FIELD_NUMBER: _ClassVar[int]
    TREEKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    BACKUPKEYS_FIELD_NUMBER: _ClassVar[int]
    PRIVATEECKEY_FIELD_NUMBER: _ClassVar[int]
    userId: int
    userName: str
    dataKey: bytes
    dataKeyType: BackupUserDataKeyType
    privateKey: bytes
    treeKey: bytes
    treeKeyType: BackupKeyType
    backupKeys: _containers.RepeatedCompositeFieldContainer[BackupKey]
    privateECKey: bytes
    def __init__(self, userId: _Optional[int] = ..., userName: _Optional[str] = ..., dataKey: _Optional[bytes] = ..., dataKeyType: _Optional[_Union[BackupUserDataKeyType, str]] = ..., privateKey: _Optional[bytes] = ..., treeKey: _Optional[bytes] = ..., treeKeyType: _Optional[_Union[BackupKeyType, str]] = ..., backupKeys: _Optional[_Iterable[_Union[BackupKey, _Mapping]]] = ..., privateECKey: _Optional[bytes] = ...) -> None: ...

class BackupResponse(_message.Message):
    __slots__ = ("enterpriseEccPrivateKey", "users", "records", "continuationToken")
    ENTERPRISEECCPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    enterpriseEccPrivateKey: bytes
    users: _containers.RepeatedCompositeFieldContainer[BackupUser]
    records: _containers.RepeatedCompositeFieldContainer[BackupRecord]
    continuationToken: bytes
    def __init__(self, enterpriseEccPrivateKey: _Optional[bytes] = ..., users: _Optional[_Iterable[_Union[BackupUser, _Mapping]]] = ..., records: _Optional[_Iterable[_Union[BackupRecord, _Mapping]]] = ..., continuationToken: _Optional[bytes] = ...) -> None: ...

class BackupFile(_message.Message):
    __slots__ = ("user", "backupUid", "fileName", "created", "downloadUrl")
    USER_FIELD_NUMBER: _ClassVar[int]
    BACKUPUID_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADURL_FIELD_NUMBER: _ClassVar[int]
    user: str
    backupUid: bytes
    fileName: str
    created: int
    downloadUrl: str
    def __init__(self, user: _Optional[str] = ..., backupUid: _Optional[bytes] = ..., fileName: _Optional[str] = ..., created: _Optional[int] = ..., downloadUrl: _Optional[str] = ...) -> None: ...

class BackupsResponse(_message.Message):
    __slots__ = ("files",)
    FILES_FIELD_NUMBER: _ClassVar[int]
    files: _containers.RepeatedCompositeFieldContainer[BackupFile]
    def __init__(self, files: _Optional[_Iterable[_Union[BackupFile, _Mapping]]] = ...) -> None: ...

class GetEnterpriseDataKeysRequest(_message.Message):
    __slots__ = ("roleId",)
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    roleId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, roleId: _Optional[_Iterable[int]] = ...) -> None: ...

class GetEnterpriseDataKeysResponse(_message.Message):
    __slots__ = ("reEncryptedRoleKey", "roleKey", "mspKey", "enterpriseKeys", "treeKey")
    REENCRYPTEDROLEKEY_FIELD_NUMBER: _ClassVar[int]
    ROLEKEY_FIELD_NUMBER: _ClassVar[int]
    MSPKEY_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEKEYS_FIELD_NUMBER: _ClassVar[int]
    TREEKEY_FIELD_NUMBER: _ClassVar[int]
    reEncryptedRoleKey: _containers.RepeatedCompositeFieldContainer[ReEncryptedRoleKey]
    roleKey: _containers.RepeatedCompositeFieldContainer[RoleKey]
    mspKey: MspKey
    enterpriseKeys: EnterpriseKeys
    treeKey: TreeKey
    def __init__(self, reEncryptedRoleKey: _Optional[_Iterable[_Union[ReEncryptedRoleKey, _Mapping]]] = ..., roleKey: _Optional[_Iterable[_Union[RoleKey, _Mapping]]] = ..., mspKey: _Optional[_Union[MspKey, _Mapping]] = ..., enterpriseKeys: _Optional[_Union[EnterpriseKeys, _Mapping]] = ..., treeKey: _Optional[_Union[TreeKey, _Mapping]] = ...) -> None: ...

class RoleKey(_message.Message):
    __slots__ = ("roleId", "encryptedKey", "keyType")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    encryptedKey: str
    keyType: EncryptedKeyType
    def __init__(self, roleId: _Optional[int] = ..., encryptedKey: _Optional[str] = ..., keyType: _Optional[_Union[EncryptedKeyType, str]] = ...) -> None: ...

class MspKey(_message.Message):
    __slots__ = ("encryptedMspTreeKey", "encryptedMspTreeKeyType")
    ENCRYPTEDMSPTREEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDMSPTREEKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    encryptedMspTreeKey: str
    encryptedMspTreeKeyType: EncryptedKeyType
    def __init__(self, encryptedMspTreeKey: _Optional[str] = ..., encryptedMspTreeKeyType: _Optional[_Union[EncryptedKeyType, str]] = ...) -> None: ...

class EnterpriseKeys(_message.Message):
    __slots__ = ("rsaPublicKey", "rsaEncryptedPrivateKey", "eccPublicKey", "eccEncryptedPrivateKey")
    RSAPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    RSAENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ECCENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    rsaPublicKey: bytes
    rsaEncryptedPrivateKey: bytes
    eccPublicKey: bytes
    eccEncryptedPrivateKey: bytes
    def __init__(self, rsaPublicKey: _Optional[bytes] = ..., rsaEncryptedPrivateKey: _Optional[bytes] = ..., eccPublicKey: _Optional[bytes] = ..., eccEncryptedPrivateKey: _Optional[bytes] = ...) -> None: ...

class TreeKey(_message.Message):
    __slots__ = ("treeKey", "keyTypeId")
    TREEKEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPEID_FIELD_NUMBER: _ClassVar[int]
    treeKey: str
    keyTypeId: BackupKeyType
    def __init__(self, treeKey: _Optional[str] = ..., keyTypeId: _Optional[_Union[BackupKeyType, str]] = ...) -> None: ...

class SharedRecordResponse(_message.Message):
    __slots__ = ("events",)
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    events: _containers.RepeatedCompositeFieldContainer[SharedRecordEvent]
    def __init__(self, events: _Optional[_Iterable[_Union[SharedRecordEvent, _Mapping]]] = ...) -> None: ...

class SharedRecordEvent(_message.Message):
    __slots__ = ("recordUid", "userName", "canEdit", "canReshare", "shareFrom")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    CANEDIT_FIELD_NUMBER: _ClassVar[int]
    CANRESHARE_FIELD_NUMBER: _ClassVar[int]
    SHAREFROM_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    userName: str
    canEdit: bool
    canReshare: bool
    shareFrom: int
    def __init__(self, recordUid: _Optional[bytes] = ..., userName: _Optional[str] = ..., canEdit: bool = ..., canReshare: bool = ..., shareFrom: _Optional[int] = ...) -> None: ...

class SetRestrictVisibilityRequest(_message.Message):
    __slots__ = ("nodeId",)
    NODEID_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    def __init__(self, nodeId: _Optional[int] = ...) -> None: ...

class UserAddRequest(_message.Message):
    __slots__ = ("enterpriseUserId", "nodeId", "encryptedData", "keyType", "fullName", "jobTitle", "email", "suppressEmailInvite")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    JOBTITLE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    SUPPRESSEMAILINVITE_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    nodeId: int
    encryptedData: bytes
    keyType: EncryptedKeyType
    fullName: str
    jobTitle: str
    email: str
    suppressEmailInvite: bool
    def __init__(self, enterpriseUserId: _Optional[int] = ..., nodeId: _Optional[int] = ..., encryptedData: _Optional[bytes] = ..., keyType: _Optional[_Union[EncryptedKeyType, str]] = ..., fullName: _Optional[str] = ..., jobTitle: _Optional[str] = ..., email: _Optional[str] = ..., suppressEmailInvite: bool = ...) -> None: ...

class UserUpdateRequest(_message.Message):
    __slots__ = ("users",)
    USERS_FIELD_NUMBER: _ClassVar[int]
    users: _containers.RepeatedCompositeFieldContainer[UserUpdate]
    def __init__(self, users: _Optional[_Iterable[_Union[UserUpdate, _Mapping]]] = ...) -> None: ...

class UserUpdate(_message.Message):
    __slots__ = ("enterpriseUserId", "nodeId", "encryptedData", "keyType", "fullName", "jobTitle", "email")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    JOBTITLE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    nodeId: int
    encryptedData: bytes
    keyType: EncryptedKeyType
    fullName: str
    jobTitle: str
    email: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., nodeId: _Optional[int] = ..., encryptedData: _Optional[bytes] = ..., keyType: _Optional[_Union[EncryptedKeyType, str]] = ..., fullName: _Optional[str] = ..., jobTitle: _Optional[str] = ..., email: _Optional[str] = ...) -> None: ...

class UserUpdateResponse(_message.Message):
    __slots__ = ("users",)
    USERS_FIELD_NUMBER: _ClassVar[int]
    users: _containers.RepeatedCompositeFieldContainer[UserUpdateResult]
    def __init__(self, users: _Optional[_Iterable[_Union[UserUpdateResult, _Mapping]]] = ...) -> None: ...

class UserUpdateResult(_message.Message):
    __slots__ = ("enterpriseUserId", "status")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    status: UserUpdateStatus
    def __init__(self, enterpriseUserId: _Optional[int] = ..., status: _Optional[_Union[UserUpdateStatus, str]] = ...) -> None: ...

class ComplianceRecordOwnersRequest(_message.Message):
    __slots__ = ("nodeIds", "includeNonShared")
    NODEIDS_FIELD_NUMBER: _ClassVar[int]
    INCLUDENONSHARED_FIELD_NUMBER: _ClassVar[int]
    nodeIds: _containers.RepeatedScalarFieldContainer[int]
    includeNonShared: bool
    def __init__(self, nodeIds: _Optional[_Iterable[int]] = ..., includeNonShared: bool = ...) -> None: ...

class ComplianceRecordOwnersResponse(_message.Message):
    __slots__ = ("recordOwners",)
    RECORDOWNERS_FIELD_NUMBER: _ClassVar[int]
    recordOwners: _containers.RepeatedCompositeFieldContainer[RecordOwner]
    def __init__(self, recordOwners: _Optional[_Iterable[_Union[RecordOwner, _Mapping]]] = ...) -> None: ...

class RecordOwner(_message.Message):
    __slots__ = ("enterpriseUserId", "shared")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    SHARED_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    shared: bool
    def __init__(self, enterpriseUserId: _Optional[int] = ..., shared: bool = ...) -> None: ...

class PreliminaryComplianceDataRequest(_message.Message):
    __slots__ = ("enterpriseUserIds", "includeNonShared", "continuationToken", "includeTotalMatchingRecordsInFirstResponse")
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    INCLUDENONSHARED_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    INCLUDETOTALMATCHINGRECORDSINFIRSTRESPONSE_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    includeNonShared: bool
    continuationToken: bytes
    includeTotalMatchingRecordsInFirstResponse: bool
    def __init__(self, enterpriseUserIds: _Optional[_Iterable[int]] = ..., includeNonShared: bool = ..., continuationToken: _Optional[bytes] = ..., includeTotalMatchingRecordsInFirstResponse: bool = ...) -> None: ...

class PreliminaryComplianceDataResponse(_message.Message):
    __slots__ = ("auditUserData", "continuationToken", "hasMore", "totalMatchingRecords")
    AUDITUSERDATA_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    TOTALMATCHINGRECORDS_FIELD_NUMBER: _ClassVar[int]
    auditUserData: _containers.RepeatedCompositeFieldContainer[AuditUserData]
    continuationToken: bytes
    hasMore: bool
    totalMatchingRecords: int
    def __init__(self, auditUserData: _Optional[_Iterable[_Union[AuditUserData, _Mapping]]] = ..., continuationToken: _Optional[bytes] = ..., hasMore: bool = ..., totalMatchingRecords: _Optional[int] = ...) -> None: ...

class AuditUserRecord(_message.Message):
    __slots__ = ("recordUid", "encryptedData", "shared")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    SHARED_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    encryptedData: bytes
    shared: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., shared: bool = ...) -> None: ...

class AuditUserData(_message.Message):
    __slots__ = ("enterpriseUserId", "auditUserRecords", "status")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    AUDITUSERRECORDS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    auditUserRecords: _containers.RepeatedCompositeFieldContainer[AuditUserRecord]
    status: AuditUserStatus
    def __init__(self, enterpriseUserId: _Optional[int] = ..., auditUserRecords: _Optional[_Iterable[_Union[AuditUserRecord, _Mapping]]] = ..., status: _Optional[_Union[AuditUserStatus, str]] = ...) -> None: ...

class ComplianceReportFilters(_message.Message):
    __slots__ = ("recordTitles", "recordUids", "jobTitles", "urls", "enterpriseUserIds")
    RECORDTITLES_FIELD_NUMBER: _ClassVar[int]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    JOBTITLES_FIELD_NUMBER: _ClassVar[int]
    URLS_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    recordTitles: _containers.RepeatedScalarFieldContainer[str]
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    jobTitles: _containers.RepeatedScalarFieldContainer[int]
    urls: _containers.RepeatedScalarFieldContainer[str]
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, recordTitles: _Optional[_Iterable[str]] = ..., recordUids: _Optional[_Iterable[bytes]] = ..., jobTitles: _Optional[_Iterable[int]] = ..., urls: _Optional[_Iterable[str]] = ..., enterpriseUserIds: _Optional[_Iterable[int]] = ...) -> None: ...

class ComplianceReportRequest(_message.Message):
    __slots__ = ("complianceReportRun", "reportName", "saveReport")
    COMPLIANCEREPORTRUN_FIELD_NUMBER: _ClassVar[int]
    REPORTNAME_FIELD_NUMBER: _ClassVar[int]
    SAVEREPORT_FIELD_NUMBER: _ClassVar[int]
    complianceReportRun: ComplianceReportRun
    reportName: str
    saveReport: bool
    def __init__(self, complianceReportRun: _Optional[_Union[ComplianceReportRun, _Mapping]] = ..., reportName: _Optional[str] = ..., saveReport: bool = ...) -> None: ...

class ComplianceReportRun(_message.Message):
    __slots__ = ("reportCriteriaAndFilter", "users", "records")
    REPORTCRITERIAANDFILTER_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    reportCriteriaAndFilter: ComplianceReportCriteriaAndFilter
    users: _containers.RepeatedScalarFieldContainer[int]
    records: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, reportCriteriaAndFilter: _Optional[_Union[ComplianceReportCriteriaAndFilter, _Mapping]] = ..., users: _Optional[_Iterable[int]] = ..., records: _Optional[_Iterable[bytes]] = ...) -> None: ...

class ComplianceReportCriteriaAndFilter(_message.Message):
    __slots__ = ("nodeId", "criteriaUid", "criteriaName", "criteria", "filters", "lastModified", "nodeEncryptedData")
    NODEID_FIELD_NUMBER: _ClassVar[int]
    CRITERIAUID_FIELD_NUMBER: _ClassVar[int]
    CRITERIANAME_FIELD_NUMBER: _ClassVar[int]
    CRITERIA_FIELD_NUMBER: _ClassVar[int]
    FILTERS_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    NODEENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    criteriaUid: bytes
    criteriaName: str
    criteria: ComplianceReportCriteria
    filters: _containers.RepeatedCompositeFieldContainer[ComplianceReportFilter]
    lastModified: int
    nodeEncryptedData: bytes
    def __init__(self, nodeId: _Optional[int] = ..., criteriaUid: _Optional[bytes] = ..., criteriaName: _Optional[str] = ..., criteria: _Optional[_Union[ComplianceReportCriteria, _Mapping]] = ..., filters: _Optional[_Iterable[_Union[ComplianceReportFilter, _Mapping]]] = ..., lastModified: _Optional[int] = ..., nodeEncryptedData: _Optional[bytes] = ...) -> None: ...

class ComplianceReportCriteria(_message.Message):
    __slots__ = ("jobTitles", "enterpriseUserIds", "includeNonShared")
    JOBTITLES_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    INCLUDENONSHARED_FIELD_NUMBER: _ClassVar[int]
    jobTitles: _containers.RepeatedScalarFieldContainer[str]
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    includeNonShared: bool
    def __init__(self, jobTitles: _Optional[_Iterable[str]] = ..., enterpriseUserIds: _Optional[_Iterable[int]] = ..., includeNonShared: bool = ...) -> None: ...

class ComplianceReportFilter(_message.Message):
    __slots__ = ("recordTitles", "recordUids", "jobTitles", "urls", "recordTypes")
    RECORDTITLES_FIELD_NUMBER: _ClassVar[int]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    JOBTITLES_FIELD_NUMBER: _ClassVar[int]
    URLS_FIELD_NUMBER: _ClassVar[int]
    RECORDTYPES_FIELD_NUMBER: _ClassVar[int]
    recordTitles: _containers.RepeatedScalarFieldContainer[str]
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    jobTitles: _containers.RepeatedScalarFieldContainer[str]
    urls: _containers.RepeatedScalarFieldContainer[str]
    recordTypes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, recordTitles: _Optional[_Iterable[str]] = ..., recordUids: _Optional[_Iterable[bytes]] = ..., jobTitles: _Optional[_Iterable[str]] = ..., urls: _Optional[_Iterable[str]] = ..., recordTypes: _Optional[_Iterable[str]] = ...) -> None: ...

class ComplianceReportResponse(_message.Message):
    __slots__ = ("dateGenerated", "runByUserName", "reportName", "reportUid", "complianceReportRun", "userProfiles", "auditTeams", "auditRecords", "userRecords", "sharedFolderRecords", "sharedFolderUsers", "sharedFolderTeams", "auditTeamUsers", "auditRoles", "linkedRecords")
    DATEGENERATED_FIELD_NUMBER: _ClassVar[int]
    RUNBYUSERNAME_FIELD_NUMBER: _ClassVar[int]
    REPORTNAME_FIELD_NUMBER: _ClassVar[int]
    REPORTUID_FIELD_NUMBER: _ClassVar[int]
    COMPLIANCEREPORTRUN_FIELD_NUMBER: _ClassVar[int]
    USERPROFILES_FIELD_NUMBER: _ClassVar[int]
    AUDITTEAMS_FIELD_NUMBER: _ClassVar[int]
    AUDITRECORDS_FIELD_NUMBER: _ClassVar[int]
    USERRECORDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERRECORDS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERUSERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDFOLDERTEAMS_FIELD_NUMBER: _ClassVar[int]
    AUDITTEAMUSERS_FIELD_NUMBER: _ClassVar[int]
    AUDITROLES_FIELD_NUMBER: _ClassVar[int]
    LINKEDRECORDS_FIELD_NUMBER: _ClassVar[int]
    dateGenerated: int
    runByUserName: str
    reportName: str
    reportUid: bytes
    complianceReportRun: ComplianceReportRun
    userProfiles: _containers.RepeatedCompositeFieldContainer[UserProfile]
    auditTeams: _containers.RepeatedCompositeFieldContainer[AuditTeam]
    auditRecords: _containers.RepeatedCompositeFieldContainer[AuditRecord]
    userRecords: _containers.RepeatedCompositeFieldContainer[UserRecord]
    sharedFolderRecords: _containers.RepeatedCompositeFieldContainer[SharedFolderRecord]
    sharedFolderUsers: _containers.RepeatedCompositeFieldContainer[SharedFolderUser]
    sharedFolderTeams: _containers.RepeatedCompositeFieldContainer[SharedFolderTeam]
    auditTeamUsers: _containers.RepeatedCompositeFieldContainer[AuditTeamUser]
    auditRoles: _containers.RepeatedCompositeFieldContainer[AuditRole]
    linkedRecords: _containers.RepeatedCompositeFieldContainer[LinkedRecord]
    def __init__(self, dateGenerated: _Optional[int] = ..., runByUserName: _Optional[str] = ..., reportName: _Optional[str] = ..., reportUid: _Optional[bytes] = ..., complianceReportRun: _Optional[_Union[ComplianceReportRun, _Mapping]] = ..., userProfiles: _Optional[_Iterable[_Union[UserProfile, _Mapping]]] = ..., auditTeams: _Optional[_Iterable[_Union[AuditTeam, _Mapping]]] = ..., auditRecords: _Optional[_Iterable[_Union[AuditRecord, _Mapping]]] = ..., userRecords: _Optional[_Iterable[_Union[UserRecord, _Mapping]]] = ..., sharedFolderRecords: _Optional[_Iterable[_Union[SharedFolderRecord, _Mapping]]] = ..., sharedFolderUsers: _Optional[_Iterable[_Union[SharedFolderUser, _Mapping]]] = ..., sharedFolderTeams: _Optional[_Iterable[_Union[SharedFolderTeam, _Mapping]]] = ..., auditTeamUsers: _Optional[_Iterable[_Union[AuditTeamUser, _Mapping]]] = ..., auditRoles: _Optional[_Iterable[_Union[AuditRole, _Mapping]]] = ..., linkedRecords: _Optional[_Iterable[_Union[LinkedRecord, _Mapping]]] = ...) -> None: ...

class AuditRecord(_message.Message):
    __slots__ = ("recordUid", "auditData", "hasAttachments", "inTrash", "treeLeft", "treeRight")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    AUDITDATA_FIELD_NUMBER: _ClassVar[int]
    HASATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    INTRASH_FIELD_NUMBER: _ClassVar[int]
    TREELEFT_FIELD_NUMBER: _ClassVar[int]
    TREERIGHT_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    auditData: bytes
    hasAttachments: bool
    inTrash: bool
    treeLeft: int
    treeRight: int
    def __init__(self, recordUid: _Optional[bytes] = ..., auditData: _Optional[bytes] = ..., hasAttachments: bool = ..., inTrash: bool = ..., treeLeft: _Optional[int] = ..., treeRight: _Optional[int] = ...) -> None: ...

class AuditRole(_message.Message):
    __slots__ = ("roleId", "encryptedData", "restrictShareOutsideEnterprise", "restrictShareAll", "restrictShareOfAttachments", "restrictMaskPasswordsWhileEditing", "roleNodeManagements")
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHAREOUTSIDEENTERPRISE_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHAREALL_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHAREOFATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    RESTRICTMASKPASSWORDSWHILEEDITING_FIELD_NUMBER: _ClassVar[int]
    ROLENODEMANAGEMENTS_FIELD_NUMBER: _ClassVar[int]
    roleId: int
    encryptedData: bytes
    restrictShareOutsideEnterprise: bool
    restrictShareAll: bool
    restrictShareOfAttachments: bool
    restrictMaskPasswordsWhileEditing: bool
    roleNodeManagements: _containers.RepeatedCompositeFieldContainer[RoleNodeManagement]
    def __init__(self, roleId: _Optional[int] = ..., encryptedData: _Optional[bytes] = ..., restrictShareOutsideEnterprise: bool = ..., restrictShareAll: bool = ..., restrictShareOfAttachments: bool = ..., restrictMaskPasswordsWhileEditing: bool = ..., roleNodeManagements: _Optional[_Iterable[_Union[RoleNodeManagement, _Mapping]]] = ...) -> None: ...

class RoleNodeManagement(_message.Message):
    __slots__ = ("treeLeft", "treeRight", "cascade", "privileges")
    TREELEFT_FIELD_NUMBER: _ClassVar[int]
    TREERIGHT_FIELD_NUMBER: _ClassVar[int]
    CASCADE_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGES_FIELD_NUMBER: _ClassVar[int]
    treeLeft: int
    treeRight: int
    cascade: bool
    privileges: int
    def __init__(self, treeLeft: _Optional[int] = ..., treeRight: _Optional[int] = ..., cascade: bool = ..., privileges: _Optional[int] = ...) -> None: ...

class UserProfile(_message.Message):
    __slots__ = ("enterpriseUserId", "fullName", "jobTitle", "email", "roleIds")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    JOBTITLE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLEIDS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    fullName: str
    jobTitle: str
    email: str
    roleIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, enterpriseUserId: _Optional[int] = ..., fullName: _Optional[str] = ..., jobTitle: _Optional[str] = ..., email: _Optional[str] = ..., roleIds: _Optional[_Iterable[int]] = ...) -> None: ...

class RecordPermission(_message.Message):
    __slots__ = ("recordUid", "permissionBits")
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONBITS_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    permissionBits: int
    def __init__(self, recordUid: _Optional[bytes] = ..., permissionBits: _Optional[int] = ...) -> None: ...

class UserRecord(_message.Message):
    __slots__ = ("enterpriseUserId", "recordPermissions")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    RECORDPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    recordPermissions: _containers.RepeatedCompositeFieldContainer[RecordPermission]
    def __init__(self, enterpriseUserId: _Optional[int] = ..., recordPermissions: _Optional[_Iterable[_Union[RecordPermission, _Mapping]]] = ...) -> None: ...

class AuditTeam(_message.Message):
    __slots__ = ("teamUid", "teamName", "restrictEdit", "restrictShare")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    TEAMNAME_FIELD_NUMBER: _ClassVar[int]
    RESTRICTEDIT_FIELD_NUMBER: _ClassVar[int]
    RESTRICTSHARE_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    teamName: str
    restrictEdit: bool
    restrictShare: bool
    def __init__(self, teamUid: _Optional[bytes] = ..., teamName: _Optional[str] = ..., restrictEdit: bool = ..., restrictShare: bool = ...) -> None: ...

class AuditTeamUser(_message.Message):
    __slots__ = ("teamUid", "enterpriseUserIds")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, teamUid: _Optional[bytes] = ..., enterpriseUserIds: _Optional[_Iterable[int]] = ...) -> None: ...

class SharedFolderRecord(_message.Message):
    __slots__ = ("sharedFolderUid", "recordPermissions", "shareAdminRecords")
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDPERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    SHAREADMINRECORDS_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    recordPermissions: _containers.RepeatedCompositeFieldContainer[RecordPermission]
    shareAdminRecords: _containers.RepeatedCompositeFieldContainer[ShareAdminRecord]
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., recordPermissions: _Optional[_Iterable[_Union[RecordPermission, _Mapping]]] = ..., shareAdminRecords: _Optional[_Iterable[_Union[ShareAdminRecord, _Mapping]]] = ...) -> None: ...

class ShareAdminRecord(_message.Message):
    __slots__ = ("enterpriseUserId", "recordPermissionIndexes")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    RECORDPERMISSIONINDEXES_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    recordPermissionIndexes: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, enterpriseUserId: _Optional[int] = ..., recordPermissionIndexes: _Optional[_Iterable[int]] = ...) -> None: ...

class SharedFolderUser(_message.Message):
    __slots__ = ("sharedFolderUid", "enterpriseUserIds")
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., enterpriseUserIds: _Optional[_Iterable[int]] = ...) -> None: ...

class SharedFolderTeam(_message.Message):
    __slots__ = ("sharedFolderUid", "teamUids")
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    TEAMUIDS_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    teamUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., teamUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class GetComplianceReportRequest(_message.Message):
    __slots__ = ("reportUid",)
    REPORTUID_FIELD_NUMBER: _ClassVar[int]
    reportUid: bytes
    def __init__(self, reportUid: _Optional[bytes] = ...) -> None: ...

class GetComplianceReportResponse(_message.Message):
    __slots__ = ("downloadUrl",)
    DOWNLOADURL_FIELD_NUMBER: _ClassVar[int]
    downloadUrl: str
    def __init__(self, downloadUrl: _Optional[str] = ...) -> None: ...

class ComplianceReportCriteriaRequest(_message.Message):
    __slots__ = ("criteriaUid",)
    CRITERIAUID_FIELD_NUMBER: _ClassVar[int]
    criteriaUid: bytes
    def __init__(self, criteriaUid: _Optional[bytes] = ...) -> None: ...

class SaveComplianceReportCriteriaResponse(_message.Message):
    __slots__ = ("criteriaUid",)
    CRITERIAUID_FIELD_NUMBER: _ClassVar[int]
    criteriaUid: bytes
    def __init__(self, criteriaUid: _Optional[bytes] = ...) -> None: ...

class LinkedRecord(_message.Message):
    __slots__ = ("ownerUid", "recordUids")
    OWNERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUIDS_FIELD_NUMBER: _ClassVar[int]
    ownerUid: bytes
    recordUids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, ownerUid: _Optional[bytes] = ..., recordUids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class GetSharingAdminsRequest(_message.Message):
    __slots__ = ("sharedFolderUid", "recordUid", "username")
    SHAREDFOLDERUID_FIELD_NUMBER: _ClassVar[int]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    sharedFolderUid: bytes
    recordUid: bytes
    username: str
    def __init__(self, sharedFolderUid: _Optional[bytes] = ..., recordUid: _Optional[bytes] = ..., username: _Optional[str] = ...) -> None: ...

class UserProfileExt(_message.Message):
    __slots__ = ("email", "fullName", "jobTitle", "isMSPMCAdmin", "isInSharedFolder", "isShareAdminForRequestedObject", "isShareAdminForSharedFolderOwner", "hasAccessToObject")
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    JOBTITLE_FIELD_NUMBER: _ClassVar[int]
    ISMSPMCADMIN_FIELD_NUMBER: _ClassVar[int]
    ISINSHAREDFOLDER_FIELD_NUMBER: _ClassVar[int]
    ISSHAREADMINFORREQUESTEDOBJECT_FIELD_NUMBER: _ClassVar[int]
    ISSHAREADMINFORSHAREDFOLDEROWNER_FIELD_NUMBER: _ClassVar[int]
    HASACCESSTOOBJECT_FIELD_NUMBER: _ClassVar[int]
    email: str
    fullName: str
    jobTitle: str
    isMSPMCAdmin: bool
    isInSharedFolder: bool
    isShareAdminForRequestedObject: bool
    isShareAdminForSharedFolderOwner: bool
    hasAccessToObject: bool
    def __init__(self, email: _Optional[str] = ..., fullName: _Optional[str] = ..., jobTitle: _Optional[str] = ..., isMSPMCAdmin: bool = ..., isInSharedFolder: bool = ..., isShareAdminForRequestedObject: bool = ..., isShareAdminForSharedFolderOwner: bool = ..., hasAccessToObject: bool = ...) -> None: ...

class GetSharingAdminsResponse(_message.Message):
    __slots__ = ("userProfileExts",)
    USERPROFILEEXTS_FIELD_NUMBER: _ClassVar[int]
    userProfileExts: _containers.RepeatedCompositeFieldContainer[UserProfileExt]
    def __init__(self, userProfileExts: _Optional[_Iterable[_Union[UserProfileExt, _Mapping]]] = ...) -> None: ...

class TeamsEnterpriseUsersAddRequest(_message.Message):
    __slots__ = ("teams",)
    TEAMS_FIELD_NUMBER: _ClassVar[int]
    teams: _containers.RepeatedCompositeFieldContainer[TeamsEnterpriseUsersAddTeamRequest]
    def __init__(self, teams: _Optional[_Iterable[_Union[TeamsEnterpriseUsersAddTeamRequest, _Mapping]]] = ...) -> None: ...

class TeamsEnterpriseUsersAddTeamRequest(_message.Message):
    __slots__ = ("teamUid", "users")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    users: _containers.RepeatedCompositeFieldContainer[TeamsEnterpriseUsersAddUserRequest]
    def __init__(self, teamUid: _Optional[bytes] = ..., users: _Optional[_Iterable[_Union[TeamsEnterpriseUsersAddUserRequest, _Mapping]]] = ...) -> None: ...

class TeamsEnterpriseUsersAddUserRequest(_message.Message):
    __slots__ = ("enterpriseUserId", "userType", "teamKey", "typedTeamKey")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERTYPE_FIELD_NUMBER: _ClassVar[int]
    TEAMKEY_FIELD_NUMBER: _ClassVar[int]
    TYPEDTEAMKEY_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    userType: TeamUserType
    teamKey: str
    typedTeamKey: TypedKey
    def __init__(self, enterpriseUserId: _Optional[int] = ..., userType: _Optional[_Union[TeamUserType, str]] = ..., teamKey: _Optional[str] = ..., typedTeamKey: _Optional[_Union[TypedKey, _Mapping]] = ...) -> None: ...

class TypedKey(_message.Message):
    __slots__ = ("key", "keyType")
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    keyType: EncryptedKeyType
    def __init__(self, key: _Optional[bytes] = ..., keyType: _Optional[_Union[EncryptedKeyType, str]] = ...) -> None: ...

class TeamsEnterpriseUsersAddResponse(_message.Message):
    __slots__ = ("teams", "revision")
    TEAMS_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    teams: _containers.RepeatedCompositeFieldContainer[TeamsEnterpriseUsersAddTeamResponse]
    revision: int
    def __init__(self, teams: _Optional[_Iterable[_Union[TeamsEnterpriseUsersAddTeamResponse, _Mapping]]] = ..., revision: _Optional[int] = ...) -> None: ...

class TeamsEnterpriseUsersAddTeamResponse(_message.Message):
    __slots__ = ("teamUid", "users", "success", "message", "resultCode", "additionalInfo")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RESULTCODE_FIELD_NUMBER: _ClassVar[int]
    ADDITIONALINFO_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    users: _containers.RepeatedCompositeFieldContainer[TeamsEnterpriseUsersAddUserResponse]
    success: bool
    message: str
    resultCode: str
    additionalInfo: str
    def __init__(self, teamUid: _Optional[bytes] = ..., users: _Optional[_Iterable[_Union[TeamsEnterpriseUsersAddUserResponse, _Mapping]]] = ..., success: bool = ..., message: _Optional[str] = ..., resultCode: _Optional[str] = ..., additionalInfo: _Optional[str] = ...) -> None: ...

class TeamsEnterpriseUsersAddUserResponse(_message.Message):
    __slots__ = ("enterpriseUserId", "revision", "success", "message", "resultCode", "additionalInfo")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RESULTCODE_FIELD_NUMBER: _ClassVar[int]
    ADDITIONALINFO_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    revision: int
    success: bool
    message: str
    resultCode: str
    additionalInfo: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., revision: _Optional[int] = ..., success: bool = ..., message: _Optional[str] = ..., resultCode: _Optional[str] = ..., additionalInfo: _Optional[str] = ...) -> None: ...

class TeamEnterpriseUserRemove(_message.Message):
    __slots__ = ("teamUid", "enterpriseUserId")
    TEAMUID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    teamUid: bytes
    enterpriseUserId: int
    def __init__(self, teamUid: _Optional[bytes] = ..., enterpriseUserId: _Optional[int] = ...) -> None: ...

class TeamEnterpriseUserRemovesRequest(_message.Message):
    __slots__ = ("teamEnterpriseUserRemove",)
    TEAMENTERPRISEUSERREMOVE_FIELD_NUMBER: _ClassVar[int]
    teamEnterpriseUserRemove: _containers.RepeatedCompositeFieldContainer[TeamEnterpriseUserRemove]
    def __init__(self, teamEnterpriseUserRemove: _Optional[_Iterable[_Union[TeamEnterpriseUserRemove, _Mapping]]] = ...) -> None: ...

class TeamEnterpriseUserRemovesResponse(_message.Message):
    __slots__ = ("teamEnterpriseUserRemoveResponse",)
    TEAMENTERPRISEUSERREMOVERESPONSE_FIELD_NUMBER: _ClassVar[int]
    teamEnterpriseUserRemoveResponse: _containers.RepeatedCompositeFieldContainer[TeamEnterpriseUserRemoveResponse]
    def __init__(self, teamEnterpriseUserRemoveResponse: _Optional[_Iterable[_Union[TeamEnterpriseUserRemoveResponse, _Mapping]]] = ...) -> None: ...

class TeamEnterpriseUserRemoveResponse(_message.Message):
    __slots__ = ("teamEnterpriseUserRemove", "success", "resultCode", "message", "additionalInfo")
    TEAMENTERPRISEUSERREMOVE_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    RESULTCODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ADDITIONALINFO_FIELD_NUMBER: _ClassVar[int]
    teamEnterpriseUserRemove: TeamEnterpriseUserRemove
    success: bool
    resultCode: str
    message: str
    additionalInfo: str
    def __init__(self, teamEnterpriseUserRemove: _Optional[_Union[TeamEnterpriseUserRemove, _Mapping]] = ..., success: bool = ..., resultCode: _Optional[str] = ..., message: _Optional[str] = ..., additionalInfo: _Optional[str] = ...) -> None: ...

class DomainAlias(_message.Message):
    __slots__ = ("domain", "alias", "status", "message")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    domain: str
    alias: str
    status: int
    message: str
    def __init__(self, domain: _Optional[str] = ..., alias: _Optional[str] = ..., status: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class DomainAliasRequest(_message.Message):
    __slots__ = ("domainAlias",)
    DOMAINALIAS_FIELD_NUMBER: _ClassVar[int]
    domainAlias: _containers.RepeatedCompositeFieldContainer[DomainAlias]
    def __init__(self, domainAlias: _Optional[_Iterable[_Union[DomainAlias, _Mapping]]] = ...) -> None: ...

class DomainAliasResponse(_message.Message):
    __slots__ = ("domainAlias",)
    DOMAINALIAS_FIELD_NUMBER: _ClassVar[int]
    domainAlias: _containers.RepeatedCompositeFieldContainer[DomainAlias]
    def __init__(self, domainAlias: _Optional[_Iterable[_Union[DomainAlias, _Mapping]]] = ...) -> None: ...

class EnterpriseUsersProvisionRequest(_message.Message):
    __slots__ = ("users", "clientVersion")
    USERS_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    users: _containers.RepeatedCompositeFieldContainer[EnterpriseUsersProvision]
    clientVersion: str
    def __init__(self, users: _Optional[_Iterable[_Union[EnterpriseUsersProvision, _Mapping]]] = ..., clientVersion: _Optional[str] = ...) -> None: ...

class EnterpriseUsersProvision(_message.Message):
    __slots__ = ("enterpriseUserId", "username", "nodeId", "encryptedData", "keyType", "fullName", "jobTitle", "enterpriseUsersDataKey", "authVerifier", "encryptionParams", "rsaPublicKey", "rsaEncryptedPrivateKey", "eccPublicKey", "eccEncryptedPrivateKey", "encryptedDeviceToken", "encryptedClientKey")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    JOBTITLE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERSDATAKEY_FIELD_NUMBER: _ClassVar[int]
    AUTHVERIFIER_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTIONPARAMS_FIELD_NUMBER: _ClassVar[int]
    RSAPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    RSAENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ECCPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ECCENCRYPTEDPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDCLIENTKEY_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    username: str
    nodeId: int
    encryptedData: str
    keyType: EncryptedKeyType
    fullName: str
    jobTitle: str
    enterpriseUsersDataKey: bytes
    authVerifier: bytes
    encryptionParams: bytes
    rsaPublicKey: bytes
    rsaEncryptedPrivateKey: bytes
    eccPublicKey: bytes
    eccEncryptedPrivateKey: bytes
    encryptedDeviceToken: bytes
    encryptedClientKey: bytes
    def __init__(self, enterpriseUserId: _Optional[int] = ..., username: _Optional[str] = ..., nodeId: _Optional[int] = ..., encryptedData: _Optional[str] = ..., keyType: _Optional[_Union[EncryptedKeyType, str]] = ..., fullName: _Optional[str] = ..., jobTitle: _Optional[str] = ..., enterpriseUsersDataKey: _Optional[bytes] = ..., authVerifier: _Optional[bytes] = ..., encryptionParams: _Optional[bytes] = ..., rsaPublicKey: _Optional[bytes] = ..., rsaEncryptedPrivateKey: _Optional[bytes] = ..., eccPublicKey: _Optional[bytes] = ..., eccEncryptedPrivateKey: _Optional[bytes] = ..., encryptedDeviceToken: _Optional[bytes] = ..., encryptedClientKey: _Optional[bytes] = ...) -> None: ...

class EnterpriseUsersProvisionResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[EnterpriseUsersProvisionResult]
    def __init__(self, results: _Optional[_Iterable[_Union[EnterpriseUsersProvisionResult, _Mapping]]] = ...) -> None: ...

class EnterpriseUsersProvisionResult(_message.Message):
    __slots__ = ("enterpriseUserId", "code", "message", "additionalInfo")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ADDITIONALINFO_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    code: str
    message: str
    additionalInfo: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., code: _Optional[str] = ..., message: _Optional[str] = ..., additionalInfo: _Optional[str] = ...) -> None: ...

class EnterpriseUsersAddRequest(_message.Message):
    __slots__ = ("users", "clientVersion")
    USERS_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    users: _containers.RepeatedCompositeFieldContainer[EnterpriseUsersAdd]
    clientVersion: str
    def __init__(self, users: _Optional[_Iterable[_Union[EnterpriseUsersAdd, _Mapping]]] = ..., clientVersion: _Optional[str] = ...) -> None: ...

class EnterpriseUsersAdd(_message.Message):
    __slots__ = ("enterpriseUserId", "username", "nodeId", "encryptedData", "keyType", "fullName", "jobTitle", "suppressEmailInvite", "inviteeLocale", "move", "roleId")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    KEYTYPE_FIELD_NUMBER: _ClassVar[int]
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    JOBTITLE_FIELD_NUMBER: _ClassVar[int]
    SUPPRESSEMAILINVITE_FIELD_NUMBER: _ClassVar[int]
    INVITEELOCALE_FIELD_NUMBER: _ClassVar[int]
    MOVE_FIELD_NUMBER: _ClassVar[int]
    ROLEID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    username: str
    nodeId: int
    encryptedData: str
    keyType: EncryptedKeyType
    fullName: str
    jobTitle: str
    suppressEmailInvite: bool
    inviteeLocale: str
    move: bool
    roleId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ..., username: _Optional[str] = ..., nodeId: _Optional[int] = ..., encryptedData: _Optional[str] = ..., keyType: _Optional[_Union[EncryptedKeyType, str]] = ..., fullName: _Optional[str] = ..., jobTitle: _Optional[str] = ..., suppressEmailInvite: bool = ..., inviteeLocale: _Optional[str] = ..., move: bool = ..., roleId: _Optional[int] = ...) -> None: ...

class EnterpriseUsersAddResponse(_message.Message):
    __slots__ = ("results", "success", "code", "message", "additionalInfo")
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ADDITIONALINFO_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[EnterpriseUsersAddResult]
    success: bool
    code: str
    message: str
    additionalInfo: str
    def __init__(self, results: _Optional[_Iterable[_Union[EnterpriseUsersAddResult, _Mapping]]] = ..., success: bool = ..., code: _Optional[str] = ..., message: _Optional[str] = ..., additionalInfo: _Optional[str] = ...) -> None: ...

class EnterpriseUsersAddResult(_message.Message):
    __slots__ = ("enterpriseUserId", "success", "verificationCode", "code", "message", "additionalInfo")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    VERIFICATIONCODE_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ADDITIONALINFO_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    success: bool
    verificationCode: str
    code: str
    message: str
    additionalInfo: str
    def __init__(self, enterpriseUserId: _Optional[int] = ..., success: bool = ..., verificationCode: _Optional[str] = ..., code: _Optional[str] = ..., message: _Optional[str] = ..., additionalInfo: _Optional[str] = ...) -> None: ...

class UpdateMSPPermitsRequest(_message.Message):
    __slots__ = ("mspEnterpriseId", "maxAllowedLicenses", "allowedMcProducts", "allowedAddOns", "maxFilePlanType", "allowUnlimitedLicenses")
    MSPENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MAXALLOWEDLICENSES_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDMCPRODUCTS_FIELD_NUMBER: _ClassVar[int]
    ALLOWEDADDONS_FIELD_NUMBER: _ClassVar[int]
    MAXFILEPLANTYPE_FIELD_NUMBER: _ClassVar[int]
    ALLOWUNLIMITEDLICENSES_FIELD_NUMBER: _ClassVar[int]
    mspEnterpriseId: int
    maxAllowedLicenses: int
    allowedMcProducts: _containers.RepeatedScalarFieldContainer[str]
    allowedAddOns: _containers.RepeatedScalarFieldContainer[str]
    maxFilePlanType: str
    allowUnlimitedLicenses: bool
    def __init__(self, mspEnterpriseId: _Optional[int] = ..., maxAllowedLicenses: _Optional[int] = ..., allowedMcProducts: _Optional[_Iterable[str]] = ..., allowedAddOns: _Optional[_Iterable[str]] = ..., maxFilePlanType: _Optional[str] = ..., allowUnlimitedLicenses: bool = ...) -> None: ...

class DeleteEnterpriseUsersRequest(_message.Message):
    __slots__ = ("enterpriseUserIds",)
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, enterpriseUserIds: _Optional[_Iterable[int]] = ...) -> None: ...

class DeleteEnterpriseUserStatus(_message.Message):
    __slots__ = ("enterpriseUserId", "status")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    status: DeleteEnterpriseUsersResult
    def __init__(self, enterpriseUserId: _Optional[int] = ..., status: _Optional[_Union[DeleteEnterpriseUsersResult, str]] = ...) -> None: ...

class DeleteEnterpriseUsersResponse(_message.Message):
    __slots__ = ("deleteStatus",)
    DELETESTATUS_FIELD_NUMBER: _ClassVar[int]
    deleteStatus: _containers.RepeatedCompositeFieldContainer[DeleteEnterpriseUserStatus]
    def __init__(self, deleteStatus: _Optional[_Iterable[_Union[DeleteEnterpriseUserStatus, _Mapping]]] = ...) -> None: ...

class ClearSecurityDataRequest(_message.Message):
    __slots__ = ("enterpriseUserId", "allUsers", "type")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ALLUSERS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: _containers.RepeatedScalarFieldContainer[int]
    allUsers: bool
    type: ClearSecurityDataType
    def __init__(self, enterpriseUserId: _Optional[_Iterable[int]] = ..., allUsers: bool = ..., type: _Optional[_Union[ClearSecurityDataType, str]] = ...) -> None: ...

class ListDomainsResponse(_message.Message):
    __slots__ = ("domain",)
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    domain: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, domain: _Optional[_Iterable[str]] = ...) -> None: ...

class ReserveDomainRequest(_message.Message):
    __slots__ = ("reserveDomainAction", "domain")
    RESERVEDOMAINACTION_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    reserveDomainAction: ReserveDomainAction
    domain: str
    def __init__(self, reserveDomainAction: _Optional[_Union[ReserveDomainAction, str]] = ..., domain: _Optional[str] = ...) -> None: ...

class ReserveDomainResponse(_message.Message):
    __slots__ = ("token",)
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    def __init__(self, token: _Optional[str] = ...) -> None: ...
