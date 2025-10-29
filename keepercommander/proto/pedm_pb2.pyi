import folder_pb2 as _folder_pb2
import NotificationCenter_pb2 as _NotificationCenter_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CollectionLinkType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    CLT_OTHER: _ClassVar[CollectionLinkType]
    CLT_AGENT: _ClassVar[CollectionLinkType]
    CLT_POLICY: _ClassVar[CollectionLinkType]
    CLT_COLLECTION: _ClassVar[CollectionLinkType]
    CLT_DEPLOYMENT: _ClassVar[CollectionLinkType]
CLT_OTHER: CollectionLinkType
CLT_AGENT: CollectionLinkType
CLT_POLICY: CollectionLinkType
CLT_COLLECTION: CollectionLinkType
CLT_DEPLOYMENT: CollectionLinkType

class PEDMTOTPValidateRequest(_message.Message):
    __slots__ = ["username", "enterpriseId", "code"]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    username: str
    enterpriseId: int
    code: int
    def __init__(self, username: _Optional[str] = ..., enterpriseId: _Optional[int] = ..., code: _Optional[int] = ...) -> None: ...

class PedmStatus(_message.Message):
    __slots__ = ["key", "success", "message"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    key: _containers.RepeatedScalarFieldContainer[bytes]
    success: bool
    message: str
    def __init__(self, key: _Optional[_Iterable[bytes]] = ..., success: bool = ..., message: _Optional[str] = ...) -> None: ...

class PedmStatusResponse(_message.Message):
    __slots__ = ["addStatus", "updateStatus", "removeStatus"]
    ADDSTATUS_FIELD_NUMBER: _ClassVar[int]
    UPDATESTATUS_FIELD_NUMBER: _ClassVar[int]
    REMOVESTATUS_FIELD_NUMBER: _ClassVar[int]
    addStatus: _containers.RepeatedCompositeFieldContainer[PedmStatus]
    updateStatus: _containers.RepeatedCompositeFieldContainer[PedmStatus]
    removeStatus: _containers.RepeatedCompositeFieldContainer[PedmStatus]
    def __init__(self, addStatus: _Optional[_Iterable[_Union[PedmStatus, _Mapping]]] = ..., updateStatus: _Optional[_Iterable[_Union[PedmStatus, _Mapping]]] = ..., removeStatus: _Optional[_Iterable[_Union[PedmStatus, _Mapping]]] = ...) -> None: ...

class DeploymentData(_message.Message):
    __slots__ = ["name", "ecPrivateKey"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ECPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    name: str
    ecPrivateKey: bytes
    def __init__(self, name: _Optional[str] = ..., ecPrivateKey: _Optional[bytes] = ...) -> None: ...

class DeploymentCreateRequest(_message.Message):
    __slots__ = ["deploymentUid", "aesKey", "ecPublicKey", "spiffeCertificate", "encryptedData", "agentData"]
    DEPLOYMENTUID_FIELD_NUMBER: _ClassVar[int]
    AESKEY_FIELD_NUMBER: _ClassVar[int]
    ECPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    SPIFFECERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    AGENTDATA_FIELD_NUMBER: _ClassVar[int]
    deploymentUid: bytes
    aesKey: bytes
    ecPublicKey: bytes
    spiffeCertificate: bytes
    encryptedData: bytes
    agentData: bytes
    def __init__(self, deploymentUid: _Optional[bytes] = ..., aesKey: _Optional[bytes] = ..., ecPublicKey: _Optional[bytes] = ..., spiffeCertificate: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., agentData: _Optional[bytes] = ...) -> None: ...

class DeploymentUpdateRequest(_message.Message):
    __slots__ = ["deploymentUid", "encryptedData", "disabled", "spiffeCertificate"]
    DEPLOYMENTUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    SPIFFECERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    deploymentUid: bytes
    encryptedData: bytes
    disabled: _folder_pb2.SetBooleanValue
    spiffeCertificate: bytes
    def __init__(self, deploymentUid: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., disabled: _Optional[_Union[_folder_pb2.SetBooleanValue, str]] = ..., spiffeCertificate: _Optional[bytes] = ...) -> None: ...

class ModifyDeploymentRequest(_message.Message):
    __slots__ = ["addDeployment", "updateDeployment", "removeDeployment"]
    ADDDEPLOYMENT_FIELD_NUMBER: _ClassVar[int]
    UPDATEDEPLOYMENT_FIELD_NUMBER: _ClassVar[int]
    REMOVEDEPLOYMENT_FIELD_NUMBER: _ClassVar[int]
    addDeployment: _containers.RepeatedCompositeFieldContainer[DeploymentCreateRequest]
    updateDeployment: _containers.RepeatedCompositeFieldContainer[DeploymentUpdateRequest]
    removeDeployment: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, addDeployment: _Optional[_Iterable[_Union[DeploymentCreateRequest, _Mapping]]] = ..., updateDeployment: _Optional[_Iterable[_Union[DeploymentUpdateRequest, _Mapping]]] = ..., removeDeployment: _Optional[_Iterable[bytes]] = ...) -> None: ...

class AgentUpdate(_message.Message):
    __slots__ = ["agentUid", "disabled", "deploymentUid"]
    AGENTUID_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    DEPLOYMENTUID_FIELD_NUMBER: _ClassVar[int]
    agentUid: bytes
    disabled: _folder_pb2.SetBooleanValue
    deploymentUid: bytes
    def __init__(self, agentUid: _Optional[bytes] = ..., disabled: _Optional[_Union[_folder_pb2.SetBooleanValue, str]] = ..., deploymentUid: _Optional[bytes] = ...) -> None: ...

class ModifyAgentRequest(_message.Message):
    __slots__ = ["updateAgent", "removeAgent"]
    UPDATEAGENT_FIELD_NUMBER: _ClassVar[int]
    REMOVEAGENT_FIELD_NUMBER: _ClassVar[int]
    updateAgent: _containers.RepeatedCompositeFieldContainer[AgentUpdate]
    removeAgent: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, updateAgent: _Optional[_Iterable[_Union[AgentUpdate, _Mapping]]] = ..., removeAgent: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PolicyAdd(_message.Message):
    __slots__ = ["policyUid", "plainData", "encryptedData", "encryptedKey", "disabled"]
    POLICYUID_FIELD_NUMBER: _ClassVar[int]
    PLAINDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDKEY_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    policyUid: bytes
    plainData: bytes
    encryptedData: bytes
    encryptedKey: bytes
    disabled: bool
    def __init__(self, policyUid: _Optional[bytes] = ..., plainData: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., encryptedKey: _Optional[bytes] = ..., disabled: bool = ...) -> None: ...

class PolicyUpdate(_message.Message):
    __slots__ = ["policyUid", "plainData", "encryptedData", "disabled"]
    POLICYUID_FIELD_NUMBER: _ClassVar[int]
    PLAINDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    policyUid: bytes
    plainData: bytes
    encryptedData: bytes
    disabled: _folder_pb2.SetBooleanValue
    def __init__(self, policyUid: _Optional[bytes] = ..., plainData: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., disabled: _Optional[_Union[_folder_pb2.SetBooleanValue, str]] = ...) -> None: ...

class PolicyRequest(_message.Message):
    __slots__ = ["addPolicy", "updatePolicy", "removePolicy"]
    ADDPOLICY_FIELD_NUMBER: _ClassVar[int]
    UPDATEPOLICY_FIELD_NUMBER: _ClassVar[int]
    REMOVEPOLICY_FIELD_NUMBER: _ClassVar[int]
    addPolicy: _containers.RepeatedCompositeFieldContainer[PolicyAdd]
    updatePolicy: _containers.RepeatedCompositeFieldContainer[PolicyUpdate]
    removePolicy: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, addPolicy: _Optional[_Iterable[_Union[PolicyAdd, _Mapping]]] = ..., updatePolicy: _Optional[_Iterable[_Union[PolicyUpdate, _Mapping]]] = ..., removePolicy: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PolicyLink(_message.Message):
    __slots__ = ["policyUid", "collectionUid"]
    POLICYUID_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONUID_FIELD_NUMBER: _ClassVar[int]
    policyUid: bytes
    collectionUid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, policyUid: _Optional[bytes] = ..., collectionUid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class SetPolicyCollectionRequest(_message.Message):
    __slots__ = ["setCollection"]
    SETCOLLECTION_FIELD_NUMBER: _ClassVar[int]
    setCollection: _containers.RepeatedCompositeFieldContainer[PolicyLink]
    def __init__(self, setCollection: _Optional[_Iterable[_Union[PolicyLink, _Mapping]]] = ...) -> None: ...

class CollectionValue(_message.Message):
    __slots__ = ["collectionUid", "collectionType", "encryptedData"]
    COLLECTIONUID_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    collectionUid: bytes
    collectionType: int
    encryptedData: bytes
    def __init__(self, collectionUid: _Optional[bytes] = ..., collectionType: _Optional[int] = ..., encryptedData: _Optional[bytes] = ...) -> None: ...

class CollectionLinkData(_message.Message):
    __slots__ = ["collectionUid", "linkUid", "linkType", "linkData"]
    COLLECTIONUID_FIELD_NUMBER: _ClassVar[int]
    LINKUID_FIELD_NUMBER: _ClassVar[int]
    LINKTYPE_FIELD_NUMBER: _ClassVar[int]
    LINKDATA_FIELD_NUMBER: _ClassVar[int]
    collectionUid: bytes
    linkUid: bytes
    linkType: CollectionLinkType
    linkData: bytes
    def __init__(self, collectionUid: _Optional[bytes] = ..., linkUid: _Optional[bytes] = ..., linkType: _Optional[_Union[CollectionLinkType, str]] = ..., linkData: _Optional[bytes] = ...) -> None: ...

class CollectionRequest(_message.Message):
    __slots__ = ["addCollection", "updateCollection", "removeCollection"]
    ADDCOLLECTION_FIELD_NUMBER: _ClassVar[int]
    UPDATECOLLECTION_FIELD_NUMBER: _ClassVar[int]
    REMOVECOLLECTION_FIELD_NUMBER: _ClassVar[int]
    addCollection: _containers.RepeatedCompositeFieldContainer[CollectionValue]
    updateCollection: _containers.RepeatedCompositeFieldContainer[CollectionValue]
    removeCollection: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, addCollection: _Optional[_Iterable[_Union[CollectionValue, _Mapping]]] = ..., updateCollection: _Optional[_Iterable[_Union[CollectionValue, _Mapping]]] = ..., removeCollection: _Optional[_Iterable[bytes]] = ...) -> None: ...

class SetCollectionLinkRequest(_message.Message):
    __slots__ = ["addCollection", "removeCollection"]
    ADDCOLLECTION_FIELD_NUMBER: _ClassVar[int]
    REMOVECOLLECTION_FIELD_NUMBER: _ClassVar[int]
    addCollection: _containers.RepeatedCompositeFieldContainer[CollectionLinkData]
    removeCollection: _containers.RepeatedCompositeFieldContainer[CollectionLink]
    def __init__(self, addCollection: _Optional[_Iterable[_Union[CollectionLinkData, _Mapping]]] = ..., removeCollection: _Optional[_Iterable[_Union[CollectionLink, _Mapping]]] = ...) -> None: ...

class ApprovalActionRequest(_message.Message):
    __slots__ = ["approve", "deny", "remove"]
    APPROVE_FIELD_NUMBER: _ClassVar[int]
    DENY_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    approve: _containers.RepeatedScalarFieldContainer[bytes]
    deny: _containers.RepeatedScalarFieldContainer[bytes]
    remove: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, approve: _Optional[_Iterable[bytes]] = ..., deny: _Optional[_Iterable[bytes]] = ..., remove: _Optional[_Iterable[bytes]] = ...) -> None: ...

class DeploymentNode(_message.Message):
    __slots__ = ["deploymentUid", "disabled", "aesKey", "ecPublicKey", "encryptedData", "agentData", "created", "modified"]
    DEPLOYMENTUID_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    AESKEY_FIELD_NUMBER: _ClassVar[int]
    ECPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    AGENTDATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_FIELD_NUMBER: _ClassVar[int]
    deploymentUid: bytes
    disabled: bool
    aesKey: bytes
    ecPublicKey: bytes
    encryptedData: bytes
    agentData: bytes
    created: int
    modified: int
    def __init__(self, deploymentUid: _Optional[bytes] = ..., disabled: bool = ..., aesKey: _Optional[bytes] = ..., ecPublicKey: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., agentData: _Optional[bytes] = ..., created: _Optional[int] = ..., modified: _Optional[int] = ...) -> None: ...

class AgentNode(_message.Message):
    __slots__ = ["agentUid", "machineId", "deploymentUid", "ecPublicKey", "disabled", "encryptedData", "created", "modified"]
    AGENTUID_FIELD_NUMBER: _ClassVar[int]
    MACHINEID_FIELD_NUMBER: _ClassVar[int]
    DEPLOYMENTUID_FIELD_NUMBER: _ClassVar[int]
    ECPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_FIELD_NUMBER: _ClassVar[int]
    agentUid: bytes
    machineId: str
    deploymentUid: bytes
    ecPublicKey: bytes
    disabled: bool
    encryptedData: bytes
    created: int
    modified: int
    def __init__(self, agentUid: _Optional[bytes] = ..., machineId: _Optional[str] = ..., deploymentUid: _Optional[bytes] = ..., ecPublicKey: _Optional[bytes] = ..., disabled: bool = ..., encryptedData: _Optional[bytes] = ..., created: _Optional[int] = ..., modified: _Optional[int] = ...) -> None: ...

class PolicyNode(_message.Message):
    __slots__ = ["policyUid", "plainData", "encryptedData", "encryptedKey", "created", "modified", "disabled"]
    POLICYUID_FIELD_NUMBER: _ClassVar[int]
    PLAINDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDKEY_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    policyUid: bytes
    plainData: bytes
    encryptedData: bytes
    encryptedKey: bytes
    created: int
    modified: int
    disabled: bool
    def __init__(self, policyUid: _Optional[bytes] = ..., plainData: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., encryptedKey: _Optional[bytes] = ..., created: _Optional[int] = ..., modified: _Optional[int] = ..., disabled: bool = ...) -> None: ...

class CollectionNode(_message.Message):
    __slots__ = ["collectionUid", "collectionType", "encryptedData", "created"]
    COLLECTIONUID_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    collectionUid: bytes
    collectionType: int
    encryptedData: bytes
    created: int
    def __init__(self, collectionUid: _Optional[bytes] = ..., collectionType: _Optional[int] = ..., encryptedData: _Optional[bytes] = ..., created: _Optional[int] = ...) -> None: ...

class CollectionLink(_message.Message):
    __slots__ = ["collectionUid", "linkUid", "linkType"]
    COLLECTIONUID_FIELD_NUMBER: _ClassVar[int]
    LINKUID_FIELD_NUMBER: _ClassVar[int]
    LINKTYPE_FIELD_NUMBER: _ClassVar[int]
    collectionUid: bytes
    linkUid: bytes
    linkType: CollectionLinkType
    def __init__(self, collectionUid: _Optional[bytes] = ..., linkUid: _Optional[bytes] = ..., linkType: _Optional[_Union[CollectionLinkType, str]] = ...) -> None: ...

class ApprovalStatusNode(_message.Message):
    __slots__ = ["approvalUid", "approvalStatus", "enterpriseUserId", "modified"]
    APPROVALUID_FIELD_NUMBER: _ClassVar[int]
    APPROVALSTATUS_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_FIELD_NUMBER: _ClassVar[int]
    approvalUid: bytes
    approvalStatus: _NotificationCenter_pb2.NotificationApprovalStatus
    enterpriseUserId: int
    modified: int
    def __init__(self, approvalUid: _Optional[bytes] = ..., approvalStatus: _Optional[_Union[_NotificationCenter_pb2.NotificationApprovalStatus, str]] = ..., enterpriseUserId: _Optional[int] = ..., modified: _Optional[int] = ...) -> None: ...

class ApprovalNode(_message.Message):
    __slots__ = ["approvalUid", "approvalType", "agentUid", "accountInfo", "applicationInfo", "justification", "expireIn", "created"]
    APPROVALUID_FIELD_NUMBER: _ClassVar[int]
    APPROVALTYPE_FIELD_NUMBER: _ClassVar[int]
    AGENTUID_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTINFO_FIELD_NUMBER: _ClassVar[int]
    APPLICATIONINFO_FIELD_NUMBER: _ClassVar[int]
    JUSTIFICATION_FIELD_NUMBER: _ClassVar[int]
    EXPIREIN_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    approvalUid: bytes
    approvalType: int
    agentUid: bytes
    accountInfo: bytes
    applicationInfo: bytes
    justification: bytes
    expireIn: int
    created: int
    def __init__(self, approvalUid: _Optional[bytes] = ..., approvalType: _Optional[int] = ..., agentUid: _Optional[bytes] = ..., accountInfo: _Optional[bytes] = ..., applicationInfo: _Optional[bytes] = ..., justification: _Optional[bytes] = ..., expireIn: _Optional[int] = ..., created: _Optional[int] = ...) -> None: ...

class FullSyncToken(_message.Message):
    __slots__ = ["startRevision", "entity", "key"]
    STARTREVISION_FIELD_NUMBER: _ClassVar[int]
    ENTITY_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    startRevision: int
    entity: int
    key: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, startRevision: _Optional[int] = ..., entity: _Optional[int] = ..., key: _Optional[_Iterable[bytes]] = ...) -> None: ...

class IncSyncToken(_message.Message):
    __slots__ = ["lastRevision"]
    LASTREVISION_FIELD_NUMBER: _ClassVar[int]
    lastRevision: int
    def __init__(self, lastRevision: _Optional[int] = ...) -> None: ...

class PedmSyncToken(_message.Message):
    __slots__ = ["fullSync", "incSync"]
    FULLSYNC_FIELD_NUMBER: _ClassVar[int]
    INCSYNC_FIELD_NUMBER: _ClassVar[int]
    fullSync: FullSyncToken
    incSync: IncSyncToken
    def __init__(self, fullSync: _Optional[_Union[FullSyncToken, _Mapping]] = ..., incSync: _Optional[_Union[IncSyncToken, _Mapping]] = ...) -> None: ...

class GetPedmDataRequest(_message.Message):
    __slots__ = ["continuationToken"]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    def __init__(self, continuationToken: _Optional[bytes] = ...) -> None: ...

class GetPedmDataResponse(_message.Message):
    __slots__ = ["continuationToken", "resetCache", "hasMore", "removedDeployments", "removedAgents", "removedPolicies", "removedCollection", "removedCollectionLink", "removedApprovals", "deployments", "agents", "policies", "collections", "collectionLink", "approvals", "approvalStatus"]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    RESETCACHE_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    REMOVEDDEPLOYMENTS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDAGENTS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDPOLICIES_FIELD_NUMBER: _ClassVar[int]
    REMOVEDCOLLECTION_FIELD_NUMBER: _ClassVar[int]
    REMOVEDCOLLECTIONLINK_FIELD_NUMBER: _ClassVar[int]
    REMOVEDAPPROVALS_FIELD_NUMBER: _ClassVar[int]
    DEPLOYMENTS_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    POLICIES_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONS_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONLINK_FIELD_NUMBER: _ClassVar[int]
    APPROVALS_FIELD_NUMBER: _ClassVar[int]
    APPROVALSTATUS_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    resetCache: bool
    hasMore: bool
    removedDeployments: _containers.RepeatedScalarFieldContainer[bytes]
    removedAgents: _containers.RepeatedScalarFieldContainer[bytes]
    removedPolicies: _containers.RepeatedScalarFieldContainer[bytes]
    removedCollection: _containers.RepeatedScalarFieldContainer[bytes]
    removedCollectionLink: _containers.RepeatedCompositeFieldContainer[CollectionLink]
    removedApprovals: _containers.RepeatedScalarFieldContainer[bytes]
    deployments: _containers.RepeatedCompositeFieldContainer[DeploymentNode]
    agents: _containers.RepeatedCompositeFieldContainer[AgentNode]
    policies: _containers.RepeatedCompositeFieldContainer[PolicyNode]
    collections: _containers.RepeatedCompositeFieldContainer[CollectionNode]
    collectionLink: _containers.RepeatedCompositeFieldContainer[CollectionLink]
    approvals: _containers.RepeatedCompositeFieldContainer[ApprovalNode]
    approvalStatus: _containers.RepeatedCompositeFieldContainer[ApprovalStatusNode]
    def __init__(self, continuationToken: _Optional[bytes] = ..., resetCache: bool = ..., hasMore: bool = ..., removedDeployments: _Optional[_Iterable[bytes]] = ..., removedAgents: _Optional[_Iterable[bytes]] = ..., removedPolicies: _Optional[_Iterable[bytes]] = ..., removedCollection: _Optional[_Iterable[bytes]] = ..., removedCollectionLink: _Optional[_Iterable[_Union[CollectionLink, _Mapping]]] = ..., removedApprovals: _Optional[_Iterable[bytes]] = ..., deployments: _Optional[_Iterable[_Union[DeploymentNode, _Mapping]]] = ..., agents: _Optional[_Iterable[_Union[AgentNode, _Mapping]]] = ..., policies: _Optional[_Iterable[_Union[PolicyNode, _Mapping]]] = ..., collections: _Optional[_Iterable[_Union[CollectionNode, _Mapping]]] = ..., collectionLink: _Optional[_Iterable[_Union[CollectionLink, _Mapping]]] = ..., approvals: _Optional[_Iterable[_Union[ApprovalNode, _Mapping]]] = ..., approvalStatus: _Optional[_Iterable[_Union[ApprovalStatusNode, _Mapping]]] = ...) -> None: ...

class PolicyAgentRequest(_message.Message):
    __slots__ = ["policyUid", "summaryOnly"]
    POLICYUID_FIELD_NUMBER: _ClassVar[int]
    SUMMARYONLY_FIELD_NUMBER: _ClassVar[int]
    policyUid: _containers.RepeatedScalarFieldContainer[bytes]
    summaryOnly: bool
    def __init__(self, policyUid: _Optional[_Iterable[bytes]] = ..., summaryOnly: bool = ...) -> None: ...

class PolicyAgentResponse(_message.Message):
    __slots__ = ["agentCount", "agentUid"]
    AGENTCOUNT_FIELD_NUMBER: _ClassVar[int]
    AGENTUID_FIELD_NUMBER: _ClassVar[int]
    agentCount: int
    agentUid: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, agentCount: _Optional[int] = ..., agentUid: _Optional[_Iterable[bytes]] = ...) -> None: ...

class AuditCollectionRequest(_message.Message):
    __slots__ = ["continuationToken", "valueUid", "collectionName"]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    VALUEUID_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONNAME_FIELD_NUMBER: _ClassVar[int]
    continuationToken: bytes
    valueUid: _containers.RepeatedScalarFieldContainer[bytes]
    collectionName: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, continuationToken: _Optional[bytes] = ..., valueUid: _Optional[_Iterable[bytes]] = ..., collectionName: _Optional[_Iterable[str]] = ...) -> None: ...

class AuditCollectionValue(_message.Message):
    __slots__ = ["collectionName", "valueUid", "encryptedData", "created"]
    COLLECTIONNAME_FIELD_NUMBER: _ClassVar[int]
    VALUEUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    collectionName: str
    valueUid: bytes
    encryptedData: bytes
    created: int
    def __init__(self, collectionName: _Optional[str] = ..., valueUid: _Optional[bytes] = ..., encryptedData: _Optional[bytes] = ..., created: _Optional[int] = ...) -> None: ...

class AuditCollectionResponse(_message.Message):
    __slots__ = ["values", "hasMore", "continuationToken"]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    CONTINUATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedCompositeFieldContainer[AuditCollectionValue]
    hasMore: bool
    continuationToken: bytes
    def __init__(self, values: _Optional[_Iterable[_Union[AuditCollectionValue, _Mapping]]] = ..., hasMore: bool = ..., continuationToken: _Optional[bytes] = ...) -> None: ...

class GetCollectionLinkRequest(_message.Message):
    __slots__ = ["collectionLink"]
    COLLECTIONLINK_FIELD_NUMBER: _ClassVar[int]
    collectionLink: _containers.RepeatedCompositeFieldContainer[CollectionLink]
    def __init__(self, collectionLink: _Optional[_Iterable[_Union[CollectionLink, _Mapping]]] = ...) -> None: ...

class GetCollectionLinkResponse(_message.Message):
    __slots__ = ["collectionLinkData"]
    COLLECTIONLINKDATA_FIELD_NUMBER: _ClassVar[int]
    collectionLinkData: _containers.RepeatedCompositeFieldContainer[CollectionLinkData]
    def __init__(self, collectionLinkData: _Optional[_Iterable[_Union[CollectionLinkData, _Mapping]]] = ...) -> None: ...

class GetActiveAgentCountRequest(_message.Message):
    __slots__ = ["enterpriseId"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, enterpriseId: _Optional[_Iterable[int]] = ...) -> None: ...

class ActiveAgentCount(_message.Message):
    __slots__ = ["enterpriseId", "activeAgents"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    ACTIVEAGENTS_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    activeAgents: int
    def __init__(self, enterpriseId: _Optional[int] = ..., activeAgents: _Optional[int] = ...) -> None: ...

class ActiveAgentFailure(_message.Message):
    __slots__ = ["enterpriseId", "message"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    message: str
    def __init__(self, enterpriseId: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class GetActiveAgentCountResponse(_message.Message):
    __slots__ = ["agentCount", "failedCount"]
    AGENTCOUNT_FIELD_NUMBER: _ClassVar[int]
    FAILEDCOUNT_FIELD_NUMBER: _ClassVar[int]
    agentCount: _containers.RepeatedCompositeFieldContainer[ActiveAgentCount]
    failedCount: _containers.RepeatedCompositeFieldContainer[ActiveAgentFailure]
    def __init__(self, agentCount: _Optional[_Iterable[_Union[ActiveAgentCount, _Mapping]]] = ..., failedCount: _Optional[_Iterable[_Union[ActiveAgentFailure, _Mapping]]] = ...) -> None: ...

class GetAgentDailyCountRequest(_message.Message):
    __slots__ = ["enterpriseId", "monthYear", "dateRange"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MONTHYEAR_FIELD_NUMBER: _ClassVar[int]
    DATERANGE_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: _containers.RepeatedScalarFieldContainer[int]
    monthYear: MonthYear
    dateRange: DateRange
    def __init__(self, enterpriseId: _Optional[_Iterable[int]] = ..., monthYear: _Optional[_Union[MonthYear, _Mapping]] = ..., dateRange: _Optional[_Union[DateRange, _Mapping]] = ...) -> None: ...

class MonthYear(_message.Message):
    __slots__ = ["month", "year"]
    MONTH_FIELD_NUMBER: _ClassVar[int]
    YEAR_FIELD_NUMBER: _ClassVar[int]
    month: int
    year: int
    def __init__(self, month: _Optional[int] = ..., year: _Optional[int] = ...) -> None: ...

class DateRange(_message.Message):
    __slots__ = ["start", "end"]
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    start: int
    end: int
    def __init__(self, start: _Optional[int] = ..., end: _Optional[int] = ...) -> None: ...

class AgentDailyCount(_message.Message):
    __slots__ = ["date", "agentCount"]
    DATE_FIELD_NUMBER: _ClassVar[int]
    AGENTCOUNT_FIELD_NUMBER: _ClassVar[int]
    date: int
    agentCount: int
    def __init__(self, date: _Optional[int] = ..., agentCount: _Optional[int] = ...) -> None: ...

class AgentCountForEnterprise(_message.Message):
    __slots__ = ["enterpriseId", "counts"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    COUNTS_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    counts: _containers.RepeatedCompositeFieldContainer[AgentDailyCount]
    def __init__(self, enterpriseId: _Optional[int] = ..., counts: _Optional[_Iterable[_Union[AgentDailyCount, _Mapping]]] = ...) -> None: ...

class GetAgentDailyCountResponse(_message.Message):
    __slots__ = ["enterpriseCounts"]
    ENTERPRISECOUNTS_FIELD_NUMBER: _ClassVar[int]
    enterpriseCounts: _containers.RepeatedCompositeFieldContainer[AgentCountForEnterprise]
    def __init__(self, enterpriseCounts: _Optional[_Iterable[_Union[AgentCountForEnterprise, _Mapping]]] = ...) -> None: ...
