from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Protocol, Union

from . import pedm_shared
from .. import utils
from ..proto import pedm_pb2
from ..storage import types as storage_types


@dataclass(frozen=True)
class PedmDeployment(storage_types.IUid[str]):
    deployment_uid: str
    name: str
    deployment_key: bytes
    public_key: bytes
    private_key: bytes
    disabled: bool
    created: datetime.datetime
    updated: datetime.datetime
    def uid(self) -> str:
        return self.deployment_uid

@dataclass(frozen=True)
class PedmAgent(storage_types.IUid[str]):
    agent_uid: str
    machine_id: str
    deployment_uid: str
    public_key: bytes = b''
    disabled: bool = False
    properties: Optional[Dict[str, Any]] = None
    created: int = 0
    def uid(self) -> str:
        return self.agent_uid


@dataclass(frozen=True)
class PedmDeploymentAgent(storage_types.IUidLink[str, str]):
    deployment_uid: str
    agent_uid: str
    def subject_uid(self) -> str:
        return self.deployment_uid
    def object_uid(self) -> str:
        return self.agent_uid


@dataclass(frozen=True)
class PedmPolicy(storage_types.IUid[str]):
    policy_uid: str
    policy_key: bytes
    admin_data: Optional[Dict[str, Any]] = None
    disabled: bool = False
    data: Optional[Dict[str, Any]] = None
    def uid(self) -> str:
        return self.policy_uid


@dataclass(frozen=True)
class PedmUpdatePolicy:
    policy_uid: str
    admin_data: Optional[Dict[str, Any]] = None
    disabled: Optional[bool] = None
    data: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class PedmCollection(storage_types.IUid[str]):
    collection_uid: str
    collection_type: int
    collection_data: Dict[str, Any]
    created: int = 0
    def uid(self) -> str:
        return self.collection_uid


@dataclass(frozen=True)
class PedmApproval(storage_types.IUid[str]):
    approval_uid: str
    approval_type: int
    agent_uid: str
    account_info: Dict[str, str]
    application_info: Dict[str, str]
    justification: str
    expire_in: int
    created: datetime.datetime
    def uid(self) -> str:
        return self.approval_uid


@dataclass()
class AddDeployment:
    name: str
    agent_info: pedm_shared.DeploymentAgentInformation
    spiffe_cert: Optional[bytes]


@dataclass
class UpdateDeployment:
    deployment_uid: str
    name: Optional[str] = None
    disabled: Optional[bool] = None
    spiffe_cert: Optional[bytes] = None


@dataclass
class UpdateAgent:
    agent_uid: str
    deployment_uid: Optional[str] = None
    disabled: Optional[bool] = None


@dataclass
class CollectionData:
    collection_uid: str
    collection_type: int
    collection_data: str


@dataclass
class CollectionLink:
    collection_uid: str
    link_uid: str
    link_type: int

@dataclass
class CollectionLinkData:
    collection_link: CollectionLink
    link_data: Optional[bytes] = None

class PedmStatus(Protocol):
    success: bool
    message: str

@dataclass(frozen=True)
class EntityStatus(PedmStatus):
    entity_uid: str
    success: bool
    message: str

@dataclass(frozen=True)
class LinkStatus(PedmStatus):
    subject_uid: str
    object_uid: str
    success: bool
    message: str

def parse_pedm_status(status: pedm_pb2.PedmStatus) -> Optional[Union[EntityStatus, LinkStatus]]:
    if len(status.key) == 1:
        return EntityStatus(entity_uid=utils.base64_url_encode(status.key[0]),
                            success=status.success, message=status.message)
    if len(status.key) == 2:
        return LinkStatus(subject_uid=utils.base64_url_encode(status.key[0]),
                          object_uid=utils.base64_url_encode(status.key[1]),
                          success=status.success, message=status.message)
    return None


@dataclass
class ModifyStatus:
    add: List[Union[EntityStatus, LinkStatus]]
    update: List[Union[EntityStatus, LinkStatus]]
    remove: List[Union[EntityStatus, LinkStatus]]

    @classmethod
    def from_proto(cls, status_rs: pedm_pb2.PedmStatusResponse) -> ModifyStatus:
        add_status = [y for y in (parse_pedm_status(x) for x in status_rs.addStatus) if y]
        update_status = [y for y in (parse_pedm_status(x) for x in status_rs.updateStatus) if y]
        remove_status = [y for y in (parse_pedm_status(x) for x in status_rs.removeStatus) if y]
        return cls(add=add_status, update=update_status, remove=remove_status)

    def merge(self, other: ModifyStatus) -> None:
        if other.add:
            self.add += other.add
        if other.update:
            self.update += other.update
        if other.remove:
            self.remove += other.remove
