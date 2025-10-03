import abc
import sqlite3
from typing import Callable
from dataclasses import dataclass

from ..storage import types as storage_types, in_memory, sqlite, sqlite_dao


@dataclass(kw_only=True)
class PedmAdminSettings(storage_types.IUid[str]):
    key: str = ''
    value: str = ''
    def uid(self) -> str:
        return self.key


@dataclass(kw_only=True)
class PedmStorageDeployment(storage_types.IUid[str]):
    deployment_uid: str = ''
    encrypted_key: bytes = b''
    disabled: bool = False
    data: bytes = b''
    public_key: bytes = b''
    created: int = 0
    last_updated: int = 0
    def uid(self) -> str:
        return self.deployment_uid


@dataclass(kw_only=True)
class PedmStorageAgent(storage_types.IUid[str]):
    agent_uid: str = ''
    machine_id: str = ''
    deployment_uid: str = ''
    public_key: bytes = b''
    data: bytes = b''
    disabled: bool = False
    created: int = 0
    modified: int = 0
    def uid(self) -> str:
        return self.agent_uid


@dataclass(kw_only=True)
class PedmStoragePolicy(storage_types.IUid[str]):
    policy_uid: str = ''
    admin_data: bytes = b''
    data: bytes = b''
    key: bytes = b''
    disabled: bool = False
    created: int = 0
    updated: int = 0
    def uid(self) -> str:
        return self.policy_uid


@dataclass(kw_only=True)
class PedmStorageCollection(storage_types.IUid[str]):
    collection_uid: str = ''
    collection_type: int = 0
    data: bytes = b''
    created: int = 0
    def uid(self) -> str:
        return self.collection_uid


@dataclass(kw_only=True)
class PedmStorageCollectionLink(storage_types.IUidLink[str, str]):
    collection_uid: str = ''
    link_uid: str = ''
    link_type: int = 0
    def subject_uid(self) -> str:
        return self.collection_uid
    def object_uid(self) -> str:
        return self.link_uid


@dataclass(kw_only=True)
class PedmStorageApproval(storage_types.IUid[str]):
    approval_uid: str = ''
    approval_type: int = 0
    agent_uid: str = ''
    account_info: bytes = b''
    application_info: bytes = b''
    justification: bytes = b''
    expire_in: int = 0
    created: int = 0
    def uid(self) -> str:
        return self.approval_uid

@dataclass(kw_only=True)
class PedmStorageApprovalStatus(storage_types.IUid[str]):
    approval_uid: str = ''
    approval_status: int = 0
    enterprise_user_id: int = 0
    modified: int = 0
    def uid(self) -> str:
        return self.approval_uid


class IPedmStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def settings(self) -> storage_types.IEntityStorage[PedmAdminSettings, str]:
        pass

    @property
    @abc.abstractmethod
    def deployments(self) -> storage_types.IEntityStorage[PedmStorageDeployment, str]:
        pass

    @property
    @abc.abstractmethod
    def agents(self) -> storage_types.IEntityStorage[PedmStorageAgent, str]:
        pass

    @property
    @abc.abstractmethod
    def policies(self) -> storage_types.IEntityStorage[PedmStoragePolicy, str]:
        pass

    @property
    @abc.abstractmethod
    def collections(self) -> storage_types.IEntityStorage[PedmStorageCollection, str]:
        pass

    @property
    @abc.abstractmethod
    def collection_links(self) -> storage_types.ILinkStorage[PedmStorageCollectionLink, str, str]:
        pass

    @property
    @abc.abstractmethod
    def approvals(self) -> storage_types.IEntityStorage[PedmStorageApproval, str]:
        pass

    @property
    @abc.abstractmethod
    def approval_status(self) -> storage_types.IEntityStorage[PedmStorageApprovalStatus, str]:
        pass

    @abc.abstractmethod
    def reset(self):
        pass


class MemoryPedmStorage(IPedmStorage):
    def __init__(self):
        self._settings = in_memory.InMemoryEntityStorage[PedmAdminSettings, str]()
        self._deployments = in_memory.InMemoryEntityStorage[PedmStorageDeployment, str]()
        self._agents = in_memory.InMemoryEntityStorage[PedmStorageAgent, str]()
        self._policies = in_memory.InMemoryEntityStorage[PedmStoragePolicy, str]()
        self._collections = in_memory.InMemoryEntityStorage[PedmStorageCollection, str]()
        self._collection_links = in_memory.InMemoryLinkStorage[PedmStorageCollectionLink, str, str]()
        self._approvals = in_memory.InMemoryEntityStorage[PedmStorageApproval, str]()
        self._approval_status = in_memory.InMemoryEntityStorage[PedmStorageApprovalStatus, str]()

    @property
    def settings(self) -> storage_types.IEntityStorage[PedmAdminSettings, str]:
        return self._settings

    @property
    def deployments(self) -> storage_types.IEntityStorage[PedmStorageDeployment, str]:
        return self._deployments

    @property
    def agents(self) -> storage_types.IEntityStorage[PedmStorageAgent, str]:
        return self._agents

    @property
    def policies(self) -> storage_types.IEntityStorage[PedmStoragePolicy, str]:
        return self._policies

    @property
    def collections(self) -> storage_types.IEntityStorage[PedmStorageCollection, str]:
        return self._collections

    @property
    def collection_links(self) -> storage_types.ILinkStorage[PedmStorageCollectionLink, str, str]:
        return self._collection_links

    @property
    def approvals(self) -> storage_types.IEntityStorage[PedmStorageApproval, str]:
        return self._approvals

    @property
    def approval_status(self) -> storage_types.IEntityStorage[PedmStorageApprovalStatus, str]:
        return self._approval_status

    def reset(self):
        self._settings.clear()
        self._deployments.clear()
        self._agents.clear()
        self._policies.clear()
        self._collections.clear()
        self._collection_links.clear()
        self._approvals.clear()
        self._approval_status.clear()


class SqlitePedmStorage(IPedmStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int):
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.owner_column = 'enterprise_id'
        setting_schema = sqlite_dao.TableSchema.load_schema(
            PedmAdminSettings, 'key', owner_column=self.owner_column, owner_type=int)
        deployment_schema = sqlite_dao.TableSchema.load_schema(
            PedmStorageDeployment, primary_key='deployment_uid', owner_column=self.owner_column, owner_type=int)
        agent_schema = sqlite_dao.TableSchema.load_schema(
            PedmStorageAgent, primary_key='agent_uid', owner_column=self.owner_column, owner_type=int)
        policy_schema = sqlite_dao.TableSchema.load_schema(
            PedmStoragePolicy, primary_key='policy_uid', owner_column=self.owner_column, owner_type=int)
        collection_schema = sqlite_dao.TableSchema.load_schema(
            PedmStorageCollection, primary_key='collection_uid', owner_column=self.owner_column, owner_type=int)
        collection_link_schema = sqlite_dao.TableSchema.load_schema(
            PedmStorageCollectionLink, primary_key=['collection_uid', 'link_uid'], indexes={'Link': 'link_uid'},
            owner_column=self.owner_column, owner_type=int)
        approval_schema = sqlite_dao.TableSchema.load_schema(
            PedmStorageApproval, primary_key='approval_uid', owner_column=self.owner_column, owner_type=int)
        approval_status_schema = sqlite_dao.TableSchema.load_schema(
            PedmStorageApprovalStatus, primary_key='approval_uid', owner_column=self.owner_column, owner_type=int)

        sqlite_dao.verify_database(
            self.get_connection(),(setting_schema, deployment_schema, agent_schema, policy_schema,
                                   collection_schema, collection_link_schema, approval_schema, approval_status_schema))

        self._settings = sqlite.SqliteEntityStorage(self.get_connection, setting_schema, owner=self.enterprise_id)
        self._deployments = sqlite.SqliteEntityStorage(self.get_connection, deployment_schema, owner=self.enterprise_id)
        self._agents = sqlite.SqliteEntityStorage(self.get_connection, agent_schema, owner=self.enterprise_id)
        self._policies = sqlite.SqliteEntityStorage(self.get_connection, policy_schema, owner=self.enterprise_id)
        self._collections = sqlite.SqliteEntityStorage(self.get_connection, collection_schema, owner=self.enterprise_id)
        self._collection_links = sqlite.SqliteLinkStorage(self.get_connection, collection_link_schema, owner=self.enterprise_id)
        self._approvals = sqlite.SqliteEntityStorage(self.get_connection, approval_schema, owner=self.enterprise_id)
        self._approval_status = sqlite.SqliteEntityStorage(self.get_connection, approval_status_schema, owner=self.enterprise_id)

    @property
    def settings(self) -> storage_types.IEntityStorage[PedmAdminSettings, str]:
        return self._settings

    @property
    def deployments(self) -> storage_types.IEntityStorage[PedmStorageDeployment, str]:
        return self._deployments

    @property
    def agents(self) -> storage_types.IEntityStorage[PedmStorageAgent, str]:
        return self._agents

    @property
    def policies(self) -> storage_types.IEntityStorage[PedmStoragePolicy, str]:
        return self._policies

    @property
    def collections(self) -> storage_types.IEntityStorage[PedmStorageCollection, str]:
        return self._collections

    @property
    def collection_links(self) -> storage_types.ILinkStorage[PedmStorageCollectionLink, str, str]:
        return self._collection_links

    @property
    def approvals(self) -> storage_types.IEntityStorage[PedmStorageApproval, str]:
        return self._approvals

    @property
    def approval_status(self) -> storage_types.IEntityStorage[PedmStorageApprovalStatus, str]:
        return self._approval_status

    def reset(self):
        self._settings.delete_all()
        self._deployments.delete_all()
        self._agents.delete_all()
        self._policies.delete_all()
        self._collections.delete_all()
        self._collection_links.delete_all()
        self._approvals.delete_all()
        self._approval_status.delete_all()
