from __future__ import annotations

import abc
import datetime
import json
import logging
from typing import List, Optional, Set, Iterable, Tuple, Dict, Any, cast

from ..params import KeeperParams
from . import admin_storage, admin_types
from .. import crypto, utils, api
from ..proto import pedm_pb2, folder_pb2
from ..storage import types as storage_types, in_memory
from ..pedm import pedm_shared


class RebuildTask:
    def __init__(self, full_rebuild = False) -> None:
        self._full_rebuild = full_rebuild
        self._agents: Optional[Set[str]] = None
        self._policies: Optional[Set[str]] = None
        self._collections: Optional[Set[str]] = None
        self._approvals: Optional[Set[str]] = None

    @property
    def full_rebuild(self) -> bool:
        return self._full_rebuild

    def add_agents(self, agents: Iterable[str]) -> None:
        if self._full_rebuild:
            return
        if self._agents is None:
            self._agents = set()
        self._agents.update(agents)

    def add_policies(self, policies: Iterable[str]) -> None:
        if self._full_rebuild:
            return
        if self._policies is None:
            self._policies = set()
        self._policies.update(policies)

    def add_collections(self, collections: Iterable[str]) -> None:
        if self._full_rebuild:
            return
        if self._collections is None:
            self._collections = set()
        self._collections.update(collections)

    def add_approvals(self, approvals: Iterable[str]) -> None:
        if self._full_rebuild:
            return
        if self._approvals is None:
            self._approvals = set()
        self._approvals.update(approvals)

    @property
    def agents(self) -> Optional[Iterable[str]]:
        return self._agents

    @property
    def policies(self) -> Optional[Iterable[str]]:
        return self._policies

    @property
    def collections(self) -> Optional[Iterable[str]]:
        return self._collections

    @property
    def approvals(self) -> Optional[Iterable[str]]:
        return self._approvals


class IPedmAdmin(abc.ABC):
    @abc.abstractmethod
    def sync_down(self, *, reload: bool = False) -> None:
        pass

    @property
    @abc.abstractmethod
    def deployments(self) -> storage_types.IEntityReader[admin_types.PedmDeployment, str]:
        pass

    @property
    @abc.abstractmethod
    def agents(self) -> storage_types.IEntityReader[admin_types.PedmAgent, str]:
        pass


# class PedmAdminNotifications(notifications.BasePushNotifications):
#     def __init__(self, *, on_message: Callable[[Union[str, bytes]], None]):
#         super().__init__()
#         self.on_message = on_message
#
#     def on_messaged_received(self, message: Union[str, bytes]):
#         self.on_message(message)
#
#     async def on_connected(self):
#         pass


class PedmPlugin(IPedmAdmin):
    def __init__(self, params: KeeperParams):
        self.params = params
        if params.enterprise is None:
            raise Exception("Not an enterprise admin")
        self._enterprise_id = params.enterprise_id
        self.enterprise_uid: str = utils.base64_url_encode(self._enterprise_id.to_bytes(16, byteorder='big'))
        self.storage: admin_storage.IPedmStorage = admin_storage.SqlitePedmStorage(params.get_connection, self._enterprise_id)

        self.device_uid = utils.generate_uid()
        self._populate_data = True
        self._agent_key: Optional[bytes] = None
        self._all_agents: Optional[bytes] = None

        self._deployments = in_memory.InMemoryEntityStorage[admin_types.PedmDeployment, str]()
        self._agents = in_memory.InMemoryEntityStorage[admin_types.PedmAgent, str]()
        self._deployment_agents = in_memory.InMemoryLinkStorage[admin_types.PedmDeploymentAgent, str, str]()
        self._policies = in_memory.InMemoryEntityStorage[admin_types.PedmPolicy, str]()
        self._collections = in_memory.InMemoryEntityStorage[admin_types.PedmCollection, str]()
        self._approvals = in_memory.InMemoryEntityStorage[admin_types.PedmApproval, str]()

        # self._push_notifications = PedmAdminNotifications(on_message=self.on_push_message)
        # self.connect_pushes()
        self._need_sync = True
        self.logger = logging.getLogger("keeper.pedm")

    """
    def connect_pushes(self):
        auth = self.loader.keeper_auth


        if 'ROUTER_URL' in os.environ:
            router_url = os.environ['ROUTER_URL']
        else:
            router_url = f'https://{auth.keeper_endpoint.get_router_server()}'
        up = urlparse(router_url)
        url_comp = ('wss' if up.scheme == 'https' else 'ws', up.netloc, 'api/user/client', None, None, None)
        url = str(urlunparse(url_comp))

        transmission_key = utils.generate_aes_key()
        session_token = auth.auth_context.session_token
        encrypted_session_token = crypto.encrypt_aes_v2(session_token, transmission_key)
        encrypted_transmission_key = endpoint.encrypt_with_keeper_key(
            transmission_key, auth.keeper_endpoint.server_key_id)

        headers = {
            'TransmissionKey': base64.b64encode(encrypted_transmission_key).decode('ascii'),
            'Authorization': 'KeeperUser ' + base64.b64encode(encrypted_session_token).decode('ascii'),
        }
        asyncio.run_coroutine_threadsafe(
            self._push_notifications.main_loop(url=url, headers=headers), background.get_loop())

    def on_push_message(self, message: Union[str, bytes]):
        self.logger.debug('Received PEDM Admin notification: %s', message)
        if isinstance(message, str):
            try:
                data = json.loads(message)
                message_type = data.get('type')
                if message_type == 'pedm_sync':
                    self._need_sync = True
            except:
                pass
    """

    def close(self):
        pass

    @property
    def deployments(self) -> storage_types.IEntityReader[admin_types.PedmDeployment, str]:
        return self._deployments

    @property
    def agents(self) -> storage_types.IEntityReader[admin_types.PedmAgent, str]:
        return self._agents

    @property
    def policies(self) -> storage_types.IEntityReader[admin_types.PedmPolicy, str]:
        return self._policies

    @property
    def collections(self) -> storage_types.IEntityReader[admin_types.PedmCollection, str]:
        return self._collections

    @property
    def deployment_agents(self) -> storage_types.ILinkReader[admin_types.PedmDeploymentAgent, str, str]:
        return self._deployment_agents

    @property
    def approvals(self) -> storage_types.IEntityReader[admin_types.PedmApproval, str]:
        return self._approvals

    @property
    def need_sync(self) -> bool:
        return self._need_sync

    @property
    def agent_key(self) -> bytes:
        if self._agent_key is None:
            enterprise = self.params.enterprise
            tree_key = enterprise['unencrypted_tree_key']
            encrypted_ec_private_key = utils.base64_url_decode(enterprise['keys']['ecc_encrypted_private_key'])
            ec_private_key = crypto.decrypt_aes_v2(encrypted_ec_private_key, tree_key)

            x1 = int.from_bytes(tree_key[:16], byteorder='big', signed=False)
            x2 = int.from_bytes(tree_key[16:], byteorder='big', signed=False)
            salt = (x1 ^ x2).to_bytes(length=16, byteorder='big', signed=False)
            self._agent_key = crypto.derive_key_v1(utils.base64_url_encode(ec_private_key), salt, 1_000_000)
        return self._agent_key

    @property
    def all_agents(self) -> bytes:
        if self._all_agents is None:
            self._all_agents = (0).to_bytes(16, byteorder='big')
        return self._all_agents

    def build_data(self, task: RebuildTask) -> None:
        enterprise = self.params.enterprise
        tree_key = enterprise['unencrypted_tree_key']

        self._deployments.clear()
        deps: List[admin_types.PedmDeployment] = []
        for dep in self.storage.deployments.get_all_entities():
            try:
                pd = self.load_deployment(dep, tree_key)
                deps.append(pd)
            except Exception as e:
                self.logger.debug('Deployment "%s" decryption error: %s', dep.deployment_uid, e)
        self._deployments.put_entities(deps)

        if task.full_rebuild:
            self._agents.clear()
            self._policies.clear()
            self._collections.clear()
            self._approvals.clear()
        else:
            if task.agents is not None:
                self._agents.delete_uids(task.agents)
            if task.policies is not None:
                self._policies.delete_uids(task.policies)
            if task.collections is not None:
                self._collections.delete_uids(task.collections)
            if task.approvals is not None:
                self._approvals.delete_uids(task.approvals)

        def get_agents() -> Iterable[admin_storage.PedmStorageAgent]:
            if task.full_rebuild:
                yield from self.storage.agents.get_all_entities()
            if task.agents is not None:
                for agent_uid in task.agents:
                    a = self.storage.agents.get_entity(agent_uid)
                    if a is not None:
                        yield a

        ags: List[admin_types.PedmAgent] = []
        for agent_dto in get_agents():
            properties: Optional[Dict[str, Any]] = None
            if agent_dto.data is not None and len(agent_dto.data) > 0:
                try:
                    decrypted_data = crypto.decrypt_aes_v2(agent_dto.data, self.agent_key)
                    properties = json.loads(decrypted_data)
                except Exception as e:
                    self.logger.debug('Agent "%s" decryption error: %s', agent_dto.agent_uid, e)
            agent = admin_types.PedmAgent(
                agent_uid=agent_dto.agent_uid, machine_id=agent_dto.machine_id, created=agent_dto.created,
                deployment_uid=agent_dto.deployment_uid, disabled=agent_dto.disabled, public_key=agent_dto.public_key,
                properties=properties)
            ags.append(agent)
        self._agents.put_entities(ags)

        self._deployment_agents.clear()
        das: List[admin_types.PedmDeploymentAgent] = []
        for agent in self._agents.get_all_entities():
            if agent.deployment_uid:
                das.append(admin_types.PedmDeploymentAgent(deployment_uid=agent.deployment_uid, agent_uid=agent.agent_uid))
        self._deployment_agents.put_links(das)

        def get_policies() -> Iterable[admin_storage.PedmStoragePolicy]:
            if task.full_rebuild:
                yield from self.storage.policies.get_all_entities()
            elif task.policies is not None:
                for policy_uid in task.policies:
                    p = self.storage.policies.get_entity(policy_uid)
                    if p is not None:
                        yield p

        policies: List[admin_types.PedmPolicy] = []
        for policy_dto in get_policies():
            try:
                policy_key = crypto.decrypt_aes_v2(policy_dto.key, self.agent_key)
                json_data = crypto.decrypt_aes_v2(policy_dto.data, policy_key)
                data = json.loads(json_data)
                admin_data = json.loads(policy_dto.admin_data)
                policy = admin_types.PedmPolicy(policy_uid=policy_dto.policy_uid, policy_key=policy_key, data=data,
                                                admin_data=admin_data, disabled=policy_dto.disabled)
                policies.append(policy)
            except Exception as e:
                self.logger.debug('Policy load error: %s', e)
        if len(policies) > 0:
            self._policies.put_entities(policies)

        def get_collections() -> Iterable[admin_storage.PedmStorageCollection]:
            if task.full_rebuild:
                yield from self.storage.collections.get_all_entities()
            elif task.collections is not None:
                for collection_uid in task.collections:
                    c = self.storage.collections.get_entity(collection_uid)
                    if c is not None:
                        yield c

        collections: List[admin_types.PedmCollection] = []
        for collection_dto in get_collections():
            try:
                collection_value = crypto.decrypt_aes_v2(collection_dto.data, self.agent_key).decode('utf-8')
                collection_data = json.loads(collection_value)
                collection = admin_types.PedmCollection(
                    collection_uid=collection_dto.collection_uid, collection_type=collection_dto.collection_type,
                    collection_data=collection_data, created=collection_dto.created)
            except Exception as e:
                self.logger.info('Collection "%s" load error: %s', collection_dto.collection_uid, e)
                collection = admin_types.PedmCollection(
                    collection_uid=collection_dto.collection_uid, collection_type=collection_dto.collection_type,
                    collection_data={}, created=collection_dto.created)
            collections.append(collection)

        if len(collections) > 0:
            self._collections.put_entities(collections)

        def get_approvals() -> Iterable[admin_storage.PedmStorageApproval]:
            if task.full_rebuild:
                yield from self.storage.approvals.get_all_entities()
            elif task.approvals is not None:
                for approval_uid in task.approvals:
                    c = self.storage.approvals.get_entity(approval_uid)
                    if c is not None:
                        yield c

        approvals: List[admin_types.PedmApproval] = []
        for approval_dto in get_approvals():
            try:
                application_info = json.loads(crypto.decrypt_aes_v2(approval_dto.application_info, self.agent_key))
                account_info = json.loads(crypto.decrypt_aes_v2(approval_dto.account_info, self.agent_key))
                justification = crypto.decrypt_aes_v2(approval_dto.justification, self.agent_key) if approval_dto.justification else b''
                created = datetime.datetime.fromtimestamp(approval_dto.created / 1000)
                approval = admin_types.PedmApproval(
                    approval_uid=approval_dto.approval_uid, approval_type=approval_dto.approval_type,
                    agent_uid=approval_dto.agent_uid, account_info=account_info,
                    application_info=application_info, justification=justification.decode('utf-8'),
                    expire_in=approval_dto.expire_in, created=created
                )
                approvals.append(approval)
            except Exception as e:
                self.logger.warning('Approval "%s" load error: %s', approval_dto.approval_uid, e)
        if len(approvals) > 0:
            self._approvals.put_entities(approvals)

    def sync_down(self, *, reload: bool = False) -> None:
        if reload:
            self.storage.reset()
            self._populate_data = True

        task = RebuildTask(self._populate_data)
        setting = self.storage.settings.get_entity('PEDM_SYNC_TOKEN')
        if setting is None:
            setting = admin_storage.PedmAdminSettings(key='PEDM_SYNC_TOKEN', value='')
        token: bytes = b''
        if isinstance(setting.value, str) and len(setting.value) > 0:
            token = utils.base64_url_decode(setting.value)

        deployments: List[ admin_storage.PedmStorageDeployment] = []
        delete_deployments: List[str] = []
        policies: List[admin_storage.PedmStoragePolicy] = []
        delete_policies: List[str] = []
        agents: List[admin_storage.PedmStorageAgent] = []
        delete_agents: List[str] = []
        collections: List[admin_storage.PedmStorageCollection] = []
        delete_collections: List[str] = []
        collection_links: List[admin_storage.PedmStorageCollectionLink] = []
        delete_collection_links: List[Tuple[str, str]] = []
        approvals: List[admin_storage.PedmStorageApproval] = []
        delete_approvals: List[str] = []
        approval_status: List[admin_storage.PedmStorageApprovalStatus] = []

        sync_rq = pedm_pb2.GetPedmDataRequest()
        done = False
        while not done:
            sync_rq.continuationToken = token
            sync_rs = api.execute_router(self.params,'pedm/sync_pedm_data', sync_rq, rs_type=pedm_pb2.GetPedmDataResponse)
            assert sync_rs is not None
            if sync_rs.resetCache:
                self.storage.reset()

            token = sync_rs.continuationToken
            done = not sync_rs.hasMore

            for ra in sync_rs.removedAgents:
                agent_uid = utils.base64_url_encode(ra)
                delete_agents.append(agent_uid)

            for rp in sync_rs.removedPolicies:
                policy_uid = utils.base64_url_encode(rp)
                delete_policies.append(policy_uid)

            for rd in sync_rs.removedDeployments:
                deployment_uid = utils.base64_url_encode(rd)
                delete_deployments.append(deployment_uid)

            for rc in sync_rs.removedCollection:
                collection_uid = utils.base64_url_encode(rc)
                delete_collections.append(collection_uid)

            for rcl in sync_rs.removedCollectionLink:
                collection_uid = utils.base64_url_encode(rcl.collectionUid)
                link_uid = utils.base64_url_encode(rcl.linkUid)
                delete_collection_links.append((collection_uid, link_uid))

            for ra in sync_rs.removedApprovals:
                approval_uid = utils.base64_url_encode(ra)
                delete_approvals.append(approval_uid)

            for deployment in sync_rs.deployments:
                dep_id = utils.base64_url_encode(deployment.deploymentUid)
                psd = admin_storage.PedmStorageDeployment(
                    deployment_uid=dep_id, public_key=deployment.ecPublicKey, encrypted_key=deployment.aesKey,
                    disabled=deployment.disabled, data=deployment.encryptedData, created=deployment.created,
                    last_updated=deployment.modified)
                deployments.append(psd)

            for policy in sync_rs.policies:
                policy_uid = utils.base64_url_encode(policy.policyUid)
                policies.append(admin_storage.PedmStoragePolicy(
                    policy_uid=policy_uid, data=policy.encryptedData, admin_data=policy.plainData,
                    key=policy.encryptedKey, disabled=policy.disabled,
                    created=policy.created, updated=policy.modified))

            for agent in sync_rs.agents:
                agent_uid = utils.base64_url_encode(agent.agentUid)
                agents.append(admin_storage.PedmStorageAgent(
                    agent_uid=agent_uid, machine_id=agent.machineId, public_key=agent.ecPublicKey,
                    deployment_uid=utils.base64_url_encode(agent.deploymentUid), data=agent.encryptedData,
                    disabled=agent.disabled, created=agent.created, modified=agent.modified))

            for collection in sync_rs.collections:
                collection_uid = utils.base64_url_encode(collection.collectionUid)
                collections.append(admin_storage.PedmStorageCollection(
                    collection_uid=collection_uid, data=collection.encryptedData,
                    collection_type=collection.collectionType, created=collection.created))

            for collection_link in sync_rs.collectionLink:
                collection_uid = utils.base64_url_encode(collection_link.collectionUid)
                link_uid = utils.base64_url_encode(collection_link.linkUid)
                collection_links.append(admin_storage.PedmStorageCollectionLink(
                    collection_uid=collection_uid, link_uid=link_uid, link_type=collection_link.linkType))

            for approval in sync_rs.approvals:
                approval_uid = utils.base64_url_encode(approval.approvalUid)
                agent_uid = utils.base64_url_encode(approval.agentUid)

                approvals.append(admin_storage.PedmStorageApproval(
                    approval_uid=approval_uid, approval_type=approval.approvalType, agent_uid=agent_uid,
                    account_info=approval.accountInfo, application_info=approval.applicationInfo,
                    justification=approval.justification, expire_in=approval.expireIn, created=approval.created))

            for status in sync_rs.approvalStatus:
                approval_uid = utils.base64_url_encode(status.approvalUid)
                approval_status.append(admin_storage.PedmStorageApprovalStatus(
                    approval_uid=approval_uid, approval_status=status.approvalStatus,
                    enterprise_user_id=status.enterpriseUserId, modified=status.modified))

        setting.value = utils.base64_url_encode(token)
        self.storage.settings.put_entities([setting])

        if len(delete_deployments) > 0:
            uids = list(delete_deployments)
            self.storage.deployments.delete_uids(uids)
        if len(delete_policies) > 0:
            uids = list(delete_policies)
            task.add_policies(uids)
            self.storage.policies.delete_uids(uids)
        if len(delete_agents) > 0:
            task.add_agents(delete_agents)
            delete_approvals.extend(
                [x.approval_uid for x in self.storage.approvals.get_all_entities() if x.agent_uid in delete_agents])
            self.storage.collection_links.delete_links_for_objects(delete_agents)
            self.storage.agents.delete_uids(delete_agents)
        if len(delete_collections) > 0:
            task.add_collections(delete_collections)
            self.storage.collection_links.delete_links_for_subjects(delete_collections)
            self.storage.collection_links.delete_links_for_objects(delete_collections)
            self.storage.collections.delete_uids(delete_collections)
        if len(delete_collection_links) > 0:
            task.add_collections((x[0] for x in delete_collection_links))
            self.storage.collection_links.delete_links(delete_collection_links)
        if len(delete_approvals) > 0:
            task.add_approvals(delete_approvals)
            self.storage.approvals.delete_uids(delete_approvals)
            self.storage.approval_status.delete_uids(delete_approvals)
        if len(deployments) > 0:
            self.storage.deployments.put_entities(deployments)
        if len(policies) > 0:
            task.add_policies((x.policy_uid for x in policies))
            self.storage.policies.put_entities(policies)
        if len(agents) > 0:
            task.add_agents((x.agent_uid for x in agents))
            self.storage.agents.put_entities(agents)
        if len(collections) > 0:
            task.add_collections((x.collection_uid for x in collections))
            self.storage.collections.put_entities(collections)
        if len(collection_links) > 0:
            self.storage.collection_links.put_links(collection_links)
        if len(approvals) > 0:
            task.add_approvals((x.approval_uid for x in approvals))
            self.storage.approvals.put_entities(approvals)
        if len(approval_status) > 0:
            task.add_approvals((x.approval_uid for x in approval_status))
            self.storage.approval_status.put_entities(approval_status)

        self.build_data(task)
        self._need_sync = False
        self._populate_data = False

    def assign_policy_collections(
            self, policies: List[bytes], collections: List[bytes]
    ) -> admin_types.ModifyStatus:
        rq = pedm_pb2.SetPolicyCollectionRequest()
        for policy_uid in policies:
            rq_link = pedm_pb2.PolicyLink()
            rq_link.policyUid = policy_uid
            rq_link.collectionUid.extend(collections)
            rq.setCollection.append(rq_link)

        status_rs = api.execute_router(self.params, rq, 'pedm/set_policy_collections', rs_type=pedm_pb2.PedmStatusResponse)
        self._need_sync = True
        assert status_rs is not None
        return admin_types.ModifyStatus.from_proto(status_rs)

    def modify_policies(self, *,
                        add_policies: Optional[Iterable[admin_types.PedmPolicy]] = None,
                        update_policies: Optional[Iterable[admin_types.PedmUpdatePolicy]] = None,
                        remove_policies: Optional[Iterable[str]] = None) -> admin_types.ModifyStatus:
        rq = pedm_pb2.PolicyRequest()
        if add_policies is not None:
            for policy in add_policies:
                pa = pedm_pb2.PolicyAdd()
                policy_uid = policy.policy_uid or utils.generate_uid()
                pa.policyUid = utils.base64_url_decode(policy_uid)
                policy_key = policy.policy_key or utils.generate_aes_key()
                pa.encryptedKey = crypto.encrypt_aes_v2(policy_key, self.agent_key)

                admin_data = json.dumps(policy.admin_data).encode('utf-8')
                pa.plainData = admin_data

                policy_data = json.dumps(policy.data).encode('utf-8')
                encrypted_data = crypto.encrypt_aes_v2(policy_data, policy_key)
                pa.encryptedData = encrypted_data

                pa.disabled = policy.disabled
                rq.addPolicy.append(pa)
        if update_policies is not None:
            for policy_update in update_policies:
                policy_uid = policy_update.policy_uid
                existing_policy = self.policies.get_entity(policy_uid)
                if existing_policy is None:
                    raise Exception(f'Update: Policy {policy_uid} not found')
                pu = pedm_pb2.PolicyUpdate()
                pu.policyUid = utils.base64_url_decode(existing_policy.policy_uid)
                if isinstance(policy_update.admin_data, dict):
                    pass
                if isinstance(policy_update.data, dict):
                    json_policy = json.dumps(policy_update.data).encode('utf-8')
                    encrypted_data = crypto.encrypt_aes_v2(json_policy, existing_policy.policy_key)
                    pu.encryptedData = encrypted_data
                if isinstance(policy_update.disabled, bool):
                    pu.disabled = folder_pb2.BOOLEAN_TRUE if policy_update.disabled else folder_pb2.BOOLEAN_FALSE
                rq.updatePolicy.append(pu)
        if remove_policies is not None:
            rq.removePolicy.extend((utils.base64_url_decode(x) for x in remove_policies))

        status_rs = api.execute_router(self.params, 'pedm/modify_policy', rq, rs_type=pedm_pb2.PedmStatusResponse)
        self._need_sync = True
        assert status_rs is not None
        return admin_types.ModifyStatus.from_proto(status_rs)


    @staticmethod
    def load_deployment(s_dep: admin_storage.PedmStorageDeployment, tree_key: bytes) -> admin_types.PedmDeployment:
        deployment_key = crypto.decrypt_aes_v2(s_dep.encrypted_key, tree_key)
        decrypted_data = crypto.decrypt_aes_v2(s_dep.data, deployment_key)
        data = pedm_pb2.DeploymentData()
        data.ParseFromString(decrypted_data)
        name = data.name
        d_private_key = data.ecPrivateKey
        created = datetime.datetime.fromtimestamp(s_dep.created / 1000)
        updated = datetime.datetime.fromtimestamp(s_dep.last_updated / 1000)
        return admin_types.PedmDeployment(
            deployment_uid=s_dep.deployment_uid, name=name, deployment_key=deployment_key, disabled=s_dep.disabled,
            created=created, updated=updated, public_key=s_dep.public_key, private_key=d_private_key)

    def modify_deployments(self, *,
                        add_deployments: Optional[Iterable[admin_types.AddDeployment]] = None,
                        update_deployments: Optional[Iterable[admin_types.UpdateDeployment]] = None,
                        remove_deployments: Optional[Iterable[str]] = None) -> admin_types.ModifyStatus:
        enterprise = self.params.enterprise
        tree_key = enterprise['unencrypted_tree_key']

        mrq = pedm_pb2.ModifyDeploymentRequest()
        if add_deployments is not None:
            for add_deployment in add_deployments:
                deployment_uid = utils.generate_uid()
                deployment_key = utils.generate_aes_key()
                priv_key, pub_key = crypto.generate_ec_key()
                d_public_key = crypto.unload_ec_public_key(pub_key)
                d_private_key = crypto.unload_ec_private_key(priv_key)

                a_rq = pedm_pb2.DeploymentCreateRequest()
                a_rq.deploymentUid = utils.base64_url_decode(deployment_uid)
                a_rq.aesKey = crypto.encrypt_aes_v2(deployment_key, tree_key)
                a_rq.ecPublicKey = d_public_key
                if isinstance(add_deployment.spiffe_cert, bytes) and len(add_deployment.spiffe_cert) > 0:
                    a_rq.spiffeCertificate = add_deployment.spiffe_cert
                data = pedm_pb2.DeploymentData()
                data.ecPrivateKey = d_private_key
                if add_deployment.name:
                    data.name = add_deployment.name
                data_bytes = data.SerializeToString()
                a_rq.encryptedData = crypto.encrypt_aes_v2(data_bytes, deployment_key)
                agent_data = json.dumps(add_deployment.agent_info.to_dict()).encode('utf-8')
                a_rq.agentData = crypto.encrypt_ec(agent_data, pub_key)
                mrq.addDeployment.append(a_rq)

        if update_deployments is not None:
            for ud in update_deployments:
                deployment_uid = ud.deployment_uid
                s_dep = self.storage.deployments.get_entity(deployment_uid)
                if not s_dep:
                    raise Exception(f'Update Deployment: "{deployment_uid}" not found')
                dep = self.load_deployment(s_dep, tree_key)

                u_rq = pedm_pb2.DeploymentUpdateRequest()
                u_rq.deploymentUid = utils.base64_url_decode(ud.deployment_uid)
                if ud.disabled is None:
                    u_rq.disabled = folder_pb2.BOOLEAN_NO_CHANGE
                else:
                    u_rq.disabled = folder_pb2.BOOLEAN_TRUE if ud.disabled else folder_pb2.BOOLEAN_FALSE
                if ud.name:
                    data = pedm_pb2.DeploymentData()
                    data.ecPrivateKey =dep.private_key
                    data.name = ud.name
                    data_bytes = data.SerializeToString()
                    u_rq.encryptedData = crypto.encrypt_aes_v2(data_bytes, dep.deployment_key)
                if ud.spiffe_cert is not None:
                    u_rq.spiffeCertificate = ud.spiffe_cert

                mrq.updateDeployment.append(u_rq)

        if remove_deployments is not None:
            for deployment_uid in remove_deployments:
                s_dep = self.storage.deployments.get_entity(deployment_uid)
                if not s_dep:
                    raise Exception(f'Delete Deployment: "{deployment_uid}" not found')
                mrq.removeDeployment.append(utils.base64_url_decode(deployment_uid))

        status_rs = api.execute_router(self.params,'pedm/modify_deployment', request=mrq, rs_type=pedm_pb2.PedmStatusResponse)
        assert status_rs is not None
        self._need_sync = True
        return admin_types.ModifyStatus.from_proto(status_rs)

    def modify_collections(self, *,
                        add_collections: Optional[Iterable[admin_types.CollectionData]] = None,
                        update_collections: Optional[Iterable[admin_types.CollectionData]] = None,
                        remove_collections: Optional[Iterable[str]] = None) -> admin_types.ModifyStatus:
        to_add: List[pedm_pb2.CollectionValue] = []
        to_update: List[pedm_pb2.CollectionValue] = []
        if add_collections is not None:
            for coll in add_collections:
                if not coll.collection_uid:
                    try:
                        data = json.loads(coll.collection_data)
                        if not isinstance(data, dict):
                            raise Exception('Collection data must be JSON object to compute UID')
                        required = pedm_shared.get_collection_required_fields(coll.collection_type)
                        if not required:
                            raise Exception(f'Unknown collection type: {coll.collection_type}')
                        key_fields = required.primary_key_fields or required.all_fields
                        key_parts: List[str] = []
                        for k in key_fields:
                            if k not in data or not isinstance(data[k], str):
                                raise Exception(f'Collection data missing required text field "{k}"')
                            key_parts.append(data[k])
                        key = ''.join(key_parts)
                        coll.collection_uid = pedm_shared.get_collection_uid(self.agent_key, coll.collection_type, key)
                    except Exception as err:
                        status.add.append(admin_types.EntityStatus(entity_uid='', success=False, message=str(err)))
                        continue
                cv = pedm_pb2.CollectionValue()
                cv.collectionUid = utils.base64_url_decode(coll.collection_uid)
                cv.collectionType = coll.collection_type
                cv.encryptedData = crypto.encrypt_aes_v2(coll.collection_data.encode(), self.agent_key)
                to_add.append(cv)

        if update_collections is not None:
            for coll in update_collections:
                if not coll.collection_uid:
                    raise Exception('Update collection requires collection_uid')
                cv = pedm_pb2.CollectionValue()
                cv.collectionUid = utils.base64_url_decode(coll.collection_uid)
                cv.collectionType = coll.collection_type
                cv.encryptedData = crypto.encrypt_aes_v2(coll.collection_data.encode(), self.agent_key)
                to_update.append(cv)
        to_remove: List[bytes] = []
        if remove_collections is not None:
            for collection_uid in remove_collections:
                to_remove.append(utils.base64_url_decode(collection_uid))

        status = admin_types.ModifyStatus(add=[], update=[], remove=[])
        while len(to_add) > 0 or len(to_update) > 0 or len(to_remove) > 0:
            crq = pedm_pb2.CollectionRequest()
            if len(to_add) > 0:
                add_chunk = to_add[:500]
                to_add = to_add[500:]
                crq.addCollection.extend(add_chunk)

            if len(to_update) > 0:
                update_chunk = to_update[:500]
                to_update = to_update[500:]
                crq.updateCollection.extend(update_chunk)

            if len(to_remove) > 0:
                remove_chunk = to_remove[:500]
                to_remove = to_remove[500:]
                crq.removeCollection.extend(remove_chunk)
            status_rs = api.execute_router(self.params, 'pedm/modify_collection', request=crq,
                                           rs_type=pedm_pb2.PedmStatusResponse)
            assert status_rs is not None
            status.merge(admin_types.ModifyStatus.from_proto(status_rs))
        self._need_sync = True
        return status

    def get_collection_links(self, *, links: Iterable[admin_types.CollectionLink]) -> Iterable[admin_types.CollectionLinkData]:
        link_rq = pedm_pb2.GetCollectionLinkRequest()
        for l in links:
            cl = pedm_pb2.CollectionLink()
            cl.collectionUid = utils.base64_url_decode(l.collection_uid)
            cl.linkType = cast(pedm_pb2.CollectionLinkType, l.link_type)
            cl.linkUid = utils.base64_url_decode(l.link_uid)
            link_rq.collectionLink.append(cl)
        link_rs = api.execute_router(self.params, 'pedm/get_collection_links', request=link_rq,
                                     rs_type=pedm_pb2.GetCollectionLinkResponse)
        assert link_rs is not None
        for ld in link_rs.collectionLinkData:
            collection_link = admin_types.CollectionLink(
                collection_uid=utils.base64_url_encode(ld.collectionUid), link_type=ld.linkType,
                link_uid=utils.base64_url_encode(ld.linkUid))
            yield admin_types.CollectionLinkData(collection_link=collection_link, link_data=ld.linkData)

    def set_collection_links(
            self, *, set_links: Optional[Iterable[admin_types.CollectionLink]] = None,
            unset_links: Optional[Iterable[admin_types.CollectionLink]] = None
    ) -> admin_types.ModifyStatus:
        clrq = pedm_pb2.SetCollectionLinkRequest()
        if set_links is not None:
            for coll in set_links:
                cln = pedm_pb2.CollectionLinkData()
                cln.collectionUid = utils.base64_url_decode(coll.collection_uid)
                cln.linkUid = utils.base64_url_decode(coll.link_uid)
                cln.linkType = coll.link_type     # type: ignore
                clrq.addCollection.append(cln)

        if unset_links is not None:
            for coll in unset_links:
                cl = pedm_pb2.CollectionLink()
                cl.collectionUid = utils.base64_url_decode(coll.collection_uid)
                cl.linkUid = utils.base64_url_decode(coll.link_uid)
                cl.linkType = coll.link_type      # type: ignore
                clrq.removeCollection.append(cl)

        status_rs = api.execute_router(self.params, 'pedm/set_collection_links', request=clrq,
                                       rs_type=pedm_pb2.PedmStatusResponse)
        assert status_rs is not None
        self._need_sync = True
        return admin_types.ModifyStatus.from_proto(status_rs)

    def modify_agents(self, *,
                        update_agents: Optional[Iterable[admin_types.UpdateAgent]] = None,
                        remove_agents: Optional[Iterable[str]] = None) -> admin_types.ModifyStatus:
        rq = pedm_pb2.ModifyAgentRequest()
        if update_agents is not None:
            for ua in update_agents:
                agent_uid = ua.agent_uid
                existing_agent = self.agents.get_entity(agent_uid)
                if existing_agent is None:
                    raise Exception(f'Update: Policy {agent_uid} not found')
                au = pedm_pb2.AgentUpdate()
                au.agentUid = utils.base64_url_decode(agent_uid)
                if isinstance(ua.deployment_uid, str):
                    au.deploymentUid = utils.base64_url_decode(ua.deployment_uid)
                if isinstance(ua.disabled, bool):
                    au.disabled = folder_pb2.BOOLEAN_TRUE if ua.disabled else folder_pb2.BOOLEAN_FALSE

                rq.updateAgent.append(au)
        if remove_agents is not None:
            rq.removeAgent.extend((utils.base64_url_decode(x) for x in remove_agents))

        status_rs = api.execute_router(self.params,'pedm/modify_agent', rq, rs_type=pedm_pb2.PedmStatusResponse)
        self._need_sync = True
        assert status_rs is not None
        return admin_types.ModifyStatus.from_proto(status_rs)

    def modify_approvals(self, *,
                        to_approve: Optional[List[bytes]] = None,
                        to_deny: Optional[List[bytes]] = None,
                        to_remove: Optional[List[bytes]] = None) -> admin_types.ModifyStatus:
        rq = pedm_pb2.ApprovalActionRequest()
        if to_approve:
            rq.approve.extend(to_approve)
        if to_deny:
            rq.deny.extend(to_deny)
        if to_remove:
            rq.remove.extend(to_remove)

        status_rs = api.execute_router(self.params, 'pedm/approval_action', rq, rs_type=pedm_pb2.PedmStatusResponse)
        self._need_sync = True
        assert status_rs is not None
        return admin_types.ModifyStatus.from_proto(status_rs)


def get_pedm_plugin(context: KeeperParams, *, skip_sync:bool=False) -> PedmPlugin:
    if context._pedm_plugin is None:
        context._pedm_plugin = PedmPlugin(context)

    if not skip_sync and context._pedm_plugin.need_sync:
        context._pedm_plugin.sync_down()
    return context._pedm_plugin
