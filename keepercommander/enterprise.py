#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import json
import logging
from typing import Optional, List, Set, Tuple, Dict

from google.protobuf import message

from .params import KeeperParams
from .proto import enterprise_pb2 as proto
from . import api, utils, crypto


def query_enterprise(params, tree_key=None):  # type: (KeeperParams, Optional[bytes]) -> None
    if not params.enterprise_loader:
        params.enterprise_loader = _EnterpriseLoader(tree_key)
    params.enterprise_loader.load(params)


def _to_key_type(key_type):  # type: (proto.EncryptedKeyType) -> str
    if key_type == proto.KT_ENCRYPTED_BY_DATA_KEY:
        return 'encrypted_by_data_key'
    if key_type == proto.KT_ENCRYPTED_BY_PUBLIC_KEY:
        return 'encrypted_by_public_key'
    if key_type == proto.KT_ENCRYPTED_BY_DATA_KEY_GCM:
        return 'encrypted_by_data_key_gcm'
    if key_type == proto.KT_ENCRYPTED_BY_PUBLIC_KEY_ECC:
        return 'encrypted_by_public_key_ecc'
    return 'no_key'


class EnterpriseInfo(object):
    def __init__(self):
        self._tree_key = b''
        self._rsa_key = b''
        self._ec_key = b''
        self._enterprise_name = ''

    @property
    def tree_key(self):
        return self._tree_key

    @property
    def rsa_key(self):
        return self._rsa_key

    @property
    def ec_key(self):
        return self._ec_key

    @property
    def enterprise_name(self):
        return self._enterprise_name


class _EnterpriseLoader(object):
    def __init__(self, tree_key=None):
        super(_EnterpriseLoader, self).__init__()
        self._enterprise = EnterpriseInfo()
        self._enterprise._tree_key = tree_key
        self._continuationToken = b''
        self._data_types = {   # type: dict[int, _EnterpriseDataParser]
            proto.NODES: _EnterpriseNodeEntity(self._enterprise),
            proto.USERS: _EnterpriseUserEntity(self._enterprise),
            proto.TEAMS: _EnterpriseTeamEntity(self._enterprise),
            proto.ROLES: _EnterpriseRoleEntity(self._enterprise),
            proto.LICENSES: _EnterpriseLicenseEntity(self._enterprise),
            proto.QUEUED_TEAMS: _EnterpriseQueuedTeamEntity(self._enterprise),
            proto.SCIMS: _EnterpriseScimEntity(self._enterprise),
            proto.SSO_SERVICES: _EnterpriseSsoServiceEntity(self._enterprise),
            proto.BRIDGES: _EnterpriseBridgeEntity(self._enterprise),
            proto.EMAIL_PROVISION: _EnterpriseEmailProvisionEntity(self._enterprise),
            proto.TEAM_USERS: _EnterpriseTeamUserEntity(self._enterprise),
            proto.QUEUED_TEAM_USERS: _EnterpriseQueuedTeamUserEntity(self._enterprise),
            proto.ROLE_USERS: _EnterpriseRoleUserEntity(self._enterprise),
            proto.ROLE_TEAMS: _EnterpriseRoleTeamEntity(self._enterprise),
            proto.MANAGED_NODES: _EnterpriseManagedNodeEntity(self._enterprise),
            proto.ROLE_PRIVILEGES: _EnterpriseRolePrivilegeEntity(self._enterprise),
            proto.ROLE_ENFORCEMENTS: _EnterpriseRoleEnforcements(self._enterprise),
            proto.MANAGED_COMPANIES: _EnterpriseManagedCompanyEntity(self._enterprise),
            proto.DEVICES_REQUEST_FOR_ADMIN_APPROVAL: _EnterpriseAdminApprovalRequestEntity(self._enterprise),
            proto.USER_ALIASES: _EnterpriseUserAliasEntity(self._enterprise),
        }
        teams = self._data_types[proto.TEAMS]
        if isinstance(teams, _EnterpriseEntity):
            teams.register_link('team_uid', self._data_types[proto.TEAM_USERS])
            teams.register_link('team_uid', self._data_types[proto.ROLE_TEAMS])
            teams.register_link('team_uid', self._data_types[proto.QUEUED_TEAM_USERS])

        users = self._data_types[proto.USERS]
        if isinstance(teams, _EnterpriseEntity):
            users.register_link('enterprise_user_id', self._data_types[proto.TEAM_USERS])
            users.register_link('enterprise_user_id', self._data_types[proto.ROLE_USERS])
            teams.register_link('enterprise_user_id', self._data_types[proto.QUEUED_TEAM_USERS])

        roles = self._data_types[proto.ROLES]
        if isinstance(roles, _EnterpriseEntity):
            roles.register_link('role_id', self._data_types[proto.ROLE_TEAMS])
            roles.register_link('role_id', self._data_types[proto.ROLE_USERS])
            roles.register_link('role_id', self._data_types[proto.MANAGED_NODES])

    @property
    def enterprise(self):
        return self._enterprise

    def load(self, params):  # type: (KeeperParams) -> None
        if params.enterprise is None:
            params.enterprise = {}
            self._continuationToken = b''

        if 'unencrypted_tree_key' not in params.enterprise or 'keys' not in params.enterprise:
            rq = proto.GetEnterpriseDataKeysRequest()
            rs = api.communicate_rest(params, rq, 'enterprise/get_enterprise_data_keys',
                                      rs_type=proto.GetEnterpriseDataKeysResponse)
            if not self._enterprise.tree_key:
                if rs.treeKey.treeKey:
                    encrypted_tree_key = utils.base64_url_decode(rs.treeKey.treeKey)
                    if rs.treeKey.keyTypeId == proto.ENCRYPTED_BY_DATA_KEY:
                        self._enterprise._tree_key = crypto.decrypt_aes_v1(encrypted_tree_key, params.data_key)
                    elif rs.treeKey.keyTypeId == proto.ENCRYPTED_BY_PUBLIC_KEY:
                        self._enterprise._tree_key = crypto.decrypt_rsa(encrypted_tree_key, params.rsa_key2)
            params.enterprise['unencrypted_tree_key'] = self._enterprise.tree_key

            keys = {}    # type: Dict[str, str]
            if rs.enterpriseKeys:
                if rs.enterpriseKeys.rsaEncryptedPrivateKey:
                    try:
                        self._enterprise._rsa_key = \
                            crypto.decrypt_aes_v2(rs.enterpriseKeys.rsaEncryptedPrivateKey, self._enterprise.tree_key)
                        keys['rsa_public_key'] = utils.base64_url_encode(rs.enterpriseKeys.rsaPublicKey)
                        keys['rsa_encrypted_private_key'] = \
                            utils.base64_url_encode(rs.enterpriseKeys.rsaEncryptedPrivateKey)
                    except:
                        logging.warning('Error decrypting enterprise RSA key')
                        keys['rsa_encrypted_private_key'] = ''
                if rs.enterpriseKeys.eccEncryptedPrivateKey:
                    keys['ecc_public_key'] = utils.base64_url_encode(rs.enterpriseKeys.eccPublicKey)
                    keys['ecc_encrypted_private_key'] = \
                        utils.base64_url_encode(rs.enterpriseKeys.eccEncryptedPrivateKey)
            if 'rsa_encrypted_private_key' not in keys:
                rsa_private, rsa_public = crypto.generate_rsa_key()
                rsa_private_key = crypto.unload_rsa_private_key(rsa_private)
                rsa_encrypted_private_key = crypto.encrypt_aes_v2(rsa_private_key, self._enterprise.tree_key)
                rsa_public_key = crypto.unload_rsa_public_key(rsa_public)
                rq = proto.EnterpriseKeyPairRequest()
                rq.enterprisePublicKey = rsa_public_key
                rq.encryptedEnterprisePrivateKey = rsa_encrypted_private_key
                rq.keyType = proto.RSA
                api.communicate_rest(params, rq, 'enterprise/set_enterprise_key_pair')
                self._enterprise._rsa_key = rsa_private_key
                keys['rsa_public_key'] = utils.base64_url_encode(rsa_public_key)
                keys['rsa_encrypted_private_key'] = utils.base64_url_encode(rsa_encrypted_private_key)

            if 'ecc_encrypted_private_key' not in keys:
                ec_private, ec_public = crypto.generate_ec_key()
                ec_private_key = crypto.unload_ec_private_key(ec_private)
                ec_encrypted_private_key = crypto.encrypt_aes_v2(ec_private_key, self._enterprise.tree_key)
                ec_public_key = crypto.unload_ec_public_key(ec_public)
                rq = proto.EnterpriseKeyPairRequest()
                rq.enterprisePublicKey = ec_public_key
                rq.encryptedEnterprisePrivateKey = ec_encrypted_private_key
                rq.keyType = proto.ECC
                api.communicate_rest(params, rq, 'enterprise/set_enterprise_key_pair')
                keys['ecc_public_key'] = utils.base64_url_encode(ec_public_key)
                keys['ecc_encrypted_private_key'] = utils.base64_url_encode(ec_encrypted_private_key)

            params.enterprise['keys'] = keys
        entities = set()
        while True:
            rq = proto.EnterpriseDataRequest()
            if self._continuationToken:
                rq.continuationToken = self._continuationToken
            rs = api.communicate_rest(params, rq, 'enterprise/get_enterprise_data_for_user',
                                      rs_type=proto.EnterpriseDataResponse)

            if rs.cacheStatus == proto.CLEAR:
                for d in self._data_types.values():
                    d.clear(params)
                self._enterprise._enterprise_name = ''

            if not self._enterprise.enterprise_name and rs.generalData:
                self._enterprise._enterprise_name = rs.generalData.enterpriseName
                params.enterprise['enterprise_name'] = self._enterprise.enterprise_name
                if rs.generalData.distributor:
                    params.enterprise['distributor'] = True

            for ed in rs.data:
                entities.add(ed.entity)
                parser = self._data_types.get(ed.entity)
                if parser:
                    parser.parse(params, ed)

            self._continuationToken = rs.continuationToken
            if not rs.hasMore:
                break
        if proto.MANAGED_NODES in entities:
            self.load_missing_role_keys(params)
        if not entities.isdisjoint([proto.MANAGED_NODES, proto.NODES, proto.ROLE_USERS]):
            if 'user_root_nodes' in params.enterprise:
                del params.enterprise['user_root_nodes']
            if 'user_managed_nodes' in params.enterprise:
                del params.enterprise['user_managed_nodes']

    @staticmethod
    def load_missing_role_keys(params):   # type: (KeeperParams) -> None
        nodes = set()
        if 'managed_nodes' in params.enterprise:
            for mn in params.enterprise['managed_nodes']:
                nodes.add(mn['role_id'])
        if len(nodes) > 0:
            roles = set()
            if 'role_keys' in params.enterprise:
                for rk in params.enterprise['role_keys']:
                    roles.add(rk['role_id'])
            if 'role_keys2' in params.enterprise:
                for rk in params.enterprise['role_keys2']:
                    roles.add(rk['role_id'])
            nodes.difference_update(roles)
        if len(nodes) > 0:
            rq = proto.GetEnterpriseDataKeysRequest()
            rq.roleId.extend(nodes)
            rs = api.communicate_rest(params, rq, 'enterprise/get_enterprise_data_keys',
                                      rs_type=proto.GetEnterpriseDataKeysResponse)
            if len(rs.roleKey) > 0:
                if 'role_keys' not in params.enterprise:
                    params.enterprise['role_keys'] = []
                for rk1 in rs.roleKey:
                    params.enterprise['role_keys'].append({
                        'role_id': rk1.roleId,
                        'encrypted_key': rk1.encryptedKey,
                        'key_type': _to_key_type(rk1.keyType)
                    })

            if len(rs.reEncryptedRoleKey) > 0:
                if 'role_keys2' not in params.enterprise:
                    params.enterprise['role_keys2'] = []
                for rk2 in rs.reEncryptedRoleKey:
                    params.enterprise['role_keys2'].append({
                        'role_id': rk2.role_id,
                        'role_key': utils.base64_url_encode(rk2.encryptedRoleKey),
                    })


class _EnterpriseDataParser(abc.ABC):
    def __init__(self, enterprise):    # type: (EnterpriseInfo) -> None
        self.enterprise = enterprise

    @abc.abstractmethod
    def parse(self, params, enterprise_data, **kwargs):  # type: (KeeperParams, proto.EnterpriseData, dict) -> None
        pass

    @abc.abstractmethod
    def get_entity_type(self):
        pass

    @abc.abstractmethod
    def get_keeper_entity_name(self):  # type: () -> str
        pass

    @abc.abstractmethod
    def to_keeper_entity(self, proto_entity, keeper_entity):
        pass

    def get_entities(self, params, create_if_absent=True):  # type: (KeeperParams, bool) -> Optional[List]
        name = self.get_keeper_entity_name()
        if name not in params.enterprise:
            if not create_if_absent:
                return None
            params.enterprise[name] = []
        return params.enterprise[name]

    def clear(self, params):  # type: (KeeperParams) -> None
        entities = self.get_entities(params, create_if_absent=False)
        if entities:
            entities.clear()


class _EnterpriseEntity(_EnterpriseDataParser):
    def __init__(self, enterprise):  # type: (EnterpriseInfo) -> None
        super(_EnterpriseEntity, self).__init__(enterprise)
        self._links = []     # type: List[Tuple[str, _CascadeDeleteLink]]

    @abc.abstractmethod
    def get_keeper_entity_id(self, proto_entity):  # type: (dict) -> any
        pass

    @abc.abstractmethod
    def get_proto_entity_id(self, proto_entity):  # type: (message.Message) -> any
        pass

    @staticmethod
    def fix_data(d):  # type: (bytes) -> bytes
        idx = d.rfind(b'}')
        if idx < len(d) - 1:
            d = d[:idx+1]
        return d

    def register_link(self, keeper_entity_id_name, parser):  # type: (str, _EnterpriseDataParser) -> None
        if isinstance(parser, _CascadeDeleteLink):
            self._links.append((keeper_entity_id_name, parser))

    def parse(self, params, enterprise_data, **kwargs):  # type: (KeeperParams, proto.EnterpriseData, dict) -> None
        if not enterprise_data.data:
            return

        entities = self.get_entities(params)
        entity_map = {self.get_keeper_entity_id(x): x for x in entities}
        entity_type = self.get_entity_type()
        deleted_entities = set()
        for entityData in enterprise_data.data:
            entity = entity_type()
            entity.ParseFromString(entityData)
            entity_id = self.get_proto_entity_id(entity)
            if enterprise_data.delete:
                if entity_id in entity_map:
                    entity_map.pop(entity_id)
                    deleted_entities.add(entity_id)
            else:
                keeper_entity = entity_map.get(entity_id)
                if not keeper_entity:
                    keeper_entity = {}
                    entity_map[entity_id] = keeper_entity
                self.to_keeper_entity(entity, keeper_entity)

        entities.clear()
        entities.extend(entity_map.values())
        if len(deleted_entities) > 0:
            for keeper_entity_id_name, link in self._links:
                link.cascade_delete(params, keeper_entity_id_name, deleted_entities)


class _CascadeDeleteLink:
    @abc.abstractmethod
    def cascade_delete(self, params, keeper_entity_id, deleted_entities):   # type: (KeeperParams, str, Set) -> None
        pass


class _EnterpriseLink(_EnterpriseDataParser, _CascadeDeleteLink):
    @abc.abstractmethod
    def get_keeper_entity1_id(self, proto_entity):  # type: (dict) -> any
        pass

    @abc.abstractmethod
    def get_keeper_entity2_id(self, proto_entity):  # type: (dict) -> any
        pass

    @abc.abstractmethod
    def get_proto_entity1_id(self, proto_entity):  # type: (message.Message) -> any
        pass

    @abc.abstractmethod
    def get_proto_entity2_id(self, proto_entity):  # type: (message.Message) -> any
        pass

    def cascade_delete(self, params, keeper_entity_id, deleted_entities):   # type: (KeeperParams, str, Set) -> None
        entities = self.get_entities(params, create_if_absent=False)
        if not entities:
            return
        to_keep = [x for x in entities if keeper_entity_id not in x or x[keeper_entity_id] not in deleted_entities]
        if len(to_keep) < len(entities):
            entities.clear()
            entities.extend(to_keep)

    def parse(self, params, enterprise_data, **kwargs):  # type: (KeeperParams, proto.EnterpriseData, dict) -> None
        entities = self.get_entities(params)
        entity_map = {
            '{0}:{1}'.format(self.get_keeper_entity1_id(x), self.get_keeper_entity2_id(x)): x for x in entities
        }
        entity_type = self.get_entity_type()
        for entityData in enterprise_data.data:
            entity = entity_type()
            entity.ParseFromString(entityData)
            entity1_id = self.get_proto_entity1_id(entity)
            entity2_id = self.get_proto_entity2_id(entity)
            key = '{0}:{1}'.format(entity1_id, entity2_id)
            if enterprise_data.delete:
                if key in entity_map:
                    entity_map.pop(key)
            else:
                keeper_entity = entity_map.get(key)
                if not keeper_entity:
                    keeper_entity = {}
                    entity_map[key] = keeper_entity
                self.to_keeper_entity(entity, keeper_entity)

        entities.clear()
        entities.extend(entity_map.values())

    def get_entities(self, params, create_if_absent=True):  # type: (KeeperParams, bool) -> Optional[List]
        name = self.get_keeper_entity_name()
        if name not in params.enterprise:
            if not create_if_absent:
                return None
            params.enterprise[name] = []
        return params.enterprise[name]


def _set_or_remove(obj, key, value):  # type: (dict, str, any) -> None
    if value is not None:
        obj[key] = value
    else:
        if key in obj:
            obj.pop(key)


class _EnterpriseNodeEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.Node, dict) -> None
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'parent_id', proto_entity.parentId if proto_entity.parentId > 0 else None)
        _set_or_remove(keeper_entity, 'bridge_id', proto_entity.bridgeId if proto_entity.bridgeId > 0 else None)
        _set_or_remove(keeper_entity, 'scim_id', proto_entity.scimId if proto_entity.scimId > 0 else None)
        _set_or_remove(keeper_entity, 'license_id', proto_entity.licenseId if proto_entity.licenseId > 0 else None)
        _set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        _set_or_remove(keeper_entity, 'duo_enabled', True if proto_entity.duoEnabled else None)
        _set_or_remove(keeper_entity, 'rsa_enabled', True if proto_entity.rsaEnabled else None)
        _set_or_remove(keeper_entity, 'sso_service_provider_id',
                       proto_entity.ssoServiceProviderId if proto_entity.ssoServiceProviderId > 0 else None)
        _set_or_remove(keeper_entity, 'restrict_visibility',
                       proto_entity.restrictVisibility if proto_entity.restrictVisibility else None)

        data = {}
        if 'encrypted_data' in keeper_entity:
            try:
                encrypted_data = utils.base64_url_decode(keeper_entity['encrypted_data'])
                data_json = crypto.decrypt_aes_v1(encrypted_data, self.enterprise.tree_key)
                data_json = self.fix_data(data_json)
                data.update(json.loads(data_json.decode('utf-8')))
            except Exception as e:
                logging.warning('Decrypt encryption data error: %s', e)
        elif 'parent_id' not in keeper_entity:
            data['displayname'] = self.enterprise.enterprise_name
        keeper_entity['data'] = data

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('node_id')

    def get_proto_entity_id(self, entity):  # type: (proto.Node) -> any
        return entity.nodeId

    def get_entity_type(self):
        return proto.Node

    def get_keeper_entity_name(self):  # type: () -> str
        return 'nodes'


class _EnterpriseUserEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.User, dict) -> None
        _set_or_remove(keeper_entity, 'enterprise_user_id', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'username', proto_entity.username)
        _set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        _set_or_remove(keeper_entity, 'key_type', proto_entity.keyType.lower())
        _set_or_remove(keeper_entity, 'status', proto_entity.status)
        _set_or_remove(keeper_entity, 'lock', proto_entity.lock)
        _set_or_remove(keeper_entity, 'user_id', proto_entity.userId)
        _set_or_remove(keeper_entity, 'account_share_expiration',
                       proto_entity.accountShareExpiration if proto_entity.accountShareExpiration > 0 else None)
        _set_or_remove(keeper_entity, 'full_name', proto_entity.fullName if proto_entity.fullName else None)
        _set_or_remove(keeper_entity, 'job_title', proto_entity.jobTitle if proto_entity.jobTitle else None)
        _set_or_remove(keeper_entity, 'tfa_enabled', proto_entity.tfaEnabled)
        data = {}
        encrypted_data = keeper_entity.get('encrypted_data')
        if encrypted_data:
            try:
                if keeper_entity.get('key_type') == 'no_key':
                    data['displayname'] = encrypted_data
                else:
                    encrypted_data = utils.base64_url_decode(keeper_entity['encrypted_data'])
                    if keeper_entity.get('key_type') == 'encrypted_by_data_key':
                        data_json = crypto.decrypt_aes_v1(encrypted_data, self.enterprise.tree_key)
                    elif keeper_entity['key_type'] == 'encrypted_by_public_key':
                        rsa_key = crypto.load_rsa_private_key(self.enterprise.rsa_key)
                        data_json = crypto.decrypt_rsa(encrypted_data, rsa_key)
                    elif keeper_entity.get('key_type') == 'encrypted_by_data_key_gcm':
                        data_json = crypto.decrypt_aes_v2(encrypted_data, self.enterprise.tree_key)
                    elif keeper_entity['key_type'] == 'encrypted_by_public_key_ecc':
                        ec_key = crypto.load_ec_private_key(self.enterprise.ec_key)
                        data_json = crypto.decrypt_ec(encrypted_data, ec_key)
                    else:
                        raise Exception(f'unsupported key type: {proto_entity.keyType}')
                    data_json = self.fix_data(data_json)
                    data.update(json.loads(data_json.decode('utf-8')))
            except Exception as e:
                logging.warning('Decrypt User data error: %s', e)
        elif 'full_name' in keeper_entity:
            data['displayname'] = keeper_entity['full_name']
        keeper_entity['data'] = data

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('enterprise_user_id')

    def get_proto_entity_id(self, entity):  # type: (proto.User) -> any
        return entity.enterpriseUserId

    def get_entity_type(self):
        return proto.User

    def get_keeper_entity_name(self):  # type: () -> str
        return 'users'


class _EnterpriseTeamEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.Team, dict) -> None
        _set_or_remove(keeper_entity, 'team_uid', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'name', proto_entity.name)
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'restrict_edit', proto_entity.restrictEdit)
        _set_or_remove(keeper_entity, 'restrict_sharing', proto_entity.restrictShare)
        _set_or_remove(keeper_entity, 'restrict_view', proto_entity.restrictView)
        _set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        _set_or_remove(keeper_entity, 'encrypted_team_key', proto_entity.encryptedTeamKey)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('team_uid')

    def get_proto_entity_id(self, entity):  # type: (proto.Team) -> any
        return utils.base64_url_encode(entity.teamUid)

    def get_entity_type(self):
        return proto.Team

    def get_keeper_entity_name(self):  # type: () -> str
        return 'teams'


class _EnterpriseRoleEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.Role, dict) -> None
        _set_or_remove(keeper_entity, 'role_id', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        _set_or_remove(keeper_entity, 'visible_below', proto_entity.visibleBelow)
        _set_or_remove(keeper_entity, 'new_user_inherit', proto_entity.newUserInherit)
        _set_or_remove(keeper_entity, 'key_type', proto_entity.keyType.lower())
        _set_or_remove(keeper_entity, 'role_type', proto_entity.roleType)
        data = {}
        encrypted_data = keeper_entity.get('encrypted_data')
        if encrypted_data:
            try:
                if keeper_entity.get('key_type') == 'no_key':
                    data['displayname'] = encrypted_data
                else:
                    encrypted_data = utils.base64_url_decode(keeper_entity['encrypted_data'])
                    if keeper_entity.get('key_type') == 'encrypted_by_data_key':
                        data_json = crypto.decrypt_aes_v1(encrypted_data, self.enterprise.tree_key)
                    elif keeper_entity.get('key_type') == 'encrypted_by_public_key':
                        rsa_key = crypto.load_rsa_private_key(self.enterprise.rsa_key)
                        data_json = crypto.decrypt_rsa(encrypted_data, rsa_key)
                    elif keeper_entity.get('key_type') == 'encrypted_by_data_key_gcm':
                        data_json = crypto.decrypt_aes_v2(encrypted_data, self.enterprise.tree_key)
                    elif keeper_entity.get('key_type') == 'encrypted_by_public_key_ecc':
                        ec_key = crypto.load_ec_private_key(self.enterprise.ec_key)
                        data_json = crypto.decrypt_ec(encrypted_data, ec_key)
                    else:
                        raise Exception(f'unsupported key type: {proto_entity.keyType}')
                    data_json = self.fix_data(data_json)
                    data.update(json.loads(data_json.decode('utf-8')))
                    if proto_entity.roleType == "pool_manager":
                        data['displayname'] = 'MSP Subscription Manager'
            except Exception as e:
                logging.warning('Decrypt encryption data error: %s', e)
        keeper_entity['data'] = data

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('role_id')

    def get_proto_entity_id(self, entity):  # type: (proto.Role) -> any
        return entity.roleId

    def get_entity_type(self):
        return proto.Role

    def get_keeper_entity_name(self):  # type: () -> str
        return 'roles'


class _EnterpriseLicenseEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.License, dict) -> None
        _set_or_remove(keeper_entity, 'paid', proto_entity.paid)
        _set_or_remove(keeper_entity, 'number_of_seats', proto_entity.numberOfSeats)
        _set_or_remove(keeper_entity, 'expiration', proto_entity.expiration)
        _set_or_remove(keeper_entity, 'license_key_id',
                       proto_entity.licenseKeyId if proto_entity.licenseKeyId > 0 else None)
        _set_or_remove(keeper_entity, 'product_type_id',
                       proto_entity.productTypeId if proto_entity.productTypeId > 0 else None)
        _set_or_remove(keeper_entity, 'name', proto_entity.name)
        _set_or_remove(keeper_entity, 'enterprise_license_id', proto_entity.enterpriseLicenseId)
        _set_or_remove(keeper_entity, 'seats_allocated', proto_entity.seatsAllocated)
        _set_or_remove(keeper_entity, 'seats_pending', proto_entity.seatsPending)
        _set_or_remove(keeper_entity, 'tier', proto_entity.tier)
        _set_or_remove(keeper_entity, 'file_plan',
                       proto_entity.filePlanTypeId if proto_entity.filePlanTypeId > 0 else None)
        _set_or_remove(keeper_entity, 'max_gb',
                       int(proto_entity.maxBytes / 1024 / 1024 / 1024) if proto_entity.filePlanTypeId > 0 else None)
        _set_or_remove(keeper_entity, 'storage_expiration',
                       proto_entity.storageExpiration if proto_entity.storageExpiration > 0 else None)
        _set_or_remove(keeper_entity, 'lic_status', proto_entity.licenseStatus)
        _set_or_remove(keeper_entity, 'distributor', proto_entity.distributor)

        if proto_entity.mspPool:
            msp_pool = [{
                'product_id': x.productId,
                'seats': x.seats,
                'availableSeats': x.availableSeats,
                'stash': x.stash
            } for x in proto_entity.mspPool]
            _set_or_remove(keeper_entity, 'msp_pool', msp_pool)

        if proto_entity.managedBy and proto_entity.managedBy.enterpriseId > 0:
            _set_or_remove(keeper_entity, 'managed_by', {
                'enterprise_id': proto_entity.managedBy.enterpriseId,
                'enterprise_name': proto_entity.managedBy.enterpriseName,
            })

        if proto_entity.addOns:
            _set_or_remove(keeper_entity, 'add_ons', [{
                'name': x.name,
                'enabled': x.enabled,
                'is_trial': x.isTrial,
                'created': x.created,
                'expiration': x.expiration,
                'included_in_product': x.includedInProduct,
                'seats': x.seats,
                'api_call_count': x.apiCallCount,
            } for x in proto_entity.addOns])

        if proto_entity.mspPermits.restricted:
            _set_or_remove(keeper_entity, 'msp_permits', {
                'allow_unlimited_licenses': proto_entity.mspPermits.allowUnlimitedLicenses,
                'allowed_mc_products': [x for x in proto_entity.mspPermits.allowedMcProducts],
                'allowed_add_ons': [x for x in proto_entity.mspPermits.allowedAddOns],
                'max_file_plan_type': proto_entity.mspPermits.maxFilePlanType,
                'mc_defaults': [{
                    'mc_product': x.mcProduct,
                    'add_ons': [a for a in x.addOns],
                    'file_plan_type': x.filePlanType,
                } for x in proto_entity.mspPermits.mcDefaults]
            })

        _set_or_remove(keeper_entity, 'next_billing_date',
                       proto_entity.nextBillingDate if proto_entity.nextBillingDate > 0 else None)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('enterprise_license_id')

    def get_proto_entity_id(self, entity):  # type: (proto.License) -> any
        return entity.enterpriseLicenseId

    def get_entity_type(self):
        return proto.License

    def get_keeper_entity_name(self):  # type: () -> str
        return 'licenses'


class _EnterpriseQueuedTeamEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.QueuedTeam, dict) -> None
        _set_or_remove(keeper_entity, 'team_uid', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'name', proto_entity.name)
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('team_uid')

    def get_proto_entity_id(self, entity):  # type: (proto.QueuedTeam) -> any
        return utils.base64_url_encode(entity.teamUid)

    def get_entity_type(self):
        return proto.QueuedTeam

    def get_keeper_entity_name(self):  # type: () -> str
        return 'queued_teams'


class _EnterpriseScimEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.Scim, dict) -> None
        _set_or_remove(keeper_entity, 'scim_id', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'status', proto_entity.status)
        _set_or_remove(keeper_entity, 'last_synced', proto_entity.lastSynced if proto_entity.lastSynced > 0 else None)
        _set_or_remove(keeper_entity, 'role_prefix', proto_entity.rolePrefix)
        _set_or_remove(keeper_entity, 'unique_groups', proto_entity.uniqueGroups)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('scim_id')

    def get_proto_entity_id(self, entity):  # type: (proto.Scim) -> any
        return entity.scimId

    def get_entity_type(self):
        return proto.Scim

    def get_keeper_entity_name(self):  # type: () -> str
        return 'scims'


class _EnterpriseTeamUserEntity(_EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.TeamUser, dict) -> None
        _set_or_remove(keeper_entity, 'team_uid', self.get_proto_entity1_id(proto_entity))
        _set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)
        user_type = 0 if proto_entity.userType == 'USER' else 1 if proto_entity.userType == 'ADMIN' else 2
        _set_or_remove(keeper_entity, 'user_type', user_type)

    def get_keeper_entity1_id(self, entity):  # type: (dict) -> any
        return entity.get('team_uid')

    def get_keeper_entity2_id(self, entity):  # type: (dict) -> any
        return entity.get('enterprise_user_id')

    def get_proto_entity1_id(self, entity):  # type: (proto.TeamUser) -> any
        return utils.base64_url_encode(entity.teamUid)

    def get_proto_entity2_id(self, entity):  # type: (proto.TeamUser) -> any
        return entity.enterpriseUserId

    def get_entity_type(self):
        return proto.TeamUser

    def get_keeper_entity_name(self):  # type: () -> str
        return 'team_users'


class _EnterpriseRoleUserEntity(_EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.RoleUser, dict) -> None
        _set_or_remove(keeper_entity, 'role_id', self.get_proto_entity1_id(proto_entity))
        _set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)

    def get_keeper_entity1_id(self, entity):  # type: (dict) -> any
        return entity.get('role_id')

    def get_keeper_entity2_id(self, entity):  # type: (dict) -> any
        return entity.get('enterprise_user_id')

    def get_proto_entity1_id(self, entity):  # type: (proto.RoleUser) -> any
        return entity.roleId

    def get_proto_entity2_id(self, entity):  # type: (proto.RoleUser) -> any
        return entity.enterpriseUserId

    def get_entity_type(self):
        return proto.RoleUser

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_users'


class _EnterpriseRoleTeamEntity(_EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.RoleTeam, dict) -> None
        _set_or_remove(keeper_entity, 'role_id', self.get_proto_entity1_id(proto_entity))
        _set_or_remove(keeper_entity, 'team_uid', self.get_proto_entity2_id(proto_entity))

    def get_keeper_entity1_id(self, entity):  # type: (dict) -> any
        return entity.get('role_id')

    def get_keeper_entity2_id(self, entity):  # type: (dict) -> any
        return entity.get('team_uid')

    def get_proto_entity1_id(self, entity):  # type: (proto.RoleTeam) -> any
        return entity.role_id

    def get_proto_entity2_id(self, entity):  # type: (proto.RoleTeam) -> any
        return utils.base64_url_encode(entity.teamUid)

    def get_entity_type(self):
        return proto.RoleTeam

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_teams'


class _EnterpriseManagedNodeEntity(_EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.ManagedNode, dict) -> None
        _set_or_remove(keeper_entity, 'role_id', self.get_proto_entity1_id(proto_entity))
        _set_or_remove(keeper_entity, 'managed_node_id', self.get_proto_entity2_id(proto_entity))
        _set_or_remove(keeper_entity, 'cascade_node_management', proto_entity.cascadeNodeManagement)

    def get_keeper_entity1_id(self, entity):  # type: (dict) -> any
        return entity.get('role_id')

    def get_keeper_entity2_id(self, entity):  # type: (dict) -> any
        return entity.get('managed_node_id')

    def get_proto_entity1_id(self, entity):  # type: (proto.ManagedNode) -> any
        return entity.roleId

    def get_proto_entity2_id(self, entity):  # type: (proto.ManagedNode) -> any
        return entity.managedNodeId

    def get_entity_type(self):
        return proto.ManagedNode

    def get_keeper_entity_name(self):  # type: () -> str
        return 'managed_nodes'


class _EnterpriseRolePrivilegeEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.RolePrivilege, dict) -> None
        _set_or_remove(keeper_entity, 'role_id', proto_entity.roleId)
        _set_or_remove(keeper_entity, 'managed_node_id', proto_entity.managedNodeId)
        _set_or_remove(keeper_entity, 'privilege', proto_entity.privilegeType)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return '{0}:{1}:{2}'.format(entity.get('role_id'), entity.get('managed_node_id'), entity.get('privilege'))

    def get_proto_entity_id(self, entity):  # type: (proto.RolePrivilege) -> any
        return '{0}:{1}:{2}'.format(entity.roleId, entity.managedNodeId, entity.privilegeType)

    def get_entity_type(self):
        return proto.RolePrivilege

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_privileges'


class _EnterpriseRoleEnforcements(_EnterpriseDataParser):
    def parse(self, params, enterprise_data, **kwargs):  # type: (KeeperParams, proto.EnterpriseData, dict) -> None
        entities = self.get_entities(params)
        entity_map = {x['role_id']: x for x in entities}
        entity_type = self.get_entity_type()
        for entityData in enterprise_data.data:
            entity = entity_type()
            entity.ParseFromString(entityData)
            role_id = entity.roleId
            enforcement_type = entity.enforcementType
            if enterprise_data.delete:
                if role_id in entity_map:
                    enforcements = entity_map[role_id]['enforcements']
                    if enforcement_type in enforcements:
                        enforcements.pop(enforcement_type)
            else:
                keeper_entity = entity_map.get(role_id)
                if not keeper_entity:
                    keeper_entity = {
                        'role_id': role_id,
                        'enforcements': {}
                    }
                    entity_map[role_id] = keeper_entity
                enforcements = keeper_entity['enforcements']
                enforcements[enforcement_type] = entity.value

        entities.clear()
        entities.extend(entity_map.values())

    def get_entity_type(self):
        return proto.RoleEnforcement

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_enforcements'

    def to_keeper_entity(self, proto_entity, keeper_entity):
        pass


class _EnterpriseManagedCompanyEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.ManagedCompany, dict) -> None
        _set_or_remove(keeper_entity, 'mc_enterprise_id', proto_entity.mcEnterpriseId)
        _set_or_remove(keeper_entity, 'mc_enterprise_name', proto_entity.mcEnterpriseName)
        _set_or_remove(keeper_entity, 'msp_node_id', proto_entity.mspNodeId)
        _set_or_remove(keeper_entity, 'number_of_seats', proto_entity.numberOfSeats)
        _set_or_remove(keeper_entity, 'number_of_users', proto_entity.numberOfUsers)
        _set_or_remove(keeper_entity, 'product_id', proto_entity.productId)
        _set_or_remove(keeper_entity, 'paused', proto_entity.isExpired)
        _set_or_remove(keeper_entity, 'tree_key', proto_entity.treeKey if proto_entity.treeKey else None)
        _set_or_remove(keeper_entity, 'tree_key_role', proto_entity.tree_key_role)
        _set_or_remove(keeper_entity, 'file_plan_type', proto_entity.filePlanType)
        _set_or_remove(keeper_entity, 'add_ons', [{
            'name': x.name,
            'seats': x.seats,
            'enabled': x.enabled,
            'is_trial': x.isTrial,
            'created': x.created,
            'expiration': x.expiration,
            'activation_time': x.activationTime,
            'included_in_product': x.includedInProduct,
        } for x in proto_entity.addOns])

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('mc_enterprise_id')

    def get_proto_entity_id(self, entity):  # type: (proto.ManagedCompany) -> any
        return entity.mcEnterpriseId

    def get_entity_type(self):
        return proto.ManagedCompany

    def get_keeper_entity_name(self):  # type: () -> str
        return 'managed_companies'


class _EnterpriseQueuedTeamUserEntity(_EnterpriseDataParser, _CascadeDeleteLink):
    def parse(self, params, enterprise_data, **kwargs):  # type: (KeeperParams, proto.EnterpriseData, dict) -> None
        entities = self.get_entities(params)
        entity_map = {x['team_uid']: x for x in entities}
        entity_type = self.get_entity_type()
        for entityData in enterprise_data.data:
            entity = entity_type()
            entity.ParseFromString(entityData)
            team_uid = utils.base64_url_encode(entity.teamUid)
            if enterprise_data.delete:
                if team_uid in entity_map:
                    users = entity_map[team_uid]['users']     # type: set
                    users.difference_update(entity.users)
            else:
                keeper_entity = entity_map.get(team_uid)
                if not keeper_entity:
                    keeper_entity = {
                        'team_uid': team_uid,
                        'users': set()
                    }
                    entity_map[team_uid] = keeper_entity
                users = keeper_entity['users']
                users.update(entity.users)

        entities.clear()
        entities.extend(entity_map.values())

    def get_entity_type(self):
        return proto.QueuedTeamUser

    def get_keeper_entity_name(self):  # type: () -> str
        return 'queued_team_users'

    def to_keeper_entity(self, proto_entity, keeper_entity):
        pass

    def cascade_delete(self, params, keeper_entity_id, deleted_entities):   # type: (KeeperParams, str, Set) -> None
        entities = self.get_entities(params)
        if not entities:
            return
        if keeper_entity_id == 'team_uid':
            to_keep = [x for x in entities if x['team_uid'] not in deleted_entities]
            if len(to_keep) < len(entities):
                entities.clear()
                entities.extend(to_keep)
        elif keeper_entity_id == 'enterprise_user_id':
            for entity in entities:
                users = entity.get('users')
                if isinstance(users, set):
                    users.difference_update(deleted_entities)


class _EnterpriseUserAliasEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):
        # type: (proto.UserAlias, dict) -> None
        _set_or_remove(keeper_entity, 'username', proto_entity.username)
        _set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity['username']

    def get_proto_entity_id(self, entity):  # type: (proto.UserAlias) -> any
        return entity.username

    def get_entity_type(self):
        return proto.UserAlias

    def get_keeper_entity_name(self):  # type: () -> str
        return 'user_aliases'


class _EnterpriseAdminApprovalRequestEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):
        # type: (proto.DeviceRequestForAdminApproval, dict) -> None
        _set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)
        _set_or_remove(keeper_entity, 'encrypted_device_token',
                       utils.base64_url_encode(proto_entity.encryptedDeviceToken))
        _set_or_remove(keeper_entity, 'device_id', proto_entity.deviceId)
        _set_or_remove(keeper_entity, 'device_public_key', utils.base64_url_encode(proto_entity.devicePublicKey))
        _set_or_remove(keeper_entity, 'device_name', proto_entity.deviceName)
        _set_or_remove(keeper_entity, 'client_version', proto_entity.clientVersion)
        _set_or_remove(keeper_entity, 'device_type', proto_entity.deviceType)
        _set_or_remove(keeper_entity, 'date', proto_entity.date)
        _set_or_remove(keeper_entity, 'ip_address', proto_entity.ipAddress)
        _set_or_remove(keeper_entity, 'location', proto_entity.location)
        _set_or_remove(keeper_entity, 'email', proto_entity.email)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return '{0}:{1}'.format(entity.get('enterprise_user_id'), entity.get('device_id'))

    def get_proto_entity_id(self, entity):  # type: (proto.DeviceRequestForAdminApproval) -> any
        return '{0}:{1}'.format(entity.enterpriseUserId, entity.deviceId)

    def get_entity_type(self):
        return proto.DeviceRequestForAdminApproval

    def get_keeper_entity_name(self):  # type: () -> str
        return 'devices_request_for_admin_approval'


class _EnterpriseSsoServiceEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.SsoService, dict) -> None
        _set_or_remove(keeper_entity, 'sso_service_provider_id', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'name', proto_entity.name)
        _set_or_remove(keeper_entity, 'sp_url', proto_entity.sp_url)
        _set_or_remove(keeper_entity, 'invite_new_users', proto_entity.inviteNewUsers)
        _set_or_remove(keeper_entity, 'active', proto_entity.active)
        _set_or_remove(keeper_entity, 'is_cloud', proto_entity.isCloud)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('sso_service_provider_id')

    def get_proto_entity_id(self, entity):  # type: (proto.SsoService) -> any
        return entity.ssoServiceProviderId

    def get_entity_type(self):
        return proto.SsoService

    def get_keeper_entity_name(self):  # type: () -> str
        return 'sso_services'


class _EnterpriseBridgeEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.Bridge, dict) -> None
        _set_or_remove(keeper_entity, 'bridge_id', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'wan_ip_enforcement', proto_entity.wanIpEnforcement)
        _set_or_remove(keeper_entity, 'lan_ip_enforcement', proto_entity.lanIpEnforcement)
        _set_or_remove(keeper_entity, 'status', proto_entity.status)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('bridge_id')

    def get_proto_entity_id(self, entity):  # type: (proto.Bridge) -> any
        return entity.bridgeId

    def get_entity_type(self):
        return proto.Bridge

    def get_keeper_entity_name(self):  # type: () -> str
        return 'bridges'


class _EnterpriseEmailProvisionEntity(_EnterpriseEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (proto.EmailProvision, dict) -> None
        _set_or_remove(keeper_entity, 'id', self.get_proto_entity_id(proto_entity))
        _set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        _set_or_remove(keeper_entity, 'domain', proto_entity.domain)
        _set_or_remove(keeper_entity, 'method', proto_entity.method)

    def get_keeper_entity_id(self, entity):  # type: (dict) -> any
        return entity.get('id')

    def get_proto_entity_id(self, entity):  # type: (proto.EmailProvision) -> any
        return entity.id

    def get_entity_type(self):
        return proto.EmailProvision

    def get_keeper_entity_name(self):  # type: () -> str
        return 'email_provision'
