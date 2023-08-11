import json

from data_vault import VaultEnvironment
from keepercommander import api, crypto, utils
from keepercommander.params import KeeperParams

_TREE_KEY = api.generate_aes_key()
_ENTERPRISE_ID = 123

_VAULT_ENV = VaultEnvironment()

_USE_DATA_KEY = True

_TEAM_KEY = api.generate_aes_key()
_TEAM1_UID = api.generate_record_uid()
_TEAM2_UID = api.generate_record_uid()
_TEAM1_NAME = 'Team 1'
_TEAM2_NAME = 'Team 2'

_NODE1_ID = (_ENTERPRISE_ID << 32) + 2
_NODE2_ID = (_ENTERPRISE_ID << 32) + 100

_USER1_ID = (_ENTERPRISE_ID << 32) + 201
_USER2_ID = (_ENTERPRISE_ID << 32) + 202
_USER2_EMAIL = 'user2@keepercommander.com'

_ROLE1_ID = (_ENTERPRISE_ID << 32) + 301
_ROLE1_NAME = 'Role 1'

_LAST_ID = 1000


class EnterpriseEnvironment:
    def __init__(self):
        self.tree_key = _TREE_KEY
        self.team_key = _TEAM_KEY
        self.team1_uid = _TEAM1_UID
        self.team2_uid = _TEAM2_UID
        self.team1_name = _TEAM1_NAME
        self.team2_name = _TEAM2_NAME
        self.user1_id = _USER1_ID
        self.user2_id = _USER2_ID
        self.node1_id = _NODE1_ID
        self.node2_id = _NODE2_ID
        self.user2_email = _USER2_EMAIL
        self.role1_id = _ROLE1_ID
        self.role1_name = _ROLE1_NAME


def enterprise_allocate_ids(params, request):
    global _LAST_ID
    rs = {
        'result': 'success',
        'result_code': '',
        'message': ''
    }
    num = request['number_requested']
    rs['number_allocated'] = num
    rs['base_id'] = _LAST_ID
    _LAST_ID += num

    return rs


def get_enterprise_data(params):
    # type: (KeeperParams) -> dict

    encrypted_tree_key = crypto.encrypt_aes_v1(_TREE_KEY, params.data_key) \
        if _USE_DATA_KEY else crypto.encrypt_rsa(_TREE_KEY, _VAULT_ENV.public_key)
    tree_key_type = 1 if _USE_DATA_KEY else 2
    rs = {
        'result': 'success',
        'result_code': '',
        'message': '',
        'enterprise_name': 'Enterprise 1',
        'tree_key': utils.base64_url_encode(encrypted_tree_key),
        'key_type_id': tree_key_type
    }

    rs['nodes'] = [
        {
            'node_id':  _NODE1_ID,
            'encrypted_data': utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps({}).encode('utf-8'), _TREE_KEY))
        },
        {
            'node_id': _NODE2_ID,
            'parent_id': _NODE1_ID,
            'encrypted_data': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': 'Sub node 1'}).encode('utf-8'), _TREE_KEY))
        }
    ]
    rs['users'] = [
        {
            'enterprise_user_id':  _USER1_ID,
            'node_id': _NODE1_ID,
            'username': params.user,
            'encrypted_data': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': 'User 1'}).encode('utf-8'), _TREE_KEY)),
            'status': 'active',
            'lock': 0,
            'tfa_enabled': True,
        },
        {
            'enterprise_user_id':  _USER2_ID,
            'node_id': _NODE2_ID,
            'username': _USER2_EMAIL,
            'encrypted_data': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': 'User 2'}).encode('utf-8'), _TREE_KEY)),
            'status': 'active',
            'lock': 1,
            'tfa_enabled': False,
        }
    ]

    rs['roles'] = [
        {
            'role_id': _ROLE1_ID,
            'node_id': _NODE1_ID,
            'encrypted_data': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': _ROLE1_NAME}).encode('utf-8'), _TREE_KEY)),
            'visible_below': True,
            'new_user_inherit': True
        }
    ]
    rs['managed_nodes'] = [
        {
            'role_id': _ROLE1_ID,
            'managed_node_id': _NODE1_ID,
            'cascade_node_management': True,
        }
    ]
    rs['role_users'] = [
        {
            'role_id': _ROLE1_ID,
            'enterprise_user_id':  _USER1_ID
        }
    ]
    rs['teams'] = [
        {
            'team_uid': _TEAM1_UID,
            'name': _TEAM1_NAME,
            'node_id': _NODE1_ID,
            'restrict_sharing': False,
            'restrict_edit': False,
            'restrict_view': False,
        },
        {
            'team_uid': _TEAM2_UID,
            'name': _TEAM2_NAME,
            'node_id': _NODE1_ID,
            'restrict_sharing': False,
            'restrict_edit': False,
            'restrict_view': False,
        }
    ]
    rs['team_users'] = [
        {
            'team_uid': _TEAM1_UID,
            'enterprise_user_id': _USER1_ID,
            'user_type': 1
        },
        {
            'team_uid': _TEAM2_UID,
            'enterprise_user_id': _USER2_ID,
            'user_type': 1
        }
    ]
    return rs
