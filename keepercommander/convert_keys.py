import logging

from . import api, utils, crypto
from .params import KeeperParams
from .proto import APIRequest_pb2, enterprise_pb2


def change_key_types(params):    # type: (KeeperParams) -> None
    if not params.forbid_rsa:
        return

    get_rq = APIRequest_pb2.GetChangeKeyTypesRequest()
    get_rq.onlyTheseObjects.extend((APIRequest_pb2.EOT_RECORD_KEY, APIRequest_pb2.EOT_SHARED_FOLDER_USER_KEY, APIRequest_pb2.EOT_SHARED_FOLDER_TEAM_KEY,
                                    APIRequest_pb2.EOT_TEAM_USER_KEY, APIRequest_pb2.EOT_USER_FOLDER_KEY))
    get_rs = api.communicate_rest(params, get_rq, 'vault/get_change_key_types', rs_type=APIRequest_pb2.GetChangeKeyTypesResponse)
    set_rq = APIRequest_pb2.ChangeKeyTypes()

    for key in get_rs.keys:
        try:
            if key.objectType == APIRequest_pb2.EOT_RECORD_KEY:
                record_uid = utils.base64_url_encode(key.uid)
                record = params.record_cache.get(record_uid)
                if record and 'record_key_unencrypted' in record:
                    record_key = record['record_key_unencrypted']
                    ckt_rq = APIRequest_pb2.ChangeKeyType()
                    ckt_rq.objectType = key.objectType
                    ckt_rq.uid = key.uid
                    ckt_rq.keyType = enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY_GCM
                    ckt_rq.key = crypto.encrypt_aes_v2(record_key, params.data_key)
                    set_rq.keys.append(ckt_rq)
            elif key.objectType == APIRequest_pb2.EOT_SHARED_FOLDER_USER_KEY:
                shared_folder_uid = utils.base64_url_encode(key.uid)
                shared_folder = params.shared_folder_cache.get(shared_folder_uid)
                if shared_folder and 'shared_folder_key_unencrypted' in shared_folder:
                    shared_folder_key = shared_folder['shared_folder_key_unencrypted']
                    ckt_rq = APIRequest_pb2.ChangeKeyType()
                    ckt_rq.objectType = key.objectType
                    ckt_rq.uid = key.uid
                    ckt_rq.keyType = enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY_GCM
                    ckt_rq.key = crypto.encrypt_aes_v2(shared_folder_key, params.data_key)
                    set_rq.keys.append(ckt_rq)
            elif key.objectType == APIRequest_pb2.EOT_TEAM_USER_KEY:
                team_uid = utils.base64_url_encode(key.uid)
                team = params.team_cache.get(team_uid)
                if team and 'team_key_unencrypted' in team:
                    team_key = team['team_key_unencrypted']
                    ckt_rq = APIRequest_pb2.ChangeKeyType()
                    ckt_rq.objectType = key.objectType
                    ckt_rq.uid = key.uid
                    ckt_rq.keyType = enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY_GCM
                    ckt_rq.key = crypto.encrypt_aes_v2(team_key, params.data_key)
                    set_rq.keys.append(ckt_rq)
            elif key.objectType == APIRequest_pb2.EOT_USER_FOLDER_KEY:
                folder_uid = utils.base64_url_encode(key.uid)
                folder = params.folder_cache.get(folder_uid)
                if folder and 'folder_key_unencrypted' in folder:
                    folder_key = folder['folder_key_unencrypted']
                    ckt_rq = APIRequest_pb2.ChangeKeyType()
                    ckt_rq.objectType = key.objectType
                    ckt_rq.uid = key.uid
                    ckt_rq.keyType = enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY_GCM
                    ckt_rq.key = crypto.encrypt_aes_v2(folder_key, params.data_key)
                    set_rq.keys.append(ckt_rq)
            elif key.objectType == APIRequest_pb2.EOT_SHARED_FOLDER_TEAM_KEY:
                shared_folder_uid = utils.base64_url_encode(key.uid)
                team_uid = utils.base64_url_encode(key.secondaryUid)
                shared_folder = params.shared_folder_cache.get(shared_folder_uid)
                team = params.team_cache.get(team_uid)
                if shared_folder and team and 'shared_folder_key_unencrypted' in shared_folder and 'team_key_unencrypted' in team:
                    shared_folder_key = shared_folder['shared_folder_key_unencrypted']
                    team_key = team['team_key_unencrypted']
                    ckt_rq = APIRequest_pb2.ChangeKeyType()
                    ckt_rq.objectType = key.objectType
                    ckt_rq.uid = key.uid
                    ckt_rq.keyType = enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY_GCM
                    ckt_rq.key = crypto.encrypt_aes_v2(shared_folder_key, team_key)
                    set_rq.keys.append(ckt_rq)
        except Exception as e:
            logging.debug('change_key_types encryption error: %s', e)
    try:
        if len(set_rq.keys) > 0:
            api.communicate_rest(params, set_rq, 'vault/change_key_types', rs_type=APIRequest_pb2.ChangeKeyTypes)

    except Exception as e:
        logging.debug('change_key_types error: %s', e)

