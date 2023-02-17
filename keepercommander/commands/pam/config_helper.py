import base64
import json
import os

from keeper_secrets_manager_core.utils import string_to_bytes, bytes_to_string

from ..folder import FolderMoveCommand
from ..record import RecordRemoveCommand
from ...display import bcolors
from ...proto import pam_pb2
from ...proto.pam_pb2 import (
    PAMConfigurationController, PAMDataOperation, PAMOperationType, PAMModifyRequest, ConfigurationAddRequest
)
from ...proto.router_pb2 import RouterRotationInfo
from ... import api, crypto, utils


def pam_decrypt_configuration_data(pam_config_v6_record):
    pam_config_v6_record.get('data'),
    pam_config_v6_record.get('record_key_unencrypted')
    data_unencrypted_bytes = crypto.decrypt_aes_v2(
        utils.base64_url_decode(pam_config_v6_record.get('data')),
        pam_config_v6_record.get('record_key_unencrypted')
    )

    data_unencrypted_json_str = bytes_to_string(data_unencrypted_bytes)
    data_unencrypted_dict = json.loads(data_unencrypted_json_str)

    return data_unencrypted_dict


def pam_configuration_get_single_value_from_field_by_id(decrypted_record_dict, field_id):
    values = pam_configuration_get_all_values_from_field_by_id(decrypted_record_dict, field_id)
    if not values:
        return None

    if len(values) > 0:
        return values[0]

    return None


def pam_configuration_get_all_values_from_field_by_id(decrypted_record_dict, field_id):
    field = pam_configuration_get_field_by_id(decrypted_record_dict, field_id)
    if not field:
        return None

    return field.get('value')


def pam_configuration_get_field_by_id(decrypted_record_dict, field_id):

    fields = decrypted_record_dict.get('fields')

    if not fields:
        return None

    found_field = next((item for item in fields if 'id' in item and item['id'] == field_id), None)

    return found_field


def pam_configuration_create_record_v6(params, data, controller_uid, folder_uid_urlsafe):

    data_json = json.dumps(data)
    record_key_unencrypted = os.urandom(32)
    record_key_encrypted = api.encrypt_aes_plain(record_key_unencrypted, params.data_key)

    config_v6_record_uid_str = api.generate_record_uid()
    config_v6_record_uid = utils.base64_url_decode(config_v6_record_uid_str)

    data = data_json.decode('utf-8') if isinstance(data_json, bytes) else data_json
    data = api.pad_aes_gcm(data)

    rdata = bytes(data, 'utf-8')
    rdata = api.encrypt_aes_plain(rdata, record_key_unencrypted)
    rdata = base64.urlsafe_b64encode(rdata).decode('utf-8')
    rdata = utils.base64_url_decode(rdata)

    car = ConfigurationAddRequest()
    car.configurationUid = config_v6_record_uid
    car.recordKey = record_key_encrypted
    car.data = rdata

    params.revision = 0
    rs = api.communicate_rest(params, car, 'pam/add_configuration_record')

    pcc = PAMConfigurationController()
    pcc.configurationUid = config_v6_record_uid
    pcc.controllerUid = utils.base64_url_decode(controller_uid)
    rs = api.communicate_rest(params, pcc, 'pam/set_configuration_controller')

    # Moving v6 record into the folder
    api.sync_down(params)

    FolderMoveCommand().execute(params, src=config_v6_record_uid_str, dst=folder_uid_urlsafe)

    print(bcolors.OKGREEN + "Configuration was successfully added. UID " + config_v6_record_uid_str + bcolors.ENDC)


def pam_configuration_create(params, gateway_uid_bytes, config_json_str, child_config_json_strings=None, parent_uid_bytes=None):

    config_operation = PAMDataOperation()
    config_operation.operationType = PAMOperationType.ADD

    top_config_uid = os.urandom(16)

    if not parent_uid_bytes:
        # Root node
        config_operation.configuration.configurationUid = top_config_uid
        config_operation.configuration.controllerUid = gateway_uid_bytes
        config_operation.configuration.data = string_to_bytes(config_json_str) # DATA size is between 16 and 516
    else:
        # Child node
        config_operation.element.elementUid = top_config_uid
        config_operation.element.parentUid = parent_uid_bytes
        config_operation.element.data = string_to_bytes(config_json_str)

    rq = PAMModifyRequest()
    rq.operations.append(config_operation)

    child_generated_uids = []

    if child_config_json_strings:

        for child_config_json_string in child_config_json_strings:
            child_generated_uid = os.urandom(16)
            child_generated_uids.append(child_generated_uid)

            child_config_operation = PAMDataOperation()
            child_config_operation.operationType = PAMOperationType.ADD
            child_config_operation.element.elementUid = child_generated_uid
            child_config_operation.element.parentUid = top_config_uid
            child_config_operation.element.data = string_to_bytes(child_config_json_string)
            rq.operations.append(child_config_operation)


    rs = api.communicate_rest(params, rq, 'pam/modify_configuration', rs_type=pam_pb2.PAMModifyResult)

    return {
        'configUid': top_config_uid,
        'childConfigUids': child_generated_uids if child_generated_uids else None
    }


def config_update(params):
    pass


def pam_configuration_get_one(params, config_uid_urlsafe):
    # rq = PAMGenericUidRequest()
    # rq.uid = config_uid_bytes
    # rs = api.communicate_rest(params, rq, 'pam/get_configuration', rs_type=pam_pb2.PAMConfiguration)

    config_record = params.record_cache[config_uid_urlsafe]

    data_unencrypted_bytes = crypto.decrypt_aes_v2(utils.base64_url_decode(config_record['data']), config_record['record_key_unencrypted'])
    data_unencrypted_json_str = bytes_to_string(data_unencrypted_bytes)
    data_unencrypted_dict = json.loads(data_unencrypted_json_str)
    config_record['data_decrypted'] = data_unencrypted_dict

    return config_record


def pam_configurations_get_all(params):

    # rs = api.communicate_rest(params, None, 'pam/get_configurations', rs_type=pam_pb2.PAMConfigurations)
    all_records = params.record_cache.values()
    all_v6_records = [rec for rec in list(all_records) if rec['version'] == 6]

    return all_v6_records


def pam_configuration_remove(params, configuration_uid):

    # TODO: Check if there are record rotations associated with this config and warn user about that before removing.

    RecordRemoveCommand().execute(params, record=configuration_uid, force=True)

    if configuration_uid in params.record_cache:
        del params.record_cache[configuration_uid]

    # SyncDownCommand().execute(params, force=True)
    print(f'{bcolors.OKGREEN}PAM Configuration was removed successfully{bcolors.ENDC}')

    # raise Exception("Not implemented yet...")
    # # just do the regular record deletion
    # config_operation = PAMDataOperation()
    # config_operation.operationType = PAMOperationType.DELETE
    #
    # config_operation.configuration.configurationUid = configuration_uid
    #
    # rq = PAMModifyRequest()
    # rq.operations.append(config_operation)
    #
    # try:
    #     rs = api.communicate_rest(params, rq, 'pam/modify_configuration', rs_type=pam_pb2.PAMModifyResult)
    #     print(f'{bcolors.OKGREEN}PAM Configuration was removed successfully{bcolors.ENDC}')
    #
    # except KeeperApiError as ex:
    #     if ex.result_code == 'doesnt_exist':
    #         print(f'{bcolors.WARNING}This PAM Configuration does not exist{bcolors.ENDC}')
    #     else:
    #         print(f'{bcolors.WARNING}Error code: {ex.result_code}. {ex.message}{bcolors.ENDC}')


def record_rotation_get(params, record_uid_bytes):

    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = record_uid_bytes

    rotation_info_rs = api.communicate_rest(params, rq, 'pam/get_rotation_info', rs_type=RouterRotationInfo)

    return rotation_info_rs


