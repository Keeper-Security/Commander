import os

from keeper_secrets_manager_core.utils import string_to_bytes

from keepercommander import api
from keepercommander.display import bcolors
from keepercommander.error import KeeperApiError
from keepercommander.proto import pam_pb2
from keepercommander.proto.pam_pb2 import PAMDataOperation, PAMOperationType, PAMModifyRequest, PAMGenericUidRequest


def rotation_settings_create(params, gateway_uid_bytes, config_json_str, child_config_json_strings=None, parent_uid_bytes=None):

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


def rotation_settings_get_one(params, config_uid_bytes):
    rq = PAMGenericUidRequest()
    rq.uid = config_uid_bytes
    rs = api.communicate_rest(params, rq, 'pam/get_configuration', rs_type=pam_pb2.PAMConfiguration)

    return rs


def rotation_settings_get_all(params):

    rs = api.communicate_rest(params, None, 'pam/get_configurations', rs_type=pam_pb2.PAMConfigurations)

    return rs


def rotation_settings_remove(params, configuration_uid):

    config_operation = PAMDataOperation()
    config_operation.operationType = PAMOperationType.DELETE

    config_operation.configuration.configurationUid = configuration_uid

    rq = PAMModifyRequest()
    rq.operations.append(config_operation)

    try:
        rs = api.communicate_rest(params, rq, 'pam/modify_configuration', rs_type=pam_pb2.PAMModifyResult)
        print(f'{bcolors.OKGREEN}Rotation Setting was removed successfully{bcolors.ENDC}')

    except KeeperApiError as ex:
        if ex.result_code == 'doesnt_exist':
            print(f'{bcolors.WARNING}This rotation setting does not exist{bcolors.ENDC}')
        else:
            print(f'{bcolors.WARNING}Error code: {ex.result_code}. {ex.message}{bcolors.ENDC}')

