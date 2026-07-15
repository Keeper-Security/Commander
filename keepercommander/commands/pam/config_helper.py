import json
import logging
import os

from keeper_secrets_manager_core.utils import string_to_bytes, bytes_to_string

from ..record import RecordRemoveCommand
from ... import api, crypto, utils, vault, vault_extensions, subfolder
from ...error import KeeperApiError
from ...nested_share_folder.common import get_folder_key
from ...nested_share_folder.record_api import create_record_data_v3, record_add_pam_configuration_v3
from ...params import KeeperParams
from ...proto import folder_pb2, pam_pb2, record_pb2, router_pb2


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


def pam_configuration_get_single_value_from_field(decrypted_record_dict, field_id):
    values = pam_configuration_get_all_values_from_field(decrypted_record_dict, field_id)
    if not values:
        return None

    if len(values) > 0:
        return values[0]

    return None


def pam_configuration_get_all_values_from_field(decrypted_record_dict, field_id):
    field = pam_configuration_get_field(decrypted_record_dict, field_id)
    if not field:
        return None

    return field.get('value')


def pam_configuration_get_field(unencrypted_record, field_identifier):

    if unencrypted_record is str:
        unencrypted_record = json.loads(unencrypted_record)

    fields = unencrypted_record.get('fields')

    if not fields:
        return None

    for field in fields:
        if field.get('id') == field_identifier:
            return field

        if field.get('type') == field_identifier:
            return field

        if field.get('label') == field_identifier:
            return field


def _resolve_pam_configuration_folder_key(params, folder_uid):
    # type: (KeeperParams, str) -> bytes | None
    folder_key = get_folder_key(params, folder_uid, raise_on_missing=False)
    if folder_key:
        return folder_key

    folder = params.folder_cache.get(folder_uid)
    shared_folder_uid = None
    if isinstance(folder, subfolder.SharedFolderFolderNode):
        shared_folder_uid = folder.shared_folder_uid
    elif isinstance(folder, subfolder.SharedFolderNode):
        shared_folder_uid = folder.uid
    if shared_folder_uid and shared_folder_uid in params.shared_folder_cache:
        shared_folder = params.shared_folder_cache.get(shared_folder_uid)
        return shared_folder.get('shared_folder_key_unencrypted')
    return None


def pam_configuration_create_record_v6(params, record, folder_uid):
    # type: (KeeperParams, vault.TypedRecord, str) -> None
    """Create a classic PAM configuration via pam/add_configuration_record."""
    if not record.record_uid:
        record.record_uid = utils.generate_uid()

    if not record.record_key:
        record.record_key = utils.generate_aes_key()

    record_data = vault_extensions.extract_typed_record_data(record)
    json_data = api.get_record_data_json_bytes(record_data)

    car = pam_pb2.ConfigurationAddRequest()
    car.configurationUid = utils.base64_url_decode(record.record_uid)
    car.recordKey = crypto.encrypt_aes_v2(record.record_key, params.data_key)
    car.data = crypto.encrypt_aes_v2(json_data, record.record_key)

    api.communicate_rest(params, car, 'pam/add_configuration_record')


def pam_configuration_create_record_nsf(params, record, folder_uid):
    # type: (KeeperParams, vault.TypedRecord, str) -> None
    """Create a PAM configuration in an NSF folder via vault/records/v3/add_pam_configuration."""
    if not record.record_uid:
        record.record_uid = utils.generate_uid()

    if not record.record_key:
        record.record_key = utils.generate_aes_key()

    record_data = vault_extensions.extract_typed_record_data(record)
    folder_key = _resolve_pam_configuration_folder_key(params, folder_uid) if folder_uid else None
    client_time = utils.current_milli_time()

    audit = None
    if params.enterprise_ec_key:
        audit_data = vault_extensions.extract_audit_data(record)
        if audit_data:
            audit = record_pb2.RecordAudit()
            audit.version = 0
            audit.data = crypto.encrypt_ec(
                json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

    if folder_uid and folder_key:
        record_add = create_record_data_v3(
            record_uid=record.record_uid,
            record_key=record.record_key,
            data=record_data,
            folder_uid=folder_uid,
            folder_key=folder_key,
            data_key=params.data_key,
            owner_key=params.data_key,
            client_modified_time=client_time,
            audit=audit,
        )
    else:
        record_add = create_record_data_v3(
            record_uid=record.record_uid,
            record_key=record.record_key,
            data=record_data,
            data_key=params.data_key,
            owner_key=params.data_key,
            client_modified_time=client_time,
            audit=audit,
        )
        if folder_uid:
            record_add.folderUid = utils.base64_url_decode(folder_uid)
            record_add.recordKeyEncryptedBy = folder_pb2.ENCRYPTED_BY_USER_KEY

    response = record_add_pam_configuration_v3(params, [record_add], client_time=client_time)
    if not response.records:
        raise KeeperApiError('no_results', 'No results from PAM configuration creation')

    record_rs = response.records[0]
    if record_rs.status != record_pb2.RS_SUCCESS:
        raise KeeperApiError(
            record_pb2.RecordModifyResult.Name(record_rs.status),
            record_rs.message or 'Failed to create PAM configuration record')
    record.revision = response.revision


def pam_configuration_create(params, gateway_uid_bytes, config_json_str, child_config_json_strings=None, parent_uid_bytes=None):

    config_operation = pam_pb2.PAMDataOperation()
    config_operation.operationType = pam_pb2.PAMOperationType.ADD

    top_config_uid = os.urandom(16)

    if not parent_uid_bytes:
        # Root node
        config_operation.configuration.configurationUid = top_config_uid
        config_operation.configuration.controllerUid = gateway_uid_bytes
        config_operation.configuration.data = string_to_bytes(config_json_str)    # DATA size is between 16 and 516
    else:
        # Child node
        config_operation.element.elementUid = top_config_uid
        config_operation.element.parentUid = parent_uid_bytes
        config_operation.element.data = string_to_bytes(config_json_str)

    rq = pam_pb2.PAMModifyRequest()
    rq.operations.append(config_operation)

    child_generated_uids = []

    if child_config_json_strings:

        for child_config_json_string in child_config_json_strings:
            child_generated_uid = os.urandom(16)
            child_generated_uids.append(child_generated_uid)

            child_config_operation = pam_pb2.PAMDataOperation()
            child_config_operation.operationType = pam_pb2.PAMOperationType.ADD
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

    if config_uid_urlsafe not in params.record_cache:
        raise Exception(f'PAM Configuration record uid {config_uid_urlsafe} not found in cache. Make sure you are entering the correct uid.')
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
    from ..nested_share_folder.helpers import is_nested_share_record
    from ... import nested_share_folder as _nsf
    from ...subfolder import find_folders
    from .config_facades import PamConfigurationRecordFacade

    if is_nested_share_record(params, configuration_uid):
        folder_uids = list(find_folders(params, configuration_uid))
        folder_uid = folder_uids[0] if folder_uids else None
        if not folder_uid:
            config = vault.KeeperRecord.load(params, configuration_uid)
            if config and isinstance(config, vault.TypedRecord):
                facade = PamConfigurationRecordFacade()
                facade.record = config
                folder_uid = facade.folder_uid
        result = _nsf.remove_record_v3(params, [{
            'record_uid': configuration_uid,
            'folder_uid': folder_uid,
            'operation_type': 'owner-trash',
        }], dry_run=False)
        if not result.get('confirmed'):
            raise Exception(
                'PAM Configuration NSF removal was not confirmed by the server.')
    else:
        RecordRemoveCommand().execute(params, record=configuration_uid, force=True)

    if configuration_uid in params.record_cache:
        del params.record_cache[configuration_uid]
    nested_recs = getattr(params, 'nested_share_records', {})
    if configuration_uid in nested_recs:
        del nested_recs[configuration_uid]

    logging.info('PAM Configuration was removed successfully.')

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


def record_rotation_get(params, record_uid_bytes):  # type: (KeeperParams, bytes) -> router_pb2.RouterRotationInfo

    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = record_uid_bytes

    rotation_info_rs = api.communicate_rest(params, rq, 'pam/get_rotation_info', rs_type=router_pb2.RouterRotationInfo)

    return rotation_info_rs


def configuration_controller_get(params, config_uid_bytes: bytes):
    """
    Get the Controller UID that has access to the configuration UID
    Retrieves a keeper.pam_controller record, from given configuration_uid provided in request.
    controller_uid is the UID of the user who has access to the configuration url_safe_str_to_bytes(config_uid)
    """
    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = config_uid_bytes

    config_info_rs = api.communicate_rest(params, rq, 'pam/get_configuration_controller',
                                          rs_type=pam_pb2.PAMController)

    return config_info_rs
