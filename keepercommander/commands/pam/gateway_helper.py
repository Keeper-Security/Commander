from typing import Sequence, Optional, List

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from ... import api, utils
from ...commands.utils import KSMCommand
from ...loginv3 import CommonHelperMethods
from ...params import KeeperParams
from ...proto import pam_pb2, enterprise_pb2


def find_one_gateway_by_uid_or_name(params, gateway_name_or_uid):
    all_gateways = get_all_gateways(params)
    gateway_uid_bytes = url_safe_str_to_bytes(gateway_name_or_uid)

    found_gateways = list(filter(lambda g: g.controllerUid == gateway_uid_bytes or g.controllerName == gateway_name_or_uid, all_gateways))
    if not found_gateways:
        return None

    first_found_gateway_uid_bytes = found_gateways[0].controllerUid

    # TODO: Print warning if there are more than 1 gateway found
    found_gateway_uid_str = CommonHelperMethods.bytes_to_url_safe_str(first_found_gateway_uid_bytes)

    return found_gateway_uid_str


def get_all_gateways(params):  # type: (KeeperParams) -> Sequence[pam_pb2.PAMController]
    rs = api.communicate_rest(params, None, 'pam/get_controllers', rs_type=pam_pb2.PAMControllersResponse)
    return rs.controllers


def find_connected_gateways(all_controllers, identifier):  # type: (List[bytes], str) -> Optional[bytes]
    # Will search connected controllers by the "controllerName", "deviceName", or "deviceToken"

    found_connected_controller_uid_bytes = next((c for c in all_controllers if (utils.base64_url_encode(c) == identifier)), None)

    if found_connected_controller_uid_bytes:
        # if len(found_connected_controller) > 1:
        #     logging.warning(f"More than one gateway with the same identifier [{identifier}] was located.")
        # else:
        #     return found_connected_controller[0]
        return found_connected_controller_uid_bytes
    else:
        return None


def create_gateway(params, gateway_name, ksm_app, config_init, ott_expire_in_min=5):

    one_time_token_dict = KSMCommand.add_client(params,
                                                app_name_or_uid=ksm_app,
                                                count=1,
                                                unlock_ip=True,
                                                first_access_expire_on=ott_expire_in_min,  # if one time token not used in 5 min then it will be expired
                                                access_expire_in_min=None, # how long the client has access to the application, None=Never, int = num of min
                                                client_name=gateway_name,
                                                config_init=False,
                                                silent=True,
                                                client_type=enterprise_pb2.DISCOVERY_AND_ROTATION_CONTROLLER)

    one_time_token_dict = one_time_token_dict[0]
    one_time_token = one_time_token_dict.get('oneTimeToken')

    if config_init:
        config_str_and_config_dict = KSMCommand.init_ksm_config(params, one_time_token, config_init,
                                                                include_config_dict=True)

        one_time_token = config_str_and_config_dict.get('config_str')

    return one_time_token


def remove_gateway(params, gateway_uid):   # type: (KeeperParams, bytes) -> None
    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = gateway_uid
    rs = api.communicate_rest(params, rq, 'pam/remove_controller', rs_type=pam_pb2.PAMRemoveControllerResponse)
    controller = next((x for x in rs.controllers if x.controllerUid == gateway_uid), None)
    if controller:
        raise Exception(controller.message)
