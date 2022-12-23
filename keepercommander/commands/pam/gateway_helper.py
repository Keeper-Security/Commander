import logging

from keepercommander import api, utils
from keepercommander.commands.utils import KSMCommand
from keepercommander.loginv3 import CommonHelperMethods
from keepercommander.proto import pam_pb2


def get_all_gateways(params):
    rs = api.communicate_rest(params, None, 'pam/get_controllers', rs_type=pam_pb2.PAMControllersResponse)
    return rs.controllers


def find_connected_gateways(all_controllers, identifier):
    # Will search connected controllers by the "controllerName", "deviceName", or "deviceToken"

    found_connected_controller = next((c for c in all_controllers
                                       if (CommonHelperMethods.bytes_to_url_safe_str(c.controllerUid) == identifier)
                                       ), None)

    if found_connected_controller:
        if len(found_connected_controller) > 1:
            logging.warning(f"More than one gateway with the same identifier [{identifier}] was located.")
        else:
            return found_connected_controller[0]
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
                                                silent=True)

    one_time_token_dict = one_time_token_dict[0]
    one_time_token = one_time_token_dict.get('oneTimeToken')

    if config_init:
        config_str_and_config_dict = KSMCommand.init_ksm_config(params, one_time_token, config_init,
                                                                include_config_dict=True)

        one_time_token = config_str_and_config_dict.get('config_str')

    return one_time_token


def remove_gateway(params, gateway_uid):
    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = utils.base64_url_decode(gateway_uid)

    rs = api.communicate_rest(params, rq, 'pam/remove_controller', rs_type=pam_pb2.PAMControllersResponse)

    # TODO: Add error checking

    return True
