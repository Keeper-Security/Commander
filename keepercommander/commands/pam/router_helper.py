import json
import logging
import os

import requests
from keeper_secrets_manager_core.utils import bytes_to_base64
from requests import ConnectionError

from keepercommander import crypto, utils, rest_api
from keepercommander.commands.base import dump_report_data
from keepercommander.commands.pam import gateway_helper
from keepercommander.commands.pam.pam_dto import GatewayAction
from keepercommander.display import bcolors
from keepercommander.error import KeeperApiError
from keepercommander.params import KeeperParams
from keepercommander.proto.pam_pb2 import PAMOnlineControllers, PAMGenericUidRequest, PAMRotationSchedulesResponse, \
    ControllerResponse
from keepercommander.proto.router_pb2 import RouterRotationInfo, RouterResponse, RouterResponseCode, RRC_OK, \
    RouterControllerMessage, RRC_BAD_STATE, RRC_TIMEOUT
from keepercommander.utils import base64_url_decode, string_to_bytes

VERIFY_SSL = True


def get_router_url(params: KeeperParams):

    krouter_env_var_name = "KROUTER_URL"

    if os.getenv(krouter_env_var_name):
        krouter_env_var_val = os.getenv(krouter_env_var_name)
        logging.debug(f"Getting Krouter url from ENV Variable '{krouter_env_var_name}'='{krouter_env_var_val}'")
        return krouter_env_var_val    # 'KROUTER_URL = http://localhost:6001' OR 'http://localhost:5001'

    krouter_server_url = 'https://connect.' + params.server  # https://connect.dev.keepersecurity.com
    logging.debug(f"KRouter url '${krouter_server_url}")

    return krouter_server_url


def router_get_connected_gateways(params):

    rs = _post_request_to_router(params, 'get_controllers')

    if type(rs) == bytes:
        pam_online_controllers = PAMOnlineControllers()
        pam_online_controllers.ParseFromString(rs)

        return pam_online_controllers

    return None


def router_get_record_rotation_info(params, record_uid_bytes):
    rq = PAMGenericUidRequest()
    rq.uid = record_uid_bytes

    rs = _post_request_to_router(params, 'get_rotation_info', rq_proto=rq)

    if type(rs) == bytes:
        rri = RouterRotationInfo()
        rri.ParseFromString(rs)

        return rri

    return None


def router_set_record_rotation_information(params, proto_request):

    rs = _post_request_to_router(params, 'set_record_rotation', proto_request)

    return rs


def router_get_rotation_schedules(params, proto_request):

    rs = _post_request_to_router(params, 'get_rotation_schedules', rq_proto=proto_request)

    if type(rs) == bytes:
        rsr = PAMRotationSchedulesResponse()
        rsr.ParseFromString(rs)

        return rsr

    return None


def _post_request_to_router(params, path, rq_proto=None, method='post'):
    krouter_host = get_router_url(params)

    transmission_key = utils.generate_aes_key()
    server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]
    encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)

    encrypted_payload = b''

    if rq_proto:
        encrypted_payload = crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)
    encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(params.session_token), transmission_key)

    try:
        rs = requests.request(method,
                              krouter_host + "/" + path,
                              verify=VERIFY_SSL,
                              headers={
                                'TransmissionKey': bytes_to_base64(encrypted_transmission_key),
                                'Authorization': f'KeeperUser {bytes_to_base64(encrypted_session_token)}'
                              },
                              data=encrypted_payload if rq_proto else None
        )
    except ConnectionError as e:
        raise KeeperApiError(-1, f"KRouter is not reachable on '{krouter_host}'. Error: ${e}")
    except Exception as ex:
        raise ex

    content_type = rs.headers.get('Content-Type') or ''

    if rs.status_code == 200:
        if content_type == 'application/json':
            return rs.json()

        rs_body = rs.content

        if type(rs_body) == bytes:

            router_response = RouterResponse()
            router_response.ParseFromString(rs_body)

            rrc = RouterResponseCode.Name(router_response.responseCode)
            if router_response.responseCode != RRC_OK:
                raise Exception(router_response.errorMessage + ' Response code: ' + rrc)

            if router_response.encryptedPayload:
                payload_encrypted = router_response.encryptedPayload
                payload_decrypted = crypto.decrypt_aes_v2(payload_encrypted, transmission_key)
            else:
                payload_decrypted = None
            return payload_decrypted

        return rs_body
    else:
        raise KeeperApiError(rs.status_code, rs.text)


def router_send_action_to_gateway(params, gateway_action: GatewayAction, message_type, is_streaming):

    krouter_host = get_router_url(params)

    # 1. Find connected gateway to send action to
    try:
        enterprise_controllers_connected = router_get_connected_gateways(params).controllers

    except requests.exceptions.ConnectionError as errc:
        logging.info(f"{bcolors.WARNING}Looks like router is down. Router URL [{krouter_host}]{bcolors.ENDC}")
        return
    except Exception as e:
        raise e

    if not enterprise_controllers_connected or len(enterprise_controllers_connected) == 0:
        print(f"{bcolors.WARNING}\tNo running or connected Gateways in your enterprise. "
              f"Start the Gateway before sending any action to it.{bcolors.ENDC}")
        return
    elif len(enterprise_controllers_connected) == 1:
        found_gateway = enterprise_controllers_connected[0]
    else:  # There are more than two Gateways connected. Selecting the right one

        if not gateway_action.gateway_destination:
            print(f"{bcolors.WARNING}There are more than one Gateways running in your enterprise. "
                  f"You need to proved gateway to the action. To find connected gateways run action "
                  f"'{bcolors.OKBLUE}dr list{bcolors.WARNING}' and provide Gateway UID or Gateway Name.{bcolors.ENDC}")

            return

        found_gateway = gateway_helper.find_connected_gateways(params, gateway_action.gateway_destination)

    router_server_cookie = found_gateway.cookie

    msg_id = gateway_action.messageId if gateway_action.messageId else GatewayAction.generate_message_id()
    msg_id_bytes = string_to_bytes(msg_id)

    rq = RouterControllerMessage()
    rq.messageUid = msg_id_bytes
    rq.controllerUid = found_gateway.controllerUid
    rq.messageType = message_type
    rq.streamResponse = is_streaming
    rq.payload = string_to_bytes(gateway_action.toJSON())

    transmission_key = utils.generate_aes_key()

    response = router_send_message_to_gateway(
        params=params,
        transmission_key=transmission_key,
        router_server_cookie=router_server_cookie,
        rq_proto=rq)

    rs_body = response.content

    if type(rs_body) == bytes:
        router_response = RouterResponse()
        router_response.ParseFromString(rs_body)

        rrc = RouterResponseCode.Name(router_response.responseCode)
        if router_response.responseCode == RRC_BAD_STATE:
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        if router_response.responseCode == RRC_TIMEOUT:
            # Router tried to send message to the Controller but the response didn't arrive on time (3 sec).
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        if router_response.responseCode != RRC_OK:
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        payload_encrypted = router_response.encryptedPayload
        if payload_encrypted:

            payload_decrypted = crypto.decrypt_aes_v2(payload_encrypted, transmission_key)

            controller_response = ControllerResponse()
            controller_response.ParseFromString(payload_decrypted)

            gateway_response_payload = json.loads(controller_response.payload)
        else:
            gateway_response_payload = {}

        # controller_response_str = router_response.get('data')
        # controller_response = json.loads(controller_response_str)

        return {
            'response': gateway_response_payload
        }


def router_send_message_to_gateway(params, transmission_key, router_server_cookie, rq_proto):

    krouter_host = get_router_url(params)

    server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]
    encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)

    encrypted_payload = b''

    if rq_proto:
        encrypted_payload = crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)
    encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(params.session_token), transmission_key)

    rs = requests.post(
        krouter_host+"/send_controller_message",
        verify=VERIFY_SSL,

        headers={
            'TransmissionKey': bytes_to_base64(encrypted_transmission_key),
            'Authorization': f'KeeperUser {bytes_to_base64(encrypted_session_token)}',
        },
        cookies={
            'AWSALB': router_server_cookie
        },
        data=encrypted_payload if rq_proto else None
    )

    if rs.status_code >= 300:
        raise Exception(str(rs.status_code) + ': error: ' + rs.reason + ', message: ' + rs.text)

    return rs


def print_router_response(router_response, original_conversation_id=None):
    if not router_response:
        return

    router_response_response = router_response.get('response')
    router_response_response_payload_str = router_response_response.get('payload')
    router_response_response_payload_dict = json.loads(router_response_response_payload_str)

    gateway_response_conversation_id = base64_url_decode(router_response_response_payload_dict.get('conversation_id')).decode("utf-8")

    if original_conversation_id and original_conversation_id != gateway_response_conversation_id:
        logging.error(f"Message ID that was sent to the server [{original_conversation_id}] and the conversation id "
                      f"received back is [{gateway_response_conversation_id}] were different. That probably means that "
                      f"the gateway sent a wrong response that was not associated with the reqeust.")

    if not router_response_response_payload_dict.get('ok'):
        print(f"{bcolors.FAIL}{json.dumps(router_response_response_payload_dict, indent=4)}{bcolors.ENDC}")
    else:
        conversation_id = router_response_response_payload_dict.get('conversation_id')

        if router_response_response_payload_dict.get('isScheduled'):

            print(f"Scheduled action id: {bcolors.OKBLUE}{conversation_id}{bcolors.ENDC}")
            print(f"The action has been scheduled, use command '{bcolors.OKGREEN}pam action job-info {conversation_id}{bcolors.ENDC}' to get status of the scheduled action")
        else:
            print(f"{bcolors.OKBLUE}{json.dumps(router_response_response_payload_dict, indent=4)}{bcolors.ENDC}")


def print_configs_from_router(params, router_response):
    configurations = router_response.get('response').get('data')

    table = []
    headers = ['Config Uid',
               'Config Name',
               'Access Record Uid',
               'Has access to record?',
               'Access Record Title',
               'Access Record Type']
    for c in configurations:

        configuration_uid = c.get('configurationUid')
        access_record_uid = c.get('accessRecordUid')
        access_record_title = c.get('accessRecordTitle') if 'accessRecordTitle' in c else '[Gateway has no access]'
        access_record_type = c.get('accessRecordType') if 'accessRecordType' in c else '[Gateway has no access]'

        has_access_to_record = access_record_uid in params.record_cache

        row_color = bcolors.FAIL
        if has_access_to_record:
            row_color = bcolors.OKGREEN

        row = [
            f'{row_color}{configuration_uid}',
            c.get('configurationName'),
            access_record_uid,
            'Yes' if has_access_to_record else 'No',
            access_record_title,
            f'{access_record_type}{bcolors.ENDC}'
        ]

        table.append(row)

    table.sort(key=lambda x: (x[3] or '', x[1].lower()))

    dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


def encrypt_pwd_complexity(rule_list_dict, record_key_unencrypted):
    # With padding
    # rule_list_json_bytes = api.get_record_data_json_bytes(rule_list_dict)
    # rule_list_json_bytes_padded = api.pad_aes_gcm(rule_list_json_bytes)
    # rule_list_json_bytes_padded_encrypted = crypto.encrypt_aes_v2(rule_list_json_bytes_padded, record_key_unencrypted)

    # Without padding
    rule_list_json = json.dumps(rule_list_dict)
    rule_list_json_bytes = rule_list_json.encode('UTF-8')
    rule_list_json_encrypted = crypto.encrypt_aes_v2(rule_list_json_bytes, record_key_unencrypted)

    return rule_list_json_encrypted
