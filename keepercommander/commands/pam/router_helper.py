import json
import logging
import os

import requests
from keeper_secrets_manager_core.utils import bytes_to_base64, url_safe_str_to_bytes
from requests import ConnectionError
from urllib.parse import urlparse

import google

from . import gateway_helper
from .pam_dto import GatewayAction
from .. import base
from ... import crypto, utils, rest_api
from ...display import bcolors
from ...error import KeeperApiError
from ...params import KeeperParams
from ...proto import pam_pb2, router_pb2

VERIFY_SSL = True


def get_router_url(params: KeeperParams):
    krouter_env_var_name = "KROUTER_URL"
    if os.getenv(krouter_env_var_name):
        krouter_server_url = os.getenv(krouter_env_var_name)
        logging.debug(f"Getting Krouter url from ENV Variable '{krouter_env_var_name}'='{krouter_server_url}'")
    else:
        base_server_url = params.rest_context.server_base
        base_server = urlparse(base_server_url).netloc
        if base_server.lower().startswith('govcloud.'):
            base_server = base_server[len('govcloud.'):]

        krouter_server_url = 'https://connect.' + base_server  # https://connect.dev.keepersecurity.com

    return krouter_server_url


def get_router_ws_url(params: KeeperParams):
    router_url = get_router_url(params)
    router_url = router_url.replace('http', 'ws')
    return router_url


def router_get_connected_gateways(params):  # type: (KeeperParams) -> pam_pb2.PAMOnlineControllers
    rs = _post_request_to_router(params, 'get_controllers')

    if type(rs) == bytes:
        pam_online_controllers = pam_pb2.PAMOnlineControllers()
        pam_online_controllers.ParseFromString(rs)
        if logging.getLogger().level <= logging.DEBUG:
            js = google.protobuf.json_format.MessageToJson(pam_online_controllers)
            logging.debug('>>> [GW RS] %s: %s', 'get_controllers', js)

        return pam_online_controllers

    return None


# def router_get_record_rotation_info(params, record_uid_bytes):
#     rq = PAMGenericUidRequest()
#     rq.uid = record_uid_bytes
#
#     rs = _post_request_to_router(params, 'get_rotation_info', rq_proto=rq)
#
#     if type(rs) == bytes:
#         rri = RouterRotationInfo()
#         rri.ParseFromString(rs)
#
#         return rri
#
#     return None


def router_set_record_rotation_information(params, proto_request):
    rs = _post_request_to_router(params, 'set_record_rotation', proto_request)

    return rs


def router_get_rotation_schedules(params, proto_request):
    return _post_request_to_router(params, 'get_rotation_schedules', rq_proto=proto_request, rs_type=pam_pb2.PAMRotationSchedulesResponse)


def router_get_relay_access_creds(params, expire_sec=None):
    query_params = {
        'expire-sec': expire_sec
    }
    return _post_request_to_router(params, 'relay_access_creds', query_params=query_params, rs_type=pam_pb2.RelayAccessCreds)


def _post_request_to_router(params, path, rq_proto=None, rs_type=None, method='post', raw_without_status_check_response=False, query_params=None):
    krouter_host = get_router_url(params)
    path = '/api/user/' + path

    transmission_key = utils.generate_aes_key()
    server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]

    if params.rest_context.server_key_id < 7:
        encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
    else:
        encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

    encrypted_payload = b''

    if rq_proto:
        if logging.getLogger().level <= logging.DEBUG:
            js = google.protobuf.json_format.MessageToJson(rq_proto)
            logging.debug('>>> [GW RQ] %s: %s', path, js)
        encrypted_payload = crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)

    encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(params.session_token), transmission_key)

    try:
        rs = requests.request(method,
                              krouter_host + path,
                              params=query_params,
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

    if raw_without_status_check_response:
        return rs

    if rs.status_code < 400:
        if content_type == 'application/json':
            return rs.json()

        rs_body = rs.content
        if isinstance(rs_body, bytes):
            router_response = router_pb2.RouterResponse()
            router_response.ParseFromString(rs_body)

            rrc = router_pb2.RouterResponseCode.Name(router_response.responseCode)
            if router_response.responseCode != router_pb2.RRC_OK:
                raise Exception(router_response.errorMessage + ' Response code: ' + rrc)

            if router_response.encryptedPayload:
                payload_encrypted = router_response.encryptedPayload
                payload_decrypted = crypto.decrypt_aes_v2(payload_encrypted, transmission_key)
            else:
                payload_decrypted = None

            if rs_type:
                if payload_decrypted:
                    rs_proto = rs_type()
                    rs_proto.ParseFromString(payload_decrypted)
                    if logging.getLogger().level <= logging.DEBUG:
                        js = google.protobuf.json_format.MessageToJson(rs_proto)
                        logging.debug('>>> [GW RS] %s: %s', 'get_rotation_schedules', js)
                    return rs_proto
                else:
                    return None

            return payload_decrypted

        return rs_body
    else:
        raise KeeperApiError(rs.status_code, rs.text)


def get_controller_cookie(params, destination_controller_uid_str):

    # TODO: Cache the cookies for controller UIDs to improve the performance
    max_count = 100
    curr_count = 0

    while True:
        if curr_count > max_count:
            logging.error(f"Too many calls without getting good response from the server. max_count={max_count}")

            return None

        resp = _post_request_to_router(params,
                                       f'bind_to_controller/{destination_controller_uid_str}',
                                       method='get',
                                       raw_without_status_check_response=True)

        # print('Cookies:')
        # for c in resp.cookies:
        #     print(c.name, c.value)

        if resp.status_code == 200:
            logging.debug("Found right host")
            return resp.cookies
        if resp.status_code == 303:
            logging.debug("Controller connected to the router, but on another host. Try another call...")
        else:
            logging.warning("Looks like there is no such controller connected to the router.")
            return None

def request_cookie_jar_to_str(cookie_jar):
    cookie_dict = dict(cookie_jar)
    found = ['%s=%s' % (name, value) for (name, value) in cookie_dict.items()]
    return ';'.join(found)


def router_send_action_to_gateway(params, gateway_action: GatewayAction, message_type, is_streaming, destination_gateway_uid_str=None, gateway_timeout=15000):
    # Default time out how long the response from the Gateway should be
    krouter_host = get_router_url(params)

    # 1. Find connected gateway to send action to
    try:
        router_enterprise_controllers_connected = \
            [x.controllerUid for x in router_get_connected_gateways(params).controllers]

    except requests.exceptions.ConnectionError as errc:
        logging.info(f"{bcolors.WARNING}Looks like router is down. Router URL [{krouter_host}]{bcolors.ENDC}")
        return
    except Exception as e:
        raise e

    if destination_gateway_uid_str:
        # Means that we want to get info for a specific Gateway

        destination_gateway_uid_bytes = url_safe_str_to_bytes(destination_gateway_uid_str)

        if destination_gateway_uid_bytes not in router_enterprise_controllers_connected:
            print(f"{bcolors.WARNING}\tThis Gateway currently is not online.{bcolors.ENDC}")
            return
    else:
        if not router_enterprise_controllers_connected or len(router_enterprise_controllers_connected) == 0:
            print(f"{bcolors.WARNING}\tNo running or connected Gateways in your enterprise. "
                  f"Start the Gateway before sending any action to it.{bcolors.ENDC}")
            return
        elif len(router_enterprise_controllers_connected) == 1:
            destination_gateway_uid_bytes = router_enterprise_controllers_connected[0]
            destination_gateway_uid_str = utils.base64_url_encode(destination_gateway_uid_bytes)
        else:  # There are more than two Gateways connected. Selecting the right one

            if not gateway_action.gateway_destination:
                print(f"{bcolors.WARNING}There are more than one Gateways running in your enterprise. "
                      f"Only '{bcolors.OKGREEN}pam action rotate{bcolors.WARNING}' is able to know "
                      f"which Gateway should receive a request. Any other commands should have a Gateway specified. "
                      f"See help for the command you are trying to use. To find connected gateways run action "
                      f"'{bcolors.OKGREEN}pam gateway list{bcolors.WARNING}' and provide Gateway UID or Gateway Name.{bcolors.ENDC}")

                return

            destination_gateway_uid_bytes = gateway_helper.find_connected_gateways(router_enterprise_controllers_connected, gateway_action.gateway_destination)
            destination_gateway_uid_str = utils.base64_url_encode(destination_gateway_uid_bytes)

    msg_id = gateway_action.conversationId if gateway_action.conversationId else GatewayAction.generate_conversation_id()
    msg_id_bytes = msg_id.encode('utf-8')

    rq = router_pb2.RouterControllerMessage()
    rq.messageUid = msg_id_bytes
    rq.controllerUid = destination_gateway_uid_bytes
    rq.messageType = message_type
    rq.streamResponse = is_streaming
    rq.payload = gateway_action.toJSON().encode('utf-8')
    rq.timeout = gateway_timeout

    transmission_key = utils.generate_aes_key()

    response = router_send_message_to_gateway(
        params=params,
        transmission_key=transmission_key,
        rq_proto=rq,
        destination_gateway_uid_str=destination_gateway_uid_str)

    rs_body = response.content

    if type(rs_body) == bytes:
        router_response = router_pb2.RouterResponse()
        router_response.ParseFromString(rs_body)

        rrc = router_pb2.RouterResponseCode.Name(router_response.responseCode)
        if router_response.responseCode == router_pb2.RRC_OK:
            logging.debug("Good response...")

        elif router_response.responseCode == router_pb2.RRC_BAD_STATE:
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        elif router_response.responseCode == router_pb2.RRC_TIMEOUT:
            # Router tried to send message to the Controller but the response didn't arrive on time
            # ex. if Router is expecting response to be within 3 sec, but the gateway didn't respond within that time
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        elif router_response.responseCode == router_pb2.RRC_CONTROLLER_DOWN:
            # Sent an action to the Controller that is no longer online
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        else:
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)


        payload_encrypted = router_response.encryptedPayload
        if payload_encrypted:

            payload_decrypted = crypto.decrypt_aes_v2(payload_encrypted, transmission_key)

            controller_response = pam_pb2.ControllerResponse()
            controller_response.ParseFromString(payload_decrypted)

            gateway_response_payload = json.loads(controller_response.payload)
        else:
            gateway_response_payload = {}

        # controller_response_str = router_response.get('data')
        # controller_response = json.loads(controller_response_str)

        return {
            'response': gateway_response_payload
        }


def router_send_message_to_gateway(params, transmission_key, rq_proto, destination_gateway_uid_str,
                                   destination_gateway_cookies=None):

    krouter_host = get_router_url(params)

    server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]

    if params.rest_context.server_key_id < 7:
        encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
    else:
        encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

    encrypted_payload = b''

    if rq_proto:
        encrypted_payload = crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)
    encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(params.session_token), transmission_key)

    if not destination_gateway_cookies:
        destination_gateway_cookies = get_controller_cookie(params, destination_gateway_uid_str)

    if not destination_gateway_cookies:
        raise Exception('Even though it seems that the Gateway is online, Commander was unable to get the '
                        'cookies to connect to the Gateway')

    rs = requests.post(
        krouter_host+"/api/user/send_controller_message",
        verify=VERIFY_SSL,

        headers={
            'TransmissionKey': bytes_to_base64(encrypted_transmission_key),
            'Authorization': f'KeeperUser {bytes_to_base64(encrypted_session_token)}',
        },
        cookies=destination_gateway_cookies,
        data=encrypted_payload if rq_proto else None
    )

    if rs.status_code >= 300:
        raise Exception(str(rs.status_code) + ': error: ' + rs.reason + ', message: ' + rs.text)

    return rs


def print_router_response(router_response, response_type, original_conversation_id=None, is_verbose=False):
    if not router_response:
        return

    router_response_response = router_response.get('response')
    router_response_response_payload_str = router_response_response.get('payload')
    router_response_response_payload_dict = json.loads(router_response_response_payload_str)

    gateway_response_conversation_id = utils.base64_url_decode(router_response_response_payload_dict.get('conversation_id')).decode("utf-8")

    if router_response_response_payload_dict.get('warnings'):
        for w in router_response_response_payload_dict.get('warnings'):
            if w:
                print(f'{bcolors.WARNING}{w}{bcolors.ENDC}')


    if original_conversation_id and original_conversation_id != gateway_response_conversation_id:
        logging.error(f"Message ID that was sent to the server [{original_conversation_id}] and the conversation id "
                      f"received back is [{gateway_response_conversation_id}] were different. That probably means that "
                      f"the gateway sent a wrong response that was not associated with the reqeust.")

    if not (router_response_response_payload_dict.get('is_ok') or router_response_response_payload_dict.get('isOk')):
        print(f"{bcolors.FAIL}{json.dumps(router_response_response_payload_dict, indent=4)}{bcolors.ENDC}")
        return

    if router_response_response_payload_dict.get('isScheduled') or router_response_response_payload_dict.get('is_scheduled'):
        conversation_id = router_response_response_payload_dict.get('conversation_id')

        print(f"Scheduled action id: {bcolors.OKBLUE}{conversation_id}{bcolors.ENDC}")
        print(f"The action has been scheduled, use command '{bcolors.OKGREEN}pam action job-info {conversation_id}{bcolors.ENDC}' to get status of the scheduled action")
        return

    elif response_type == 'job_info':
        job_info = router_response_response_payload_dict.get('data')
        exec_response_value = job_info.get('execResponseValue')
        exec_response_value_msg = exec_response_value.get('message') if exec_response_value else None
        exec_response_value_logs = exec_response_value.get('execLog') if exec_response_value else None
        exec_duration = job_info.get('executionDuration')
        exec_status = job_info.get('status')
        exec_exception = job_info.get('execException')

        print(f'Execution Details\n-------------------------')

        if exec_status == 'finished':
            font_color = bcolors.OKGREEN
        elif exec_status == 'running':
            font_color = bcolors.WARNING
        else:
            font_color = bcolors.FAIL

        print(f'\t{font_color}Status              : {job_info.get("reason") if job_info.get("reason") else exec_status}{bcolors.ENDC}')

        if exec_duration:
            print(f'\t{font_color}Duration            : {exec_duration}{bcolors.ENDC}')

        if exec_response_value_msg:
            print(f'\t{font_color}Response Message    : {exec_response_value_msg}{bcolors.ENDC}')

        if exec_response_value_logs:
            print(f'\t{font_color}Post-execution scripts logs:{bcolors.ENDC}')
            for el in exec_response_value_logs:
                print(f'\t\t{font_color}script: {el.get("name")}{bcolors.ENDC}')
                print(f'\t\t{font_color}return code: {el.get("return_code")}{bcolors.ENDC}')
                if el.get("stdout"):
                    print(f'\t\t{font_color}stdout:\n---\n{bcolors.OKBLUE}{el.get("stdout")}{font_color}\n---{bcolors.ENDC}')
                if el.get("stderr"):
                    print(f'\t\t{font_color}stderr:\n---\n{bcolors.WARNING}{el.get("stderr")}{font_color}\n---{bcolors.ENDC}')
                print(f'\n')

        if exec_exception:
            print(f'\t{font_color}Execution Exception : {exec_exception}{bcolors.ENDC}')

        # print(f"{bcolors.OKBLUE}{json.dumps(router_response_response_payload_dict, indent=4)}{bcolors.ENDC}")

    elif response_type == 'gateway_info':

        gateway_info = router_response_response_payload_dict.get('data')

        print(f'{bcolors.OKBLUE}Gateway Details{bcolors.ENDC}')
        gateway_config = gateway_info.get('gateway-config')
        print(f'\t{bcolors.OKGREEN}Started Time      : {gateway_config.get("connection_info").get("started")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Logs File         : {gateway_config.get("ws_log_file")}{bcolors.ENDC}')

        print(f'\n{bcolors.OKBLUE}KSM Application Details{bcolors.ENDC}')
        ksm_app = gateway_info.get('ksm').get('app')
        warnings_row_color = bcolors.WARNING if ksm_app.get("warnings") else bcolors.OKGREEN

        print(f'\t{bcolors.OKGREEN}Application Title : {ksm_app.get("title")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Number of Records : {ksm_app.get("records-count")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Number of Folders : {ksm_app.get("folders-count")}{bcolors.ENDC}')
        print(f'\t{warnings_row_color}Warnings          : {ksm_app.get("warnings")}{bcolors.ENDC}')

        print(f'\n{bcolors.OKBLUE}Host Details{bcolors.ENDC}')
        host_details = gateway_info.get('machine')
        installed_packages_list = host_details.get('installed-python-packages')
        installed_packages_str = ', '.join(installed_packages_list)

        hostname = host_details.get('hostname')
        ip_address_local = host_details.get('ip_address_local')
        ip_address_external = host_details.get('ip_address_external')

        print(f'\t{bcolors.OKGREEN}Hostname          : {hostname}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}IP Address (loc.) : {ip_address_local}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}IP Address (ext.) : {ip_address_external}{bcolors.ENDC}')

        print(f'\t{bcolors.OKGREEN}OS                : {host_details.get("os")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Current Time      : {host_details.get("current-time")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Executable        : {host_details.get("executable")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Package Directory : {host_details.get("package-dir")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Working Directory : {host_details.get("working-dir")}{bcolors.ENDC}')

        if is_verbose:
            print(f'\t{bcolors.OKGREEN}Installed Packages: {installed_packages_str}{bcolors.ENDC}')

        print(f'\n{bcolors.OKBLUE}Router Details{bcolors.ENDC}')
        router_details = gateway_info.get('router').get('connection')
        print(f'\t{bcolors.OKGREEN}Base URL          : {router_details.get("base-url")}{bcolors.ENDC}')
        print(f'\t{bcolors.OKGREEN}Connection Status : {router_details.get("status")}{bcolors.ENDC}')

        print(f'\n{bcolors.OKBLUE}PAM Configurations(s) Available to Gateway{bcolors.ENDC}')
        pam_configs = gateway_info.get('pam_configurations')

        if pam_configs:
            for pc in pam_configs:
                print(f'\t{bcolors.OKGREEN}UID          : {pc}{bcolors.ENDC}')
        else:
            print(f'\t{bcolors.WARNING}No PAM Configurations{bcolors.ENDC}')

    # else:
    #     print(f"{bcolors.OKBLUE}{json.dumps(router_response_response_payload_dict, indent=4)}{bcolors.ENDC}")


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

    base.dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


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
