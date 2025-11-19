import json
import logging
import os
from datetime import datetime

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

VERIFY_SSL = bool(os.environ.get("VERIFY_SSL", "TRUE") == "TRUE")


def get_router_url(params: KeeperParams):
    krouter_env_var_name = "KROUTER_URL"
    if os.getenv(krouter_env_var_name):
        krouter_server_url = os.getenv(krouter_env_var_name)
        logging.debug(f"Getting Krouter url from ENV Variable '{krouter_env_var_name}'='{krouter_server_url}'")
    else:
        base_server_url = params.rest_context.server_base
        base_server = urlparse(base_server_url).netloc
        str_base_server = base_server
        if isinstance(base_server, bytes):
            base_server = base_server.decode('utf-8')
        
        # In GovCloud environments, the router service is not under the govcloud subdomain
        krouter_server_url = 'https://connect.' + base_server
        if '.govcloud.' in krouter_server_url:
            krouter_server_url = krouter_server_url.replace('.govcloud.', '.')

    return krouter_server_url


def get_router_ws_url(params: KeeperParams):
    router_url = get_router_url(params)
    # More precise replacement of just the scheme
    if router_url.startswith('https://'):
        router_url = 'wss://' + router_url[8:]
    elif router_url.startswith('http://'):
        router_url = 'ws://' + router_url[7:]
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


def router_set_record_rotation_information(params, proto_request, transmission_key=None,
                                           encrypted_transmission_key=None, encrypted_session_token=None):
    rs = _post_request_to_router(params, 'set_record_rotation', proto_request, transmission_key=transmission_key,
                                 encrypted_transmission_key=encrypted_transmission_key,
                                 encrypted_session_token=encrypted_session_token)

    return rs


def router_get_rotation_schedules(params, proto_request):
    return _post_request_to_router(params, 'get_rotation_schedules', rq_proto=proto_request, rs_type=pam_pb2.PAMRotationSchedulesResponse)


def router_get_relay_access_creds(params, expire_sec=None):
    query_params = {
        'expire-sec': expire_sec
    }
    return _post_request_to_router(params, 'relay_access_creds', query_params=query_params, rs_type=pam_pb2.RelayAccessCreds)


def _post_request_to_router(params, path, rq_proto=None, rs_type=None, method='post',
                            raw_without_status_check_response=False, query_params=None, transmission_key=None,
                            encrypted_transmission_key=None, encrypted_session_token=None):
    krouter_host = get_router_url(params)
    path = '/api/user/' + path

    if not transmission_key:
        transmission_key = utils.generate_aes_key()
    if not encrypted_transmission_key:
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

    if not encrypted_session_token:
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


def router_send_action_to_gateway(params, gateway_action: GatewayAction, message_type, is_streaming,
                                  destination_gateway_uid_str=None, gateway_timeout=15000, transmission_key=None,
                                  encrypted_transmission_key=None, encrypted_session_token=None):
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

    msg_id = gateway_action.conversationId if gateway_action.conversationId else GatewayAction.generate_conversation_id('true')

    rq = router_pb2.RouterControllerMessage()
    rq.messageUid = utils.base64_url_decode(msg_id) if isinstance(msg_id, str) else msg_id
    rq.controllerUid = destination_gateway_uid_bytes
    rq.messageType = message_type
    rq.streamResponse = is_streaming
    rq.payload = gateway_action.toJSON().encode('utf-8')
    rq.timeout = gateway_timeout

    if not transmission_key:
        transmission_key = utils.generate_aes_key()

    response = router_send_message_to_gateway(
        params=params,
        transmission_key=transmission_key,
        rq_proto=rq,
        encrypted_transmission_key=encrypted_transmission_key,
        encrypted_session_token=encrypted_session_token)

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


def router_send_message_to_gateway(params, transmission_key, rq_proto,
                                   encrypted_transmission_key=None, encrypted_session_token=None):

    krouter_host = get_router_url(params)

    if not encrypted_transmission_key:
        server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]

        if params.rest_context.server_key_id < 7:
            encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
        else:
            encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

    encrypted_payload = b''

    if rq_proto:
        encrypted_payload = crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)
    if not encrypted_session_token:
        encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(params.session_token), transmission_key)

    rs = requests.post(
        krouter_host+"/api/user/send_controller_message",
        verify=VERIFY_SSL,

        headers={
            'TransmissionKey': bytes_to_base64(encrypted_transmission_key),
            'Authorization': f'KeeperUser {bytes_to_base64(encrypted_session_token)}',
        },
        data=encrypted_payload if rq_proto else None
    )

    if rs.status_code >= 300:
        raise Exception(str(rs.status_code) + ': error: ' + rs.reason + ', message: ' + rs.text)

    return rs


def get_response_payload(router_response):

    router_response_response = router_response.get('response')
    router_response_response_payload_str = router_response_response.get('payload')
    router_response_response_payload_dict = json.loads(router_response_response_payload_str)

    return router_response_response_payload_dict


def get_dag_leafs(params, encrypted_session_token, encrypted_transmission_key, record_id):
    """
    POST a stringified JSON object to /api/dag/get_leafs on the KRouter
    The object is:
    {
      vertex: string,
      graphId: number
    }
    """
    krouter_host = get_router_url(params)
    path = '/api/user/get_leafs'

    payload = {
        'vertex': record_id,
        'graphId': 0
    }

    try:
        rs = requests.request('post',
                              krouter_host + path,
                              verify=VERIFY_SSL,
                              headers={
                                  'TransmissionKey': bytes_to_base64(encrypted_transmission_key),
                                  'Authorization': f'KeeperUser {bytes_to_base64(encrypted_session_token)}'
                              },
                              data=json.dumps(payload).encode('utf-8')
                              )
    except ConnectionError as e:
        raise KeeperApiError(-1, f"KRouter is not reachable on '{krouter_host}'. Error: ${e}")
    except Exception as ex:
        raise ex

    if rs.status_code == 200:
        logging.debug("Found right host")
        return rs.json()
    else:
        logging.warning("Looks like there is no such controller connected to the router.")
        return None


def print_router_response(router_response, response_type, original_conversation_id=None, is_verbose=False, gateway_uid=''):
    if not router_response:
        return

    router_response_response = router_response.get('response')
    router_response_response_payload_str = router_response_response.get('payload')
    router_response_response_payload_dict = json.loads(router_response_response_payload_str)

    if router_response_response_payload_dict.get('warnings'):
        for w in router_response_response_payload_dict.get('warnings'):
            if w:
                print(f'{bcolors.WARNING}{w}{bcolors.ENDC}')

    if original_conversation_id:
        # gateway_response_conversation_id = utils.base64_url_decode(router_response_response_payload_dict.get('conversation_id')).decode("utf-8")
        # IDs are either bytes or base64 encoded strings which may be padded
        gateway_response_conversation_id = router_response_response_payload_dict.get('conversation_id', None)
        oid = (utils.base64_url_decode(original_conversation_id)
               if isinstance(original_conversation_id, str)
               else original_conversation_id)
        gid = (utils.base64_url_decode(gateway_response_conversation_id)
               if isinstance(gateway_response_conversation_id, str)
               else gateway_response_conversation_id)

        if oid != gid:
            logging.error(f"Message ID that was sent to the server [{original_conversation_id}] and the conversation id "
                          f"received back [{gateway_response_conversation_id}] are different. That probably means that "
                          f"the gateway sent a wrong response that was not associated with the request.")

    if not (router_response_response_payload_dict.get('is_ok') or router_response_response_payload_dict.get('isOk')):
        print(f"{bcolors.FAIL}{json.dumps(router_response_response_payload_dict, indent=4)}{bcolors.ENDC}")
        return

    if router_response_response_payload_dict.get('isScheduled') or router_response_response_payload_dict.get('is_scheduled'):
        conversation_id = router_response_response_payload_dict.get('conversation_id')

        gwinfo = f" --gateway={gateway_uid}" if gateway_uid else ""
        print(f"Scheduled action id: {bcolors.OKBLUE}{conversation_id}{bcolors.ENDC}")
        print(f"The action has been scheduled, use command '{bcolors.OKGREEN}pam action job-info {conversation_id}{gwinfo}{bcolors.ENDC}' to get status of the scheduled action")
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

        # Version and Gateway Details
        print(f'\n{bcolors.OKBLUE}Gateway Details{bcolors.ENDC}')
        gateway_config = gateway_info.get('gateway-config', {})
        version_info = gateway_config.get('version', {})
        if version_info.get("current"):
            print(f'\t{bcolors.OKGREEN}Version           : {version_info.get("current")}{bcolors.ENDC}')

        # Convert Unix timestamp to readable format
        started_time = gateway_config.get("connection_info", {}).get("started")
        try:
            if started_time:
                started_dt = datetime.fromtimestamp(float(started_time))
                local_tz = datetime.now().astimezone().tzinfo
                started_str = f"{started_dt.strftime('%Y-%m-%d %H:%M:%S')} {local_tz}"
                print(f'\t{bcolors.OKGREEN}Started Time      : {started_str}{bcolors.ENDC}')
        except (ValueError, TypeError):
            pass  # Skip if timestamp is invalid

        if gateway_config.get("ws_log_file"):
            print(f'\t{bcolors.OKGREEN}Logs Location     : {gateway_config.get("ws_log_file")}{bcolors.ENDC}')

        # Environment Info
        machine_env = gateway_info.get('machine', {}).get('environment', {})
        if machine_env and machine_env.get('provider'):
            print(f'\n{bcolors.OKBLUE}Environment Details{bcolors.ENDC}')
            env_color = bcolors.WARNING if machine_env.get('provider') == 'Local/Other' else bcolors.OKGREEN
            print(f'\t{env_color}Provider          : {machine_env.get("provider")}{bcolors.ENDC}')
            if machine_env.get('provider') != 'Local/Other':
                if machine_env.get('account_id'):
                    print(f'\t{env_color}Account           : {machine_env.get("account_id")}{bcolors.ENDC}')
                if machine_env.get('region'):
                    print(f'\t{env_color}Region            : {machine_env.get("region")}{bcolors.ENDC}')
                if machine_env.get('instance_type'):
                    print(f'\t{env_color}Instance Type     : {machine_env.get("instance_type")}{bcolors.ENDC}')

        # Machine Details
        machine = gateway_info.get('machine', {})
        print(f'\n{bcolors.OKBLUE}Machine Details{bcolors.ENDC}')

        if machine.get("hostname"):
            print(f'\t{bcolors.OKGREEN}Hostname          : {machine.get("hostname")}{bcolors.ENDC}')
        if machine.get("ip_address_local") and machine.get("ip_address_local") != "unknown":
            print(f'\t{bcolors.OKGREEN}IP (Local)        : {machine.get("ip_address_local")}{bcolors.ENDC}')
        if machine.get("ip_address_external"):
            print(f'\t{bcolors.OKGREEN}IP (External)     : {machine.get("ip_address_external")}{bcolors.ENDC}')

        os_info = []
        if machine.get("system"): os_info.append(machine.get("system"))
        if machine.get("release"): os_info.append(machine.get("release"))
        if os_info:
            print(f'\t{bcolors.OKGREEN}Operating System  : {" ".join(os_info)}{bcolors.ENDC}')

        memory = machine.get('memory', {})
        if memory.get('free_gb') is not None and memory.get('total_gb') is not None:
            print(
                f'\t{bcolors.OKGREEN}Memory            : {memory.get("free_gb")}GB free / {memory.get("total_gb")}GB total{bcolors.ENDC}')

        # Core Package Versions - Extract from installed packages
        installed_packages = {
            pkg.split('==')[0]: pkg.split('==')[1]
            for pkg in machine.get('installed-python-packages', [])
        }

        core_packages = [
            ('KDNRM', installed_packages.get('kdnrm')),
            ('Keeper GraphSync', installed_packages.get('keeper-dag')),
            ('Discovery Common', installed_packages.get('discovery-common'))
        ]

        # Only print Core Components section if at least one core package is found
        if any(version for _, version in core_packages):
            print(f'\n{bcolors.OKBLUE}Core Components{bcolors.ENDC}')
            for name, version in core_packages:
                if version:  # Only print if version is found
                    print(f'\t{bcolors.OKGREEN}{name:<16} : {version}{bcolors.ENDC}')

        # KSM Details
        print(f'\n{bcolors.OKBLUE}KSM Application Details{bcolors.ENDC}')
        ksm_app = gateway_info.get('ksm', {}).get('app', {})
        warnings_color = bcolors.WARNING if ksm_app.get("warnings") else bcolors.OKGREEN

        if ksm_app.get("title"):
            print(f'\t{bcolors.OKGREEN}Title             : {ksm_app.get("title")}{bcolors.ENDC}')
        if ksm_app.get("records-count") is not None:
            print(f'\t{bcolors.OKGREEN}Records Count     : {ksm_app.get("records-count")}{bcolors.ENDC}')
        if ksm_app.get("folders-count") is not None:
            print(f'\t{bcolors.OKGREEN}Folders Count     : {ksm_app.get("folders-count")}{bcolors.ENDC}')
        if ksm_app.get("expires-on"):
            print(f'\t{bcolors.OKGREEN}Expires On        : {ksm_app.get("expires-on")}{bcolors.ENDC}')
        print(f'\t{warnings_color}Warnings          : {ksm_app.get("warnings") or "None"}{bcolors.ENDC}')

        # Router Details
        print(f'\n{bcolors.OKBLUE}Router Connection{bcolors.ENDC}')
        router_conn = gateway_info.get('router', {}).get('connection', {})
        if router_conn.get("base-url"):
            print(f'\t{bcolors.OKGREEN}URL               : {router_conn.get("base-url")}{bcolors.ENDC}')
        router_status = router_conn.get("status", "UNKNOWN").lower()
        status_color = bcolors.OKGREEN if router_status == "connected" else bcolors.WARNING
        print(f'\t{status_color}Status            : {router_status}{bcolors.ENDC}')

        # PAM Configurations
        print(f'\n{bcolors.OKBLUE}PAM Configurations Accessible to this Gateway{bcolors.ENDC}')
        pam_configs = gateway_info.get('pam_configurations', [])
        if pam_configs:
            for idx, config in enumerate(pam_configs, 1):
                print(f'\t{bcolors.OKGREEN}{idx}. {config}{bcolors.ENDC}')
        else:
            print(f'\t{bcolors.WARNING}No PAM Configurations found{bcolors.ENDC}')

        # Additional details for verbose mode
        if is_verbose:
            print(f'\n{bcolors.OKBLUE}Additional Details{bcolors.ENDC}')
            if machine.get("working-dir"):
                print(f'\t{bcolors.OKGREEN}Working Directory : {machine.get("working-dir")}{bcolors.ENDC}')
            if machine.get("package-dir"):
                print(f'\t{bcolors.OKGREEN}Package Directory: {machine.get("package-dir")}{bcolors.ENDC}')
            if machine.get("executable"):
                print(f'\t{bcolors.OKGREEN}Python Executable: {machine.get("executable")}{bcolors.ENDC}')

            if machine.get('installed-python-packages'):
                print(f'\n{bcolors.OKBLUE}Installed Python Packages{bcolors.ENDC}')
                for package in sorted(machine.get('installed-python-packages', [])):
                    print(f'\t{bcolors.OKGREEN}{package}{bcolors.ENDC}')

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
