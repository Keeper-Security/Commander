import json
import logging

import requests

from keepercommander.commands.base import dump_report_data
from keepercommander.commands.pam import gateway_helper
from keepercommander.commands.pam.pam_dto import GatewayAction
from keepercommander.display import bcolors
from keepercommander.proto.enterprise_pb2 import RouterControllerMessage, RouterRotationInfo, PAMGenericUidRequest
from keepercommander.utils import base64_url_decode, string_to_bytes

# KROUTER_URL = 'https://krouter-svc4-2049537335.us-east-1.elb.amazonaws.com/client'
KROUTER_URL = 'https://connect.dev.keepersecurity.com'
# KROUTER_URL = 'http://localhost:5001'
# KROUTER_URL = 'http://localhost:6080/worker/client'

VERIFY_SSL = True


def router_get_connected_gateways(params):
    response = requests.get(
        KROUTER_URL+"/client",
        verify=VERIFY_SSL,
        headers={
            'Authorization': f'KeeperUser ${params.session_token}'
        })

    if response.status_code != 200:
        raise Exception("Router is down [status code=" + str(response.status_code) + "]")

    resp = json.loads(response.text)

    return resp.get('controllers')


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


def _post_request_to_router(params, path, rq_proto=None):
    rs = requests.post(
        KROUTER_URL + "/" + path,
        verify=VERIFY_SSL,
        headers={
            'Authorization': f'KeeperUser ${params.session_token}'
        },
        data=rq_proto.SerializeToString()
    )

    content_type = rs.headers.get('Content-Type') or ''

    if rs.status_code == 200:
        if content_type == 'application/json':
            return rs.json()

        rs_body = rs.content
        return rs_body


def router_send_action_to_gateway(params, gateway_action: GatewayAction):
    # 1. Find connected gateway to send action to
    try:
        enterprise_controllers_connected = router_get_connected_gateways(params)

    except requests.exceptions.ConnectionError as errc:
        logging.info(f"{bcolors.WARNING}Looks like router is down. Router URL [{KROUTER_URL}]{bcolors.ENDC}")
        return
    except Exception as e:
        logging.warning(f"Unhandled error during retrieval of the connected gateways. {str(e)}")
        return

    if len(enterprise_controllers_connected) == 1:
        found_gateway = enterprise_controllers_connected[0]
    elif len(enterprise_controllers_connected) == 0:
        print(f"{bcolors.WARNING}\tNo running gateways for your enterprise. Start the gateway before sending any actions{bcolors.ENDC}")
        return
    else:  # There are more than two Gateways connected. Selecting the right one

        if not gateway_action.gateway_destination:
            print(f"{bcolors.WARNING}There are more than one Gateways running in your enterprise. "
                  f"You need to proved gateway to the action. To find connected gateways run action "
                  f"'{bcolors.OKBLUE}dr list{bcolors.WARNING}' and provide Gateway UID or Gateway Name.{bcolors.ENDC}")

            return

        found_gateway = gateway_helper.find_connected_gateways(params, gateway_action.gateway_destination)

    router_server_cookie = found_gateway.get('cookie')

    msg_id = gateway_action.messageId if gateway_action.messageId else GatewayAction.generate_message_id()
    msg_id_bytes = string_to_bytes(msg_id)

    rq = RouterControllerMessage()
    rq.messageUid = msg_id_bytes
    rq.controllerUid = base64_url_decode(found_gateway.get('controllerUid'))
    rq.stream = False
    rq.payload = string_to_bytes(gateway_action.toJSON())

    response = router_send_message_to_gateway(
        session_token=params.session_token,
        router_server_cookie=router_server_cookie,
        rq_proto=rq)

    router_response = json.loads(response.text)
    gateway_response = json.loads(router_response.get('gatewayResponse'))
    gateway_response_payload = json.loads(gateway_response.get('payload'))

    # controller_response_str = router_response.get('data')
    # controller_response = json.loads(controller_response_str)

    return {
        'response': gateway_response_payload
    }


def router_send_message_to_gateway(session_token, router_server_cookie, rq_proto):

    rs = requests.post(
        KROUTER_URL+"/send_controller_message",
        verify=VERIFY_SSL,
        headers={
            'Authorization': f'KeeperUser ${session_token}'
        },
        cookies={
            'AWSALB': router_server_cookie
        },
        data=rq_proto.SerializeToString())

    if rs.status_code >= 300:
        raise Exception(str(rs.status_code) + ': error: ' + rs.reason + ', message: ' + rs.text)

    return rs


def print_router_response(router_response, original_message_id=None):
    if not router_response:
        return

    gateway_response_data = router_response.get('response')

    gateway_response_message_id = base64_url_decode(gateway_response_data.get('messageId')).decode("utf-8")

    if original_message_id and original_message_id != gateway_response_message_id:
        logging.error(f"Message ID that was sent to the server [{original_message_id}] and the message id received "
                      f"back [{gateway_response_message_id}] were different. That probably means that the "
                      f"gateway sent a wrong response that was not associated with the reqeust.")

    if not gateway_response_data.get('ok'):
        print(f"{bcolors.FAIL}{json.dumps(gateway_response_data, indent=4)}{bcolors.ENDC}")
    else:
        message_id = gateway_response_data.get('messageId')

        if gateway_response_data.get('isScheduled'):

            print(f"Scheduled action id: {bcolors.OKBLUE}{message_id}{bcolors.ENDC}")
            print(f"The action has been scheduled, use command '{bcolors.OKGREEN}pam action job-info {message_id}{bcolors.ENDC}' to get status of the scheduled action")
        else:
            print(f"{bcolors.OKBLUE}{json.dumps(gateway_response_data, indent=4)}{bcolors.ENDC}")


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
