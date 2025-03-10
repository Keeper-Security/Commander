from __future__ import annotations
import json
from ..pam.router_helper import router_send_action_to_gateway
from ..pam.pam_dto import GatewayAction
from ..pam.router_helper import get_response_payload
from ...proto import pam_pb2
from ...display import bcolors
import logging
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..discover import GatewayContext
    from ...params import KeeperParams


class GatewayActionSaasListCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 languages: Optional[List[str]] = None):

        if languages is None:
            languages = ["en_US"]

        self.configurationUid = configuration_uid
        self.languages = languages

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionSaasListCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionSaasListCommandInputs, conversation_id=None):
        super().__init__('saas-list', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


def get_gateway_saas_schema(params: KeeperParams, gateway_context: GatewayContext):
    if gateway_context is None:
        print(f"{bcolors.FAIL}The user record does not have the set gateway{bcolors.ENDC}")
        return

    # Get schema information from the Gateway
    action_inputs = GatewayActionSaasListCommandInputs(
        configuration_uid=gateway_context.configuration_uid,
    )

    conversation_id = GatewayAction.generate_conversation_id()
    router_response = router_send_action_to_gateway(
        params=params,
        gateway_action=GatewayActionSaasListCommand(
            inputs=action_inputs,
            conversation_id=conversation_id),
        message_type=pam_pb2.CMT_GENERAL,
        is_streaming=False,
        destination_gateway_uid_str=gateway_context.gateway_uid
    )

    if router_response is None:
        print(f"{bcolors.FAIL}Did not get router response.{bcolors.ENDC}")
        return None

    response = router_response.get("response")
    logging.debug(f"Router Response: {response}")
    payload = get_response_payload(router_response)
    data = payload.get("data")
    if data is None:
        raise Exception("The router returned a failure.")
    elif data.get("success") is False:
        error = data.get("error")
        logging.debug(f"gateway returned: {error}")
        print(f"{bcolors.FAIL}Could not get a list of SaaS plugins available on the gateway.{bcolors.ENDC}")
        return None

    return data
