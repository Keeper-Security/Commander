from __future__ import annotations
import logging
import argparse
from ..pam.pam_dto import GatewayAction
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ..pam.router_helper import router_send_action_to_gateway
from ..pam.router_helper import get_response_payload
from ...proto import pam_pb2
from .list import PAMActionServiceListCommand
import json
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class GatewayActionUserServiceMapCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 languages: Optional[List[str]] = None,
                 ):

        if languages is None:
            languages = ["en_US"]

        self.configurationUid = configuration_uid
        self.languages = languages

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionUserServiceMapCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionUserServiceMapCommandInputs, conversation_id=None):
        super().__init__('user-service-map', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

class PAMActionUserServiceMapCommand(PAMGatewayActionDiscoverCommandBase):

    parser = argparse.ArgumentParser(prog='pam action saas config')

    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')
    parser.add_argument('--by-machine', '-m', required=False, dest='do_by_machine', action='store_true',
                        help='List by machine')

    def get_parser(self):
        return PAMActionUserServiceMapCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        print("")

        gateway = kwargs.get("gateway")  # type: str
        configuration_uid = kwargs.get('configuration_uid')  # type Optional[str]

        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=configuration_uid)
            if gateway_context is None:
                print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.{bcolors.ENDC}")
                return

            if not gateway_context.gateway_version_gte(params, "1.8.5"):
                print(f"{bcolors.FAIL}Cannot run this command. "
                      f"Gateway required to be version 1.8.5 or greater.{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            multi_conf_msg(gateway, err)

        action_inputs = GatewayActionUserServiceMapCommandInputs(
            configuration_uid=gateway_context.configuration_uid,
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionUserServiceMapCommand(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_context.gateway_uid
        )

        if router_response is None:
            print(f"{bcolors.FAIL}Did not get router response.{bcolors.ENDC}")
            return

        response = router_response.get("response")
        logging.debug(f"Router Response: {response}")
        payload = get_response_payload(router_response)
        data = payload.get("data")
        if data is None:
            print(f"{bcolors.FAIL}The router returned a failure.{bcolors.ENDC}")
            return
        elif data.get("success") is False:
            error = data.get("error")
            logging.debug(f"gateway returned: {error}")
            print(f"{bcolors.FAIL}Could not map users to Windows services.{bcolors.ENDC}")
        else:

            print(f"{bcolors.OKGREEN}Finished mapping users to Windows services.{bcolors.ENDC}")

            list_command = PAMActionServiceListCommand()
            list_command.execute(params=params,
                                 gateway=gateway,
                                 configuration_uid=configuration_uid,
                                 do_by_machine=kwargs.get("do_by_machine", False))
