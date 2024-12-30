from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...discovery_common.rm_types import RmResponse
from ..pam.pam_dto import GatewayAction
from ..pam.router_helper import router_send_action_to_gateway
from ...proto import pam_pb2
from ...display import bcolors
import json
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class GatewayActionRmDeleteUserCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 user: str,
                 resource_uid: Optional[str] = None,
                 user_uid: Optional[str] = None):

        self.configurationUid = configuration_uid
        self.user = user
        self.resourceUid = resource_uid
        self.userUid = user_uid

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRmDeleteUserCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionRmDeleteUserCommandInputs, conversation_id=None):
        super().__init__('rm-delete-user', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class RmDeleteUserCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-rm-user-delete')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')

    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='Resource UID')
    parser.add_argument('--user-uid', '-u', required=False, dest='user_id', action='store',
                        help='User UID')
    parser.add_argument('--user', required=False, dest='user', action='store', help='User Name')

    def get_parser(self):
        return RmDeleteUserCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        user = kwargs.get('user')
        user_uid = kwargs.get('user_uid')

        if user is None and user_uid is None:
            print(f"{bcolors.FAIL}Either the --user or --user-uid is required.{bcolors.ENDC}")
            return

        if user_uid is not None:
            user = None

        action_inputs = GatewayActionRmDeleteUserCommandInputs(
            configuration_uid=gateway_context.configuration_uid,
            resource_uid=kwargs.get('resource_uid'),
            user_uid=user_uid,
            user=user
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionRmDeleteUserCommand(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_context.gateway_uid
        )
        data = self.get_response_data(router_response)
        if data is None:
            raise Exception("The router returned a failure.")
        elif data.get("success") is False:
            error = data.get("error")
            print(f"{bcolors.FAIL}Could not delete user: {error}{bcolors.ENDC}")
            return

        print("")

        res_json = gateway_context.decrypt(data.get("data"))
        res = RmResponse.model_validate(res_json)

        print(f"{bcolors.OKGREEN}User deleted successfully{bcolors.ENDC}")
        print("")
        if len(res.notes) > 0:
            print(f"{bcolors.HEADER}Notes{bcolors.ENDC}")
            for note in res.notes:
                print(f"{bcolors.BOLD}*{bcolors.ENDC} {note}")

        print("")
