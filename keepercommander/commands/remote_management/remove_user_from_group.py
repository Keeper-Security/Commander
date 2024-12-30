from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.pam_dto import GatewayAction
from ..pam.router_helper import router_send_action_to_gateway
from ...proto import pam_pb2
from ...display import bcolors
import json
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class GatewayActionRmRemoveUserFromGroupCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 group_id: str,
                 resource_uid: Optional[str] = None,
                 user_uid: Optional[str] = None,
                 user: Optional[str] = None):

        self.configurationUid = configuration_uid
        self.resourceUid = resource_uid
        self.userUid = user_uid
        self.user = user
        self.groupId = group_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRmRemoveUserFromGroupCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionRmRemoveUserFromGroupCommandInputs, conversation_id=None):
        super().__init__('rm-remove-user-from-group', inputs=inputs, conversation_id=conversation_id,
                         is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class RmRemoveUserFromGroupCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-rm-group-remove')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')

    parser.add_argument('--group', required=True, dest='group', action='store', help='Group Name or ID')

    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='Resource UID')
    parser.add_argument('--user-uid', '-u', required=False, dest='user_uid', action='store',
                        help='User UID')
    parser.add_argument('--user', required=False, dest='user', action='store', help='Username')

    def get_parser(self):
        return RmRemoveUserFromGroupCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        action_inputs = GatewayActionRmRemoveUserFromGroupCommandInputs(
            configuration_uid=gateway_context.configuration_uid,
            resource_uid=kwargs.get('resource_uid'),
            user_uid=kwargs.get('user_uid'),
            user=kwargs.get('user'),
            group_id=kwargs.get('group')
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionRmRemoveUserFromGroupCommand(
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
            print(f"{bcolors.FAIL}Could not remove user from group: {error}{bcolors.ENDC}")
            return

        print("")
        print(f"{bcolors.OKGREEN}User removed from group.{bcolors.ENDC}")
        print("")
