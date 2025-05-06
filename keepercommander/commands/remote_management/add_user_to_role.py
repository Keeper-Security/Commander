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


class GatewayActionRmAddUserToRoleCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 role_id: str,
                 resource_uid: Optional[str] = None,
                 user_uid: Optional[str] = None,
                 user: Optional[str] = None,
                 database: Optional[str] = None):

        self.configurationUid = configuration_uid
        self.resourceUid = resource_uid
        self.userUid = user_uid
        self.user = user
        self.roleId = role_id
        self.database = database

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRmAddUserToRoleCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionRmAddUserToRoleCommandInputs, conversation_id=None):
        super().__init__('rm-add-user-to-role', inputs=inputs, conversation_id=conversation_id,
                         is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class RmAddUserToRoleCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-rm-role-add')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')

    parser.add_argument('--role', required=True, dest='role', action='store', help='Role Name or ID')

    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='Resource UID')
    parser.add_argument('--user-uid', '-u', required=False, dest='user_uid', action='store',
                        help='User UID')
    parser.add_argument('--user', required=False, dest='user', action='store', help='Username')
    parser.add_argument('--database', required=False, dest='database', action='store',
                        help='Override the connect database')

    def get_parser(self):
        return RmAddUserToRoleCommand.parser

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

        if user is not None:
            user = gateway_context.encrypt_str(user)

        action_inputs = GatewayActionRmAddUserToRoleCommandInputs(
            configuration_uid=gateway_context.configuration_uid,
            resource_uid=kwargs.get('resource_uid'),
            user_uid=user_uid,
            user=user,
            role_id=kwargs.get('role'),
            database=kwargs.get('database')
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionRmAddUserToRoleCommand(
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
            print(f"{bcolors.FAIL}Could not add user to role: {error}{bcolors.ENDC}")
            return

        print("")
        print(f"{bcolors.OKGREEN}User added to role.{bcolors.ENDC}")
        print("")
