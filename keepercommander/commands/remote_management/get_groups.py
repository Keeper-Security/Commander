from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.pam_dto import GatewayAction
from ..pam.router_helper import router_send_action_to_gateway
from ...discovery_common.rm_types import RmGroup
from ...proto import pam_pb2
from ...display import bcolors
import json
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class GatewayActionRmGetGroupsCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 include_users: bool = True,
                 resource_uid: Optional[str] = None,
                 user_uid: Optional[str] = None,
                 database: Optional[str] = None,
                 include_groups: Optional[List[str]] = None,
                 exclude_groups: Optional[List[str]] = None):

        self.configurationUid = configuration_uid
        self.resourceUid = resource_uid
        self.userUid = user_uid
        self.database = database
        self.includeGroups = include_groups,
        self.excludeGroups = exclude_groups,
        self.includeUsers = include_users

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRmGetGroupsCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionRmGetGroupsCommandInputs, conversation_id=None):
        super().__init__('rm-group-list', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class RmGetGroupsCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-rm-group-list')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')

    parser.add_argument('--user', '-u', required=False, dest='user', action='store',
                        help='User Name')

    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='Resource UID')
    parser.add_argument('--user-uid', '-i', required=False, dest='user_id', action='store',
                        help='User UID')
    parser.add_argument('--exclude-users', required=False, dest='exclude_users',
                        action='store_true', help='Exclude users attached to role.')
    parser.add_argument('--database', required=False, dest='database', action='store',
                        help='Override the connect database')

    def get_parser(self):
        return RmGetGroupsCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        exclude_users = kwargs.get("exclude_users", False)

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        action_inputs = GatewayActionRmGetGroupsCommandInputs(
            configuration_uid=gateway_context.configuration_uid,
            resource_uid=kwargs.get('resource_uid'),
            user_uid=kwargs.get('user_id'),
            include_users=not exclude_users,
            database=kwargs.get("database")
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionRmGetGroupsCommand(
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
            print(f"{bcolors.FAIL}Could not get Groups: {error}{bcolors.ENDC}")
            return

        group_list = gateway_context.decrypt(data.get("data"))

        print("")
        print(f"{bcolors.HEADER}Groups{bcolors.ENDC}")

        for group in group_list:
            g = RmGroup.model_validate(group)
            print(f"{bcolors.BOLD}  * {bcolors.ENDC}{bcolors.OKBLUE}{g.name}{bcolors.ENDC} ({g.id})")
            if exclude_users is not True:
                for user in g.users:
                    print(f"{bcolors.OKGREEN}    + {bcolors.ENDC}{user.name}")
        print("")
