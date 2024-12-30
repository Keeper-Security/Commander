from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.pam_dto import GatewayAction
from ..pam.router_helper import router_send_action_to_gateway
from ...proto import pam_pb2
from ...display import bcolors
from ...discovery_common.rm_types import RmScriptResponse
import json
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class GatewayActionRmRunScriptCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 script_content: str,
                 resource_uid: Optional[str] = None,
                 user_uid: Optional[str] = None,
                 dry_run: bool = False):

        self.configurationUid = configuration_uid
        self.scriptContent = script_content
        self.resourceUid = resource_uid
        self.userUid = user_uid
        self.dryRun = dry_run

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRmRunScriptCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionRmRunScriptCommandInputs, conversation_id=None):
        super().__init__('pam-rm-script', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class RmRunScriptCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-rm-script')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')
    parser.add_argument('--script-file', '-f', required=True, dest='script_file', action='store',
                        help='Script File')

    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='Resource UID')
    parser.add_argument('--user-uid', '-u', required=False, dest='user_id', action='store',
                        help='User UID')
    parser.add_argument('--dry-run', required=False, dest='dry_run', action='store_true',
                        help='View the script')

    def get_parser(self):
        return RmRunScriptCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        script_file = kwargs.get('script_file', False)
        script_content = None
        with open(script_file, 'r') as fh:
            script_content = fh.read()
            fh.close()
        if script_content is None or script_content == "":
            print(f"{bcolors.FAIL}The script file is empty.")

        dry_run = kwargs.get('dry_run', False)

        action_inputs = GatewayActionRmRunScriptCommandInputs(
            configuration_uid=gateway_context.configuration_uid,
            script_content=gateway_context.encrypt_str(script_content),
            resource_uid=kwargs.get('resource_uid'),
            user_uid=kwargs.get('user_id'),
            dry_run=dry_run,
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionRmRunScriptCommand(
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
            print(f"{bcolors.FAIL}Could not run the script: {error}{bcolors.ENDC}")
            return

        result_json = gateway_context.decrypt(data.get("data"))
        result = RmScriptResponse.model_validate(result_json)

        print("")
        if dry_run is True:
            print(result.script)
        else:
            print(f"{bcolors.OKGREEN}Script was run successfully.{bcolors.ENDC}")
            print("")
            print(f"{bcolors.HEADER}STDOUT{bcolors.ENDC}")
            print(result.stdout)
        print("")



