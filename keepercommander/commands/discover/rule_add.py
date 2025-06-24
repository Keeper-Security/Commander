from __future__ import annotations
import argparse
import logging
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.pam_dto import GatewayActionDiscoverRuleValidateInputs, GatewayActionDiscoverRuleValidate, GatewayAction
from ..pam.router_helper import router_send_action_to_gateway, router_get_connected_gateways
from ...display import bcolors
from ...proto import pam_pb2
from ...discovery_common.rule import Rules
from ...discovery_common.types import ActionRuleItem
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class PAMGatewayActionDiscoverRuleAddCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-discover-rule-add')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--action', '-a', required=True, choices=['add', 'ignore', 'prompt'],
                        dest='rule_action', action='store', help='Action to take if rule matches')
    parser.add_argument('--priority', '-p', required=True, dest='priority', action='store', type=int,
                        help='Rule execute priority')
    parser.add_argument('--ignore-case', required=False, dest='ignore_case', action='store_true',
                        help='Ignore value case. Rule value must be in lowercase.')
    parser.add_argument('--shared-folder-uid', required=False, dest='shared_folder_uid',
                        action='store', help='Folder to place record.')
    parser.add_argument('--statement', '-s', required=True, dest='statement', action='store',
                        help='Rule statement')

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleAddCommand.parser

    @staticmethod
    def validate_rule_statement(params: KeeperParams, gateway_context: GatewayContext, statement: str):

        # Send rule the gateway to be validated. The rule is encrypted. It might contain sensitive information.
        action_inputs = GatewayActionDiscoverRuleValidateInputs(
            configuration_uid=gateway_context.configuration_uid,
            statement=gateway_context.encrypt_str(statement)
        )
        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionDiscoverRuleValidate(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_DISCOVERY,
            is_streaming=False,
            destination_gateway_uid_str=gateway_context.gateway_uid
        )

        data = PAMGatewayActionDiscoverCommandBase.get_response_data(router_response)

        if data is None:
            raise Exception("The router returned a failure.")
        elif data.get("success") is False:
            error = data.get("error")
            raise Exception(f"The rule does not appear valid: {error}")

        statement_struct = data.get("statementStruct")
        logging.debug(f"Rule Structure = {statement_struct}")
        if isinstance(statement_struct, list) is False:
            raise Exception(f"The structured rule statement is not a list.")

        return statement_struct

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        try:
            gateway = kwargs.get("gateway")
            gateway_context = GatewayContext.from_gateway(params, gateway)
            if gateway_context is None:
                print(f'{bcolors.FAIL}Discovery job gateway [{gateway}] was not found.{bcolors.ENDC}')
                return

            # If we are setting the shared_folder_uid, make sure it exists.
            shared_folder_uid = kwargs.get("shared_folder_uid")
            if shared_folder_uid is not None:
                shared_folder_uids = gateway_context.get_shared_folders(params)
                exists = next((x for x in shared_folder_uids if x["uid"] == shared_folder_uid), None)
                if exists is None:
                    print(f"{bcolors.FAIL}The shared folder UID {shared_folder_uid} is not part of this "
                          f"application/gateway. Valid shared folder UID are:{bcolors.ENDC}")
                    for item in shared_folder_uids:
                        print(f"* {item['uid']} - {item['name']}")
                    return

            statement = kwargs.get("statement")
            statement_struct = self.validate_rule_statement(
                params=params,
                gateway_context=gateway_context,
                statement=statement
            )

            # If the rule passes its validation, then add control DAG
            rules = Rules(record=gateway_context.configuration, params=params)
            new_rule = ActionRuleItem(
                action=kwargs.get("rule_action"),
                priority=kwargs.get("priority"),
                case_sensitive=not kwargs.get("ignore_case", False),
                shared_folder_uid=kwargs.get("shared_folder_uid"),
                statement=statement_struct,
                enabled=True
            )
            rules.add_rule(new_rule)

            print(f"{bcolors.OKGREEN}Rule has been added{bcolors.ENDC}")
        except Exception as err:
            print(f"{bcolors.FAIL}Rule was not added: {err}{bcolors.ENDC}")
