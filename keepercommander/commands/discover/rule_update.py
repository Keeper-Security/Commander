from __future__ import annotations
import argparse
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from .rule_add import PAMGatewayActionDiscoverRuleAddCommand
from ..pam.router_helper import router_get_connected_gateways
from ...display import bcolors
from ...discovery_common.rule import Rules, RuleTypeEnum


class PAMGatewayActionDiscoverRuleUpdateCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-discover-rule-update')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--rule-id', '-i', required=True, dest='rule_id', action='store',
                        help='Identifier for the rule')
    parser.add_argument('--action', '-a', required=False, choices=['add', 'ignore', 'prompt'],
                        dest='rule_action', action='store', help='Update the action to take if rule matches')
    parser.add_argument('--priority', '-p', required=False, dest='priority', action='store', type=int,
                        help='Update the rule execute priority')
    parser.add_argument('--ignore-case', required=False, dest='ignore_case', action='store_true',
                        help='Update the rule to ignore case')
    parser.add_argument('--no-ignore-case', required=False, dest='ignore_case', action='store_false',
                        help='Update the rule to not ignore case')
    parser.add_argument('--shared-folder-uid', required=False, dest='shared_folder_uid',
                        action='store', help='Update the folder to place record.')
    parser.add_argument('--statement', '-s', required=False, dest='statement', action='store',
                        help='Update the rule statement')

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleUpdateCommand.parser

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        gateway = kwargs.get("gateway")
        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f'{bcolors.FAIL}Discovery job gateway [{gateway}] was not found.{bcolors.ENDC}')
            return

        try:
            rule_id = kwargs.get("rule_id")
            rules = Rules(record=gateway_context.configuration, params=params)
            rule_item = rules.get_rule_item(rule_type=RuleTypeEnum.ACTION, rule_id=rule_id)
            if rule_item is None:
                raise ValueError("Rule Id does not exist.")

            rule_action = kwargs.get("rule_action")
            if rule_action is not None:
                rule_item.action = RuleTypeEnum.find_enum(rule_action)
            priority = kwargs.get("priority")
            if priority is not None:
                rule_item.priority = priority
            ignore_case = kwargs.get("ignore_case")
            if ignore_case is not None:
                rule_item.case_sensitive = not ignore_case
            shared_folder_uid = kwargs.get("shared_folder_uid")
            if shared_folder_uid is not None:
                rule_item.shared_folder_uid = shared_folder_uid
            statement = kwargs.get("statement")
            if statement is not None:
                rule_item.statement = PAMGatewayActionDiscoverRuleAddCommand.validate_rule_statement(
                    params=params,
                    gateway_context=gateway_context,
                    statement=statement
                )
            rules.update_rule(rule_item)
            print(f"{bcolors.OKGREEN}Rule has been updated{bcolors.ENDC}")
        except Exception as err:
            print(f"{bcolors.FAIL}Rule was not updated: {err}{bcolors.ENDC}")
