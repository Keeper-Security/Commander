from __future__ import annotations
import argparse
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ..pam.router_helper import router_get_connected_gateways
from ...discovery_common.rule import Rules
from ...discovery_common.types import RuleTypeEnum
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...discovery_common.types import RuleItem


class PAMGatewayActionDiscoverRuleListCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-discover-rule-list')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--search', '-s', required=False, dest='search', action='store',
                        help='Search for rules.')

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleListCommand.parser

    @staticmethod
    def print_rule_table(rule_list: List[RuleItem]):

        print("")
        print(f"{bcolors.HEADER}{'Rule ID'.ljust(15, ' ')} "
              f"{'Action'.ljust(6, ' ')} "
              f"{'Priority'.ljust(8, ' ')} "
              f"{'Case'.ljust(12, ' ')} "
              f"{'Added'.ljust(19, ' ')} "
              f"{'Shared Folder UID'.ljust(22, ' ')} "
              "Rule"
              f"{bcolors.ENDC}")

        print(f"{''.ljust(15, '=')} "
              f"{''.ljust(6, '=')} "
              f"{''.ljust(8, '=')} "
              f"{''.ljust(12, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(10, '=')} ")

        for rule in rule_list:
            if rule.case_sensitive is True:
                ignore_case_str = "Sensitive"
            else:
                ignore_case_str = "Insensitive"

            shared_folder_uid = ""
            if rule.shared_folder_uid is not None:
                shared_folder_uid = rule.shared_folder_uid
            print(f"{bcolors.OKGREEN}{rule.rule_id.ljust(14, ' ')}{bcolors.ENDC} "
                  f"{rule.action.value.ljust(6, ' ')} "
                  f"{str(rule.priority).rjust(8, ' ')} "
                  f"{ignore_case_str.ljust(12, ' ')} "
                  f"{rule.added_ts_str.ljust(19, ' ')} "
                  f"{shared_folder_uid.ljust(22, ' ')} "
                  f"{Rules.make_action_rule_statement_str(rule.statement)}")

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        gateway = kwargs.get("gateway")
        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f'{bcolors.FAIL}Discovery job gateway [{gateway}] was not found.{bcolors.ENDC}')
            return

        rules = Rules(record=gateway_context.configuration, params=params)
        rule_list = rules.rule_list(rule_type=RuleTypeEnum.ACTION,
                                    search=kwargs.get("search"))  # type: List[RuleItem]
        if len(rule_list) == 0:
            print(f"{bcolors.FAIL}There are no rules. Use 'pam action discovery rule add' "
                  f"to create rules.{bcolors.ENDC}")
            return

        self.print_rule_table(rule_list=rule_list)
