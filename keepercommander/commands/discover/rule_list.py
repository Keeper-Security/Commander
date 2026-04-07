from __future__ import annotations
import argparse
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ..pam.router_helper import router_get_connected_gateways
from ...discovery_common.rule import Rules
from ...discovery_common.types import RuleTypeEnum
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...discovery_common.types import RuleItem


class PAMGatewayActionDiscoverRuleListCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action discover rule list')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    parser.add_argument('--search', '-s', required=False, dest='search', action='store',
                        help='Search for rules.')

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleListCommand.parser

    @staticmethod
    def print_rule_table(rule_list: List[RuleItem]):

        print("")
        print(f"{bcolors.HEADER}{'Rule ID'.ljust(15, ' ')} "
              f"{'Name'.ljust(20, ' ')} "
              f"{'Action'.ljust(6, ' ')} "
              f"{'Priority'.ljust(8, ' ')} "
              f"{'Case'.ljust(12, ' ')} "
              f"{'Added'.ljust(19, ' ')} "
              f"{'Shared Folder UID'.ljust(22, ' ')} "
              f"{'Admin UID'.ljust(22, ' ')} "
              "Rule"
              f"{bcolors.ENDC}")

        print(f"{''.ljust(15, '=')} "
              f"{''.ljust(20, '=')} "
              f"{''.ljust(6, '=')} "
              f"{''.ljust(8, '=')} "
              f"{''.ljust(12, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(10, '=')} ")

        for rule in rule_list:
            if rule.case_sensitive:
                ignore_case_str = "Sensitive"
            else:
                ignore_case_str = "Insensitive"

            shared_folder_uid = ""
            if rule.shared_folder_uid is not None:
                shared_folder_uid = rule.shared_folder_uid

            admin_uid = ""
            if rule.admin_uid is not None:
                admin_uid = rule.admin_uid

            name = ""
            if rule.name is not None:
                name = rule.name

            color = bcolors.FAIL
            action_value = f"NONE"
            if rule.action is not None:
                color = ""
                action_value = rule.action.value

            print(f"{bcolors.OKGREEN}{rule.rule_id.ljust(14, ' ')}{bcolors.ENDC} "
                  f"{name[:20].ljust(20, ' ')} "
                  f"{color}{action_value.ljust(6, ' ')}{bcolors.ENDC} "
                  f"{str(rule.priority).rjust(8, ' ')} "
                  f"{ignore_case_str.ljust(12, ' ')} "
                  f"{rule.added_ts_str.ljust(19, ' ')} "
                  f"{shared_folder_uid.ljust(22, ' ')} "
                  f"{admin_uid.ljust(22, ' ')} "
                  f"{Rules.make_action_rule_statement_str(rule.statement)}")

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        gateway = kwargs.get("gateway")
        configuration_uid = kwargs.get('configuration_uid')
        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=configuration_uid)
            if gateway_context is None:
                print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            multi_conf_msg(gateway, err)
            return

        rules = Rules(record=gateway_context.configuration, params=params)
        rule_list = rules.rule_list(rule_type=RuleTypeEnum.ACTION,
                                    search=kwargs.get("search"))  # type: List[RuleItem]
        if len(rule_list) == 0:
            print("")
            text = f"{bcolors.FAIL}There are no rules. " \
                   f"Use 'pam action discover rule add -g {gateway_context.gateway_uid} "
            if configuration_uid:
                text += f"-c {gateway_context.configuration_uid}' "
            text += f"to create rules.{bcolors.ENDC}"
            print(text)
            return

        self.print_rule_table(rule_list=rule_list)
