from __future__ import annotations
import argparse
import json
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
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format (table, json)')

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleListCommand.parser

    @staticmethod
    def _rule_to_dict(rule: RuleItem):
        action_value = None
        if getattr(rule, 'action', None) is not None:
            action_value = rule.action.value
        return {
            'rule_id': rule.rule_id,
            'name': rule.name or '',
            'action': action_value,
            'priority': rule.priority,
            'case_sensitive': bool(rule.case_sensitive),
            'added': rule.added_ts_str if rule.added_ts else '',
            'shared_folder_uid': getattr(rule, 'shared_folder_uid', None) or '',
            'admin_uid': getattr(rule, 'admin_uid', None) or '',
            'rule': Rules.make_action_rule_statement_str(rule.statement),
        }

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
        format_type = kwargs.get('format') or 'table'
        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=configuration_uid)
            if gateway_context is None:
                message = f'Could not find the gateway configuration for {gateway}.'
                if format_type == 'json':
                    print(json.dumps({'message': message}, indent=2))
                else:
                    print(f"{bcolors.FAIL}{message}{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            if format_type == 'json':
                configs = []
                for item in (err.items or []):
                    record = item.get('configuration_record')
                    if record is not None:
                        configs.append({
                            'uid': getattr(record, 'record_uid', ''),
                            'title': getattr(record, 'title', ''),
                        })
                print(json.dumps({
                    'message': f'Found multiple configuration records for gateway {gateway}.',
                    'configurations': configs,
                }, indent=2))
            else:
                multi_conf_msg(gateway, err)
            return

        rules = Rules(record=gateway_context.configuration, params=params)
        rule_list = rules.rule_list(rule_type=RuleTypeEnum.ACTION,
                                    search=kwargs.get("search"))  # type: List[RuleItem]
        if len(rule_list) == 0:
            if format_type == 'json':
                print(json.dumps({'rules': []}, indent=2))
                return
            print("")
            text = f"{bcolors.FAIL}There are no rules. " \
                   f"Use 'pam action discover rule add -g {gateway_context.gateway_uid} "
            if configuration_uid:
                text += f"-c {gateway_context.configuration_uid}' "
            text += f"to create rules.{bcolors.ENDC}"
            print(text)
            return

        if format_type == 'json':
            print(json.dumps({
                'gateway': gateway_context.gateway_name,
                'gateway_uid': gateway_context.gateway_uid,
                'configuration_uid': gateway_context.configuration_uid,
                'rules': [self._rule_to_dict(rule) for rule in rule_list],
            }, indent=2))
            return

        self.print_rule_table(rule_list=rule_list)
