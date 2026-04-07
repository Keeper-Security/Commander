from __future__ import annotations
import argparse
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from .rule_add import PAMGatewayActionDiscoverRuleAddCommand
from ..pam.router_helper import router_get_connected_gateways
from ...display import bcolors
from ...discovery_common.rule import Rules, RuleActionEnum, RuleTypeEnum


class PAMGatewayActionDiscoverRuleUpdateCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action discover rule update')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    parser.add_argument('--rule-id', '-i', required=True, dest='rule_id', action='store',
                        help='Identifier for the rule')
    parser.add_argument('--action', '-a', required=False, choices=['add', 'ignore', 'prompt'],
                        dest='rule_action', action='store', help='Update the action to take if rule matches')
    parser.add_argument('--priority', '-p', required=False, dest='priority', action='store', type=int,
                        help='Update the rule execute priority')
    parser.add_argument('--name', '-n', required=False, dest='name', action='store', type=str,
                        help='Rule name')
    parser.add_argument('--ignore-case', required=False, dest='ignore_case', action='store_true',
                        help='Update the rule to ignore case')
    parser.add_argument('--no-ignore-case', required=False, dest='ignore_case', action='store_false',
                        help='Update the rule to not ignore case')
    parser.add_argument('--shared-folder-uid', required=False, dest='shared_folder_uid',
                        action='store', help='Update the folder to place record.')
    parser.add_argument('--admin-uid', required=False, dest='admin_uid',
                        action='store', help='Admin record UID to use for resource.')
    parser.add_argument('--clear-shared-folder-uid', required=False, dest='clear_shared_folder_uid',
                        action='store_true', help='Clear shared folder UID, use default.')
    parser.add_argument('--clear-admin-uid', required=False, dest='clear_admin_uid',
                        action='store_true', help='Clear admin UID')
    parser.add_argument('--statement', '-s', required=False, dest='statement', action='store',
                        help='Update the rule statement')
    parser.add_argument('--active', required=False, dest='active', action='store_true',
                        help='Enable rule.')
    parser.add_argument('--disable', required=False, dest='active', action='store_false',
                        help='Disable rule.')
    parser.set_defaults(active=None, ignore_case=None)

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleUpdateCommand.parser

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        gateway = kwargs.get("gateway")
        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=kwargs.get('configuration_uid'))
            if gateway_context is None:
                print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            multi_conf_msg(gateway, err)
            return

        try:
            rule_id = kwargs.get("rule_id")
            rules = Rules(record=gateway_context.configuration, params=params)
            rule_item = rules.get_rule_item(rule_type=RuleTypeEnum.ACTION, rule_id=rule_id)
            if rule_item is None:
                raise ValueError("Rule Id does not exist.")

            rule_action = kwargs.get("rule_action")
            if rule_action is not None:
                action = RuleActionEnum.find_enum(rule_action)
                if action is None:
                    raise ValueError(f"The action does not look correct: {rule_action}")
                rule_item.action = action

            priority = kwargs.get("priority")
            if priority is not None:
                print("  * Changing the priority of the rule.")
                rule_item.priority = priority

            ignore_case = kwargs.get("ignore_case")
            if ignore_case is not None:
                if ignore_case:
                    print("  * Ignore the case of text.")
                else:
                    print("  * Make rule text case sensitive.")

                rule_item.case_sensitive = not ignore_case

            if kwargs.get("clear_shared_folder_uid"):
                print("  * Clearing shared folder.")
                rule_item.shared_folder_uid = None
            else:
                shared_folder_uid = kwargs.get("shared_folder_uid")
                if shared_folder_uid is not None:
                    if len(shared_folder_uid) != 22:
                        print(f"{bcolors.FAIL}The shared folder UID {shared_folder_uid} is not the correct length."
                              f"{bcolors.ENDC}")
                    print("  * Changing shared folder UID.")
                    rule_item.shared_folder_uid = shared_folder_uid

            if kwargs.get("clear_admin_uid"):
                print("  * Clearing resource admin UID.")
                rule_item.admin_uid = None
            else:
                admin_uid = kwargs.get("admin_uid")
                if admin_uid is not None:
                    if len(admin_uid) != 22:
                        print(f"{bcolors.FAIL}The admin UID {admin_uid} is not the correct length."
                              f"{bcolors.ENDC}")
                        return
                    print("  * Changing the resource admin UID.")
                    rule_item.admin_uid = admin_uid

            statement = kwargs.get("statement")
            if statement is not None:
                # validate_rule_statement will throw exceptions.
                statement_struct = PAMGatewayActionDiscoverRuleAddCommand.validate_rule_statement(
                    params=params,
                    gateway_context=gateway_context,
                    statement=statement
                )

                print("  * Changing the rule statement.")

            name = kwargs.get("name")
            if name is not None:
                print("  * Changing the rule name.")
                rule_item.name = name

            enabled = kwargs.get("active")
            if enabled is not None:
                if enabled:
                    print("  * Enabling the rule.")
                else:
                    print("  * Disabling the rule.")
                rule_item.enabled = enabled

            rules.update_rule(rule_item)
            print(f"{bcolors.OKGREEN}Rule has been updated{bcolors.ENDC}")
        except Exception as err:
            print(f"{bcolors.FAIL}Rule was not updated: {err}{bcolors.ENDC}")
