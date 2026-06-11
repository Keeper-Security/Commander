import argparse
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ..pam.router_helper import router_get_connected_gateways
from ...display import bcolors
from ...discovery_common.rule import Rules
from ...discovery_common.types import RuleTypeEnum


class PAMGatewayActionDiscoverRuleRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action discover rule remove')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    parser.add_argument('--rule-id', '-i', required=False, dest='rule_id', action='store',
                        help='Identifier for the rule')
    parser.add_argument('--remove-all', required=False, dest='remove_all', action='store_true',
                        help='Remove all the rules.')

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleRemoveCommand.parser

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

        rule_id = kwargs.get("rule_id")
        remove_all = kwargs.get("remove_all")

        if rule_id is None and remove_all is None:
            print(f'{bcolors.FAIL}Either --rule-id or --remove-all are required.{bcolors.ENDC}')
            return

        try:
            rules = Rules(record=gateway_context.configuration, params=params)
            if remove_all:
                rules.remove_all(RuleTypeEnum.ACTION)
                print(f"{bcolors.OKGREEN}All rules removed.{bcolors.ENDC}")
            else:

                rule_item = rules.get_rule_item(rule_type=RuleTypeEnum.ACTION, rule_id=rule_id)
                if rule_item is None:
                    raise ValueError("Rule Id does not exist.")
                rules.remove_rule(rule_item)

                print(f"{bcolors.OKGREEN}Rule has been removed.{bcolors.ENDC}")
        except Exception as err:
            if remove_all:
                print(f"{bcolors.FAIL}Rules have NOT been removed: {err}{bcolors.ENDC}")
            else:
                print(f"{bcolors.FAIL}Rule was not removed: {err}{bcolors.ENDC}")
