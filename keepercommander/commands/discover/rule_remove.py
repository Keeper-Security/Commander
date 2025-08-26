import argparse
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.router_helper import router_get_connected_gateways
from ...display import bcolors
from ...discovery_common.rule import Rules
from ...discovery_common.types import RuleTypeEnum


class PAMGatewayActionDiscoverRuleRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-discover-rule-remove')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID')
    parser.add_argument('--rule-id', '-i', required=True, dest='rule_id', action='store',
                        help='Identifier for the rule')

    def get_parser(self):
        return PAMGatewayActionDiscoverRuleRemoveCommand.parser

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
            rules.remove_rule(rule_item)

            print(f"{bcolors.OKGREEN}Rule has been removed.{bcolors.ENDC}")
        except Exception as err:
            print(f"{bcolors.FAIL}Rule was not removed: {err}{bcolors.ENDC}")
