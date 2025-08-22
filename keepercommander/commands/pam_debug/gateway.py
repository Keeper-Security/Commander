from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from .graph import PAMDebugGraphCommand
from ...display import bcolors
from ...discovery_common.infrastructure import Infrastructure
from ...discovery_common.record_link import RecordLink
from ...discovery_common.user_service import UserService
from ...discovery_common.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class PAMDebugGatewayCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-debug-gateway')

    type_name_map = {
        PAM_USER: "PAM User",
        PAM_MACHINE: "PAM Machine",
        PAM_DATABASE: "PAM Database",
        PAM_DIRECTORY: "PAM Directory",
    }

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')

    def get_parser(self):
        return PAMDebugGatewayCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        debug_level = kwargs.get("debug_level", False)

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        infra = Infrastructure(record=gateway_context.configuration, params=params, fail_on_corrupt=False)
        infra.load()

        record_link = RecordLink(record=gateway_context.configuration, params=params, fail_on_corrupt=False)
        user_service = UserService(record=gateway_context.configuration, params=params, fail_on_corrupt=False)

        if gateway_context is None:
            print(f"  {self._f('Cannot get gateway information. Gateway may not be up.')}")
            return

        print("")
        print(self._h("Gateway Information"))
        print(f"  {self._b('Gateway UID')}: {gateway_context.gateway_uid}")
        print(f"  {self._b('Gateway Name')}: {gateway_context.gateway_name}")
        if gateway_context.configuration is not None:
            print(f"  {self._b('Configuration UID')}: {gateway_context.configuration_uid}")
            print(f"  {self._b('Configuration Title')}: {gateway_context.configuration.title}")
            print(f"  {self._b('Configuration Key Bytes Hex')}: {gateway_context.configuration.record_key.hex()}")
        else:
            print(f"  {self._f('The gateway appears to not have a configuration.')}")
        print("")

        graph = PAMDebugGraphCommand()

        if infra.dag.has_graph is True:
            print(self._h("Infrastructure Graph"))
            graph.do_list(params=params, gateway_context=gateway_context, graph_type="infra", debug_level=debug_level,
                          indent=1)
        else:
            print(f"{self._f('The gateway configuration does not have a infrastructure graph.')}")

        print("")

        if record_link.dag.has_graph is True:
            print(self._h("Record Linking Graph"))
            graph.do_list(params=params, gateway_context=gateway_context, graph_type="rl", debug_level=debug_level,
                          indent=1)
        else:
            print(f"{self._f('The gateway configuration does not have a record linking graph.')}")

        print("")

        if user_service.dag.has_graph is True:
            print(self._h("User to Service/Task Graph"))
            graph.do_list(params=params, gateway_context=gateway_context, graph_type="service", debug_level=debug_level,
                          indent=1)
        else:
            print(f"{self._f('The gateway configuration does not have a user to service/task graph.')}")

        print("")
