from __future__ import annotations
import argparse
import logging
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from ...display import bcolors
from ... import vault
from ...discovery_common.record_link import RecordLink
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMDebugLinkCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-debug-link')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')
    parser.add_argument('--resource-uid', '-r', required=True, dest='resource_uid', action='store',
                        help='Resource record UID.')
    parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                        help='GraphSync debug level. Default is 0', type=int, default=0)

    def get_parser(self):
        return PAMDebugLinkCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        resource_uid = kwargs.get("resource_uid")
        debug_level = int(kwargs.get("debug_level", 0))

        print("")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        record_link = RecordLink(record=gateway_context.configuration,
                                 params=params,
                                 logger=logging,
                                 debug_level=debug_level)

        resource_record = vault.KeeperRecord.load(params, resource_uid)  # type: Optional[TypedRecord]
        if resource_record is None:
            print(f"{bcolors.FAIL}The parent record does not exists.{bcolors.ENDC}")
            return

        if resource_record.record_type not in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
            print(f"{bcolors.FAIL}The resource record type, {resource_record.record_type} "
                  f"is not allowed.{bcolors.ENDC}")
            return

        try:
            record_link.belongs_to(resource_uid, gateway_context.configuration_uid, )
            record_link.save()
            print(f"{bcolors.OKGREEN}Added link between '{resource_uid}' and "
                  f"{gateway_context.configuration_uid}{bcolors.ENDC}")
        except Exception as err:
            print(f"{bcolors.FAIL}Could not add LINK: {err}{bcolors.ENDC}")
            raise err
