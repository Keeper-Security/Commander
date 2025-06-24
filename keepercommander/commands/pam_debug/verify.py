from __future__ import annotations
from . import get_connection
import logging
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ...vault import TypedRecord
from ...discovery_common.verify import Verify
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import KeeperRecord


class PAMDebugVerifyCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-debug-verify')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')
    parser.add_argument('--fix', required=False, dest='fix', action='store_true',
                        help='Fix all problems.')
    parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                        help='GraphSync debug level. Default is 0', type=int, default=0)

    def get_parser(self):
        return PAMDebugVerifyCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        fix = kwargs.get("fix", False)
        debug_level = kwargs.get("debug_level", False)

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        def _record_lookup(record_uid: str) -> KeeperRecord:
            return TypedRecord.load(params, record_uid)

        colors = {
            Verify.OK: bcolors.OKGREEN,
            Verify.FAIL: bcolors.FAIL,
            Verify.UNK: bcolors.OKBLUE,
            Verify.TITLE: bcolors.BOLD,
            Verify.COLOR_RESET: bcolors.ENDC
        }

        verify = Verify(record=gateway_context.configuration, logger=logging, debug_level=debug_level,
                        output=sys.stdout, params=params, colors=colors)
        verify.run(fix=fix,
                   lookup_record_func=_record_lookup)
