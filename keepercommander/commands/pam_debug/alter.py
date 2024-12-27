from __future__ import annotations
import argparse
import os
from ..discover import PAMGatewayActionDiscoverCommandBase
from ...display import bcolors
from ... import vault
from discovery_common.infrastructure import Infrastructure
from discovery_common.record_link import RecordLink
from discovery_common.types import UserAcl, DiscoveryObject
from keeper_dag import EdgeType
from importlib.metadata import version
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMDebugAlterCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-pam-command-debug')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=False, dest='gateway', action='store',
                        help='Gateway name or UID.')

    def get_parser(self):
        return PAMDebugAlterCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        pass