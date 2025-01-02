from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

from ..discover import PAMGatewayActionDiscoverCommandBase

if TYPE_CHECKING:
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