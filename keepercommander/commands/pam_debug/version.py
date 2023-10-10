from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase
from ...display import bcolors
from importlib.metadata import version
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class PAMDebugVersionCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-pam-command-debug')

    def execute(self, params: KeeperParams, **kwargs):

        print("")
        print(f"{bcolors.BOLD}keeper-dag version:{bcolors.ENDC} {version('keeper-dag')}")
        print(f"{bcolors.BOLD}discovery-common version:{bcolors.ENDC} {version('discovery-common')}")
        print("")