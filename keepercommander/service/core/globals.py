#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from typing import Optional
from keepercommander.params import KeeperParams

_current_params: Optional[KeeperParams] = None

def init_globals(params: KeeperParams) -> None:
    global _current_params
    _current_params = params

def get_current_params() -> Optional[KeeperParams]:
    return _current_params