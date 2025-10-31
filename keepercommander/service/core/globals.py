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
from ...params import KeeperParams
from ... import utils

_current_params: Optional[KeeperParams] = None

def init_globals(params: KeeperParams) -> None:
    global _current_params
    _current_params = params

def get_current_params() -> Optional[KeeperParams]:
    return _current_params

def ensure_params_loaded() -> KeeperParams:
    """Load params from config if not already loaded."""
    params = get_current_params()
    if not params: 
        from ...__main__ import get_params_from_config
        config_path = utils.get_default_path() / "config.json"
        params = get_params_from_config(str(config_path))
        init_globals(params)
    return params