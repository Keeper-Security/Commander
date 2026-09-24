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

from typing import Dict, Optional
from ...params import KeeperParams
from ... import utils

_current_params: Optional[KeeperParams] = None
_pending_vault_metadata: Optional[Dict[str, str]] = None

def init_globals(params: KeeperParams) -> None:
    global _current_params
    _current_params = params

def get_current_params() -> Optional[KeeperParams]:
    return _current_params

def set_pending_vault_metadata(record_uid: str, api_key: str) -> None:
    """
    Stash a Docker-config record UID + API key for a one-time vault metadata
    write, to be consumed by ServiceManager.start_service() once the real
    service URL is known. Transient (in-memory, same-process only) -- never
    persisted to the saved service config, since it only needs to survive
    from the current service-create invocation through to the immediately
    following start_service() call, not across restarts.
    """
    global _pending_vault_metadata
    _pending_vault_metadata = {'record_uid': record_uid, 'api_key': api_key}

def pop_pending_vault_metadata() -> Optional[Dict[str, str]]:
    """Return and clear the pending vault metadata update, if any."""
    global _pending_vault_metadata
    value = _pending_vault_metadata
    _pending_vault_metadata = None
    return value

def ensure_params_loaded() -> KeeperParams:
    """Load params from config if not already loaded."""
    params = get_current_params()
    if not params: 
        from ...__main__ import get_params_from_config
        config_path = utils.get_default_path() / "config.json"
        params = get_params_from_config(str(config_path))
        init_globals(params)
    return params