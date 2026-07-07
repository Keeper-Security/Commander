#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)



from typing import Any, Dict, Optional

from .master_policy_mapper import MasterPolicyMapper
from .policy_rules import PLATFORM_MONITOR_KEYS, PLATFORM_RECORD_KEYS, flatten_asmx_grid, truthy


class SessionRecordingResolver:
    """Resolves CyberArk session-recording flags for master policy config.

    Consolidates logic previously duplicated in the import orchestrator with
    private AccountMapper / MasterPolicyMapper method calls.
    """

    @staticmethod
    def resolve_from_monitoring_data(session_data: Optional[dict]) -> Optional[bool]:
        """Return True/False when recording can be determined, else None."""
        if not session_data:
            return None
        rules: Dict[str, Any] = {}
        rules.update(MasterPolicyMapper.normalize(session_data))
        rules.update(flatten_asmx_grid(session_data))
        for key in PLATFORM_RECORD_KEYS:
            if key in rules:
                return truthy(rules[key])
        for key in PLATFORM_MONITOR_KEYS:
            if key in rules and truthy(rules[key]):
                return True
        return None

    @classmethod
    def apply_to_master_config(cls, master_config: dict,
                               session_data: Optional[dict]) -> dict:
        """Merge session-recording flags into a master policy config dict."""
        config = dict(master_config)
        flag = cls.resolve_from_monitoring_data(session_data)
        if flag is True:
            config["graphical_session_recording"] = "on"
            config["text_session_recording"] = "on"
        elif flag is False:
            config.setdefault("graphical_session_recording", "off")
            config.setdefault("text_session_recording", "off")
        return config
