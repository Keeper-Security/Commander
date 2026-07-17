#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)



from typing import Any, Dict, Tuple

# Session-recording field aliases across CyberArk API shapes.
PLATFORM_RECORD_KEYS: Tuple[str, ...] = (
    "recordAndSaveSessionActivity", "RecordAndSaveSessionActivity",
    "RecordActivity", "recordActivity", "RecordSession",
)
PLATFORM_MONITOR_KEYS: Tuple[str, ...] = (
    "requirePrivilegedSessionMonitoringAndIsolation",
    "RequirePrivilegedSessionMonitoringAndIsolation",
    "RequireMonitoringAndIsolation", "requireMonitoringAndIsolation",
    "MonitorSession",
)
PLATFORM_DUAL_CONTROL_KEYS: Tuple[str, ...] = (
    "requireDualControlPasswordAccessApproval", "RequireDualControlPasswordAccessApproval",
    "DualControl", "dualControl", "RequireDualControl",
)
PLATFORM_EXCLUSIVE_KEYS: Tuple[str, ...] = (
    "enforceCheckinCheckoutExclusiveAccess",
    "EnforceCheckinCheckoutExclusiveAccess",
    "EnforceExclusiveAccess", "enforceExclusiveAccess",
)
PLATFORM_ONETIME_KEYS: Tuple[str, ...] = (
    "enforceOnetimePasswordAccess", "EnforceOnetimePasswordAccess",
    "EnforceOneTimePassword", "enforceOneTimePassword",
)


def truthy(val) -> bool:
    """Coerce CyberArk boolean-ish values (true/false/Yes/No/1/0) to bool."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in ("true", "yes", "y", "1", "on", "active")
    return False


def flatten_asmx_grid(data: dict) -> Dict[str, Any]:
    """Flatten PoliciesMgt.asmx ExtJS-grid ``{data: [{name, value}, ...]}`` shape."""
    out: Dict[str, Any] = {}
    if not isinstance(data, dict):
        return out
    envelope = data.get("d", data)
    if not isinstance(envelope, dict):
        envelope = data
    rows = (envelope.get("data") or envelope.get("Data")
            or envelope.get("rows") or envelope.get("rules")
            or envelope.get("Rules") or [])
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = (row.get("name") or row.get("Name")
                    or row.get("RuleName") or row.get("ruleName") or "")
            if not name:
                continue
            if "value" in row:
                out[name] = row.get("value")
            elif "Value" in row:
                out[name] = row.get("Value")
            elif "Active" in row:
                out[name] = row.get("Active")
            else:
                out[name] = True
    return out
