#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)
#
# Dependents / service-account discovery.
#
# CyberArk lets a master account's password be consumed by Windows services,
# scheduled tasks and IIS application pools running on remote hosts. The
# ``/Accounts/{id}/Dependents`` endpoint returns one entry per (host, service,
# type) tuple. KeeperPAM models the same relationship via
# ``pam action service add`` (machine-uid + user-uid + type), so the importer
# collects dependents during the mapping phase and replays them as service
# mappings after the vault import succeeds.

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional, TYPE_CHECKING

from prompt_toolkit import HTML, print_formatted_text

from .ui import _esc

if TYPE_CHECKING:
    from .client import CyberArkPVWAClient


# CyberArk dependent ``type`` / ``platformId`` values → Keeper service-mapping
# verbs accepted by ``PAMActionServiceAddCommand`` (--type service|task|iis).
# Keys are matched case-insensitively after stripping non-alphanumerics so
# spellings like ``Windows Service``, ``Win32Service``, ``WinService``, and
# the Privilege Cloud ``SchedTask`` platformId all resolve.
_DEPENDENT_TYPE_ALIASES: Dict[str, str] = {
    # Windows services
    "windowsservice": "service",
    "win32service": "service",
    "winservice": "service",
    "service": "service",
    "ntservice": "service",
    # Scheduled tasks
    "scheduledtask": "task",
    "windowsscheduledtask": "task",
    "schedtask": "task",
    "task": "task",
    # IIS application pools
    "iisapppool": "iis",
    "iisapplicationpool": "iis",
    "iisapppools": "iis",
    "iis": "iis",
}


def _normalize_dependent_type(raw_type: str) -> Optional[str]:
    """Map CyberArk's ``Type`` string to Keeper's service verb or ``None``.

    Returning ``None`` means we recognize the dependent but do not have a
    Keeper equivalent (e.g. COM+ application). Callers should record those in
    the unmapped-items list so admins can act on them manually.
    """
    if not raw_type:
        return None
    key = "".join(ch for ch in str(raw_type).lower() if ch.isalnum())
    return _DEPENDENT_TYPE_ALIASES.get(key)


def resolve_account_dependents(client: 'CyberArkPVWAClient',
                               account: dict,
                               master_user_title: str) -> List[dict]:
    """Fetch dependents for a CyberArk master account and shape them for replay.

    Each returned dict carries everything the post-import phase needs to call
    ``pam action service add`` without re-querying CyberArk:

    * ``machine_address`` — host where the service runs (used to find the
      Keeper PAM Machine record).
    * ``service_type`` — Keeper verb (service|task|iis) or ``None`` for
      unsupported categories.
    * ``raw_type`` — original CyberArk ``Type`` string (kept for reporting).
    * ``service_name`` — informational, surfaced in the report only.
    * ``master_user_title`` — Keeper title of the pamUser record that holds
      the rotated credential (i.e. the user the service runs as).
    * ``master_account_id`` / ``master_account_name`` — CyberArk source IDs
      preserved for the audit report.

    Network / authorization failures surface as an empty list — dependents
    are best-effort metadata and must never abort the import.
    """
    account_id = account.get("id", "") or ""
    if not account_id:
        return []
    raw_dependents = client.fetch_account_dependents(account_id)
    if not raw_dependents:
        return []

    master_account_name = account.get("name", "") or ""
    results: List[dict] = []
    dropped: List[dict] = []
    for dep in raw_dependents:
        # Privilege Cloud nests the actually-useful fields under
        # ``platformDependentProperties`` ({"address": "...", "serviceName":
        # "..."} / {"taskName": "..."} / {"appPoolName": "..."}). Self-hosted
        # PVWA flattens them. We try both.
        props = (dep.get("platformDependentProperties")
                 or dep.get("PlatformDependentProperties") or {})
        if not isinstance(props, dict):
            props = {}

        address = (_first_nonempty(
            dep,
            ("Address", "address", "Host", "host", "MachineAddress",
             "machineAddress", "TargetAddress", "targetAddress",
             "ComputerName", "computerName"),
        ) or _first_nonempty(
            props,
            ("address", "Address", "host", "Host", "machineAddress",
             "MachineAddress"),
        ))
        # ``platformId`` (Privilege Cloud) is the most reliable type signal —
        # it returns concise category codes like ``WinService`` / ``SchedTask``
        # / ``IISAppPool``. Self-hosted PVWA exposes a ``type`` field with
        # human-readable strings; we accept both.
        raw_type = _first_nonempty(
            dep,
            ("platformId", "PlatformId", "PlatformID", "Type", "type",
             "DependencyType", "dependentType", "dependencyType"),
        )
        name = (_first_nonempty(
            props,
            ("serviceName", "ServiceName", "taskName", "TaskName",
             "appPoolName", "AppPoolName", "name", "Name"),
        ) or _first_nonempty(
            dep,
            ("Name", "name", "DependencyName", "dependentName",
             "ServiceName", "serviceName"),
        ))
        dep_id = _first_nonempty(
            dep, ("id", "Id", "ID", "DependencyID", "dependencyId"),
        )
        if not address:
            dropped.append(dep)
            continue
        results.append({
            "machine_address": address,
            "service_type": _normalize_dependent_type(raw_type),
            "raw_type": raw_type,
            "service_name": name,
            "master_user_title": master_user_title,
            "master_account_id": account_id,
            "master_account_name": master_account_name,
            "dependent_account_id": str(dep_id) if dep_id else "",
        })

    if dropped:
        # Surface the raw entries that were filtered out so operators can
        # see which CyberArk field actually carries the host. Without this
        # the importer silently swallows mis-shaped responses and the
        # downstream "There are no service mappings" symptom is hard to
        # diagnose.
        try:
            pretty = json.dumps(dropped, indent=2, sort_keys=True)
        except (TypeError, ValueError):
            pretty = repr(dropped)
        print_formatted_text(HTML(
            f"<ansiyellow>⚠ Skipped {len(dropped)} dependent(s) on "
            f"account <b>{_esc(master_account_name or account_id)}</b> "
            f"— no recognizable address field. Raw entries:</ansiyellow>"))
        print(pretty)
        logging.warning(
            "Dropped %d dependent(s) on account %s — no address field matched. "
            "If CyberArk returned a different field name, please report it.",
            len(dropped), account_id,
        )

    if results:
        logging.debug(
            "Resolved %d CyberArk dependent(s) for account '%s'",
            len(results), master_account_name or account_id,
        )
    return results


def _first_nonempty(source: dict, keys: tuple) -> str:
    """Return the first non-empty stringified value for any of ``keys`` in
    ``source``. Mirrors the case-insensitive field-name shopping CyberArk
    forces on us — Privilege Cloud uses lowercase, self-hosted PVWA uses
    PascalCase, and individual platform plugins occasionally invent their own.
    """
    for key in keys:
        val = source.get(key)
        if val is None:
            continue
        text = str(val).strip()
        if text:
            return text
    return ""
