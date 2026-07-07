#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import logging
import math
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .user_team_matcher import UserTeamMatcher

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .safe_folder_mapper import SafeFolderMapper


def build_shared_folder_permissions(safe_member_map: Dict[str, List[dict]],
                                    user_team_matcher: Optional['UserTeamMatcher'] = None,
                                    ) -> dict:
    """Aggregate safe member permissions into Keeper shared folder permission format.

    Merges permissions across all safes — if a user appears in multiple safes,
    they get the highest permission tier across all of them.

    Returns dict with 'shared_folder_resources' and 'shared_folder_users' keys
    matching the format expected by edit.py get_folder_permissions().
    """
    if not safe_member_map:
        return {}

    # Aggregate: for each member, take the highest permission across safes
    member_perms = {}  # (name, member_type) → highest permissions dict
    for safe_id, members in safe_member_map.items():
        for m in members:
            name = m.get("name", "")
            mtype = m.get("member_type", "user")
            perms = m.get("permissions", {})
            key = (name.lower(), mtype)

            if key not in member_perms:
                member_perms[key] = {"name": name, "member_type": mtype, "permissions": dict(perms)}
            else:
                # Merge — take the more permissive value for each field
                existing = member_perms[key]["permissions"]
                for field in ("manage_users", "manage_records", "can_edit", "can_share"):
                    if perms.get(field, False):
                        existing[field] = True

    # Build permission entries, matching to Keeper users/teams if possible
    permission_entries = []
    for (name_lower, mtype), entry in member_perms.items():
        name = entry["name"]
        perms = entry["permissions"]

        # Try to match to a Keeper user or team
        matched_name = None
        if user_team_matcher:
            if mtype == "user":
                matched_name = user_team_matcher.match_user(name)
            elif mtype == "team":
                matched_name = user_team_matcher.match_team(name)

        if not matched_name:
            continue  # Skip unmatched — they'll appear in the CSV report

        perm_entry = {
            "name": matched_name,
            "manage_users": perms.get("manage_users", False),
            "manage_records": perms.get("manage_records", False),
        }
        permission_entries.append(perm_entry)

    if not permission_entries:
        return {}

    # Both shared folders get the same permission set (resources and users folders)
    folder_perms = {
        "manage_users": True,
        "manage_records": True,
        "can_edit": True,
        "can_share": True,
        "permissions": permission_entries,
    }
    return {
        "shared_folder_resources": dict(folder_perms),
        "shared_folder_users": dict(folder_perms),
    }


def build_safe_folders(safe_member_map: Dict[str, List[dict]],
                       folder_mapper: 'SafeFolderMapper',
                       user_team_matcher: Optional['UserTeamMatcher'] = None,
                       ) -> List[dict]:
    """Build the per-safe ``safe_folders`` list for the import JSON.

    Each entry maps to a Keeper shared folder named after the CyberArk safe
    (after ``SafeFolderMapper`` sanitization) and carries *only* that safe's
    permission set — no cross-safe aggregation, so members of safe A do not
    leak access to safe B.

    Only safes that had at least one account successfully mapped during
    import appear in ``folder_mapper.iter_mapped()`` — empty CyberArk safes
    (or safes whose accounts were all skipped) do not get a folder entry.
    """
    if folder_mapper is None or folder_mapper.mode != "safe":
        return []

    # Resolved folder name → raw safe name (first wins so report ordering
    # mirrors the order safes were processed in the orchestrator).
    folder_to_safe: Dict[str, str] = {}
    for raw, resolved in folder_mapper.iter_mapped():
        if not resolved:
            continue
        folder_to_safe.setdefault(resolved, raw)

    safe_folders: List[dict] = []
    for resolved, raw in folder_to_safe.items():
        members = safe_member_map.get(raw) or []
        permission_entries: List[dict] = []
        for m in members:
            name = m.get("name", "")
            mtype = m.get("member_type", "user")
            perms = m.get("permissions", {}) or {}
            matched_name = None
            if user_team_matcher:
                if mtype == "user":
                    matched_name = user_team_matcher.match_user(name)
                elif mtype == "team":
                    matched_name = user_team_matcher.match_team(name)
            if not matched_name:
                # Unmatched principals are surfaced via the CSV report; do
                # not silently grant them access to the safe folder.
                continue
            permission_entries.append({
                "name": matched_name,
                "manage_users": bool(perms.get("manage_users", False)),
                "manage_records": bool(perms.get("manage_records", False)),
            })

        safe_folders.append({
            "name": resolved,
            "safe_name": raw,
            "manage_users": True,
            "manage_records": True,
            "can_edit": True,
            "can_share": True,
            "permissions": permission_entries,
        })
    return safe_folders


def validate_import_data(resources: List[dict], users: List[dict]) -> List[str]:
    """Pre-import validation. Returns list of warning strings."""
    warnings = []

    # Resources missing host/address
    for r in resources:
        if not r.get("host"):
            warnings.append(f'Resource "{r.get("title", "?")}" has no host/address')

    # Nested users missing password (will be created without credentials)
    no_pw = []
    for r in resources:
        for u in r.get("users", []):
            if not u.get("password") and not u.get("private_pem_key"):
                no_pw.append(u.get("title", "?"))
    # External users missing password
    for u in users:
        if not u.get("password") and not u.get("private_pem_key"):
            no_pw.append(u.get("title", "?"))
    if no_pw:
        warnings.append(f'{len(no_pw)} user(s) have no password or SSH key '
                        f'— will be created without credentials')

    # External (unnested) users without resource linkage
    if users:
        warnings.append(f'{len(users)} standalone login record(s) not linked to a resource')

    # Rotation enabled but no password (rotation will fail)
    for r in resources:
        for u in r.get("users", []):
            rs = u.get("rotation_settings", {})
            if (rs.get("enabled") == "on"
                    and not u.get("password")
                    and not u.get("private_pem_key")):
                warnings.append(
                    f'User "{u.get("title", "?")}" has rotation enabled but '
                    f'no password/key — rotation will fail until credentials are set')

    return warnings


def build_import_json(project_name: str, gateway_name: Optional[str],
                      resources: List[dict], users: List[dict],
                      safe_member_map: Optional[Dict[str, List[dict]]] = None,
                      user_team_matcher: Optional['UserTeamMatcher'] = None,
                      master_policy_config: Optional[dict] = None,
                      folder_mapper: Optional['SafeFolderMapper'] = None,
                      ) -> dict:
    """Build the pam project import JSON from mapped records."""
    mp = master_policy_config or {}
    # Imported from CyberArk Master Policy "Require password change every X
    # days" (PasswordChangeDays) when present — see MasterPolicyMapper. Falls
    # back to on-demand so an admin without master-policy read access still
    # gets a working PAM Configuration.
    rotation_schedule = mp.get("default_rotation_schedule") or {"type": "on-demand"}
    if not isinstance(rotation_schedule, dict):
        rotation_schedule = {"type": "on-demand"}
    pam_config = {
        "environment": "local",
        "title": f"{project_name} Configuration",
        "connections": mp.get("connections", "on"),
        "rotation": mp.get("rotation", "on"),
        "tunneling": mp.get("tunneling", "on"),
        "graphical_session_recording": mp.get("graphical_session_recording", "off"),
        "text_session_recording": mp.get("text_session_recording", "off"),
        # Keeper-specific features set explicitly so PamConfigEnvironment
        # doesn't fall back to its on/off defaults that don't match the
        # CyberArk migration intent.
        "remote_browser_isolation": mp.get("remote_browser_isolation", "off"),
        "ai_threat_detection": mp.get("ai_threat_detection", "off"),
        "ai_terminate_session_on_detection": mp.get("ai_terminate_session_on_detection", "off"),
        "default_rotation_schedule": rotation_schedule,
    }
    if gateway_name:
        pam_config["gateway_name"] = gateway_name

    result = {
        "project": project_name,
        "pam_configuration": pam_config,
        "pam_data": {
            "resources": resources,
            "users": users,
        },
    }

    # ``safe`` mode emits one ``safe_folders`` entry per CyberArk safe so
    # each one becomes its own Keeper shared folder with its own permission
    # set. The legacy aggregated ``shared_folder_resources`` /
    # ``shared_folder_users`` blocks are intentionally NOT emitted because
    # they would cause edit.py's process_folders to create the old two-
    # folder layout in addition to the new safe folders.
    safe_mode = folder_mapper is not None and folder_mapper.mode == "safe"
    if safe_mode:
        safe_folders = build_safe_folders(
            safe_member_map or {}, folder_mapper, user_team_matcher,
        )
        if safe_folders:
            result["safe_folders"] = safe_folders
    elif safe_member_map:
        sf_perms = build_shared_folder_permissions(safe_member_map, user_team_matcher)
        if sf_perms:
            result.update(sf_perms)

    return result


def build_extend_json(resources: List[dict], users: List[dict]) -> dict:
    """Build the pam project extend JSON (pam_data only)."""
    return {
        "pam_data": {
            "resources": resources,
            "users": users,
        }
    }


def strip_credentials(data: dict):
    """Remove passwords from import JSON for safe --output without --include-credentials."""
    pam_data = data.get("pam_data", {})
    for user in pam_data.get("users", []):
        if "password" in user:
            user["password"] = "***"
    for resource in pam_data.get("resources", []):
        for user in resource.get("users", []):
            if "password" in user:
                user["password"] = "***"


def format_duration(seconds: float) -> str:
    """Format seconds as 'Xm Ys'. Handles negative, inf, nan."""
    if math.isnan(seconds) or math.isinf(seconds):
        return "N/A"
    seconds = max(0, min(seconds, 999999))  # clamp to ~11.5 days max
    m = int(seconds) // 60
    s = int(seconds) % 60
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def build_report(project_name: str, safes_processed: int, total_accounts: int,
                 resource_counts: Dict[str, Dict[str, int]],
                 platform_counts: Dict[str, Dict[str, Any]],
                 skipped: List[dict], incomplete_count: int,
                 duration: float, project_result: Optional[dict] = None,
                 unmapped_platforms: Optional[Dict[str, int]] = None,
                 unmapped_items: Optional[List[dict]] = None,
                 server: str = '') -> str:
    """Build structured post-import report matching the spec."""
    lines = []
    lines.append('=' * 60)
    lines.append(f' CyberArk PAM → KeeperPAM Migration Report')
    lines.append(f' {project_name}')
    lines.append('=' * 60)
    lines.append('')

    # Source summary
    lines.append(' SOURCE SUMMARY')
    lines.append(' ' + '-' * 40)
    if server:
        lines.append(f'   Server:           {server}')
    lines.append(f'   Safes processed:  {safes_processed}')
    lines.append(f'   Accounts found:   {total_accounts}')
    lines.append('')

    # Project assets
    if project_result:
        lines.append(' PROJECT ASSETS')
        lines.append(' ' + '-' * 40)
        gw = project_result.get("gateway", {})
        if gw:
            gw_token = gw.get('gateway_token', '')
            lines.append(f'   Gateway:    {gw.get("gateway_name", "N/A")} ({gw.get("gateway_uid", "N/A")})')
        ksm = project_result.get("ksm_app", {})
        if ksm:
            lines.append(f'   KSM App:    {ksm.get("app_uid", "N/A")}')
        config = project_result.get("config_uid", "")
        if config:
            lines.append(f'   Config UID: {config}')
        folders = project_result.get("folders", {})
        if folders:
            safe_entries = folders.get("safe_folders") or []
            if safe_entries:
                # ``safe`` mode: one shared folder per CyberArk safe plus
                # an admin-only Config folder. Each safe folder has two
                # subfolders (``Resources`` for assets, ``Users`` for
                # credentials) that inherit the safe's permission set.
                # Surface them explicitly so the operator can confirm
                # the per-safe permission separation is in place.
                config_name = folders.get("config_folder", folders.get("resources_folder", "Config"))
                config_uid_v = folders.get("config_folder_uid", folders.get("resources_folder_uid", "N/A"))
                lines.append(f'   Config:     {config_name} ({config_uid_v})')
                lines.append(f'   Safe folders created: {len(safe_entries)}  '
                             f'(each contains "<safe> - Resources" and "<safe> - Users" subfolders)')
                for entry in safe_entries:
                    if not isinstance(entry, dict):
                        continue
                    nm = entry.get("name", "?")
                    uid = entry.get("uid", "N/A")
                    safe_name = entry.get("safe_name", "")
                    suffix = f' [safe: {safe_name}]' if safe_name and safe_name != nm else ''
                    lines.append(f'     • {nm} ({uid}){suffix}')
            else:
                lines.append(f'   Resources:  {folders.get("resources_folder", "N/A")} ({folders.get("resources_folder_uid", "N/A")})')
                lines.append(f'   Users:      {folders.get("users_folder", "N/A")} ({folders.get("users_folder_uid", "N/A")})')
        lines.append('')

    # Import results
    lines.append(' IMPORT RESULTS')
    lines.append(' ' + '-' * 40)
    if not resource_counts:
        resource_counts = {}
    total_ok = total_skip = total_err = 0
    for rtype in ("pamMachine", "pamDatabase", "pamUser", "login"):
        counts = resource_counts.get(rtype, {"ok": 0, "skip": 0, "err": 0})
        lines.append(f'   {rtype:18s} {counts["ok"]:>4d} ok  {counts["skip"]:>4d} skip  {counts["err"]:>4d} err')
        total_ok += counts["ok"]
        total_skip += counts["skip"]
        total_err += counts["err"]
    lines.append(f'   {"TOTAL":18s} {total_ok:>4d} ok  {total_skip:>4d} skip  {total_err:>4d} err')
    lines.append(f'   Duration:   {format_duration(duration)}')
    lines.append('')

    # Platform mapping
    if platform_counts:
        lines.append(' PLATFORM MAPPING')
        lines.append(' ' + '-' * 40)
        for pid, info in sorted(platform_counts.items()):
            rotation = info.get("rotation", "N/A")
            count = info.get("count", 0)
            marker = ""
            if unmapped_platforms and pid in unmapped_platforms:
                marker = " ← use --platform-map"
                rotation = "UNMAPPED"
            lines.append(f'   {pid:20s} → {rotation:12s} ({count} accounts){marker}')
        lines.append('')

    # Skipped accounts
    if skipped:
        password_failed = sum(1 for s in (skipped or []) if s.get("reason") == "password retrieval failed")
        cpm_disabled = sum(1 for s in (skipped or []) if s.get("reason") == "CPM disabled")
        lines.append(' SKIPPED ACCOUNTS')
        lines.append(' ' + '-' * 40)
        if cpm_disabled:
            lines.append(f'   Manual mgmt (CPM disabled):  {cpm_disabled}')
        if password_failed:
            lines.append(f'   Password retrieval failed:   {password_failed}')
        if incomplete_count:
            lines.append(f'   Incomplete (missing fields): {incomplete_count}')
        lines.append('')

    # UNMAPPED section
    if unmapped_items:
        lines.append(' UNMAPPED — REQUIRES MANUAL ACTION')
        lines.append(' ' + '-' * 40)
        by_category = {}  # type: Dict[str, List[dict]]
        for item in unmapped_items:
            cat = item.get("category", "Other")
            by_category.setdefault(cat, []).append(item)
        for cat, items in sorted(by_category.items()):
            lines.append(f'   {cat}:')
            for item in items:
                lines.append(f'     {item.get("item", "")}')
                lines.append(f'       Action: {item.get("action", "")}')
            lines.append('')

    # Gateway deployment
    gw_token = ''
    if project_result:
        gw_token = project_result.get("gateway", {}).get("gateway_token", "")
    if gw_token:
        lines.append(' GATEWAY DEPLOYMENT')
        lines.append(' ' + '-' * 40)
        lines.append(f'   Access Token: {gw_token}')
        lines.append('')
        lines.append(f'   docker run -d --name keeper-gateway \\')
        lines.append(f'     -e GATEWAY_CONFIG="{gw_token}" \\')
        lines.append(f'     -e ACCEPT_EULA=Y --shm-size=2g \\')
        lines.append(f'     --restart unless-stopped keeper/gateway:latest')
        lines.append('')

    # Next steps
    lines.append(' NEXT STEPS')
    lines.append(' ' + '-' * 40)
    lines.append(f'   1. Review UNMAPPED section — action each item')
    lines.append(f'   2. Verify: pam gateway list')
    lines.append(f'   3. Cleanup: pam project cyberark-cleanup --name "{project_name}"')
    lines.append('')

    # Command (redacted)
    lines.append(' COMMAND (redacted)')
    lines.append(' ' + '-' * 40)
    cmd = f'pam project cyberark-import {server}'
    if project_name:
        cmd += f' --name "{project_name}"'
    lines.append(f'   {cmd}')
    lines.append('')
    lines.append('=' * 60)

    return "\n".join(lines)
