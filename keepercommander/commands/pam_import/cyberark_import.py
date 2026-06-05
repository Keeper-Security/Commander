#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
# CyberArk → KeeperPAM import orchestrator
# Fetches accounts from CyberArk PVWA, maps them to PAM record types,
# and calls pam project import/extend to create vault records.
#

from __future__ import annotations

import argparse
import atexit
import copy
import json
import logging
import os
import re
import tempfile
import time
from typing import List, Optional

from prompt_toolkit import HTML, print_formatted_text

from ..base import Command
from ...display import bcolors
from ...error import CommandError
from ...importer.cyberark.cyberark_pam import (
    CyberArkPVWAClient,
    AccountMapper,
    MasterPolicyMapper,
    UserTeamMatcher,
    PermissionMapper,
    SafeFolderMapper,
    AdaptiveThrottler,
    apply_safe_filter,
    exclude_system_safes,
    resolve_linked_accounts,
    pick_admin_credentials,
    pick_launch_credentials,
    detect_dual_account,
    build_import_json,
    build_extend_json,
    build_report,
    format_duration,
    strip_credentials,
    validate_import_data,
)

# Track temp files for cleanup on abnormal exit
_pending_temp_files = set()


def _cleanup_temp_files():
    """Remove any temp files left behind on abnormal exit."""
    for f in list(_pending_temp_files):
        try:
            if os.path.exists(f):
                # Overwrite with zeros before deleting to reduce credential exposure window
                size = os.path.getsize(f)
                with open(f, 'wb') as fh:
                    fh.write(b'\x00' * size)
                os.unlink(f)
        except Exception:
            pass  # Broad catch — atexit runs during interpreter shutdown
        _pending_temp_files.discard(f)


atexit.register(_cleanup_temp_files)


def _write_secure_temp_json(data: dict) -> str:
    """Write data to a temp file with restrictive permissions (owner-only read/write).
    Returns the temp file path. Caller MUST call _remove_secure_temp() after use."""
    # Create temp file with restrictive permissions atomically (no race window)
    tmp_dir = tempfile.gettempdir()
    fd = tempfile.mkstemp(suffix='.json', prefix='keeper_ca_import_', dir=tmp_dir)
    tmp_fd, tmp_path = fd
    try:
        with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        # mkstemp creates with 0o600 by default on POSIX
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    _pending_temp_files.add(tmp_path)
    return tmp_path


def _remove_secure_temp(tmp_path: str):
    """Securely remove a temp file — overwrite content before unlinking."""
    try:
        if os.path.exists(tmp_path):
            size = os.path.getsize(tmp_path)
            with open(tmp_path, 'wb') as f:
                f.write(b'\x00' * size)
            os.unlink(tmp_path)
    except OSError:
        pass
    _pending_temp_files.discard(tmp_path)


class CyberArkPAMImportCommand(Command):
    parser = argparse.ArgumentParser(
        prog="pam project cyberark-import",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Dry-run from Privilege Cloud
  pam project cyberark-import tenant.cyberark.cloud --dry-run

  # List available safes
  pam project cyberark-import pvwa.example.com --list-safes

  # Import specific safes only
  pam project cyberark-import pvwa.example.com --safes "Windows*,Unix*" --name "PAM Migration"

  # Exclude safes
  pam project cyberark-import pvwa.example.com --exclude-safes "Test*,Dev*"

  # Save JSON for review
  pam project cyberark-import pvwa.example.com --dry-run --output /tmp/review.json

  # Full import with custom platform mapping
  pam project cyberark-import pvwa.example.com --platform-map platforms.json --name "Prod"

  # Non-interactive batch mode
  pam project cyberark-import pvwa.example.com --name "Auto Import" --yes

  # Self-hosted with SSL verification disabled
  pam project cyberark-import pvwa.internal.com --no-verify-ssl --name "Internal"
        ''')
    parser.add_argument("server", action="store", help="CyberArk PVWA host (e.g. mycompany.cyberark.cloud or pvwa.example.com)")
    parser.add_argument("--name", "-n", required=False, dest="project_name", action="store",
                        default="", help="PAM project name (default: CyberArk Migration)")
    parser.add_argument("--config", "-c", required=False, dest="config", action="store",
                        default="", help="Extend existing PAM project (PAM Configuration UID or title)")
    parser.add_argument("--gateway", "-g", required=False, dest="gateway", action="store",
                        default="", help="Gateway UID or name (new project only)")
    parser.add_argument("--folder-mode", required=False, dest="folder_mode", action="store",
                        choices=["ksm", "exact", "flat"], default="flat",
                        help="Safe → folder mapping mode (default: flat)")
    parser.add_argument("--safes", required=False, dest="safes", action="store",
                        default="", help="Include only matching Safes (comma-separated, supports globs)")
    parser.add_argument("--exclude-safes", required=False, dest="exclude_safes", action="store",
                        default="", help="Exclude matching Safes (comma-separated, supports globs)")
    parser.add_argument("--list-safes", required=False, dest="list_safes", action="store_true",
                        default=False, help="List Safes with account counts and exit")
    parser.add_argument("--dry-run", "-d", required=False, dest="dry_run", action="store_true",
                        default=False, help="Preview import without modifying vault")
    parser.add_argument("--output", "-o", required=False, dest="output", action="store",
                        default="", help="Save generated import JSON to file")
    parser.add_argument("--include-credentials", required=False, dest="include_credentials",
                        action="store_true", default=False,
                        help="Include passwords in --output or --dry-run display")
    parser.add_argument("--estimate", required=False, dest="estimate", action="store_true",
                        default=False, help="Count accounts and estimate import time, then exit")
    parser.add_argument("--yes", "-y", required=False, dest="yes", action="store_true",
                        default=False, help="Skip confirmation prompts")
    parser.add_argument("--skip-users", required=False, dest="skip_users", action="store_true",
                        default=False, help="Import machine/database records only, skip pamUser records")
    parser.add_argument("--batch-size", required=False, dest="batch_size", action="store",
                        type=int, default=100, help="Records per import batch (default: 100)")
    parser.add_argument("--batch-delay", required=False, dest="batch_delay", action="store",
                        type=float, default=0.5, help="Base delay between batches in seconds (default: 0.5)")
    parser.add_argument("--platform-map", required=False, dest="platform_map", action="store",
                        default="", help="JSON file mapping CyberArk platformIds to KeeperPAM rotation types")
    parser.add_argument("--state-filter", required=False, dest="state_filter", action="store",
                        default="", help="Comma-separated CPM states to include (default: all)")
    parser.add_argument("--no-verify-ssl", required=False, dest="no_verify_ssl", action="store_true",
                        default=False, help="Disable SSL certificate verification for self-hosted PVWA (insecure)")
    parser.add_argument("--include-system-safes", required=False, dest="include_system_safes",
                        action="store_true", default=False,
                        help="Include CyberArk system safes (VaultInternal, PVWAConfig, etc.)")
    parser.add_argument("--skip-linked-accounts", required=False, dest="skip_linked_accounts",
                        action="store_true", default=False,
                        help="Skip logon/reconcile/enable linked account resolution")
    parser.add_argument("--skip-members", required=False, dest="skip_members",
                        action="store_true", default=False,
                        help="Skip safe member extraction and folder permissions")
    parser.add_argument("--user-map", required=False, dest="user_map", action="store",
                        default="", help="JSON file mapping CyberArk users to Keeper emails")

    def get_parser(self):
        return CyberArkPAMImportCommand.parser

    def execute(self, params, **kwargs):
        server = kwargs.get("server", "")
        project_name = kwargs.get("project_name", "") or "CyberArk Migration"
        config_uid = kwargs.get("config", "")
        gateway_name = kwargs.get("gateway", "")
        folder_mode = kwargs.get("folder_mode", "flat")
        safe_include = kwargs.get("safes", "")
        safe_exclude = kwargs.get("exclude_safes", "")
        list_safes = kwargs.get("list_safes", False)
        dry_run = kwargs.get("dry_run", False)
        output_file = kwargs.get("output", "")
        include_creds = kwargs.get("include_credentials", False)
        estimate_only = kwargs.get("estimate", False)
        skip_confirm = kwargs.get("yes", False)
        skip_users = kwargs.get("skip_users", False)
        skip_linked = kwargs.get("skip_linked_accounts", False)

        # All placeholder flags now implemented (Phases 3-5 complete)

        batch_size = int(kwargs.get("batch_size") or 100)
        batch_delay = float(kwargs.get("batch_delay") or 0.5)
        platform_map_file = kwargs.get("platform_map", "")
        state_filter_str = kwargs.get("state_filter", "")

        # Validate batch parameters
        if batch_size < 1:
            raise CommandError("pam project cyberark-import", "--batch-size must be >= 1")
        if batch_delay < 0:
            raise CommandError("pam project cyberark-import", "--batch-delay must be >= 0")

        if not server:
            raise CommandError("pam project cyberark-import", "CyberArk PVWA server is required")

        # Load and validate platform map override
        platform_map_override = None
        if platform_map_file:
            if not os.path.isfile(platform_map_file):
                raise CommandError("pam project cyberark-import",
                                   f"Platform map file not found: {platform_map_file}")
            try:
                with open(platform_map_file, encoding="utf-8") as f:
                    platform_map_override = json.load(f)
            except json.JSONDecodeError as e:
                raise CommandError("pam project cyberark-import",
                                   f"Invalid JSON in platform map file: {e}")
            if not isinstance(platform_map_override, dict):
                raise CommandError("pam project cyberark-import",
                                   "Platform map must be a JSON object mapping platformId to settings")
            for key, entry in platform_map_override.items():
                if not isinstance(entry, dict) or "record_type" not in entry:
                    raise CommandError("pam project cyberark-import",
                                       f"Platform map entry '{key}' must be an object with a 'record_type' field")

        no_verify_ssl = kwargs.get("no_verify_ssl", False)
        state_filter = [s.strip() for s in state_filter_str.split(",") if s.strip()] if state_filter_str else None

        # ── Resolve gateway UID → name if needed ─────────────
        if gateway_name and not config_uid:
            try:
                from ..pam.gateway_helper import get_all_gateways
                from ...loginv3 import CommonHelperMethods
                all_gw = get_all_gateways(params)
                gw_uid_bytes = CommonHelperMethods.url_safe_str_to_bytes(gateway_name)
                for gw in all_gw:
                    if gw.controllerUid == gw_uid_bytes:
                        gateway_name = gw.controllerName
                        logging.info(f"Resolved gateway UID to name: {gateway_name}")
                        break
            except Exception:
                pass  # Use gateway_name as-is (may be a name already)

        # ── Phase 0: Authenticate ────────────────────────────
        try:
            client = CyberArkPVWAClient(server, verify_ssl=not no_verify_ssl)
        except ValueError as e:
            raise CommandError("pam project cyberark-import", str(e))
        if not client.authenticate():
            raise CommandError("pam project cyberark-import",
                               "Authentication failed. Check credentials and try again.")

        try:
            self._run_import(params, client, kwargs, dry_run, output_file,
                             include_creds, estimate_only, skip_confirm, skip_users,
                             skip_linked, safe_include, safe_exclude, list_safes,
                             batch_size, batch_delay, folder_mode, project_name,
                             config_uid, gateway_name, platform_map_override,
                             state_filter)
        finally:
            client.logoff()

    def _run_import(self, params, client, kwargs, dry_run, output_file,
                    include_creds, estimate_only, skip_confirm, skip_users,
                    skip_linked, safe_include, safe_exclude, list_safes,
                    batch_size, batch_delay, folder_mode, project_name,
                    config_uid, gateway_name, platform_map_override,
                    state_filter):
        """Core import logic — separated from execute() for logoff guarantee."""

        unmapped_items = []  # items requiring manual action post-import

        # ── Phase 0e: Fetch Master Policy (Layer 5) ─────────
        master_policy_config = dict(MasterPolicyMapper.DEFAULTS)
        if not dry_run:
            print_formatted_text(HTML("Fetching Master Policy..."))
            policy_data = client.fetch_master_policy()
            if policy_data:
                master_policy_config, mp_unmapped = \
                    MasterPolicyMapper.map_policy(policy_data)
                unmapped_items.extend(mp_unmapped)
                print_formatted_text(HTML(
                    f"Master Policy: session_recording="
                    f"<b>{master_policy_config.get('graphical_session_recording', 'off')}</b>, "
                    f"connections=<b>{master_policy_config.get('connections', 'on')}</b>"))
            else:
                logging.warning(f'{bcolors.WARNING}Master Policy not accessible — '
                                f'using defaults. Review PAM config settings manually.{bcolors.ENDC}')

        # ── Phase 0b: Fetch Safes ────────────────────────────
        all_safes = client.fetch_safes()
        if not all_safes:
            return

        # Exclude system safes (VaultInternal, PVWAConfig, etc.)
        include_system = kwargs.get("include_system_safes", False)
        safes = exclude_system_safes(all_safes, include_system=include_system)
        system_excluded = len(all_safes) - len(safes)

        # Apply --safes / --exclude-safes filters
        safes = apply_safe_filter(safes, safe_include or None, safe_exclude or None)
        if not safes:
            print_formatted_text(HTML("<ansiyellow>No safes match the filter criteria</ansiyellow>"))
            return

        # ── Early exit: --list-safes ─────────────────────────
        if list_safes:
            self._list_safes_detailed(safes, system_excluded)
            return

        # Interactive safe picker (when no --safes flag in interactive mode)
        if (not safe_include and not safe_exclude
                and not skip_confirm
                and not dry_run and not output_file
                and not getattr(params, 'batch_mode', False)):
            selected = self._interactive_safe_picker(safes)
            if selected is not None:
                # Use exact matching (not glob) for interactive selection
                # to handle safe names containing *, ?, [, ] characters
                selected_set = {n.strip() for n in selected.split(',')}
                safes = [s for s in safes if s.get("safeName", "") in selected_set]
                if not safes:
                    print_formatted_text(HTML("<ansiyellow>No safes selected</ansiyellow>"))
                    return

        safe_names = [s.get("safeUrlId", s["safeName"]) for s in safes]

        # ── Phase 1b: Fetch safe members (Layer 2) ──────────
        skip_members = kwargs.get("skip_members", False)
        safe_member_map = {}  # safeUrlId → [mapped_member_dicts]
        member_unmapped = []  # members not matched to Keeper users/teams
        if not skip_members and not dry_run:
            print_formatted_text(HTML(
                f"\nFetching safe members from <b>{len(safe_names)}</b> safes..."))
            for safe_url_id in safe_names:
                raw_members = client.fetch_safe_members(safe_url_id)
                mapped = []
                for m in raw_members:
                    mapped_member = PermissionMapper.map_member(m)
                    mapped.append(mapped_member)
                    # Track unmapped permissions for report
                    if mapped_member["unmapped_permissions"]:
                        for up in mapped_member["unmapped_permissions"]:
                            unmapped_items.append({
                                "category": "Safe member permission",
                                "item": f"{mapped_member['name']} in {safe_url_id}",
                                "action": f"CyberArk permission '{up}' has no "
                                          f"Keeper equivalent",
                            })
                if mapped:
                    safe_member_map[safe_url_id] = mapped
            total_members = sum(len(v) for v in safe_member_map.values())
            print_formatted_text(HTML(
                f"Found <b>{total_members}</b> members across "
                f"<b>{len(safe_member_map)}</b> safes"))

        # ── Phase 0b2: Fetch vault users/groups (Layer 6) ────
        user_team_matcher = None
        if not skip_users and not skip_members and not dry_run:
            print_formatted_text(HTML("\nFetching CyberArk vault users and groups..."))
            ca_users = client.fetch_users()
            ca_groups = client.fetch_user_groups()

            # Load --user-map override if provided
            user_map_file = kwargs.get("user_map", "")
            user_map_override = None
            if user_map_file:
                try:
                    with open(user_map_file, encoding="utf-8") as f:
                        user_map_override = json.load(f)
                    if not isinstance(user_map_override, dict):
                        raise CommandError("pam project cyberark-import",
                                           f"--user-map file must contain a JSON object, "
                                           f"got {type(user_map_override).__name__}")
                except (FileNotFoundError, ValueError) as e:
                    raise CommandError("pam project cyberark-import",
                                       f"Failed to load --user-map file: {e}")

            # Build matcher (Keeper users/teams loaded from params if available)
            keeper_users = []
            keeper_teams = []
            if hasattr(params, 'enterprise') and params.enterprise:
                for u in params.enterprise.get('users', []):
                    keeper_users.append({
                        'email': u.get('username', ''),
                        'username': u.get('username', ''),
                    })
            else:
                logging.warning(f'{bcolors.WARNING}Enterprise data not available — '
                                f'all safe members will appear as unmatched. '
                                f'Ensure you are logged in as an enterprise admin.{bcolors.ENDC}')
            if hasattr(params, 'available_team_cache') and params.available_team_cache:
                for t in params.available_team_cache:
                    keeper_teams.append({
                        'name': t.get('team_name', ''),
                    })

            user_team_matcher = UserTeamMatcher(
                keeper_users=keeper_users,
                keeper_teams=keeper_teams,
                user_map_override=user_map_override)

            print_formatted_text(HTML(
                f"Found <b>{len(ca_users)}</b> vault users, "
                f"<b>{len(ca_groups)}</b> groups"))

        # ── Phase 0c: Fetch accounts ─────────────────────────
        print_formatted_text(HTML(f"\nFetching accounts from <b>{len(safe_names)}</b> safes..."))
        accounts_by_safe = client.fetch_accounts(safe_names, state_filter=state_filter)
        total_accounts = sum(len(v) for v in accounts_by_safe.values())

        if total_accounts == 0:
            print_formatted_text(HTML("<ansiyellow>No accounts found in selected safes</ansiyellow>"))
            return

        # ── Early exit: --estimate ───────────────────────────
        if estimate_only:
            est_seconds = total_accounts * 3  # ~2s password retrieval + ~1s vault write
            print(f"\nSafes:    {len(accounts_by_safe)}")
            print(f"Accounts: {total_accounts}")
            print(f"Estimated import time: ~{format_duration(est_seconds)}")
            return

        # ── Phase 2: Map accounts → PAM records ─────────────
        mapper = AccountMapper(platform_map_override)
        folder_mapper = SafeFolderMapper(mode=folder_mode)

        pam_resources = []
        pam_users = []      # standalone login records
        incomplete = []
        skipped = []
        platform_counts = {}  # platformId → {rotation, count}

        skip_all_passwords = {}

        for safe_name, accounts in accounts_by_safe.items():
            for account in accounts:
                platform_id = account.get("platformId", "Unknown")

                # Track platform counts for report
                if platform_id not in platform_counts:
                    mapping = mapper.platform_map.get(platform_id, {})
                    platform_counts[platform_id] = {
                        "rotation": mapping.get("rotation", "UNMAPPED"),
                        "count": 0,
                    }
                platform_counts[platform_id]["count"] += 1

                # Check completeness
                is_incomplete, reason = mapper.is_incomplete(account)

                # Retrieve password
                password = None
                if not dry_run or include_creds:
                    password = client.retrieve_password(
                        account.get("id", ""),
                        account_name=account.get("name", ""),
                        safe_name=safe_name,
                        skip_all=skip_all_passwords,
                    )
                    if password is None:
                        skipped.append({
                            "account": account.get("name", ""),
                            "safe": safe_name,
                            "reason": "password retrieval failed",
                        })
                        continue

                # Map to PAM record
                record = mapper.map_account(account, password, safe_name)
                if record is None:
                    skipped.append({
                        "account": account.get("name", ""),
                        "safe": safe_name,
                        "reason": f"unmappable platformId: {platform_id}",
                    })
                    continue

                # Set folder paths — resources and users go under separate
                # shared folder roots (matching KCM import pattern that
                # edit.py/extend.py expects for folder resolution)
                if folder_mode != "flat":
                    safe_folder = folder_mapper.map_safe(safe_name, project_name)
                    if safe_folder:
                        res_root = f"{project_name} - Resources"
                        usr_root = f"{project_name} - Users"
                        if record.get("type") == "login":
                            record["folder_path"] = f"{usr_root}/{safe_folder}"
                        else:
                            record["folder_path"] = f"{res_root}/{safe_folder}"
                        if record.get("users"):
                            for u in record["users"]:
                                u["folder_path"] = f"{usr_root}/{safe_folder}"

                if is_incomplete:
                    record["notes"] = f"INCOMPLETE: {reason}"
                    incomplete.append(record)

                # Detect dual accounts
                dual_fields = detect_dual_account(account)
                if dual_fields:
                    # Add custom fields to the record
                    if "custom" not in record:
                        record["custom"] = []
                    for key, val in dual_fields.items():
                        record["custom"].append({"type": "text", "label": key, "value": [val]})
                    unmapped_items.append({
                        "category": "Dual account pair",
                        "item": account.get("name", ""),
                        "action": "Exclusive rotation behavior requires manual "
                                  "configuration in KeeperPAM rotation settings",
                    })

                # Resolve linked accounts (logon/reconcile/enable)
                if (not skip_linked and not dry_run and not skip_users
                        and record.get("type") != "login"):
                    linked_users = resolve_linked_accounts(client, account)
                    if linked_users:
                        if "users" not in record:
                            record["users"] = []
                        record["users"].extend(linked_users)
                        admin_title, admin_role = pick_admin_credentials(linked_users)
                        if admin_title:
                            ps = record.setdefault("pam_settings", {})
                            conn = ps.setdefault("connection", {})
                            conn["administrative_credentials"] = admin_title
                            logging.info("Mapped %s account '%s' as administrative_credentials on '%s'",
                                         admin_role, admin_title, record.get("title", ""))
                        logon_title = pick_launch_credentials(linked_users)
                        if logon_title:
                            ps = record.setdefault("pam_settings", {})
                            conn = ps.setdefault("connection", {})
                            conn["launch_credentials"] = logon_title
                            logging.info("Overrode launch_credentials with logon account '%s' on '%s'",
                                         logon_title, record.get("title", ""))
                        # Apply folder_path to linked users (they were added
                        # after the initial folder_path assignment)
                        if folder_mode != "flat":
                            safe_folder = folder_mapper.map_safe(safe_name, project_name)
                            if safe_folder:
                                usr_root = f"{project_name} - Users"
                                for lu in linked_users:
                                    lu["folder_path"] = f"{usr_root}/{safe_folder}"

                # Sort by record type
                if record.get("type") == "login":
                    pam_users.append(record)
                else:
                    if skip_users:
                        record.pop("users", None)
                    pam_resources.append(record)

        # ── Summary ──────────────────────────────────────────
        resource_count = len(pam_resources)
        user_count = sum(len(r.get("users", [])) for r in pam_resources)
        login_count = len(pam_users)
        print()
        print(f"{bcolors.OKBLUE}Mapped {total_accounts} CyberArk accounts:{bcolors.ENDC}")
        print(f"  Resources (pamMachine/pamDatabase): {resource_count}")
        print(f"  Users (pamUser, nested):            {user_count}")
        print(f"  Logins (BusinessWebsite):           {login_count}")
        if unmapped_items:
            print(f"  {bcolors.WARNING}Unmapped (manual action needed):  {len(unmapped_items)}{bcolors.ENDC}")
        if incomplete:
            print(f"  {bcolors.WARNING}Incomplete:                         {len(incomplete)}{bcolors.ENDC}")
        if skipped:
            print(f"  {bcolors.WARNING}Skipped:                            {len(skipped)}{bcolors.ENDC}")
        if mapper.unmapped_platforms:
            print(f"  {bcolors.WARNING}Unmapped platforms (defaulted):     "
                  f"{sum(mapper.unmapped_platforms.values())}{bcolors.ENDC}")
            for pid, cnt in mapper.unmapped_platforms.items():
                print(f"    {pid}: {cnt} accounts")
        print()

        # ── Pre-import validation ────────────────────────────
        validation_warnings = validate_import_data(pam_resources, pam_users)
        if validation_warnings:
            print_formatted_text(HTML(f"\n<ansiyellow>⚠ {len(validation_warnings)} validation warning(s):</ansiyellow>"))
            for w in validation_warnings:
                print_formatted_text(HTML(f"  <ansiyellow>• {_esc(w)}</ansiyellow>"))
            print()

        # ── Build import JSON ────────────────────────────────
        if config_uid:
            import_data = build_extend_json(pam_resources, pam_users)
        else:
            import_data = build_import_json(
                project_name=project_name,
                gateway_name=gateway_name or None,
                resources=pam_resources,
                users=pam_users,
                safe_member_map=safe_member_map if safe_member_map else None,
                user_team_matcher=user_team_matcher,
                master_policy_config=master_policy_config,
            )

        # ── Early exit: --output ─────────────────────────────
        if output_file:
            output_data = copy.deepcopy(import_data)  # deep copy
            if not include_creds:
                strip_credentials(output_data)
            fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            print(f"Import JSON saved to: {output_file}")
            return

        # ── Early exit: --dry-run ────────────────────────────
        if dry_run:
            print("[DRY RUN] No changes will be made to the vault.")
            print()
            output_data = copy.deepcopy(import_data)
            if not include_creds:
                strip_credentials(output_data)
            print(json.dumps(output_data, indent=2))
            print()
            print(f"[DRY RUN COMPLETE] {resource_count} resources, {user_count} users, "
                  f"{login_count} logins would be imported.")
            return

        # ── Confirmation ─────────────────────────────────────
        if not skip_confirm:
            print(f"Ready to import {resource_count} resources, {user_count} users, "
                  f"{login_count} logins into project '{project_name}'.")
            if config_uid:
                print(f"Extending existing PAM configuration: {config_uid}")
            else:
                print("A new PAM project will be created.")
            confirm = input("Proceed? [y/N] ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Import cancelled.")
                return

        # ── Phase 6-8: Import to vault ───────────────────────
        import_start = time.time()
        project_result = None

        try:
            project_result = self._execute_import(
                params, import_data, project_name, config_uid,
                batch_size, batch_delay, pam_resources, pam_users,
            )
        except Exception as e:
            # Log only the exception type and non-sensitive message to avoid credential leaks
            logging.error(f"Import failed: {type(e).__name__}")
            logging.debug(f"Import error details: {e}")
            print_formatted_text(HTML(f"\nImport <ansired>failed</ansired>: {type(e).__name__}"))
            return

        import_duration = time.time() - import_start

        # ── Phase 9: Report ──────────────────────────────────
        resource_counts = {
            "pamMachine": {"ok": 0, "skip": 0, "err": 0},
            "pamDatabase": {"ok": 0, "skip": 0, "err": 0},
            "pamUser": {"ok": 0, "skip": 0, "err": 0},
            "login": {"ok": 0, "skip": 0, "err": 0},
        }
        for r in pam_resources:
            rtype = r.get("type", "pamMachine")
            resource_counts.setdefault(rtype, {"ok": 0, "skip": 0, "err": 0})
            resource_counts[rtype]["ok"] += 1
            for u in r.get("users", []):
                resource_counts["pamUser"]["ok"] += 1
        for u in pam_users:
            resource_counts["login"]["ok"] += 1

        report_text = build_report(
            project_name=project_name,
            safes_processed=len(accounts_by_safe),
            total_accounts=total_accounts,
            resource_counts=resource_counts,
            platform_counts=platform_counts,
            skipped=skipped,
            incomplete_count=len(incomplete),
            duration=import_duration,
            project_result=project_result,
            unmapped_platforms=mapper.unmapped_platforms,
            unmapped_items=unmapped_items,
            server=kwargs.get("server", ""),
        )

        # Strip gateway token from notes (it goes in custom fields instead)
        notes_text = report_text
        gw_token = (project_result or {}).get("gateway", {}).get("gateway_token", "")
        if gw_token:
            notes_text = notes_text.replace(
                gw_token, '(see "Gateway Access Token" field on this record)')

        try:
            print()
            print(report_text)
        except (BrokenPipeError, OSError):
            pass

        # Save report + CSV as vault attachments
        report_config_uid = (project_result or {}).get("config_uid", "") or config_uid
        if report_config_uid:
            tmp_files = []
            try:
                from ..record_edit import RecordUploadAttachmentCommand
                attachments = []

                # Report .md file
                report_tmp = tempfile.NamedTemporaryFile(
                    mode='w', suffix='.md', prefix='CyberArk-Import-Report-',
                    delete=False, encoding='utf-8')
                report_tmp.write(notes_text)
                report_tmp.close()
                tmp_files.append(report_tmp.name)
                attachments.append(report_tmp.name)

                # CSV for unmatched users (if any)
                if user_team_matcher and user_team_matcher.unmatched:
                    csv_content = user_team_matcher.generate_csv()
                    if csv_content:
                        csv_tmp = tempfile.NamedTemporaryFile(
                            mode='w', suffix='.csv',
                            prefix='ca_users_to_provision_',
                            delete=False, encoding='utf-8')
                        csv_tmp.write(csv_content)
                        csv_tmp.close()
                        tmp_files.append(csv_tmp.name)
                        attachments.append(csv_tmp.name)

                if attachments:
                    RecordUploadAttachmentCommand().execute(
                        params, record=report_config_uid, file=attachments)
                    try:
                        print(f"Report saved to PAM config record: {report_config_uid}")
                        if len(attachments) > 1:
                            print("CSV (ca_users_to_provision) attached")
                    except (BrokenPipeError, OSError):
                        pass
            except Exception as e:
                logging.warning(f"Failed to save report attachment: {type(e).__name__}")
            finally:
                for f in tmp_files:
                    try:
                        os.unlink(f)
                    except OSError:
                        pass

    def _execute_import(self, params, import_data: dict, project_name: str,
                        config_uid: str, batch_size: int, batch_delay: float,
                        resources: List[dict], users: List[dict]) -> Optional[dict]:
        """Execute the vault import using pam project import/extend commands."""
        from .edit import PAMProjectImportCommand
        from .extend import PAMProjectExtendCommand

        # Write JSON to temp file for the import command
        total_records = len(resources) + len(users)

        if total_records <= batch_size:
            # Single batch — use import or extend directly
            return self._single_batch_import(
                params, import_data, project_name, config_uid
            )
        else:
            # Multi-batch: first batch creates project, remaining extend
            return self._multi_batch_import(
                params, import_data, project_name, config_uid,
                resources, users, batch_size, batch_delay,
            )

    def _single_batch_import(self, params, import_data: dict,
                             project_name: str, config_uid: str) -> dict:
        """Import all records in a single batch."""
        from .edit import PAMProjectImportCommand
        from .extend import PAMProjectExtendCommand

        tmp_path = _write_secure_temp_json(import_data)
        try:
            if config_uid:
                PAMProjectExtendCommand().execute(
                    params, config=config_uid, file_name=tmp_path, dry_run=False
                )
            else:
                PAMProjectImportCommand().execute(
                    params, project_name=project_name, file_name=tmp_path, dry_run=False
                )
        finally:
            _remove_secure_temp(tmp_path)

        resolved_config_uid = config_uid or self._find_config_uid(params, project_name)
        return {"project_name": project_name, "config_uid": resolved_config_uid}

    def _multi_batch_import(self, params, import_data: dict,
                            project_name: str, config_uid: str,
                            resources: List[dict], users: List[dict],
                            batch_size: int, batch_delay: float) -> dict:
        """Import records in multiple batches with adaptive throttling."""
        from .edit import PAMProjectImportCommand
        from .extend import PAMProjectExtendCommand

        throttler = AdaptiveThrottler(base_delay=batch_delay, batch_size=batch_size)
        all_items = resources + users

        for i in range(0, len(all_items), batch_size):
            batch = all_items[i:i + batch_size]
            batch_resources = [r for r in batch if r.get("type") in ("pamMachine", "pamDatabase", "pamDirectory", "pamRemoteBrowser")]
            batch_users = [r for r in batch if r.get("type") in ("login", "pamUser")]
            batch_num = (i // batch_size) + 1
            total_batches = (len(all_items) + batch_size - 1) // batch_size
            print(f"Processing batch {batch_num}/{total_batches} ({len(batch)} records)...")

            batch_start = time.time()

            if i == 0 and not config_uid:
                # First batch: create project skeleton + records
                first_batch_data = dict(import_data)
                first_batch_data["pam_data"] = {
                    "resources": batch_resources,
                    "users": batch_users,
                }
                tmp_path = _write_secure_temp_json(first_batch_data)
                try:
                    PAMProjectImportCommand().execute(
                        params, project_name=project_name, file_name=tmp_path, dry_run=False
                    )
                finally:
                    _remove_secure_temp(tmp_path)

                # For subsequent batches, we need the PAM config UID
                # Try to find it by project name
                if not config_uid:
                    config_uid = self._find_config_uid(params, project_name)
            else:
                # Subsequent batches: extend
                extend_data = build_extend_json(batch_resources, batch_users)
                tmp_path = _write_secure_temp_json(extend_data)
                try:
                    if config_uid:
                        PAMProjectExtendCommand().execute(
                            params, config=config_uid, file_name=tmp_path, dry_run=False
                        )
                    else:
                        logging.error("Cannot extend: PAM configuration UID not found after initial import")
                        break
                finally:
                    _remove_secure_temp(tmp_path)

            batch_duration_ms = (time.time() - batch_start) * 1000
            throttler.record_response(batch_duration_ms, True)
            if i + batch_size < len(all_items):
                throttler.wait()

        return {"project_name": project_name, "config_uid": config_uid}

    def _find_config_uid(self, params, project_name: str) -> str:
        """Find PAM configuration UID by project name after initial import.
        Handles #N suffix deduplication from PAMProjectImportCommand."""
        from ... import api, vault_extensions

        api.sync_down(params)
        config_base = f"{project_name} Configuration".casefold()
        candidates = []
        for c in vault_extensions.find_records(params, record_version=6):
            t = c.title.casefold()
            if t == config_base or (t.startswith(config_base) and re.match(r' #\d+$', t[len(config_base):])):
                candidates.append(c)
        if not candidates:
            logging.warning(f"PAM configuration not found for project '{project_name}' after import")
            return ""
        # Prefer highest suffix number (most recently created)
        # Sort numerically, not lexicographically (so #10 > #9)
        def _sort_key(c):
            m = re.search(r' #(\d+)$', c.title)
            return int(m.group(1)) if m else 0
        candidates.sort(key=_sort_key, reverse=True)
        return candidates[0].record_uid

    @staticmethod
    def _list_safes_detailed(safes: List[dict], system_excluded: int):
        """List safes with details for --list-safes output."""
        print(f'\n{bcolors.OKBLUE}Available CyberArk Safes:{bcolors.ENDC}')
        print('=' * 60)
        print(f'  {"#":<4s} {"Safe Name":<35s} {"CPM":>10s}')
        print('  ' + '-' * 55)
        for i, safe in enumerate(safes, 1):
            name = safe.get("safeName", "?")
            cpm = safe.get("managingCPM", "—") or "—"
            print(f'  {i:<4d} {name:<35s} {cpm:>10s}')
        print('  ' + '-' * 55)
        print(f'  Total: {len(safes)} safes')
        if system_excluded > 0:
            print(f'  ({system_excluded} system safes excluded — use --include-system-safes to show)')
        print()
        print('  Use --safes "Name1,Name2" to import specific safes')
        print('  Use --exclude-safes "Name1,Name2" to exclude safes')
        print('  Wildcards supported: --safes "Windows*,Unix*"')
        print()

    @staticmethod
    def _interactive_safe_picker(safes: List[dict]) -> Optional[str]:
        """Show safes and let user select which to import.

        Returns comma-separated safe names for apply_safe_filter,
        or None to import all.
        """
        print(f'\n{bcolors.OKBLUE}CyberArk Safes Found:{bcolors.ENDC}')
        print('─' * 50)
        numbered = []
        for i, safe in enumerate(safes, 1):
            name = safe.get("safeName", "?")
            numbered.append(name)
            print(f'  [{i}] {name}')
        print(f'\n  [A] Import ALL safes ({len(safes)})')
        print()

        try:
            choice = input(f'  Select safes (comma-separated numbers, or A for all) [A]: ').strip()
        except EOFError:
            return None

        if not choice or choice.upper() == 'A':
            return None

        selected = []
        for part in choice.split(','):
            part = part.strip()
            try:
                idx = int(part) - 1
                if 0 <= idx < len(numbered):
                    selected.append(numbered[idx])
            except ValueError:
                continue

        if not selected:
            return None

        logging.warning('Selected safes: %s', ', '.join(selected))
        return ','.join(selected)


class CyberArkPAMCleanupCommand(Command):
    """Delete all records and folders created by a CyberArk PAM import."""

    parser = argparse.ArgumentParser(
        prog="pam project cyberark-cleanup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Preview what would be deleted
  pam project cyberark-cleanup --name "CyberArk Migration" --dry-run

  # Delete by project name
  pam project cyberark-cleanup --name "CyberArk Migration" --yes

  # Delete by PAM config UID
  pam project cyberark-cleanup --config VxANFEPLi8E9gdtlDmfBvw --yes
        ''')
    parser.add_argument("--name", "-n", dest="project_name", action="store",
                        default="", help="Project name (matches PAM config title prefix)")
    parser.add_argument("--config", "-c", dest="config_uid", action="store",
                        default="", help="PAM config record UID")
    parser.add_argument("--dry-run", "-d", dest="dry_run", action="store_true",
                        default=False, help="Show what would be deleted")
    parser.add_argument("--yes", "-y", dest="auto_confirm", action="store_true",
                        default=False, help="Skip confirmation prompt")

    def get_parser(self):
        return CyberArkPAMCleanupCommand.parser

    def execute(self, params, **kwargs):
        project_name = kwargs.get("project_name", "")
        config_uid = kwargs.get("config_uid", "")
        dry_run = kwargs.get("dry_run", False)
        auto_confirm = kwargs.get("auto_confirm", False)

        if not project_name and not config_uid:
            raise CommandError("pam project cyberark-cleanup",
                               "Either --name or --config is required")

        from ... import api, vault, vault_extensions

        api.sync_down(params)

        # Find PAM config by name or UID
        if config_uid:
            config_rec = vault.KeeperRecord.load(params, config_uid)
            if not config_rec:
                raise CommandError("pam project cyberark-cleanup",
                                   f"PAM config record '{config_uid}' not found")
            project_name = config_rec.title.replace(" Configuration", "")
        else:
            config_base = f"{project_name} Configuration".casefold()
            config_rec = None
            for c in vault_extensions.find_records(params, record_version=6):
                if c.title.casefold().startswith(config_base):
                    config_rec = c
                    config_uid = c.record_uid
                    break
            if not config_rec:
                raise CommandError("pam project cyberark-cleanup",
                                   f"PAM config for project '{project_name}' not found")

        # Find shared folders
        res_name = f"{project_name} - Resources"
        usr_name = f"{project_name} - Users"
        sf_uids = []
        record_count = 0
        for sf_uid, sf in params.shared_folder_cache.items():
            name = sf.get("name_unencrypted", "")
            if name in (res_name, usr_name):
                sf_uids.append(sf_uid)
                records_in_sf = params.subfolder_record_cache.get(sf_uid, set())
                record_count += len(records_in_sf)

        print(f"\nCyberArk PAM Project Cleanup")
        print("=" * 50)
        print(f"  Project:   {project_name}")
        print(f"  Config:    {config_uid}")
        print(f"  Folders:   {len(sf_uids)}")
        print(f"  Records:   ~{record_count}")

        if dry_run:
            print("  (dry run — no changes made)")
            print("=" * 50)
            return

        if not auto_confirm:
            answer = input("\n  Delete all records and folders? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                print("  Cancelled.")
                return

        # Delete records in shared folders
        from ..record_edit import RecordDeleteCommand
        deleted = 0
        failed = 0
        for sf_uid in sf_uids:
            records = params.subfolder_record_cache.get(sf_uid, set())
            for rec_uid in list(records):
                try:
                    RecordDeleteCommand().execute(params, force=True, record=rec_uid)
                    deleted += 1
                except Exception as e:
                    failed += 1
                    logging.warning("Failed to delete record %s: %s",
                                    rec_uid, type(e).__name__)

        # Delete PAM config record
        try:
            RecordDeleteCommand().execute(params, force=True, record=config_uid)
            deleted += 1
        except Exception as e:
            failed += 1
            logging.warning("Failed to delete PAM config record %s: %s",
                            config_uid, type(e).__name__)

        api.sync_down(params)
        msg = f"\nCleanup complete: {deleted} records deleted"
        if failed:
            msg += f" ({failed} failed — see warnings above)"
        print(msg)
        print("=" * 50)
