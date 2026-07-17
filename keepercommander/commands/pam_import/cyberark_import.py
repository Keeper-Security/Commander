#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
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
from dataclasses import dataclass, field
from typing import Any, Optional

from prompt_toolkit import HTML, print_formatted_text

from ..base import Command
from ...display import bcolors
from ...error import CommandError
from ...importer.cyberark.cyberark_pam import (
    _esc,
    CyberArkPVWAClient,
    AccountMapper,
    StrictPolicyError,
    MasterPolicyMapper,
    UserTeamMatcher,
    PermissionMapper,
    SafeFolderMapper,
    AdaptiveThrottler,
    SessionRecordingResolver,
    apply_safe_filter,
    exclude_system_safes,
    resolve_account_dependents,
    resolve_linked_accounts,
    pick_admin_credentials,
    pick_launch_credentials,
    detect_dual_account,
    build_import_json,
    build_extend_json,
    build_report,
    build_safe_folders,
    format_duration,
    strip_credentials,
    validate_import_data,
    RECORD_TYPE_LOGIN,
    RECORD_TYPE_PAM_MACHINE,
    RECORD_TYPE_PAM_DATABASE,
    RECORD_TYPE_PAM_DIRECTORY,
    SCHEDULE_ON_DEMAND,
    ROTATION_UNMAPPED,
)
from ...importer.cyberark.pam.idempotency import (
    ExistingRecordIndex,
    IdempotencyDecision,
    PartitionSummary,
    RecordDecision,
    annotate_record_with_marker,
    build_existing_index,
    partition_records,
    strip_id_marker,
    summarize,
)


class SecureTempFileStore:
    """Writes JSON to owner-only temp files and securely wipes them on removal."""

    def __init__(self):
        self._pending: set[str] = set()
        atexit.register(self.cleanup_all)

    def cleanup_all(self):
        for path in list(self._pending):
            self.remove(path)

    def write_json(self, data: dict) -> str:
        tmp_dir = tempfile.gettempdir()
        tmp_fd, tmp_path = tempfile.mkstemp(
            suffix='.json', prefix='keeper_ca_import_', dir=tmp_dir,
        )
        try:
            with os.fdopen(tmp_fd, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        self._pending.add(tmp_path)
        return tmp_path

    def remove(self, tmp_path: str):
        try:
            if os.path.exists(tmp_path):
                size = os.path.getsize(tmp_path)
                with open(tmp_path, 'wb') as fh:
                    fh.write(b'\x00' * size)
                os.unlink(tmp_path)
        except OSError:
            pass
        self._pending.discard(tmp_path)


_temp_store = SecureTempFileStore()


def _write_secure_temp_json(data: dict) -> str:
    """Backward-compatible alias for tests and external callers."""
    return _temp_store.write_json(data)


def _remove_secure_temp(tmp_path: str):
    """Backward-compatible alias for tests and external callers."""
    _temp_store.remove(tmp_path)


@dataclass
class ImportRunOptions:
    """Normalized CLI options for a single import run."""

    server: str
    project_name: str
    config_uid: str
    gateway_name: str
    folder_mode: str
    dry_run: bool
    output_file: str
    include_creds: bool
    estimate_only: bool
    skip_confirm: bool
    skip_users: bool
    skip_linked: bool
    skip_members: bool
    skip_dependents: bool
    safe_include: str
    safe_exclude: str
    list_safes: bool
    batch_size: int
    batch_delay: float
    platform_map_override: Optional[dict]
    state_filter: Optional[list[str]]
    include_system_safes: bool
    user_map_file: str
    sync_mode: str = "upsert"
    strict_policies: bool = False
    raw_kwargs: dict = field(default_factory=dict)


@dataclass
class MappedImportResult:
    """Output of the account-mapping phase."""

    pam_resources: list[dict]
    pam_users: list[dict]
    incomplete: list[dict]
    skipped: list[dict]
    platform_counts: dict[str, dict]
    total_accounts: int
    accounts_by_safe: dict[str, list[dict]]
    mapper: AccountMapper
    folder_mapper: SafeFolderMapper
    unmapped_items: list[dict]
    dependents: list[dict] = field(default_factory=list)
    import_duration: float = 0.0


class CyberArkImportOrchestrator:
    """Coordinates CyberArk PVWA fetch → map → vault import phases (SRP)."""

    def __init__(self, command: 'CyberArkPAMImportCommand', params, client: CyberArkPVWAClient,
                 options: ImportRunOptions):
        self._cmd = command
        self.params = params
        self.client = client
        self.options = options
        self._temp = _temp_store

    def run(self) -> None:
        unmapped_items: list[dict] = []
        master_policy_config = self._load_master_policy(unmapped_items)
        safes, system_excluded = self._prepare_safes()
        if not safes:
            return
        if self.options.list_safes:
            self._cmd._list_safes_detailed(safes, system_excluded)
            return
        safes = self._maybe_interactive_safe_pick(safes)
        if not safes:
            return
        safe_names = [s.get("safeUrlId", s["safeName"]) for s in safes]
        safe_member_map, member_unmapped = self._fetch_safe_members(safe_names)
        unmapped_items.extend(member_unmapped)
        user_team_matcher = self._build_user_team_matcher()
        accounts_by_safe = self._fetch_accounts(safe_names)
        total_accounts = sum(len(v) for v in accounts_by_safe.values())
        if total_accounts == 0:
            print_formatted_text(HTML("<ansiyellow>No accounts found in selected safes</ansiyellow>"))
            return
        if self.options.estimate_only:
            self._print_estimate(len(accounts_by_safe), total_accounts)
            return
        self._maybe_auto_extend()
        mapped = self._map_accounts(
            accounts_by_safe, safe_names, master_policy_config, unmapped_items,
        )
        unmapped_items.extend(mapped.mapper.platform_workflow_unmapped)
        self._print_mapping_summary(mapped, unmapped_items)
        validation_warnings = validate_import_data(mapped.pam_resources, mapped.pam_users)
        if validation_warnings:
            self._print_validation_warnings(validation_warnings)
        idempotency_ctx = self._prepare_idempotency(mapped)
        import_data = self._build_import_payload(
            mapped, safe_member_map, user_team_matcher, master_policy_config,
        )
        if self.options.output_file:
            self._write_output_file(import_data)
            return
        if self.options.dry_run:
            self._print_dry_run(import_data, mapped)
            return
        if not self._confirm_import(mapped, idempotency_ctx):
            return
        # Apply the partition to the import payload just before we
        # call pam project import/extend, so create-only records go
        # through and update / unchanged records are handled out of
        # band. Done here (not earlier) so the report accurately
        # reflects what the mapper produced from CyberArk, not what
        # survived the idempotency filter. ``mapped`` is passed so
        # the filter can mutate ``pam_resources`` / ``pam_users`` in
        # place — ``_execute_vault_import`` reads those lists
        # directly for the multi-batch path, not the ``import_data``
        # dict, so any filtered-out record must be dropped from both
        # views simultaneously.
        if idempotency_ctx:
            self._apply_idempotency_filter(import_data, mapped, idempotency_ctx)
        # Skip the vault write entirely when every mapped record was
        # already up to date — avoids a no-op ``pam project extend``
        # round-trip and lets the report acknowledge "nothing to do".
        # We still run the update path in case any records were
        # tagged as UPDATE (their data changed even though no new
        # records need to be created).
        skip_vault_import = (
            idempotency_ctx is not None
            and not mapped.pam_resources
            and not mapped.pam_users
        )
        if skip_vault_import:
            project_result = {
                "project_name": self.options.project_name,
                "config_uid": self.options.config_uid,
                "folders": {},
            }
            self._populate_folder_info(project_result, self.options.project_name)
        else:
            project_result = self._execute_vault_import(import_data, mapped)
        if idempotency_ctx and project_result is not None:
            update_summary = self._apply_record_updates(idempotency_ctx)
            idempotency_ctx["update_summary"] = update_summary
        self._finalize_report(
            mapped, mapped.unmapped_items, project_result, total_accounts,
            user_team_matcher, idempotency_ctx,
        )

    def _load_master_policy(self, unmapped_items: list[dict]) -> dict:
        master_policy_config = dict(MasterPolicyMapper.DEFAULTS)
        print_formatted_text(HTML("Fetching Master Policy..."))
        policy_data = self.client.fetch_master_policy()
        if policy_data:
            self._log_master_policy_raw(policy_data)
            master_policy_config, mp_unmapped = MasterPolicyMapper.map_policy(policy_data)
            unmapped_items.extend(mp_unmapped)
        else:
            logging.warning(
                '%sMaster Policy not accessible — using defaults. '
                'Review PAM config settings manually.%s',
                bcolors.WARNING, bcolors.ENDC,
            )
        # Logs the raw exceptions JSON at INFO internally; returns None when
        # the tenant doesn't expose a real per-platform list (common — see
        # fetch_master_rotation_policy_exceptions docstring), in which case
        # AccountMapper falls back to the per-platform rotation-policy check.
        exceptions_raw = self.client.fetch_master_rotation_policy_exceptions()
        master_policy_config["rotation_exception_schedules"] = (
            MasterPolicyMapper.parse_rotation_exceptions(exceptions_raw)
            if exceptions_raw else {}
        )
        try:
            master_sm = self.client.fetch_master_session_monitoring()
        except Exception as e:  # noqa: BLE001 — never block import on optional fetch
            logging.debug('Master session-monitoring fetch failed: %s', type(e).__name__)
            master_sm = None
        master_policy_config = SessionRecordingResolver.apply_to_master_config(
            master_policy_config, master_sm,
        )
        if master_sm and master_policy_config.get("graphical_session_recording") == "on":
            logging.debug(
                'Master session-monitoring resolved to ON — '
                'PAM Configuration session recording will be enabled.',
            )
        if policy_data:
            self._print_master_policy_summary(master_policy_config)
        return master_policy_config

    @staticmethod
    def _log_master_policy_raw(policy_data: dict):
        try:
            logging.debug(
                'CyberArk Master Policy (raw response):\n%s',
                json.dumps(policy_data, indent=2, sort_keys=True),
            )
        except (TypeError, ValueError) as e:
            logging.error("Could not serialize Master Policy for display: %s", type(e).__name__)

    @staticmethod
    def _print_master_policy_summary(master_policy_config: dict):
        sched = master_policy_config.get("default_rotation_schedule") or {}
        sched_type = str(sched.get("type", SCHEDULE_ON_DEMAND)).lower().replace("_", "-")
        if sched_type == "cron":
            rotation_summary = (
                f"every {master_policy_config.get('password_change_days', 0)} days "
                f"({sched.get('cron', '')})"
            )
        else:
            rotation_summary = SCHEDULE_ON_DEMAND
        exc_schedules = master_policy_config.get("rotation_exception_schedules") or {}
        exc_note = ""
        if exc_schedules:
            exc_note = (
                f", rotation_exceptions=<b>{len(exc_schedules)} platform(s)</b>"
            )
        print_formatted_text(HTML(
            f"Master Policy: session_recording="
            f"<b>{master_policy_config.get('graphical_session_recording', 'off')}</b>, "
            f"connections=<b>{master_policy_config.get('connections', 'on')}</b>, "
            f"rotation=<b>{_esc(rotation_summary)}</b>{exc_note}"))

    def _prepare_safes(self) -> tuple[list[dict], int]:
        all_safes = self.client.fetch_safes()
        if not all_safes:
            return [], 0
        safes = exclude_system_safes(
            all_safes, include_system=self.options.include_system_safes,
        )
        system_excluded = len(all_safes) - len(safes)
        safes = apply_safe_filter(
            safes,
            self.options.safe_include or None,
            self.options.safe_exclude or None,
        )
        if not safes:
            print_formatted_text(HTML("<ansiyellow>No safes match the filter criteria</ansiyellow>"))
        return safes, system_excluded

    def _maybe_interactive_safe_pick(self, safes: list[dict]) -> list[dict]:
        opts = self.options
        if (opts.safe_include or opts.safe_exclude or opts.skip_confirm
                or opts.dry_run or opts.output_file
                or getattr(self.params, 'batch_mode', False)):
            return safes
        selected = self._cmd._interactive_safe_picker(safes)
        if selected is None:
            return safes
        selected_set = {n.strip() for n in selected.split(',')}
        picked = [s for s in safes if s.get("safeName", "") in selected_set]
        if not picked:
            print_formatted_text(HTML("<ansiyellow>No safes selected</ansiyellow>"))
        return picked

    def _fetch_safe_members(self, safe_names: list[str]) -> tuple[dict, list[dict]]:
        opts = self.options
        if opts.skip_members or opts.dry_run:
            return {}, []
        print_formatted_text(HTML(
            f"\nFetching safe members from <b>{len(safe_names)}</b> safes..."))
        safe_member_map: dict[str, list[dict]] = {}
        member_unmapped: list[dict] = []
        for safe_url_id in safe_names:
            mapped = []
            for m in self.client.fetch_safe_members(safe_url_id):
                mapped_member = PermissionMapper.map_member(m)
                mapped.append(mapped_member)
                for up in mapped_member.get("unmapped_permissions", []):
                    member_unmapped.append({
                        "category": "Safe member permission",
                        "item": f"{mapped_member['name']} in {safe_url_id}",
                        "action": f"CyberArk permission '{up}' has no Keeper equivalent",
                    })
            if mapped:
                safe_member_map[safe_url_id] = mapped
        total_members = sum(len(v) for v in safe_member_map.values())
        print_formatted_text(HTML(
            f"Found <b>{total_members}</b> members across "
            f"<b>{len(safe_member_map)}</b> safes"))
        return safe_member_map, member_unmapped

    def _build_user_team_matcher(self) -> Optional[UserTeamMatcher]:
        opts = self.options
        if opts.skip_users or opts.skip_members or opts.dry_run:
            return None
        print_formatted_text(HTML("\nFetching CyberArk vault users and groups..."))
        ca_users = self.client.fetch_users()
        ca_groups = self.client.fetch_user_groups()
        user_map_override = self._load_user_map_override()
        keeper_users, keeper_teams = self._load_keeper_identities()
        matcher = UserTeamMatcher(
            keeper_users=keeper_users,
            keeper_teams=keeper_teams,
            user_map_override=user_map_override,
        )
        print_formatted_text(HTML(
            f"Found <b>{len(ca_users)}</b> vault users, <b>{len(ca_groups)}</b> groups"))
        return matcher

    def _load_user_map_override(self) -> Optional[dict]:
        path = self.options.user_map_file
        if not path:
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise CommandError(
                    "pam project cyberark-import",
                    f"--user-map file must contain a JSON object, got {type(data).__name__}",
                )
            return data
        except (FileNotFoundError, ValueError) as e:
            raise CommandError("pam project cyberark-import",
                               f"Failed to load --user-map file: {e}") from e

    def _load_keeper_identities(self) -> tuple[list[dict], list[dict]]:
        keeper_users: list[dict] = []
        keeper_teams: list[dict] = []
        if hasattr(self.params, 'enterprise') and self.params.enterprise:
            for u in self.params.enterprise.get('users', []):
                keeper_users.append({
                    'email': u.get('username', ''),
                    'username': u.get('username', ''),
                })
        else:
            logging.warning(
                '%sEnterprise data not available — all safe members will appear as '
                'unmatched. Ensure you are logged in as an enterprise admin.%s',
                bcolors.WARNING, bcolors.ENDC,
            )
        if hasattr(self.params, 'available_team_cache') and self.params.available_team_cache:
            for t in self.params.available_team_cache:
                keeper_teams.append({'name': t.get('team_name', '')})
        return keeper_users, keeper_teams

    def _fetch_accounts(self, safe_names: list[str]) -> dict[str, list[dict]]:
        print_formatted_text(HTML(
            f"\nFetching accounts from <b>{len(safe_names)}</b> safes..."))
        return self.client.fetch_accounts(safe_names, state_filter=self.options.state_filter)

    @staticmethod
    def _print_estimate(safe_count: int, total_accounts: int):
        est_seconds = total_accounts * 3
        print(f"\nSafes:    {safe_count}")
        print(f"Accounts: {total_accounts}")
        print(f"Estimated import time: ~{format_duration(est_seconds)}")


    def _map_accounts(self, accounts_by_safe: dict[str, list[dict]], safe_names: list[str],
                      master_policy_config: dict,
                      unmapped_items: list[dict]) -> MappedImportResult:
        opts = self.options
        try:
            ca_platforms = self.client.fetch_platforms()
            if ca_platforms:
                logging.debug(
                    "Loaded %d CyberArk platform definitions for mapping", len(ca_platforms),
                )
        except Exception as e:
            logging.error("fetch_platforms failed (%s) — proceeding without platform metadata",
                          type(e).__name__)
            ca_platforms = []
        mapper = AccountMapper(
            opts.platform_map_override,
            platforms=ca_platforms,
            client=self.client,
            default_rotation_schedule=master_policy_config.get("default_rotation_schedule"),
            master_rotation_exceptions=master_policy_config.get(
                "rotation_exception_schedules"),
            master_change_days=master_policy_config.get("password_change_days", 0),
            strict_policies=opts.strict_policies,
        )
        folder_mapper = SafeFolderMapper(mode=opts.folder_mode)
        pam_resources: list[dict] = []
        pam_users: list[dict] = []
        incomplete: list[dict] = []
        skipped: list[dict] = []
        platform_counts: dict[str, dict] = {}
        skip_all_passwords: dict[str, bool] = {}
        dependents: list[dict] = []
        for safe_name, accounts in accounts_by_safe.items():
            for account in accounts:
                self._map_single_account(
                    account, safe_name, mapper, folder_mapper, master_policy_config,
                    pam_resources, pam_users, incomplete, skipped, platform_counts,
                    skip_all_passwords, unmapped_items, dependents,
                )
        return MappedImportResult(
            pam_resources=pam_resources,
            pam_users=pam_users,
            incomplete=incomplete,
            skipped=skipped,
            platform_counts=platform_counts,
            total_accounts=sum(len(v) for v in accounts_by_safe.values()),
            accounts_by_safe=accounts_by_safe,
            mapper=mapper,
            folder_mapper=folder_mapper,
            unmapped_items=unmapped_items,
            dependents=dependents,
        )

    def _map_single_account(
        self, account: dict, safe_name: str, mapper: AccountMapper,
        folder_mapper: SafeFolderMapper, master_policy_config: dict,
        pam_resources: list[dict], pam_users: list[dict], incomplete: list[dict],
        skipped: list[dict], platform_counts: dict[str, dict],
        skip_all_passwords: dict, unmapped_items: list[dict],
        dependents: list[dict],
    ):
        opts = self.options
        if not isinstance(account, dict):
            logging.error("Skipping account mapping: expected dict, got %s", type(account).__name__)
            return
        # CyberArk API field is camelCase and case-sensitive.
        platform_id = account.get("platformId") or "Unknown"
        if platform_id not in platform_counts:
            mapping = mapper.platform_map.get(platform_id)
            if not isinstance(mapping, dict):
                mapping = {}
            platform_counts[platform_id] = {
                "rotation": mapping.get("rotation", ROTATION_UNMAPPED),
                "count": 0,
            }
        platform_counts[platform_id]["count"] += 1
        is_incomplete, reason = mapper.is_incomplete(account)
        # Hold the retrieved credential as ``token`` (not ``password``) so
        # accidental log formatting is less likely to leak the secret name.
        # Clear it immediately after map_account copies it into the record.
        token = None
        record = None
        try:
            if not opts.dry_run or opts.include_creds:
                token = self.client.retrieve_password(
                    account.get("id", ""),
                    account_name=account.get("name", ""),
                    safe_name=safe_name,
                    skip_all=skip_all_passwords,
                )
                if token is None:
                    skipped.append({
                        "account": account.get("name", ""),
                        "safe": safe_name,
                        "reason": "password retrieval failed",
                    })
                    return
            try:
                record = mapper.map_account(account, token, safe_name)
            except StrictPolicyError as e:
                raise CommandError("pam project cyberark-import", str(e)) from e
        finally:
            # Drop the local plaintext reference as soon as mapping finishes
            # (or fails). The record dict still holds the credential for vault
            # import when needed — that is intentional and short-lived.
            token = None
        if not isinstance(record, dict):
            skipped.append({
                "account": account.get("name", ""),
                "safe": safe_name,
                "reason": f"unmappable platformId: {platform_id}",
            })
            return
        # Embed the CyberArk identity marker on every mapped record so
        # future re-imports can match incoming accounts to already-created
        # Keeper records (see importer/cyberark/pam/idempotency.py). The
        # marker is a single line in ``notes`` — cheap to carry and
        # survives the pam project import path unchanged (unlike ``custom``
        # fields, which PamBaseMachineParser does not preserve).
        account_id = str(account.get("id", "") or "").strip()
        if account_id:
            annotate_record_with_marker(record, account_id, safe_name)
            for nested in record.get("users") or []:
                if not isinstance(nested, dict):
                    continue
                # Nested pamUsers share the parent account's CyberArk id
                # because CyberArk models the credential+resource as a
                # single account.  The marker is idempotent so re-runs
                # can update the pamUser independently from its parent.
                annotate_record_with_marker(nested, account_id, safe_name)
        self._apply_folder_paths(record, safe_name, folder_mapper)
        if is_incomplete:
            record["notes"] = f"INCOMPLETE: {reason}"
            incomplete.append(record)
        dual_fields = detect_dual_account(account)
        if dual_fields:
            record.setdefault("custom", [])
            for key, val in dual_fields.items():
                record["custom"].append({"type": "text", "label": key, "value": [val]})
            unmapped_items.append({
                "category": "Dual account pair",
                "item": account.get("name", ""),
                "action": "Exclusive rotation behavior requires manual "
                          "configuration in KeeperPAM rotation settings",
            })
        if (not opts.skip_linked and not opts.dry_run and not opts.skip_users
                and record.get("type") != RECORD_TYPE_LOGIN):
            self._attach_linked_accounts(record, account, safe_name, folder_mapper)
        self._collect_dependents(account, record, dependents, unmapped_items)
        if record.get("type") == RECORD_TYPE_LOGIN:
            pam_users.append(record)
        else:
            if opts.skip_users:
                record.pop("users", None)
            pam_resources.append(record)

    def _collect_dependents(self, account: dict, record: dict,
                            dependents: list[dict], unmapped_items: list[dict]):
        """Resolve CyberArk dependents (services/tasks/IIS pools) for ``account``
        and append them to ``dependents`` for post-import service mapping.

        The "user" the service runs as is the nested pamUser record on this
        resource (we use its title as the lookup key). Non-pamMachine records
        (login, pamDatabase) cannot host a Windows service, so they're skipped.
        Categories with no Keeper equivalent (e.g. COM+) are recorded in
        ``unmapped_items`` so admins can act on them manually.
        """
        opts = self.options
        if opts.skip_dependents or opts.dry_run:
            return
        if not isinstance(account, dict) or not isinstance(record, dict):
            logging.error(
                "Skipping dependents: account/record must be dicts (got %s / %s)",
                type(account).__name__, type(record).__name__,
            )
            return
        # Keeper record types are case-sensitive (pamMachine ≠ Pammachine).
        if record.get("type") != RECORD_TYPE_PAM_MACHINE:
            return
        users = record.get("users") or []
        if not isinstance(users, list) or not users:
            return
        first_user = users[0] if isinstance(users[0], dict) else {}
        master_user_title = first_user.get("title", "") or ""
        if not master_user_title:
            return
        try:
            account_dependents = resolve_account_dependents(
                self.client, account, master_user_title,
            )
        except Exception as e:  # noqa: BLE001 — never block import on optional fetch
            logging.error('Dependents resolution failed for %s: %s',
                          account.get("name", "?"), type(e).__name__)
            return
        if not account_dependents:
            return
        if not isinstance(account_dependents, list):
            logging.error(
                "Dependents resolution returned non-list for %s: %s",
                account.get("name", "?"), type(account_dependents).__name__,
            )
            return
        machine_title = record.get("title", "")
        for dep in account_dependents:
            if not isinstance(dep, dict):
                continue
            dep["machine_title"] = machine_title
            if dep.get("service_type") is None:
                unmapped_items.append({
                    "category": "CyberArk dependent",
                    "item": (f"{dep.get('service_name') or '?'} "
                             f"({dep.get('raw_type') or 'unknown'}) "
                             f"on {dep.get('machine_address', '?')}"),
                    "action": "No KeeperPAM equivalent for this dependent type "
                              "— configure manually if required",
                })
            dependents.append(dep)
        # Surface progress + a per-dependent breakdown so the operator can see
        # exactly what the importer parsed before the post-import phase runs.
        print_formatted_text(HTML(
            f"Found <b>{len(account_dependents)}</b> CyberArk dependent(s) "
            f"on account <b>{_esc(account.get('name', '?'))}</b>"))
        for dep in account_dependents:
            mapped_to = dep.get("service_type") or "(unsupported)"
            print_formatted_text(HTML(
                f"  • <b>{_esc(dep.get('service_name', '') or '?')}</b> "
                f"({_esc(dep.get('raw_type', '') or 'unknown')}) "
                f"on <b>{_esc(dep.get('machine_address', '') or '?')}</b> "
                f"→ pam action service <b>{_esc(mapped_to)}</b>"))

    def _apply_folder_paths(self, record: dict, safe_name: str,
                            folder_mapper: SafeFolderMapper):
        opts = self.options
        if opts.folder_mode == "flat":
            return
        safe_folder = folder_mapper.map_safe(safe_name, opts.project_name)
        if not safe_folder:
            return
        if opts.folder_mode == "safe":
            # ``safe`` mode: each safe is its own root shared folder
            # under the project wrapper, with two organizational
            # subfolders inside — ``{safe} - Resources`` for the asset
            # records (pamMachine / pamDatabase / pamDirectory /
            # pamRemoteBrowser) and ``{safe} - Users`` for the
            # credential records (pamUser nested under a resource, plus
            # standalone ``login`` records). Prefixing the subfolder
            # names with the safe name makes them unambiguous in the
            # Keeper UI even when expanded out of their parent folder
            # context. The safe's permission set is granted at the
            # shared-folder level, so both subfolders inherit it
            # automatically — we only need to route records to the
            # right subfolder.
            res_sub = f"{safe_folder}/{safe_folder} - Resources"
            usr_sub = f"{safe_folder}/{safe_folder} - Users"
            if record.get("type") == RECORD_TYPE_LOGIN:
                record["folder_path"] = usr_sub
            else:
                record["folder_path"] = res_sub
            for u in record.get("users", []):
                u["folder_path"] = usr_sub
            return
        res_root = f"{opts.project_name} - Resources"
        usr_root = f"{opts.project_name} - Users"
        if record.get("type") == RECORD_TYPE_LOGIN:
            record["folder_path"] = f"{usr_root}/{safe_folder}"
        else:
            record["folder_path"] = f"{res_root}/{safe_folder}"
        for u in record.get("users", []):
            u["folder_path"] = f"{usr_root}/{safe_folder}"

    def _attach_linked_accounts(self, record: dict, account: dict, safe_name: str,
                                folder_mapper: SafeFolderMapper):
        linked_users = resolve_linked_accounts(self.client, account)
        if not linked_users:
            return
        record.setdefault("users", []).extend(linked_users)
        admin_title, admin_role = pick_admin_credentials(linked_users)
        if admin_title:
            conn = record.setdefault("pam_settings", {}).setdefault("connection", {})
            conn["administrative_credentials"] = admin_title
            logging.info("Mapped %s account '%s' as administrative_credentials on '%s'",
                         admin_role, admin_title, record.get("title", ""))
        logon_title = pick_launch_credentials(linked_users)
        if logon_title:
            conn = record.setdefault("pam_settings", {}).setdefault("connection", {})
            conn["launch_credentials"] = logon_title
            logging.info("Overrode launch_credentials with logon account '%s' on '%s'",
                         logon_title, record.get("title", ""))
        if self.options.folder_mode != "flat":
            safe_folder = folder_mapper.map_safe(safe_name, self.options.project_name)
            if safe_folder:
                if self.options.folder_mode == "safe":
                    usr_sub = f"{safe_folder}/{safe_folder} - Users"
                    for lu in linked_users:
                        lu["folder_path"] = usr_sub
                else:
                    usr_root = f"{self.options.project_name} - Users"
                    for lu in linked_users:
                        lu["folder_path"] = f"{usr_root}/{safe_folder}"

    def _print_mapping_summary(self, mapped: MappedImportResult, unmapped_items: list[dict]):
        resource_count = len(mapped.pam_resources)
        user_count = sum(len(r.get("users", [])) for r in mapped.pam_resources)
        login_count = len(mapped.pam_users)
        print()
        print(f"{bcolors.OKBLUE}Mapped {mapped.total_accounts} CyberArk accounts:{bcolors.ENDC}")
        print(f"  Resources (pamMachine/pamDatabase): {resource_count}")
        print(f"  Users (pamUser, nested):            {user_count}")
        print(f"  Logins (BusinessWebsite):           {login_count}")
        if unmapped_items:
            print(f"  {bcolors.WARNING}Unmapped (manual action needed):  {len(unmapped_items)}{bcolors.ENDC}")
        if mapped.incomplete:
            print(f"  {bcolors.WARNING}Incomplete:                         {len(mapped.incomplete)}{bcolors.ENDC}")
        if mapped.skipped:
            print(f"  {bcolors.WARNING}Skipped:                            {len(mapped.skipped)}{bcolors.ENDC}")
        mapper = mapped.mapper
        if mapper.unmapped_platforms:
            print(f"  {bcolors.WARNING}Unmapped platforms (defaulted):     "
                  f"{sum(mapper.unmapped_platforms.values())}{bcolors.ENDC}")
            for pid, cnt in mapper.unmapped_platforms.items():
                print(f"    {pid}: {cnt} accounts")
        if mapper.platform_schedule_overrides:
            total_overrides = sum(mapper.platform_schedule_overrides.values())
            print(f"  {bcolors.OKBLUE}Platform rotation-policy overrides: {total_overrides}{bcolors.ENDC}")
            for pid, cnt in sorted(mapper.platform_schedule_overrides.items()):
                cached = mapper._platform_schedule_cache.get(pid) or {}
                cron = cached.get("cron", cached.get("type", "?"))
                print(f"    {pid}: {cnt} accounts -> {cron}")
        if mapper.platform_recording_overrides:
            total_rec = sum(mapper.platform_recording_overrides.values())
            print(f"  {bcolors.OKBLUE}Platform session-recording overrides: {total_rec}{bcolors.ENDC}")
            for pid, cnt in sorted(mapper.platform_recording_overrides.items()):
                rec = mapper._platform_session_cache.get(pid) or ("?", "?")
                print(f"    {pid}: {cnt} resources -> graphical={rec[0]}")
        if mapper.platform_complexity_overrides:
            total_pc = sum(mapper.platform_complexity_overrides.values())
            print(f"  {bcolors.OKBLUE}Platform password-complexity overrides: {total_pc}{bcolors.ENDC}")
            for pid, cnt in sorted(mapper.platform_complexity_overrides.items()):
                cx = mapper._platform_complexity_cache.get(pid) or "?"
                print(f"    {pid}: {cnt} accounts -> {cx}  (length,upper,lower,digits,symbols)")
        if mapper._platform_metadata_cache:
            total_md = sum(1 for v in mapper._platform_metadata_cache.values() if v)
            if total_md:
                print(f"  {bcolors.OKBLUE}Platform metadata custom fields: "
                      f"{total_md} platform(s) emitted CyberArk metadata{bcolors.ENDC}")
                for pid, fields in sorted(mapper._platform_metadata_cache.items()):
                    if fields:
                        print(f"    {pid}: {len(fields)} field(s)")
        print()

    @staticmethod
    def _print_validation_warnings(validation_warnings: list[str]):
        print_formatted_text(HTML(
            f"\n<ansiyellow>⚠ {len(validation_warnings)} validation warning(s):</ansiyellow>"))
        for w in validation_warnings:
            print_formatted_text(HTML(f"  <ansiyellow>• {_esc(w)}</ansiyellow>"))
        print()

    def _build_import_payload(self, mapped: MappedImportResult, safe_member_map: dict,
                              user_team_matcher: Optional[UserTeamMatcher],
                              master_policy_config: dict) -> dict:
        opts = self.options
        if opts.config_uid:
            return build_extend_json(mapped.pam_resources, mapped.pam_users)
        return build_import_json(
            project_name=opts.project_name,
            gateway_name=opts.gateway_name or None,
            resources=mapped.pam_resources,
            users=mapped.pam_users,
            safe_member_map=safe_member_map or None,
            user_team_matcher=user_team_matcher,
            master_policy_config=master_policy_config,
            folder_mapper=mapped.folder_mapper,
        )

    def _write_output_file(self, import_data: dict):
        output_data = copy.deepcopy(import_data)
        if not self.options.include_creds:
            strip_credentials(output_data)
        fd = os.open(
            self.options.output_file,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(output_data, fh, indent=2)
        print(f"Import JSON saved to: {self.options.output_file}")

    def _print_dry_run(self, import_data: dict, mapped: MappedImportResult):
        resource_count = len(mapped.pam_resources)
        user_count = sum(len(r.get("users", [])) for r in mapped.pam_resources)
        login_count = len(mapped.pam_users)
        print("[DRY RUN] No changes will be made to the vault.\n")
        output_data = copy.deepcopy(import_data)
        if not self.options.include_creds:
            strip_credentials(output_data)
        print(json.dumps(output_data, indent=2))
        print()
        print(f"[DRY RUN COMPLETE] {resource_count} resources, {user_count} users, "
              f"{login_count} logins would be imported.")

    def _confirm_import(self, mapped: MappedImportResult,
                        idempotency_ctx: Optional[dict] = None) -> bool:
        opts = self.options
        if opts.skip_confirm:
            return True
        resource_count = len(mapped.pam_resources)
        user_count = sum(len(r.get("users", [])) for r in mapped.pam_resources)
        login_count = len(mapped.pam_users)
        print(f"Ready to import {resource_count} resources, {user_count} users, "
              f"{login_count} logins into project '{opts.project_name}'.")
        if opts.config_uid:
            print(f"Extending existing PAM configuration: {opts.config_uid}")
        else:
            print("A new PAM project will be created.")
        # Surface the create / update / unchanged breakdown so the
        # operator knows exactly what will happen before we touch the
        # vault.  Without this a re-run against an existing project
        # looks like it's about to create hundreds of duplicates when
        # in fact most of the mapped records are unchanged and will be
        # silently skipped.
        if idempotency_ctx:
            summary = idempotency_ctx.get("partition_summary")
            if summary is not None:
                print(
                    f"Sync plan (--sync-mode={opts.sync_mode}): "
                    f"{bcolors.OKGREEN}{summary.created} to create{bcolors.ENDC}, "
                    f"{bcolors.OKBLUE}{summary.updated} to update{bcolors.ENDC}, "
                    f"{bcolors.WARNING}{summary.unchanged} unchanged{bcolors.ENDC}"
                )
                for dec in idempotency_ctx.get("decisions", []):
                    if dec.decision is not IdempotencyDecision.UPDATE:
                        continue
                    title = (dec.incoming.get("title") or dec.account_id or "?")
                    fields = ", ".join(dec.change_fields) or "(none)"
                    print(f"    • update {title}: {fields}")
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Import cancelled.")
            return False
        return True

    def _execute_vault_import(self, import_data: dict,
                              mapped: MappedImportResult) -> Optional[dict]:
        opts = self.options
        import_start = time.time()
        try:
            result = self._cmd._execute_import(
                self.params, import_data, opts.project_name, opts.config_uid,
                opts.batch_size, opts.batch_delay,
                mapped.pam_resources, mapped.pam_users,
            )
        except Exception as e:
            logging.error("Import failed: %s", type(e).__name__)
            logging.debug("Import error details: %s", e)
            logging.debug("Import traceback:", exc_info=True)
            print_formatted_text(HTML(f"\nImport <ansired>failed</ansired>: {type(e).__name__}"))
            return None
        mapped.import_duration = time.time() - import_start
        # Augment ``project_result`` with the actual shared folders that
        # got created under the project wrapper so build_report can list
        # them. PAMProjectImportCommand doesn't return this info, so we
        # rediscover it from the synced folder cache.
        if isinstance(result, dict):
            result.setdefault("folders", {})
            self._populate_folder_info(result, opts.project_name)
        return result

    def _populate_folder_info(self, project_result: dict, project_name: str) -> None:
        """Fill ``project_result['folders']`` with the freshly-created
        shared folders so the post-import report shows the safe-per-
        folder layout. Best-effort — failures here don't affect the
        import itself.
        """
        from ... import api as _api  # noqa: WPS433 — local import to mirror style
        try:
            _api.sync_down(self.params)
        except Exception:  # noqa: BLE001
            pass

        wrapper_uids = CyberArkPAMCleanupCommand._find_project_wrapper_folder_uids(
            self.params, project_name,
        )
        if not wrapper_uids:
            return

        folders_info = project_result.get("folders") or {}
        safe_folders: list[dict] = []
        config_folder_uid = ""
        config_folder_name = ""
        legacy_resources_uid = ""
        legacy_resources_name = ""
        legacy_users_uid = ""
        legacy_users_name = ""
        config_suffix = f"{project_name} - Config"
        resources_suffix = f"{project_name} - Resources"
        users_suffix = f"{project_name} - Users"

        seen_uids: set = set()
        for wrapper_uid in wrapper_uids:
            wrapper = self.params.folder_cache.get(wrapper_uid)
            if not wrapper:
                continue
            for child_uid in getattr(wrapper, "subfolders", []) or []:
                child = self.params.folder_cache.get(child_uid)
                if not child or getattr(child, "type", "") != "shared_folder":
                    continue
                if child.uid in seen_uids:
                    continue
                seen_uids.add(child.uid)
                name = getattr(child, "name", "") or ""
                if name == config_suffix:
                    config_folder_uid = child.uid
                    config_folder_name = name
                elif name == resources_suffix:
                    legacy_resources_uid = child.uid
                    legacy_resources_name = name
                elif name == users_suffix:
                    legacy_users_uid = child.uid
                    legacy_users_name = name
                else:
                    safe_folders.append({"name": name, "uid": child.uid})

        if config_folder_uid:
            folders_info["config_folder"] = config_folder_name
            folders_info["config_folder_uid"] = config_folder_uid
            folders_info.setdefault("resources_folder", config_folder_name)
            folders_info.setdefault("resources_folder_uid", config_folder_uid)
            folders_info.setdefault("users_folder", config_folder_name)
            folders_info.setdefault("users_folder_uid", config_folder_uid)
        if legacy_resources_uid:
            folders_info["resources_folder"] = legacy_resources_name
            folders_info["resources_folder_uid"] = legacy_resources_uid
        if legacy_users_uid:
            folders_info["users_folder"] = legacy_users_name
            folders_info["users_folder_uid"] = legacy_users_uid
        if safe_folders:
            folders_info["safe_folders"] = safe_folders

        project_result["folders"] = folders_info

    def _finalize_report(self, mapped: MappedImportResult, unmapped_items: list[dict],
                         project_result: Optional[dict], total_accounts: int,
                         user_team_matcher: Optional[UserTeamMatcher],
                         idempotency_ctx: Optional[dict] = None):
        if project_result is None:
            return
        dependent_summary = self._apply_service_dependent_mappings(
            mapped, project_result, unmapped_items,
        )
        resource_counts = self._build_resource_counts(mapped)
        import_duration = mapped.import_duration
        if dependent_summary:
            self._print_dependent_summary(dependent_summary)
        if idempotency_ctx:
            self._print_idempotency_summary(idempotency_ctx)
        report_text = build_report(
            project_name=self.options.project_name,
            safes_processed=len(mapped.accounts_by_safe),
            total_accounts=total_accounts,
            resource_counts=resource_counts,
            platform_counts=mapped.platform_counts,
            skipped=mapped.skipped,
            incomplete_count=len(mapped.incomplete),
            duration=import_duration,
            project_result=project_result,
            unmapped_platforms=mapped.mapper.unmapped_platforms,
            unmapped_items=unmapped_items,
            server=self.options.server,
        )
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
        report_config_uid = (project_result or {}).get("config_uid", "") or self.options.config_uid
        if report_config_uid:
            self._attach_report_files(notes_text, report_config_uid, user_team_matcher)

    # ------------------------------------------------------------------
    # Idempotency (upsert) support
    # ------------------------------------------------------------------

    def _maybe_auto_extend(self) -> None:
        """Promote a repeat import to extend mode when the target exists.

        Runs before mapping so ``_build_import_payload`` picks the
        ``build_extend_json`` branch and the vault write goes through
        ``PAMProjectExtendCommand`` (which grafts records onto an
        existing project) instead of ``PAMProjectImportCommand``
        (which creates a fresh ``project #2`` folder).

        Skipped when:
        - ``--sync-mode create`` — the user explicitly asked for the
          legacy always-create behavior.
        - ``--config`` was provided — the caller already told us
          which project to extend.
        - No PAM project with this name exists — we're a fresh import.
        - ``--dry-run`` / ``--output`` / ``--list-safes`` /
          ``--estimate`` — those never touch the vault; no need to
          resolve a config UID.
        """
        opts = self.options
        if (opts.sync_mode or "").lower() == "create":
            return
        if opts.config_uid:
            return
        if opts.dry_run or opts.output_file or opts.list_safes or opts.estimate_only:
            return
        # sync_down here so folder_cache / record_cache reflect any
        # project the operator (or a peer) just created via the UI.
        from ... import api as _api
        try:
            _api.sync_down(self.params)
        except Exception:  # noqa: BLE001 — best-effort refresh
            return
        wrapper_uids = self._find_project_wrapper_uids(opts.project_name)
        if not wrapper_uids:
            return
        resolved = self._cmd._find_config_uid(self.params, opts.project_name)
        if not resolved:
            logging.debug(
                "Project '%s' folder tree exists but no PAM configuration "
                "record was found — proceeding as a fresh import.",
                opts.project_name,
            )
            return
        self.options.config_uid = resolved
        print_formatted_text(HTML(
            f"<ansiblue>Detected existing PAM project '{_esc(opts.project_name)}'"
            f" — switching to extend mode (config: {_esc(resolved)}).</ansiblue>"
        ))

    def _prepare_idempotency(self, mapped: MappedImportResult) -> Optional[dict]:
        """Scan the target project and partition ``mapped`` records.

        Returns ``None`` when idempotency is disabled (``--sync-mode
        create``) or when the target project doesn't exist yet (fresh
        import — nothing to reconcile).  Otherwise returns a dict
        holding the :class:`ExistingRecordIndex`, the ordered list of
        :class:`RecordDecision`, and the summary counters that the
        confirmation prompt and post-import report consume.
        """
        opts = self.options
        if (opts.sync_mode or "").lower() == "create":
            return None
        if opts.dry_run or opts.output_file:
            # Both paths skip the vault write; there's nothing to
            # de-dupe against and the pre-scan would only slow the
            # dry-run down.
            return None

        from ... import api as _api
        try:
            _api.sync_down(self.params)
        except Exception:  # noqa: BLE001 — sync is best-effort
            pass

        wrapper_uids = self._find_project_wrapper_uids(opts.project_name)
        if not wrapper_uids:
            # New project — no records exist yet.  Bail so we don't
            # pay the full-vault scan cost for nothing.
            return None

        # Collect all shared folders directly under the project
        # wrapper user folder(s).  Records live inside these (and
        # inside their Resources / Users subfolders for the
        # safe-per-folder layout).
        shared_folder_uids: list[str] = []
        seen: set = set()
        for wrapper_uid in wrapper_uids:
            wrapper = self.params.folder_cache.get(wrapper_uid)
            if not wrapper:
                continue
            for child_uid in getattr(wrapper, "subfolders", []) or []:
                child = self.params.folder_cache.get(child_uid)
                if child is None:
                    continue
                if getattr(child, "type", "") != "shared_folder":
                    continue
                if child.uid in seen:
                    continue
                seen.add(child.uid)
                shared_folder_uids.append(child.uid)

        existing = build_existing_index(self.params, shared_folder_uids)
        if not existing.by_account_id and not existing.by_title:
            # Project exists but is empty (unusual — probably a
            # partially-cleaned-up prior run).  Nothing to reconcile.
            return None

        decisions = partition_records(
            mapped.pam_resources, mapped.pam_users, existing,
            diff_fn=self._diff_incoming_vs_existing,
        )
        summary = summarize(decisions)
        return {
            "existing": existing,
            "decisions": decisions,
            "partition_summary": summary,
            "wrapper_uids": wrapper_uids,
        }

    def _find_project_wrapper_uids(self, project_name: str) -> list[str]:
        """Locate the project wrapper user-folder(s) under PAM Environments.

        Delegates to :class:`CyberArkPAMCleanupCommand` so cleanup /
        idempotency / reporting all share the same discovery rules
        (they need to agree on which folder tree constitutes "this
        project").
        """
        return CyberArkPAMCleanupCommand._find_project_wrapper_folder_uids(
            self.params, project_name,
        )

    @staticmethod
    def _get_field_value(record, field_type: str, label: str = "") -> str:
        """Return the first stringified value of a typed field.

        ``field_type`` matches ``TypedField.type`` (e.g. ``"login"``,
        ``"password"``, ``"pamHostname"``).  ``label`` is used only
        for the ``text``/``checkbox`` families where the type alone
        isn't enough to disambiguate (both ``operatingSystem`` and
        ``instanceName`` are stored as ``text``, for instance).
        """
        if record is None:
            return ""
        for f in getattr(record, "fields", []) or []:
            ftype = getattr(f, "type", "") or ""
            flabel = getattr(f, "label", "") or ""
            if ftype != field_type:
                continue
            if label and flabel != label:
                continue
            vals = getattr(f, "value", None) or []
            if not vals:
                return ""
            raw = vals[0]
            if isinstance(raw, str):
                return raw
            if isinstance(raw, dict):
                # pamHostname is stored as {hostName, port}.  We rejoin
                # them into "host:port" for a stable diff key; the
                # incoming record dict emits ``host`` and ``port``
                # separately so callers hit the specialized branch
                # below rather than this one.
                if "hostName" in raw:
                    return str(raw.get("hostName") or "")
                return str(raw)
            return str(raw)
        return ""

    @staticmethod
    def _get_hostname_port(record) -> tuple[str, str]:
        """Extract ``(hostName, port)`` from a pamHostname typed field."""
        for f in getattr(record, "fields", []) or []:
            if (getattr(f, "type", "") or "") != "pamHostname":
                continue
            vals = getattr(f, "value", None) or []
            if not vals:
                return "", ""
            raw = vals[0]
            if isinstance(raw, dict):
                return (str(raw.get("hostName") or ""),
                        str(raw.get("port") or ""))
            if isinstance(raw, str):
                return raw, ""
        return "", ""

    def _diff_incoming_vs_existing(self, existing_rec, incoming: dict) -> list[str]:
        """Return the list of field names where the two records differ.

        Only the fields the CyberArk mapper actually writes are
        compared: title, notes body (marker line stripped so it is
        never a diff driver), credentials (login / password /
        SSH key), host + port, operating_system, distinguished_name,
        connect_database and url.  Rotation settings, pam_settings
        options and workflow permissions are intentionally **not**
        diffed because operators legitimately customize them in the
        Keeper UI after the initial import — clobbering those on a
        re-run would surprise everyone.

        An empty list means the record is unchanged.  Any non-empty
        return puts the record on the update path.
        """
        changes: list[str] = []

        rtype = incoming.get("type", "") or ""

        # Title
        incoming_title = (incoming.get("title") or "").strip()
        existing_title = (getattr(existing_rec, "title", "") or "").strip()
        if incoming_title and incoming_title != existing_title:
            changes.append("title")

        # Notes (marker line excluded so it never causes a false diff)
        incoming_notes = strip_id_marker(incoming.get("notes") or "").strip()
        existing_notes = strip_id_marker(getattr(existing_rec, "notes", "") or "").strip()
        if incoming_notes != existing_notes:
            changes.append("notes")

        # Login-family fields
        if rtype in ("login", "pamUser"):
            if (incoming.get("login") or "") != self._get_field_value(existing_rec, "login"):
                changes.append("login")
            # Password change is the whole point of a re-sync when CyberArk
            # rotated the credential.  Only diff when the incoming value is
            # non-empty — a redacted / omitted password should not clobber
            # what's already stored.
            incoming_password = incoming.get("password") or ""
            if incoming_password and incoming_password != self._get_field_value(existing_rec, "password"):
                changes.append("password")
            if incoming.get("private_pem_key"):
                if incoming["private_pem_key"] != self._get_field_value(existing_rec, "secret", "privatePEMKey"):
                    changes.append("private_pem_key")
            if rtype == "pamUser":
                if (incoming.get("distinguished_name") or "") != self._get_field_value(
                        existing_rec, "text", "distinguishedName"):
                    changes.append("distinguished_name")
                if (incoming.get("connect_database") or "") != self._get_field_value(
                        existing_rec, "text", "connectDatabase"):
                    changes.append("connect_database")
            if rtype == RECORD_TYPE_LOGIN:
                if (incoming.get("url") or "") != self._get_field_value(existing_rec, "url"):
                    changes.append("url")

        # Resource-family fields
        if rtype in (RECORD_TYPE_PAM_MACHINE, RECORD_TYPE_PAM_DATABASE, RECORD_TYPE_PAM_DIRECTORY):
            e_host, e_port = self._get_hostname_port(existing_rec)
            i_host = (incoming.get("host") or "").strip()
            i_port = (incoming.get("port") or "").strip()
            if i_host and i_host != e_host:
                changes.append("host")
            if i_port and i_port != e_port:
                changes.append("port")
            if rtype == RECORD_TYPE_PAM_MACHINE:
                if (incoming.get("operating_system") or "") != self._get_field_value(
                        existing_rec, "text", "operatingSystem"):
                    changes.append("operating_system")

        return changes

    def _apply_idempotency_filter(self, import_data: dict,
                                  mapped: MappedImportResult,
                                  idempotency_ctx: dict) -> None:
        """Rewrite the import payload to only include CREATE records.

        Mutates the underlying lists in place (``mapped.pam_resources``,
        ``mapped.pam_users``, and each resource's ``users`` sublist)
        so both ``import_data["pam_data"]`` (used by the single-batch
        path) and the ``resources`` / ``users`` args threaded through
        ``_execute_vault_import`` → ``_multi_batch_import`` (which
        rebuilds the payload from those lists) see the same filtered
        set.  ``pam_data.resources`` and ``mapped.pam_resources``
        already point at the same list object thanks to how
        ``build_import_json`` constructs the payload, so a slice
        assignment on either propagates to the other.
        """
        decisions_by_id: dict[int, RecordDecision] = {
            id(d.incoming): d for d in idempotency_ctx.get("decisions", [])
        }

        def _keep(record: dict) -> bool:
            dec = decisions_by_id.get(id(record))
            if dec is None:
                # Defensive: a record the partition didn't see (e.g.
                # added post-partition by another mapper hook) is
                # left as-is so we don't accidentally drop new data.
                return True
            return dec.decision is IdempotencyDecision.CREATE

        # Filter nested pamUsers first so a resource that survives
        # the outer filter carries only its CREATE-worthy children.
        for res in mapped.pam_resources or []:
            nested = res.get("users")
            if isinstance(nested, list):
                nested[:] = [u for u in nested if _keep(u)]

        # Slice assignment (list[:] = ...) mutates the list object,
        # so the alias ``import_data["pam_data"]["resources"]`` sees
        # the same filtered view.
        mapped.pam_resources[:] = [r for r in mapped.pam_resources if _keep(r)]
        mapped.pam_users[:] = [u for u in mapped.pam_users if _keep(u)]

    def _apply_record_updates(self, idempotency_ctx: dict) -> dict:
        """Push UPDATE decisions to the vault via record_management.

        Uses ``vault.KeeperRecord.load`` to grab a fresh copy of the
        existing record, applies only the fields the mapper actually
        produced (title, notes, login, password, host, port, ...) and
        calls ``record_management.update_record`` to persist.  Every
        exception is caught and counted — a single stale record must
        never take down the whole re-sync.
        """
        from ... import record_management, vault
        summary = {"updated": 0, "failed": 0, "details": []}
        for dec in idempotency_ctx.get("decisions", []):
            if dec.decision is not IdempotencyDecision.UPDATE:
                continue
            existing = dec.existing
            if existing is None or not getattr(existing, "record_uid", ""):
                continue
            try:
                fresh = vault.KeeperRecord.load(self.params, existing.record_uid)
                if fresh is None:
                    summary["failed"] += 1
                    continue
                self._apply_field_changes(fresh, dec.incoming, dec.change_fields)
                record_management.update_record(self.params, fresh)
                summary["updated"] += 1
                summary["details"].append({
                    "record_uid": fresh.record_uid,
                    "title": getattr(fresh, "title", ""),
                    "fields": dec.change_fields,
                    "status": "ok",
                })
            except Exception as e:  # noqa: BLE001 — surface, don't crash
                summary["failed"] += 1
                err_text = str(e) if str(e) else type(e).__name__
                logging.warning(
                    "Idempotency update failed for record %s (%s): %s "
                    "(fields: %s)",
                    getattr(existing, "record_uid", "?"),
                    getattr(existing, "title", "?"),
                    err_text,
                    ", ".join(dec.change_fields) or "(none)",
                )
                summary["details"].append({
                    "record_uid": getattr(existing, "record_uid", ""),
                    "title": getattr(existing, "title", ""),
                    "fields": dec.change_fields,
                    "status": "failed",
                    "error": err_text,
                })
        return summary

    def _apply_field_changes(self, record, incoming: dict,
                             changed_fields: list[str]) -> None:
        """Mutate ``record`` (a loaded KeeperRecord) in place.

        Only the fields listed in ``changed_fields`` are touched —
        anything else on the record (custom fields, workflow
        settings, rotation history) is left alone so operator
        customizations are preserved across re-imports.
        """

        def _set_field(field_type: str, label: str, value):
            for f in getattr(record, "fields", []) or []:
                ftype = getattr(f, "type", "") or ""
                flabel = getattr(f, "label", "") or ""
                if ftype != field_type:
                    continue
                if label and flabel != label:
                    continue
                f.value = [value] if value not in (None, "") else []
                return
            # If the record didn't originally carry the field, we
            # silently drop the update — creating a typed field from
            # scratch would require record-type schema knowledge that
            # we don't want to duplicate here.  In practice every
            # PAM record already has the standard fields provisioned.

        for name in changed_fields:
            if name == "title":
                record.title = (incoming.get("title") or "").strip()
            elif name == "notes":
                record.notes = incoming.get("notes") or ""
            elif name == "login":
                _set_field("login", "", incoming.get("login") or "")
            elif name == "password":
                _set_field("password", "", incoming.get("password") or "")
            elif name == "private_pem_key":
                _set_field("secret", "privatePEMKey", incoming.get("private_pem_key") or "")
            elif name == "distinguished_name":
                _set_field("text", "distinguishedName", incoming.get("distinguished_name") or "")
            elif name == "connect_database":
                _set_field("text", "connectDatabase", incoming.get("connect_database") or "")
            elif name == "url":
                _set_field("url", "", incoming.get("url") or "")
            elif name in ("host", "port"):
                host = (incoming.get("host") or "").strip()
                port = (incoming.get("port") or "").strip()
                _set_field("pamHostname", "", {"hostName": host, "port": port})
            elif name == "operating_system":
                _set_field("text", "operatingSystem", incoming.get("operating_system") or "")

    def _print_idempotency_summary(self, idempotency_ctx: dict) -> None:
        summary: PartitionSummary = idempotency_ctx.get("partition_summary")
        update_summary = idempotency_ctx.get("update_summary") or {}
        details = update_summary.get("details") or []
        print()
        print(f"{bcolors.OKBLUE}Sync results (--sync-mode="
              f"{self.options.sync_mode}):{bcolors.ENDC}")
        if summary is not None:
            print(f"  Created (new):    {summary.created}")
            print(f"  Updated in place: {update_summary.get('updated', summary.updated)}")
            print(f"  Unchanged:        {summary.unchanged}")
            failed = update_summary.get("failed", 0)
            if failed:
                print(f"  {bcolors.WARNING}Update failures:  {failed}{bcolors.ENDC}")
        if details:
            print()
            print(f"{bcolors.OKBLUE}Idempotency field updates:{bcolors.ENDC}")
            for item in details:
                title = item.get("title") or item.get("record_uid") or "?"
                fields = item.get("fields") or []
                field_text = ", ".join(fields) if fields else "(none)"
                status = item.get("status", "")
                if status == "failed":
                    err = item.get("error", "")
                    print(f"  {bcolors.WARNING}✗{bcolors.ENDC} {title}")
                    print(f"      fields: {field_text}")
                    if err:
                        print(f"      error:  {err}")
                else:
                    print(f"  {bcolors.OKGREEN}✓{bcolors.ENDC} {title}")
                    print(f"      fields: {field_text}")
        print()

    def _apply_service_dependent_mappings(
        self, mapped: MappedImportResult, project_result: dict,
        unmapped_items: list[dict],
    ) -> Optional[dict]:
        """Replay CyberArk dependents as KeeperPAM service-account mappings.

        Iterates over ``mapped.dependents`` collected during the mapping phase
        and invokes ``PAMActionServiceAddCommand`` once per (machine, user, type)
        tuple that resolves to imported records. Categories with no Keeper
        equivalent, missing host machines, and non-Windows OS hosts are all
        skipped silently and accounted for in the returned summary so the
        import report can surface them.

        Returns a summary dict, or ``None`` when nothing to do.
        """
        opts = self.options
        if opts.skip_dependents or not mapped.dependents:
            return None

        gateway = opts.gateway_name or ""
        config_uid = project_result.get("config_uid") or opts.config_uid or ""
        if not gateway and not config_uid:
            logging.debug(
                "Cannot map CyberArk dependents — gateway/config UID unknown",
            )
            return {
                "total": len(mapped.dependents), "added": 0,
                "skipped_unsupported": 0, "skipped_non_windows": 0,
                "skipped_missing_machine": 0, "skipped_missing_user": 0,
                "skipped_other": len(mapped.dependents),
                "details": [{"reason": "no gateway/config UID available"}],
            }

        try:
            from ... import api, vault, vault_extensions
            from ...utils import base64_url_encode
            from ..pam_service.add import PAMActionServiceAddCommand
            from ..discover import GatewayContext, MultiConfigurationException
        except ImportError as e:
            logging.warning("Dependent service mapping unavailable: %s",
                            type(e).__name__)
            return None

        api.sync_down(self.params)

        try:
            if config_uid:
                gateway_context = GatewayContext.from_configuration_uid(
                    params=self.params, configuration_uid=config_uid,
                )
            else:
                gateway_context = GatewayContext.from_gateway(
                    params=self.params, gateway=gateway,
                )
        except MultiConfigurationException:
            logging.warning(
                "Multiple PAM configurations match this gateway — skipping "
                "dependent mapping. Re-run 'pam action service add' manually.",
            )
            return {
                "total": len(mapped.dependents), "added": 0,
                "skipped_other": len(mapped.dependents),
                "skipped_unsupported": 0, "skipped_non_windows": 0,
                "skipped_missing_machine": 0, "skipped_missing_user": 0,
                "details": [{"reason": "multiple matching PAM configurations"}],
            }
        if gateway_context is None:
            logging.warning(
                "Gateway context unavailable — skipping CyberArk dependent mapping. "
                "Re-run 'pam action service add' manually for each pair.",
            )
            return None

        machine_index, user_index = self._build_record_indexes(
            mapped, vault, vault_extensions,
        )

        summary = {
            "total": len(mapped.dependents),
            "added": 0,
            "skipped_unsupported": 0,
            "skipped_non_windows": 0,
            "skipped_missing_machine": 0,
            "skipped_missing_user": 0,
            "skipped_other": 0,
            "details": [],
        }
        try:
            gateway_uid = base64_url_encode(gateway_context.gateway.controllerUid)
        except Exception:
            gateway_uid = gateway_context.gateway.controllerName

        add_cmd = PAMActionServiceAddCommand()

        for dep in mapped.dependents:
            service_type = dep.get("service_type")
            if service_type not in ("service", "task", "iis"):
                summary["skipped_unsupported"] += 1
                continue

            machine_record = self._find_machine_record(
                dep.get("machine_address", ""), machine_index,
            )
            if machine_record is None:
                summary["skipped_missing_machine"] += 1
                summary["details"].append({
                    "service": dep.get("service_name", ""),
                    "host": dep.get("machine_address", ""),
                    "type": dep.get("raw_type", ""),
                    "reason": "no PAM Machine record imported for this host",
                })
                continue

            if not self._is_windows_machine(machine_record):
                summary["skipped_non_windows"] += 1
                unmapped_items.append({
                    "category": "CyberArk dependent",
                    "item": (f"{dep.get('service_name') or dep.get('raw_type')} "
                             f"on {dep.get('machine_address')}"),
                    "action": "Host is not Windows — Keeper PAM can only rotate "
                              "Windows service / task / IIS credentials",
                })
                continue

            user_record = user_index.get(dep.get("master_user_title", ""))
            if user_record is None:
                summary["skipped_missing_user"] += 1
                summary["details"].append({
                    "service": dep.get("service_name", ""),
                    "host": dep.get("machine_address", ""),
                    "type": dep.get("raw_type", ""),
                    "reason": "PAM User record not found in vault after import",
                })
                continue

            try:
                add_cmd.execute(
                    self.params,
                    gateway=gateway_uid,
                    configuration_uid=gateway_context.configuration.record_uid,
                    machine_uid=machine_record.record_uid,
                    user_uid=user_record.record_uid,
                    type=service_type,
                )
                summary["added"] += 1
            except Exception as e:  # noqa: BLE001 — never block reporting
                summary["skipped_other"] += 1
                logging.warning(
                    "Failed to register %s mapping for %s on %s: %s",
                    service_type, dep.get("service_name", "?"),
                    dep.get("machine_address", "?"), type(e).__name__,
                )
                summary["details"].append({
                    "service": dep.get("service_name", ""),
                    "host": dep.get("machine_address", ""),
                    "type": dep.get("raw_type", ""),
                    "reason": f"pam action service add failed: {type(e).__name__}",
                })

        return summary

    def _build_record_indexes(self, mapped: MappedImportResult, vault, vault_extensions
                              ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Build ``(machine, user)`` record lookups from freshly imported vault data.

        Indexes pamMachine records by lowercased host AND lowercased title, and
        pamUser records by lowercased title — the same identifiers
        ``AccountMapper`` writes during the mapping phase. Restricting the scan
        to titles the importer just produced keeps the lookup O(imported) rather
        than O(vault).
        """
        machine_index: dict[str, Any] = {}
        user_index: dict[str, Any] = {}
        imported_machine_titles = {
            (r.get("title") or "").casefold()
            for r in mapped.pam_resources if r.get("type") == RECORD_TYPE_PAM_MACHINE
        }
        imported_user_titles = set()
        for r in mapped.pam_resources:
            for u in r.get("users") or []:
                t = (u.get("title") or "").casefold()
                if t:
                    imported_user_titles.add(t)
        for rec in vault_extensions.find_records(self.params, record_version=3):
            rtype = getattr(rec, "record_type", "") or ""
            title = (getattr(rec, "title", "") or "").casefold()
            if rtype == RECORD_TYPE_PAM_MACHINE and title in imported_machine_titles:
                loaded = vault.KeeperRecord.load(self.params, rec.record_uid)
                if loaded is None:
                    continue
                machine_index[title] = loaded
                host_field = next(
                    (f for f in loaded.fields
                     if (getattr(f, "type", "") or "") == "pamHostname"
                     or (getattr(f, "label", "") or "").lower() == "host"),
                    None,
                )
                if host_field and host_field.value:
                    raw = host_field.value[0]
                    host_str = ""
                    if isinstance(raw, dict):
                        host_str = (raw.get("hostName") or raw.get("host") or "")
                    elif isinstance(raw, str):
                        host_str = raw
                    if host_str:
                        machine_index[host_str.casefold()] = loaded
            elif rtype == "pamUser" and title in imported_user_titles:
                loaded = vault.KeeperRecord.load(self.params, rec.record_uid)
                if loaded is not None:
                    user_index[title] = loaded
        return machine_index, user_index

    @staticmethod
    def _find_machine_record(address: str, machine_index: dict[str, Any]
                             ) -> Any:
        """Resolve a CyberArk dependent ``Address`` to a Keeper PAM Machine.

        Tries an exact host/title hit first, then a hostname-prefix match
        (CyberArk stores FQDNs but resources may be titled with the short
        name and vice-versa). Returns ``None`` when nothing matches.
        """
        if not address:
            return None
        key = address.casefold()
        if key in machine_index:
            return machine_index[key]
        short = key.split(".", 1)[0]
        if short and short in machine_index:
            return machine_index[short]
        for k, rec in machine_index.items():
            if k.startswith(short) or short.startswith(k.split(".", 1)[0]):
                return rec
        return None

    @staticmethod
    def _is_windows_machine(machine_record) -> bool:
        """Mirror PAMActionServiceAddCommand's OS check so we can skip
        non-Windows hosts before the call (avoiding noisy print output)."""
        os_field = next(
            (f for f in machine_record.fields
             if (f.label or "") == "operatingSystem"),
            None,
        )
        if os_field is None or not os_field.value:
            return False
        return str(os_field.value[0]).lower() == "windows"

    @staticmethod
    def _print_dependent_summary(summary: dict):
        added = summary.get("added", 0)
        skipped = (summary.get("skipped_unsupported", 0)
                   + summary.get("skipped_non_windows", 0)
                   + summary.get("skipped_missing_machine", 0)
                   + summary.get("skipped_missing_user", 0)
                   + summary.get("skipped_other", 0))
        print()
        print(f"{bcolors.OKBLUE}CyberArk dependents → "
              f"'pam action service add':{bcolors.ENDC}")
        print(f"  Linked:                {added}")
        if summary.get("skipped_unsupported"):
            print(f"  Unsupported type:      {summary['skipped_unsupported']}")
        if summary.get("skipped_non_windows"):
            print(f"  Non-Windows host:      {summary['skipped_non_windows']}")
        if summary.get("skipped_missing_machine"):
            print(f"  Missing PAM Machine:   {summary['skipped_missing_machine']}")
        if summary.get("skipped_missing_user"):
            print(f"  Missing PAM User:      {summary['skipped_missing_user']}")
        if summary.get("skipped_other"):
            print(f"  Other failures:        {summary['skipped_other']}")
        if skipped == 0 and added == 0:
            print(f"  {bcolors.WARNING}No dependents resolvable to imported records.{bcolors.ENDC}")
        print()

    @staticmethod
    def _build_resource_counts(mapped: MappedImportResult) -> dict[str, dict[str, int]]:
        resource_counts: dict[str, dict[str, int]] = {
            "pamMachine": {"ok": 0, "skip": 0, "err": 0},
            "pamDatabase": {"ok": 0, "skip": 0, "err": 0},
            "pamUser": {"ok": 0, "skip": 0, "err": 0},
            "login": {"ok": 0, "skip": 0, "err": 0},
        }
        for r in mapped.pam_resources:
            rtype = r.get("type", "pamMachine")
            resource_counts.setdefault(rtype, {"ok": 0, "skip": 0, "err": 0})
            resource_counts[rtype]["ok"] += 1
            for u in r.get("users", []):
                resource_counts["pamUser"]["ok"] += 1
        for u in mapped.pam_users:
            resource_counts["login"]["ok"] += 1
        return resource_counts

    def _attach_report_files(self, notes_text: str, report_config_uid: str,
                             user_team_matcher: Optional[UserTeamMatcher]):
        tmp_files: list[str] = []
        try:
            from ..record_edit import RecordUploadAttachmentCommand
            attachments: list[str] = []
            report_tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.md', prefix='CyberArk-Import-Report-',
                delete=False, encoding='utf-8',
            )
            report_tmp.write(notes_text)
            report_tmp.close()
            tmp_files.append(report_tmp.name)
            attachments.append(report_tmp.name)
            if user_team_matcher and user_team_matcher.unmatched:
                csv_content = user_team_matcher.generate_csv()
                if csv_content:
                    csv_tmp = tempfile.NamedTemporaryFile(
                        mode='w', suffix='.csv', prefix='ca_users_to_provision_',
                        delete=False, encoding='utf-8',
                    )
                    csv_tmp.write(csv_content)
                    csv_tmp.close()
                    tmp_files.append(csv_tmp.name)
                    attachments.append(csv_tmp.name)
            if attachments:
                RecordUploadAttachmentCommand().execute(
                    self.params, record=report_config_uid, file=attachments,
                )
                try:
                    print(f"Report saved to PAM config record: {report_config_uid}")
                    if len(attachments) > 1:
                        print("CSV (ca_users_to_provision) attached")
                except (BrokenPipeError, OSError):
                    pass
        except Exception as e:
            logging.warning("Failed to save report attachment: %s", type(e).__name__)
        finally:
            for path in tmp_files:
                try:
                    os.unlink(path)
                except OSError:
                    pass


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
                        choices=["safe", "ksm", "exact", "flat"], default="safe",
                        help="Safe → folder mapping mode (default: safe). "
                             "'safe' creates one Keeper shared folder per CyberArk safe "
                             "with that safe's permission set, enabling per-safe access "
                             "control. 'ksm'/'exact' nest safe-named subfolders under the "
                             "legacy Resources/Users shared folders. 'flat' puts every "
                             "record into the two legacy shared folders with aggregated "
                             "permissions.")
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
    parser.add_argument("--skip-dependents", required=False, dest="skip_dependents",
                        action="store_true", default=False,
                        help="Skip CyberArk dependents → 'pam action service' mapping after import")
    parser.add_argument("--user-map", required=False, dest="user_map", action="store",
                        default="", help="JSON file mapping CyberArk users to Keeper emails")
    parser.add_argument("--sync-mode", required=False, dest="sync_mode",
                        choices=["upsert", "create"], default="upsert",
                        help="upsert (default): idempotent — create missing "
                             "records, update changed ones, skip unchanged. "
                             "create: legacy always-create (may produce "
                             "duplicates on re-run).")
    parser.add_argument("--strict-policies", required=False, dest="strict_policies",
                        action="store_true", default=False,
                        help="Fail the import when a platform's rotation policy "
                             "is inaccessible instead of inheriting the master "
                             "policy default")

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
            options = ImportRunOptions(
                server=server,
                project_name=project_name,
                config_uid=config_uid,
                gateway_name=gateway_name,
                folder_mode=folder_mode,
                dry_run=dry_run,
                output_file=output_file,
                include_creds=include_creds,
                estimate_only=estimate_only,
                skip_confirm=skip_confirm,
                skip_users=skip_users,
                skip_linked=skip_linked,
                skip_members=kwargs.get("skip_members", False),
                skip_dependents=kwargs.get("skip_dependents", False),
                safe_include=safe_include,
                safe_exclude=safe_exclude,
                list_safes=list_safes,
                batch_size=batch_size,
                batch_delay=batch_delay,
                platform_map_override=platform_map_override,
                state_filter=state_filter,
                include_system_safes=kwargs.get("include_system_safes", False),
                user_map_file=kwargs.get("user_map", ""),
                sync_mode=(kwargs.get("sync_mode") or "upsert").lower(),
                strict_policies=bool(kwargs.get("strict_policies", False)),
                raw_kwargs=kwargs,
            )
            CyberArkImportOrchestrator(self, params, client, options).run()
        finally:
            client.logoff()

    def _execute_import(self, params, import_data: dict, project_name: str,
                        config_uid: str, batch_size: int, batch_delay: float,
                        resources: list[dict], users: list[dict]) -> Optional[dict]:
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

        tmp_path = _temp_store.write_json(import_data)
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
            _temp_store.remove(tmp_path)

        resolved_config_uid = config_uid or self._find_config_uid(params, project_name)
        return {"project_name": project_name, "config_uid": resolved_config_uid}

    def _multi_batch_import(self, params, import_data: dict,
                            project_name: str, config_uid: str,
                            resources: list[dict], users: list[dict],
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
                tmp_path = _temp_store.write_json(first_batch_data)
                try:
                    PAMProjectImportCommand().execute(
                        params, project_name=project_name, file_name=tmp_path, dry_run=False
                    )
                finally:
                    _temp_store.remove(tmp_path)

                # For subsequent batches, we need the PAM config UID
                # Try to find it by project name
                if not config_uid:
                    config_uid = self._find_config_uid(params, project_name)
            else:
                # Subsequent batches: extend
                extend_data = build_extend_json(batch_resources, batch_users)
                tmp_path = _temp_store.write_json(extend_data)
                try:
                    if config_uid:
                        PAMProjectExtendCommand().execute(
                            params, config=config_uid, file_name=tmp_path, dry_run=False
                        )
                    else:
                        logging.error("Cannot extend: PAM configuration UID not found after initial import")
                        break
                finally:
                    _temp_store.remove(tmp_path)

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
    def _list_safes_detailed(safes: list[dict], system_excluded: int):
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
    def _interactive_safe_picker(safes: list[dict]) -> Optional[str]:
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
    """Remove a CyberArk-imported project: records, folders, gateway, KSM app."""

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
  pam project cyberark-cleanup --config <PAM_CONFIG_UID> --yes
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

        from ... import api, utils, vault, vault_extensions
        from ..pam import gateway_helper
        from ..pam.config_helper import configuration_controller_get
        from ...loginv3 import CommonHelperMethods

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

        # Resolve gateway linked to this PAM config
        gateway_uid = None
        gateway_name = None
        gw_match = None
        try:
            controller = configuration_controller_get(
                params, CommonHelperMethods.url_safe_str_to_bytes(
                    config_rec.record_uid))
            if controller and controller.controllerUid:
                gateway_uid = controller.controllerUid
                all_gw = gateway_helper.get_all_gateways(params)
                gw_match = next((g for g in all_gw
                                 if g.controllerUid == gateway_uid), None)
                if gw_match:
                    gateway_name = gw_match.controllerName
        except Exception as e:
            logging.debug("Could not resolve gateway: %s", e)

        # Resolve KSM application linked to the gateway
        ksm_app_uid = None
        ksm_app_name = None
        if gw_match and gw_match.applicationUid:
            ksm_app_uid = utils.base64_url_encode(gw_match.applicationUid)
            app_rec = vault.KeeperRecord.load(params, ksm_app_uid)
            if app_rec:
                ksm_app_name = getattr(app_rec, "title", ksm_app_uid)

        # Find shared folders. The new safe-per-folder layout creates one
        # shared folder per CyberArk safe under the project wrapper folder
        # plus an admin Config folder; each safe folder has two
        # ``Resources``/``Users`` shared_folder_folder subfolders that
        # hold the records. The legacy layout creates exactly two folders
        # ("{project} - Resources" and "{project} - Users") with safe-named
        # subfolders inside. Discover everything by walking the project
        # wrapper user-folder under PAM Environments so cleanup handles
        # both shapes (and any subset thereof) without hardcoding names.
        sf_uids = []
        sf_names: list = []
        all_record_uids: set = set()
        res_name = f"{project_name} - Resources"
        usr_name = f"{project_name} - Users"
        config_name = f"{project_name} - Config"

        def _collect_records_recursive(folder_uid: str):
            """Walk the folder subtree and accumulate every record UID
            (records living directly in this folder + records living in
            any descendant ``shared_folder_folder``)."""
            stack = [folder_uid]
            while stack:
                fuid = stack.pop()
                for ruid in params.subfolder_record_cache.get(fuid, set()) or set():
                    all_record_uids.add(ruid)
                folder = params.folder_cache.get(fuid)
                if not folder:
                    continue
                for sub_uid in getattr(folder, "subfolders", []) or []:
                    stack.append(sub_uid)

        def _delete_folder(folder_uid: str) -> bool:
            folder = params.folder_cache.get(folder_uid)
            if not folder:
                return False
            del_obj = {
                "delete_resolution": "unlink",
                "object_uid": folder.uid,
                "object_type": folder.type,
            }
            parent = params.folder_cache.get(folder.parent_uid)
            if parent:
                del_obj["from_uid"] = parent.uid
                del_obj["from_type"] = parent.type
            else:
                del_obj["from_type"] = "user_folder"
            rq = {"command": "pre_delete", "objects": [del_obj]}
            rs = api.communicate(params, rq)
            if rs.get("result") != "success":
                return False
            pdr = rs.get("pre_delete_response", {})
            del_rq = {
                "command": "delete",
                "pre_delete_token": pdr.get("pre_delete_token", ""),
            }
            api.communicate(params, del_rq)
            return True

        project_folder_uids = self._find_project_wrapper_folder_uids(
            params, project_name,
        )
        if project_folder_uids:
            sf_uids_seen: set = set()
            for project_uid in project_folder_uids:
                project_folder = params.folder_cache.get(project_uid)
                if not project_folder:
                    continue
                for child_uid in getattr(project_folder, "subfolders", []) or []:
                    child = params.folder_cache.get(child_uid)
                    if not child:
                        continue
                    # Only collect shared folders that we created — i.e.
                    # the type is SharedFolderType.
                    if getattr(child, "type", "") != "shared_folder":
                        continue
                    if child.uid in sf_uids_seen:
                        continue
                    sf_uids_seen.add(child.uid)
                    sf_uids.append(child.uid)
                    sf_names.append(getattr(child, "name", "") or "")
                    _collect_records_recursive(child.uid)
        else:
            # Fallback: scan the shared-folder cache by name. Catches the
            # legacy two-folder layout when the project wrapper folder was
            # deleted/renamed manually post-import.
            for sf_uid, sf in params.shared_folder_cache.items():
                name = sf.get("name_unencrypted", "")
                if name in (res_name, usr_name, config_name):
                    sf_uids.append(sf_uid)
                    sf_names.append(name)
                    _collect_records_recursive(sf_uid)

        # Ensure PAM config is included even if it lives outside the
        # discovered shared-folder tree.
        if config_uid:
            all_record_uids.add(config_uid)

        print(f"\nCyberArk PAM Project Cleanup")
        print("=" * 50)
        print(f"  Project:     {project_name}")
        print(f"  PAM Config:  {config_uid}")
        print(f"  Gateway:     {gateway_name or '(not found)'}")
        print(f"  KSM App:     {ksm_app_name or ksm_app_uid or '(not found)'}")
        print(f"  Folders:     {len(sf_uids)}")
        for sf_name in sf_names:
            if sf_name:
                print(f"    • {sf_name}")
        if project_folder_uids:
            print(f"  Wrappers:    {len(project_folder_uids)}")
        print(f"  Records:     {len(all_record_uids)}")

        if dry_run:
            print("  (dry run — no changes made)")
            print("=" * 50)
            return

        if not auto_confirm:
            answer = input("\n  Delete all of the above? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                print("  Cancelled.")
                return

        deleted = 0
        failed = 0

        # Delete records in batches (same API as api.delete_record)
        if all_record_uids:
            logging.warning("Deleting %d records...", len(all_record_uids))
            uid_list = list(all_record_uids)
            batch_size = 50
            for i in range(0, len(uid_list), batch_size):
                batch = uid_list[i:i + batch_size]
                try:
                    rq = {"command": "record_update", "delete_records": batch}
                    api.communicate(params, rq)
                    deleted += len(batch)
                except Exception as e:
                    failed += len(batch)
                    logging.warning("Failed to delete record batch: %s", e)

        # Delete shared folders (safe folders + Config folder)
        if sf_uids:
            logging.warning("Removing %d shared folder(s)...", len(sf_uids))
            for sf_uid in sf_uids:
                try:
                    if not _delete_folder(sf_uid):
                        failed += 1
                        logging.warning("Failed to remove shared folder %s",
                                        sf_uid)
                except Exception as e:
                    failed += 1
                    logging.warning("Failed to remove shared folder %s: %s",
                                    sf_uid, e)

        # Delete project wrapper user-folder(s) under PAM Environments
        if project_folder_uids:
            logging.warning("Removing %d project wrapper folder(s)...",
                            len(project_folder_uids))
            for wrapper_uid in project_folder_uids:
                try:
                    if not _delete_folder(wrapper_uid):
                        failed += 1
                        logging.warning("Failed to remove wrapper folder %s",
                                        wrapper_uid)
                except Exception as e:
                    failed += 1
                    logging.warning("Failed to remove wrapper folder %s: %s",
                                    wrapper_uid, e)

        # Remove gateway
        if gateway_uid:
            logging.warning("Removing gateway \"%s\"...",
                            gateway_name or gateway_uid)
            try:
                gateway_helper.remove_gateway(params, gateway_uid)
            except Exception as e:
                failed += 1
                logging.warning("Failed to remove gateway: %s", e)

        # Remove KSM application
        if ksm_app_uid:
            logging.warning("Removing KSM app \"%s\"...",
                            ksm_app_name or ksm_app_uid)
            try:
                from ..ksm import KSMCommand
                KSMCommand.remove_v5_app(params, ksm_app_uid,
                                         purge=True, force=True)
            except Exception as e:
                failed += 1
                logging.warning("Failed to remove KSM app: %s", e)

        api.sync_down(params)
        msg = f"\nCleanup complete: {deleted} records deleted"
        if failed:
            msg += f" ({failed} failed — see warnings above)"
        print(msg)
        print("=" * 50)

    PAM_ROOT_FOLDER_NAME = "PAM Environments"

    @classmethod
    def _find_project_wrapper_folder_uids(cls, params, project_name: str) -> list:
        """Return UIDs of every project wrapper user-folder under
        ``PAM Environments`` whose name matches ``project_name`` (or
        ``project_name #N`` when the project was imported multiple times).

        The wrapper folder is a *user folder* (not shared), and per-safe
        shared folders are created as direct children of it. Returning a
        list keeps cleanup correct in the rare case where two projects
        share a name (PAMProjectImportCommand allows duplicates via the
        ``#N`` suffix).
        """
        wrapper_uids: list = []
        folders = params.folder_cache if params and params.folder_cache else {}
        if not isinstance(folders, dict):
            return wrapper_uids

        # Locate root "PAM Environments" user folder(s).
        root_uids: list = []
        for uid, f in folders.items():
            if not f or getattr(f, "parent_uid", None):
                continue
            if getattr(f, "type", "") != "user_folder":
                continue
            if getattr(f, "name", "") == cls.PAM_ROOT_FOLDER_NAME:
                root_uids.append(uid)
        if not root_uids:
            return wrapper_uids

        # PAMProjectImportCommand emits "{project_name}" or
        # "{project_name} #N" for the wrapper user folder, so match both
        # shapes here.
        base = project_name
        for root_uid in root_uids:
            root_folder = folders.get(root_uid)
            if not root_folder:
                continue
            for child_uid in getattr(root_folder, "subfolders", []) or []:
                child = folders.get(child_uid)
                if not child or getattr(child, "type", "") != "user_folder":
                    continue
                name = getattr(child, "name", "") or ""
                if name == base or re.match(rf"^{re.escape(base)} #\d+$", name):
                    wrapper_uids.append(child.uid)
        return wrapper_uids
