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

"""Sync multi-channel approver references in integration config records with the vault."""

import json
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

from .... import api, vault
from ....display import bcolors
from ....error import CommandError
from ...docker import ApprovalsConfig, ApproverTeam
from .approvals_setup import (
    APPROVALS_FIELD_LABELS,
    FIELD_APPROVALS_CHANNEL_ID,
    FIELD_APPROVALS_TEAMS,
    FIELD_MULTI_CHANNEL_ENABLED,
    approvals_config_to_record_fields,
    build_record_uids,
    build_shared_folder_uids,
    build_team_lookup,
    print_approvals_config,
)

if TYPE_CHECKING:
    from ....params import KeeperParams


@dataclass
class TeamDriftEntry:
    team: ApproverTeam
    removed: bool = False
    renamed_to: Optional[str] = None
    removed_folder_uids: List[str] = field(default_factory=list)
    removed_record_uids: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.removed
            or self.renamed_to
            or self.removed_folder_uids
            or self.removed_record_uids
        )


@dataclass
class ApprovalsDriftReport:
    entries: List[TeamDriftEntry] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(entry.has_changes for entry in self.entries)


def custom_fields_by_label(record: vault.KeeperRecord) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for custom in getattr(record, 'custom', None) or []:
        value = custom.get_default_value()
        if value is not None:
            result[custom.label] = str(value)
    return result


def parse_approvals_from_record(
    record: vault.KeeperRecord,
    command_name: str = '',
) -> ApprovalsConfig:
    fields = custom_fields_by_label(record)
    multi_channel = fields.get(FIELD_MULTI_CHANNEL_ENABLED, 'false').strip().lower() == 'true'
    single_channel_id = fields.get(FIELD_APPROVALS_CHANNEL_ID, '').strip()
    teams_json = fields.get(FIELD_APPROVALS_TEAMS, '').strip()

    teams: List[ApproverTeam] = []
    if teams_json:
        try:
            raw_teams = json.loads(teams_json)
        except json.JSONDecodeError as exc:
            raise CommandError(command_name, f'Invalid {FIELD_APPROVALS_TEAMS} JSON: {exc}') from exc
        if not isinstance(raw_teams, list):
            raise CommandError(command_name, f'{FIELD_APPROVALS_TEAMS} must be a JSON array')

        seen_team_uids = set()
        for item in raw_teams:
            if not isinstance(item, dict):
                continue
            team_uid = str(item.get('team_uid', '')).strip()
            channel_id = str(item.get('channel_id', '')).strip()
            if not team_uid or not channel_id or team_uid in seen_team_uids:
                continue
            seen_team_uids.add(team_uid)
            teams.append(ApproverTeam(
                team_uid=team_uid,
                name=str(item.get('name', '')).strip() or team_uid,
                channel_id=channel_id,
                folder_uids=list(dict.fromkeys(
                    str(u).strip() for u in (item.get('folder_uids') or []) if str(u).strip()
                )),
                record_uids=list(dict.fromkeys(
                    str(u).strip() for u in (item.get('record_uids') or []) if str(u).strip()
                )),
            ))

    return ApprovalsConfig(
        multi_channel_enabled=multi_channel,
        single_channel_id=single_channel_id,
        teams=teams,
    )


def merge_approvals_custom_fields(existing_custom: List, config: ApprovalsConfig) -> List:
    preserved = [f for f in (existing_custom or []) if f.label not in APPROVALS_FIELD_LABELS]
    return preserved + approvals_config_to_record_fields(config)


def analyze_approvals_drift(
    params: 'KeeperParams',
    config: ApprovalsConfig,
) -> Tuple[ApprovalsConfig, ApprovalsDriftReport]:
    by_uid, _ = build_team_lookup(params)
    known_folders = build_shared_folder_uids(params)
    known_records = build_record_uids(params)

    report = ApprovalsDriftReport()
    cleaned_teams: List[ApproverTeam] = []

    for team in config.teams:
        if team.team_uid not in by_uid:
            report.entries.append(TeamDriftEntry(team=team, removed=True))
            continue

        current_name = by_uid[team.team_uid][1] or team.name
        removed_folders = [uid for uid in team.folder_uids if uid not in known_folders]
        removed_records = [uid for uid in team.record_uids if uid not in known_records]
        renamed_to = current_name if current_name != team.name else None

        entry = TeamDriftEntry(
            team=team,
            renamed_to=renamed_to,
            removed_folder_uids=removed_folders,
            removed_record_uids=removed_records,
        )
        if entry.has_changes:
            report.entries.append(entry)

        cleaned_teams.append(replace(
            team,
            name=current_name,
            folder_uids=[uid for uid in team.folder_uids if uid in known_folders],
            record_uids=[uid for uid in team.record_uids if uid in known_records],
        ))

    cleaned = ApprovalsConfig(
        multi_channel_enabled=config.multi_channel_enabled,
        single_channel_id=config.single_channel_id,
        teams=cleaned_teams,
    )
    return cleaned, report


def print_approvals_drift_report(report: ApprovalsDriftReport) -> None:
    print(f"\n{bcolors.BOLD}Vault sync changes:{bcolors.ENDC}")
    if not report.has_changes:
        print(f"  {bcolors.OKGREEN}No removed or renamed approver references found.{bcolors.ENDC}")
        return

    for entry in report.entries:
        team = entry.team
        label = f'{team.name} ({team.team_uid})'
        if entry.removed:
            print(f"  {bcolors.FAIL}• Removed team (no longer in vault): {label}{bcolors.ENDC}")
            continue
        if entry.renamed_to:
            print(
                f"  {bcolors.OKBLUE}• Team renamed: {team.name} → {entry.renamed_to} "
                f'({team.team_uid}){bcolors.ENDC}'
            )
        for folder_uid in entry.removed_folder_uids:
            print(f"  {bcolors.FAIL}• Removed shared folder UID for {label}: {folder_uid}{bcolors.ENDC}")
        for record_uid in entry.removed_record_uids:
            print(f"  {bcolors.FAIL}• Removed record UID for {label}: {record_uid}{bcolors.ENDC}")


def sync_approvals_config(
    params: 'KeeperParams',
    config: ApprovalsConfig,
    command_name: str = '',
) -> Tuple[ApprovalsConfig, ApprovalsDriftReport]:
    """Remove stale vault references and refresh team names. Non-interactive."""
    if not config.multi_channel_enabled:
        raise CommandError(
            command_name,
            'Single-channel mode has no approver team mappings to sync. '
            'Re-run setup or enable multi-channel approvers first.',
        )

    cleaned, report = analyze_approvals_drift(params, config)
    print_approvals_drift_report(report)

    if not cleaned.teams and config.teams:
        print(
            f"  {bcolors.OKBLUE}All configured approver teams were removed. "
            f'Requests will use the default approvals channel until teams are added again.{bcolors.ENDC}'
        )

    return cleaned, report


def run_approvals_sync_down(
    params: 'KeeperParams',
    record_uid: str,
    marker_field: str,
    update_record: Callable[[str, ApprovalsConfig], None],
    command_name: str = '',
    sync_vault: bool = True,
) -> ApprovalsConfig:
    if sync_vault:
        params.sync_data = True
        api.sync_down(params)

    record = vault.KeeperRecord.load(params, record_uid)
    if not record:
        raise CommandError(command_name, f'Record not found: {record_uid}')

    fields = custom_fields_by_label(record)
    if marker_field not in fields:
        raise CommandError(
            command_name,
            f'Record {record_uid} is not a supported integration config record '
            f'(missing "{marker_field}" field)',
        )

    config = parse_approvals_from_record(record, command_name=command_name)
    updated, report = sync_approvals_config(params, config, command_name=command_name)

    if report.has_changes:
        update_record(record_uid, updated)
        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Approver configuration synced with vault{bcolors.ENDC}")
    else:
        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ Approver configuration is already up to date{bcolors.ENDC}")

    print_approvals_config(updated)
    return updated
