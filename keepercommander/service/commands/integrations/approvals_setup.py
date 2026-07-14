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

"""Shared approval-channel setup for integration app setup commands."""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Callable, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from .... import api, utils, vault
from ....display import bcolors
from ...docker import ApprovalsConfig, ApproverTeam

if TYPE_CHECKING:
    from ....params import KeeperParams

logger = logging.getLogger(__name__)

FIELD_MULTI_CHANNEL_ENABLED = 'multi_channel_approvers_enabled'
FIELD_APPROVALS_CHANNEL_ID = 'approvals_channel_id'
FIELD_APPROVALS_TEAMS = 'approvals_teams'
APPROVALS_FIELD_LABELS = frozenset({
    FIELD_MULTI_CHANNEL_ENABLED,
    FIELD_APPROVALS_CHANNEL_ID,
    FIELD_APPROVALS_TEAMS,
})


@dataclass
class ApprovalsChannelProfile:
    """Platform-specific labels and channel ID validation."""
    channel_header: str
    single_channel_description: str
    channel_description: str
    default_channel_description: str
    channel_prompt: str
    validate_channel: Callable[[str], bool]
    channel_error: str


SLACK_APPROVALS_PROFILE = ApprovalsChannelProfile(
    channel_header='APPROVALS_CHANNEL_ID',
    single_channel_description='Slack channel ID for approval notifications',
    channel_description='Slack channel where approval requests for this approver team are sent',
    default_channel_description=(
        'Default channel for EPM privilege requests, SSO Cloud device approvals, '
        'and approval requests from users not assigned to an approver team'
    ),
    channel_prompt='Channel ID (starts with C):',
    validate_channel=lambda c: bool(c and c.startswith('C')),
    channel_error="Invalid Approvals Channel ID (must start with 'C')",
)


def is_valid_keeper_uid(value: str) -> bool:
    if not value or not value.strip():
        return False
    try:
        return len(utils.base64_url_decode(value.strip())) == 16
    except Exception:
        return False


def parse_comma_separated_uids(raw: str) -> List[str]:
    if not raw or not raw.strip():
        return []
    return [part.strip() for part in raw.split(',') if part.strip()]


def build_team_lookup(
    params: 'KeeperParams',
) -> Tuple[Dict[str, Tuple[str, str]], Dict[str, List[Tuple[str, str]]]]:
    """Build team UID and case-insensitive name lookups from cached vault data."""
    if params.available_team_cache is None:
        try:
            api.load_available_teams(params)
        except Exception as exc:
            logger.debug('Could not load available teams: %s', exc)

    by_uid: Dict[str, Tuple[str, str]] = {}
    by_name_lower: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

    def add_team(team_uid: str, team_name: str) -> None:
        if not team_uid:
            return
        name = team_name or team_uid
        if team_uid not in by_uid:
            by_uid[team_uid] = (team_uid, name)
        by_name_lower[name.casefold()].append((team_uid, name))

    for team_uid, team_data in params.team_cache.items():
        add_team(team_uid, team_data.get('name', ''))

    enterprise = params.enterprise or {}
    for source_key in ('teams', 'queued_teams'):
        for team in enterprise.get(source_key, []):
            add_team(team.get('team_uid', ''), team.get('name', ''))

    for team in params.available_team_cache or []:
        add_team(team.get('team_uid', ''), team.get('team_name', ''))

    return by_uid, by_name_lower


def build_shared_folder_uids(params: 'KeeperParams') -> Set[str]:
    """Shared folders and nested share folders only (not private user folders)."""
    uids = set(params.shared_folder_cache.keys())
    uids.update(getattr(params, 'nested_share_folders', {}).keys())
    uids.discard('')
    return uids


def build_record_uids(params: 'KeeperParams') -> Set[str]:
    uids = set(params.record_cache.keys())
    uids.update(getattr(params, 'nested_share_records', {}).keys())
    return uids


def _resolve_keeper_team(
    team_input: str,
    by_uid: Dict[str, Tuple[str, str]],
    by_name_lower: Dict[str, List[Tuple[str, str]]],
) -> Tuple[Optional[Tuple[str, str]], Optional[str]]:
    value = team_input.strip()
    if not value:
        return None, 'Team name or UID is required'

    if value in by_uid:
        return by_uid[value], None

    matches = list({(uid, name) for uid, name in by_name_lower.get(value.casefold(), [])})
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, f'Team name "{value}" is not unique. Use the team UID.'
    return None, f'Team "{value}" not found. Use a valid team name or team UID.'


def _prompt_keeper_team(
    by_uid: Dict[str, Tuple[str, str]],
    by_name_lower: Dict[str, List[Tuple[str, str]]],
) -> Tuple[str, str]:
    print(f"\n{bcolors.BOLD}TEAM:{bcolors.ENDC}")
    print(f"  Keeper team name or team UID for this approver group")
    while True:
        value = input(f"{bcolors.OKBLUE}Team name or UID:{bcolors.ENDC} ").strip()
        resolved, error = _resolve_keeper_team(value, by_uid, by_name_lower)
        if resolved:
            return resolved
        print(f"{bcolors.FAIL}Error: {error}{bcolors.ENDC}")


def _validate_uids(
    uids: List[str],
    known_uids: Set[str],
    uid_label: str,
    mistyped: Optional[Dict[str, Set[str]]] = None,
) -> List[str]:
    """Return validation errors for UIDs. mistyped maps error message -> UID set."""
    errors: List[str] = []
    mistyped = mistyped or {}
    for uid in uids:
        if uid in known_uids:
            continue
        typed_error = next((msg for msg, bad_uids in mistyped.items() if uid in bad_uids), None)
        if typed_error:
            errors.append(typed_error.format(uid=uid))
        else:
            errors.append(
                f'{uid_label} UID "{uid}" not found in your vault '
                f'(run "sync-down" if it was recently added)'
            )
    return errors


def _prompt_vault_uid_list(
    header: str,
    description: str,
    prompt_label: str,
    known_uids: Set[str],
    uid_label: str,
    mistyped: Optional[Dict[str, Set[str]]] = None,
) -> List[str]:
    print(f"\n{bcolors.BOLD}{header}:{bcolors.ENDC}")
    print(f"  {description}")
    while True:
        value = input(f"{bcolors.OKBLUE}{prompt_label}{bcolors.ENDC} ").strip()
        if not value:
            return []
        uids = parse_comma_separated_uids(value)
        if not uids or not all(is_valid_keeper_uid(uid) for uid in uids):
            print(f"{bcolors.FAIL}Error: Each UID must be a valid Keeper {uid_label} UID{bcolors.ENDC}")
            continue
        errors = _validate_uids(uids, known_uids, uid_label, mistyped=mistyped)
        if errors:
            for error in errors:
                print(f"{bcolors.FAIL}Error: {error}{bcolors.ENDC}")
            continue
        return uids


def _prompt_channel(
    profile: ApprovalsChannelProfile,
    prompt_with_validation: Callable[[str, Callable[[str], bool], str], str],
    description: str,
    header: Optional[str] = None,
) -> str:
    print(f"\n{bcolors.BOLD}{header or profile.channel_header}:{bcolors.ENDC}")
    print(f"  {description}")
    return prompt_with_validation(
        profile.channel_prompt,
        profile.validate_channel,
        profile.channel_error,
    )


def collect_approvals_config(
    params: 'KeeperParams',
    prompt_yes_no: Callable[[str, bool], bool],
    prompt_with_validation: Callable[[str, Callable[[str], bool], str], str],
    profile: ApprovalsChannelProfile,
) -> ApprovalsConfig:
    """Collect single- or multi-channel approval routing configuration."""
    print(f"\n{bcolors.BOLD}MULTI-CHANNEL APPROVERS:{bcolors.ENDC}")
    print(f"  Route approval notifications to different channels by approver team")
    multi_channel = prompt_yes_no('Enable multi-channel approvers?', default=False)

    if not multi_channel:
        return ApprovalsConfig(
            multi_channel_enabled=False,
            single_channel_id=_prompt_channel(
                profile, prompt_with_validation, profile.single_channel_description,
            ),
        )

    teams: List[ApproverTeam] = []
    by_uid, by_name_lower = build_team_lookup(params)
    while True:
        team_uid, team_name = _prompt_keeper_team(by_uid, by_name_lower)
        channel_id = _prompt_channel(
            profile,
            prompt_with_validation,
            f'{profile.channel_description} for {team_name}',
        )
        teams.append(ApproverTeam(
            team_uid=team_uid,
            name=team_name,
            channel_id=channel_id,
        ))
        if not prompt_yes_no('Add another approver team?', default=False):
            break

    print(f"\n{bcolors.BOLD}FOLDER/RECORD BOUNDARIES (optional):{bcolors.ENDC}")
    print(f"  Restrict each team to specific shared folder or record UIDs")
    if prompt_yes_no('Specify shared folder or record UIDs per team?', default=False):
        teams = _collect_team_boundaries(params, teams)

    return ApprovalsConfig(
        multi_channel_enabled=True,
        single_channel_id=_prompt_channel(
            profile,
            prompt_with_validation,
            profile.default_channel_description,
            header=f'DEFAULT {profile.channel_header}',
        ),
        teams=teams,
    )


def _collect_team_boundaries(
    params: 'KeeperParams',
    teams: List[ApproverTeam],
) -> List[ApproverTeam]:
    shared_folder_uids = build_shared_folder_uids(params)
    record_uids = build_record_uids(params)
    user_folder_uids = (
        set(params.folder_cache.keys()) | set(params.subfolder_cache.keys())
    ) - shared_folder_uids - {''}

    updated: List[ApproverTeam] = []
    for team in teams:
        folders = _prompt_vault_uid_list(
            f'SHARED FOLDER UIDs FOR {team.name}',
            'Comma-separated shared folder UIDs (optional, press Enter to skip)',
            'Shared Folder UIDs:',
            shared_folder_uids,
            'shared folder',
            mistyped={
                '"{uid}" is a record UID, not a shared folder UID': record_uids,
                '"{uid}" is not a shared folder UID (use a shared folder UID from list-sf)': user_folder_uids,
            },
        )
        records = _prompt_vault_uid_list(
            f'RECORD UIDs FOR {team.name}',
            'Comma-separated record UIDs (optional, press Enter to skip)',
            'Record UIDs:',
            record_uids,
            'record',
            mistyped={
                '"{uid}" is a shared folder UID, not a record UID': shared_folder_uids,
            },
        )
        updated.append(replace(team, folder_uids=folders, record_uids=records))
    return updated


def approvals_config_to_record_fields(config: ApprovalsConfig) -> List:
    teams_json = ''
    if config.multi_channel_enabled:
        teams_json = json.dumps([
            {
                'team_uid': team.team_uid,
                'name': team.name,
                'channel_id': team.channel_id,
                'folder_uids': team.folder_uids,
                'record_uids': team.record_uids,
            }
            for team in config.teams
        ], indent=2)

    return [
        vault.TypedField.new_field(
            'text',
            'true' if config.multi_channel_enabled else 'false',
            FIELD_MULTI_CHANNEL_ENABLED,
        ),
        vault.TypedField.new_field(
            'text',
            config.single_channel_id,
            FIELD_APPROVALS_CHANNEL_ID,
        ),
        vault.TypedField.new_field('multiline', teams_json, FIELD_APPROVALS_TEAMS),
    ]


def print_approvals_config(config: ApprovalsConfig) -> None:
    if not config.multi_channel_enabled:
        print(f"    • Approvals Channel: {bcolors.OKBLUE}{config.single_channel_id}{bcolors.ENDC}")
        return

    print(f"    • Multi-Channel Approvers: {bcolors.OKBLUE}enabled ({len(config.teams)} teams){bcolors.ENDC}")
    print(f"    • Default Approvals Channel: {bcolors.OKBLUE}{config.single_channel_id}{bcolors.ENDC}")
    for team in config.teams:
        print(f"    • {team.name} ({team.team_uid}): channel {bcolors.OKBLUE}{team.channel_id}{bcolors.ENDC}")
        if team.folder_uids:
            print(f"      Shared Folder UIDs: {', '.join(team.folder_uids)}")
        if team.record_uids:
            print(f"      Record UIDs: {', '.join(team.record_uids)}")
