#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..base import Command, user_choice
from ... import utils
from ...error import CommandError
from ...importer.cyberark.pam.import_builder import format_unmapped_section, strip_credentials, validate_import_data
from ...importer.cyberark.pam.user_team_matcher import UserTeamMatcher
from ...importer.thycotic.pam import (
    AccessGrant, Crosswalk, DelineaPamClient, FindingLog, PermissionMapper, Principal, PrincipalKind,
    RotationMapper, RotationPolicy, SecretGrantTarget, build_pam_import,
)
from .cyberark_import import SecureTempFileStore
from .delinea_access import COMMAND, apply_secret_grants, choose_nsf, run_with_classic_fallback

_temp_store = SecureTempFileStore()
DEFAULT_IMPORT_JSON = 'delinea_import.json'


def _all_users(resources: Optional[List[dict]], users: Optional[List[dict]] = None) -> List[dict]:
    """Top-level users plus the users nested under each resource."""
    return list(users or []) + [user for resource in resources or [] for user in resource.get('users') or []]


def _normalize_folder_path(path: str) -> str:
    """Backslash separators, no edge slashes, casefolded."""
    return (path or '').replace('/', '\\').strip().strip('\\').casefold()


def select_folders(folders: List[dict], prefixes: List[str]) -> List[dict]:
    """Keep folders whose path starts with one of ``prefixes``. Empty means all."""
    wanted = [_normalize_folder_path(prefix) for prefix in prefixes if prefix.strip()]
    if not wanted:
        return list(folders)
    selected = []
    for folder in folders:
        path = _normalize_folder_path(folder.get('folderPath') or folder.get('folderName'))
        name = (folder.get('folderName') or '').casefold()
        if any(path == prefix or path.startswith(prefix + '\\') or name == prefix for prefix in wanted):
            selected.append(folder)
    return selected


@dataclass
class DelineaImportOptions:
    server: str
    project_name: str = 'Delinea Migration'
    gateway: str = ''
    use_nsf: bool = False
    folders: List[str] = field(default_factory=list)
    dry_run: bool = False
    output_file: str = ''
    include_credentials: bool = False
    yes: bool = False
    skip_permissions: bool = False
    crosswalk_file: str = ''
    crosswalk_out: str = ''
    crosswalk_check: int = 0
    user_map_file: str = ''

    @classmethod
    def from_kwargs(cls, kwargs: dict) -> 'DelineaImportOptions':
        server = kwargs.get('server') or ''
        if not server:
            raise CommandError(
                COMMAND, 'Secret Server host or URL is required')
        check = int(kwargs.get('crosswalk_check') or 0)
        if check < 0:
            raise CommandError(COMMAND, '--crosswalk-check must be >= 0')
        return cls(
            server=server,
            project_name=kwargs.get('project_name') or 'Delinea Migration',
            gateway=kwargs.get('gateway') or '',
            use_nsf=kwargs.get('use_nsf') is True,
            folders=[x.strip() for x in (kwargs.get('folders')
                                         or '').split(',') if x.strip()],
            dry_run=kwargs.get('dry_run') is True,
            output_file=kwargs.get('output') or '',
            include_credentials=kwargs.get('include_credentials') is True,
            yes=kwargs.get('yes') is True,
            skip_permissions=kwargs.get('skip_permissions') is True,
            crosswalk_file=kwargs.get('crosswalk') or '',
            crosswalk_out=kwargs.get('crosswalk_out') or '',
            crosswalk_check=check,
            user_map_file=kwargs.get('user_map') or '',
        )


@dataclass
class DelineaMappedImport:
    resources: List[dict] = field(default_factory=list)
    users: List[dict] = field(default_factory=list)
    folder_grants: Dict[str, List[AccessGrant]] = field(default_factory=dict)
    secret_grants: List[SecretGrantTarget] = field(default_factory=list)
    rotations: List[RotationPolicy] = field(default_factory=list)


class DelineaImportOrchestrator:
    """Runs one ``pam project delinea-import``: map, build JSON, import, apply secret grants, report."""

    def __init__(self, params, client: DelineaPamClient, options: DelineaImportOptions):
        self.params = params
        self.client = client
        self.options = options
        self.findings = FindingLog()
        self.permissions = PermissionMapper({}, {}, self.findings)
        self.matcher: Optional[UserTeamMatcher] = None
        self.import_document: dict = {}

    def run(self) -> None:
        opts = self.options
        if opts.crosswalk_out or opts.crosswalk_check:
            crosswalk = Crosswalk.load(opts.crosswalk_file) if opts.crosswalk_file else Crosswalk()
            self.run_crosswalk(crosswalk)
            return
        if opts.crosswalk_file:
            logging.warning('Password changer crosswalk file is not applied; using the built-in map')

        mapped = self.map(Crosswalk())
        users = _all_users(mapped.resources, mapped.users)
        for warning in validate_import_data(mapped.resources, mapped.users):
            logging.warning(warning)

        json_path = opts.output_file or DEFAULT_IMPORT_JSON
        self.write_output(self.import_document, json_path)
        if opts.dry_run:
            self.print_dry_run(mapped)
            return
        if opts.output_file:
            return
        if not opts.yes and user_choice(f'Import {len(mapped.resources)} resources and {len(users)} users '
                                        f'into "{opts.project_name}"?', 'yn', 'n').lower() != 'y':
            return

        use_nsf = choose_nsf(self.params, opts.use_nsf, self.findings)
        used_nsf = run_with_classic_fallback(
            self.params, opts.project_name, use_nsf,
            lambda nsf: self.import_project(self.import_document, nsf),
            self.findings,
        )
        if mapped.secret_grants and not opts.skip_permissions:
            apply_secret_grants(self.params, mapped.secret_grants,
                                used_nsf, self.keeper_email, self.findings)
        self.report(mapped, used_nsf=used_nsf)

    def run_crosswalk(self, crosswalk: Crosswalk) -> None:
        """``--crosswalk-out``: discover and write the template. ``--crosswalk-check N``: validate and print."""
        raise NotImplementedError

    def map(self, crosswalk: Crosswalk) -> DelineaMappedImport:
        """Read Secret Server and build ``self.import_document``. No vault writes."""
        logging.debug('Using built-in password changer map (%d changers)', len(crosswalk.mappings))
        folders = select_folders(self.client.folder_secret_details(), self.options.folders)
        if self.options.folders and not folders:
            logging.warning('No Secret Server folders matched --folders %s', ', '.join(self.options.folders))
        document = build_pam_import(folders, self.options.project_name)
        if self.options.gateway:
            document['pam_configuration']['gateway_name'] = self.options.gateway
        self.import_document = document
        return DelineaMappedImport(resources=document['pam_data']['resources'])

    def build_matcher(self) -> UserTeamMatcher:
        """``UserTeamMatcher`` over enterprise users / teams and the ``--user-map`` JSON object."""
        raise NotImplementedError

    def keeper_name(self, principal: Principal) -> Optional[str]:
        if not self.matcher:
            return None
        if principal.kind is PrincipalKind.TEAM:
            return self.matcher.match_team(principal.name)
        return self.matcher.match_user(principal.name, principal.email)

    def keeper_email(self, principal: Principal) -> Optional[str]:
        return self.keeper_name(principal) if principal.kind is PrincipalKind.USER else None

    def build_import_json(self, mapped: DelineaMappedImport, use_nsf: bool) -> dict:
        opts = self.options
        pam_configuration = {
            'environment': 'local',
            'title': f'{opts.project_name} Configuration',
            'connections': 'on',
            'rotation': 'on',
            'tunneling': 'off',
            'graphical_session_recording': 'on',
            'text_session_recording': 'on',
            'remote_browser_isolation': 'off',
            'default_rotation_schedule': {'type': 'on-demand'},
        }
        if opts.gateway:
            pam_configuration['gateway_name'] = opts.gateway

        safe_folders = []
        for name, grants in mapped.folder_grants.items():
            entries = []
            for grant in grants:
                keeper_name = self.keeper_name(grant.principal)
                entry = self.permissions.to_permission_entry(
                    grant, keeper_name, use_nsf) if keeper_name else None
                if entry:
                    entries.append(entry)
            safe_folders.append({'name': name, 'safe_name': name, 'permissions': entries,
                                 **self.permissions.classic_folder_defaults(name, grants)})

        return {
            'project': opts.project_name,
            'pam_configuration': pam_configuration,
            'pam_data': {'resources': mapped.resources, 'users': mapped.users},
            'safe_folders': safe_folders,
        }

    def import_project(self, import_data: dict, use_nsf: bool) -> None:
        from .edit import PAMProjectImportCommand
        path = _temp_store.write_json(import_data)
        try:
            PAMProjectImportCommand().execute(self.params, project_name=self.options.project_name,
                                              file_name=path, dry_run=False, use_nsf=use_nsf)
        finally:
            _temp_store.remove(path)

    def write_output(self, import_data: dict, path: str = '') -> None:
        """Save the redacted import document (default ``delinea_import.json``)."""
        path = path or self.options.output_file or DEFAULT_IMPORT_JSON
        data = self.redacted_document(import_data)
        # Lock permissions before writing (0o600 on POSIX, ACL on Windows).
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        utils.set_file_permissions(path)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        print(f'Import JSON saved to: {path}')

    def print_dry_run(self, mapped: DelineaMappedImport) -> None:
        """Print the import document without writing to the vault."""
        users = _all_users(mapped.resources, mapped.users)
        print('[DRY RUN] No changes will be made to the vault.\n')
        print(json.dumps(self.redacted_document(self.import_document), indent=2))
        print()
        print(f'[DRY RUN COMPLETE] {len(mapped.resources)} resources, {len(users)} users would be imported.')
        section = format_unmapped_section([f.to_dict() for f in self.findings])
        if section:
            print(section)

    def redacted_document(self, import_data: dict) -> dict:
        data = copy.deepcopy(import_data)
        if self.options.include_credentials:
            return data
        strip_credentials(data)
        pam_data = data.get('pam_data') or {}
        for user in _all_users(pam_data.get('resources'), pam_data.get('users')):
            if user.get('private_pem_key'):
                user['private_pem_key'] = '***'
        return data

    def report(self, mapped: DelineaMappedImport, used_nsf: Optional[bool]) -> None:
        mode = 'dry run' if used_nsf is None else (
            'Nested Share Folders' if used_nsf else 'classic shared folders')
        users = _all_users(mapped.resources, mapped.users)
        print(f'\nDelinea import ({mode}): {len(mapped.resources)} resources, {len(users)} users, '
              f'{len(mapped.folder_grants)} folders, {len(mapped.secret_grants)} secrets with own permissions')
        if mapped.rotations:
            rotation = RotationMapper.summary(mapped.rotations)
            print('Rotation: ' + ', '.join(f'{k} {v}' for k, v in sorted(rotation.items())))
        else:
            enabled = sum(1 for user in users if (user.get('rotation_settings') or {}).get('enabled') == 'on')
            print(f'Rotation: enabled {enabled}, disabled {len(users) - enabled}')
        section = format_unmapped_section([f.to_dict() for f in self.findings])
        if section:
            print(section)


class DelineaPAMImportCommand(Command):
    parser = argparse.ArgumentParser(
        prog=COMMAND,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Write the password changer crosswalk template, edit it, then validate it
  pam project delinea-import ss.example.com --crosswalk-out crosswalk.csv
  pam project delinea-import ss.example.com --crosswalk crosswalk.csv --crosswalk-check 3

  # Write delinea_import.json and print it. Nothing is imported.
  pam project delinea-import ss.example.com --dry-run

  # Write review.json and exit
  pam project delinea-import ss.example.com --output review.json

  # Import into Nested Share Folders (falls back to classic if NSF is unavailable)
  pam project delinea-import ss.example.com --name "PAM Migration" --gateway "GW1" --nsf
        ''')
    parser.add_argument('server', action='store',
                        help='Secret Server host or URL')
    parser.add_argument('--name', '-n', dest='project_name', action='store', default='',
                        help='PAM project name (default: Delinea Migration)')
    parser.add_argument('--gateway', '-g', dest='gateway', action='store', default='',
                        help='Keeper Gateway name for the PAM configuration')
    parser.add_argument('--nsf', dest='use_nsf', action='store_true',
                        help='Create folders as Nested Share Folders; falls back to classic when unavailable')
    parser.add_argument('--folders', dest='folders', action='store', default='',
                        help='Comma-separated Secret Server folder paths to import (default: all)')
    parser.add_argument('--dry-run', '-d', dest='dry_run', action='store_true',
                        help='Preview the import JSON without modifying the vault')
    parser.add_argument('--output', '-o', dest='output', action='store', default='',
                        help='Save the import JSON to this file and exit (default file: delinea_import.json)')
    parser.add_argument('--include-credentials', dest='include_credentials', action='store_true',
                        help='Include passwords in --output or --dry-run display')
    parser.add_argument('--yes', '-y', dest='yes',
                        action='store_true', help='Skip the confirmation prompt')
    parser.add_argument('--skip-permissions', dest='skip_permissions', action='store_true',
                        help='Do not migrate folder or secret permissions')
    parser.add_argument('--user-map', dest='user_map', action='store', default='',
                        help='JSON object mapping Secret Server user/group names to Keeper emails/teams')
    parser.add_argument('--crosswalk', dest='crosswalk', action='store', default='',
                        help='Password changer crosswalk CSV (overrides the built-in map)')
    parser.add_argument('--crosswalk-out', dest='crosswalk_out', action='store', default='',
                        help='Write every password changer, protocol and port to this CSV and exit')
    parser.add_argument('--crosswalk-check', dest='crosswalk_check', action='store', type=int, default=0,
                        help='Validate the crosswalk against N sample secrets per changer and exit')

    def get_parser(self):
        return DelineaPAMImportCommand.parser

    def execute(self, params, **kwargs):
        options = DelineaImportOptions.from_kwargs(kwargs)
        client = DelineaPamClient.connect(
            options.server, proxy=params.rest_context.proxies)
        if not client:
            raise CommandError(COMMAND, 'Could not connect to Secret Server')
        DelineaImportOrchestrator(params, client, options).run()