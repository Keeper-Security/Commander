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
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..base import Command, user_choice
from ... import utils
from ...error import CommandError
from ...importer.cyberark.pam.import_builder import format_unmapped_section, strip_credentials, validate_import_data
from ...importer.cyberark.pam.user_team_matcher import UserTeamMatcher
from ...importer.thycotic.pam import (
    AccessGrant, Crosswalk, DelineaPamClient, FindingLog, PermissionMapper, Principal, PrincipalKind,
    RotationMapper, RotationPolicy, SecretGrantTarget,
)
from .cyberark_import import SecureTempFileStore
from .delinea_access import COMMAND, apply_secret_grants, choose_nsf, run_with_classic_fallback

_temp_store = SecureTempFileStore()


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

    def run(self) -> None:
        opts = self.options
        crosswalk = Crosswalk.load(
            opts.crosswalk_file) if opts.crosswalk_file else Crosswalk()
        if opts.crosswalk_out or opts.crosswalk_check:
            self.run_crosswalk(crosswalk)
            return

        use_nsf = choose_nsf(self.params, opts.use_nsf, self.findings)
        mapped = self.map(crosswalk)
        for warning in validate_import_data(mapped.resources, mapped.users):
            logging.warning(warning)

        if opts.output_file:
            self.write_output(self.build_import_json(mapped, use_nsf))
        if opts.dry_run:
            self.report(mapped, used_nsf=None)
            return
        if not opts.yes and user_choice(f'Import {len(mapped.resources)} resources and {len(mapped.users)} users '
                                        f'into "{opts.project_name}"?', 'yn', 'n').lower() != 'y':
            return

        used_nsf = run_with_classic_fallback(
            self.params, opts.project_name, use_nsf,
            lambda nsf: self.import_project(
                self.build_import_json(mapped, nsf), nsf),
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
        """Read Secret Server and map everything; no vault writes.

        1. ``permission_boundaries(client.folders())`` limited to ``options.folders``
           (folder path prefixes; empty means all); each boundary is named by
           ``SafeFolderMapper('safe')``. ``self.permissions`` is built from
           ``client.users()`` / ``client.groups()``.
        2. ``folder_grants`` has a key for every boundary that receives records;
           unless ``skip_permissions`` its value is
           ``self.permissions.folder_grants(client.folder_permissions(boundary))``
           and ``self.matcher`` comes from ``build_matcher``.
        3. Per secret in ``client.secret_ids``: ``SecretMapper.map_secret``; then
           ``client.secret_permissions`` and ``PermissionMapper.is_override`` give
           ``secret_grants``.
        4. Each id in ``MappedSecret.references`` is fetched once and emitted via
           ``map_reference`` into ``users``; resources go through ``merge_resources``.
        5. More than one distinct ``RotationPolicy.site_name`` adds a Finding (one
           gateway per PAM configuration).
        """
        raise NotImplementedError

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

    def write_output(self, import_data: dict) -> None:
        data = copy.deepcopy(import_data)
        if not self.options.include_credentials:
            strip_credentials(data)
            for user in data['pam_data']['users'] + [u for r in data['pam_data']['resources']
                                                     for u in r.get('users', [])]:
                if user.get('private_pem_key'):
                    user['private_pem_key'] = '***'
        with open(self.options.output_file, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        utils.set_file_permissions(self.options.output_file)
        logging.info('Import JSON written to %s', self.options.output_file)

    def report(self, mapped: DelineaMappedImport, used_nsf: Optional[bool]) -> None:
        mode = 'dry run' if used_nsf is None else (
            'Nested Share Folders' if used_nsf else 'classic shared folders')
        print(f'\nDelinea import ({mode}): {len(mapped.resources)} resources, {len(mapped.users)} users, '
              f'{len(mapped.folder_grants)} folders, {len(mapped.secret_grants)} secrets with own permissions')
        rotation = RotationMapper.summary(mapped.rotations)
        print('Rotation: ' +
              ', '.join(f'{k} {v}' for k, v in sorted(rotation.items())))
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

  # Review the import without writing to the vault
  pam project delinea-import ss.example.com --crosswalk crosswalk.csv --dry-run --output review.json

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
                        help='Map and report without writing to the vault')
    parser.add_argument('--output', '-o', dest='output', action='store', default='',
                        help='Write the generated import JSON to this file')
    parser.add_argument('--include-credentials', dest='include_credentials', action='store_true',
                        help='Keep passwords and private keys in --output')
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
