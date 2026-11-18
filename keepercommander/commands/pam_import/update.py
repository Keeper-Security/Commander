#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""`pam project update` - bring EXISTING PAM records in line with an import JSON.

Phases: options -> JSON -> scope of the KSM app -> match every JSON item to a vault record -> read the current
state -> compare -> report -> (confirm) -> apply. This module does the I/O and the orchestration; the matching and
the comparison are pure (``update_plan``, ``update_diff``, ``update_compare``), the output is ``update_report``.

STATUS: the planning side is complete (`-d`, `--estimate`, `--format json`). The WRITE side (``update_apply``) is not
written yet: a write run stops with an error after it has shown the plan.
"""

from __future__ import annotations

import argparse
import json
import logging
import os.path
import sys
from typing import Any, Dict, List, Optional

from .import_items import KIND_RESOURCE, load_items
from .ksm_scope import collect_ksm_scope
from .nsf_helpers import find_pam_configuration, get_ksm_app_folders
from .port_forward_validation import preflight_port_forward
from .record_matcher import RecordIndex
from . import update_diff as ud
from . import update_plan as up
from . import update_report as report
from .vault_reader import read_vault_state
from .workflow_apply import approver_warnings
from ..base import Command
from ..pam import gateway_helper
from ..pam.config_helper import configuration_controller_get
from ... import api, utils, vault
from ...display import bcolors
from ...error import CommandError
from ...proto import pam_pb2

PROG = 'pam project update'

SYNTAX_HELP = '''\
pam project update - bring EXISTING PAM records in line with an import JSON

WHAT IT DOES
  Reads the same JSON as `pam project import` and `pam project extend`, compares it with the records and the
  graph settings (connection, JIT, KeeperAI, rotation, workflow ...) that are already in the vault and changes
  only what differs. It never creates and never removes records:
    in the JSON but not in the vault -> error: run `pam project extend` first (nothing is written)
    in the vault but not in the JSON -> counted and left alone

  Only the keys you WROTE in the JSON are compared. A key you did not write is never reset to a default.

MODES (--mode)
  merge      (default) keep everything the JSON does not mention; where both set a value the JSON wins;
                       lists are merged (union)
  overwrite            the record becomes what the JSON describes:
                         - the settings object (pamSettings / pamRemoteBrowserSettings) is acted on ONLY when the
                           JSON item has a `pam_settings` section; keys not part of it are REMOVED
                         - custom fields are acted on ONLY when the JSON item has a `custom` list
                         - known fields the JSON does not set are removed (never title, host, port, URL, secrets)
                         - graph settings are not removed yet (that rule is still to be decided)
  Never touched in either mode: record uid / type / folder, locked, service_names, attachments.

PASSWORDS (--include-passwords)
  By default passwords are skipped (rotation may have changed them in the vault). If some differ you get one
  warning with the count. With --include-passwords the vault passwords are REPLACED by the JSON ones. Omitting a
  password from the JSON never removes it. Passwords, secrets and notes are never printed.

READING THE REPORT
  Record = changed record fields    Graph = changed graph / rotation / workflow settings
  ~ changed   + added   - removed (overwrite only)       -v lists every change and the identical records

NO UNDO
  Record fields can be restored from the record history in the Web Vault; graph settings cannot be restored with
  Commander. Run with -d first, especially before --mode overwrite.

EXAMPLES
  1. See what would change (nothing is written):      pam project update -c "Prod Config" -f import.json -d
  2. The same, field by field:                        pam project update -c "Prod Config" -f import.json -d -v
  3. Apply it (shows the plan, asks to continue):     pam project update -c "Prod Config" -f import.json
  4. Apply without the question (scripts, Service Mode): ... -y
  5. Make the vault match the JSON exactly:           ... --mode overwrite -d      (review, then add -y)
  6. Also replace the vault passwords with the JSON:  ... --include-passwords -d
  7. Quick count of what differs:                     ... --estimate
'''

# options that make `--syntax-help` an error when combined with it: name -> value that means "not given"
_OTHER_OPTIONS = {'config': None, 'file_name': None, 'output_format': 'text', 'dry_run': False, 'verbose': False,
                  'yes': False, 'mode': 'merge', 'include_passwords': False, 'skip_attachments': False,
                  'estimate': False}


def load_import_json(file_name: str) -> Dict[str, Any]:
    """The JSON of ``--filename``: a file, or the JSON text itself."""
    data: Any = {}
    if not (file_name != '' and os.path.isfile(file_name)):
        try:
            data = json.loads(file_name)
        except ValueError:
            raise CommandError(PROG, f'''PAM Import JSON file not found: "{file_name}" ''')
    if not data:
        try:
            with open(file_name, encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            raise CommandError(PROG, f'''Unable to read file "{file_name}": {e}''')
    if not isinstance(data, dict):
        raise CommandError(PROG, 'The import JSON must be an object like {"pam_data": {"resources": [], "users": []}}')
    return data


def check_options(params, kwargs: Dict[str, Any], stdin_is_tty: Optional[bool] = None) -> None:
    """Argument errors (raised, never returned as plan errors)."""
    if kwargs.get('syntax_help'):
        given = [name for name, default in _OTHER_OPTIONS.items() if kwargs.get(name) not in (None, '', default)]
        if given:
            raise CommandError(PROG, '--syntax-help cannot be combined with other options')
        return
    if not kwargs.get('config') or not kwargs.get('file_name'):
        raise CommandError(PROG, '--config and --filename are required (except with --syntax-help)')
    dry = bool(kwargs.get('dry_run') or kwargs.get('estimate'))
    if kwargs.get('output_format') == 'json' and not (kwargs.get('yes') or dry):
        # a confirmation prompt would be mixed into the JSON on stdout
        raise CommandError(PROG, '--format json needs -y, -d or --estimate')
    if not dry and not kwargs.get('yes'):
        # Same explicit-consent rule as `nsf-convert` (needs -f/--force in Service Mode) and `universalsecretsync`
        # (never applies in Service Mode): a command that can overwrite or remove data is not confirmed implicitly.
        # In Service Mode, or whenever stdin is not a terminal, there is nobody to answer a prompt.
        tty = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
        if getattr(params, 'service_mode', False) or not tty:
            raise CommandError(PROG, f'{PROG} needs -y (or -d) in Service Mode and when input is not a terminal')


def _config_of(params):
    """The configuration a record belongs to, where the vault says so: the rotation cache holds it for a user (or
    resource) with a rotation. None = unknown (the PAM graph check after reading covers the resources)."""
    def config_of(uid: str):
        entry = (getattr(params, 'record_rotation_cache', None) or {}).get(uid)
        return (entry or {}).get('configuration_uid') or None
    return config_of


def _can_write(params):
    def can_write(uid: str):
        if uid not in (params.record_cache or {}):
            return None                      # unknown (for example a Nested Share Folder record): allowed
        return api.resolve_record_write_path(params, uid) is not None
    return can_write


def _find_ksm_app(params, configuration) -> tuple:
    controller = configuration_controller_get(params, utils.base64_url_decode(configuration.record_uid))
    if not (controller and isinstance(controller, pam_pb2.PAMController) and controller.controllerUid):   # pylint: disable=no-member
        raise CommandError(PROG, f'Gateway UID not found for configuration {configuration.record_uid}.')
    gateways = [g for g in gateway_helper.get_all_gateways(params) if g.controllerUid == controller.controllerUid]
    if not gateways:
        raise CommandError(PROG, f'KSM APP UID not found for Gateway {utils.base64_url_encode(controller.controllerUid)}.')
    app_uid = utils.base64_url_encode(gateways[0].applicationUid)
    app = vault.KeeperRecord.load(params, app_uid)
    if not (app and isinstance(app, vault.ApplicationRecord) and app.version == 5):
        raise CommandError(PROG, f'PAM KSM Application record not found: "{app_uid}"')
    return app_uid, app, controller


def _wants_workflow(item) -> bool:
    settings = item.raw.get('pam_settings') if isinstance(item.raw.get('pam_settings'), dict) else {}
    options = settings.get('options') if isinstance(settings.get('options'), dict) else {}
    return item.kind == KIND_RESOURCE and isinstance(options.get('workflow'), dict)


class PAMProjectUpdateCommand(Command):
    parser = argparse.ArgumentParser(prog=PROG, add_help=True)
    parser.add_argument('--config', '-c', dest='config', action='store', help='PAM Configuration UID or Title')
    parser.add_argument('--filename', '-f', dest='file_name', action='store',
                        help='JSON file (or JSON text) with the import data.')
    parser.add_argument('--format', dest='output_format', choices=['text', 'json'], default='text',
                        help='Output format. json needs -y, -d or --estimate.')
    parser.add_argument('--dry-run', '-d', dest='dry_run', action='store_true', default=False,
                        help='Show what would change; write nothing.')
    parser.add_argument('--verbose', '-v', dest='verbose', action='store_true', default=False,
                        help='Field-by-field report, identical records included.')
    parser.add_argument('--yes', '-y', dest='yes', action='store_true', default=False,
                        help='Do not ask for confirmation. Required in Service Mode and when input is not a '
                             'terminal (a write run is never confirmed implicitly).')
    parser.add_argument('--mode', dest='mode', choices=[ud.MODE_MERGE, ud.MODE_OVERWRITE], default=ud.MODE_MERGE,
                        help='merge (default): keys the JSON sets win, everything else stays. overwrite: the record '
                             'becomes what the JSON describes (REMOVES keys; cannot be reverted by Commander).')
    parser.add_argument('--include-passwords', dest='include_passwords', action='store_true', default=False,
                        help='Replace the passwords in the vault with the passwords from the JSON. By default they '
                             'are skipped, because rotation may have changed them in the vault.')
    parser.add_argument('--skip-attachments', dest='skip_attachments', action='store_true', default=False,
                        help='Do not compare or upload attachment / script files.')
    parser.add_argument('--estimate', dest='estimate', action='store_true', default=False,
                        help='Only count the records that differ; never writes.')
    parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', default=False,
                        help='Long help: file format, modes and examples.')

    def get_parser(self):
        return PAMProjectUpdateCommand.parser

    # ------------------------------------------------------------------------------------------------------
    def execute(self, params, **kwargs):
        check_options(params, kwargs)
        if kwargs.get('syntax_help'):
            print(SYNTAX_HELP)
            return None

        as_json = kwargs.get('output_format') == 'json'
        dry = bool(kwargs.get('dry_run') or kwargs.get('estimate'))
        verbose = bool(kwargs.get('verbose'))
        mode = kwargs.get('mode') or ud.MODE_MERGE
        include_passwords = bool(kwargs.get('include_passwords'))

        plan = self.build_plan(params, kwargs, mode, include_passwords)

        if as_json:
            return json.dumps(report.to_dict(plan, verbose=verbose, estimate=bool(kwargs.get('estimate'))), indent=2)
        if kwargs.get('estimate'):
            print(report.estimate_line(plan))
            for e in plan.errors:
                print(f'ERROR: {e}')
            for w in plan.warnings:
                print(f'WARNING: {w}')
            for line in report.password_summary(plan):
                print(line)
        else:
            print(report.format_text(plan, verbose=verbose))
        if plan.errors:
            raise CommandError(PROG, f'{len(plan.errors)} error(s); nothing was written.')
        if dry:
            if kwargs.get('dry_run'):
                print('[DRY RUN COMPLETE] No changes were made.')
            return None
        if not plan.changed:
            print('Nothing to update')
            return None
        if not kwargs.get('yes'):
            if mode == ud.MODE_OVERWRITE:
                print(f'{bcolors.WARNING}--mode overwrite REMOVES keys that are not in the JSON; Commander cannot '
                      f'revert it.{bcolors.ENDC}')
            if input('Continue? [y/N] ').strip().lower() not in ('y', 'yes'):
                print('Cancelled; nothing was written.')
                return None
        return self.apply(params, plan, kwargs)

    # ------------------------------------------------------------------------------------------------------
    def build_plan(self, params, kwargs: Dict[str, Any], mode: str, include_passwords: bool) -> up.UpdatePlan:
        file_name = str(kwargs.get('file_name') or '')
        config_name = str(kwargs.get('config') or '')
        api.sync_down(params)
        configuration = find_pam_configuration(params, config_name)
        if not (configuration and isinstance(configuration, vault.TypedRecord) and configuration.version == 6):
            raise CommandError(PROG, f'''PAM configuration not found: "{config_name}" ''')

        data = load_import_json(file_name)
        pam_data = data.get('pam_data') if isinstance(data.get('pam_data'), dict) else {}
        if not (pam_data.get('resources') or pam_data.get('users')):
            raise CommandError(PROG, f'''PAM data missing - file "{file_name}" must be a valid JSON ex. '''
                                     '''{"pam_data": {"resources": [], "users":[]}} ''')
        if any(key != 'pam_data' for key in data):
            logging.warning(f'{bcolors.WARNING}WARNING: Import JSON contains extra data - `update` uses only '
                            f'"pam_data": {{ }} {bcolors.ENDC}')
        if not preflight_port_forward(pam_data, PROG, bcolors):
            raise CommandError(PROG, 'The JSON failed the port_forward checks; nothing was compared.')

        app_uid, _app, _controller = _find_ksm_app(params, configuration)
        folders = get_ksm_app_folders(params, app_uid)
        if not folders:
            raise CommandError(PROG, f' No shared folders found for KSM Application: "{app_uid}" ')
        scope = collect_ksm_scope(params, app_uid, folder_roots=folders)

        items, problems = load_items(pam_data, configuration.record_uid)
        index = RecordIndex(scope.match_records())
        errors, missing = up.match_items(
            items, index, config_uid=configuration.record_uid,
            path_to_folder_uid={f.path: f.uid for f in scope.folders.values() if f.path},
            config_of=_config_of(params), can_write=_can_write(params), vault_has_uid=lambda uid: uid in (params.record_cache or {}),
            describe_location=scope.describe_location, folder_label=scope.folder_label)

        matched = [i for i in items if i.uid]
        state = read_vault_state(params, configuration.record_uid, [i.uid for i in matched],
                                 workflow_uids=[i.uid for i in matched if _wants_workflow(i)])
        plan = up.assemble_plan(items, index, state, errors, missing, config_uid=configuration.record_uid,
                                mode=mode, include_passwords=include_passwords,
                                scope_records=scope.record_tuples(), problems=problems,
                                skip_files=bool(kwargs.get('skip_attachments')),
                                service_mode=bool(getattr(params, 'service_mode', False)))
        plan.errors.extend(state.errors)
        # a workflow approver who is not a Keeper user would make the workflow fail when it is written
        plan.warnings.extend(approver_warnings(params, [i.obj for i in matched if i.kind == KIND_RESOURCE
                                                        and _wants_workflow(i)]))
        for line in scope.nsf_warnings(ignored=False):
            plan.warnings.append(line)
        return plan

    def apply(self, params, plan: up.UpdatePlan, kwargs: Dict[str, Any]):
        """Write the changes of *plan*. NOT IMPLEMENTED YET (`update_apply`, order of work step 5)."""
        raise CommandError(PROG, 'Writing is not implemented yet: only -d / --dry-run and --estimate work.')
