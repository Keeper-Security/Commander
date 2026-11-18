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

"""The plan of `pam project update`: match every JSON item to a vault record, read nothing here, compare, and
collect the result. No I/O: the caller (``update.py``) supplies the index, the hooks and the state that
``vault_reader`` read, so the whole planning logic is unit-testable.

Error policy (plan, "Error policy"): PLAN errors (a record that is missing, outside the KSM app, ambiguous, of
another type, ...) block a write run and are all listed; warnings never block.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from . import update_compare as uc
from . import update_diff as ud
from . import update_schema as us
from .import_items import KIND_NESTED_USER, KIND_RESOURCE, KIND_USER, ImportItem
from .record_matcher import (
    MODE_UPDATE, STATUS_EXISTING, STATUS_MISSING, RecordIndex, match_record,
)
from ...keeper_dag.types import PamGraphId
from ...recordv3 import RecordV3


@dataclass
class ItemResult:
    item: ImportItem
    uid: str
    title: str
    record_type: str
    changes: List[ud.Change] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    passwords_skipped: int = 0
    passwords_to_write: int = 0
    passwords_on_rotating: int = 0
    new_ai_blob: Optional[Dict[str, Any]] = None     # for the apply step: the AI blob built from the stored one
    new_jit_blob: Optional[Dict[str, Any]] = None    # the whole jit_settings blob: stored one + the changed keys
    acl_holders: Dict[str, List[str]] = field(default_factory=dict)   # {'admin': [uids], 'launch': [uids]} now
    workflow_options: Any = None                     # PamWorkflowOptions to send (stored + written keys)
    meta_version: int = 0                            # version of the stored meta edge

    @property
    def record_changes(self) -> int:
        return sum(1 for c in self.changes if c.kind == ud.KIND_RECORD)

    @property
    def graph_changes(self) -> int:
        return sum(1 for c in self.changes if c.kind == ud.KIND_GRAPH)

    @property
    def differs(self) -> bool:
        return bool(self.changes)


@dataclass
class UpdatePlan:
    mode: str = ud.MODE_MERGE
    include_passwords: bool = False
    results: List[ItemResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)          # PLAN errors: block a write run
    warnings: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)         # JSON items not in the vault (subset of the errors)
    not_in_json: List[Tuple[str, str, str]] = field(default_factory=list)   # (uid, title, type)

    @property
    def changed(self) -> List[ItemResult]:
        return [r for r in self.results if r.differs]

    @property
    def identical(self) -> List[ItemResult]:
        return [r for r in self.results if not r.differs]

    @property
    def record_changes(self) -> int:
        return sum(r.record_changes for r in self.results)

    @property
    def graph_changes(self) -> int:
        return sum(r.graph_changes for r in self.results)

    @property
    def passwords_skipped(self) -> int:
        return sum(r.passwords_skipped for r in self.results)

    @property
    def passwords_to_write(self) -> int:
        return sum(r.passwords_to_write for r in self.results)

    @property
    def passwords_on_rotating(self) -> int:
        return sum(r.passwords_on_rotating for r in self.results)

    @property
    def ok(self) -> bool:
        return not self.errors


# --------------------------------------------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------------------------------------------

def duplicate_title_errors(items: List[ImportItem]) -> Tuple[List[str], set]:
    """Two JSON items with the same title in the same scope cannot be told apart (the same rule `extend` has).

    Scope = the item's ``folder_path``, or "global" without one; titles compare trimmed and without regard to case.
    An item with an explicit valid ``uid`` is disambiguated already and is left out. Returns (errors, ids of the
    items involved)."""
    groups: Dict[Tuple[str, str], List[ImportItem]] = {}
    for item in items:
        uid_imp = getattr(item.obj, 'uid_imported', None)
        if isinstance(uid_imp, str) and RecordV3.is_valid_ref_uid(uid_imp):
            continue
        title = item.title
        if not title:
            continue
        scope = (getattr(item.obj, 'folder_path', None) or '').strip() or 'global'
        groups.setdefault((scope, title.casefold()), []).append(item)
    errors: List[str] = []
    involved = set()
    for (scope, _), group in groups.items():
        if len(group) > 1:
            where = f'folder {scope}' if scope != 'global' else 'global'
            errors.append(f'Duplicate import records with same title "{group[0].title}" in same scope ({where}). '
                          'Add explicit "title" or "uid" in the JSON to disambiguate.')
            involved.update(id(i) for i in group)
    return errors, involved


def match_items(items: List[ImportItem], index: RecordIndex, *, config_uid: str = '',
                path_to_folder_uid: Optional[Dict[str, str]] = None,
                config_of: Optional[Callable[[str], Optional[str]]] = None,
                can_write: Optional[Callable[[str], Optional[bool]]] = None,
                vault_has_uid: Optional[Callable[[str], bool]] = None,
                describe_location: Optional[Callable[[str], str]] = None,
                folder_label: Optional[Callable[[str], str]] = None
                ) -> Tuple[List[str], List[str]]:
    """Match every item (mode ``update``); sets ``item.uid`` / ``status`` / ``message``.

    Returns (errors, missing): every item that could not be matched is an error; the ones that simply are not in
    the vault are also named in ``missing`` for the "run `pam project extend` first" hint. A uid is claimed by
    one item only: two items that resolve to the same record are an error (a record is written once per run).
    """
    path_to_folder_uid = path_to_folder_uid or {}
    errors, duplicated = duplicate_title_errors(items)
    missing: List[str] = []
    claimed: Dict[str, ImportItem] = {}
    for item in items:
        obj = item.obj
        uid_imp = getattr(obj, 'uid_imported', None)
        uid_imp = uid_imp if isinstance(uid_imp, str) and RecordV3.is_valid_ref_uid(uid_imp) else None
        folder_path = (getattr(obj, 'folder_path', None) or '').strip()
        parent = item.parent
        suffix = f' user on machine {parent.ident}' if parent else ''
        result = match_record(
            index, ident=item.ident, machine_suffix=suffix, uid_imported=uid_imp or None,
            folder_path=folder_path, folder_uid=path_to_folder_uid.get(folder_path, '') if folder_path else '',
            title=item.title, login=item.login, expected_type=item.record_type, mode=MODE_UPDATE,
            config_uid=config_uid, config_of=config_of, can_write=can_write, vault_has_uid=vault_has_uid,
            describe_location=describe_location, folder_label=folder_label)
        item.status, item.message = result.status, result.message
        if result.status == STATUS_EXISTING:
            if result.uid in claimed:
                item.status = 'error'
                item.message = (f'record {item.ident} matches the same vault record as {claimed[result.uid].ident}; '
                                'add "uid" or "folder_path" to the JSON to tell them apart')
                if id(item) not in duplicated:        # a duplicate title is reported once, above
                    errors.append(item.message)
                continue
            claimed[result.uid] = item
            item.uid = result.uid
            continue
        errors.append(result.message)
        if result.status == STATUS_MISSING:
            missing.append(item.ident)
    return errors, missing


def missing_hint(missing: List[str], limit: int = 5) -> str:
    shown = ', '.join(missing[:limit]) + (f' and {len(missing) - limit} more' if len(missing) > limit else '')
    return (f'{len(missing)} record(s) in the JSON are not in the vault: {shown}. '
            'Run `pam project extend` first so they get created, then run `update`.')


# --------------------------------------------------------------------------------------------------------------
# references
# --------------------------------------------------------------------------------------------------------------

def build_ref_resolver(items: List[ImportItem], index: RecordIndex) -> Callable[[str], Optional[str]]:
    """Title / login of a record named in the JSON -> UID: a matched JSON user first, then a unique vault title."""
    by_name: Dict[str, str] = {}
    for item in items:
        if item.uid and item.kind != KIND_RESOURCE:
            for name in (item.title, item.login):
                if name:
                    by_name.setdefault(name.lower(), item.uid)

    def resolve(ref: Any) -> Optional[str]:
        text = str(ref or '').strip()
        if not text:
            return None
        found = by_name.get(text.lower())
        if found:
            return found
        if index.has_uid(text):
            return text
        candidates = index.by_title(text)
        return candidates[0].uid if len(candidates) == 1 else None
    return resolve


def _first_ref(value: Any) -> str:
    """The first reference of a value that may be a string, a multiline string or a list."""
    if isinstance(value, list):
        value = value[0] if value else ''
    return str(value or '').strip().splitlines()[0].strip() if str(value or '').strip() else ''


# --------------------------------------------------------------------------------------------------------------
# comparing
# --------------------------------------------------------------------------------------------------------------

def _pam_settings_raw(raw: Dict[str, Any]) -> Dict[str, Any]:
    value = raw.get('pam_settings')
    return value if isinstance(value, dict) else {}


def _resource_graph_changes(item: ImportItem, result: ItemResult, state, config_uid: str, mode: str,
                            resolve: Callable[[str], Optional[str]], graph_overwrite: bool) -> None:
    graph = state.graphs.get(PamGraphId.PAM.value)
    if graph is None:
        result.warnings.append(f'{item.ident}: the PAM graph could not be read; graph settings are not compared')
        return
    uid = result.uid
    obj = item.obj
    settings = _pam_settings_raw(item.raw)
    options = settings.get('options') if isinstance(settings.get('options'), dict) else {}
    connection = settings.get('connection') if isinstance(settings.get('connection'), dict) else {}
    loaded = getattr(obj, 'pam_settings', None) or getattr(obj, 'rbi_settings', None)

    stored_meta = graph.data(uid, 'meta')
    result.meta_version = int((stored_meta or {}).get('version') or 0) if isinstance(stored_meta, dict) else 0
    result.acl_holders = uc.acl_holders(graph.edges_of_type(uid, 'acl'), uid)
    changes, warnings = ud.diff_meta(options, connection, stored_meta, mode=mode,
                                     graph_overwrite=graph_overwrite)
    result.changes.extend(changes)
    result.warnings.extend(f'{item.ident}: {w}' for w in warnings)

    jit = getattr(loaded, 'jit_settings', None)
    if jit is not None and isinstance(options.get('jit_settings'), dict):
        stored_jit = graph.data(uid, 'jit_settings')
        changes, warnings = ud.diff_jit(options['jit_settings'], jit.to_dag_dict(), stored_jit,
                                        mode=mode, graph_overwrite=graph_overwrite)
        if changes:
            blob = dict(stored_jit) if isinstance(stored_jit, dict) else {}
            for change in changes:
                key = change.path.split('.', 1)[1]
                if change.op == ud.OP_REMOVE:
                    blob.pop(key, None)
                else:
                    blob[key] = change.new
            result.new_jit_blob = blob
        result.changes.extend(changes)
        result.warnings.extend(f'{item.ident}: {w}' for w in warnings)

    if isinstance(options.get('ai_settings'), dict):
        blob, changes, warnings = uc.plan_ai(options['ai_settings'], graph.data(uid, 'ai_settings'), mode=mode,
                                             graph_overwrite=graph_overwrite)
        result.changes.extend(changes)
        result.new_ai_blob = blob
        result.warnings.extend(f'{item.ident}: {w}' for w in warnings)

    if isinstance(options.get('workflow'), dict):
        if uid in state.workflows:
            current_wf = state.workflows.get(uid)
            changes, warnings = uc.diff_workflow(getattr(loaded, 'workflow', None), options['workflow'],
                                                 current_wf, mode=mode, graph_overwrite=graph_overwrite,
                                                 title=item.title)
            result.changes.extend(changes)
            result.warnings.extend(warnings)
            if changes and getattr(loaded, 'workflow', None) is not None:
                try:
                    result.workflow_options = uc.merged_workflow_options(
                        loaded.workflow, options['workflow'], current_wf, mode=mode, graph_overwrite=graph_overwrite)
                except ValueError as err:
                    result.warnings.append(f'{item.ident}: the workflow cannot be updated safely: {err}')
                    result.changes = [c for c in result.changes if not c.path.startswith('workflow')]
        else:
            result.warnings.append(f'{item.ident}: the workflow could not be read; it is not compared')

    names = {'administrative_credentials': 'admin_credential', 'launch_credentials': 'launch_credential',
             'autofill_credentials': 'http_credentials'}
    sftp = connection.get('sftp') if isinstance(connection.get('sftp'), dict) else {}
    explicit: List[str] = []
    resolved: Dict[str, Optional[str]] = {}
    for raw_key, name in names.items():
        if raw_key in connection:
            explicit.append(name)
            resolved[name] = resolve(_first_ref(connection[raw_key]))
    for raw_key, name in (('sftp_resource', 'sftp_resource'), ('sftp_user_credentials', 'sftp_user')):
        if raw_key in sftp:
            explicit.append(name)
            resolved[name] = resolve(_first_ref(sftp[raw_key]))
    if explicit:
        record = state.records.get(uid)
        pam_field = ud.find_field(record.data, us.Target(us.KIND_RECORD, field='pamSettings', scope=us.SCOPE_ANY)) \
            if record else None
        rbi_field = ud.find_field(record.data, us.Target(us.KIND_RECORD, field='pamRemoteBrowserSettings',
                                                         scope=us.SCOPE_ANY)) if record else None
        field_value = ((pam_field or rbi_field or {}).get('value') or [{}])[0]
        current_conn = field_value.get('connection') if isinstance(field_value, dict) else {}
        changes, warnings = uc.diff_credential_refs(resolved, explicit, current_conn, graph.edges_of_type(uid, 'acl'),
                                                    uid, title=item.title)
        result.changes.extend(changes)
        result.warnings.extend(warnings)


def _user_rotation_changes(item: ImportItem, result: ItemResult, state, config_uid: str,
                           resolve: Callable[[str], Optional[str]]) -> None:
    rotation = getattr(item.obj, 'rotation_settings', None)
    raw_rotation = item.raw.get('rotation_settings')
    if rotation is None or not isinstance(raw_rotation, dict):
        return
    record = state.records.get(result.uid)
    if item.parent is not None:
        machine_uid = item.parent.uid
    else:
        machine_uid = resolve(rotation.resource) or ''
    changes, warnings = uc.diff_rotation(rotation, raw_rotation.keys(), record.rotation if record else None,
                                         expected_resource_uid=machine_uid or '', expected_config_uid=config_uid,
                                         title=item.title)
    result.changes.extend(changes)
    result.warnings.extend(warnings)


def _raw_files(item: ImportItem) -> List[Tuple[str, str]]:
    """(kind, path) of every attachment / script file the JSON item names. kind: 'attachment' | 'script'."""
    found: List[Tuple[str, str]] = []
    for kind, key in (('attachment', 'attachments'), ('script', 'scripts')):
        values = item.raw.get(key)
        for entry in values if isinstance(values, list) else []:
            path = entry if isinstance(entry, str) else (entry.get('file') if isinstance(entry, dict) else None)
            if isinstance(path, str) and path.strip():
                found.append((kind, path.strip()))
    return found


def file_problems(items: List[ImportItem], skip_files: bool, service_mode: bool = False) -> Tuple[List[str], List[str]]:
    """(errors, warnings) about the files the JSON names, found before anything is compared.

    A file that is missing on the local disk is a PLAN error (the files can be big and are not copied with the
    JSON) unless files are skipped. In Service Mode files are disabled (the host disk must not be readable through
    a request) and skipped with a warning."""
    errors: List[str] = []
    named = [(item, kind, path) for item in items for kind, path in _raw_files(item)]
    if service_mode and named:
        return [], [f'attachments and script files are disabled in Service Mode - skipped {len(named)} file(s)']
    if skip_files:
        return [], ([f'attachments and script files are skipped (--skip-attachments): {len(named)} file(s)']
                    if named else [])
    for item, kind, path in named:
        if not os.path.isfile(os.path.abspath(os.path.expanduser(path))):
            errors.append(f'{kind} file for {item.ident} not found on this computer: "{path}" '
                          '(fix the path or use --skip-attachments)')
    return errors, []


def _vault_scripts(record_state) -> List[Dict[str, Any]]:
    """The script entries of the vault record: {name, command, record_refs} (name from the file record)."""
    names = {f.get('record_uid'): f.get('name') for f in (record_state.files or [])}
    out: List[Dict[str, Any]] = []
    for pool in ('fields', 'custom'):
        for fld in (record_state.data or {}).get(pool) or []:
            if fld.get('type') != 'script':
                continue
            for value in fld.get('value') or []:
                if isinstance(value, dict):
                    out.append({'name': names.get(value.get('fileRef')), 'command': value.get('command') or '',
                                'record_refs': sorted(value.get('recordRef') or [])})
    return out


def _script_notes(item: ImportItem, result: ItemResult, record_state, resolve) -> None:
    """For a script whose file has the same name and size (so it is NOT re-uploaded) report the other settings that
    differ, as warnings: update does not change them, because that would mean uploading the file again."""
    vault = _vault_scripts(record_state)
    for script in getattr(getattr(item.obj, 'scripts', None), 'scripts', None) or []:
        name = os.path.basename(os.path.abspath(os.path.expanduser(script.file)))
        current = next((v for v in vault if v['name'] == name), None)
        if current is None:
            continue
        why = 'not updated: the file name and size match, and update does not upload a file again'
        if (script.script_command or '') != current['command']:
            result.warnings.append(f'{item.ident}: script "{name}": command differs (vault "{current["command"]}", '
                                   f'JSON "{script.script_command or ""}") - {why}')
        wanted = sorted(filter(None, (resolve(c) for c in script.additional_credentials or [])))
        unresolved = [c for c in script.additional_credentials or [] if not resolve(c)]
        if wanted != current['record_refs'] or unresolved:
            extra = f' (could not resolve: {", ".join(unresolved)})' if unresolved else ''
            result.warnings.append(f'{item.ident}: script "{name}": additional credentials differ (vault '
                                   f'{len(current["record_refs"])}, JSON {len(wanted)}){extra} - {why}')


def _file_changes(item: ImportItem, result: ItemResult, record_state) -> None:
    """Attachments and script files: compared by name and size (the vault keeps no content hash). A file with the
    same name and size is the same file; the same name with another size is replaced; a new name is added. Files
    are never removed, in either mode (they are separate file records)."""
    have = list(record_state.files or [])
    for kind, path in _raw_files(item):
        full = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(full):
            continue                                  # reported as a plan error by file_problems
        name, size = os.path.basename(full), os.path.getsize(full)
        label = f'{kind} "{name}"'
        same_name = [f for f in have if f.get('name') == name]
        if any(f.get('size') == size for f in same_name):
            continue                                  # same file; a script's other settings are reported below
        target = us.Target(us.KIND_FILES, note=kind)
        if same_name:
            old = same_name[0].get('size')
            result.changes.append(ud.Change(ud.KIND_RECORD, ud.OP_CHANGE, label, f'{old} bytes', f'{size} bytes',
                                            target=target, note='file replaced'))
        else:
            result.changes.append(ud.Change(ud.KIND_RECORD, ud.OP_ADD, label, None, f'{size} bytes', target=target))


def diff_items(items: List[ImportItem], state, *, config_uid: str, mode: str = ud.MODE_MERGE,
               include_passwords: bool = False, resolve: Optional[Callable[[str], Optional[str]]] = None,
               graph_overwrite: bool = False, skip_files: bool = False,
               errors_out: Optional[List[str]] = None) -> List[ItemResult]:
    """Compare every matched item with the state ``vault_reader`` read. Unmatched items are skipped (they are
    plan errors already). Plan errors found while comparing (a resource that is not linked to the configuration)
    are appended to *errors_out*."""
    resolve = resolve or (lambda ref: None)
    errors_out = errors_out if errors_out is not None else []
    results: List[ItemResult] = []
    for item in items:
        if not item.uid:
            continue
        record_state = state.records.get(item.uid)
        title = item.title
        result = ItemResult(item=item, uid=item.uid, title=title, record_type=item.record_type)
        results.append(result)
        if record_state is None or not record_state.data:
            result.warnings.append(f'{item.ident}: the vault record could not be read; it is not compared')
            continue
        for err in record_state.errors:
            result.warnings.append(f'{item.ident}: {err.get("message", err)}')
        rotating = bool(record_state.rotation and not record_state.rotation.get('disabled'))
        diff = ud.diff_record(item.raw, item.record_type, item.obj, record_state.data, mode=mode,
                              include_passwords=include_passwords, rotating=rotating, uid=item.uid, title=title)
        result.changes.extend(diff.changes)
        result.warnings.extend(diff.warnings)
        result.passwords_skipped = diff.passwords_skipped
        result.passwords_to_write = diff.passwords_to_write
        result.passwords_on_rotating = diff.passwords_on_rotating
        if not skip_files:
            _file_changes(item, result, record_state)
            _script_notes(item, result, record_state, resolve)
        if item.kind == KIND_RESOURCE:
            graph = state.graphs.get(PamGraphId.PAM.value)
            if graph is not None and config_uid and graph.edge(item.uid, config_uid, None, 'link') is None:
                # The PAM graph of this configuration has no link from the resource to it: the record belongs to
                # another configuration (or to none). update never links or moves a resource.
                errors_out.append(f'record {item.ident} is not linked to this PAM configuration (it belongs to '
                                  'another configuration or none); update does not link resources')
                continue
            _resource_graph_changes(item, result, state, config_uid, mode, resolve, graph_overwrite)
        else:
            _user_rotation_changes(item, result, state, config_uid, resolve)
    return results


def build_plan(items: List[ImportItem], index: RecordIndex, state, *, config_uid: str,
               mode: str = ud.MODE_MERGE, include_passwords: bool = False, matching: Optional[dict] = None,
               scope_records: Iterable[Tuple[str, str, str, str]] = (), graph_overwrite: bool = False,
               problems: Iterable[str] = (), skip_files: bool = False, service_mode: bool = False) -> UpdatePlan:
    """Match, compare and collect, for a caller that already has the state. A caller that must match first (to
    know which records to read) calls ``match_items``, reads, then ``assemble_plan``."""
    errors, missing = match_items(items, index, config_uid=config_uid, **(matching or {}))
    return assemble_plan(items, index, state, errors, missing, config_uid=config_uid, mode=mode,
                         include_passwords=include_passwords, scope_records=scope_records,
                         graph_overwrite=graph_overwrite, problems=problems, skip_files=skip_files,
                         service_mode=service_mode)


def assemble_plan(items: List[ImportItem], index: RecordIndex, state, errors: List[str], missing: List[str], *,
                  config_uid: str, mode: str = ud.MODE_MERGE, include_passwords: bool = False,
                  scope_records: Iterable[Tuple[str, str, str, str]] = (), graph_overwrite: bool = False,
                  problems: Iterable[str] = (), skip_files: bool = False, service_mode: bool = False) -> UpdatePlan:
    """The plan from the matching result and the state read for the matched records."""
    plan = UpdatePlan(mode=mode, include_passwords=include_passwords)
    plan.errors.extend(problems)
    plan.errors.extend(errors)
    file_errors, file_warnings = file_problems(items, skip_files, service_mode)
    plan.errors.extend(file_errors)
    plan.warnings.extend(file_warnings)
    skip_files = skip_files or service_mode
    plan.missing = missing
    if missing:
        plan.errors.append(missing_hint(missing))
    if state is not None:
        plan.results = diff_items(items, state, config_uid=config_uid, mode=mode, include_passwords=include_passwords,
                                  resolve=build_ref_resolver(items, index), graph_overwrite=graph_overwrite,
                                  skip_files=skip_files, errors_out=plan.errors)
    matched = {i.uid for i in items if i.uid}
    pam_types = set(us.RESOURCE_TYPES + us.RBI_TYPES + us.USER_TYPES)
    plan.not_in_json = [(uid, title, rtype) for uid, title, rtype, _login in scope_records
                        if uid not in matched and rtype in pam_types]
    for result in plan.results:
        plan.warnings.extend(result.warnings)
    return plan
