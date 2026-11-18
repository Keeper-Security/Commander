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

"""What would `pam project update` change?  Pure functions, no I/O.

Inputs are plain data: the raw JSON item, the item loaded by the import parsers, and the CURRENT state read by
``vault_reader`` (record JSON as ``get --format=json`` shows it, graph ``meta`` / ``jit_settings`` dicts).
Output is a list of ``Change`` objects per record. Nothing here talks to the server, so all of it is unit-testable.

Rules implemented (plan, section ``--mode``):

* the diff looks only at the keys the user WROTE (``update_schema.explicit_paths``); the loaders fill in defaults,
  so comparing the loaded object as a whole would reset a vault value the JSON never mentioned;
* ``merge`` (default): written keys win, every other key of the record stays;
* ``overwrite``: inside the containers the JSON mentions (``pamSettings`` / ``pamRemoteBrowserSettings``) the vault
  object becomes what the import would build, so keys that are not in it are REMOVED; known record fields that
  the JSON does not set are removed too (``update_schema.removable_in_overwrite``). The GRAPH side of
  ``overwrite`` (removing meta flags, JIT keys, ACL links) is a deferred decision and is off unless asked for;
* passwords (password, private key, one-time-code seed) are written only with ``include_passwords``; without it a
  differing secret is only COUNTED; omission never wipes a secret;
* secrets and notes are never put into a message: ``Change.shown()`` gives ``<hidden>``.

``overwrite`` on the record side - what it does and does NOT do (documented in the README, section
"pam project update", and in ``--syntax-help``; keep the three in step):

* It acts on the ``pamSettings`` / ``pamRemoteBrowserSettings`` object ONLY when the JSON item has a ``pam_settings``
  section. A JSON item without ``pam_settings`` leaves that object of the vault record completely alone, in both
  modes: an item that does not mention the section is "not about it", it is not an instruction to empty it.
* Custom fields are removed only when the JSON item has a ``custom`` list (then the vault's custom fields that are
  not in the list are removed, except secrets). An item without a ``custom`` list leaves the vault's custom fields
  alone, in both modes.
* Known fields (text / checkbox fields of the record type) that the JSON does not set are removed; the title, the
  host / port, ``rbiUrl`` and secrets never are.
* The GRAPH side (meta flags, JIT keys, links) is not touched by ``overwrite`` at all until the owner decides
  what it may remove (``graph_overwrite``, off by default; plan: "What `overwrite` may remove from the graph").

NOT done here yet (see the plan): the comparators for the KeeperAI settings (audit metadata inside the blob),
admin / launch credential links and other references (they need the UIDs the matcher resolved), rotation and
workflow (open item 2). A path that needs one of them is reported as a warning, never silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import update_schema as us
from .base import DagOptionValue

MODE_MERGE = 'merge'
MODE_OVERWRITE = 'overwrite'

KIND_RECORD = 'record'
KIND_GRAPH = 'graph'

OP_CHANGE = '~'
OP_ADD = '+'
OP_REMOVE = '-'

HIDDEN = '<hidden>'
# shown as "differs", never printed
HIDDEN_RECORD_PATHS = ('notes',)
# keys that are never removed from a vault object, in any mode (owned by the back-end / discovery)
PROTECTED_KEYS = frozenset({'locked', 'service_names'})
# connection keys that hold UIDs of other records: compared by the reference comparators, not here
REF_OUTPUT_KEYS = frozenset({'userRecords', 'userRecordUid', 'launchRecordUid', 'httpCredentialsUid',
                             'sftpResourceUid', 'sftpUserUid'})
# containers (record field types) whose content `overwrite` makes equal to the built object
OWNED_CONTAINERS = ('pamSettings', 'pamRemoteBrowserSettings')


class _Remove:
    def __repr__(self):
        return 'REMOVE'


REMOVE = _Remove()   # desired value meaning "remove this key" (a tri-state option set to `default`)


@dataclass(frozen=True)
class Change:
    kind: str                      # KIND_RECORD | KIND_GRAPH
    op: str                        # OP_CHANGE | OP_ADD | OP_REMOVE
    path: str                      # for the report: 'pamSettings.connection.port', 'meta.allowedSettings.connections'
    old: Any = None
    new: Any = None
    hidden: bool = False           # secret or notes: never printed
    secret: bool = False           # password group: written only with --include-passwords
    target: Optional[us.Target] = None
    note: str = ''

    def shown(self) -> Tuple[Any, Any]:
        """(old, new) as they may be printed."""
        if self.hidden:
            return (HIDDEN if self.old is not None else None, HIDDEN if self.new is not None else None)
        return self.old, self.new


@dataclass
class RecordDiff:
    uid: str
    title: str
    record_type: str
    changes: List[Change] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    passwords_skipped: int = 0        # differing secrets NOT written (flag off)
    passwords_to_write: int = 0       # differing secrets written (flag on)
    passwords_on_rotating: int = 0    # of passwords_to_write: users with rotation enabled

    @property
    def record_changes(self) -> int:
        return sum(1 for c in self.changes if c.kind == KIND_RECORD)

    @property
    def graph_changes(self) -> int:
        return sum(1 for c in self.changes if c.kind == KIND_GRAPH)

    @property
    def differs(self) -> bool:
        return bool(self.changes)


# --------------------------------------------------------------------------------------------------------------
# values
# --------------------------------------------------------------------------------------------------------------

def canon(value: Any) -> Any:
    """Normal form for comparing: strings trimmed, containers recursively."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return [canon(v) for v in value]
    if isinstance(value, dict):
        return {k: canon(v) for k, v in value.items()}
    return value


def is_blank(value: Any) -> bool:
    return value is None or value == '' or value == [] or value == {}


def same(a: Any, b: Any) -> bool:
    a, b = canon(a), canon(b)
    if isinstance(a, bool) != isinstance(b, bool):
        return False                        # True == 1 in Python: keep a checkbox apart from a number
    if a == b:
        return True
    # a number and its text form: the vault keeps ports as text, the parsers return numbers for some keys
    if isinstance(a, (int, float)) and isinstance(b, str):
        return str(a) == b
    if isinstance(b, (int, float)) and isinstance(a, str):
        return str(b) == a
    return False


def _dig(data: Any, parts: List[str]) -> Tuple[bool, Any]:
    """(found, value) of a dotted path inside nested dicts."""
    node = data
    for part in parts:
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _flatten(data: Any, prefix: str = '') -> Dict[str, Any]:
    """Leaves of nested dicts as dotted paths; lists and empty dicts are leaves."""
    if not isinstance(data, dict) or not data:
        return {prefix: data} if prefix else {}
    out: Dict[str, Any] = {}
    for key, value in data.items():
        path = f'{prefix}.{key}' if prefix else str(key)
        if isinstance(value, dict) and value:
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out


# --------------------------------------------------------------------------------------------------------------
# reading the current record (record JSON as `get --format=json` gives it)
# --------------------------------------------------------------------------------------------------------------

def _label_matches(candidate: Dict[str, Any], label: str) -> bool:
    if not label:
        return True
    existing = candidate.get('label')
    return bool(existing) and existing.casefold() == label.casefold()


def find_field(data: Dict[str, Any], target: us.Target) -> Optional[Dict[str, Any]]:
    pools = {us.SCOPE_TYPED: ('fields',), us.SCOPE_CUSTOM: ('custom',), us.SCOPE_ANY: ('fields', 'custom')}.get(target.scope)
    for pool in pools or ():
        for candidate in data.get(pool) or []:
            if candidate.get('type') == target.field and _label_matches(candidate, target.label):
                return candidate
    return None


def current_value(data: Dict[str, Any], target: us.Target) -> Tuple[bool, Any]:
    """(exists, value) of the record value *target* points at."""
    if target.scope == us.SCOPE_STANDARD:
        return (target.field in data), data.get(target.field)
    found = find_field(data, target)
    if found is None:
        return False, None
    values = found.get('value') or []
    if not values:
        return False, None
    value = values[0]
    if not target.sub:
        return True, value
    return _dig(value, target.sub.split('.'))


# --------------------------------------------------------------------------------------------------------------
# desired values, from the object the import parsers built (vault-shaped)
# --------------------------------------------------------------------------------------------------------------

# raw key -> attribute of the loaded Pam*Object (the same attributes pam_record_build reads)
RAW_ATTR: Dict[str, str] = {
    'title': 'title', 'notes': 'notes', 'otp': 'oneTimeCode',
    'ssl_verification': 'sslVerification', 'operating_system': 'operatingSystem', 'instance_name': 'instanceName',
    'instance_id': 'instanceId', 'provider_group': 'providerGroup', 'provider_region': 'providerRegion',
    'use_ssl': 'useSSL', 'database_id': 'databaseId', 'database_type': 'databaseType', 'domain_name': 'domainName',
    'alternative_ips': 'alternativeIPs', 'directory_id': 'directoryId', 'directory_type': 'directoryType',
    'user_match': 'userMatch',
    'account_identifier': 'accountIdentifier',
    'login': 'login', 'password': 'password', 'private_pem_key': 'privatePEMKey',
    'distinguished_name': 'distinguishedName', 'connect_database': 'connectDatabase', 'managed': 'managed',
}
_FAMILY_ATTR_OVERRIDES: Dict[str, Dict[str, str]] = {
    us.FAMILY_RBI: {'url': 'rbiUrl'},
    us.FAMILY_LOGIN: {'url': 'url'},
}


def settings_container(obj: Any, family: str) -> Optional[Dict[str, Any]]:
    """The vault-shaped `pamSettings` / `pamRemoteBrowserSettings` object the import builds for *obj*."""
    if family == us.FAMILY_RESOURCE:
        ps = getattr(obj, 'pam_settings', None)
        if ps is None:
            return None
        return {
            'allowSupplyHost': True if ps.allowSupplyHost is True else False,
            'portForward': ps.portForward.to_record_dict() if ps.portForward else {},
            'connection': ps.connection.to_record_dict() if ps.connection else {},
        }
    if family == us.FAMILY_RBI:
        rbi = getattr(obj, 'rbi_settings', None)
        if rbi is None or rbi.connection is None:
            return None
        return {'connection': rbi.connection.to_record_dict()}
    return None


def desired_value(obj: Any, raw_path: str, target: us.Target, family: str,
                  container: Optional[Dict[str, Any]]) -> Tuple[bool, Any]:
    """(available, value) wanted at *raw_path*. Not available = the import parser rejected / dropped the value."""
    if target.field in OWNED_CONTAINERS:
        if container is None:
            return False, None
        found, value = _dig(container, target.sub.split('.')) if target.sub else (True, container)
        return found, value
    if target.field == 'pamHostname':
        value = getattr(obj, 'host' if target.sub == 'hostName' else 'port', None)
        return (value is not None), (value.strip() if isinstance(value, str) else value)
    attr = _FAMILY_ATTR_OVERRIDES.get(family, {}).get(raw_path) or RAW_ATTR.get(raw_path)
    if not attr:
        return False, None
    value = getattr(obj, attr, None)
    if value is None:
        return False, None
    return True, value


# --------------------------------------------------------------------------------------------------------------
# record side
# --------------------------------------------------------------------------------------------------------------

def _display(target: us.Target) -> str:
    return us.describe(target)


def _record_change(op, target, path, old, new) -> Change:
    hidden = target.secret or (target.scope == us.SCOPE_STANDARD and target.field in HIDDEN_RECORD_PATHS)
    return Change(KIND_RECORD, op, path, old, new, hidden=hidden, secret=target.secret, target=target)


def _compare(result: RecordDiff, target: us.Target, path: str, exists: bool, current: Any, wanted: Any,
             include_passwords: bool, rotating: bool) -> None:
    if exists and not is_blank(current):
        if same(current, wanted):
            return
        op = OP_CHANGE
    else:
        if is_blank(wanted):
            return
        op = OP_ADD
    if target.secret:
        if not include_passwords:
            result.passwords_skipped += 1
            return
        result.passwords_to_write += 1
        if rotating:
            result.passwords_on_rotating += 1
    result.changes.append(_record_change(op, target, path, current if exists else None, wanted))


def _removals(current: Any, wanted: Any, prefix: str) -> Iterable[Tuple[str, Any]]:
    """Dotted paths (and values) of keys in *current* that *wanted* does not have; protected and reference keys stay."""
    if not isinstance(current, dict):
        return
    for key, value in current.items():
        if key in PROTECTED_KEYS or key in REF_OUTPUT_KEYS:
            continue
        path = f'{prefix}.{key}' if prefix else key
        if not isinstance(wanted, dict) or key not in wanted:
            if not is_blank(value):
                yield path, value
        elif isinstance(value, dict) and isinstance(wanted.get(key), dict):
            yield from _removals(value, wanted[key], path)


def _diff_custom(result: RecordDiff, raw_custom: Any, current: Dict[str, Any], mode: str, target: us.Target,
                 loaded: List[Dict[str, Any]]) -> None:
    """Custom text fields: matched by (type, label), like the Web Vault does.

    Only called when the JSON item HAS a ``custom`` list. In ``overwrite`` the vault's custom fields that are not
    in that list are removed (secrets are not); an item with no ``custom`` list never reaches this function, so
    its vault custom fields are left alone in both modes (documented rule, see the module text).
    """
    wanted_keys = set()
    for item in loaded:
        key = (item['type'], item['label'].casefold())
        wanted_keys.add(key)
        existing = next((c for c in current.get('custom') or []
                         if c.get('type') == item['type'] and (c.get('label') or '').casefold() == key[1]), None)
        path = f'custom "{item["label"]}"'
        values = (existing or {}).get('value') or []
        old = values[0] if values else None
        if existing is None or is_blank(old):
            result.changes.append(Change(KIND_RECORD, OP_ADD, path, None, item['value'], target=target))
        elif not same(old, item['value']):
            result.changes.append(Change(KIND_RECORD, OP_CHANGE, path, old, item['value'], target=target))
    if mode == MODE_OVERWRITE:
        for existing in current.get('custom') or []:
            key = (existing.get('type'), (existing.get('label') or '').casefold())
            if key in wanted_keys or existing.get('type') in ('password', 'secret', 'otp'):
                continue
            values = existing.get('value') or []
            if values and not is_blank(values[0]):
                result.changes.append(Change(KIND_RECORD, OP_REMOVE, f'custom "{existing.get("label")}"',
                                             values[0], None, target=target))


def diff_record(raw: Dict[str, Any], record_type: str, obj: Any, current: Dict[str, Any], *,
                mode: str = MODE_MERGE, include_passwords: bool = False, rotating: bool = False,
                uid: str = '', title: str = '') -> RecordDiff:
    """The RECORD-side changes of one item. *current* is the vault record JSON (title, notes, fields, custom)."""
    classification = us.classify(raw, record_type)
    family = us.family_of(record_type)
    result = RecordDiff(uid=uid, title=title or str(raw.get('title') or ''), record_type=record_type)
    for path in classification.unmapped:
        result.warnings.append(us.unmapped_warning(path, result.title))

    container = settings_container(obj, family) if family else None
    touches_container = False
    for path, target in sorted(classification.mapped.items()):
        if target.kind != us.KIND_RECORD:
            continue
        if path == 'custom':
            _diff_custom(result, raw.get('custom'), current, mode, target, getattr(obj, 'custom', None) or [])
            continue
        if target.field in OWNED_CONTAINERS:
            touches_container = True
            if 'whole' in target.note:
                continue            # {} written for the object: only `overwrite` acts on it (below)
        available, wanted = desired_value(obj, path, target, family, container)
        if not available:
            result.warnings.append(f'"{result.title}": the value of "{path}" was not accepted by the import parser '
                                   '(skipped)')
            continue
        exists, old = current_value(current, target)
        _compare(result, target, _display(target), exists, old, wanted, include_passwords, rotating)

    if mode == MODE_OVERWRITE:
        _overwrite_record(result, classification, family, record_type, obj, current, container, touches_container,
                          include_passwords, rotating)
    return result


def _overwrite_record(result, classification, family, record_type, obj, current, container, touches_container,
                      include_passwords, rotating) -> None:
    """The extra work of `overwrite` on the record side (see the module text for the rules)."""
    written = {(c.target.field, c.target.label, c.target.sub) for c in result.changes if c.target}
    # 1. inside the settings object the JSON mentions: the vault object becomes the built one.
    #    `touches_container` is True only if the JSON item has a `pam_settings` section; without it the vault's
    #    settings object is NOT touched (an item that does not mention it is not an instruction to empty it).
    if touches_container and container is not None:
        owner = 'pamSettings' if family == us.FAMILY_RESOURCE else 'pamRemoteBrowserSettings'
        scope = us.SCOPE_CUSTOM if family == us.FAMILY_RESOURCE else us.SCOPE_ANY
        base = us.Target(us.KIND_RECORD, field=owner, scope=scope)
        exists, vault_object = current_value(current, base)
        vault_object = vault_object if exists and isinstance(vault_object, dict) else {}
        for sub, wanted in _flatten(container).items():
            if isinstance(wanted, dict) and not wanted:
                continue          # an empty object (no port_forward written): nothing to set, extras are removed below
            target = us.Target(us.KIND_RECORD, field=owner, sub=sub, scope=scope)
            if (owner, '', sub) in written or (sub.split('.')[0] == 'connection'
                                               and sub.split('.')[-1] in REF_OUTPUT_KEYS):
                continue
            found, old = _dig(vault_object, sub.split('.'))
            _compare(result, target, _display(target), found, old, wanted, include_passwords, rotating)
        for sub, old in _removals(vault_object, container, ''):
            target = us.Target(us.KIND_RECORD, field=owner, sub=sub, scope=scope)
            result.changes.append(Change(KIND_RECORD, OP_REMOVE, _display(target), old, None, target=target))
    # 2. known fields the JSON does not set
    rows = {**us.COMMON_ROWS, **us.FAMILY_ROWS.get(family or '', {})}
    for path, target in rows.items():
        if target.kind != us.KIND_RECORD or path in classification.mapped or path == 'custom':
            continue
        if target.scope == us.SCOPE_STANDARD or not us.removable_in_overwrite(target):
            continue
        exists, old = current_value(current, target)
        if exists and not is_blank(old):
            result.changes.append(Change(KIND_RECORD, OP_REMOVE, _display(target), old, None, target=target))


# --------------------------------------------------------------------------------------------------------------
# graph side: meta and jit_settings (plain dicts in, changes out)
# --------------------------------------------------------------------------------------------------------------

def _graph_change(op: str, comparator: str, path: str, old: Any, new: Any, note: str = '') -> Change:
    return Change(KIND_GRAPH, op, f'{comparator}.{path}', old, new, note=note,
                  target=us.Target(us.KIND_GRAPH, comparator=comparator, key=path))


def diff_flat(comparator: str, wanted: Dict[str, Any], current: Optional[Dict[str, Any]], *,
              explicit_only: Optional[Iterable[str]] = None, remove_extra: bool = False,
              protected: Iterable[str] = ()) -> List[Change]:
    """Changes between a wanted dict and the current one (nested keys are dotted paths).

    ``explicit_only`` limits the comparison to those dotted keys (the keys the user wrote); ``REMOVE`` as a wanted
    value removes the key. ``remove_extra`` also removes current keys that are not wanted (the deferred graph side
    of `overwrite`).
    """
    current = current if isinstance(current, dict) else {}
    flat_wanted = _flatten(wanted)
    keys = list(flat_wanted) if explicit_only is None else [k for k in flat_wanted if k in set(explicit_only)]
    changes: List[Change] = []
    for key in sorted(keys):
        value = flat_wanted[key]
        found, old = _dig(current, key.split('.'))
        if value is REMOVE:
            if found and not is_blank(old):
                changes.append(_graph_change(OP_REMOVE, comparator, key, old, None, 'back to the default'))
        elif not found or is_blank(old):
            if not is_blank(value):
                changes.append(_graph_change(OP_ADD, comparator, key, None, value))
        elif not same(old, value):
            changes.append(_graph_change(OP_CHANGE, comparator, key, old, value))
    if remove_extra:
        skip = set(protected) | PROTECTED_KEYS
        for key, old in _flatten(current).items():
            if key.split('.')[0] in skip or key in flat_wanted or is_blank(old):
                continue
            changes.append(_graph_change(OP_REMOVE, comparator, key, old, None))
    return changes


def desired_meta(raw_options: Any, raw_connection: Any = None) -> Dict[str, Any]:
    """The `meta` keys the JSON sets: option flags (on / off / default) and rotate_creds_on_session_termination."""
    wanted: Dict[str, Any] = {}
    if isinstance(raw_options, dict):
        for flag, (meta_key, _note) in us.OPTION_FLAGS.items():
            if flag not in raw_options:
                continue
            option = DagOptionValue.map(raw_options[flag]) if not isinstance(raw_options[flag], bool) else (
                DagOptionValue.ON if raw_options[flag] else DagOptionValue.OFF)
            if option is None:
                continue
            if option == DagOptionValue.DEFAULT:
                value: Any = REMOVE
            else:
                value = option == DagOptionValue.ON
                if flag == 'update_services':
                    value = not value               # stored inverted as no_update_services
            _nest(wanted, meta_key, value)
    if isinstance(raw_connection, dict) and 'rotate_creds_on_session_termination' in raw_connection:
        flag = raw_connection['rotate_creds_on_session_termination']
        if isinstance(flag, str):
            flag = flag.strip().lower() in ('true', 'yes', 'on', '1')
        _nest(wanted, 'rotateOnTermination', bool(flag))
    return wanted


def _nest(target: Dict[str, Any], dotted: str, value: Any) -> None:
    node = target
    parts = dotted.split('.')
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


CANNOT_RESET_THROUGH_ROUTER = 'cannot be reset to its default through the router (left as it is)'


def diff_meta(raw_options: Any, raw_connection: Any, current_meta: Optional[Dict[str, Any]], *,
              mode: str = MODE_MERGE, graph_overwrite: bool = False) -> Tuple[List[Change], List[str]]:
    """Changes of the resource `meta` edge: the option flags and rotate_creds_on_session_termination.

    Returns (changes, warnings). The meta edge is written through krouter (`configure_resource`) only: the router
    deep-merges it, so it can set a flag to true / false but can NEVER remove a key, and the legacy direct write
    that could is not to be used (it may be switched off at any time; owner decision 2026-11-16). A REMOVE of a
    meta key (an option set to `default`, or a key `overwrite` would drop) is therefore not a change: it becomes a
    warning and the key stays. Keeping it out of the changes also keeps a re-run idempotent.
    """
    wanted = desired_meta(raw_options, raw_connection)
    found = diff_flat('meta', wanted, current_meta,
                      remove_extra=(mode == MODE_OVERWRITE and graph_overwrite),
                      protected=('version', 'locked', 'idpConfigUid', 'defaultElevationTime'))
    changes = [c for c in found if c.op != OP_REMOVE]
    warnings = [f'{c.path} {CANNOT_RESET_THROUGH_ROUTER}' for c in found if c.op == OP_REMOVE]
    return changes, warnings


# raw jit_settings key -> key of the `jit_settings` DATA edge (source: DagJitSettingsObject.to_dag_dict)
JIT_RAW_TO_DAG: Dict[str, str] = {
    'create_ephemeral': 'createEphemeral',
    'elevate': 'elevate',
    'elevation_method': 'elevationMethod',
    'elevation_string': 'elevationString',
    'base_distinguished_name': 'baseDistinguishedName',
    'ephemeral_account_type': 'ephemeralAccountType',
    'use_idp_elevation': 'useIDPElevation',
}
# jit keys that live elsewhere: `pam_directory_record` is a link to a directory record (reference comparator),
# `default_elevation_time` is stored in the resource meta (defaultElevationTime, milliseconds)
JIT_OTHER = frozenset({'pam_directory_record', 'default_elevation_time'})


def diff_jit(raw_jit: Any, wanted_dag: Optional[Dict[str, Any]], current_jit: Optional[Dict[str, Any]], *,
             mode: str = MODE_MERGE, graph_overwrite: bool = False) -> Tuple[List[Change], List[str]]:
    """Changes of the `jit_settings` edge. *wanted_dag* is ``DagJitSettingsObject.to_dag_dict()``; only the keys the
    JSON wrote are compared (the object fills in defaults). Returns (changes, warnings)."""
    warnings: List[str] = []
    if not isinstance(raw_jit, dict):
        return [], warnings
    explicit = []
    for raw_key in raw_jit:
        if raw_key in JIT_RAW_TO_DAG:
            explicit.append(JIT_RAW_TO_DAG[raw_key])
        elif raw_key not in JIT_OTHER:
            warnings.append(f'key "pam_settings.options.jit_settings.{raw_key}" is not handled by update (ignored)')
    changes = diff_flat('jit_settings', wanted_dag or {}, current_jit,
                        explicit_only=None if (mode == MODE_OVERWRITE and graph_overwrite) else explicit,
                        remove_extra=(mode == MODE_OVERWRITE and graph_overwrite))
    return changes, warnings


# comparators that do not exist yet: a path that needs one is reported, never dropped silently. Empty since
# 2026-11-16: KeeperAI, rotation, workflow and the credential references are compared by `update_compare`
# (the orchestrator calls them with the UIDs the matcher resolved and the state `vault_reader` read).
NOT_COMPARED_YET: Dict[str, str] = {}


def not_compared_warnings(raw: Dict[str, Any], record_type: str, title: str = '') -> List[str]:
    """One warning per kind of setting the JSON mentions that this module does not compare yet."""
    classification = us.classify(raw, record_type)
    seen: Dict[str, str] = {}
    for path, target in classification.mapped.items():
        if target.kind in (us.KIND_GRAPH, us.KIND_API, us.KIND_REF) and target.comparator in NOT_COMPARED_YET:
            seen.setdefault(target.comparator, path)
    who = f'"{title}": ' if title else ''
    return [f'{who}{NOT_COMPARED_YET[name]} is not compared yet ("{path}")' for name, path in sorted(seen.items())]
