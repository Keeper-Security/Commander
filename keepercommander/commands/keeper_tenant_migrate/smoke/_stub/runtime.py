"""Kwarg-strict Commander stub for CI smoke.

The premise: Commander's argparse parsers define the EXACT set of `dest`
names each .execute() will accept. The plugin's commander_clients.py
forwards a curated set of those kwargs. If we ever drift (rename,
remove, mistype), live tenants reject the call — but the unit fakes
silently accept it, so unit tests pass while the real SDK would fail.

This stub closes that gap by:
  1. Reading each Command class's real argparse parser at install time.
  2. Recording the dest set for that class.
  3. Monkey-patching .execute() to assert every kwarg ∈ dest set.
  4. Maintaining a plausible `params.enterprise` snapshot so the smoke
     drivers can verify end-to-end state (create node → count goes up).

Why not use the existing `tests/test_commander_kwargs.py`? That file
checks one method at a time with a CaptureHelper, and only validates
the kwargs sent — it doesn't run the subcommand end-to-end. The smoke
layer covers the FULL path: parser → command → client → SDK.
"""

import contextlib
import logging
import os
import threading
from unittest import mock


# Public name surfaced to smoke tests. Inherits from BaseException so
# commander_clients._call's `except Exception` swallow does NOT catch it
# — drift must escape to the smoke test. Reads as a deliberate API
# contract: "the stub asserted unknown kwargs that drift from the real
# SDK", same outcome as the live argparse rejecting the call.
class StubAssertionError(BaseException):
    """Raised when the plugin sends a kwarg not in the SDK's argparse."""


# Per-thread record of the most recent unknown-kwarg report. Tests may
# read this to assert *which* kwarg drifted, not just that something did.
_local = threading.local()


def register_unknown_kwarg(cmd_name, unknown, valid):
    """Record an unknown-kwarg event (used by the smoke harness self-test)."""
    _local.last_unknown = (cmd_name, set(unknown), set(valid))


def get_last_unknown_kwarg():
    """Return the most recent unknown-kwarg event, or None."""
    return getattr(_local, 'last_unknown', None)


def _parser_dests(cmd_cls):
    """Return the dest set of `cmd_cls`'s argparse parser.

    Filters out 'help' (always present, never sent through .execute()).
    Returns the empty set if the class has no parser (e.g., GroupCommand
    delegates to subcommands).
    """
    parser = None
    if hasattr(cmd_cls, 'get_parser'):
        try:
            parser = cmd_cls().get_parser()
        except Exception:                                  # noqa: BLE001
            parser = None
    if parser is None or not hasattr(parser, '_actions'):
        return set()
    return {a.dest for a in parser._actions if a.dest and a.dest != 'help'}


def build_smoke_params(*, enterprise_name='SmokeCo',
                       scope_node='MIGRATION-TEST-NODE',
                       prefix='MIGTEST-'):
    """Construct a params-shaped object the smoke drivers can mutate.

    Mirrors keepercommander.params.KeeperParams in the bits the plugin
    actually reads: enterprise dict, record_cache, folder_cache, server,
    user, current_folder. No login state, no session keys — the stub
    swallows every Command.execute() call without ever touching the SDK
    transport layer.
    """

    class _SmokeParams:
        pass

    p = _SmokeParams()
    p.user = f'admin@{enterprise_name.lower()}.example'
    p.server = 'https://keepersecurity.eu'
    p.config_filename = ''
    p.current_folder = None

    # Enterprise: one root node + one MIGRATION-TEST-NODE child.
    # `scope_node` is a child of root; the stub creates everything
    # underneath it via `enterprise-node --add` calls.
    p.enterprise = {
        'enterprise_name': enterprise_name,
        'nodes': [
            {'node_id': 1,
             'data': {'displayname': enterprise_name},
             'parent_id': None},
            {'node_id': 2,
             'data': {'displayname': scope_node,
                      'restrict_visibility': False},
             'parent_id': 1},
        ],
        'teams': [],
        'roles': [],
        'users': [
            {'enterprise_user_id': 100,
             'username': p.user,
             'node_id': 1,
             'status': 'active',
             'two_factor_enabled': False,
             'job_title': 'Admin'},
            # Pre-existing MIGTEST user (so users smoke can classify CREATE vs SKIP).
            {'enterprise_user_id': 101,
             'username': f'{prefix.lower().rstrip("-")}-existing@{enterprise_name.lower()}.example',
             'node_id': 2,
             'status': 'active',
             'two_factor_enabled': False,
             'job_title': 'Eng'},
        ],
        'shared_folders': [],
        'shared_folder_users': [],
        'shared_folder_teams': [],
        'managed_nodes': [],
        'role_privileges': [],
        'role_enforcements': [],
        'role_users': [],
        'role_teams': [],
        'queued_team_users': [],
    }
    p.record_cache = {}
    p.folder_cache = {}
    p.subfolder_cache = {}
    p.subfolder_record_cache = {}
    p.session_token = b''                                   # unused, presence only
    p.scope_node = scope_node
    p.prefix = prefix
    return p


class StubKwargRecorder:
    """Records every (cmd_name, kwargs) tuple the harness intercepts."""

    def __init__(self):
        self.calls = []

    def record(self, cmd_name, kwargs):
        self.calls.append((cmd_name, dict(kwargs)))

    def names(self):
        return [c[0] for c in self.calls]

    def kwargs_for(self, cmd_name):
        return [c[1] for c in self.calls if c[0] == cmd_name]

    def reset(self):
        self.calls.clear()


class StubCommander(contextlib.ExitStack):
    """Context manager that installs the kwarg-strict stub.

    Patches every Commander Command class the plugin imports inside
    commander_clients.py. Each .execute() call:
       1. Validates kwargs against the parser dest set.
       2. Records the call.
       3. Mutates params.enterprise so subsequent reads see the state.

    Optional kwarg overrides per command class via `behaviors` —
    a dict {CommandClass: callable(params, kwargs) -> None}. Used to
    simulate edge cases (Commander silent skip, network drop, etc.).

    Optional `extra_strict_drift`: dict {CommandClass: set_of_kwarg_names}
    of kwargs to *also* reject as if they were unknown. Used by the
    harness self-test to simulate SDK drift.
    """

    def __init__(self, *, behaviors=None, extra_strict_drift=None):
        super().__init__()
        self.recorder = StubKwargRecorder()
        self._behaviors = dict(behaviors or {})
        self._drift = {cls: set(names) for cls, names
                       in (extra_strict_drift or {}).items()}
        self._patched_classes = []

    # ── Public registration helpers ──────────────────────────────────

    def register_drift(self, cmd_cls, kwarg_name):
        """Mark `kwarg_name` as drifted for `cmd_cls` (rejected on call)."""
        self._drift.setdefault(cmd_cls, set()).add(kwarg_name)

    # ── Context-manager plumbing ─────────────────────────────────────

    def __enter__(self):
        super().__enter__()
        self._install()
        return self

    def _install(self):
        # Import lazily — keepercommander imports are slow.
        from keepercommander.commands.enterprise import (
            EnterpriseNodeCommand, EnterpriseRoleCommand,
            EnterpriseTeamCommand, EnterpriseUserCommand,
        )
        from keepercommander.commands.folder import (
            FolderMakeCommand, FolderRemoveCommand,
        )
        from keepercommander.commands.record_edit import (
            RecordDownloadAttachmentCommand,
            RecordUploadAttachmentCommand,
        )
        from keepercommander.commands.register import (
            ShareFolderCommand, ShareRecordCommand,
        )
        from keepercommander.importer.commands import (
            ApplyMembershipCommand, LoadRecordTypeCommand,
            RecordImportCommand,
        )
        # `record` module path moves between Commander versions; resolve
        # at install time.
        try:
            from keepercommander.commands.record import RecordRemoveCommand
        except ImportError:                                # pragma: no cover
            RecordRemoveCommand = None

        targets = [
            EnterpriseNodeCommand, EnterpriseRoleCommand,
            EnterpriseTeamCommand, EnterpriseUserCommand,
            FolderMakeCommand, FolderRemoveCommand,
            RecordDownloadAttachmentCommand,
            RecordUploadAttachmentCommand,
            ShareFolderCommand, ShareRecordCommand,
            ApplyMembershipCommand, LoadRecordTypeCommand,
            RecordImportCommand,
        ]
        if RecordRemoveCommand is not None:
            targets.append(RecordRemoveCommand)

        # Build the dest table once, at install time. The argparse
        # parsers are read from the REAL Commander module — so any
        # plugin kwarg that's not a real dest is rejected.
        self._dest_table = {cls: _parser_dests(cls) for cls in targets}

        # Also patch the api.sync_down + api.query_enterprise pair the
        # plugin calls before reading state — they would otherwise try
        # to hit the network.
        from keepercommander import api
        self.enter_context(mock.patch.object(api, 'sync_down', _noop))
        self.enter_context(mock.patch.object(api, 'query_enterprise', _noop))
        self.enter_context(mock.patch.object(api, 'get_record',
                                              side_effect=_fake_get_record))

        for cls in targets:
            self._patched_classes.append(cls)
            patched = self._make_execute(cls)
            self.enter_context(mock.patch.object(cls, 'execute', patched))

    def _make_execute(self, cls):
        recorder = self.recorder
        dests = self._dest_table[cls]
        behaviors = self._behaviors
        drift = self._drift

        def execute(self_, params, **kwargs):              # noqa: ARG001
            cls_name = cls.__name__
            sent = set(kwargs.keys())
            forbidden = sent & drift.get(cls, set())
            if forbidden:
                register_unknown_kwarg(cls_name, forbidden, dests)
                raise StubAssertionError(
                    f'{cls_name}: drift-rejected kwargs {forbidden} '
                    f'(harness self-test mode)')
            unknown = sent - dests
            if unknown:
                register_unknown_kwarg(cls_name, unknown, dests)
                raise StubAssertionError(
                    f'{cls_name}: unknown kwargs {unknown}. '
                    f'Valid dests: {sorted(dests)}')
            recorder.record(cls_name, kwargs)
            # Default state-mutator: keeps params.enterprise consistent
            # so smoke drivers can verify create/delete cycles.
            _default_mutator(cls, params, kwargs)
            # Per-test override (simulate silent skip / failure / etc).
            override = behaviors.get(cls)
            if override is not None:
                override(params, kwargs)

        return execute

    def parser_dests(self, cmd_cls):
        """Read access to the install-time dest table (for assertions)."""
        return set(self._dest_table.get(cmd_cls, set()))


# ─── Helpers ─────────────────────────────────────────────────────────


def _noop(*_args, **_kwargs):
    return None


def _fake_get_record(params, uid):
    """Stand-in for keepercommander.api.get_record.

    Reads from params.record_cache. Returns a tiny stand-in object with
    .title and .record_uid attrs. Sufficient for records-export and the
    cleanup record listing path. Title comes from the JSON-encoded
    `data_unencrypted` blob to match the real cache shape.
    """
    cache = getattr(params, 'record_cache', {}) or {}
    cached = cache.get(uid)
    if not cached:
        return None
    title = cached.get('title') or ''
    if not title:
        import json as _json
        raw = cached.get('data_unencrypted', b'{}')
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', errors='replace')
        try:
            title = (_json.loads(raw) or {}).get('title') or ''
        except _json.JSONDecodeError:
            title = ''

    class _R:
        pass

    r = _R()
    r.record_uid = uid
    r.title = title
    return r


def _default_mutator(cls, params, kwargs):
    """Fold kwargs into params.enterprise so verify can read state back.

    Only the state changes the smoke drivers need — node/team/role
    create+delete, user invite, record cache. No need to model every
    Commander side-effect.
    """
    cls_name = cls.__name__
    ent = getattr(params, 'enterprise', None) or {}
    if cls_name == 'EnterpriseNodeCommand':
        if kwargs.get('add'):
            _add_node(ent, kwargs)
        elif kwargs.get('delete'):
            _delete_node(ent, kwargs)
    elif cls_name == 'EnterpriseTeamCommand':
        if kwargs.get('add'):
            _add_team(ent, kwargs)
        elif kwargs.get('delete'):
            _delete_team(ent, kwargs)
        elif kwargs.get('add_user'):
            _add_team_user(ent, kwargs)
    elif cls_name == 'EnterpriseRoleCommand':
        if kwargs.get('add'):
            _add_role(ent, kwargs)
        elif kwargs.get('delete'):
            _delete_role(ent, kwargs)
    elif cls_name == 'EnterpriseUserCommand':
        if kwargs.get('invite'):
            _invite_user(ent, kwargs)
        elif kwargs.get('lock'):
            _lock_user(ent, kwargs)
        elif kwargs.get('delete'):
            _delete_user(ent, kwargs)


def _names(kw, key):
    val = kw.get(key)
    if isinstance(val, list):
        return [v for v in val if v]
    return [val] if val else []


def _add_node(ent, kw):
    nodes = ent.setdefault('nodes', [])
    parent_name = (kw.get('parent') or '')
    parent_id = None
    for n in nodes:
        nm = (n.get('data') or {}).get('displayname') or ''
        if nm == parent_name:
            parent_id = n.get('node_id')
            break
    if parent_id is None and parent_name:
        # Implicit parent — place under root.
        parent_id = nodes[0].get('node_id') if nodes else 1
    next_id = max((n.get('node_id') or 0) for n in nodes) + 1 if nodes else 1
    for name in _names(kw, 'node'):
        nodes.append({
            'node_id': next_id,
            'data': {'displayname': name, 'restrict_visibility': False},
            'parent_id': parent_id,
        })
        next_id += 1


def _delete_node(ent, kw):
    target = set(_names(kw, 'node'))
    if not target:
        return
    keep = []
    for n in ent.get('nodes') or []:
        nm = (n.get('data') or {}).get('displayname') or ''
        if nm in target:
            continue
        keep.append(n)
    ent['nodes'] = keep


def _add_team(ent, kw):
    teams = ent.setdefault('teams', [])
    node_name = kw.get('node') or ''
    node_id = _find_node_id(ent, node_name)
    for name in _names(kw, 'team'):
        teams.append({
            'team_uid': f't-{len(teams) + 1:04d}',
            'name': name,
            'node_id': node_id,
            'restrict_share': kw.get('restrict_share', 'off'),
            'restrict_edit': kw.get('restrict_edit', 'off'),
            'restrict_view': kw.get('restrict_view', 'off'),
            'restrict_sharing': kw.get('restrict_share', 'off'),
        })


def _delete_team(ent, kw):
    target = set(_names(kw, 'team'))
    ent['teams'] = [t for t in ent.get('teams') or []
                    if t.get('name') not in target]


def _add_team_user(ent, kw):
    """Approve queued user OR add user to team, whichever models reality."""
    qtu = ent.setdefault('queued_team_users', [])
    team_names = set(_names(kw, 'team'))
    user_emails = set(_names(kw, 'add_user'))
    for tn in team_names:
        for ue in user_emails:
            qtu.append({'team_name': tn, 'username': ue})


def _add_role(ent, kw):
    roles = ent.setdefault('roles', [])
    node_id = _find_node_id(ent, kw.get('node') or '')
    for name in _names(kw, 'role'):
        roles.append({
            'role_id': 1000 + len(roles) + 1,
            'data': {'displayname': name},
            'node_id': node_id,
            'new_user_inherit': kw.get('new_user') == 'on',
        })


def _delete_role(ent, kw):
    target = set(_names(kw, 'role'))
    keep = []
    for r in ent.get('roles') or []:
        nm = (r.get('data') or {}).get('displayname') or r.get('name', '')
        if nm in target:
            continue
        keep.append(r)
    ent['roles'] = keep


def _invite_user(ent, kw):
    users = ent.setdefault('users', [])
    emails = _names(kw, 'email')
    if not emails:
        return
    node_id = _find_node_id(ent, kw.get('node') or '') or 2
    for email in emails:
        users.append({
            'enterprise_user_id': 2000 + len(users),
            'username': email,
            'node_id': node_id,
            'status': 'invited',
            'two_factor_enabled': False,
            'job_title': kw.get('jobtitle') or '',
        })


def _lock_user(ent, kw):
    target = {e.lower() for e in _names(kw, 'email')}
    for u in ent.get('users') or []:
        if (u.get('username') or '').lower() in target:
            u['status'] = 'locked'


def _delete_user(ent, kw):
    target = {e.lower() for e in _names(kw, 'email')}
    ent['users'] = [u for u in ent.get('users') or []
                    if (u.get('username') or '').lower() not in target]


def _find_node_id(ent, name):
    if not name:
        return None
    for n in ent.get('nodes') or []:
        nm = (n.get('data') or {}).get('displayname') or ''
        if nm == name:
            return n.get('node_id')
    return None


# ─── Smoke-side record-cache helpers ─────────────────────────────────


def seed_record(params, *, uid, title, record_type='login',
                fields=None, folders=None):
    """Seed `params.record_cache` with a record so records-export sees it.

    The shape mirrors what Commander's sync_down would write — just
    enough for records-export to render the JSON file end-to-end.
    """
    import json as _json
    data = {
        'type': record_type,
        'title': title,
        'fields': fields or [],
    }
    params.record_cache[uid] = {
        'data_unencrypted': _json.dumps(data).encode('utf-8'),
        'shares': {'user_permissions': [], 'shared_folder_permissions': []},
    }
    if folders is not None:
        # Optional folder hookup — folder index reads subfolder_record_cache.
        getattr(params, 'subfolder_record_cache', {}).setdefault(uid, list(folders))
    return uid


def writeable_run_dir(suffix=''):
    """Helper for smoke tests — ephemeral run-dir under /tmp."""
    import tempfile
    return tempfile.mkdtemp(prefix=f'kcmd-smoke-{suffix}-')


# Silence the plugin's chatty INFO output during smoke runs.
logging.getLogger('keepercommander.commands.keeper_tenant_migrate').setLevel(logging.WARNING)

# Keep the `os` import used for nothing visible right now — it's
# referenced by tests that import this module.
_ = os
