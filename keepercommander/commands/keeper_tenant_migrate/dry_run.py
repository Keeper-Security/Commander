"""Dry-run wrapper + planning-diff report.

The `DryRun` wrapper intercepts every mutating call on a Commander client
and records it as a *planned operation* without touching the tenant.
Non-mutating calls (list_entities, count_*, get_record_json, sync_down)
pass through to the real client so the driver reads accurate state.

After the driver finishes, `classify_plan(dry_run, target_state)`
compares each planned op against current target state and reports:
  - CREATE     — target lacks the entity; migration would add it
  - SKIP       — target already has a matching entity; no-op
  - CONFLICT   — target has a same-named entity but with different attrs
                 (e.g., team has a different restricts string)
  - UNCHECKED  — we can't tell from target state alone (e.g., attachment
                 upload without a prior export)

`render_report(plan, classification)` emits a Markdown summary so users
see exactly what the migration would do before committing.
"""

import logging


# Return shapes for the methods we stub out. Keyed by method name.
# Folder-create methods return synthetic UID strings so downstream
# `new_uid[:12]` slices in structure.step_vault_folders don't crash on
# the bare True default. The synthetic UIDs are clearly non-real and
# never reach an API call (DryRun records the call instead).
_DRY_RUN_RETURNS = {
    'invite_user':       (True, '[dry-run]'),
    'share_record':      'OK',
    'download_attachments': [],
    'add_user_folder':       '[DRY-RUN-USER-FOLDER]',
    'add_shared_folder':     '[DRY-RUN-SHARED-FOLDER]',
    'add_subfolder':         '[DRY-RUN-SUB-FOLDER]',
}


class DryRun:
    """Transparent wrapper. Mutating calls → recorded + logged; reads → passthrough."""

    PASSTHROUGH = frozenset({
        'list_entities', 'user_exists', 'get_record_json',
        'count_nodes', 'count_teams', 'count_roles', 'count_users',
        'sync_down',
    })

    def __init__(self, client, *, logger_name='tenant-migrate.dry-run'):
        self._client = client
        self._log = logging.getLogger(logger_name)
        self._calls = []

    @property
    def calls(self):
        return self._calls

    def _stub(self, name):
        def call(*args, **kwargs):
            self._calls.append((name, args, kwargs))
            arg_repr = ', '.join(repr(a) for a in args)
            kw_repr = ', '.join(f'{k}={v!r}' for k, v in kwargs.items())
            self._log.info('[dry-run] %s(%s%s%s)', name, arg_repr,
                           ', ' if arg_repr and kw_repr else '', kw_repr)
            return _DRY_RUN_RETURNS.get(name, True)
        return call

    def __getattr__(self, name):
        if name in self.PASSTHROUGH:
            return getattr(self._client, name)
        # Any non-passthrough attribute returns a logging stub. We don't
        # require the wrapped client to implement it — DryRun may be driven
        # across multiple protocols at once.
        attr = getattr(self._client, name, None)
        if attr is not None and not callable(attr):
            return attr
        return self._stub(name)


# ─── Plan classification ─────────────────────────────────────────────────────


CREATE = 'CREATE'
SKIP = 'SKIP'
CONFLICT = 'CONFLICT'
UNCHECKED = 'UNCHECKED'
DELETE = 'DELETE'
MANUAL = 'MANUAL'   # needs a human action outside this tool (user or admin)


def _index_by_name(items):
    """{name: entity_dict} for a target_state list."""
    return {(e.get('name') or '').lower(): e for e in items or [] if e.get('name')}


def _index_users_by_email(items):
    return {(e.get('email') or '').lower(): e
            for e in items or [] if e.get('email')}


def classify_plan(dry_run, target_state):
    """Walk the planned ops and classify each against target_state.

    Returns list of dicts:
      {'op': method_name, 'args': tuple, 'kwargs': dict,
       'classification': CREATE|SKIP|CONFLICT|UNCHECKED|DELETE,
       'detail': str}
    """
    node_idx = _index_by_name(target_state.get('nodes', []))
    team_idx = _index_by_name(target_state.get('teams', []))
    role_idx = _index_by_name(target_state.get('roles', []))
    user_idx = _index_users_by_email(target_state.get('users', []))
    sf_idx = _index_by_name(target_state.get('shared_folders', []))

    out = []
    for name, args, kwargs in dry_run.calls:
        classification = UNCHECKED
        detail = ''

        if name == 'create_node':
            node_name = args[0] if args else kwargs.get('name', '')
            hit = node_idx.get(node_name.lower())
            if hit is None:
                classification, detail = CREATE, f'node {node_name!r}'
            else:
                classification, detail = SKIP, f'node {node_name!r} already exists'

        elif name == 'create_team':
            team_name = args[0] if args else kwargs.get('name', '')
            hit = team_idx.get(team_name.lower())
            if hit is None:
                classification, detail = CREATE, f'team {team_name!r}'
            else:
                src_node = args[1] if len(args) > 1 else kwargs.get('node', '')
                src_restricts = _team_restricts_from_args(args, kwargs)
                if src_node and src_node != (hit.get('parent') or ''):
                    classification, detail = (
                        CONFLICT,
                        f"team {team_name!r} exists but on a different node "
                        f"(target: {hit.get('parent', '')!r}, source: {src_node!r})"
                    )
                elif src_restricts and src_restricts != (hit.get('restricts') or ''):
                    classification, detail = (
                        CONFLICT,
                        f"team {team_name!r} exists with different restricts "
                        f"(target: {hit.get('restricts', '')!r}, "
                        f"source: {src_restricts!r})"
                    )
                else:
                    classification, detail = SKIP, f'team {team_name!r} already matches'

        elif name == 'create_role':
            role_name = args[0] if args else kwargs.get('name', '')
            hit = role_idx.get(role_name.lower())
            if hit is None:
                classification, detail = CREATE, f'role {role_name!r}'
            else:
                classification, detail = SKIP, f'role {role_name!r} already exists'

        elif name in ('invite_user', 'assign_user_to_node'):
            email = args[0] if args else ''
            if email and email.lower() in user_idx:
                classification, detail = SKIP, f'user {email!r} already on target'
            elif email:
                classification, detail = CREATE, f'user {email!r}'

        elif name == 'toggle_node_isolated':
            node_name = args[0] if args else kwargs.get('name', '')
            hit = node_idx.get(node_name.lower())
            if hit is None:
                classification = UNCHECKED
                detail = f'node {node_name!r} not on target (will be created first)'
            elif hit.get('isolated'):
                classification, detail = SKIP, f'node {node_name!r} already isolated'
            else:
                classification, detail = CREATE, f'node {node_name!r} isolated toggle'

        # Cleanup operations
        elif name in ('delete_team', 'delete_role', 'delete_node',
                       'delete_record', 'delete_shared_folder',
                       'lock_user', 'delete_user'):
            target_name = args[0] if args else ''
            classification = DELETE
            detail = f'{name.replace("_", " ")}: {target_name!r}'

        else:
            classification = UNCHECKED
            detail = f'{name} (no target-state probe for this op)'

        out.append({
            'op': name, 'args': args, 'kwargs': kwargs,
            'classification': classification, 'detail': detail,
        })
    return out


def _team_restricts_from_args(args, kwargs):
    """Rebuild the R/W/S restricts string from create_team args."""
    rs = args[2] if len(args) > 2 else kwargs.get('restrict_share', 'off')
    re_ = args[3] if len(args) > 3 else kwargs.get('restrict_edit', 'off')
    rv = args[4] if len(args) > 4 else kwargs.get('restrict_view', 'off')
    parts = []
    if re_ == 'on':
        parts.append('R')
    if rv == 'on':
        parts.append('W')
    if rs == 'on':
        parts.append('S')
    return ' '.join(parts)


def summarize(classified):
    counts = {CREATE: 0, SKIP: 0, CONFLICT: 0, UNCHECKED: 0, DELETE: 0}
    for entry in classified:
        counts[entry['classification']] = counts.get(entry['classification'], 0) + 1
    return counts


def render_report(classified, summary=None):
    """Markdown: summary table + per-category lists."""
    summary = summary or summarize(classified)
    lines = ['# Dry-run plan', '']
    lines.append('| Outcome | Count |')
    lines.append('|---------|------:|')
    for key in (CREATE, SKIP, CONFLICT, DELETE, UNCHECKED):
        lines.append(f'| {key} | {summary.get(key, 0)} |')
    lines.append(f'| **Total** | {sum(summary.values())} |')
    lines.append('')

    by_class = {CREATE: [], SKIP: [], CONFLICT: [], DELETE: [], UNCHECKED: []}
    for entry in classified:
        by_class[entry['classification']].append(entry)

    for key in (CONFLICT, CREATE, DELETE, SKIP, UNCHECKED):
        rows = by_class[key]
        if not rows:
            continue
        lines.append(f'## {key} ({len(rows)})')
        lines.append('')
        for r in rows[:200]:   # cap for readability
            lines.append(f'- `{r["op"]}` — {r["detail"]}')
        if len(rows) > 200:
            lines.append(f'- ...and {len(rows) - 200} more')
        lines.append('')

    return '\n'.join(lines) + '\n'
