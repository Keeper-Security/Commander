"""Nested-SF planner: classify shared_folder_folder subfolders against a 5-option migration matrix.

Reads a `live_inventory` / `plan`-produced inventory JSON, walks every
`shared_folder_folder` (subfolder living inside a `shared_folder`), and
classifies it against the 5-option migration matrix documented in
`.context/sf-option-matrix.md`:

- `preserve-subfolder` (legacy `inherit`): keep as `shared_folder_folder`
  on target, inheriting parent perms/membership.
- `promote-to-sibling` (legacy `promote-to-shared_folder`): create a top-
  level shared_folder on target with qualified name `Parent - Child`.
- `promote-to-true-nested`: forward-compat placeholder — only emitted
  when `commander_supports_true_nested_sf()` returns `True` (no released
  Commander version supports this today; see
  `.context/sf-commander-surface.md`).
- `flatten-with-prefix`: create a top-level SF named `Parent__Child` on
  legacy targets that don't support `shared_folder_folder`.
- `needs-review`: parent SF data missing or ambiguous — operator must
  edit plan JSON before structure consumes it.

Plus the emergent `hybrid-per-folder` mode: a plan JSON with a mix of
the above per-row actions.

Operator UX:
- `--default-action <key>` controls the default for every subfolder
  that diverges from parent.
- `--per-folder-rules <json>` overrides per-subfolder UID.
- Each row carries `conflict_resolution` ∈ {error, suffix, merge} for
  name-collision handling at apply time (default `error`).
"""

import datetime
import hashlib
import json
import logging
import os


# ─── Classification keys (legacy-compatible) ────────────────────────────────

PROMOTE = 'promotion-candidate'
INHERIT = 'inherit'
UNKNOWN = 'cannot-classify'

# ─── 5-option action enum ───────────────────────────────────────────────────

ACTION_PRESERVE = 'preserve-subfolder'
ACTION_PROMOTE = 'promote-to-sibling'
ACTION_TRUE_NESTED = 'promote-to-true-nested'
ACTION_FLATTEN = 'flatten-with-prefix'
ACTION_REVIEW = 'needs-review'

# Legacy aliases — preserved for backwards-compat with plans written by
# previous versions (tests that imported the old name keep working).
ACTION_PRESERVE_LEGACY = 'preserve-as-subfolder'
ACTION_PROMOTE_LEGACY = 'promote-to-shared_folder'

ALL_ACTIONS = (
    ACTION_PRESERVE,
    ACTION_PROMOTE,
    ACTION_TRUE_NESTED,
    ACTION_FLATTEN,
    ACTION_REVIEW,
)
DIVERGENT_ACTIONS = (
    ACTION_PROMOTE,
    ACTION_TRUE_NESTED,
    ACTION_FLATTEN,
)

# ─── Conflict resolution policy ─────────────────────────────────────────────

CONFLICT_ERROR = 'error'
CONFLICT_SUFFIX = 'suffix'
CONFLICT_MERGE = 'merge'

ALL_CONFLICT_POLICIES = (CONFLICT_ERROR, CONFLICT_SUFFIX, CONFLICT_MERGE)


_PERM_KEYS = ('default_manage_users', 'default_manage_records',
               'default_can_edit', 'default_can_share')


def _norm_perm(value):
    return None if value is None else bool(value)


def _user_signature(users):
    out = {}
    for u in users or []:
        if not isinstance(u, dict):
            continue
        email = (u.get('username') or u.get('email') or '').strip().lower()
        if not email:
            continue
        out[email] = {
            'manage_users': bool(u.get('manage_users', False)),
            'manage_records': bool(u.get('manage_records', False)),
            'can_edit': bool(u.get('can_edit', False)),
            'can_share': bool(u.get('can_share', False)),
        }
    return out


def _team_signature(teams):
    out = {}
    for t in teams or []:
        if not isinstance(t, dict):
            continue
        name = (t.get('name') or t.get('team_name') or '').strip()
        if not name:
            continue
        out[name] = {
            'manage_users': bool(t.get('manage_users', False)),
            'manage_records': bool(t.get('manage_records', False)),
        }
    return out


def _perm_signature(sf):
    return {k: _norm_perm(sf.get(k)) for k in _PERM_KEYS}


def _diff_users(parent_users, child_users):
    extra = sorted(set(child_users) - set(parent_users))
    missing = sorted(set(parent_users) - set(child_users))
    differing = sorted(
        e for e in (set(parent_users) & set(child_users))
        if parent_users[e] != child_users[e]
    )
    return extra, missing, differing


def _diff_teams(parent_teams, child_teams):
    extra = sorted(set(child_teams) - set(parent_teams))
    missing = sorted(set(parent_teams) - set(child_teams))
    differing = sorted(
        n for n in (set(parent_teams) & set(child_teams))
        if parent_teams[n] != child_teams[n]
    )
    return extra, missing, differing


def _diff_perms(parent_perms, child_perms):
    return sorted(
        k for k in _PERM_KEYS
        if parent_perms.get(k) is not None
        and child_perms.get(k) is not None
        and parent_perms[k] != child_perms[k]
    )


def _has_membership(sf):
    return bool((sf.get('users') or []) or (sf.get('teams') or []))


def _qualified_name(parent_name, child_name):
    return f'{parent_name} - {child_name}'


def _flattened_name(parent_name, child_name):
    return f'{parent_name}__{child_name}'


def _build_sf_index(shared_folders):
    by_uid = {}
    for sf in shared_folders or []:
        uid = sf.get('uid') or sf.get('shared_folder_uid') or ''
        if uid:
            by_uid[uid] = sf
    return by_uid


def commander_supports_true_nested_sf(*, version=None, source_path=None):
    """Runtime probe — does the loaded Commander expose true-nested SF?

    Returns False for every released Commander up through v17.2.15
    (verified by `.context/sf-commander-surface.md`). The probe checks
    two signals in order:

    1. `version` argument (or `keepercommander.__version__` if absent):
       only flips `True` when the version is unambiguously newer than the
       last known no-support release — for now hardcoded to `False` for
       any version string we recognise.
    2. The Commander source: when reachable, look for the canonical
       'Shared folders cannot be nested' guard in
       `keepercommander/commands/folder.py`. If absent (i.e., Keeper
       removed the block), assume true-nested is now allowed.

    `source_path` lets tests inject a fake folder.py path — defaults to
    the real Commander install when None.
    """
    sentinel = 'Shared folders cannot be nested'
    # Probe 1: explicit version override (most deterministic in tests)
    if version is None:
        try:                                     # pragma: no cover
            from keepercommander import __version__ as version
        except Exception:                         # noqa: BLE001
            version = ''
    if version:
        # Every version we know about does NOT support true nested SF.
        # When Keeper releases a version that does, this list updates +
        # the sentinel-source check below also flips.
        no_support = (
            '17.1.0', '17.2.0', '17.2.1', '17.2.2', '17.2.3', '17.2.4',
            '17.2.5', '17.2.6', '17.2.7', '17.2.8', '17.2.9', '17.2.10',
            '17.2.11', '17.2.12', '17.2.13', '17.2.14', '17.2.15',
        )
        if version in no_support:
            # Still consult source — in case a hot-fix removed the block.
            pass
    # Probe 2: source-side sentinel check
    if source_path is None:
        try:                                     # pragma: no cover
            import keepercommander.commands.folder as _folder_mod
            source_path = _folder_mod.__file__
        except Exception:                         # noqa: BLE001
            source_path = ''
    if source_path and os.path.isfile(source_path):
        try:
            with open(source_path) as f:
                text = f.read()
        except OSError:
            return False
        return sentinel not in text
    return False


def _classify_subfolder(parent_sf, subfolder, *,
                         default_action=ACTION_PROMOTE,
                         override_action=None,
                         supports_true_nested=False):
    """Return (classification, action, reason, diff_dict).

    `parent_sf` is the SF entity dict; `subfolder` is a vault_folder
    entry of type shared_folder_folder, with optional embedded
    'sf_view' key holding the cached user/team/perm shape.
    `default_action` is the strategy applied to every divergent
    subfolder (default `promote-to-sibling` — matches legacy behaviour).
    `override_action` (when set) wins over `default_action` and over the
    diff-based recommendation; this is how `--per-folder-rules` works.
    `supports_true_nested` should be the result of
    `commander_supports_true_nested_sf()` — when False and
    `default_action == ACTION_TRUE_NESTED`, falls back to
    `ACTION_PROMOTE`.
    """
    sub_view = subfolder.get('sf_view') or {}

    if parent_sf is None:
        return (UNKNOWN, ACTION_REVIEW,
                'parent shared_folder not present in inventory',
                {})

    # Operator override always wins (modulo true-nested gating).
    if override_action and override_action in ALL_ACTIONS:
        if (override_action == ACTION_TRUE_NESTED
                and not supports_true_nested):
            return (PROMOTE, ACTION_PROMOTE,
                    'override true-nested → sibling (Commander lacks '
                    'support)',
                    {})
        if override_action == ACTION_PRESERVE:
            return (INHERIT, override_action,
                    'operator override: preserve as subfolder', {})
        if override_action == ACTION_REVIEW:
            return (UNKNOWN, override_action,
                    'operator override: needs-review', {})
        return (PROMOTE, override_action,
                f'operator override: {override_action}', {})

    parent_users = _user_signature(parent_sf.get('users'))
    parent_teams = _team_signature(parent_sf.get('teams'))
    parent_perms = _perm_signature(parent_sf)

    has_sub_data = bool(sub_view)
    if not has_sub_data:
        return (INHERIT, ACTION_PRESERVE,
                'no subfolder-level data captured (default inherit)',
                {})

    sub_users = _user_signature(sub_view.get('users'))
    sub_teams = _team_signature(sub_view.get('teams'))
    sub_perms = _perm_signature(sub_view)

    if not _has_membership(sub_view) and all(
            sub_perms.get(k) is None for k in _PERM_KEYS):
        return (INHERIT, ACTION_PRESERVE,
                'subfolder carries no independent membership or '
                'permissions', {})

    extra_u, missing_u, differing_u = _diff_users(parent_users, sub_users)
    extra_t, missing_t, differing_t = _diff_teams(parent_teams, sub_teams)
    differing_p = _diff_perms(parent_perms, sub_perms)

    member_diff = bool(extra_u or missing_u or differing_u
                       or extra_t or missing_t or differing_t)
    perm_diff = bool(differing_p)

    if not member_diff and not perm_diff:
        return (INHERIT, ACTION_PRESERVE,
                'membership and permissions match parent', {})

    # Divergent — pick action by default_action, modulo true-nested
    # availability.
    chosen = default_action
    if chosen == ACTION_TRUE_NESTED and not supports_true_nested:
        chosen = ACTION_PROMOTE
    if chosen not in DIVERGENT_ACTIONS:
        # Operator passed `preserve-subfolder` or `needs-review` as
        # default — a divergent subfolder still deserves a tag. Promote
        # for safety.
        chosen = ACTION_PROMOTE

    reasons = []
    diff_payload = {}
    if extra_u or missing_u or differing_u:
        u_payload = {}
        if extra_u:
            u_payload['extra'] = extra_u
        if missing_u:
            u_payload['missing'] = missing_u
        if differing_u:
            u_payload['differing'] = differing_u
        diff_payload['users'] = u_payload
        if extra_u:
            reasons.append(f'adds users not in parent: '
                            f'{", ".join(extra_u)}')
        if missing_u:
            reasons.append(f'omits parent users: {", ".join(missing_u)}')
        if differing_u:
            reasons.append(f'differing per-user perms: '
                            f'{", ".join(differing_u)}')
    if extra_t or missing_t or differing_t:
        t_payload = {}
        if extra_t:
            t_payload['extra'] = extra_t
        if missing_t:
            t_payload['missing'] = missing_t
        if differing_t:
            t_payload['differing'] = differing_t
        diff_payload['teams'] = t_payload
        if extra_t:
            reasons.append(f'adds teams not in parent: '
                            f'{", ".join(extra_t)}')
        if missing_t:
            reasons.append(f'omits parent teams: {", ".join(missing_t)}')
        if differing_t:
            reasons.append(f'differing per-team perms: '
                            f'{", ".join(differing_t)}')
    if differing_p:
        diff_payload['permissions'] = differing_p
        reasons.append(f'differing default permissions: '
                        f'{", ".join(differing_p)}')

    return (PROMOTE, chosen,
            '; '.join(reasons) or 'membership or perms differ',
            diff_payload)


def _resolve_parent_sf_uid(subfolder, sf_index):
    """Walk parent_chain to find the enclosing shared_folder UID."""
    direct = subfolder.get('shared_folder_uid', '') or ''
    if direct and direct in sf_index:
        return direct
    for ancestor_uid in subfolder.get('parent_chain') or []:
        if ancestor_uid in sf_index:
            return ancestor_uid
    return ''


def _subfolder_path(subfolder, folder_index):
    parts = [subfolder.get('name', '')]
    for ancestor_uid in subfolder.get('parent_chain') or []:
        ancestor = folder_index.get(ancestor_uid)
        if ancestor is None:
            break
        parts.append(ancestor.get('name', ''))
        if ancestor.get('type') == 'shared_folder':
            break
    return '/'.join(reversed([p for p in parts if p]))


def _normalize_per_folder_rules(per_folder_rules):
    """Return a {uid: action} dict — accepts dict, str path, or None."""
    if per_folder_rules is None:
        return {}
    if isinstance(per_folder_rules, dict):
        return {k: v for k, v in per_folder_rules.items()
                if isinstance(k, str) and isinstance(v, str)}
    if isinstance(per_folder_rules, str) and per_folder_rules:
        if not os.path.isfile(per_folder_rules):
            logging.warning('per-folder-rules path not found: %s — '
                             'ignoring', per_folder_rules)
            return {}
        try:
            with open(per_folder_rules) as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {k: v for k, v in data.items()
                        if isinstance(k, str) and isinstance(v, str)}
        except (OSError, json.JSONDecodeError) as e:
            logging.warning('failed to load per-folder-rules %s: %s',
                             per_folder_rules, e)
    return {}


def classify_inventory(inventory, *, default_action=ACTION_PROMOTE,
                        per_folder_rules=None,
                        default_conflict_resolution=CONFLICT_ERROR,
                        supports_true_nested=None):
    """Return a list of decision dicts + summary for every shared_folder_folder.

    `inventory` is the dict produced by `live_inventory.build_inventory_from_params`
    or `inventory.InventoryAssembler.build`. Missing pieces (no
    vault_folders, no shared_folders) yield an empty result, not an error.
    `default_action` controls the recommendation for divergent subfolders
    (default `promote-to-sibling`). `per_folder_rules` is either a {uid:
    action} dict or a path to a JSON file with that shape.
    `default_conflict_resolution` populates each row's
    `conflict_resolution` field. `supports_true_nested` skips the
    Commander probe when set (tests).
    """
    entities = inventory.get('entities') or {}
    vault_folders = entities.get('vault_folders') or []
    shared_folders = entities.get('shared_folders') or []

    sf_index = _build_sf_index(shared_folders)
    folder_index = {f.get('uid'): f for f in vault_folders if f.get('uid')}
    overrides = _normalize_per_folder_rules(per_folder_rules)
    if supports_true_nested is None:
        supports_true_nested = commander_supports_true_nested_sf()
    if default_conflict_resolution not in ALL_CONFLICT_POLICIES:
        default_conflict_resolution = CONFLICT_ERROR
    if default_action not in ALL_ACTIONS:
        default_action = ACTION_PROMOTE

    decisions = []
    for vf in vault_folders:
        if vf.get('type') != 'shared_folder_folder':
            continue
        sub_uid = vf.get('uid', '')
        sub_name = vf.get('name', '')
        parent_uid = _resolve_parent_sf_uid(vf, sf_index)
        parent_sf = sf_index.get(parent_uid) if parent_uid else None
        cls, action, reason, diff = _classify_subfolder(
            parent_sf, vf,
            default_action=default_action,
            override_action=overrides.get(sub_uid),
            supports_true_nested=supports_true_nested,
        )

        sub_path = _subfolder_path(vf, folder_index)
        if parent_sf:
            parent_name = parent_sf.get('name', '')
            promotion_name = _qualified_name(parent_name, sub_name)
            flatten_name = _flattened_name(parent_name, sub_name)
        else:
            parent_name = ''
            promotion_name = sub_name
            flatten_name = sub_name

        if action == ACTION_PROMOTE:
            proposed_target_name = promotion_name
        elif action == ACTION_FLATTEN:
            proposed_target_name = flatten_name
        elif action == ACTION_TRUE_NESTED:
            proposed_target_name = sub_name
        else:
            proposed_target_name = ''

        decision = {
            'parent_sf_uid': parent_uid,
            'parent_sf_name': parent_name,
            'subfolder_uid': sub_uid,
            'subfolder_name': sub_name,
            'subfolder_path': sub_path,
            'classification': cls,
            'reason': reason,
            'proposed_target_action': action,
            'proposed_promoted_name': proposed_target_name,
            'conflict_resolution': default_conflict_resolution,
        }
        if diff:
            decision['membership_diff'] = diff
        decisions.append(decision)

    summary = {INHERIT: 0, PROMOTE: 0, UNKNOWN: 0}
    action_summary = {a: 0 for a in ALL_ACTIONS}
    for d in decisions:
        summary[d['classification']] = summary.get(d['classification'], 0) + 1
        a = d['proposed_target_action']
        if a in action_summary:
            action_summary[a] += 1

    return {
        'scanned_at': datetime.datetime.utcnow().strftime(
            '%Y-%m-%dT%H:%M:%SZ'),
        'source_tenant': inventory.get('source_root', '')
                          or inventory.get('source_user', ''),
        'scope_node': inventory.get('scope_node', ''),
        'prefix_filter': inventory.get('prefix_filter', ''),
        'default_action': default_action,
        'default_conflict_resolution': default_conflict_resolution,
        'commander_supports_true_nested_sf': bool(supports_true_nested),
        'decisions': decisions,
        'summary': summary,
        'action_summary': action_summary,
    }


def write_plan(plan, output_path):
    """Write the plan JSON + sha256 sidecar (0600). Returns checksum."""
    with open(output_path, 'w') as f:
        json.dump(plan, f, indent=2)
    os.chmod(output_path, 0o600)
    with open(output_path, 'rb') as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    sidecar = output_path + '.sha256'
    with open(sidecar, 'w') as f:
        f.write(checksum + '\n')
    os.chmod(sidecar, 0o600)
    logging.info('Nested-SF plan: %s (sha256: %s)', output_path, checksum)
    return checksum


def load_inventory(inventory_path):
    with open(inventory_path) as f:
        return json.load(f)


def load_plan(plan_path):
    with open(plan_path) as f:
        return json.load(f)


def _normalize_action(action):
    """Translate legacy action names into the 5-option enum."""
    if action == ACTION_PRESERVE_LEGACY:
        return ACTION_PRESERVE
    if action == ACTION_PROMOTE_LEGACY:
        return ACTION_PROMOTE
    return action


def action_lookup(plan):
    """{subfolder_uid: decision_dict_with_normalized_action}.

    Used by `step_vault_folders` to dispatch on a per-subfolder basis.
    Skips rows that lack a UID. Rows without an action default to
    `ACTION_PRESERVE`. Legacy action names are translated.
    """
    out = {}
    for d in plan.get('decisions') or []:
        uid = d.get('subfolder_uid', '')
        if not uid:
            continue
        normalized = dict(d)
        normalized['proposed_target_action'] = _normalize_action(
            d.get('proposed_target_action') or ACTION_PRESERVE)
        out[uid] = normalized
    return out


def promotion_lookup(plan):
    """Backwards-compat: {subfolder_uid: decision_dict} for legacy promote rows.

    Kept for any caller still using the v1.3.0-rc2 API. New consumers
    should use `action_lookup` (full 5-option dispatch).
    """
    out = {}
    for d in plan.get('decisions') or []:
        action = _normalize_action(
            d.get('proposed_target_action') or ACTION_PRESERVE)
        if action == ACTION_PROMOTE:
            uid = d.get('subfolder_uid', '')
            if uid:
                out[uid] = d
    return out


def resolve_name_collision(name, existing_names, *, policy=CONFLICT_ERROR):
    """Apply `policy` to a candidate target name.

    Returns (resolved_name, status) where status ∈
    {`ok`, `suffixed`, `merged`, `error`}. `existing_names` is an
    iterable of names that already exist on target. `error` policy
    raises NO exception — the caller decides whether to fail; the
    materializer translates `error` into a FAILED step record.
    """
    existing = set(existing_names or ())
    if name not in existing:
        return name, 'ok'
    if policy == CONFLICT_MERGE:
        return name, 'merged'
    if policy == CONFLICT_SUFFIX:
        for i in range(2, 1000):
            candidate = f'{name} ({i})'
            if candidate not in existing:
                return candidate, 'suffixed'
        # Out of suffixes — degrade to error.
        return name, 'error'
    return name, 'error'
