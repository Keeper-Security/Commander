"""Enterprise-structure restoration (port of 05b_restore_enterprise_structure.sh).

The 13-step dependency order (each relying on the previous):

  Step 0:  Custom record types (before any record import)
  Step 1:  Nodes (topological sort: parent before child)
  Step 2:  Isolated node flags (after node creation)
  Step 3:  Teams (bare: name + node + restrictions)
  Step 4:  Roles (bare: name + node only, NO enforcements)
  Step 5:  Role managed nodes + privileges
  Step 6:  Role enforcements (4-phase: SIMPLE / account_share / FILE / direct_api)
  Step 7:  Users → node assignments
  Step 8:  Users → team assignments
  Step 9:  Users → role assignments
  Step 10: Teams → role assignments
  Step 11: Shared folder membership (apply-membership)
  Step 12: Validation counts

Steps 0-3 are implemented here; Steps 4-12 will be added in follow-up commits.
The `StructureClient` protocol abstracts every write operation so tests can
drive the restore without hitting a live tenant.
"""

from collections import Counter, OrderedDict
import json
import logging
import os

from .helpers.node_paths import leaf_of, remap_root


# Built-in Keeper role names that must not be clobbered. Source roles matching
# these names get ' (Migrated)' appended on the target.
BUILTIN_ROLE_NAMES = frozenset({
    'Keeper Administrator',
    'Administrator',
    'Admin',
    'Enterprise Admin',
    'Executive',
})
BUILTIN_ROLE_SUFFIX = ' (Migrated)'

# Enforcement types that require file-based value passing (too complex for CLI).
FILE_ENFORCEMENT_KEYS = frozenset({
    'generated_password_complexity',
    'master_password_reentry',
    'two_factor_by_ip',
})

# Enforcements that can lock the tenant administrator out of the target
# tenant if mis-applied during cross-tenant migration. v1.7 default:
# SKIP these on roles in BUILTIN_ROLE_NAMES so a flawed source value
# can't lock the operator out before they can fix it. Opt back in via
# `--apply-admin-lockout-risk-enforcements`. Triggered by:
#  - `require_account_share`: binds login to a target role NAME that
#    may not be migratable (already covered by Bug 47/64/51 + Scope-A
#    verify SKIP; included here for unified handling).
#  - `restrict_ip_addresses`: IP allowlist drift caused the 2026-04-26
#    `jlima+demo2` lockout incident.
#  - `master_password_reentry`: vault-open re-prompt cadence; if mis-
#    set the admin can't open the vault to fix it.
#  - `two_factor_by_ip`: 2FA bypass per CIDR; misalignment can leave
#    admin always 2FA-blocked from any client.
LOCKOUT_RISK_ENFORCEMENTS = frozenset({
    'require_account_share',
    'restrict_ip_addresses',
    'master_password_reentry',
    'two_factor_by_ip',
})


# ─── Pure data-processing helpers (testable without a client) ────────────────


def topological_node_order(nodes, scope_node_name='', target_root='Root'):
    """Return nodes in creation order with parent names resolved.

    Accepts two input shapes (ported inventory + bash enterprise-map dir):
      - node_id/parent_id   (bash enterprise_map_*/nodes.json shape)
      - id/parent (NAME)    (Python plan output, live_inventory.py shape)
    Output: list of (name, parent_name, isolated) tuples, parent-before-child.

    For subtree-scoped migrations, the subtree root is excluded from the
    inventory (its descendants get captured). Direct children of the
    subtree root carry `parent=<scope_node_name>` but the scope root
    itself isn't in `node_map`. We remap those parents to `target_root`
    so the subtree gets reparented under the target tenant root (often
    the same name, but may differ).
    """
    # Normalize into a uniform shape. Prefer the id-based form when available.
    use_ids = any(n.get('node_id') for n in nodes)

    node_map = OrderedDict()
    name_to_id = {}
    # Bug 58 (v1.6) — name-keyed mode collapsed duplicate child names
    # like 'Finance' (one per Subsidiary) into a single entry, so only
    # ONE got created on target and the other 2 were silently dropped.
    # Use the source `id` field as the key when it's present (live
    # inventory captures it on every node), composite-fallback when
    # not. Track name → [ids] separately so parent-by-name lookups
    # still work.
    name_to_nids = {}
    for n in nodes:
        name = n.get('name', '')
        if not name:
            continue
        if use_ids:
            nid = str(n.get('node_id', ''))
            if not nid:
                continue
            parent_id = str(n.get('parent_id', '') or '')
            name_to_id[name] = nid
        else:
            # Bug 58 — prefer source `id` for unique nid; fall back to
            # composite `(name, parent)` when `id` is absent (older
            # inventories, hand-staged plan files).
            src_id = n.get('id')
            if src_id is not None:
                nid = f'id:{src_id}'
            else:
                nid = (name, n.get('parent', '') or '')
            parent_id = n.get('parent', '') or ''
            name_to_nids.setdefault(name, []).append(nid)
        isolated = bool(n.get('isolated', False))
        node_map[nid] = {'name': name, 'parent_id': parent_id, 'isolated': isolated}

    # Name-based inputs may reference parents by name — when we're id-based, the
    # already-normalized parent_id points at real ids, no extra mapping needed.

    visited = set()
    order = []

    def visit(nid):
        if nid in visited or nid not in node_map:
            return
        parent = node_map[nid]['parent_id']
        # Bug 58 — id-mode parent_id is an id (direct lookup); name-
        # mode parent_id is a NAME, so fan-out via name_to_nids to
        # cover the rare case of multiple parents sharing a name. When
        # parent name resolves to multiple nids, visit them all — the
        # `visited` set keeps the output deduplicated.
        if parent:
            if parent in node_map:
                visit(parent)
            else:
                for parent_nid in name_to_nids.get(parent, ()):
                    visit(parent_nid)
        visited.add(nid)
        order.append(nid)

    for nid in list(node_map.keys()):
        visit(nid)

    scope_lower = scope_node_name.lower() if scope_node_name else ''

    # Full-tenant mode only (no scope): identify the source
    # enterprise-root node so we can remap its direct children's parent
    # to target_root. Commander stores the root either with the
    # enterprise name as displayname, or — observed live on 2026-04-20
    # — with a literal displayname='root'. Either way, a top-level
    # child that points at the source root must be reparented to
    # target_root, otherwise `enterprise-node --parent "root"` fails on
    # target because that name doesn't exist there. Scoped mode is
    # handled below via the existing Case 1/2 and does NOT apply here.
    root_nids_full_tenant = set()
    if not scope_lower:
        for nid, node in node_map.items():
            if not (node.get('parent_id') or ''):
                root_nids_full_tenant.add(nid)

    out = []
    for nid in order:
        n = node_map[nid]
        # Bug 58 — name-mode parent_id is a NAME string; resolve via
        # name_to_nids when direct id lookup fails. id-mode keeps the
        # direct path.
        parent_entry = node_map.get(n['parent_id'])
        if parent_entry is None and n['parent_id']:
            parent_nids = name_to_nids.get(n['parent_id'], ())
            if parent_nids:
                parent_entry = node_map.get(parent_nids[0])
        parent_name = parent_entry['name'] if parent_entry else ''

        # Full-tenant root remap: if this node's parent IS the source
        # enterprise root, substitute target_root regardless of what
        # name the source root happens to carry in its data.
        parent_in_roots = (
            n['parent_id'] in root_nids_full_tenant
            or any(pn in root_nids_full_tenant
                   for pn in name_to_nids.get(n['parent_id'], ()))
        )
        if parent_in_roots:
            parent_name = target_root

        if not parent_name:
            orig_parent = (n['parent_id'] or '').lower()
            # Case 1 — this node IS the scope root itself (it appears in
            # the inventory with no parent). Guard: ONLY apply when the
            # node also has no parent_id in the inventory — otherwise a
            # legitimately-named descendant with the same name as the
            # scope root (rare but possible) would get wrongly reparented.
            if (scope_lower and n['name'].lower() == scope_lower
                    and not n['parent_id']):
                parent_name = target_root
            # Case 2 — this node's parent was the scope root, which was
            # excluded from the inventory. Place these children UNDER the
            # scope node on target (which is expected to pre-exist on
            # target — the operator creates the scope-node container
            # before running migration). Preserves source topology under
            # the scope. Bug 16 fix: previously remapped to target_root
            # which silently flattened the subtree (children landed as
            # siblings of the scope node instead of beneath it).
            elif scope_lower and orig_parent == scope_lower:
                parent_name = scope_node_name
            else:
                continue

        # Full-tenant mode: skip the source root itself — it already
        # exists on target as `target_root`; we only reparent its
        # children. (Scoped mode's root handling stays untouched — its
        # scope root goes through Case 1 and IS emitted, so the target
        # can recreate it as a subtree anchor.)
        if nid in root_nids_full_tenant:
            continue

        out.append((n['name'], parent_name, n['isolated']))
    return out


def extract_isolated_nodes(nodes):
    """Return names of nodes whose `isolated` flag is truthy."""
    out = []
    for n in nodes:
        if n.get('isolated') and n.get('name'):
            out.append(n['name'])
    return out


def dedupe_node_names(node_order):
    """Bug 73 — disambiguate duplicate node names by suffixing with the
    parent leaf name. Mirrors `dedupe_team_names` / `dedupe_role_names`.

    `node_order` is the output of `topological_node_order`: a list of
    (name, parent_name, isolated) tuples in creation order.

    Why: Commander's `enterprise-node --add` does tenant-wide name dedup
    (commands/enterprise.py:1147-1161, ignores --parent), so the SECOND
    create call for the same leaf name silently skips. Source topologies
    that legitimately carry e.g. `Finance` under multiple Subsidiary
    parents can't land all duplicates via the CLI. The rename-with-suffix
    pattern that v1.6.0 already uses for teams (Bug 67) and roles makes
    each create-name unique on target, so the CLI can no-op-skip path
    is never triggered.

    Returns:
      - rows: list of dicts {'original_name', 'create_name', 'parent_name',
              'isolated'} in same order as input
      - rename_log: list of (original_name, parent_name, renamed) tuples
              for the rename map persisted to rename_map.json
    """
    name_counts = Counter(name for name, _p, _i in node_order if name)
    duplicates = {n for n, c in name_counts.items() if c > 1}

    rows = []
    rename_log = []
    for name, parent_name, isolated in node_order:
        create_name = name
        if name in duplicates and parent_name:
            suffix = leaf_of(parent_name).strip()
            if suffix:
                create_name = f'{name} ({suffix})'
                rename_log.append((name, parent_name, create_name))
        rows.append({
            'original_name': name,
            'create_name': create_name,
            'parent_name': parent_name,
            'isolated': isolated,
        })
    return rows, rename_log


def restricts_flags(restricts_code):
    """Map Keeper's restricts string (R=edit, W=view, S=share) to on/off triple.

    Returns (restrict_share, restrict_edit, restrict_view) each 'on' or 'off'.
    """
    code = (restricts_code or '').upper()
    return (
        'on' if 'S' in code else 'off',
        'on' if 'R' in code else 'off',
        'on' if 'W' in code else 'off',
    )


def resolve_builtin_role_collision(role_name):
    """Append ' (Migrated)' if the role name collides with a Keeper built-in.

    Prevents overwriting or silently skipping the source role when creating it
    on a tenant that already has the same-named Keeper-defined role.
    """
    if role_name in BUILTIN_ROLE_NAMES:
        return role_name + BUILTIN_ROLE_SUFFIX
    return role_name


def dedupe_role_names(roles, source_root='My company', target_root='Root'):
    """Same dedup strategy as dedupe_team_names, applied to roles.

    Each output row also has `new_user` ('on' if default_role else 'off') and
    resolves built-in role collisions on the final create_name.
    """
    name_counts = Counter(
        r.get('name', '').strip()
        for r in roles
        if r.get('name', '').strip()
    )
    duplicates = {n for n, c in name_counts.items() if c > 1}

    rows = []
    rename_log = []
    for r in roles:
        name = (r.get('name') or '').strip()
        if not name:
            continue
        src_node = (r.get('node') or r.get('node_name') or source_root).strip()
        if src_node == source_root:
            node = target_root
        else:
            node = leaf_of(src_node) if src_node else ''

        create_name = name
        if name in duplicates and node:
            suffix = leaf_of(node).strip()
            if suffix:
                create_name = f'{name} ({suffix})'
                # Bug 61 fix — use RAW src_node (source-side path) not
                # post-remap `node`. validate.py looks up by
                # `role.get('node', '')` which is the source-side
                # value verbatim. Storing post-remap was a silent
                # broken contract: verify never resolved any
                # dedup-renamed role (rehearsal-15 false-positive
                # NOT FOUND on 7+ Departaments-* roles confirmed
                # this).
                rename_log.append((name, src_node, create_name))

        # Built-in collision guard runs LAST — after dedup suffixing so it
        # applies to the final chosen name.
        final_name = resolve_builtin_role_collision(create_name)

        # Bug 78 — when builtin-collision adds the ' (Migrated)' suffix,
        # record the rename so verify's `target_name_for` can pair the
        # source role with the correctly-suffixed target role. Without
        # this, verify pairs source 'Keeper Administrator' against the
        # target tenant's pre-existing built-in role of the same name
        # and reports false-positive divergence on every enforcement /
        # privilege / managed_node check (rehearsal-15 surfaced this
        # as the apparent password_complexity multi-domain truncation —
        # actually the migrated copy `Keeper Administrator (Migrated)`
        # had both elements preserved correctly).
        # Key is raw source-side `src_node` (matches validate.py's
        # `role.get('node', '')` lookup); the existing dedup branch
        # above stores post-remap `node` for legacy reasons (separate
        # Bug 61 lookup-key mismatch, not addressed here).
        if final_name != create_name:
            rename_log.append((name, src_node, final_name))

        rows.append({
            'original_name': name,
            'create_name': final_name,
            'node': node,
            # Post-1.1.1 inventory carries `new_user`; older inventory
            # rows only had `default_role`. Accept either.
            'new_user': 'on' if (r.get('new_user') or r.get('default_role')) else 'off',
        })
    return rows, rename_log


_CROSS_TENANT_ID_ENFORCEMENTS = frozenset({
    # Bug 17 — `require_account_share` value is the role's own ID,
    # which is server-assigned and therefore always differs between
    # source and target tenants. A naive resume comparison
    # (`str(target_value) != str(source_value)`) always reports
    # "different" and triggers a re-issue. Commander then rejects the
    # re-issue with "cannot update enforcement" because the value
    # references the role id directly. Treat these keys as
    # already-applied whenever target has ANY non-empty value — the
    # original migration set them correctly; re-issue is wrong on
    # resume by design.
    'require_account_share',
})


def _is_record_types_key(key):
    """True when this enforcement key is typed `record_types` in
    Commander's ENFORCEMENTS dict. The value carries record-type IDs
    that need translation to names before the CLI parser can accept
    it. Falls back to False (skip translation) when the constants
    can't be imported."""
    try:
        from keepercommander.constants import ENFORCEMENTS
    except ImportError:
        return False
    return ENFORCEMENTS.get((key or '').lower()) == 'record_types'


def _enforcement_already_applied(key, source_value, target_enfs):
    """Compare source enforcement value to target value, accounting
    for keys whose values are inherently cross-tenant (role IDs etc.).

    Returns True when the resume gate should treat the pair as
    already-applied (skip the re-issue), False otherwise.
    """
    target_value = target_enfs.get(key, '')
    if key in _CROSS_TENANT_ID_ENFORCEMENTS:
        # Any non-empty target value means the original migration
        # applied this enforcement. Don't re-issue with the source-
        # side ID — it can never match cross-tenant.
        return bool(target_value)
    return str(target_value) == str(source_value)


def find_schema_violations(roles_complete):
    """Return a list of (role_name, reason) for roles whose shape violates
    Keeper's server-side schema rules.

    Currently catches Bug 13 — a role cannot carry both `managed_nodes`
    (admin role) and `teams`. Server-side rejection is masked by misleading
    error messages ("lack required privilege", "no objects provided"), so
    a pre-flight catches the impossible combination before issuing API
    calls and surfaces the actual constraint.

    Real source data from Keeper's tenants never produces this combo —
    the server enforces it on writes. A non-empty return from this
    function indicates corrupt / hand-edited inventory.
    """
    violations = []
    for r in roles_complete or []:
        name = (r.get('name') or '').strip()
        if not name:
            continue
        managed = r.get('managed_nodes') or []
        teams = r.get('teams') or []
        if managed and teams:
            violations.append(
                (name, f'has managed_nodes ({len(managed)}) AND teams '
                       f'({len(teams)}); admin and team membership are '
                       'mutually exclusive on a Keeper role')
            )
    return violations


def plan_managed_nodes(roles, source_root='My company', target_root='Root',
                        role_rename_lookup=None,
                        node_rename_lookup=None):
    """Emit a list of (role_name, target_node, cascade, [privileges]) tuples.

    `roles` must be the "complete" form from enterprise-role ROLE --format json,
    including managed_nodes[] with node_name/cascade/privileges.

    Bug 67 (rehearsal-11/12) — when `role_rename_lookup` is supplied
    ({(orig_name, remapped_target_node) → renamed}), use the renamed
    target name so callers' `role_name in created_roles` checks
    resolve. Bug 67 v2 (rehearsal-12) — the lookup key uses the
    POST-REMAP target node (dedupe_role_names: `My company` →
    target_root, nested paths → leaf_of). Match that here so the
    rename resolves.

    Bug 80 (v1.7) — when `node_rename_lookup` is supplied, resolve
    each managed_node binding through it BEFORE the source-root
    remap. Lookup shape:
        {(source_node_id, source_parent_path) → renamed_target_name}
    This is the disambiguating fix for the case where source has
    multiple sibling nodes with the same leaf name (e.g. three
    `Finance` nodes under different `Subsidiary` parents). Pre-Bug-80
    captures don't carry `source_node_id`/`source_parent_path` on
    each managed_node entry — for those, the lookup falls through to
    the prior name-only behavior (backwards-compatible).
    """
    rename = role_rename_lookup or {}
    node_rename = node_rename_lookup or {}
    out = []
    for r in roles:
        name = (r.get('name') or '').strip()
        if not name:
            continue
        src_node = (r.get('node') or r.get('node_name') or source_root).strip()
        if src_node == source_root:
            remapped_node = target_root
        else:
            remapped_node = leaf_of(src_node) if src_node else ''
        renamed = rename.get((name, remapped_node))
        if renamed:
            effective_role_name = renamed
        else:
            effective_role_name = resolve_builtin_role_collision(name)
        for mn in r.get('managed_nodes', []) or []:
            mn_node = (mn.get('node_name') or '').strip()
            # Bug 80 — when the captured managed_node entry carries
            # disambiguation context, prefer it over name-only
            # remapping. The lookup key is the SOURCE node's
            # identity (id + parent path) which uniquely points at
            # one source node even when its name has duplicates.
            mn_src_id = (mn.get('source_node_id') or '').strip()
            mn_src_path = (mn.get('source_parent_path') or '').strip()
            disambig_target = None
            if mn_src_id or mn_src_path:
                disambig_target = node_rename.get((mn_src_id, mn_src_path))
            if disambig_target:
                node = disambig_target
            else:
                node = remap_root(mn_node, source_root, target_root) if mn_node else ''
            if not node:
                continue
            cascade = 'on' if mn.get('cascade', False) else 'off'
            privs = [p for p in (mn.get('privileges') or []) if p]
            out.append((effective_role_name, node, cascade, privs))
    return out


def classify_enforcement(role_name, key, value, id_to_name,
                          source_role_meta=None,
                          apply_admin_lockout_risk_enforcements=False):
    """Return a dict describing how to apply one enforcement to one role.

    Shape: {'phase': 'SIMPLE'|'ACCOUNT_SHARE'|'FILE'|'SKIP', ...}

    'SIMPLE'        → pass as `key:value` to --enforcement
    'ACCOUNT_SHARE' → require_account_share; value is the resolved role NAME
    'FILE'          → key's value is JSON; caller writes to a file and passes $FILE=path
    'SKIP'          → unresolvable (e.g. role_id missing from map)

    `source_role_meta` (optional): {role_name: {'has_transfer_account': bool}}.
    When supplied, enables Bug 64 (Upstream-3 reclassified) pre-flight:
    require_account_share on roles without TRANSFER_ACCOUNT is invalid
    source config; target rejects it server-side. Pre-flight SKIP
    avoids the wasted API call and gives operators a clearer reason.

    `apply_admin_lockout_risk_enforcements` (v1.7 default False): when
    False, SKIP every key in `LOCKOUT_RISK_ENFORCEMENTS` for roles in
    `BUILTIN_ROLE_NAMES`. The 2026-04-26 `jlima+demo2` lockout incident
    proved these enforcements can lock the operator out of the target
    if cross-tenant drift mis-applies them. Operators can opt back in
    after they've audited the values for target-tenant compatibility.
    """
    # v1.7 — lockout-risk default-skip on builtin-admin roles. Match
    # against the bare name (strip BUILTIN_ROLE_SUFFIX) so a Migrated-
    # suffixed builtin still trips the guard.
    if (key in LOCKOUT_RISK_ENFORCEMENTS
            and not apply_admin_lockout_risk_enforcements):
        bare_name = role_name.replace(BUILTIN_ROLE_SUFFIX, '')
        if bare_name in BUILTIN_ROLE_NAMES:
            return {'phase': 'SKIP',
                    'reason': (f'lockout-risk enforcement {key!r} on '
                               f'builtin-admin role {bare_name!r}; '
                               'default-skip to prevent admin lockout. '
                               'Opt in via '
                               '--apply-admin-lockout-risk-enforcements '
                               'after auditing the source value for '
                               'target-tenant compatibility.'),
                    'role': role_name, 'key': key, 'value': value}
    # FILE-based first (value shape: dict/list/str)
    if key in FILE_ENFORCEMENT_KEYS:
        if not value:
            return {'phase': 'SKIP', 'reason': 'empty value'}
        body = value if isinstance(value, str) else json.dumps(value)
        return {'phase': 'FILE', 'role': role_name, 'key': key, 'body': body}

    # require_account_share resolves role_id → role NAME
    if key == 'require_account_share':
        # Bug 64 (v1.6, Upstream-3 reclassified) — source has invalid
        # config: require_account_share on a role that doesn't itself
        # carry TRANSFER_ACCOUNT. Target's stricter validation rejects
        # with generic 'bad_inputs_enforcement'. Pre-flight SKIP with
        # a clearer operator-facing reason. Source-side data-quality
        # issue, not target environment — only fixable on source by
        # the operator.
        if source_role_meta is not None:
            meta = source_role_meta.get(role_name) or source_role_meta.get(
                role_name.replace(BUILTIN_ROLE_SUFFIX, '')) or {}
            if not meta.get('has_transfer_account', False):
                return {'phase': 'SKIP',
                        'reason': ('source role lacks TRANSFER_ACCOUNT '
                                   'privilege — require_account_share '
                                   'enforcement is invalid for non-admin '
                                   'roles. Source data-quality issue '
                                   '(Bug 64, ex-Upstream-3); fix by '
                                   'either granting TRANSFER_ACCOUNT '
                                   'on source or removing the enforcement '
                                   'from the role on source'),
                        'role': role_name, 'key': key, 'value': value}
        resolved = id_to_name.get(str(value), '')
        if not resolved:
            return {'phase': 'SKIP', 'reason': 'unresolved role_id',
                    'role': role_name, 'key': key, 'value': value}
        target_value_name = resolved_builtin_role_collision_if_needed(resolved)
        # Bug 47 — self-reference: when the resolved target name
        # equals the role being written to, the role requires account-
        # share through itself. Commander rejects with a generic
        # "cannot update enforcement" envelope (Upstream-1) and no
        # value-format encoding recovers. Bug 17's resume-only gate
        # doesn't fire on fresh runs, so without this guard the call
        # goes out and fails. Skip cleanly — self-reference carries
        # no useful migration semantics cross-tenant.
        if target_value_name == role_name:
            return {'phase': 'SKIP',
                    'reason': 'self-reference (role requires account '
                              'share through itself); cannot apply '
                              'cross-tenant',
                    'role': role_name, 'key': key,
                    'value': target_value_name}
        return {'phase': 'ACCOUNT_SHARE', 'role': role_name, 'key': key,
                'value': target_value_name}

    # Everything else: SIMPLE (booleans as lowercase strings; ints as strings)
    if isinstance(value, bool):
        v = 'true' if value else 'false'
    elif isinstance(value, int):
        v = str(value)
    else:
        v = value
    return {'phase': 'SIMPLE', 'role': role_name, 'key': key, 'value': v}


# Small alias used inside classify_enforcement to keep the call-site clean.
def resolved_builtin_role_collision_if_needed(name):
    return resolve_builtin_role_collision(name)


def build_id_to_role_name(roles):
    """Map source role_id → source role_name for require_account_share lookup."""
    out = {}
    for r in roles:
        rid = str(r.get('role_id', '') or r.get('id', ''))
        name = r.get('name', '')
        if rid and name:
            out[rid] = name
    return out


def build_source_role_meta(roles):
    # Bug 64 — index source role privilege metadata by name (and the
    # builtin-collision-suffixed name so post-rename lookups work).
    # Currently captures `has_transfer_account` to gate
    # require_account_share at classify time. Mirrors Commander's
    # SDK-side check in commands/enterprise.py:2556.
    out = {}
    for r in roles or []:
        name = (r.get('name') or '').strip()
        if not name:
            continue
        privs = []
        for mn in r.get('managed_nodes', []) or []:
            for p in mn.get('privileges', []) or []:
                privs.append((p or '').lower())
        meta = {'has_transfer_account': 'transfer_account' in privs}
        out[name] = meta
        # Builtin-collision aware: classify sees the SUFFIX'd target
        # name; map both spellings to the same metadata.
        suffixed = resolve_builtin_role_collision(name)
        if suffixed != name:
            out[suffixed] = meta
    return out


def target_node_for_user(src_node, source_root, target_root):
    """Return the target-side leaf node name the user should be assigned to, or
    empty string if the user sits on either root (no explicit assignment needed).

    Bash reference maps source-root users to target_root then immediately skips
    them — same net effect as returning '' here.
    """
    if not src_node or src_node == source_root:
        return ''
    leaf = leaf_of(src_node)
    if leaf in (source_root, target_root):
        return ''
    return leaf


def plan_user_node_assignments(users, source_root, target_root):
    """Yield (email, target_node_leaf) pairs, skipping users on the root."""
    for u in users:
        email = (u.get('email') or '').strip()
        src_node = (u.get('node') or '').strip()
        node = target_node_for_user(src_node, source_root, target_root)
        if email and node:
            yield email, node


def plan_user_team_assignments(users):
    """Yield (email, team_name) for every user-team membership in the source."""
    for u in users:
        email = (u.get('email') or '').strip()
        if not email:
            continue
        for team in u.get('teams') or []:
            team_name = team.strip() if isinstance(team, str) else ''
            if team_name:
                yield email, team_name


def plan_role_user_assignments(roles_complete, role_rename_lookup=None):
    """Yield (role_name, email) for every user-role membership in roles_complete.

    Role name is run through the built-in collision resolver so assignments
    land on the actual target-side role name.

    Bug 83 (v1.7.2) — when `role_rename_lookup` is supplied, also
    resolve dedup-renamed roles. Lookup key is `(source_role_name,
    source_role_node)` matching `self.role_rename_log` shape after
    Bug 61 fix. Without this resolution, dedup-renamed roles get
    every user assignment SKIPped at structure write time
    ('target role never created — call suppressed') because the
    source name doesn't match `created_roles`.
    """
    role_rename_lookup = role_rename_lookup or {}
    for r in roles_complete:
        role_name = (r.get('name') or '').strip()
        if not role_name:
            continue
        src_node = (r.get('node') or '').strip()
        # First check dedup rename (source-side disambiguation), then
        # builtin-collision (post-dedup `(Migrated)` suffix). Order
        # matches `dedupe_role_names`.
        target_role = role_rename_lookup.get(
            (role_name, src_node), role_name)
        target_role = resolve_builtin_role_collision(target_role)
        for u in r.get('users') or []:
            email = (u.get('username') or u.get('email') or '').strip()
            if email:
                yield target_role, email


def plan_role_team_assignments(roles_complete,
                                role_rename_lookup=None,
                                team_rename_lookup_by_name=None):
    """Yield (role_name, team_name, is_admin_role) per role-team membership.

    Admin roles (those with any managed_nodes) reject team assignments per
    Keeper's enterprise_common.py:172 — caller should SKIP those.

    Bug 83 (v1.7.2) — `role_rename_lookup` keyed by
    `(source_role_name, source_role_node)` resolves dedup-renamed
    source roles to their target-side names.
    `team_rename_lookup_by_name` is `{source_team_name:
    [renamed_target_team_names]}` because source role.teams carries
    only team names (not nodes), so multiple source teams with the
    same name (each at a different source node, dedup-renamed
    differently on target) all map under the same key. The caller
    should attempt each renamed candidate and let Commander reject
    those that don't apply for the role's scope. When a team isn't
    in the lookup, pass through the source name (un-renamed teams).
    """
    role_rename_lookup = role_rename_lookup or {}
    team_rename_lookup_by_name = team_rename_lookup_by_name or {}
    for r in roles_complete:
        role_name = (r.get('name') or '').strip()
        if not role_name:
            continue
        src_node = (r.get('node') or '').strip()
        target_role = role_rename_lookup.get(
            (role_name, src_node), role_name)
        target_role = resolve_builtin_role_collision(target_role)
        is_admin = bool(r.get('managed_nodes'))
        for t in r.get('teams') or []:
            # `live_inventory` emits role.teams as a list of plain
            # team-name strings; an older / alternative producer
            # (assemble-inventory etc.) emits a list of dicts with
            # `team_name` or `name` keys. Handle both.
            if isinstance(t, dict):
                team_name = (t.get('team_name') or t.get('name') or '').strip()
            elif isinstance(t, str):
                team_name = t.strip()
            else:
                team_name = ''
            if not team_name:
                continue
            # Resolve renamed teams. Multiple targets when source had
            # duplicate-name teams at different nodes; emit one
            # tuple per candidate so the caller can attempt each.
            candidates = team_rename_lookup_by_name.get(team_name)
            if candidates:
                for renamed in candidates:
                    yield target_role, renamed, is_admin
            else:
                yield target_role, team_name, is_admin


def dedupe_team_names(teams, source_root='My company', target_root='Root'):
    """Resolve duplicate team names by suffixing with the leaf node name.

    Returns a list of dicts:
        {
            'original_name': str,
            'create_name': str,     # name to pass to --add
            'node': str,            # remapped node (leaf-of, except source-root)
            'restrict_share': 'on'|'off',
            'restrict_edit':  'on'|'off',
            'restrict_view':  'on'|'off',
        }
    plus a list of (original, node, renamed) tuples for the rename map file.
    """
    name_counts = Counter(
        t.get('name', '').strip()
        for t in teams
        if t.get('name', '').strip()
    )
    duplicates = {n for n, c in name_counts.items() if c > 1}

    rows = []
    rename_log = []
    for t in teams:
        name = t.get('name', '').strip()
        if not name:
            continue
        src_node = (t.get('node') or t.get('node_name') or '').strip()
        if src_node == source_root:
            node = target_root
        else:
            node = leaf_of(src_node) if src_node else ''

        create_name = name
        if name in duplicates and node:
            suffix = leaf_of(node).strip()
            if suffix:
                create_name = f'{name} ({suffix})'
                # Bug 61 fix — use RAW src_node (source-side path) not
                # post-remap `node`. validate.py looks up by
                # `team.get('node', '')` which is the source-side
                # value verbatim. Storing post-remap was a silent
                # broken contract: verify never resolved any
                # dedup-renamed team.
                rename_log.append((name, src_node, create_name))

        rs, re_, rv = restricts_flags(t.get('restricts', ''))
        rows.append({
            'original_name': name,
            'create_name': create_name,
            'node': node,
            'restrict_share': rs,
            'restrict_edit': re_,
            'restrict_view': rv,
        })
    return rows, rename_log


# ─── Client abstraction: every target-side write goes through this ──────────


class StructureClient:
    """Protocol for writes to the target tenant. Implementations: Commander SDK,
    subprocess wrapper, or an in-memory fake for tests.

    All methods return True on success, False on any failure (the caller decides
    whether the failure is fatal or just a SKIPPED/already-exists notice).
    """

    def load_record_types(self, path):
        raise NotImplementedError

    def create_node(self, name, parent_name):
        raise NotImplementedError

    def toggle_node_isolated(self, name):
        raise NotImplementedError

    def create_team(self, name, node, restrict_share, restrict_edit, restrict_view):
        raise NotImplementedError

    def create_role(self, name, node, new_user):
        raise NotImplementedError

    def add_role_managed_node(self, role_name, node_name, cascade):
        raise NotImplementedError

    def add_role_privilege(self, role_name, privilege, node_name):
        raise NotImplementedError

    def set_role_enforcement_simple(self, role_name, key, value):
        raise NotImplementedError

    def set_role_enforcements_simple_batch(self, role_name, pairs):
        """Set multiple SIMPLE-phase enforcements in ONE API call.

        `pairs` = iterable of (key, value) tuples.

        Returns True when the underlying call succeeded (the whole
        batch was accepted; per-key skips are logged by Commander
        and captured by SilentFailureCapture but don't fail the call
        because Commander's parser uses `continue` on bad values).

        The default implementation iterates (for backends that don't
        support batching). Commander implementations override with a
        single _call passing the full list.
        """
        if not pairs:
            return True
        ok_all = True
        for key, value in pairs:
            if not self.set_role_enforcement_simple(role_name, key, value):
                ok_all = False
        return ok_all

    def set_role_enforcement_file(self, role_name, key, file_path):
        raise NotImplementedError

    def assign_user_to_node(self, email, node_name):
        raise NotImplementedError

    def add_user_to_team(self, email, team_name):
        raise NotImplementedError

    def add_user_to_role(self, role_name, email):
        raise NotImplementedError

    def add_team_to_role(self, role_name, team_name):
        raise NotImplementedError

    def apply_membership(self, path):
        raise NotImplementedError

    def add_user_folder(self, name, parent_uid=''):
        """Create a vault-side user_folder under `parent_uid` (empty = at
        vault root). Returns the new folder UID on success, '' on
        failure. idempotent when a user_folder of the same name already
        exists under the same parent — returns existing UID instead.
        """
        raise NotImplementedError

    def add_shared_folder(self, name, parent_uid='', *,
                           default_manage_users=False,
                           default_manage_records=False,
                           default_can_edit=False,
                           default_can_share=False):
        """Create a vault-side shared_folder under `parent_uid` (empty =
        at vault root). Returns the new SF UID on success, '' on failure.
        default_* flags configure the SF's default permissions for
        records + members added later. Idempotent as with add_user_folder.
        """
        raise NotImplementedError

    def add_subfolder(self, name, parent_sf_folder_uid):
        """Create a shared_folder_folder inside a shared_folder (or
        another shared_folder_folder). Returns the new subfolder UID on
        success, '' on failure. parent_sf_folder_uid must be a
        shared_folder or shared_folder_folder UID on target."""
        raise NotImplementedError

    def count_nodes(self, scope_node=''):
        raise NotImplementedError

    def count_teams(self, scope_node=''):
        raise NotImplementedError

    def count_roles(self, scope_node=''):
        raise NotImplementedError

    def count_users(self, scope_node=''):
        raise NotImplementedError

    # ── Projections (resume-after-crash, G7) ────────────────────────
    # Each projection returns a snapshot of the relevant target-side
    # entity so a `--resume` run can pre-filter its source inputs to the
    # delta. Defaults return empty (the 2026-04-22 design doc's "additive
    # only" rule — when target has nothing, resume is identical to a
    # cold run). Live Commander backends override.

    def list_node_names(self, scope_node=''):
        """Return a set of node names already on target, optionally
        scoped to a subtree. Used by `step_nodes` resume."""
        return set()

    def list_team_names(self, scope_node=''):
        """Return a set of team names already on target."""
        return set()

    def list_role_names(self, scope_node=''):
        """Return a set of role names already on target."""
        return set()

    def list_isolated_node_names(self, scope_node=''):
        """Return a set of nodes whose isolated flag is currently set."""
        return set()

    def list_role_managed_nodes(self, role_name):
        """Return a set of (node_name, cascade) tuples currently
        managed by `role_name` on target."""
        return set()

    def list_role_privileges(self, role_name):
        """Return a set of (privilege, node_name) tuples currently
        granted to `role_name` on target."""
        return set()

    def list_role_enforcements(self, role_name):
        """Return a dict {key: value} of enforcements set on the
        target-side role. Empty dict when the role is absent."""
        return {}

    def list_user_node_assignments(self):
        """Return a dict {email_lower: target_node_leaf} for users
        currently assigned to a non-root node."""
        return {}

    def list_user_team_memberships(self):
        """Return a dict {email_lower: set(team_names)} of current
        team memberships on target."""
        return {}

    def list_role_user_memberships(self):
        """Return a dict {role_name: set(emails_lower)} of users
        currently assigned to each role on target."""
        return {}

    def list_role_team_memberships(self):
        """Return a dict {role_name: set(team_names)} of teams
        currently assigned to each role on target."""
        return {}

    def list_shared_folder_names(self):
        """Return a set of vault-side shared_folder names currently
        present in the session (vault root + children)."""
        return set()

    def find_folder_uid(self, name, parent_uid):
        """Return the existing folder UID for a folder of `name`
        directly under `parent_uid` (or '' for vault root). Empty
        string when no such folder exists. Used by `step_vault_folders`
        on resume to recover the source→target uid_map for folders
        already created before the crash."""
        return ''


class FakeClient(StructureClient):
    """In-memory client used by tests to assert sequence of operations.

    Resume-aware projection state lives in `existing_*` attributes —
    tests pre-populate these to simulate target-side state at the
    moment of a `--resume` invocation. Empty defaults match the
    cold-start case (target has nothing) so all pre-resume tests
    stay green without modification.
    """

    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on or set()
        # Resume projections — tests pre-seed to simulate "target had
        # this entity before --resume ran". Empty by default.
        self.existing_nodes = set()
        self.existing_isolated_nodes = set()
        self.existing_teams = set()
        self.existing_roles = set()
        self.existing_managed_nodes = {}
        self.existing_role_privileges = {}
        self.existing_role_enforcements = {}
        self.existing_user_nodes = {}
        self.existing_user_teams = {}
        self.existing_role_users = {}
        self.existing_role_teams = {}
        self.existing_shared_folders = set()

    def _record(self, op, args):
        self.calls.append((op, args))
        return op not in self.fail_on

    def load_record_types(self, path):
        return self._record('load_record_types', (path,))

    def create_node(self, name, parent_name):
        return self._record('create_node', (name, parent_name))

    def toggle_node_isolated(self, name):
        return self._record('toggle_node_isolated', (name,))

    def create_team(self, name, node, restrict_share, restrict_edit, restrict_view):
        return self._record('create_team', (name, node, restrict_share,
                                            restrict_edit, restrict_view))

    def create_role(self, name, node, new_user):
        return self._record('create_role', (name, node, new_user))

    def add_role_managed_node(self, role_name, node_name, cascade):
        return self._record('add_role_managed_node', (role_name, node_name, cascade))

    def add_role_privilege(self, role_name, privilege, node_name):
        return self._record('add_role_privilege', (role_name, privilege, node_name))

    def set_role_enforcement_simple(self, role_name, key, value):
        return self._record('set_role_enforcement_simple', (role_name, key, value))

    def set_role_enforcements_simple_batch(self, role_name, pairs):
        return self._record('set_role_enforcements_simple_batch',
                             (role_name, tuple(pairs)))

    def set_role_enforcement_file(self, role_name, key, file_path):
        return self._record('set_role_enforcement_file', (role_name, key, file_path))

    def assign_user_to_node(self, email, node_name):
        return self._record('assign_user_to_node', (email, node_name))

    def add_user_to_team(self, email, team_name):
        return self._record('add_user_to_team', (email, team_name))

    def add_user_to_role(self, role_name, email):
        return self._record('add_user_to_role', (role_name, email))

    def add_team_to_role(self, role_name, team_name):
        return self._record('add_team_to_role', (role_name, team_name))

    def apply_membership(self, path):
        return self._record('apply_membership', (path,))

    def add_user_folder(self, name, parent_uid=''):
        if 'add_user_folder' in self.fail_on:
            self.calls.append(('add_user_folder', (name, parent_uid)))
            return ''
        # Synthesize a deterministic UID from name + parent for test
        # assertion predictability. Real impl returns Commander's UID.
        new_uid = f'uf-{name}-{parent_uid or "root"}'
        self.calls.append(('add_user_folder', (name, parent_uid, new_uid)))
        return new_uid

    def add_shared_folder(self, name, parent_uid='', *,
                           default_manage_users=False,
                           default_manage_records=False,
                           default_can_edit=False,
                           default_can_share=False):
        if 'add_shared_folder' in self.fail_on:
            self.calls.append(('add_shared_folder', (name, parent_uid)))
            return ''
        new_uid = f'sf-{name}-{parent_uid or "root"}'
        self.calls.append(('add_shared_folder', (
            name, parent_uid, new_uid,
            default_manage_users, default_manage_records,
            default_can_edit, default_can_share,
        )))
        return new_uid

    def add_subfolder(self, name, parent_sf_folder_uid):
        if 'add_subfolder' in self.fail_on:
            self.calls.append(('add_subfolder', (name, parent_sf_folder_uid)))
            return ''
        new_uid = f'sff-{name}-{parent_sf_folder_uid}'
        self.calls.append(('add_subfolder',
                            (name, parent_sf_folder_uid, new_uid)))
        return new_uid

    def count_nodes(self, scope_node=''):
        return len(self.calls)  # tests override if they care

    def count_teams(self, scope_node=''):
        return 0

    def count_roles(self, scope_node=''):
        return 0

    def count_users(self, scope_node=''):
        return 0

    # ── Projection overrides ──────────────────────────────────────
    def list_node_names(self, scope_node=''):
        return set(self.existing_nodes)

    def list_team_names(self, scope_node=''):
        return set(self.existing_teams)

    def list_role_names(self, scope_node=''):
        return set(self.existing_roles)

    def list_isolated_node_names(self, scope_node=''):
        return set(self.existing_isolated_nodes)

    def list_role_managed_nodes(self, role_name):
        return set(self.existing_managed_nodes.get(role_name, set()))

    def list_role_privileges(self, role_name):
        return set(self.existing_role_privileges.get(role_name, set()))

    def list_role_enforcements(self, role_name):
        return dict(self.existing_role_enforcements.get(role_name, {}))

    def list_user_node_assignments(self):
        return dict(self.existing_user_nodes)

    def list_user_team_memberships(self):
        return {k: set(v) for k, v in self.existing_user_teams.items()}

    def list_role_user_memberships(self):
        return {k: set(v) for k, v in self.existing_role_users.items()}

    def list_role_team_memberships(self):
        return {k: set(v) for k, v in self.existing_role_teams.items()}

    def list_shared_folder_names(self):
        return set(self.existing_shared_folders)

    def find_folder_uid(self, name, parent_uid):
        # `existing_folder_uids` is a {(name, parent_uid): uid} dict
        # tests pre-seed when exercising step_vault_folders resume.
        if not hasattr(self, 'existing_folder_uids'):
            return ''
        return self.existing_folder_uids.get((name, parent_uid or ''), '')


# ─── Restore driver ──────────────────────────────────────────────────────────


class StepResult:
    SUCCESS = 'SUCCESS'
    SKIPPED = 'SKIPPED'
    FAILED = 'FAILED'

    __slots__ = ('category', 'name', 'action', 'status', 'notes')

    def __init__(self, category, name, action, status, notes=''):
        self.category = category
        self.name = name
        self.action = action
        self.status = status
        self.notes = notes

    def as_row(self):
        return [self.category, self.name, self.action, self.status, self.notes]


class StructureRestore:
    """Drive the 13-step structure restore against a `StructureClient`.

    Takes pre-loaded plan data (dicts/lists from the inventory or enterprise map)
    so it can be exercised in tests without touching disk.
    """

    def __init__(self, client, *, source_root='My company', target_root='Root',
                 scope_node='', delay=0.0, jitter=0.0,
                 reserve_quota_every=0, reserve_quota_seconds=2.0,
                 resume=False, preserve_duplicate_node_names=False,
                 apply_admin_lockout_risk_enforcements=False):
        self.client = client
        self.source_root = source_root
        self.target_root = target_root
        self.scope_node = scope_node
        self.results = []
        self.counters = {'SUCCESS': 0, 'SKIPPED': 0, 'FAILED': 0}
        # Bug 73 — opt-in: when True, skip the node rename-with-suffix
        # disambiguation and pass duplicate names straight through to
        # `client.create_node` (the bypass in
        # `commander_clients.CommanderStructureClient.create_node`
        # will then submit `node_add` directly and rely on the server
        # accepting duplicate displaynames under distinct parents). The
        # default (False) keeps target names unique by suffixing with
        # the parent leaf, mirroring the team/role rename pattern.
        self.preserve_duplicate_node_names = bool(preserve_duplicate_node_names)
        # v1.7 — opt-in to apply lockout-risk enforcements
        # (`require_account_share`, `restrict_ip_addresses`,
        # `master_password_reentry`, `two_factor_by_ip`) on
        # BUILTIN_ROLE_NAMES roles. Default False keeps the operator
        # safe from cross-tenant drift causing target-tenant lockout
        # (2026-04-26 `jlima+demo2` incident). When True, restores
        # pre-v1.7 behavior.
        self.apply_admin_lockout_risk_enforcements = bool(
            apply_admin_lockout_risk_enforcements)
        # G7 — Resume after mid-stage crash.
        # When `resume=True`, every step queries the target tenant's
        # current state once at entry and pre-filters its source rows
        # to only the delta. Default off — pre-G7 callers see no
        # behavior change without explicitly passing the flag.
        self.resume = bool(resume)
        # When resume is on, count of skipped-already-present per
        # step is captured so an idempotent re-run reports 0 work.
        self.resume_skipped = 0
        self.resume_reconciled = 0
        # Throttle management across step loops.
        #
        # delay: floor sleep between per-entity API calls. ~2-3s on
        #   full-tenant restores; 0 disables.
        # jitter: add random.uniform(0, jitter) to each sleep so we
        #   desync from Commander's 30s throttle-backoff wave.
        # reserve_quota_every: every N calls, insert a longer pause
        #   (reserve_quota_seconds) so the admin's browser session can
        #   reclaim rate-limit quota and stay usable during the migration.
        #   0 disables.
        self._delay = max(float(delay or 0.0), 0.0)
        self._jitter = max(float(jitter or 0.0), 0.0)
        self._reserve_every = max(int(reserve_quota_every or 0), 0)
        self._reserve_seconds = max(float(reserve_quota_seconds or 0.0), 0.0)
        self._call_counter = 0
        # Injectable for tests — default to real time.sleep.
        import time as _time
        self._sleep = _time.sleep
        # Track entities that successfully landed on target so downstream
        # steps can skip work against entities that never got created
        # (avoids the 2026-04-20 'Role X is not found: Skipping' cascade
        # where step_enforcements + step_managed_nodes looped over every
        # failed role and produced dozens of log lines per missing
        # entity). Populated by step_nodes / step_teams / step_roles.
        self.created_nodes = set()
        self.created_teams = set()
        self.created_roles = set()
        # Rename logs captured by step_teams / step_roles. Each is a
        # list[(original_name, source_node, renamed_name)] from
        # `dedupe_team_names` / `dedupe_role_names`. Always populated,
        # even when there are no actual renames (empty list). Exposed
        # so commands.py can include the data in the structure audit
        # event — previously the return values from step_teams /
        # step_roles were silently dropped.
        self.team_rename_log = []
        self.role_rename_log = []
        self.node_rename_log = []

    def _last_error(self):
        """Retrieve Commander's last error text (if the backing client
        exposes it) so per-entity FAILED notes carry a real reason
        instead of the stock 'may already exist'."""
        # Only CommanderStructureClient wires the module-level stash.
        # FakeClient tests + other impls return '' and notes stay terse.
        try:
            from . import commander_clients
            return commander_clients.get_last_call_error()
        except Exception:                               # noqa: BLE001
            return ''

    def _failed_notes(self, base_notes):
        """Compose a FAILED StepResult.notes value that includes
        Commander's actual error message when available, falling back
        to the passed base_notes ('may already exist'-style) when the
        client didn't surface anything."""
        err = (self._last_error() or '').strip()
        return f'{base_notes} [err: {err}]' if err else base_notes

    # ── Cross-tenant tolerance ────────────────────────────────────
    # Error substrings that indicate the call failed because the
    # source-side entity has a shape the target can't accept (privilege
    # deprecation, MSP-only privilege, enforcement key retired). These
    # are NOT bugs — they're semantic divergence between tenant
    # generations / types. We SKIP with a loud note instead of
    # FAILing so the operator isn't forced to hand-patch inventory
    # before each migration run.
    _CROSS_TENANT_SKIP_MARKERS = (
        'invalid privilege',     # priv gone / MSP-only on non-MSP target
        'invalid enforcement',   # enforcement key retired or renamed
        'privilege not supported',
        'enforcement not supported',
        'not a valid privilege',
    )

    # Dependency-not-present markers. These indicate Commander refused
    # because the referenced entity doesn't exist on target yet — a
    # cascade we expect in auto-migrate when the `users` stage is
    # SKIPPED (sends real emails) and subsequent role-user / team-user
    # assignments can't find the user. Treat as SKIPPED instead of
    # FAILED so the structure stage doesn't halt on expected gaps.
    _DEPENDENCY_NOT_FOUND_MARKERS = (
        'user not found',
        'role not found',
        'team not found',
        'user is not found',
        'role is not found',
        'team is not found',
        'node is not found',
        'is not found: skipping',   # Commander's generic idiom
        # Bug 54 (v1.5.6) — Commander's `enterprise-user` command uses a
        # different rejection idiom for missing users: `enterprise-user:
        # No such user(s)`. Surfaced by 2026-05-01 rehearsal-8 against
        # MSP target where the `users` stage was skipped (auto-migrate
        # default) — 11 user_node assignments cascade-failed because the
        # users hadn't been invited yet. Classify as SKIPPED so the
        # pipeline doesn't halt; operator can re-run user_node after
        # the users stage completes.
        'no such user',
    )

    # Enforcement-shape markers. Commander rejects enforcements whose
    # value doesn't fit its expected format (dict-valued KEYs need
    # `$FILE=path`, Phase-C; list/scalar KEYs go through `KEY:[VAL]`,
    # Phase-A/B). Until enforcement_direct routing is extended to
    # cover all dict-valued keys, these land as SKIPPED with a clear
    # note about which enforcement couldn't be applied.
    _ENFORCEMENT_SHAPE_MARKERS = (
        'is skipped. expected format',
        'expects "login"',  # two_factor_duration_* — see throttle.py
    )

    # Bug 13 — Keeper schema rule: a role can have managed_nodes (admin
    # role) OR teams, never both. Commander rejects either combo with
    # misleading messages — "lack required privilege" for the
    # managed_nodes-after-team case, "no objects provided" / "teams
    # cannot be assigned to roles with administrative permissions" for
    # the team-after-managed_nodes case. Surface as FAILED with the
    # actual constraint named so operators don't chase phantom IAM
    # issues.
    _SCHEMA_VIOLATION_MARKERS = (
        'teams cannot be assigned to roles with administrative permissions',
        'no objects provided',
    )

    # Bug 51 / Upstream-3 — cross-tenant REQUIRE_ACCOUNT_SHARE rejection.
    # Commander rejects any role-A → role-B require_account_share (where
    # A and B are different roles, both admin, both carry TRANSFER_ACCOUNT
    # — i.e. all 4 documented CLI gates pass) with a generic
    # 'bad_inputs_enforcement' envelope and no specific error code.
    # Bug 47 caught the self-ref subset pre-flight; cross-refs fall
    # through to the API call and trip this. Plugin-side workaround is
    # SKIP with a loud operator-facing note recording the role-pair so
    # the operator can apply require_account_share manually post-
    # migration via Keeper Admin Console (see UPSTREAM_BUGS.md
    # Upstream-3). Forward-compat: if Upstream-3 is ever resolved
    # upstream, this marker won't fire because the call will succeed.
    _UPSTREAM3_REJECTION_MARKERS = (
        'require_account_share',
    )

    # Bug 53 / Upstream-4 (v1.5.6) — environment-restricted BOOLEAN
    # enforcement rejection. Surfaced 2026-05-01 rehearsal-8 against
    # MSP target on `ALLOW_CAN_EDIT_EXTERNAL_SHARES`. The server
    # returns the same generic `bad_inputs_enforcement` envelope as
    # Upstream-1/3 but for a BOOLEAN-typed enforcement. v1.5.3 →
    # v1.5.5 attempted plugin-side fixes by adjusting the value
    # marshaling (omitted → string `'true'` → Python bool `True`);
    # all three got the same `value=null` rejection. The constraint
    # is environmental (target tenant doesn't permit the enforcement
    # at the role level — likely tied to MSP-context external-share
    # restrictions), not value-format. SKIP-with-audit so the
    # pipeline doesn't halt; operator can apply manually if/when the
    # target tenant config changes. See UPSTREAM_BUGS.md Upstream-4.
    _UPSTREAM4_REJECTION_MARKERS = (
        'valuetype=boolean',
    )

    def _classify_error(self, err_text):
        """Return ('SKIPPED', reason) when err_text matches a known
        cross-tenant-divergence OR dependency-not-present marker,
        else ('FAILED', err_text).
        """
        low = (err_text or '').lower()
        for marker in self._CROSS_TENANT_SKIP_MARKERS:
            if marker in low:
                return 'SKIPPED', f'target does not support this ({err_text.strip()})'
        for marker in self._DEPENDENCY_NOT_FOUND_MARKERS:
            if marker in low:
                return 'SKIPPED', (
                    f'dependency missing on target ({err_text.strip()}); '
                    'usually resolves after `users` stage runs'
                )
        for marker in self._ENFORCEMENT_SHAPE_MARKERS:
            if marker in low:
                return 'SKIPPED', (
                    f'enforcement value shape not accepted by Commander '
                    f'CLI ({err_text.strip()}); v1.4.1 will route '
                    'dict-valued enforcements through enforcement_direct'
                )
        for marker in self._SCHEMA_VIOLATION_MARKERS:
            if marker in low:
                return 'FAILED', (
                    'Keeper schema rule: a role cannot carry both '
                    'managed_nodes (admin) and teams. Source role likely '
                    f'has both flags set ({err_text.strip()}). Re-export '
                    'inventory or split the role on source before retry.'
                )
        # Bug 51 — must come AFTER the schema-violation check so that
        # 'no objects provided' isn't masked. The substring is narrow
        # (`require_account_share` literal) so false-positives are
        # confined to the same Commander rejection path.
        for marker in self._UPSTREAM3_REJECTION_MARKERS:
            if marker in low and 'cannot update enforcement' in low:
                return 'SKIPPED', (
                    'cross-tenant REQUIRE_ACCOUNT_SHARE rejection '
                    '(Upstream-3); no plugin-side workaround — '
                    'operator must apply manually post-migration via '
                    'Keeper Admin Console. Server: '
                    f'{err_text.strip()}'
                )
        # Bug 53 / Upstream-4 — environment-restricted BOOLEAN
        # enforcement. Same envelope as Upstream-1/3, different
        # constraint class. Match requires both 'valuetype=boolean'
        # and 'cannot update enforcement' so we don't catch unrelated
        # boolean-type validation errors.
        for marker in self._UPSTREAM4_REJECTION_MARKERS:
            if marker in low and 'cannot update enforcement' in low:
                return 'SKIPPED', (
                    'environment-restricted BOOLEAN enforcement '
                    '(Upstream-4); target tenant does not permit '
                    'this enforcement (e.g. MSP-context external-'
                    'share restrictions). Apply manually post-'
                    'migration via Keeper Admin Console if needed. '
                    f'Server: {err_text.strip()}'
                )
        return 'FAILED', err_text

    def _record_or_classify(self, category, name, action, ok, notes_ok=''):
        """Standard record pattern: SUCCESS when ok=True, else route
        through the classifier to decide SKIPPED vs FAILED."""
        if ok:
            self._record(category, name, action,
                          StepResult.SUCCESS, notes_ok)
            return
        status, reason = self._classify_error(self._last_error())
        if status == 'SKIPPED':
            self._record(category, name, action,
                          StepResult.SKIPPED, reason)
        else:
            self._record(category, name, action,
                          StepResult.FAILED, self._failed_notes(notes_ok))

    def _record(self, category, name, action, status, notes=''):
        self.results.append(StepResult(category, name, action, status, notes))
        self.counters[status] += 1

    def _pace(self):
        """Rate-limit a single API call. Called AFTER every entity
        operation inside step loops. No-op when delay/jitter/reserve
        are all zero — existing unit tests that don't configure
        throttling see the original zero-sleep behavior.

        Combines three levers:
          - Base delay (floor)
          - Jitter (prevents alignment with Commander's 30s throttle
            retry wave)
          - Yield budget (every Nth call, longer pause so the user's
            browser session can reclaim rate-limit quota)
        """
        if self._delay <= 0 and self._jitter <= 0 and self._reserve_every <= 0:
            return
        self._call_counter += 1
        sleep_for = self._delay
        if self._jitter > 0:
            import random
            sleep_for += random.uniform(0, self._jitter)
        if (self._reserve_every > 0
                and self._call_counter % self._reserve_every == 0):
            sleep_for += self._reserve_seconds
        if sleep_for > 0:
            self._sleep(sleep_for)

    # Step 0 ---------------------------------------------------------------

    def step_record_types(self, record_types_path):
        if not record_types_path:
            logging.info('Step 0: no record_types.json — skipping')
            return
        ok = self.client.load_record_types(record_types_path)
        self._record('record_types', 'Custom record types', 'load',
                     StepResult.SUCCESS if ok else StepResult.FAILED,
                     '' if ok else 'May already exist')

    # Step 1 ---------------------------------------------------------------

    def step_nodes(self, nodes):
        order = topological_node_order(nodes, self.scope_node, self.target_root)
        # Bug 73 — disambiguate duplicate leaf names by suffixing with the
        # parent leaf (e.g. 'Finance' under three Subsidiaries becomes
        # 'Finance (Subsidiary 1)', 'Finance (Subsidiary 2)', ...). The
        # rename-with-suffix pattern matches what step_teams and
        # step_roles already do, and it sidesteps Commander's tenant-
        # wide name dedup at `enterprise-node --add`. Opt out via
        # `preserve_duplicate_node_names=True` to fall through to the
        # SDK boundary's direct `node_add` bypass instead — only safe
        # when the server is verified to accept duplicate displaynames.
        if self.preserve_duplicate_node_names:
            rows = [{'original_name': name, 'create_name': name,
                     'parent_name': parent_name, 'isolated': isolated}
                    for name, parent_name, isolated in order]
            rename_log = []
        else:
            rows, rename_log = dedupe_node_names(order)
        self.node_rename_log = list(rename_log)
        existing = (self.client.list_node_names(self.scope_node)
                    if self.resume else set())
        for row in rows:
            create_name = row['create_name']
            parent_name = row['parent_name']
            base_notes = ''
            if create_name != row['original_name']:
                base_notes = (f"duplicate — renamed from "
                              f"\"{row['original_name']}\"")
            if self.resume and create_name in existing:
                self.created_nodes.add(create_name)
                self.resume_skipped += 1
                resume_note = (
                    f'{base_notes}; already present (resume)'
                ).strip('; ').strip() or 'already present (resume)'
                self._record('node', create_name, 'create',
                             StepResult.SKIPPED, resume_note)
                continue
            ok = self.client.create_node(create_name, parent_name)
            if ok:
                self.created_nodes.add(create_name)
                ok_notes = f'Parent: {parent_name}'
                if base_notes:
                    ok_notes = f'{ok_notes}; {base_notes}'
                if self.resume:
                    ok_notes += ' (created — was missing on resume)'
                self._record('node', create_name, 'create',
                             StepResult.SUCCESS, ok_notes)
            else:
                fail_notes = f'Parent: {parent_name} (may already exist)'
                if base_notes:
                    fail_notes = f'{fail_notes}; {base_notes}'
                self._record('node', create_name, 'create',
                             StepResult.FAILED, self._failed_notes(fail_notes))
            self._pace()

    # Step 2 ---------------------------------------------------------------

    def step_isolated_flags(self, nodes):
        already_isolated = (
            self.client.list_isolated_node_names(self.scope_node)
            if self.resume else set()
        )
        gate_active = bool(self.created_nodes)
        # Bug 73 — node_rename_log entries map (original_name, parent_name)
        # to the renamed target name. Source's `isolated=True` rows
        # carry the ORIGINAL name and a parent (for duplicate names);
        # to toggle the right target node we must look up the renamed
        # form. For non-duplicates the mapping is identity (no entry
        # in node_rename_log) and the original name passes through.
        node_rename = {(orig, parent): renamed
                       for orig, parent, renamed in self.node_rename_log}
        # Index source rows by (name, parent) so we can resolve each
        # isolated row to the matching target name. extract_isolated_nodes
        # only returns the leaf name, which is ambiguous when duplicates
        # exist — we re-walk the source to recover the parent context.
        source_isolated_pairs = []
        for n in nodes or []:
            if not n.get('isolated'):
                continue
            nm = n.get('name', '')
            if not nm:
                continue
            par = (n.get('parent') or n.get('parent_name') or '').strip()
            if par == self.source_root:
                par = self.target_root
            else:
                par = leaf_of(par) if par else ''
            source_isolated_pairs.append((nm, par))
        for orig_name, parent_name in source_isolated_pairs:
            target_name = node_rename.get((orig_name, parent_name), orig_name)
            if gate_active and target_name not in self.created_nodes:
                self._record('node', target_name, 'toggle-isolated',
                              StepResult.SKIPPED,
                              'target node never created — call suppressed')
                continue
            if self.resume and target_name in already_isolated:
                self.resume_skipped += 1
                self._record('node', target_name, 'toggle-isolated',
                              StepResult.SKIPPED,
                              'already isolated (resume)')
                continue
            ok = self.client.toggle_node_isolated(target_name)
            notes_ok = ''
            if ok and self.resume:
                notes_ok = 'created — was missing on resume'
            self._record('node', target_name, 'toggle-isolated',
                         StepResult.SUCCESS if ok else StepResult.FAILED,
                         notes_ok if ok else 'May already be isolated')
            self._pace()

    # Step 3 ---------------------------------------------------------------

    def step_teams(self, teams):
        rows, rename_log = dedupe_team_names(teams, self.source_root, self.target_root)
        self.team_rename_log = list(rename_log)
        existing = (self.client.list_team_names(self.scope_node)
                    if self.resume else set())
        for row in rows:
            base_notes = ''
            if row['create_name'] != row['original_name']:
                base_notes = f"duplicate — renamed from \"{row['original_name']}\""
            if self.resume and row['create_name'] in existing:
                self.created_teams.add(row['create_name'])
                self.resume_skipped += 1
                resume_note = (base_notes + '; already present (resume)').strip(
                    '; ').strip() or 'already present (resume)'
                self._record('team', row['create_name'], 'create',
                              StepResult.SKIPPED, resume_note)
                continue
            ok = self.client.create_team(
                row['create_name'], row['node'],
                row['restrict_share'], row['restrict_edit'], row['restrict_view'],
            )
            if ok:
                self.created_teams.add(row['create_name'])
                ok_notes = base_notes
                if self.resume:
                    ok_notes = (
                        (base_notes + '; created — was missing on resume')
                        .strip('; ').strip())
                self._record('team', row['create_name'], 'create',
                              StepResult.SUCCESS, ok_notes)
            else:
                fail_note = (base_notes + ' (may already exist)').strip()
                self._record('team', row['create_name'], 'create',
                              StepResult.FAILED,
                              self._failed_notes(fail_note))
            self._pace()
        return rename_log

    # Step 4 ---------------------------------------------------------------

    def step_roles(self, roles):
        rows, rename_log = dedupe_role_names(roles, self.source_root, self.target_root)
        self.role_rename_log = list(rename_log)
        existing = (self.client.list_role_names(self.scope_node)
                    if self.resume else set())
        for row in rows:
            note_parts = []
            if row['create_name'] != row['original_name']:
                note_parts.append(f"renamed from \"{row['original_name']}\"")
            if row['new_user'] == 'on':
                note_parts.append('default for new users')
            notes = '; '.join(note_parts)
            if self.resume and row['create_name'] in existing:
                self.created_roles.add(row['create_name'])
                self.resume_skipped += 1
                resume_note = (notes + '; already present (resume)').strip(
                    '; ').strip() or 'already present (resume)'
                self._record('role', row['create_name'], 'create',
                              StepResult.SKIPPED, resume_note)
                continue
            ok = self.client.create_role(row['create_name'], row['node'], row['new_user'])
            if ok:
                self.created_roles.add(row['create_name'])
                ok_notes = notes
                if self.resume:
                    ok_notes = (
                        (notes + '; created — was missing on resume')
                        .strip('; ').strip())
                self._record('role', row['create_name'], 'create',
                              StepResult.SUCCESS, ok_notes)
            else:
                fail_note = (notes + ' (may already exist)').strip('; ').strip()
                self._record('role', row['create_name'], 'create',
                              StepResult.FAILED,
                              self._failed_notes(fail_note))
            self._pace()
        return rename_log

    # Step 5 ---------------------------------------------------------------

    def _build_node_rename_lookup(self, roles_complete):
        """Bug 80 — translate `self.node_rename_log` from
        `(orig_name, parent_name, renamed)` into
        `{(source_node_id, source_parent_path): renamed_target}`
        keyed by the disambiguation context that
        `live_inventory._build_role_managed_nodes` now records on
        each managed_node entry.

        We need a way to map (orig leaf name, parent name) back to a
        specific source `node_id`. The role list itself doesn't
        carry node-id mapping data — but the captured managed_nodes
        entries DO (via `source_node_id` + `source_parent_path`).
        Walk every role's managed_nodes once to build a `(orig_leaf,
        parent_leaf) → [source_node_ids]` index, then for each
        rename_log entry pick the matching id(s) and emit lookup
        rows.

        Pre-Bug-80 inventories don't carry the new fields — the
        lookup ends up empty and migration falls through to
        name-only remapping (backwards-compatible).
        """
        if not self.node_rename_log:
            return {}
        # Index source-managed-node entries by (leaf, parent_leaf).
        index = {}
        for r in roles_complete or []:
            for mn in r.get('managed_nodes', []) or []:
                src_id = (mn.get('source_node_id') or '').strip()
                src_path = (mn.get('source_parent_path') or '').strip()
                if not src_id:
                    continue
                leaf = (mn.get('node_name') or '').strip()
                # parent leaf = last segment of source_parent_path
                # MINUS the leaf itself if path ends with it.
                parent_leaf = ''
                if src_path:
                    parts = [p for p in src_path.split('\\') if p]
                    if parts and parts[-1] == leaf and len(parts) >= 2:
                        parent_leaf = parts[-2]
                    elif parts:
                        parent_leaf = parts[-1]
                index.setdefault((leaf, parent_leaf), set()).add(
                    (src_id, src_path))
        # Build lookup keyed by (source_node_id, source_parent_path).
        lookup = {}
        for orig, parent, renamed in self.node_rename_log:
            ids_paths = index.get((orig, parent), set())
            for src_id, src_path in ids_paths:
                lookup[(src_id, src_path)] = renamed
        return lookup

    def step_managed_nodes(self, roles_complete):
        """Add managed-node + privilege assignments per role.

        `roles_complete` is the list from enterprise-role <ROLE> --format json,
        each with managed_nodes[] containing node_name/cascade/privileges[].

        Skips roles that weren't created on target (see created_roles set
        populated by step_roles). Before this gate, missing roles produced
        cascades of 'Role X is not found: Skipping' — one line per
        enforcement attempted against the missing target role. The gate
        reduces that to a single SKIPPED record per missing role.
        """
        # Bug 13 pre-flight — any source role with both managed_nodes
        # and teams violates Keeper's schema. Recording them up-front
        # turns Commander's misleading "lack required privilege" /
        # "no objects provided" rejections into a clear, actionable
        # FAILED entry pointing at the source-data fix.
        schema_violations = {
            name: reason
            for name, reason in find_schema_violations(roles_complete)
        }
        for v_name, v_reason in schema_violations.items():
            self._record('role_admin', v_name, 'pre-flight',
                          StepResult.FAILED,
                          f'schema-impossible role shape: {v_reason}. '
                          'No managed_node grant attempted.')
        gate_active = bool(self.created_roles)
        # Resume cache — fetched per role on first encounter, then reused
        # for that role's privilege loop. Empty when resume is off.
        resume_managed_cache = {}
        resume_priv_cache = {}
        # Bug 67 — dedup-rename map so plan_managed_nodes emits the
        # disambiguated target name (matches step_roles' created
        # entries).
        role_rename_lookup = {(o, n): renamed
                               for o, n, renamed in self.role_rename_log}
        # Bug 80 — node disambiguation lookup for managed_nodes
        # bindings on duplicate-leaf source siblings. node_rename_log
        # entries are (orig_name, parent_name, renamed) — translate to
        # the (source_node_id, source_parent_path) shape that
        # plan_managed_nodes expects via inventory's source-node map.
        node_rename_lookup = self._build_node_rename_lookup(roles_complete)
        # Bug 80 — pre-fetch the set of node names that exist on
        # target so we can FAIL loudly when a managed_node binding
        # points at a non-existent target node. Pre-Bug-80,
        # `add_role_managed_node` returned silent SUCCESS in that
        # case (rehearsal-15 `Permissions -  Share` → `Finance`
        # symptom — Finance was Bug-73-renamed to
        # `Finance (Subsidiary X)` so the original name had no
        # target). With this pre-check, the operator gets a clear
        # FAILED row pointing at the missing-node root cause instead
        # of a confusing post-migration verify drift.
        # Defensive against minimal test clients (smoke harness etc.)
        # that don't implement the full StructureClient ABI or return
        # non-iterable stubs — fall back to created_nodes alone, which
        # disables the gate without breaking those callers.
        try:
            target_node_names = set(self.client.list_node_names())
        except (AttributeError, TypeError):
            target_node_names = set()
        target_node_names |= self.created_nodes
        for role_name, node_name, cascade, privs in plan_managed_nodes(
                roles_complete, self.source_root, self.target_root,
                role_rename_lookup=role_rename_lookup,
                node_rename_lookup=node_rename_lookup):
            if role_name in schema_violations:
                # Already recorded as FAILED above; suppress per-node
                # calls so we don't multiply the failure record.
                continue
            if gate_active and role_name not in self.created_roles:
                self._record('role_admin', f'{role_name} → {node_name}',
                              'add-admin', StepResult.SKIPPED,
                              f'role never created on target — '
                              f'{1 + len(privs)} calls suppressed')
                continue
            # Bug 80 — target node existence pre-check. Only fires
            # when Bug-73 disambiguation actually happened on this
            # run (`self.node_rename_log` non-empty); without
            # rename activity, name-only resolution has always
            # worked and there's no Bug-80 vector to guard against.
            # We also accept leaf-form match against
            # `target_node_names` (Commander stores by displayname,
            # while plan_managed_nodes may emit a path-form name
            # for nested target nodes).
            if (self.node_rename_log and target_node_names
                    and node_name not in target_node_names
                    and leaf_of(node_name) not in target_node_names):
                self._record('role_admin', f'{role_name} → {node_name}',
                              'add-admin', StepResult.FAILED,
                              self._failed_notes(
                                  f'target node {node_name!r} does not '
                                  'exist on target (Bug 80 — duplicate-'
                                  'leaf source name lost when target '
                                  'was Bug-73-renamed, OR captured '
                                  'binding references a node missing '
                                  'from target). Inspect rename_map.json '
                                  'and fix the binding manually.'))
                # Don't try the privileges either — they would all
                # fail with the same root cause.
                continue
            if self.resume and role_name not in resume_managed_cache:
                resume_managed_cache[role_name] = (
                    self.client.list_role_managed_nodes(role_name))
                resume_priv_cache[role_name] = (
                    self.client.list_role_privileges(role_name))
            cur_managed = resume_managed_cache.get(role_name, set())
            cur_privs = resume_priv_cache.get(role_name, set())
            already_admin = (self.resume
                             and (node_name, cascade) in cur_managed)
            if already_admin:
                self.resume_skipped += 1
                self._record('role_admin', f'{role_name} → {node_name}',
                              'add-admin', StepResult.SKIPPED,
                              f'already admin (resume); cascade={cascade}')
            else:
                ok = self.client.add_role_managed_node(role_name, node_name, cascade)
                if ok:
                    ok_notes = f'cascade={cascade}'
                    if self.resume:
                        ok_notes += ' (created — was missing on resume)'
                    self._record('role_admin', f'{role_name} → {node_name}',
                                  'add-admin', StepResult.SUCCESS, ok_notes)
                else:
                    status, reason = self._classify_error(self._last_error())
                    self._record('role_admin', f'{role_name} → {node_name}',
                                  'add-admin',
                                  getattr(StepResult, status),
                                  (reason if status == 'SKIPPED'
                                   else self._failed_notes(f'cascade={cascade}')))
                self._pace()
            for priv in privs:
                if self.resume and (priv, node_name) in cur_privs:
                    self.resume_skipped += 1
                    self._record('role_priv',
                                  f'{role_name}: {priv} on {node_name}',
                                  'add-privilege', StepResult.SKIPPED,
                                  'already granted (resume)')
                    continue
                priv_ok = self.client.add_role_privilege(role_name, priv, node_name)
                if priv_ok:
                    note_ok = ''
                    if self.resume:
                        note_ok = 'created — was missing on resume'
                    self._record('role_priv',
                                  f'{role_name}: {priv} on {node_name}',
                                  'add-privilege', StepResult.SUCCESS,
                                  note_ok)
                else:
                    # Invalid-privilege is a common cross-tenant divergence
                    # (MSP-only privs on non-MSP target, deprecated keys
                    # between enterprise generations). SKIP with a clear
                    # note rather than FAIL — the role's other privileges
                    # can still apply, and the pipeline shouldn't halt on
                    # a source-specific privilege target can't accept.
                    status, reason = self._classify_error(self._last_error())
                    self._record('role_priv',
                                  f'{role_name}: {priv} on {node_name}',
                                  'add-privilege',
                                  getattr(StepResult, status),
                                  reason if status == 'SKIPPED'
                                  else self._failed_notes(''))
                self._pace()

    # Step 6 ---------------------------------------------------------------

    def step_enforcements(self, roles_complete, complexity_dir=None,
                           direct_api_fn=None,
                           record_types_translator=None):
        """Apply role enforcements (Phase A SIMPLE / Phase B account_share / Phase C FILE).

        Phase-D record_types is routed through SIMPLE (Commander resolves by name).
        `complexity_dir` (optional) is where FILE-phase JSON bodies are written;
        if not provided, a temp dir is created and reused across this call.

        `direct_api_fn` (optional): callable(role_name, {key: value}) → dict of
        results, used for enforcement keys that the CLI rejects (json/jsonarray
        types). Default: no direct-API fallback — bail gracefully with SKIP.

        `record_types_translator` (optional): callable(value) → str. Live
        inventory captures `restrict_record_types` (and any other
        record_types-typed enforcement) as the post-translation JSON
        `{"std":[<ids>],"ent":[<ids>]}`. Commander's CLI parser expects
        comma-separated NAMES and re-translates to IDs internally on
        target. The translator does the IDs → names step using target's
        record_types table. Default: no translation (raw value passes
        through; Commander rejects it with bad_inputs_value).
        """
        id_to_name = build_id_to_role_name(roles_complete)
        # Bug 64 — pre-flight TRANSFER_ACCOUNT check for
        # require_account_share. Pre-compute per-role privilege
        # metadata so classify_enforcement can SKIP source-misconfigured
        # cases before they hit the target's stricter validation.
        source_role_meta = build_source_role_meta(roles_complete)

        created_tmp = False
        if complexity_dir is None:
            import tempfile
            complexity_dir = tempfile.mkdtemp(prefix='keeper_enf_')
            created_tmp = True
        else:
            os.makedirs(complexity_dir, exist_ok=True)

        try:
            simple_count = 0
            file_count = 0
            skip_count = 0
            fail_count = 0
            direct_count = 0

            # enforcement_direct is a sibling module — an ImportError here
            # means a packaging bug (someone deleted the file). Silently
            # treating everything as CLI-supported would route json/jsonarray
            # enforcements through a parser that rejects them, so the
            # restore would silently drop them. Fail loud.
            from .enforcement_direct import is_cli_unsupported

            gate_active = bool(self.created_roles)
            # Bug 67 (rehearsal-11) — step_roles renames duplicate-name
            # source roles by appending source-node suffix (e.g.
            # 'Departaments - Finance Interns' →
            # 'Departaments - Finance Interns (Master Company - Azure
            # SSO Cloud Connector)'). step_enforcements was looking up
            # the ORIGINAL source name in created_roles → SKIPped
            # every renamed role's enforcements as 'role never created
            # on target'. rehearsal-11 surfaced this on 8+ roles with
            # 220+ suppressed enforcements.
            #
            # Bug 67 v2 (rehearsal-12) — the rename_log key uses the
            # POST-REMAP target node (dedupe_role_names: `My company`
            # → target_root, nested paths → leaf_of). My v1.6.1 fix
            # used the raw source `node` field — never matched →
            # rename never resolved. Apply the same node remap as
            # dedupe_role_names does so the key matches.
            role_rename_lookup = {(o, n): renamed
                                   for o, n, renamed in self.role_rename_log}

            def _remapped_role_node(role):
                src = (role.get('node') or role.get('node_name')
                       or self.source_root).strip()
                if src == self.source_root:
                    return self.target_root
                return leaf_of(src) if src else ''

            for r in roles_complete:
                role_name = (r.get('name') or '').strip()
                if not role_name:
                    continue
                # Dedup/builtin collision doesn't run against enforcements — we apply
                # them to whatever role name the step_roles step created. For
                # built-in collisions only the target-side name matters, which is
                # role_name + ' (Migrated)' when applicable.
                # Bug 67 — also resolve through the dedup rename map so
                # disambiguated target names take precedence over the
                # original source name.
                remapped_node = _remapped_role_node(r)
                renamed = role_rename_lookup.get((role_name, remapped_node))
                if renamed:
                    target_role_name = renamed
                else:
                    target_role_name = resolve_builtin_role_collision(role_name)
                # Gate: skip roles that never landed on target. Pre-gate
                # behavior was one CLI call per enforcement against a
                # non-existent role — 13 lines per role of 'Role X is
                # not found: Skipping' spam. Single SKIPPED record is
                # much easier to scan.
                if gate_active and target_role_name not in self.created_roles:
                    enf_count = len(r.get('enforcements') or {})
                    self._record('enforcement', target_role_name, 'skip-missing',
                                  StepResult.SKIPPED,
                                  f'role never created on target — '
                                  f'{enf_count} enforcement(s) suppressed')
                    continue

                enfs = r.get('enforcements', {}) or {}
                if not isinstance(enfs, dict):
                    continue

                # Resume reconciliation: drop enforcement keys whose
                # values already match what's on target. A role that
                # had every enforcement applied pre-crash becomes a
                # no-op on resume; one mid-stage role lands the
                # missing keys only.
                if self.resume:
                    target_enfs = self.client.list_role_enforcements(
                        target_role_name)
                    if target_enfs:
                        before = len(enfs)
                        enfs = {
                            k: v for k, v in enfs.items()
                            if not _enforcement_already_applied(
                                k, v, target_enfs)
                        }
                        skipped_now = before - len(enfs)
                        if skipped_now:
                            self.resume_skipped += skipped_now
                            self._record(
                                'enforcement', target_role_name,
                                'skip-already-set', StepResult.SKIPPED,
                                f'{skipped_now} enforcement(s) '
                                f'already applied (resume)')
                        if not enfs:
                            continue

                # Partition the role's enforcements: route CLI-unsupported
                # (json/jsonarray/unknown) through the direct-API path if
                # available; everything else through the existing classifier.
                # Pre-translation: record_types-typed enforcements need
                # IDs → names conversion before they hit the CLI parser.
                # See `enforcement_direct.record_types_value_to_names`.

                # v1.7 — lockout-risk default-skip MUST run BEFORE the
                # cli/direct partition. Two of the four lockout-risk
                # keys (`master_password_reentry`,
                # `two_factor_by_ip`) are typed `json`/`jsonarray` in
                # Commander's ENFORCEMENTS table and route to the
                # direct-API path, which never invokes
                # classify_enforcement. A previous (rev1) shape kept
                # the guard inside classify_enforcement and silently
                # let those two keys through — code-reviewer caught
                # the gap. Hoisting here ensures both partitions
                # honor the same rule.
                bare_role = target_role_name.replace(BUILTIN_ROLE_SUFFIX, '')
                if (bare_role in BUILTIN_ROLE_NAMES
                        and not self.apply_admin_lockout_risk_enforcements):
                    lockout_keys_present = [
                        k for k in list(enfs.keys())
                        if k in LOCKOUT_RISK_ENFORCEMENTS]
                    for k in lockout_keys_present:
                        del enfs[k]
                        skip_count += 1
                        reason = (f'lockout-risk enforcement {k!r} on '
                                  f'builtin-admin role {bare_role!r}; '
                                  'default-skip to prevent admin '
                                  'lockout. Opt in via --apply-admin-'
                                  'lockout-risk-enforcements after '
                                  'auditing the source value for '
                                  'target-tenant compatibility.')
                        logging.info('Skip enforcement %s.%s: %s',
                                     target_role_name, k, reason)
                        # Per-key SKIP audit row for verify-side
                        # consumption (T2.2). Same shape as the
                        # classify_enforcement-emitted rows so
                        # `load_structure_skipped_enforcements`
                        # picks them up uniformly.
                        self._record(
                            'enforcement',
                            f'{target_role_name}.{k}',
                            'classify-skip',
                            StepResult.SKIPPED, reason)
                cli_enfs = {}
                direct_enfs = {}
                for key, value in enfs.items():
                    if is_cli_unsupported(key):
                        direct_enfs[key] = value
                    else:
                        if (_is_record_types_key(key)
                                and record_types_translator is not None):
                            value = record_types_translator(value)
                        cli_enfs[key] = value

                if direct_enfs:
                    if direct_api_fn is None:
                        skip_count += len(direct_enfs)
                        logging.info('Skipping %d direct-API enforcement(s) on %s '
                                     '(no direct_api_fn provided): %s',
                                     len(direct_enfs), target_role_name,
                                     sorted(direct_enfs))
                    else:
                        results = direct_api_fn(target_role_name, direct_enfs)
                        for key, (ok, msg) in (results or {}).items():
                            if ok:
                                direct_count += 1
                            else:
                                # Bug 53 (v1.5.6) — direct-API failures
                                # used to count as fail unconditionally.
                                # Route through the same classifier as
                                # the CLI batch path so known-upstream
                                # rejections (Upstream-1/3 require_
                                # account_share, Upstream-4 BOOLEAN
                                # value=null on environment-restricted
                                # enforcements like ALLOW_CAN_EDIT_
                                # EXTERNAL_SHARES) become SKIPPED with
                                # an operator-facing reason. v1.5.3 →
                                # v1.5.5 attempted to fix Bug 48 by
                                # adjusting the value marshaling
                                # (string → bool); rehearsal-8 proved
                                # the rejection is environmental
                                # (server-side check on target tenant
                                # constraints, not the value
                                # serialization). SKIP-with-audit is
                                # the correct workaround until the
                                # constraint is documented upstream.
                                status, reason = self._classify_error(msg)
                                if status == 'SKIPPED':
                                    skip_count += 1
                                    logging.warning(
                                        'direct-API %s.%s skipped: %s',
                                        target_role_name, key, reason,
                                    )
                                else:
                                    fail_count += 1
                                    logging.warning(
                                        'direct-API %s.%s failed: %s',
                                        target_role_name, key, msg,
                                    )

                # v1.4.2: collect SIMPLE + ACCOUNT_SHARE enforcements
                # for this role and send them in ONE API call. Commander's
                # --enforcement flag is plural (argparse append) and its
                # parser `continue`s on bad values (enterprise.py:2339,
                # 2382) so batching is safe.
                #
                # Result tallying: the batched call's return value is a
                # single bool. If the whole call succeeded, count every
                # pair as simple_count. If it failed (or a silent skip
                # was captured), count as fail — we lose per-key
                # granularity here, but Commander's own warnings (caught
                # via SilentFailureCapture) preserve the diagnostic.
                # `classify_enforcement` returns `decision['role']` ==
                # `target_role_name` for every SIMPLE/ACCOUNT_SHARE phase
                # today; the batch is sent against the role we're
                # currently restoring.
                simple_pairs = []
                for key, value in cli_enfs.items():
                    decision = classify_enforcement(
                        target_role_name, key, value, id_to_name,
                        source_role_meta=source_role_meta,
                        apply_admin_lockout_risk_enforcements=(
                            self.apply_admin_lockout_risk_enforcements))
                    if decision['phase'] in ('SIMPLE', 'ACCOUNT_SHARE'):
                        simple_pairs.append(
                            (decision['key'], decision['value']))
                    elif decision['phase'] == 'FILE':
                        # Bug 62 (v1.6) — role names with `:` (e.g.
                        # 'Access Level: Read-Only') leaked into the
                        # file path, breaking Commander's CLI parser
                        # which splits `KEY:VALUE` on the first colon.
                        # Result: every FILE-phase enforcement on a
                        # colon-named role got SKIP'd with shape-marker
                        # in rehearsal-10. Strip it (and other CLI-
                        # parser meta chars) defensively.
                        safe_name = (target_role_name
                                     .replace('/', '_')
                                     .replace(' ', '_')
                                     .replace('\\', '_')
                                     .replace(':', '_')
                                     .replace('=', '_')
                                     .replace('$', '_'))
                        fpath = os.path.join(complexity_dir, f'{safe_name}_{key}.json')
                        with open(fpath, 'w') as f:
                            f.write(decision['body'])
                        # Bug 78 — pre-write WARN audit row when
                        # `generated_password_complexity` value is a
                        # multi-element list. Commander's CLI is
                        # observed to truncate to the first element
                        # in some envs (rehearsal-15 captured the
                        # symptom). Operators see a structure-side
                        # WARNING up front so the post-migration
                        # verify FAIL isn't a surprise — and they
                        # know to apply remaining rules manually.
                        if key == 'generated_password_complexity':
                            try:
                                _parsed = json.loads(decision['body'])
                                if isinstance(_parsed, list) and len(_parsed) > 1:
                                    self._record(
                                        'enforcement',
                                        f'{target_role_name}.{key}',
                                        'multi-domain-warn',
                                        StepResult.SUCCESS,
                                        (f'multi-element value '
                                         f'({len(_parsed)} rules); '
                                         'Commander CLI may truncate '
                                         'to first rule (Bug 78). '
                                         'Verify will surface the '
                                         'symptom; apply remaining '
                                         'rules manually if Bug 78 '
                                         'fires.'))
                            except (TypeError, ValueError, KeyError):
                                pass
                        ok = self.client.set_role_enforcement_file(
                            decision['role'], decision['key'], fpath)
                        if ok:
                            file_count += 1
                        else:
                            # Bug 57 (v1.5.7) — FILE-phase failures
                            # used to silently increment fail_count
                            # with no log output and no classifier
                            # routing. That made the residual 4
                            # FAILED entries in rehearsal-9 invisible
                            # in both the log and the per-step CSV.
                            # Mirror the direct-API path (Bug 53):
                            # log at WARNING with the captured
                            # Commander error AND route through
                            # `_classify_error` so known-upstream
                            # rejections (shape, dependency, Upstream-
                            # 1/3/4) become SKIPPED with operator-
                            # facing reasons.
                            err = self._last_error() or ''
                            status, reason = self._classify_error(err)
                            if status == 'SKIPPED':
                                skip_count += 1
                                logging.warning(
                                    'FILE enforcement %s.%s '
                                    'skipped: %s',
                                    decision['role'], decision['key'],
                                    reason,
                                )
                            else:
                                fail_count += 1
                                logging.warning(
                                    'FILE enforcement %s.%s '
                                    'failed: %s',
                                    decision['role'], decision['key'],
                                    err or '(no error captured)',
                                )
                        self._pace()
                    else:  # SKIP
                        skip_count += 1
                        logging.info('Skip enforcement %s.%s: %s',
                                     target_role_name, key, decision.get('reason', ''))
                        # v1.7 — emit a per-(role, key) SKIP audit row
                        # so verify can distinguish intentional skips
                        # (Bug 47/64/51 + lockout-risk default-skip)
                        # from unexpected absence on target. Pre-v1.7
                        # the only SKIP record was the aggregate
                        # `enforcements,All roles,set,SUCCESS` row,
                        # which collapsed all per-key skips into a
                        # number. Verify reads this on Bug 76.2 /
                        # T2.2 to sharpen the SKIP message.
                        self._record(
                            'enforcement',
                            f'{target_role_name}.{key}',
                            'classify-skip',
                            StepResult.SKIPPED,
                            decision.get('reason', ''))

                # v1.4.2: send the collected SIMPLE/ACCOUNT_SHARE
                # enforcements in ONE batched API call per role.
                # Commander's parser `continue`s on bad values
                # (enterprise.py:2339, 2382), so one bad key doesn't
                # kill the batch. SilentFailureCapture surfaces any
                # per-key skips as _last_call_error notes.
                if simple_pairs:
                    ok = self.client.set_role_enforcements_simple_batch(
                        target_role_name, simple_pairs)
                    if ok:
                        simple_count += len(simple_pairs)
                    else:
                        # Whole-batch failure. Route through
                        # `_classify_error` so all known-upstream
                        # markers (shape, dependency, Upstream-3
                        # REQUIRE_ACCOUNT_SHARE rejection) propagate
                        # consistently. `_last_error` carries
                        # Commander's first rejection message in the
                        # batch.
                        status, reason = self._classify_error(
                            self._last_error() or '')
                        if status == 'SKIPPED':
                            skip_count += len(simple_pairs)
                            logging.warning(
                                'enforcement batch on %s skipped '
                                '(%d pairs): %s',
                                target_role_name, len(simple_pairs),
                                reason,
                            )
                        else:
                            fail_count += len(simple_pairs)
                            logging.warning(
                                'enforcement batch on %s failed '
                                '(%d pairs)',
                                target_role_name, len(simple_pairs),
                            )
                    self._pace()

            notes = (f'{simple_count} simple + {file_count} file + '
                     f'{direct_count} direct; {fail_count} failed; '
                     f'{skip_count} skipped')
            status = StepResult.SUCCESS if fail_count == 0 else StepResult.FAILED
            self._record('enforcements', 'All roles', 'set', status, notes)
            return {'simple': simple_count, 'file': file_count,
                    'direct': direct_count,
                    'failed': fail_count, 'skipped': skip_count}
        finally:
            if created_tmp:
                import shutil
                shutil.rmtree(complexity_dir, ignore_errors=True)

    # Step 7 ---------------------------------------------------------------

    def step_user_nodes(self, users):
        existing = (self.client.list_user_node_assignments()
                    if self.resume else {})
        gate_active = bool(self.created_nodes)
        for email, node in plan_user_node_assignments(users, self.source_root, self.target_root):
            if gate_active and node not in self.created_nodes:
                self._record('user_node', f'{email} → {node}',
                              'assign', StepResult.SKIPPED,
                              'target node never created — call suppressed')
                continue
            if (self.resume
                    and existing.get((email or '').lower()) == node):
                self.resume_skipped += 1
                self._record('user_node', f'{email} → {node}',
                              'assign', StepResult.SKIPPED,
                              'already assigned (resume)')
                continue
            ok = self.client.assign_user_to_node(email, node)
            self._record_or_classify(
                'user_node', f'{email} → {node}', 'assign', ok,
                notes_ok=('created — was missing on resume'
                          if (self.resume and ok) else ''))
            self._pace()

    # Step 8 ---------------------------------------------------------------

    def step_user_teams(self, users):
        existing = (self.client.list_user_team_memberships()
                    if self.resume else {})
        # Gate on created_teams set populated by step_teams. Rename
        # caveat: dedupe_team_names can rename a duplicate team to
        # `<name> [<leaf>]`; users.teams still references the original
        # name. The gate sees only the renamed value and would skip
        # the legitimate user. That mirrors the call behavior today
        # (which also fails on renames — no rename map is applied),
        # so the gate is strictly no-worse, and on the common case
        # (no renames) it prevents per-user cascades when a team
        # failed to create. Full rename-aware mapping is a separate
        # follow-up.
        gate_active = bool(self.created_teams)
        for email, team in plan_user_team_assignments(users):
            if gate_active and team not in self.created_teams:
                self._record('user_team', f'{email} → {team}',
                              'add-team', StepResult.SKIPPED,
                              'target team never created — call suppressed')
                continue
            email_l = (email or '').lower()
            if self.resume and team in existing.get(email_l, set()):
                self.resume_skipped += 1
                self._record('user_team', f'{email} → {team}',
                              'add-team', StepResult.SKIPPED,
                              'already member (resume)')
                continue
            ok = self.client.add_user_to_team(email, team)
            self._record_or_classify(
                'user_team', f'{email} → {team}', 'add-team', ok,
                notes_ok=('created — was missing on resume'
                          if (self.resume and ok) else ''))
            self._pace()

    # Step 9 ---------------------------------------------------------------

    def step_role_users(self, roles_complete):
        existing = (self.client.list_role_user_memberships()
                    if self.resume else {})
        gate_active = bool(self.created_roles)
        # Bug 83 — build role rename lookup from self.role_rename_log
        # so dedup-renamed source roles route assignments to the
        # correct target role. Pre-fix, every dedup-renamed role had
        # its user assignments SKIPped at the gate below.
        role_rename_lookup = {(orig, src_node): renamed
                              for orig, src_node, renamed
                              in self.role_rename_log}
        for role_name, email in plan_role_user_assignments(
                roles_complete, role_rename_lookup=role_rename_lookup):
            if gate_active and role_name not in self.created_roles:
                self._record('role_user', f'{email} → {role_name}',
                              'add-user', StepResult.SKIPPED,
                              'target role never created — call suppressed')
                continue
            email_l = (email or '').lower()
            if self.resume and email_l in existing.get(role_name, set()):
                self.resume_skipped += 1
                self._record('role_user', f'{email} → {role_name}',
                              'add-user', StepResult.SKIPPED,
                              'already member (resume)')
                continue
            ok = self.client.add_user_to_role(role_name, email)
            self._record_or_classify(
                'role_user', f'{email} → {role_name}', 'add-user', ok,
                notes_ok=('created — was missing on resume'
                          if (self.resume and ok) else ''))
            self._pace()

    # Step 10 --------------------------------------------------------------

    def step_role_teams(self, roles_complete):
        """Admin roles reject team assignments (Keeper limitation) — mark SKIPPED."""
        existing = (self.client.list_role_team_memberships()
                    if self.resume else {})
        # Gate on created_roles + created_teams so missing-dependency
        # cascades land as one SKIPPED record per (role,team) pair
        # rather than failing through Commander. Same rename caveat as
        # step_user_teams applies for the team side.
        gate_roles = bool(self.created_roles)
        gate_teams = bool(self.created_teams)
        # Bug 83 — build rename lookups so dedup-renamed source
        # role + team names route to their target counterparts.
        # Source role.teams carries only team NAMES (no node), so
        # team lookup is by name alone with a list of candidates;
        # plan_role_team_assignments emits one tuple per candidate
        # and the gate below picks the one that matches a created
        # team.
        role_rename_lookup = {(orig, src_node): renamed
                              for orig, src_node, renamed
                              in self.role_rename_log}
        team_rename_by_name: dict = {}
        for orig, _src_node, renamed in self.team_rename_log:
            team_rename_by_name.setdefault(orig, []).append(renamed)
        for role_name, team_name, is_admin in plan_role_team_assignments(
                roles_complete,
                role_rename_lookup=role_rename_lookup,
                team_rename_lookup_by_name=team_rename_by_name):
            if is_admin:
                self._record('role_team', f'{team_name} → {role_name}', 'skip',
                             StepResult.SKIPPED,
                             'Admin role rejects team adds (Keeper limitation)')
                continue
            if gate_roles and role_name not in self.created_roles:
                self._record('role_team', f'{team_name} → {role_name}',
                              'add-team', StepResult.SKIPPED,
                              'target role never created — call suppressed')
                continue
            if gate_teams and team_name not in self.created_teams:
                self._record('role_team', f'{team_name} → {role_name}',
                              'add-team', StepResult.SKIPPED,
                              'target team never created — call suppressed')
                continue
            if (self.resume
                    and team_name in existing.get(role_name, set())):
                self.resume_skipped += 1
                self._record('role_team',
                              f'{team_name} → {role_name}',
                              'add-team', StepResult.SKIPPED,
                              'already member (resume)')
                continue
            ok = self.client.add_team_to_role(role_name, team_name)
            self._record_or_classify(
                'role_team', f'{team_name} → {role_name}', 'add-team',
                ok,
                notes_ok=('created — was missing on resume'
                          if (self.resume and ok) else ''))
            self._pace()

    # Step 11 --------------------------------------------------------------

    def step_vault_folders(self, vault_folders, *, uid_map=None,
                            promotion_plan=None, action_plan=None,
                            existing_target_names=None):
        """Re-create personal-vault folders on target in parents-before-children order.

        `vault_folders` is the list captured by
        live_inventory.build_vault_folder_entities — each entry carries
        type, source parent_uid, and parent_chain.

        `uid_map` (mutable dict, optional) is populated with
        {source_uid -> target_uid} so downstream stages (records-import,
        SF reconcile) can translate source UIDs to target UIDs when
        binding records to folders.

        `promotion_plan` (optional, legacy 2-option) is a
        {subfolder_uid: decision_dict} produced by
        `nested_sf_plan.promotion_lookup`. When set, listed subfolders
        get created as top-level shared_folders. Kept for backwards
        compatibility with v1.3.0-rc2 callers.

        `action_plan` (optional, 5-option) supersedes `promotion_plan`.
        It is the {subfolder_uid: decision_dict} produced by
        `nested_sf_plan.action_lookup` and dispatches per row to one of
        the 5 materializers. When both are passed, `action_plan` wins.

        `existing_target_names` (optional) is the set of top-level SF
        names already on target — used by sibling/flatten conflict
        resolution. Defaults to empty.

        Returns the uid_map (caller may pre-seed with scope-root
        mappings, e.g. source-side MIGRATION-TEST-NODE UID → target-side
        equivalent).
        """
        from . import nested_sf_plan as _nsfp
        if uid_map is None:
            uid_map = {}
        # Resolve dispatch table — action_plan wins over promotion_plan;
        # legacy promotion_plan rows get translated to ACTION_PROMOTE.
        if action_plan:
            dispatch = dict(action_plan)
        elif promotion_plan:
            dispatch = {}
            for uid, decision in promotion_plan.items():
                row = dict(decision)
                row['proposed_target_action'] = _nsfp.ACTION_PROMOTE
                dispatch[uid] = row
        else:
            dispatch = {}
        existing_target_names = set(existing_target_names or ())

        if not vault_folders:
            self._record('vault_folders', '(none)', 'create',
                          StepResult.SKIPPED,
                          'No vault folders in inventory')
            return uid_map

        for vf in vault_folders:
            name = vf.get('name', '')
            ftype = vf.get('type', '')
            src_uid = vf.get('uid', '')
            src_parent = vf.get('parent_uid', '') or ''
            # Bug 55 (v1.5.6) — Commander rejects shared-folder creation
            # when the name carries trailing/leading whitespace (returns
            # empty UID with no error envelope). Surfaced 2026-05-01
            # rehearsal-8: 'Keeper Demo Console users ' and "Where'd I
            # Put It? Enterprise " each got `client returned empty UID`,
            # then their 4 child subfolders cascade-failed because the
            # parent uid_map was missing. Strip on the way in. The
            # source captured the trailing space; target won't.
            name = (name or '').strip()
            if not name or not ftype or not src_uid:
                self._record('vault_folders', name or '(unknown)', 'create',
                              StepResult.FAILED,
                              f'incomplete entry — type={ftype!r}')
                continue

            decision = (dispatch.get(src_uid) if ftype == 'shared_folder_folder'
                        else None)
            action = (decision.get('proposed_target_action')
                      if decision else None) or _nsfp.ACTION_PRESERVE

            # Promoted / flattened / true-nested subfolders skip parent
            # resolution — they land at target vault root as siblings.
            divergent = (ftype == 'shared_folder_folder'
                         and decision is not None
                         and action in _nsfp.DIVERGENT_ACTIONS)
            review_only = (decision is not None
                           and action == _nsfp.ACTION_REVIEW)

            if review_only:
                self._record('vault_folders', name,
                              f'create-{ftype}',
                              StepResult.SKIPPED,
                              'plan flags subfolder as needs-review')
                continue

            if not divergent:
                if src_parent and src_parent not in uid_map:
                    self._record('vault_folders', name, f'create-{ftype}',
                                  StepResult.FAILED,
                                  f'source parent {src_parent!r} not in uid_map '
                                  f'(check parent_chain ordering)')
                    continue
                tgt_parent = uid_map.get(src_parent, '')
            else:
                tgt_parent = ''

            # Resume: recover source→target UID mapping for folders
            # that already exist on target. Pre-resume the operator had
            # to either replay the whole run or hand-build the uid_map
            # — now structure --resume re-derives it from current state.
            if self.resume:
                if divergent:
                    lookup_name = (decision.get('proposed_promoted_name')
                                    or name)
                    lookup_parent = ''
                    op_label = action
                else:
                    lookup_name = name
                    lookup_parent = tgt_parent
                    op_label = f'create-{ftype}'
                existing_uid = self.client.find_folder_uid(
                    lookup_name, lookup_parent)
                if existing_uid:
                    uid_map[src_uid] = existing_uid
                    self.resume_skipped += 1
                    self._record('vault_folders', name, op_label,
                                  StepResult.SKIPPED,
                                  f'already present (resume); '
                                  f'target_uid={existing_uid[:12]}')
                    continue

            try:
                if divergent:
                    new_uid, op_label, status_note = self._materialize_divergent(
                        vf, decision, existing_target_names, _nsfp,
                    )
                    if new_uid is None:
                        # Materializer reported a failure; record + skip.
                        self._record('vault_folders', name, op_label,
                                      StepResult.FAILED,
                                      status_note or 'materialization failed')
                        continue
                    if new_uid == '':
                        # Merge sentinel: operator chose CONFLICT_MERGE.
                        # Existing SF absorbs this subfolder; no create,
                        # no uid mapping (records reference parent SF).
                        self._record('vault_folders', name, op_label,
                                      StepResult.SUCCESS, status_note)
                        self._pace()
                        continue
                elif ftype == 'user_folder':
                    new_uid = self.client.add_user_folder(
                        name=name, parent_uid=tgt_parent,
                    )
                    op_label = f'create-{ftype}'
                    status_note = ''
                elif ftype == 'shared_folder':
                    new_uid = self.client.add_shared_folder(
                        name=name, parent_uid=tgt_parent,
                        default_manage_users=bool(vf.get('default_manage_users')),
                        default_manage_records=bool(vf.get('default_manage_records')),
                        default_can_edit=bool(vf.get('default_can_edit')),
                        default_can_share=bool(vf.get('default_can_share')),
                    )
                    op_label = f'create-{ftype}'
                    status_note = ''
                elif ftype == 'shared_folder_folder':
                    new_uid = self.client.add_subfolder(
                        name=name, parent_sf_folder_uid=tgt_parent,
                    )
                    op_label = f'create-{ftype}'
                    status_note = ''
                else:
                    self._record('vault_folders', name, 'create',
                                  StepResult.FAILED,
                                  f'unknown folder type {ftype!r}')
                    continue
            except NotImplementedError as e:
                self._record('vault_folders', name,
                              f'create-{ftype}',
                              StepResult.FAILED, str(e))
                continue
            except Exception as e:                      # noqa: BLE001
                self._record('vault_folders', name, f'create-{ftype}',
                              StepResult.FAILED, f'{type(e).__name__}: {e}')
                continue

            if not new_uid:
                self._record('vault_folders', name, op_label,
                              StepResult.FAILED, 'client returned empty UID')
                continue

            uid_map[src_uid] = new_uid
            ok_notes = f'target_uid={new_uid[:12]}'
            if self.resume:
                ok_notes += ' (created — was missing on resume)'
            if status_note:
                ok_notes = f'{ok_notes} {status_note}'.strip()
            self._record('vault_folders', name, op_label,
                          StepResult.SUCCESS, ok_notes)
            self._pace()

        return uid_map

    # ─── Per-action materializers (5-option dispatch table) ────────────────

    def _materialize_divergent(self, vf, decision, existing_target_names,
                                 nsfp_module):
        """Dispatch a divergent subfolder to its materializer.

        Returns (new_uid, op_label, status_note). new_uid is '' on
        client failure or None on materializer-level rejection (e.g.,
        unresolved conflict, true-nested unsupported).
        """
        action = decision.get('proposed_target_action')
        if action == nsfp_module.ACTION_PROMOTE:
            return self._apply_promote_sibling(
                vf, decision, existing_target_names, nsfp_module)
        if action == nsfp_module.ACTION_FLATTEN:
            return self._apply_flatten_prefix(
                vf, decision, existing_target_names, nsfp_module)
        if action == nsfp_module.ACTION_TRUE_NESTED:
            return self._apply_promote_true_nested(
                vf, decision, nsfp_module)
        # ACTION_PRESERVE handled by the caller (not divergent).
        return (None, f'create-shared_folder_folder',
                f'unknown divergent action {action!r}')

    def _apply_preserve_subfolder(self, vf, tgt_parent):
        """Materialize as shared_folder_folder under tgt_parent.

        Kept as a named method for symmetry with the divergent options
        and to give the dispatch table a complete picture; the calling
        path uses it inline for performance.
        """
        return self.client.add_subfolder(
            name=vf.get('name', ''),
            parent_sf_folder_uid=tgt_parent,
        )

    def _apply_promote_sibling(self, vf, decision,
                                existing_target_names, nsfp_module):
        """Create a top-level SF named `Parent - Child` (sibling promotion)."""
        name_candidate = (decision.get('proposed_promoted_name')
                          or vf.get('name', ''))
        policy = (decision.get('conflict_resolution')
                  or nsfp_module.CONFLICT_ERROR)
        resolved, status = nsfp_module.resolve_name_collision(
            name_candidate, existing_target_names, policy=policy)
        if status == 'error':
            return (None, 'promote-to-sibling',
                    f'name collision unresolved (policy={policy}, '
                    f'name={name_candidate!r})')
        if status == 'merged':
            # operator chose merge — record but do not create.
            return ('', 'promote-to-sibling-merged',
                    f'merged into existing SF {resolved!r}')
        new_uid = self.client.add_shared_folder(
            name=resolved, parent_uid='',
            default_manage_users=bool(vf.get('default_manage_users')),
            default_manage_records=bool(vf.get('default_manage_records')),
            default_can_edit=bool(vf.get('default_can_edit')),
            default_can_share=bool(vf.get('default_can_share')),
        )
        if new_uid:
            existing_target_names.add(resolved)
        note = ''
        if status == 'suffixed':
            note = f'suffixed to {resolved!r} (policy=suffix)'
        return (new_uid, 'promote-to-sibling', note)

    def _apply_flatten_prefix(self, vf, decision,
                                existing_target_names, nsfp_module):
        """Create a top-level SF named `Parent__Child` (flat naming)."""
        name_candidate = (decision.get('proposed_promoted_name')
                          or vf.get('name', ''))
        policy = (decision.get('conflict_resolution')
                  or nsfp_module.CONFLICT_ERROR)
        resolved, status = nsfp_module.resolve_name_collision(
            name_candidate, existing_target_names, policy=policy)
        if status == 'error':
            return (None, 'flatten-with-prefix',
                    f'name collision unresolved (policy={policy}, '
                    f'name={name_candidate!r})')
        if status == 'merged':
            return ('', 'flatten-with-prefix-merged',
                    f'merged into existing SF {resolved!r}')
        new_uid = self.client.add_shared_folder(
            name=resolved, parent_uid='',
            default_manage_users=bool(vf.get('default_manage_users')),
            default_manage_records=bool(vf.get('default_manage_records')),
            default_can_edit=bool(vf.get('default_can_edit')),
            default_can_share=bool(vf.get('default_can_share')),
        )
        if new_uid:
            existing_target_names.add(resolved)
        note = ''
        if status == 'suffixed':
            note = f'suffixed to {resolved!r} (policy=suffix)'
        return (new_uid, 'flatten-with-prefix', note)

    def _apply_promote_true_nested(self, vf, decision, nsfp_module):
        """Forward-compat stub — raises until Commander ships nested-SF support."""
        raise NotImplementedError(
            'promote-to-true-nested needs Commander nested-SF '
            'support (audit confirmed unavailable through v17.2.15); '
            f'subfolder UID={vf.get("uid", "")!r}')

    def step_sf_membership(self, membership_path, flat_fallback_path=None):
        """Apply shared folder membership with automatic flattened-fallback.

        Paths may be None to indicate missing files.

        Resume note: this step is NOT state-reconciled like steps 1-10
        and 12. Commander's `apply-membership` is mostly idempotent at
        the SDK level (already-present members are no-ops or warnings)
        but the per-key visibility provided by other steps' resume path
        is absent here. Operators running `--resume` should verify
        post-run that no duplicate-membership warnings were captured by
        SilentFailureCapture.
        """
        if not membership_path:
            self._record('sf_membership', 'Shared folders', 'apply-membership',
                         StepResult.SKIPPED, 'No membership file')
            return
        if self.resume:
            logging.info(
                'step_sf_membership: not state-reconciled — re-runs '
                'apply-membership and relies on Commander natural '
                'idempotency. Verify duplicate-membership warnings '
                'in the audit log post-run.'
            )
            self._record('sf_membership', 'All shared folders',
                          'apply-membership',
                          StepResult.SUCCESS,
                          'resume mode — relying on Commander idempotency')
        if self.client.apply_membership(membership_path):
            if not self.resume:
                self._record('sf_membership', 'All shared folders', 'apply-membership',
                             StepResult.SUCCESS, 'Native restore')
            return
        if flat_fallback_path and self.client.apply_membership(flat_fallback_path):
            self._record('sf_membership', 'All shared folders (flat)', 'apply-membership',
                         StepResult.SUCCESS, 'Flattened fallback')
            return
        self._record('sf_membership', 'Shared folders', 'apply-membership',
                     StepResult.FAILED,
                     'Both full and flat failed' if flat_fallback_path else 'No flat fallback')

    # Step 12 --------------------------------------------------------------

    def step_validate(self, expected_counts):
        """Compare live target counts to the source expected_counts dict.

        expected_counts keys: 'nodes', 'teams', 'roles' (users optional).
        Returns a dict of observed vs expected vs match flags, plus the
        aggregate summary counts (RESTORED/SKIPPED/FAILED) from prior steps.
        """
        scope = self.scope_node or ''
        observed = {
            'nodes': self.client.count_nodes(scope),
            'teams': self.client.count_teams(scope),
            'roles': self.client.count_roles(scope),
            'users': self.client.count_users(scope),
        }
        report = {
            'observed': observed,
            'expected': dict(expected_counts),
            'match': {},
            'summary': dict(self.counters),
        }
        for k in ('nodes', 'teams', 'roles'):
            if k in expected_counts:
                report['match'][k] = (observed[k] == expected_counts[k])
        return report
