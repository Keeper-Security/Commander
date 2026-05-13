"""Build an inventory directly from Commander's in-memory enterprise data.

`InventoryAssembler` (inventory.py) consumes staged CSV/JSON files from disk
— the format produced by `migration_scripts/00d_migration_inventory.sh`.
This module provides the equivalent assembly path starting from the live
`params.enterprise` dict, so the `plan` subcommand can skip the CSV staging
step entirely when a Commander session is attached.

Output shape is identical to `InventoryAssembler.build()`, so downstream
consumers (`reconcile`, `verify`, `transition-check`, `structure`) don't
care which source produced the inventory.

The node-scoping filter (--node X) mirrors the bash script: only the named
subtree + its descendants make it into the inventory. `params.enterprise`
carries parent_id pointers, so we compute the descendant set up-front and
filter every entity against it.
"""

import datetime
import hashlib
import json
import logging


def _node_displayname(node, enterprise_name):
    """Resolve a node's display name, normalizing the source enterprise
    root to `enterprise_name`.

    Commander stores the enterprise-root node with any of:
      - an empty/missing displayname (fall back to enterprise_name)
      - the enterprise_name itself as displayname (already fine)
      - a literal 'root' / 'Root' (observed live on 2026-04-20 on the
        'My company' source tenant — caused every top-level team +
        role to record node='root', which downstream commands can't
        resolve on the target tenant)

    The 'root' literal is only treated as a source-root marker when
    the node has NO parent_id — a legitimately-named child folder
    happening to be called 'root' stays as-is.
    """
    data = node.get('data', {}) or {}
    name = data.get('displayname') or ''
    is_root = not node.get('parent_id')
    if is_root:
        if not name or name.lower() == 'root':
            return enterprise_name or ''
    return name


def _build_node_path_map(ent):
    """{node_id: "Root\\Sub\\Team"} for full-path rendering."""
    name_by_id = {}
    parent_by_id = {}
    for n in ent.get('nodes', []) or []:
        nid = n.get('node_id')
        name_by_id[nid] = _node_displayname(n, ent.get('enterprise_name', ''))
        parent_by_id[nid] = n.get('parent_id')

    def full_path(nid):
        parts = []
        cur = nid
        guard = 0
        while cur is not None and guard < 32:
            parts.append(name_by_id.get(cur, ''))
            cur = parent_by_id.get(cur)
            guard += 1
        return '\\'.join(reversed([p for p in parts if p]))

    return {nid: full_path(nid) for nid in name_by_id}


def _compute_descendants(ent, scope_node_name):
    """Return the set of node_ids in the scope subtree (including scope root).

    Empty string scope_node_name means "no scoping" — returns None to signal
    "accept everything".
    """
    if not scope_node_name:
        return None
    enterprise_name = ent.get('enterprise_name', '')
    scope_lower = scope_node_name.lower()

    # Find the scope root node(s) by name
    scope_ids = set()
    children_by_parent = {}
    for n in ent.get('nodes', []) or []:
        nid = n.get('node_id')
        name = _node_displayname(n, enterprise_name)
        if name.lower() == scope_lower:
            scope_ids.add(nid)
        children_by_parent.setdefault(n.get('parent_id'), []).append(nid)

    # BFS down from every matching root
    stack = list(scope_ids)
    descendants = set()
    while stack:
        cur = stack.pop()
        if cur in descendants:
            continue
        descendants.add(cur)
        stack.extend(children_by_parent.get(cur, []))
    return descendants


def build_node_entities(ent, descendants, path_map, prefix):
    out = []
    enterprise_name = ent.get('enterprise_name', '')
    for n in ent.get('nodes', []) or []:
        nid = n.get('node_id')
        if descendants is not None and nid not in descendants:
            continue
        name = _node_displayname(n, enterprise_name)
        if prefix and not name.startswith(prefix):
            continue
        parent_name = ''
        if n.get('parent_id'):
            parent_node = next(
                (p for p in ent.get('nodes', []) or [] if p.get('node_id') == n['parent_id']),
                None,
            )
            if parent_node:
                parent_name = _node_displayname(parent_node, enterprise_name)
        data = n.get('data', {}) or {}
        out.append({
            'id': str(nid),
            'name': name,
            'parent': parent_name,
            'isolated': bool(data.get('restrict_visibility', False)),
            'user_count': 0,  # will be backfilled
            'team_count': 0,
            'role_count': 0,
        })
    return out


def _backfill_entity_counts(nodes_out, ent, descendants):
    """Populate user_count / team_count / role_count on every node dict."""
    by_id = {n['id']: n for n in nodes_out}
    for u in ent.get('users', []) or []:
        nid = u.get('node_id')
        if nid is None:
            continue
        if descendants is not None and nid not in descendants:
            continue
        n = by_id.get(str(nid))
        if n:
            n['user_count'] += 1
    for t in ent.get('teams', []) or []:
        nid = t.get('node_id')
        if nid is None:
            continue
        if descendants is not None and nid not in descendants:
            continue
        n = by_id.get(str(nid))
        if n:
            n['team_count'] += 1
    for r in ent.get('roles', []) or []:
        nid = r.get('node_id')
        if nid is None:
            continue
        if descendants is not None and nid not in descendants:
            continue
        n = by_id.get(str(nid))
        if n:
            n['role_count'] += 1


def restricts_code(team):
    # Commander's team object uses `restrict_sharing` (not `restrict_share`);
    # mismatched key silently strips the re-share restriction from every
    # migrated team. Verified against live params.enterprise['teams'] —
    # keys are restrict_edit / restrict_sharing / restrict_view.
    code = ''
    if team.get('restrict_edit'):
        code += 'R'
    if team.get('restrict_view'):
        code += ' W' if code else 'W'
    if team.get('restrict_sharing') or team.get('restrict_share'):
        code += ' S' if code else 'S'
    return code


def build_team_entities(ent, descendants, path_map, prefix):
    out = []
    for t in ent.get('teams', []) or []:
        nid = t.get('node_id')
        if descendants is not None and nid not in descendants:
            continue
        name = t.get('name', '')
        if prefix and not name.startswith(prefix):
            continue
        # `queued_users` are users the admin invited to the team BEFORE
        # those users accepted the tenant-level invite. Commander holds
        # them in the team's queue; they become full members once the
        # underlying user accepts. On target we must re-invite them to
        # the team after their tenant invite is accepted, otherwise the
        # team membership silently fails to form.
        queued = []
        for qu in t.get('queued_users') or []:
            if isinstance(qu, dict):
                email = (qu.get('username') or qu.get('email') or '').strip()
                if email:
                    queued.append(email)
            elif isinstance(qu, str) and qu.strip():
                queued.append(qu.strip())
        out.append({
            'uid': t.get('team_uid', '') or t.get('uid', ''),
            'name': name,
            'restricts': restricts_code(t),
            'node': path_map.get(nid, ''),
            'user_count': 0,
            'role_count': 0,
            'queued_users': queued,
        })
    return out


def build_role_pivots(ent):
    """Pivot Commander's flat role_* lists into per-role dicts.

    Commander keeps `managed_nodes`, `role_privileges`, `role_enforcements`,
    `role_users`, `role_teams` as flat tables on `params.enterprise` — one
    row per (role_id, target). structure.py's step_managed_nodes /
    step_enforcements / step_role_users / step_role_teams expect the
    per-role aggregations embedded on each role entity. We do the pivot
    here once and memoize by role_id.
    """
    # node_id → node name (for resolving managed_node_id → node_name)
    enterprise_name = ent.get('enterprise_name', '')
    node_by_id = {}
    for n in ent.get('nodes', []) or []:
        node_by_id[n.get('node_id')] = _node_displayname(n, enterprise_name)
    # team_uid → team name
    team_by_uid = {t.get('team_uid'): t.get('name', '') for t in ent.get('teams', []) or []}

    # Bug 80 — for each source node, also record its parent_node_id
    # so disambiguation context can flow into the captured
    # managed_nodes entry. When source has multiple sibling nodes
    # with the same leaf name (Bug 73 territory), `node_name` alone
    # is ambiguous; (`source_node_id`, parent_path) preserves the
    # exact source binding so migration can resolve the right
    # post-rename target node.
    parent_id_by_id = {}
    for n in ent.get('nodes', []) or []:
        parent_id_by_id[n.get('node_id')] = n.get('parent_id')

    def _node_path(node_id):
        """Return source full path `Root\\Sub1\\Leaf` for the node id.
        Walks parent chain via `parent_id_by_id`. Empty when the chain
        breaks (orphan). Used as a stable, human-readable disambiguator
        the migration side can match against capture-target-state."""
        parts = []
        seen = set()
        cur = node_id
        while cur is not None and cur not in seen:
            seen.add(cur)
            parts.append(node_by_id.get(cur, ''))
            cur = parent_id_by_id.get(cur)
        return '\\'.join(reversed([p for p in parts if p]))

    managed = {}
    for mn in ent.get('managed_nodes', []) or []:
        rid = mn.get('role_id')
        if rid is None:
            # Orphan managed-nodes row with no role_id — dropping it
            # silently would lose admin grants. Log once per orphan.
            logging.warning('managed_nodes row missing role_id: %r', mn)
            continue
        mnid = mn.get('managed_node_id')
        managed.setdefault(rid, []).append({
            'node_name': node_by_id.get(mnid, ''),
            # Bug 80 disambiguation context — backwards-compatible:
            # pre-Bug-80 inventories don't carry these keys; the
            # migration side falls back to `node_name`-only lookup
            # when they're missing.
            'source_node_id': str(mnid) if mnid is not None else '',
            'source_parent_path': _node_path(mnid),
            'cascade': bool(mn.get('cascade_node_management', False)),
            'privileges': [],    # filled next
        })

    # role_id → managed_node_id → entry (for appending privileges)
    mn_index = {}
    for rid, entries in managed.items():
        mn_index[rid] = {e['node_name']: e for e in entries}

    for rp in ent.get('role_privileges', []) or []:
        rid = rp.get('role_id')
        node_name = node_by_id.get(rp.get('managed_node_id'), '')
        priv = rp.get('privilege', '')
        if rid is None or not priv:
            logging.warning('role_privileges row incomplete: %r', rp)
            continue
        if rid not in mn_index:
            # Privilege references a role that has no managed_nodes row
            # — orphaned after a node was deleted, or a sync glitch.
            # Dropping silently would migrate a role with the admin
            # designation but without the privileges. Warn.
            logging.warning(
                'role_privileges row for role_id=%s references '
                'managed_node_id=%s that has no matching managed_nodes '
                'entry — privilege %r dropped', rid,
                rp.get('managed_node_id'), priv)
            continue
        entry = mn_index[rid].get(node_name)
        if entry is None:
            logging.warning(
                'role_privileges row for role_id=%s managed_node_id=%s '
                'resolved to node_name=%r which is not in this role\'s '
                'managed_nodes entries — privilege %r dropped',
                rid, rp.get('managed_node_id'), node_name, priv)
            continue
        entry['privileges'].append(priv)

    enforcements = {}
    for re_ in ent.get('role_enforcements', []) or []:
        rid = re_.get('role_id')
        if rid is None:
            continue
        enforcements.setdefault(rid, {}).update(re_.get('enforcements', {}) or {})

    # Build enterprise_user_id -> email lookup so role_users materializes
    # as [{username: email, ...}] dicts — matches the shape
    # structure.plan_role_user_assignments expects. Raw int IDs were
    # landing in role['users'] and breaking the structure stage when
    # auto-migrate ran against a real tenant (2026-04-20).
    email_by_user_id = {}
    for u in ent.get('users', []) or []:
        u_id = u.get('enterprise_user_id')
        email = (u.get('username') or u.get('email') or '').strip()
        if u_id is not None and email:
            email_by_user_id[u_id] = email

    role_users = {}
    for ru in ent.get('role_users', []) or []:
        rid = ru.get('role_id')
        uid = ru.get('enterprise_user_id')
        if rid is None or uid is None:
            continue
        email = email_by_user_id.get(uid, '')
        if not email:
            # Orphaned role_users row — user was deleted but the
            # join-table entry lingered. Drop with a warning.
            logging.warning('role_users row references missing '
                            'enterprise_user_id=%s — dropped', uid)
            continue
        role_users.setdefault(rid, []).append({'username': email})

    # Dedupe role_teams at pivot time. Commander occasionally emits
    # duplicate rows in `role_teams` for the same (role_id, team_uid)
    # pair after a sync glitch — we'd otherwise issue duplicate
    # `enterprise-team --add-user` calls and hit 'already in role' errors.
    role_teams_sets = {}
    for rt in ent.get('role_teams', []) or []:
        rid = rt.get('role_id')
        tuid = rt.get('team_uid')
        if rid is None or not tuid:
            continue
        name = team_by_uid.get(tuid, '')
        if name:
            role_teams_sets.setdefault(rid, set()).add(name)
    role_teams = {rid: sorted(names) for rid, names in role_teams_sets.items()}

    return managed, enforcements, role_users, role_teams


def _source_record_type_id_to_name(params, communicator=None):
    # Source-side id_to_name for `record_types`-typed enforcement values
    # (Bug 60 / Task #17). The translator at enforcement_direct.py was
    # historically called with TARGET params at write-time — standard
    # types resolved (UIDs happen to be stable), but custom enterprise
    # types didn't and emitted `<unknown:NNN>` tokens that Commander
    # rejected. Querying source at capture-time gives portable names
    # the target's CLI parser can re-resolve to its own UIDs natively.
    out = {}
    try:
        if communicator is None:
            from keepercommander import api
            from keepercommander.proto import record_pb2
            rq = record_pb2.RecordTypesRequest()
            rq.standard = True
            rq.user = True
            rq.enterprise = True
            rs = api.communicate_rest(
                params, rq, 'vault/get_record_types',
                rs_type=record_pb2.RecordTypesResponse)
            for rti in rs.recordTypes or []:
                try:
                    rto = json.loads(rti.content)
                    name = rto.get('$id')
                    if name:
                        out[rti.recordTypeId] = name
                except (TypeError, ValueError):
                    continue
        else:
            out = communicator() or {}
    except Exception as e:                                 # noqa: BLE001
        logging.warning(
            '_source_record_type_id_to_name: get_record_types '
            'unavailable, restrict_record_types enforcement values '
            'will retain raw IDs: %r', e)
    return out


def _translate_record_types_enforcement(value, id_to_name):
    # Convert `{"std":[ids],"ent":[ids]}` JSON to comma-separated
    # NAMES using the supplied source id_to_name. Idempotent: returns
    # value unchanged if it's already a string without `{`. Empty input
    # returns 'all' (Commander's keyword for cleared restriction).
    #
    # Bug 66 (rehearsal-11): source `restrict_record_types` enforcements
    # sometimes reference record-type IDs that no longer exist on source
    # itself — dangling references from deleted enterprise types. The
    # CLI parser rejects the whole batch when ANY token in the value
    # is unrecognized. Filter out unresolvable IDs and log them so the
    # operator can audit + fix on source if needed. Source data-quality
    # issue, not plugin bug, but plugin can salvage the resolvable
    # subset rather than fail the whole enforcement.
    if isinstance(value, str) and '{' not in value:
        return value
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return value
    if not isinstance(parsed, dict):
        return value
    std_ids = list(parsed.get('std') or [])
    ent_ids = list(parsed.get('ent') or [])
    if not (std_ids or ent_ids):
        return 'all'
    names = []
    dangling = []
    for rid in std_ids + ent_ids:
        n = id_to_name.get(rid)
        if n:
            names.append(n)
        else:
            dangling.append(rid)
    if dangling:
        logging.warning(
            'restrict_record_types: %d dangling record-type ID(s) on '
            'source dropped from enforcement value (deleted custom '
            'types still referenced): %s. Source data-quality issue; '
            'fix on source by either restoring the types or '
            'updating the enforcement.',
            len(dangling), dangling)
    if not names:
        # All IDs unresolved — emit 'all' (Commander's cleared keyword)
        # rather than empty string which the CLI parser rejects.
        return 'all'
    return ','.join(names)


# Bug 63 / Upstream-4 (re-classified 2026-05-03) — deprecated source-side
# enforcement key aliases that target Commander/server doesn't accept
# under the legacy name + semantics. Mapping is `legacy_key →
# (canonical_key, value_transformer)`. Originally catalogued as
# Upstream-4 "environmental BOOLEAN rejection"; investigation traced
# the rejection to the legacy key being recognized server-side by
# enforcementId but the semantic-inversion not being applied to its
# value. e.g. `allow_can_edit_external_shares=true` should be
# rewritten to `restrict_can_edit_external_shares=false` (semantic
# inversion: ALLOW true == RESTRICT false).
def _invert_bool_value(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return 'false' if value.lower() in ('true', '1', 'yes', 'on') else 'true'
    return value


_DEPRECATED_ENFORCEMENT_KEYS = {
    'allow_can_edit_external_shares': (
        'restrict_can_edit_external_shares', _invert_bool_value),
}


def _remap_role_enforcement_values(roles, *, record_types_id_to_name,
                                    enforcement_types=None):
    # Walk each role's enforcements in-place, translating tenant-local-ID
    # values to portable bridge attributes at source-capture time.
    # Handles `record_types`-typed keys (Task #17), legacy-alias key
    # rewrites (Upstream-4 reclassified). Extends in Task #16
    # (account_share user_id → email) and Task #13 (fileRef).
    # `enforcement_types` is the {key: type} map (defaults to Commander's
    # ENFORCEMENTS); injected so unit tests don't have to monkey-patch
    # the keepercommander module.
    if enforcement_types is None:
        try:
            from keepercommander.constants import ENFORCEMENTS
            enforcement_types = ENFORCEMENTS
        except ImportError:
            enforcement_types = {}
    for role in roles or []:
        enfs = role.get('enforcements') or {}
        if not enfs:
            continue
        for key, value in list(enfs.items()):
            klow = (key or '').lower()
            # Bug 63 / Upstream-4 — deprecated alias pre-rewrite.
            if klow in _DEPRECATED_ENFORCEMENT_KEYS:
                new_key, transform = _DEPRECATED_ENFORCEMENT_KEYS[klow]
                enfs.pop(key)
                enfs[new_key] = transform(value)
                logging.info(
                    'enforcement remap: legacy %r=%r → canonical %r=%r '
                    'on role %r (Upstream-4 reclassified to plugin '
                    'deprecated-alias handling)',
                    key, value, new_key, enfs[new_key],
                    role.get('name', ''))
                continue
            if enforcement_types.get(klow) == 'record_types':
                enfs[key] = _translate_record_types_enforcement(
                    value, record_types_id_to_name)


def build_role_entities(ent, descendants, path_map, prefix):
    out = []
    managed_by_role, enf_by_role, users_by_role, teams_by_role = build_role_pivots(ent)
    for r in ent.get('roles', []) or []:
        nid = r.get('node_id')
        if descendants is not None and nid not in descendants:
            continue
        data = r.get('data', {}) or {}
        name = data.get('displayname') or r.get('name', '')
        if prefix and not name.startswith(prefix):
            continue
        # Commander keeps the "default for new users" flag on the outer
        # role dict under `new_user_inherit`, NOT in data.default_role.
        # Capturing the wrong key silently loses the flag on migration.
        new_user_flag = bool(r.get('new_user_inherit', False))
        rid = r.get('role_id')
        # Prefer pivoted data from top-level enterprise tables (the
        # real SDK shape). Fall back to inline fields on the role dict
        # itself — some fixtures and older formats put them there.
        pivoted_managed = managed_by_role.get(rid, [])
        pivoted_enf = enf_by_role.get(rid, {})
        pivoted_users = users_by_role.get(rid, [])
        pivoted_teams = teams_by_role.get(rid, [])
        out.append({
            'id': rid,
            'name': name,
            'node': path_map.get(nid, ''),
            'new_user': new_user_flag,
            # Keep `default_role` for backwards compatibility with
            # any pre-1.1.1 inventory JSON that carried it. Same value.
            'default_role': new_user_flag,
            'visible_below': bool(r.get('visible_below', False)),
            'managed_nodes': pivoted_managed or (r.get('managed_nodes') or []),
            'enforcements': pivoted_enf or (r.get('enforcements') or {}),
            'users': pivoted_users or (r.get('users') or []),
            'teams': pivoted_teams or (r.get('teams') or []),
        })
    return out


def build_user_entities(ent, descendants, path_map, prefix, hsf_map=None):
    # Users-in-scope: either they live on a scoped node OR they're in a scoped
    # team/role. Prefix filter is applied to the user's team/role names.
    scoped_team_names = set()
    scoped_role_names = set()
    if descendants is not None:
        for t in ent.get('teams', []) or []:
            if t.get('node_id') in descendants:
                scoped_team_names.add(t.get('name', ''))
        for r in ent.get('roles', []) or []:
            if r.get('node_id') in descendants:
                data = r.get('data', {}) or {}
                scoped_role_names.add(data.get('displayname') or r.get('name', ''))

    out = []
    for u in ent.get('users', []) or []:
        nid = u.get('node_id')
        user_teams = [t.get('team_name', t.get('name', ''))
                      for t in u.get('teams', []) or [] if isinstance(t, dict)]
        user_roles = [r.get('role_name', r.get('name', ''))
                      for r in u.get('roles', []) or [] if isinstance(r, dict)]

        if descendants is not None:
            on_scoped_node = nid in descendants
            on_scoped_team = any(tn in scoped_team_names for tn in user_teams)
            on_scoped_role = any(rn in scoped_role_names for rn in user_roles)
            if not (on_scoped_node or on_scoped_team or on_scoped_role):
                continue

        email = u.get('username', '') or u.get('email', '')
        if prefix and not email.startswith(prefix):
            # Also allow if any team/role matches prefix (structure-only roster)
            if not any(n.startswith(prefix) for n in user_teams + user_roles):
                continue

        aliases_raw = u.get('aliases', []) or []
        aliases = []
        for a in aliases_raw:
            if isinstance(a, str) and a and a.lower() != email.lower():
                aliases.append(a)
            elif isinstance(a, dict):
                ae = a.get('username', '') or a.get('email', '')
                if ae and ae.lower() != email.lower():
                    aliases.append(ae)

        hsf_for_user = sorted((hsf_map or {}).get(email.strip().lower(), []))
        # SSO-provisioned detection — any of these signals means the user's
        # identity and password live with the IdP, not Keeper. Inviting by
        # email won't work: the IdP must re-provision on the new tenant
        # via SCIM, and the SAML ACS URL changes too.
        sso_sp_id = (u.get('sso_service_provider_id')
                      or u.get('sso_provider_id') or 0)
        is_sso = bool(sso_sp_id) or bool(u.get('is_sso') or u.get('sso'))
        out.append({
            'id': str(u.get('enterprise_user_id', '') or ''),
            'email': email,
            'status': u.get('status', ''),
            'transfer_status': u.get('transfer_status', ''),
            'node': path_map.get(nid, ''),
            'teams': user_teams,
            'roles': user_roles,
            'alias': '\n'.join(aliases),
            'aliases': aliases,
            '2fa_enabled': bool(u.get('two_factor_enabled', False)),
            'job_title': u.get('job_title', ''),
            'hide_shared_folders_teams': hsf_for_user,
            'is_sso': is_sso,
            'sso_service_provider_id': str(sso_sp_id) if sso_sp_id else '',
        })
    return out


_HSF_MARKER = '(No Shared Folders)'


def scrape_team_hsf_users(text_output, team_name):
    """Parse `enterprise-team TEAM` stdout. Return list of user emails whose
    user_type==2 (hide_shared_folders=on) — identified by the line-suffix
    marker '(No Shared Folders)'.

    Commander prints one user per line, with the marker appended when the
    user has hsf set for that team. Same regex idea as bash/awk reference.
    """
    if not text_output or _HSF_MARKER not in text_output:
        return []
    emails = []
    for line in text_output.splitlines():
        if _HSF_MARKER not in line:
            continue
        for tok in line.split():
            if '@' in tok:
                emails.append(tok.strip())
                break
    return emails


def _capture_team_stdout(team_cmd, params, team_name):
    """Invoke EnterpriseTeamCommand with stdout redirected to a buffer."""
    import contextlib
    import io
    import sys

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            team_cmd.execute(params, team=[team_name])
    except Exception:                                   # noqa: BLE001
        # Any Commander-side error is non-fatal for the scrape — we just
        # return whatever we captured (possibly empty).
        pass
    return buf.getvalue()


def build_hsf_map(params, team_names):
    """Return {email_lower: set(team_names_with_hsf)} by scraping team output."""
    from keepercommander.commands.enterprise import EnterpriseTeamCommand
    cmd = EnterpriseTeamCommand()
    mapping = {}
    for team in team_names:
        if not team:
            continue
        output = _capture_team_stdout(cmd, params, team)
        for email in scrape_team_hsf_users(output, team):
            mapping.setdefault(email.strip().lower(), set()).add(team)
    return mapping


def _build_record_folder_map(params):
    """Return {record_uid: (folder_uid, folder_type)} covering both
    personal-folder placement (subfolder_record_cache) and SF-membership
    (shared_folder_cache[...].records).

    folder_uid is '' when the record is at the vault root (no folder).
    folder_type is one of: 'root', 'user_folder', 'shared_folder',
    'shared_folder_folder'. When a record is reachable via multiple paths
    (admins can put the same record in several folders), the first match
    wins — the UI presents the same record then too.
    """
    fc = getattr(params, 'folder_cache', {}) or {}
    out = {}

    # 1. Personal folders (user_folder + root). subfolder_record_cache is
    #    a dict {folder_uid: set(record_uid, …)} where '' means vault root.
    src = getattr(params, 'subfolder_record_cache', {}) or {}
    for folder_uid, record_uids in src.items():
        folder = fc.get(folder_uid) if folder_uid else None
        ftype = (getattr(folder, 'type', '') or '') if folder else 'root'
        for r_uid in (record_uids or ()):
            out.setdefault(r_uid, (folder_uid or '', ftype))

    # 2. Shared folders + shared-folder subfolders. These use a separate
    #    cache — shared_folder_cache[uid].records is a list of dicts
    #    carrying record_uid + (optionally) can_edit/can_share.
    sfc = getattr(params, 'shared_folder_cache', {}) or {}
    for sf_uid, sf in sfc.items():
        recs = sf.get('records', []) if isinstance(sf, dict) else []
        for rec in (recs or ()):
            r_uid = rec.get('record_uid', '') if isinstance(rec, dict) else rec
            if not r_uid:
                continue
            # Subfolder placement inside an SF lives on the record entry
            # as folder_uid (the shared_folder_folder UID).
            sff_uid = (rec.get('folder_uid') or '') if isinstance(rec, dict) else ''
            if sff_uid:
                out.setdefault(r_uid, (sff_uid, 'shared_folder_folder'))
            else:
                out.setdefault(r_uid, (sf_uid, 'shared_folder'))

    return out


def _folder_name_path(folder_cache, folder_uid, max_depth=32):
    """Join folder names from folder_uid up to the vault root with '/'.
    Empty string when folder_uid is empty (record is at vault root)."""
    if not folder_uid:
        return ''
    parts = []
    cur = folder_uid
    guard = 0
    while cur and guard < max_depth:
        node = folder_cache.get(cur)
        if node is None:
            break
        name = getattr(node, 'name', '') or ''
        parts.append(name)
        cur = getattr(node, 'parent_uid', '') or ''
        guard += 1
    return '/'.join(reversed(parts))


def build_record_types(params, communicator=None):
    """Fetch enterprise + user-defined record types from the live tenant.

    Bug 40 — pre-fix `--inventory` mode emitted no record_types, so
    `_load_from_inventory` set `record_types_path=''` and step_record_types
    short-circuited. Records of custom enterprise types (PAM-heavy
    customers in particular have `pamMachine`, `pamUser`, `pamDatabase`
    as enterprise types) imported on target with the right `$type` after
    Bug 34, but the type DEFINITION was absent. Editing those records
    on target then surfaces "unknown record type" or strips custom fields.

    Returns the list shape consumed by Commander's `LoadRecordTypeCommand`:
    `[{record_type_name, description, fields:[{$type, label?, required?}]}, ...]`.
    Standard types are excluded (they exist on every tenant), so the
    resulting list contains only what the migration must propagate.

    Falls back to an empty list if the proto-level call fails (offline,
    older Commander, missing scopes). The migration then runs as if the
    pre-Bug-40 behaviour: structure-restore proceeds, records still
    import, but custom types still aren't created on target. Operator
    workaround documented in LIVE_BUGS Bug 40 stays available.
    """
    out = []
    try:
        if communicator is None:
            from keepercommander import api
            from keepercommander.proto import record_pb2
            rq = record_pb2.RecordTypesRequest()
            # Standard types ship with every tenant — never need migrating.
            rq.standard = False
            rq.user = True
            rq.enterprise = True
            rs = api.communicate_rest(
                params, rq, 'vault/get_record_types',
                rs_type=record_pb2.RecordTypesResponse)
            entries = list(rs.recordTypes or [])
            raw = [(rti.recordTypeId, rti.content) for rti in entries]
        else:
            raw = communicator() or []
    except Exception as e:                                 # noqa: BLE001
        logging.warning(
            'build_record_types: get_record_types unavailable, '
            'inventory will carry no record_types: %r', e)
        return out

    for _, content_str in raw:
        try:
            content = json.loads(content_str)
        except (TypeError, ValueError):
            continue
        if not isinstance(content, dict):
            continue
        type_name = content.get('$id')
        if not type_name:
            continue
        # Translate API shape → LoadRecordTypeCommand input shape.
        # `$ref` (API) → `$type` (loader). Names mirror what
        # `LoadRecordTypeCommand.execute` reads.
        fields = []
        for f in content.get('fields') or []:
            if not isinstance(f, dict):
                continue
            ref = f.get('$ref') or f.get('$type')
            if not ref:
                continue
            fld = {'$type': ref}
            if f.get('label'):
                fld['label'] = f['label']
            if f.get('required') is True:
                fld['required'] = True
            fields.append(fld)
        out.append({
            'record_type_name': type_name,
            'description': content.get('description', '') or '',
            'fields': fields,
        })
    return out


def build_record_entities(params, prefix, include_fields=False):
    """Emit a per-record summary list from params.record_cache.

    Each entry is the same shape as inventory.py::summarize_record so
    phase_records can diff either direction, plus PR-A additions:
      folder_uid  — UID of the folder the record lives in ('' = root)
      folder_path — '/'-joined folder names from root to immediate parent
      folder_type — 'root' | 'user_folder' | 'shared_folder'
                     | 'shared_folder_folder'
    """
    from .inventory import summarize_record
    from keepercommander import api
    import json as _json

    cache = getattr(params, 'record_cache', None) or {}
    folder_cache = getattr(params, 'folder_cache', {}) or {}
    record_folder_map = _build_record_folder_map(params)

    # Bug 36 — `params.record_cache[uid]['shares']` is NOT populated by
    # `sync_down`; it requires a separate `vault/get_records_details`
    # call (Commander's `api.get_record_shares`). Pre-fix the inventory's
    # direct_shares list was always empty, so the migration plan
    # under-reported pre-flight share counts and downstream consumers
    # (estimate, manual-actions, plan-report) couldn't see real share
    # workload. Bug 19 fixed the records-shares-extract path; this is
    # the same fix for the inventory path.
    #
    # Batch the lazy fetch — one API call covers every record we'll
    # visit (in scope after prefix filter). Avoids N+1 round-trips
    # for large vaults. Best-effort: a probe failure (offline,
    # missing endpoint) leaves direct_shares empty, same as pre-fix
    # behavior, so the inventory still emits even if the share
    # endpoint is unreachable.
    uids_needing_shares = [
        uid for uid, c in cache.items()
        if not (c.get('shares') if isinstance(c, dict) else None)
    ]
    if uids_needing_shares:
        try:
            api.get_record_shares(params, uids_needing_shares)
        except Exception as e:                          # noqa: BLE001
            logging.debug('live_inventory: batch share probe failed: %r', e)

    out = []
    for uid, cached in cache.items():
        rec = api.get_record(params, uid)
        if rec is None or not rec.title:
            continue
        if prefix and not rec.title.startswith(prefix):
            continue
        data_raw = cached.get('data_unencrypted', b'{}')
        if isinstance(data_raw, bytes):
            data_raw = data_raw.decode('utf-8', errors='replace')
        try:
            data = _json.loads(data_raw)
        except _json.JSONDecodeError as e:
            # Corrupt cache blob would silently become an empty record in
            # the plan. Better to warn + skip — the user can inspect and
            # sync-down again, rather than migrate a body-less record.
            logging.warning('live_inventory: cache corrupt for %s: %s', uid, e)
            continue
        source_rec = dict(data)
        source_rec['record_uid'] = uid
        source_rec['title'] = rec.title
        # Re-read shares from cache (the batch call above mutates
        # record_cache[uid]['shares'] in place).
        shares = (cache.get(uid, {}) or {}).get('shares') or {}
        source_rec['user_permissions'] = shares.get('user_permissions', [])[:]
        entry = summarize_record(source_rec, include_fields=include_fields)
        folder_uid, folder_type = record_folder_map.get(uid, ('', 'root'))
        entry['folder_uid'] = folder_uid
        entry['folder_type'] = folder_type
        entry['folder_path'] = _folder_name_path(folder_cache, folder_uid)
        out.append(entry)
    return out


def _normalize_sf_user_perm(u):
    """Normalize one SF user entry into a comparable dict.

    Source data shape varies between Keeper SDK versions — some carry
    manage_users/manage_records, others only can_edit/can_share. We
    capture all four explicitly so the validator can diff per-user."""
    if not isinstance(u, dict):
        return None
    email = (u.get('username') or u.get('email') or '').strip().lower()
    if not email:
        return None
    return {
        'username': email,
        'manage_users': bool(u.get('manage_users', False)),
        'manage_records': bool(u.get('manage_records', False)),
        'can_edit': bool(u.get('can_edit', False)),
        'can_share': bool(u.get('can_share', False)),
    }


def _normalize_sf_team_perm(t):
    if not isinstance(t, dict):
        return None
    name = (t.get('name') or t.get('team_name') or '').strip()
    if not name:
        return None
    return {
        'name': name,
        'manage_users': bool(t.get('manage_users', False)),
        'manage_records': bool(t.get('manage_records', False)),
    }


def _folder_parent_chain(folder_cache, uid):
    """Walk parent_uid chain upward from `uid`, returning list of ancestor
    UIDs in order [parent, grandparent, ...]. Stops at a missing parent or
    at the root (empty parent_uid). Guards against cache loops."""
    chain = []
    guard = 0
    node = folder_cache.get(uid)
    cur = getattr(node, 'parent_uid', '') or '' if node else ''
    while cur and guard < 32:
        chain.append(cur)
        parent = folder_cache.get(cur)
        if parent is None:
            break
        cur = getattr(parent, 'parent_uid', '') or ''
        guard += 1
    return chain


def resolve_scope_vault_root(params, scope_node):
    """Map an enterprise scope-node name to a vault-side user_folder UID.

    Admins who run the rebuild batch create a user_folder of the same
    name as the enterprise scope node so records and SFs can sit under
    the matching vault path. If that convention is followed, the scope
    node name will have exactly one top-level user_folder twin and this
    returns its UID.

    Returns '' when scope_node is empty OR no matching vault folder
    exists — caller should treat '' as "no vault scope, enumerate at
    admin root".
    """
    if not scope_node:
        return ''
    folder_cache = getattr(params, 'folder_cache', {}) or {}
    target = (scope_node or '').strip()
    matches = []
    for uid, node in folder_cache.items():
        name = getattr(node, 'name', '') or ''
        ftype = getattr(node, 'type', '') or ''
        parent = getattr(node, 'parent_uid', '') or ''
        # Top-level user_folder whose name matches the scope node.
        if ftype == 'user_folder' and name == target and not parent:
            matches.append(uid)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        logging.warning(
            'scope_vault_root ambiguous: %d top-level user_folders '
            'named %r — picking first; rename or reorganize the vault '
            'to disambiguate.', len(matches), target,
        )
        return matches[0]
    return ''


# Folder types the vault-enumerator emits. Anything else (e.g.
# RootFolderType) is walked-through but never produced.
_VAULT_FOLDER_TYPES = ('user_folder', 'shared_folder', 'shared_folder_folder')


def build_vault_folder_entities(params, prefix='', scope_vault_root_uid=''):
    """Enumerate personal-vault folders under `scope_vault_root_uid` whose
    name matches `prefix`. Emits parents before children so callers can
    create them in order on target.

    Returned entries:
      {'uid':           str,
       'name':          str,
       'type':          'user_folder' | 'shared_folder'
                        | 'shared_folder_folder',
       'parent_uid':    str — empty if the folder is top-level,
       'parent_chain':  [parent_uid, grandparent_uid, ...],
       # shared_folder_folder entries also carry the containing SF UID:
       'shared_folder_uid': str}

    Non-matching user_folders between the scope root and a matching
    descendant are NOT emitted — the assumption is that a prefix-scoped
    migration collapses untracked folders up to the nearest matching
    ancestor. Customers who need the intermediate folders preserved
    should name them with the prefix too.
    """
    folder_cache = getattr(params, 'folder_cache', {}) or {}
    if not folder_cache:
        return []

    # Build parent_uid -> list[child_uid] for BFS descent.
    children_of = {}
    for uid, node in folder_cache.items():
        parent = getattr(node, 'parent_uid', '') or ''
        children_of.setdefault(parent, []).append(uid)

    # BFS from the scope root; if no scope, start at top-level (parent='').
    queue = [scope_vault_root_uid if scope_vault_root_uid else '']
    visited = set()
    out = []
    while queue:
        current = queue.pop(0)
        for child_uid in children_of.get(current, []):
            if child_uid in visited:
                continue
            visited.add(child_uid)
            node = folder_cache.get(child_uid)
            if node is None:
                continue
            name = getattr(node, 'name', '') or ''
            ftype = getattr(node, 'type', '') or ''
            if ftype in _VAULT_FOLDER_TYPES and (not prefix or name.startswith(prefix)):
                entry = {
                    'uid': child_uid,
                    'name': name,
                    'type': ftype,
                    'parent_uid': getattr(node, 'parent_uid', '') or '',
                    'parent_chain': _folder_parent_chain(folder_cache, child_uid),
                }
                if ftype == 'shared_folder_folder':
                    entry['shared_folder_uid'] = getattr(
                        node, 'shared_folder_uid', '') or ''
                # Bug 22 — propagate SF default permissions onto the
                # vault_folder entry so step_vault_folders can pass
                # them to add_shared_folder. Without this they're all
                # None and the target SF gets default-False/False
                # regardless of source state.
                if ftype == 'shared_folder':
                    sf_cache = getattr(params, 'shared_folder_cache', {}) or {}
                    sf = sf_cache.get(child_uid) or {}
                    entry['default_manage_users'] = bool(
                        sf.get('default_manage_users', False))
                    entry['default_manage_records'] = bool(
                        sf.get('default_manage_records', False))
                    entry['default_can_edit'] = bool(
                        sf.get('default_can_edit', False))
                    entry['default_can_share'] = bool(
                        sf.get('default_can_share', False))
                out.append(entry)
            # Always descend — a non-matching user_folder may still
            # contain prefix-matching descendants.
            queue.append(child_uid)
    return out


_SF_RECORD_SAFE_KEYS = ('record_uid', 'can_edit', 'can_share',
                         'folder_uid')
# Explicit allowlist — every other key (record_key_unencrypted, raw
# encrypted blobs, SDK-internal state) stays out of the JSON inventory.
# Crypto material MUST NEVER be serialized; on-disk inventories are
# shared across hosts during migrations.


def _normalize_sf_record(rec):
    """Strip a shared_folder_cache record entry down to the fields the
    migration pipeline needs. Rejects anything carrying crypto material."""
    if not isinstance(rec, dict):
        r_uid = str(rec) if rec else ''
        return {'record_uid': r_uid} if r_uid else None
    out = {k: rec[k] for k in _SF_RECORD_SAFE_KEYS if k in rec}
    # Booleans should come through as booleans even when the SDK hands
    # us None/0/1 — keeps downstream checks boolean-pure.
    if 'can_edit' in out:
        out['can_edit'] = bool(out['can_edit'])
    if 'can_share' in out:
        out['can_share'] = bool(out['can_share'])
    return out if out.get('record_uid') else None


def _normalize_sf_entry(sf, *, extra=None):
    """Common shape-conversion used by both the enterprise-side and the
    personal-vault SF enumerators. `sf` is the raw SF dict (from either
    ent['shared_folders'] or params.shared_folder_cache[uid]); `extra`
    merges in vault-only fields (parent_uid, parent_chain, source='vault').

    Record entries inside sf['records'] go through _normalize_sf_record
    to strip crypto material — raw SDK records carry
    record_key_unencrypted bytes that JSON can't serialize AND that we
    must not persist to disk.
    """
    name = sf.get('name', '') or ''
    users = [p for p in (_normalize_sf_user_perm(u)
                           for u in sf.get('users', []) or [])
             if p is not None]
    teams = [p for p in (_normalize_sf_team_perm(t)
                           for t in sf.get('teams', []) or [])
             if p is not None]
    records = [r for r in (_normalize_sf_record(rec)
                             for rec in sf.get('records', []) or [])
               if r is not None]
    out = {
        'uid': sf.get('shared_folder_uid', '') or sf.get('uid', ''),
        'name': name,
        'default_manage_users': sf.get('default_manage_users'),
        'default_manage_records': sf.get('default_manage_records'),
        'default_can_edit': sf.get('default_can_edit'),
        'default_can_share': sf.get('default_can_share'),
        'users': users,
        'teams': teams,
        'records': records,
    }
    if extra:
        out.update(extra)
    return out


def build_shared_folder_entities(ent, prefix, *, params=None,
                                   vault_folders=None):
    """Return a merged list of shared folders visible to the admin.

    Two sources:

    1. `ent['shared_folders']` — enterprise-level SFs, already structured
       with users/teams/records/defaults. Historically the only source.
    2. `params.shared_folder_cache` joined with `vault_folders` — personal-
       vault SFs the admin owns. Keeper stores these only in the vault
       caches; they never appear under `ent['shared_folders']`. This is
       the gap that the 2026-04-20 audit surfaced (see SECURITY_MODEL.md
       — shared-folder mirror gap). Personal SFs get a `source='vault'`
       marker plus parent_uid / parent_chain fields from P1.1 so the
       structure stage can recreate the vault hierarchy on target.

    Dedup: enterprise wins on UID collision. Vault entries include a
    `source` field so callers can tell them apart; enterprise entries
    get `source='enterprise'`.
    """
    out = []
    seen_uids = set()

    for sf in ent.get('shared_folders', []) or []:
        name = sf.get('name', '') or ''
        if prefix and not name.startswith(prefix):
            continue
        entry = _normalize_sf_entry(sf, extra={'source': 'enterprise'})
        uid = entry['uid']
        if uid:
            seen_uids.add(uid)
        out.append(entry)

    # Personal-vault SFs — only emit when the caller passed both sides of
    # the join (params for shared_folder_cache, vault_folders for the
    # hierarchical context). Older callers that don't pass these see
    # exactly the previous behavior.
    if params is not None and vault_folders is not None:
        sf_cache = getattr(params, 'shared_folder_cache', {}) or {}
        for vf in vault_folders:
            if vf.get('type') != 'shared_folder':
                continue
            uid = vf.get('uid', '')
            if not uid or uid in seen_uids:
                continue
            raw = sf_cache.get(uid)
            if raw is None:
                # Folder_cache has the entry but shared_folder_cache
                # doesn't — admin probably lost direct access to it
                # (pending accept). Emit a skeletal entry so the
                # hierarchy is still recorded; downstream stages will
                # see empty users/teams/records and SKIP destructive ops.
                raw = {'name': vf.get('name', ''), 'shared_folder_uid': uid}
            # Prefer the plain name from folder_cache (vf['name']) over
            # shared_folder_cache['name'] — the SF cache sometimes stores
            # the still-encrypted name blob until first access, and we
            # want human-readable names in the inventory.
            name = vf.get('name', '') or raw.get('name', '') or ''
            if prefix and not name.startswith(prefix):
                continue
            entry = _normalize_sf_entry(raw, extra={
                'source': 'vault',
                'parent_uid': vf.get('parent_uid', ''),
                'parent_chain': vf.get('parent_chain', []),
            })
            entry['name'] = name
            entry['uid'] = uid
            out.append(entry)
            seen_uids.add(uid)

    return out


def compute_counts(entities):
    records = entities.get('records', []) or []
    roles = entities.get('roles', []) or []
    vault_folders = entities.get('vault_folders', []) or []
    return {
        'nodes': len(entities.get('nodes', [])),
        'teams': len(entities.get('teams', [])),
        'roles': len(roles),
        'users': len(entities.get('users', [])),
        'shared_folders': len(entities.get('shared_folders', [])),
        'vault_folders': len(vault_folders),
        'vault_user_folders': sum(
            1 for f in vault_folders if f.get('type') == 'user_folder'),
        'vault_subfolders': sum(
            1 for f in vault_folders if f.get('type') == 'shared_folder_folder'),
        'records': len(records),
        'attachments': sum(r.get('attachment_count', 0) for r in records),
        'direct_shares': sum(len(r.get('direct_shares', [])) for r in records),
        'total_enforcements': sum(len(r.get('enforcements', {})) for r in roles),
        'total_privileges': sum(
            sum(len(mn.get('privileges', []) or []) for mn in r.get('managed_nodes', []) or [])
            for r in roles
        ),
    }


def build_inventory_from_params(params, *, scope_node='', prefix='',
                                 target_user='', target_root='',
                                 include_fields=False, scrape_hsf=True):
    """Return the full inventory dict from a live Commander session.

    scrape_hsf: when True (default) and there are teams in scope, invoke
    EnterpriseTeamCommand per team to scrape `(No Shared Folders)` markers
    into per-user hide_shared_folders_teams lists. Skip by setting False
    for fast/large-tenant runs where hsf isn't needed.
    """
    ent = getattr(params, 'enterprise', None) or {}
    if not ent:
        logging.warning('params.enterprise is empty — run `sync-down` or log in first')

    source_user = getattr(params, 'user', '') or ent.get('user', '')
    server = getattr(params, 'server', '') or ent.get('server', '')
    enterprise_name = ent.get('enterprise_name', '')

    descendants = _compute_descendants(ent, scope_node)
    path_map = _build_node_path_map(ent)

    nodes = build_node_entities(ent, descendants, path_map, prefix)
    _backfill_entity_counts(nodes, ent, descendants)
    teams = build_team_entities(ent, descendants, path_map, prefix)
    roles = build_role_entities(ent, descendants, path_map, prefix)

    hsf_map = {}
    if scrape_hsf and teams:
        team_names = [t.get('name', '') for t in teams if t.get('name')]
        try:
            hsf_map = build_hsf_map(params, team_names)
        except Exception as e:                         # noqa: BLE001
            logging.warning('hsf scrape failed, continuing without it: %r', e)
            hsf_map = {}

    users = build_user_entities(ent, descendants, path_map, prefix, hsf_map=hsf_map)

    # Vault-side capture (PR-A — shared folder mirror gap 2026-04-20).
    # Enumerate personal-vault folders under the enterprise scope node's
    # twin user_folder, then merge any shared_folders found into the
    # canonical entity list.
    scope_vault_root_uid = resolve_scope_vault_root(params, scope_node)
    vault_folders = build_vault_folder_entities(
        params, prefix=prefix,
        scope_vault_root_uid=scope_vault_root_uid,
    )
    sfs = build_shared_folder_entities(
        ent, prefix, params=params, vault_folders=vault_folders,
    )

    records = build_record_entities(params, prefix, include_fields=include_fields)

    # Bug 40 — embed enterprise/user record-type definitions so
    # `--inventory` mode can recreate them on target. Empty list when
    # the source has no custom types or the API is unavailable.
    record_types = build_record_types(params)

    # Task #17 / Bug 60 — translate `restrict_record_types` enforcement
    # values from source-tenant record-type IDs to portable NAMES
    # before they hit the inventory file. Target's CLI parser
    # re-resolves names → target IDs at write time.
    record_types_id_to_name = _source_record_type_id_to_name(params)
    if record_types_id_to_name:
        _remap_role_enforcement_values(
            roles, record_types_id_to_name=record_types_id_to_name)

    entities = {
        'nodes': nodes, 'teams': teams, 'roles': roles, 'users': users,
        'shared_folders': sfs,
        'vault_folders': vault_folders,
        'records': records,
        'record_types': record_types,
    }

    sso_config = build_sso_config(ent)

    return {
        'captured_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_user': source_user,
        'source_server': server,
        'source_root': enterprise_name,
        'target_user': target_user,
        'target_root': target_root,
        'scope_node': scope_node,
        'prefix_filter': prefix,
        'counts': compute_counts(entities),
        'entities': entities,
        'sso_config': sso_config,
    }


def build_sso_config(ent):
    """Return the source tenant's SSO/SCIM configuration that the admin
    must re-point at the new tenant.

    SSO providers: captured from `sso_services`. Commander doesn't
    expose SAML entity_id / ACS URL / metadata URL directly in this
    table — only `sp_url` (a generic service-provider URL) and
    node scope. The rest must be fetched via `enterprise sso-info`
    or copied from the Keeper Admin Console; we surface the fields
    we CAN see and note the gap for manual action.

    SCIM endpoints: captured from `scims` table — these are unique
    per tenant (the SCIM token grants access to THIS tenant only),
    so the admin MUST rotate the IdP's SCIM bearer token and repoint
    the SCIM base URL to the new tenant.

    Bridges (on-prem AD/LDAP sync): captured from `bridges` — the
    appliance's configured endpoint is tenant-specific.

    Empty dict when nothing is configured.
    """
    providers = ent.get('sso_services') or ent.get('sso_cloud_providers') or []
    provider_out = []
    for p in providers or []:
        if not isinstance(p, dict):
            continue
        provider_out.append({
            'name': p.get('name', ''),
            'sso_service_provider_id': p.get('sso_service_provider_id'),
            'entity_id': p.get('sp_entity_id') or p.get('entity_id', ''),
            'sp_url': p.get('sp_url', '') or p.get('acs_url', ''),
            'metadata_url': p.get('metadata_url', ''),
            'invite_new_users': bool(p.get('invite_new_users', False)),
            'is_cloud': bool(p.get('is_cloud', False)),
            'active': bool(p.get('is_active') or p.get('active', True)),
            'node_id': p.get('node_id'),
        })

    scim_out = []
    for s in ent.get('scims', []) or []:
        if not isinstance(s, dict):
            continue
        scim_out.append({
            'scim_id': s.get('scim_id'),
            'node_id': s.get('node_id'),
            'status': s.get('status', ''),
            'last_synced': s.get('last_synced'),
            'role_prefix': s.get('role_prefix', ''),
            'unique_groups': bool(s.get('unique_groups', False)),
            # NOTE: the SCIM bearer TOKEN is never exposed via
            # enterprise sync — only its presence/configuration. On
            # target the admin must generate a fresh token and paste
            # it into the IdP.
        })

    bridge_out = []
    for b in ent.get('bridges', []) or []:
        if not isinstance(b, dict):
            continue
        bridge_out.append({
            'bridge_id': b.get('bridge_id'),
            'node_id': b.get('node_id'),
            'status': b.get('status', ''),
            'wan_ip_enforcement': b.get('wan_ip_enforcement', ''),
            'lan_ip_enforcement': b.get('lan_ip_enforcement', ''),
        })

    user_count_sso = sum(
        1 for u in ent.get('users', []) or []
        if u.get('sso_service_provider_id') or u.get('is_sso'))

    return {
        'providers': provider_out,
        'scims': scim_out,
        'bridges': bridge_out,
        'user_count_sso': user_count_sso,
    }


def write_inventory(inventory, output_path):
    """Write the inventory JSON + a sha256 sidecar.

    File mode is set to 0600 (owner read/write only) because an inventory
    with `include_fields=True` contains plaintext login/password/notes/TOTP
    values. The mode is applied unconditionally — cheap and harmless for
    the lightweight variant.
    """
    import os
    with open(output_path, 'w') as f:
        json.dump(inventory, f, indent=2)
    os.chmod(output_path, 0o600)
    with open(output_path, 'rb') as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    sidecar = output_path + '.sha256'
    with open(sidecar, 'w') as f:
        f.write(checksum + '\n')
    os.chmod(sidecar, 0o600)
    return checksum
