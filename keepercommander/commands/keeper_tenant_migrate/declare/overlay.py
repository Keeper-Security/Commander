"""Pure overlay engine. Given a captured inventory.json (as a dict) and
an OverlayManifest, return a new inventory dict with edits applied.

No I/O; deterministic; the base dict is not mutated.

Edit application order:
  1. ``scope`` filter (Phase 1.2) — prune nodes + cascade-drop
     roles/teams that reference dropped nodes. Runs first so subsequent
     edits operate on the post-filter universe.
  2. ``nodes.remap`` (Phase 1.2) — node name rewrites with cross-ref
     propagation to ``roles[*].node`` and ``teams[*].node``.
  3. ``teams.drop`` (Phase 1.2) — drop happens before rename so an
     entry can be both renamed away from its old name AND dropped
     under that old name in the same overlay (drop wins).
  4. ``teams.rename`` (Phase 1.2) — team name rewrites + cross-ref
     propagation to ``roles[*].teams[*]`` / ``shared_folders[*].teams[*]``
     / ``users[*].teams[*]``. Heterogeneous entries (string OR dict
     with ``team_name``/``name`` keys) handled per ``structure.py:770``.
  5. ``users.drop`` (Phase 1.2) — fnmatch-glob drop with cascade to
     ``shared_folders[*].users[*].username`` and
     ``records[*].direct_shares[*].username``.
  6. ``users.domain_remap`` (Phase 1.2) — domain rewrites on
     ``users[*].email/aliases``, ``shared_folders[*].users[*].username``,
     and ``records[*].direct_shares[*].username``. Drop runs first so
     a user dropped under their old domain is gone before remap runs.
  7. ``roles.drop`` — same drop-before-rename pattern.
  8. ``roles.strip_enforcements``
  9. ``roles.rename``
 10. ``shared_folders.rename``
"""
import fnmatch
from copy import deepcopy
from typing import Dict, List

from ..email_remap import remap_email
from .schema.overlay_v1 import OverlayManifest, ScopeFilter


def apply_overlay(base: dict, manifest: OverlayManifest) -> dict:
    """Return a new inventory dict with the manifest's edits applied."""
    out = deepcopy(base)
    e = manifest.edits

    if e.scope.include_nodes or e.scope.exclude_nodes:
        _filter_scope(out, e.scope)
    if e.nodes.remap:
        _remap_nodes(out, e.nodes.remap)
    if e.teams.drop:
        _drop_teams(out, e.teams.drop)
    if e.teams.rename:
        _rename_teams(out, e.teams.rename)
    if e.users.drop:
        _drop_users(out, e.users.drop)
    if e.users.domain_remap:
        _domain_remap_users(out, e.users.domain_remap)
    if e.roles.drop:
        _drop_roles(out, e.roles.drop)
    if e.roles.strip_enforcements:
        _strip_role_enforcements(out, e.roles.strip_enforcements)
    if e.roles.rename:
        _rename_roles(out, e.roles.rename)
    if e.shared_folders.rename:
        _rename_shared_folders(out, e.shared_folders.rename)

    return out


# ─── Scope filter (Phase 1.2) ────────────────────────────────────────────────


def _matches_scope(name: str, scope: ScopeFilter) -> bool:
    """True if ``name`` survives the include/exclude filter pair.

    include_nodes empty → pass-through (no whitelist).
    include_nodes non-empty → name must match at least one glob.
    exclude_nodes — name must NOT match any glob (applied after include).
    """
    if scope.include_nodes:
        if not any(fnmatch.fnmatchcase(name, pat) for pat in scope.include_nodes):
            return False
    if scope.exclude_nodes:
        if any(fnmatch.fnmatchcase(name, pat) for pat in scope.exclude_nodes):
            return False
    return True


def _filter_scope(inv: dict, scope: ScopeFilter) -> None:
    """Apply scope filter to entities.nodes; cascade-drop roles + teams
    whose ``node`` references a filtered-out node.

    Tenant-level entities (no ``node`` field, or empty) survive
    unconditionally — they aren't scoped to any node.

    Counts (``inv['counts']`` keys ``nodes`` / ``roles`` / ``teams``)
    decremented by removal counts.
    """
    entities = inv.get("entities") or {}
    nodes = entities.get("nodes") or []

    surviving_node_names = {
        n.get("name") for n in nodes
        if isinstance(n.get("name"), str) and _matches_scope(n["name"], scope)
    }

    # Filter nodes list
    before_nodes = len(nodes)
    entities["nodes"] = [
        n for n in nodes
        if isinstance(n.get("name"), str) and n["name"] in surviving_node_names
    ]
    nodes_removed = before_nodes - len(entities["nodes"])

    # Cascade-drop roles whose `node` references a filtered-out node.
    # Tenant-level roles (no node field, empty string, or None) survive.
    roles_removed = _drop_node_referencing(entities, "roles", surviving_node_names)
    teams_removed = _drop_node_referencing(entities, "teams", surviving_node_names)

    # Decrement counts (best-effort; only if the count key exists).
    counts = inv.get("counts")
    if isinstance(counts, dict):
        if nodes_removed and "nodes" in counts:
            counts["nodes"] = max(0, counts["nodes"] - nodes_removed)
        if roles_removed and "roles" in counts:
            counts["roles"] = max(0, counts["roles"] - roles_removed)
        if teams_removed and "teams" in counts:
            counts["teams"] = max(0, counts["teams"] - teams_removed)


def _drop_node_referencing(entities: dict, key: str, surviving: set) -> int:
    """Drop entries from ``entities[key]`` whose ``node`` is not in
    ``surviving``. Tenant-level entries (empty/missing node) survive.

    Returns the number of entries removed.
    """
    items = entities.get(key)
    if not isinstance(items, list):
        return 0
    before = len(items)
    entities[key] = [
        item for item in items
        if not item.get("node") or item.get("node") in surviving
    ]
    return before - len(entities[key])


# ─── Nodes (Phase 1.2) ───────────────────────────────────────────────────────


def _remap_nodes(inv: dict, remap: Dict[str, str]) -> None:
    """Rename nodes by exact name match; propagate to roles + teams.

    Atomicity: ``remap`` is fixed at function entry; each entity is
    touched once with its CURRENT name. Swap patterns like
    ``{"A": "B", "B": "A"}`` work correctly because the lookup is
    against the captured map, not the in-flight inventory state.

    Cross-reference propagation:
      - ``entities.roles[*].node`` — if value is in ``remap``, rewrite
      - ``entities.teams[*].node`` — same

    Other potential references (shared_folders, records) are NOT
    propagated — the inventory schema doesn't carry node refs on
    those entity types as of v1.7.5. If a future inventory version
    adds such refs, extend this function.
    """
    entities = inv.get("entities") or {}

    # Pass 1: rename entities.nodes[*].name.
    for node in entities.get("nodes") or []:
        old = node.get("name")
        if old in remap:
            node["name"] = remap[old]

    # Pass 2: propagate to roles[*].node + teams[*].node.
    # Each role/team is touched once with its CURRENT (= original) `node`
    # value because we only just rewrote `nodes[*].name`, not the
    # back-references on roles/teams.
    for entity_key in ("roles", "teams"):
        items = entities.get(entity_key)
        if not isinstance(items, list):
            continue
        for item in items:
            old_node = item.get("node")
            if old_node in remap:
                item["node"] = remap[old_node]


# ─── Teams (Phase 1.2) ───────────────────────────────────────────────────────
#
# Cross-reference scope: roles[*].teams, shared_folders[*].teams,
# users[*].teams. Entries are heterogeneous — plain name string OR
# dict with ``team_name``/``name`` keys per ``structure.py:770-775``.


def _team_ref_name(entry):
    """Extract the team-name string from a heterogeneous entry.

    Mirrors ``structure.py:770-775`` shape detection. Returns empty
    string for unknown shapes (caller should treat as no-match).
    """
    if isinstance(entry, dict):
        return (entry.get("team_name") or entry.get("name") or "").strip()
    if isinstance(entry, str):
        return entry.strip()
    return ""


def _set_team_ref_name(entry, new_name):
    """Rewrite the team-name in a heterogeneous entry, in place.

    Returns the new entry (possibly the same object mutated; caller
    can ignore the return value if the list is mutated by index).
    """
    if isinstance(entry, dict):
        # Preserve whichever key the source used; default to team_name.
        if "team_name" in entry:
            entry["team_name"] = new_name
        elif "name" in entry:
            entry["name"] = new_name
        else:
            entry["team_name"] = new_name
        return entry
    if isinstance(entry, str):
        return new_name
    return entry


def _walk_team_refs(entities: dict, transform):
    """Apply ``transform(entry, current_name)`` to every team-ref entry
    in roles[*].teams, shared_folders[*].teams, and users[*].teams.

    ``transform`` returns either the new entry value (kept in place) or
    the sentinel ``_DROP`` to remove the entry. Lists are rewritten
    list-comprehension-style to support drops.
    """
    for parent_key in ("roles", "shared_folders", "users"):
        items = entities.get(parent_key)
        if not isinstance(items, list):
            continue
        for parent in items:
            teams_list = parent.get("teams")
            if not isinstance(teams_list, list):
                continue
            new_list = []
            for entry in teams_list:
                current_name = _team_ref_name(entry)
                result = transform(entry, current_name)
                if result is _DROP:
                    continue
                new_list.append(result)
            parent["teams"] = new_list


# Sentinel — distinct object so transform results can signal "drop"
# without colliding with any string / dict / None value.
_DROP = object()


def _drop_teams(inv: dict, drop: List[str]) -> None:
    """Remove teams whose name is in ``drop``. Cascade-removes
    references from roles/shared_folders/users teams[*] lists.
    Updates the teams count if present."""
    entities = inv.get("entities") or {}
    drop_set = set(drop)

    # 1. Remove from entities.teams.
    teams = entities.get("teams") or []
    before = len(teams)
    entities["teams"] = [t for t in teams
                         if t.get("name") not in drop_set]
    removed = before - len(entities["teams"])

    # 2. Cascade: remove team-refs from roles/shared_folders/users.
    def _drop_if_named(entry, name):
        return _DROP if name in drop_set else entry
    _walk_team_refs(entities, _drop_if_named)

    # 3. Decrement count.
    if removed and "counts" in inv and isinstance(inv["counts"], dict):
        if "teams" in inv["counts"]:
            inv["counts"]["teams"] = max(0, inv["counts"]["teams"] - removed)


def _rename_teams(inv: dict, rename: Dict[str, str]) -> None:
    """Rename teams by name; propagate to roles/shared_folders/users
    teams[*] back-references.

    Atomic: ``rename`` dict captured before any rewrite. Entries touched
    once with their CURRENT (pre-rename) team-name. Swap patterns work.
    """
    entities = inv.get("entities") or {}

    # 1. Rewrite entities.teams[*].name.
    for team in entities.get("teams") or []:
        old = team.get("name")
        if old in rename:
            team["name"] = rename[old]

    # 2. Cascade to roles/shared_folders/users teams[*] back-refs.
    def _rename_if_matched(entry, current_name):
        if current_name in rename:
            return _set_team_ref_name(entry, rename[current_name])
        return entry
    _walk_team_refs(entities, _rename_if_matched)


# ─── Users (Phase 1.2) ───────────────────────────────────────────────────────
#
# Cascade scope: shared_folders[*].users[*].username and
# records[*].direct_shares[*].username (both username-keyed dicts;
# raw Commander shape passed through inventory unchanged).


def _user_email(user: dict) -> str:
    """Normalized email for a user dict; empty string if missing."""
    return (user.get("email") or "").strip()


def _matches_any_glob(name: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pat) for pat in patterns)


def _drop_users(inv: dict, drop: List[str]) -> None:
    """Drop users whose email matches any fnmatch glob in ``drop``.

    Cascades: removes matching ``username`` entries from
    ``shared_folders[*].users`` and ``records[*].direct_shares``.
    Decrements ``inv['counts']['users']`` if present.
    """
    entities = inv.get("entities") or {}
    users = entities.get("users") or []

    surviving: List[dict] = []
    removed_emails: set = set()
    for u in users:
        email = _user_email(u)
        if email and _matches_any_glob(email, drop):
            removed_emails.add(email)
        else:
            surviving.append(u)
    entities["users"] = surviving
    removed = len(users) - len(surviving)

    def _username_dropped(entry) -> bool:
        return (isinstance(entry, dict)
                and (entry.get("username") or "").strip() in removed_emails)

    for sf in entities.get("shared_folders") or []:
        sf_users = sf.get("users")
        if isinstance(sf_users, list):
            sf["users"] = [u for u in sf_users if not _username_dropped(u)]

    for rec in entities.get("records") or []:
        ds = rec.get("direct_shares")
        if isinstance(ds, list):
            rec["direct_shares"] = [s for s in ds if not _username_dropped(s)]

    counts = inv.get("counts")
    if removed and isinstance(counts, dict) and "users" in counts:
        counts["users"] = max(0, counts["users"] - removed)


def _remap_email_multi(email: str, mapping: Dict[str, str]) -> str:
    """Apply the first matching domain rewrite from ``mapping``.

    Match is case-insensitive on the domain (``remap_email`` semantics).
    """
    for old_domain, new_domain in mapping.items():
        new = remap_email(email, old_domain, new_domain)
        if new != email:
            return new
    return email


def _domain_remap_users(inv: dict, mapping: Dict[str, str]) -> None:
    """Apply ``{old_domain: new_domain}`` rewrites to user emails and
    every place an email reference is keyed by ``username``.

    Atomic: ``mapping`` captured before any rewrite. Each address is
    matched against the captured map exactly once. Multiple keys can
    coexist (e.g. ``{"a.com": "b.com", "c.com": "d.com"}``); first
    matching pair wins on a per-address basis.
    """
    entities = inv.get("entities") or {}

    for user in entities.get("users") or []:
        email = user.get("email")
        if isinstance(email, str) and email:
            user["email"] = _remap_email_multi(email, mapping)

        aliases = user.get("aliases")
        if isinstance(aliases, list):
            user["aliases"] = [
                _remap_email_multi(a, mapping) if isinstance(a, str) else a
                for a in aliases
            ]

        # Raw concat ``alias`` field: rebuild from the (now-remapped)
        # primary email + aliases when present, mirroring the producer
        # in inventory.py:135-145 (alias-list excludes the primary).
        if "alias" in user:
            primary = (user.get("email") or "").strip()
            alias_list = user.get("aliases") or []
            extras = [a for a in alias_list
                      if isinstance(a, str) and a and a.lower() != primary.lower()]
            if primary or extras:
                user["alias"] = "\n".join(([primary] if primary else []) + extras)

    for sf in entities.get("shared_folders") or []:
        for grant in sf.get("users") or []:
            if isinstance(grant, dict) and isinstance(grant.get("username"), str):
                grant["username"] = _remap_email_multi(grant["username"], mapping)

    for rec in entities.get("records") or []:
        for share in rec.get("direct_shares") or []:
            if isinstance(share, dict) and isinstance(share.get("username"), str):
                share["username"] = _remap_email_multi(share["username"], mapping)


# ─── Roles ───────────────────────────────────────────────────────────────────


def _drop_roles(inv: dict, drop: List[str]) -> None:
    """Remove roles whose name is in ``drop``. Updates roles count."""
    entities = inv.get("entities") or {}
    roles = entities.get("roles") or []
    before = len(roles)
    drop_set = set(drop)
    entities["roles"] = [r for r in roles if r.get("name") not in drop_set]
    removed = before - len(entities["roles"])
    if removed and "counts" in inv and "roles" in inv["counts"]:
        inv["counts"]["roles"] = max(0, inv["counts"]["roles"] - removed)


def _strip_role_enforcements(inv: dict, mapping: Dict[str, List[str]]) -> None:
    """Remove specific enforcement keys from named roles.

    Bug 76.2 / lockout-risk pattern: strip require_account_share or
    restrict_ip_addresses from the target's admin roles before apply.
    """
    entities = inv.get("entities") or {}
    for role in entities.get("roles") or []:
        keys = mapping.get(role.get("name"))
        if not keys:
            continue
        enf = role.get("enforcements")
        if isinstance(enf, dict):
            for k in keys:
                enf.pop(k, None)


def _rename_roles(inv: dict, rename: Dict[str, str]) -> None:
    """Rename roles by name in-place; propagate to require_account_share."""
    entities = inv.get("entities") or {}

    for role in entities.get("roles") or []:
        old = role.get("name")
        if old in rename:
            role["name"] = rename[old]

    for role in entities.get("roles") or []:
        enf = role.get("enforcements") or {}
        ras = enf.get("require_account_share")
        if isinstance(ras, str) and ras in rename:
            enf["require_account_share"] = rename[ras]


# ─── Shared folders ──────────────────────────────────────────────────────────


def _rename_shared_folders(inv: dict, rename: Dict[str, str]) -> None:
    """Rename shared folders by name. Updates folder_path on contained
    records when the folder name appears as a leading path component."""
    entities = inv.get("entities") or {}
    sfs = entities.get("shared_folders") or []

    sf_uids_renamed: Dict[str, str] = {}
    for sf in sfs:
        old = sf.get("name")
        if old in rename:
            new = rename[old]
            sf["name"] = new
            uid = sf.get("uid")
            if uid:
                sf_uids_renamed[uid] = (old, new)

    if not sf_uids_renamed:
        return

    # Update folder_path on records contained in the renamed SF.
    # folder_path on records is a slash-joined name path; folder_uid is
    # the SF's uid. We anchor on uid (stable) and rewrite the name token.
    for rec in entities.get("records") or []:
        fuid = rec.get("folder_uid")
        if fuid in sf_uids_renamed:
            old, new = sf_uids_renamed[fuid]
            fp = rec.get("folder_path") or ""
            # folder_path uses forward-slash path joins; replace the
            # first occurrence of the old name as a path component.
            parts = fp.split("/") if fp else []
            for i, part in enumerate(parts):
                if part == old:
                    parts[i] = new
                    break
            rec["folder_path"] = "/".join(parts) if parts else fp
