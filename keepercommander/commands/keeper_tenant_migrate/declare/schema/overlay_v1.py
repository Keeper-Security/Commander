"""Schema: tenant-overlay.v1 — operator-edit overlay over a captured inventory.

A tenant-overlay manifest expresses what to change about a captured
inventory.json before it is fed into the existing tenant-migrate
pipeline. The base inventory carries the full source-tenant state;
the overlay narrows or rewrites it for the target conventions.

Phase 1.1 covers role rewrites and shared-folder renames.
Phase 1.2 adds: scope filters, node remap, team rename/drop, and
user drop/domain-remap.
"""
from typing import Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class RoleEdits(_Strict):
    """Edits scoped to roles."""

    rename: Dict[str, str] = Field(default_factory=dict)
    drop: List[str] = Field(default_factory=list)
    # role-name -> list of enforcement keys to strip from that role
    strip_enforcements: Dict[str, List[str]] = Field(default_factory=dict)


class SharedFolderEdits(_Strict):
    rename: Dict[str, str] = Field(default_factory=dict)


class TeamEdits(_Strict):
    """Edits scoped to teams.

    ``rename`` is a {old_name: new_name} dict applied to
    ``entities.teams[*].name`` by exact match. Cross-reference
    propagation goes wider than nodes because team-name back-references
    appear in three other entity types per ``inventory.py``:

      - ``entities.roles[*].teams[*]``           — role-team membership
      - ``entities.shared_folders[*].teams[*]``  — SF team membership
      - ``entities.users[*].teams[*]``           — user-team membership

    Entries in those `teams[*]` lists are heterogeneous per the
    keeperCMD source (``structure.py:770-775``): they may be plain
    name strings OR dicts with ``team_name`` / ``name`` keys depending
    on which producer emitted the inventory (live_inventory vs
    assemble-inventory). Both shapes are handled.

    ``drop`` removes teams by name from ``entities.teams`` AND from
    the three back-reference lists above. Same heterogeneous-entry
    handling.

    Atomicity: same as ``nodes.remap`` — captured rename dict is fixed
    at function entry; swap patterns work.
    """

    rename: Dict[str, str] = Field(default_factory=dict)
    drop: List[str] = Field(default_factory=list)


class UserEdits(_Strict):
    """Edits scoped to users.

    ``drop`` is a list of fnmatch-style globs (``*``, ``?``, ``[abc]``)
    matched against ``entities.users[*].email``. Matching users are
    removed; cross-references in ``shared_folders[*].users`` and
    ``records[*].direct_shares`` (both keyed by ``username``) are
    cascaded so the inventory remains internally consistent.

    ``domain_remap`` is an ``{old_domain: new_domain}`` dict applied to:
      - ``users[*].email`` and ``users[*].aliases[*]`` (and the raw
        concat ``users[*].alias`` field)
      - ``shared_folders[*].users[*].username``
      - ``records[*].direct_shares[*].username``

    Domain match is case-insensitive; the local part keeps its case
    (``Admin@Acme.com`` → ``Admin@acme.io`` when remapping ``acme.com``
    → ``acme.io``). Non-matching addresses pass through untouched. The
    pure ``email_remap.remap_email`` helper does the per-address work.

    **Drop is applied before domain_remap** so an operator can drop a
    user under their old-domain email AND remap surviving users in the
    same overlay. Both edits are atomic — captured map fixed at entry.

    **Out of scope (v1)**: user-level role/team membership rewrites
    (those are role/team edits in their respective sections);
    enforcements that store usernames; queued team memberships (those
    are runtime artifacts, not inventory state).
    """

    drop: List[str] = Field(default_factory=list)
    domain_remap: Dict[str, str] = Field(default_factory=dict)


class NodeEdits(_Strict):
    """Edits scoped to nodes.

    ``remap`` is a {old_name: new_name} dict applied to ``entities.nodes``
    by exact name match. Cross-references propagate: ``roles[*].node`` and
    ``teams[*].node`` get rewritten if they reference a remapped name.

    Atomic: the remap dict is captured before any rewrite, so swap
    patterns like ``{"A": "B", "B": "A"}`` work correctly regardless of
    iteration order. Each entity is touched once with its current name.

    Collision: if remap target collides with an existing un-remapped node
    name (or with another remap target), the operator gets two nodes
    sharing a name. Not validated at schema-load time — operator's
    responsibility. The downstream migration pipeline's own deduplication
    (Bug 73 / Layer 1 rename-with-suffix, ``--preserve-duplicate-node-names``)
    is the safety net.
    """

    remap: Dict[str, str] = Field(default_factory=dict)


class ScopeFilter(_Strict):
    """Glob-based subtree filter on inventory nodes.

    Both lists are fnmatch-style globs (``*``, ``?``, ``[abc]``) matched
    against the node ``name`` field. Order:

      1. ``include_nodes`` — if non-empty, only nodes matching at least
         one glob survive. Empty list = pass-through (no whitelist
         applied; all nodes are candidates for the exclude pass).
      2. ``exclude_nodes`` — applied to the post-include set; nodes
         matching any glob are dropped.

    **Cascade semantics**: when a node is dropped, ``roles`` and ``teams``
    whose ``node`` field references the dropped node are also dropped.
    Roles/teams with no ``node`` field (tenant-level) survive
    unconditionally. ``shared_folders`` and ``records`` have no direct
    node reference in the inventory schema and are NOT cascade-dropped;
    operators wanting to scope those should pair scope filters with
    explicit ``shared_folders.drop`` (Phase 1.3+) or rely on the
    downstream migration pipeline's own scoping (``--scope-node`` /
    ``--prefix``).
    """

    include_nodes: List[str] = Field(default_factory=list)
    exclude_nodes: List[str] = Field(default_factory=list)


class OverlayEdits(_Strict):
    """Set of edits applied to the captured inventory."""

    scope: ScopeFilter = Field(default_factory=ScopeFilter)
    nodes: NodeEdits = Field(default_factory=NodeEdits)
    teams: TeamEdits = Field(default_factory=TeamEdits)
    users: UserEdits = Field(default_factory=UserEdits)
    roles: RoleEdits = Field(default_factory=RoleEdits)
    shared_folders: SharedFolderEdits = Field(default_factory=SharedFolderEdits)


class OverlayManifest(_Strict):
    """Top-level overlay manifest. ``schema`` is required and pinned."""

    schema_: Literal["tenant-overlay.v1"] = Field(alias="schema")
    name: str
    base: str
    edits: OverlayEdits = Field(default_factory=OverlayEdits)
