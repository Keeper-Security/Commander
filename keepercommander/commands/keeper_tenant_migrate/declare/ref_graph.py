"""Reference-graph validator. Checks that every overlay edit targets
something that actually exists in the captured base inventory.

Runs after schema validation, before apply. Returns a list of human-
readable errors; an empty list means all refs resolve.
"""
from typing import List

from .schema.overlay_v1 import OverlayManifest


def find_dangling_refs(manifest: OverlayManifest, base: dict) -> List[str]:
    """Return error strings for manifest edits whose target is missing from base."""
    errors: List[str] = []
    entities = base.get("entities") or {}

    role_names = {
        r.get("name") for r in (entities.get("roles") or [])
        if r.get("name")
    }
    for old in manifest.edits.roles.rename:
        if old not in role_names:
            errors.append(f"roles.rename: {old!r} not found in base")
    for name in manifest.edits.roles.drop:
        if name not in role_names:
            errors.append(f"roles.drop: {name!r} not found in base")
    for name in manifest.edits.roles.strip_enforcements:
        if name not in role_names:
            errors.append(f"roles.strip_enforcements: {name!r} not found in base")

    sf_names = {
        s.get("name") for s in (entities.get("shared_folders") or [])
        if s.get("name")
    }
    for old in manifest.edits.shared_folders.rename:
        if old not in sf_names:
            errors.append(f"shared_folders.rename: {old!r} not found in base")

    node_names = {
        n.get("name") for n in (entities.get("nodes") or [])
        if n.get("name")
    }
    for old in manifest.edits.nodes.remap:
        if old not in node_names:
            errors.append(f"nodes.remap: {old!r} not found in base")

    team_names = {
        t.get("name") for t in (entities.get("teams") or [])
        if t.get("name")
    }
    for old in manifest.edits.teams.rename:
        if old not in team_names:
            errors.append(f"teams.rename: {old!r} not found in base")
    for name in manifest.edits.teams.drop:
        if name not in team_names:
            errors.append(f"teams.drop: {name!r} not found in base")

    # scope.include_nodes/exclude_nodes are fnmatch globs — operator may
    # intentionally write a pattern that matches zero nodes; not validated.
    # users.drop is also a glob; users.domain_remap keys are domain strings
    # (not user identifiers) — neither has an inventory referent to check.

    return errors
