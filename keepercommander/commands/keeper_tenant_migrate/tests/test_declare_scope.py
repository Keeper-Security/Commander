"""Phase 1.2 — scope.include_nodes / scope.exclude_nodes filter tests.

The filter prunes ``entities.nodes`` and cascade-drops roles + teams
whose ``node`` references a filtered-out node. Tenant-level entries
(no node field) survive unconditionally.
"""
import unittest

from keepercommander.commands.keeper_tenant_migrate.declare.overlay import apply_overlay
from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


def _scoped_inventory():
    """Inventory with nodes + node-referencing roles + teams + a
    tenant-level role with no node assignment."""
    return {
        "captured_at": "2026-05-10T00:00:00Z",
        "counts": {"nodes": 4, "roles": 4, "teams": 3, "shared_folders": 0,
                   "records": 0},
        "entities": {
            "nodes": [
                {"uid": "n_root", "name": "Acme"},
                {"uid": "n_eng", "name": "Engineering"},
                {"uid": "n_ops", "name": "Operations"},
                {"uid": "n_test", "name": "MIGRATION-TEST-NODE"},
            ],
            "roles": [
                {"id": 1, "name": "Admin", "node": "Acme"},
                {"id": 2, "name": "EngLead", "node": "Engineering"},
                {"id": 3, "name": "OpsOnCall", "node": "Operations"},
                {"id": 4, "name": "TenantWide"},  # no node = tenant-level
            ],
            "teams": [
                {"id": "t1", "name": "Eng", "node": "Engineering"},
                {"id": "t2", "name": "Ops", "node": "Operations"},
                {"id": "t3", "name": "AllHands"},  # no node
            ],
            "shared_folders": [],
            "records": [],
        },
    }


def _manifest(edits):
    return OverlayManifest.model_validate(
        {"schema": "tenant-overlay.v1", "name": "test",
         "base": "/dev/null", "edits": edits}
    )


class ScopeIncludeTests(unittest.TestCase):
    """include_nodes whitelist: nodes must match at least one glob."""

    def test_exact_name_keeps_only_that_node(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"include_nodes": ["Engineering"]}})
        out = apply_overlay(inv, m)
        names = [n["name"] for n in out["entities"]["nodes"]]
        self.assertEqual(names, ["Engineering"])

    def test_glob_star_keeps_all_matching(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"include_nodes": ["MIGRATION-TEST-*"]}})
        out = apply_overlay(inv, m)
        names = [n["name"] for n in out["entities"]["nodes"]]
        self.assertEqual(names, ["MIGRATION-TEST-NODE"])

    def test_multiple_globs_union(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"include_nodes": ["Acme", "Engineering"]}})
        out = apply_overlay(inv, m)
        names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(names, ["Acme", "Engineering"])

    def test_no_match_drops_all_nodes(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"include_nodes": ["Nonexistent"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["nodes"], [])

    def test_empty_include_list_passthrough(self):
        """include_nodes=[] = no whitelist, all nodes survive (the
        exclude pass alone determines drops)."""
        inv = _scoped_inventory()
        m = _manifest({"scope": {"include_nodes": []}})
        out = apply_overlay(inv, m)
        self.assertEqual(len(out["entities"]["nodes"]), 4)


class ScopeExcludeTests(unittest.TestCase):
    """exclude_nodes blacklist applied to post-include set."""

    def test_exact_name_drops_only_that_node(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"exclude_nodes": ["Operations"]}})
        out = apply_overlay(inv, m)
        names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(names,
                         ["Acme", "Engineering", "MIGRATION-TEST-NODE"])

    def test_glob_drops_matching(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"exclude_nodes": ["MIGRATION-*"]}})
        out = apply_overlay(inv, m)
        names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(names, ["Acme", "Engineering", "Operations"])

    def test_exclude_after_include(self):
        """exclude applies to the post-include set."""
        inv = _scoped_inventory()
        m = _manifest({"scope": {
            "include_nodes": ["*", ],
            "exclude_nodes": ["Operations", "MIGRATION-TEST-NODE"],
        }})
        out = apply_overlay(inv, m)
        names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(names, ["Acme", "Engineering"])


class ScopeCascadeTests(unittest.TestCase):
    """Cascade-drop: roles + teams whose `node` references a dropped
    node are also dropped. Tenant-level (no `node`) entries survive."""

    def test_role_in_dropped_node_is_cascade_dropped(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"exclude_nodes": ["Engineering"]}})
        out = apply_overlay(inv, m)
        role_names = sorted(r["name"] for r in out["entities"]["roles"])
        # EngLead lived in Engineering — should be cascade-dropped.
        self.assertIn("Admin", role_names)
        self.assertIn("OpsOnCall", role_names)
        self.assertIn("TenantWide", role_names)
        self.assertNotIn("EngLead", role_names)

    def test_tenant_level_role_always_survives(self):
        """A role with no `node` field is tenant-wide and unaffected."""
        inv = _scoped_inventory()
        m = _manifest({"scope": {"include_nodes": ["NobodyMatches"]}})
        out = apply_overlay(inv, m)
        role_names = [r["name"] for r in out["entities"]["roles"]]
        # All node-scoped roles dropped; tenant-wide one stays.
        self.assertEqual(role_names, ["TenantWide"])

    def test_team_in_dropped_node_is_cascade_dropped(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"exclude_nodes": ["Operations"]}})
        out = apply_overlay(inv, m)
        team_names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(team_names, ["AllHands", "Eng"])

    def test_counts_decremented(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"exclude_nodes": ["Operations"]}})
        out = apply_overlay(inv, m)
        # 4 nodes - 1 = 3
        self.assertEqual(out["counts"]["nodes"], 3)
        # 4 roles - 1 (OpsOnCall) = 3
        self.assertEqual(out["counts"]["roles"], 3)
        # 3 teams - 1 (Ops) = 2
        self.assertEqual(out["counts"]["teams"], 2)


class ScopeNoEffectTests(unittest.TestCase):
    """Empty scope filter is a no-op."""

    def test_default_scope_is_passthrough(self):
        inv = _scoped_inventory()
        m = _manifest({})
        out = apply_overlay(inv, m)
        self.assertEqual(len(out["entities"]["nodes"]), 4)
        self.assertEqual(len(out["entities"]["roles"]), 4)
        self.assertEqual(len(out["entities"]["teams"]), 3)
        self.assertEqual(out["counts"]["nodes"], 4)

    def test_explicit_empty_scope_is_passthrough(self):
        inv = _scoped_inventory()
        m = _manifest({"scope": {"include_nodes": [], "exclude_nodes": []}})
        out = apply_overlay(inv, m)
        self.assertEqual(len(out["entities"]["nodes"]), 4)


class ScopeOrderingTests(unittest.TestCase):
    """Scope filter runs before role/SF edits; subsequent edits see
    the post-filter universe."""

    def test_scope_then_role_drop(self):
        """If scope drops a node containing a role AND roles.drop also
        names that role: scope wins (role gone via cascade), drop is a
        no-op on the post-scope set."""
        inv = _scoped_inventory()
        m = _manifest({
            "scope": {"exclude_nodes": ["Engineering"]},
            "roles": {"drop": ["EngLead"]},
        })
        out = apply_overlay(inv, m)
        role_names = [r["name"] for r in out["entities"]["roles"]]
        self.assertNotIn("EngLead", role_names)
        # No double-drop, no error.

    def test_scope_then_role_rename(self):
        """If scope drops a role's node, the role is gone before the
        rename pass — rename becomes a no-op for that name."""
        inv = _scoped_inventory()
        m = _manifest({
            "scope": {"exclude_nodes": ["Engineering"]},
            "roles": {"rename": {"EngLead": "EngineeringLead"}},
        })
        out = apply_overlay(inv, m)
        role_names = [r["name"] for r in out["entities"]["roles"]]
        self.assertNotIn("EngineeringLead", role_names)
        self.assertNotIn("EngLead", role_names)
