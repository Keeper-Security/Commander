"""Phase 1.2 — nodes.remap: node rename with cross-ref propagation
to roles[*].node and teams[*].node. Exact-name match (not glob);
atomic against captured remap dict so swap patterns work."""
import unittest

from keepercommander.commands.keeper_tenant_migrate.declare.overlay import apply_overlay
from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


def _node_inv():
    """Inventory with nodes + node-referencing roles + teams + a
    tenant-level role (no node assignment)."""
    return {
        "captured_at": "2026-05-10T00:00:00Z",
        "counts": {"nodes": 3, "roles": 3, "teams": 2,
                   "shared_folders": 0, "records": 0},
        "entities": {
            "nodes": [
                {"uid": "n1", "name": "Acme"},
                {"uid": "n2", "name": "Engineering"},
                {"uid": "n3", "name": "Operations"},
            ],
            "roles": [
                {"id": 1, "name": "Admin", "node": "Acme"},
                {"id": 2, "name": "EngLead", "node": "Engineering"},
                {"id": 3, "name": "Tenant"},  # no node
            ],
            "teams": [
                {"id": "t1", "name": "Eng", "node": "Engineering"},
                {"id": "t2", "name": "Ops", "node": "Operations"},
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


class NodeRemapBasicTests(unittest.TestCase):
    """Single-node rename + propagation."""

    def test_rename_single_node(self):
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {"Engineering": "Eng"}}})
        out = apply_overlay(inv, m)
        names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(names, ["Acme", "Eng", "Operations"])

    def test_rename_propagates_to_role_node(self):
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {"Engineering": "Eng"}}})
        out = apply_overlay(inv, m)
        eng_lead = next(r for r in out["entities"]["roles"]
                        if r["name"] == "EngLead")
        self.assertEqual(eng_lead["node"], "Eng")

    def test_rename_propagates_to_team_node(self):
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {"Engineering": "Eng"}}})
        out = apply_overlay(inv, m)
        eng_team = next(t for t in out["entities"]["teams"] if t["name"] == "Eng")
        self.assertEqual(eng_team["node"], "Eng")

    def test_unrelated_role_unaffected(self):
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {"Engineering": "Eng"}}})
        out = apply_overlay(inv, m)
        admin = next(r for r in out["entities"]["roles"] if r["name"] == "Admin")
        self.assertEqual(admin["node"], "Acme")  # unchanged

    def test_tenant_level_role_unaffected(self):
        """A role with no `node` field is tenant-wide; remap doesn't touch it."""
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {"Engineering": "Eng"}}})
        out = apply_overlay(inv, m)
        tenant = next(r for r in out["entities"]["roles"] if r["name"] == "Tenant")
        self.assertNotIn("node", tenant)


class NodeRemapMultipleTests(unittest.TestCase):
    """Multi-node remap in single overlay."""

    def test_remap_multiple_nodes(self):
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {
            "Engineering": "Eng",
            "Operations": "Ops",
        }}})
        out = apply_overlay(inv, m)
        names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(names, ["Acme", "Eng", "Ops"])

    def test_swap_pattern_works_atomically(self):
        """``{"A": "B", "B": "A"}`` should swap correctly — depends on
        atomic capture of remap dict before rewrite."""
        inv = {
            "entities": {
                "nodes": [{"uid": "x", "name": "A"},
                          {"uid": "y", "name": "B"}],
                "roles": [{"id": 1, "name": "rA", "node": "A"},
                          {"id": 2, "name": "rB", "node": "B"}],
                "teams": [],
                "shared_folders": [], "records": [],
            },
            "counts": {"nodes": 2, "roles": 2, "teams": 0,
                       "shared_folders": 0, "records": 0},
        }
        m = _manifest({"nodes": {"remap": {"A": "B", "B": "A"}}})
        out = apply_overlay(inv, m)
        # Each node gets renamed to its swapped target; no double-swap.
        node_names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(node_names, ["A", "B"])
        # Role refs swap accordingly: rA's node was A → B; rB's was B → A.
        ra = next(r for r in out["entities"]["roles"] if r["name"] == "rA")
        rb = next(r for r in out["entities"]["roles"] if r["name"] == "rB")
        self.assertEqual(ra["node"], "B")
        self.assertEqual(rb["node"], "A")

    def test_remap_target_collision_allowed(self):
        """``{"A": "X", "B": "X"}`` collides two nodes both at X.
        Operator's responsibility; downstream pipeline's dedup catches it."""
        inv = {
            "entities": {
                "nodes": [{"uid": "x", "name": "A"},
                          {"uid": "y", "name": "B"}],
                "roles": [], "teams": [],
                "shared_folders": [], "records": [],
            },
            "counts": {"nodes": 2, "roles": 0, "teams": 0,
                       "shared_folders": 0, "records": 0},
        }
        m = _manifest({"nodes": {"remap": {"A": "X", "B": "X"}}})
        out = apply_overlay(inv, m)
        names = [n["name"] for n in out["entities"]["nodes"]]
        # Both renamed to X; collision NOT auto-resolved.
        self.assertEqual(sorted(names), ["X", "X"])


class NodeRemapEdgeCasesTests(unittest.TestCase):
    """Edge cases: missing fields, empty remap, no-op renames."""

    def test_empty_remap_is_passthrough(self):
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {}}})
        out = apply_overlay(inv, m)
        node_names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(node_names, ["Acme", "Engineering", "Operations"])

    def test_remap_unknown_node_is_noop(self):
        """Renaming a node that doesn't exist — no error, no effect."""
        inv = _node_inv()
        m = _manifest({"nodes": {"remap": {"DoesNotExist": "Whatever"}}})
        out = apply_overlay(inv, m)
        node_names = sorted(n["name"] for n in out["entities"]["nodes"])
        self.assertEqual(node_names, ["Acme", "Engineering", "Operations"])

    def test_node_with_no_name_field_is_skipped(self):
        inv = {
            "entities": {
                "nodes": [{"uid": "x"},  # no name
                          {"uid": "y", "name": "Real"}],
                "roles": [], "teams": [],
                "shared_folders": [], "records": [],
            },
            "counts": {"nodes": 2, "roles": 0, "teams": 0,
                       "shared_folders": 0, "records": 0},
        }
        m = _manifest({"nodes": {"remap": {"Real": "Renamed"}}})
        out = apply_overlay(inv, m)
        names = [n.get("name") for n in out["entities"]["nodes"]]
        # Order preserved; nameless entry untouched; named entry renamed.
        self.assertEqual(names, [None, "Renamed"])


class NodeRemapOrderingTests(unittest.TestCase):
    """Ordering with scope filter + role/SF edits."""

    def test_scope_then_remap(self):
        """Scope drops Operations first; remap then operates on
        post-scope universe (Operations is gone, won't be remapped)."""
        inv = _node_inv()
        m = _manifest({
            "scope": {"exclude_nodes": ["Operations"]},
            "nodes": {"remap": {"Operations": "Ops",
                                "Engineering": "Eng"}},
        })
        out = apply_overlay(inv, m)
        node_names = sorted(n["name"] for n in out["entities"]["nodes"])
        # Operations dropped; Engineering renamed.
        self.assertEqual(node_names, ["Acme", "Eng"])
        # Role ref propagation only for surviving nodes.
        eng_lead = next(r for r in out["entities"]["roles"]
                        if r["name"] == "EngLead")
        self.assertEqual(eng_lead["node"], "Eng")

    def test_remap_then_role_rename(self):
        """remap runs before role rename; role rename sees post-remap
        node names but operates on role names (independent axis)."""
        inv = _node_inv()
        m = _manifest({
            "nodes": {"remap": {"Engineering": "Eng"}},
            "roles": {"rename": {"EngLead": "EngineeringLead"}},
        })
        out = apply_overlay(inv, m)
        # Role renamed; its node ref already remapped.
        renamed = next(r for r in out["entities"]["roles"]
                       if r["name"] == "EngineeringLead")
        self.assertEqual(renamed["node"], "Eng")

    def test_remap_then_role_drop(self):
        """remap then drop. Dropped role's node ref doesn't matter."""
        inv = _node_inv()
        m = _manifest({
            "nodes": {"remap": {"Engineering": "Eng"}},
            "roles": {"drop": ["EngLead"]},
        })
        out = apply_overlay(inv, m)
        role_names = sorted(r["name"] for r in out["entities"]["roles"])
        self.assertEqual(role_names, ["Admin", "Tenant"])


class NodeRemapMissingFieldsTests(unittest.TestCase):
    """Inventory with missing entity fields — no crashes."""

    def test_no_nodes_field(self):
        inv = {
            "entities": {"roles": [{"id": 1, "name": "R", "node": "X"}],
                         "teams": [], "shared_folders": [], "records": []},
            "counts": {"nodes": 0, "roles": 1, "teams": 0,
                       "shared_folders": 0, "records": 0},
        }
        m = _manifest({"nodes": {"remap": {"X": "Y"}}})
        out = apply_overlay(inv, m)
        # No nodes to rename, but role ref still propagates.
        role = out["entities"]["roles"][0]
        self.assertEqual(role["node"], "Y")

    def test_no_roles_field(self):
        inv = {
            "entities": {"nodes": [{"uid": "x", "name": "A"}],
                         "shared_folders": [], "records": []},
            "counts": {"nodes": 1, "roles": 0, "teams": 0,
                       "shared_folders": 0, "records": 0},
        }
        m = _manifest({"nodes": {"remap": {"A": "B"}}})
        out = apply_overlay(inv, m)
        # No roles to propagate to; node renamed.
        self.assertEqual(out["entities"]["nodes"][0]["name"], "B")

    def test_role_with_no_node_field_unaffected(self):
        inv = {
            "entities": {
                "nodes": [{"uid": "x", "name": "A"}],
                "roles": [{"id": 1, "name": "TenantLevel"}],  # no node
                "teams": [],
                "shared_folders": [], "records": [],
            },
            "counts": {"nodes": 1, "roles": 1, "teams": 0,
                       "shared_folders": 0, "records": 0},
        }
        m = _manifest({"nodes": {"remap": {"A": "B"}}})
        out = apply_overlay(inv, m)
        role = out["entities"]["roles"][0]
        self.assertNotIn("node", role)
