"""Phase 1.2 — teams.rename / teams.drop with cross-ref propagation
to roles[*].teams, shared_folders[*].teams, users[*].teams.

Heterogeneous entry shape: each `teams[*]` entry can be a plain name
string OR a dict with `team_name`/`name` keys per `structure.py:770-775`
(live_inventory emits strings; assemble-inventory emits dicts).
Both shapes handled.
"""
import unittest

from keepercommander.commands.keeper_tenant_migrate.declare.overlay import apply_overlay
from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


def _team_inv(role_team_shape="string", sf_team_shape="string",
              user_team_shape="string"):
    """Inventory with teams + role/SF/user teams[*] back-refs.

    `*_team_shape` controls how the teams[*] entries are emitted:
      - "string" — plain name strings (live_inventory shape)
      - "dict_team_name" — {"team_name": "Eng"}
      - "dict_name" — {"name": "Eng"}
      - "mixed" — first as string, second as dict
    """
    def make_team_ref(name, shape):
        if shape == "string":
            return name
        if shape == "dict_team_name":
            return {"team_name": name}
        if shape == "dict_name":
            return {"name": name}
        if shape == "mixed":
            return None  # caller fills in directly
        raise ValueError(shape)

    return {
        "captured_at": "2026-05-10T00:00:00Z",
        "counts": {"nodes": 0, "roles": 1, "teams": 2,
                   "shared_folders": 1, "records": 0},
        "entities": {
            "nodes": [],
            "roles": [
                {"id": 1, "name": "Lead",
                 "teams": [make_team_ref("Eng", role_team_shape),
                           make_team_ref("Ops", role_team_shape)]},
            ],
            "teams": [
                {"id": "t1", "name": "Eng"},
                {"id": "t2", "name": "Ops"},
            ],
            "shared_folders": [
                {"uid": "sf1", "name": "EngFolder",
                 "teams": [make_team_ref("Eng", sf_team_shape)]},
            ],
            "users": [
                {"email": "alice@x.com",
                 "teams": [make_team_ref("Eng", user_team_shape),
                           make_team_ref("Ops", user_team_shape)]},
            ],
            "records": [],
        },
    }


def _manifest(edits):
    return OverlayManifest.model_validate(
        {"schema": "tenant-overlay.v1", "name": "test",
         "base": "/dev/null", "edits": edits}
    )


# ─── Rename ──────────────────────────────────────────────────────────────────


class TeamRenameStringRefsTests(unittest.TestCase):
    """live_inventory shape: teams[*] entries are plain name strings."""

    def test_rename_propagates_to_role(self):
        inv = _team_inv(role_team_shape="string")
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        role = out["entities"]["roles"][0]
        self.assertEqual(role["teams"], ["Engineering", "Ops"])

    def test_rename_propagates_to_sf(self):
        inv = _team_inv(sf_team_shape="string")
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        sf = out["entities"]["shared_folders"][0]
        self.assertEqual(sf["teams"], ["Engineering"])

    def test_rename_propagates_to_user(self):
        inv = _team_inv(user_team_shape="string")
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        user = out["entities"]["users"][0]
        self.assertEqual(user["teams"], ["Engineering", "Ops"])

    def test_rename_renames_team_entity(self):
        inv = _team_inv()
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(names, ["Engineering", "Ops"])


class TeamRenameDictRefsTests(unittest.TestCase):
    """assemble-inventory shape: teams[*] entries are dicts."""

    def test_rename_propagates_to_dict_team_name(self):
        inv = _team_inv(role_team_shape="dict_team_name")
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        role = out["entities"]["roles"][0]
        self.assertEqual(role["teams"][0], {"team_name": "Engineering"})

    def test_rename_propagates_to_dict_name(self):
        inv = _team_inv(role_team_shape="dict_name")
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        role = out["entities"]["roles"][0]
        self.assertEqual(role["teams"][0], {"name": "Engineering"})

    def test_rename_preserves_dict_extra_fields(self):
        """dict entries with extra fields (beyond team_name/name) keep them."""
        inv = _team_inv()
        # Manually inject a richer dict entry
        inv["entities"]["roles"][0]["teams"] = [
            {"team_name": "Eng", "is_admin": True, "extra": "data"},
        ]
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        team_ref = out["entities"]["roles"][0]["teams"][0]
        self.assertEqual(team_ref["team_name"], "Engineering")
        self.assertTrue(team_ref["is_admin"])
        self.assertEqual(team_ref["extra"], "data")


class TeamRenameAtomicityTests(unittest.TestCase):
    """Swap and multi-rename patterns."""

    def test_swap_pattern(self):
        """{"Eng": "Ops", "Ops": "Eng"} swaps both teams atomically."""
        inv = _team_inv()
        m = _manifest({"teams": {"rename": {"Eng": "Ops", "Ops": "Eng"}}})
        out = apply_overlay(inv, m)
        # Team entities swapped names
        names = [t["name"] for t in out["entities"]["teams"]]
        self.assertEqual(names, ["Ops", "Eng"])  # order preserved by id
        # Role refs swapped: original was [Eng, Ops], now [Ops, Eng]
        self.assertEqual(out["entities"]["roles"][0]["teams"], ["Ops", "Eng"])

    def test_multi_rename(self):
        inv = _team_inv()
        m = _manifest({"teams": {"rename": {
            "Eng": "Engineering",
            "Ops": "Operations",
        }}})
        out = apply_overlay(inv, m)
        names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(names, ["Engineering", "Operations"])
        role_teams = sorted(out["entities"]["roles"][0]["teams"])
        self.assertEqual(role_teams, ["Engineering", "Operations"])


class TeamDropTests(unittest.TestCase):
    """drop removes teams + cascade-clears team-refs."""

    def test_drop_removes_team_entity(self):
        inv = _team_inv()
        m = _manifest({"teams": {"drop": ["Eng"]}})
        out = apply_overlay(inv, m)
        names = [t["name"] for t in out["entities"]["teams"]]
        self.assertEqual(names, ["Ops"])

    def test_drop_cascades_to_role_refs(self):
        inv = _team_inv()
        m = _manifest({"teams": {"drop": ["Eng"]}})
        out = apply_overlay(inv, m)
        # Role had ["Eng", "Ops"]; "Eng" removed
        self.assertEqual(out["entities"]["roles"][0]["teams"], ["Ops"])

    def test_drop_cascades_to_sf_refs(self):
        inv = _team_inv()
        m = _manifest({"teams": {"drop": ["Eng"]}})
        out = apply_overlay(inv, m)
        # SF had ["Eng"]; now empty
        self.assertEqual(out["entities"]["shared_folders"][0]["teams"], [])

    def test_drop_cascades_to_user_refs(self):
        inv = _team_inv()
        m = _manifest({"teams": {"drop": ["Eng"]}})
        out = apply_overlay(inv, m)
        # User had ["Eng", "Ops"]; "Eng" removed
        self.assertEqual(out["entities"]["users"][0]["teams"], ["Ops"])

    def test_drop_decrements_count(self):
        inv = _team_inv()
        m = _manifest({"teams": {"drop": ["Eng"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["counts"]["teams"], 1)  # 2 - 1

    def test_drop_with_dict_refs(self):
        inv = _team_inv(role_team_shape="dict_team_name")
        m = _manifest({"teams": {"drop": ["Eng"]}})
        out = apply_overlay(inv, m)
        # Role had [{team_name:Eng}, {team_name:Ops}]; first removed
        self.assertEqual(out["entities"]["roles"][0]["teams"],
                         [{"team_name": "Ops"}])


class TeamDropRenameInteractionTests(unittest.TestCase):
    """drop runs before rename (same as roles); drop wins on collisions."""

    def test_drop_before_rename(self):
        """If both drop and rename target the same team name, drop
        runs first → rename becomes a no-op."""
        inv = _team_inv()
        m = _manifest({"teams": {
            "drop": ["Eng"],
            "rename": {"Eng": "Engineering"},
        }})
        out = apply_overlay(inv, m)
        names = [t["name"] for t in out["entities"]["teams"]]
        self.assertEqual(names, ["Ops"])
        # Role refs: Eng was dropped (not renamed); only Ops left
        self.assertEqual(out["entities"]["roles"][0]["teams"], ["Ops"])


class TeamEdgeCasesTests(unittest.TestCase):
    """Missing fields, empty/no-op, malformed entries."""

    def test_empty_rename_passthrough(self):
        inv = _team_inv()
        m = _manifest({"teams": {"rename": {}}})
        out = apply_overlay(inv, m)
        names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(names, ["Eng", "Ops"])

    def test_rename_unknown_team_noop(self):
        inv = _team_inv()
        m = _manifest({"teams": {"rename": {"DoesNotExist": "Whatever"}}})
        out = apply_overlay(inv, m)
        names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(names, ["Eng", "Ops"])

    def test_inventory_with_no_users_field(self):
        """Some inventories may not carry a users list (rehearsal-16 had 0)."""
        inv = _team_inv()
        del inv["entities"]["users"]
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        # Doesn't crash; team entity renamed; role refs propagate
        names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(names, ["Engineering", "Ops"])

    def test_role_with_no_teams_field(self):
        inv = _team_inv()
        del inv["entities"]["roles"][0]["teams"]
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        # Doesn't crash; team renamed
        names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(names, ["Engineering", "Ops"])

    def test_dict_entry_with_neither_team_name_nor_name(self):
        """Dict entry with only unrelated keys — no team-name to match,
        rename leaves it alone."""
        inv = _team_inv()
        inv["entities"]["roles"][0]["teams"] = [{"unrelated_key": "value"}]
        m = _manifest({"teams": {"rename": {"Eng": "Engineering"}}})
        out = apply_overlay(inv, m)
        # Untouched
        self.assertEqual(out["entities"]["roles"][0]["teams"],
                         [{"unrelated_key": "value"}])
