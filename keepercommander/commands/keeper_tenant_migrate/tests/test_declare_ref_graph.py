"""Tests for keepercommander.commands.keeper_tenant_migrate.declare.ref_graph."""
import unittest

from keepercommander.commands.keeper_tenant_migrate.declare.ref_graph import find_dangling_refs
from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


def _m(edits):
    return OverlayManifest.model_validate(
        {"schema": "tenant-overlay.v1", "name": "t",
         "base": "/dev/null", "edits": edits}
    )


def _base():
    return {
        "entities": {
            "roles": [{"name": "Admin"}, {"name": "Basic"}],
            "shared_folders": [{"name": "Engineering"}],
            "nodes": [{"name": "Eng"}, {"name": "Ops"}],
            "teams": [{"name": "TeamA"}, {"name": "TeamB"}],
        }
    }


class RefGraphTests(unittest.TestCase):
    def test_clean_manifest_no_errors(self):
        m = _m({"roles": {"rename": {"Admin": "Administrator"},
                          "drop": ["Basic"]},
                "shared_folders": {"rename": {"Engineering": "Eng"}}})
        self.assertEqual(find_dangling_refs(m, _base()), [])

    def test_dangling_role_rename(self):
        m = _m({"roles": {"rename": {"NoSuch": "X"}}})
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 1)
        self.assertIn("NoSuch", errs[0])
        self.assertIn("rename", errs[0])

    def test_dangling_role_drop(self):
        m = _m({"roles": {"drop": ["NoSuch", "Admin"]}})
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 1)
        self.assertIn("NoSuch", errs[0])

    def test_dangling_role_strip(self):
        m = _m({"roles": {"strip_enforcements": {"Ghost": ["x"]}}})
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 1)
        self.assertIn("Ghost", errs[0])
        self.assertIn("strip_enforcements", errs[0])

    def test_dangling_sf_rename(self):
        m = _m({"shared_folders": {"rename": {"Phantom": "P"}}})
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 1)
        self.assertIn("Phantom", errs[0])

    def test_multiple_dangling(self):
        m = _m({
            "roles": {"rename": {"NoSuch1": "X"},
                      "drop": ["NoSuch2"]},
            "shared_folders": {"rename": {"NoSuch3": "Y"}},
        })
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 3)

    def test_empty_base_all_refs_dangle(self):
        m = _m({"roles": {"rename": {"Admin": "X"}}})
        self.assertEqual(len(find_dangling_refs(m, {})), 1)

    def test_base_with_none_entities(self):
        m = _m({"roles": {"drop": ["Admin"]}})
        self.assertEqual(len(find_dangling_refs(m, {"entities": None})), 1)

    # Phase 1.2 verbs — exact-name validation

    def test_clean_node_remap(self):
        m = _m({"nodes": {"remap": {"Eng": "Engineering"}}})
        self.assertEqual(find_dangling_refs(m, _base()), [])

    def test_dangling_node_remap(self):
        m = _m({"nodes": {"remap": {"NoSuch": "X"}}})
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 1)
        self.assertIn("NoSuch", errs[0])
        self.assertIn("nodes.remap", errs[0])

    def test_clean_team_rename_drop(self):
        m = _m({"teams": {"rename": {"TeamA": "AlphaTeam"},
                          "drop": ["TeamB"]}})
        self.assertEqual(find_dangling_refs(m, _base()), [])

    def test_dangling_team_rename(self):
        m = _m({"teams": {"rename": {"Ghost": "X"}}})
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 1)
        self.assertIn("Ghost", errs[0])
        self.assertIn("teams.rename", errs[0])

    def test_dangling_team_drop(self):
        m = _m({"teams": {"drop": ["Ghost", "TeamA"]}})
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 1)
        self.assertIn("Ghost", errs[0])
        self.assertIn("teams.drop", errs[0])

    def test_scope_globs_not_validated(self):
        # Globs can intentionally match zero nodes; ref_graph stays silent.
        m = _m({"scope": {"include_nodes": ["NoSuchNode-*"],
                          "exclude_nodes": ["AlsoMissing-?"]}})
        self.assertEqual(find_dangling_refs(m, _base()), [])

    def test_users_drop_glob_not_validated(self):
        m = _m({"users": {"drop": ["*@nonexistent.com"]}})
        self.assertEqual(find_dangling_refs(m, _base()), [])

    def test_users_domain_remap_not_validated(self):
        # Domain keys aren't user identifiers; pre-staging a remap for an
        # absent domain is legitimate (idempotent reapply).
        m = _m({"users": {"domain_remap": {"absent.com": "new.com"}}})
        self.assertEqual(find_dangling_refs(m, _base()), [])

    def test_phase_1_2_multi_dangling(self):
        m = _m({
            "nodes": {"remap": {"NoNode": "X"}},
            "teams": {"rename": {"NoTeam": "Y"},
                      "drop": ["NoTeam2"]},
        })
        errs = find_dangling_refs(m, _base())
        self.assertEqual(len(errs), 3)


if __name__ == "__main__":
    unittest.main()
