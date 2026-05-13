"""Tests for keepercommander.commands.keeper_tenant_migrate.declare.overlay — pure overlay engine."""
import unittest

from keepercommander.commands.keeper_tenant_migrate.declare.overlay import apply_overlay
from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


def _fixture_inventory():
    """Minimal in-memory inventory shaped like a real captured one."""
    return {
        "captured_at": "2026-05-07T00:00:00Z",
        "counts": {"roles": 3, "shared_folders": 2, "records": 2},
        "entities": {
            "roles": [
                {
                    "id": 1,
                    "name": "Admin",
                    "node": "Acme",
                    "enforcements": {
                        "require_account_share": "Admin",
                        "restrict_ip_addresses": "10.0.0.0/8",
                    },
                },
                {"id": 2, "name": "Basic", "node": "Acme", "enforcements": {}},
                {"id": 3, "name": "Guest", "node": "Acme", "enforcements": {}},
            ],
            "shared_folders": [
                {"uid": "sf1", "name": "Engineering"},
                {"uid": "sf2", "name": "Ops"},
            ],
            "records": [
                {"uid": "r1", "folder_uid": "sf1", "folder_path": "Engineering"},
                {"uid": "r2", "folder_uid": "sf1", "folder_path": "Engineering/Subfolder"},
            ],
        },
    }


def _manifest(edits):
    return OverlayManifest.model_validate(
        {"schema": "tenant-overlay.v1", "name": "test", "base": "/dev/null",
         "edits": edits}
    )


class RoleRenameTests(unittest.TestCase):
    def test_rename_basic(self):
        inv = _fixture_inventory()
        m = _manifest({"roles": {"rename": {"Admin": "Administrator"}}})
        out = apply_overlay(inv, m)
        names = [r["name"] for r in out["entities"]["roles"]]
        self.assertIn("Administrator", names)
        self.assertNotIn("Admin", names)

    def test_rename_propagates_to_require_account_share(self):
        inv = _fixture_inventory()
        m = _manifest({"roles": {"rename": {"Admin": "Administrator"}}})
        out = apply_overlay(inv, m)
        admin = next(r for r in out["entities"]["roles"] if r["name"] == "Administrator")
        self.assertEqual(admin["enforcements"]["require_account_share"], "Administrator")

    def test_rename_other_fields_preserved(self):
        inv = _fixture_inventory()
        m = _manifest({"roles": {"rename": {"Admin": "Administrator"}}})
        out = apply_overlay(inv, m)
        admin = next(r for r in out["entities"]["roles"] if r["name"] == "Administrator")
        self.assertEqual(admin["id"], 1)
        self.assertEqual(admin["enforcements"]["restrict_ip_addresses"], "10.0.0.0/8")


class RoleDropTests(unittest.TestCase):
    def test_drop_removes_role(self):
        inv = _fixture_inventory()
        m = _manifest({"roles": {"drop": ["Basic"]}})
        out = apply_overlay(inv, m)
        names = [r["name"] for r in out["entities"]["roles"]]
        self.assertNotIn("Basic", names)
        self.assertEqual(len(out["entities"]["roles"]), 2)

    def test_drop_decrements_count(self):
        inv = _fixture_inventory()
        m = _manifest({"roles": {"drop": ["Basic"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["counts"]["roles"], 2)


class StripEnforcementsTests(unittest.TestCase):
    def test_strip_removes_specified_keys(self):
        inv = _fixture_inventory()
        m = _manifest({"roles": {"strip_enforcements":
                                 {"Admin": ["require_account_share"]}}})
        out = apply_overlay(inv, m)
        admin = next(r for r in out["entities"]["roles"] if r["name"] == "Admin")
        self.assertNotIn("require_account_share", admin["enforcements"])
        self.assertIn("restrict_ip_addresses", admin["enforcements"])

    def test_strip_unknown_role_is_noop(self):
        inv = _fixture_inventory()
        m = _manifest({"roles": {"strip_enforcements":
                                 {"NoSuchRole": ["x"]}}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["roles"], inv["entities"]["roles"])


class SharedFolderRenameTests(unittest.TestCase):
    def test_rename_basic(self):
        inv = _fixture_inventory()
        m = _manifest({"shared_folders": {"rename": {"Engineering": "Eng"}}})
        out = apply_overlay(inv, m)
        names = [s["name"] for s in out["entities"]["shared_folders"]]
        self.assertIn("Eng", names)
        self.assertNotIn("Engineering", names)

    def test_rename_propagates_to_records_folder_path(self):
        inv = _fixture_inventory()
        m = _manifest({"shared_folders": {"rename": {"Engineering": "Eng"}}})
        out = apply_overlay(inv, m)
        paths = [r["folder_path"] for r in out["entities"]["records"]]
        self.assertEqual(paths, ["Eng", "Eng/Subfolder"])


class PurityTests(unittest.TestCase):
    def test_apply_does_not_mutate_base(self):
        inv = _fixture_inventory()
        snapshot = _fixture_inventory()
        m = _manifest({"roles": {"rename": {"Admin": "X"},
                                 "drop": ["Basic"]}})
        apply_overlay(inv, m)
        self.assertEqual(inv, snapshot)

    def test_no_edits_returns_equivalent(self):
        inv = _fixture_inventory()
        m = _manifest({})
        out = apply_overlay(inv, m)
        self.assertEqual(out, inv)


class RobustnessTests(unittest.TestCase):
    def test_entities_none_is_tolerated(self):
        """Regression for F1: a base inventory with entities=None must not
        raise — the helpers operate on whatever roles/sfs/records lists they
        find (none, in this case)."""
        out = apply_overlay({"entities": None},
                            _manifest({"roles": {"drop": ["X"]}}))
        # output passes through; no roles to drop, no exception
        self.assertIsNone(out["entities"])

    def test_entities_missing_is_tolerated(self):
        out = apply_overlay({"counts": {}},
                            _manifest({"roles": {"rename": {"X": "Y"}}}))
        # No entities key invented
        self.assertNotIn("entities", out)


class EditOrderTests(unittest.TestCase):
    """Pin the documented edit order: drops first, then strip_enforcements,
    then rename. strip therefore targets the OLD (pre-rename) role name."""

    def _admin(self, **enf):
        return {
            "id": 1, "name": "Admin", "node": "Acme",
            "enforcements": {"require_account_share": "Admin", **enf},
        }

    def test_drop_wins_when_both_target_same_role(self):
        inv = {"entities": {"roles": [self._admin()]}, "counts": {"roles": 1}}
        m = _manifest({"roles": {"drop": ["Admin"],
                                 "rename": {"Admin": "Administrator"}}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["roles"], [])

    def test_strip_targets_old_name_then_rename_runs(self):
        inv = {"entities": {"roles": [self._admin(restrict_ip_addresses="10/8")]},
               "counts": {"roles": 1}}
        m = _manifest({"roles": {
            "rename": {"Admin": "Administrator"},
            "strip_enforcements": {"Admin": ["restrict_ip_addresses"]},
        }})
        out = apply_overlay(inv, m)
        r = out["entities"]["roles"][0]
        # strip ran before rename — the key is gone
        self.assertNotIn("restrict_ip_addresses", r["enforcements"])
        # rename then propagated
        self.assertEqual(r["name"], "Administrator")
        self.assertEqual(r["enforcements"]["require_account_share"], "Administrator")

    def test_strip_using_new_name_is_a_noop(self):
        """Operator-facing contract: strip_enforcements keys are matched
        against the role's CURRENT (pre-rename) name. Using the post-rename
        name is therefore a no-op — caught here so any future re-ordering
        of operations updates this test deliberately."""
        inv = {"entities": {"roles": [self._admin(extra="x")]},
               "counts": {"roles": 1}}
        m = _manifest({"roles": {
            "rename": {"Admin": "Administrator"},
            "strip_enforcements": {"Administrator": ["extra"]},
        }})
        out = apply_overlay(inv, m)
        r = out["entities"]["roles"][0]
        self.assertEqual(r["name"], "Administrator")
        self.assertIn("extra", r["enforcements"])  # still present



if __name__ == "__main__":
    unittest.main()
