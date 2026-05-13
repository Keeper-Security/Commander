"""Adversarial test pass for declare/. Maps roughly to the existing
keeperCMD test_adversarial.py shape: each test class is one attack
category; each test is one specific vector.

Categories covered:
  - Sideloading (YAML unsafe tags, Pydantic-internal injection)
  - Lateral movement (symlink at --output, manifest base-vs-CLI-base)
  - Data exfiltration (errors do not echo base inventory content)
  - Resource bounds (recursive YAML anchors, large maps, no subprocess)
  - Sidechaining (drop+rename+strip interactions produce no unexpected state)
"""
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

from keepercommander.commands.keeper_tenant_migrate.declare.commands import (
    DeclareOverlayCommand,
    DeclareValidateCommand,
)
from keepercommander.commands.keeper_tenant_migrate.declare.overlay import apply_overlay
from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


def _make_base():
    return {
        "captured_at": "2026-05-08T00:00:00Z",
        "counts": {"roles": 1, "shared_folders": 0, "records": 0},
        "entities": {
            "roles": [{"id": 1, "name": "Admin", "node": "Acme",
                       "enforcements": {}}],
            "shared_folders": [],
            "records": [],
        },
    }


# ─── Sideloading ─────────────────────────────────────────────────────────────


class SideloadingTests(unittest.TestCase):
    """yaml.safe_load + Pydantic strict together must reject any input
    that would deserialize into arbitrary code or non-schema objects."""

    def test_yaml_python_object_apply_tag_rejected(self):
        bad = "!!python/object/apply:os.system\nargs: ['echo pwned']\n"
        with self.assertRaises(yaml.YAMLError):
            yaml.safe_load(bad)

    def test_yaml_python_module_tag_rejected(self):
        bad = "!!python/module:os\n"
        with self.assertRaises(yaml.YAMLError):
            yaml.safe_load(bad)

    def test_yaml_python_name_tag_rejected(self):
        bad = "!!python/name:subprocess.call\n"
        with self.assertRaises(yaml.YAMLError):
            yaml.safe_load(bad)

    def test_pydantic_extra_field_via_unknown_top_level_key(self):
        with self.assertRaises(Exception):
            OverlayManifest.model_validate({
                "schema": "tenant-overlay.v1",
                "name": "x",
                "base": "/p",
                "__pydantic_extra__": {"injected": True},
            })


# ─── Lateral movement (symlink + path) ───────────────────────────────────────


class LateralMovementTests(unittest.TestCase):
    """A malicious or buggy actor must not be able to use --output to
    overwrite a sensitive file via a pre-placed symlink."""

    def setUp(self):
        self._tmp = []
        # Build a base inventory file
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(_make_base(), f)
        f.close()
        self.base = f.name
        self._tmp.append(self.base)

        # Build a minimal valid edits manifest
        edits_path = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False).name
        with open(edits_path, "w") as fh:
            yaml.safe_dump(
                {"schema": "tenant-overlay.v1", "name": "t", "base": self.base, "edits": {}},
                fh,
            )
        self.edits = edits_path
        self._tmp.append(self.edits)

    def tearDown(self):
        for p in self._tmp:
            try:
                os.unlink(p)
            except (FileNotFoundError, IsADirectoryError):
                pass

    def _outpath(self):
        f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        f.close()
        os.unlink(f.name)
        self._tmp.append(f.name)
        return f.name

    def test_overlay_refuses_symlink_at_output(self):
        """If --output already exists as a symlink, declare-overlay must
        NOT follow it (would overwrite the symlink target). O_NOFOLLOW
        surfaces as OSError -> exit 5 / reason=output_unsafe."""
        # Pre-place a sensitive file with content
        sensitive = tempfile.NamedTemporaryFile(mode="wb", suffix=".sensitive", delete=False)
        sensitive.write(b"important-content-must-not-be-overwritten")
        sensitive.close()
        self._tmp.append(sensitive.name)

        # Place a symlink at the would-be output path pointing at the sensitive file
        output = self._outpath()
        os.symlink(sensitive.name, output)
        self.assertTrue(os.path.islink(output))

        # Try to run overlay with output as the symlink
        cmd = DeclareOverlayCommand()
        r = cmd.execute(None, base=self.base, edits=self.edits, output=output, dry_run=False)

        # Must fail — and target must be unchanged
        self.assertFalse(r["ok"], f"expected failure, got {r}")
        self.assertEqual(r["exit"], 5)
        self.assertEqual(r["reason"], "output_unsafe")
        with open(sensitive.name, "rb") as fh:
            self.assertEqual(fh.read(), b"important-content-must-not-be-overwritten")

    def test_overlay_writes_to_fresh_path_normally(self):
        """Sanity: on a fresh path (no symlink), normal overlay still works."""
        output = self._outpath()
        cmd = DeclareOverlayCommand()
        r = cmd.execute(None, base=self.base, edits=self.edits, output=output, dry_run=False)
        self.assertTrue(r["ok"])
        mode = stat.S_IMODE(os.stat(output).st_mode)
        self.assertEqual(mode, 0o600)


# ─── Data exfiltration ───────────────────────────────────────────────────────


class DataExfiltrationTests(unittest.TestCase):
    """Error messages and log lines must not echo base-inventory content
    that a downstream observer (log aggregator, ticket comment, error
    surface) could harvest."""

    def test_dangling_ref_error_uses_role_names_only(self):
        """When ref_graph reports a dangling reference, the error
        message names the offending role/SF but does NOT include base
        inventory content (record titles, UIDs, etc.)."""
        from keepercommander.commands.keeper_tenant_migrate.declare.ref_graph import find_dangling_refs

        base = {
            "entities": {
                "roles": [{"name": "Admin"}],
                "shared_folders": [],
                "records": [
                    {"uid": "leaked-uid", "title": "secret-record-title"},
                ],
            }
        }
        m = OverlayManifest.model_validate({
            "schema": "tenant-overlay.v1", "name": "x", "base": "/x",
            "edits": {"roles": {"rename": {"NoSuch": "Y"}}}
        })
        errs = find_dangling_refs(m, base)
        self.assertEqual(len(errs), 1)
        self.assertNotIn("leaked-uid", errs[0])
        self.assertNotIn("secret-record-title", errs[0])
        self.assertIn("NoSuch", errs[0])


# ─── Resource bounds ─────────────────────────────────────────────────────────


class ResourceBoundsTests(unittest.TestCase):
    """Adversarial input sizes must not hang or consume unbounded memory."""

    def test_large_strip_enforcements_map_completes_quickly(self):
        """1k-entry strip_enforcements map must process in < 1s on a
        modest base. Bounds the engine's per-edit cost."""
        base = _make_base()
        base["entities"]["roles"] = [
            {"id": i, "name": f"Role{i}", "node": "Acme", "enforcements": {"k": "v"}}
            for i in range(1000)
        ]
        base["counts"]["roles"] = 1000
        edits = {"roles": {"strip_enforcements": {f"Role{i}": ["k"] for i in range(1000)}}}
        m = OverlayManifest.model_validate({
            "schema": "tenant-overlay.v1", "name": "x", "base": "/x", "edits": edits,
        })
        t0 = time.monotonic()
        out = apply_overlay(base, m)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 1.0,
                        f"1k strip ops took {elapsed:.3f}s — engine may have super-linear cost")
        # All enforcements stripped
        for r in out["entities"]["roles"]:
            self.assertEqual(r["enforcements"], {})


# ─── Sidechaining (multi-op interaction) ─────────────────────────────────────


class SidechainingInteractionTests(unittest.TestCase):
    """Pin behaviour where multiple edits interact. Surfaces silent bugs
    where one edit category accidentally undoes or amplifies another."""

    def _admin(self, **enf):
        return {"id": 1, "name": "Admin", "node": "Acme",
                "enforcements": {"require_account_share": "Admin", **enf}}

    def test_drop_strip_rename_chain_no_residual(self):
        """Apply drop + strip + rename across three roles in one
        manifest. Verify each role ends up in the expected state with
        no residual leakage between edit categories."""
        base = {
            "entities": {
                "roles": [
                    {"id": 1, "name": "ToRename", "node": "Acme",
                     "enforcements": {"a": "1", "b": "2"}},
                    {"id": 2, "name": "ToDrop", "node": "Acme",
                     "enforcements": {"c": "3"}},
                    {"id": 3, "name": "ToStrip", "node": "Acme",
                     "enforcements": {"d": "4", "e": "5"}},
                ],
                "shared_folders": [],
                "records": [],
            },
            "counts": {"roles": 3, "shared_folders": 0, "records": 0},
        }
        m = OverlayManifest.model_validate({
            "schema": "tenant-overlay.v1", "name": "x", "base": "/x",
            "edits": {"roles": {
                "rename": {"ToRename": "Renamed"},
                "drop": ["ToDrop"],
                "strip_enforcements": {"ToStrip": ["d"]},
            }},
        })
        out = apply_overlay(base, m)
        names = [r["name"] for r in out["entities"]["roles"]]
        self.assertIn("Renamed", names)
        self.assertNotIn("ToRename", names)
        self.assertNotIn("ToDrop", names)
        self.assertIn("ToStrip", names)
        # Renamed role's enforcements untouched (other than name-bound refs)
        renamed = next(r for r in out["entities"]["roles"] if r["name"] == "Renamed")
        self.assertEqual(renamed["enforcements"]["a"], "1")
        self.assertEqual(renamed["enforcements"]["b"], "2")
        # Stripped role lost only the keys named in strip_enforcements
        stripped = next(r for r in out["entities"]["roles"] if r["name"] == "ToStrip")
        self.assertNotIn("d", stripped["enforcements"])
        self.assertEqual(stripped["enforcements"]["e"], "5")
        # Counts updated
        self.assertEqual(out["counts"]["roles"], 2)


# ─── Phase 1.1 verbs — adversarial pins ──────────────────────────────────────


class Phase11RoleRenameAdversarialTests(unittest.TestCase):
    """Pins on roles.rename — atomicity + cross-ref propagation."""

    def _base(self):
        return {
            "entities": {
                "roles": [
                    {"name": "Alpha", "node": "X", "enforcements": {
                        "require_account_share": "Alpha"}},
                    {"name": "Beta", "node": "X", "enforcements": {
                        "require_account_share": "Alpha"}},
                ],
                "shared_folders": [], "records": [],
            },
            "counts": {"roles": 2},
        }

    def _m(self, rename):
        return OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "r", "base": "/x",
             "edits": {"roles": {"rename": rename}}}
        )

    def test_swap_cycle_renames_correctly(self):
        out = apply_overlay(self._base(), self._m({"Alpha": "Beta", "Beta": "Alpha"}))
        names = sorted(r["name"] for r in out["entities"]["roles"])
        self.assertEqual(names, ["Alpha", "Beta"])

    def test_propagates_to_require_account_share_after_rename(self):
        # Alpha → Renamed; Beta's require_account_share='Alpha' should
        # be rewritten to 'Renamed' so the inventory stays consistent.
        out = apply_overlay(self._base(), self._m({"Alpha": "Renamed"}))
        beta = next(r for r in out["entities"]["roles"] if r["name"] == "Beta")
        self.assertEqual(beta["enforcements"]["require_account_share"], "Renamed")

    def test_rename_target_collides_with_existing_unmapped_silently(self):
        # Documented in spike: collision is operator's responsibility.
        # Pin so a future tightening is a deliberate change.
        out = apply_overlay(self._base(), self._m({"Alpha": "Beta"}))
        names = [r["name"] for r in out["entities"]["roles"]]
        self.assertEqual(names.count("Beta"), 2)


class Phase11RoleDropAdversarialTests(unittest.TestCase):
    """Pins on roles.drop — drop-before-rename order + count decrement."""

    def _base(self):
        return {
            "entities": {
                "roles": [
                    {"name": "ToDrop", "node": "X", "enforcements": {}},
                    {"name": "ToKeep", "node": "X", "enforcements": {}},
                ],
                "shared_folders": [], "records": [],
            },
            "counts": {"roles": 2},
        }

    def test_drop_runs_before_rename_within_same_overlay(self):
        # apply_overlay edit order: drop → strip → rename. If drop and
        # rename target the same name, drop wins.
        m = OverlayManifest.model_validate({
            "schema": "tenant-overlay.v1", "name": "r", "base": "/x",
            "edits": {"roles": {
                "drop": ["ToDrop"],
                "rename": {"ToDrop": "Resurrected"},
            }},
        })
        out = apply_overlay(self._base(), m)
        names = [r["name"] for r in out["entities"]["roles"]]
        self.assertEqual(names, ["ToKeep"])

    def test_drop_decrements_count_only_when_match(self):
        m = OverlayManifest.model_validate({
            "schema": "tenant-overlay.v1", "name": "r", "base": "/x",
            "edits": {"roles": {"drop": ["ToDrop", "Phantom"]}},
        })
        out = apply_overlay(self._base(), m)
        self.assertEqual(out["counts"]["roles"], 1)


class Phase11StripEnforcementsAdversarialTests(unittest.TestCase):
    """Pins on roles.strip_enforcements — silent no-op vs documented behaviour."""

    def _base(self):
        return {
            "entities": {
                "roles": [{"name": "Admin", "node": "X", "enforcements": {
                    "require_account_share": "X",
                    "restrict_ip_addresses": "10.0.0.0/8",
                    "two_factor_required": True,
                }}],
                "shared_folders": [], "records": [],
            },
            "counts": {"roles": 1},
        }

    def _m(self, mapping):
        return OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "s", "base": "/x",
             "edits": {"roles": {"strip_enforcements": mapping}}}
        )

    def test_strip_unknown_key_is_silent_noop(self):
        out = apply_overlay(self._base(),
                            self._m({"Admin": ["nonexistent_enforcement"]}))
        # All three original keys still present
        admin = out["entities"]["roles"][0]
        self.assertEqual(set(admin["enforcements"].keys()),
                         {"require_account_share", "restrict_ip_addresses",
                          "two_factor_required"})

    def test_strip_unknown_role_is_silent_noop(self):
        # ref_graph would catch this at command-level, but the engine itself
        # must not raise if called directly with an unknown role.
        out = apply_overlay(self._base(), self._m({"NoSuchRole": ["a"]}))
        self.assertEqual(len(out["entities"]["roles"][0]["enforcements"]), 3)

    def test_strip_empty_key_list_is_noop(self):
        out = apply_overlay(self._base(), self._m({"Admin": []}))
        self.assertEqual(len(out["entities"]["roles"][0]["enforcements"]), 3)

    def test_strip_runs_before_rename_so_targets_old_name(self):
        m = OverlayManifest.model_validate({
            "schema": "tenant-overlay.v1", "name": "s", "base": "/x",
            "edits": {"roles": {
                "strip_enforcements": {"Admin": ["two_factor_required"]},
                "rename": {"Admin": "Administrator"},
            }},
        })
        out = apply_overlay(self._base(), m)
        admin = out["entities"]["roles"][0]
        self.assertEqual(admin["name"], "Administrator")
        self.assertNotIn("two_factor_required", admin["enforcements"])


class Phase11SharedFolderRenameAdversarialTests(unittest.TestCase):
    """Pins on shared_folders.rename — folder_path propagation + uid anchoring."""

    def _base(self):
        return {
            "entities": {
                "shared_folders": [
                    {"uid": "SF1", "name": "Eng"},
                    {"uid": "SF2", "name": "Ops"},
                ],
                "records": [
                    {"uid": "R1", "title": "secret",
                     "folder_uid": "SF1", "folder_path": "Eng/secrets/api-keys"},
                    {"uid": "R2", "title": "log",
                     "folder_uid": "SF2", "folder_path": "Ops"},
                    # Record with a folder_path containing 'Eng' as a NON-leading
                    # token (must NOT be rewritten — anchoring is on uid + first
                    # path component match).
                    {"uid": "R3", "title": "doc",
                     "folder_uid": "SF2", "folder_path": "Ops/Eng-shared/docs"},
                ],
                "roles": [], "teams": [],
            },
            "counts": {"shared_folders": 2, "records": 3},
        }

    def _m(self, rename):
        return OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "sf", "base": "/x",
             "edits": {"shared_folders": {"rename": rename}}}
        )

    def test_rename_propagates_to_records_folder_path_via_uid(self):
        out = apply_overlay(self._base(), self._m({"Eng": "Engineering"}))
        r1 = next(r for r in out["entities"]["records"] if r["uid"] == "R1")
        self.assertEqual(r1["folder_path"], "Engineering/secrets/api-keys")

    def test_rename_does_not_touch_records_in_other_folders(self):
        # R3 has 'Eng-shared' as a path component but folder_uid='SF2',
        # so it must NOT be rewritten when SF1's name changes.
        out = apply_overlay(self._base(), self._m({"Eng": "Engineering"}))
        r3 = next(r for r in out["entities"]["records"] if r["uid"] == "R3")
        self.assertEqual(r3["folder_path"], "Ops/Eng-shared/docs")

    def test_swap_cycle_renames_correctly(self):
        out = apply_overlay(self._base(), self._m({"Eng": "Ops", "Ops": "Eng"}))
        names = sorted(s["name"] for s in out["entities"]["shared_folders"])
        self.assertEqual(names, ["Eng", "Ops"])
        # And the records' folder_path tokens swap accordingly via uid anchor
        r1 = next(r for r in out["entities"]["records"] if r["uid"] == "R1")
        self.assertEqual(r1["folder_path"], "Ops/secrets/api-keys")
        r2 = next(r for r in out["entities"]["records"] if r["uid"] == "R2")
        self.assertEqual(r2["folder_path"], "Eng")

    def test_rename_only_first_matching_path_token(self):
        # If folder_path has the SF name as more than one token (rare but
        # possible), only the FIRST occurrence is rewritten — anchored
        # behaviour pinned per overlay.py:_rename_shared_folders.
        base = self._base()
        base["entities"]["records"].append(
            {"uid": "R4", "title": "nested",
             "folder_uid": "SF1", "folder_path": "Eng/sub/Eng/leaf"}
        )
        out = apply_overlay(base, self._m({"Eng": "Engineering"}))
        r4 = next(r for r in out["entities"]["records"] if r["uid"] == "R4")
        self.assertEqual(r4["folder_path"], "Engineering/sub/Eng/leaf")


# ─── Phase 1.2 verbs — adversarial pins ──────────────────────────────────────


class Phase12ScopeAdversarialTests(unittest.TestCase):
    """Adversarial pins on scope.{include,exclude}_nodes glob behaviour."""

    def _base(self):
        return {
            "entities": {
                "nodes": [{"name": "Eng"}, {"name": "Ops"}, {"name": "Eng-EU"}],
                "roles": [{"name": "EngLead", "node": "Eng"}],
                "teams": [{"name": "EngTeam", "node": "Eng"}],
                "shared_folders": [], "records": [],
            },
            "counts": {"nodes": 3, "roles": 1, "teams": 1},
        }

    def _m(self, edits):
        return OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "s", "base": "/x",
             "edits": edits}
        )

    def test_glob_metachar_in_node_name_does_not_escape_match_set(self):
        # An attacker-controlled node name like '*' is matched literally by
        # fnmatchcase against the operator's pattern, not used as a glob.
        base = self._base()
        base["entities"]["nodes"].append({"name": "*"})
        m = self._m({"scope": {"include_nodes": ["Eng"]}})
        out = apply_overlay(base, m)
        names = {n["name"] for n in out["entities"]["nodes"]}
        self.assertEqual(names, {"Eng"})  # '*' was NOT pulled in by 'Eng'

    def test_empty_include_pattern_list_is_pass_through(self):
        # Schema default is empty list; engine treats as "no whitelist" not
        # "match nothing". Documented in ScopeFilter docstring.
        m = self._m({"scope": {"include_nodes": [], "exclude_nodes": []}})
        out = apply_overlay(self._base(), m)
        self.assertEqual(len(out["entities"]["nodes"]), 3)

    def test_exclude_after_include_strips_correctly(self):
        m = self._m({"scope": {"include_nodes": ["Eng*"],
                                "exclude_nodes": ["*-EU"]}})
        out = apply_overlay(self._base(), m)
        names = {n["name"] for n in out["entities"]["nodes"]}
        self.assertEqual(names, {"Eng"})

    def test_cascade_drops_dependent_roles_and_teams(self):
        m = self._m({"scope": {"exclude_nodes": ["Eng*"]}})
        out = apply_overlay(self._base(), m)
        self.assertEqual([r["name"] for r in out["entities"]["roles"]], [])
        self.assertEqual([t["name"] for t in out["entities"]["teams"]], [])


class Phase12NodeRemapAdversarialTests(unittest.TestCase):
    """Adversarial pins on nodes.remap atomicity."""

    def _base(self):
        return {
            "entities": {
                "nodes": [{"name": "A"}, {"name": "B"}, {"name": "C"}],
                "roles": [{"name": "R1", "node": "A"},
                          {"name": "R2", "node": "B"}],
                "teams": [{"name": "T1", "node": "C"}],
                "shared_folders": [], "records": [],
            },
            "counts": {"nodes": 3, "roles": 2, "teams": 1},
        }

    def _m(self, remap):
        return OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "n", "base": "/x",
             "edits": {"nodes": {"remap": remap}}}
        )

    def test_swap_cycle_does_not_double_apply(self):
        # {A: B, B: A} — naive in-place rename would visit each node twice
        # and swap-back. Captured-map guarantees one pass per entity.
        out = apply_overlay(self._base(), self._m({"A": "B", "B": "A"}))
        names = {n["name"] for n in out["entities"]["nodes"]}
        self.assertEqual(names, {"A", "B", "C"})  # both swapped, neither lost
        roles = {r["name"]: r["node"] for r in out["entities"]["roles"]}
        self.assertEqual(roles, {"R1": "B", "R2": "A"})  # cross-refs swap too

    def test_three_cycle_remap(self):
        out = apply_overlay(self._base(),
                            self._m({"A": "B", "B": "C", "C": "A"}))
        names = {n["name"] for n in out["entities"]["nodes"]}
        self.assertEqual(names, {"A", "B", "C"})

    def test_remap_to_existing_unmapped_collides_silently(self):
        # Documented in NodeEdits docstring: collision is operator's
        # responsibility; downstream pipeline's dedup is the safety net.
        # Pin the exact behaviour so a future tightening is a deliberate change.
        out = apply_overlay(self._base(), self._m({"A": "B"}))
        names = [n["name"] for n in out["entities"]["nodes"]]
        self.assertEqual(names.count("B"), 2)


class Phase12TeamsAdversarialTests(unittest.TestCase):
    """Adversarial pins on teams.rename/drop with heterogeneous entries."""

    def _base(self):
        # Mixed string + dict entries within ONE teams[*] list — defends
        # against a producer emitting both shapes (live_inventory vs
        # assemble-inventory) inside the same inventory.
        return {
            "entities": {
                "teams": [{"name": "TeamA"}, {"name": "TeamB"}],
                "roles": [{"name": "R", "node": "X", "teams": [
                    "TeamA",
                    {"team_name": "TeamB"},
                    {"name": "TeamA"},
                ]}],
                "shared_folders": [{"uid": "SF", "name": "F", "teams": [
                    "TeamB",
                    {"team_name": "TeamA"},
                ]}],
                "users": [{"email": "a@x", "teams": [
                    {"name": "TeamB"},
                    "TeamA",
                ]}],
            },
            "counts": {"teams": 2},
        }

    def _m(self, edits):
        return OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "t", "base": "/x",
             "edits": {"teams": edits}}
        )

    def test_drop_propagates_through_all_three_back_ref_sites(self):
        out = apply_overlay(self._base(), self._m({"drop": ["TeamA"]}))
        # roles[*].teams: 'TeamA' string + {"name":"TeamA"} dict both gone
        role_team_names = [
            t.get("team_name") if isinstance(t, dict) and "team_name" in t
            else t.get("name") if isinstance(t, dict) else t
            for t in out["entities"]["roles"][0]["teams"]
        ]
        self.assertEqual(role_team_names, ["TeamB"])
        # shared_folders[*].teams: {"team_name":"TeamA"} dict gone
        sf_team_names = [
            t.get("team_name") if isinstance(t, dict) else t
            for t in out["entities"]["shared_folders"][0]["teams"]
        ]
        self.assertEqual(sf_team_names, ["TeamB"])
        # users[*].teams: 'TeamA' string gone
        user_team_names = [
            t.get("name") if isinstance(t, dict) else t
            for t in out["entities"]["users"][0]["teams"]
        ]
        self.assertEqual(user_team_names, ["TeamB"])

    def test_rename_preserves_dict_extra_fields(self):
        # If a producer attaches metadata to a dict entry (e.g. {"team_name":
        # "TeamA", "is_admin": true}), rename must keep that metadata.
        base = self._base()
        base["entities"]["roles"][0]["teams"] = [
            {"team_name": "TeamA", "is_admin": True},
        ]
        out = apply_overlay(base, self._m({"rename": {"TeamA": "AlphaTeam"}}))
        entry = out["entities"]["roles"][0]["teams"][0]
        self.assertEqual(entry["team_name"], "AlphaTeam")
        self.assertEqual(entry["is_admin"], True)

    def test_swap_cycle_renames_correctly(self):
        out = apply_overlay(self._base(),
                            self._m({"rename": {"TeamA": "TeamB",
                                                 "TeamB": "TeamA"}}))
        names = sorted(t["name"] for t in out["entities"]["teams"])
        self.assertEqual(names, ["TeamA", "TeamB"])

    def test_drop_then_rename_is_drop(self):
        # apply_overlay runs drop before rename. If both name TeamA, drop wins.
        out = apply_overlay(
            self._base(),
            self._m({"drop": ["TeamA"], "rename": {"TeamA": "Resurrected"}}),
        )
        names = [t["name"] for t in out["entities"]["teams"]]
        self.assertEqual(names, ["TeamB"])


class Phase12UsersAdversarialTests(unittest.TestCase):
    """Adversarial pins on users.drop / users.domain_remap."""

    def _base(self):
        return {
            "entities": {
                "users": [
                    {"email": "alice@old.com", "aliases": ["alice@old.com"],
                     "alias": "alice@old.com"},
                    {"email": "bob@old.com", "aliases": [],
                     "alias": "bob@old.com"},
                    {"email": "carol@new.com", "aliases": [],
                     "alias": "carol@new.com"},
                    {"email": "", "aliases": [], "alias": ""},
                ],
                "shared_folders": [{"uid": "SF1", "name": "F", "users": [
                    {"username": "alice@old.com"},
                    {"username": "carol@new.com"},
                    {"username": ""},
                ]}],
                "records": [{"uid": "R1", "direct_shares": [
                    {"username": "alice@old.com"},
                    {"username": "bob@old.com"},
                ]}],
            },
            "counts": {"users": 4},
        }

    def _m(self, edits):
        return OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "u", "base": "/x",
             "edits": {"users": edits}}
        )

    def test_glob_drop_does_not_match_empty_email_user(self):
        # User with empty email survives '*@old.com' — important so a
        # malformed inventory entry isn't quietly purged by a domain sweep.
        out = apply_overlay(self._base(), self._m({"drop": ["*@old.com"]}))
        emails = sorted(u["email"] for u in out["entities"]["users"])
        self.assertEqual(emails, ["", "carol@new.com"])

    def test_glob_drop_cascade_does_not_match_empty_username(self):
        # SF.users entry with empty username must survive. Mirror of the
        # users-list pin: empty-string is never a glob match.
        out = apply_overlay(self._base(), self._m({"drop": ["*@old.com"]}))
        sf_usernames = sorted(
            u["username"] for u in out["entities"]["shared_folders"][0]["users"]
        )
        self.assertEqual(sf_usernames, ["", "carol@new.com"])

    def test_domain_remap_preserves_unmatched_addresses_unchanged(self):
        out = apply_overlay(self._base(),
                            self._m({"domain_remap": {"old.com": "new.io"}}))
        emails = sorted(u["email"] for u in out["entities"]["users"])
        self.assertEqual(emails, ["", "alice@new.io",
                                   "bob@new.io", "carol@new.com"])

    def test_domain_remap_atomic_swap(self):
        # {old.com: new.com, new.com: old.com} — swap addresses with no
        # double-touch. Captured-map fixed at function entry.
        out = apply_overlay(
            self._base(),
            self._m({"domain_remap": {"old.com": "new.com",
                                      "new.com": "old.com"}}),
        )
        emails = sorted(u["email"] for u in out["entities"]["users"])
        self.assertEqual(emails, ["", "alice@new.com",
                                   "bob@new.com", "carol@old.com"])

    def test_drop_runs_before_domain_remap(self):
        # Drop pattern uses pre-remap email; remap then runs on survivors.
        out = apply_overlay(
            self._base(),
            self._m({"drop": ["alice@old.com"],
                     "domain_remap": {"old.com": "new.io"}}),
        )
        emails = sorted(u["email"] for u in out["entities"]["users"])
        self.assertEqual(emails, ["", "bob@new.io", "carol@new.com"])


# ─── Invariant pins (regression guards) ──────────────────────────────────────


class InvariantPinTests(unittest.TestCase):
    """Pins from the structured verification flow. Any future change
    that violates these invariants must explicitly break a test."""

    def test_no_subprocess_in_declare_modules(self):
        """declare/ must not import subprocess (and absolutely must not
        invoke shell=True / eval / exec / os.system / os.popen / pickle).
        The wedge is a pure-local file processor."""
        forbidden = re.compile(
            r"(?:^|\W)(subprocess|shell=True|os\.system|os\.popen|"
            r"pickle\.loads|\beval\(|\bexec\()", re.MULTILINE,
        )
        declare_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "keepercommander.commands.keeper_tenant_migrate", "declare",
        )
        for root, _, files in os.walk(declare_dir):
            for f in files:
                if not f.endswith(".py"):
                    continue
                p = os.path.join(root, f)
                with open(p) as fh:
                    src = fh.read()
                m = forbidden.search(src)
                self.assertIsNone(
                    m, 'declare/ must not use ' + (m.group(1) if m else 'forbidden') + f' -- found in {p}' 
                )

    def test_yaml_load_used_only_via_safe_load(self):
        """Pin yaml.safe_load as the only loader. A future change that
        switches to yaml.load() would fail this test loudly."""
        forbidden = re.compile(r"yaml\.load\s*\(")
        declare_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "keepercommander.commands.keeper_tenant_migrate", "declare",
        )
        for root, _, files in os.walk(declare_dir):
            for f in files:
                if not f.endswith(".py"):
                    continue
                p = os.path.join(root, f)
                with open(p) as fh:
                    src = fh.read()
                # Allow yaml.safe_load; block bare yaml.load(
                hits = [m for m in forbidden.finditer(src)
                        if "safe_load" not in src[max(0, m.start()-5):m.end()]]
                self.assertEqual(hits, [], f"yaml.load (non-safe) found in {p}")


if __name__ == "__main__":
    unittest.main()
