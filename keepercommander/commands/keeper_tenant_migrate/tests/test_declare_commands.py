"""Tests for keepercommander.commands.keeper_tenant_migrate.declare.commands — CLI verb behavior.

Exercises DeclareValidateCommand and DeclareOverlayCommand directly
(no Commander session needed). Confirms exit-code 0/2 contract,
0o600 output, dry-run semantics, and that `declare` is registered
on TenantMigrateCommand.
"""
import json
import os
import stat
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.commands import TenantMigrateCommand
from keepercommander.commands.keeper_tenant_migrate.declare.commands import (
    DeclareGroupCommand,
    DeclareOverlayCommand,
    DeclareValidateCommand,
)


def _write_yaml(body):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    f.write(body)
    f.close()
    return f.name


def _write_json(data):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, f)
    f.close()
    return f.name


def _minimal_inventory():
    return {
        "counts": {"roles": 1},
        "entities": {
            "roles": [{"id": 1, "name": "Admin", "node": "Acme",
                       "enforcements": {}}],
            "shared_folders": [],
            "records": [],
        },
    }


class RegistrationTests(unittest.TestCase):
    def test_declare_registered_on_tenant_migrate(self):
        tm = TenantMigrateCommand()
        self.assertIn("declare", tm._commands)
        self.assertIsInstance(tm._commands["declare"], DeclareGroupCommand)

    def test_declare_subverbs(self):
        d = DeclareGroupCommand()
        self.assertEqual(set(d._commands), {"overlay", "validate"})


class ValidateExitCodeTests(unittest.TestCase):
    def setUp(self):
        self.cmd = DeclareValidateCommand()
        self._tmp = []

    def tearDown(self):
        for p in self._tmp:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def _yaml(self, body):
        p = _write_yaml(body)
        self._tmp.append(p)
        return p

    def test_pass(self):
        p = self._yaml(
            "schema: tenant-overlay.v1\nname: ok\nbase: /dev/null\n"
        )
        r = self.cmd.execute(None, manifest=p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["exit"], 0)

    def test_unknown_schema_version_exit_2(self):
        p = self._yaml(
            "schema: tenant-overlay.v2\nname: x\nbase: /dev/null\n"
        )
        r = self.cmd.execute(None, manifest=p)
        self.assertFalse(r["ok"])
        self.assertEqual(r["exit"], 2)
        self.assertEqual(r["reason"], "schema")

    def test_extra_field_exit_2(self):
        p = self._yaml(
            "schema: tenant-overlay.v1\nname: x\nbase: /p\nextra: 1\n"
        )
        r = self.cmd.execute(None, manifest=p)
        self.assertFalse(r["ok"])
        self.assertEqual(r["exit"], 2)
        self.assertEqual(r["reason"], "schema")

    def test_non_mapping_yaml_exit_2_parse(self):
        p = self._yaml("- not_a_mapping\n- another\n")
        r = self.cmd.execute(None, manifest=p)
        self.assertFalse(r["ok"])
        self.assertEqual(r["exit"], 2)
        self.assertEqual(r["reason"], "parse")


class OverlayCliTests(unittest.TestCase):
    def setUp(self):
        self.cmd = DeclareOverlayCommand()
        self._tmp = []
        self.base = _write_json(_minimal_inventory())
        self._tmp.append(self.base)

    def tearDown(self):
        for p in self._tmp:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def _yaml(self, body):
        p = _write_yaml(body)
        self._tmp.append(p)
        return p

    def _outpath(self):
        f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        f.close()
        os.unlink(f.name)  # let the command create with 0o600
        self._tmp.append(f.name)
        return f.name

    def test_overlay_writes_inventory_at_0o600(self):
        edits = self._yaml(
            f"schema: tenant-overlay.v1\nname: t\nbase: {self.base}\n"
            "edits:\n  roles:\n    rename:\n      Admin: Administrator\n"
        )
        out = self._outpath()
        r = self.cmd.execute(None, base=self.base, edits=edits, output=out)
        self.assertTrue(r["ok"])
        self.assertEqual(r["exit"], 0)
        mode = stat.S_IMODE(os.stat(out).st_mode)
        self.assertEqual(mode, 0o600)
        with open(out) as fh:
            data = json.load(fh)
        names = [r["name"] for r in data["entities"]["roles"]]
        self.assertEqual(names, ["Administrator"])

    def test_overlay_dry_run_does_not_write_output(self):
        edits = self._yaml(
            f"schema: tenant-overlay.v1\nname: t\nbase: {self.base}\nedits: {{}}\n"
        )
        out = self._outpath()
        r = self.cmd.execute(
            None, base=self.base, edits=edits, output=out, dry_run=True
        )
        self.assertTrue(r["ok"])
        self.assertTrue(r["dry_run"])
        self.assertFalse(os.path.exists(out))

    def test_overlay_bad_schema_returns_exit_2(self):
        edits = self._yaml(
            f"schema: tenant-overlay.v9\nname: t\nbase: {self.base}\nedits: {{}}\n"
        )
        out = self._outpath()
        r = self.cmd.execute(None, base=self.base, edits=edits, output=out)
        self.assertFalse(r["ok"])
        self.assertEqual(r["exit"], 2)

    def test_overlay_dangling_role_rename_exit_3(self):
        edits = self._yaml(
            f"schema: tenant-overlay.v1\nname: t\nbase: {self.base}\n"
            "edits:\n  roles:\n    rename:\n      DoesNotExist: X\n"
        )
        out = self._outpath()
        r = self.cmd.execute(None, base=self.base, edits=edits, output=out)
        self.assertFalse(r["ok"])
        self.assertEqual(r["exit"], 3)
        self.assertEqual(r["reason"], "dangling_ref")

    def test_overlay_secret_field_in_manifest_exit_2(self):
        edits = self._yaml(
            f"schema: tenant-overlay.v1\nname: t\nbase: {self.base}\n"
            "edits: {}\npassword: leaked\n"
        )
        out = self._outpath()
        r = self.cmd.execute(None, base=self.base, edits=edits, output=out)
        self.assertFalse(r["ok"])
        # Schema rejects 'password' (extra='forbid') AND secret_guard
        # would also fire — either way exit=2 / reason=schema or parse.
        self.assertEqual(r["exit"], 2)

if __name__ == "__main__":
    unittest.main()
