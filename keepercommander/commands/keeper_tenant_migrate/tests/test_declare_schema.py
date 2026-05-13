"""Tests for keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1."""
import unittest

from pydantic import ValidationError

from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


class SchemaContractTests(unittest.TestCase):
    def test_minimal_valid_manifest(self):
        m = OverlayManifest.model_validate(
            {"schema": "tenant-overlay.v1", "name": "x", "base": "/p"}
        )
        self.assertEqual(m.schema_, "tenant-overlay.v1")
        self.assertEqual(m.name, "x")

    def test_schema_field_required(self):
        with self.assertRaises(ValidationError):
            OverlayManifest.model_validate({"name": "x", "base": "/p"})

    def test_schema_pinned_to_v1(self):
        with self.assertRaises(ValidationError):
            OverlayManifest.model_validate(
                {"schema": "tenant-overlay.v2", "name": "x", "base": "/p"}
            )

    def test_extra_top_level_field_rejected(self):
        with self.assertRaises(ValidationError):
            OverlayManifest.model_validate(
                {"schema": "tenant-overlay.v1", "name": "x",
                 "base": "/p", "extra": 1}
            )

    def test_extra_field_in_edits_rejected(self):
        with self.assertRaises(ValidationError):
            OverlayManifest.model_validate(
                {"schema": "tenant-overlay.v1", "name": "x", "base": "/p",
                 "edits": {"roles": {"bogus": True}}}
            )

    def test_roles_rename_value_must_be_string(self):
        with self.assertRaises(ValidationError):
            OverlayManifest.model_validate(
                {"schema": "tenant-overlay.v1", "name": "x", "base": "/p",
                 "edits": {"roles": {"rename": {"A": 12345}}}}
            )

    def test_strip_enforcements_value_must_be_list_of_strings(self):
        with self.assertRaises(ValidationError):
            OverlayManifest.model_validate(
                {"schema": "tenant-overlay.v1", "name": "x", "base": "/p",
                 "edits": {"roles": {"strip_enforcements": {"A": "single-string"}}}}
            )


if __name__ == "__main__":
    unittest.main()
