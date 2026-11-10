#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import os
import tempfile
import unittest
from unittest import mock

from keepercommander.importer import commands
from keepercommander.importer.importer import PathDelimiter, SharedFolder


class TestApplyPamProjectPrefix(unittest.TestCase):
    def test_bare_safe_maps_under_pam_project(self):
        path = commands.apply_pam_project_prefix("Acme_Michael_Rodriguez", "Acme Test Import")
        expected = PathDelimiter.join(
            ["PAM Environments", "Acme Test Import", "Acme_Michael_Rodriguez"]
        )
        self.assertEqual(path, expected)

    def test_already_prefixed_path_is_unchanged(self):
        existing = PathDelimiter.join(
            ["PAM Environments", "Acme Test Import", "Acme_David_Chen"]
        )
        self.assertEqual(
            commands.apply_pam_project_prefix(existing, "Acme Test Import"),
            existing,
        )

    def test_forward_slash_prefixed_path_is_normalized(self):
        existing = "PAM Environments/Acme Test Import/Acme_Jane_Miller"
        result = commands.apply_pam_project_prefix(existing, "Acme Test Import")
        expected = PathDelimiter.join(
            ["PAM Environments", "Acme Test Import", "Acme_Jane_Miller"]
        )
        self.assertEqual(result, expected)

    def test_empty_project_returns_original_path(self):
        self.assertEqual(
            commands.apply_pam_project_prefix("Safe One", ""),
            "Safe One",
        )

    def test_sanitize_strips_path_separators_in_leaf(self):
        path = commands.apply_pam_project_prefix("Bad/Name", "Proj")
        expected = PathDelimiter.join(["PAM Environments", "Proj", "Bad_Name"])
        self.assertEqual(path, expected)

    def test_multiple_leading_trailing_separators(self):
        """Test that multiple leading/trailing separators are properly stripped."""
        path = "///Acme_Safe\\\\"
        result = commands.membership_safe_name(path)
        self.assertEqual(result, "Acme_Safe")

    def test_mixed_separators_in_middle_are_sanitized(self):
        """Test that mixed separators in the middle are sanitized to underscores."""
        path = commands.apply_pam_project_prefix("Path/With\\Mixed", "Proj")
        self.assertIn("Path_With_Mixed", path)

    def test_empty_safe_name_after_sanitization(self):
        """Test handling when safe name becomes empty after sanitization."""
        path = commands.apply_pam_project_prefix("///", "Proj")
        self.assertIsNotNone(path)

    def test_prefix_case_variation_in_project_name(self):
        """Test prefix matching with different case variations."""
        existing = PathDelimiter.join(["PAM Environments", "acme test", "Safe"])
        result = commands.apply_pam_project_prefix(existing, "Acme Test")
        count = result.count("PAM Environments")
        self.assertEqual(count, 1, "Should not duplicate PAM Environments prefix")


class TestFilterSharedFoldersBySafes(unittest.TestCase):
    def _folder(self, path):
        folder = SharedFolder()
        folder.path = path
        return folder

    def test_glob_filter_keeps_matching_leaf_names(self):
        folders = [
            self._folder("Acme_Michael_Rodriguez"),
            self._folder("Acme_David_Chen"),
            self._folder("PVWAReports"),
        ]
        matched = commands.filter_shared_folders_by_safes(folders, "Acme_*")
        self.assertEqual(
            [f.path for f in matched],
            ["Acme_Michael_Rodriguez", "Acme_David_Chen"],
        )

    def test_empty_pattern_returns_all(self):
        folders = [self._folder("A"), self._folder("B")]
        self.assertEqual(commands.filter_shared_folders_by_safes(folders, ""), folders)
        self.assertEqual(commands.filter_shared_folders_by_safes(folders, None), folders)

    def test_membership_safe_name_uses_leaf(self):
        path = PathDelimiter.join(["PAM Environments", "Acme Test Import", "Acme_X"])
        self.assertEqual(commands.membership_safe_name(path), "Acme_X")

    def test_multiple_glob_patterns(self):
        """Test filtering with multiple comma-separated glob patterns."""
        folders = [
            self._folder("Acme_A"),
            self._folder("Acme_B"),
            self._folder("Corp_C"),
            self._folder("Corp_D"),
        ]
        matched = commands.filter_shared_folders_by_safes(folders, "Acme_*,Corp_*")
        self.assertEqual(len(matched), 4)

    def test_glob_with_brackets_and_questions(self):
        """Test glob patterns with ? and [] wildcards."""
        folders = [
            self._folder("Safe_001"),
            self._folder("Safe_002"),
            self._folder("Safe_100"),
        ]
        matched = commands.filter_shared_folders_by_safes(folders, "Safe_0??")
        self.assertEqual(len(matched), 2)

    def test_whitespace_in_patterns_is_trimmed(self):
        """Test that whitespace in comma-separated patterns is properly trimmed."""
        folders = [self._folder("A"), self._folder("B"), self._folder("C")]
        matched = commands.filter_shared_folders_by_safes(folders, " A , B ")
        self.assertEqual(len(matched), 2)

    def test_deep_nested_paths(self):
        """Test that deep nested paths correctly identify leaf folder."""
        deep_path = PathDelimiter.join(
            ["PAM Environments", "Project", "Safe", "Sub1", "Sub2", "Sub3"]
        )
        leaf = commands.membership_safe_name(deep_path)
        self.assertEqual(leaf, "Sub3")

    def test_special_characters_in_safe_names(self):
        """Test that special characters are preserved in safe names."""
        special_cases = [
            "Safe With Spaces",
            "Safe-With-Dashes",
            "Safe_With_Underscores",
            "Safe (Production)",
            "Safe [Test]",
        ]
        for safe in special_cases:
            result = commands.membership_safe_name(safe)
            self.assertEqual(result, safe, f"Failed for: {safe}")

    def test_filter_with_no_matches(self):
        """Test filtering when glob pattern matches nothing."""
        folders = [self._folder("PVWAReports"), self._folder("PrivilegeCloud")]
        matched = commands.filter_shared_folders_by_safes(folders, "Acme_*")
        self.assertEqual(len(matched), 0)

    def test_unicode_safe_names(self):
        """Test that unicode characters are handled correctly."""
        unicode_safe = "Säfe_Nämé"
        result = commands.membership_safe_name(unicode_safe)
        self.assertEqual(result, unicode_safe)

    def test_filter_preserves_order(self):
        """Test that filtering preserves the order of matched folders."""
        folders = [
            self._folder("Zebra_1"),
            self._folder("Acme_1"),
            self._folder("Zebra_2"),
            self._folder("Acme_2"),
        ]
        matched = commands.filter_shared_folders_by_safes(folders, "Acme_*")
        paths = [f.path for f in matched]
        self.assertEqual(paths, ["Acme_1", "Acme_2"])


class TestApplyMembershipParserPamArgs(unittest.TestCase):
    def test_parser_accepts_pam_project_and_safes(self):
        args = commands.apply_membership_parser.parse_args(
            [
                "--pam-project",
                "Acme Test Import",
                "--safes",
                "Acme_*",
                "--list-safes",
                "membership.json",
            ]
        )
        self.assertEqual(args.pam_project, "Acme Test Import")
        self.assertEqual(args.safes, "Acme_*")
        self.assertTrue(args.list_safes)
        self.assertEqual(args.name, "membership.json")


class TestApplyMembershipCommandPam(unittest.TestCase):
    def test_execute_rewrites_paths_and_clears_uid(self):
        folder = SharedFolder()
        folder.path = "Acme_Michael_Rodriguez"
        folder.uid = "cyberark-safe-id"

        payload = {
            "shared_folders": [
                {
                    "path": "Acme_Michael_Rodriguez",
                    "uid": "cyberark-safe-id",
                    "permissions": [{"name": "user@example.com", "manage_users": False, "manage_records": False}],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "membership.json")
            with open(path, "w", encoding="utf-8") as handle:
                import json
                json.dump(payload, handle)

            captured = {}

            def fake_import_user_permissions(params, shared_folders, full_sync=False, unsafe=False):
                captured["folders"] = list(shared_folders)

            with mock.patch.object(commands.imp_exp, "import_user_permissions", side_effect=fake_import_user_permissions):
                commands.ApplyMembershipCommand().execute(
                    mock.Mock(),
                    name=path,
                    pam_project="Acme Test Import",
                )

        self.assertEqual(len(captured["folders"]), 1)
        expected = PathDelimiter.join(
            ["PAM Environments", "Acme Test Import", "Acme_Michael_Rodriguez"]
        )
        self.assertEqual(captured["folders"][0].path, expected)
        self.assertIsNone(captured["folders"][0].uid)

    def test_list_safes_prints_and_skips_apply(self):
        payload = {
            "shared_folders": [
                {
                    "path": "Acme_David_Chen",
                    "permissions": [{"name": "user@example.com"}],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "membership.json")
            with open(path, "w", encoding="utf-8") as handle:
                import json
                json.dump(payload, handle)

            with mock.patch.object(commands.imp_exp, "import_user_permissions") as apply_mock:
                with mock.patch("builtins.print") as print_mock:
                    commands.ApplyMembershipCommand().execute(
                        mock.Mock(),
                        name=path,
                        pam_project="Acme Test Import",
                        list_safes=True,
                    )
            apply_mock.assert_not_called()
            printed = print_mock.call_args[0][0]
            self.assertIn("Acme_David_Chen", printed)
            self.assertIn("PAM Environments", printed)


if __name__ == "__main__":
    unittest.main()
