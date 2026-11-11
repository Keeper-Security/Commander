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
from keepercommander.importer import pam_membership
from keepercommander.importer.importer import PathDelimiter, SharedFolder


class TestMembershipSafeName(unittest.TestCase):
    def test_membership_safe_name_uses_leaf(self):
        path = PathDelimiter.join(["PAM Environments", "Acme Test Import", "Acme_X"])
        self.assertEqual(commands.membership_safe_name(path), "Acme_X")

    def test_empty_and_whitespace_return_empty(self):
        self.assertEqual(commands.membership_safe_name(""), "")
        self.assertEqual(commands.membership_safe_name("   "), "")
        self.assertEqual(commands.membership_safe_name(None), "")
        self.assertEqual(commands.membership_safe_name("/"), "")
        self.assertEqual(commands.membership_safe_name("\\"), "")
        self.assertEqual(commands.membership_safe_name("/\\"), "")

    def test_strips_leading_trailing_separators(self):
        self.assertEqual(commands.membership_safe_name("/AcmeSafe/"), "AcmeSafe")
        self.assertEqual(commands.membership_safe_name("\\AcmeSafe\\"), "AcmeSafe")
        self.assertEqual(commands.membership_safe_name("/PAM Environments/AcmeSafe/"), "AcmeSafe")

    def test_nested_backslash_path_uses_last_component(self):
        nested = PathDelimiter.join(["parent", "child", "leaf"])
        self.assertEqual(commands.membership_safe_name(nested), "leaf")


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

    def test_already_prefixed_is_case_insensitive(self):
        existing = "pam environments/acme test import/Acme_David_Chen"
        result = commands.apply_pam_project_prefix(existing, "Acme Test Import")
        expected = PathDelimiter.join(
            ["pam environments", "acme test import", "Acme_David_Chen"]
        )
        self.assertEqual(result, expected)

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
        self.assertEqual(
            commands.apply_pam_project_prefix("Safe One", "   "),
            "Safe One",
        )
        self.assertEqual(
            commands.apply_pam_project_prefix("Safe One", None),
            "Safe One",
        )

    def test_project_with_surrounding_separators_is_cleaned(self):
        path = commands.apply_pam_project_prefix("AcmeSafe", "/Proj\\")
        expected = PathDelimiter.join(["PAM Environments", "Proj", "AcmeSafe"])
        self.assertEqual(path, expected)

    def test_empty_folder_path_becomes_unnamed_safe(self):
        path = commands.apply_pam_project_prefix("", "Proj")
        expected = PathDelimiter.join(["PAM Environments", "Proj", "Unnamed-Safe"])
        self.assertEqual(path, expected)
        path = commands.apply_pam_project_prefix("   ", "Proj")
        self.assertEqual(path, expected)

    def test_sanitize_strips_path_separators_in_leaf(self):
        path = commands.apply_pam_project_prefix("Bad/Name", "Proj")
        expected = PathDelimiter.join(["PAM Environments", "Proj", "Bad_Name"])
        self.assertEqual(path, expected)

    def test_sanitize_backslash_and_dotdot_in_leaf(self):
        path = commands.apply_pam_project_prefix("Bad\\Name..X", "Proj")
        expected = PathDelimiter.join(["PAM Environments", "Proj", "Bad_Name_X"])
        self.assertEqual(path, expected)

    def test_sanitize_control_characters_and_truncation(self):
        dirty = "Safe\x00Name\nWith\tControl"
        path = commands.apply_pam_project_prefix(dirty, "Proj")
        leaf = commands.membership_safe_name(path)
        self.assertEqual(leaf, "SafeNameWithControl")
        self.assertNotIn("\x00", leaf)
        self.assertNotIn("\n", leaf)

        long_name = "A" * 40
        path = commands.apply_pam_project_prefix(long_name, "Proj")
        leaf = commands.membership_safe_name(path)
        self.assertEqual(len(leaf), 28)
        self.assertTrue(leaf.startswith("A"))

    def test_prefix_only_path_is_unchanged(self):
        prefix = PathDelimiter.join(["PAM Environments", "Acme Test Import"])
        self.assertEqual(
            commands.apply_pam_project_prefix(prefix, "Acme Test Import"),
            prefix,
        )


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
        self.assertEqual(commands.filter_shared_folders_by_safes(folders, " , , "), folders)

    def test_empty_folder_list_returns_empty(self):
        self.assertEqual(commands.filter_shared_folders_by_safes([], "Acme_*"), [])
        self.assertEqual(commands.filter_shared_folders_by_safes(None, "Acme_*"), None)

    def test_comma_separated_patterns(self):
        folders = [
            self._folder("Acme_A"),
            self._folder("Beta_B"),
            self._folder("Other"),
        ]
        matched = commands.filter_shared_folders_by_safes(folders, "Acme_*, Beta_*")
        self.assertEqual([f.path for f in matched], ["Acme_A", "Beta_B"])

    def test_nested_path_filters_by_leaf_name(self):
        nested = PathDelimiter.join(["PAM Environments", "Proj", "Acme_Leaf"])
        folders = [
            self._folder(nested),
            self._folder("PVWAReports"),
            self._folder("/Acme_Trailing/"),
        ]
        matched = commands.filter_shared_folders_by_safes(folders, "Acme_*")
        self.assertEqual(
            [f.path for f in matched],
            [nested, "/Acme_Trailing/"],
        )

    def test_no_match_returns_empty(self):
        folders = [self._folder("PVWAReports")]
        self.assertEqual(commands.filter_shared_folders_by_safes(folders, "Acme_*"), [])

    def test_glob_with_brackets_and_questions(self):
        folders = [
            self._folder("Safe_001"),
            self._folder("Safe_002"),
            self._folder("Safe_100"),
        ]
        matched = commands.filter_shared_folders_by_safes(folders, "Safe_0??")
        self.assertEqual([f.path for f in matched], ["Safe_001", "Safe_002"])

    def test_unicode_safe_names(self):
        unicode_cases = [
            "Säfe_Nämé",
            "安全_Safe",
            "Café_DB",
        ]
        for safe in unicode_cases:
            result = commands.membership_safe_name(safe)
            self.assertEqual(result, safe)


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
    def _write_membership(self, tmp, payload):
        path = os.path.join(tmp, "membership.json")
        with open(path, "w", encoding="utf-8") as handle:
            import json
            json.dump(payload, handle)
        return path

    def test_execute_rewrites_paths_and_clears_uid(self):
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
            path = self._write_membership(tmp, payload)
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

    def test_execute_applies_safes_filter_before_prefix(self):
        payload = {
            "shared_folders": [
                {
                    "path": "Acme_Keep",
                    "permissions": [{"name": "user@example.com"}],
                },
                {
                    "path": "Skip_Me",
                    "permissions": [{"name": "user@example.com"}],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_membership(tmp, payload)
            captured = {}

            def fake_import_user_permissions(params, shared_folders, full_sync=False, unsafe=False):
                captured["folders"] = list(shared_folders)

            with mock.patch.object(commands.imp_exp, "import_user_permissions", side_effect=fake_import_user_permissions):
                commands.ApplyMembershipCommand().execute(
                    mock.Mock(),
                    name=path,
                    pam_project="Proj",
                    safes="Acme_*",
                )

        self.assertEqual(len(captured["folders"]), 1)
        self.assertEqual(
            captured["folders"][0].path,
            PathDelimiter.join(["PAM Environments", "Proj", "Acme_Keep"]),
        )

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
            path = self._write_membership(tmp, payload)

            with mock.patch.object(commands.imp_exp, "import_user_permissions") as apply_mock:
                with mock.patch("builtins.print") as print_mock:
                    commands.ApplyMembershipCommand().execute(
                        mock.Mock(),
                        name=path,
                        pam_project="Acme Test Import",
                        list_safes=True,
                    )
            apply_mock.assert_not_called()
            printed_output = '\n'.join(call[0][0] for call in print_mock.call_args_list)
            self.assertIn("Acme_David_Chen", printed_output)
            self.assertIn("PAM Environments", printed_output)

    def test_missing_file_skips_apply(self):
        with mock.patch.object(commands.imp_exp, "import_user_permissions") as apply_mock:
            commands.ApplyMembershipCommand().execute(
                mock.Mock(),
                name="does-not-exist-membership.json",
                pam_project="Proj",
            )
        apply_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
