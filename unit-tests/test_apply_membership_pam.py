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
