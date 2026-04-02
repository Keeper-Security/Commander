"""Tests for PR #1890: security hardening for PAM import engine."""

import unittest
from unittest.mock import MagicMock, patch

import pytest

try:
    from keepercommander.commands.pam_import.edit import PAMProjectImportCommand, MAX_ITERATIONS
    from keepercommander.error import CommandError
except ImportError as _import_err:
    pytest.skip(f"Skipping PAM import tests: {_import_err}", allow_module_level=True)


class TestFolderNameLoopGuard(unittest.TestCase):
    """process_folders() must not loop indefinitely when all names are taken."""

    def _make_command(self):
        cmd = PAMProjectImportCommand.__new__(PAMProjectImportCommand)
        return cmd

    def test_loop_terminates_after_max_iterations(self):
        """If all folder names are taken, should raise CommandError."""
        cmd = self._make_command()
        mock_folder = MagicMock()
        mock_folder.type = mock_folder.UserFolderType
        cmd.find_folders = MagicMock(return_value=[mock_folder])

        project = {
            "data": {},
            "options": {"dry_run": False, "project_name": "TestProject"},
            "folders": {},
            "gateway": {},
        }
        with self.assertRaises(CommandError) as ctx:
            cmd.process_folders(MagicMock(), project)
        self.assertIn(str(MAX_ITERATIONS), str(ctx.exception))

    @patch('keepercommander.commands.pam_import.edit.api')
    def test_loop_finds_name_on_first_try(self, mock_api):
        """If the first name is available, loop exits immediately."""
        cmd = self._make_command()
        cmd.find_folders = MagicMock(return_value=[])
        cmd.create_subfolder = MagicMock(return_value="new-uid")

        project = {
            "data": {},
            "options": {"dry_run": False, "project_name": "TestProject"},
            "folders": {},
            "gateway": {},
        }
        result = cmd.process_folders(MagicMock(), project)
        self.assertEqual(result["project_folder"], "TestProject")


class TestTokenClearing(unittest.TestCase):
    """Sensitive gateway tokens must be cleared from memory after display."""

    def test_res_dict_cleared_after_display(self):
        """Both project gateway dict AND res dict should be cleared after execute output."""
        import inspect
        source = inspect.getsource(PAMProjectImportCommand.execute)
        # Verify the res dict is also cleared (not just project gateway)
        self.assertIn('res["access_token"] = ""', source)
        self.assertIn('res["device_uid"] = ""', source)

    def test_warning_emitted_before_token_display(self):
        """A warning about sensitive token must appear before the print."""
        import inspect
        source = inspect.getsource(PAMProjectImportCommand.execute)
        warning_pos = source.find('gateway bootstrap token')
        print_pos = source.find('json.dumps(res')
        self.assertGreater(warning_pos, -1, 'Missing gateway bootstrap token warning')
        self.assertGreater(print_pos, -1, 'Missing JSON output of res')
        self.assertLess(warning_pos, print_pos, 'Warning must appear before token output')


class TestMaxIterationsConsistency(unittest.TestCase):
    """All name-uniqueness loops should use the same MAX_ITERATIONS guard."""

    def test_all_loops_guarded(self):
        """All name-uniqueness loops should have a MAX_ITERATIONS guard."""
        import inspect
        source = inspect.getsource(PAMProjectImportCommand)
        # Count CommandError raises that mention the iteration limit
        count = source.count('MAX_ITERATIONS')
        # Should be at least 4: folders, app name, gateway name, PAM config name
        self.assertGreaterEqual(count, 4,
            f'Expected at least 4 MAX_ITERATIONS references, found {count}')


if __name__ == '__main__':
    unittest.main()
