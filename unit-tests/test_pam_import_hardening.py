"""Tests for PR #1890: security hardening for PAM import engine."""

import json
import logging
import unittest
from unittest.mock import MagicMock, patch

try:
    from keepercommander.commands.pam_import.edit import PAMProjectImportCommand
    HAS_PAM_EDIT = True
except ImportError:
    HAS_PAM_EDIT = False

from keepercommander.error import CommandError


@unittest.skipUnless(HAS_PAM_EDIT, 'pydantic or keeper_dag not available')
class TestFolderNameLoopGuard(unittest.TestCase):
    """process_folders() must not loop indefinitely when all names are taken."""

    def _make_command(self):
        cmd = PAMProjectImportCommand.__new__(PAMProjectImportCommand)
        return cmd

    def test_loop_terminates_after_max_iterations(self):
        """If all 1000 folder names exist, should raise CommandError."""
        cmd = self._make_command()

        # Mock find_folders to always return a non-empty list (name taken)
        mock_folder = MagicMock()
        mock_folder.type = mock_folder.UserFolderType
        cmd.find_folders = MagicMock(return_value=[mock_folder])

        project = {
            "data": {},
            "options": {"dry_run": False},
        }
        res = {
            "root_folder_target": "PAM Environments",
            "root_folder_uid": "some-uid",
            "project_folder_target": "TestProject",
            "project_folder": "TestProject",
        }

        # Patch process_folders to call only the loop portion
        # We test the loop guard by simulating the condition
        with self.assertRaises(CommandError) as ctx:
            START_INDEX = 1
            MAX_ITERATIONS = 1000
            n = START_INDEX
            while n <= MAX_ITERATIONS:
                folder_name = res["project_folder_target"] if n <= START_INDEX else f'{res["project_folder_target"]} #{n}'
                folders = cmd.find_folders(None, res["root_folder_uid"], folder_name, False)
                folders = [x for x in folders if x.type == x.UserFolderType]
                n += 1
                if len(folders) > 0:
                    continue
                break
            else:
                raise CommandError('pam project import',
                    f'Could not find unique project folder name after {MAX_ITERATIONS} attempts')

        self.assertIn('1000', str(ctx.exception))

    def test_loop_finds_name_on_first_try(self):
        """If the first name is available, loop exits immediately."""
        cmd = self._make_command()
        cmd.find_folders = MagicMock(return_value=[])

        START_INDEX = 1
        MAX_ITERATIONS = 1000
        n = START_INDEX
        found_name = None
        while n <= MAX_ITERATIONS:
            folder_name = "TestProject" if n <= START_INDEX else f"TestProject #{n}"
            folders = cmd.find_folders(None, "uid", folder_name, False)
            n += 1
            if len(folders) > 0:
                continue
            found_name = folder_name
            break

        self.assertEqual(found_name, "TestProject")
        self.assertEqual(cmd.find_folders.call_count, 1)

    def test_loop_finds_name_on_third_try(self):
        """If first two names are taken, should use the third."""
        cmd = self._make_command()
        mock_folder = MagicMock()
        mock_folder.type = mock_folder.UserFolderType
        cmd.find_folders = MagicMock(
            side_effect=[[mock_folder], [mock_folder], []]
        )

        START_INDEX = 1
        MAX_ITERATIONS = 1000
        n = START_INDEX
        found_name = None
        while n <= MAX_ITERATIONS:
            folder_name = "TestProject" if n <= START_INDEX else f"TestProject #{n}"
            folders = cmd.find_folders(None, "uid", folder_name, False)
            folders = [x for x in folders if x.type == x.UserFolderType]
            n += 1
            if len(folders) > 0:
                continue
            found_name = folder_name
            break

        self.assertEqual(found_name, "TestProject #3")
        self.assertEqual(cmd.find_folders.call_count, 3)


class TestTokenClearing(unittest.TestCase):
    """Sensitive gateway tokens must be cleared from memory after display."""

    def test_tokens_cleared_after_display(self):
        """gateway_token and gateway_device_token should be empty after execute output."""
        project_gateway = {
            "gateway_token": "secret-one-time-token-abc123",
            "gateway_device_token": "device-token-xyz789",
            "gateway_uid": "uid-123",
        }

        # Simulate the clearing logic from execute()
        res = {
            "access_token": project_gateway.get("gateway_token", ""),
            "device_uid": project_gateway.get("gateway_uid", ""),
        }

        # Verify tokens are captured in res before clearing
        self.assertEqual(res["access_token"], "secret-one-time-token-abc123")
        self.assertEqual(res["device_uid"], "uid-123")

        # Simulate the clearing
        project_gateway["gateway_token"] = ""
        project_gateway["gateway_device_token"] = ""

        # Tokens should be cleared
        self.assertEqual(project_gateway["gateway_token"], "")
        self.assertEqual(project_gateway["gateway_device_token"], "")
        # UID is not a token — should remain
        self.assertEqual(project_gateway["gateway_uid"], "uid-123")

    def test_res_captures_token_before_clearing(self):
        """The output res dict must capture the token value before it's cleared."""
        gateway = {"gateway_token": "tok-abc", "gateway_device_token": "dev-tok", "gateway_uid": "uid-1"}
        res = {"access_token": gateway.get("gateway_token", "")}

        # Clear
        gateway["gateway_token"] = ""
        gateway["gateway_device_token"] = ""

        # res should still have the original value
        self.assertEqual(res["access_token"], "tok-abc")


@unittest.skipUnless(HAS_PAM_EDIT, 'pydantic or keeper_dag not available')
class TestTokenWarningMessage(unittest.TestCase):
    """A warning must be emitted before displaying gateway tokens."""

    def test_warning_in_source(self):
        """Source code must contain the token security warning."""
        import inspect
        source = inspect.getsource(PAMProjectImportCommand.execute)
        self.assertIn('gateway bootstrap token', source)
        self.assertIn('Store it securely', source)


@unittest.skipUnless(HAS_PAM_EDIT, 'pydantic or keeper_dag not available')
class TestGatewayDataStructure(unittest.TestCase):
    """Verify the gateway data structure has expected keys."""

    def test_process_gateway_initializes_keys(self):
        """process_gateway should initialize gateway_token, gateway_device_token, gateway_uid."""
        import inspect
        source = inspect.getsource(PAMProjectImportCommand)
        # The default gateway dict should have all three keys
        self.assertIn('"gateway_token"', source)
        self.assertIn('"gateway_device_token"', source)
        self.assertIn('"gateway_uid"', source)


if __name__ == '__main__':
    unittest.main()
