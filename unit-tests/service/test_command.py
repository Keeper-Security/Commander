import json
import unittest

from unittest import TestCase, mock
from flask import Flask
from keepercommander import params as params_module
from keepercommander.service.util.command_util import CommandExecutor
from keepercommander.service.util.exceptions import CommandExecutionError
from keepercommander.service.util.parse_keeper_response import parse_keeper_response
from keepercommander.service.util.protected_records import get_protected_record_uids

PROTECTED_TITLE = 'Commander Service Mode Config'
PROTECTED_UID = 'PROTECTED_CONFIG_UID'
NORMAL_UID = 'NORMAL_RECORD_UID'


def _record_cache_entry(uid, title):
    return {
        'record_uid': uid,
        'version': 2,
        'revision': 1,
        'client_modified_time': 0,
        'shared': False,
        'record_key_unencrypted': b'0' * 32,
        'data_unencrypted': json.dumps({'title': title}).encode('utf-8'),
    }


def _params_with_protected_and_normal_record():
    p = params_module.KeeperParams()
    p.service_mode = False
    p.record_cache = {
        PROTECTED_UID: _record_cache_entry(PROTECTED_UID, PROTECTED_TITLE),
        NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
    }
    return p

class TestCommandAPI(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.client = self.app.test_client()
            
        @self.app.route('/api/v1/executecommand', methods=['POST'])
        def execute_command():
            command = "ls"
            response, status_code = CommandExecutor.execute(command)
            return {'response': response}, status_code

    def test_validate_command(self):
        """Test command validation"""
        result, status_code = CommandExecutor.validate_command("")
        self.assertIsNotNone(result)
        self.assertEqual(status_code, 400)
        self.assertEqual(result["error"], "No command provided.")

        result = CommandExecutor.validate_command("ls")
        self.assertIsNone(result)

    def test_validate_session(self):
        """Test session validation"""
        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=None):
            result, status_code = CommandExecutor.validate_session()
            self.assertEqual(status_code, 401)
            self.assertIn("No active session", result["error"])

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value={"session": "active"}):
            result = CommandExecutor.validate_session()
            self.assertIsNone(result)

    @unittest.skip
    def test_command_execution_success(self):
        """Test successful command execution"""
        mock_params = {"session": "active"}
        test_command = "ls"
        expected_output = "Folder1\nFolder2\n"

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=mock_params), \
            mock.patch('keepercommander.cli.do_command', return_value=expected_output), \
            mock.patch('keepercommander.service.util.command_util.ConfigReader.read_config', return_value=None):

            response, status_code = CommandExecutor.execute(test_command)
            self.assertEqual(status_code, 200)
            self.assertIsNotNone(response)

    @unittest.skip
    def test_command_execution_failure(self):
        """Test command execution failure"""
        mock_params = {"session": "active"}
        test_command = "invalid_command"

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=mock_params), \
            mock.patch('keepercommander.cli.do_command', side_effect=Exception("Command failed")), \
            self.assertRaises(CommandExecutionError):
                
            CommandExecutor.execute(test_command)

    def test_response_encryption(self):
        """Test response encryption when key is present"""
        test_response = {"status": "success", "data": "test"}

        mock_key = "0" * 32

        with mock.patch('keepercommander.service.util.command_util.ConfigReader.read_config', return_value=mock_key):
            encrypted_response = CommandExecutor.encrypt_response(test_response)
            self.assertIsInstance(encrypted_response, bytes)
            self.assertGreater(len(encrypted_response), 0)

    def test_response_parsing(self):
        """Test response parsing for different commands"""

        ls_response = "# Folder UID\n1 folder1_uid folder1 rw\n# Record UID\n1 record1_uid login record1"
        parsed = parse_keeper_response("ls", ls_response)
        self.assertEqual(parsed["status"], "success")
        self.assertEqual(parsed["command"], "ls")
        self.assertIn("folders", parsed["data"])
        self.assertIn("records", parsed["data"])

        tree_response = "Root\n  Folder1\n    SubFolder1"
        parsed = parse_keeper_response("tree", tree_response)
        self.assertEqual(parsed["command"], "tree")
        self.assertIsInstance(parsed["data"], dict)
        self.assertIn("tree", parsed["data"])

    def test_capture_output(self):
        """Test command output capture"""
        test_command = "ls"
        expected_output = "test output"
        mock_params = {"session": "active"}

        with mock.patch('keepercommander.cli.do_command', return_value=expected_output):
            return_value, output, logs = CommandExecutor.capture_output_and_logs(mock_params, test_command)
            self.assertEqual(return_value, expected_output)

    @unittest.skip
    def test_integration_command_flow(self):
        """Test the complete command execution flow"""
        test_command = "ls"
        mock_params = {"session": "active"}
        expected_output = "# Folder UID\n1 folder1_uid folder1 rw"

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=mock_params), \
            mock.patch('keepercommander.cli.do_command', return_value=expected_output), \
            mock.patch('keepercommander.service.util.command_util.ConfigReader.read_config', return_value=None):

            response, status_code = CommandExecutor.execute(test_command)
            self.assertEqual(status_code, 200)
            self.assertIsNotNone(response)


class TestProtectedRecordCommandExecution(TestCase):
    """End-to-end proof, through CommandExecutor.execute, that Service Mode's own config record stays blocked while unrelated records work."""

    def _run(self, command, params=None):
        params = params or _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(command)
        return response, status_code, mock_capture, params

    def test_blocked_commands_never_reach_cli_dispatch(self):
        for command in (
            f'get {PROTECTED_UID}',
            f'get "{PROTECTED_TITLE}"',
            f'list {PROTECTED_UID}',
            f'search {PROTECTED_UID}',
            f'record-update --record {PROTECTED_UID} title=x',
            f'record-update --record={PROTECTED_UID} title=x',
            f'rm {PROTECTED_UID}',
            f'share-record {PROTECTED_UID} --email a@b.com',
            f'share-folder --record {PROTECTED_UID} -e a@b.com',
            f'share-folder --record={PROTECTED_UID} -e a@b.com',
            f'ls "{PROTECTED_TITLE}"',
            f'tree "{PROTECTED_TITLE}"',
            f'nsf-get {PROTECTED_UID}',
            # Not one of the commands anyone would think to curate a list around --
            # proves the check isn't gated by command name at all.
            f'keep-alive {PROTECTED_UID}',
        ):
            with self.subTest(command=command):
                response, status_code, mock_capture, _ = self._run(command)
                self.assertEqual(status_code, 403)
                self.assertEqual(response.get('status'), 'error')
                mock_capture.assert_not_called()

    def test_unrelated_record_commands_are_unaffected(self):
        for command in (
            f'get {NORMAL_UID}',
            f'list {NORMAL_UID}',
            f'search {NORMAL_UID}',
            f'record-update --record {NORMAL_UID} title=x',
            f'rm {NORMAL_UID}',
            f'share-record {NORMAL_UID} --email a@b.com',
        ):
            with self.subTest(command=command):
                response, status_code, mock_capture, _ = self._run(command)
                self.assertEqual(status_code, 200)
                mock_capture.assert_called_once()

    def test_record_cache_is_popped_during_dispatch_and_restored_after(self):
        params = _params_with_protected_and_normal_record()
        seen_during_call = {}

        def fake_capture(p, command):
            seen_during_call['keys'] = set(p.record_cache.keys())
            return 'ok', 'ok', ''

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=fake_capture):
            response, status_code = CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertEqual(status_code, 200)
        self.assertNotIn(PROTECTED_UID, seen_during_call['keys'])
        self.assertIn(NORMAL_UID, seen_during_call['keys'])
        # Restored after the call returns -- the shared params singleton must
        # not stay permanently blind to its own config record.
        self.assertIn(PROTECTED_UID, params.record_cache)

    def test_record_cache_restored_even_if_dispatch_raises(self):
        params = _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', side_effect=CommandExecutionError('boom')
        ):
            response, status_code = CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertEqual(status_code, 400)
        self.assertIn(PROTECTED_UID, params.record_cache)

    def test_protected_record_check_runs_for_every_command(self):
        """The check is unconditional -- even a command with no known relationship
        to records (whoami) still triggers it, so no command can be missed."""
        params = _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ), mock.patch(
            'keepercommander.service.util.command_util.get_protected_record_uids',
            wraps=get_protected_record_uids,
        ) as mock_get_uids:
            CommandExecutor.execute('whoami')
            mock_get_uids.assert_called_once()

    def test_sailpoint_handling_runs_inside_the_record_cache_guard(self):
        """SailPoint's own pre-processing (handle_command) can resolve/act on
        records before cli.do_command ever runs -- it must run with the guard
        already active, not before it, or a folder/recursive share under
        SailPoint mode could reach the protected record before it's hidden."""
        params = _params_with_protected_and_normal_record()
        seen_during_handle_command = {}

        def fake_handle_command(p, command):
            seen_during_handle_command['keys'] = set(p.record_cache.keys())
            return command, None

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': 'sailpoint-uid'}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.handle_command',
            side_effect=fake_handle_command,
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ):
            CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertNotIn(PROTECTED_UID, seen_during_handle_command['keys'])
        self.assertIn(NORMAL_UID, seen_during_handle_command['keys'])
        # Restored after the whole guarded block exits, same as the non-SailPoint case.
        self.assertIn(PROTECTED_UID, params.record_cache)