import sys
import unittest

if sys.version_info >= (3, 8):
    import pytest
    from unittest import TestCase, mock
    from flask import Flask
    from keepercommander.service.util.command_util import CommandExecutor
    from keepercommander.service.util.exceptions import CommandExecutionError
    from keepercommander.service.util.parse_keeper_response import parse_keeper_response

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