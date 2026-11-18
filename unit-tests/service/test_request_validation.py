import json
import unittest

from flask import Flask

from keepercommander.service.util.request_validation import RequestValidator

app = Flask(__name__)


class TestValidateRequestJson(unittest.TestCase):
    def test_valid_json_passes(self):
        with app.test_request_context('/', method='POST',
                                       data=json.dumps({"command": "ls"}),
                                       content_type='application/json'):
            self.assertIsNone(RequestValidator.validate_request_json())

    def test_wrong_content_type_rejected(self):
        with app.test_request_context('/', method='POST',
                                       data='{"command": "ls"}',
                                       content_type='text/plain'):
            response, status = RequestValidator.validate_request_json()
            self.assertEqual(status, 400)
            self.assertIn('Content-Type', response.get_json()['error'])

    def test_empty_json_object_rejected(self):
        """{} is falsy in Python, and was rejected by the old `if not request.json`
        check - the get_json()-based rewrite must preserve that, not just check for None."""
        with app.test_request_context('/', method='POST',
                                       data='{}',
                                       content_type='application/json'):
            response, status = RequestValidator.validate_request_json()
            self.assertEqual(status, 400)
            self.assertEqual(response.get_json()['error'], 'Invalid or empty JSON')

    def test_malformed_json_does_not_leak_parser_detail(self):
        with app.test_request_context('/', method='POST',
                                       data='{not valid json',
                                       content_type='application/json'):
            response, status = RequestValidator.validate_request_json()
            self.assertEqual(status, 400)
            error_message = response.get_json()['error']
            self.assertEqual(error_message, 'Invalid JSON format')
            self.assertNotIn('not valid json', error_message)
            self.assertNotIn('line', error_message)
            self.assertNotIn('column', error_message)


class TestValidatePamFiledataPaths(unittest.TestCase):
    """Test rejection of host file paths in Service Mode PAM FILEDATA imports."""

    def test_non_filedata_command_allowed(self):
        """PAM commands without --filename=FILEDATA should not be validated."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "users": [
                        {"attachments": [{"file": "/etc/passwd"}]}
                    ]
                }
            }
        }
        command = "pam project import --name='Test' --filename=/some/file --output=base64"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        self.assertIsNone(error)

    def test_filedata_without_attachments_allowed(self):
        """PAM FILEDATA without attachment paths should be allowed."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "name": "TestProject",
                    "description": "Safe import"
                }
            }
        }
        command = "pam project import --name='Test' --filename=FILEDATA --output=base64"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        self.assertIsNone(error)

    def test_filedata_with_attachment_file_path_rejected(self):
        """PAM FILEDATA with attachment file paths must be rejected."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "users": [
                        {
                            "attachments": [
                                {"file": "/tmp/keeper-marker.txt"}
                            ]
                        }
                    ]
                }
            }
        }
        command = "pam project import --name='S020 PoC' --filename=FILEDATA --output=base64"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        self.assertIsNotNone(error)
        self.assertIn("Local attachment and script paths are not permitted", error)

    def test_filedata_with_script_file_path_rejected(self):
        """PAM FILEDATA with script file paths must be rejected."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "connections": [
                        {
                            "scripts": [
                                {"file": "/home/user/.ssh/config"}
                            ]
                        }
                    ]
                }
            }
        }
        command = "pam project import --name='Test' --filename=FILEDATA --output=base64"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        self.assertIsNotNone(error)
        self.assertIn("Local attachment and script paths are not permitted", error)

    def test_nested_attachment_path_rejected(self):
        """Nested PAM structures with attachment paths must be rejected."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "gateways": [
                        {
                            "resources": [
                                {
                                    "attachments": [
                                        {"file": "/etc/shadow"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        }
        command = "pam project import --name='Test' --filename=FILEDATA --output=base64"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        self.assertIsNotNone(error)

    def test_empty_attachment_path_allowed(self):
        """Empty or whitespace-only attachment paths should not trigger rejection."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "users": [
                        {"attachments": [{"file": ""}]}
                    ]
                }
            }
        }
        command = "pam project import --name='Test' --filename=FILEDATA --output=base64"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        self.assertIsNone(error)

    def test_attachment_string_rejected(self):
        """String values in attachments array should be treated as file paths."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "users": [
                        {"attachments": ["/tmp/marker.txt"]}
                    ]
                }
            }
        }
        command = "pam project import --name='Test' --filename=FILEDATA --output=base64"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        self.assertIsNotNone(error)

    def test_malformed_command_ignored(self):
        """Malformed commands should not crash the validator."""
        request_data = {
            "filedata": {
                "pam_data": {
                    "users": [
                        {"attachments": [{"file": "/etc/passwd"}]}
                    ]
                }
            }
        }
        command = "pam project import )(invalid"
        error = RequestValidator.validate_pam_filedata_paths(request_data, command)
        # Should not crash; validation is None because command is malformed
        self.assertIsNone(error)


if __name__ == '__main__':
    unittest.main()
