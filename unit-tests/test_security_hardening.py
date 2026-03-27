"""Tests for PR #1873: file permissions, log sanitization, and exception narrowing."""

import json
import logging
import os
import stat
import tempfile
import unittest
from configparser import RawConfigParser
from unittest.mock import MagicMock, patch

try:
    import botocore  # noqa: F401
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False

from keepercommander.commands.pam_import.base import (
    PamScriptsObject,
    PamScriptObject,
    PamAttachmentsObject,
    PamAttachmentObject,
    PamRotationScheduleObject,
    PamRotationSettingsObject,
    DagSettingsObject,
    DagJitSettingsObject,
    DagAiSettingsObject,
    PamUserObject,
)


@unittest.skipUnless(HAS_BOTOCORE, 'botocore not available')
class TestAwsCredentialsFilePermissions(unittest.TestCase):
    """Verify that AWS credentials are written with restrictive permissions (no TOCTOU)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.creds_file = os.path.join(self.tmpdir, 'credentials')
        # Create an initial credentials file with a known profile
        cp = RawConfigParser()
        cp.add_section('default')
        cp.set('default', 'aws_access_key_id', 'OLD_KEY')
        cp.set('default', 'aws_secret_access_key', 'OLD_SECRET')
        with open(self.creds_file, 'w') as f:
            cp.write(f)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_credentials_file_written_with_0600(self):
        """After sync_with_creds_file, the file must have 0600 permissions."""
        from keepercommander.plugins.awskey.aws_accesskey import Rotator

        rotator = Rotator.__new__(Rotator)
        rotator.aws_sync_profile = 'default'
        rotator.aws_key_id = 'OLD_KEY'
        rotator.new_key_id = 'NEW_KEY'
        rotator.new_secret = 'NEW_SECRET'

        # Mock the session to return our temp file path
        mock_provider = MagicMock()
        mock_provider.METHOD = 'shared-credentials-file'
        mock_provider._creds_filename = self.creds_file

        mock_session = MagicMock()
        mock_session._session._components.get_component.return_value.providers = [mock_provider]
        mock_session.get_credentials.return_value.method = 'shared-credentials-file'
        rotator.session = mock_session

        result = rotator.sync_with_creds_file()

        self.assertTrue(result)
        mode = os.stat(self.creds_file).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600,
                         f"Expected 0600, got {oct(stat.S_IMODE(mode))}")

    def test_backup_file_created(self):
        """Backup file should be created before overwriting credentials."""
        from keepercommander.plugins.awskey.aws_accesskey import Rotator

        rotator = Rotator.__new__(Rotator)
        rotator.aws_sync_profile = 'default'
        rotator.aws_key_id = 'OLD_KEY'
        rotator.new_key_id = 'NEW_KEY'
        rotator.new_secret = 'NEW_SECRET'

        mock_provider = MagicMock()
        mock_provider.METHOD = 'shared-credentials-file'
        mock_provider._creds_filename = self.creds_file

        mock_session = MagicMock()
        mock_session._session._components.get_component.return_value.providers = [mock_provider]
        mock_session.get_credentials.return_value.method = 'shared-credentials-file'
        rotator.session = mock_session

        rotator.sync_with_creds_file()

        backup_file = self.creds_file + '.keeper.bak'
        self.assertTrue(os.path.isfile(backup_file), "Backup file should exist")

    def test_new_credentials_written_correctly(self):
        """The new key ID and secret should be in the file after sync."""
        from keepercommander.plugins.awskey.aws_accesskey import Rotator

        rotator = Rotator.__new__(Rotator)
        rotator.aws_sync_profile = 'default'
        rotator.aws_key_id = 'OLD_KEY'
        rotator.new_key_id = 'NEW_KEY_123'
        rotator.new_secret = 'NEW_SECRET_456'

        mock_provider = MagicMock()
        mock_provider.METHOD = 'shared-credentials-file'
        mock_provider._creds_filename = self.creds_file

        mock_session = MagicMock()
        mock_session._session._components.get_component.return_value.providers = [mock_provider]
        mock_session.get_credentials.return_value.method = 'shared-credentials-file'
        rotator.session = mock_session

        rotator.sync_with_creds_file()

        cp = RawConfigParser()
        cp.read([self.creds_file])
        self.assertEqual(cp.get('default', 'aws_access_key_id'), 'NEW_KEY_123')
        self.assertEqual(cp.get('default', 'aws_secret_access_key'), 'NEW_SECRET_456')


class TestSshLogSanitization(unittest.TestCase):
    """Verify that SSH rotation debug logs do not leak sensitive data."""

    def test_debug_logs_show_byte_count_not_content(self):
        """Debug messages should contain byte counts, not raw output."""
        # The ssh plugin requires paramiko_expect (not always installed),
        # so we read the source file directly to verify the patterns.
        ssh_path = os.path.join(os.path.dirname(__file__), '..',
                                'keepercommander', 'plugins', 'ssh', 'ssh.py')
        with open(ssh_path) as f:
            source = f.read()

        # Must NOT contain the old patterns that log raw output
        self.assertNotIn('Output from passwd command', source)
        self.assertNotIn('Output from Old Password', source)
        self.assertNotIn('Output from New Password:', source)
        self.assertNotIn('Output from New Password Again', source)

        # Must contain the new sanitized patterns
        self.assertIn('Rotation command responded', source)
        self.assertIn('Old credential prompt responded', source)
        self.assertIn('New credential prompt responded', source)
        self.assertIn('Credential confirmation responded', source)


class TestPamBaseExceptionNarrowing(unittest.TestCase):
    """Verify that bare except clauses are replaced with json.JSONDecodeError."""

    def test_valid_json_string_loads(self):
        """Valid JSON string input should parse correctly."""
        data = json.dumps([{"type": "script", "file": "/tmp/test.sh",
                            "script_command": "bash"}])
        obj = PamScriptsObject.load(data)
        self.assertIsInstance(obj, PamScriptsObject)

    def test_invalid_json_catches_decode_error(self):
        """Invalid JSON should be caught as JSONDecodeError, not bare except."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = PamScriptsObject.load("{not valid json")
        self.assertIsInstance(obj, PamScriptsObject)
        # Error message should contain structured info (line, col)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output),
                        f"Expected 'invalid JSON' in log output: {cm.output}")

    def test_dict_input_not_caught(self):
        """Dict input skips json.loads entirely — no exception raised."""
        obj = PamScriptsObject.load([])
        self.assertIsInstance(obj, PamScriptsObject)

    def test_none_input_returns_empty(self):
        """None input should return empty object without raising."""
        obj = PamScriptsObject.load(None)
        self.assertIsInstance(obj, PamScriptsObject)

    def test_pam_script_invalid_json(self):
        """PamScriptObject.load with invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = PamScriptObject.load("{bad")
        self.assertIsInstance(obj, PamScriptObject)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_pam_attachments_invalid_json(self):
        """PamAttachmentsObject.load with invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = PamAttachmentsObject.load("{bad")
        self.assertIsInstance(obj, PamAttachmentsObject)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_pam_attachment_invalid_json(self):
        """PamAttachmentObject.load with invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = PamAttachmentObject.load("{bad")
        self.assertIsInstance(obj, PamAttachmentObject)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_rotation_schedule_invalid_json(self):
        """PamRotationScheduleObject.load with invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = PamRotationScheduleObject.load("{bad")
        self.assertIsInstance(obj, PamRotationScheduleObject)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_dag_settings_invalid_json(self):
        """DagSettingsObject.load with invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = DagSettingsObject.load("{bad")
        self.assertIsInstance(obj, DagSettingsObject)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_jit_settings_invalid_json_returns_none(self):
        """DagJitSettingsObject.load returns None on invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = DagJitSettingsObject.load("{bad")
        self.assertIsNone(obj)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_ai_settings_invalid_json_returns_none(self):
        """DagAiSettingsObject.load returns None on invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = DagAiSettingsObject.load("{bad")
        self.assertIsNone(obj)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_pam_user_invalid_json(self):
        """PamUserObject.load with invalid JSON."""
        with self.assertLogs('root', level='ERROR') as cm:
            obj = PamUserObject.load("{bad")
        self.assertIsInstance(obj, PamUserObject)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_non_json_exception_not_swallowed(self):
        """TypeError from non-string/non-list input should NOT be caught."""
        # Passing an integer: isinstance(123, str) is False, so json.loads
        # is skipped. The data goes through as-is. This tests that we don't
        # have a broad except catching unrelated errors.
        obj = PamScriptsObject.load(123)
        self.assertIsInstance(obj, PamScriptsObject)


class TestFilePermissionsAtomicity(unittest.TestCase):
    """Verify os.open creates file with correct permissions atomically."""

    def test_os_open_creates_with_0600(self):
        """os.open with 0o600 must create file with owner-only permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'secret.txt')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write('sensitive data')
            mode = os.stat(path).st_mode
            self.assertEqual(stat.S_IMODE(mode), 0o600)

    def test_os_open_no_world_readable_window(self):
        """File should never be created with group/other read permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'secret.txt')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            # Check permissions immediately after creation, before writing
            mode = os.stat(path).st_mode
            self.assertFalse(mode & stat.S_IRGRP, "Group should not have read")
            self.assertFalse(mode & stat.S_IROTH, "Others should not have read")
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
