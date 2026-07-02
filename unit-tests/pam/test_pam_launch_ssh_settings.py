"""
Unit tests for `_extract_ssh_settings` in pam_launch/terminal_connection.py.

Record JSON (Web Vault / pam_import) stores SSH fields as `hostKey`, `command`, and
`sftp.enableSftp`. The extractor maps them to protocol_specific names consumed by
`_build_guacamole_connection_settings` (host-key, command, enable-sftp).
"""

import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_launch.terminal_connection import _extract_ssh_settings
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import terminal_connection: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestExtractSshSettings(unittest.TestCase):
    def test_reads_record_shaped_fields(self):
        connection = {
            'hostKey': 'AAAAhostkey',
            'command': '/bin/bash -l',
            'sftp': {'enableSftp': True, 'sftpRootDirectory': '/uploads'},
        }
        result = _extract_ssh_settings(connection)
        self.assertEqual(result['publicHostKey'], 'AAAAhostkey')
        self.assertEqual(result['executeCommand'], '/bin/bash -l')
        self.assertTrue(result['sftpEnabled'])
        self.assertEqual(result['sftpRootDirectory'], '/uploads')

    def test_legacy_wrong_keys_are_ignored(self):
        connection = {
            'publicHostKey': 'legacy-key',
            'executeCommand': 'legacy-cmd',
            'sftpEnabled': True,
        }
        result = _extract_ssh_settings(connection)
        self.assertEqual(result['publicHostKey'], '')
        self.assertEqual(result['executeCommand'], '')
        self.assertFalse(result['sftpEnabled'])

    def test_defaults_when_fields_absent(self):
        result = _extract_ssh_settings({})
        self.assertEqual(result['publicHostKey'], '')
        self.assertEqual(result['executeCommand'], '')
        self.assertFalse(result['sftpEnabled'])
        self.assertEqual(result['sftpRootDirectory'], '')


if __name__ == '__main__':
    unittest.main()
