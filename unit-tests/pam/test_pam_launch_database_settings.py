"""
Unit tests for `_extract_database_settings` in pam_launch/terminal_connection.py.

Record JSON stores the default DB name as `database` (not `defaultDatabase`).
`useSSL` lives on the pamDatabase record checkbox for rotation/proxy — not on
pamSettings.connection.
"""

import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_launch.terminal_connection import _extract_database_settings
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import terminal_connection: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestExtractDatabaseSettings(unittest.TestCase):
    def test_reads_record_shaped_fields(self):
        connection = {
            'database': 'mydb',
            'disableCsvExport': True,
            'disableCsvImport': True,
        }
        result = _extract_database_settings(connection)
        self.assertEqual(result['defaultDatabase'], 'mydb')
        self.assertTrue(result['disableCsvExport'])
        self.assertTrue(result['disableCsvImport'])

    def test_legacy_default_database_key_is_ignored(self):
        connection = {'defaultDatabase': 'wrong-key'}
        result = _extract_database_settings(connection)
        self.assertEqual(result['defaultDatabase'], '')

    def test_connection_use_ssl_is_ignored(self):
        connection = {'database': 'mydb', 'useSSL': True}
        result = _extract_database_settings(connection)
        self.assertNotIn('useSSL', result)

    def test_defaults_when_fields_absent(self):
        result = _extract_database_settings({})
        self.assertEqual(result['defaultDatabase'], '')
        self.assertFalse(result['disableCsvExport'])
        self.assertFalse(result['disableCsvImport'])


if __name__ == '__main__':
    unittest.main()
