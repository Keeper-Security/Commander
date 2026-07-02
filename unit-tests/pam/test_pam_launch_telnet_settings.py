"""
Unit tests for `_extract_telnet_settings` in pam_launch/terminal_connection.py.
"""

import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_launch.terminal_connection import _extract_telnet_settings
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import terminal_connection: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestExtractTelnetSettings(unittest.TestCase):
    def test_reads_all_regex_fields(self):
        connection = {
            'usernameRegex': 'User:',
            'passwordRegex': 'Pass:',
            'loginSuccessRegex': 'Welcome',
            'loginFailureRegex': 'Denied',
        }
        result = _extract_telnet_settings(connection)
        self.assertEqual(result['usernameRegex'], 'User:')
        self.assertEqual(result['passwordRegex'], 'Pass:')
        self.assertEqual(result['loginSuccessRegex'], 'Welcome')
        self.assertEqual(result['loginFailureRegex'], 'Denied')

    def test_defaults_when_fields_absent(self):
        result = _extract_telnet_settings({})
        self.assertEqual(result['usernameRegex'], '')
        self.assertEqual(result['passwordRegex'], '')
        self.assertEqual(result['loginSuccessRegex'], '')
        self.assertEqual(result['loginFailureRegex'], '')


if __name__ == '__main__':
    unittest.main()
