"""
Unit tests for `scrollback` (Maximum Scrollback Size) in the `pam project import` /
`pam project extend` connection settings.

scrollback lives in TerminalDisplayConnectionSettings (mirrors the Web Vault) and is
threaded through terminal protocols (SSH, Telnet, Kubernetes) and CLI-capable DB protocols
(mysql, postgresql, sql-server). It is validated as a positive integer (like audio_bps /
audio_sample_rate): zero, negative, and non-numeric values are rejected with a warning.
KeeperDb-only DB protocols have no terminal display, so they never carry scrollback.
"""

import logging
import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_import.base import PamSettingsFieldData
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import pam_import.base: {e}"


def _record_scrollback(protocol, scrollback):
    data = {'protocol': protocol}
    if scrollback is not None:
        data['scrollback'] = scrollback
    obj = PamSettingsFieldData.get_connection_class(data)
    return obj.to_record_dict().get('scrollback') if obj else 'NO_CLASS'


@unittest.skipIf(skip_tests, skip_reason)
class TestPamImportScrollback(unittest.TestCase):
    TERMINAL_PROTOCOLS = ['ssh', 'telnet', 'kubernetes']
    CLI_CAPABLE_DB_PROTOCOLS = ['mysql', 'postgresql', 'sql-server']
    KEEPER_DB_ONLY_PROTOCOLS = [
        'mariadb', 'oracle', 'mongodb', 'redis', 'elasticsearch', 'clickhouse', 'dynamodb',
    ]
    SCROLLBACK_PROTOCOLS = TERMINAL_PROTOCOLS + CLI_CAPABLE_DB_PROTOCOLS

    def setUp(self):
        # Silence the expected validation warnings for invalid inputs.
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_valid_int_round_trips(self):
        for proto in self.SCROLLBACK_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertEqual(_record_scrollback(proto, 5000), 5000)

    def test_valid_string_int_parsed(self):
        for proto in self.SCROLLBACK_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertEqual(_record_scrollback(proto, '4096'), 4096)

    def test_zero_rejected(self):
        for proto in self.SCROLLBACK_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertIsNone(_record_scrollback(proto, 0))

    def test_negative_rejected(self):
        for proto in self.SCROLLBACK_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertIsNone(_record_scrollback(proto, -10))

    def test_non_numeric_rejected(self):
        for proto in self.SCROLLBACK_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertIsNone(_record_scrollback(proto, 'abc'))

    def test_float_string_rejected(self):
        for proto in self.SCROLLBACK_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertIsNone(_record_scrollback(proto, '12.5'))

    def test_not_provided_absent(self):
        for proto in self.SCROLLBACK_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertIsNone(_record_scrollback(proto, None))

    def test_keeper_db_only_protocols_have_no_scrollback(self):
        for proto in self.KEEPER_DB_ONLY_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertIsNone(_record_scrollback(proto, 5000))


if __name__ == '__main__':
    unittest.main()
