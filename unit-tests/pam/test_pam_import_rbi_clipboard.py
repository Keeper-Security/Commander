"""
Unit tests for `clipboard_buffer_size` and `allow_supply_user` in the `pam project import` /
`pam project extend` RBI (pamRemoteBrowser, protocol "http") connection settings.

Mirrors `pam rbi edit --clipboard-buffer-size` / `--allow-supply-user`: the clipboard limit is given by
name (256kb/1mb/10mb/50mb, case-insensitive; "default" or omitted = unset) and stored in bytes.
"""

import logging
import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_import.base import (
        PamRemoteBrowserSettings,
        parse_clipboard_buffer_size,
    )
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import pam_import.base: {e}"


def _record_connection(**extra):
    # a connection with only "protocol" loads as empty, so always carry one unrelated setting
    data = {'connection': {'protocol': 'http', 'recording_include_keys': False, **extra}}
    settings = PamRemoteBrowserSettings.load(data)
    return settings.connection.to_record_dict() if settings.connection else None


@unittest.skipIf(skip_tests, skip_reason)
class TestPamImportRbiClipboardBufferSize(unittest.TestCase):
    SIZES = {'256kb': 256 * 1024, '1mb': 1024 * 1024, '10mb': 10 * 1024 * 1024, '50mb': 50 * 1024 * 1024}

    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_names_converted_to_bytes(self):
        for name, size in self.SIZES.items():
            with self.subTest(name=name):
                self.assertEqual(_record_connection(clipboard_buffer_size=name)['clipboardBufferSize'], size)

    def test_names_case_insensitive(self):
        self.assertEqual(_record_connection(clipboard_buffer_size='10MB')['clipboardBufferSize'], 10 * 1024 * 1024)
        self.assertEqual(_record_connection(clipboard_buffer_size=' 256Kb ')['clipboardBufferSize'], 256 * 1024)

    def test_exact_byte_values_accepted(self):
        for size in self.SIZES.values():
            with self.subTest(size=size):
                self.assertEqual(_record_connection(clipboard_buffer_size=size)['clipboardBufferSize'], size)
                self.assertEqual(_record_connection(clipboard_buffer_size=str(size))['clipboardBufferSize'], size)

    def test_default_and_omitted_leave_key_unset(self):
        self.assertNotIn('clipboardBufferSize', _record_connection())
        self.assertNotIn('clipboardBufferSize', _record_connection(clipboard_buffer_size='default'))
        self.assertNotIn('clipboardBufferSize', _record_connection(clipboard_buffer_size=''))
        self.assertNotIn('clipboardBufferSize', _record_connection(clipboard_buffer_size=None))

    def test_invalid_values_rejected(self):
        for bad in ('2mb', 'big', '-1', 0, 1024, 12345, True, 1.5, ['1mb']):
            with self.subTest(value=bad):
                self.assertIsNone(parse_clipboard_buffer_size(bad))
                self.assertNotIn('clipboardBufferSize', _record_connection(clipboard_buffer_size=bad))

    def test_other_settings_unaffected(self):
        conn = _record_connection(clipboard_buffer_size='1mb', disable_copy=True, disable_paste=False)
        self.assertEqual(conn['clipboardBufferSize'], 1024 * 1024)
        self.assertIs(conn['disableCopy'], True)
        self.assertIs(conn['disablePaste'], False)

    def test_other_clipboard_protocols_carry_clipboard_buffer_size_too(self):
        # copy, not move: RBI keeps it, RDP/SSH/VNC/Telnet and all databases have it as well (as in the Web Vault)
        from keepercommander.commands.pam_import.base import PamSettingsFieldData
        protos = ('rdp', 'ssh', 'vnc', 'telnet', 'mysql', 'postgresql', 'sql-server', 'mariadb', 'oracle',
                  'mongodb', 'redis', 'elasticsearch', 'clickhouse', 'dynamodb')
        for proto in protos:
            with self.subTest(protocol=proto):
                obj = PamSettingsFieldData.get_connection_class(
                    {'protocol': proto, 'clipboard_buffer_size': '1mb'})
                self.assertEqual(obj.to_record_dict().get('clipboardBufferSize'), 1024 * 1024)

    def test_kubernetes_clipboard_buffer_size_is_code_only(self):
        # the Web Vault has no clipboard settings for Kubernetes, but the KCM Kubernetes plugin declares
        # clipboard-buffer-size, so it is accepted (Tier 2: code only, not documented in the README)
        from keepercommander.commands.pam_import.base import PamSettingsFieldData
        obj = PamSettingsFieldData.get_connection_class({'protocol': 'kubernetes', 'clipboard_buffer_size': '1mb'})
        self.assertEqual(obj.to_record_dict().get('clipboardBufferSize'), 1024 * 1024)


@unittest.skipIf(skip_tests, skip_reason)
class TestPamImportRbiAllowSupplyUser(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_true_false_round_trip(self):
        self.assertIs(_record_connection(allow_supply_user=True)['allowSupplyUser'], True)
        self.assertIs(_record_connection(allow_supply_user=False)['allowSupplyUser'], False)
        self.assertIs(_record_connection(allow_supply_user='true')['allowSupplyUser'], True)

    def test_omitted_leaves_key_unset(self):
        self.assertNotIn('allowSupplyUser', _record_connection())


if __name__ == '__main__':
    unittest.main()
