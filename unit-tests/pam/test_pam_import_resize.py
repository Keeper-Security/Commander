"""
Unit tests for display resizing in the `pam project import` / `pam project extend` connection settings.

Matches KCM:
* RDP has `resize-method` (import key `resize_method`): "" = no dynamic resizing, "display-update", "reconnect".
  The old `disable_dynamic_resizing` boolean is no longer supported.
* VNC has a separate boolean `disable-display-resize` (import key `disable_display_resize`); RDP does not have it.
"""

import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_import.base import PamSettingsFieldData, parse_rdp_resize_method
    from keepercommander.commands.pam_import.kcm_import import KCMParameterMapper
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import pam_import: {e}"


def _record(protocol, **extra):
    obj = PamSettingsFieldData.get_connection_class({'protocol': protocol, **extra})
    return obj.to_record_dict() if obj else None


def _kcm_row(protocol, name, value):
    return {
        'connection_id': 1, 'name': 'conn', 'protocol': protocol, 'max_connections': None,
        'parameter_name': name, 'parameter_value': value, 'connection_group_id': None, 'parent_id': None,
        'group_name': None, 'attribute_name': None, 'attribute_value': None,
    }


@unittest.skipIf(skip_tests, skip_reason)
class TestRdpResizeMethod(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_values_round_trip(self):
        for value in ('display-update', 'reconnect', ''):
            with self.subTest(value=value):
                self.assertEqual(_record('rdp', resize_method=value)['resizeMethod'], value)

    def test_empty_means_no_dynamic_resizing_and_is_written(self):
        self.assertIn('resizeMethod', _record('rdp', resize_method=''))
        self.assertEqual(_record('rdp', resize_method='')['resizeMethod'], '')

    def test_case_and_whitespace_normalized(self):
        self.assertEqual(_record('rdp', resize_method=' Reconnect ')['resizeMethod'], 'reconnect')
        self.assertEqual(_record('rdp', resize_method='DISPLAY-UPDATE')['resizeMethod'], 'display-update')

    def test_omitted_or_null_uses_default_display_update(self):
        self.assertEqual(_record('rdp')['resizeMethod'], 'display-update')
        self.assertEqual(_record('rdp', resize_method=None)['resizeMethod'], 'display-update')

    def test_invalid_value_falls_back_to_default(self):
        for bad in ('resize', 'none', 'reconnectx', 0, 1, True, ['reconnect']):
            with self.subTest(value=bad):
                self.assertEqual(_record('rdp', resize_method=bad)['resizeMethod'], 'display-update')
                self.assertIsNone(parse_rdp_resize_method(bad))

    def test_disable_dynamic_resizing_is_no_longer_supported(self):
        for value in (True, False):
            with self.subTest(value=value):
                # ignored: the default applies, and it never produces "" (no dynamic resizing)
                self.assertEqual(_record('rdp', disable_dynamic_resizing=value)['resizeMethod'], 'display-update')

    def test_disable_dynamic_resizing_logs_a_warning(self):
        logging.disable(logging.NOTSET)
        with self.assertLogs(level='WARNING') as cm:
            _record('rdp', disable_dynamic_resizing=True)
        self.assertTrue(any('disable_dynamic_resizing' in m and 'resize_method' in m for m in cm.output))

    def test_resize_method_wins_over_the_removed_key(self):
        self.assertEqual(_record('rdp', resize_method='', disable_dynamic_resizing=False)['resizeMethod'], '')

    def test_rdp_has_no_disable_display_resize(self):
        self.assertNotIn('disableDisplayResize', _record('rdp', disable_display_resize=True))

    def test_other_protocols_do_not_carry_resize_method(self):
        for proto in ('vnc', 'ssh', 'telnet', 'kubernetes'):
            with self.subTest(protocol=proto):
                self.assertNotIn('resizeMethod', _record(proto, resize_method='reconnect'))


@unittest.skipIf(skip_tests, skip_reason)
class TestVncDisableDisplayResize(unittest.TestCase):
    def test_true_false_round_trip(self):
        self.assertIs(_record('vnc', disable_display_resize=True)['disableDisplayResize'], True)
        self.assertIs(_record('vnc', disable_display_resize=False)['disableDisplayResize'], False)
        self.assertIs(_record('vnc', disable_display_resize='true')['disableDisplayResize'], True)

    def test_omitted_leaves_key_unset(self):
        self.assertNotIn('disableDisplayResize', _record('vnc'))

    def test_vnc_has_no_resize_method(self):
        self.assertNotIn('resizeMethod', _record('vnc', disable_display_resize=True, resize_method='reconnect'))

    def test_only_vnc_carries_it(self):
        for proto in ('rdp', 'ssh', 'telnet', 'kubernetes'):
            with self.subTest(protocol=proto):
                self.assertNotIn('disableDisplayResize', _record(proto, disable_display_resize=True))


@unittest.skipIf(skip_tests, skip_reason)
class TestKcmResizeMapping(unittest.TestCase):
    def _connection(self, protocol, name, value):
        resources, _ = KCMParameterMapper().transform([_kcm_row(protocol, name, value)])
        return resources[0]['pam_settings']['connection']

    def test_rdp_resize_method_maps_to_resize_method(self):
        for value in ('display-update', 'reconnect', ''):
            with self.subTest(value=value):
                self.assertEqual(self._connection('rdp', 'resize-method', value)['resize_method'], value)

    def test_vnc_disable_display_resize_maps_to_its_own_key(self):
        conn = self._connection('vnc', 'disable-display-resize', 'true')
        self.assertEqual(conn['disable_display_resize'], 'true')
        self.assertNotIn('disable_dynamic_resizing', conn)

    def test_kcm_values_end_up_in_the_record(self):
        conn = self._connection('rdp', 'resize-method', 'reconnect')
        self.assertEqual(_record('rdp', **{k: v for k, v in conn.items() if k != 'protocol'})['resizeMethod'], 'reconnect')
        conn = self._connection('vnc', 'disable-display-resize', 'true')
        self.assertIs(_record('vnc', **{k: v for k, v in conn.items() if k != 'protocol'})['disableDisplayResize'], True)


if __name__ == '__main__':
    unittest.main()
