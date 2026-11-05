"""
RBI (pamRemoteBrowser, protocol http) options added to `pam project import/extend`:
accept_language / suppress_js_dialogs (in the Web Vault) and the KCM-only options
(read_only, enable_webgl, disable_webauthn, timezone, cef_log_level, recording_exclude_*),
plus the kcm_mappings.json entries for them.
"""
import json
import logging
import os
import unittest

from keepercommander.commands.pam_import import base
from keepercommander.commands.pam_import.base import ConnectionSettingsHTTP


def _rec(**kw):
    kw.setdefault('protocol', 'http')
    return ConnectionSettingsHTTP.load(kw).to_record_dict()


class TestRbiVaultOptions(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_accept_language(self):
        self.assertEqual(_rec(accept_language=' en-US,en;q=0.9 ')['acceptLanguage'], 'en-US,en;q=0.9')
        for empty in (None, '', '   ', 5):
            self.assertNotIn('acceptLanguage', _rec(accept_language=empty))

    def test_suppress_js_dialogs(self):
        self.assertIs(_rec(suppress_js_dialogs=True)['suppressJsDialogs'], True)
        self.assertIs(_rec(suppress_js_dialogs='false')['suppressJsDialogs'], False)
        self.assertNotIn('suppressJsDialogs', _rec())
        self.assertNotIn('suppressJsDialogs', _rec(suppress_js_dialogs='maybe'))


class TestRbiKcmOnlyOptions(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_booleans(self):
        for key, rec_key in (('read_only', 'readOnly'), ('enable_webgl', 'enableWebgl'),
                             ('disable_webauthn', 'disableWebauthn'),
                             ('recording_exclude_output', 'recordingExcludeOutput'),
                             ('recording_exclude_mouse', 'recordingExcludeMouse'),
                             ('recording_exclude_touch', 'recordingExcludeTouch')):
            with self.subTest(key=key):
                self.assertIs(_rec(**{key: True})[rec_key], True)
                self.assertIs(_rec(**{key: 'false'})[rec_key], False)
                self.assertNotIn(rec_key, _rec())

    def test_timezone(self):
        self.assertEqual(_rec(timezone=' Europe/Sofia ')['timezone'], 'Europe/Sofia')
        self.assertNotIn('timezone', _rec(timezone=''))

    def test_cef_log_level(self):
        self.assertEqual(_rec(cef_log_level='Verbose')['cefLogLevel'], 'verbose')
        for level in base.RBI_CEF_LOG_LEVELS:
            self.assertEqual(_rec(cef_log_level=level)['cefLogLevel'], level)
        self.assertNotIn('cefLogLevel', _rec(cef_log_level='loud'))

    def test_invalid_values_warn_and_are_skipped(self):
        logging.disable(logging.NOTSET)
        with self.assertLogs(level='WARNING') as cm:
            rec = _rec(cef_log_level='loud', timezone=5, accept_language=5)
        self.assertNotIn('cefLogLevel', rec)
        self.assertNotIn('timezone', rec)
        self.assertNotIn('acceptLanguage', rec)
        self.assertEqual(len(cm.output), 3)


class TestKcmMappings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.path.join(os.path.dirname(base.__file__), 'kcm_mappings.json')
        with open(path, encoding='utf-8') as f:
            cls.res = json.load(f)['resources']

    def test_rbi_options_are_mapped(self):
        expected = {
            'audio-bps': 'audio_bps', 'audio-channels': 'audio_channels', 'audio-sample-rate': 'audio_sample_rate',
            'clipboard-buffer-size': 'clipboard_buffer_size',
            'allow-file-uploads': 'allow_file_uploads', 'allow-file-downloads': 'allow_file_downloads',
            'accept-language': 'accept_language', 'suppress-js-dialogs': 'suppress_js_dialogs',
            'read-only': 'read_only', 'enable-webgl': 'enable_webgl', 'disable-webauthn': 'disable_webauthn',
            'timezone': 'timezone', 'cef-log-level': 'cef_log_level',
            'recording-exclude-output': 'recording_exclude_output',
            'recording-exclude-mouse': 'recording_exclude_mouse',
            'recording-exclude-touch': 'recording_exclude_touch',
        }
        for kcm, key in expected.items():
            with self.subTest(kcm=kcm):
                self.assertEqual(self.res.get(kcm), f'pam_settings.connection.{key}')

    def test_every_mapped_rbi_key_is_loaded_by_the_http_class(self):
        sample = {'audio_bps': 16, 'audio_channels': 2, 'audio_sample_rate': 44100, 'clipboard_buffer_size': '1mb',
                  'allow_file_uploads': True, 'allow_file_downloads': True, 'accept_language': 'en',
                  'suppress_js_dialogs': True, 'read_only': True, 'enable_webgl': True, 'disable_webauthn': True,
                  'timezone': 'UTC', 'cef_log_level': 'info', 'recording_exclude_output': True,
                  'recording_exclude_mouse': True, 'recording_exclude_touch': True}
        logging.disable(logging.CRITICAL)
        try:
            rec = _rec(**sample)
        finally:
            logging.disable(logging.NOTSET)
        self.assertEqual(len(rec) - 1, len(sample))  # minus "protocol"


if __name__ == '__main__':
    unittest.main()
