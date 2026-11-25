"""Tests for the Telnet terminal / login / WoL / recording options of `pam project import/extend`."""
import logging
import unittest

from keepercommander.commands.pam_import.base import PamSettingsFieldData


def _record(**extra):
    conn = {"protocol": "telnet", "port": "23", **extra}
    psfd = PamSettingsFieldData.load({"connection": conn})
    return psfd.connection.to_record_dict()


class TestTelnetTier1(unittest.TestCase):
    def test_all_tier1_options(self):
        got = _record(font_name="Menlo", read_only=True, backspace="8", terminal_type="vt100",
                      clipboard_buffer_size="10mb")
        self.assertEqual(got, {
            "protocol": "telnet", "port": "23", "fontName": "Menlo", "readOnly": True, "backspace": "8",
            "terminalType": "vt100", "clipboardBufferSize": 10 * 1024 * 1024,
        })

    def test_existing_telnet_options_unchanged(self):
        got = _record(username_regex="login:", password_regex="pass:", login_success_regex="\\$", login_failure_regex="denied",
                      color_scheme="green-black", font_size=14, scrollback=800, disable_paste=True)
        self.assertEqual(got, {
            "protocol": "telnet", "port": "23", "usernameRegex": "login:", "passwordRegex": "pass:",
            "loginSuccessRegex": "\\$", "loginFailureRegex": "denied", "colorScheme": "green-black",
            "fontSize": "14", "scrollback": 800, "disablePaste": True,
        })

    def test_backspace_values(self):
        self.assertEqual(_record(backspace=127).get("backspace"), "127")
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("backspace", _record(backspace="9"))

    def test_terminal_type_outside_kcm_list_written_with_warning(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            self.assertEqual(_record(terminal_type="rxvt").get("terminalType"), "rxvt")
        self.assertIn("terminal_type", "\n".join(cm.output))
        with self.assertNoLogs(level=logging.WARNING):
            self.assertEqual(_record(terminal_type="xterm-256color").get("terminalType"), "xterm-256color")

    def test_blank_and_invalid_strings_skipped(self):
        with self.assertLogs(level=logging.WARNING):
            got = _record(font_name=5, terminal_type=[])
        self.assertEqual(got, {"protocol": "telnet", "port": "23"})
        self.assertEqual(_record(font_name="  ", terminal_type=""), {"protocol": "telnet", "port": "23"})


class TestTelnetLoginRegexPair(unittest.TestCase):
    def test_single_regex_warns_but_is_written(self):
        for key, rec in (("login_success_regex", "loginSuccessRegex"), ("login_failure_regex", "loginFailureRegex")):
            with self.assertLogs(level=logging.WARNING) as cm:
                got = _record(**{key: "x"})
            self.assertEqual(got.get(rec), "x")
            text = "\n".join(cm.output)
            self.assertIn("guacd", text)
            self.assertIn("ignore", text)

    def test_pair_or_none_no_warning(self):
        with self.assertNoLogs(level=logging.WARNING):
            _record(login_success_regex="a", login_failure_regex="b")
        with self.assertNoLogs(level=logging.WARNING):
            _record(username_regex="u")

    def test_patterns_not_validated(self):
        # POSIX extended regexes are checked by guacd; Commander does not compile them
        with self.assertNoLogs(level=logging.WARNING):
            got = _record(login_success_regex="([", login_failure_regex="a{")
        self.assertEqual(got.get("loginSuccessRegex"), "([")


class TestTelnetTier2(unittest.TestCase):
    def test_tier2_options(self):
        got = _record(func_keys_and_keypad="ESC", timeout="30", wol_send_packet=True, wol_mac_addr="00:11:22:33:44:55",
                      wol_wait_time=5, recording_exclude_mouse=True, recording_include_clipboard=False)
        self.assertEqual(got, {
            "protocol": "telnet", "port": "23", "funcKeysAndKeypad": "esc", "timeout": 30,
            "wolSendPacket": True, "wolMacAddr": "00:11:22:33:44:55", "wolWaitTime": 5,
            "recordingExcludeMouse": True, "recordingIncludeClipboard": False,
        })

    def test_tier2_invalid(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            got = _record(func_keys_and_keypad="x", timeout=0)
        self.assertEqual(got, {"protocol": "telnet", "port": "23"})
        self.assertIn("func_keys_and_keypad", "\n".join(cm.output))

    def test_exclude_touch_not_read(self):
        self.assertNotIn("recordingExcludeTouch", _record(recording_exclude_touch=True))


class TestTelnetNotAdded(unittest.TestCase):
    def test_dropped_options_and_sftp(self):
        got = _record(typescript_path="/t", typescript_name="n", recording_path="/r", username="u", password="p")
        self.assertEqual(got, {"protocol": "telnet", "port": "23"})

    def test_sftp_warns_for_telnet(self):
        # collected on load, logged with the machine title by validate_record
        psfd = PamSettingsFieldData.load({"connection": {"protocol": "telnet", "port": "23", "sftp": {"enable_sftp": True}}})
        self.assertEqual(len(psfd.sftp_warnings), 1)
        self.assertNotIn("sftp", psfd.connection.to_record_dict())


if __name__ == "__main__":
    unittest.main()
