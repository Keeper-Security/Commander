"""Tests for the SSH terminal / session / WoL / recording options of `pam project import/extend`."""
import logging
import unittest

from keepercommander.commands.pam_import.base import (
    PamSettingsFieldData,
    TerminalBehaviorConnectionSettings,
)


def _record(**extra):
    conn = {"protocol": "ssh", **extra}
    psfd = PamSettingsFieldData.load({"connection": conn})
    return psfd.connection.to_record_dict()


class TestSshTier1(unittest.TestCase):
    def test_all_tier1_options(self):
        got = _record(font_name="Menlo", read_only="true", backspace=8, terminal_type="xterm-256color",
                      locale="en_US.UTF-8", timezone="America/New_York", server_alive_interval=30,
                      clipboard_buffer_size="50mb")
        self.assertEqual(got, {
            "protocol": "ssh", "fontName": "Menlo", "readOnly": True, "backspace": "8",
            "terminalType": "xterm-256color", "locale": "en_US.UTF-8", "timezone": "America/New_York",
            "serverAliveInterval": 30, "clipboardBufferSize": 50 * 1024 * 1024,
        })

    def test_existing_ssh_options_unchanged(self):
        got = _record(public_host_key="AAAA", command="/bin/bash", color_scheme="gray-black", font_size=12,
                      scrollback=500, disable_copy=True,
                      sftp={"enable_sftp": True, "sftp_root_directory": "/tmp"})
        self.assertEqual(got, {
            "protocol": "ssh", "hostKey": "AAAA", "command": "/bin/bash", "colorScheme": "gray-black",
            "fontSize": "12", "scrollback": 500, "disableCopy": True,
            "sftp": {"enableSftp": True, "sftpRootDirectory": "/tmp"},
        })

    def test_backspace_values(self):
        self.assertEqual(_record(backspace="127").get("backspace"), "127")
        self.assertEqual(_record(backspace=127).get("backspace"), "127")
        self.assertEqual(TerminalBehaviorConnectionSettings.load({"backspace": 8}).backspace, "8")
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("backspace", _record(port="1", backspace="9"))

    def test_terminal_type_outside_kcm_list_written_with_warning(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            got = _record(terminal_type="rxvt")
        self.assertEqual(got.get("terminalType"), "rxvt")
        self.assertIn("terminal_type", "\n".join(cm.output))
        # listed value: no warning
        with self.assertNoLogs(level=logging.WARNING):
            _record(terminal_type="vt100")

    def test_server_alive_interval(self):
        self.assertEqual(_record(server_alive_interval=0).get("serverAliveInterval"), 0)
        self.assertEqual(_record(server_alive_interval="2").get("serverAliveInterval"), 2)
        with self.assertLogs(level=logging.WARNING) as cm:
            self.assertEqual(_record(server_alive_interval=1).get("serverAliveInterval"), 2)
        self.assertIn("stored as 2", "\n".join(cm.output))
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("serverAliveInterval", _record(port="1", server_alive_interval=-5))

    def test_blank_and_invalid_strings_skipped(self):
        with self.assertLogs(level=logging.WARNING):
            got = _record(port="1", font_name=5, locale=[], timezone=7)
        self.assertEqual(got, {"protocol": "ssh", "port": "1"})
        self.assertEqual(_record(port="1", font_name="  ", locale="", timezone=""), {"protocol": "ssh", "port": "1"})

    def test_other_terminal_protocols_unaffected(self):
        # the Web Vault hides the terminal display fields for the KeeperDB-only database protocols
        psfd = PamSettingsFieldData.load({"connection": {"protocol": "mariadb", "font_name": "x", "read_only": True, "port": "3306"}})
        self.assertNotIn("fontName", psfd.connection.to_record_dict())
        self.assertNotIn("readOnly", psfd.connection.to_record_dict())


class TestSshTier2(unittest.TestCase):
    def test_tier2_options(self):
        got = _record(func_keys_and_keypad="VT100", timeout="15", wol_send_packet=True,
                      wol_mac_addr="00-11-22-33-44-55", wol_udp_port=9, wol_wait_time=0,
                      recording_exclude_output=True, recording_include_clipboard=False)
        self.assertEqual(got, {
            "protocol": "ssh", "funcKeysAndKeypad": "vt100", "timeout": 15,
            "wolSendPacket": True, "wolMacAddr": "00-11-22-33-44-55", "wolUdpPort": 9, "wolWaitTime": 0,
            "recordingExcludeOutput": True, "recordingIncludeClipboard": False,
        })

    def test_tier2_invalid(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            got = _record(port="1", func_keys_and_keypad="x", timeout=0)
        self.assertEqual(got, {"protocol": "ssh", "port": "1"})
        text = "\n".join(cm.output)
        self.assertIn("func_keys_and_keypad", text)
        self.assertIn("timeout", text)


class TestSshNotAdded(unittest.TestCase):
    def test_dropped_options_are_not_processed(self):
        got = _record(port="1", enable_agent=True, clipboard_encoding="UTF-8", recording_path="/x", recording_name="n",
                      typescript_path="/t", typescript_name="n", username="u", password="p", private_key="k")
        self.assertEqual(got, {"protocol": "ssh", "port": "1"})


if __name__ == "__main__":
    unittest.main()
