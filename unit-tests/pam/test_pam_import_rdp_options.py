"""Tests for the RDP display / device / performance / remote-app options of `pam project import/extend`."""
import logging
import unittest

from keepercommander.commands.pam_import.base import (
    RDP_SERVER_LAYOUTS,
    PamSettingsFieldData,
)


def _record(**extra):
    conn = {"protocol": "rdp", "port": "3389", **extra}
    psfd = PamSettingsFieldData.load({"connection": conn})
    got = psfd.connection.to_record_dict()
    got.pop("resizeMethod", None)  # always written (default display-update)
    return got


class TestRdpTier1(unittest.TestCase):
    def test_all_tier1_options(self):
        got = _record(
            initial_program="C:\\app.exe", client_name="kc-host", server_layout="DE-DE-QWERTZ", timezone="Europe/Berlin",
            enable_touch=True, console=False, width=1920, height="1080", dpi=96, color_depth=32,
            force_lossless=True, read_only=False, normalize_clipboard="Unix",
            console_audio=True, enable_audio_input=True, enable_printing=True, printer_name="Office",
            enable_theming=True, enable_font_smoothing=True, enable_desktop_composition=False, enable_menu_animations=False,
            disable_bitmap_caching=True, disable_offscreen_caching=False, disable_glyph_caching=True,
            remote_app="||notepad", remote_app_dir="C:\\tmp", remote_app_args="/x")
        self.assertEqual(got, {
            "protocol": "rdp", "port": "3389",
            "initialProgram": "C:\\app.exe", "clientName": "kc-host", "serverLayout": "de-de-qwertz", "timezone": "Europe/Berlin",
            "enableTouch": True, "console": False, "width": 1920, "height": 1080, "dpi": 96, "colorDepth": 32,
            "forceLossless": True, "readOnly": False, "normalizeClipboard": "unix",
            "consoleAudio": True, "enableAudioInput": True, "enablePrinting": True, "printerName": "Office",
            "enableTheming": True, "enableFontSmoothing": True, "enableDesktopComposition": False, "enableMenuAnimations": False,
            "disableBitmapCaching": True, "disableOffscreenCaching": False, "disableGlyphCaching": True,
            "remoteApp": "||notepad", "remoteAppDir": "C:\\tmp", "remoteAppArgs": "/x",
        })

    def test_vault_printer_key_not_read(self):
        self.assertNotIn("printerName", _record(redirectedPrinterName="X"))

    def test_width_height_dpi_must_be_positive_whole_numbers(self):
        for bad in (0, "0", -5, "-5", 12.5, "abc", True):
            with self.assertLogs(level=logging.WARNING):
                got = _record(width=bad, height=bad, dpi=bad)
            for k in ("width", "height", "dpi"):
                self.assertNotIn(k, got, bad)
        self.assertEqual(_record(width="800").get("width"), 800)

    def test_server_layout_known_and_unknown(self):
        self.assertEqual(len(RDP_SERVER_LAYOUTS), 24)
        self.assertEqual(_record(server_layout="failsafe").get("serverLayout"), "failsafe")
        with self.assertLogs(level=logging.WARNING) as cm:
            got = _record(server_layout="xx-yy")
        self.assertNotIn("serverLayout", got)
        text = "\n".join(cm.output)
        self.assertIn("skipped", text)
        self.assertIn("guacd will use its default layout 'en-us-qwerty'", text)

    def test_color_depth(self):
        with self.assertNoLogs(level=logging.WARNING):
            self.assertEqual(_record(color_depth=32).get("colorDepth"), 32)
        for d in (8, 16, 24):
            # guacd ignores depths below 32 while the RDP Graphics Pipeline is enabled (default): written, with a warning
            with self.assertLogs(level=logging.WARNING) as cm:
                self.assertEqual(_record(color_depth=d).get("colorDepth"), d)
            self.assertIn("graphics pipeline", "\n".join(cm.output).lower())
        with self.assertNoLogs(level=logging.WARNING):
            self.assertEqual(_record(color_depth=16, disable_gfx=True).get("colorDepth"), 16)
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("colorDepth", _record(color_depth=15))

    def test_normalize_clipboard_and_invalid(self):
        for v in ("preserve", "unix", "windows"):
            self.assertEqual(_record(normalize_clipboard=v).get("normalizeClipboard"), v)
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("normalizeClipboard", _record(normalize_clipboard="mac"))

    def test_client_name_over_32_bytes_warns_but_accepted(self):
        name = "x" * 40
        with self.assertLogs(level=logging.WARNING) as cm:
            self.assertEqual(_record(client_name=name).get("clientName"), name)
        self.assertIn("guacd", "\n".join(cm.output))
        # bytes, not characters: 20 two-byte characters = 40 bytes
        with self.assertLogs(level=logging.WARNING):
            self.assertEqual(_record(client_name="\u00e9" * 20).get("clientName"), "\u00e9" * 20)
        with self.assertNoLogs(level=logging.WARNING):
            _record(client_name="x" * 32)

    def test_existing_rdp_options_unchanged(self):
        got = _record(security="nla", ignore_server_cert=True, clipboard_buffer_size="50mb", drive_redirection_path="user",
                      resize_method="reconnect")
        psfd = PamSettingsFieldData.load({"connection": {"protocol": "rdp", "port": "1", "resize_method": "reconnect"}})
        self.assertEqual(psfd.connection.to_record_dict().get("resizeMethod"), "reconnect")
        self.assertEqual(got["security"], "nla")
        self.assertEqual(got["clipboardBufferSize"], 50 * 1024 * 1024)
        self.assertEqual(got["driveRedirectionPath"], "user")


class TestRdpTier2(unittest.TestCase):
    def test_tier2_options(self):
        got = _record(drive_redirection_name="Share", disable_download=True, disable_upload=False, timeout="20",
                      cert_tofu=True, cert_fingerprints=["sha256:aa", "sha1:bb"], disable_gfx=True,
                      static_channels="a,b", wol_send_packet=True, wol_mac_addr="00:11:22:33:44:55",
                      recording_exclude_output=True, recording_exclude_touch=True, recording_include_clipboard=False)
        self.assertEqual(got, {
            "protocol": "rdp", "port": "3389",
            "driveRedirectionName": "Share", "disableDownload": True, "disableUpload": False, "timeout": 20,
            "certTofu": True, "certFingerprints": "sha256:aa,sha1:bb", "disableGfx": True, "staticChannels": "a,b",
            "wolSendPacket": True, "wolMacAddr": "00:11:22:33:44:55",
            "recordingExcludeOutput": True, "recordingExcludeTouch": True, "recordingIncludeClipboard": False,
        })

    def test_exclude_touch_only_for_rdp(self):
        psfd = PamSettingsFieldData.load({"connection": {"protocol": "vnc", "port": "1", "recording_exclude_touch": True}})
        self.assertNotIn("recordingExcludeTouch", psfd.connection.to_record_dict())
        psfd = PamSettingsFieldData.load({"connection": {"protocol": "ssh", "port": "1", "recording_exclude_touch": True}})
        self.assertNotIn("recordingExcludeTouch", psfd.connection.to_record_dict())

    def test_timeout_invalid(self):
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("timeout", _record(timeout=0))


class TestRdpNotAdded(unittest.TestCase):
    def test_dropped_options_are_not_processed(self):
        got = _record(drive_path="/x", drive_name="n", create_drive_path=True, enable_drive=True,
                      gateway_hostname="gw", gateway_port=443, gateway_username="u", gateway_password="p",
                      gateway_domain="d", recording_path="/r", typescript_path="/t", username="u", password="p")
        self.assertEqual(got, {"protocol": "rdp", "port": "3389"})


if __name__ == "__main__":
    unittest.main()
