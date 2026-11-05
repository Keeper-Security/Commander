"""Tests for the VNC display / clipboard / audio / WoL / recording options of `pam project import/extend`."""
import logging
import unittest

from keepercommander.commands.pam_import.base import (
    PamSettingsFieldData,
    parse_int_in_range,
    parse_vnc_encodings,
)


def _record(**extra):
    conn = {"protocol": "vnc", **extra}
    psfd = PamSettingsFieldData.load({"connection": conn})
    return psfd.connection.to_record_dict()


class TestVncTier1(unittest.TestCase):
    def test_all_tier1_options(self):
        got = _record(
            read_only=True, swap_red_blue="true", force_lossless=False,
            cursor="Remote", color_depth=24, clipboard_encoding="utf-8",
            enable_audio=True, audio_servername="pa.example",
            compress_level=6, quality_level="9", encodings="tight, ZRLE copyrect")
        self.assertEqual(got, {
            "protocol": "vnc",
            "readOnly": True, "swapRedBlue": True, "forceLossless": False,
            "cursor": "remote", "colorDepth": "24", "clipboardEncoding": "UTF-8",
            "enableAudio": True, "audioServername": "pa.example",
            "compressLevel": 6, "qualityLevel": 9, "encodings": "tight zrle copyrect",
        })

    def test_vault_key_names_are_not_used(self):
        # KCM names are used on purpose; the Web Vault names (compressionLevel etc.) are not read
        got = _record(port="5900", compressionLevel=6, displayQuality=3, displayEncodings=["tight"])
        self.assertEqual(got, {"protocol": "vnc", "port": "5900"})

    def test_encodings_list_and_dedupe(self):
        self.assertEqual(parse_vnc_encodings(["Tight", "raw", "tight"]), "tight raw")
        self.assertEqual(parse_vnc_encodings(["ultra", "zlib", "corre"]), "ultra zlib corre")
        self.assertIsNone(parse_vnc_encodings(""))
        self.assertIsNone(parse_vnc_encodings([]))

    def test_invalid_values_skipped_with_warning(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            got = _record(port="1", cursor="middle", color_depth=15, clipboard_encoding="latin9",
                          compress_level=10, quality_level=-1, encodings="bogus tight")
        self.assertEqual(got, {"protocol": "vnc", "port": "1", "encodings": "tight"})
        text = "\n".join(cm.output)
        for key in ("cursor", "color_depth", "clipboard_encoding", "compress_level", "quality_level", "encodings"):
            self.assertIn(key, text)

    def test_bounds(self):
        self.assertEqual(_record(compress_level=0, quality_level=0).get("compressLevel"), 0)
        self.assertEqual(_record(compress_level=9, quality_level=9).get("qualityLevel"), 9)
        self.assertIsNone(parse_int_in_range(True, "x", 0, 9))
        self.assertIsNone(parse_int_in_range("abc", "x", 0, 9))

    def test_existing_vnc_options_unchanged(self):
        got = _record(destination_host="h", destination_port="5901", disable_display_resize=True,
                      clipboard_buffer_size="1mb", disable_copy=True)
        self.assertEqual(got, {"protocol": "vnc", "destHost": "h", "destPort": "5901",
                               "disableDisplayResize": True, "clipboardBufferSize": 1048576, "disableCopy": True})


class TestVncTier2(unittest.TestCase):
    def test_wol_and_recording_and_server_input(self):
        got = _record(disable_server_input=True, wol_send_packet=True, wol_mac_addr="00:11:22:33:44:55",
                      wol_broadcast_addr="192.168.1.255", wol_udp_port="7", wol_wait_time=30,
                      recording_exclude_output=True, recording_exclude_mouse=False, recording_include_clipboard=True)
        self.assertEqual(got, {
            "protocol": "vnc", "disableServerInput": True,
            "wolSendPacket": True, "wolMacAddr": "00:11:22:33:44:55", "wolBroadcastAddr": "192.168.1.255",
            "wolUdpPort": 7, "wolWaitTime": 30,
            "recordingExcludeOutput": True, "recordingExcludeMouse": False, "recordingIncludeClipboard": True,
        })

    def test_wol_wait_time_zero_kept(self):
        self.assertEqual(_record(wol_wait_time=0).get("wolWaitTime"), 0)

    def test_wol_invalid_values(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            got = _record(port="1", wol_send_packet=True, wol_mac_addr="nope", wol_broadcast_addr="x.y",
                          wol_udp_port=70000, wol_wait_time=-5)
        self.assertEqual(got, {"protocol": "vnc", "port": "1", "wolSendPacket": True})
        text = "\n".join(cm.output)
        for key in ("wol_mac_addr", "wol_broadcast_addr", "wol_udp_port", "wol_wait_time", "wol_send_packet is true"):
            self.assertIn(key, text)

    def test_ipv6_broadcast_accepted(self):
        self.assertEqual(_record(wol_broadcast_addr="ff02::1").get("wolBroadcastAddr"), "ff02::1")


if __name__ == "__main__":
    unittest.main()
