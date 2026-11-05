"""Tests for the Kubernetes SSL / exec command / terminal / clipboard options of `pam project import/extend`."""
import logging
import unittest

from keepercommander.commands.pam_import.base import PamSettingsFieldData


def _record(**extra):
    conn = {"protocol": "kubernetes", "port": "6443", **extra}
    psfd = PamSettingsFieldData.load({"connection": conn})
    return psfd.connection.to_record_dict()


class TestK8sTier1(unittest.TestCase):
    def test_all_tier1_options(self):
        got = _record(use_ssl=True, exec_command="/bin/sh", font_name="Menlo", read_only="true", backspace=8)
        self.assertEqual(got, {
            "protocol": "kubernetes", "port": "6443", "useSSL": True, "execCommand": "/bin/sh",
            "fontName": "Menlo", "readOnly": True, "backspace": "8",
        })

    def test_vault_command_key_not_read(self):
        # KCM name on purpose; the Web Vault's "command" key is not read (and is dropped by the Gateway / guacd)
        self.assertNotIn("execCommand", _record(command="/bin/sh"))
        self.assertNotIn("command", _record(command="/bin/sh"))

    def test_use_ssl_false_is_written(self):
        self.assertEqual(_record(use_ssl=False).get("useSSL"), False)

    def test_existing_k8s_options_unchanged(self):
        got = _record(namespace="ns", pod_name="pod-1", container="app", ignore_server_cert=True,
                      ca_certificate="CA", client_certificate="CRT", client_key="KEY",
                      color_scheme="gray-black", font_size=14, scrollback=500)
        self.assertEqual(got, {
            "protocol": "kubernetes", "port": "6443", "namespace": "ns", "pod": "pod-1", "container": "app",
            "ignoreCert": True, "caCert": "CA", "clientCert": "CRT", "clientKey": "KEY",
            "colorScheme": "gray-black", "fontSize": "14", "scrollback": 500,
        })

    def test_backspace_values_and_blank_strings(self):
        self.assertEqual(_record(backspace="127").get("backspace"), "127")
        with self.assertLogs(level=logging.WARNING):
            got = _record(backspace="9", font_name=5, exec_command=[])
        self.assertEqual(got, {"protocol": "kubernetes", "port": "6443"})
        self.assertEqual(_record(font_name=" ", exec_command=""), {"protocol": "kubernetes", "port": "6443"})


class TestK8sTier2(unittest.TestCase):
    def test_tier2_options(self):
        got = _record(terminal_type="xterm", func_keys_and_keypad="VT100", disable_copy=True, disable_paste=False,
                      clipboard_buffer_size="1mb", recording_exclude_output=True, recording_include_clipboard=False)
        self.assertEqual(got, {
            "protocol": "kubernetes", "port": "6443", "terminalType": "xterm", "funcKeysAndKeypad": "vt100",
            "disableCopy": True, "disablePaste": False, "clipboardBufferSize": 1024 * 1024,
            "recordingExcludeOutput": True, "recordingIncludeClipboard": False,
        })

    def test_terminal_type_outside_list_warns_but_written(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            self.assertEqual(_record(terminal_type="rxvt").get("terminalType"), "rxvt")
        self.assertIn("terminal_type", "\n".join(cm.output))

    def test_invalid_func_keys(self):
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("funcKeysAndKeypad", _record(func_keys_and_keypad="x"))

    def test_not_declared_by_kubernetes_are_ignored(self):
        got = _record(timeout=30, wol_send_packet=True, wol_mac_addr="00:11:22:33:44:55", recording_exclude_touch=True)
        self.assertEqual(got, {"protocol": "kubernetes", "port": "6443"})


class TestK8sNotAdded(unittest.TestCase):
    def test_dropped_options_are_not_processed(self):
        got = _record(typescript_path="/t", recording_path="/r", username="u", password="p", kubeconfig="x", token="t")
        self.assertEqual(got, {"protocol": "kubernetes", "port": "6443"})


if __name__ == "__main__":
    unittest.main()
