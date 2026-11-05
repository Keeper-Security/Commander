"""Tests for the `sftp` object of pam_settings.connection (RDP / SSH / VNC) in pam project import/extend."""
import logging
import unittest

from keepercommander.commands.pam_import.base import (
    PamMachineObject,
    PamSettingsFieldData,
    sftp_import_warnings,
)


def _connection(protocol, sftp):
    return {"protocol": protocol, "sftp": sftp}


def _record_sftp(protocol, sftp):
    psfd = PamSettingsFieldData.load({"connection": _connection(protocol, sftp)})
    return psfd.connection.to_record_dict().get("sftp", {})


class TestSftpTier2Options(unittest.TestCase):
    def test_rdp_vnc_full_object(self):
        sftp = {
            "enable_sftp": True,
            "sftp_root_directory": "/root",
            "sftp_upload_directory": "/up",
            "sftp_keepalive_interval": 12,
            "sftp_timeout": "30",
            "sftp_disable_download": True,
            "sftp_disable_upload": "false",
        }
        for proto in ("rdp", "vnc"):
            got = _record_sftp(proto, sftp)
            self.assertEqual(got, {
                "enableSftp": True,
                "sftpRootDirectory": "/root",
                "sftpDirectory": "/up",
                "sftpServerAliveInterval": 12,
                "sftpTimeout": 30,
                "sftpDisableDownload": True,
                "sftpDisableUpload": False,
            }, proto)

    def test_ssh_only_root_and_disable_flags(self):
        got = _record_sftp("ssh", {
            "enable_sftp": True,
            "sftp_root_directory": "/root",
            "sftp_disable_download": True,
            "sftp_disable_upload": True,
            "sftp_timeout": 30,
            "sftp_upload_directory": "/up",
        })
        self.assertEqual(got, {
            "enableSftp": True,
            "sftpRootDirectory": "/root",
            "sftpDisableDownload": True,
            "sftpDisableUpload": True,
        })

    def test_timeout_zero_and_invalid_not_emitted(self):
        self.assertNotIn("sftpTimeout", _record_sftp("rdp", {"enable_sftp": True, "sftp_timeout": 0}))
        self.assertNotIn("sftpTimeout", _record_sftp("rdp", {"enable_sftp": True, "sftp_timeout": "abc"}))

    def test_keys_added_when_sftp_not_enabled(self):
        # SFTP exception: keys are still added, only a warning is printed
        got = _record_sftp("rdp", {"sftp_root_directory": "/r", "sftp_timeout": 5, "sftp_disable_upload": True})
        self.assertEqual(got, {"sftpRootDirectory": "/r", "sftpTimeout": 5, "sftpDisableUpload": True})
        got = _record_sftp("rdp", {"enable_sftp": False, "sftp_timeout": 5})
        self.assertEqual(got, {"enableSftp": False, "sftpTimeout": 5})


class TestSftpWarnings(unittest.TestCase):
    def test_no_warning_when_enabled_with_resource(self):
        c = _connection("rdp", {"enable_sftp": True, "sftp_resource": "M2", "sftp_timeout": 5})
        self.assertEqual(sftp_import_warnings(c), [])

    def test_warns_disabled_until_enabled(self):
        for sftp in ({"sftp_root_directory": "/r"}, {"enable_sftp": False, "sftp_resource": "M2"}):
            msgs = sftp_import_warnings(_connection("rdp", sftp))
            self.assertEqual(len(msgs), 1)
            self.assertIn("stay disabled until SFTP is enabled", msgs[0])

    def test_no_warning_for_only_enable_false_or_empty(self):
        self.assertEqual(sftp_import_warnings(_connection("rdp", {"enable_sftp": False})), [])
        self.assertEqual(sftp_import_warnings(_connection("rdp", {})), [])
        self.assertEqual(sftp_import_warnings({"protocol": "rdp"}), [])

    def test_rdp_vnc_missing_resource(self):
        for proto in ("rdp", "vnc"):
            msgs = sftp_import_warnings(_connection(proto, {"enable_sftp": True}))
            self.assertEqual(len(msgs), 1, proto)
            self.assertIn("sftp_resource", msgs[0])

    def test_ssh_does_not_need_resource_but_warns_on_rdp_vnc_keys(self):
        self.assertEqual(sftp_import_warnings(_connection("ssh", {"enable_sftp": True})), [])
        msgs = sftp_import_warnings(_connection(
            "ssh", {"enable_sftp": True, "sftp_resource": "M2", "sftp_timeout": 5, "sftp_root_directory": "/r"}))
        self.assertEqual(len(msgs), 1)
        self.assertIn("sftp_resource", msgs[0])
        self.assertIn("sftp_timeout", msgs[0])
        self.assertNotIn("sftp_root_directory", msgs[0])

    def test_ssh_rdp_only_keys_do_not_count_as_set_settings(self):
        msgs = sftp_import_warnings(_connection("ssh", {"sftp_timeout": 5}))
        self.assertEqual(len(msgs), 1)
        self.assertIn("not supported for SSH", msgs[0])

    def test_unsupported_protocol(self):
        for proto in ("telnet", "kubernetes", "mysql"):
            msgs = sftp_import_warnings(_connection(proto, {"enable_sftp": True}))
            self.assertEqual(len(msgs), 1, proto)
            self.assertIn("not supported for protocol", msgs[0])

    def test_psfd_load_collects_and_machine_logs_with_title(self):
        data = {
            "type": "pamMachine", "title": "M1", "host": "h1", "port": "22",
            "pam_settings": {"connection": _connection("rdp", {"sftp_root_directory": "/r"})},
        }
        psfd = PamSettingsFieldData.load(data["pam_settings"])
        self.assertEqual(len(psfd.sftp_warnings), 1)
        with self.assertLogs(level=logging.WARNING) as cm:
            PamMachineObject.load(data)
        text = "\n".join(cm.output)
        self.assertIn('PAM Machine "M1"', text)
        self.assertIn("stay disabled until SFTP is enabled", text)

    def test_warnings_do_not_make_settings_non_empty(self):
        psfd = PamSettingsFieldData.load({"connection": {"protocol": "telnet", "sftp": {"enable_sftp": True}}})
        self.assertEqual(len(psfd.sftp_warnings), 1)
        self.assertTrue(psfd.is_empty())


if __name__ == "__main__":
    unittest.main()
