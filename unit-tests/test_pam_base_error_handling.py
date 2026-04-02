"""Tests for PR #1892: narrowed exception handling and path validation in PAM base."""

import json
import os
import tempfile
import unittest

from keepercommander.commands.pam_import.base import (
    PamScriptsObject,
    PamScriptObject,
    PamAttachmentsObject,
    PamAttachmentObject,
    PamRotationScheduleObject,
    PamRotationSettingsObject,
    DagSettingsObject,
    DagJitSettingsObject,
    DagAiSettingsObject,
    PamUserObject,
    LoginUserObject,
    PamBaseMachineParser,
    PamMachineObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamRemoteBrowserObject,
    BaseConnectionSettings,
    ConnectionSettingsRDP,
    ConnectionSettingsHTTP,
    ConnectionSettingsVNC,
    ConnectionSettingsTelnet,
    ConnectionSettingsSSH,
    ConnectionSettingsKubernetes,
    BaseDatabaseConnectionSettings,
    ConnectionSettingsSqlServer,
    ConnectionSettingsPostgreSQL,
    ConnectionSettingsMySQL,
    PamPortForwardSettings,
    PamRemoteBrowserSettings,
    PamSettingsFieldData,
    ClipboardConnectionSettings,
    SFTPRootDirectorySettings,
    SFTPConnectionSettings,
    TerminalDisplayConnectionSettings,
)


class TestJsonDecodeErrorNarrowing(unittest.TestCase):
    """All json.loads sites must catch only JSONDecodeError, not bare except."""

    LOAD_CLASSES = [
        PamScriptsObject,
        PamScriptObject,
        PamAttachmentsObject,
        PamAttachmentObject,
        PamRotationScheduleObject,
        DagSettingsObject,
        PamUserObject,
        LoginUserObject,
        BaseConnectionSettings,
        ConnectionSettingsRDP,
        ConnectionSettingsHTTP,
        ConnectionSettingsVNC,
        ConnectionSettingsTelnet,
        ConnectionSettingsSSH,
        ConnectionSettingsKubernetes,
        BaseDatabaseConnectionSettings,
        ConnectionSettingsSqlServer,
        ConnectionSettingsPostgreSQL,
        ConnectionSettingsMySQL,
        PamPortForwardSettings,
        PamRemoteBrowserSettings,
        PamSettingsFieldData,
        ClipboardConnectionSettings,
        SFTPRootDirectorySettings,
        SFTPConnectionSettings,
        TerminalDisplayConnectionSettings,
        PamMachineObject,
        PamDatabaseObject,
        PamDirectoryObject,
        PamRemoteBrowserObject,
    ]

    RETURNS_NONE = [DagJitSettingsObject, DagAiSettingsObject]

    def test_invalid_json_logs_structured_error(self):
        """All load() methods should log 'invalid JSON' with line/col info."""
        for cls in self.LOAD_CLASSES:
            with self.subTest(cls=cls.__name__):
                with self.assertLogs(level='ERROR') as cm:
                    cls.load("{not valid json")
                self.assertTrue(
                    any('invalid JSON' in msg for msg in cm.output),
                    f"{cls.__name__}: expected 'invalid JSON' in log, got: {cm.output}"
                )

    def test_invalid_json_returns_object(self):
        """load() with bad JSON should return an object, not raise."""
        for cls in self.LOAD_CLASSES:
            with self.subTest(cls=cls.__name__):
                with self.assertLogs(level='ERROR'):
                    obj = cls.load("{bad")
                self.assertIsNotNone(obj)

    def test_invalid_json_returns_none_for_optional_types(self):
        """DagJitSettings and DagAiSettings return None on invalid JSON."""
        for cls in self.RETURNS_NONE:
            with self.subTest(cls=cls.__name__):
                with self.assertLogs(level='ERROR'):
                    obj = cls.load("{bad")
                self.assertIsNone(obj)

    def test_valid_json_parses_without_error(self):
        """Valid JSON string should parse without error logs."""
        obj = PamUserObject.load(json.dumps({"type": "pamUser"}))
        self.assertIsInstance(obj, PamUserObject)

    def test_dict_input_skips_parsing(self):
        """Dict input should not trigger json.loads."""
        obj = PamUserObject.load({"type": "pamUser"})
        self.assertIsInstance(obj, PamUserObject)

    def test_none_input_returns_empty(self):
        """None input should return empty object."""
        obj = PamScriptsObject.load(None)
        self.assertIsInstance(obj, PamScriptsObject)

    def test_integer_input_not_caught(self):
        """Non-string input bypasses json.loads — no exception swallowed."""
        obj = PamScriptsObject.load(123)
        self.assertIsInstance(obj, PamScriptsObject)


class TestCronFieldExceptionHandling(unittest.TestCase):
    """import_schedule_field uses string parsing, not JSON — test error paths."""

    def test_cron_malformed_expression(self):
        """Malformed CRON expression should log error."""
        data = {"type": "cron", "cron": "{not-json"}
        with self.assertLogs(level='ERROR') as cm:
            PamRotationScheduleObject.load(json.dumps(data))
        self.assertTrue(
            any('CRON' in msg for msg in cm.output)
        )

    def test_type_builtin_not_shadowed(self):
        """e.__class__.__name__ must be used, not type(e).__name__.

        The local variable `type = data.get('type', None)` shadows the
        built-in type(). Using type(e) would crash with TypeError.
        """
        data = {"type": "cron", "cron": "invalid-cron-value"}
        with self.assertLogs(level='ERROR') as cm:
            obj = PamRotationScheduleObject.load(data)
        self.assertIsInstance(obj, PamRotationScheduleObject)
        self.assertTrue(any('unexpected structure' in msg or 'CRON' in msg
                            for msg in cm.output))

    def test_rotation_settings_invalid_json(self):
        """PamRotationSettingsObject.load should handle invalid JSON."""
        with self.assertLogs(level='ERROR') as cm:
            obj = PamRotationSettingsObject.load("{bad json")
        self.assertIsInstance(obj, PamRotationSettingsObject)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))

    def test_base_machine_parser_invalid_json(self):
        """PamBaseMachineParser.load should handle invalid JSON."""
        with self.assertLogs(level='ERROR') as cm:
            obj = PamBaseMachineParser.load("pamMachine", "{bad json")
        self.assertIsNotNone(obj)
        self.assertTrue(any('invalid JSON' in msg for msg in cm.output))


class TestPathValidation(unittest.TestCase):
    """PamScriptObject and PamAttachmentObject must reject path traversal."""

    def test_dotdot_path_rejected(self):
        obj = PamScriptObject()
        obj.file = "../../../etc/passwd"
        self.assertFalse(obj.validate())

    def test_dotdot_in_middle_rejected(self):
        obj = PamScriptObject()
        obj.file = "scripts/../../etc/passwd"
        self.assertFalse(obj.validate())

    def test_normal_path_accepted(self):
        with tempfile.NamedTemporaryFile(suffix='.sh', delete=False) as f:
            tmppath = f.name
            f.write(b"#!/bin/bash\necho test\n")
        try:
            obj = PamScriptObject()
            obj.file = tmppath
            self.assertTrue(obj.validate())
        finally:
            os.unlink(tmppath)

    def test_empty_string_rejected(self):
        obj = PamScriptObject()
        obj.file = ""
        self.assertFalse(obj.validate())

    def test_nonexistent_file_rejected(self):
        obj = PamScriptObject()
        obj.file = "/nonexistent/path/script.sh"
        self.assertFalse(obj.validate())

    def test_attachment_dotdot_rejected(self):
        obj = PamAttachmentObject()
        obj.file = "../../../etc/shadow"
        self.assertFalse(obj.validate())

    def test_attachment_normal_path_accepted(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmppath = f.name
            f.write(b"test content")
        try:
            obj = PamAttachmentObject()
            obj.file = tmppath
            self.assertTrue(obj.validate())
        finally:
            os.unlink(tmppath)


if __name__ == '__main__':
    unittest.main()
