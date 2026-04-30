"""Test that pam project import rejects duplicate UIDs."""
import logging
import sys
import unittest

if sys.version_info >= (3, 8):
    from keepercommander.commands.pam_import.edit import PAMProjectImportCommand

    def _minimal_project(resources, users=None):
        """Build a minimal project dict matching the structure process_data expects."""
        return {
            "data": {
                "pam_data": {
                    "resources": resources,
                    "users": users or [],
                    "rotation_profiles": {},
                }
            },
            "pam_config": {"pam_config_uid": "test-config-uid"},
            "folders": {
                "resources_folder_uid": "sfr-test",
                "users_folder_uid": "sfu-test",
            },
        }

    class TestPAMImportDuplicateUid(unittest.TestCase):
        """process_data must abort when the import JSON contains duplicate uid values."""

        def test_duplicate_uid_logs_error_and_returns(self):
            """process_data aborts with logging.error when two resources share a uid."""
            from unittest.mock import MagicMock
            project = _minimal_project([
                {'type': 'pamMachine', 'title': 'Machine A', 'uid': 'duplicate-uid-1'},
                {'type': 'pamMachine', 'title': 'Machine B', 'uid': 'duplicate-uid-1'},
            ])
            cmd = PAMProjectImportCommand()
            params = MagicMock()
            params.record_cache = {}
            params.shared_folder_cache = {}
            params.folder_cache = {}

            # assertLogs with no logger name captures from root logger (where logging.error writes)
            with self.assertLogs(level='ERROR') as log_ctx:
                try:
                    cmd.process_data(params, project)
                except Exception:
                    pass  # early return path may surface as exception in some code paths

            self.assertTrue(
                any('duplicate uid' in msg.lower() or 'duplicate-uid-1' in msg
                    for msg in log_ctx.output),
                f'Expected duplicate UID error in logs, got: {log_ctx.output}'
            )

        def test_unique_uids_pass_dedup_check(self):
            """process_data does NOT emit a duplicate-uid error when all UIDs are unique."""
            from unittest.mock import MagicMock
            import io

            project = _minimal_project([
                {'type': 'pamMachine', 'title': 'Machine A', 'uid': 'uid-alpha'},
                {'type': 'pamMachine', 'title': 'Machine B', 'uid': 'uid-beta'},
            ])
            cmd = PAMProjectImportCommand()
            params = MagicMock()
            params.record_cache = {}
            params.shared_folder_cache = {}
            params.folder_cache = {}

            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setLevel(logging.ERROR)
            root_logger = logging.getLogger()
            root_logger.addHandler(handler)
            try:
                try:
                    cmd.process_data(params, project)
                except Exception:
                    pass
                output = stream.getvalue()
                self.assertNotIn('duplicate uid', output.lower(),
                                 f'Unexpected duplicate UID error for unique UIDs: {output}')
            finally:
                root_logger.removeHandler(handler)


if __name__ == '__main__':
    unittest.main()
