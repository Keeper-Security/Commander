import os
import platform
import stat
import subprocess
import tempfile
from unittest import TestCase

from keepercommander.keeper_dag.connection.local import Connection as LocalConnection


class TestLocalDagPermissions(TestCase):
    def test_create_database_sets_owner_only_access(self):
        """Local DAG SQLite db must be locked to owner-only access.

        POSIX: verifies mode == 0o600 via os.stat.
        Windows: verifies the icacls-applied ACL has the principals stripped
        by `set_file_permissions` (NT AUTHORITY\\SYSTEM, BUILTIN\\Administrators)
        — Python's os.stat().st_mode reads DOS attributes, not the NTFS DACL.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            LocalConnection(db_file='test_dag.db', db_dir=tmp_dir)
            db_path = os.path.join(tmp_dir, 'test_dag.db')
            self.assertTrue(os.path.isfile(db_path))

            if platform.system() == 'Windows':
                acl_dump = subprocess.run(
                    ['icacls', db_path],
                    capture_output=True, text=True, check=True,
                ).stdout
                self.assertNotIn(
                    'NT AUTHORITY\\SYSTEM', acl_dump,
                    f'SYSTEM should have been removed but is still in the ACL:\n{acl_dump}',
                )
                self.assertNotIn(
                    'BUILTIN\\Administrators', acl_dump,
                    f'Administrators should have been removed but is still in the ACL:\n{acl_dump}',
                )
            else:
                mode = stat.S_IMODE(os.stat(db_path).st_mode)
                self.assertEqual(mode, 0o600,
                                 f'Expected 0o600 on freshly created local DAG db, got {oct(mode)}')
