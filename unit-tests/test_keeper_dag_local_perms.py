import os
import platform
import stat
import tempfile
from unittest import TestCase, skipIf

from keepercommander.keeper_dag.connection.local import Connection as LocalConnection


@skipIf(platform.system() == 'Windows',
        'POSIX mode bits are not meaningful on Windows; the secure-perms helper uses icacls there')
class TestLocalDagPermissions(TestCase):
    def test_create_database_sets_mode_600(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            LocalConnection(db_file='test_dag.db', db_dir=tmp_dir)
            db_path = os.path.join(tmp_dir, 'test_dag.db')
            self.assertTrue(os.path.isfile(db_path))
            mode = stat.S_IMODE(os.stat(db_path).st_mode)
            self.assertEqual(mode, 0o600,
                             f'Expected 0o600 on freshly created local DAG db, got {oct(mode)}')
