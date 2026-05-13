import csv
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.take_ownership import (
    FakeOwnershipClient,
    _sanitize_for_filename,
    load_ready_users,
    process_users,
)


class SanitizeFilenameTests(unittest.TestCase):
    def test_non_alphanumeric_becomes_underscore_plus_hash_suffix(self):
        # Prefix: non-alnum → '_', Unicode letters preserved (isalnum True).
        # Suffix: 8 hex chars of sha256(email) for collision resistance.
        result = _sanitize_for_filename('alice+demo@x.com')
        self.assertTrue(result.startswith('alice_demo_x_com_'))
        self.assertEqual(len(result), len('alice_demo_x_com') + 1 + 8)


class LoadReadyUsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_filters_by_ready_status(self):
        path = os.path.join(self.tmp, 'ver.csv')
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['email', 'full_name', 'expected_folder',
                        'record_count', 'status'])
            w.writerow(['a@x', 'Alice', 'MIGRATION-A', '5', 'READY'])
            w.writerow(['b@x', 'Bob', 'MIGRATION-B', '3', 'NOT_READY'])
            w.writerow(['c@x', 'Cat', 'MIGRATION-C', '2', 'READY'])
            w.writerow(['d@x', 'Dave', '', '0', 'READY'])  # no folder, skip
        users = list(load_ready_users(path))
        emails = [u['email'] for u in users]
        self.assertEqual(emails, ['a@x', 'c@x'])


class ProcessUsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.backup_dir = os.path.join(self.tmp, 'backups')
        self.report_path = os.path.join(self.tmp, 'report.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _users(self):
        return [
            {'email': 'alice@x', 'full_name': 'Alice',
             'folder': 'MIGRATION-ALICE', 'record_count': '5'},
            {'email': 'bob@x', 'full_name': 'Bob',
             'folder': 'MIGRATION-BOB', 'record_count': '3'},
        ]

    def test_both_succeed(self):
        client = FakeOwnershipClient()
        summary = process_users(self._users(), client, 'admin@x',
                                self.backup_dir, self.report_path,
                                sleep_seconds=0, timestamp='ts')
        self.assertEqual(summary['total'], 2)
        self.assertEqual(summary['backups'], 2)
        self.assertEqual(summary['ownerships'], 2)
        self.assertEqual(summary['errors'], 0)
        # Backup files written — filenames carry an 8-char hash suffix so
        # Unicode emails that sanitize to same prefix don't collide.
        files = sorted(os.listdir(self.backup_dir))
        self.assertEqual(len(files), 2)
        self.assertTrue(any(f.startswith('alice_x_') for f in files))
        self.assertTrue(any(f.startswith('bob_x_') for f in files))
        # Report rows
        with open(self.report_path, newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row['status'], 'SUCCESS')
            self.assertEqual(row['backup_created'], 'YES')
            self.assertEqual(row['ownership_taken'], 'YES')

    def test_backup_failure_skips_ownership(self):
        client = FakeOwnershipClient(export_fail_for={'MIGRATION-ALICE'})
        summary = process_users(self._users(), client, 'admin@x',
                                self.backup_dir, self.report_path,
                                sleep_seconds=0, timestamp='ts')
        self.assertEqual(summary['backups'], 1)
        self.assertEqual(summary['ownerships'], 1)
        self.assertEqual(summary['errors'], 1)
        # Alice's ownership op never called
        ownership_calls = [c for c in client.calls if c[0] == 'ownership']
        self.assertEqual(len(ownership_calls), 1)
        self.assertEqual(ownership_calls[0][1], 'MIGRATION-BOB')

    def test_ownership_failure_still_keeps_backup(self):
        client = FakeOwnershipClient(ownership_fail_for={'MIGRATION-BOB'})
        summary = process_users(self._users(), client, 'admin@x',
                                self.backup_dir, self.report_path,
                                sleep_seconds=0, timestamp='ts')
        self.assertEqual(summary['backups'], 2)
        self.assertEqual(summary['ownerships'], 1)  # only Alice
        self.assertEqual(summary['errors'], 1)
        # Bob's backup file exists even though ownership failed
        files = os.listdir(self.backup_dir)
        self.assertTrue(any(f.startswith('bob_x_') for f in files))

    def test_dry_run_suppresses_report_csv(self):
        """Regression: dry-run must NOT leave a SUCCESS report on disk.
        Real callers wrap the live client in DryRun — do the same here."""
        from keepercommander.commands.keeper_tenant_migrate.dry_run import DryRun
        client = DryRun(FakeOwnershipClient())
        summary = process_users(self._users(), client, 'admin@x',
                                self.backup_dir, self.report_path,
                                sleep_seconds=0, timestamp='ts',
                                dry_run=True)
        self.assertTrue(summary.get('dry_run'))
        self.assertFalse(os.path.exists(self.report_path))
        # Backup dir NOT created (we don't want a 0-byte dir on disk)
        self.assertFalse(os.path.isdir(self.backup_dir))
        # DryRun recorded the planned ops for caller to classify_plan()
        ops = [c[0] for c in client.calls]
        self.assertIn('export_folder_json', ops)
        self.assertIn('take_folder_ownership', ops)

    def test_sleep_called_between_rows(self):
        client = FakeOwnershipClient()
        sleep_calls = []
        process_users(self._users(), client, 'admin@x',
                      self.backup_dir, self.report_path,
                      sleep_seconds=0.5,
                      sleeper=sleep_calls.append,
                      timestamp='ts')
        # One sleep per user
        self.assertEqual(sleep_calls, [0.5, 0.5])


if __name__ == '__main__':
    unittest.main()
