import csv
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.take_ownership_restore import (
    FakeRestoreClient,
    load_ownership_report,
    restore,
)


def _write_report(path, rows):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=[
            'email', 'full_name', 'folder', 'backup_created',
            'ownership_taken', 'record_count', 'status', 'notes',
        ])
        w.writeheader()
        for row in rows:
            w.writerow(row)


class LoadOwnershipReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'report.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_only_yes_rows_yielded(self):
        _write_report(self.path, [
            {'email': 'a@x', 'folder': 'MIGRATION-A',
             'ownership_taken': 'YES', 'backup_created': 'YES',
             'full_name': 'Alice', 'record_count': '1',
             'status': 'SUCCESS', 'notes': ''},
            {'email': 'b@x', 'folder': 'MIGRATION-B',
             'ownership_taken': 'NO',  'backup_created': 'NO',
             'full_name': 'Bob', 'record_count': '0',
             'status': 'FAILED', 'notes': 'backup failed'},
        ])
        rows = list(load_ownership_report(self.path))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['email'], 'a@x')


class RestoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.report = os.path.join(self.tmp, 'report.csv')
        _write_report(self.report, [
            {'email': 'a@x', 'folder': 'MIGRATION-A',
             'ownership_taken': 'YES', 'backup_created': 'YES',
             'full_name': 'A', 'record_count': '1',
             'status': 'SUCCESS', 'notes': ''},
            {'email': 'b@x', 'folder': 'MIGRATION-B',
             'ownership_taken': 'YES', 'backup_created': 'YES',
             'full_name': 'B', 'record_count': '2',
             'status': 'SUCCESS', 'notes': ''},
        ])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_happy_path(self):
        client = FakeRestoreClient()
        result = restore(client, self.report)
        self.assertEqual(result['total'], 2)
        self.assertEqual(result['restored'], 2)
        self.assertEqual(result['failed'], 0)
        folders = [c[1] for c in client.calls]
        self.assertEqual(sorted(folders), ['MIGRATION-A', 'MIGRATION-B'])

    def test_dry_run_lists_without_calling_client(self):
        client = FakeRestoreClient()
        result = restore(client, self.report, dry_run=True)
        self.assertTrue(result['dry_run'])
        self.assertEqual(result['total'], 2)
        self.assertEqual(client.calls, [])

    def test_failure_reported(self):
        client = FakeRestoreClient(fail_for={'MIGRATION-B'})
        result = restore(client, self.report)
        self.assertEqual(result['restored'], 1)
        self.assertEqual(result['failed'], 1)

    def test_backup_integrity_check_blocks_on_missing_manifest(self):
        """When --verify-backup-dir is given but the dir has no
        SHA256SUMS.txt, restore refuses."""
        missing_dir = os.path.join(self.tmp, 'no-manifest')
        os.makedirs(missing_dir)
        client = FakeRestoreClient()
        result = restore(client, self.report, verify_backup_dir=missing_dir)
        self.assertTrue(result['blocked'])
        self.assertEqual(result['reason'], 'no_backup_manifest')
        self.assertEqual(client.calls, [])

    def test_backup_integrity_check_blocks_on_mismatch(self):
        """Tampered backup dir → restore refuses."""
        from keepercommander.commands.keeper_tenant_migrate.audit import write_sha256sums
        backup_dir = os.path.join(self.tmp, 'backup')
        os.makedirs(backup_dir)
        with open(os.path.join(backup_dir, 'a.json'), 'w') as f:
            f.write('{}')
        write_sha256sums(backup_dir)
        # Tamper with the file after the manifest was written.
        with open(os.path.join(backup_dir, 'a.json'), 'w') as f:
            f.write('{"tampered": true}')
        client = FakeRestoreClient()
        result = restore(client, self.report, verify_backup_dir=backup_dir)
        self.assertTrue(result['blocked'])
        self.assertEqual(result['reason'], 'backup_integrity')


class LoadOwnershipReportSkipTests(unittest.TestCase):
    """Cover the empty-email and empty-folder skip path (line 50)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'report.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_yes_row_with_blank_email_is_skipped(self):
        _write_report(self.path, [
            {'email': '', 'folder': 'MIGRATION-A',
             'ownership_taken': 'YES', 'backup_created': 'YES',
             'full_name': '', 'record_count': '0',
             'status': 'SUCCESS', 'notes': ''},
            {'email': 'a@x', 'folder': '',
             'ownership_taken': 'YES', 'backup_created': 'YES',
             'full_name': 'A', 'record_count': '0',
             'status': 'SUCCESS', 'notes': ''},
        ])
        rows = list(load_ownership_report(self.path))
        self.assertEqual(rows, [])


class AuditChainBrokenTests(unittest.TestCase):
    """Cover the audit-log chain verification path (lines 77-85)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.report = os.path.join(self.tmp, 'report.csv')
        _write_report(self.report, [
            {'email': 'a@x', 'folder': 'MIGRATION-A',
             'ownership_taken': 'YES', 'backup_created': 'YES',
             'full_name': 'A', 'record_count': '1',
             'status': 'SUCCESS', 'notes': ''},
        ])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_audit_chain_broken_blocks_restore(self):
        """A backup dir with valid SHA256SUMS but a broken audit chain
        must refuse the restore."""
        from keepercommander.commands.keeper_tenant_migrate.audit import write_sha256sums

        backup_dir = os.path.join(self.tmp, 'backup')
        os.makedirs(backup_dir)
        with open(os.path.join(backup_dir, 'a.json'), 'w') as f:
            f.write('{}')
        write_sha256sums(backup_dir)
        # Write a malformed audit.log — chain verifier expects line-N's
        # prev_hash to equal the SHA256 of line-(N-1). A garbage second
        # entry breaks the chain.
        with open(os.path.join(backup_dir, 'audit.log'), 'w') as f:
            f.write('{"seq": 1, "prev_hash": "0000", "ts": "2026-01-01"}\n')
            f.write('{"seq": 2, "prev_hash": "wrong", "ts": "2026-01-02"}\n')

        client = FakeRestoreClient()
        result = restore(client, self.report, verify_backup_dir=backup_dir)
        self.assertTrue(result['blocked'])
        self.assertEqual(result['reason'], 'audit_chain_broken')
        self.assertIn('broken_line', result)
        self.assertEqual(client.calls, [])

    def test_audit_chain_intact_proceeds_to_restore(self):
        """When audit.log exists AND chain verifies, restore proceeds."""
        from keepercommander.commands.keeper_tenant_migrate.audit import (
            append_audit_event,
            write_sha256sums,
        )

        backup_dir = os.path.join(self.tmp, 'backup')
        os.makedirs(backup_dir)
        with open(os.path.join(backup_dir, 'a.json'), 'w') as f:
            f.write('{}')
        # Append two well-formed entries (proper chain).
        log_path = os.path.join(backup_dir, 'audit.log')
        append_audit_event(log_path, {'event': 'create', 'email': 'a@x'})
        append_audit_event(log_path, {'event': 'transfer', 'email': 'a@x'})
        # SHA256SUMS must include the audit.log we just wrote.
        write_sha256sums(backup_dir)
        client = FakeRestoreClient()
        result = restore(client, self.report, verify_backup_dir=backup_dir)
        # Chain ok → not blocked → proceeds to grant ownership
        self.assertNotIn('blocked', result)
        self.assertEqual(result['restored'], 1)


if __name__ == '__main__':
    unittest.main()
