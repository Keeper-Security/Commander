"""P2.5 smoke tests: checkpoint + resume wiring for the remaining four
loop stages (users, records-attachments-upload, take-ownership,
transfer-user). Confirms the wiring calls checkpoint methods and clears
on success. Deep crash/resume/mismatch coverage lives in
test_checkpoint.py and test_shares.py / test_sf_reconcile.py — the
protocol itself is not re-tested here.
"""

import csv
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.checkpoint import Checkpoint


class TestUsersCheckpointWiring(unittest.TestCase):
    def test_successful_run_clears_checkpoint(self):
        from keepercommander.commands.keeper_tenant_migrate.users import FakeUserClient, UserRunner
        client = FakeUserClient()
        with tempfile.TemporaryDirectory() as run_dir:
            ck = Checkpoint('users', run_dir)
            runner = UserRunner(
                client, source_root='My company', target_root='Root',
                delay=0, batch_size=0, sleeper=lambda _s: None,
                checkpoint=ck,
            )
            roster = [{'email': 'a@x', 'full_name': 'A'},
                      {'email': 'b@x', 'full_name': 'B'}]
            results = runner.run(roster)
            self.assertEqual(len(results), 2)
            # Successful completion → checkpoint cleared.
            self.assertIsNone(ck.load())


class TestAttachmentsUploadCheckpointWiring(unittest.TestCase):
    def test_successful_run_clears_checkpoint(self):
        from keepercommander.commands.keeper_tenant_migrate.attachments import (
            AttachmentUploader, FakeAttachmentClient,
        )
        with tempfile.TemporaryDirectory() as staging:
            # Build an empty staging dir — uploader returns SKIP, that's fine
            # for verifying the checkpoint lifecycle (mark_done → clear).
            ck = Checkpoint('records-attachments-upload', staging)
            up = AttachmentUploader(
                FakeAttachmentClient(), staging, delay=0, batch_size=0,
                sleeper=lambda _s: None, checkpoint=ck,
            )
            pairs = [{'source_uid': 's1', 'target_uid': 't1'},
                     {'source_uid': 's2', 'target_uid': 't2'}]
            summary = up.run(pairs)
            self.assertEqual(summary['total'], 2)
            self.assertIsNone(ck.load())
            # resumed is present in the summary shape
            self.assertEqual(summary['resumed'], 0)


class TestTakeOwnershipCheckpointWiring(unittest.TestCase):
    def test_successful_run_clears_checkpoint(self):
        from keepercommander.commands.keeper_tenant_migrate.take_ownership import (
            FakeOwnershipClient, process_users,
        )
        with tempfile.TemporaryDirectory() as d:
            ck = Checkpoint('take-ownership', d)
            users = [
                {'email': 'alice@x', 'full_name': 'Alice',
                 'folder': '/MIGRATION-Alice', 'record_count': '5'},
                {'email': 'bob@x', 'full_name': 'Bob',
                 'folder': '/MIGRATION-Bob', 'record_count': '3'},
            ]
            summary = process_users(
                users, FakeOwnershipClient(),
                admin_email='admin@x', backup_dir=d,
                report_path=os.path.join(d, 'report.csv'),
                sleep_seconds=0, sleeper=lambda _s: None,
                checkpoint=ck,
            )
            self.assertEqual(summary['total'], 2)
            self.assertEqual(summary['backups'], 2)
            self.assertEqual(summary['ownerships'], 2)
            self.assertIsNone(ck.load())

    def test_resume_appends_to_existing_report(self):
        from keepercommander.commands.keeper_tenant_migrate.take_ownership import (
            FakeOwnershipClient, process_users,
        )
        from keepercommander.commands.keeper_tenant_migrate.checkpoint import hash_rows
        with tempfile.TemporaryDirectory() as d:
            report = os.path.join(d, 'report.csv')
            # Pre-seed a partial report + checkpoint (as if prior run made it
            # through user 1 of 2).
            users = [
                {'email': 'alice@x', 'full_name': 'Alice',
                 'folder': '/MIGRATION-Alice', 'record_count': '5'},
                {'email': 'bob@x', 'full_name': 'Bob',
                 'folder': '/MIGRATION-Bob', 'record_count': '3'},
            ]
            keyed = [(u['email'], u['folder']) for u in users]
            with open(report, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(['email', 'full_name', 'folder', 'backup_created',
                            'ownership_taken', 'record_count', 'status',
                            'notes'])
                w.writerow(['alice@x', 'Alice', '/MIGRATION-Alice',
                            'YES', 'YES', '5', 'SUCCESS', 'prior run'])
            ck = Checkpoint('take-ownership', d)
            ck.mark_done(1, input_sha256=hash_rows(keyed))

            # Resume from checkpoint: only Bob should be processed this run.
            summary = process_users(
                users, FakeOwnershipClient(),
                admin_email='admin@x', backup_dir=d,
                report_path=report,
                sleep_seconds=0, sleeper=lambda _s: None,
                checkpoint=ck, resume=True,
            )
            # Total counts both rows (parity); only Bob actually processed.
            self.assertEqual(summary['total'], 2)
            self.assertEqual(summary['backups'], 1)
            self.assertEqual(summary['ownerships'], 1)
            # Report now has header + Alice (prior) + Bob (this run).
            with open(report) as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 3)
            self.assertIn('bob@x', lines[-1])


class TestTransferUserCheckpointWiring(unittest.TestCase):
    def test_successful_run_clears_checkpoint(self):
        from keepercommander.commands.keeper_tenant_migrate.transfer_user import (
            FakeTransferUserClient, process_users,
        )
        with tempfile.TemporaryDirectory() as d:
            ck = Checkpoint('transfer-user', d)
            users = [
                {'email': 'alice@x', 'name': 'Alice',
                 'transfer_status': 'READY_TRANSFER'},
                {'email': 'bob@x', 'name': 'Bob',
                 'transfer_status': 'READY_TRANSFER'},
            ]
            summary = process_users(
                users, FakeTransferUserClient(),
                admin_email='admin@x',
                report_path=os.path.join(d, 'report.csv'),
                sleep_seconds=0, sleeper=lambda _s: None,
                checkpoint=ck,
            )
            self.assertEqual(summary['total'], 2)
            self.assertEqual(summary['transferred'], 2)
            self.assertIsNone(ck.load())


if __name__ == '__main__':
    unittest.main()
