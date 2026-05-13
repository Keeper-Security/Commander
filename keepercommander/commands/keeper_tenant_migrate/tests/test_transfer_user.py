import csv
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.transfer_user import (
    FakeTransferUserClient,
    load_ready_transfer_users,
    process_users,
)


class LoadReadyTransferUsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_filters_by_migration_path_token(self):
        path = os.path.join(self.tmp, 'readiness.csv')
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['email', 'name', 'status', 'transfer_status',
                        'has_folder', 'migration_path', 'action_needed'])
            w.writerow(['a@x', 'Alice', 'A', 'accepted', 'no',
                        'READY_TRANSFER', 'run transfer'])
            w.writerow(['b@x', 'Bob', 'A', '', 'yes',
                        'READY_FOLDER', 'path A'])
            w.writerow(['c@x', 'Cat', 'A', 'accepted', 'yes',
                        'READY_FOLDER + READY_TRANSFER', 'hybrid'])
            w.writerow(['d@x', 'Dave', 'A', '', '', 'NOT_READY', ''])
        users = list(load_ready_transfer_users(path))
        emails = [u['email'] for u in users]
        # a@x and c@x match; b@x and d@x don't
        self.assertEqual(emails, ['a@x', 'c@x'])

    def test_header_case_insensitive_token_match(self):
        path = os.path.join(self.tmp, 'readiness.csv')
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['email', 'name', 'migration_path'])
            w.writerow(['a@x', 'Alice', 'ready_transfer'])  # lowercase — still matches
        users = list(load_ready_transfer_users(path))
        self.assertEqual([u['email'] for u in users], ['a@x'])


class ProcessUsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.report_path = os.path.join(self.tmp, 'report.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _users(self):
        return [
            {'email': 'alice@x', 'name': 'Alice', 'transfer_status': 'accepted'},
            {'email': 'bob@x', 'name': 'Bob', 'transfer_status': 'accepted'},
        ]

    def test_happy_path_transfers_all(self):
        client = FakeTransferUserClient()
        summary = process_users(self._users(), client, 'admin@x',
                                self.report_path, sleep_seconds=0)
        self.assertEqual(summary['total'], 2)
        self.assertEqual(summary['transferred'], 2)
        self.assertEqual(summary['skipped'], 0)
        self.assertEqual(summary['errors'], 0)
        # Post-transfer sync-down called per user
        sync_calls = [c for c in client.calls if c[0] == 'sync_down']
        self.assertEqual(len(sync_calls), 2)

    def test_admin_self_transfer_is_skipped(self):
        users = self._users() + [
            {'email': 'admin@x', 'name': 'Admin', 'transfer_status': ''},
        ]
        client = FakeTransferUserClient()
        summary = process_users(users, client, 'admin@x',
                                self.report_path, sleep_seconds=0)
        self.assertEqual(summary['skipped'], 1)
        # Only alice + bob got transferred — admin bypass preserved
        transfer_calls = [c for c in client.calls if c[0] == 'transfer']
        self.assertEqual(len(transfer_calls), 2)

    def test_self_match_is_case_insensitive(self):
        users = [{'email': 'Admin@X', 'name': 'Admin', 'transfer_status': ''}]
        client = FakeTransferUserClient()
        summary = process_users(users, client, 'admin@x',
                                self.report_path, sleep_seconds=0)
        self.assertEqual(summary['skipped'], 1)

    def test_transfer_failure_reported(self):
        client = FakeTransferUserClient(fail_for={'bob@x'})
        summary = process_users(self._users(), client, 'admin@x',
                                self.report_path, sleep_seconds=0)
        self.assertEqual(summary['transferred'], 1)
        self.assertEqual(summary['errors'], 1)
        # No sync-down for the failed transfer (we only sync after success)
        sync_calls = [c for c in client.calls if c[0] == 'sync_down']
        self.assertEqual(len(sync_calls), 1)

    def test_dry_run_suppresses_report_csv(self):
        """Compliance: dry-run must NOT produce a 'SUCCESS' transfer log."""
        client = FakeTransferUserClient()
        summary = process_users(self._users(), client, 'admin@x',
                                self.report_path, sleep_seconds=0,
                                dry_run=True)
        self.assertTrue(summary.get('dry_run'))
        self.assertFalse(os.path.exists(self.report_path))

    def test_sleeper_called_between_successful_transfers(self):
        client = FakeTransferUserClient()
        sleep_calls = []
        process_users(self._users(), client, 'admin@x',
                      self.report_path, sleep_seconds=2.0,
                      sleeper=sleep_calls.append)
        self.assertEqual(sleep_calls, [2.0, 2.0])

    def test_high7_transient_exception_recorded_and_loop_continues(self):
        """HIGH-7 regression — pre-fix client.transfer_user_vault was
        called bare. transient errors propagated up out of the loop,
        aborting before the row's checkpoint mark_done ran. On --resume
        the row looked untouched even though transfer-user is non-
        idempotent and the source user may have been partially auto-
        locked.

        Post-fix: the call is wrapped in try/except. Exceptions tally
        as errors, the row is written with a clear FAILED + manual-
        review-required note, and the loop continues to the next user.
        """

        class FlakyTransferClient:
            def __init__(self):
                self.calls = []

            def transfer_user_vault(self, email, admin_email):
                self.calls.append(('transfer_user_vault', email, admin_email))
                if email == 'bob@x':
                    raise RuntimeError('simulated transient: HTTP 429')
                return True

            def sync_down(self):
                self.calls.append(('sync_down',))

        client = FlakyTransferClient()
        users = [
            {'email': 'alice@x', 'name': 'Alice',
             'transfer_status': 'pending'},
            {'email': 'bob@x', 'name': 'Bob',
             'transfer_status': 'pending'},
            {'email': 'carol@x', 'name': 'Carol',
             'transfer_status': 'pending'},
        ]
        # Loop must NOT abort on bob@x — carol@x must still be processed.
        summary = process_users(users, client, 'admin@x',
                                self.report_path, sleep_seconds=0)
        self.assertEqual(summary['transferred'], 2,
                         'expected alice + carol to transfer; got '
                         f'{summary["transferred"]}')
        self.assertEqual(summary['errors'], 1)

        # Report CSV must include bob@x with FAILED + manual-review notes.
        with open(self.report_path) as f:
            import csv as _csv
            lines = list(_csv.reader(f))
        rows_by_email = {r[0]: r for r in lines[1:]}
        self.assertEqual(rows_by_email['bob@x'][4], 'FAILED')
        notes = rows_by_email['bob@x'][5].lower()
        self.assertIn('non-idempotent', notes)
        self.assertIn('manual review', notes)


if __name__ == '__main__':
    unittest.main()
