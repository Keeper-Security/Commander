import csv
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.decommission import (
    FakeDecommissionClient,
    load_user_emails,
    process_users,
)


class LoadUserEmailsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'roster.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_reads_email_column(self):
        with open(self.path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['email', 'full_name'])
            w.writerow(['alice@x', 'Alice'])
            w.writerow(['', 'Nobody'])
            w.writerow(['bob@x', 'Bob'])
        self.assertEqual(list(load_user_emails(self.path)), ['alice@x', 'bob@x'])


class ProcessUsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.report_path = os.path.join(self.tmp, 'report.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_all_succeed(self):
        client = FakeDecommissionClient()
        summary = process_users(['a@x', 'b@x'], client, self.report_path,
                                sleep_seconds=0)
        self.assertEqual(summary['total'], 2)
        self.assertEqual(summary['locked'], 2)
        self.assertEqual(summary['deleted'], 2)
        self.assertEqual(summary['errors'], 0)

    def test_lock_failure_does_not_block_delete(self):
        """Bash script uses || true on lock; delete still attempted."""
        client = FakeDecommissionClient(lock_fail={'a@x'})
        summary = process_users(['a@x'], client, self.report_path,
                                sleep_seconds=0)
        self.assertEqual(summary['locked'], 0)
        self.assertEqual(summary['deleted'], 1)
        self.assertEqual(summary['errors'], 0)

    def test_delete_failure_reported(self):
        client = FakeDecommissionClient(delete_fail={'a@x'})
        summary = process_users(['a@x'], client, self.report_path,
                                sleep_seconds=0)
        self.assertEqual(summary['errors'], 1)
        self.assertEqual(summary['deleted'], 0)

    def test_dry_run_suppresses_report_csv(self):
        """Regression: decommission must NOT produce a report showing
        deletions that didn't happen — compliance foot-gun.

        HIGH-8 contract change 2026-05-08: pre-fix, the dry_run path
        DID invoke client.lock_user / client.delete_user (relying on
        the caller wrapping the client in DryRun to stub them). The
        invariant was load-bearing only because the caller wrapped
        correctly. Post-fix, dry_run does NOT invoke client methods
        regardless of wrapper — the function honors its own dry_run
        contract locally. Test updated to reflect the new contract.
        """
        client = FakeDecommissionClient()
        summary = process_users(['a@x', 'b@x'], client, self.report_path,
                                sleep_seconds=0, dry_run=True)
        self.assertTrue(summary.get('dry_run'))
        self.assertFalse(os.path.exists(self.report_path))
        # HIGH-8: dry_run no longer invokes destructive client methods.
        # If the caller needs a "what would be done" preview that
        # exercises the client, that's a separate concern (planner
        # subcommand), not a side-effect of dry_run on this function.
        self.assertEqual(client.calls, [],
                         f'dry_run=True invoked client methods: '
                         f'{client.calls} — HIGH-8 regression')

    def test_sleeper_called_between_users(self):
        client = FakeDecommissionClient()
        sleeps = []
        process_users(['a@x', 'b@x'], client, self.report_path,
                      sleep_seconds=0.5, sleeper=sleeps.append)
        self.assertEqual(sleeps, [0.5, 0.5])

    def test_silent_delete_failure_is_counted_as_error(self):
        """Regression guard for the decommission hardening 2026-04-19:
        Commander's enterprise-user --delete silently warns (doesn't
        raise) when the user has owned records / queued teams. The
        plugin used to count that as success. Verify-after-delete
        via client.is_user_present() catches it.
        """
        # seeded → user shows as present before ops
        client = FakeDecommissionClient(
            silent_delete_fail={'stubborn@x'},
        ).seed(['stubborn@x', 'clean@x'])
        summary = process_users(
            ['stubborn@x', 'clean@x'], client, self.report_path,
            sleep_seconds=0,
        )
        # clean@x: real delete removed it, deleted counter +1.
        # stubborn@x: silent no-op — delete returned True but user
        # still present, must count as error, NOT as deleted.
        self.assertEqual(summary['deleted'], 1)
        self.assertEqual(summary['errors'], 1)

        # The report must correctly show deleted=NO for the silent
        # failure (compliance foot-gun if it said YES).
        with open(self.report_path) as f:
            lines = list(csv.reader(f))
        # Header + 2 rows
        rows_by_email = {row[0]: row for row in lines[1:]}
        self.assertEqual(rows_by_email['clean@x'][2], 'YES')
        self.assertEqual(rows_by_email['stubborn@x'][2], 'NO')
        self.assertIn('silent', rows_by_email['stubborn@x'][4].lower())

    def test_is_user_present_error_does_not_crash_loop(self):
        """If the client's is_user_present raises (e.g., network
        blip mid-loop), processing continues — we log and skip
        verify, not crash the whole decommission."""

        class FlakyClient(FakeDecommissionClient):
            def is_user_present(self, email):
                raise RuntimeError('simulated query flap')

        client = FlakyClient().seed([])
        summary = process_users(['a@x', 'b@x'], client, self.report_path,
                                sleep_seconds=0)
        # Delete returned True; is_user_present raised → verify
        # skipped with a warning; delete is trusted.
        self.assertEqual(summary['deleted'], 2)
        self.assertEqual(summary['errors'], 0)

    def test_high3_subclass_without_is_user_present_override_fails_loud(self):
        """HIGH-3 regression — pre-fix the base DecommissionClient
        class returned False from is_user_present, so any subclass
        that forgot the override silently lost the verify-after-delete
        guarantee. Every delete reported SUCCESS regardless of post-
        delete state. Post-fix the base raises NotImplementedError;
        the decommission loop catches NotImplementedError separately
        from generic Exception and reports the row as FAILED with a
        clear 'verify-after-delete not implemented' message.
        """
        from keepercommander.commands.keeper_tenant_migrate.decommission import DecommissionClient

        class BadSubclass(DecommissionClient):
            # Forgets to override is_user_present.
            # Doesn't set trust_no_verify=True.
            def lock_user(self, email):
                return True

            def delete_user(self, email):
                return True

        client = BadSubclass()
        summary = process_users(['a@x'], client, self.report_path,
                                sleep_seconds=0)
        # Delete returned True, but verify wasn't implemented and
        # client didn't opt out — must be FAILED, not SUCCESS.
        self.assertEqual(summary['errors'], 1)
        self.assertEqual(summary['deleted'], 0)

        with open(self.report_path) as f:
            lines = list(csv.reader(f))
        row = lines[1]
        self.assertEqual(row[0], 'a@x')
        self.assertEqual(row[2], 'NO',
                         'deleted column must be NO when verify is '
                         'not implemented (HIGH-3 invariant)')
        self.assertEqual(row[3], 'FAILED')
        notes = row[4].lower()
        self.assertIn('verify', notes)
        self.assertIn('not implemented', notes)

    def test_high8_dry_run_does_not_invoke_client_destructive_methods(self):
        """HIGH-8 regression — pre-fix the `if dry_run:` branch
        literally called client.lock_user + client.delete_user. The
        production CLI happened to wrap the client in DryRun so the
        calls were stubbed, but the docstring's invariant ('skip the
        CSV entirely. Compliance teams must NEVER see a decommission
        report showing deletions that didn't happen') was only
        load-bearing because the caller wrapped correctly. Any future
        caller that passes dry_run=True with an unwrapped client got
        real deletions.

        Post-fix: dry-run is a local invariant. The destructive
        methods are not called regardless of how the client is wrapped.
        """
        # Use a client that records every call. If process_users
        # in dry_run mode invokes lock_user / delete_user / etc., the
        # call list will be non-empty.
        from keepercommander.commands.keeper_tenant_migrate.decommission import DecommissionClient

        class RecordingClient(DecommissionClient):
            trust_no_verify = True   # avoid HIGH-3 raise

            def __init__(self):
                self.calls = []

            def lock_user(self, email):
                self.calls.append(('lock_user', email))
                return True

            def delete_user(self, email):
                self.calls.append(('delete_user', email))
                return True

        client = RecordingClient()
        summary = process_users(['a@x', 'b@x'], client, self.report_path,
                                sleep_seconds=0, dry_run=True)

        # Dry-run should have invoked NEITHER lock_user NOR delete_user.
        self.assertEqual(client.calls, [],
                         f'dry_run=True invoked client destructive methods: '
                         f'{client.calls} — HIGH-8 regression')
        self.assertTrue(summary.get('dry_run'))
        self.assertEqual(summary['total'], 2)

    def test_high3_explicit_trust_no_verify_opt_out_works(self):
        """HIGH-3 — subclasses that legitimately can't or don't want
        to implement is_user_present (e.g. some test fixtures, some
        external wrappers) can set `trust_no_verify = True` to opt
        out explicitly. The opt-out is visible in code review (unlike
        the silent return-False default it replaces) and produces a
        SUCCESS row that mentions the verify was skipped.
        """
        from keepercommander.commands.keeper_tenant_migrate.decommission import DecommissionClient

        class TrustingClient(DecommissionClient):
            trust_no_verify = True

            def lock_user(self, email):
                return True

            def delete_user(self, email):
                return True

        client = TrustingClient()
        summary = process_users(['a@x'], client, self.report_path,
                                sleep_seconds=0)
        # Delete returned True; verify skipped explicitly → SUCCESS.
        self.assertEqual(summary['deleted'], 1)
        self.assertEqual(summary['errors'], 0)

        with open(self.report_path) as f:
            lines = list(csv.reader(f))
        row = lines[1]
        self.assertEqual(row[3], 'SUCCESS')
        self.assertIn('verify skipped', row[4].lower())


if __name__ == '__main__':
    unittest.main()
