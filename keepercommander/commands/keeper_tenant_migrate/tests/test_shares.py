import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.checkpoint import Checkpoint
from keepercommander.commands.keeper_tenant_migrate.shares import (
    FakeShareClient,
    ShareApplier,
    ShareRestorer,
    extract_direct_shares,
    extract_shares,
    read_extract_manifest,
    write_extract_manifest,
)


class ExtractDirectSharesTests(unittest.TestCase):
    def test_skips_owner(self):
        rec = {'user_permissions': [
            {'username': 'owner@x', 'owner': True, 'editable': True},
            {'username': 'alice@x', 'owner': False, 'editable': True, 'shareable': False},
        ]}
        specs = extract_direct_shares(rec)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0]['username'], 'alice@x')
        self.assertTrue(specs[0]['editable'])
        self.assertFalse(specs[0]['shareable'])

    def test_empty_permissions_returns_empty(self):
        self.assertEqual(extract_direct_shares({}), [])
        self.assertEqual(extract_direct_shares({'user_permissions': []}), [])

    def test_share_admin_flag_preserved(self):
        rec = {'user_permissions': [
            {'username': 'admin@x', 'owner': False, 'share_admin': True},
        ]}
        specs = extract_direct_shares(rec)
        self.assertTrue(specs[0]['share_admin'])


class ShareRestorerTests(unittest.TestCase):
    def test_pass_when_all_shares_ok(self):
        records = {'s1': {'user_permissions': [
            {'username': 'a@x', 'owner': False, 'editable': True},
            {'username': 'b@x', 'owner': False},
        ]}}
        client = FakeShareClient(records=records)
        restorer = ShareRestorer(client)
        summary = restorer.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['pass'], 1)
        self.assertEqual(summary['per_record'][0]['applied'], 2)

    def test_skip_when_source_record_not_found(self):
        client = FakeShareClient(records={})
        restorer = ShareRestorer(client)
        summary = restorer.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['skip'], 1)

    def test_skip_when_record_has_only_owner(self):
        client = FakeShareClient(records={'s1': {
            'user_permissions': [{'username': 'owner@x', 'owner': True}],
        }})
        restorer = ShareRestorer(client)
        summary = restorer.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['skip'], 1)

    def test_pending_invitation_counts_as_applied(self):
        records = {'s1': {'user_permissions': [
            {'username': 'cross-tenant@y', 'owner': False, 'editable': False},
        ]}}
        client = FakeShareClient(records=records,
                                 share_behavior=lambda *_a: 'PENDING_INVITATION')
        restorer = ShareRestorer(client)
        summary = restorer.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['pass'], 1)
        self.assertEqual(summary['per_record'][0]['applied'], 1)

    def test_user_not_found_counts_failure_unless_skip_flag(self):
        records = {'s1': {'user_permissions': [
            {'username': 'missing@x', 'owner': False},
        ]}}
        # default: failure
        client = FakeShareClient(records=records,
                                 share_behavior=lambda *_a: 'USER_NOT_FOUND')
        restorer = ShareRestorer(client)
        summary = restorer.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['fail'], 1)
        self.assertIn('user not found', summary['per_record'][0]['errors'][0])

        # with skip_missing_users: skip silently, still PASS if nothing failed
        client = FakeShareClient(records=records,
                                 share_behavior=lambda *_a: 'USER_NOT_FOUND')
        restorer = ShareRestorer(client, skip_missing_users=True)
        summary = restorer.run([{'source_uid': 's1', 'target_uid': 't1'}])
        self.assertEqual(summary['pass'], 1)
        self.assertEqual(summary['per_record'][0]['failed'], 0)


class ShareRestorerResumeTests(unittest.TestCase):
    """End-to-end: crash mid-loop, checkpoint captures progress, rerun resumes."""

    def _make_client_with_5_records(self):
        return FakeShareClient(records={
            f's{i}': {'user_permissions': [
                {'username': f'u{i}@x', 'owner': False, 'editable': True},
            ]}
            for i in range(1, 6)
        })

    def _pairs(self):
        return [{'source_uid': f's{i}', 'target_uid': f't{i}'}
                for i in range(1, 6)]

    def test_crash_midway_then_resume_picks_up_at_next_pair(self):
        pairs = self._pairs()

        # A client that succeeds for pairs 1-3 then raises on pair 4.
        call_count = {'n': 0}

        def fail_after_3(target_uid, email):
            call_count['n'] += 1
            if call_count['n'] == 4:
                raise RuntimeError('simulated transient failure')
            return 'OK'

        client = FakeShareClient(
            records=self._make_client_with_5_records().records,
            share_behavior=fail_after_3,
        )
        with tempfile.TemporaryDirectory() as run_dir:
            ck = Checkpoint('records-shares', run_dir)

            restorer = ShareRestorer(client, checkpoint=ck, resume=False,
                                     sleeper=lambda _s: None)
            with self.assertRaises(RuntimeError):
                restorer.run(pairs)

            # Checkpoint captured the last successful pair (3).
            state = ck.load()
            self.assertEqual(state['last_index'], 3)
            self.assertEqual(state['stage'], 'records-shares')

            # Second run — identical inputs, second client handles all fine.
            # --resume must pick up at pair 4.
            client2 = FakeShareClient(
                records=self._make_client_with_5_records().records,
            )
            restorer2 = ShareRestorer(client2, checkpoint=ck, resume=True,
                                      sleeper=lambda _s: None)
            summary = restorer2.run(pairs)

            # 5 entries total: 3 resumed-over + 2 actually processed.
            self.assertEqual(summary['total'], 5)
            self.assertEqual(summary['resumed'], 3)
            self.assertEqual(summary['pass'], 2)  # pairs 4 + 5

            # Checkpoint cleared on stage completion.
            self.assertIsNone(ck.load())

    def test_resume_refused_when_manifest_changed(self):
        pairs = self._pairs()
        with tempfile.TemporaryDirectory() as run_dir:
            ck = Checkpoint('records-shares', run_dir)
            from keepercommander.commands.keeper_tenant_migrate.checkpoint import hash_rows
            ck.mark_done(2, input_sha256=hash_rows(pairs))

            # Different pairs list — SHA mismatch.
            changed = pairs + [{'source_uid': 's6', 'target_uid': 't6'}]
            restorer = ShareRestorer(self._make_client_with_5_records(),
                                     checkpoint=ck, resume=True,
                                     sleeper=lambda _s: None)
            from keepercommander.commands.keeper_tenant_migrate.checkpoint import CheckpointMismatchError
            with self.assertRaises(CheckpointMismatchError):
                restorer.run(changed)

    def test_force_restart_wipes_stale_checkpoint(self):
        pairs = self._pairs()
        with tempfile.TemporaryDirectory() as run_dir:
            ck = Checkpoint('records-shares', run_dir)
            from keepercommander.commands.keeper_tenant_migrate.checkpoint import hash_rows
            ck.mark_done(2, input_sha256=hash_rows(pairs))

            # Different pairs — normally would error, but force_restart wins.
            changed = [{'source_uid': 's9', 'target_uid': 't9'}]
            client = FakeShareClient(records={'s9': {'user_permissions': [
                {'username': 'x@x', 'owner': False},
            ]}})
            restorer = ShareRestorer(client, checkpoint=ck, resume=True,
                                     force_restart=True,
                                     sleeper=lambda _s: None)
            summary = restorer.run(changed)
            self.assertEqual(summary['total'], 1)
            self.assertEqual(summary['resumed'], 0)
            self.assertEqual(summary['pass'], 1)


class ExtractSharesTests(unittest.TestCase):
    """Bug 20 — source-side extract phase."""

    def test_extract_emits_one_entry_per_pair(self):
        records = {
            's1': {'title': 'Login', 'user_permissions': [
                {'username': 'alice@x', 'owner': False, 'editable': True},
                {'username': 'owner@x', 'owner': True},
            ]},
            's2': {'title': 'Notes', 'user_permissions': []},
        }
        client = FakeShareClient(records=records)
        pairs = [
            {'source_uid': 's1', 'target_uid': 't1'},
            {'source_uid': 's2', 'target_uid': 't2'},
        ]
        out = extract_shares(client, pairs)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]['source_uid'], 's1')
        self.assertEqual(out[0]['target_uid'], 't1')
        self.assertEqual(out[0]['title'], 'Login')
        self.assertEqual(len(out[0]['shares']), 1)
        self.assertEqual(out[0]['shares'][0]['username'], 'alice@x')
        self.assertTrue(out[0]['shares'][0]['editable'])
        # s2 produces an entry even though it has no shares — apply
        # phase still gets the source/target UID pair for audit.
        self.assertEqual(out[1]['shares'], [])

    def test_extract_applies_email_remap(self):
        records = {'s1': {'user_permissions': [
            {'username': 'alice@old.example', 'owner': False},
        ]}}
        client = FakeShareClient(records=records)
        out = extract_shares(
            client, [{'source_uid': 's1', 'target_uid': 't1'}],
            old_domain='old.example', new_domain='new.example',
        )
        self.assertEqual(out[0]['shares'][0]['username'],
                         'alice@new.example')

    def test_extract_skips_pairs_with_missing_uid(self):
        client = FakeShareClient(records={})
        out = extract_shares(client, [
            {'source_uid': '', 'target_uid': 't1'},
            {'source_uid': 's1', 'target_uid': ''},
            {'source_uid': 's2', 'target_uid': 't2'},
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['source_uid'], 's2')


class ExtractManifestRoundTripTests(unittest.TestCase):
    """Bug 20 — JSON manifest format."""

    def test_round_trip_preserves_entries(self):
        with tempfile.TemporaryDirectory() as td:
            entries = [
                {'source_uid': 's1', 'target_uid': 't1', 'title': 'L',
                 'shares': [{'username': 'a@x', 'editable': True,
                              'shareable': False}]},
                {'source_uid': 's2', 'target_uid': 't2', 'title': 'N',
                 'shares': []},
            ]
            path = write_extract_manifest(f'{td}/extract.json', entries)
            loaded = read_extract_manifest(path)
            self.assertEqual(loaded, entries)

    def test_manifest_file_is_0600(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            path = write_extract_manifest(f'{td}/extract.json', [])
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_unknown_version_rejected(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            path = f'{td}/bad.json'
            with open(path, 'w') as f:
                json.dump({'_meta': {'version': 999}, 'entries': []}, f)
            with self.assertRaises(ValueError):
                read_extract_manifest(path)


class ShareApplierTests(unittest.TestCase):
    """Bug 20 — target-side apply phase."""

    def test_pass_when_all_shares_ok(self):
        client = FakeShareClient()  # default behavior returns 'OK'
        applier = ShareApplier(client)
        entries = [
            {'source_uid': 's1', 'target_uid': 't1', 'title': 'X',
             'shares': [{'username': 'a@x', 'editable': True,
                          'shareable': False}]},
        ]
        summary = applier.run(entries)
        self.assertEqual(summary['pass'], 1)
        self.assertEqual(summary['per_record'][0]['applied'], 1)
        # share_record was called with the target_uid (NOT source_uid).
        share_calls = [c for c in client.calls if c[0] == 'share_record']
        self.assertEqual(share_calls[0][1][0], 't1')
        self.assertEqual(share_calls[0][1][1], 'a@x')

    def test_skip_when_entry_has_no_shares(self):
        client = FakeShareClient()
        applier = ShareApplier(client)
        summary = applier.run([
            {'source_uid': 's1', 'target_uid': 't1', 'shares': []},
        ])
        self.assertEqual(summary['skip'], 1)
        share_calls = [c for c in client.calls if c[0] == 'share_record']
        self.assertEqual(share_calls, [])

    def test_user_not_found_fails_unless_skip_flag(self):
        client = FakeShareClient(
            share_behavior=lambda *_a: 'USER_NOT_FOUND',
        )
        entries = [
            {'source_uid': 's1', 'target_uid': 't1', 'shares': [
                {'username': 'missing@x', 'editable': False, 'shareable': False},
            ]},
        ]
        # default — fails
        summary = ShareApplier(client).run(entries)
        self.assertEqual(summary['fail'], 1)
        self.assertIn('user not found', summary['per_record'][0]['errors'][0])
        # with --skip-missing-users — skipped, not failed
        client2 = FakeShareClient(
            share_behavior=lambda *_a: 'USER_NOT_FOUND')
        summary2 = ShareApplier(client2,
                                  skip_missing_users=True).run(entries)
        self.assertEqual(summary2['fail'], 0)

    def test_pending_invitation_counts_as_applied(self):
        client = FakeShareClient(
            share_behavior=lambda *_a: 'PENDING_INVITATION',
        )
        entries = [
            {'source_uid': 's1', 'target_uid': 't1', 'shares': [
                {'username': 'pending@x', 'editable': False, 'shareable': False},
            ]},
        ]
        summary = ShareApplier(client).run(entries)
        self.assertEqual(summary['pass'], 1)
        self.assertEqual(summary['per_record'][0]['applied'], 1)
        self.assertEqual(len(summary['per_record'][0]['grants']), 1)

    def test_apply_skips_entries_without_target_uid(self):
        client = FakeShareClient()
        entries = [
            {'source_uid': 's1', 'target_uid': '', 'shares': [
                {'username': 'a@x'},
            ]},
        ]
        summary = ShareApplier(client).run(entries)
        self.assertEqual(summary['skip'], 1)
        # No share_record calls for entries without target_uid.
        share_calls = [c for c in client.calls if c[0] == 'share_record']
        self.assertEqual(share_calls, [])


if __name__ == '__main__':
    unittest.main()
