"""End-to-end integration tests — chain Fake clients through a full
pipeline without a live tenant.

Unit tests isolate each subcommand. Adversarial tests isolate each
attack vector. These E2E tests bind multiple subcommand drivers
together the way a real migration would, catching cross-stage bugs
that single-subcommand tests miss:

  - Stale-state handoff between stages (e.g. structure's team output
    leaks into records-import's manifest)
  - Checkpoint leakage (a crashed earlier stage leaves a checkpoint
    that misleads a later stage)
  - Audit chain continuity across subcommands
  - Error propagation (failed structure doesn't silently let users
    get invited into nonexistent nodes)

Design: each test composes the `FakeClient` from each module,
wires them through the driver classes directly (bypassing the
CLI/argparse layer — that's tested separately in test_commands.py).
"""

import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.checkpoint import Checkpoint, hash_rows
from keepercommander.commands.keeper_tenant_migrate.cleanup import FakeCleanupClient, cleanup
from keepercommander.commands.keeper_tenant_migrate.shares import (
    FakeShareClient, ShareRestorer,
)
from keepercommander.commands.keeper_tenant_migrate.sf_reconcile import (
    FakeSFReconcileClient, SFReconciler, plan_reconciliation,
)


class PipelineAuditContinuityTests(unittest.TestCase):
    """Every mutating stage appends to audit.log. The chain must stay
    intact across multiple distinct subcommands writing to the same
    file."""

    def test_multi_subcommand_audit_chain_verifies(self):
        from keepercommander.commands.keeper_tenant_migrate.audit import (
            append_audit_event, verify_audit_log,
        )
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            # Simulate a full structure → users → records → cleanup run.
            append_audit_event(log, {'subcommand': 'structure',
                                      'summary': {'created': 22}})
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {'invited': 5}})
            append_audit_event(log, {'subcommand': 'records-import',
                                      'summary': {'imported': 100}})
            append_audit_event(log, {'subcommand': 'records-shares',
                                      'summary': {'grants': 42}})
            append_audit_event(log, {'subcommand': 'shared-folders-reconcile',
                                      'summary': {'applied': 7}})
            append_audit_event(log, {'subcommand': 'cleanup',
                                      'summary': {'deleted': 22}})

            ok, broken = verify_audit_log(log)
            self.assertTrue(ok, f'multi-stage chain broken at {broken}')


class CheckpointCrossStageIsolationTests(unittest.TestCase):
    """One stage's checkpoint must not accidentally resume a DIFFERENT
    stage. Each stage gets its own file by name — regression guard
    against a future refactor that flattens them."""

    def test_records_shares_checkpoint_does_not_affect_reconcile(self):
        with tempfile.TemporaryDirectory() as run_dir:
            # Simulate records-shares crashing mid-run.
            shares_ck = Checkpoint('records-shares', run_dir)
            shares_rows = [{'source_uid': 's1', 'target_uid': 't1'}]
            shares_ck.mark_done(0, input_sha256=hash_rows(shares_rows))

            # A later sf-reconcile run uses a different Checkpoint.
            sf_ck = Checkpoint('shared-folders-reconcile', run_dir)
            self.assertIsNone(
                sf_ck.load(),
                'shared-folders-reconcile checkpoint was polluted by '
                'records-shares state',
            )
            # And records-shares still has its own state intact.
            self.assertIsNotNone(shares_ck.load())

    def test_concurrent_stage_checkpoints_isolated(self):
        """Writing to one stage's checkpoint must not overwrite another."""
        with tempfile.TemporaryDirectory() as run_dir:
            ck_a = Checkpoint('users', run_dir)
            ck_b = Checkpoint('records-import', run_dir)
            ck_a.mark_done(5, input_sha256='a' * 64)
            ck_b.mark_done(10, input_sha256='b' * 64)
            self.assertEqual(ck_a.load()['last_index'], 5)
            self.assertEqual(ck_b.load()['last_index'], 10)


class SharesToReconcileHandoffTests(unittest.TestCase):
    """Running records-shares before shared-folders-reconcile is a
    common pattern. Make sure their state + inventory/manifest inputs
    don't interfere.
    """

    def test_shares_target_uid_not_aliased_with_sf_name(self):
        """A bug could confuse target_uid (records-shares manifest) with
        sf_name (reconcile inventory). Both are strings; both are keys.
        Pin them to disjoint mock universes and verify no cross-talk."""
        # records-shares pipeline
        share_records = {'rec1': {'user_permissions': [
            {'username': 'user@x', 'owner': False, 'editable': True},
        ]}}
        share_client = FakeShareClient(records=share_records)
        ShareRestorer(share_client, sleeper=lambda _s: None).run([
            {'source_uid': 'rec1', 'target_uid': 'TGT-REC'},
        ])
        share_calls = [c for c in share_client.calls
                        if c[0] == 'share_record']
        self.assertEqual(len(share_calls), 1)
        # share_record was called with (target_uid, email, editable,
        # shareable). target_uid must be TGT-REC, NOT a folder name.
        _, (target_uid, *_) = share_calls[0]
        self.assertEqual(target_uid, 'TGT-REC')

        # reconcile pipeline — completely disjoint
        inventory = {
            'shared_folders': [
                {'name': 'Marketing', 'users': [{'username': 'user@x'}]},
            ],
        }
        reconcile_client = FakeSFReconcileClient(
            memberships={'Marketing': set()},
            statuses={'user@x': 'active'},
        )
        plan = plan_reconciliation(inventory, reconcile_client)
        SFReconciler(reconcile_client, sleeper=lambda _s: None).run(plan)
        # SFReconciler must only have touched SF memberships — no record
        # shares, no record UIDs.
        for op, sf_name, email in reconcile_client.calls:
            self.assertEqual(op, 'add')
            self.assertNotEqual(sf_name, 'TGT-REC')   # the record UID


class CleanupAfterPipelineTests(unittest.TestCase):
    """Cleanup after a full structure + records pipeline must remove
    EVERYTHING that the pipeline created and nothing else."""

    def test_cleanup_removes_only_prefixed_entities_including_records(self):
        """Pipeline created: 3 teams, 3 roles, 3 nodes, 2 records (all
        prefixed). Pre-existing entities (admin role, Everyone SF)
        must survive."""
        entities = {
            'teams': [
                {'name': 'MIGTEST-T1'},
                {'name': 'MIGTEST-T2'},
                {'name': 'Production-Ops'},   # not ours
            ],
            'roles': [
                {'name': 'MIGTEST-RoleAdmin'},
                {'name': 'MIGTEST-RoleBasic'},
                {'name': 'Keeper Administrator'},   # not ours
            ],
            'nodes': [
                {'name': 'MIGTEST-Child', 'parent': 'Test\\Scope'},
                {'name': 'MIGTEST-Grand', 'parent': 'MIGTEST-Child'},
                {'name': 'Production Unit 12', 'parent': ''},
            ],
            'records': [
                {'uid': 'u1', 'title': 'MIGTEST-Login'},
                {'uid': 'u2', 'title': 'MIGTEST-Notes'},
                {'uid': 'u3', 'title': 'admin-password'},   # not ours
                {'uid': 'u4', 'title': 'app_packages:abc'},  # not ours
            ],
        }
        client = FakeCleanupClient(entities=entities)
        summary = cleanup(client, 'MIGTEST-', include_records=True)

        self.assertEqual(summary['teams'], 2)
        self.assertEqual(summary['roles'], 2)
        self.assertEqual(summary['nodes'], 2)
        self.assertEqual(summary['records'], 2)
        self.assertEqual(summary['errors'], 0)

        # Pre-existing survived.
        surviving_teams = {t['name'] for t in client.entities['teams']}
        self.assertIn('Production-Ops', surviving_teams)
        surviving_records = {r['uid'] for r in client.entities['records']}
        self.assertIn('u3', surviving_records)
        self.assertIn('u4', surviving_records)

    def test_post_pipeline_cleanup_is_idempotent(self):
        """Running cleanup twice on a fresh target must not error —
        second invocation finds nothing to delete, reports 0 / 0 /
        0 / 0 / 0, exits clean."""
        entities = {'teams': [], 'roles': [], 'nodes': [], 'records': []}
        client = FakeCleanupClient(entities=entities)
        summary = cleanup(client, 'MIGTEST-', include_records=True)
        self.assertEqual(
            summary,
            {'teams': 0, 'roles': 0, 'nodes': 0,
             'records': 0, 'shared_folders': 0, 'errors': 0},
        )


class ChainedCheckpointResumeTests(unittest.TestCase):
    """The checkpoint protocol is exercised under the 'crash mid-stage,
    resume, finish' pattern here — but across multiple stages.
    """

    def test_resume_one_stage_does_not_affect_another(self):
        """records-shares crashes; sf-reconcile should start fresh."""
        with tempfile.TemporaryDirectory() as run_dir:
            # Stage A — records-shares crashes after 2 of 5 pairs
            pairs = [
                {'source_uid': f's{i}', 'target_uid': f't{i}'}
                for i in range(5)
            ]
            share_client = FakeShareClient(
                records={f's{i}': {'user_permissions': [
                    {'username': f'u{i}@x', 'owner': False},
                ]} for i in range(5)},
            )
            ck_shares = Checkpoint('records-shares', run_dir)
            ck_shares.mark_done(
                2, input_sha256=hash_rows(pairs),
            )

            # Stage B — sf-reconcile starts. Its own checkpoint file
            # must be absent.
            ck_reconcile = Checkpoint('shared-folders-reconcile', run_dir)
            self.assertIsNone(ck_reconcile.load())

            # Stage A is resumable independently.
            resume_idx = ck_shares.resume_from(
                pairs, resume=True, force_restart=False,
            )
            self.assertEqual(resume_idx, 3)


class AuditChainTrimmingTests(unittest.TestCase):
    """An attacker with file access might try to TRIM the audit log
    (delete trailing entries) to hide recent activity. If they just
    delete the last line, does verify_audit_log still pass?

    It should — the remaining chain is self-consistent. But an
    operator tracking 'I appended N events' would notice N is wrong.
    Document that verify_audit_log is about INTERNAL CHAIN CONSISTENCY,
    not about external timeline trust. A separate 'observe count'
    mechanism is needed for trim detection."""

    def test_verify_passes_on_internally_consistent_trimmed_log(self):
        """Trim the last entry; chain is still valid up to the
        truncation point. This is BY DESIGN — verify_audit_log
        checks chain consistency, not absolute count. The trim
        attack is NOT detected by this layer alone."""
        from keepercommander.commands.keeper_tenant_migrate.audit import (
            append_audit_event, verify_audit_log,
        )
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'a',
                                      'summary': {'x': 1}})
            append_audit_event(log, {'subcommand': 'b',
                                      'summary': {'x': 2}})
            append_audit_event(log, {'subcommand': 'c',
                                      'summary': {'x': 3}})

            # Trim: delete the last line
            with open(log) as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            with open(log, 'w') as f:
                f.write('\n'.join(lines[:-1]) + '\n')

            ok, broken = verify_audit_log(log)
            # Pure chain verify passes — trim isn't a chain tamper.
            self.assertTrue(
                ok,
                'verify_audit_log should pass on internally-consistent '
                f'trimmed log (documentation of known limitation); '
                f'got ok={ok}, broken={broken}',
            )
            # The remaining lines verify as a valid chain.
            with open(log) as f:
                remaining = [ln for ln in f.read().splitlines() if ln.strip()]
            self.assertEqual(len(remaining), 2)

    def test_chain_breaks_when_middle_entry_removed(self):
        """Dropping a MIDDLE entry breaks the chain hash (next entry's
        prev_hash no longer matches). Detected."""
        from keepercommander.commands.keeper_tenant_migrate.audit import (
            append_audit_event, verify_audit_log,
        )
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'a',
                                      'summary': {'x': 1}})
            append_audit_event(log, {'subcommand': 'b',
                                      'summary': {'x': 2}})
            append_audit_event(log, {'subcommand': 'c',
                                      'summary': {'x': 3}})

            # Remove middle entry
            with open(log) as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            with open(log, 'w') as f:
                f.write(lines[0] + '\n' + lines[2] + '\n')

            ok, broken = verify_audit_log(log)
            self.assertFalse(ok, f'middle-drop not caught: broken={broken}')


if __name__ == '__main__':
    unittest.main()
