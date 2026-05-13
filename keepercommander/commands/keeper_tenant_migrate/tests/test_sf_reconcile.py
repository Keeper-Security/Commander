"""Tests for shared-folder reconciliation."""

import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate import sf_reconcile
from keepercommander.commands.keeper_tenant_migrate.checkpoint import Checkpoint


SIMPLE_INVENTORY = {
    'shared_folders': [
        {'name': 'Marketing', 'users': [
            {'username': 'alice@acme.io'},
            {'username': 'bob@acme.io'},
            {'username': 'charlie@acme.io'},
        ]},
        {'name': 'Finance', 'users': [
            {'username': 'alice@acme.io'},
            {'username': 'dave@acme.io'},
        ]},
    ],
}


class TestPlan(unittest.TestCase):
    def test_all_active_all_missing_all_apply(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': set(), 'Finance': set()},
            statuses={
                'alice@acme.io': 'active',
                'bob@acme.io': 'active',
                'charlie@acme.io': 'active',
                'dave@acme.io': 'active',
            },
        )
        plan = sf_reconcile.plan_reconciliation(SIMPLE_INVENTORY, client)
        self.assertEqual(len(plan.to_apply), 5)
        self.assertEqual(len(plan.pending), 0)
        self.assertEqual(len(plan.errors), 0)
        self.assertEqual(plan.user_counts['active'], 4)

    def test_pending_users_go_to_pending_bucket(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': set(), 'Finance': set()},
            statuses={
                'alice@acme.io': 'active',
                'bob@acme.io': 'invited',
                'charlie@acme.io': 'pending',
                'dave@acme.io': 'active',
            },
        )
        plan = sf_reconcile.plan_reconciliation(SIMPLE_INVENTORY, client)
        # Alice: 2 (Marketing, Finance), Dave: 1 (Finance) → 3 to apply
        self.assertEqual(len(plan.to_apply), 3)
        apply_emails = {i.email for i in plan.to_apply}
        self.assertEqual(apply_emails, {'alice@acme.io', 'dave@acme.io'})
        pending_emails = {i.email for i in plan.pending}
        self.assertEqual(pending_emails, {'bob@acme.io', 'charlie@acme.io'})

    def test_already_member_not_in_apply(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={
                'Marketing': {'alice@acme.io'},        # alice already in
                'Finance': {'alice@acme.io', 'dave@acme.io'},  # both in
            },
            statuses={
                'alice@acme.io': 'active', 'bob@acme.io': 'active',
                'charlie@acme.io': 'active', 'dave@acme.io': 'active',
            },
        )
        plan = sf_reconcile.plan_reconciliation(SIMPLE_INVENTORY, client)
        # Only bob + charlie need Marketing → 2 to apply
        self.assertEqual(len(plan.to_apply), 2)
        self.assertEqual({i.email for i in plan.to_apply},
                         {'bob@acme.io', 'charlie@acme.io'})

    def test_missing_sf_becomes_error(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': set()},   # Finance missing on target
            statuses={'alice@acme.io': 'active', 'bob@acme.io': 'active',
                      'charlie@acme.io': 'active', 'dave@acme.io': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(SIMPLE_INVENTORY, client)
        # Marketing: 3 to apply; Finance missing: 2 errors
        self.assertEqual(len(plan.to_apply), 3)
        self.assertEqual(len(plan.errors), 2)
        for err in plan.errors:
            self.assertEqual(err.sf_name, 'Finance')
            self.assertIn('not found', err.reason)

    def test_email_remap_honored(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': set(), 'Finance': set()},
            statuses={
                'alice@keeperdemo.io': 'active',
                'bob@keeperdemo.io': 'active',
                'charlie@keeperdemo.io': 'active',
                'dave@keeperdemo.io': 'active',
            },
        )
        plan = sf_reconcile.plan_reconciliation(
            SIMPLE_INVENTORY, client,
            old_domain='acme.io', new_domain='keeperdemo.io',
        )
        self.assertEqual(len(plan.to_apply), 5)
        for item in plan.to_apply:
            self.assertTrue(item.email.endswith('@keeperdemo.io'),
                            f'unexpected email: {item.email}')


class TestReconcilerRun(unittest.TestCase):
    def _setup(self, behavior=None):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': set(), 'Finance': set()},
            statuses={
                'alice@acme.io': 'active', 'bob@acme.io': 'active',
                'charlie@acme.io': 'active', 'dave@acme.io': 'active',
            },
            behavior=behavior,
        )
        plan = sf_reconcile.plan_reconciliation(SIMPLE_INVENTORY, client)
        return client, plan

    def test_happy_path_applies_all(self):
        client, plan = self._setup()
        rec = sf_reconcile.SFReconciler(client, sleeper=lambda _s: None)
        result = rec.run(plan)
        self.assertEqual(len(result['applied']), 5)
        self.assertEqual(len(result['errors']), 0)
        self.assertEqual(result['resumed'], 0)
        # Post-run memberships reflect applied grants
        post = client.list_sf_memberships()
        self.assertEqual(post['Marketing'],
                         {'alice@acme.io', 'bob@acme.io', 'charlie@acme.io'})

    def test_already_member_counts_as_applied(self):
        client, plan = self._setup(behavior=lambda *_: 'ALREADY_MEMBER')
        rec = sf_reconcile.SFReconciler(client, sleeper=lambda _s: None)
        result = rec.run(plan)
        self.assertEqual(len(result['applied']), 5)
        self.assertEqual(len(result['errors']), 0)

    def test_runtime_errors_collected(self):
        client, plan = self._setup(behavior=lambda *_: 'FAIL')
        rec = sf_reconcile.SFReconciler(client, sleeper=lambda _s: None)
        result = rec.run(plan)
        self.assertEqual(len(result['applied']), 0)
        # plan-level errors (0) + runtime errors (5)
        self.assertEqual(len(result['errors']), 5)

    def test_resume_after_crash_picks_up_at_next(self):
        client, plan = self._setup()
        calls = {'n': 0}

        def fail_after_2(sf_name, email):
            calls['n'] += 1
            if calls['n'] == 3:
                raise RuntimeError('simulated transient')
            # success + mutate the fake's membership table
            client._memberships.setdefault(sf_name, set()).add(email.lower())
            return 'OK'

        client._behavior = fail_after_2
        with tempfile.TemporaryDirectory() as run_dir:
            ck = Checkpoint('shared-folders-reconcile', run_dir)
            rec = sf_reconcile.SFReconciler(
                client, checkpoint=ck, sleeper=lambda _s: None,
            )
            with self.assertRaises(RuntimeError):
                rec.run(plan)
            state = ck.load()
            self.assertEqual(state['last_index'], 2)

            # Resume with a fresh behavior — all succeed now.
            client._behavior = None  # defaults to OK + mutate
            rec2 = sf_reconcile.SFReconciler(
                client, checkpoint=ck, resume=True,
                sleeper=lambda _s: None,
            )
            # Build a NEW plan from current client state — the 2 already-applied
            # are now in actual, so they drop out of to_apply. That means the
            # new plan has 3 items (not 5), and the checkpoint's last_index=2
            # doesn't match. Expected: refuse + force-restart.
            new_plan = sf_reconcile.plan_reconciliation(
                SIMPLE_INVENTORY, client,
            )
            from keepercommander.commands.keeper_tenant_migrate.checkpoint import CheckpointMismatchError
            with self.assertRaises(CheckpointMismatchError):
                rec2.run(new_plan)

            # With the same plan we had before, resume works.
            rec3 = sf_reconcile.SFReconciler(
                client, checkpoint=ck, resume=True,
                sleeper=lambda _s: None,
            )
            result = rec3.run(plan)
            self.assertEqual(result['resumed'], 2)
            self.assertEqual(len(result['applied']), 3)
            # Checkpoint cleared on success.
            self.assertIsNone(ck.load())

    def test_high4_failed_rows_not_marked_done_so_resume_retries(self):
        """HIGH-4 regression — pre-fix mark_done(i) ran unconditionally
        after both the success branch AND the error branch. Errored
        rows were persistently skipped on --resume; operator's only
        escape was --force-restart, which then re-applied every OK
        row from scratch.

        Post-fix: only OK / ALREADY_MEMBER rows advance the
        checkpoint; failed rows stay un-checkpointed.

        Test approach: force a failure mid-run via a runtime exception
        AFTER an OK row + a FAILED row. The exception aborts the run
        before clear()-on-success fires, so we can inspect the
        persisted checkpoint state. last_index should reflect ONLY
        the OK row (1 not 2) — the failed row didn't advance.
        """
        client, plan = self._setup()
        # plan is sorted by (sf_name, email). For SIMPLE_INVENTORY,
        # the first 5 calls are: alice@Marketing, bob@Marketing,
        # charlie@Finance, alice@Finance, dave@Finance.
        calls = {'n': 0}

        def ok_then_fail_then_crash(sf_name, email):
            calls['n'] += 1
            if calls['n'] == 1:
                # Row 0: success → mark_done should fire (last_index=0)
                client._memberships.setdefault(sf_name, set()).add(email.lower())
                return 'OK'
            if calls['n'] == 2:
                # Row 1: API_ERROR → mark_done should NOT fire
                return 'API_ERROR'
            if calls['n'] == 3:
                # Row 2: crash → forces an exception, run aborts
                # before checkpoint.clear() runs; persisted state
                # tells us what mark_done landed.
                raise RuntimeError('simulated mid-run crash')
            client._memberships.setdefault(sf_name, set()).add(email.lower())
            return 'OK'

        client._behavior = ok_then_fail_then_crash
        with tempfile.TemporaryDirectory() as run_dir:
            ck = Checkpoint('shared-folders-reconcile', run_dir)
            rec = sf_reconcile.SFReconciler(
                client, checkpoint=ck, sleeper=lambda _s: None,
            )
            with self.assertRaises(RuntimeError):
                rec.run(plan)
            state = ck.load()
            # The loop uses enumerate(to_apply, start=1) so rows are
            # 1-indexed. Row 1 = first OK call, Row 2 = API_ERROR,
            # Row 3 = crash.
            # Pre-fix: rows 1 + 2 both mark_done → last_index = 2.
            # Post-fix: only row 1 marks done (row 2 failed) → last_index = 1.
            self.assertEqual(state['last_index'], 1,
                             f'expected last_index=1 (only the one OK row '
                             f'advanced the checkpoint), got '
                             f'{state["last_index"]} — HIGH-4 regression: '
                             f'failed row was incorrectly marked done')


class TestRender(unittest.TestCase):
    def test_render_plan_only(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': set(), 'Finance': set()},
            statuses={
                'alice@acme.io': 'active',
                'bob@acme.io': 'invited',
                'charlie@acme.io': 'pending',
                'dave@acme.io': 'active',
            },
        )
        plan = sf_reconcile.plan_reconciliation(SIMPLE_INVENTORY, client)
        md = sf_reconcile.render_report(plan)
        self.assertIn('Activation progress', md)
        self.assertIn('Would apply', md)
        self.assertIn('alice@acme.io', md)
        self.assertIn('Still pending', md)
        self.assertIn('bob@acme.io', md)

    def test_render_with_run_result(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': set(), 'Finance': set()},
            statuses={'alice@acme.io': 'active', 'bob@acme.io': 'invited',
                      'charlie@acme.io': 'pending', 'dave@acme.io': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(SIMPLE_INVENTORY, client)
        rec = sf_reconcile.SFReconciler(client, sleeper=lambda _s: None)
        result = rec.run(plan)
        md = sf_reconcile.render_report(plan, run=result)
        self.assertIn('Applied this run', md)
        self.assertIn('alice@acme.io', md)
        self.assertIn('Still pending', md)


class PruneTests(unittest.TestCase):
    """--prune opts into destructive removal of target memberships
    absent from source inventory. Must be explicit on both the plan
    AND the reconciler, and must be scoped to SFs that actually exist
    in the source inventory (out-of-scope SFs untouched)."""

    def test_prune_off_by_default_does_not_plan_removals(self):
        """Current behavior — add-only. Prune list stays empty."""
        inventory = {
            'shared_folders': [
                {'name': 'Marketing', 'users': [
                    {'username': 'alice@acme.io'},
                ]},
            ],
        }
        client = sf_reconcile.FakeSFReconcileClient(
            # Target has an extra member that's NOT in source inventory.
            memberships={'Marketing': {'alice@acme.io', 'extra@acme.io'}},
            statuses={'alice@acme.io': 'active',
                      'extra@acme.io': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inventory, client)
        self.assertEqual(plan.to_prune, [])

    def test_prune_true_surfaces_extras_as_prune_candidates(self):
        inventory = {
            'shared_folders': [
                {'name': 'Marketing', 'users': [
                    {'username': 'alice@acme.io'},
                ]},
            ],
        }
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': {'alice@acme.io', 'extra@acme.io'}},
            statuses={'alice@acme.io': 'active',
                      'extra@acme.io': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inventory, client,
                                                  prune=True)
        prune_emails = {i.email for i in plan.to_prune}
        self.assertEqual(prune_emails, {'extra@acme.io'})
        # Scoped to the SF: only Marketing's extras.
        sf_names = {i.sf_name for i in plan.to_prune}
        self.assertEqual(sf_names, {'Marketing'})

    def test_prune_does_not_touch_out_of_scope_sfs(self):
        """Critical safety: an SF that exists on target but NOT in
        source inventory is out-of-scope. Its members must be
        untouched even under --prune."""
        inventory = {
            'shared_folders': [
                {'name': 'Marketing', 'users': [
                    {'username': 'alice@acme.io'},
                ]},
            ],
        }
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={
                'Marketing': {'alice@acme.io'},
                'Prod-SF': {'prod-admin@acme.io'},  # out of inventory scope
            },
            statuses={'alice@acme.io': 'active',
                      'prod-admin@acme.io': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inventory, client,
                                                  prune=True)
        # Marketing is in scope → its extras could be pruned (none here).
        # Prod-SF is out of scope → its members must NEVER appear in
        # the prune list.
        prune_sfs = {i.sf_name for i in plan.to_prune}
        self.assertNotIn('Prod-SF', prune_sfs)

    def test_reconciler_with_prune_flag_executes_removals(self):
        inventory = {
            'shared_folders': [
                {'name': 'Marketing', 'users': [
                    {'username': 'alice@acme.io'},
                ]},
            ],
        }
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing': {'alice@acme.io', 'old@acme.io'}},
            statuses={'alice@acme.io': 'active',
                      'old@acme.io': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inventory, client,
                                                  prune=True)
        reconciler = sf_reconcile.SFReconciler(
            client, prune=True, sleeper=lambda _s: None,
        )
        result = reconciler.run(plan)

        self.assertEqual(len(result['pruned']), 1)
        self.assertEqual(result['pruned'][0].email, 'old@acme.io')
        # Target state after run: 'old@acme.io' actually removed.
        self.assertNotIn('old@acme.io',
                          client.list_sf_memberships()['Marketing'])
        self.assertIn('alice@acme.io',
                       client.list_sf_memberships()['Marketing'])

    def test_reconciler_without_prune_flag_ignores_to_prune_list(self):
        """Plan generated with prune=True, passed to a reconciler with
        prune=False. The reconciler must NOT execute the removals —
        explicit opt-in on both sides."""
        inventory = {
            'shared_folders': [
                {'name': 'F', 'users': [{'username': 'keep@x'}]},
            ],
        }
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': {'keep@x', 'old@x'}},
            statuses={'keep@x': 'active', 'old@x': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inventory, client,
                                                  prune=True)
        self.assertEqual(len(plan.to_prune), 1)   # would prune 'old@x'

        # But the reconciler has prune=False → ignored.
        reconciler = sf_reconcile.SFReconciler(
            client, prune=False, sleeper=lambda _s: None,
        )
        result = reconciler.run(plan)
        self.assertEqual(result.get('pruned', []), [])
        # Target state: 'old@x' STILL present — the safe default held.
        self.assertIn('old@x', client.list_sf_memberships()['F'])


class DefaultRemoveTests(unittest.TestCase):
    """Cover SFReconcileClient.remove_user_from_sf default ('FAIL') and
    FakeSFReconcileClient.remove_user_from_sf custom-behavior path."""

    def test_default_protocol_remove_returns_fail(self):
        """The base class's default refuses removals — opt-in safety."""
        base = sf_reconcile.SFReconcileClient.remove_user_from_sf(
            sf_reconcile.SFReconcileClient(), 'F', 'a@x')
        self.assertEqual(base, 'FAIL')

    def test_fake_with_custom_remove_behavior(self):
        """A custom remove_behavior callable overrides the default OK code."""
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': {'old@x'}},
            statuses={'old@x': 'active'},
            remove_behavior=lambda sf, em: 'FAIL',
        )
        code = client.remove_user_from_sf('F', 'old@x')
        self.assertEqual(code, 'FAIL')
        # Membership untouched on FAIL.
        self.assertIn('old@x', client.list_sf_memberships()['F'])


class MalformedInventoryTests(unittest.TestCase):
    """Cover defensive guards against bad inventory entries (lines 165, 176)."""

    def test_non_dict_sf_entry_skipped(self):
        """A list-typed SF entry shouldn't crash the planner."""
        inv = {'shared_folders': [
            'not-a-dict',
            {'name': 'F', 'users': [{'username': 'a@x'}]},
        ]}
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': set()},
            statuses={'a@x': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inv, client)
        self.assertEqual(len(plan.to_apply), 1)

    def test_member_neither_str_nor_dict_skipped(self):
        """A None or int member entry must be skipped, not raise."""
        inv = {'shared_folders': [
            {'name': 'F', 'users': [
                None,
                42,
                {'username': 'good@x'},
            ]},
        ]}
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': set()},
            statuses={'good@x': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inv, client)
        self.assertEqual(len(plan.to_apply), 1)
        self.assertEqual(plan.to_apply[0].email, 'good@x')


class PruneScopeEdgeCaseTests(unittest.TestCase):
    """Cover prune analysis when an SF in inventory is missing on target
    (line 262 — `if sf_name not in actual: continue`)."""

    def test_inventory_sf_missing_on_target_yields_no_prune_entries(self):
        inv = {'shared_folders': [
            {'name': 'GoneFromTarget',
             'users': [{'username': 'a@x'}]},
            {'name': 'F',
             'users': [{'username': 'keep@x'}]},
        ]}
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': {'keep@x', 'extra@x'}},  # GoneFromTarget absent
            statuses={'a@x': 'active', 'keep@x': 'active', 'extra@x': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inv, client, prune=True)
        # GoneFromTarget produces an error (not on target), but prune
        # analysis only walks SFs present on BOTH sides — so to_prune
        # only carries 'extra@x' from F.
        prune_sfs = {i.sf_name for i in plan.to_prune}
        self.assertEqual(prune_sfs, {'F'})


class SleeperPathTests(unittest.TestCase):
    """Cover the inter-call sleeper paths (lines 331, 334-335, 360)."""

    def test_apply_with_delay_calls_sleeper(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': set()},
            statuses={'a@x': 'active', 'b@x': 'active'},
        )
        inv = {'shared_folders': [
            {'name': 'F', 'users': [{'username': 'a@x'},
                                       {'username': 'b@x'}]},
        ]}
        plan = sf_reconcile.plan_reconciliation(inv, client)
        sleep_calls = []
        reconciler = sf_reconcile.SFReconciler(
            client, delay=0.01, sleeper=sleep_calls.append,
        )
        reconciler.run(plan)
        # 2 applied calls + sleeper invocation per item; backoff Retry uses
        # the same sleeper, so we just check it fired at least twice.
        self.assertGreaterEqual(len(sleep_calls), 2)

    def test_batch_size_pause_fires_after_n_items(self):
        """When batch_size=1, every iteration triggers a longer pause."""
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': set()},
            statuses={'a@x': 'active', 'b@x': 'active'},
        )
        inv = {'shared_folders': [
            {'name': 'F', 'users': [{'username': 'a@x'},
                                       {'username': 'b@x'}]},
        ]}
        plan = sf_reconcile.plan_reconciliation(inv, client)
        sleep_calls = []
        reconciler = sf_reconcile.SFReconciler(
            client, delay=0.01, batch_size=1,
            sleeper=sleep_calls.append,
        )
        reconciler.run(plan)
        # batch pause is max(delay*2, 1.0) → must see a 1.0+ entry per
        # batch boundary (one per item with batch_size=1).
        big_sleeps = [s for s in sleep_calls if s >= 1.0]
        self.assertGreaterEqual(len(big_sleeps), 2)

    def test_prune_with_delay_calls_sleeper(self):
        inv = {'shared_folders': [
            {'name': 'F', 'users': [{'username': 'keep@x'}]},
        ]}
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': {'keep@x', 'old1@x', 'old2@x'}},
            statuses={'keep@x': 'active', 'old1@x': 'active',
                      'old2@x': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(inv, client, prune=True)
        sleep_calls = []
        reconciler = sf_reconcile.SFReconciler(
            client, prune=True, delay=0.01,
            sleeper=sleep_calls.append,
        )
        result = reconciler.run(plan)
        self.assertEqual(len(result['pruned']), 2)
        # Sleeper fired during prune loop too.
        self.assertGreaterEqual(len(sleep_calls), 2)

    def test_prune_with_failing_remove_records_error(self):
        """Prune codes other than OK/NOT_MEMBER end up in errors list."""
        inv = {'shared_folders': [
            {'name': 'F', 'users': [{'username': 'keep@x'}]},
        ]}
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'F': {'keep@x', 'old@x'}},
            statuses={'keep@x': 'active', 'old@x': 'active'},
            remove_behavior=lambda sf, em: 'SF_NOT_FOUND',
        )
        plan = sf_reconcile.plan_reconciliation(inv, client, prune=True)
        reconciler = sf_reconcile.SFReconciler(
            client, prune=True, sleeper=lambda _s: None,
        )
        result = reconciler.run(plan)
        self.assertEqual(result['pruned'], [])
        # The prune failure landed in errors list with the prune-fail prefix.
        self.assertTrue(any('prune failed' in e.reason
                              for e in result['errors']))


class RenderReportFullCoverageTests(unittest.TestCase):
    """Cover the rendering branches for a real run dict (lines 400-413)."""

    def test_render_with_run_no_applied_emits_empty_marker(self):
        plan = sf_reconcile.ReconcilePlan(user_counts={'active': 0,
                                                          'pending_or_invited': 0,
                                                          'target_total': 0})
        report = sf_reconcile.render_report(
            plan,
            run={'applied': [], 'errors': [], 'resumed': 0, 'pending': []})
        self.assertIn('nothing to apply', report)

    def test_render_with_applied_lists_each_item(self):
        plan = sf_reconcile.ReconcilePlan()
        run = {
            'applied': [sf_reconcile.ReconcileItem(
                email='a@x', sf_name='F')],
            'errors': [],
            'resumed': 5,
            'pending': [],
            'user_counts': {'active': 1, 'pending_or_invited': 0,
                            'target_total': 1},
        }
        report = sf_reconcile.render_report(plan, run=run)
        self.assertIn('a@x', report)
        self.assertIn('F', report)
        self.assertIn('skipped 5 items', report)

    def test_render_with_errors_emits_error_section(self):
        plan = sf_reconcile.ReconcilePlan()
        run = {
            'applied': [],
            'errors': [sf_reconcile.ReconcileItem(
                email='a@x', sf_name='F', reason='oops')],
            'resumed': 0,
            'pending': [],
        }
        report = sf_reconcile.render_report(plan, run=run)
        self.assertIn('### Errors', report)
        self.assertIn('oops', report)


class LoadInventoryFileTests(unittest.TestCase):
    """Cover load_inventory file-read helper (lines 436-438)."""

    def test_round_trip(self):
        import json
        import os
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'inv.json')
            with open(path, 'w') as f:
                json.dump({'shared_folders': []}, f)
            loaded = sf_reconcile.load_inventory(path)
            self.assertEqual(loaded, {'shared_folders': []})


if __name__ == '__main__':
    unittest.main()
