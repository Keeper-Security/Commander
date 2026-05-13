import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.audit import append_audit_event
from keepercommander.commands.keeper_tenant_migrate.undo import (
    FakeUndoClient,
    IRREVERSIBLE,
    MANUAL,
    REVERSIBLE,
    _invert_event,
    execute_plans,
    plan_undo,
    run,
)


def _log_with_events(log_path, events):
    for ev in events:
        append_audit_event(log_path, ev)


class InvertEventTests(unittest.TestCase):
    def test_users_invert_locks_each_invited(self):
        ev = {'subcommand': 'users',
              'summary': {'invited_emails': ['a@x', 'b@x']}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(
            [op for op, _ in plan.ops], ['lock_user', 'lock_user'])

    def test_users_hard_adds_delete_op(self):
        ev = {'subcommand': 'users',
              'summary': {'invited_emails': ['a@x']}}
        plan = _invert_event(ev, hard=True)
        ops = [op for op, _ in plan.ops]
        self.assertEqual(ops, ['lock_user', 'delete_user'])

    def test_structure_invert_deletes_in_reverse_order(self):
        ev = {'subcommand': 'structure',
              'summary': {'created_entities': {
                  'nodes': ['n1'], 'teams': ['t1'], 'roles': ['r1'],
                  'shared_folders': ['sf1'],
              }}}
        plan = _invert_event(ev, hard=False)
        verbs = [op for op, _ in plan.ops]
        # SFs first, then roles, teams, nodes (dep order)
        self.assertEqual(verbs, ['delete_shared_folder', 'delete_role',
                                  'delete_team', 'delete_node'])

    def test_structure_node_deletes_in_reverse_topological_order(self):
        """Bug 18 — audit log records nodes in creation order
        (parents-before-children). Undo must iterate in reverse so
        children are deleted before their parents; otherwise the
        server rejects the parent delete with 'must first delete or
        move the objects on this node'."""
        ev = {'subcommand': 'structure',
              'summary': {'created_entities': {
                  'nodes': ['parent', 'child', 'grandchild'],
                  'teams': [], 'roles': [], 'shared_folders': [],
              }}}
        plan = _invert_event(ev, hard=False)
        # Pull just the node names from the delete_node ops
        deleted_names = [args[0] for op, args in plan.ops
                         if op == 'delete_node']
        self.assertEqual(deleted_names,
                          ['grandchild', 'child', 'parent'])

    def test_take_ownership_emits_manual_action(self):
        ev = {'subcommand': 'take-ownership',
              'outputs': {'report_output': '/tmp/r.csv'}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, MANUAL)
        self.assertIn('take-ownership-restore', plan.notes)
        self.assertIn('/tmp/r.csv', plan.notes)

    def test_records_import_is_manual(self):
        ev = {'subcommand': 'records-import',
              'summary': {'imported_uids': ['u1', 'u2']}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, MANUAL)
        self.assertIn('Delete by UID', plan.notes)

    def test_records_references_rewrite_is_manual(self):
        """Bug 33 (v1.5.1) — undo for the references rewrite is MANUAL.
        Reverting requires the before-image; operator re-imports from
        the source bundle to restore source-shaped UIDs."""
        ev = {'subcommand': 'records-references-rewrite',
              'summary': {'rewritten_uids': ['t1', 't2', 't3'],
                          'records_rewritten': 3, 'refs_remapped': 5}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, MANUAL)
        self.assertIn('3 record', plan.notes)
        self.assertIn('re-import', plan.notes)

    def test_records_shares_revokes_each(self):
        ev = {'subcommand': 'records-shares',
              'summary': {'share_grants': [
                  {'target_uid': 't1', 'email': 'a@x'},
                  {'target_uid': 't2', 'email': 'b@x'},
              ]}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(len(plan.ops), 2)
        self.assertEqual(plan.ops[0][0], 'revoke_record_share')

    def test_records_shares_apply_revokes_each(self):
        """Bug 45 — undo recognizes records-shares-apply (Bug 20 split).
        Audit-event shape is identical to the legacy single-session
        records-shares; only the subcommand label changed."""
        ev = {'subcommand': 'records-shares-apply',
              'summary': {'share_grants': [
                  {'target_uid': 't1', 'email': 'a@x'},
              ]}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(len(plan.ops), 1)
        self.assertEqual(plan.ops[0], ('revoke_record_share', ('t1', 'a@x')))

    def test_records_shares_extract_is_noop(self):
        """Bug 45 — extract is source-side only; no target state to undo."""
        ev = {'subcommand': 'records-shares-extract',
              'summary': {'pairs_total': 5, 'total_grants': 3}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(plan.ops, [])

    def test_records_attachments_upload_deletes_each(self):
        """Bug 45 — undo recognizes records-attachments-upload."""
        ev = {'subcommand': 'records-attachments-upload',
              'summary': {'uploaded_files': [
                  {'target_uid': 't1', 'file_name': 'doc.pdf'},
              ]}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(plan.ops, [('delete_attachment', ('t1', 'doc.pdf'))])

    def test_records_attachments_download_is_noop(self):
        """Bug 45 — download is source-side only."""
        ev = {'subcommand': 'records-attachments-download',
              'summary': {'total_files': 3}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(plan.ops, [])

    def test_cleanup_is_irreversible(self):
        ev = {'subcommand': 'cleanup', 'summary': {}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, IRREVERSIBLE)

    def test_readonly_is_noop(self):
        ev = {'subcommand': 'verify', 'summary': {}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(plan.ops, [])

    def test_unknown_subcommand_is_manual(self):
        ev = {'subcommand': 'something-new', 'summary': {}}
        plan = _invert_event(ev, hard=False)
        self.assertEqual(plan.kind, MANUAL)


class PlanUndoWalksBackwardsTests(unittest.TestCase):
    def test_plan_returns_events_newest_first(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            _log_with_events(log, [
                {'subcommand': 'structure', 'summary': {'created_entities':
                    {'nodes': ['n1']}}},
                {'subcommand': 'users',
                 'summary': {'invited_emails': ['a@x']}},
            ])
            plans = plan_undo(log)
            self.assertEqual(len(plans), 2)
            # Newest event (users) first
            self.assertEqual(plans[0].event['subcommand'], 'users')
            self.assertEqual(plans[1].event['subcommand'], 'structure')

    def test_up_to_signature_stops_before_that_event(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            e1 = append_audit_event(log, {
                'subcommand': 'structure',
                'summary': {'created_entities': {'nodes': ['n1']}}})
            append_audit_event(log, {
                'subcommand': 'users',
                'summary': {'invited_emails': ['a@x']}})
            plans = plan_undo(log, up_to_signature=e1['signature'])
            self.assertEqual(len(plans), 1)
            self.assertEqual(plans[0].event['subcommand'], 'users')


class ExecutePlansTests(unittest.TestCase):
    def test_runs_every_op_on_client(self):
        plans = plan_undo._module_test_fake_plans() if hasattr(
            plan_undo, '_module_test_fake_plans') else None
        # Build plans by hand:
        from keepercommander.commands.keeper_tenant_migrate.undo import UndoPlan, REVERSIBLE
        p1 = UndoPlan({'subcommand': 'users'}, REVERSIBLE,
                       ops=[('lock_user', ('a@x',)),
                             ('lock_user', ('b@x',))])
        p2 = UndoPlan({'subcommand': 'records-shares'}, REVERSIBLE,
                       ops=[('revoke_record_share', ('uid1', 'a@x'))])
        client = FakeUndoClient()
        summary = execute_plans([p1, p2], client)
        self.assertEqual(summary['reversed'], 3)
        self.assertEqual(summary['failed'], 0)
        # Calls were recorded on client
        self.assertEqual(len(client.calls), 3)

    def test_counts_manual_and_irreversible(self):
        from keepercommander.commands.keeper_tenant_migrate.undo import UndoPlan, MANUAL, IRREVERSIBLE
        plans = [
            UndoPlan({'subcommand': 'records-import'}, MANUAL, notes='x'),
            UndoPlan({'subcommand': 'cleanup'}, IRREVERSIBLE, notes='y'),
        ]
        summary = execute_plans(plans, FakeUndoClient())
        self.assertEqual(summary['manual'], 1)
        self.assertEqual(summary['irreversible'], 1)
        self.assertEqual(summary['reversed'], 0)

    def test_client_failure_is_counted(self):
        from keepercommander.commands.keeper_tenant_migrate.undo import UndoPlan, REVERSIBLE
        p = UndoPlan({'subcommand': 'users'}, REVERSIBLE,
                      ops=[('lock_user', ('a@x',))])
        client = FakeUndoClient(fail_ops={'lock_user'})
        summary = execute_plans([p], client)
        self.assertEqual(summary['failed'], 1)
        self.assertEqual(summary['reversed'], 0)

    def test_high5_manual_action_required_tallies_as_manual_not_failed(self):
        """HIGH-5 regression — pre-fix CommanderUndoClient.delete_attachment
        returned False with just a logging.warning, so the undo loop
        counted it as a generic failure. Operators reading the undo
        summary saw "X failed" with no signal that those Xs were
        actually "human action required" rather than runtime errors.

        Post-fix the client raises ManualActionRequired; the loop
        catches it separately and tallies as `manual`.
        """
        from keepercommander.commands.keeper_tenant_migrate.undo import (
            UndoPlan, REVERSIBLE, ManualActionRequired,
        )

        class ManualActionClient:
            def needs_human(self, *args):
                raise ManualActionRequired(
                    'this op cannot run automatically — operator must act'
                )

        p = UndoPlan({'subcommand': 'records-attachments'}, REVERSIBLE,
                      ops=[('needs_human', ('arg1', 'arg2'))])
        summary = execute_plans([p], ManualActionClient())
        # The op must NOT be counted as 'failed' — that would hide
        # the manual-action signal and confuse compliance teams.
        self.assertEqual(summary['failed'], 0,
                         'ManualActionRequired must not be tallied as failed')
        self.assertEqual(summary['manual'], 1,
                         'ManualActionRequired must be tallied as manual')
        self.assertEqual(summary['reversed'], 0)


class RunDriverTests(unittest.TestCase):
    def test_refuses_when_chain_broken(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {'invited_emails': ['a@x']}})
            # Break the chain by hand-editing the file
            with open(log) as f:
                content = f.read()
            with open(log, 'w') as f:
                f.write(content.replace('users', 'usersX'))
            result = run(log, FakeUndoClient(), execute=False)
            self.assertFalse(result['ok'])
            self.assertEqual(result['reason'], 'chain_broken')

    def test_dry_run_returns_plans_without_executing(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {'invited_emails': ['a@x']}})
            result = run(log, FakeUndoClient(), execute=False)
            self.assertTrue(result['ok'])
            self.assertFalse(result['executed'])
            self.assertEqual(result['count'], 1)

    def test_execute_calls_client(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {'invited_emails': ['a@x']}})
            client = FakeUndoClient()
            result = run(log, client, execute=True)
            self.assertTrue(result['executed'])
            self.assertEqual(result['summary']['reversed'], 1)
            self.assertEqual(client.calls[0], ('lock_user', ('a@x',)))


if __name__ == '__main__':
    unittest.main()
