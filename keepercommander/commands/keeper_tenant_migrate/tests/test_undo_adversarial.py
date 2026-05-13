"""Undo adversarial + fuzz tests.

`undo` is the rollback safety net. A tampered / malformed / malicious
audit.log must not:

  - Crash the plugin (unhandled exception)
  - Cause silent no-op (operator thinks rollback happened)
  - Issue rogue reversals targeting wrong entities (lateral movement
    via audit injection)
  - Bypass chain-verification (refuses to undo when chain is broken)

Each test enumerates one attack or malformed-input scenario and
asserts the expected defense fires.
"""

import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.audit import append_audit_event
from keepercommander.commands.keeper_tenant_migrate.undo import (
    FakeUndoClient, IRREVERSIBLE, MANUAL, REVERSIBLE,
    UndoPlan, _invert_event, execute_plans, plan_undo, run,
)


# ── Category A — malformed / missing fields ─────────────────────────

class InvertEventRobustnessTests(unittest.TestCase):
    """_invert_event must tolerate every weird event shape without
    crashing. Unknown subcommands → MANUAL. Missing summary → empty
    reversal."""

    def test_missing_subcommand_key_is_manual(self):
        # No 'subcommand' key at all.
        plan = _invert_event({}, hard=False)
        self.assertEqual(plan.kind, MANUAL)
        self.assertIn('unknown', plan.notes.lower())

    def test_unknown_subcommand_is_manual(self):
        plan = _invert_event(
            {'subcommand': 'attacker-injected-subcmd'}, hard=False,
        )
        self.assertEqual(plan.kind, MANUAL)

    def test_users_with_missing_invited_emails_is_harmless(self):
        """No invited_emails key → no reversal ops, not a crash."""
        plan = _invert_event(
            {'subcommand': 'users', 'summary': {}},
            hard=False,
        )
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(plan.ops, [])

    def test_structure_with_missing_created_entities_produces_no_ops(self):
        plan = _invert_event(
            {'subcommand': 'structure', 'summary': {}},
            hard=False,
        )
        self.assertEqual(plan.kind, REVERSIBLE)
        self.assertEqual(plan.ops, [])

    def test_records_shares_with_non_dict_grant_filtered(self):
        """An attacker-crafted share_grants list could contain strings
        / null entries. _invert_event filters to dicts only."""
        plan = _invert_event(
            {'subcommand': 'records-shares', 'summary': {
                'share_grants': [
                    {'target_uid': 'ok', 'email': 'a@x'},
                    'not a dict',
                    None,
                    {'target_uid': 'also-ok', 'email': 'b@x'},
                ],
            }},
            hard=False,
        )
        self.assertEqual(plan.kind, REVERSIBLE)
        # Only the 2 valid dicts became ops.
        self.assertEqual(len(plan.ops), 2)

    def test_records_attachments_non_dict_uploads_filtered(self):
        plan = _invert_event(
            {'subcommand': 'records-attachments', 'summary': {
                'uploaded': [
                    {'target_uid': 'tg1', 'file_name': 'a.txt'},
                    12345,
                    'nope',
                ],
            }},
            hard=False,
        )
        self.assertEqual(len(plan.ops), 1)

    def test_cleanup_is_irreversible(self):
        plan = _invert_event({'subcommand': 'cleanup', 'summary': {}},
                              hard=False)
        self.assertEqual(plan.kind, IRREVERSIBLE)

    def test_decommission_is_irreversible(self):
        plan = _invert_event({'subcommand': 'decommission', 'summary': {}},
                              hard=False)
        self.assertEqual(plan.kind, IRREVERSIBLE)


# ── Category B — chain tamper refuses to undo ───────────────────────

class UndoRefusesOnBrokenChainTests(unittest.TestCase):
    """The chain-verify gate is the primary safety rail. If any prior
    entry was tampered with, undo must REFUSE to execute — it can't
    trust the plan it's about to reverse."""

    def test_run_returns_error_on_broken_chain(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {'invited_emails': ['a@x']}})
            append_audit_event(log, {'subcommand': 'structure',
                                      'summary': {
                                          'created_entities': {
                                              'nodes': ['MIGTEST-N'],
                                          }}})
            # Tamper line 1 — changes the hash chain.
            with open(log) as f:
                lines = f.read().splitlines()
            first = json.loads(lines[0])
            first['summary']['invited_emails'] = ['a@x', 'attacker@x']
            lines[0] = json.dumps(first)
            with open(log, 'w') as f:
                f.write('\n'.join(lines) + '\n')

            client = FakeUndoClient()
            result = run(log, client, execute=True)
            self.assertFalse(result.get('ok', True))
            self.assertEqual(result.get('reason'), 'chain_broken')
            # Critical: no ops were actually dispatched to the client.
            self.assertEqual(client.calls, [])


# ── Category C — execute_plans error handling ───────────────────────

class ExecutePlansTests(unittest.TestCase):
    def test_missing_client_method_is_counted_as_failure(self):
        """A plan may reference a verb the client doesn't implement
        (e.g., a newer version of the plugin than the client)."""
        plan = UndoPlan(
            event={'subcommand': 'users'},
            kind=REVERSIBLE,
            ops=[('nonexistent_method', ('a@x',))],
        )
        client = FakeUndoClient()
        summary = execute_plans([plan], client)
        self.assertEqual(summary['failed'], 1)
        self.assertEqual(summary['reversed'], 0)
        self.assertEqual(client.calls, [])   # no call attempted

    def test_client_raising_exception_counts_as_failure(self):
        """Transient network/server errors mid-undo must NOT halt the
        whole rollback. Log + count + continue."""

        class FlakyClient(FakeUndoClient):
            def lock_user(self, email):
                raise RuntimeError('network blip')

        plan = UndoPlan(
            event={'subcommand': 'users'},
            kind=REVERSIBLE,
            ops=[('lock_user', ('a@x',)),
                 ('lock_user', ('b@x',))],
        )
        client = FlakyClient()
        summary = execute_plans([plan], client)
        self.assertEqual(summary['failed'], 2)
        self.assertEqual(summary['reversed'], 0)

    def test_manual_plans_never_dispatch_ops(self):
        plan = UndoPlan(
            event={'subcommand': 'take-ownership'},
            kind=MANUAL, ops=[],
            notes='Run restore by hand.',
        )
        client = FakeUndoClient()
        summary = execute_plans([plan], client)
        self.assertEqual(summary['manual'], 1)
        self.assertEqual(client.calls, [])

    def test_irreversible_plans_never_dispatch_ops(self):
        plan = UndoPlan(
            event={'subcommand': 'cleanup'},
            kind=IRREVERSIBLE, ops=[],
        )
        client = FakeUndoClient()
        summary = execute_plans([plan], client)
        self.assertEqual(summary['irreversible'], 1)
        self.assertEqual(client.calls, [])


# ── Category D — injection via audit summary ────────────────────────

class AuditInjectionTests(unittest.TestCase):
    """The summary field is operator-supplied in places. An attacker
    who writes a crafted audit event must not be able to force undo
    to delete UNRELATED entities."""

    def test_structure_summary_cannot_reach_outside_tenant_scope(self):
        """A crafted structure event specifies nodes that the victim
        tenant cares about. Undo dispatches `delete_node(name)` for
        each — if the attacker put 'Production Root' in the list,
        can they force deletion? No — the client-side handles the
        actual write, and Commander's enterprise-node --delete
        requires the node to actually exist. But the plugin's job is
        to faithfully reflect the event. Regression guard: the plan
        must contain exactly the names in the summary, no more, no
        less, no escapes."""
        event = {
            'subcommand': 'structure',
            'summary': {'created_entities': {
                'nodes': ['MIGTEST-A', 'Production Root',
                           '../admin', '; rm -rf /',
                           'MIGTEST-B'],
            }},
        }
        plan = _invert_event(event, hard=False)
        names_in_ops = [args[0] for verb, args in plan.ops
                         if verb == 'delete_node']
        # Every name from the event flows through unchanged — the
        # plugin doesn't sanitize; Commander enforces tenant scope.
        # Regression test ensures we don't silently drop 'suspicious'
        # entries either (that would hide tampering).
        # Bug 18 — node deletes are emitted in REVERSE creation order
        # (children first) so dependent deletes don't fail. The set of
        # names is unchanged; only the order is flipped.
        self.assertEqual(names_in_ops, [
            'MIGTEST-B', '; rm -rf /', '../admin',
            'Production Root', 'MIGTEST-A',
        ])
        self.assertEqual(set(names_in_ops),
                          {'MIGTEST-A', 'Production Root',
                           '../admin', '; rm -rf /', 'MIGTEST-B'})
        # A tampered event like this should be caught by the chain-
        # verify gate BEFORE execute_plans runs. The defense is chain
        # integrity, not plan-layer input sanitization.

    def test_users_summary_with_non_string_emails_passes_through(self):
        """Non-string entries shouldn't be silently promoted into
        strings (that would be data laundering)."""
        event = {
            'subcommand': 'users',
            'summary': {'invited_emails': ['a@x', 123, None,
                                            {'nested': 'dict'}, 'b@x']},
        }
        plan = _invert_event(event, hard=False)
        # Every entry, even non-strings, flows through; the client
        # would then receive a non-string arg and fail. Surfaces as
        # an error, never silently passes.
        self.assertEqual(len(plan.ops), 5)


# ── Category E — plan_undo reversed-order guarantee ─────────────────

class PlanUndoOrderingTests(unittest.TestCase):
    """plan_undo walks the log in reverse. The order of returned
    plans must be the reverse of the events — critical so later
    mutations get undone before earlier ones (structure stays intact
    until its record/share dependents are gone)."""

    def test_plans_returned_in_reverse_event_order(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'structure',
                                      'summary': {
                                          'created_entities': {
                                              'nodes': ['N1']}}})
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {'invited_emails': ['u@x']}})
            append_audit_event(log, {'subcommand': 'records-shares',
                                      'summary': {'share_grants': [
                                          {'target_uid': 't1',
                                           'email': 'u@x'}]}})

            plans = plan_undo(log)
            # Returned in reverse: records-shares first, then users,
            # then structure — so shares are revoked before users
            # are locked, and users are locked before nodes deleted.
            subcommands = [p.event['subcommand'] for p in plans]
            self.assertEqual(subcommands,
                             ['records-shares', 'users', 'structure'])

    def test_up_to_signature_stops_walk(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'structure',
                                      'summary': {}})
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {}})
            append_audit_event(log, {'subcommand': 'records-shares',
                                      'summary': {'share_grants': []}})

            # Read the second event's signature so we can stop there.
            with open(log) as f:
                events = [json.loads(ln) for ln in f.read().splitlines()
                           if ln.strip()]
            users_sig = events[1].get('signature')
            self.assertIsNotNone(users_sig)

            plans = plan_undo(log, up_to_signature=users_sig)
            # Walk from newest (records-shares), stops BEFORE users.
            subcommands = [p.event['subcommand'] for p in plans]
            self.assertEqual(subcommands, ['records-shares'])


# ── Category F — malformed-audit-log fuzz ───────────────────────────

class MalformedLogFuzzTests(unittest.TestCase):
    """Audit log may be truncated mid-write, contain trailing garbage,
    or have empty lines. Behavior must be predictable."""

    def test_empty_log_returns_empty_plans(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            with open(log, 'w') as f:
                pass   # empty file
            plans = plan_undo(log)
            self.assertEqual(plans, [])

    def test_log_with_blank_lines_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'users',
                                      'summary': {}})
            # Add blank lines (simulates editor behavior).
            with open(log, 'a') as f:
                f.write('\n\n   \n')
            append_audit_event(log, {'subcommand': 'structure',
                                      'summary': {}})
            plans = plan_undo(log)
            # 2 valid events → 2 plans. Blank lines skipped.
            self.assertEqual(len(plans), 2)


if __name__ == '__main__':
    unittest.main()
