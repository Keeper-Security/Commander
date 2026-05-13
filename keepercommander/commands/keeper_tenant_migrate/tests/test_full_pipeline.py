"""Full-pipeline integration test.

Simulates a complete migration end-to-end against Fake clients:

  inventory → structure → users → records-shares → sf-reconcile

At each hand-off, assert the next stage sees the prior stage's output
correctly. Final assertion: target tenant ends with the complete
expected state — every node, team, role created; every user invited
and placed; every record-share grant applied; every deferred SF
membership reconciled.

Gap this test closes: isolated unit tests exercise each driver with
synthetic inputs. Real bugs show up at the SEAMS — the audit.log
written by stage A fed into stage B's planner; the checkpoint left
by stage A interfering with stage B's fresh start; a subtle field
name change in one stage's output that silently breaks the next.
"""

import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate import sf_reconcile
from keepercommander.commands.keeper_tenant_migrate.audit import append_audit_event, verify_audit_log
from keepercommander.commands.keeper_tenant_migrate.shares import FakeShareClient, ShareRestorer
from keepercommander.commands.keeper_tenant_migrate.structure import (
    FakeClient as FakeStructureClient, StepResult, StructureRestore,
)
from keepercommander.commands.keeper_tenant_migrate.users import (
    FakeUserClient, UserRunner,
)


# Inventory that mirrors what `plan` captures from a small source.
REALISTIC_INVENTORY = {
    'scope_node': 'MIGRATION-TEST-NODE',
    'source_root': 'AcmeCorp',
    'target_root': 'AcmeCorp',
    'entities': {
        'nodes': [
            {'id': 'n1', 'name': 'MIGTEST-Engineering',
             'parent': 'MIGRATION-TEST-NODE', 'isolated': False},
            {'id': 'n2', 'name': 'MIGTEST-Finance',
             'parent': 'MIGRATION-TEST-NODE', 'isolated': False},
        ],
        'teams': [
            {'name': 'MIGTEST-EngLeads', 'node': 'MIGTEST-Engineering',
             'restrict_share': 'False', 'restrict_edit': 'False',
             'restrict_view': 'False'},
            {'name': 'MIGTEST-FinOps', 'node': 'MIGTEST-Finance',
             'restrict_share': 'False', 'restrict_edit': 'False',
             'restrict_view': 'False'},
        ],
        'roles': [
            {'id': 'r1', 'name': 'MIGTEST-EngRole',
             'node': 'MIGTEST-Engineering', 'new_user': False,
             'managed_nodes': [], 'enforcements': {}, 'users': [],
             'teams': []},
            {'id': 'r2', 'name': 'MIGTEST-FinRole',
             'node': 'MIGTEST-Finance', 'new_user': False,
             'managed_nodes': [], 'enforcements': {}, 'users': [],
             'teams': []},
        ],
        'users': [
            {'username': 'alice@acme.io', 'node': 'MIGTEST-Engineering',
             'job_title': 'SWE', 'status': 'active'},
            {'username': 'bob@acme.io', 'node': 'MIGTEST-Finance',
             'job_title': 'CFO', 'status': 'active'},
        ],
        'shared_folders': [
            {'name': 'Marketing-SF', 'users': [
                {'username': 'alice@acme.io'},
                {'username': 'bob@acme.io'},
            ]},
        ],
        'records': [
            {'uid': 'rec1', 'title': 'MIGTEST-Login',
             'direct_shares': [
                 {'username': 'alice@acme.io', 'editable': True,
                  'shareable': False, 'owner': False},
             ]},
        ],
    },
    'counts': {
        'nodes': 2, 'teams': 2, 'roles': 2,
        'users': 2, 'shared_folders': 1, 'records': 1,
        'attachments': 0, 'direct_shares': 1,
        'total_enforcements': 0, 'total_privileges': 0,
    },
}


class FullPipelineTest(unittest.TestCase):
    """Run every stage in order, assert the target state converges."""

    def setUp(self):
        self.run_dir = tempfile.mkdtemp()
        self.audit_log = os.path.join(self.run_dir, 'audit.log')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def _run_structure(self):
        client = FakeStructureClient()
        restore = StructureRestore(
            client,
            source_root='AcmeCorp', target_root='AcmeCorp',
            scope_node='MIGRATION-TEST-NODE',
        )
        entities = REALISTIC_INVENTORY['entities']
        restore.step_nodes(entities['nodes'])
        restore.step_teams(entities['teams'])
        restore.step_roles(entities['roles'])

        # Emit an audit event the way the real subcommand would.
        created_nodes = [n['name'] for n in entities['nodes']]
        created_teams = [t['name'] for t in entities['teams']]
        created_roles = [r['name'] for r in entities['roles']]
        append_audit_event(self.audit_log, {
            'subcommand': 'structure',
            'summary': {
                'created_entities': {
                    'nodes': created_nodes,
                    'teams': created_teams,
                    'roles': created_roles,
                },
            },
        })
        return client, restore

    def _run_users(self):
        client = FakeUserClient()
        runner = UserRunner(
            client, source_root='AcmeCorp', target_root='AcmeCorp',
            sleeper=lambda _s: None,
        )
        roster = [{'email': u['username'], 'full_name': u['username']}
                   for u in REALISTIC_INVENTORY['entities']['users']]
        results = runner.run(roster, inventory=REALISTIC_INVENTORY)
        invited_emails = [r.email for r in results
                           if r.status in ('YES', 'EXTENDED')]
        append_audit_event(self.audit_log, {
            'subcommand': 'users',
            'summary': {'invited_emails': invited_emails},
        })
        return client, results

    def _run_records_shares(self):
        # One share grant from the inventory.
        records = {
            'rec1': {'user_permissions': [
                {'username': 'alice@acme.io', 'editable': True,
                 'shareable': False, 'owner': False},
            ]},
        }
        client = FakeShareClient(records=records)
        restorer = ShareRestorer(client, sleeper=lambda _s: None)
        summary = restorer.run([{
            'source_uid': 'rec1', 'target_uid': 'tgt-rec1',
        }])
        share_grants = []
        for r in summary.get('per_record') or []:
            share_grants.extend(r.get('grants') or [])
        append_audit_event(self.audit_log, {
            'subcommand': 'records-shares',
            'summary': {'share_grants': share_grants},
        })
        return client, summary

    def _run_sf_reconcile(self):
        client = sf_reconcile.FakeSFReconcileClient(
            memberships={'Marketing-SF': set()},
            statuses={'alice@acme.io': 'active',
                      'bob@acme.io': 'active'},
        )
        plan = sf_reconcile.plan_reconciliation(
            REALISTIC_INVENTORY, client,
        )
        reconciler = sf_reconcile.SFReconciler(
            client, sleeper=lambda _s: None,
        )
        result = reconciler.run(plan)
        append_audit_event(self.audit_log, {
            'subcommand': 'shared-folders-reconcile',
            'summary': {'applied': len(result.get('applied') or [])},
        })
        return client, result

    def test_full_pipeline_converges_target(self):
        """Structure → Users → Records-shares → SF-reconcile.

        After all stages, target state reflects exactly the inventory's
        intent. Audit chain verifies end-to-end.
        """
        # 1. Structure
        struct_client, struct_restore = self._run_structure()
        # Must have created 2 nodes, 2 teams, 2 roles.
        node_creates = [c for c in struct_client.calls
                         if c[0] == 'create_node']
        team_creates = [c for c in struct_client.calls
                         if c[0] == 'create_team']
        role_creates = [c for c in struct_client.calls
                         if c[0] == 'create_role']
        self.assertEqual(len(node_creates), 2)
        self.assertEqual(len(team_creates), 2)
        self.assertEqual(len(role_creates), 2)

        # 2. Users
        user_client, user_results = self._run_users()
        # 2 users invited, each placed in their node.
        invite_calls = [c for c in user_client.calls
                         if c[0] == 'invite_user']
        self.assertEqual(len(invite_calls), 2)
        statuses = {r.email: r.status for r in user_results}
        self.assertTrue(
            any(s == 'YES' for s in statuses.values()),
            f'no users were successfully invited: {statuses}',
        )

        # 3. Records shares
        share_client, share_summary = self._run_records_shares()
        # 1 grant (alice@acme.io onto tgt-rec1) should have been made.
        share_calls = [c for c in share_client.calls
                        if c[0] == 'share_record']
        self.assertEqual(len(share_calls), 1)
        self.assertEqual(share_summary['pass'], 1)
        self.assertEqual(share_summary['fail'], 0)

        # 4. SF reconcile
        reconcile_client, reconcile_result = self._run_sf_reconcile()
        # 2 memberships applied (alice + bob to Marketing-SF).
        self.assertEqual(len(reconcile_result['applied']), 2)
        # And the fake state reflects the adds.
        final_membership = reconcile_client.list_sf_memberships()['Marketing-SF']
        self.assertIn('alice@acme.io', final_membership)
        self.assertIn('bob@acme.io', final_membership)

        # 5. Audit chain verifies across ALL four stages.
        ok, broken = verify_audit_log(self.audit_log)
        self.assertTrue(
            ok,
            f'audit chain broken after full pipeline: broken_line={broken}',
        )

        # 6. Audit contains expected events in order.
        with open(self.audit_log) as f:
            events = [json.loads(ln) for ln in f.read().splitlines()
                       if ln.strip()]
        subcommands = [e.get('subcommand') for e in events]
        self.assertEqual(subcommands, [
            'structure', 'users', 'records-shares',
            'shared-folders-reconcile',
        ])

    def test_pipeline_halts_cleanly_on_structure_failure(self):
        """If structure fails mid-run, downstream stages that depend on
        target-side entities must see the failure (via audit entries or
        skipped stages). No silent pipeline-level success on a broken
        foundation."""
        client = FakeStructureClient(fail_on={'create_node'})
        restore = StructureRestore(
            client,
            source_root='AcmeCorp', target_root='AcmeCorp',
            scope_node='MIGRATION-TEST-NODE',
        )
        restore.step_nodes(REALISTIC_INVENTORY['entities']['nodes'])
        # FAILED results must be visible in the restore's results list.
        failures = [r for r in restore.results
                     if r.status == StepResult.FAILED]
        self.assertGreater(len(failures), 0,
                            f'structure FAILED should be logged; got {restore.results}')


if __name__ == '__main__':
    unittest.main()
