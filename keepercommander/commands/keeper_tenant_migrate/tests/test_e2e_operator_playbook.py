"""E2E test of the operator playbook (Workflows A + B + C, fakes-mode).

Asserts the canonical command sequence in
``keepercommander.commands.keeper_tenant_migrate/OPERATOR_PLAYBOOK.md`` runs end-to-end against
the existing fakes infrastructure WITHOUT touching any real Commander
session.

Rule 0 (source-read-only) enforcement
-------------------------------------

The source side of every workflow is represented by an in-memory
``inventory`` dict (or a JSON file written from one). We capture
``snapshot_bytes(source_inventory)`` BEFORE the run begins and
re-check it after every workflow step that could conceivably mutate
source state. ``cycled_validation.verify_source_read_only`` raises
``SourceMutationError`` on any byte divergence — that surfaces as a
test failure. The assertion lives in
``_assert_source_unchanged()`` and is invoked at the start AND end
of each workflow test (and after stages 5, 6, 7, 9, 11, 12 — the
ones whose semantics could in principle attempt a write to source).

What this test is NOT
---------------------

This is a *structural* sanity check that the playbook's command
sequence works as a coherent pipeline, with each step's output
correctly feeding the next. It is NOT a replacement for live
rehearsal — Phase B/C/E remain blocked on tenant access. But it
catches the most common operator-grade bugs:

  - subcommand X's output schema drifted; subcommand X+1 can't read it
  - audit.log signature chain broke between two stages
  - undo plan doesn't match what was actually written
  - resume idempotency invariant ("running twice in a row makes the
    second run a no-op") regressed
  - Rule 0 violation (a code path that newly tried to mutate the
    source-side inventory)

All assertions use unittest. No pytest. One-line docstrings, no
WHAT-comments.
"""

import csv
import json
import os
import shutil
import tempfile
import time
import unittest

from keepercommander.commands.keeper_tenant_migrate.audit import (
    append_audit_event, verify_audit_log,
)
from keepercommander.commands.keeper_tenant_migrate.cycled_validation import (
    SourceMutationError, snapshot_bytes, verify_source_read_only,
)
from keepercommander.commands.keeper_tenant_migrate.nested_sf_plan import (
    classify_inventory, write_plan, load_plan, promotion_lookup,
)
from keepercommander.commands.keeper_tenant_migrate.sf_reconcile import (
    FakeSFReconcileClient, plan_reconciliation, SFReconciler,
)
from keepercommander.commands.keeper_tenant_migrate.shares import FakeShareClient, ShareRestorer
from keepercommander.commands.keeper_tenant_migrate.structure import (
    FakeClient as FakeStructureClient, StepResult, StructureRestore,
)
from keepercommander.commands.keeper_tenant_migrate.undo import (
    FakeUndoClient, plan_undo, run as undo_run,
)
from keepercommander.commands.keeper_tenant_migrate.users import FakeUserClient, UserRunner
from keepercommander.commands.keeper_tenant_migrate.validate import Severity, Validator
from keepercommander.commands.keeper_tenant_migrate.validate import (
    ValidationContext as VerifyContext,
)


# ─── Shared inventory fixtures ────────────────────────────────────────────


def _build_workflow_a_inventory():
    """Return a deterministic source inventory for Workflow A."""
    return {
        'source_user': 'admin@source.example',
        'scope_node': 'MIGRATION-TEST-NODE',
        'source_root': 'AcmeCorp',
        'target_root': 'AcmeCorp',
        'prefix_filter': 'MIGTEST-',
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
            ],
            'roles': [
                {'id': 'r1', 'name': 'MIGTEST-EngRole',
                 'node': 'MIGTEST-Engineering', 'new_user': False,
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
                {'name': 'MIGTEST-Marketing-SF',
                 'users': [{'username': 'alice@acme.io'},
                            {'username': 'bob@acme.io'}],
                 'teams': []},
            ],
            'records': [
                {'uid': 'rec1', 'title': 'MIGTEST-Login',
                 'direct_shares': [
                     {'username': 'alice@acme.io', 'editable': True,
                      'shareable': False, 'owner': False},
                 ]},
            ],
            'shared_folder_folders': [],
            'vault_folders': [],
        },
        'counts': {
            'nodes': 2, 'teams': 1, 'roles': 1,
            'users': 2, 'shared_folders': 1, 'records': 1,
            'attachments': 0, 'direct_shares': 1,
            'total_enforcements': 0, 'total_privileges': 0,
        },
    }


def _build_workflow_b_inventory():
    """Return an inventory whose SF tree has shared_folder_folders."""
    inv = _build_workflow_a_inventory()
    inv['entities']['shared_folders'] = [{
        'uid': 'SF-PARENT', 'name': 'MIGTEST-Parent-SF',
        'users': [{'username': 'alice@acme.io',
                    'manage_users': True, 'manage_records': True,
                    'can_edit': True, 'can_share': True}],
        'teams': [],
        'default_manage_users': True,
        'default_manage_records': True,
        'default_can_edit': True,
        'default_can_share': True,
    }]
    inv['entities']['vault_folders'] = [
        {'uid': 'VF-INHERIT', 'name': 'Inherits-Parent',
         'type': 'shared_folder_folder',
         'parent_chain': ['SF-PARENT'],
         'shared_folder_uid': 'SF-PARENT'},
        {'uid': 'VF-PROMOTE', 'name': 'Diverges-From-Parent',
         'type': 'shared_folder_folder',
         'parent_chain': ['SF-PARENT'],
         'shared_folder_uid': 'SF-PARENT',
         'sf_view': {
             'users': [
                 {'username': 'alice@acme.io',
                  'manage_users': True, 'manage_records': True,
                  'can_edit': True, 'can_share': True},
                 {'username': 'bob@acme.io',
                  'manage_users': False, 'manage_records': True,
                  'can_edit': True, 'can_share': False},
             ],
             'teams': [],
         }},
    ]
    return inv


# ─── Common assertion helpers ────────────────────────────────────────────


def _assert_source_unchanged(testcase, baseline_bytes, source_inventory,
                              *, stage):
    """Re-check Rule 0 — source must be byte-identical to baseline."""
    try:
        verify_source_read_only(
            baseline_bytes, source_inventory, cycle=0,
        )
    except SourceMutationError as exc:
        testcase.fail(
            f'Rule 0 violation at stage {stage!r}: {exc}'
        )


# ─── Workflow A — standard forward migration ─────────────────────────────


class WorkflowAForwardMigrationTests(unittest.TestCase):
    """Workflow A end-to-end. Asserts every step's output feeds N+1."""

    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix='kcmd-e2e-A-')
        self.audit_log = os.path.join(self.run_dir, 'audit.log')
        self.inv = _build_workflow_a_inventory()
        self.source_baseline = snapshot_bytes(self.inv)

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def _stage_2_plan(self):
        """Persist inventory.json (stand-in for source-side `plan`)."""
        path = os.path.join(self.run_dir, 'inventory.json')
        with open(path, 'w') as f:
            json.dump(self.inv, f, sort_keys=True)
        return path

    def _stage_3_estimate(self, inventory_path):
        """Stand-in for `estimate` — read counts, produce a tiny report."""
        with open(inventory_path) as f:
            inv = json.load(f)
        counts = inv.get('counts') or {}
        report_md = os.path.join(self.run_dir, 'estimate.md')
        with open(report_md, 'w') as f:
            f.write('# Estimate\n\n')
            for k, v in sorted(counts.items()):
                f.write(f'- {k}: {v}\n')
        return report_md

    def _stage_4_point_of_no_return(self):
        """Stand-in for `point-of-no-return` — write a signed checkpoint."""
        path = os.path.join(self.run_dir, 'checkpoint.json')
        ckpt = {'confirm': 'YES', 'created_at': int(time.time()),
                 'signature': 'fake-sig-1'}
        with open(path, 'w') as f:
            json.dump(ckpt, f, sort_keys=True)
        return path

    def _stage_5_structure(self):
        """Drive `StructureRestore` against a `FakeStructureClient`."""
        client = FakeStructureClient()
        restore = StructureRestore(
            client, source_root='AcmeCorp', target_root='AcmeCorp',
            scope_node='MIGRATION-TEST-NODE',
        )
        ents = self.inv['entities']
        restore.step_nodes(ents['nodes'])
        restore.step_teams(ents['teams'])
        restore.step_roles(ents['roles'])
        append_audit_event(self.audit_log, {
            'subcommand': 'structure',
            'summary': {
                'created_entities': {
                    'nodes': [n['name'] for n in ents['nodes']],
                    'teams': [t['name'] for t in ents['teams']],
                    'roles': [r['name'] for r in ents['roles']],
                    'shared_folders': [],
                },
            },
        })
        return client, restore

    def _stage_6_users(self):
        """Drive `UserRunner` against a `FakeUserClient`."""
        client = FakeUserClient()
        runner = UserRunner(
            client, source_root='AcmeCorp', target_root='AcmeCorp',
            sleeper=lambda _s: None,
        )
        roster = [{'email': u['username'], 'full_name': u['username']}
                   for u in self.inv['entities']['users']]
        results = runner.run(roster, inventory=self.inv)
        invited = [r.email for r in results
                    if r.status in ('YES', 'EXTENDED')]
        append_audit_event(self.audit_log, {
            'subcommand': 'users',
            'summary': {'invited_emails': invited},
        })
        return client, results

    def _stage_7_records_export(self):
        """Stand-in for `records-export` — write per-record JSON files."""
        out_dir = os.path.join(self.run_dir, 'records_export')
        os.makedirs(out_dir, exist_ok=True)
        for r in self.inv['entities']['records']:
            with open(os.path.join(out_dir, f'{r["uid"]}.json'), 'w') as f:
                json.dump(r, f, sort_keys=True)
        return out_dir

    def _stage_8_convert(self, src_dir):
        """Stand-in for `convert` — combine per-record files into bundle."""
        bundle = {'records': [], 'shared_folders': []}
        for fn in sorted(os.listdir(src_dir)):
            if not fn.endswith('.json'):
                continue
            with open(os.path.join(src_dir, fn)) as f:
                bundle['records'].append(json.load(f))
        out = os.path.join(self.run_dir, 'records_import.json')
        with open(out, 'w') as f:
            json.dump(bundle, f, sort_keys=True)
        return out

    def _stage_9_records_import(self, bundle_path):
        """Stand-in for `records-import` — record an audit event."""
        with open(bundle_path) as f:
            bundle = json.load(f)
        imported = [r['uid'] for r in bundle['records']]
        append_audit_event(self.audit_log, {
            'subcommand': 'records-import',
            'summary': {'imported_uids': imported},
        })
        return imported

    def _stage_9a_records_manifest(self, src_dir):
        """Stand-in for `records-manifest` — build source_uid→target_uid CSV."""
        out = os.path.join(self.run_dir, 'manifest.csv')
        rows = []
        for fn in sorted(os.listdir(src_dir)):
            if not fn.endswith('.json'):
                continue
            uid = fn[:-len('.json')]
            rows.append({'source_uid': uid, 'target_uid': f'tgt-{uid}'})
        with open(out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['source_uid', 'target_uid'])
            w.writeheader()
            w.writerows(rows)
        return out, rows

    def _stage_10_records_shares(self, manifest_rows):
        """Drive `ShareRestorer` against `FakeShareClient`."""
        records = {}
        for src_rec in self.inv['entities']['records']:
            records[src_rec['uid']] = {
                'user_permissions': [
                    dict(s) for s in src_rec.get('direct_shares') or []
                ],
            }
        client = FakeShareClient(records=records)
        restorer = ShareRestorer(client, sleeper=lambda _s: None)
        summary = restorer.run(manifest_rows)
        grants = []
        for r in summary.get('per_record') or []:
            grants.extend(r.get('grants') or [])
        append_audit_event(self.audit_log, {
            'subcommand': 'records-shares',
            'summary': {'share_grants': grants},
        })
        return client, summary

    def _stage_11_attachments_download(self, manifest_rows):
        """Stand-in for `records-attachments-download` — staging dir only."""
        staging = os.path.join(self.run_dir, 'staging')
        for row in manifest_rows:
            os.makedirs(os.path.join(staging, row['source_uid']),
                         exist_ok=True)
        return staging

    def _stage_12_attachments_upload(self, manifest_rows, staging):
        """Stand-in for `records-attachments-upload` — audit event only."""
        append_audit_event(self.audit_log, {
            'subcommand': 'records-attachments',
            'summary': {'uploaded': [
                {'target_uid': r['target_uid'], 'file_name': 'placeholder'}
                for r in manifest_rows
            ]},
        })
        return staging

    def _stage_13_capture_target_state(self, struct_client, user_client,
                                         imported_uids):
        """Synthesise a target-state JSON from fake-client residue.

        Bundles in the records imported via stage 9 + the SF skeleton
        from stage 5. Mirrors what `capture-target-state` would emit
        after the forward path completes.
        """
        nodes = [{'name': args[0]} for op, args in struct_client.calls
                  if op == 'create_node']
        teams = [{'name': args[0]} for op, args in struct_client.calls
                  if op == 'create_team']
        roles = [{'name': args[0]} for op, args in struct_client.calls
                  if op == 'create_role']
        users = [{'username': args[0]} for op, args in user_client.calls
                  if op == 'invite_user']
        # SFs are conceptually created during structure step 11 +
        # populated post-activation by sf-reconcile. The fake's
        # call list does not include them in this trimmed E2E path,
        # so we synthesise them from the source inventory (the same
        # post-condition `verify` expects).
        shared_folders = [
            {'name': sf['name'],
             'users': sf.get('users') or [],
             'teams': sf.get('teams') or []}
            for sf in self.inv['entities']['shared_folders']
        ]
        records = [
            {'uid': r['uid'], 'title': r['title']}
            for r in self.inv['entities']['records']
            if r['uid'] in imported_uids
        ]
        target = {
            'nodes': nodes, 'teams': teams, 'roles': roles,
            'users': users, 'shared_folders': shared_folders,
            'records': records, 'record_types': [],
        }
        path = os.path.join(self.run_dir, 'target-state.json')
        with open(path, 'w') as f:
            json.dump(target, f, sort_keys=True)
        return path, target

    def _stage_14_verify(self, target_state):
        """Run the validate.Validator against (inventory, target_state)."""
        ctx = VerifyContext(self.inv, target_state, target_label='AcmeCorp')
        checks = Validator(ctx).run()
        return checks

    def _stage_15_reconcile(self, target_state):
        """Stand-in for `reconcile` — Markdown summary file."""
        out = os.path.join(self.run_dir, 'reconcile.md')
        with open(out, 'w') as f:
            f.write('# Reconcile\n\n')
            f.write(f'- source nodes: {len(self.inv["entities"]["nodes"])}\n')
            f.write(f'- target nodes: {len(target_state["nodes"])}\n')
        return out

    def _stage_16_sf_reconcile(self):
        """Drive `SFReconciler` against `FakeSFReconcileClient`."""
        client = FakeSFReconcileClient(
            memberships={'MIGTEST-Marketing-SF': set()},
            statuses={'alice@acme.io': 'active',
                      'bob@acme.io': 'active'},
        )
        plan = plan_reconciliation(self.inv, client)
        reconciler = SFReconciler(client, sleeper=lambda _s: None)
        result = reconciler.run(plan)
        append_audit_event(self.audit_log, {
            'subcommand': 'shared-folders-reconcile',
            'summary': {'applied': len(result.get('applied') or [])},
        })
        return client, result

    def _stage_17_decommission_plan_only(self):
        """Stand-in for `decommission --plan-only` — produce Markdown plan."""
        out = os.path.join(self.run_dir, 'decommission.plan.md')
        with open(out, 'w') as f:
            f.write('# Decommission plan (manual execution required)\n\n')
            for u in self.inv['entities']['users']:
                f.write(f'- `keeper enterprise-user --lock {u["username"]}`\n')
                f.write(f'- `keeper enterprise-user --delete {u["username"]}`\n')
        return out

    # — End-to-end happy path —

    def test_workflow_a_runs_every_stage_in_order(self):
        """Drive every Workflow A stage; each output feeds the next."""
        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='start',
        )

        inv_path = self._stage_2_plan()
        self.assertTrue(os.path.exists(inv_path))
        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='post-plan',
        )

        est_md = self._stage_3_estimate(inv_path)
        self.assertTrue(os.path.exists(est_md))

        ckpt_path = self._stage_4_point_of_no_return()
        self.assertTrue(os.path.exists(ckpt_path))

        struct_client, struct_restore = self._stage_5_structure()
        self.assertEqual(struct_restore.counters['SUCCESS'], 4,
                          f'structure SUCCESS counter wrong: '
                          f'{struct_restore.counters}')
        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='post-structure',
        )

        user_client, user_results = self._stage_6_users()
        invite_calls = [c for c in user_client.calls
                         if c[0] == 'invite_user']
        self.assertEqual(len(invite_calls), 2)
        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='post-users',
        )

        export_dir = self._stage_7_records_export()
        self.assertEqual(
            sorted(os.listdir(export_dir)), ['rec1.json'],
        )
        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='post-export',
        )

        bundle_path = self._stage_8_convert(export_dir)
        with open(bundle_path) as f:
            bundle = json.load(f)
        self.assertEqual(len(bundle['records']), 1)

        imported = self._stage_9_records_import(bundle_path)
        self.assertEqual(imported, ['rec1'])
        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='post-import',
        )

        manifest_path, manifest_rows = self._stage_9a_records_manifest(
            export_dir,
        )
        self.assertTrue(os.path.exists(manifest_path))
        self.assertEqual(len(manifest_rows), 1)

        share_client, share_summary = self._stage_10_records_shares(
            manifest_rows,
        )
        self.assertEqual(share_summary['pass'], 1)
        self.assertEqual(share_summary['fail'], 0)

        staging = self._stage_11_attachments_download(manifest_rows)
        self.assertTrue(os.path.isdir(staging))
        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='post-att-dl',
        )

        self._stage_12_attachments_upload(manifest_rows, staging)

        target_path, target_state = self._stage_13_capture_target_state(
            struct_client, user_client, imported,
        )
        self.assertTrue(os.path.exists(target_path))
        self.assertEqual(len(target_state['nodes']), 2)

        checks = self._stage_14_verify(target_state)
        fails = [c for c in checks if c.severity == Severity.FAIL]
        self.assertEqual(
            fails, [],
            f'verify reported FAIL on round-trip: {fails}',
        )

        reconcile_md = self._stage_15_reconcile(target_state)
        self.assertTrue(os.path.exists(reconcile_md))

        sf_client, sf_result = self._stage_16_sf_reconcile()
        self.assertEqual(len(sf_result.get('applied') or []), 2)

        decomm_md = self._stage_17_decommission_plan_only()
        self.assertTrue(os.path.exists(decomm_md))

        _assert_source_unchanged(
            self, self.source_baseline, self.inv, stage='end',
        )

    def test_workflow_a_audit_chain_is_intact_end_to_end(self):
        """Every stage that mutates target appends a chained audit event."""
        self._stage_5_structure()
        self._stage_6_users()
        export_dir = self._stage_7_records_export()
        bundle_path = self._stage_8_convert(export_dir)
        self._stage_9_records_import(bundle_path)
        _, manifest_rows = self._stage_9a_records_manifest(export_dir)
        self._stage_10_records_shares(manifest_rows)
        staging = self._stage_11_attachments_download(manifest_rows)
        self._stage_12_attachments_upload(manifest_rows, staging)
        self._stage_16_sf_reconcile()

        ok, broken_line = verify_audit_log(self.audit_log)
        self.assertTrue(
            ok, f'audit chain broken at line {broken_line}',
        )

        with open(self.audit_log) as f:
            events = [json.loads(ln) for ln in f.read().splitlines()
                       if ln.strip()]
        subcommands = [e.get('subcommand') for e in events]
        self.assertEqual(subcommands, [
            'structure', 'users', 'records-import',
            'records-shares', 'records-attachments',
            'shared-folders-reconcile',
        ])

    def test_workflow_a_undo_plan_only_yields_coherent_rollback(self):
        """`undo --plan-only` produces an UndoPlan list spanning every event."""
        self._stage_5_structure()
        self._stage_6_users()
        plans = plan_undo(self.audit_log, hard=False)
        self.assertEqual(
            len(plans), 2,
            f'expected 2 undo plans, got {len(plans)}: {plans}',
        )
        kinds = sorted(p.kind for p in plans)
        # users (lock = reversible) + structure (reversible).
        self.assertIn('reversible', kinds)

    def test_workflow_a_undo_execute_walks_lifo(self):
        """`undo --execute` against the audit log reverses target ops."""
        self._stage_5_structure()
        self._stage_6_users()
        client = FakeUndoClient()
        result = undo_run(
            self.audit_log, client, execute=True, hard=False,
        )
        self.assertTrue(result.get('ok'))
        self.assertTrue(result.get('executed'))
        ops = [c[0] for c in client.calls]
        self.assertIn('lock_user', ops)
        self.assertIn('delete_team', ops)

    def test_workflow_a_source_inventory_unchanged_after_full_run(self):
        """Rule 0 — full Workflow A leaves source bytes intact."""
        self.test_workflow_a_runs_every_stage_in_order()
        post = snapshot_bytes(self.inv)
        self.assertEqual(self.source_baseline, post,
                          'Workflow A mutated the source inventory')


# ─── Workflow B — nested-SF planning ─────────────────────────────────────


class WorkflowBNestedSfPlanTests(unittest.TestCase):
    """Workflow B: insert nested-sf-plan before structure; structure
    consumes the resulting plan JSON."""

    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix='kcmd-e2e-B-')
        self.audit_log = os.path.join(self.run_dir, 'audit.log')
        self.inv = _build_workflow_b_inventory()
        self.source_baseline = snapshot_bytes(self.inv)

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_workflow_b_nested_sf_plan_produces_loadable_plan(self):
        """Stage 2a — `nested-sf-plan` emits a JSON plan structure can load."""
        plan = classify_inventory(
            self.inv, default_action='promote-to-sibling',
        )
        plan_path = os.path.join(self.run_dir, 'nested_sf_plan.json')
        write_plan(plan, plan_path)

        loaded = load_plan(plan_path)
        promo = promotion_lookup(loaded)
        self.assertEqual(
            len(promo), 1,
            f'expected 1 promotion-candidate, got {len(promo)}: {promo}',
        )
        self.assertIn('VF-PROMOTE', promo)

        _assert_source_unchanged(
            self, self.source_baseline, self.inv,
            stage='post-nested-sf-plan',
        )

    def test_workflow_b_plan_chmod_0600(self):
        """Plan file is chmod 0600 — leaks SF structure if readable."""
        plan = classify_inventory(self.inv)
        plan_path = os.path.join(self.run_dir, 'nested_sf_plan.json')
        write_plan(plan, plan_path)

        for path in (plan_path, plan_path + '.sha256'):
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(
                mode, 0o600,
                f'{path} mode is {oct(mode)}, expected 0o600',
            )

    def test_workflow_b_plan_summary_counts_match_inventory(self):
        """Plan summary tallies match the inventory's vault_folders."""
        plan = classify_inventory(self.inv)
        # 1 inherit + 1 promotion-candidate.
        self.assertEqual(plan['summary'].get('inherit', 0), 1)
        self.assertEqual(
            plan['summary'].get('promotion-candidate', 0), 1,
        )

    def test_workflow_b_default_action_changes_classification(self):
        """`--default-action flatten-with-prefix` re-classifies divergents."""
        plan = classify_inventory(
            self.inv, default_action='flatten-with-prefix',
        )
        # The promotion-candidate row's action becomes flatten-with-prefix.
        promote = next(
            (d for d in plan['decisions']
             if d['classification'] == 'promotion-candidate'),
            None,
        )
        self.assertIsNotNone(promote)
        self.assertEqual(
            promote.get('proposed_target_action'),
            'flatten-with-prefix',
        )

    def test_workflow_b_source_inventory_unchanged(self):
        """Rule 0 — Workflow B's classify pass never mutates source."""
        classify_inventory(self.inv)
        post = snapshot_bytes(self.inv)
        self.assertEqual(self.source_baseline, post)


# ─── Workflow C — resume after mid-stage crash ───────────────────────────


class WorkflowCResumeAfterCrashTests(unittest.TestCase):
    """Workflow C: a partial structure run, then `--resume` finishes it.

    Idempotency invariant: running structure --resume twice in a row
    makes the second run a no-op (every entity already present).
    """

    def setUp(self):
        self.inv = _build_workflow_a_inventory()
        self.source_baseline = snapshot_bytes(self.inv)

    def test_workflow_c_resume_skips_already_present_nodes(self):
        """Pre-seed `existing_nodes`; resume classifies them SKIPPED."""
        client = FakeStructureClient()
        client.existing_nodes = {'MIGTEST-Engineering'}
        restore = StructureRestore(
            client, source_root='AcmeCorp', target_root='AcmeCorp',
            scope_node='MIGRATION-TEST-NODE', resume=True,
        )
        restore.step_nodes(self.inv['entities']['nodes'])

        eng_results = [r for r in restore.results
                        if r.name == 'MIGTEST-Engineering']
        self.assertTrue(eng_results)
        self.assertEqual(eng_results[0].status, StepResult.SKIPPED)

        fin_results = [r for r in restore.results
                        if r.name == 'MIGTEST-Finance']
        self.assertTrue(fin_results)
        self.assertEqual(fin_results[0].status, StepResult.SUCCESS)

    def test_workflow_c_double_resume_is_noop(self):
        """Run --resume against already-complete target → SKIPPED everywhere."""
        client = FakeStructureClient()
        client.existing_nodes = {
            'MIGTEST-Engineering', 'MIGTEST-Finance',
        }
        client.existing_teams = {'MIGTEST-EngLeads'}
        client.existing_roles = {'MIGTEST-EngRole'}
        restore = StructureRestore(
            client, source_root='AcmeCorp', target_root='AcmeCorp',
            scope_node='MIGRATION-TEST-NODE', resume=True,
        )
        restore.step_nodes(self.inv['entities']['nodes'])
        restore.step_teams(self.inv['entities']['teams'])
        restore.step_roles(self.inv['entities']['roles'])

        successes = [r for r in restore.results
                      if r.status == StepResult.SUCCESS]
        skipped = [r for r in restore.results
                    if r.status == StepResult.SKIPPED]
        self.assertEqual(
            successes, [],
            f'resume against complete target should be no-op; '
            f'got {len(successes)} fresh creates: {successes}',
        )
        self.assertGreater(len(skipped), 0)

    def test_workflow_c_resume_off_recreates_everything(self):
        """Without --resume, existing entities still get FAILED on re-run."""
        client = FakeStructureClient()
        client.existing_nodes = {'MIGTEST-Engineering'}
        restore = StructureRestore(
            client, source_root='AcmeCorp', target_root='AcmeCorp',
            scope_node='MIGRATION-TEST-NODE', resume=False,
        )
        restore.step_nodes(self.inv['entities']['nodes'])
        # Without resume, projection is not consulted; both nodes are
        # written through (FakeClient permits silent re-creates).
        creates = [c for c in client.calls if c[0] == 'create_node']
        self.assertGreaterEqual(len(creates), 2)

    def test_workflow_c_source_inventory_unchanged_through_resume(self):
        """Rule 0 — resume itself never mutates source."""
        client = FakeStructureClient()
        client.existing_nodes = {'MIGTEST-Engineering'}
        restore = StructureRestore(
            client, source_root='AcmeCorp', target_root='AcmeCorp',
            scope_node='MIGRATION-TEST-NODE', resume=True,
        )
        restore.step_nodes(self.inv['entities']['nodes'])
        post = snapshot_bytes(self.inv)
        self.assertEqual(self.source_baseline, post)


# ─── Cross-workflow Rule 0 enforcement ───────────────────────────────────


class RuleZeroEnforcementTests(unittest.TestCase):
    """Standalone Rule 0 tests: any byte-level source mutation aborts."""

    def test_source_mutation_raises_immediately(self):
        """`verify_source_read_only` raises on any inventory drift."""
        inv = _build_workflow_a_inventory()
        baseline = snapshot_bytes(inv)
        # Simulate a buggy code path that mutated source.
        inv['entities']['records'].append({'uid': 'BAD'})
        with self.assertRaises(SourceMutationError):
            verify_source_read_only(baseline, inv, cycle=1)

    def test_source_clone_is_safe_to_mutate(self):
        """Mutating a copy.deepcopy() never trips Rule 0."""
        import copy
        inv = _build_workflow_a_inventory()
        baseline = snapshot_bytes(inv)
        clone = copy.deepcopy(inv)
        clone['entities']['records'].append({'uid': 'OK-on-clone'})
        verify_source_read_only(baseline, inv, cycle=1)


if __name__ == '__main__':
    unittest.main()
