"""Integration tests for the offline-capable commands.py subcommands.

Live-tenant commands (structure, users) require authenticated params and
are exercised only via the ProtocolCompletenessTests in
test_commander_clients.py.

These tests drive execute() directly with synthetic fixtures on disk.
"""

import csv
import json
import os
import tempfile
import unittest

from unittest import mock

from keepercommander.commands.keeper_tenant_migrate.commands import (
    AssembleInventoryCommand,
    AuditLockoutRiskCommand,
    CaptureTargetStateCommand,
    ConvertCommand,
    PlanCommand,
    ReconcileCommand,
    RunCommand,
    StructureCommand,
    TransitionCheckCommand,
    VerifyCommand,
    _detect_target_root,
    _params_enterprise_to_target_state,
)


class DetectTargetRootTests(unittest.TestCase):
    def test_returns_displayname_of_root_node(self):
        class FakeParams:
            enterprise = {
                'nodes': [
                    {'data': {'displayname': 'Keeperdemo'}},   # no parent_id → root
                    {'data': {'displayname': 'Sub'}, 'parent_id': 1},
                ],
                'enterprise_name': 'Keeperdemo',
            }
        self.assertEqual(_detect_target_root(FakeParams()), 'Keeperdemo')

    def test_falls_back_to_enterprise_name_when_displayname_empty(self):
        class FakeParams:
            enterprise = {
                'nodes': [{'data': {}}],  # no parent_id → root, empty displayname
                'enterprise_name': 'Fallback-Name',
            }
        self.assertEqual(_detect_target_root(FakeParams()), 'Fallback-Name')

    def test_empty_enterprise_returns_empty(self):
        class FakeParams:
            enterprise = {}
        self.assertEqual(_detect_target_root(FakeParams()), '')


def _write_sample_inventory(path):
    inv = {
        'captured_at': '2026-04-18T12:00:00Z',
        'source_user': 'admin@src', 'source_root': 'My company',
        'target_user': 'admin@tgt', 'target_root': 'Keeperdemo',
        'counts': {'nodes': 1, 'teams': 1, 'roles': 0,
                   'users': 1, 'shared_folders': 0,
                   'records': 0, 'attachments': 0, 'direct_shares': 0},
        'entities': {
            'nodes': [{'name': 'MIGRATION-TEST-NODE', 'isolated': False}],
            'teams': [{'name': 'T1', 'restricts': ''}],
            'roles': [], 'users': [{'email': 'alice@x'}],
            'shared_folders': [], 'records': [],
        },
    }
    with open(path, 'w') as f:
        json.dump(inv, f)


class VerifyCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_execute_with_matching_target_state_passes(self):
        inv_path = os.path.join(self.tmp, 'inv.json')
        _write_sample_inventory(inv_path)
        target = {
            'nodes': [{'name': 'MIGRATION-TEST-NODE', 'isolated': False}],
            'teams': [{'name': 'T1', 'restricts': ''}],
            'roles': [],
            # Bug 42 — phase_users runs now; matching target must mirror
            # the source user or every run reports a FAIL here.
            'users': [{'email': 'alice@x', 'status': 'active'}],
            'shared_folders': [],
        }
        target_path = os.path.join(self.tmp, 'target.json')
        with open(target_path, 'w') as f:
            json.dump(target, f)
        csv_out = os.path.join(self.tmp, 'checks.csv')

        cmd = VerifyCommand()
        result = cmd.execute(None, inventory=inv_path, target_state=target_path, output=csv_out)

        self.assertEqual(result['counts']['FAIL'], 0)
        self.assertGreaterEqual(result['counts']['PASS'], 2)
        # CSV written
        self.assertTrue(os.path.exists(csv_out))
        with open(csv_out, newline='') as f:
            rows = list(csv.reader(f))
        self.assertEqual(rows[0], ['phase', 'severity', 'message', 'detail'])
        self.assertGreater(len(rows), 1)

    def test_execute_flags_missing_node(self):
        # verify now exits nonzero (raises CommandError) when checks
        # contain FAIL rows, instead of silently returning a dict the
        # caller had to inspect. Empty target → at least one FAIL →
        # raise. Artifacts (checks.csv if --output set, audit.log,
        # SHA256SUMS.txt) are written BEFORE the raise so post-mortem
        # is unaffected.
        from keepercommander.commands.base import CommandError
        inv_path = os.path.join(self.tmp, 'inv.json')
        _write_sample_inventory(inv_path)
        target = {'nodes': [], 'teams': [], 'roles': [], 'users': [], 'shared_folders': []}
        target_path = os.path.join(self.tmp, 'target.json')
        with open(target_path, 'w') as f:
            json.dump(target, f)

        cmd = VerifyCommand()
        with self.assertRaises(CommandError) as ctx:
            cmd.execute(None, inventory=inv_path, target_state=target_path, output=None)
        self.assertIn('FAIL row', str(ctx.exception))

    def test_warn_and_skip_do_not_raise(self):
        # WARN + SKIP rows are advisory; they MUST NOT trigger the
        # fail-loud raise. Use a no-op Validator that emits only WARN
        # rows to pin the contract: only Severity.FAIL counts.
        from unittest.mock import patch
        from keepercommander.commands.keeper_tenant_migrate import validate as _v

        inv_path = os.path.join(self.tmp, 'inv.json')
        _write_sample_inventory(inv_path)
        target = {
            'nodes': [{'name': 'MIGRATION-TEST-NODE', 'isolated': False}],
            'teams': [{'name': 'T1', 'restricts': ''}],
            'roles': [], 'users': [{'email': 'alice@x', 'status': 'active'}],
            'shared_folders': [],
        }
        target_path = os.path.join(self.tmp, 'target.json')
        with open(target_path, 'w') as f:
            json.dump(target, f)

        warn_only_checks = [
            _v.Check('manual', _v.Severity.WARN, 'advisory note', ''),
            _v.Check('manual', _v.Severity.SKIP, 'phase skipped', ''),
        ]
        with patch.object(_v.Validator, 'run',
                           return_value=warn_only_checks):
            result = VerifyCommand().execute(
                None, inventory=inv_path, target_state=target_path, output=None)
        self.assertEqual(result['counts']['FAIL'], 0)
        self.assertEqual(result['counts']['WARN'], 1)
        self.assertEqual(result['counts']['SKIP'], 1)


class StructureLoadFromInventoryTests(unittest.TestCase):
    """Bug 40 — `--inventory` mode must materialize record_types.json
    next to the inventory and thread the path into the load result so
    step_record_types creates custom enterprise types on target. Pre-fix
    the loader hardcoded `record_types_path=''` and step_record_types
    short-circuited."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_inv(self, **entities):
        ent = {'nodes': [], 'teams': [], 'roles': [], 'users': [],
               'shared_folders': [], 'records': []}
        ent.update(entities)
        path = os.path.join(self.tmp, 'inv.json')
        with open(path, 'w') as f:
            json.dump({'entities': ent}, f)
        return path

    def test_record_types_present_writes_sidecar(self):
        rts = [
            {'record_type_name': 'pamMachine', 'description': '',
             'fields': [{'$type': 'login'}]},
        ]
        inv_path = self._write_inv(record_types=rts)
        result = StructureCommand()._load_from_inventory(inv_path)
        self.assertTrue(result['record_types_path'])
        with open(result['record_types_path']) as f:
            payload = json.load(f)
        # Sidecar uses the wrapper shape Commander's loader consumes.
        self.assertEqual(payload, {'record_types': rts})

    def test_no_record_types_keeps_empty_path(self):
        inv_path = self._write_inv()  # no record_types in entities
        result = StructureCommand()._load_from_inventory(inv_path)
        self.assertEqual(result['record_types_path'], '')

    def test_empty_record_types_list_keeps_empty_path(self):
        # Source with no custom enterprise types — nothing to migrate.
        inv_path = self._write_inv(record_types=[])
        result = StructureCommand()._load_from_inventory(inv_path)
        self.assertEqual(result['record_types_path'], '')


class ReconcileCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_execute_writes_report_and_summary(self):
        inv_path = os.path.join(self.tmp, 'inv.json')
        _write_sample_inventory(inv_path)
        target = {
            'nodes': [{'name': 'MIGRATION-TEST-NODE'}],
            'teams': [{'name': 'T1'}], 'roles': [],
            'users': [], 'shared_folders': [],
        }
        target_path = os.path.join(self.tmp, 'target.json')
        with open(target_path, 'w') as f:
            json.dump(target, f)
        output = os.path.join(self.tmp, 'recon.md')

        cmd = ReconcileCommand()
        result = cmd.execute(None, inventory=inv_path, target_state=target_path, output=output)

        self.assertTrue(os.path.exists(output))
        self.assertEqual(len(result['summary']['deltas']['users']['missing']), 1)
        # Missing user is flagged in the Markdown report
        report = open(output).read()
        self.assertIn('Missing Users', report)


class ConvertCommandTests(unittest.TestCase):
    def test_execute_delegates_to_record_converter(self):
        # Use the existing fixtures dir
        fixtures = os.path.join(os.path.dirname(__file__), 'fixtures')
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as t:
            output = t.name
        try:
            cmd = ConvertCommand()
            result = cmd.execute(None, input_dir=fixtures, output=output,
                                 include_sf=False, split_by_type=False,
                                 compliance_csv=None, sf_json=None)
            self.assertGreater(result['records'], 0)
        finally:
            os.unlink(output)


class TransitionCheckCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_execute_with_roster_writes_both_outputs(self):
        roster = os.path.join(self.tmp, 'roster.csv')
        target_csv = os.path.join(self.tmp, 'target.csv')
        csv_out = os.path.join(self.tmp, 'plan.csv')
        md_out = os.path.join(self.tmp, 'plan.md')

        with open(roster, 'w') as f:
            f.write('email,name\nalice@x,Alice\nbob@x,Bob\n')
        with open(target_csv, 'w') as f:
            f.write('User ID,Email,Status\n1,alice@x,Active\n')

        cmd = TransitionCheckCommand()
        result = cmd.execute(None, inventory=None, roster=roster,
                             target_users_csv=target_csv, target_label='msp',
                             csv_output=csv_out, md_output=md_out)
        self.assertTrue(os.path.exists(csv_out))
        self.assertTrue(os.path.exists(md_out))
        self.assertEqual(result['tally']['A'], 1)  # bob@x is NEW
        self.assertEqual(result['tally']['D'], 1)  # alice@x is ALREADY_IN_TARGET


class ParamsEnterpriseToTargetStateTests(unittest.TestCase):
    def test_projects_nodes_teams_roles_users_sfs(self):
        class FakeParams:
            enterprise = {
                'enterprise_name': 'Keeperdemo',
                'nodes': [
                    {'node_id': 1, 'data': {}, 'parent_id': None},  # root
                    {'node_id': 2, 'data': {'displayname': 'Sub',
                                             'restrict_visibility': True},
                     'parent_id': 1},
                ],
                'teams': [
                    {'name': 'T1', 'restrict_edit': True,
                     'restrict_view': False, 'restrict_share': True},
                ],
                'roles': [
                    # new_user_inherit is where Commander actually stores
                    # the "default for new users" flag (data.default_role
                    # is unused).
                    {'role_id': 42, 'node_id': 2,
                     'new_user_inherit': True,
                     'data': {'displayname': 'R1'},
                     'enforcements': {'two_factor_required': True},
                     'managed_nodes': [{'cascade': True, 'privileges': ['MANAGE_USER']}],
                     'teams': [{'name': 'T1'}]},
                ],
                'users': [{'username': 'alice@x', 'node_id': 2, 'status': 'Active'}],
                'shared_folders': [{'name': 'SF1', 'default_can_edit': True}],
                'record_types': [{'content': {'$id': 'myType'}}],
            }

        state = _params_enterprise_to_target_state(FakeParams())
        self.assertEqual(state['nodes'][0]['name'], 'Keeperdemo')  # root falls back
        self.assertEqual(state['nodes'][1]['name'], 'Sub')
        self.assertTrue(state['nodes'][1]['isolated'])
        self.assertEqual(state['teams'][0]['restricts'], 'R S')
        self.assertEqual(state['roles'][0]['name'], 'R1')
        self.assertTrue(state['roles'][0]['default_role'])
        self.assertEqual(state['users'][0]['email'], 'alice@x')
        self.assertTrue(state['shared_folders'][0]['default_can_edit'])
        self.assertEqual(state['record_types'][0]['content']['$id'], 'myType')

    def test_empty_enterprise_returns_empty_shape(self):
        class FakeParams:
            enterprise = {}
        state = _params_enterprise_to_target_state(FakeParams())
        self.assertEqual(state['nodes'], [])
        self.assertEqual(state['teams'], [])
        self.assertEqual(state['roles'], [])


class CaptureTargetStateCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_execute_writes_json_file(self):
        class FakeParams:
            enterprise = {
                'enterprise_name': 'Keeperdemo',
                'nodes': [{'node_id': 1, 'data': {'displayname': 'Root'}}],
                'teams': [], 'roles': [], 'users': [], 'shared_folders': [],
            }

        output = os.path.join(self.tmp, 'state.json')
        cmd = CaptureTargetStateCommand()
        # Patch sync_down so we don't call Commander's real api.
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down',
                        return_value=True):
            cmd.execute(FakeParams(), output=output)
        self.assertTrue(os.path.exists(output))
        with open(output) as f:
            state = json.load(f)
        self.assertEqual(len(state['nodes']), 1)


class PlanCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_execute_captures_inventory_from_current_params(self):
        class FakeParams:
            user = 'admin@src'
            server = 'https://keepersecurity.eu'
            enterprise = {
                'enterprise_name': 'My company',
                'nodes': [
                    {'node_id': 1, 'data': {'displayname': 'My company'}, 'parent_id': None},
                    {'node_id': 2, 'data': {'displayname': 'MIGRATION-TEST-NODE'},
                     'parent_id': 1},
                ],
                'teams': [{'team_uid': 'T', 'name': 'MIGTEST-T', 'node_id': 2,
                           'restrict_edit': False, 'restrict_view': False,
                           'restrict_share': False}],
                'roles': [], 'users': [], 'shared_folders': [],
            }

        output = os.path.join(self.tmp, 'inv.json')
        cmd = PlanCommand()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down',
                        return_value=True):
            result = cmd.execute(FakeParams(), output=output,
                                 scope_node='MIGRATION-TEST-NODE',
                                 prefix='MIGTEST-', target_user='', target_root='')
        self.assertTrue(os.path.exists(output))
        self.assertTrue(os.path.exists(output + '.sha256'))
        self.assertEqual(result['counts']['teams'], 1)
        self.assertEqual(result['source_root'], 'My company')


class RunCommandTests(unittest.TestCase):
    """The orchestrator is exercised in test_orchestrator.py; here we verify the
    command wires stages to the right subcommands and halts cleanly when
    optional stages are skipped.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.inv_path = os.path.join(self.tmp, 'inv.json')
        _write_sample_inventory(self.inv_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _params(self):
        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {
                'enterprise_name': 'Keeperdemo',
                'nodes': [{'node_id': 1,
                           'data': {'displayname': 'Keeperdemo'}}],
                'teams': [], 'roles': [], 'users': [], 'shared_folders': [],
            }
            record_cache = {}
        return FakeParams()

    def test_run_executes_all_stages_with_stubbed_subcommands(self):
        # Patch each subcommand's execute to just record it ran — we're not
        # trying to test the real structure/users/verify/reconcile paths here,
        # only the orchestration layout.
        called = []

        def stub_execute(tag):
            def _stub(self, params, **kwargs):
                called.append(tag)
            return _stub

        patches = [
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.StructureCommand.execute',
                       stub_execute('structure')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.UsersCommand.execute',
                       stub_execute('users')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.CaptureTargetStateCommand.execute',
                       stub_execute('capture')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.VerifyCommand.execute',
                       stub_execute('verify')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.ReconcileCommand.execute',
                       stub_execute('reconcile')),
        ]
        for p in patches:
            p.start()
        try:
            out_dir = os.path.join(self.tmp, 'out')
            roster = os.path.join(self.tmp, 'roster.csv')
            with open(roster, 'w') as f:
                f.write('email,full_name\nalice@x,Alice\n')
            RunCommand().execute(
                self._params(),
                inventory=self.inv_path,
                roster=roster,
                transition_plan=None,
                source_root='My company', target_root='Keeperdemo',
                scope_node='', default_node='',
                output_dir=out_dir,
                resume=False, start_stage=None, end_stage=None,
            )
        finally:
            for p in patches:
                p.stop()

        # structure + users run once; verify + reconcile each trigger capture first
        self.assertIn('structure', called)
        self.assertIn('users', called)
        self.assertEqual(called.count('capture'), 2)
        self.assertIn('verify', called)
        self.assertIn('reconcile', called)

    def test_run_records_stage_chains_import_attachments_shares(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import (
            RecordsAttachmentsCommand, RecordsImportCommand,
            RecordsSharesCommand,
        )

        called = []

        def stub_execute(tag):
            def _stub(self, params, **kwargs):
                called.append(tag)
            return _stub

        out_dir = os.path.join(self.tmp, 'out')
        os.makedirs(out_dir, exist_ok=True)
        # Seed the run-dir with the bundle + manifest the stage looks for.
        with open(os.path.join(out_dir, 'records_import.json'), 'w') as f:
            f.write('{"records": []}')
        with open(os.path.join(out_dir, 'manifest.csv'), 'w') as f:
            f.write('source_uid,target_uid,status\nS1,T1,PAIRED\n')

        roster = os.path.join(self.tmp, 'roster.csv')
        with open(roster, 'w') as f:
            f.write('email,full_name\nalice@x,Alice\n')

        patches = [
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.StructureCommand.execute',
                       stub_execute('structure')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.UsersCommand.execute',
                       stub_execute('users')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.CaptureTargetStateCommand.execute',
                       stub_execute('capture')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.VerifyCommand.execute',
                       stub_execute('verify')),
            mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.ReconcileCommand.execute',
                       stub_execute('reconcile')),
            mock.patch.object(RecordsImportCommand, 'execute',
                               stub_execute('records-import')),
            mock.patch.object(RecordsAttachmentsCommand, 'execute',
                               stub_execute('records-attachments')),
            mock.patch.object(RecordsSharesCommand, 'execute',
                               stub_execute('records-shares')),
        ]
        for p in patches:
            p.start()
        try:
            RunCommand().execute(
                self._params(),
                inventory=self.inv_path,
                roster=roster,
                transition_plan=None,
                source_root='My company', target_root='Keeperdemo',
                scope_node='', default_node='',
                output_dir=out_dir,
                resume=False, start_stage=None, end_stage=None,
            )
        finally:
            for p in patches:
                p.stop()

        self.assertIn('records-import', called)
        self.assertIn('records-attachments', called)
        self.assertIn('records-shares', called)
        # Relative ordering: import must fire before attachments / shares
        self.assertLess(called.index('records-import'),
                         called.index('records-attachments'))
        self.assertLess(called.index('records-attachments'),
                         called.index('records-shares'))
        # Orchestrator wrote a results JSON
        self.assertTrue(os.path.exists(os.path.join(out_dir, 'orchestrator_results.json')))

    def test_run_without_roster_skips_users_stage(self):
        called = []

        def stub_execute(tag):
            def _stub(self, params, **kwargs):
                called.append(tag)
            return _stub

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.StructureCommand.execute',
                        stub_execute('structure')), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.UsersCommand.execute',
                        stub_execute('users')), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.CaptureTargetStateCommand.execute',
                        stub_execute('capture')), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.VerifyCommand.execute',
                        stub_execute('verify')), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.ReconcileCommand.execute',
                        stub_execute('reconcile')):
            out_dir = os.path.join(self.tmp, 'out_nouser')
            RunCommand().execute(
                self._params(),
                inventory=self.inv_path,
                roster=None, transition_plan=None,
                source_root='My company', target_root='Keeperdemo',
                scope_node='', default_node='',
                output_dir=out_dir,
                resume=False, start_stage=None, end_stage=None,
            )
        self.assertIn('structure', called)
        self.assertNotIn('users', called)


class DecommissionCheckpointGateTests(unittest.TestCase):
    """End-to-end: missing/expired/tampered checkpoint must block even in
    dry-run mode — regression for the silent-gate-bypass risk.
    """
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.roster = os.path.join(self.tmp, 'roster.csv')
        self.report = os.path.join(self.tmp, 'report.csv')
        with open(self.roster, 'w') as f:
            f.write('email\nalice@x\nbob@x\n')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_missing_checkpoint_blocks(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import DecommissionCommand
        cmd = DecommissionCommand()
        res = cmd.execute(
            None, roster=self.roster,
            checkpoint=os.path.join(self.tmp, 'no_such_checkpoint.json'),
            report_output=self.report, delay=0, max_age_hours=72,
            dry_run=True, dry_run_report='',
        )
        self.assertTrue(res['blocked'])
        self.assertFalse(os.path.exists(self.report))

    def test_expired_checkpoint_blocks(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import DecommissionCommand
        from keepercommander.commands.keeper_tenant_migrate.gate import write_checkpoint
        cp_path = os.path.join(self.tmp, 'cp.json')
        write_checkpoint({
            'timestamp': '2020-01-01T00:00:00Z',
            'checks_path': '', 'checks_summary': {}, 'reconcile_path': '',
        }, cp_path)
        res = DecommissionCommand().execute(
            None, roster=self.roster, checkpoint=cp_path,
            report_output=self.report, delay=0, max_age_hours=72,
            dry_run=True, dry_run_report='',
        )
        self.assertTrue(res['blocked'])
        self.assertIn('expired', res['reason'])


class AssembleInventoryCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Minimal staging dir
        with open(os.path.join(self.tmp, 'nodes.csv'), 'w') as f:
            f.write('1,"MIGRATION-TEST-NODE","My company",false,0,0,0\n')
        with open(os.path.join(self.tmp, 'teams.csv'), 'w') as f:
            f.write('')
        with open(os.path.join(self.tmp, 'users.csv'), 'w') as f:
            f.write('')
        with open(os.path.join(self.tmp, 'shared_folders.json'), 'w') as f:
            f.write('[]')
        os.makedirs(os.path.join(self.tmp, 'roles'))
        os.makedirs(os.path.join(self.tmp, 'records'))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_execute_writes_inventory_json_and_sidecar(self):
        output = os.path.join(self.tmp, 'inv.json')
        cmd = AssembleInventoryCommand()
        result = cmd.execute(None, input_dir=self.tmp, output=output,
                             prefix='MIGRATION-',
                             scope_node='MIGRATION-TEST-NODE',
                             source_user='admin@src', source_server='',
                             source_root='My company',
                             target_user='', target_root='')
        self.assertTrue(os.path.exists(output))
        self.assertTrue(os.path.exists(output + '.sha256'))
        self.assertEqual(result['counts']['nodes'], 1)


class AuditEventEmissionTests(unittest.TestCase):
    """Each destructive subcommand must stamp an audit event whose
    `summary` carries the data `tenant-migrate undo` needs to unwind
    the run. Without these fields undo finds nothing to roll back."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.inv_path = os.path.join(self.tmp, 'inv.json')
        _write_sample_inventory(self.inv_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _read_audit_events(self, path):
        events = []
        if not os.path.exists(path):
            return events
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def test_users_audit_emits_invited_emails(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import UsersCommand
        from keepercommander.commands.keeper_tenant_migrate.users import FakeUserClient

        roster = os.path.join(self.tmp, 'roster.csv')
        with open(roster, 'w') as f:
            f.write('email,full_name\nalice@x,Alice\nbob@x,Bob\n')

        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {'enterprise_name': 'Keeperdemo',
                           'nodes': [{'node_id': 1,
                                       'data': {'displayname': 'Keeperdemo'}}],
                           'users': [], 'teams': [], 'roles': []}
            record_cache = {}

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderUserClient',
                         return_value=FakeUserClient()), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'):
            UsersCommand().execute(
                FakeParams(),
                inventory=self.inv_path,
                roster=roster,
                source_root='My company',
                target_root='Keeperdemo',
                default_node='',
            )

        events = self._read_audit_events(os.path.join(self.tmp, 'audit.log'))
        self.assertEqual(len(events), 1)
        evt = events[0]
        self.assertEqual(evt['subcommand'], 'users')
        self.assertIn('invited_emails', evt['summary'])
        self.assertEqual(set(evt['summary']['invited_emails']),
                          {'alice@x', 'bob@x'})
        self.assertEqual(evt['summary']['counts']['invited'], 2)

    def test_records_shares_audit_emits_share_grants(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsSharesCommand

        manifest = os.path.join(self.tmp, 'manifest.csv')
        with open(manifest, 'w') as f:
            f.write('source_uid,target_uid,status\nS1,T1,PAIRED\n')

        from keepercommander.commands.keeper_tenant_migrate.shares import FakeShareClient
        share_client = FakeShareClient(records={
            'S1': {'user_permissions': [
                {'username': 'alice@x', 'editable': True, 'shareable': False,
                  'owner': False},
            ]},
        })

        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {}
            record_cache = {}

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderShareClient',
                         return_value=share_client), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'):
            RecordsSharesCommand().execute(
                FakeParams(),
                manifest=manifest,
                skip_missing_users=False,
            )

        events = self._read_audit_events(os.path.join(self.tmp, 'audit.log'))
        self.assertEqual(len(events), 1)
        evt = events[0]
        self.assertEqual(evt['subcommand'], 'records-shares')
        grants = evt['summary']['share_grants']
        self.assertEqual(grants, [{'target_uid': 'T1', 'email': 'alice@x'}])

    def test_records_import_audit_emits_imported_uids(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsImportCommand

        input_path = os.path.join(self.tmp, 'import.json')
        with open(input_path, 'w') as f:
            f.write('{"records": []}')

        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {}
            # Populate record_cache mid-import to simulate new UIDs landing.
            record_cache = {'preexisting': {}}

        fp = FakeParams()

        def fake_execute(self, params, **kwargs):
            # Simulate import landing two new records.
            params.record_cache['new1'] = {}
            params.record_cache['new2'] = {}

        with mock.patch('keepercommander.importer.commands.RecordImportCommand.execute',
                         fake_execute):
            RecordsImportCommand().execute(fp, input=input_path)

        events = self._read_audit_events(os.path.join(self.tmp, 'audit.log'))
        self.assertEqual(len(events), 1)
        evt = events[0]
        self.assertEqual(evt['subcommand'], 'records-import')
        self.assertEqual(sorted(evt['summary']['imported_uids']),
                          ['new1', 'new2'])

    def test_records_import_chunked_calls_execute_per_chunk(self):
        """Bug 68 (v1.6.2) — chunked import. When --chunk-size > 0
        the bundle is split and cmd.execute() is called once per
        chunk with `name` pointing at a per-chunk temp file. Mirrors
        pam-import's natural inter-call pacing for heavily-throttled
        tenants."""
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsImportCommand

        # 25 records, chunk_size=10 → 3 chunks (10+10+5).
        records = [{'title': f'R{i}', '$type': 'login'} for i in range(25)]
        input_path = os.path.join(self.tmp, 'import.json')
        with open(input_path, 'w') as f:
            json.dump({'records': records}, f)

        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {}
            record_cache = {}

        fp = FakeParams()
        executed_inputs = []

        def fake_execute(self, params, **kwargs):
            # Capture the per-chunk input file so we can assert
            # the chunking. Each call gets a unique temp path.
            executed_inputs.append(kwargs.get('name'))

        with mock.patch('keepercommander.importer.commands.RecordImportCommand.execute',
                         fake_execute):
            RecordsImportCommand().execute(
                fp, input=input_path,
                chunk_size=10, chunk_delay=0.0,  # no sleep in tests
            )

        self.assertEqual(len(executed_inputs), 3)
        # Each chunk's temp file should differ from the others +
        # from the original input.
        self.assertEqual(len(set(executed_inputs)), 3)
        for path in executed_inputs:
            self.assertNotEqual(path, input_path)

    def test_records_import_chunk_size_zero_runs_monolithic(self):
        """Bug 68 — chunk_size=0 (default) preserves the legacy
        monolithic single-call import."""
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsImportCommand

        input_path = os.path.join(self.tmp, 'import.json')
        with open(input_path, 'w') as f:
            json.dump({'records': [
                {'title': 'A'}, {'title': 'B'}, {'title': 'C'},
            ]}, f)

        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {}
            record_cache = {}

        executed_inputs = []

        def fake_execute(self, params, **kwargs):
            executed_inputs.append(kwargs.get('name'))

        with mock.patch('keepercommander.importer.commands.RecordImportCommand.execute',
                         fake_execute):
            RecordsImportCommand().execute(FakeParams(), input=input_path)

        # Monolithic: one call, original input path.
        self.assertEqual(len(executed_inputs), 1)
        self.assertEqual(executed_inputs[0], input_path)

    def test_records_references_rewrite_audit_writes_to_audit_log(self):
        """Bug 50: audit event must land at <run-dir>/audit.log,
        not <run-dir>/. Pre-fix the caller passed kwargs['run_dir']
        directly to append_audit_event, which then tried to
        open(<dir>, 'a') and raised IsADirectoryError. The broad
        except swallowed it as a non-fatal warning so every v1.5.1+
        records-references-rewrite event was silently dropped."""
        from keepercommander.commands.keeper_tenant_migrate.commands import (
            RecordsReferencesRewriteCommand,
        )

        manifest = os.path.join(self.tmp, 'manifest.csv')
        with open(manifest, 'w') as f:
            f.write('source_uid,target_uid,title\nS1,T1,Rec1\n')

        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {}
            record_cache = {}

        # Mock the rewriter so we exercise the audit-write path
        # without needing a live Commander session or real records.
        clean_result = {
            'records_inspected': 1, 'records_with_refs': 0,
            'records_rewritten': 0, 'refs_remapped': 0,
            'refs_unknown': 0, 'refs_empty': 0,
            'load_failures': 0, 'persist_failures': 0,
            'rewritten_uids': [], 'failed_uids': [],
        }
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'), \
             mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commander_clients.'
                'CommanderRecordReferenceClient'), \
             mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.references_rewrite.ReferencesRewriter'
             ) as Rewriter:
            Rewriter.return_value.run.return_value = clean_result
            RecordsReferencesRewriteCommand().execute(
                FakeParams(),
                manifest=manifest,
                run_dir=self.tmp,
                dry_run=False,
            )

        audit_log = os.path.join(self.tmp, 'audit.log')
        self.assertTrue(os.path.isfile(audit_log),
                        'Bug 50: audit event must land at '
                        '<run-dir>/audit.log as a file')
        self.assertGreater(os.path.getsize(audit_log), 0,
                           'audit.log was created but empty')
        events = self._read_audit_events(audit_log)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['subcommand'],
                         'records-references-rewrite')

    # ---------------- Phase 2 Commit 1: 5 destructive verbs ----------------
    # cleanup / transfer-user / take-ownership-restore / undo /
    # point-of-no-return previously executed without writing a chain
    # entry. The audit chain is the tamper-evident record of what
    # mutated the tenant — silent destructive ops are the worst-case
    # failure mode for `audit-verify` and for `undo`. These regressions
    # fail-CLOSED if the emission is ever stripped.

    def _fake_target_params(self):
        class FakeParams:
            user = 'admin@tgt'
            server = 'https://tgt'
            enterprise = {'enterprise_name': 'Keeperdemo'}
            session_token = 'fake'
            record_cache = {}
        return FakeParams()

    def test_cleanup_emits_audit_event(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import CleanupCommand

        run_dir = self.tmp
        params = self._fake_target_params()
        fake_summary = {'teams': 1, 'roles': 2, 'nodes': 0,
                         'records': 0, 'errors': 0}

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commands._enforce_source_mode_from_kwargs'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderCleanupClient'
        ) as cc, mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.cleanup.cleanup', return_value=fake_summary
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.cleanup.matching_entities',
            return_value={'teams': [], 'roles': [], 'nodes': []},
        ):
            cc.return_value.list_entities.return_value = {
                'teams': [], 'roles': [], 'nodes': []}
            CleanupCommand().execute(
                params,
                prefix='MIGTEST-',
                yes=True, confirm=True,
                batch_cap=50, override_batch_cap=False,
                expected_tenant_name='Keeperdemo',
                run_dir=run_dir,
                confirm_source_destructive=True,
                dry_run=False,
            )

        events = self._read_audit_events(os.path.join(run_dir, 'audit.log'))
        self.assertEqual(len(events), 1,
                         'cleanup must emit exactly one audit event')
        evt = events[0]
        self.assertEqual(evt['subcommand'], 'cleanup')
        self.assertEqual(evt['inputs']['prefix'], 'MIGTEST-')
        self.assertEqual(evt['summary']['teams_deleted'], 1)
        self.assertEqual(evt['summary']['roles_deleted'], 2)

    def test_transfer_user_emits_audit_event(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import TransferUserCommand

        run_dir = self.tmp
        readiness = os.path.join(run_dir, 'readiness.csv')
        with open(readiness, 'w') as f:
            f.write('email,status\nalice@x,READY_TRANSFER\n'
                    'bob@x,READY_TRANSFER\n')
        params = self._fake_target_params()
        fake_summary = {'total': 2, 'transferred': 2,
                         'skipped': 0, 'errors': 0}

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commands._enforce_source_mode_from_kwargs'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderTransferUserClient'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.transfer_user.process_users',
            return_value=fake_summary,
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.checkpoint.Checkpoint'
        ):
            TransferUserCommand().execute(
                params,
                admin_email='admin@tgt',
                readiness_report=readiness,
                report_output=os.path.join(run_dir, 'transfer-report.csv'),
                yes=True,
                batch_cap=50, override_batch_cap=False,
                expected_tenant_name='Keeperdemo',
                run_dir=run_dir,
                confirm_source_destructive=True,
                dry_run=False,
            )

        events = self._read_audit_events(os.path.join(run_dir, 'audit.log'))
        emit = [e for e in events if e['subcommand'] == 'transfer-user']
        self.assertEqual(len(emit), 1,
                         'transfer-user must emit exactly one audit event')
        evt = emit[0]
        self.assertEqual(evt['inputs']['admin_email'], 'admin@tgt')
        self.assertEqual(evt['summary']['transferred'], 2)

    def test_take_ownership_restore_emits_audit_event(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import TakeOwnershipRestoreCommand

        run_dir = self.tmp
        report = os.path.join(run_dir, 'ownership-report.csv')
        with open(report, 'w') as f:
            f.write('record_uid,owner_email\nU1,alice@x\n')
        params = self._fake_target_params()
        fake_result = {'restored': 1, 'skipped': 0, 'errors': 0}

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderRestoreClient'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.take_ownership_restore.restore',
            return_value=fake_result,
        ):
            TakeOwnershipRestoreCommand().execute(
                params,
                report=report,
                run_dir=run_dir,
                dry_run=False,
            )

        events = self._read_audit_events(os.path.join(run_dir, 'audit.log'))
        emit = [e for e in events if e['subcommand']
                == 'take-ownership-restore']
        self.assertEqual(len(emit), 1,
                         'take-ownership-restore must emit one audit event')
        self.assertEqual(emit[0]['summary']['restored'], 1)

    def test_point_of_no_return_emits_audit_event(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import PointOfNoReturnCommand

        run_dir = self.tmp
        checks = os.path.join(run_dir, 'checks.csv')
        with open(checks, 'w') as f:
            f.write('phase,status\nstructure,PASS\n')
        ckpt = os.path.join(run_dir, 'checkpoint.json')
        params = self._fake_target_params()
        fake_checkpoint = {'timestamp': '2026-05-10T12:00:00Z',
                           'verdict': 'PASS'}

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.gate.evaluate',
            return_value=fake_checkpoint,
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.gate.write_checkpoint',
            return_value=fake_checkpoint,
        ):
            PointOfNoReturnCommand().execute(
                params,
                checks=checks,
                checkpoint=ckpt,
                run_dir=run_dir,
                confirm='I-UNDERSTAND',
            )

        events = self._read_audit_events(os.path.join(run_dir, 'audit.log'))
        emit = [e for e in events if e['subcommand'] == 'point-of-no-return']
        self.assertEqual(len(emit), 1,
                         'point-of-no-return must emit one audit event')
        evt = emit[0]
        self.assertTrue(evt['summary']['passed'])
        self.assertEqual(evt['summary']['checkpoint_timestamp'],
                         '2026-05-10T12:00:00Z')

    def test_undo_emits_audit_event_to_separate_log(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import UndoCommand

        run_dir = self.tmp
        source_audit = os.path.join(run_dir, 'audit.log')
        # Seed the source audit log so it exists (undo reads from it).
        with open(source_audit, 'w') as f:
            f.write('')
        params = self._fake_target_params()
        fake_result = {'reversed': 3, 'skipped': 0, 'errors': 0}

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderUndoClient'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.undo.run', return_value=fake_result,
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.safeguards.banner_for'
        ):
            UndoCommand().execute(
                params,
                audit_log=source_audit,
                hard=False,
                execute=True,
                yes=True,
            )

        # Undo writes to a SEPARATE log so it doesn't corrupt the chain
        # it just consumed. Default location: audit.undo.log alongside.
        undo_log = os.path.join(run_dir, 'audit.undo.log')
        self.assertTrue(os.path.isfile(undo_log),
                        'undo must write to audit.undo.log (not the '
                        'source audit.log being unwound)')
        events = self._read_audit_events(undo_log)
        emit = [e for e in events if e['subcommand'] == 'undo']
        self.assertEqual(len(emit), 1,
                         'undo must emit one self-recording event')
        self.assertEqual(emit[0]['inputs']['source_audit_log'], source_audit)
        self.assertFalse(emit[0]['inputs']['hard'])
        self.assertTrue(emit[0]['inputs']['execute'])
        self.assertEqual(emit[0]['summary']['reversed'], 3)
        # --mc absent → empty-string default (proves the field is in
        # the chain so audit-verify can correlate undo events with the
        # original MC-scoped operations).
        self.assertIn('mc', emit[0]['inputs'])
        self.assertEqual(emit[0]['inputs']['mc'], '')

    def test_undo_threads_mc_flag_through_to_audit_inputs(self):
        """Phase 2 Audit 3 #5: undo accepts --mc so reversal stays
        scoped to the same Managed Company the original events ran
        under. MCContext wraps the mutation; the chain entry records
        the MC name for downstream correlation."""
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import UndoCommand

        run_dir = self.tmp
        source_audit = os.path.join(run_dir, 'audit.log')
        with open(source_audit, 'w') as f:
            f.write('')
        params = self._fake_target_params()
        fake_result = {'reversed': 1, 'skipped': 0, 'errors': 0}

        # MCContext yields its `params` arg as ctx.params when the MC
        # name is empty AND a synthetic MC-scoped params object when
        # set. Patching it lets us assert undo_run sees the scoped
        # params without standing up a full Commander session.
        captured_params = []
        def fake_undo_run(audit_log, client, **kw):
            captured_params.append(client)
            return fake_result

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderUndoClient'
        ) as cc, mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.undo.run',
            side_effect=fake_undo_run,
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.safeguards.banner_for'
        ):
            UndoCommand().execute(
                params,
                audit_log=source_audit,
                hard=False, execute=True, yes=True,
                mc='AcmeMC',
            )
            # CommanderUndoClient was called with the MC-scoped params
            # rather than the raw params object.
            self.assertEqual(cc.call_count, 1)

        undo_log = os.path.join(run_dir, 'audit.undo.log')
        events = self._read_audit_events(undo_log)
        emit = [e for e in events if e['subcommand'] == 'undo']
        self.assertEqual(len(emit), 1)
        self.assertEqual(emit[0]['inputs']['mc'], 'AcmeMC',
                         'undo must record --mc in the chain entry so '
                         'audit-verify can correlate the reversal with '
                         'the MC-scoped originals')

    # ---------- audit-emission LOCATION regressions ----------
    # Phase 2 audit-emission follow-up (2026-05-11): records-export +
    # take-ownership were emitting their chain entries to sub-
    # directories (records_export/audit.log and backup_dir/audit.log
    # respectively), fragmenting the chain that audit-verify walks.
    # Both must now land the chain event at <run_dir>/audit.log per
    # the published contract (dsk_hooks.py:20, OUTPUT_CONTRACT.md:35).
    # These regressions fail-CLOSED if the location ever drifts back.

    def test_records_export_writes_audit_event_to_top_level_run_dir(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsExportCommand

        run_dir = self.tmp
        output_dir = os.path.join(run_dir, 'records_export')
        params = self._fake_target_params()

        # Patch the heavy lifting — we only care about audit-event
        # placement, not the export mechanics.
        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'
        ), mock.patch(
            'keepercommander.api.get_record', return_value=None
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commands._build_folder_path_index',
            return_value={},
        ):
            RecordsExportCommand().execute(
                params,
                output_dir=output_dir,
                run_dir=run_dir,
                prefix='',
            )

        top_audit = os.path.join(run_dir, 'audit.log')
        sub_audit = os.path.join(output_dir, 'audit.log')
        events_top = self._read_audit_events(top_audit)
        events_sub = self._read_audit_events(sub_audit)
        emit_top = [e for e in events_top
                    if e.get('subcommand') == 'records-export']
        self.assertEqual(len(emit_top), 1,
                         'records-export must emit ONE chain entry at '
                         '<run_dir>/audit.log per the published '
                         'contract; got %d at %s' %
                         (len(emit_top), top_audit))
        self.assertEqual(
            [e for e in events_sub
             if e.get('subcommand') == 'records-export'], [],
            'records-export must NOT write the chain entry to '
            '<output_dir>/audit.log — that fragments the chain. '
            'SHA256SUMS sidecar in output_dir is fine; chain event '
            'is not.')

    def test_records_export_fallback_uses_parent_of_output_dir(self):
        """Standalone invocation (no run_dir kwarg, no audit_log kwarg):
        the new fallback uses parent-of-output_dir so the chain event
        still lands at the natural top-level even without an explicit
        run_dir hint."""
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsExportCommand

        # Build a synthetic 2-level layout: top/sub
        top = self.tmp
        output_dir = os.path.join(top, 'records_export')
        params = self._fake_target_params()

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'
        ), mock.patch(
            'keepercommander.api.get_record', return_value=None
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commands._build_folder_path_index',
            return_value={},
        ):
            RecordsExportCommand().execute(
                params,
                output_dir=output_dir,
                prefix='',
                # NB: no run_dir, no audit_log
            )

        # Audit chain event lands at parent-of-output_dir (= top),
        # NOT inside output_dir.
        events_top = self._read_audit_events(
            os.path.join(top, 'audit.log'))
        events_sub = self._read_audit_events(
            os.path.join(output_dir, 'audit.log'))
        self.assertEqual(
            len([e for e in events_top
                 if e.get('subcommand') == 'records-export']), 1,
            'fallback must put chain entry at parent-of-output_dir')
        self.assertEqual(
            [e for e in events_sub
             if e.get('subcommand') == 'records-export'], [],
            'fallback must NOT put chain entry inside output_dir')

    def test_phase8_users_prefers_run_dir_over_dirname_inventory(self):
        """Phase 8 unified fallback: when both `run_dir` and `inventory`
        are supplied AND they live in DIFFERENT directories, the audit
        chain event must land at <run_dir>/audit.log — NOT at
        <dirname(inventory)>/audit.log. Pre-Phase-8 the dirname fallback
        was the only path; this regression locks the priority order."""
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import UsersCommand
        from keepercommander.commands.keeper_tenant_migrate.users import FakeUserClient

        # Two distinct directories: run_dir at top-level, inventory in
        # a sibling subdir. If the code regresses to dirname(inventory),
        # the chain event would land in the wrong place.
        run_dir = self.tmp
        sibling = os.path.join(self.tmp, 'sibling-input-dir')
        os.makedirs(sibling, exist_ok=True)
        inv_path = os.path.join(sibling, 'inv.json')
        _write_sample_inventory(inv_path)
        roster = os.path.join(sibling, 'roster.csv')
        with open(roster, 'w') as f:
            f.write('email,full_name\nalice@x,Alice\n')

        class FakeParams:
            user = 'admin@tgt'
            server = 'https://x'
            enterprise = {'enterprise_name': 'Keeperdemo',
                           'nodes': [{'node_id': 1,
                                       'data': {'displayname': 'Keeperdemo'}}],
                           'users': [], 'teams': [], 'roles': []}
            record_cache = {}

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderUserClient',
                         return_value=FakeUserClient()), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'):
            UsersCommand().execute(
                FakeParams(),
                inventory=inv_path,
                roster=roster,
                source_root='My company',
                target_root='Keeperdemo',
                default_node='',
                run_dir=run_dir,
            )

        # run_dir branch must win
        events_top = self._read_audit_events(
            os.path.join(run_dir, 'audit.log'))
        events_sibling = self._read_audit_events(
            os.path.join(sibling, 'audit.log'))
        emit_top = [e for e in events_top if e['subcommand'] == 'users']
        self.assertEqual(len(emit_top), 1,
                         'Phase 8: run_dir branch must win — chain '
                         'entry at <run_dir>/audit.log')
        self.assertEqual(
            [e for e in events_sibling if e['subcommand'] == 'users'], [],
            'Phase 8: regression — chain entry must NOT land at '
            'dirname(inventory) when run_dir is provided')

    def test_take_ownership_writes_audit_event_to_top_level_run_dir(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commands import TakeOwnershipCommand

        run_dir = self.tmp
        backup_dir = os.path.join(run_dir, 'backup')
        os.makedirs(backup_dir, exist_ok=True)
        # Seed a stub backup file so the chmod loop + sha256 path
        # has something to walk.
        with open(os.path.join(backup_dir, 'stub.json'), 'w') as f:
            f.write('{}')
        verification_report = os.path.join(run_dir, 'verification.csv')
        with open(verification_report, 'w') as f:
            f.write('email,status\nalice@x,READY\n')
        report_output = os.path.join(run_dir, 'take-ownership-report.csv')
        params = self._fake_target_params()
        fake_summary = {'total': 1, 'backups': 1,
                         'ownerships': 1, 'errors': 0}

        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commands._enforce_source_mode_from_kwargs'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.CommanderOwnershipClient'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.take_ownership.process_users',
            return_value=fake_summary,
        ), mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.checkpoint.Checkpoint'
        ):
            TakeOwnershipCommand().execute(
                params,
                admin_email='admin@tgt',
                verification_report=verification_report,
                backup_dir=backup_dir,
                report_output=report_output,
                run_dir=run_dir,
                yes=True,
                expected_tenant_name='Keeperdemo',
                confirm_source_destructive=True,
                dry_run=False,
            )

        top_audit = os.path.join(run_dir, 'audit.log')
        sub_audit = os.path.join(backup_dir, 'audit.log')
        events_top = self._read_audit_events(top_audit)
        events_sub = self._read_audit_events(sub_audit)
        emit_top = [e for e in events_top
                    if e.get('subcommand') == 'take-ownership']
        self.assertEqual(len(emit_top), 1,
                         'take-ownership must emit ONE chain entry at '
                         '<run_dir>/audit.log per the published '
                         'contract; got %d at %s' %
                         (len(emit_top), top_audit))
        self.assertEqual(
            [e for e in events_sub
             if e.get('subcommand') == 'take-ownership'], [],
            'take-ownership must NOT write the chain entry to '
            '<backup_dir>/audit.log — that fragments the chain.')


class VerifySha256SumsTests(unittest.TestCase):
    """Regression: VerifyCommand.execute must write a run-dir-wide
    SHA256SUMS.txt manifest. Without it, audit-verify has nothing to
    validate and reports ok=False forever."""

    def test_verify_writes_manifest_at_run_dir(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import VerifyCommand

        with tempfile.TemporaryDirectory() as run_dir:
            inv_path = os.path.join(run_dir, 'inv.json')
            ts_path = os.path.join(run_dir, 'target_state.json')
            out_path = os.path.join(run_dir, 'checks.csv')
            _write_sample_inventory(inv_path)
            with open(ts_path, 'w') as f:
                json.dump({'nodes': [], 'teams': [], 'roles': [],
                            'users': [], 'shared_folders': [],
                            'records': [], 'record_types': [],
                            'server': 'https://x', 'data_center': 'EU'}, f)

            class FakeParams:
                user = 'admin@tgt'
                server = 'https://x'
                enterprise = {'enterprise_name': 'Acme',
                               'nodes': [], 'users': [],
                               'teams': [], 'roles': []}
                record_cache = {}

            # Verify now raises CommandError on FAIL rows but still
            # writes the SHA256SUMS.txt manifest BEFORE raising.
            from keepercommander.commands.base import CommandError
            try:
                VerifyCommand().execute(
                    FakeParams(),
                    inventory=inv_path,
                    target_state=ts_path,
                    output=out_path,
                )
            except CommandError:
                pass  # FAIL rows expected against this synthetic target
            manifest = os.path.join(run_dir, 'SHA256SUMS.txt')
            self.assertTrue(
                os.path.exists(manifest),
                'Verify did not emit SHA256SUMS.txt; audit-verify would fail')
            # audit.log must be excluded (self-referential hash would be stale)
            with open(manifest) as f:
                content = f.read()
            self.assertNotIn('audit.log', content)


class RecordsImportPermissionsDefaultTests(unittest.TestCase):
    """Regression: RecordsImportCommand must pass permissions='N' by
    default so Commander's native import doesn't hit an interactive
    prompt in batch mode (live rehearsal hit EOFError here)."""

    def test_permissions_defaults_to_N(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsImportCommand

        with tempfile.TemporaryDirectory() as tmp:
            bundle = os.path.join(tmp, 'bundle.json')
            with open(bundle, 'w') as f:
                f.write('{"records": []}')

            captured_kwargs = {}

            def fake_execute(self, params, **kw):
                captured_kwargs.update(kw)

            class FakeParams:
                user = 'admin@tgt'
                enterprise = {}
                record_cache = {}

            with mock.patch('keepercommander.importer.commands.RecordImportCommand.execute',
                             fake_execute):
                RecordsImportCommand().execute(
                    FakeParams(), input=bundle)

            self.assertEqual(captured_kwargs.get('permissions'), 'N')
            self.assertTrue(captured_kwargs.get('shared'))

    def test_explicit_permissions_override_respected(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import RecordsImportCommand

        with tempfile.TemporaryDirectory() as tmp:
            bundle = os.path.join(tmp, 'bundle.json')
            with open(bundle, 'w') as f:
                f.write('{"records": []}')

            captured_kwargs = {}

            def fake_execute(self, params, **kw):
                captured_kwargs.update(kw)

            class FakeParams:
                user = 'admin@tgt'
                enterprise = {}
                record_cache = {}

            with mock.patch('keepercommander.importer.commands.RecordImportCommand.execute',
                             fake_execute):
                RecordsImportCommand().execute(
                    FakeParams(), input=bundle, permissions='ure')

            self.assertEqual(captured_kwargs.get('permissions'), 'ure')


class FolderPathIndexTests(unittest.TestCase):
    """User folder hierarchy must be captured at export time and
    emitted on the import bundle — otherwise every record lands at
    the target vault root and we lose the hierarchy."""

    class _FakeFolder:
        def __init__(self, uid, name, parent_uid=None, sf_uid=None):
            self.uid = uid
            self.name = name
            self.parent_uid = parent_uid
            self.shared_folder_uid = sf_uid

    def test_build_folder_path_index_resolves_nested_user_folders(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import _build_folder_path_index

        F = self._FakeFolder

        class FakeParams:
            folder_cache = {
                'f1': F('f1', 'Work', None),
                'f2': F('f2', 'Creds', 'f1'),     # Work/Creds
                'f3': F('f3', 'Team SF', None, sf_uid='sf1'),
            }
            subfolder_record_cache = {
                'f1': {'r1'},
                'f2': {'r2', 'r3'},
                'f3': {'r4'},    # shared folder
            }

        index = _build_folder_path_index(FakeParams())
        self.assertEqual(index['r1'], [{'path': 'Work',
                                         'shared_folder_uid': None}])
        self.assertEqual(index['r2'], [{'path': 'Work\\Creds',
                                         'shared_folder_uid': None}])
        self.assertEqual(index['r3'], [{'path': 'Work\\Creds',
                                         'shared_folder_uid': None}])
        self.assertEqual(index['r4'], [{'path': 'Team SF',
                                         'shared_folder_uid': 'sf1'}])

    def test_record_in_multiple_folders_captured(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import _build_folder_path_index

        F = self._FakeFolder

        class FakeParams:
            folder_cache = {
                'f1': F('f1', 'A'),
                'f2': F('f2', 'B'),
            }
            subfolder_record_cache = {
                'f1': {'r1'},
                'f2': {'r1'},    # same record in both
            }

        index = _build_folder_path_index(FakeParams())
        self.assertEqual(len(index['r1']), 2)
        paths = {f['path'] for f in index['r1']}
        self.assertEqual(paths, {'A', 'B'})


class ConverterFolderEmissionTests(unittest.TestCase):
    """Converter must read source rec.folders[] and emit them in the
    import bundle — user-folder paths as `folder`, shared-folder
    placements as `shared_folder`."""

    def test_user_folder_emitted_as_folder_key(self):
        from keepercommander.commands.keeper_tenant_migrate.converter import RecordConverter

        conv = RecordConverter()
        src = [{
            'record_uid': 'r1', 'title': 'R1', 'type': 'login',
            'folders': [{'path': 'Work\\Creds', 'shared_folder_uid': None}],
            'fields': [], 'custom': [],
        }]
        out, assigned = conv.convert(src, record_to_sf={})
        self.assertEqual(assigned, 1)
        self.assertEqual(out[0]['folders'],
                          [{'folder': 'Work\\Creds'}])

    def test_shared_folder_emitted_as_shared_folder_key(self):
        from keepercommander.commands.keeper_tenant_migrate.converter import RecordConverter

        conv = RecordConverter()
        src = [{
            'record_uid': 'r1', 'title': 'R1', 'type': 'login',
            'folders': [{'path': 'Team SF', 'shared_folder_uid': 'sf1'}],
            'fields': [], 'custom': [],
        }]
        out, _ = conv.convert(src, record_to_sf={})
        self.assertEqual(out[0]['folders'],
                          [{'shared_folder': 'Team SF',
                            'can_edit': True, 'can_share': True}])

    def test_record_with_no_folders_has_no_folders_key(self):
        from keepercommander.commands.keeper_tenant_migrate.converter import RecordConverter

        conv = RecordConverter()
        src = [{'record_uid': 'r1', 'title': 'R1', 'type': 'login',
                'fields': [], 'custom': []}]
        out, assigned = conv.convert(src, record_to_sf={})
        self.assertEqual(assigned, 0)
        self.assertNotIn('folders', out[0])


class ApproveTeamQueueUserTests(unittest.TestCase):
    """The real SDK client was silently missing until 1.1.0 — a
    regression to wrong kwargs would silently drop queued team
    memberships. Lock the call shape down."""

    def test_wires_enterprise_team_with_add_user(self):
        from unittest import mock
        from keepercommander.commands.keeper_tenant_migrate.commander_clients import CommanderUserClient

        called = {}

        def fake_execute(self, params, **kw):
            called.update(kw)

        class FakeParams:
            enterprise = {}

        with mock.patch(
            'keepercommander.commands.enterprise.EnterpriseTeamCommand.execute',
            fake_execute,
        ):
            client = CommanderUserClient(FakeParams())
            ok = client.approve_team_queue_user('alice@x', 'Security Team')
        self.assertTrue(ok)
        self.assertEqual(called.get('team'), ['Security Team'])
        self.assertEqual(called.get('add_user'), ['alice@x'])
        self.assertTrue(called.get('force'))


class CaptureLightweightRecordsTests(unittest.TestCase):
    """Regression: capture-target-state MUST always emit state['records']
    (empty list when cache empty). Verify's phase_records depends on
    the key being present, not conditional on --include-fields."""

    def test_records_key_always_present(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import CaptureTargetStateCommand

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'state.json')

            class FakeParams:
                user = 'admin@tgt'
                server = 'https://x'
                enterprise = {'enterprise_name': 'Acme',
                               'nodes': [], 'users': [],
                               'teams': [], 'roles': [], 'shared_folders': []}
                record_cache = {}

            with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'):
                CaptureTargetStateCommand().execute(
                    FakeParams(), output=out,
                    include_fields=False, prefix='')
            with open(out) as f:
                state = json.load(f)
            self.assertIn('records', state)
            self.assertEqual(state['records'], [])

    def test_one_bad_record_does_not_abort_capture(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import CaptureTargetStateCommand

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'state.json')

            class FakeParams:
                user = 'admin@tgt'
                server = 'https://x'
                enterprise = {'enterprise_name': 'Acme',
                               'nodes': [], 'users': [],
                               'teams': [], 'roles': [], 'shared_folders': []}
                record_cache = {'good1': {}, 'bad': {}, 'good2': {}}

            class _StubRec:
                def __init__(self, title):
                    self.title = title

            calls = []

            def flaky_get(params, uid):
                calls.append(uid)
                if uid == 'bad':
                    raise RuntimeError('simulated decrypt failure')
                return _StubRec(f'Rec-{uid}')

            with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'), \
                 mock.patch('keepercommander.api.get_record', flaky_get):
                CaptureTargetStateCommand().execute(
                    FakeParams(), output=out,
                    include_fields=False, prefix='')
            with open(out) as f:
                state = json.load(f)
            titles = {r['title'] for r in state['records']}
            # The bad record is skipped; the good ones still land.
            self.assertEqual(titles, {'Rec-good1', 'Rec-good2'})


class AuditLockoutRiskCommandTests(unittest.TestCase):
    """v1.7 — read-only audit subcommand. Test scan + render helpers
    directly with synthetic fixtures (no live tenant)."""

    def _scan(self, roles):
        from keepercommander.commands.keeper_tenant_migrate.structure import (
            BUILTIN_ROLE_NAMES, BUILTIN_ROLE_SUFFIX,
            LOCKOUT_RISK_ENFORCEMENTS)
        return AuditLockoutRiskCommand._scan_roles(
            roles, BUILTIN_ROLE_NAMES, BUILTIN_ROLE_SUFFIX,
            LOCKOUT_RISK_ENFORCEMENTS)

    def test_scan_filters_to_builtin_admin_roles_only(self):
        roles = [
            {'name': 'Custom Role',
             'enforcements': {'restrict_ip_addresses': '10.0.0.0/8'}},
            {'name': 'Administrator',
             'enforcements': {'restrict_ip_addresses': '10.0.0.0/8'}},
        ]
        result = self._scan(roles)
        self.assertNotIn('Custom Role', result)
        self.assertIn('Administrator', result)
        self.assertEqual(result['Administrator'], ['restrict_ip_addresses'])

    def test_scan_handles_migrated_suffix(self):
        roles = [{'name': 'Keeper Administrator (Migrated)',
                  'enforcements': {'require_account_share': '99'}}]
        result = self._scan(roles)
        self.assertEqual(result, {'Keeper Administrator':
                                  ['require_account_share']})

    def test_scan_skips_non_lockout_risk_enforcements(self):
        """A builtin-admin role with only non-lockout-risk enforcements
        should still appear (with an empty list) — operator wants to
        see all builtin-admin roles for completeness."""
        roles = [{'name': 'Administrator',
                  'enforcements': {'two_factor_required': True}}]
        result = self._scan(roles)
        self.assertEqual(result, {'Administrator': []})

    def test_render_no_findings(self):
        report = AuditLockoutRiskCommand._render_markdown(
            {}, None,
            {'require_account_share', 'restrict_ip_addresses'})
        self.assertIn('# Lockout-Risk Enforcement Audit', report)
        self.assertIn('no builtin-admin roles found on target', report)

    def test_render_with_findings_and_drift(self):
        target = {'Administrator': ['restrict_ip_addresses']}
        source = {'Administrator': ['require_account_share',
                                    'restrict_ip_addresses']}
        report = AuditLockoutRiskCommand._render_markdown(
            target, source,
            {'require_account_share', 'restrict_ip_addresses',
             'master_password_reentry', 'two_factor_by_ip'})
        self.assertIn('Source-vs-target drift', report)
        self.assertIn('require_account_share', report)
        self.assertIn('Administrator', report)

    def test_render_no_drift_when_source_target_match(self):
        target = {'Administrator': ['restrict_ip_addresses']}
        source = {'Administrator': ['restrict_ip_addresses']}
        report = AuditLockoutRiskCommand._render_markdown(
            target, source, {'restrict_ip_addresses'})
        self.assertIn('no drift', report)


if __name__ == '__main__':
    unittest.main()
