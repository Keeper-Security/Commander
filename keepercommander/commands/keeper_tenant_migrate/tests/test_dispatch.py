"""End-to-end dispatch tests — invoke subcommands via `TenantMigrateCommand.execute_args()`.

The rest of the suite calls `.execute(params, **kwargs)` directly. That
skips the path Commander actually takes in its shell:

  TenantMigrateCommand.execute_args(params, "structure --inventory FOO")
    → strip verb → look up subcommand
    → SubCommand.execute_args(params, "--inventory FOO")
    → shlex.split + parser.parse_args
    → merge opts.__dict__ into kwargs
    → SubCommand.execute(params, **kwargs)

Bugs in argparse definitions (wrong `dest`, `required` mismatches,
action type errors) only surface through this path. This module exercises
it for every offline subcommand using synthetic inputs.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate import register_commands


def _make_group():
    commands = {}
    register_commands(commands)
    return commands['tenant-migrate']


class _FakeParams:
    def __init__(self):
        self.user = 'admin@x'
        self.session_token = 'fake'
        self.server = 'https://x'
        self.enterprise = {}
        self.record_cache = {}
        self.environment_variables = {}


class DispatchHelpTests(unittest.TestCase):
    def test_empty_verb_prints_help(self):
        group = _make_group()
        # No verb → prints help, shouldn't raise
        group.execute_args(_FakeParams(), '', command='tenant-migrate')


class ConvertDispatchTests(unittest.TestCase):
    """convert is pure offline — exercises the full parse + execute path."""

    def test_missing_required_flag_fails_cleanly(self):
        group = _make_group()
        # Missing --output; parser raises ParseError which Commander's
        # Command base class catches + logs at ERROR. No exception should
        # escape to the caller.
        try:
            group.execute_args(_FakeParams(),
                               'convert --input-dir /tmp/nonexistent',
                               command='tenant-migrate')
        except Exception as e:                         # noqa: BLE001
            self.fail(f'execute_args should swallow parse errors, got {e!r}')

    def test_full_flag_set_reaches_executor(self):
        group = _make_group()
        fixtures = os.path.join(os.path.dirname(__file__), 'fixtures')
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as t:
            out = t.name
        try:
            group.execute_args(
                _FakeParams(),
                f'convert --input-dir {fixtures} --output {out}',
                command='tenant-migrate',
            )
            with open(out) as f:
                data = json.load(f)
            self.assertIn('records', data)
            self.assertGreater(len(data['records']), 0)
        finally:
            os.unlink(out)


class AssembleInventoryDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Minimal staging dir
        with open(os.path.join(self.tmp, 'nodes.csv'), 'w') as f:
            f.write('1,"MIGTEST-Root","",false,0,0,0\n')
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

    def test_assemble_dispatched_via_group(self):
        group = _make_group()
        output = os.path.join(self.tmp, 'inv.json')
        group.execute_args(
            _FakeParams(),
            f'assemble-inventory --input-dir {self.tmp} --output {output} '
            f'--prefix MIGTEST-',
            command='tenant-migrate',
        )
        self.assertTrue(os.path.exists(output))
        self.assertTrue(os.path.exists(output + '.sha256'))


class TransitionCheckDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_transition_check_via_roster(self):
        roster = os.path.join(self.tmp, 'roster.csv')
        target = os.path.join(self.tmp, 'target.csv')
        csv_out = os.path.join(self.tmp, 'plan.csv')
        md_out = os.path.join(self.tmp, 'plan.md')
        with open(roster, 'w') as f:
            f.write('email,name\nalice@x,Alice\n')
        with open(target, 'w') as f:
            f.write('User ID,Email,Status\n1,alice@x,Active\n')

        group = _make_group()
        group.execute_args(
            _FakeParams(),
            f'transition-check --roster {roster} '
            f'--target-users-csv {target} '
            f'--csv-output {csv_out} --md-output {md_out}',
            command='tenant-migrate',
        )
        self.assertTrue(os.path.exists(csv_out))
        self.assertTrue(os.path.exists(md_out))


class VerifyDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_verify_flags_parse_and_reach_driver(self):
        inv = os.path.join(self.tmp, 'inv.json')
        state = os.path.join(self.tmp, 'state.json')
        checks = os.path.join(self.tmp, 'checks.csv')
        with open(inv, 'w') as f:
            json.dump({
                'captured_at': 'x', 'source_user': '', 'source_root': '',
                'counts': {'nodes': 1, 'teams': 0, 'roles': 0,
                           'users': 0, 'shared_folders': 0,
                           'records': 0, 'attachments': 0, 'direct_shares': 0},
                'entities': {
                    'nodes': [{'name': 'N1'}], 'teams': [], 'roles': [],
                    'users': [], 'shared_folders': [], 'records': [],
                },
            }, f)
        with open(state, 'w') as f:
            json.dump({'nodes': [{'name': 'N1'}], 'teams': [], 'roles': [],
                       'users': [], 'shared_folders': []}, f)

        group = _make_group()
        group.execute_args(
            _FakeParams(),
            f'verify --inventory {inv} --target-state {state} --output {checks}',
            command='tenant-migrate',
        )
        self.assertTrue(os.path.exists(checks))


class StructureDispatchTests(unittest.TestCase):
    """Verify --inventory and --steps flags parse through the full path."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_inventory_mutually_exclusive_with_plan(self):
        """Passing both --plan and --inventory should be rejected by the
        argparse mutually-exclusive group BEFORE any execute() call."""
        captured = []

        def fake_execute(self, params, **kwargs):
            captured.append(kwargs)

        group = _make_group()
        with mock.patch(
            'keepercommander.commands.keeper_tenant_migrate.commands.StructureCommand.execute',
            fake_execute,
        ):
            group.execute_args(
                _FakeParams(),
                'structure --plan /tmp/p --inventory /tmp/i.json',
                command='tenant-migrate',
            )
        # Mutex guard fired → execute never reached.
        self.assertEqual(captured, [])

    def test_steps_flag_value_reaches_executor(self):
        """--steps 4-6 must arrive in kwargs as the string '4-6'."""
        captured = {}

        def fake_execute(self, params, **kwargs):
            captured.update(kwargs)

        inv = os.path.join(self.tmp, 'inv.json')
        with open(inv, 'w') as f:
            json.dump({'entities': {'nodes': [], 'teams': [], 'roles': [],
                                     'users': [], 'shared_folders': [],
                                     'records': []},
                       'counts': {}}, f)

        group = _make_group()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commands.StructureCommand.execute',
                        fake_execute):
            group.execute_args(
                _FakeParams(),
                f'structure --inventory {inv} --steps 4-6 --scope-node X',
                command='tenant-migrate',
            )
        self.assertEqual(captured.get('steps'), '4-6')
        self.assertEqual(captured.get('scope_node'), 'X')
        self.assertEqual(captured.get('inventory'), inv)


class ReconcileDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_reconcile_writes_markdown(self):
        inv = os.path.join(self.tmp, 'inv.json')
        state = os.path.join(self.tmp, 'state.json')
        out = os.path.join(self.tmp, 'recon.md')
        with open(inv, 'w') as f:
            json.dump({
                'captured_at': 'x', 'source_user': '', 'source_root': '',
                'target_user': '', 'target_root': '',
                'counts': {'nodes': 1, 'teams': 0, 'roles': 0,
                           'users': 0, 'shared_folders': 0,
                           'records': 0, 'attachments': 0, 'direct_shares': 0},
                'entities': {
                    'nodes': [{'name': 'N1'}], 'teams': [], 'roles': [],
                    'users': [], 'shared_folders': [], 'records': [],
                },
            }, f)
        with open(state, 'w') as f:
            json.dump({'nodes': [{'name': 'N1'}], 'teams': [], 'roles': [],
                       'users': [], 'shared_folders': []}, f)

        group = _make_group()
        group.execute_args(
            _FakeParams(),
            f'reconcile --inventory {inv} --target-state {state} --output {out}',
            command='tenant-migrate',
        )
        self.assertTrue(os.path.exists(out))
        self.assertIn('Reconciliation Report', open(out).read())


if __name__ == '__main__':
    unittest.main()
