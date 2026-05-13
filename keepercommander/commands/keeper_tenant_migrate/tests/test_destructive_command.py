"""Structural guarantee that source-mode interlock is applied to
every destructive subcommand.

Before v1.4.1 the enforcement was a convention: each destructive
Command's execute() called `_enforce_source_mode_from_kwargs` at the
top. A future destructive Command that forgot the call would silently
bypass the 4-layer interlock. This test suite + the
DestructiveCommand base class turn that into a type-system guarantee:

  1. `DestructiveCommand.__init_subclass__` raises at IMPORT time
     when a subclass fails to set `SUBCOMMAND = '<name>'`.
  2. `DestructiveCommand.execute()` applies the interlock BEFORE
     dispatching to subclass `_run()`. Cannot be forgotten.
  3. These tests enumerate every Command that calls a destructive
     client method (delete_*, remove_*, transfer_*) and assert it
     inherits from DestructiveCommand. Catches the case where
     someone adds a new destructive subcommand without using the
     base class.
"""

import ast
import inspect
import unittest
from pathlib import Path

from keepercommander.commands.keeper_tenant_migrate import commands
from keepercommander.commands.keeper_tenant_migrate.commands import (
    Command,
    DestructiveCommand,
    DESTRUCTIVE_COMMANDS,
    CleanupCommand,
    DecommissionCommand,
    TakeOwnershipCommand,
    TransferUserCommand,
)
from keepercommander.commands.keeper_tenant_migrate.safeguards import (
    DestructiveCommandMisconfigured,
    SafeguardBlocked,
)


class _FakeParams:
    def __init__(self, server='tgt.example.com', user='admin@tgt'):
        self.server = server
        self.user = user
        self.enterprise = {'enterprise_name': 'TestCorp'}


class DestructiveCommandMarkerTests(unittest.TestCase):

    def test_registry_has_all_four(self):
        names = {c.__name__ for c in DESTRUCTIVE_COMMANDS}
        self.assertIn('CleanupCommand', names)
        self.assertIn('DecommissionCommand', names)
        self.assertIn('TakeOwnershipCommand', names)
        self.assertIn('TransferUserCommand', names)

    def test_each_has_subcommand_attr(self):
        for cls in DESTRUCTIVE_COMMANDS:
            self.assertTrue(
                getattr(cls, 'SUBCOMMAND', ''),
                f'{cls.__name__} missing SUBCOMMAND class attribute',
            )

    def test_subcommand_names_are_unique(self):
        names = [c.SUBCOMMAND for c in DESTRUCTIVE_COMMANDS]
        self.assertEqual(len(names), len(set(names)),
                          f'duplicate SUBCOMMAND: {names}')

    def test_subclass_without_subcommand_raises_at_definition(self):
        # Mimic a future Command author forgetting to declare SUBCOMMAND.
        with self.assertRaises(DestructiveCommandMisconfigured):
            class _Bad(DestructiveCommand):
                pass

    def test_subclass_with_subcommand_registers(self):
        # Positive path — declaring SUBCOMMAND works and auto-registers.
        before = len(DESTRUCTIVE_COMMANDS)

        class _Good(DestructiveCommand):
            SUBCOMMAND = 'test-good'
            def get_parser(self): return None
            def _run(self, params, **kwargs): return 'ok'

        try:
            self.assertEqual(len(DESTRUCTIVE_COMMANDS), before + 1)
            self.assertIs(DESTRUCTIVE_COMMANDS[-1], _Good)
        finally:
            # Keep the class list stable across tests
            DESTRUCTIVE_COMMANDS.pop()


class DestructiveCommandInterlockTests(unittest.TestCase):
    """The base class's execute() fires the source-mode check before
    dispatching to _run(). When the session IS the source tenant (per
    the run-spec), failing to pass --confirm-source-destructive must
    block.
    """

    def setUp(self):
        self._calls = []

        class _Demo(DestructiveCommand):
            SUBCOMMAND = 'test-demo'
            def get_parser(self_cmd): return None
            def _run(self_cmd, params, **kwargs):
                self._calls.append(('run', params, kwargs))
                return 'ran'

        self.cmd = _Demo()

    def tearDown(self):
        while DESTRUCTIVE_COMMANDS and DESTRUCTIVE_COMMANDS[-1].__name__ == '_Demo':
            DESTRUCTIVE_COMMANDS.pop()

    def _source_matching_params(self):
        # Session that the run-spec identifies as the SOURCE tenant —
        # required to make the interlock fire at all (target-side
        # destructive ops have different safeguards).
        return _FakeParams(server='src.example.com', user='admin@src')

    def _source_matching_spec(self):
        return {
            'source': {
                'user': 'admin@src',
                'enterprise_name': 'TestCorp',
                'server': 'src.example.com',
            },
        }

    def _write_spec_to_rundir(self, spec):
        import tempfile, os
        from keepercommander.commands.keeper_tenant_migrate.wizard import save_migration_yaml
        run_dir = tempfile.mkdtemp(prefix='testdestructive_')
        save_migration_yaml(run_dir, spec)
        return run_dir

    def test_dry_run_bypasses_guard(self):
        # dry_run=True must let _run() fire without any interlock.
        r = self.cmd.execute(_FakeParams(), dry_run=True)
        self.assertEqual(r, 'ran')
        self.assertEqual(len(self._calls), 1)

    def test_live_source_without_confirm_blocks(self):
        # Session IS the source; spec says read_only (default); no
        # confirm flag → base class catches SafeguardBlocked and
        # returns the standard {'blocked': True, ...} dict.
        import shutil
        spec = self._source_matching_spec()
        run_dir = self._write_spec_to_rundir(spec)
        try:
            result = self.cmd.execute(
                self._source_matching_params(),
                run_dir=run_dir,
            )
            self.assertIsInstance(result, dict)
            self.assertTrue(result.get('blocked'))
            self.assertIn('read_only', result.get('reason', ''))
            self.assertEqual(self._calls, [])
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_live_target_session_is_noop(self):
        # Session matches the spec's TARGET side → source-mode interlock
        # is a no-op (target-side destructives have their own safeguards).
        # Spec must include both source AND target sections so
        # detect_session_role returns 'target' rather than 'unknown';
        # SEC-1 (commit 8b16e46) tightened the unknown-role path to
        # fail-closed for destructive ops, so an unclassifiable session
        # cannot fall through.
        import shutil
        spec = self._source_matching_spec()
        spec['target'] = {
            'user': 'admin@tgt',
            'enterprise_name': 'OtherCorp',
            'server': 'tgt.example.com',
        }
        run_dir = self._write_spec_to_rundir(spec)
        try:
            tgt_params = _FakeParams(server='tgt.example.com',
                                      user='admin@tgt')
            tgt_params.enterprise = {'enterprise_name': 'OtherCorp'}
            r = self.cmd.execute(tgt_params, run_dir=run_dir)
            self.assertEqual(r, 'ran')
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_live_source_with_full_authorization_dispatches(self):
        # Source session + destructive spec + confirm flag + matching
        # tenant-name → all 4 layers satisfied, _run fires.
        import shutil
        spec = self._source_matching_spec()
        spec['source_mode'] = 'destructive'
        run_dir = self._write_spec_to_rundir(spec)
        try:
            r = self.cmd.execute(
                self._source_matching_params(),
                run_dir=run_dir,
                confirm_source_destructive=True,
                expected_tenant_name='TestCorp',
            )
            self.assertEqual(r, 'ran')
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class DestructiveCallGraphAuditTests(unittest.TestCase):
    """Source-code audit: enumerate every Command subclass whose
    methods reference a known-destructive client call. Every one must
    inherit from DestructiveCommand. Catches the regression where a
    future developer adds a new destructive Command but forgets the
    base class.
    """

    # Method names on the client abstraction that actually write.
    # Keep this list narrow and explicit — adding a new client method
    # should prompt a deliberate decision on whether it's destructive.
    DESTRUCTIVE_CLIENT_METHODS = (
        'delete_team', 'delete_role', 'delete_node', 'delete_user',
        'delete_record',
        'remove_team_user', 'remove_role_user',
        'transfer_user', 'take_ownership',
        'lock_user', 'decommission_user',
    )

    # Non-destructive subcommands that legitimately read but don't
    # mutate source; they must stay Command (not DestructiveCommand).
    # Add to this set if a new read-only subcommand gets flagged.
    READ_ONLY_EXCEPTIONS = {
        'Command',            # base
        'DestructiveCommand', # base
    }

    def test_every_destructive_command_inherits_base(self):
        commands_path = Path(commands.__file__)
        source = commands_path.read_text()
        tree = ast.parse(source)

        violations = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not node.name.endswith('Command'):
                continue
            if node.name in self.READ_ONLY_EXCEPTIONS:
                continue

            # Does this class's body reference any destructive
            # client method?
            class_src = ast.get_source_segment(source, node) or ''
            uses_destructive = any(
                f'.{m}(' in class_src
                for m in self.DESTRUCTIVE_CLIENT_METHODS
            )
            if not uses_destructive:
                continue

            # Is it a DestructiveCommand?
            cls = getattr(commands, node.name, None)
            if cls is None:
                # Class may be nested / synthetic; skip
                continue
            if not issubclass(cls, DestructiveCommand):
                violations.append(
                    f'{node.name} uses destructive client calls but '
                    f'does not inherit from DestructiveCommand'
                )

        self.assertEqual(
            violations, [],
            f'\n  '.join(['Structural violation(s):'] + violations),
        )


if __name__ == '__main__':
    unittest.main()
