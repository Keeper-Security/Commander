import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate.mc_context import MCContext, switch_to_mc, switch_to_msp


class SwitchToMcTests(unittest.TestCase):
    def test_empty_mc_is_noop_success(self):
        sentinel = object()
        ok, out = switch_to_mc(sentinel, '')
        self.assertTrue(ok)
        self.assertIs(out, sentinel)
        ok, out = switch_to_mc(sentinel, None)
        self.assertTrue(ok)
        self.assertIs(out, sentinel)

    def test_success_returns_mc_params_from_dict(self):
        sentinel_msp = object()
        sentinel_mc = object()
        with mock.patch('keepercommander.commands.msp.SwitchToMcCommand') as M, \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context._mc_module') as mod:
            M.return_value.execute.return_value = None
            mod.return_value.current_mc_id = 42
            mod.return_value.mc_params_dict = {42: sentinel_mc}
            ok, out = switch_to_mc(sentinel_msp, 'MyMC')
            self.assertTrue(ok)
            self.assertIs(out, sentinel_mc)

    def test_success_but_no_mc_params_stashed_is_failure(self):
        sentinel_msp = object()
        with mock.patch('keepercommander.commands.msp.SwitchToMcCommand') as M, \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context._mc_module') as mod:
            M.return_value.execute.return_value = None
            mod.return_value.current_mc_id = None
            mod.return_value.mc_params_dict = {}
            ok, out = switch_to_mc(sentinel_msp, 'MyMC')
            self.assertFalse(ok)
            self.assertIs(out, sentinel_msp)

    def test_command_error_returns_false_with_original_params(self):
        sentinel = object()
        with mock.patch('keepercommander.commands.msp.SwitchToMcCommand') as M:
            M.return_value.execute.side_effect = RuntimeError('boom')
            ok, out = switch_to_mc(sentinel, 'MyMC')
            self.assertFalse(ok)
            self.assertIs(out, sentinel)

    def test_numeric_id_stringified(self):
        with mock.patch('keepercommander.commands.msp.SwitchToMcCommand') as M, \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context._mc_module') as mod:
            instance = M.return_value
            instance.execute.return_value = None
            mod.return_value.current_mc_id = 12345
            mod.return_value.mc_params_dict = {12345: object()}
            switch_to_mc(object(), 12345)
            _, kwargs = instance.execute.call_args
            self.assertEqual(kwargs['mc'], '12345')


class SwitchToMspTests(unittest.TestCase):
    def test_success_returns_stashed_msp_params(self):
        sentinel_mc = object()
        sentinel_msp = object()
        with mock.patch('keepercommander.commands.msp.SwitchToMspCommand') as M, \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context._mc_module') as mod:
            M.return_value.execute.return_value = None
            mod.return_value.msp_params = sentinel_msp
            ok, out = switch_to_msp(sentinel_mc)
            self.assertTrue(ok)
            self.assertIs(out, sentinel_msp)

    def test_exception_returns_false_with_fallback(self):
        sentinel_mc = object()
        with mock.patch('keepercommander.commands.msp.SwitchToMspCommand') as M, \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context._mc_module') as mod:
            M.return_value.execute.side_effect = RuntimeError('bad')
            mod.return_value.msp_params = None
            ok, out = switch_to_msp(sentinel_mc)
            self.assertFalse(ok)
            self.assertIs(out, sentinel_mc)


class MCContextTests(unittest.TestCase):
    def test_enter_skips_when_mc_empty(self):
        sentinel = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc') as sm, \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp') as sp:
            with MCContext(sentinel, '') as ctx:
                self.assertIs(ctx.params, sentinel)
            sm.assert_not_called()
            sp.assert_not_called()

    def test_enter_swaps_params_to_mc_scope(self):
        sentinel_msp = object()
        sentinel_mc = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(True, sentinel_mc)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp',
                        return_value=(True, sentinel_msp)):
            with MCContext(sentinel_msp, 'MyMC') as ctx:
                # Inside the block, ctx.params points at the MC session.
                self.assertIs(ctx.params, sentinel_mc)
            # After exit, restored to the stashed MSP params.
            self.assertIs(ctx.params, sentinel_msp)

    def test_failed_switch_keeps_msp_params_and_skips_revert(self):
        sentinel_msp = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(False, sentinel_msp)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp') as sp:
            with MCContext(sentinel_msp, 'MyMC') as ctx:
                # Failed switch — operator must see MSP params, not MC.
                self.assertIs(ctx.params, sentinel_msp)
            sp.assert_not_called()

    def test_inner_exception_still_reverts(self):
        sentinel_msp = object()
        sentinel_mc = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(True, sentinel_mc)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp',
                        return_value=(True, sentinel_msp)) as sp:
            with self.assertRaises(RuntimeError):
                with MCContext(sentinel_msp, 'MyMC'):
                    raise RuntimeError('kaboom')
            sp.assert_called_once()

    def test_is_in_mc_false_when_no_mc(self):
        """is_in_mc is False when MCContext was entered without an MC name."""
        sentinel = object()
        with MCContext(sentinel, '') as ctx:
            self.assertFalse(ctx.is_in_mc)

    def test_is_in_mc_true_after_successful_switch(self):
        """is_in_mc flips True only after switch_to_mc returns success."""
        sentinel_msp = object()
        sentinel_mc = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(True, sentinel_mc)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp',
                        return_value=(True, sentinel_msp)):
            with MCContext(sentinel_msp, 'MyMC') as ctx:
                self.assertTrue(ctx.is_in_mc)
                self.assertIs(ctx.params, sentinel_mc)

    def test_is_in_mc_false_on_failed_switch(self):
        """is_in_mc stays False if switch_to_mc reported failure — caller
        code can use this to avoid taking MC-only fast paths against
        what is actually still the MSP session."""
        sentinel_msp = object()
        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(False, sentinel_msp)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp'):
            with MCContext(sentinel_msp, 'MyMC') as ctx:
                self.assertFalse(ctx.is_in_mc)


class StructureMCTargetRootRegressionTests(unittest.TestCase):
    """Regression coverage for the 2026-05-14 Tier 7 verify-mc failure.

    When `structure --mc <name>` switches params to the MC scope, the
    structure command must resolve `target_root` from the MC's
    enterprise data (the MC's top-level node name) so the scope-root
    remap in `topological_node_order` can correctly reparent
    scope-node-excluded children.

    Pre-fix symptoms (real rehearsal-17 Tier 7 verify-mc artefacts):
      * 3 custom teams missing on target MC
      * 5 custom roles missing on target MC
      * 2 nodes (`MIGTEST-Child-Node`, `MIGTEST-Isolated-Node`) attached to
        `root` instead of `MIGRATION-TEST-NODE`
      * 2 count diffs (teams 0<3, roles 1<5)

    Root cause: `_run()` called `_detect_target_root(params)` BEFORE
    the structure command's own `sync_down`. For the non-MC path,
    `params.enterprise` was already populated from the running shell;
    for MC, `ctx.params` was fresh + sparse, so `_detect_target_root`
    returned empty and target_root fell back to the literal 'Root',
    which doesn't match the MC's actual top-level node name.

    Fix: when `ctx.is_in_mc`, eagerly `sync_down(ctx.params)` and
    resolve target_root explicitly in `execute()`, passing through
    `kwargs` so `_run()` sees the right value via the explicit
    `kwargs.get('target_root')` branch.
    """

    def test_mc_path_pre_resolves_target_root_before_run(self):
        from keepercommander.commands.keeper_tenant_migrate.commands import StructureCommand

        # Build a synthetic MC-scoped params whose enterprise carries
        # a known top-level node ('MC-Acme-Root') so the resolver has
        # something concrete to find.
        class _MCParams:
            enterprise = {
                'enterprise_name': 'MC-Acme',
                'nodes': [
                    {'node_id': 1, 'parent_id': 0,
                     'data': {'displayname': 'MC-Acme-Root'}},
                ],
            }
        mc_params = _MCParams()
        msp_params = object()

        captured = {}

        def fake_run(self, params_arg, kwargs_arg):
            captured['target_root'] = kwargs_arg.get('target_root')
            captured['params_is_mc'] = (params_arg is mc_params)
            return None

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_mc',
                        return_value=(True, mc_params)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.mc_context.switch_to_msp',
                        return_value=(True, msp_params)), \
             mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down') as sd, \
             mock.patch.object(StructureCommand, '_run', new=fake_run):
            cmd = StructureCommand()
            cmd.execute(msp_params, mc='MC-Acme', inventory='/dev/null')

        # The synthetic _run captured what got passed.
        self.assertEqual(captured.get('target_root'), 'MC-Acme-Root',
                         'structure --mc must pre-resolve target_root '
                         'from MC enterprise data so the scope-root '
                         'remap targets the MC root (rehearsal-17 '
                         'Tier 7 regression)')
        self.assertTrue(captured.get('params_is_mc'),
                        '_run must receive ctx.params (the MC-scoped '
                        'params), not the original MSP params')
        sd.assert_called()

    def test_non_mc_path_unchanged(self):
        """Without --mc, the structure command must NOT call sync_down
        eagerly + must NOT inject target_root. This guards against
        regression of the non-MC path that has been working since
        rehearsal-15."""
        from keepercommander.commands.keeper_tenant_migrate.commands import StructureCommand

        msp_params = object()
        captured = {}

        def fake_run(self, params_arg, kwargs_arg):
            captured['target_root'] = kwargs_arg.get('target_root')
            return None

        with mock.patch('keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down') as sd, \
             mock.patch.object(StructureCommand, '_run', new=fake_run):
            cmd = StructureCommand()
            cmd.execute(msp_params, mc='', inventory='/dev/null')

        self.assertIsNone(captured.get('target_root'),
                          'non-MC path must let _run resolve target_root '
                          'via its own _detect_target_root() call')
        sd.assert_not_called()


if __name__ == '__main__':
    unittest.main()
