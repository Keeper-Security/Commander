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


if __name__ == '__main__':
    unittest.main()
