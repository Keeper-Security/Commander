import os
import types
import unittest
from unittest import mock

from keepercommander.commands import msp
from keepercommander.commands.msp import SwitchToMcCommand, SwitchToMspCommand
from keepercommander.commands.tunnel import tunnel_lifecycle
from keepercommander.commands.tunnel.port_forward.tunnel_helpers import TunnelSession
from keepercommander.commands.utils import LogoutCommand
from keepercommander.error import CommandError
from keepercommander import utils


class TestTunnelLifecycle(unittest.TestCase):
    def setUp(self):
        self._saved_msp_params = msp.msp_params
        self._saved_mc_params = dict(msp.mc_params_dict)
        self._saved_current_mc_id = msp.current_mc_id
        msp.msp_params = None
        msp.mc_params_dict.clear()
        msp.current_mc_id = None

    def tearDown(self):
        msp.msp_params = self._saved_msp_params
        msp.mc_params_dict.clear()
        msp.mc_params_dict.update(self._saved_mc_params)
        msp.current_mc_id = self._saved_current_mc_id

    def _account_uid(self, raw=b'acct-a'):
        return utils.base64_url_encode(raw)

    def _make_params(self, account_raw=b'acct-a', records=None):
        return types.SimpleNamespace(
            account_uid_bytes=account_raw,
            records=records or {'uid-1': object()},
        )

    def test_resolve_tunnel_context_regular_when_mc_active(self):
        msp.current_mc_id = 42
        self.assertEqual(tunnel_lifecycle.resolve_tunnel_context(), tunnel_lifecycle.TUNNEL_CONTEXT_REGULAR)

    def test_resolve_tunnel_context_msp_when_not_impersonating(self):
        msp.current_mc_id = None
        self.assertEqual(tunnel_lifecycle.resolve_tunnel_context(), tunnel_lifecycle.TUNNEL_CONTEXT_MSP)

    def test_apply_tunnel_ownership_tags_session(self):
        msp.current_mc_id = 7
        params = self._make_params()
        session = TunnelSession('tube-1', 'conv', 'gw', b'key')
        ownership = tunnel_lifecycle.apply_tunnel_ownership(session, params)
        self.assertEqual(ownership['owning_context'], tunnel_lifecycle.TUNNEL_CONTEXT_REGULAR)
        self.assertEqual(session.owning_context, tunnel_lifecycle.TUNNEL_CONTEXT_REGULAR)
        self.assertEqual(session.owning_account_uid, ownership['owning_account_uid'])

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.get_or_create_tube_registry')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.get_tunnel_session')
    def test_context_switch_hides_without_stopping(self, session_mock, registry_mock):
        registry = mock.Mock()
        registry.all_tube_ids.return_value = ['tube-1']
        registry.get_connection_ids_by_tube_id = mock.Mock(return_value=[])
        registry.get_conversation_ids_by_tube_id.return_value = []
        registry.get_connection_state.return_value = 'connected'
        registry_mock.return_value = registry

        session = TunnelSession('tube-1', 'conv', 'gw', b'key', record_uid='uid-1')
        session.owning_account_uid = self._account_uid()
        session.owning_context = tunnel_lifecycle.TUNNEL_CONTEXT_REGULAR
        session_mock.return_value = session

        params = self._make_params()
        msp.mc_params_dict[42] = params

        msp.current_mc_id = 42
        self.assertEqual(len(list(tunnel_lifecycle.iter_visible_in_process_tunnels(params))), 1)

        msp.current_mc_id = None
        self.assertEqual(len(list(tunnel_lifecycle.iter_visible_in_process_tunnels(params))), 0)

        msp.current_mc_id = 42
        self.assertEqual(len(list(tunnel_lifecycle.iter_visible_in_process_tunnels(params))), 1)

        registry.close_tube.assert_not_called()

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.get_or_create_tube_registry')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.get_tunnel_session')
    def test_account_switch_hides_without_stopping(self, session_mock, registry_mock):
        registry = mock.Mock()
        registry.all_tube_ids.return_value = ['tube-a']
        registry_mock.return_value = registry

        session = TunnelSession('tube-a', 'conv', 'gw', b'key', record_uid='uid-1')
        session.owning_account_uid = self._account_uid(b'acct-a')
        session.owning_context = tunnel_lifecycle.TUNNEL_CONTEXT_MSP
        session_mock.return_value = session

        params_a = self._make_params(b'acct-a')
        params_b = self._make_params(b'acct-b')

        visible_for_b = list(tunnel_lifecycle.iter_visible_in_process_tunnels(params_b))
        self.assertEqual(visible_for_b, [])

        visible_for_a = list(tunnel_lifecycle.iter_visible_in_process_tunnels(params_a))
        self.assertEqual(len(visible_for_a), 1)

        registry.close_tube.assert_not_called()

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.list_registered_tunnels')
    def test_registry_tunnel_visible_when_record_cache_is_incomplete(self, list_registered_tunnels_mock):
        params = self._make_params(records={})
        owning_account_uid = self._account_uid(b'acct-a')
        list_registered_tunnels_mock.return_value = [{
            'pid': 123,
            'record_uid': 'uid-1',
            'tube_id': 'tube-1',
            'owning_account_uid': owning_account_uid,
            'owning_context': tunnel_lifecycle.TUNNEL_CONTEXT_MSP,
        }]

        entries = list(tunnel_lifecycle.iter_visible_registry_tunnels(params))

        self.assertEqual(1, len(entries))
        self.assertEqual('tube-1', entries[0]['tube_id'])

    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.list_external_projections', return_value=[])
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.list_registered_tunnels')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle._iter_scoped_in_process_tunnels')
    def test_logout_description_dedupes_live_tube_and_registry_entry(
        self,
        iter_tubes_mock,
        list_registered_tunnels_mock,
        list_external_mock,
    ):
        params = self._make_params()
        owning_account_uid = self._account_uid(b'acct-a')
        session = TunnelSession('tube-1', 'conv', 'gw', b'key', record_uid='uid-1')
        session.owning_account_uid = owning_account_uid
        session.host = '127.0.0.1'
        session.port = 49153
        session.target_host = 'server-ssh-with-key-1'
        session.target_port = 2222
        iter_tubes_mock.return_value = [(params, mock.Mock(), 'tube-1', session)]
        list_registered_tunnels_mock.return_value = [{
            'pid': 6201,
            'record_uid': 'uid-1',
            'tube_id': 'tube-1',
            'host': '127.0.0.1',
            'port': 49153,
            'owning_account_uid': owning_account_uid,
        }]

        descriptions = tunnel_lifecycle.describe_active_pam_tunnels_on_logout(params)

        self.assertEqual([
            'uid-1 (local 127.0.0.1:49153 -> remote server-ssh-with-key-1:2222)'
        ], descriptions)
        list_external_mock.assert_called_once_with(clean_stale=False)

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.stop_tunnel_process')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.unregister_tunnel')
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.request_owner_stop')
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.list_external_projections', return_value=[])
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.list_registered_tunnels')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.close_tube_idempotently', return_value=(True, 'stopped'))
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.publish_stopping')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle._iter_scoped_in_process_tunnels')
    def test_logout_does_not_signal_current_process_registry_duplicate(
        self,
        iter_tubes_mock,
        publish_stopping,
        close_tube,
        list_registered_tunnels_mock,
        list_external_mock,
        request_owner_stop,
        unregister_mock,
        stop_process,
    ):
        params = self._make_params()
        owning_account_uid = self._account_uid(b'acct-a')
        session = TunnelSession('tube-1', 'conv', 'gw', b'key', record_uid='uid-1')
        session.owning_account_uid = owning_account_uid
        session.host = '127.0.0.1'
        session.port = 49153
        iter_tubes_mock.return_value = [(params, mock.Mock(), 'tube-1', session)]
        list_registered_tunnels_mock.return_value = [{
            'pid': os.getpid(),
            'record_uid': 'uid-1',
            'tube_id': 'tube-1',
            'host': '127.0.0.1',
            'port': 49153,
            'owning_account_uid': owning_account_uid,
        }]

        stopped, failed = tunnel_lifecycle.close_pam_tunnels_on_logout(params)

        self.assertEqual((1, 0), (stopped, failed))
        close_tube.assert_called_once()
        stop_process.assert_not_called()
        unregister_mock.assert_called_once_with(os.getpid())
        request_owner_stop.assert_not_called()

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.stop_tunnel_process')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.unregister_tunnel')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.is_pid_alive', return_value=True)
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.request_owner_stop')
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.list_external_projections', return_value=[])
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle._iter_scoped_registry_tunnels')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle._iter_scoped_in_process_tunnels', return_value=[])
    def test_stop_scoped_never_signals_current_process_registry_entry(
        self,
        iter_tubes_mock,
        iter_registry_mock,
        list_external_mock,
        request_owner_stop,
        is_alive,
        unregister_mock,
        stop_process,
    ):
        iter_registry_mock.return_value = [{
            'pid': os.getpid(),
            'record_uid': 'uid-1',
            'tube_id': 'tube-stale',
            'host': '127.0.0.1',
            'port': 49153,
        }]

        stopped, failed = tunnel_lifecycle.stop_scoped_active_pam_tunnels(
            [self._make_params()],
            include_all=True,
        )

        self.assertEqual((1, 0), (stopped, failed))
        unregister_mock.assert_called_once_with(os.getpid())
        stop_process.assert_not_called()

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.unregister_tunnel_session')
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.publish_stopped')
    def test_close_missing_tube_is_already_stopped(self, publish_stopped, unregister_mock):
        class FakeRegistry:
            def close_tube(self, tube_id, reason=None):
                raise RuntimeError('tube not found')

        session = TunnelSession('tube-missing', 'conv', 'gw', b'key', record_uid='uid-1')
        ok, message = tunnel_lifecycle.close_tube_idempotently(
            FakeRegistry(),
            'tube-missing',
            session,
        )

        self.assertTrue(ok)
        self.assertEqual(message, 'already_stopped')
        unregister_mock.assert_called_once_with('tube-missing')
        publish_stopped.assert_called_once_with(session)

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.list_registered_tunnels', return_value=[])
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.unregister_tunnel_session')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.get_tunnel_session')
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.publish_stopped')
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.get_or_create_tube_registry')
    def test_reconcile_prunes_closed_local_tube(
        self,
        registry_mock,
        publish_stopped,
        session_mock,
        unregister_mock,
        list_registry_mock,
    ):
        registry = mock.Mock()
        registry.all_tube_ids.return_value = ['tube-closed']
        registry.tube_found.return_value = True
        registry.get_connection_state.return_value = 'closed'
        registry_mock.return_value = registry
        session = TunnelSession('tube-closed', 'conv', 'gw', b'key', record_uid='uid-1')
        session_mock.return_value = session

        pruned = tunnel_lifecycle.reconcile_local_tunnel_liveness(self._make_params())

        self.assertEqual(pruned, 1)
        unregister_mock.assert_called_once_with('tube-closed')
        publish_stopped.assert_called_once_with(session)
        list_registry_mock.assert_called_once_with(clean_stale=True)

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.stop_scoped_active_pam_tunnels', return_value=(0, 0))
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle._iter_scoped_in_process_tunnels', return_value=[])
    @mock.patch('keepercommander.commands.tunnel.pam_state_bridge.list_external_projections', return_value=[])
    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.list_registered_tunnels', return_value=[])
    def test_close_pam_tunnels_on_logout_targets_account(self, list_reg_mock, list_ext_mock, iter_mock, stop_mock):
        params = self._make_params(b'acct-a')
        with mock.patch(
            'keepercommander.commands.tunnel.tunnel_lifecycle.resolve_tunnel_account_uid',
            return_value=self._account_uid(b'acct-a'),
        ):
            stopped, failed = tunnel_lifecycle.close_pam_tunnels_on_logout(params)
        self.assertEqual((stopped, failed), (0, 0))
        iter_mock.assert_called_once()

    @mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.close_pam_tunnels_on_logout')
    @mock.patch('keepercommander.commands.utils.api.communicate_rest')
    def test_logout_closes_owned_tunnels_only(self, communicate_mock, close_mock):
        params = types.SimpleNamespace(
            session_token='token',
            sso_login_info=None,
            commands=[],
            clear_session=mock.Mock(),
        )
        LogoutCommand().execute(params)
        close_mock.assert_called_once_with(params)

    def test_switch_to_msp_does_not_close_tunnels(self):
        msp.current_mc_id = 42
        with mock.patch('keepercommander.commands.msp.api.query_enterprise'):
            with mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.close_pam_tunnels_on_logout') as close_mock:
                SwitchToMspCommand().execute(self._make_params())
        close_mock.assert_not_called()

    @mock.patch('keepercommander.commands.msp.api.login_and_get_mc_params_login_v3')
    @mock.patch('keepercommander.commands.msp.get_mc_by_name_or_id')
    def test_switch_to_mc_does_not_close_tunnels(self, get_mc_mock, login_mc_mock):
        params = types.SimpleNamespace(enterprise={'managed_companies': []}, account_uid_bytes=b'acct-a', records={})
        get_mc_mock.return_value = {'mc_enterprise_id': 99, 'mc_enterprise_name': 'Acme'}
        login_mc_mock.return_value = types.SimpleNamespace(account_uid_bytes=b'acct-a', records={})
        with mock.patch('keepercommander.commands.tunnel.tunnel_lifecycle.close_pam_tunnels_on_logout') as close_mock:
            SwitchToMcCommand().execute(params, mc='Acme')
        close_mock.assert_not_called()

    def test_switch_to_msp_already_msp_raises(self):
        with self.assertRaises(CommandError):
            SwitchToMspCommand().execute(self._make_params())


if __name__ == '__main__':
    unittest.main()
