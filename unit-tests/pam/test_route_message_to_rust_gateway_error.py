"""
Regression test: an async Gateway error (is_ok=False) delivered via the
WebSocket message-routing path must close the tube for a KeeperSSH Proxy
tunnel that failed to open, not just stash the error onto fields nobody
reads again.

Bug: route_message_to_rust()'s is_ok=False branch only set
session.gateway_error_message/gateway_error_event, which are only ever
consumed by the synchronous connect-retry wait in tunnel_and_connections.py.
A KeeperSSH Proxy setup failure arriving after that window closes (Rust's
real upstream auth/connect attempt takes a real network round trip) left
the tube open forever.

Scope of the fix (deliberately narrow): only the 3 known-fatal KeeperSSH
Proxy setup error codes (auth/timeout/config), only within the same window
as the longest legitimate startup delay (ephemeral JIT account creation,
120s by default). Everything else — the generic proxy error code, unrelated
gateway errors (e.g. 401 on get_leafs), and any error arriving after the
window — must keep today's log-and-stash-only behavior so a plain SSH
tunnel or an already-established, long-running KeeperSSH Proxy tunnel is
never torn down by an unrelated later message.
"""

import json
import unittest
from unittest import mock

from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    CloseConnectionReasons,
    TunnelSession,
    ephemeral_gateway_timeout_ms,
    get_tunnel_session,
    register_conversation_key,
    register_tunnel_session,
    route_message_to_rust,
    unregister_conversation_key,
    unregister_tunnel_session,
)

_WINDOW_SECONDS = ephemeral_gateway_timeout_ms(True) / 1000.0


class TestRouteMessageToRustGatewayError(unittest.TestCase):
    def setUp(self):
        self.conversation_id = 'conv-under-test'
        self.tube_id = 'tube-under-test'
        register_conversation_key(self.conversation_id, b'dummy-symmetric-key')
        self.session = TunnelSession(
            tube_id=self.tube_id, conversation_id=self.conversation_id,
            gateway_uid='gw-uid', symmetric_key=b'dummy-symmetric-key',
        )
        register_tunnel_session(self.tube_id, self.session)

    def tearDown(self):
        unregister_conversation_key(self.conversation_id)
        unregister_tunnel_session(self.tube_id)

    def _gateway_error_response(self, error_text):
        return {
            'conversationId': self.conversation_id,
            'payload': json.dumps({'is_ok': False, 'data': error_text}),
        }

    def _make_registry(self):
        tube_registry = mock.Mock()
        tube_registry.tube_id_from_connection_id.return_value = self.tube_id
        return tube_registry

    def test_auth_failed_within_window_closes_and_unregisters_tube(self):
        tube_registry = self._make_registry()

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_auth_failed'),
            tube_registry,
        )

        tube_registry.close_tube.assert_called_once_with(
            self.tube_id, reason=CloseConnectionReasons.Normal)
        self.assertIsNone(get_tunnel_session(self.tube_id))

    def test_timeout_within_window_closes_tube(self):
        tube_registry = self._make_registry()

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_timeout'),
            tube_registry,
        )

        tube_registry.close_tube.assert_called_once_with(
            self.tube_id, reason=CloseConnectionReasons.Normal)

    def test_config_error_within_window_closes_tube(self):
        tube_registry = self._make_registry()

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_config_error'),
            tube_registry,
        )

        tube_registry.close_tube.assert_called_once_with(
            self.tube_id, reason=CloseConnectionReasons.Normal)

    def test_generic_proxy_error_code_does_not_close_tube(self):
        # The generic `..._keeperssh_proxy_error` code (missing module /
        # missing credentials / unexpected error) is covered by earlier,
        # synchronous validation -- not in scope for this async fallback.
        tube_registry = self._make_registry()

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_error'),
            tube_registry,
        )

        tube_registry.close_tube.assert_not_called()
        self.assertIsNotNone(get_tunnel_session(self.tube_id))

    def test_unrelated_gateway_error_does_not_close_tube(self):
        # E.g. a 401 on get_leafs for an unrelated action on the same
        # conversation -- must not tear down an otherwise-healthy tunnel.
        tube_registry = self._make_registry()

        route_message_to_rust(self._gateway_error_response('some unrelated error'), tube_registry)

        tube_registry.close_tube.assert_not_called()

    def test_auth_failed_after_window_does_not_close_tube(self):
        # Simulate a long-running, already-established tunnel: creation_time
        # is older than the startup grace window, so even a matching fatal
        # code must not close it.
        self.session.creation_time -= (_WINDOW_SECONDS + 5)
        tube_registry = self._make_registry()

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_auth_failed'),
            tube_registry,
        )

        tube_registry.close_tube.assert_not_called()
        self.assertIsNotNone(get_tunnel_session(self.tube_id))

    def test_matching_code_still_stashes_message_when_outside_window(self):
        self.session.creation_time -= (_WINDOW_SECONDS + 5)
        tube_registry = self._make_registry()

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_timeout'),
            tube_registry,
        )

        self.assertEqual(self.session.gateway_error_message, 'gateway_webrtcaction_keeperssh_proxy_timeout')
        self.assertTrue(self.session.gateway_error_event.is_set())

    def test_gateway_error_still_stashes_message_for_synchronous_waiter(self):
        # Even for a non-matching/non-fatal error, the message/event stash
        # must still happen so a synchronous waiter still in its retry
        # window picks up the real error text instead of a generic timeout.
        tube_registry = self._make_registry()

        route_message_to_rust(self._gateway_error_response('specific failure reason'), tube_registry)

        self.assertEqual(self.session.gateway_error_message, 'specific failure reason')
        self.assertTrue(self.session.gateway_error_event.is_set())

    def test_no_tube_found_does_not_raise(self):
        tube_registry = mock.Mock()
        tube_registry.tube_id_from_connection_id.return_value = None

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_auth_failed'),
            tube_registry,
        )

        tube_registry.close_tube.assert_not_called()

    def test_close_tube_exception_does_not_prevent_unregister(self):
        tube_registry = self._make_registry()
        tube_registry.close_tube.side_effect = Exception('tube already gone')

        route_message_to_rust(
            self._gateway_error_response('gateway_webrtcaction_keeperssh_proxy_auth_failed'),
            tube_registry,
        )

        self.assertIsNone(get_tunnel_session(self.tube_id))


if __name__ == '__main__':
    unittest.main()
