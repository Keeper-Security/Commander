"""
Unit tests for `pam tunnel start`'s handling of the AIClosed (code 15) close
reason — the signal already reaches `TunnelSignalHandler` today, but used to
fall through to a silent `logging.debug(...)` with nothing shown to the user.
"""
import io
import json
import threading
import unittest
from contextlib import redirect_stdout

from keepercommander.commands.pam_launch.launch import EXIT_CODE_AI_TERMINATED
from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    TunnelSignalHandler,
    _print_ai_closed_banner,
)
from keepercommander.commands.tunnel_and_connections import (
    _AI_CLOSED_EXIT_CODE_BY_RECORD,
    _LEASE_SHUTDOWN_EVENTS_BY_RECORD,
)


class TestPrintAIClosedBanner(unittest.TestCase):

    def test_banner_text(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _print_ai_closed_banner()
        out = buf.getvalue()
        self.assertIn('Session terminated by KeeperAI.', out)
        self.assertIn('Critical activity was detected during this session.', out)
        self.assertIn('Contact your administrator to unlock this record.', out)


class TestTunnelSignalHandlerAIClosed(unittest.TestCase):

    def setUp(self):
        self.record_uid = 'test-ai-closed-record-uid'
        self.addCleanup(_AI_CLOSED_EXIT_CODE_BY_RECORD.pop, self.record_uid, None)
        self.addCleanup(_LEASE_SHUTDOWN_EVENTS_BY_RECORD.pop, self.record_uid, None)

    def _make_handler(self):
        return TunnelSignalHandler(
            params=None,
            record_uid=self.record_uid,
            gateway_uid='gateway-uid',
            symmetric_key=b'0' * 32,
            base64_nonce='nonce',
            conversation_id='conversation-id',
            tube_registry=None,
        )

    def _send_ai_closed(self, handler):
        payload = {
            'kind': 'channel_closed',
            'tube_id': 'fake-tube-id',
            'conversation_id': 'conversation-id',
            'data': json.dumps({'close_reason': {'code': 15}}),
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            handler.signal_from_rust(payload)
        return buf.getvalue()

    def test_prints_banner_and_sets_exit_code(self):
        handler = self._make_handler()
        out = self._send_ai_closed(handler)
        self.assertIn('Session terminated by KeeperAI.', out)
        self.assertEqual(
            _AI_CLOSED_EXIT_CODE_BY_RECORD.get(self.record_uid),
            EXIT_CODE_AI_TERMINATED,
        )

    def test_wakes_registered_foreground_shutdown_event(self):
        shutdown_event = threading.Event()
        _LEASE_SHUTDOWN_EVENTS_BY_RECORD[self.record_uid] = shutdown_event
        handler = self._make_handler()
        self._send_ai_closed(handler)
        self.assertTrue(shutdown_event.is_set())

    def test_no_shutdown_event_registered_does_not_raise(self):
        handler = self._make_handler()
        # No entry in _LEASE_SHUTDOWN_EVENTS_BY_RECORD for this record_uid —
        # mirrors interactive-shell mode, which never registers one.
        self._send_ai_closed(handler)
        self.assertEqual(
            _AI_CLOSED_EXIT_CODE_BY_RECORD.get(self.record_uid),
            EXIT_CODE_AI_TERMINATED,
        )


if __name__ == '__main__':
    unittest.main()
