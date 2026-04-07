"""Tests for execute_rest() throttle retry logic in rest_api.py.

Verifies:
- Normal (non-throttled) requests are unaffected
- Throttled requests retry up to 3 times with exponential backoff
- KeeperApiError raised after max retries
- --fail-on-throttle skips retries entirely
- Server's "try again in X" message is parsed correctly (seconds + minutes)
- Server wait capped at 300s
- Backoff takes the larger of server hint vs exponential schedule
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir so imports work from unit-tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from keepercommander.rest_api import execute_rest
from keepercommander.error import KeeperApiError
from keepercommander.params import RestApiContext
from keepercommander.proto import APIRequest_pb2 as proto


def make_context(fail_on_throttle=False):
    """Create a real RestApiContext with QRC disabled to simplify mocking."""
    ctx = RestApiContext(server='https://keepersecurity.com', locale='en_US')
    ctx.transmission_key = os.urandom(32)
    ctx.server_key_id = 7
    ctx.fail_on_throttle = fail_on_throttle
    ctx.disable_qrc()  # Skip QRC key negotiation
    return ctx


def make_throttle_response(message="Please try again in 1 minute"):
    """Build a fake HTTP 403 throttle response."""
    body = {"error": "throttled", "message": message}
    resp = MagicMock()
    resp.status_code = 403
    resp.headers = {'Content-Type': 'application/json'}
    resp.json.return_value = body
    resp.content = json.dumps(body).encode()
    return resp


def make_success_response():
    """Build a fake HTTP 200 response with empty body."""
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {'Content-Type': 'application/octet-stream'}
    resp.content = b''
    return resp


def make_payload():
    """Create a minimal ApiRequestPayload for execute_rest."""
    return proto.ApiRequestPayload()


class TestThrottleRetry(unittest.TestCase):
    """Tests for the bounded retry with exponential backoff on 403 throttle."""

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_normal_request_unaffected(self, mock_post, mock_sleep):
        """Non-throttled 200 response should pass through with no retries."""
        mock_post.return_value = make_success_response()

        execute_rest(make_context(), 'test/endpoint', make_payload())

        self.assertEqual(mock_post.call_count, 1)
        mock_sleep.assert_not_called()

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_retries_then_succeeds(self, mock_post, mock_sleep):
        """Throttle twice, succeed on 3rd attempt."""
        mock_post.side_effect = [
            make_throttle_response("try again in 30 seconds"),
            make_throttle_response("try again in 30 seconds"),
            make_success_response(),
        ]

        execute_rest(make_context(), 'test/endpoint', make_payload())

        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)
        # 1st: max(30, 30*2^0=30) = 30
        # 2nd: max(30, 30*2^1=60) = 60
        calls = [c[0][0] for c in mock_sleep.call_args_list]
        self.assertEqual(calls, [30, 60])

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_raises_after_max_retries(self, mock_post, mock_sleep):
        """Always throttled — should raise KeeperApiError after 3 retries."""
        mock_post.return_value = make_throttle_response("try again in 1 minute")

        with self.assertRaises(KeeperApiError):
            execute_rest(make_context(), 'test/endpoint', make_payload())

        # 1 initial + 3 retries = 4 posts, error raised when retry 4 > max 3
        self.assertEqual(mock_post.call_count, 4)
        self.assertEqual(mock_sleep.call_count, 3)

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_fail_on_throttle_skips_retry(self, mock_post, mock_sleep):
        """--fail-on-throttle should return error immediately with no retries."""
        mock_post.return_value = make_throttle_response()

        result = execute_rest(make_context(fail_on_throttle=True), 'test/endpoint', make_payload())

        # When fail_on_throttle=True, the throttle block is skipped and the
        # failure dict is returned directly (no retry, no exception)
        self.assertEqual(result.get('error'), 'throttled')
        self.assertEqual(mock_post.call_count, 1)
        mock_sleep.assert_not_called()

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_parses_seconds_hint(self, mock_post, mock_sleep):
        """Server says 'try again in 45 seconds' — wait should be 45s."""
        mock_post.side_effect = [
            make_throttle_response("try again in 45 seconds"),
            make_success_response(),
        ]

        execute_rest(make_context(), 'test/endpoint', make_payload())

        # max(45, 30*2^0=30) = 45
        mock_sleep.assert_called_once_with(45)

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_parses_minutes_hint(self, mock_post, mock_sleep):
        """Server says 'try again in 2 minutes' — wait should be 120s."""
        mock_post.side_effect = [
            make_throttle_response("try again in 2 minutes"),
            make_success_response(),
        ]

        execute_rest(make_context(), 'test/endpoint', make_payload())

        # max(120, 30*2^0=30) = 120
        mock_sleep.assert_called_once_with(120)

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_caps_server_wait_at_300s(self, mock_post, mock_sleep):
        """Server says 'try again in 49 minutes' — capped to 300s."""
        mock_post.side_effect = [
            make_throttle_response("try again in 49 minutes"),
            make_success_response(),
        ]

        execute_rest(make_context(), 'test/endpoint', make_payload())

        # min(2940, 300)=300; max(300, 30*2^0=30) = 300
        mock_sleep.assert_called_once_with(300)

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_exponential_backoff_progression(self, mock_post, mock_sleep):
        """Verify backoff doubles: 30s, 60s, 120s when server hint is small."""
        mock_post.return_value = make_throttle_response("try again in 10 seconds")

        with self.assertRaises(KeeperApiError):
            execute_rest(make_context(), 'test/endpoint', make_payload())

        # Server says 10s, but backoff wins: max(10, 30*2^0)=30, max(10, 30*2^1)=60, max(10, 30*2^2)=120
        calls = [c[0][0] for c in mock_sleep.call_args_list]
        self.assertEqual(calls, [30, 60, 120])

    @patch('keepercommander.rest_api.time.sleep')
    @patch('keepercommander.rest_api.requests.post')
    def test_no_message_defaults_to_60s(self, mock_post, mock_sleep):
        """Missing 'try again' text defaults to 60s server hint."""
        mock_post.side_effect = [
            make_throttle_response("Rate limit exceeded"),  # no "try again in X"
            make_success_response(),
        ]

        execute_rest(make_context(), 'test/endpoint', make_payload())

        # Default 60s; max(60, 30*2^0=30) = 60
        mock_sleep.assert_called_once_with(60)


if __name__ == '__main__':
    unittest.main()
