"""Tests for PAM batch throttle retry helpers."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.error import KeeperApiError
from keepercommander.commands.pam_import.throttle_retry import (
    call_with_throttle_retry,
    compute_throttle_wait,
    is_throttle_error,
    raise_if_http_throttled,
    rest_fail_on_throttle,
)


class TestIsThrottleError(unittest.TestCase):
    def test_keeper_api_throttled(self):
        self.assertTrue(is_throttle_error(KeeperApiError('throttled', 'Please try again in 1 minute')))

    def test_int_http_status_does_not_crash(self):
        """KRouter raises KeeperApiError(status_code: int, body) — must not call .lower() on int."""
        self.assertFalse(is_throttle_error(KeeperApiError(500, 'Internal server error')))
        self.assertTrue(is_throttle_error(KeeperApiError(429, 'Too Many Requests')))

    def test_message_patterns(self):
        self.assertTrue(is_throttle_error(Exception('HTTP 429 rate limit exceeded')))
        self.assertFalse(is_throttle_error(Exception('access denied')))


class TestComputeThrottleWait(unittest.TestCase):
    def test_parses_minutes_and_applies_backoff_floor(self):
        err = KeeperApiError('throttled', 'Please try again in 2 minutes')
        self.assertEqual(compute_throttle_wait(err, 1), 120.0)
        self.assertEqual(compute_throttle_wait(err, 2), 120.0)

    def test_exponential_backoff_when_hint_is_small(self):
        err = KeeperApiError('throttled', 'try again in 10 seconds')
        self.assertEqual(compute_throttle_wait(err, 1), 30.0)
        self.assertEqual(compute_throttle_wait(err, 2), 60.0)


class TestCallWithThrottleRetry(unittest.TestCase):
    @patch('keepercommander.commands.pam_import.throttle_retry.time.sleep')
    def test_retries_then_succeeds(self, sleep):
        calls = {'n': 0}

        def fn():
            calls['n'] += 1
            if calls['n'] < 3:
                raise KeeperApiError('throttled', 'try again in 5 seconds')
            return 'ok'

        self.assertEqual(call_with_throttle_retry(fn, label='test'), 'ok')
        self.assertEqual(calls['n'], 3)
        self.assertEqual(sleep.call_count, 2)

    @patch('keepercommander.commands.pam_import.throttle_retry.time.sleep')
    def test_raises_after_max_retries_by_default(self, sleep):
        def fn():
            raise KeeperApiError('throttled', 'try again in 5 seconds')

        with self.assertRaises(KeeperApiError):
            call_with_throttle_retry(fn, max_retries=2, on_exhausted='raise')
        self.assertEqual(sleep.call_count, 2)

    @patch('keepercommander.commands.pam_import.throttle_retry.time.sleep')
    def test_repeat_max_interval_keeps_retrying(self, sleep):
        calls = {'n': 0}

        def fn():
            calls['n'] += 1
            if calls['n'] < 5:
                raise KeeperApiError('throttled', 'try again in 10 seconds')
            return 'ok'

        result = call_with_throttle_retry(
            fn, max_retries=2, on_exhausted='repeat_max_interval',
        )
        self.assertEqual(result, 'ok')
        self.assertEqual(calls['n'], 5)
        self.assertEqual(sleep.call_count, 4)
        # attempts 1–2 progressive (30, 60); attempts 3–4 repeat max (60)
        self.assertEqual(sleep.call_args_list[0].args[0], 30.0)
        self.assertEqual(sleep.call_args_list[1].args[0], 60.0)
        self.assertEqual(sleep.call_args_list[2].args[0], 60.0)
        self.assertEqual(sleep.call_args_list[3].args[0], 60.0)

    @patch('keepercommander.commands.pam_import.throttle_retry.time.sleep')
    def test_non_throttle_propagates_immediately(self, sleep):
        with self.assertRaises(KeeperApiError):
            call_with_throttle_retry(lambda: (_ for _ in ()).throw(KeeperApiError('access_denied', 'nope')))
        sleep.assert_not_called()

    def test_fail_on_throttle_skips_retry(self):
        calls = {'n': 0}

        def fn():
            calls['n'] += 1
            raise KeeperApiError('throttled', 'wait')

        with self.assertRaises(KeeperApiError):
            call_with_throttle_retry(fn, fail_on_throttle=True)
        self.assertEqual(calls['n'], 1)

    def test_rest_fail_on_throttle_ignores_magic_mock(self):
        params = MagicMock()
        params.rest_context.fail_on_throttle = MagicMock()
        self.assertFalse(rest_fail_on_throttle(params))
        params.rest_context.fail_on_throttle = True
        self.assertTrue(rest_fail_on_throttle(params))


class TestRaiseIfHttpThrottled(unittest.TestCase):
    def test_raises_on_json_throttle(self):
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {'Content-Type': 'application/json'}
        resp.json.return_value = {'error': 'throttled', 'message': 'slow down'}
        with self.assertRaises(KeeperApiError):
            raise_if_http_throttled(resp)

    def test_ignores_non_throttle_403(self):
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {'Content-Type': 'application/json'}
        resp.json.return_value = {'error': 'access_denied', 'message': 'no'}
        raise_if_http_throttled(resp)


if __name__ == '__main__':
    unittest.main()
