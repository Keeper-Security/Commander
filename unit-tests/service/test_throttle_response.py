"""Service-mode throttle / rate-limit JSON 429 handling."""

import unittest
from unittest import mock

from flask_limiter.errors import RateLimitExceeded

from keepercommander.error import KeeperApiError
from keepercommander.service.app import create_app
from keepercommander.service.util.command_util import CommandExecutor
from keepercommander.service.util.parse_keeper_response import KeeperResponseParser
from keepercommander.service.util.throttle import (
    RESULT_EDGE_429,
    RESULT_RATE_LIMITED,
    RESULT_THROTTLED,
    clean_throttle_message,
    is_throttle_error,
    is_throttle_text,
    rate_limited_response,
    throttle_error_response,
)


class TestThrottleHelpers(unittest.TestCase):
    def test_clean_throttle_message_strips_retry_log_noise(self):
        noisy = (
            "Throttled (attempt 1/3), retrying in 60 seconds\n"
            "Throttled (attempt 1/3), retrying in 60 seconds\n"
            "Due to repeated attempts, your request has been throttled. Try again in 1 minute."
        )
        self.assertEqual(
            clean_throttle_message(noisy),
            'Due to repeated attempts, your request has been throttled. Try again in 1 minute.',
        )
        self.assertEqual(
            clean_throttle_message('Throttled (attempt 1/3), retrying in 60 seconds\n' * 5),
            'Request throttled by Keeper API',
        )

    def test_clean_throttle_message_strips_result_code_prefix(self):
        self.assertEqual(
            clean_throttle_message('throttled: Try again in 1 minute.'),
            'Try again in 1 minute.',
        )

    def test_is_throttle_detection(self):
        self.assertTrue(is_throttle_error(KeeperApiError('throttled', 'slow down')))
        self.assertTrue(is_throttle_error(KeeperApiError(429, 'Too Many Requests')))
        self.assertTrue(is_throttle_text('too many requests'))
        self.assertFalse(is_throttle_text('invalid rate limit config value'))
        self.assertFalse(is_throttle_error(KeeperApiError('access_denied', 'nope')))

    def test_throttle_and_rate_limited_response_shapes(self):
        body, status = throttle_error_response('Try again in 1 minute.', RESULT_THROTTLED)
        self.assertEqual(status, 429)
        self.assertEqual(body['result_code'], RESULT_THROTTLED)
        self.assertEqual(body['error'], 'Try again in 1 minute.')

        body, status = throttle_error_response('Too Many Requests', 429)
        self.assertEqual(body['result_code'], RESULT_EDGE_429)

        body, status = rate_limited_response('3 per 1 minute')
        self.assertEqual(status, 429)
        self.assertEqual(body['result_code'], RESULT_RATE_LIMITED)
        self.assertIn('3 per 1 minute', body['error'])


class TestThrottleResponse(unittest.TestCase):
    def test_parser_maps_throttled_text_to_429(self):
        result = KeeperResponseParser._parse_logging_based_command(
            'keep-alive',
            'throttled: Due to repeated attempts, your request has been throttled.',
        )
        self.assertEqual(result['status_code'], 429)
        self.assertEqual(result['result_code'], RESULT_THROTTLED)
        self.assertEqual(
            result['error'],
            'Due to repeated attempts, your request has been throttled.',
        )

    def test_parser_does_not_treat_rate_limit_config_text_as_throttle(self):
        result = KeeperResponseParser._parse_logging_based_command(
            'help',
            'Invalid rate limit config value',
        )
        self.assertNotEqual(result.get('status_code'), 429)
        self.assertNotEqual(result.get('result_code'), RESULT_THROTTLED)

    def test_execute_maps_keeper_throttle_to_429(self):
        err = KeeperApiError('throttled', 'Try again in 1 minute.')
        params = mock.Mock(service_mode=False)
        params.rest_context = mock.Mock()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded',
            return_value=params,
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=err):
            body, status = CommandExecutor.execute('keep-alive')
        self.assertEqual(status, 429)
        self.assertEqual(body['result_code'], RESULT_THROTTLED)
        self.assertEqual(body['error'], 'Try again in 1 minute.')

    def test_execute_maps_edge_429(self):
        err = KeeperApiError(429, 'Too Many Requests')
        params = mock.Mock(service_mode=False)
        params.rest_context = mock.Mock()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded',
            return_value=params,
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=err):
            body, status = CommandExecutor.execute('keep-alive')
        self.assertEqual(status, 429)
        self.assertEqual(body['result_code'], RESULT_EDGE_429)
        self.assertEqual(body['error'], 'Too Many Requests')

    def test_execute_preserves_non_throttle_keeper_error_as_500(self):
        err = KeeperApiError('access_denied', 'nope')
        params = mock.Mock(service_mode=False)
        params.rest_context = mock.Mock()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded',
            return_value=params,
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=err):
            body, status = CommandExecutor.execute('keep-alive')
        self.assertEqual(status, 500)
        self.assertIn('Unexpected error', body['error'])

    def test_flask_limiter_returns_json_429(self):
        with mock.patch('keepercommander.service.app.init_routes'), \
             mock.patch('keepercommander.service.app.is_behind_proxy', return_value=False), \
             mock.patch('keepercommander.service.app.limiter.init_app'):
            app = create_app()

        limit = mock.MagicMock()
        limit.error_message = '3 per 1 minute'

        @app.route('/_test_limited')
        def _limited():
            raise RateLimitExceeded(limit)

        resp = app.test_client().get('/_test_limited')
        self.assertEqual(resp.status_code, 429)
        data = resp.get_json()
        self.assertEqual(data['status'], 'error')
        self.assertEqual(data['result_code'], RESULT_RATE_LIMITED)
        self.assertIn('rate limit', data['error'].lower())


if __name__ == '__main__':
    unittest.main()
