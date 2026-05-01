"""Unit tests for PAM import workflow parsing, validation, and protobuf assembly."""

import unittest
from unittest.mock import MagicMock, patch

from keepercommander.error import CommandError, KeeperApiError
from keepercommander.commands.pam_import.base import PamWorkflowOptions
from keepercommander.commands.pam_import import workflow_apply
from keepercommander.commands.pam_import.workflow_apply import (
    _build_temporal_filter,
    _build_parameters,
    _DAY_PROTO_MAP,
    _is_throttle_error,
    _post_with_throttle_retry,
)
from keepercommander.commands.workflow.helpers import WorkflowFormatter
from keepercommander.proto import workflow_pb2

# time-of-day is HHMM-encoded on the wire (e.g. 09:00 -> 900) — see
# WorkflowFormatter._parse_time_to_hhmm. Keep the test name from before but
# point it at the canonical helper so we drift with it instead of with our copy.
_parse_time_to_hhmm = WorkflowFormatter._parse_time_to_hhmm


# ---------------------------------------------------------------------------
# Duration parsing
# ---------------------------------------------------------------------------

class TestParseDuration(unittest.TestCase):

    def test_hours(self):
        self.assertEqual(PamWorkflowOptions._parse_duration('8h'), 8 * 3_600_000)

    def test_minutes(self):
        self.assertEqual(PamWorkflowOptions._parse_duration('30m'), 30 * 60_000)

    def test_days(self):
        self.assertEqual(PamWorkflowOptions._parse_duration('1d'), 86_400_000)

    def test_bare_integer_treated_as_minutes(self):
        self.assertEqual(PamWorkflowOptions._parse_duration('45'), 45 * 60_000)

    def test_none_returns_default(self):
        self.assertEqual(PamWorkflowOptions._parse_duration(None), 86_400_000)

    def test_zero_raises(self):
        with self.assertRaises(CommandError):
            PamWorkflowOptions._parse_duration('0h')

    def test_negative_raises(self):
        with self.assertRaises(CommandError):
            PamWorkflowOptions._parse_duration('-1d')

    def test_invalid_string_raises(self):
        with self.assertRaises(CommandError):
            PamWorkflowOptions._parse_duration('invalid')

    def test_uppercase_suffix(self):
        self.assertEqual(PamWorkflowOptions._parse_duration('2H'), 2 * 3_600_000)


# ---------------------------------------------------------------------------
# Day mapping
# ---------------------------------------------------------------------------

class TestDayMapping(unittest.TestCase):

    def test_all_3letter_tokens_in_map(self):
        expected = {'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'}
        self.assertEqual(set(_DAY_PROTO_MAP.keys()), expected)

    def test_monday_maps_to_proto(self):
        self.assertEqual(_DAY_PROTO_MAP['mon'], workflow_pb2.MONDAY)

    def test_friday_maps_to_proto(self):
        self.assertEqual(_DAY_PROTO_MAP['fri'], workflow_pb2.FRIDAY)


# ---------------------------------------------------------------------------
# Time-of-day parsing
# ---------------------------------------------------------------------------

class TestParseTimeToHHMM(unittest.TestCase):
    """Server expects HHMM integer encoding (e.g. 09:00 -> 900, 17:30 -> 1730)."""

    def test_midnight(self):
        self.assertEqual(_parse_time_to_hhmm('00:00'), 0)

    def test_nine_am(self):
        self.assertEqual(_parse_time_to_hhmm('09:00'), 900)

    def test_half_past_five_pm(self):
        self.assertEqual(_parse_time_to_hhmm('17:30'), 1730)

    def test_invalid_format_raises(self):
        with self.assertRaises(CommandError):
            _parse_time_to_hhmm('25:00')

    def test_non_numeric_raises(self):
        with self.assertRaises(CommandError):
            _parse_time_to_hhmm('ab:cd')


# ---------------------------------------------------------------------------
# V2: trivial workflow detection
# ---------------------------------------------------------------------------

class TestTrivialWorkflow(unittest.TestCase):

    def test_empty_dict_returns_none(self):
        self.assertIsNone(PamWorkflowOptions.load({}))

    def test_none_returns_none(self):
        self.assertIsNone(PamWorkflowOptions.load(None))

    def test_all_flags_off_no_temporal_returns_none(self):
        self.assertIsNone(PamWorkflowOptions.load({
            'approvals_needed': 0,
            'checkout_needed': False,
            'require_mfa': False,
        }))

    def test_checkout_needed_true_is_non_trivial(self):
        opts = PamWorkflowOptions.load({'checkout_needed': True, 'access_duration': '2h'})
        self.assertIsNotNone(opts)
        self.assertTrue(opts.checkout_needed)

    def test_require_mfa_true_is_non_trivial(self):
        opts = PamWorkflowOptions.load({'require_mfa': True})
        self.assertIsNotNone(opts)

    def test_allowed_days_is_non_trivial(self):
        opts = PamWorkflowOptions.load({'allowed_times': {'allowed_days': ['mon'], 'timezone': 'UTC'}})
        self.assertIsNotNone(opts)

    def test_approvals_needed_gt0_is_non_trivial(self):
        opts = PamWorkflowOptions.load({'approvals_needed': 2})
        self.assertIsNotNone(opts)


# ---------------------------------------------------------------------------
# V7: escalation_after requires escalation: true
# ---------------------------------------------------------------------------

class TestEscalationValidation(unittest.TestCase):

    def test_escalation_after_without_escalation_raises(self):
        data = {
            'approvals_needed': 1,
            'approvers': [{
                'principal': {'type': 'user', 'email': 'a@b.com'},
                'escalation': False,
                'escalation_after': '30m',
            }],
        }
        with self.assertRaises(CommandError):
            PamWorkflowOptions.load(data)

    def test_escalation_after_with_escalation_true_ok(self):
        data = {
            'approvals_needed': 1,
            'approvers': [{
                'principal': {'type': 'user', 'email': 'a@b.com'},
                'escalation': True,
                'escalation_after': '30m',
            }],
        }
        opts = PamWorkflowOptions.load(data)
        self.assertIsNotNone(opts)
        self.assertEqual(opts.approvers[0]['escalation_after_ms'], 30 * 60_000)


# ---------------------------------------------------------------------------
# V8: time_ranges requires timezone
# ---------------------------------------------------------------------------

class TestTimezoneRequirement(unittest.TestCase):

    def test_time_ranges_without_timezone_raises(self):
        data = {
            'require_mfa': True,
            'allowed_times': {
                'time_ranges': [{'start': '09:00', 'end': '17:00'}],
            },
        }
        with self.assertRaises(CommandError):
            PamWorkflowOptions.load(data)

    def test_time_ranges_with_timezone_ok(self):
        data = {
            'require_mfa': True,
            'allowed_times': {
                'time_ranges': [{'start': '09:00', 'end': '17:00'}],
                'timezone': 'America/New_York',
            },
        }
        opts = PamWorkflowOptions.load(data)
        self.assertIsNotNone(opts)
        self.assertEqual(opts.timezone, 'America/New_York')
        self.assertEqual(len(opts.time_ranges), 1)


# ---------------------------------------------------------------------------
# V9: access_duration default
# ---------------------------------------------------------------------------

class TestAccessDurationDefault(unittest.TestCase):

    def test_missing_access_duration_defaults_to_1d(self):
        opts = PamWorkflowOptions.load({'approvals_needed': 1})
        self.assertEqual(opts.access_duration_ms, 86_400_000)

    def test_explicit_duration_parsed(self):
        opts = PamWorkflowOptions.load({'approvals_needed': 1, 'access_duration': '4h'})
        self.assertEqual(opts.access_duration_ms, 4 * 3_600_000)


# ---------------------------------------------------------------------------
# Protobuf assembly: _build_parameters
# ---------------------------------------------------------------------------

class TestBuildParameters(unittest.TestCase):

    def _make_uid_bytes(self):
        import base64
        return base64.urlsafe_b64decode('AAAAAAAAAAAAAAAAAAAAAA==')

    def test_basic_fields_populated(self):
        opts = PamWorkflowOptions.load({
            'approvals_needed': 2,
            'checkout_needed': True,
            'require_mfa': True,
            'access_duration': '8h',
        })
        uid_bytes = self._make_uid_bytes()
        params_proto = _build_parameters(uid_bytes, 'Test Machine', opts)
        self.assertEqual(params_proto.approvalsNeeded, 2)
        self.assertTrue(params_proto.checkoutNeeded)
        self.assertTrue(params_proto.requireMFA)
        self.assertEqual(params_proto.accessLength, 8 * 3_600_000)
        self.assertEqual(params_proto.resource.value, uid_bytes)
        self.assertEqual(params_proto.resource.name, 'Test Machine')

    def test_temporal_filter_attached(self):
        opts = PamWorkflowOptions.load({
            'require_mfa': True,
            'allowed_times': {
                'allowed_days': ['mon', 'fri'],
                'time_ranges': [{'start': '09:00', 'end': '17:00'}],
                'timezone': 'UTC',
            },
        })
        uid_bytes = self._make_uid_bytes()
        params_proto = _build_parameters(uid_bytes, 'Box', opts)
        at = params_proto.allowedTimes
        self.assertIn(workflow_pb2.MONDAY, at.allowedDays)
        self.assertIn(workflow_pb2.FRIDAY, at.allowedDays)
        self.assertEqual(len(at.timeRanges), 1)
        # HHMM integer encoding: 09:00 -> 900, 17:00 -> 1700
        self.assertEqual(at.timeRanges[0].startTime, 900)
        self.assertEqual(at.timeRanges[0].endTime, 1700)
        self.assertEqual(at.timeZone, 'UTC')

    def test_no_allowed_times_no_temporal(self):
        opts = PamWorkflowOptions.load({'approvals_needed': 1})
        uid_bytes = self._make_uid_bytes()
        params_proto = _build_parameters(uid_bytes, 'Box', opts)
        self.assertFalse(params_proto.HasField('allowedTimes'))


# ---------------------------------------------------------------------------
# validate_principals
# ---------------------------------------------------------------------------

class TestValidatePrincipals(unittest.TestCase):

    def _make_params(self, team_uids):
        p = MagicMock()
        p.team_cache = {uid: {} for uid in team_uids}
        return p

    def test_known_team_uid_passes(self):
        opts = PamWorkflowOptions.load({
            'approvals_needed': 1,
            'approvers': [{'principal': {'type': 'team', 'team_uid_base64url': 'validUID123'}}],
        })
        params = self._make_params(['validUID123'])
        opts.validate_principals(params, 'MyResource')

    def test_unknown_team_uid_raises(self):
        opts = PamWorkflowOptions.load({
            'approvals_needed': 1,
            'approvers': [{'principal': {'type': 'team', 'team_uid_base64url': 'unknownUID'}}],
        })
        params = self._make_params(['otherUID'])
        with self.assertRaises(CommandError):
            opts.validate_principals(params, 'MyResource')

    def test_user_principal_not_checked_against_team_cache(self):
        opts = PamWorkflowOptions.load({
            'approvals_needed': 1,
            'approvers': [{'principal': {'type': 'user', 'email': 'user@example.com'}}],
        })
        params = self._make_params([])
        opts.validate_principals(params)


# ---------------------------------------------------------------------------
# Throttle / 429 retry wrapper
# ---------------------------------------------------------------------------

class TestThrottleErrorDetection(unittest.TestCase):

    def test_keeper_api_error_429_is_throttle(self):
        self.assertTrue(_is_throttle_error(KeeperApiError(429, 'Too many requests')))

    def test_keeper_api_error_500_is_not_throttle(self):
        self.assertFalse(_is_throttle_error(KeeperApiError(500, 'Internal error')))

    def test_string_throttle_in_msg_is_throttle(self):
        self.assertTrue(_is_throttle_error(Exception('record was throttled')))

    def test_too_many_in_msg_is_throttle(self):
        self.assertTrue(_is_throttle_error(Exception('Too many requests')))

    def test_unrelated_error_is_not_throttle(self):
        self.assertFalse(_is_throttle_error(Exception('connection refused')))


class TestThrottleRetry(unittest.TestCase):

    def test_no_retry_on_non_throttle(self):
        with patch.object(workflow_apply, '_post_request_to_router',
                          side_effect=KeeperApiError(500, 'boom')) as mock_post:
            with self.assertRaises(KeeperApiError):
                _post_with_throttle_retry(MagicMock(), 'read_workflow_config')
        self.assertEqual(mock_post.call_count, 1)

    def test_retries_then_succeeds(self):
        # First two calls 429, third succeeds. Patch sleep to keep test fast.
        side_effects = [KeeperApiError(429, 'Too many requests'),
                        KeeperApiError(429, 'Too many requests'),
                        'OK']
        with patch.object(workflow_apply, '_post_request_to_router',
                          side_effect=side_effects) as mock_post, \
             patch.object(workflow_apply.time, 'sleep') as mock_sleep:
            result = _post_with_throttle_retry(MagicMock(), 'read_workflow_config')
        self.assertEqual(result, 'OK')
        self.assertEqual(mock_post.call_count, 3)
        # Two backoff sleeps: 10s, 15s (10 * 1.5)
        self.assertEqual([round(c.args[0], 2) for c in mock_sleep.call_args_list], [10.0, 15.0])

    def test_exhausts_retries_and_reraises(self):
        with patch.object(workflow_apply, '_post_request_to_router',
                          side_effect=KeeperApiError(429, 'Too many requests')) as mock_post, \
             patch.object(workflow_apply.time, 'sleep'):
            with self.assertRaises(KeeperApiError):
                _post_with_throttle_retry(MagicMock(), 'read_workflow_config')
        self.assertEqual(mock_post.call_count, workflow_apply._THROTTLE_MAX_RETRIES)


if __name__ == '__main__':
    unittest.main()
