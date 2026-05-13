import unittest

from keepercommander.commands.keeper_tenant_migrate.backoff import Retry, is_transient
from keepercommander.commands.keeper_tenant_migrate.safeguards import SafeguardBlocked


try:
    from keepercommander.error import KeeperApiError as _KeeperApiError
    _base = _KeeperApiError

    class _FakeApiError(_base):
        """Real subclass of KeeperApiError so the backoff type-allowlist
        accepts it — otherwise the allowlist rejects based on class."""
        def __init__(self, result_code, message):
            super().__init__(result_code, message)
except ImportError:                                  # pragma: no cover

    class _FakeApiError(Exception):
        def __init__(self, result_code, message):
            super().__init__(message)
            self.result_code = result_code


class IsTransientTests(unittest.TestCase):
    def test_plain_message_with_429_substring(self):
        self.assertTrue(is_transient(ConnectionError('got HTTP 429 from server')))

    def test_rate_limit_phrase(self):
        self.assertTrue(is_transient(ConnectionError('you are being rate limited')))

    def test_session_expired(self):
        self.assertTrue(is_transient(ConnectionError('session expired, re-auth')))

    def test_connection_reset(self):
        self.assertTrue(is_transient(ConnectionError('connection reset by peer')))

    def test_non_transient_passes_through(self):
        self.assertFalse(is_transient(ConnectionError('record not found')))

    def test_fatal_marker_overrides_transient_noise(self):
        # If the message mentions both forbidden AND timeout, it's fatal.
        self.assertFalse(is_transient(ConnectionError('forbidden: timed out')))

    def test_generic_exception_never_transient(self):
        # Type allow-list: generic programmer-bug exceptions with
        # confusing messages must never retry — they're bugs, not
        # transients. ValueError('got 429 cols') MUST NOT be retried.
        self.assertFalse(is_transient(ValueError('waited 429 ms')))
        self.assertFalse(is_transient(RuntimeError('timeout from cache')))
        self.assertFalse(is_transient(KeyError('session expired key')))

    def test_result_code_throttled(self):
        self.assertTrue(is_transient(_FakeApiError('throttled', 'x')))

    def test_result_code_auth_failed(self):
        self.assertTrue(is_transient(_FakeApiError('auth_failed', 'x')))

    def test_result_code_benign_is_not_transient(self):
        self.assertFalse(is_transient(_FakeApiError('invalid_param', 'x')))

    def test_none_exc(self):
        self.assertFalse(is_transient(None))


class RetrySuccessPathTests(unittest.TestCase):
    def test_returns_value_on_first_try(self):
        r = Retry(delay=0.0, sleeper=lambda _s: None)
        self.assertEqual(r.call(lambda: 42), 42)

    def test_non_transient_propagates_immediately(self):
        calls = []
        r = Retry(delay=0.0, sleeper=lambda _s: None)

        def boom():
            calls.append(1)
            raise ValueError('not retryable')

        with self.assertRaises(ValueError):
            r.call(boom)
        self.assertEqual(len(calls), 1)   # never retried


class RetryTransientPathTests(unittest.TestCase):
    def test_retries_once_on_transient_error(self):
        slept = []
        calls = {'n': 0}

        def attempt():
            calls['n'] += 1
            if calls['n'] == 1:
                raise ConnectionError('throttled — try again')
            return 'ok'

        r = Retry(delay=2.0, sleeper=slept.append)
        self.assertEqual(r.call(attempt, op_label='t'), 'ok')
        self.assertEqual(calls['n'], 2)
        self.assertEqual(len(slept), 1)
        # backoff_multiplier=2, attempt=0 → wait=delay*1=2.0 (but clamped to >=1.0)
        self.assertEqual(slept[0], 2.0)

    def test_second_transient_hit_escalates_to_safeguard(self):
        def always_throttled():
            raise ConnectionError('throttled forever')

        r = Retry(delay=0.5, sleeper=lambda _s: None)
        with self.assertRaises(SafeguardBlocked):
            r.call(always_throttled, op_label='probe')

    def test_zero_delay_still_waits_at_least_one_second(self):
        slept = []
        calls = {'n': 0}

        def attempt():
            calls['n'] += 1
            if calls['n'] == 1:
                raise ConnectionError('connection reset')
            return 'ok'

        r = Retry(delay=0.0, sleeper=slept.append)
        r.call(attempt)
        # Delay floor is 1.0 so the tenant actually gets a breather.
        self.assertGreaterEqual(slept[0], 1.0)

    def test_max_retries_two_allows_two_retries(self):
        calls = {'n': 0}

        def attempt():
            calls['n'] += 1
            if calls['n'] < 3:
                raise ConnectionError('throttled')
            return 'ok'

        r = Retry(delay=0.1, sleeper=lambda _s: None, max_retries=2)
        self.assertEqual(r.call(attempt), 'ok')
        self.assertEqual(calls['n'], 3)


class RunnerIntegrationTests(unittest.TestCase):
    """Smoke — each runner honors one retry on a transient call."""

    def test_user_runner_does_not_retry_invite_on_transient(self):
        # invite_user sends an email on each call — it's NOT idempotent.
        # Retry.call(idempotent=False) must surface the transient without
        # retrying so we don't send a duplicate invite email.
        from keepercommander.commands.keeper_tenant_migrate.users import UserRunner, FakeUserClient

        calls = {'n': 0}
        orig_invite = FakeUserClient.invite_user

        def flaky_invite(self, email, full_name, node, job_title=''):
            calls['n'] += 1
            if calls['n'] == 1:
                raise ConnectionError('throttled — slow down')
            return orig_invite(self, email, full_name, node, job_title)

        FakeUserClient.invite_user = flaky_invite
        try:
            client = FakeUserClient()
            runner = UserRunner(client, source_root='src', target_root='Root',
                                 delay=0.0, sleeper=lambda _s: None)
            with self.assertRaises(SafeguardBlocked):
                runner.run([{'email': 'alice@x', 'full_name': 'A'}])
            # Exactly one invite attempt — no duplicate email sent.
            self.assertEqual(calls['n'], 1)
        finally:
            FakeUserClient.invite_user = orig_invite

    def test_user_runner_retries_idempotent_placement(self):
        # Placement ops (add_user_team / add_user_role / add_user_alias)
        # ARE idempotent on the Keeper API side — Retry SHOULD retry
        # those on transient errors to absorb throttle blips.
        from keepercommander.commands.keeper_tenant_migrate.users import UserRunner, FakeUserClient

        calls = {'n': 0}
        orig = FakeUserClient.add_user_team

        def flaky_add(self, email, team_name, hsf_on=False):
            calls['n'] += 1
            if calls['n'] == 1:
                raise ConnectionError('rate-limit; retry')
            return orig(self, email, team_name, hsf_on=hsf_on)

        FakeUserClient.add_user_team = flaky_add
        try:
            client = FakeUserClient()
            runner = UserRunner(client, source_root='src', target_root='Root',
                                 delay=0.0, sleeper=lambda _s: None)
            inv = {'entities': {'users': [
                {'email': 'alice@x', 'teams': ['T1']},
            ]}}
            results = runner.run(
                [{'email': 'alice@x', 'full_name': 'A'}],
                inventory=inv,
            )
            self.assertEqual(results[0].status, 'YES')
            self.assertEqual(calls['n'], 2)   # one retry fired
            self.assertIn('T1', results[0].assignments['teams'])
        finally:
            FakeUserClient.add_user_team = orig

    def test_share_restorer_escalates_on_second_transient_hit(self):
        from keepercommander.commands.keeper_tenant_migrate.shares import ShareRestorer, FakeShareClient

        def always_throttled(target_uid, email):
            raise ConnectionError('throttled')

        client = FakeShareClient(
            records={'S1': {'user_permissions': [
                {'username': 'alice@x', 'editable': True,
                  'shareable': False, 'owner': False},
            ]}},
            share_behavior=always_throttled,
        )
        restorer = ShareRestorer(client, delay=0.0,
                                   sleeper=lambda _s: None)
        with self.assertRaises(SafeguardBlocked):
            restorer.run([{'source_uid': 'S1', 'target_uid': 'T1'}])


if __name__ == '__main__':
    unittest.main()
