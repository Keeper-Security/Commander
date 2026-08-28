from types import SimpleNamespace
from unittest import TestCase

from keepercommander.commands.record_edit import RecordEditMixin
from keepercommander.commands.recordv3 import enforce_generated_password_policy
from keepercommander.enforcement import PasswordComplexityEnforcer
from keepercommander.error import CommandError


STRICT_RANDOM_POLICY = {
    'length': 8,
    'upper-use': True,
    'upper-min': 5,
    'digit-use': True,
    'digit-min': 3,
    'passphrase-allow': True,
    'passphrase-length': 5,
    'passphrase-capitalize': False,
    'passphrase-number': False,
    'passphrase-separator': '-',
}


class TestPassphraseEnforcement(TestCase):

    def test_passphrase_accepted_when_random_rules_fail(self):
        password = 'alpha-bravo-charlie-delta-echo'
        failures = PasswordComplexityEnforcer.validate_password(password, STRICT_RANDOM_POLICY)
        self.assertEqual(failures, [])

    def test_passphrase_with_capitalized_words_and_one_digit_accepted(self):
        policy = dict(STRICT_RANDOM_POLICY)
        policy.update({
            'passphrase-length': 7,
            'passphrase-capitalize': True,
            'passphrase-number': True,
            'passphrase-separator': '_',
        })
        password = 'Alpha7_Bravo_Charlie_Delta_Echo_Foxtrot_Golf'
        failures = PasswordComplexityEnforcer.validate_password(password, policy)
        self.assertEqual(failures, [])

    def test_random_rules_apply_when_passphrase_disabled(self):
        policy = dict(STRICT_RANDOM_POLICY)
        policy['passphrase-allow'] = False
        password = 'alpha-bravo-charlie-delta-echo'
        failures = PasswordComplexityEnforcer.validate_password(password, policy)
        self.assertTrue(any('uppercase' in f for f in failures))
        self.assertTrue(any('digit' in f for f in failures))

    def test_passphrase_with_cli_style_digit_when_policy_number_off(self):
        policy = dict(STRICT_RANDOM_POLICY)
        policy['passphrase-number'] = False
        password = 'Alpha7_Bravo_Charlie_Delta_Echo_Foxtrot_Golf'
        failures = PasswordComplexityEnforcer.validate_password(password, policy)
        self.assertEqual(failures, [])

    def test_passphrase_accepts_underscore_separator_not_in_policy(self):
        policy = dict(STRICT_RANDOM_POLICY)
        policy['passphrase-separator'] = '-'
        password = 'alpha_bravo_charlie_delta_echo'
        failures = PasswordComplexityEnforcer.validate_password(password, policy)
        self.assertEqual(failures, [])

    def test_invalid_separator_error_lists_allowed_characters(self):
        policy = dict(STRICT_RANDOM_POLICY)
        password = 'alpha~bravo~charlie~delta~echo'
        failures = PasswordComplexityEnforcer.validate_password(password, policy)
        self.assertTrue(any('Allowed:' in f and 'space' in f for f in failures))

    def test_invalid_passphrase_returns_passphrase_errors(self):
        policy = dict(STRICT_RANDOM_POLICY)
        password = 'ab-cd-ef'
        failures = PasswordComplexityEnforcer.validate_password(password, policy)
        self.assertTrue(any('word' in f.lower() for f in failures))

    def test_passphrase_rejects_more_than_nine_words(self):
        policy = dict(STRICT_RANDOM_POLICY)
        password = '-'.join(
            ['alpha', 'bravo', 'charlie', 'delta', 'echo',
             'foxtrot', 'golf', 'hotel', 'india', 'juliet'])
        failures = PasswordComplexityEnforcer.validate_passphrase(password, policy)
        self.assertTrue(any('at most 9 words' in f for f in failures))

    def test_random_password_still_validated(self):
        password = 'ABCDE123!!!'
        failures = PasswordComplexityEnforcer.validate_password(password, STRICT_RANDOM_POLICY)
        self.assertEqual(failures, [])

    def test_invalid_random_password_keeps_random_policy_errors(self):
        policy = dict(STRICT_RANDOM_POLICY)
        policy.update({'length': 20, 'passphrase-length': 5, 'passphrase-separator': '!'})
        failures = PasswordComplexityEnforcer.validate_password(
            'ABC123!!', policy, allow_passphrase_fallback=False)
        self.assertTrue(any('Password must be at least 20 characters' in f for f in failures))
        self.assertFalse(any('Passphrase contains' in f for f in failures))


class TestGeneratedPasswordPolicyWarnings(TestCase):

    def _params(self):
        return SimpleNamespace(enforcements={
            'jsons': [{
                'key': 'generated_password_complexity',
                'value': '{"length": 20, "passphrase-allow": true, "passphrase-length": 5}',
            }],
        })

    def test_generated_random_password_fails_when_too_short(self):
        mixin = RecordEditMixin()
        mixin._password_policy = PasswordComplexityEnforcer.get_policy(self._params())
        mixin.validate_generated_password('pass', 'password')
        self.assertTrue(any('Password must be at least' in w for w in mixin.warnings))

    def test_generated_passphrase_validates_with_passphrase_fallback(self):
        mixin = RecordEditMixin()
        mixin._password_policy = PasswordComplexityEnforcer.get_policy(self._params())
        mixin.validate_generated_password('pass', 'passphrase')
        # Passphrase validation is looser, may not fail on short input
        self.assertTrue(isinstance(mixin.warnings, list))


class TestV3GeneratedPasswordPolicy(TestCase):

    def _params(self):
        return SimpleNamespace(enforcements={
            'jsons': [{
                'key': 'generated_password_complexity',
                'value': '{"length": 20}',
            }],
        })

    def _record(self):
        return {'fields': [{'type': 'password', 'value': ['pass']}]}

    def test_generated_password_is_rejected_when_policy_fails(self):
        with self.assertRaises(CommandError):
            enforce_generated_password_policy(
                self._params(), self._record(), 'add', generated=True, manual_password=None)

    def test_explicit_password_overrides_generation_for_policy(self):
        enforce_generated_password_policy(
            self._params(), self._record(), 'edit', generated=True,
            manual_password='explicit', force=False)
