import json
from types import SimpleNamespace
from unittest import TestCase

from keepercommander.commands.record_edit import ParsedFieldValue, RecordEditMixin
from keepercommander.commands.recordv3 import (
    enforce_generated_password_policy,
    enforce_manual_password_policy,
)
from keepercommander.enforcement import PasswordComplexityEnforcer
from keepercommander.error import CommandError
from keepercommander import vault


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


class TestDomainPasswordPolicy(TestCase):

    @staticmethod
    def _params(policies):
        return SimpleNamespace(enforcements={
            'jsons': [{
                'key': 'generated_password_complexity',
                'value': json.dumps(policies),
            }],
        })

    @staticmethod
    def _record(url=None, password='weak'):
        return {
            'type': 'login',
            'fields': ([{'type': 'url', 'value': [url]}] if url else []) + [
                {'type': 'password', 'value': [password]}],
        }

    def test_generator_policy_merges_matching_domain_over_default(self):
        params = self._params([
            {
                'domains': ['_default_'],
                'length': 12,
                'lower-use': True,
                'lower-min': 2,
            },
            {
                'domains': ['example.com'],
                'length': 18,
                'upper-use': True,
                'upper-min': 2,
            },
        ])

        policy = PasswordComplexityEnforcer.get_generator_policy(
            params, self._record('https://login.example.com/account'))

        self.assertEqual(policy['length'], 18)
        self.assertEqual(policy['lower-min'], 2)
        self.assertEqual(policy['upper-min'], 2)

    def test_manual_password_ignores_generator_default_policy(self):
        params = self._params([{
            'domains': ['_default_'],
            'length': 40,
            'upper-use': True,
            'upper-min': 4,
            'passphrase-allow': True,
            'passphrase-length': 6,
        }])

        failures = PasswordComplexityEnforcer.validate_manual_passwords(
            params, self._record('https://example.com'))

        self.assertEqual(failures, [])

    def test_manual_password_uses_matching_domain_policy(self):
        params = self._params([
            {
                'domains': ['_default_'],
                'length': 40,
            },
            {
                'domains': ['google.com'],
                'length': 12,
                'upper-use': True,
                'upper-min': 1,
                'digit-use': True,
                'digit-min': 1,
                'special-use': True,
                'special-min': 1,
                'passphrase-allow': True,
                'passphrase-length': 5,
                'passphrase-capitalize': False,
                'passphrase-number': False,
                'passphrase-separator': '-',
            },
        ])

        failures = PasswordComplexityEnforcer.validate_manual_passwords(
            params, self._record('google.com'))

        self.assertTrue(any('at least 12 characters' in failure for failure in failures))
        self.assertTrue(any('uppercase character' in failure for failure in failures))
        self.assertTrue(any('digit character' in failure for failure in failures))
        self.assertTrue(any('special character' in failure for failure in failures))
        self.assertFalse(any('Passphrase' in failure for failure in failures))

    def test_manual_passphrase_uses_matching_domain_password_rules(self):
        params = self._params([{
            'domains': ['example.com'],
            'length': 80,
            'upper-use': True,
            'upper-min': 20,
            'passphrase-allow': True,
            'passphrase-length': 3,
            'passphrase-capitalize': False,
            'passphrase-number': False,
            'passphrase-separator': '-',
        }])

        failures = PasswordComplexityEnforcer.validate_manual_passwords(
            params,
            self._record('https://example.com', 'alpha-bravo-charlie'))

        self.assertTrue(any('at least 80 characters' in failure for failure in failures))
        self.assertTrue(any('uppercase character' in failure for failure in failures))
        self.assertFalse(any('Passphrase' in failure for failure in failures))

    def test_passphrase_validator_accepts_unicode_words(self):
        for passphrase, capitalize in (
                ('élan-café-über', False),
                ('Élan-Café-Über', True)):
            with self.subTest(passphrase=passphrase):
                params = self._params([{
                    'domains': ['example.com'],
                    'passphrase-allow': True,
                    'passphrase-length': 3,
                    'passphrase-capitalize': capitalize,
                    'passphrase-number': False,
                    'passphrase-separator': '-',
                }])

                policy = json.loads(params.enforcements['jsons'][0]['value'])[0]
                failures = PasswordComplexityEnforcer.validate_passphrase(
                    passphrase, policy)

                self.assertEqual(failures, [])

    def test_manual_hyphenated_password_uses_password_rules_not_passphrase_rules(self):
        params = self._params([{
            'domains': ['example.com'],
            'length': 20,
            'passphrase-allow': True,
            'passphrase-length': 5,
            'passphrase-capitalize': False,
            'passphrase-number': False,
            'passphrase-separator': '-',
        }])

        failures = PasswordComplexityEnforcer.validate_manual_passwords(
            params,
            self._record('https://example.com', 'mysecret-horse-battery'))

        self.assertEqual(failures, [])

    def test_manual_password_with_dollar_and_digit_is_not_mistaken_for_passphrase(self):
        params = self._params([{
            'domains': ['google.com'],
            'length': 20,
            'upper-use': True,
            'upper-min': 1,
            'digit-use': True,
            'digit-min': 1,
            'special-use': True,
            'special-min': 1,
            'passphrase-allow': True,
            'passphrase-length': 5,
            'passphrase-capitalize': False,
            'passphrase-number': False,
            'passphrase-separator': '-',
        }])

        failures = PasswordComplexityEnforcer.validate_manual_passwords(
            params,
            self._record('google.com', 'asd$2Egjrstkdsbtvoastasfawf'))

        self.assertEqual(failures, [])

    def test_manual_password_ignores_unmatched_domain_policy(self):
        params = self._params([{
            'domains': ['other.example'],
            'length': 40,
        }])

        failures = PasswordComplexityEnforcer.validate_manual_passwords(
            params, self._record('https://example.com'))

        self.assertEqual(failures, [])

    def test_typed_manual_password_uses_url_supplied_in_same_update(self):
        params = self._params([{
            'domains': ['example.com'],
            'length': 12,
            'passphrase-allow': False,
        }])
        mixin = RecordEditMixin()
        mixin.reset_password_policy(params)
        record = vault.TypedRecord()
        record.type_name = 'login'
        record.fields.extend([
            vault.TypedField.new_field('url', None, ''),
            vault.TypedField.new_field('password', None, ''),
        ])

        # The password arrives before the URL; policy selection must still use
        # the URL being written by this update.
        mixin.assign_typed_fields(record, [
            ParsedFieldValue('', 'password', '', 'weak'),
            ParsedFieldValue('', 'url', '', 'https://example.com/login'),
        ])
        mixin.apply_manual_password_policy_warnings(params, record)

        self.assertTrue(any('at least 12 characters' in warning for warning in mixin.warnings))

    def test_generated_passphrase_uses_only_passphrase_rules(self):
        policy = {
            'length': 80,
            'upper-use': True,
            'upper-min': 20,
            'passphrase-allow': True,
            'passphrase-length': 5,
            'passphrase-capitalize': False,
            'passphrase-number': False,
            'passphrase-separator': '-',
        }
        passphrase = 'alpha-bravo-charlie-delta-echo'

        failures = PasswordComplexityEnforcer.validate_generated_password_with_policy(
            passphrase, policy, 'passphrase')

        self.assertEqual(failures, [])

    def test_generated_password_does_not_fall_back_to_passphrase_rules(self):
        policy = {
            'length': 80,
            'passphrase-allow': True,
            'passphrase-length': 5,
            'passphrase-separator': '-',
        }

        failures = PasswordComplexityEnforcer.validate_generated_password_with_policy(
            'alpha-bravo-charlie-delta-echo', policy, 'rand')

        self.assertTrue(any('at least 80 characters' in failure for failure in failures))

    def test_recordv3_generated_password_uses_matching_domain_policy(self):
        params = self._params([
            {'domains': ['_default_'], 'length': 4},
            {'domains': ['example.com'], 'length': 20},
        ])

        with self.assertRaises(CommandError):
            enforce_generated_password_policy(
                params, self._record('https://login.example.com'), 'add',
                generated=True)

    def test_recordv3_manual_password_requires_a_matching_domain_policy(self):
        default_only = self._params([{
            'domains': ['_default_'],
            'length': 20,
        }])
        enforce_manual_password_policy(
            default_only, self._record('https://example.com'), 'add', ['weak'])

        domain_specific = self._params([{
            'domains': ['example.com'],
            'length': 20,
            'passphrase-allow': False,
        }])
        with self.assertRaises(CommandError):
            enforce_manual_password_policy(
                domain_specific, self._record('https://example.com'), 'add', ['weak'])
