"""
cp-rotation-skip-feat — Story 1 validator tests

Tests for the schema-validator changes that gate the rest of the feature:
  - rotation: block becomes optional
  - rotation.on_demand (boolean, mutually exclusive with rotation.schedule)
  - rotation.rotate_on_provision (boolean, default true)
  - account.existing_password (non-empty string)
  - INVARIANT-001 cross-section invariant
  - DEFAULT_COMPLEXITY module-level constant
  - empty-dict rotation: {} edge case
  - regression: account.initial_password still rejected (KC-1007-2 unchanged)
  - regression: deprecated pam.rotation: shape still emits migration error
"""

import pytest
from unittest import TestCase
from unittest.mock import MagicMock

from keepercommander.commands.credential_provision import (
    CredentialProvisionCommand,
    DEFAULT_COMPLEXITY,
)


# =============================================================================
# Shared fixtures / helpers
# =============================================================================


def make_valid_user():
    return {
        'first_name': 'Test',
        'last_name': 'User',
        'personal_email': 'test@example.com',
    }


def make_valid_account(extra=None):
    base = {
        'username': 'svc-test',
        'pam_config_uid': 'abc123',
    }
    if extra:
        base.update(extra)
    return base


def make_valid_rotation(extra=None):
    base = {
        'schedule': '0 0 3 * * ?',
        'password_complexity': '32,5,5,5,5',
    }
    if extra:
        base.update(extra)
    return base


def make_params():
    """Minimal KeeperParams mock — these validator tests must not trigger
    vault/api lookups, so the configs avoid directory_uid / delivery.share_to."""
    p = MagicMock()
    p.key_cache = {}
    return p


# =============================================================================
# DEFAULT_COMPLEXITY module constant
# =============================================================================


@pytest.mark.unit
class TestDefaultComplexityConstant(TestCase):
    def test_default_complexity_is_defined(self):
        self.assertIsNotNone(DEFAULT_COMPLEXITY)

    def test_default_complexity_is_a_valid_complexity_string(self):
        # Format: "length,upper,lower,digit,special"
        parts = DEFAULT_COMPLEXITY.split(',')
        self.assertEqual(len(parts), 5)
        for p in parts:
            int(p)  # would raise if not numeric

    def test_default_complexity_meets_minimum_strength(self):
        # Sanity: length >= 16, each class >= 2 (these are the architect's stated defaults).
        parts = [int(p) for p in DEFAULT_COMPLEXITY.split(',')]
        self.assertGreaterEqual(parts[0], 16, "default length must be at least 16")
        for cls_count in parts[1:]:
            self.assertGreaterEqual(cls_count, 2, "each character class count must be at least 2")


# =============================================================================
# rotation: block is now optional
# =============================================================================


@pytest.mark.unit
class TestRotationBlockOptional(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def test_validate_succeeds_without_rotation_block(self):
        config = {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertEqual(errors, [], f"Expected no errors, got: {errors}")

    def test_validate_succeeds_with_full_rotation_block_unchanged(self):
        # Regression: existing YAMLs (with rotation block) must keep validating
        config = {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'rotation': make_valid_rotation(),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertEqual(errors, [], f"Expected no errors, got: {errors}")


# =============================================================================
# Empty-dict rotation: {} edge case
# =============================================================================


@pytest.mark.unit
class TestEmptyRotationDict(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def test_null_rotation_value_rejected_with_helpful_error(self):
        """Regression for review #C: `rotation:` with no value parses to None
        in YAML and would crash downstream .get() calls. Validator must reject
        with a clear message before any None-attribute access."""
        config = {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'rotation': None,  # <-- bare `rotation:` key, no value
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(
            any('rotation' in e and 'no value' in e for e in errors),
            f'Expected helpful "rotation: was specified but has no value" error; got: {errors}',
        )

    def test_empty_rotation_dict_does_not_silently_pass(self):
        # rotation: {} — present but empty — must be rejected
        # (either as "missing schedule/on_demand" or with a structural error)
        config = {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'rotation': {},
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(len(errors) > 0, "Empty rotation: {} dict must produce a validation error")


# =============================================================================
# schedule / on_demand mutual exclusivity (ROT-001)
# =============================================================================


@pytest.mark.unit
class TestScheduleOnDemandMutex(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _base_config(self, rotation):
        return {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'rotation': rotation,
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }

    def test_only_schedule_validates(self):
        cfg = self._base_config({
            'schedule': '0 0 3 * * ?',
            'password_complexity': '32,5,5,5,5',
        })
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertEqual(errors, [], f"Expected no errors, got: {errors}")

    def test_only_on_demand_validates(self):
        cfg = self._base_config({
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
        })
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertEqual(errors, [], f"Expected no errors, got: {errors}")

    def test_both_schedule_and_on_demand_rejected(self):
        cfg = self._base_config({
            'schedule': '0 0 3 * * ?',
            'on_demand': True,
            'password_complexity': '32,5,5,5,5',
        })
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(
            any('schedule' in e and 'on_demand' in e for e in errors),
            f"Expected mutual-exclusivity error, got: {errors}",
        )

    def test_neither_schedule_nor_on_demand_rejected(self):
        cfg = self._base_config({
            'password_complexity': '32,5,5,5,5',
        })
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(len(errors) > 0,
            "Rotation block missing both schedule and on_demand must be rejected")


# =============================================================================
# on_demand type check (ROT-002)
# =============================================================================


@pytest.mark.unit
class TestOnDemandTypeCheck(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _config_with_on_demand(self, value):
        return {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'rotation': {
                'on_demand': value,
                'password_complexity': '32,5,5,5,5',
            },
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }

    def test_on_demand_true_validates(self):
        errors = self.cmd._validate_config(self.params, self._config_with_on_demand(True))
        self.assertEqual(errors, [], f"Got: {errors}")

    def test_on_demand_string_rejected(self):
        errors = self.cmd._validate_config(self.params, self._config_with_on_demand("true"))
        self.assertTrue(any('on_demand' in e and 'boolean' in e.lower() for e in errors),
                        f"Expected on_demand boolean type error, got: {errors}")

    def test_on_demand_int_rejected(self):
        errors = self.cmd._validate_config(self.params, self._config_with_on_demand(1))
        self.assertTrue(any('on_demand' in e and 'boolean' in e.lower() for e in errors),
                        f"Expected on_demand boolean type error, got: {errors}")


# =============================================================================
# rotate_on_provision type check (ROT-003)
# =============================================================================


@pytest.mark.unit
class TestRotateOnProvisionTypeCheck(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _config_with_rop(self, value):
        return {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'rotation': {
                'schedule': '0 0 3 * * ?',
                'password_complexity': '32,5,5,5,5',
                'rotate_on_provision': value,
            },
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }

    def test_rotate_on_provision_true_validates(self):
        errors = self.cmd._validate_config(self.params, self._config_with_rop(True))
        self.assertEqual(errors, [], f"Got: {errors}")

    def test_rotate_on_provision_false_validates(self):
        errors = self.cmd._validate_config(self.params, self._config_with_rop(False))
        self.assertEqual(errors, [], f"Got: {errors}")

    def test_rotate_on_provision_string_rejected(self):
        errors = self.cmd._validate_config(self.params, self._config_with_rop("false"))
        self.assertTrue(
            any('rotate_on_provision' in e and 'boolean' in e.lower() for e in errors),
            f"Got: {errors}",
        )


# =============================================================================
# account.existing_password (ACC-001)
# =============================================================================


@pytest.mark.unit
class TestExistingPasswordValidation(TestCase):
    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def test_existing_password_non_empty_string_validates_without_rotation(self):
        config = {
            'user': make_valid_user(),
            'account': make_valid_account({'existing_password': 'KnownPass123!'}),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertEqual(errors, [], f"Got: {errors}")

    def test_existing_password_empty_string_rejected(self):
        config = {
            'user': make_valid_user(),
            'account': make_valid_account({'existing_password': ''}),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(
            any('existing_password' in e for e in errors),
            f"Got: {errors}",
        )

    def test_existing_password_whitespace_only_rejected(self):
        """Regression for review #D (round 4): whitespace-only strings like
        '   ' or '\\t' are non-empty but meaningless. Validator must reject
        per its stated 'non-empty string' contract."""
        for value in ['   ', '\t', '\n', '  \t\n  ']:
            config = {
                'user': make_valid_user(),
                'account': make_valid_account({'existing_password': value}),
                'email': {'config_name': 'none', 'send_to': 'test@example.com'},
            }
            errors = self.cmd._validate_config(self.params, config)
            self.assertTrue(
                any('existing_password' in e for e in errors),
                f'Expected rejection for whitespace-only value {value!r}; got: {errors}',
            )

    def test_existing_password_preserves_internal_whitespace(self):
        """Passwords legitimately containing internal whitespace must NOT be
        rejected — only purely-whitespace strings are rejected."""
        config = {
            'user': make_valid_user(),
            'account': make_valid_account({'existing_password': 'pass with spaces'}),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertEqual(errors, [],
            f'Internal whitespace in passwords must be preserved; got: {errors}')

    def test_existing_password_non_string_rejected(self):
        config = {
            'user': make_valid_user(),
            'account': make_valid_account({'existing_password': 12345}),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(
            any('existing_password' in e for e in errors),
            f"Got: {errors}",
        )


# =============================================================================
# INVARIANT-001 cross-section invariant
# =============================================================================


@pytest.mark.unit
class TestInvariant001(TestCase):
    """
    INVARIANT-001: existing_password is rejected if a rotation: block is
    present AND rotate_on_provision is not explicitly false.

    This is the load-bearing security check that prevents the customer-supplied
    password from being pushed to the target system at provisioning time.
    """

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _config(self, rotation, existing_password=None):
        account = make_valid_account()
        if existing_password is not None:
            account['existing_password'] = existing_password
        return {
            'user': make_valid_user(),
            'account': account,
            'rotation': rotation,
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }

    def test_existing_password_with_schedule_and_default_rop_rejected(self):
        # No rotate_on_provision => defaults to true => rejection
        cfg = self._config(
            rotation={'schedule': '0 0 3 * * ?', 'password_complexity': '32,5,5,5,5'},
            existing_password='KnownPass123!',
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(
            any('existing_password' in e for e in errors),
            f"INVARIANT-001 must reject, got: {errors}",
        )

    def test_existing_password_with_schedule_and_explicit_rop_true_rejected(self):
        cfg = self._config(
            rotation={
                'schedule': '0 0 3 * * ?',
                'password_complexity': '32,5,5,5,5',
                'rotate_on_provision': True,
            },
            existing_password='KnownPass123!',
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(
            any('existing_password' in e for e in errors),
            f"INVARIANT-001 must reject, got: {errors}",
        )

    def test_existing_password_with_on_demand_and_default_rop_rejected(self):
        # on_demand + default rop=true => still fires _rotate_immediately => rejected
        cfg = self._config(
            rotation={'on_demand': True, 'password_complexity': '32,5,5,5,5'},
            existing_password='KnownPass123!',
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(
            any('existing_password' in e for e in errors),
            f"INVARIANT-001 must reject, got: {errors}",
        )

    def test_existing_password_with_rop_false_validates(self):
        # Cell 7 of behavior matrix: schedule + rop=false + existing_password => allowed
        cfg = self._config(
            rotation={
                'schedule': '0 0 3 * * ?',
                'password_complexity': '32,5,5,5,5',
                'rotate_on_provision': False,
            },
            existing_password='KnownPass123!',
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertEqual(errors, [], f"Got: {errors}")

    def test_existing_password_with_on_demand_and_rop_false_validates(self):
        # Cell 8 of behavior matrix (Tandem's case)
        cfg = self._config(
            rotation={
                'on_demand': True,
                'password_complexity': '32,5,5,5,5',
                'rotate_on_provision': False,
            },
            existing_password='KnownPass123!',
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertEqual(errors, [], f"Got: {errors}")

    def test_existing_password_with_no_rotation_block_validates(self):
        # Cell 2 of behavior matrix
        config = {
            'user': make_valid_user(),
            'account': make_valid_account({'existing_password': 'KnownPass123!'}),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertEqual(errors, [], f"Got: {errors}")

    def test_invariant_error_message_mentions_remediation(self):
        # Error message must guide the operator to a fix
        cfg = self._config(
            rotation={'schedule': '0 0 3 * * ?', 'password_complexity': '32,5,5,5,5'},
            existing_password='KnownPass123!',
        )
        errors = self.cmd._validate_config(self.params, cfg)
        joined = '\n'.join(errors)
        self.assertIn('rotate_on_provision', joined,
                      "Error message should mention rotate_on_provision as a remediation option")


# =============================================================================
# Regression: delivery.transfer_ownership / remove_from_service_vault must be
# rejected when ANY rotation is configured (schedule OR on_demand).
# Catches the bug where the has_rotation predicate only checked schedule.
# =============================================================================


@pytest.mark.unit
class TestRotationDeliveryInvariant(TestCase):
    """The existing transfer_ownership/remove_from_service_vault incompatibility
    with rotation must apply to BOTH schedule and on_demand modes. Pre-fix,
    has_rotation = bool(rotation.schedule) missed the on_demand case."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def _config(self, rotation, delivery):
        return {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'rotation': rotation,
            'delivery': delivery,
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }

    def test_on_demand_with_transfer_ownership_rejected(self):
        cfg = self._config(
            rotation={'on_demand': True, 'password_complexity': '32,5,5,5,5'},
            delivery={'share_to': 'someone@example.com', 'transfer_ownership': True},
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(
            any('transfer_ownership' in e and 'rotation' in e for e in errors),
            f"Expected transfer_ownership-rotation incompatibility error; got: {errors}",
        )

    def test_on_demand_with_remove_from_service_vault_rejected(self):
        cfg = self._config(
            rotation={'on_demand': True, 'password_complexity': '32,5,5,5,5'},
            delivery={'share_to': 'someone@example.com', 'remove_from_service_vault': True},
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(
            any('remove_from_service_vault' in e and 'rotation' in e for e in errors),
            f"Expected remove_from_service_vault-rotation incompatibility error; got: {errors}",
        )

    def test_schedule_with_transfer_ownership_still_rejected(self):
        # Regression: pre-existing behavior for schedule mode must still fire.
        cfg = self._config(
            rotation={'schedule': '0 0 3 * * ?', 'password_complexity': '32,5,5,5,5'},
            delivery={'share_to': 'someone@example.com', 'transfer_ownership': True},
        )
        errors = self.cmd._validate_config(self.params, cfg)
        self.assertTrue(
            any('transfer_ownership' in e for e in errors),
            f"Expected rejection; got: {errors}",
        )


# =============================================================================
# Regression: account.initial_password still rejected (KC-1007-2)
# =============================================================================


@pytest.mark.unit
class TestInitialPasswordStillRejected(TestCase):
    """initial_password rejection from KC-1007-2 must remain unchanged."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def test_initial_password_still_rejected(self):
        config = {
            'user': make_valid_user(),
            'account': make_valid_account({'initial_password': 'whatever'}),
            'rotation': make_valid_rotation(),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(any('initial_password' in e for e in errors),
                        f"Got: {errors}")


# =============================================================================
# Regression: deprecated pam.rotation: shape still emits migration error
# =============================================================================


@pytest.mark.unit
class TestDeprecatedPamRotationMigrationError(TestCase):
    """The pre-existing deprecation migration error must be unchanged."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def test_deprecated_pam_rotation_emits_migration_error(self):
        config = {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'pam': {
                'rotation': {
                    'schedule': '0 0 3 * * ?',
                    'password_complexity': '32,5,5,5,5',
                }
            },
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(
            any('deprecated' in e.lower() for e in errors),
            f"Expected deprecation migration error, got: {errors}",
        )


# =============================================================================
# Regression: existing required-field errors still fire
# =============================================================================


@pytest.mark.unit
class TestRequiredSectionsRegression(TestCase):
    """user and account remain required; rotation no longer is."""

    def setUp(self):
        self.cmd = CredentialProvisionCommand()
        self.params = make_params()

    def test_missing_user_section_rejected(self):
        config = {
            'account': make_valid_account(),
            'rotation': make_valid_rotation(),
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(any('user' in e for e in errors), f"Got: {errors}")

    def test_missing_account_section_rejected(self):
        config = {
            'user': make_valid_user(),
            'rotation': make_valid_rotation(),
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertTrue(any('account' in e for e in errors), f"Got: {errors}")

    def test_missing_rotation_section_no_longer_rejected(self):
        # Critical regression target: pre-feature this would have failed.
        config = {
            'user': make_valid_user(),
            'account': make_valid_account(),
            'email': {'config_name': 'none', 'send_to': 'test@example.com'},
        }
        errors = self.cmd._validate_config(self.params, config)
        self.assertEqual(errors, [],
            f"rotation: should be optional now; got: {errors}")
