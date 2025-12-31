#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

"""
Unit Tests for Automated Credential Provisioning (KC-1007, KC-1026)

Tests the foundation, YAML parsing, and validation framework implemented in Story KC-1007-2.
Tests base64 configuration input for Service Mode API integration (KC-1026).
"""

import base64
import sys
import unittest
import tempfile
import os
from unittest.mock import Mock, MagicMock
import pytest

# Try to import - will fail on Python 3.7 due to pydantic dependency
try:
    from keepercommander.commands.credential_provision import CredentialProvisionCommand, yaml, validate_cron_expression
    from keepercommander.error import CommandError
    # Check if dependencies are available
    CREDENTIAL_PROVISION_AVAILABLE = (yaml is not None and validate_cron_expression is not None)
except ImportError:
    # Skip all tests if import fails (Python 3.7)
    CREDENTIAL_PROVISION_AVAILABLE = False
    CredentialProvisionCommand = None
    CommandError = None
    yaml = None
    validate_cron_expression = None

# Skip all tests if credential_provision dependencies are not available
pytestmark = pytest.mark.skipif(
    not CREDENTIAL_PROVISION_AVAILABLE,
    reason="Requires Python 3.8+ and PyYAML (pydantic and yaml dependencies)"
)


class TestYAMLParsing(unittest.TestCase):
    """Test YAML file loading and parsing."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def test_valid_yaml_loads(self):
        """Test that valid YAML files load correctly."""
        yaml_content = """
user:
  first_name: "John"
  last_name: "Doe"
  personal_email: "john@example.com"
account:
  username: "john.doe"
  pam_config_uid: "test-uid"
pam:
  rotation:
    schedule: "0 0 3 * * ?"
    password_complexity: "32,5,5,5,5"
email:
  config_name: "Test Config"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            config = self.cmd._load_yaml(temp_path)
            self.assertIsInstance(config, dict)
            self.assertEqual(config['user']['first_name'], 'John')
            self.assertEqual(config['account']['username'], 'john.doe')
        finally:
            os.unlink(temp_path)

    def test_missing_file_raises_error(self):
        """Test that missing files raise appropriate error."""
        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml('/nonexistent/path/file.yaml')

        self.assertIn('not found', str(context.exception))

    def test_invalid_yaml_raises_error(self):
        """Test that invalid YAML syntax raises error."""
        invalid_yaml = """
user:
  first_name: "John
  unterminated_string
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            temp_path = f.name

        try:
            with self.assertRaises(CommandError) as context:
                self.cmd._load_yaml(temp_path)

            self.assertIn('YAML syntax error', str(context.exception))
        finally:
            os.unlink(temp_path)

    def test_non_dict_yaml_raises_error(self):
        """Test that non-dictionary YAML raises error."""
        yaml_content = """
- item1
- item2
- item3
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            with self.assertRaises(CommandError) as context:
                self.cmd._load_yaml(temp_path)

            self.assertIn('must be a dictionary', str(context.exception))
        finally:
            os.unlink(temp_path)


class TestBase64YAMLParsing(unittest.TestCase):
    """Test base64-encoded YAML loading and parsing (KC-1026)."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def _encode_yaml(self, yaml_content: str) -> str:
        """Helper to encode YAML string to base64."""
        return base64.b64encode(yaml_content.encode('utf-8')).decode('ascii')

    def test_valid_base64_yaml_loads(self):
        """Test that valid base64-encoded YAML loads correctly."""
        yaml_content = """
user:
  first_name: "John"
  last_name: "Doe"
  personal_email: "john@example.com"
account:
  username: "john.doe"
  pam_config_uid: "test-uid"
pam:
  rotation:
    schedule: "0 0 3 * * ?"
    password_complexity: "32,5,5,5,5"
email:
  config_name: "Test Config"
"""
        base64_content = self._encode_yaml(yaml_content)

        config = self.cmd._load_yaml_base64(base64_content)
        self.assertIsInstance(config, dict)
        self.assertEqual(config['user']['first_name'], 'John')
        self.assertEqual(config['account']['username'], 'john.doe')

    def test_valid_base64_simple_yaml(self):
        """Test simple YAML configuration via base64."""
        yaml_content = "user:\n  name: test"
        base64_content = self._encode_yaml(yaml_content)

        config = self.cmd._load_yaml_base64(base64_content)
        self.assertEqual(config['user']['name'], 'test')

    def test_invalid_base64_raises_error(self):
        """Test that invalid base64 raises appropriate error."""
        invalid_base64 = "not-valid-base64!!!"

        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml_base64(invalid_base64)

        self.assertIn('Invalid base64 encoding', str(context.exception))

    def test_invalid_base64_characters_raises_error(self):
        """Test that base64 with invalid characters raises error."""
        # Contains invalid characters for base64
        invalid_base64 = "abc$%^&*()xyz"

        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml_base64(invalid_base64)

        self.assertIn('Invalid base64 encoding', str(context.exception))

    def test_valid_base64_invalid_yaml_raises_error(self):
        """Test that valid base64 with invalid YAML raises error."""
        # Invalid YAML syntax
        invalid_yaml = "user:\n  first_name: \"John\n  unterminated_string"
        base64_content = self._encode_yaml(invalid_yaml)

        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml_base64(base64_content)

        self.assertIn('YAML syntax error', str(context.exception))

    def test_valid_base64_non_dict_yaml_raises_error(self):
        """Test that YAML that isn't a dict raises appropriate error."""
        list_yaml = "- item1\n- item2\n- item3"
        base64_content = self._encode_yaml(list_yaml)

        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml_base64(base64_content)

        self.assertIn('must be a dictionary', str(context.exception))

    def test_valid_base64_scalar_yaml_raises_error(self):
        """Test that scalar YAML (not dict) raises appropriate error."""
        scalar_yaml = "just a plain string"
        base64_content = self._encode_yaml(scalar_yaml)

        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml_base64(base64_content)

        self.assertIn('must be a dictionary', str(context.exception))

    def test_valid_base64_non_utf8_raises_error(self):
        """Test that non-UTF8 content raises appropriate error."""
        # Binary content that's not valid UTF-8
        binary_content = b'\x80\x81\x82\x83'
        base64_content = base64.b64encode(binary_content).decode('ascii')

        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml_base64(base64_content)

        self.assertIn('Invalid UTF-8 encoding', str(context.exception))

    def test_empty_base64_raises_error(self):
        """Test that empty base64 string is handled appropriately."""
        # Empty string decodes to empty, which is not a valid dict
        empty_yaml = ""
        base64_content = self._encode_yaml(empty_yaml)

        with self.assertRaises(CommandError) as context:
            self.cmd._load_yaml_base64(base64_content)

        # yaml.safe_load returns None for empty string, which is not a dict
        self.assertIn('must be a dictionary', str(context.exception))

    def test_base64_with_padding(self):
        """Test that base64 with proper padding works."""
        yaml_content = "key: value"
        base64_content = self._encode_yaml(yaml_content)

        # Ensure padding is present (base64 length should be multiple of 4)
        self.assertEqual(len(base64_content) % 4, 0)

        config = self.cmd._load_yaml_base64(base64_content)
        self.assertEqual(config['key'], 'value')

    def test_base64_unicode_content(self):
        """Test that base64-encoded Unicode YAML works correctly."""
        yaml_content = """
user:
  first_name: "日本語"
  last_name: "テスト"
"""
        base64_content = self._encode_yaml(yaml_content)

        config = self.cmd._load_yaml_base64(base64_content)
        self.assertEqual(config['user']['first_name'], '日本語')
        self.assertEqual(config['user']['last_name'], 'テスト')

    def test_base64_preserves_yaml_types(self):
        """Test that YAML types are preserved through base64 encoding."""
        yaml_content = """
string_field: "hello"
integer_field: 42
float_field: 3.14
boolean_field: true
null_field: null
list_field:
  - item1
  - item2
"""
        base64_content = self._encode_yaml(yaml_content)

        config = self.cmd._load_yaml_base64(base64_content)
        self.assertEqual(config['string_field'], 'hello')
        self.assertEqual(config['integer_field'], 42)
        self.assertAlmostEqual(config['float_field'], 3.14)
        self.assertTrue(config['boolean_field'])
        self.assertIsNone(config['null_field'])
        self.assertEqual(config['list_field'], ['item1', 'item2'])


class TestValidationHelpers(unittest.TestCase):
    """Test validation helper functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    # Email and CRON validation tests removed - now using Commander utilities:
    # - utils.is_email() for email validation
    # - validate_cron_expression() for CRON validation
    # These utilities are tested elsewhere in Commander's test suite

    def test_valid_complexity_formats(self):
        """Test valid password complexity formats."""
        valid_complexities = [
            '32,5,5,5,5',  # Standard complexity
            '16,3,3,3,3',  # Lower requirements
            '64,10,10,10,10',  # Higher requirements
            '12,0,0,0,0',  # Minimum length only
        ]
        for complexity in valid_complexities:
            self.assertTrue(
                self.cmd._is_valid_complexity(complexity),
                f'Should accept valid complexity: {complexity}'
            )

    def test_invalid_complexity_formats(self):
        """Test invalid password complexity detection."""
        invalid_complexities = [
            'invalid',
            '32',  # Too few parts
            '32,5,5',  # Too few parts
            '32,5,5,5,5,5',  # Too many parts
            'a,b,c,d,e',  # Non-numeric
            '32,-5,5,5,5',  # Negative numbers
        ]
        for complexity in invalid_complexities:
            self.assertFalse(
                self.cmd._is_valid_complexity(complexity),
                f'Should reject invalid complexity: {complexity}'
            )

    def test_valid_expiry_formats(self):
        """Test valid share URL expiry formats (days, hours, minutes)."""
        valid_expiries = [
            '7d',  # 7 days
            '24h',  # 24 hours
            '60mi',  # 60 minutes
            '1d',  # 1 day
            '168h',  # 168 hours (7 days)
            '365d',  # 1 year
            '1mo',  # 1 month
            '1y',  # 1 year
        ]
        for expiry in valid_expiries:
            self.assertTrue(
                self.cmd._is_valid_expiry(expiry),
                f'Should accept valid expiry: {expiry}'
            )

    def test_invalid_expiry_formats(self):
        """Test invalid share URL expiry detection."""
        invalid_expiries = [
            'invalid',  # No number/unit
            '7',  # No unit
            'd7',  # Unit first
            '7x',  # Invalid unit
            '7m',  # Wrong: use 'mi' for minutes, not 'm'
            '60m',  # Wrong: use 'mi' for minutes, not 'm'
            '7.5d',  # Decimal not supported
            '',  # Empty string
            'abc',  # No number
            '7 d',  # Space not allowed
            'm7',  # Unit first
            '7dm',  # Multiple units
        ]
        for expiry in invalid_expiries:
            self.assertFalse(
                self.cmd._is_valid_expiry(expiry),
                f'Should reject invalid expiry: {expiry}'
            )


class TestUserSectionValidation(unittest.TestCase):
    """Test user section validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def test_valid_user_section(self):
        """Test that valid user section passes validation."""
        user = {
            'first_name': 'John',
            'last_name': 'Doe',
            'personal_email': 'john@example.com',
            'corporate_email': 'john.doe@company.com',
            'employee_id': 'EMP123',
            'department': 'Engineering',
        }
        errors = self.cmd._validate_user_section(user)
        self.assertEqual(len(errors), 0, 'Valid user section should have no errors')

    def test_missing_required_fields(self):
        """Test detection of missing required fields."""
        user = {
            'first_name': 'John',
            # Missing last_name and personal_email
        }
        errors = self.cmd._validate_user_section(user)
        self.assertGreater(len(errors), 0, 'Should detect missing fields')
        error_text = ' '.join(errors)
        self.assertIn('last_name', error_text)
        self.assertIn('personal_email', error_text)

    def test_invalid_email_format(self):
        """Test detection of invalid email formats."""
        user = {
            'first_name': 'John',
            'last_name': 'Doe',
            'personal_email': 'not-an-email',  # Invalid
        }
        errors = self.cmd._validate_user_section(user)
        self.assertGreater(len(errors), 0, 'Should detect invalid email')
        self.assertIn('invalid', ' '.join(errors).lower())


class TestAccountSectionValidation(unittest.TestCase):
    """Test account section validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def test_valid_account_section(self):
        """Test that valid account section passes validation."""
        account = {
            'username': 'john.doe',
            'pam_config_uid': 'abc123-def456-ghi789',
            'domain': 'COMPANY',
            'ou_path': 'OU=Users,DC=company,DC=com',
        }
        errors = self.cmd._validate_account_section(account)
        self.assertEqual(len(errors), 0, 'Valid account section should have no errors')

    def test_missing_required_fields(self):
        """Test detection of missing required fields."""
        account = {
            # Missing username and pam_config_uid
        }
        errors = self.cmd._validate_account_section(account)
        self.assertGreater(len(errors), 0, 'Should detect missing fields')
        error_text = ' '.join(errors)
        self.assertIn('username', error_text)
        self.assertIn('pam_config_uid', error_text)

    def test_reject_initial_password_field(self):
        """Test that initial_password field is rejected (security issue)."""
        account = {
            'username': 'john.doe',
            'pam_config_uid': 'test-uid',
            'initial_password': 'Temp123!',  # Should be rejected
        }
        errors = self.cmd._validate_account_section(account)
        self.assertGreater(len(errors), 0, 'Should reject initial_password')
        error_text = ' '.join(errors)
        self.assertIn('initial_password', error_text)
        self.assertIn('NOT supported', error_text)


class TestPAMSectionValidation(unittest.TestCase):
    """Test PAM section validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def test_valid_pam_section(self):
        """Test that valid PAM section passes validation."""
        pam = {
            'rotation': {
                'rotate_immediately': True,
                'schedule': '0 0 3 * * ?',
                'password_complexity': '32,5,5,5,5',
            },
            'pam_user_title': 'PAM: John Doe',
            'login_record_title': 'John Doe Login',
        }
        errors = self.cmd._validate_pam_section(pam)
        self.assertEqual(len(errors), 0, 'Valid PAM section should have no errors')

    def test_missing_rotation_section(self):
        """Test detection of missing rotation section."""
        pam = {}
        errors = self.cmd._validate_pam_section(pam)
        self.assertGreater(len(errors), 0, 'Should detect missing rotation')
        self.assertIn('rotation', ' '.join(errors))

    def test_invalid_cron_schedule(self):
        """Test detection of invalid CRON schedule."""
        pam = {
            'rotation': {
                'schedule': 'invalid cron',  # Invalid
                'password_complexity': '32,5,5,5,5',
            }
        }
        errors = self.cmd._validate_pam_section(pam)
        self.assertGreater(len(errors), 0, 'Should detect invalid CRON')
        self.assertIn('CRON', ' '.join(errors))

    def test_invalid_complexity_format(self):
        """Test detection of invalid complexity format."""
        pam = {
            'rotation': {
                'schedule': '0 0 3 * * ?',
                'password_complexity': 'invalid',  # Invalid
            }
        }
        errors = self.cmd._validate_pam_section(pam)
        self.assertGreater(len(errors), 0, 'Should detect invalid complexity')
        self.assertIn('complexity', ' '.join(errors).lower())


class TestEmailSectionValidation(unittest.TestCase):
    """Test email section validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()
        self.mock_params = Mock()

    def test_valid_email_section(self):
        """Test that valid email section passes validation."""
        email = {
            'config_name': 'Company Gmail',
            'send_to': 'user@example.com',
            'subject': 'Welcome!',
            'share_url_expiry': '7d',
        }
        errors = self.cmd._validate_email_section(self.mock_params, email)
        self.assertEqual(len(errors), 0, 'Valid email section should have no errors')

    def test_missing_config_name(self):
        """Test detection of missing config_name."""
        email = {}
        errors = self.cmd._validate_email_section(self.mock_params, email)
        self.assertGreater(len(errors), 0, 'Should detect missing config_name')
        self.assertIn('config_name', ' '.join(errors))

    def test_invalid_send_to_value(self):
        """Test detection of invalid send_to value."""
        email = {
            'config_name': 'Test Config',
            'send_to': 'invalid_value',  # Should be personal, corporate, or both
        }
        errors = self.cmd._validate_email_section(self.mock_params, email)
        self.assertGreater(len(errors), 0, 'Should detect invalid send_to')
        self.assertIn('send_to', ' '.join(errors))

    def test_invalid_expiry_format(self):
        """Test detection of invalid expiry format."""
        email = {
            'config_name': 'Test Config',
            'share_url_expiry': 'invalid',
        }
        errors = self.cmd._validate_email_section(self.mock_params, email)
        self.assertGreater(len(errors), 0, 'Should detect invalid expiry')
        self.assertIn('expiry', ' '.join(errors).lower())


class TestComprehensiveValidation(unittest.TestCase):
    """Test complete configuration validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()
        self.mock_params = Mock()

    def test_valid_complete_config(self):
        """Test that a complete valid configuration passes."""
        config = {
            'user': {
                'first_name': 'John',
                'last_name': 'Doe',
                'personal_email': 'john@example.com',
            },
            'account': {
                'username': 'john.doe',
                'pam_config_uid': 'test-uid',
            },
            'pam': {
                'rotation': {
                    'schedule': '0 0 3 * * ?',
                    'password_complexity': '32,5,5,5,5',
                }
            },
            'email': {
                'config_name': 'Test Config',
                'send_to': 'john@example.com',
            }
        }
        errors = self.cmd._validate_config(self.mock_params, config)
        self.assertEqual(len(errors), 0, 'Valid config should have no errors')

    def test_missing_required_sections(self):
        """Test detection of missing required sections."""
        config = {
            'user': {'first_name': 'John'},
            # Missing account, pam, email sections
        }
        errors = self.cmd._validate_config(self.mock_params, config)
        self.assertGreater(len(errors), 0, 'Should detect missing sections')
        error_text = ' '.join(errors)
        self.assertIn('account', error_text)
        self.assertIn('pam', error_text)
        self.assertIn('email', error_text)

    def test_multiple_validation_errors(self):
        """Test that multiple errors are collected (not fail-fast)."""
        config = {
            'user': {
                'first_name': 'John',
                # Missing last_name and personal_email
            },
            'account': {
                # Missing username and pam_config_uid
            },
            'pam': {
                'rotation': {
                    'schedule': 'invalid',  # Invalid CRON
                    'password_complexity': 'invalid',  # Invalid format
                }
            },
            'email': {
                # Missing config_name
            }
        }
        errors = self.cmd._validate_config(self.mock_params, config)
        # Should have multiple errors from different sections
        self.assertGreater(len(errors), 5, 'Should collect multiple errors')


class TestPasswordGeneration(unittest.TestCase):
    """Test password generation (KC-1007-3)."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def test_generate_password_valid_complexity(self):
        """Test password generation with valid complexity."""
        complexity = '32,5,5,5,5'
        password = self.cmd._generate_password(complexity)

        self.assertIsInstance(password, str)
        self.assertEqual(len(password), 32, 'Password should be 32 characters')

    def test_password_meets_complexity_requirements(self):
        """Test that generated password meets all complexity requirements."""
        complexity = '20,3,3,3,3'
        password = self.cmd._generate_password(complexity)

        # Count character types
        upper_count = sum(1 for c in password if c.isupper())
        lower_count = sum(1 for c in password if c.islower())
        digit_count = sum(1 for c in password if c.isdigit())
        special_count = sum(1 for c in password if not c.isalnum())

        self.assertGreaterEqual(upper_count, 3, 'Should have at least 3 uppercase')
        self.assertGreaterEqual(lower_count, 3, 'Should have at least 3 lowercase')
        self.assertGreaterEqual(digit_count, 3, 'Should have at least 3 digits')
        self.assertGreaterEqual(special_count, 3, 'Should have at least 3 special')

    def test_password_randomness(self):
        """Test that passwords are random (different each time)."""
        complexity = '16,2,2,2,2'
        passwords = [self.cmd._generate_password(complexity) for _ in range(5)]

        # All passwords should be unique
        self.assertEqual(len(set(passwords)), 5, 'All passwords should be different')

    def test_invalid_complexity_format(self):
        """Test error handling for invalid complexity format."""
        invalid_complexities = [
            'invalid',
            '32',  # Too few parts
            '32,5,5',  # Too few parts
            '32,5,5,5,5,5',  # Too many parts
            'a,b,c,d,e',  # Non-numeric
        ]

        for complexity in invalid_complexities:
            with self.assertRaises(ValueError):
                self.cmd._generate_password(complexity)

    # NOTE: KeeperPasswordGenerator doesn't validate that complexity sum <= length.
    # If sum > length, it generates a password with sum length (ignores the length parameter).
    # This is the expected behavior of Commander's built-in generator.

    # Low-level password generation tests removed - now using Commander's built-in generator:
    # KeeperPasswordGenerator is tested elsewhere in Commander's test suite

    def test_minimum_length_password(self):
        """Test password generation with minimum requirements."""
        # Minimum: 12 characters with at least 1 of each category
        # Note: Can't use all zeros (would raise 'Password character set is empty')
        complexity = '12,1,1,1,1'
        password = self.cmd._generate_password(complexity)

        self.assertEqual(len(password), 12)
        # Should have at least 1 of each required character type
        self.assertGreaterEqual(sum(1 for c in password if c.isupper()), 1)
        self.assertGreaterEqual(sum(1 for c in password if c.islower()), 1)
        self.assertGreaterEqual(sum(1 for c in password if c.isdigit()), 1)
        self.assertGreaterEqual(sum(1 for c in password if not c.isalnum()), 1)

    def test_high_complexity_password(self):
        """Test password generation with high complexity."""
        complexity = '64,10,10,10,10'
        password = self.cmd._generate_password(complexity)

        self.assertEqual(len(password), 64)

        upper_count = sum(1 for c in password if c.isupper())
        lower_count = sum(1 for c in password if c.islower())
        digit_count = sum(1 for c in password if c.isdigit())
        special_count = sum(1 for c in password if not c.isalnum())

        self.assertGreaterEqual(upper_count, 10)
        self.assertGreaterEqual(lower_count, 10)
        self.assertGreaterEqual(digit_count, 10)
        self.assertGreaterEqual(special_count, 10)

    def test_password_contains_only_allowed_characters(self):
        """Test that password only contains allowed character sets."""
        import string
        complexity = '20,5,5,5,5'
        password = self.cmd._generate_password(complexity)

        allowed_chars = (
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits +
            '''!@#$%^?();',.=+[]<>{}-_/\\*&:"`~|'''
        )

        for char in password:
            self.assertIn(char, allowed_chars, f'Character {char} not in allowed set')


class TestRollbackLogic(unittest.TestCase):
    """Test rollback logic for failed provisioning."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def test_provisioning_state_initialization(self):
        """Test ProvisioningState initializes with None values (Login records removed)."""
        from keepercommander.commands.credential_provision import ProvisioningState
        state = ProvisioningState()
        self.assertIsNone(state.pam_user_uid)
        self.assertFalse(state.dag_link_created)
        self.assertIsNone(state.folder_created)

    def test_provisioning_state_tracking(self):
        """Test ProvisioningState tracks created resources (Login records removed)."""
        from keepercommander.commands.credential_provision import ProvisioningState
        state = ProvisioningState()

        # Simulate tracking resources
        state.pam_user_uid = 'test-pam-uid-123'
        state.dag_link_created = True
        state.folder_created = '/test/folder/path'

        self.assertEqual(state.pam_user_uid, 'test-pam-uid-123')
        self.assertTrue(state.dag_link_created)
        self.assertEqual(state.folder_created, '/test/folder/path')

    def test_rollback_with_no_resources(self):
        """Test rollback gracefully handles empty state."""
        from keepercommander.commands.credential_provision import ProvisioningState
        from unittest.mock import Mock

        state = ProvisioningState()
        params = Mock()

        # Should not raise exception with empty state
        try:
            self.cmd._rollback(state, params)
        except Exception as e:
            self.fail(f'Rollback with empty state raised exception: {e}')

    def test_rollback_deletes_pam_user_only(self):
        """Test rollback deletes PAM User (Login records no longer created)."""
        from keepercommander.commands.credential_provision import ProvisioningState
        from unittest.mock import Mock, patch

        state = ProvisioningState()
        state.pam_user_uid = 'test-pam-uid'
        params = Mock()

        with patch('keepercommander.api.delete_record') as mock_delete:
            self.cmd._rollback(state, params)
            mock_delete.assert_called_once_with(params, 'test-pam-uid')

    def test_rollback_deletes_pam_user(self):
        """Test rollback deletes PAM User if created."""
        from keepercommander.commands.credential_provision import ProvisioningState
        from unittest.mock import Mock, patch

        state = ProvisioningState()
        state.pam_user_uid = 'test-pam-uid'
        params = Mock()

        with patch('keepercommander.api.delete_record') as mock_delete:
            self.cmd._rollback(state, params)
            mock_delete.assert_any_call(params, 'test-pam-uid')

    def test_rollback_handles_deletion_errors(self):
        """Test rollback continues even if deletion fails."""
        from keepercommander.commands.credential_provision import ProvisioningState
        from unittest.mock import Mock, patch

        state = ProvisioningState()
        state.pam_user_uid = 'test-pam-uid'
        params = Mock()

        with patch('keepercommander.api.delete_record', side_effect=Exception('Delete failed')):
            # Should not raise exception
            try:
                self.cmd._rollback(state, params)
            except Exception as e:
                self.fail(f'Rollback raised exception on deletion error: {e}')

    def test_rollback_with_folder_created(self):
        """Test rollback tracks folder creation state (Login records removed)."""
        from keepercommander.commands.credential_provision import ProvisioningState
        from unittest.mock import Mock, patch

        state = ProvisioningState()
        state.pam_user_uid = 'test-pam-uid'
        state.folder_created = '/test/folder'
        params = Mock()

        with patch('keepercommander.api.delete_record') as mock_delete:
            self.cmd._rollback(state, params)

            # Verify PAM User was deleted
            mock_delete.assert_called_once_with(params, 'test-pam-uid')


if __name__ == '__main__':
    unittest.main()
