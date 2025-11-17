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
Unit Tests for Automated Credential Provisioning (KC-1007)

Tests the foundation, YAML parsing, and validation framework implemented in Story KC-1007-2.
"""

import unittest
import tempfile
import os
from unittest.mock import Mock, MagicMock

from keepercommander.commands.credential_provision import CredentialProvisionCommand
from keepercommander.error import CommandError


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


class TestValidationHelpers(unittest.TestCase):
    """Test validation helper functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.cmd = CredentialProvisionCommand()

    def test_valid_email_formats(self):
        """Test valid email format validation."""
        valid_emails = [
            'user@example.com',
            'john.doe@company.co.uk',
            'test+tag@domain.org',
            'user_name@sub.domain.com',
        ]
        for email in valid_emails:
            self.assertTrue(
                self.cmd._is_valid_email(email),
                f'Should accept valid email: {email}'
            )

    def test_invalid_email_formats(self):
        """Test invalid email format detection."""
        invalid_emails = [
            'not-an-email',
            '@example.com',
            'user@',
            'user @example.com',
            'user@domain',
        ]
        for email in invalid_emails:
            self.assertFalse(
                self.cmd._is_valid_email(email),
                f'Should reject invalid email: {email}'
            )

    def test_valid_cron_formats(self):
        """Test valid CRON schedule formats (6-field)."""
        valid_crons = [
            '0 0 3 * * ?',  # Daily at 3 AM
            '0 30 2 * * 0',  # Weekly Sunday 2:30 AM
            '0 0 12 1 * ?',  # Monthly 1st at noon
            '*/30 * * * * ?',  # Every 30 seconds
            '0 0 */2 * * ?',  # Every 2 hours
        ]
        for cron in valid_crons:
            self.assertTrue(
                self.cmd._is_valid_cron(cron),
                f'Should accept valid CRON: {cron}'
            )

    def test_invalid_cron_formats(self):
        """Test invalid CRON schedule detection."""
        invalid_crons = [
            'invalid',
            '0 0 3 * *',  # Only 5 fields (need 6)
            '99 0 3 * * ?',  # Invalid seconds
            '0 0 25 * * ?',  # Invalid hour
        ]
        for cron in invalid_crons:
            self.assertFalse(
                self.cmd._is_valid_cron(cron),
                f'Should reject invalid CRON: {cron}'
            )

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
        """Test valid share URL expiry formats."""
        valid_expiries = [
            '7d',  # 7 days
            '24h',  # 24 hours
            '60m',  # 60 minutes
            '1d',
            '168h',
        ]
        for expiry in valid_expiries:
            self.assertTrue(
                self.cmd._is_valid_expiry(expiry),
                f'Should accept valid expiry: {expiry}'
            )

    def test_invalid_expiry_formats(self):
        """Test invalid share URL expiry detection."""
        invalid_expiries = [
            'invalid',
            '7',  # No unit
            'd7',  # Unit first
            '7x',  # Invalid unit
            '7.5d',  # Decimal not supported
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
            'send_to': 'personal',
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

    def test_complexity_exceeds_length(self):
        """Test error when complexity requirements exceed password length."""
        # Total requirements: 10+10+10+10 = 40, but length is only 20
        complexity = '20,10,10,10,10'

        with self.assertRaises(ValueError) as context:
            self.cmd._generate_password(complexity)

        self.assertIn('exceed length', str(context.exception).lower())

    def test_generate_random_password_direct(self):
        """Test _generate_random_password directly."""
        password = self.cmd._generate_random_password(
            length=30,
            min_upper=5,
            min_lower=5,
            min_digits=5,
            min_special=5
        )

        self.assertEqual(len(password), 30)

        # Verify minimums
        upper_count = sum(1 for c in password if c.isupper())
        lower_count = sum(1 for c in password if c.islower())
        digit_count = sum(1 for c in password if c.isdigit())
        special_count = sum(1 for c in password if not c.isalnum())

        self.assertGreaterEqual(upper_count, 5)
        self.assertGreaterEqual(lower_count, 5)
        self.assertGreaterEqual(digit_count, 5)
        self.assertGreaterEqual(special_count, 5)

    def test_minimum_length_password(self):
        """Test password generation with minimum requirements."""
        # Minimum: 12 characters with 0,0,0,0 requirements
        complexity = '12,0,0,0,0'
        password = self.cmd._generate_password(complexity)

        self.assertEqual(len(password), 12)

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


if __name__ == '__main__':
    unittest.main()
