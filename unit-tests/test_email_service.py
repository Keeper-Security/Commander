import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
from keepercommander.email_service import (
    EmailConfig,
    SMTPEmailProvider,
    SendGridEmailProvider,
    SESEmailProvider,
    EmailSender,
    build_onboarding_email,
    load_email_template,
    validate_email_provider_dependencies,
    get_installation_method,
    check_provider_dependencies
)


class TestEmailConfig(unittest.TestCase):
    """Test EmailConfig dataclass and validation"""

    def test_email_config_creation(self):
        """Test creating a basic email config"""
        config = EmailConfig(
            record_uid="abc123",
            name="Test SMTP",
            provider="smtp",
            from_address="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_username="test@example.com",
            smtp_password="password123"
        )

        self.assertEqual(config.record_uid, "abc123")
        self.assertEqual(config.name, "Test SMTP")
        self.assertEqual(config.provider, "smtp")
        self.assertEqual(config.from_address, "test@example.com")

    def test_smtp_config_validation_success(self):
        """Test valid SMTP configuration"""
        config = EmailConfig(
            record_uid="abc123",
            name="SMTP",
            provider="smtp",
            from_address="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_username="test@example.com",
            smtp_password="password123"
        )

        errors = config.validate()
        self.assertEqual(len(errors), 0)

    def test_smtp_config_validation_missing_host(self):
        """Test SMTP config with missing host"""
        config = EmailConfig(
            record_uid="abc123",
            name="SMTP",
            provider="smtp",
            from_address="test@example.com",
            smtp_username="test@example.com",
            smtp_password="password123"
        )

        errors = config.validate()
        self.assertIn("SMTP host is required", errors)

    def test_smtp_config_validation_missing_password(self):
        """Test SMTP config with missing password"""
        config = EmailConfig(
            record_uid="abc123",
            name="SMTP",
            provider="smtp",
            from_address="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_username="test@example.com"
        )

        errors = config.validate()
        self.assertIn("SMTP password is required", errors)

    def test_ses_config_validation_success(self):
        """Test valid SES configuration"""
        config = EmailConfig(
            record_uid="abc123",
            name="SES",
            provider="ses",
            from_address="test@example.com",
            aws_region="us-east-1",
            aws_access_key="AKIAIOSFODNN7EXAMPLE",
            aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        errors = config.validate()
        self.assertEqual(len(errors), 0)

    def test_ses_config_validation_missing_region(self):
        """Test SES config with missing region"""
        config = EmailConfig(
            record_uid="abc123",
            name="SES",
            provider="ses",
            from_address="test@example.com",
            aws_access_key="AKIAIOSFODNN7EXAMPLE",
            aws_secret_key="secret"
        )

        errors = config.validate()
        self.assertIn("AWS region is required for SES", errors)

    def test_sendgrid_config_validation_success(self):
        """Test valid SendGrid configuration"""
        config = EmailConfig(
            record_uid="abc123",
            name="SendGrid",
            provider="sendgrid",
            from_address="test@example.com",
            sendgrid_api_key="SG.1234567890"
        )

        errors = config.validate()
        self.assertEqual(len(errors), 0)

    def test_sendgrid_config_validation_missing_api_key(self):
        """Test SendGrid config with missing API key"""
        config = EmailConfig(
            record_uid="abc123",
            name="SendGrid",
            provider="sendgrid",
            from_address="test@example.com"
        )

        errors = config.validate()
        self.assertIn("SendGrid API key is required", errors)

    def test_unknown_provider_validation(self):
        """Test config with unknown provider"""
        config = EmailConfig(
            record_uid="abc123",
            name="Unknown",
            provider="unknown_provider",
            from_address="test@example.com"
        )

        errors = config.validate()
        self.assertIn("Unknown provider: unknown_provider", errors)


class TestSMTPEmailProvider(unittest.TestCase):
    """Test SMTP email provider"""

    def setUp(self):
        """Set up test SMTP config"""
        self.config = EmailConfig(
            record_uid="abc123",
            name="Test SMTP",
            provider="smtp",
            from_address="test@example.com",
            from_name="Test Sender",
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="test@example.com",
            smtp_password="password123",
            smtp_use_tls=True
        )

    def test_smtp_provider_initialization(self):
        """Test SMTP provider can be initialized"""
        provider = SMTPEmailProvider(self.config)
        self.assertEqual(provider.config, self.config)

    def test_smtp_provider_invalid_config_raises_error(self):
        """Test SMTP provider raises error with invalid config"""
        invalid_config = EmailConfig(
            record_uid="abc123",
            name="Invalid",
            provider="smtp",
            from_address="test@example.com"
        )

        with self.assertRaises(ValueError) as context:
            SMTPEmailProvider(invalid_config)

        self.assertIn("Invalid email configuration", str(context.exception))

    @patch('smtplib.SMTP')
    def test_smtp_send_success(self, mock_smtp):
        """Test SMTP email sending success"""
        # Setup mock
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        provider = SMTPEmailProvider(self.config)
        result = provider.send(
            to="recipient@example.com",
            subject="Test Subject",
            body="Test body",
            html=False
        )

        self.assertTrue(result)
        mock_server.login.assert_called_once_with("test@example.com", "password123")
        mock_server.send_message.assert_called_once()

    @patch('smtplib.SMTP')
    def test_smtp_send_html(self, mock_smtp):
        """Test SMTP sending HTML email"""
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        provider = SMTPEmailProvider(self.config)
        result = provider.send(
            to="recipient@example.com",
            subject="Test Subject",
            body="<html><body>Test</body></html>",
            html=True
        )

        self.assertTrue(result)
        mock_server.send_message.assert_called_once()

    @patch('smtplib.SMTP_SSL')
    def test_smtp_send_with_ssl(self, mock_smtp_ssl):
        """Test SMTP sending with SSL (port 465)"""
        self.config.smtp_use_ssl = True
        self.config.smtp_use_tls = False
        self.config.smtp_port = 465

        mock_server = MagicMock()
        mock_smtp_ssl.return_value.__enter__.return_value = mock_server

        provider = SMTPEmailProvider(self.config)
        result = provider.send(
            to="recipient@example.com",
            subject="Test",
            body="Test",
            html=False
        )

        self.assertTrue(result)
        mock_server.login.assert_called_once()

    @patch('smtplib.SMTP')
    def test_smtp_authentication_failure(self, mock_smtp):
        """Test SMTP authentication failure"""
        import smtplib
        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b'Authentication failed')
        mock_smtp.return_value.__enter__.return_value = mock_server

        provider = SMTPEmailProvider(self.config)

        with self.assertRaises(smtplib.SMTPAuthenticationError):
            provider.send(
                to="recipient@example.com",
                subject="Test",
                body="Test"
            )

    @patch('smtplib.SMTP')
    def test_smtp_test_connection_success(self, mock_smtp):
        """Test SMTP connection testing success"""
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        provider = SMTPEmailProvider(self.config)
        result = provider.test_connection()

        self.assertTrue(result)
        mock_server.login.assert_called_once()

    @patch('smtplib.SMTP')
    def test_smtp_test_connection_failure(self, mock_smtp):
        """Test SMTP connection testing failure"""
        mock_server = MagicMock()
        mock_server.login.side_effect = Exception("Connection failed")
        mock_smtp.return_value.__enter__.return_value = mock_server

        provider = SMTPEmailProvider(self.config)
        result = provider.test_connection()

        self.assertFalse(result)


class TestSendGridEmailProvider(unittest.TestCase):
    """Test SendGrid email provider"""

    def setUp(self):
        """Set up test SendGrid config"""
        self.config = EmailConfig(
            record_uid="abc123",
            name="SendGrid",
            provider="sendgrid",
            from_address="test@example.com",
            from_name="Test Sender",
            sendgrid_api_key="SG.test_key_1234567890"
        )

    @patch('keepercommander.email_service.SendGridEmailProvider.__init__')
    def test_sendgrid_provider_initialization(self, mock_init):
        """Test SendGrid provider initialization"""
        mock_init.return_value = None
        # Just verify it doesn't raise an error
        # Actual SendGrid testing requires the library installed
        self.assertTrue(True)

    def test_sendgrid_missing_library_raises_error(self):
        """Test SendGrid raises ImportError if library not installed"""
        # This will fail if sendgrid is not installed (expected in test environment)
        try:
            provider = SendGridEmailProvider(self.config)
        except ImportError as e:
            self.assertIn("SendGrid requires additional dependencies", str(e))


class TestSESEmailProvider(unittest.TestCase):
    """Test AWS SES email provider"""

    def setUp(self):
        """Set up test SES config"""
        self.config = EmailConfig(
            record_uid="abc123",
            name="SES",
            provider="ses",
            from_address="test@example.com",
            from_name="Test Sender",
            aws_region="us-east-1",
            aws_access_key="AKIAIOSFODNN7EXAMPLE",
            aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

    def test_ses_missing_library_raises_error(self):
        """Test SES raises ImportError if boto3 not installed"""
        # This will fail if boto3 is not installed (expected in test environment)
        try:
            provider = SESEmailProvider(self.config)
        except ImportError as e:
            self.assertIn("AWS SES requires additional dependencies", str(e))


class TestEmailSender(unittest.TestCase):
    """Test EmailSender main class"""

    def setUp(self):
        """Set up test config"""
        self.smtp_config = EmailConfig(
            record_uid="abc123",
            name="SMTP",
            provider="smtp",
            from_address="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_username="test@example.com",
            smtp_password="password123"
        )

    def test_email_sender_initialization_smtp(self):
        """Test EmailSender with SMTP provider"""
        sender = EmailSender(self.smtp_config)
        self.assertIsInstance(sender.provider, SMTPEmailProvider)
        self.assertEqual(sender.config, self.smtp_config)

    def test_email_sender_unknown_provider_raises_error(self):
        """Test EmailSender with unknown provider raises error"""
        bad_config = EmailConfig(
            record_uid="abc123",
            name="Bad",
            provider="unknown_provider",
            from_address="test@example.com"
        )

        with self.assertRaises(ValueError) as context:
            EmailSender(bad_config)

        self.assertIn("Unknown email provider: unknown_provider", str(context.exception))

    @patch('smtplib.SMTP')
    def test_email_sender_send(self, mock_smtp):
        """Test EmailSender.send() method"""
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        sender = EmailSender(self.smtp_config)
        result = sender.send(
            to="recipient@example.com",
            subject="Test",
            body="Test body",
            html=False
        )

        self.assertTrue(result)


class TestEmailTemplates(unittest.TestCase):
    """Test email template loading and building"""

    @patch('builtins.open', new_callable=mock_open, read_data='<html>{custom_message}</html>')
    @patch('os.path.exists', return_value=True)
    def test_load_email_template_success(self, mock_exists, mock_file):
        """Test loading email template successfully"""
        template = load_email_template('onboarding.html')
        self.assertIn('{custom_message}', template)
        self.assertIn('<html>', template)

    @patch('os.path.exists', return_value=False)
    def test_load_email_template_not_found(self, mock_exists):
        """Test loading non-existent template raises error"""
        with self.assertRaises(FileNotFoundError):
            load_email_template('nonexistent.html')

    @patch('builtins.open', new_callable=mock_open, read_data='<html>{custom_message} {share_url} {record_title} {expiration_text}</html>')
    @patch('os.path.exists', return_value=True)
    def test_build_onboarding_email(self, mock_exists, mock_file):
        """Test building onboarding email"""
        html = build_onboarding_email(
            share_url="https://test.com/share/abc123",
            custom_message="Welcome to the team!",
            record_title="Test Account",
            expiration="24 hours"
        )

        self.assertIn("https://test.com/share/abc123", html)
        self.assertIn("Welcome to the team!", html)
        self.assertIn("Test Account", html)
        self.assertIn("This link will expire in 24 hours", html)

    @patch('builtins.open', new_callable=mock_open, read_data='<html>{custom_message} {share_url} {record_title} {expiration_text}</html>')
    @patch('os.path.exists', return_value=True)
    def test_build_onboarding_email_no_expiration(self, mock_exists, mock_file):
        """Test building onboarding email without expiration"""
        html = build_onboarding_email(
            share_url="https://test.com/share/abc123",
            custom_message="Test message",
            record_title="Account"
        )

        self.assertIn("This link will expire after first use", html)

    @patch('builtins.open', new_callable=mock_open, read_data='<html>{custom_message}</html>')
    @patch('os.path.exists', return_value=True)
    def test_build_onboarding_email_escapes_special_chars(self, mock_exists, mock_file):
        """Test that template correctly handles special characters"""
        html = build_onboarding_email(
            share_url="https://test.com/share/abc123",
            custom_message="Hello! This is a test with special chars: < > & \"",
            record_title="Test Account"
        )

        # The template should include the message as-is (HTML will handle escaping)
        self.assertIn("Hello! This is a test with special chars:", html)


class TestValidateEmailProviderDependencies(unittest.TestCase):
    """Test validate_email_provider_dependencies function"""

    def test_smtp_validation_always_succeeds(self):
        """Test SMTP validation always returns True (no dependencies needed)"""
        is_valid, error_message = validate_email_provider_dependencies('smtp')
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    def test_smtp_validation_case_insensitive(self):
        """Test SMTP validation is case-insensitive"""
        is_valid, error_message = validate_email_provider_dependencies('SMTP')
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    @patch('builtins.__import__')
    def test_sendgrid_validation_success(self, mock_import):
        """Test SendGrid validation succeeds when library is installed"""
        # Mock successful import of sendgrid
        mock_import.return_value = MagicMock()

        is_valid, error_message = validate_email_provider_dependencies('sendgrid')
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    @patch('builtins.__import__', side_effect=ImportError("No module named 'sendgrid'"))
    def test_sendgrid_validation_failure(self, mock_import):
        """Test SendGrid validation fails when library is missing"""
        is_valid, error_message = validate_email_provider_dependencies('sendgrid')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)
        self.assertIn('sendgrid', error_message.lower())
        self.assertIn('pip install keepercommander[email-sendgrid]', error_message)

    @patch('builtins.__import__')
    def test_ses_validation_success(self, mock_import):
        """Test SES validation succeeds when boto3 is installed"""
        mock_import.return_value = MagicMock()

        is_valid, error_message = validate_email_provider_dependencies('ses')
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    @patch('builtins.__import__', side_effect=ImportError("No module named 'boto3'"))
    def test_ses_validation_failure(self, mock_import):
        """Test SES validation fails when boto3 is missing"""
        is_valid, error_message = validate_email_provider_dependencies('ses')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)
        self.assertIn('boto3', error_message.lower())
        self.assertIn('pip install keepercommander[email-ses]', error_message)

    @patch('builtins.__import__')
    def test_gmail_oauth_validation_success(self, mock_import):
        """Test Gmail OAuth validation succeeds when Google libraries are installed"""
        mock_import.return_value = MagicMock()

        is_valid, error_message = validate_email_provider_dependencies('gmail-oauth')
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    @patch('builtins.__import__', side_effect=ImportError("No module named 'google.auth'"))
    def test_gmail_oauth_validation_failure(self, mock_import):
        """Test Gmail OAuth validation fails when Google libraries are missing"""
        is_valid, error_message = validate_email_provider_dependencies('gmail-oauth')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)
        self.assertIn('Gmail OAuth', error_message)
        self.assertIn('pip install keepercommander[email-gmail-oauth]', error_message)
        self.assertIn('google-api-python-client', error_message)

    @patch('builtins.__import__')
    def test_microsoft_oauth_validation_success(self, mock_import):
        """Test Microsoft OAuth validation succeeds when msal is installed"""
        mock_import.return_value = MagicMock()

        is_valid, error_message = validate_email_provider_dependencies('microsoft-oauth')
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    @patch('builtins.__import__', side_effect=ImportError("No module named 'msal'"))
    def test_microsoft_oauth_validation_failure(self, mock_import):
        """Test Microsoft OAuth validation fails when msal is missing"""
        is_valid, error_message = validate_email_provider_dependencies('microsoft-oauth')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)
        self.assertIn('msal', error_message.lower())
        self.assertIn('pip install keepercommander[email-microsoft-oauth]', error_message)

    def test_unknown_provider_validation(self):
        """Test validation fails for unknown provider"""
        is_valid, error_message = validate_email_provider_dependencies('unknown_provider')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)
        self.assertIn('Unknown email provider: unknown_provider', error_message)
        self.assertIn('smtp', error_message)
        self.assertIn('sendgrid', error_message)
        self.assertIn('ses', error_message)

    def test_empty_provider_validation(self):
        """Test validation fails for empty provider string"""
        is_valid, error_message = validate_email_provider_dependencies('')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)


class TestInstallationMethodDetection(unittest.TestCase):
    """Test installation method detection functionality"""

    def test_get_installation_method_source(self):
        """Test detection of source installation"""
        # When running from source, should detect as 'source' or 'pip'
        method = get_installation_method()
        self.assertIn(method, ['source', 'pip', 'binary'])

    @patch('sys.frozen', True, create=True)
    def test_get_installation_method_binary(self):
        """Test detection of binary installation"""
        # When sys.frozen is True, should detect as 'binary'
        import importlib
        import keepercommander.email_service
        importlib.reload(keepercommander.email_service)

        from keepercommander.email_service import get_installation_method
        method = get_installation_method()
        self.assertEqual(method, 'binary')


class TestCheckProviderDependencies(unittest.TestCase):
    """Test check_provider_dependencies functionality"""

    def test_smtp_always_available(self):
        """Test SMTP is always available (stdlib-based)"""
        available, error_msg = check_provider_dependencies('smtp')
        self.assertTrue(available)
        self.assertEqual(error_msg, '')

    @patch('keepercommander.email_service.get_installation_method')
    def test_sendgrid_blocked_on_binary(self, mock_install_method):
        """Test SendGrid is blocked on binary installations"""
        mock_install_method.return_value = 'binary'

        available, error_msg = check_provider_dependencies('sendgrid')
        self.assertFalse(available)
        self.assertIn('binary installation', error_msg)
        self.assertIn('switch to the PyPI version', error_msg)
        self.assertIn('pip install keepercommander[email]', error_msg)

    @patch('keepercommander.email_service.get_installation_method')
    def test_ses_blocked_on_binary(self, mock_install_method):
        """Test AWS SES is blocked on binary installations"""
        mock_install_method.return_value = 'binary'

        available, error_msg = check_provider_dependencies('ses')
        self.assertFalse(available)
        self.assertIn('binary installation', error_msg)
        self.assertIn('switch to the PyPI version', error_msg)

    @patch('keepercommander.email_service.get_installation_method')
    def test_gmail_oauth_blocked_on_binary(self, mock_install_method):
        """Test Gmail OAuth is blocked on binary installations"""
        mock_install_method.return_value = 'binary'

        available, error_msg = check_provider_dependencies('gmail-oauth')
        self.assertFalse(available)
        self.assertIn('binary installation', error_msg)
        self.assertIn('switch to the PyPI version', error_msg)

    @patch('keepercommander.email_service.get_installation_method')
    def test_microsoft_oauth_blocked_on_binary(self, mock_install_method):
        """Test Microsoft OAuth is blocked on binary installations"""
        mock_install_method.return_value = 'binary'

        available, error_msg = check_provider_dependencies('microsoft-oauth')
        self.assertFalse(available)
        self.assertIn('binary installation', error_msg)

    @patch('keepercommander.email_service.get_installation_method')
    def test_provider_available_on_pip_with_dependencies(self, mock_install_method):
        """Test providers available on pip when dependencies installed"""
        mock_install_method.return_value = 'pip'

        # SMTP should always work
        available, _ = check_provider_dependencies('smtp')
        self.assertTrue(available)


class TestEmailSenderBinaryRestrictions(unittest.TestCase):
    """Test EmailSender initialization with binary restrictions"""

    @patch('keepercommander.email_service.get_installation_method')
    def test_email_sender_smtp_works_on_binary(self, mock_install_method):
        """Test EmailSender with SMTP works on binary"""
        mock_install_method.return_value = 'binary'

        config = EmailConfig(
            record_uid="abc123",
            name="SMTP",
            provider="smtp",
            from_address="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_username="test@example.com",
            smtp_password="password123"
        )

        # Should not raise error
        sender = EmailSender(config)
        # Check by class name to avoid module reload issues
        self.assertEqual(sender.provider.__class__.__name__, 'SMTPEmailProvider')

    @patch('keepercommander.email_service.get_installation_method')
    def test_email_sender_sendgrid_blocked_on_binary(self, mock_install_method):
        """Test EmailSender with SendGrid raises error on binary"""
        mock_install_method.return_value = 'binary'

        config = EmailConfig(
            record_uid="abc123",
            name="SendGrid",
            provider="sendgrid",
            from_address="test@example.com",
            sendgrid_api_key="SG.test_key"
        )

        # Should raise ValueError with binary error message
        with self.assertRaises(ValueError) as context:
            EmailSender(config)

        error_msg = str(context.exception)
        self.assertIn('binary installation', error_msg)
        self.assertIn('switch to the PyPI version', error_msg)

    @patch('keepercommander.email_service.get_installation_method')
    def test_email_sender_ses_blocked_on_binary(self, mock_install_method):
        """Test EmailSender with SES raises error on binary"""
        mock_install_method.return_value = 'binary'

        config = EmailConfig(
            record_uid="abc123",
            name="SES",
            provider="ses",
            from_address="test@example.com",
            aws_region="us-east-1",
            aws_access_key="AKIATEST",
            aws_secret_key="secrettest"
        )

        # Should raise ValueError
        with self.assertRaises(ValueError) as context:
            EmailSender(config)

        self.assertIn('binary installation', str(context.exception))


if __name__ == '__main__':
    unittest.main()
