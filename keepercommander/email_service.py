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
Email Service Module for Keeper Commander

Provides email sending capabilities for automated onboarding and credential sharing.
Supports multiple email providers: SMTP, AWS SES, SendGrid.

Zero-knowledge architecture preserved - emails sent client-side with customer's
email infrastructure.
"""

from __future__ import annotations
import logging
import os
import smtplib
import ssl
import sys
import keepercommander
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any, List



def get_installation_method():
    """
    Detect Keeper Commander installation method.

    Returns:
        str: 'binary' (PyInstaller frozen), 'pip' (installed via pip), or 'source' (development)
    """

    # Check if running as PyInstaller binary
    if getattr(sys, 'frozen', False):
        return 'binary'

    # Check if installed via pip
    location = keepercommander.__file__

    if 'site-packages' in location or 'dist-packages' in location:
        return 'pip'

    # Running from source
    return 'source'


def check_provider_dependencies(provider: str) -> tuple:
    """
    Check if dependencies for a provider are available.

    Args:
        provider: Provider name (smtp, ses, sendgrid, gmail-oauth, microsoft-oauth)

    Returns:
        tuple: (dependencies_available: bool, error_message: str)
    """
    if provider == 'smtp':
        # SMTP uses standard library, always works
        return (True, '')

    installation_method = get_installation_method()

    # Binary installations only support SMTP
    if installation_method == 'binary':
        return (
            False,
            f'{provider} is not available in the binary installation.\n'
            f'\n'
            f'To use this provider, you must switch to the PyPI version:\n'
            f'  1. Uninstall the binary version\n'
            f'  2. Install via pip with email dependencies:\n'
            f'     pip install keepercommander[email]\n'
            f'\n'
            f'The binary version only supports SMTP for email functionality.'
        )

    # Check for required packages on pip/source installations
    if provider == 'ses':
        try:
            import boto3
            return (True, '')
        except ImportError:
            return (
                False,
                'AWS SES requires additional dependencies.\n'
                'Install with:\n'
                '  pip install keepercommander[email-ses]\n'
                '  # or install all email providers:\n'
                '  pip install keepercommander[email]'
            )

    elif provider == 'sendgrid':
        try:
            import sendgrid
            return (True, '')
        except ImportError:
            return (
                False,
                'SendGrid requires additional dependencies.\n'
                'Install with:\n'
                '  pip install keepercommander[email-sendgrid]\n'
                '  # or install all email providers:\n'
                '  pip install keepercommander[email]'
            )

    elif provider == 'gmail-oauth':
        try:
            import google.auth
            import googleapiclient
            return (True, '')
        except ImportError:
            return (
                False,
                'Gmail OAuth requires additional dependencies.\n'
                'Install with:\n'
                '  pip install keepercommander[email-gmail-oauth]\n'
                '  # or install all email providers:\n'
                '  pip install keepercommander[email]'
            )

    elif provider == 'microsoft-oauth':
        try:
            import msal
            return (True, '')
        except ImportError:
            return (
                False,
                'Microsoft OAuth requires additional dependencies.\n'
                'Install with:\n'
                '  pip install keepercommander[email-microsoft-oauth]\n'
                '  # or install all email providers:\n'
                '  pip install keepercommander[email]'
            )

    return (True, '')


@dataclass
class EmailConfig:
    """
    Email configuration for sending emails via various providers.

    Stored as Keeper records (login type) with encrypted credentials.
    See ADR Decision 1 in ONBOARDING_FEATURE_IMPLEMENTATION_PLAN.md

    Supported providers:
    - smtp: Standard SMTP with username/password
    - ses: AWS Simple Email Service
    - sendgrid: SendGrid API
    - gmail-oauth: Gmail with OAuth 2.0 (uses Gmail API)
    - microsoft-oauth: Microsoft 365/Outlook with OAuth 2.0 (uses Graph API)
    """
    record_uid: str
    name: str
    provider: str  # 'smtp', 'ses', 'sendgrid', 'gmail-oauth', 'microsoft-oauth'
    from_address: str
    from_name: str = "Keeper Commander"

    # SMTP-specific
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False

    # AWS SES-specific
    aws_region: Optional[str] = None
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None

    # SendGrid-specific
    sendgrid_api_key: Optional[str] = None

    # OAuth-specific (gmail-oauth, microsoft-oauth)
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_access_token: Optional[str] = None
    oauth_refresh_token: Optional[str] = None
    oauth_token_expiry: Optional[str] = None  # ISO 8601 format
    oauth_scopes: Optional[List[str]] = None
    oauth_tenant_id: Optional[str] = None  # For Microsoft 365 (can be 'common', 'organizations', or specific tenant ID)

    # Additional metadata
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    # Internal flag to track OAuth token updates (not stored in Keeper)
    _oauth_tokens_updated: bool = field(default=False, init=False)

    def validate(self) -> List[str]:
        """
        Validate email configuration completeness.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not self.provider:
            errors.append("Provider is required")

        if not self.from_address:
            errors.append("From address is required")

        if self.provider == 'smtp':
            if not self.smtp_host:
                errors.append("SMTP host is required")
            if not self.smtp_username:
                errors.append("SMTP username is required")
            if not self.smtp_password:
                errors.append("SMTP password is required")

        elif self.provider == 'ses':
            if not self.aws_region:
                errors.append("AWS region is required for SES")
            if not self.aws_access_key:
                errors.append("AWS access key is required for SES")
            if not self.aws_secret_key:
                errors.append("AWS secret key is required for SES")

        elif self.provider == 'sendgrid':
            if not self.sendgrid_api_key:
                errors.append("SendGrid API key is required")

        elif self.provider in ('gmail-oauth', 'microsoft-oauth'):
            # OAuth providers require either interactive auth OR manual token entry
            if not self.oauth_client_id:
                errors.append(f"OAuth client ID is required for {self.provider}")
            if not self.oauth_client_secret:
                errors.append(f"OAuth client secret is required for {self.provider}")

            # If no access token, we'll do interactive OAuth flow
            # If access token provided, we should also have refresh token
            if self.oauth_access_token and not self.oauth_refresh_token:
                errors.append("OAuth refresh token is required when access token is provided")

            # Microsoft requires tenant ID
            if self.provider == 'microsoft-oauth' and not self.oauth_tenant_id:
                errors.append("OAuth tenant ID is required for Microsoft (use 'common' for multi-tenant)")

        else:
            errors.append(f"Unknown provider: {self.provider}")

        return errors

    def is_oauth_provider(self) -> bool:
        """Check if this config uses OAuth authentication."""
        return self.provider in ('gmail-oauth', 'microsoft-oauth')

    def tokens_need_refresh(self) -> bool:
        """
        Check if OAuth tokens need to be refreshed.

        Returns:
            True if tokens are expired or will expire soon (within 5 minutes)
        """
        if not self.is_oauth_provider():
            return False

        if not self.oauth_token_expiry:
            # No expiry set, assume tokens are valid
            return False

        try:
            from datetime import datetime, timedelta, timezone
            expiry = datetime.fromisoformat(self.oauth_token_expiry.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            # Refresh if expired or expiring within 5 minutes
            return expiry <= now + timedelta(minutes=5)
        except Exception:
            # If we can't parse the expiry, assume we need to refresh
            return True


class EmailProvider(ABC):
    """
    Abstract base class for email providers.

    Each provider implements send() method for their specific API/protocol.
    """

    def __init__(self, config: EmailConfig):
        self.config = config
        validation_errors = config.validate()
        if validation_errors:
            raise ValueError(f"Invalid email configuration: {', '.join(validation_errors)}")

    @abstractmethod
    def send(self, to: str, subject: str, body: str, html: bool = False) -> bool:
        """
        Send email via provider.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body (plain text or HTML)
            html: True if body is HTML

        Returns:
            True if sent successfully, False otherwise

        Raises:
            Exception: If send fails with unrecoverable error
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to email provider.

        Returns:
            True if connection successful, False otherwise
        """
        pass


class SMTPEmailProvider(EmailProvider):
    """
    SMTP email provider implementation.

    Supports standard SMTP with TLS/SSL for Gmail, Office 365, and other SMTP servers.
    """

    def __init__(self, config: EmailConfig):
        super().__init__(config)
        self._connection = None

    def send(self, to: str, subject: str, body: str, html: bool = False) -> bool:
        """
        Send email via SMTP.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body
            html: True if body is HTML

        Returns:
            True if sent successfully

        Raises:
            smtplib.SMTPException: If SMTP operation fails
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.from_name} <{self.config.from_address}>"
            msg['To'] = to

            # Attach body
            if html:
                part = MIMEText(body, 'html')
            else:
                part = MIMEText(body, 'plain')
            msg.attach(part)

            # Connect and send
            if self.config.smtp_use_ssl:
                # Use SMTP_SSL for port 465
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    self.config.smtp_host,
                    self.config.smtp_port,
                    context=context
                ) as server:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                    server.send_message(msg)
            else:
                # Use SMTP with STARTTLS for port 587
                with smtplib.SMTP(
                    self.config.smtp_host,
                    self.config.smtp_port,
                    timeout=30
                ) as server:
                    server.ehlo()
                    if self.config.smtp_use_tls:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                        server.ehlo()
                    server.login(self.config.smtp_username, self.config.smtp_password)
                    server.send_message(msg)

            logging.info(f"[EMAIL] SMTP email sent to {to} via {self.config.smtp_host}")
            return True

        except smtplib.SMTPAuthenticationError as e:
            logging.error(f"[EMAIL] SMTP authentication failed: {e}")
            raise
        except smtplib.SMTPException as e:
            logging.error(f"[EMAIL] SMTP error: {e}")
            raise
        except Exception as e:
            logging.error(f"[EMAIL] Unexpected error sending email: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test SMTP connection and authentication.

        Returns:
            True if connection successful
        """
        try:
            if self.config.smtp_use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    self.config.smtp_host,
                    self.config.smtp_port,
                    context=context,
                    timeout=10
                ) as server:
                    server.login(self.config.smtp_username, self.config.smtp_password)
            else:
                with smtplib.SMTP(
                    self.config.smtp_host,
                    self.config.smtp_port,
                    timeout=10
                ) as server:
                    server.ehlo()
                    if self.config.smtp_use_tls:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                        server.ehlo()
                    server.login(self.config.smtp_username, self.config.smtp_password)

            logging.info(f"[EMAIL] SMTP connection test successful: {self.config.smtp_host}")
            return True

        except Exception as e:
            logging.error(f"[EMAIL] SMTP connection test failed: {e}")
            return False


class SendGridEmailProvider(EmailProvider):
    """
    SendGrid email provider implementation.

    Uses SendGrid HTTP API for sending emails.
    """

    def __init__(self, config: EmailConfig):
        super().__init__(config)
        # Import here to avoid dependency if not using SendGrid
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail
            self.SendGridAPIClient = SendGridAPIClient
            self.Mail = Mail
        except ImportError:
            _, error_message = check_provider_dependencies('sendgrid')
            raise ImportError(error_message)

    def send(self, to: str, subject: str, body: str, html: bool = False) -> bool:
        """
        Send email via SendGrid API.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body
            html: True if body is HTML

        Returns:
            True if sent successfully
        """
        try:
            message = self.Mail(
                from_email=(self.config.from_address, self.config.from_name),
                to_emails=to,
                subject=subject,
                html_content=body if html else None,
                plain_text_content=body if not html else None
            )

            sg = self.SendGridAPIClient(self.config.sendgrid_api_key)
            response = sg.send(message)

            if response.status_code in (200, 201, 202):
                logging.info(f"[EMAIL] SendGrid email sent to {to}")
                return True
            else:
                logging.error(f"[EMAIL] SendGrid returned status {response.status_code}")
                return False

        except Exception as e:
            logging.error(f"[EMAIL] SendGrid error: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test SendGrid API connection.

        Returns:
            True if API key is valid
        """
        try:
            # SendGrid doesn't have a dedicated test endpoint
            # We can verify the API key format and try to initialize the client
            sg = self.SendGridAPIClient(self.config.sendgrid_api_key)

            # If we get here without exception, API key format is valid
            # Note: This doesn't guarantee the key is active, but it's the best we can do
            logging.info("[EMAIL] SendGrid API client initialized successfully")
            return True

        except Exception as e:
            logging.error(f"[EMAIL] SendGrid connection test failed: {e}")
            return False


class SESEmailProvider(EmailProvider):
    """
    AWS SES email provider implementation.

    Uses boto3 to send emails via Amazon Simple Email Service.
    """

    def __init__(self, config: EmailConfig):
        super().__init__(config)
        # Import here to avoid dependency if not using SES
        try:
            import boto3
            from botocore.exceptions import ClientError
            self.boto3 = boto3
            self.ClientError = ClientError
        except ImportError:
            _, error_message = check_provider_dependencies('ses')
            raise ImportError(error_message)

        # Initialize SES client
        self.ses_client = self.boto3.client(
            'ses',
            region_name=self.config.aws_region,
            aws_access_key_id=self.config.aws_access_key,
            aws_secret_access_key=self.config.aws_secret_key
        )

    def send(self, to: str, subject: str, body: str, html: bool = False) -> bool:
        """
        Send email via AWS SES.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body
            html: True if body is HTML

        Returns:
            True if sent successfully
        """
        try:
            if html:
                body_part = {'Html': {'Charset': 'UTF-8', 'Data': body}}
            else:
                body_part = {'Text': {'Charset': 'UTF-8', 'Data': body}}

            response = self.ses_client.send_email(
                Source=f"{self.config.from_name} <{self.config.from_address}>",
                Destination={'ToAddresses': [to]},
                Message={
                    'Subject': {'Charset': 'UTF-8', 'Data': subject},
                    'Body': body_part
                }
            )

            message_id = response.get('MessageId')
            logging.info(f"[EMAIL] SES email sent to {to}, MessageId: {message_id}")
            return True

        except self.ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']

            if error_code == 'MessageRejected':
                logging.error(f"[EMAIL] SES rejected message: {error_message}")
            elif error_code == 'ConfigurationSetDoesNotExist':
                logging.error(f"[EMAIL] SES configuration error: {error_message}")
            else:
                logging.error(f"[EMAIL] SES error ({error_code}): {error_message}")

            raise

        except Exception as e:
            logging.error(f"[EMAIL] SES unexpected error: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test AWS SES connection and verify email address.

        Returns:
            True if connection successful and sender email verified
        """
        try:
            # Check if sender email is verified in SES
            response = self.ses_client.get_identity_verification_attributes(
                Identities=[self.config.from_address]
            )

            attributes = response.get('VerificationAttributes', {})
            status = attributes.get(self.config.from_address, {}).get('VerificationStatus')

            if status == 'Success':
                logging.info(f"[EMAIL] SES connection test successful, {self.config.from_address} is verified")
                return True
            else:
                logging.warning(
                    f"[EMAIL] SES email {self.config.from_address} not verified. "
                    f"Status: {status}. Emails may fail to send."
                )
                return False

        except self.ClientError as e:
            logging.error(f"[EMAIL] SES connection test failed: {e}")
            return False

        except Exception as e:
            logging.error(f"[EMAIL] SES unexpected error: {e}")
            return False


class GmailOAuthProvider(EmailProvider):
    """
    Gmail OAuth email provider implementation.

    Uses Gmail API with OAuth 2.0 authentication instead of SMTP.
    Automatically refreshes expired tokens.
    """

    def __init__(self, config: EmailConfig):
        """
        Initialize Gmail OAuth provider.

        Args:
            config: EmailConfig with OAuth credentials
        """
        super().__init__(config)

        # Import Gmail API dependencies
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build

            self.Request = Request
            self.Credentials = Credentials
            self.build = build
        except ImportError as e:
            _, error_message = check_provider_dependencies('gmail-oauth')
            raise ImportError(error_message) from e

        self.credentials = self._load_credentials()
        self.service = None

    def _load_credentials(self):
        """Load OAuth credentials from config."""
        from datetime import datetime, timezone

        if not self.config.oauth_access_token:
            raise ValueError("Gmail OAuth access token is required")

        # Parse token expiry
        token_expiry = None
        if self.config.oauth_token_expiry:
            try:
                # Parse as timezone-aware datetime
                expiry_aware = datetime.fromisoformat(
                    self.config.oauth_token_expiry.replace('Z', '+00:00')
                )
                # Convert to naive UTC datetime (Google's library expects naive datetimes)
                token_expiry = expiry_aware.replace(tzinfo=None)
            except Exception:
                pass

        # Create credentials object
        creds = self.Credentials(
            token=self.config.oauth_access_token,
            refresh_token=self.config.oauth_refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=self.config.oauth_client_id,
            client_secret=self.config.oauth_client_secret,
            scopes=['https://www.googleapis.com/auth/gmail.send']
        )

        # Set expiry if available (as naive UTC datetime)
        if token_expiry:
            creds.expiry = token_expiry

        return creds

    def _refresh_if_expired(self):
        """Refresh tokens if expired."""
        if self.credentials.expired or not self.credentials.valid:
            logging.info("[EMAIL] Gmail OAuth tokens expired, refreshing...")
            self.credentials.refresh(self.Request())

            # Update config with new tokens
            self.config.oauth_access_token = self.credentials.token
            if self.credentials.refresh_token:
                self.config.oauth_refresh_token = self.credentials.refresh_token
            if self.credentials.expiry:
                self.config.oauth_token_expiry = self.credentials.expiry.isoformat()

            # Mark tokens as updated so caller can persist them
            self.config._oauth_tokens_updated = True

            logging.info("[EMAIL] Gmail OAuth tokens refreshed successfully")

    def _get_service(self):
        """Get or create Gmail API service."""
        if not self.service:
            self._refresh_if_expired()
            self.service = self.build('gmail', 'v1', credentials=self.credentials)
        return self.service

    def send(self, to: str, subject: str, body: str, html: bool = False) -> bool:
        """
        Send email via Gmail API.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body (HTML or plain text)
            html: True if body is HTML

        Returns:
            True if sent successfully
        """
        try:
            import base64
            from email.mime.text import MIMEText

            # Create message
            message = MIMEText(body, 'html' if html else 'plain')
            message['to'] = to
            message['from'] = f"{self.config.from_name} <{self.config.from_address}>"
            message['subject'] = subject

            # Encode message
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')

            # Send via Gmail API
            service = self._get_service()
            service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()

            logging.info(f"[EMAIL] Gmail OAuth email sent to {to}")
            return True

        except Exception as e:
            logging.error(f"[EMAIL] Gmail OAuth error: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test Gmail OAuth connection.

        Returns:
            True if credentials are valid
        """
        try:
            # Refresh tokens if needed
            self._refresh_if_expired()

            # Verify credentials are valid by checking they're not expired
            # Note: gmail.send scope doesn't allow reading profile/labels
            # so we just verify the credentials object is valid
            if self.credentials and self.credentials.valid:
                logging.info(f"[EMAIL] Gmail OAuth connection successful: {self.config.from_address}")
                return True
            else:
                logging.error("[EMAIL] Gmail OAuth credentials are invalid")
                return False

        except Exception as e:
            logging.error(f"[EMAIL] Gmail OAuth connection test failed: {e}")
            return False


class MicrosoftOAuthProvider(EmailProvider):
    """
    Microsoft OAuth email provider implementation.

    Uses Microsoft Graph API with OAuth 2.0 authentication.
    Supports Microsoft 365, Outlook.com, and organizational accounts.
    """

    def __init__(self, config: EmailConfig):
        """
        Initialize Microsoft OAuth provider.

        Args:
            config: EmailConfig with OAuth credentials and tenant_id
        """
        super().__init__(config)

        # Import msal dependency
        try:
            import msal
            self.msal = msal
        except ImportError as e:
            _, error_message = check_provider_dependencies('microsoft-oauth')
            raise ImportError(error_message) from e

        if not self.config.oauth_tenant_id:
            raise ValueError("Microsoft OAuth requires tenant_id (use 'common' for multi-tenant)")

        # Build MSAL confidential client app
        self.app = self._build_msal_app()
        self.token_cache = {}

    def _build_msal_app(self):
        """Build MSAL confidential client application."""
        authority = f"https://login.microsoftonline.com/{self.config.oauth_tenant_id}"

        return self.msal.ConfidentialClientApplication(
            client_id=self.config.oauth_client_id,
            client_credential=self.config.oauth_client_secret,
            authority=authority
        )

    def _get_access_token(self) -> str:
        """
        Get valid access token, refreshing if necessary.

        Returns:
            Valid access token
        """
        # Check if we have cached token and it's still valid
        if self.config.oauth_access_token and not self.config.tokens_need_refresh():
            return self.config.oauth_access_token

        # Need to refresh token
        if not self.config.oauth_refresh_token:
            raise ValueError("OAuth refresh token is required to refresh access token")

        logging.info("[EMAIL] Microsoft OAuth tokens expired, refreshing...")

        # Acquire token by refresh token
        result = self.app.acquire_token_by_refresh_token(
            refresh_token=self.config.oauth_refresh_token,
            scopes=['https://graph.microsoft.com/Mail.Send']
        )

        if 'access_token' in result:
            # Update config with new tokens
            self.config.oauth_access_token = result['access_token']

            # Update refresh token if new one provided
            if 'refresh_token' in result:
                self.config.oauth_refresh_token = result['refresh_token']

            # Calculate and update expiry
            if 'expires_in' in result:
                from datetime import datetime, timedelta, timezone
                expiry = datetime.now(timezone.utc) + timedelta(seconds=result['expires_in'])
                self.config.oauth_token_expiry = expiry.isoformat()

            # Mark tokens as updated so caller can persist them
            self.config._oauth_tokens_updated = True

            logging.info("[EMAIL] Microsoft OAuth tokens refreshed successfully")
            return result['access_token']
        else:
            error = result.get('error', 'Unknown error')
            error_desc = result.get('error_description', '')
            raise Exception(f"Failed to refresh Microsoft OAuth token: {error} - {error_desc}")

    def send(self, to: str, subject: str, body: str, html: bool = False) -> bool:
        """
        Send email via Microsoft Graph API.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body (HTML or plain text)
            html: True if body is HTML

        Returns:
            True if sent successfully
        """
        try:
            import requests

            # Get valid access token
            access_token = self._get_access_token()

            # Build Graph API request
            url = 'https://graph.microsoft.com/v1.0/me/sendMail'
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            # Construct email message
            message = {
                'message': {
                    'subject': subject,
                    'body': {
                        'contentType': 'HTML' if html else 'Text',
                        'content': body
                    },
                    'toRecipients': [
                        {
                            'emailAddress': {
                                'address': to
                            }
                        }
                    ],
                    'from': {
                        'emailAddress': {
                            'name': self.config.from_name,
                            'address': self.config.from_address
                        }
                    }
                },
                'saveToSentItems': 'true'
            }

            # Send request
            response = requests.post(url, headers=headers, json=message)

            if response.status_code == 202:
                logging.info(f"[EMAIL] Microsoft Graph email sent to {to}")
                return True
            else:
                logging.error(f"[EMAIL] Microsoft Graph returned status {response.status_code}: {response.text}")
                return False

        except Exception as e:
            logging.error(f"[EMAIL] Microsoft OAuth error: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test Microsoft OAuth connection.

        Returns:
            True if credentials are valid
        """
        try:
            import requests

            # Get valid access token
            access_token = self._get_access_token()

            # Try to get user profile to verify connection
            url = 'https://graph.microsoft.com/v1.0/me'
            headers = {
                'Authorization': f'Bearer {access_token}'
            }

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                email = data.get('mail') or data.get('userPrincipalName')
                logging.info(f"[EMAIL] Microsoft OAuth connection successful: {email}")
                return True
            else:
                logging.error(f"[EMAIL] Microsoft OAuth connection test failed: {response.status_code}")
                return False

        except Exception as e:
            logging.error(f"[EMAIL] Microsoft OAuth connection test failed: {e}")
            return False


class EmailSender:
    """
    Main email sender class that routes to appropriate provider.

    Usage:
        config = EmailConfig(...)
        sender = EmailSender(config)
        sender.send(to='user@example.com', subject='Test', body='Hello', html=True)
    """

    def __init__(self, config: EmailConfig):
        """
        Initialize email sender with configuration.

        Args:
            config: EmailConfig object

        Raises:
            ValueError: If provider is unknown or config invalid
        """
        self.config = config

        # Check provider compatibility with current installation
        dependencies_available, error_message = check_provider_dependencies(config.provider)
        if not dependencies_available:
            raise ValueError(error_message)

        # Create provider instance
        provider_map = {
            'smtp': SMTPEmailProvider,
            'sendgrid': SendGridEmailProvider,
            'ses': SESEmailProvider,
            'gmail-oauth': GmailOAuthProvider,
            'microsoft-oauth': MicrosoftOAuthProvider,
        }

        provider_class = provider_map.get(config.provider.lower())
        if not provider_class:
            raise ValueError(
                f"Unknown email provider: {config.provider}. "
                f"Supported: {', '.join(provider_map.keys())}"
            )

        self.provider = provider_class(config)

    def send(self, to: str, subject: str, body: str, html: bool = False) -> bool:
        """
        Send email via configured provider.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body
            html: True if body is HTML

        Returns:
            True if sent successfully

        Raises:
            Exception: If send fails
        """
        logging.info(f"[EMAIL] Sending email to {to} via {self.config.provider}")
        return self.provider.send(to, subject, body, html)

    def test_connection(self) -> bool:
        """
        Test connection to email provider.

        Returns:
            True if connection successful
        """
        return self.provider.test_connection()


def load_email_template(template_name: str = 'onboarding.html') -> str:
    """
    Load email template from resources directory.

    Args:
        template_name: Name of template file (default: onboarding.html)

    Returns:
        Template content as string

    Raises:
        FileNotFoundError: If template file doesn't exist
    """
    # Get path to template file
    module_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(module_dir, 'resources', 'email_templates', template_name)

    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Email template not found: {template_path}")

    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()


def build_onboarding_email(
    share_url: str,
    custom_message: str,
    record_title: str,
    expiration: Optional[str] = None
) -> str:
    """
    Build HTML email for onboarding with one-time share link.

    Args:
        share_url: One-time share URL
        custom_message: Custom message from administrator
        record_title: Title of the record being shared
        expiration: Human-readable expiration time (e.g., "24 hours", "1 day")

    Returns:
        HTML email body

    Raises:
        FileNotFoundError: If email template not found
    """
    # Load template
    template = load_email_template('onboarding.html')

    # Prepare variables
    expiration_text = (
        f"This link will expire in {expiration}"
        if expiration
        else "This link will expire after first use"
    )

    # Fill in template
    html = template.format(
        custom_message=custom_message,
        share_url=share_url,
        record_title=record_title,
        expiration_text=expiration_text
    )

    return html


def validate_email_provider_dependencies(provider: str) -> tuple[bool, Optional[str]]:
    """
    Validate that required dependencies for an email provider are installed.

    This function checks if dependencies are available WITHOUT creating the provider instance,
    allowing early validation before performing operations like password rotation.

    Args:
        provider: Email provider name ('smtp', 'sendgrid', 'ses', 'gmail-oauth', 'microsoft-oauth')

    Returns:
        Tuple of (is_valid, error_message):
            - is_valid: True if dependencies are available, False otherwise
            - error_message: None if valid, otherwise contains install instructions

    Examples:
        >>> valid, error = validate_email_provider_dependencies('gmail-oauth')
        >>> if not valid:
        ...     print(error)
        Gmail OAuth requires google-api-python-client and related libraries.
        Install with: pip install keepercommander[email-gmail-oauth]
    """
    provider = provider.lower()

    # SMTP uses Python built-ins, no extra dependencies needed
    if provider == 'smtp':
        return True, None

    # SendGrid
    if provider == 'sendgrid':
        try:
            import sendgrid  # noqa: F401
            return True, None
        except ImportError:
            return False, (
                "SendGrid email provider requires the 'sendgrid' library.\n"
                "Install with: pip install keepercommander[email-sendgrid]\n"
                "Or install manually: pip install sendgrid>=6.10.0"
            )

    # AWS SES
    if provider == 'ses':
        try:
            import boto3  # noqa: F401
            return True, None
        except ImportError:
            return False, (
                "AWS SES email provider requires the 'boto3' library.\n"
                "Install with: pip install keepercommander[email-ses]\n"
                "Or install manually: pip install boto3>=1.26.0"
            )

    # Gmail OAuth
    if provider == 'gmail-oauth':
        try:
            import google.auth  # noqa: F401
            import google.auth.transport.requests  # noqa: F401
            import google.oauth2.credentials  # noqa: F401
            import googleapiclient.discovery  # noqa: F401
            return True, None
        except ImportError:
            return False, (
                "Gmail OAuth email provider requires Google API libraries.\n"
                "Install with: pip install keepercommander[email-gmail-oauth]\n"
                "Or install manually: pip install google-api-python-client google-auth google-auth-oauthlib google-auth-httplib2"
            )

    # Microsoft OAuth
    if provider == 'microsoft-oauth':
        try:
            import msal  # noqa: F401
            return True, None
        except ImportError:
            return False, (
                "Microsoft OAuth email provider requires the 'msal' library.\n"
                "Install with: pip install keepercommander[email-microsoft-oauth]\n"
                "Or install manually: pip install msal>=1.20.0"
            )

    # Unknown provider
    return False, (
        f"Unknown email provider: {provider}\n"
        f"Supported providers: smtp, sendgrid, ses, gmail-oauth, microsoft-oauth"
    )
