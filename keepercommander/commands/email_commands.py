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
Email Configuration Commands for Keeper Commander

Manages email provider configurations stored as Keeper records.
Supports SMTP, AWS SES, and SendGrid providers.
"""

import argparse
import json
import logging
from typing import Optional

from .base import Command, GroupCommand, dump_report_data, field_to_title
from .. import api, crypto, utils, vault, vault_extensions, record_management
from ..email_service import EmailConfig, EmailSender, check_provider_dependencies, get_installation_method
from ..params import KeeperParams
from ..error import CommandError


# =============================================================================
# Argument Parsers
# =============================================================================

email_config_parser = argparse.ArgumentParser(
    prog='email-config',
    description='Manage email provider configurations'
)

# email-config create
email_config_create_parser = argparse.ArgumentParser(
    prog='email-config create',
    description='Create a new email configuration'
)
email_config_create_parser.add_argument(
    '--name',
    required=True,
    help='Name for this email configuration'
)
email_config_create_parser.add_argument(
    '--provider',
    required=True,
    choices=['smtp', 'ses', 'sendgrid', 'gmail-oauth', 'microsoft-oauth'],
    help='Email provider type'
)
email_config_create_parser.add_argument(
    '--from-address',
    dest='from_address',
    required=True,
    help='From email address'
)
email_config_create_parser.add_argument(
    '--from-name',
    dest='from_name',
    default='Keeper Commander',
    help='From display name (default: Keeper Commander)'
)
email_config_create_parser.add_argument(
    '--folder',
    help='Folder path or UID where email config record will be stored'
)

# SMTP options
smtp_group = email_config_create_parser.add_argument_group('SMTP Options')
smtp_group.add_argument('--smtp-host', help='SMTP server hostname')
smtp_group.add_argument('--smtp-port', type=int, default=587, help='SMTP port (default: 587)')
smtp_group.add_argument('--smtp-username', help='SMTP username')
smtp_group.add_argument('--smtp-password', help='SMTP password')
tls_group = smtp_group.add_mutually_exclusive_group()
tls_group.add_argument('--smtp-use-tls', dest='smtp_use_tls', action='store_true', default=None,
                       help='Use TLS (STARTTLS on port 587)')
tls_group.add_argument('--smtp-no-tls', dest='smtp_use_tls', action='store_false',
                       help='Disable TLS (for testing/local servers)')
smtp_group.add_argument('--smtp-use-ssl', dest='smtp_use_ssl', action='store_true',
                       help='Use SSL (port 465)')

# AWS SES options
ses_group = email_config_create_parser.add_argument_group('AWS SES Options')
ses_group.add_argument('--aws-region', help='AWS region (e.g., us-east-1)')
ses_group.add_argument('--aws-access-key', help='AWS access key ID')
ses_group.add_argument('--aws-secret-key', help='AWS secret access key')

# SendGrid options
sendgrid_group = email_config_create_parser.add_argument_group('SendGrid Options')
sendgrid_group.add_argument('--sendgrid-api-key', help='SendGrid API key')

# OAuth options (Gmail and Microsoft)
oauth_group = email_config_create_parser.add_argument_group('OAuth Options (gmail-oauth, microsoft-oauth)')
oauth_group.add_argument('--oauth-client-id', help='OAuth client ID')
oauth_group.add_argument('--oauth-client-secret', help='OAuth client secret')
oauth_group.add_argument('--oauth-tenant-id', help='Microsoft tenant ID (use "common" for multi-tenant, or specific tenant ID)')
oauth_group.add_argument('--oauth-access-token', help='OAuth access token (for manual token entry)')
oauth_group.add_argument('--oauth-refresh-token', help='OAuth refresh token (for manual token entry)')
oauth_group.add_argument('--oauth-token-expiry', help='OAuth token expiry in ISO 8601 format (for manual token entry)')
oauth_group.add_argument('--oauth-port', type=int, default=8080, help='Port for OAuth callback server (default: 8080)')

# email-config list
email_config_list_parser = argparse.ArgumentParser(
    prog='email-config list',
    description='List all email configurations'
)
email_config_list_parser.add_argument(
    '--format',
    dest='format',
    action='store',
    choices=['table', 'json', 'csv'],
    default='table',
    help='Output format (default: table)'
)

# email-config test
email_config_test_parser = argparse.ArgumentParser(
    prog='email-config test',
    description='Test email configuration connection'
)
email_config_test_parser.add_argument(
    'name',
    help='Name of email configuration to test'
)
email_config_test_parser.add_argument(
    '--to',
    help='Send test email to this address'
)

# email-config delete
email_config_delete_parser = argparse.ArgumentParser(
    prog='email-config delete',
    description='Delete an email configuration'
)
email_config_delete_parser.add_argument(
    'name',
    help='Name of email configuration to delete'
)
email_config_delete_parser.add_argument(
    '-f', '--force',
    action='store_true',
    help='Do not prompt for confirmation'
)


# =============================================================================
# Helper Functions
# =============================================================================

def find_email_config_record(params: KeeperParams, name: str) -> Optional[str]:
    """
    Find email config record by name.

    Args:
        params: KeeperParams session
        name: Name of email configuration

    Returns:
        Record UID if found, None otherwise
    """
    for record_uid in params.record_cache:
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            continue
        if record.record_type != 'login':
            continue

        # Check if this is an email config by looking for custom field
        try:
            record_dict = vault_extensions.extract_typed_record_data(record)
            custom_fields = record_dict.get('custom', [])
            for field in custom_fields:
                if field.get('type') == 'text' and field.get('label') == '__email_config__':
                    if record.title == name:
                        return record_uid
        except:
            continue

    return None


def load_email_config_from_record(params: KeeperParams, record_uid: str) -> EmailConfig:
    """
    Load EmailConfig from a Keeper record.

    Args:
        params: KeeperParams session
        record_uid: Record UID

    Returns:
        EmailConfig object

    Raises:
        CommandError: If record not found or invalid
    """
    if record_uid not in params.record_cache:
        raise CommandError('email-config', f'Record {record_uid} not found')

    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord):
        raise CommandError('email-config', f'Record {record_uid} is not a typed record')

    # Extract record data
    record_dict = vault_extensions.extract_typed_record_data(record)

    # Get login/password fields
    fields = record_dict.get('fields', [])
    login = None
    password = None

    for field in fields:
        if field.get('type') == 'login':
            values = field.get('value', [])
            if values:
                login = values[0]
        elif field.get('type') == 'password':
            values = field.get('value', [])
            if values:
                password = values[0]

    # Get custom fields with provider configuration
    custom_fields = record_dict.get('custom', [])
    provider_data = {}

    for field in custom_fields:
        label = field.get('label', '')
        if label.startswith('__email_'):
            continue  # Skip marker fields

        values = field.get('value', [])
        if values:
            provider_data[label] = values[0]

    # Build EmailConfig
    provider = provider_data.get('provider', 'smtp')

    config = EmailConfig(
        record_uid=record_uid,
        name=record.title,
        provider=provider,
        from_address=provider_data.get('from_address', ''),
        from_name=provider_data.get('from_name', 'Keeper Commander')
    )

    # Provider-specific fields
    if provider == 'smtp':
        config.smtp_host = provider_data.get('smtp_host')
        config.smtp_port = int(provider_data.get('smtp_port', 587))
        config.smtp_username = login or provider_data.get('smtp_username')
        config.smtp_password = password or provider_data.get('smtp_password')
        config.smtp_use_tls = provider_data.get('smtp_use_tls', 'true').lower() == 'true'
        config.smtp_use_ssl = provider_data.get('smtp_use_ssl', 'false').lower() == 'true'

    elif provider == 'ses':
        config.aws_region = provider_data.get('aws_region')
        config.aws_access_key = login or provider_data.get('aws_access_key')
        config.aws_secret_key = password or provider_data.get('aws_secret_key')

    elif provider == 'sendgrid':
        config.sendgrid_api_key = password or provider_data.get('sendgrid_api_key')

    elif provider in ('gmail-oauth', 'microsoft-oauth'):
        # OAuth tokens stored in login/password fields
        config.oauth_access_token = login
        config.oauth_refresh_token = password

        # OAuth configuration from custom fields
        config.oauth_client_id = provider_data.get('oauth_client_id')
        config.oauth_client_secret = provider_data.get('oauth_client_secret')
        config.oauth_token_expiry = provider_data.get('oauth_token_expiry')

        if provider == 'microsoft-oauth':
            config.oauth_tenant_id = provider_data.get('oauth_tenant_id', 'common')

    return config


def create_email_config_record(params: KeeperParams, config: EmailConfig, folder_uid: Optional[str] = None) -> str:
    """
    Create a Keeper record to store email configuration.

    Uses login record type with custom fields to store provider configuration.

    Args:
        params: KeeperParams session
        config: EmailConfig to store
        folder_uid: Optional folder UID

    Returns:
        Record UID of created record
    """
    # Create typed record
    record_uid = utils.generate_uid()
    record_key = utils.generate_aes_key()

    # Build record data
    fields = []
    custom_fields = []

    # Add marker field to identify this as an email config
    custom_fields.append({
        'type': 'text',
        'label': '__email_config__',
        'value': ['true']
    })

    # Provider-specific fields
    custom_fields.append({'type': 'text', 'label': 'provider', 'value': [config.provider]})
    custom_fields.append({'type': 'text', 'label': 'from_address', 'value': [config.from_address]})
    custom_fields.append({'type': 'text', 'label': 'from_name', 'value': [config.from_name]})

    if config.provider == 'smtp':
        # Use login/password fields for SMTP credentials
        fields.append({'type': 'login', 'value': [config.smtp_username or '']})
        fields.append({'type': 'password', 'value': [config.smtp_password or '']})

        # Additional SMTP config in custom fields
        custom_fields.append({'type': 'text', 'label': 'smtp_host', 'value': [config.smtp_host or '']})
        custom_fields.append({'type': 'text', 'label': 'smtp_port', 'value': [str(config.smtp_port)]})
        custom_fields.append({'type': 'text', 'label': 'smtp_use_tls', 'value': [str(config.smtp_use_tls).lower()]})
        custom_fields.append({'type': 'text', 'label': 'smtp_use_ssl', 'value': [str(config.smtp_use_ssl).lower()]})

    elif config.provider == 'ses':
        # Use login/password for AWS credentials
        fields.append({'type': 'login', 'value': [config.aws_access_key or '']})
        fields.append({'type': 'password', 'value': [config.aws_secret_key or '']})

        custom_fields.append({'type': 'text', 'label': 'aws_region', 'value': [config.aws_region or '']})

    elif config.provider == 'sendgrid':
        # Use password field for API key
        fields.append({'type': 'password', 'value': [config.sendgrid_api_key or '']})

    elif config.provider in ('gmail-oauth', 'microsoft-oauth'):
        # Store OAuth tokens in password fields (encrypted)
        fields.append({'type': 'login', 'value': [config.oauth_access_token or '']})
        fields.append({'type': 'password', 'value': [config.oauth_refresh_token or '']})

        # OAuth configuration in custom fields
        custom_fields.append({'type': 'text', 'label': 'oauth_client_id', 'value': [config.oauth_client_id or '']})
        custom_fields.append({'type': 'text', 'label': 'oauth_client_secret', 'value': [config.oauth_client_secret or '']})

        if config.oauth_token_expiry:
            custom_fields.append({'type': 'text', 'label': 'oauth_token_expiry', 'value': [config.oauth_token_expiry]})

        if config.provider == 'microsoft-oauth' and config.oauth_tenant_id:
            custom_fields.append({'type': 'text', 'label': 'oauth_tenant_id', 'value': [config.oauth_tenant_id]})

    # Build record JSON
    record_data = {
        'title': config.name,
        'type': 'login',
        'fields': fields,
        'custom': custom_fields
    }

    # Create TypedRecord
    record = vault.TypedRecord()
    record.record_uid = record_uid
    record.record_key = record_key

    # Load record data (this populates type_name, title, fields, custom)
    record.load_record_data(record_data)

    # Add to vault
    record_management.add_record_to_folder(params, record, folder_uid)

    logging.info(f'[EMAIL-CONFIG] Created email configuration record: {config.name} ({record_uid})')

    return record_uid


def update_oauth_tokens_in_record(params: KeeperParams, record_uid: str,
                                   access_token: str, refresh_token: str,
                                   token_expiry: str) -> None:
    """
    Update OAuth tokens in email config record after automatic refresh.

    This function is called by OAuth email providers (GmailOAuthProvider,
    MicrosoftOAuthProvider) after they automatically refresh expired tokens.
    It updates the Keeper record to persist the new tokens.

    Args:
        params: Keeper session parameters
        record_uid: UID of the email config record to update
        access_token: New OAuth access token
        refresh_token: New OAuth refresh token (may be same as old)
        token_expiry: New token expiry in ISO 8601 format

    Raises:
        CommandError: If record not found or update fails
    """
    # Load the record
    if record_uid not in params.record_cache:
        params.sync_data = True
        api.sync_down(params)

    if record_uid not in params.record_cache:
        raise CommandError('email-config', f'Email configuration record not found: {record_uid}')

    # Load as TypedRecord
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord):
        raise CommandError('email-config', f'Record is not a TypedRecord: {record_uid}')

    # Update token fields (login = access_token, password = refresh_token)
    for field in record.fields:
        if field.type == 'login':
            field.value = [access_token]
        elif field.type == 'password':
            field.value = [refresh_token]

    # Update token expiry in custom fields
    expiry_field_found = False
    for field in record.custom:
        if field.label == 'oauth_token_expiry':
            field.value = [token_expiry]
            expiry_field_found = True
            break

    # Add expiry field if it doesn't exist
    if not expiry_field_found:
        record.custom.append(vault.TypedField.new_field('text', token_expiry, 'oauth_token_expiry'))

    # Update the record
    record_management.update_record(params, record)

    # Sync changes
    params.sync_data = True
    api.sync_down(params)

    logging.debug(f'[EMAIL-CONFIG] Updated OAuth tokens for record: {record_uid}')


# =============================================================================
# Command Classes
# =============================================================================

class EmailConfigCreateCommand(Command):
    """Create a new email configuration."""

    def get_parser(self):
        return email_config_create_parser

    def execute(self, params: KeeperParams, **kwargs):
        """Execute email-config create command."""
        name = kwargs.get('name')
        provider = kwargs.get('provider')

        # Check if config with this name already exists
        existing_uid = find_email_config_record(params, name)
        if existing_uid:
            raise CommandError('email-config', f'Email configuration "{name}" already exists')

        # Check provider compatibility and warn if dependencies unavailable
        dependencies_available, warning_message = check_provider_dependencies(provider)
        if not dependencies_available:
            installation_method = get_installation_method()
            print(f"\n[WARNING] {warning_message}")
            if provider in ('gmail-oauth', 'microsoft-oauth') and installation_method == 'binary':
                print("[WARNING] OAuth interactive flow is not available on binary installation.")
                print("[WARNING] You must provide tokens manually using --oauth-access-token, --oauth-refresh-token, and --oauth-token-expiry.")
            print("[WARNING] Configuration will be created but cannot be used until dependencies are available.\n")

        # Build EmailConfig from arguments
        config = EmailConfig(
            record_uid='',  # Will be generated
            name=name,
            provider=provider,
            from_address=kwargs.get('from_address'),
            from_name=kwargs.get('from_name', 'Keeper Commander')
        )

        # Provider-specific configuration
        if provider == 'smtp':
            config.smtp_host = kwargs.get('smtp_host')
            config.smtp_port = kwargs.get('smtp_port', 587)
            config.smtp_username = kwargs.get('smtp_username')
            config.smtp_password = kwargs.get('smtp_password')
            config.smtp_use_tls = kwargs.get('smtp_use_tls', True)
            config.smtp_use_ssl = kwargs.get('smtp_use_ssl', False)

        elif provider == 'ses':
            config.aws_region = kwargs.get('aws_region')
            config.aws_access_key = kwargs.get('aws_access_key')
            config.aws_secret_key = kwargs.get('aws_secret_key')

        elif provider == 'sendgrid':
            config.sendgrid_api_key = kwargs.get('sendgrid_api_key')

        elif provider in ('gmail-oauth', 'microsoft-oauth'):
            config.oauth_client_id = kwargs.get('oauth_client_id')
            config.oauth_client_secret = kwargs.get('oauth_client_secret')

            # Microsoft requires tenant ID
            if provider == 'microsoft-oauth':
                config.oauth_tenant_id = kwargs.get('oauth_tenant_id', 'common')

            # Check if manual tokens provided
            if kwargs.get('oauth_access_token'):
                # Manual token entry
                config.oauth_access_token = kwargs.get('oauth_access_token')
                config.oauth_refresh_token = kwargs.get('oauth_refresh_token')
                config.oauth_token_expiry = kwargs.get('oauth_token_expiry')
                logging.info(f'[EMAIL-CONFIG] Using manually provided OAuth tokens')
            else:
                # Interactive OAuth flow
                # Block OAuth flow on binary installation
                installation_method = get_installation_method()
                if installation_method == 'binary':
                    raise CommandError(
                        'email-config',
                        f'Interactive OAuth flow is not available on binary installation.\n'
                        f'\n'
                        f'To use OAuth providers, you must switch to the PyPI version:\n'
                        f'  1. Uninstall the binary version\n'
                        f'  2. Install via pip with email dependencies:\n'
                        f'     pip install keepercommander[email]\n'
                        f'\n'
                        f'Alternatively, if you must use the binary, provide OAuth tokens manually:\n'
                        f'  --oauth-access-token <token>\n'
                        f'  --oauth-refresh-token <token>\n'
                        f'  --oauth-token-expiry <ISO-8601-datetime>'
                    )

                from ..oauth_helpers import GoogleOAuthFlow, MicrosoftOAuthFlow, perform_interactive_oauth

                logging.info(f'[EMAIL-CONFIG] Starting interactive OAuth flow for {provider}')
                print(f"\n[EMAIL-CONFIG] Authenticating with {provider}...")
                print(f"[EMAIL-CONFIG] You'll need to authorize in your browser.\n")

                # Create OAuth flow handler
                if provider == 'gmail-oauth':
                    flow = GoogleOAuthFlow(
                        client_id=config.oauth_client_id,
                        client_secret=config.oauth_client_secret
                    )
                else:  # microsoft-oauth
                    flow = MicrosoftOAuthFlow(
                        client_id=config.oauth_client_id,
                        client_secret=config.oauth_client_secret,
                        tenant_id=config.oauth_tenant_id
                    )

                # Perform interactive OAuth
                try:
                    port = kwargs.get('oauth_port', 8080)
                    tokens = perform_interactive_oauth(flow, port=port)

                    config.oauth_access_token = tokens['access_token']
                    config.oauth_refresh_token = tokens['refresh_token']
                    config.oauth_token_expiry = tokens['expiry']

                    logging.info(f'[EMAIL-CONFIG] OAuth authentication successful')
                except Exception as e:
                    raise CommandError('email-config', f'OAuth authentication failed: {e}')

        # Validate configuration
        errors = config.validate()
        if errors:
            raise CommandError('email-config', f'Invalid configuration: {", ".join(errors)}')

        # Resolve folder
        folder_uid = None
        folder_name = kwargs.get('folder')
        if folder_name:
            if folder_name in params.folder_cache:
                folder_uid = folder_name
            else:
                # Try to resolve folder path
                from ..subfolder import try_resolve_path
                rs = try_resolve_path(params, folder_name)
                if rs is not None:
                    folder, _ = rs
                    folder_uid = folder.uid
                else:
                    raise CommandError('email-config', f'Folder "{folder_name}" not found')

        # Create record
        record_uid = create_email_config_record(params, config, folder_uid)

        # Sync with server
        api.sync_down(params)

        logging.info(f'Email configuration "{name}" created successfully (UID: {record_uid})')
        return f'Email configuration "{name}" created successfully'


class EmailConfigListCommand(Command):
    """List all email configurations."""

    def get_parser(self):
        return email_config_list_parser

    def execute(self, params: KeeperParams, **kwargs):
        """Execute email-config list command."""
        configs = []

        # Find all email config records
        for record_uid in params.record_cache:
            try:
                record = vault.KeeperRecord.load(params, record_uid)
                if not isinstance(record, vault.TypedRecord):
                    continue
                if record.record_type != 'login':
                    continue

                # Check if this is an email config
                record_dict = vault_extensions.extract_typed_record_data(record)
                custom_fields = record_dict.get('custom', [])

                is_email_config = False
                provider = None
                from_address = None

                for field in custom_fields:
                    if field.get('label') == '__email_config__':
                        is_email_config = True
                    elif field.get('label') == 'provider':
                        values = field.get('value', [])
                        if values:
                            provider = values[0]
                    elif field.get('label') == 'from_address':
                        values = field.get('value', [])
                        if values:
                            from_address = values[0]

                if is_email_config:
                    configs.append({
                        'name': record.title,
                        'record_uid': record_uid,
                        'provider': provider or 'unknown',
                        'from_address': from_address or ''
                    })
            except Exception as e:
                logging.debug(f'Error loading record {record_uid}: {e}')
                continue

        if not configs:
            logging.info('No email configurations found')
            return

        # Display results
        output_format = kwargs.get('format', 'table')

        if output_format == 'json':
            print(json.dumps(configs, indent=2))
        else:
            headers = ['Name', 'Provider', 'From Address', 'Record UID']
            table = [
                [c['name'], c['provider'], c['from_address'], c['record_uid']]
                for c in configs
            ]
            dump_report_data(table, headers, fmt=output_format)


class EmailConfigTestCommand(Command):
    """Test email configuration connection."""

    def get_parser(self):
        return email_config_test_parser

    def execute(self, params: KeeperParams, **kwargs):
        """Execute email-config test command."""
        name = kwargs.get('name')
        to_address = kwargs.get('to')

        # Find config
        record_uid = find_email_config_record(params, name)
        if not record_uid:
            raise CommandError('email-config', f'Email configuration "{name}" not found')

        # Load config
        config = load_email_config_from_record(params, record_uid)

        # Check provider dependencies before testing
        dependencies_available, error_message = check_provider_dependencies(config.provider)
        if not dependencies_available:
            raise CommandError('email-config', error_message)

        # Create sender
        try:
            sender = EmailSender(config)
        except Exception as e:
            raise CommandError('email-config', f'Failed to initialize email sender: {e}')

        # Test connection
        logging.info(f'Testing connection for "{name}" ({config.provider})...')

        try:
            success = sender.test_connection()
            if success:
                logging.info(f'✓ Connection test successful for "{name}"')

                # Send test email if address provided
                if to_address:
                    logging.info(f'Sending test email to {to_address}...')
                    subject = 'Keeper Commander Email Test'
                    body = f'This is a test email from Keeper Commander.\n\nEmail Configuration: {name}\nProvider: {config.provider}'

                    sender.send(to_address, subject, body, html=False)
                    logging.info(f'✓ Test email sent successfully to {to_address}')

                # Persist OAuth tokens if they were refreshed
                if config.is_oauth_provider() and config._oauth_tokens_updated:
                    logging.debug(f'[EMAIL-CONFIG] Persisting refreshed OAuth tokens for "{name}"')
                    update_oauth_tokens_in_record(
                        params,
                        record_uid,
                        config.oauth_access_token,
                        config.oauth_refresh_token,
                        config.oauth_token_expiry
                    )

                if to_address:
                    return f'Connection test passed. Test email sent to {to_address}'
                else:
                    return f'Connection test passed for "{name}"'
            else:
                raise CommandError('email-config', f'Connection test failed for "{name}"')
        except Exception as e:
            raise CommandError('email-config', f'Connection test failed: {e}')


class EmailConfigDeleteCommand(Command):
    """Delete an email configuration."""

    def get_parser(self):
        return email_config_delete_parser

    def execute(self, params: KeeperParams, **kwargs):
        """Execute email-config delete command."""
        name = kwargs.get('name')
        force = kwargs.get('force', False)

        # Find config
        record_uid = find_email_config_record(params, name)
        if not record_uid:
            raise CommandError('email-config', f'Email configuration "{name}" not found')

        # Confirm deletion
        if not force:
            from ..commands.base import user_choice
            answer = user_choice(f'Delete email configuration "{name}"?', 'yn', 'n')
            if answer.lower() != 'y':
                logging.info('Delete cancelled')
                return

        # Delete record
        from .record import RecordRemoveCommand
        remove_cmd = RecordRemoveCommand()
        remove_cmd.execute(params, record=record_uid, force=True)

        # Sync cache to reflect deletion
        from .. import api
        api.sync_down(params)

        logging.info(f'Email configuration "{name}" deleted successfully')
        return f'Email configuration "{name}" deleted'


class EmailConfigCommand(GroupCommand):
    """Email configuration management commands."""

    def __init__(self):
        super(EmailConfigCommand, self).__init__()
        self.register_command('create', EmailConfigCreateCommand(),
                            'Create a new email configuration')
        self.register_command('list', EmailConfigListCommand(),
                            'List all email configurations')
        self.register_command('test', EmailConfigTestCommand(),
                            'Test email configuration connection')
        self.register_command('delete', EmailConfigDeleteCommand(),
                            'Delete an email configuration')
        self.default_verb = 'list'
