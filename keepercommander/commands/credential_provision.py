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
Automated Credential Provisioning Command (KC-1007)

Automates employee credential provisioning by creating PAM User records with
password rotation, generating share URLs, and delivering credentials via email.

This command integrates with external HR systems (Aquera, Workday, etc.) to
streamline onboarding workflows.

Usage:
    keeper credential-provision --config employee.yaml
    keeper credential-provision --config employee.yaml --dry-run
    keeper credential-provision --config employee.yaml --output json

    # For API/Service Mode usage (base64-encoded YAML):
    keeper credential-provision --config-base64 <base64-encoded-yaml>
    keeper credential-provision --config-base64 <base64-encoded-yaml> --dry-run
"""

import argparse
import base64
import json
import logging
import os
import re
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlunparse, urlparse

try:
    import yaml
except ImportError:
    yaml = None

from keepercommander.commands.base import Command, suppress_exit, raise_parse_exception
from .. import api, vault, vault_extensions, crypto, utils, generator
from ..error import CommandError
from ..params import KeeperParams
from ..subfolder import try_resolve_path, get_folder_path
from ..record_management import add_record_to_folder
from ..record_facades import LoginRecordFacade
from ..proto import APIRequest_pb2
from ..commands.folder import FolderMakeCommand

# RecordLink and discoveryrotation require pydantic (Python 3.8+)
try:
    from ..discovery_common.record_link import RecordLink
    from ..commands.discoveryrotation import (
        PAMCreateRecordRotationCommand,
        PAMGatewayActionRotateCommand,
        validate_cron_expression
    )
except ImportError:
    RecordLink = None  # Will be None on Python 3.7
    PAMCreateRecordRotationCommand = None
    PAMGatewayActionRotateCommand = None
    validate_cron_expression = None
from ..commands.helpers.timeout import parse_timeout, format_timeout
from ..commands import email_commands
from ..email_service import EmailSender, build_onboarding_email
from keepercommander.commands.pam.user_facade import PamUserRecordFacade
from keepercommander.commands.pam.config_facades import PamConfigurationRecordFacade

# =============================================================================
# Argument Parser
# =============================================================================

credential_provision_parser = argparse.ArgumentParser(
    prog='credential-provision',
    description='Automate PAM User credential provisioning with password rotation '
                'and email delivery'
)

# Config input: file path OR base64-encoded content (mutually exclusive)
config_group = credential_provision_parser.add_mutually_exclusive_group(required=True)

config_group.add_argument(
    '--config',
    dest='config',
    help='Path to YAML configuration file'
)

config_group.add_argument(
    '--config-base64',
    dest='config_base64',
    help='Base64-encoded YAML configuration content (for API/Service Mode usage)'
)

credential_provision_parser.add_argument(
    '--dry-run',
    dest='dry_run',
    action='store_true',
    help='Validate configuration and preview actions without making changes'
)

credential_provision_parser.add_argument(
    '--output',
    dest='output',
    choices=['text', 'json'],
    default='text',
    help='Output format: text (human-readable) or json (machine-readable)'
)

credential_provision_parser.error = raise_parse_exception
credential_provision_parser.exit = suppress_exit

# =============================================================================
# Registration Functions
# =============================================================================

def register_commands(commands):
    commands['credential-provision'] = CredentialProvisionCommand()

def register_command_info(aliases, command_info):
    aliases['cp'] = 'credential-provision'
    command_info['credential-provision'] = 'Automate PAM User credential provisioning'

# =============================================================================
# Main Command Class
# =============================================================================

class ProvisioningState:
    """Track provisioning state for rollback on critical failure."""

    def __init__(self):
        self.pam_user_uid = None
        self.dag_link_created = False
        self.folder_created = None

class CredentialProvisionCommand(Command):
    """
    Automated Credential Provisioning Command

    This command orchestrates the following operations:
    1. Parse and validate YAML configuration
    2. Check for duplicate PAM Users
    3. Generate secure password
    4. Create PAM User record with rotation configured
    5. Submit immediate password rotation
    6. Generate one-time share URL for PAM User
    7. Send welcome email with credentials
    """

    def get_parser(self):
        return credential_provision_parser

    def execute(self, params: KeeperParams, **kwargs):
        """
        Execute credential provisioning workflow.

        Args:
            params: KeeperParams session
            **kwargs: Command arguments (config, dry_run, output)

        Returns:
            None (outputs to stdout)

        Raises:
            CommandError: On validation or execution failure
        """
        # Check for yaml dependency
        if yaml is None:
            raise CommandError(
                'credential-provision',
                'PyYAML is required for this command.\n'
                'Install with: pip install pyyaml'
            )

        config_path = kwargs.get('config')
        config_base64 = kwargs.get('config_base64')
        dry_run = kwargs.get('dry_run', False)
        output_format = kwargs.get('output', 'text')

        try:
            # Load and validate YAML configuration from file path or base64 content
            if config_path:
                if output_format == 'text':
                    logging.info(f'Loading configuration from: {config_path}')
                config = self._load_yaml(config_path)
            elif config_base64:
                if output_format == 'text':
                    logging.info('Loading configuration from base64-encoded content')
                config = self._load_yaml_base64(config_base64)
            else:
                # This shouldn't happen due to argparse required=True, but be defensive
                raise CommandError(
                    'credential-provision',
                    'Either --config or --config-base64 is required'
                )
            validation_errors = self._validate_config(params, config)

            if validation_errors:
                error_msg = 'Configuration validation failed:\n\n' + '\n'.join(
                    f'  • {err}' for err in validation_errors
                )
                if output_format == 'json':
                    result = {
                        'success': False,
                        'error': 'Validation failed',
                        'validation_errors': validation_errors
                    }
                    print(json.dumps(result, indent=2))
                else:
                    logging.error(error_msg)
                raise CommandError('credential-provision', error_msg)

            # System-specific field validation
            pam_config_uid = config['account']['pam_config_uid']

            # Load PAM Config record properly (not from raw cache)
            try:
                pam_config_record = vault.KeeperRecord.load(params, pam_config_uid)
            except Exception as e:
                error_msg = f'Failed to load PAM Configuration: {pam_config_uid}'
                if output_format == 'json':
                    result = {'success': False, 'error': error_msg, 'details': str(e)}
                    print(json.dumps(result, indent=2))
                else:
                    logging.error(error_msg)
                    logging.error(f'Error: {e}')
                    logging.error('Make sure you have access to this PAM Configuration')
                raise CommandError('credential-provision', error_msg)

            if not pam_config_record:
                error_msg = f'PAM Configuration not found in vault: {pam_config_uid}'
                if output_format == 'json':
                    result = {'success': False, 'error': error_msg}
                    print(json.dumps(result, indent=2))
                else:
                    logging.error(error_msg)
                    logging.error('Make sure you have access to this PAM Configuration')
                raise CommandError('credential-provision', error_msg)

            # Validate system-specific fields based on PAM type
            system_errors = self._validate_system_specific_fields(config, pam_config_record, params)

            if system_errors:
                error_msg = 'System-specific validation failed:\n\n' + '\n'.join(
                    f'  • {err}' for err in system_errors
                )
                if output_format == 'json':
                    result = {
                        'success': False,
                        'error': 'System-specific validation failed',
                        'validation_errors': system_errors
                    }
                    print(json.dumps(result, indent=2))
                else:
                    logging.error(error_msg)
                raise CommandError('credential-provision', error_msg)

            if output_format == 'text':
                logging.info('✅ Configuration validated')

            # Dry-run mode (validation only)
            if dry_run:
                self._dry_run_report(params, config, output_format)
                return

            # Execute provisioning
            state = ProvisioningState()

            try:
                # Check for duplicates
                if self._check_duplicate(config, params):
                    error_msg = f'Duplicate PAM User already exists for username: {config["account"]["username"]}'
                    if output_format == 'json':
                        result = {'success': False, 'error': error_msg}
                        print(json.dumps(result, indent=2))
                    else:
                        logging.error(error_msg)
                    raise CommandError('credential-provision', error_msg)

                # Generate password and create PAM User
                password = self._generate_password(config['pam']['rotation']['password_complexity'])
                pam_user_uid = self._create_pam_user(config, password, params)
                state.pam_user_uid = pam_user_uid

                # Link to PAM Configuration and configure rotation
                self._create_dag_link(pam_user_uid, config['account']['pam_config_uid'], params)
                state.dag_link_created = True
                self._configure_rotation(pam_user_uid, config, params)

                if output_format == 'text':
                    logging.info('✅ PAM User created and linked')

                # Perform immediate rotation if configured
                rotation_success = self._rotate_immediately(pam_user_uid, config, params)

                if output_format == 'text':
                    logging.info('✅ Password rotation submitted')

                # Generate share URL for PAM User (shares source of truth, not a copy)
                share_url = self._generate_share_url(pam_user_uid, config, params)

                if output_format == 'text':
                    logging.info('✅ Share URL generated for PAM User')

                # Send welcome email
                email_success = self._send_email(config, share_url, params)

                if output_format == 'text':
                    logging.info('✅ Email with one-time share sent')
                else:
                    result = {
                        'success': True,
                        'pam_user_uid': pam_user_uid,
                        'share_url': share_url,
                        'username': config['account']['username'],
                        'employee_name': f"{config['user']['first_name']} {config['user']['last_name']}",
                        'rotation_status': 'synced' if rotation_success else 'scheduled',
                        'email_status': 'sent' if email_success else 'failed',
                        'message': 'Credential provisioning complete'
                    }
                    print(json.dumps(result, indent=2))

            except CommandError as e:
                self._rollback(state, params)
                raise
            except Exception as e:
                logging.error(f'\n❌ UNEXPECTED FAILURE: {str(e)}')
                logging.error(f'Provisioning failed: {str(e)}')
                self._rollback(state, params)
                if output_format == 'json':
                    result = {'success': False, 'error': str(e)}
                    print(json.dumps(result, indent=2))
                raise CommandError('credential-provision', f'Provisioning failed: {str(e)}')

        except CommandError:
            raise
        except Exception as e:
            logging.error(f'Unexpected error: {str(e)}')
            if output_format == 'json':
                result = {
                    'success': False,
                    'error': str(e)
                }
                print(json.dumps(result, indent=2))
            raise CommandError('credential-provision', str(e))

    # =========================================================================
    # YAML Loading
    # =========================================================================

    def _load_yaml(self, file_path: str) -> Dict[str, Any]:
        """
        Load and parse YAML configuration file.

        Args:
            file_path: Path to YAML file

        Returns:
            Parsed configuration dictionary

        Raises:
            CommandError: If file not found or YAML syntax invalid
        """
        if not os.path.exists(file_path):
            raise CommandError(
                'credential-provision',
                f'Configuration file not found: {file_path}'
            )

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if not isinstance(config, dict):
                raise CommandError(
                    'credential-provision',
                    f'Invalid YAML: Root element must be a dictionary/object'
                )

            return config

        except yaml.YAMLError as e:
            raise CommandError(
                'credential-provision',
                f'YAML syntax error in {file_path}:\n{str(e)}'
            )
        except Exception as e:
            raise CommandError(
                'credential-provision',
                f'Error reading {file_path}: {str(e)}'
            )

    def _load_yaml_base64(self, base64_content: str) -> Dict[str, Any]:
        """
        Load and parse YAML configuration from base64-encoded string.

        Supports standard RFC 4648 base64 encoding. The input should be the base64
        representation of a UTF-8 encoded YAML string.

        This method enables Service Mode API integration where file paths are not
        accessible between the API caller and the Commander server.

        Args:
            base64_content: Base64-encoded YAML configuration string

        Returns:
            Parsed configuration dictionary

        Raises:
            CommandError: If base64 invalid, UTF-8 decoding fails, or YAML syntax error

        Example:
            # Encode YAML file to base64:
            # base64 < employee.yaml

            # Use in command:
            # credential-provision --config-base64 dXNlcjoKICBmaXJzdF9uYW1lOi...
        """
        # Step 1: Decode base64
        try:
            yaml_bytes = base64.b64decode(base64_content, validate=True)
        except Exception as e:
            raise CommandError(
                'credential-provision',
                f'Invalid base64 encoding: {str(e)}'
            )

        # Step 2: Decode UTF-8
        try:
            yaml_string = yaml_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise CommandError(
                'credential-provision',
                f'Invalid UTF-8 encoding in decoded content: {str(e)}'
            )

        # Step 3: Parse YAML
        try:
            config = yaml.safe_load(yaml_string)

            if not isinstance(config, dict):
                raise CommandError(
                    'credential-provision',
                    'Invalid YAML: Root element must be a dictionary/object'
                )

            return config

        except yaml.YAMLError as e:
            raise CommandError(
                'credential-provision',
                f'YAML syntax error in decoded content:\n{str(e)}'
            )

    # =========================================================================
    # Validation Framework
    # =========================================================================

    def _validate_config(self, params: KeeperParams, config: Dict[str, Any]) -> List[str]:
        """
        Comprehensive configuration validation.

        Collects all validation errors rather than failing fast, providing
        better user experience by showing all issues at once.

        Args:
            params: KeeperParams session
            config: Parsed YAML configuration

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Validate required top-level sections
        required_sections = ['user', 'account', 'pam', 'email']
        for section in required_sections:
            if section not in config:
                errors.append(f'Missing required section: {section}')

        # If critical sections missing, return early (can't validate further)
        if errors:
            return errors

        # Validate each section
        errors.extend(self._validate_user_section(config.get('user', {})))
        errors.extend(self._validate_account_section(config.get('account', {})))
        errors.extend(self._validate_pam_section(config.get('pam', {})))
        errors.extend(self._validate_email_section(params, config.get('email', {})))

        # Validate optional vault section
        if 'vault' in config:
            errors.extend(self._validate_vault_section(params, config['vault']))

        # Validate optional managed_company section (MSP scenarios)
        if 'managed_company' in config:
            errors.extend(self._validate_mc_context(params, config['managed_company']))

        return errors

    def _validate_user_section(self, user: Dict[str, Any]) -> List[str]:
        """Validate user section (employee information)."""
        errors = []

        # Required fields
        required = ['first_name', 'last_name', 'personal_email']
        for field in required:
            if not user.get(field):
                errors.append(f'user.{field} is required')

        # Validate email format
        personal_email = user.get('personal_email', '')
        if personal_email and not utils.is_email(personal_email):
            errors.append(f'user.personal_email is invalid: {personal_email}')

        # Validate corporate email if provided
        corporate_email = user.get('corporate_email', '')
        if corporate_email and not utils.is_email(corporate_email):
            errors.append(f'user.corporate_email is invalid: {corporate_email}')

        # Validate manager_email if provided
        manager_email = user.get('manager_email', '')
        if manager_email and not utils.is_email(manager_email):
            errors.append(f'user.manager_email is invalid: {manager_email}')

        return errors

    def _validate_account_section(self, account: Dict[str, Any]) -> List[str]:
        """Validate account section (target system credentials)."""
        errors = []

        # Required fields
        if not account.get('username'):
            errors.append('account.username is required')

        if not account.get('pam_config_uid'):
            errors.append('account.pam_config_uid is required')

        # CRITICAL: Reject old 'initial_password' field (security issue)
        # Per blocker resolution, passwords are generated by Commander, not provided in YAML
        if 'initial_password' in account:
            errors.append(
                'account.initial_password is NOT supported (security).\n'
                '    Commander generates secure passwords automatically.\n'
                '    Remove this field from your YAML configuration.'
            )

        return errors

    def _validate_pam_section(self, pam: Dict[str, Any]) -> List[str]:
        """Validate PAM section (rotation configuration)."""
        errors = []

        # Validate rotation subsection
        rotation = pam.get('rotation', {})
        if not rotation:
            errors.append('pam.rotation section is required')
            return errors

        # Required rotation fields
        if not rotation.get('schedule'):
            errors.append('pam.rotation.schedule is required (CRON format)')
        else:
            schedule = rotation['schedule']
            if validate_cron_expression and not validate_cron_expression(schedule, for_rotation=True)[0]:
                errors.append(
                    f'pam.rotation.schedule has invalid CRON format: {schedule}\n'
                    f'    Expected 6 fields: seconds minute hour day month day-of-week\n'
                    f'    Example: "0 0 3 * * ?" (Daily at 3:00:00 AM)'
                )

        if not rotation.get('password_complexity'):
            errors.append('pam.rotation.password_complexity is required')
        else:
            complexity = rotation['password_complexity']
            if not self._is_valid_complexity(complexity):
                errors.append(
                    f'pam.rotation.password_complexity has invalid format: {complexity}\n'
                    f'    Expected: "length,upper,lower,digit,special"\n'
                    f'    Example: "32,5,5,5,5"'
                )

        return errors

    def _validate_email_section(self, params: KeeperParams, email: Dict[str, Any]) -> List[str]:
        """Validate email section and check for email config existence."""
        errors = []

        # Required field
        config_name = email.get('config_name')
        if not config_name:
            errors.append('email.config_name is required')
            return errors

        # Validate send_to - must be a valid email address
        send_to = email.get('send_to')
        if not send_to:
            errors.append('email.send_to is required and must be a valid email address')
        elif not utils.is_email(send_to):
            errors.append(f'email.send_to must be a valid email address: {send_to}')

        # Validate share_url_expiry if provided
        expiry = email.get('share_url_expiry', '7d')
        if expiry and not self._is_valid_expiry(expiry):
            errors.append(
                f'email.share_url_expiry has invalid format: {expiry}\n'
                f'    Expected: <number>d (days), <number>h (hours), or <number>mi (minutes)\n'
                f'    Examples: "7d", "24h", "60mi"\n'
                f'    Note: Use "mi" for minutes, not "m"'
            )

        return errors

    def _validate_vault_section(self, params: KeeperParams, vault_config: Dict[str, Any]) -> List[str]:
        """Validate vault section (folder paths)."""
        errors = []

        folder = vault_config.get('folder')
        if folder:
            # TODO: Check if folder exists (implement in next phase)

            if not isinstance(folder, str) or not folder.strip():
                errors.append('vault.folder must be a non-empty string')

        return errors

    def _validate_mc_context(self, params: KeeperParams, managed_company: str) -> List[str]:
        """Validate managed company context (MSP scenarios)."""
        errors = []

        if not managed_company or not isinstance(managed_company, str):
            errors.append('managed_company must be a non-empty string')

        # TODO: Validate MC exists and is accessible (implement in next phase)

        return errors

    # =========================================================================
    # Validation Helper Functions
    # =========================================================================

    def _is_valid_complexity(self, complexity: str) -> bool:
        """Validate password complexity format: length,upper,lower,digit,special"""
        parts = complexity.split(',')

        if len(parts) != 5:
            return False

        try:
            # All parts must be non-negative integers
            values = [int(p) for p in parts]
            return all(v >= 0 for v in values)
        except ValueError:
            return False

    def _is_valid_expiry(self, expiry: str) -> bool:
        """
        Validate share URL expiry format.

        Valid formats: <number>d (days), <number>h (hours), <number>mi (minutes)
        Examples: 7d, 24h, 60mi

        Note: parse_timeout() uses 'mi' for minutes, not 'm'.
        Valid units: years/y, months/mo, days/d, hours/h, minutes/mi
        """
        pattern = r'^\d+(y|mo|d|h|mi)$'
        return bool(re.match(pattern, expiry))

    # =========================================================================
    # Dry-Run Mode
    # =========================================================================

    @staticmethod
    def _mask_pii(value: str) -> str:
        """
        Fully redact PII for security in dry-run output.

        All PII (names, emails, etc.) are replaced with [REDACTED] to prevent
        exposure in logs, screenshots, or shared output.

        Args:
            value: PII value to redact

        Returns:
            "[REDACTED]" for any non-empty value
        """
        return "[REDACTED]" if value else value

    def _dry_run_report(self, params: KeeperParams, config: Dict[str, Any], output_format: str):
        """
        Generate dry-run report showing what would be created.

        PII (names, emails) are partially masked for security.

        Args:
            params: KeeperParams session
            config: Validated configuration
            output_format: 'text' or 'json'
        """
        user = config.get('user', {})
        account = config.get('account', {})
        pam = config.get('pam', {})
        email_config = config.get('email', {})
        vault_config = config.get('vault', {})

        employee_name = f"{user.get('first_name')} {user.get('last_name')}"
        username = account.get('username')

        # Fully redact PII for dry-run output (security best practice)
        redacted_name = self._mask_pii(employee_name)
        redacted_email = self._mask_pii(user.get('personal_email', ''))
        redacted_username = self._mask_pii(username)

        if output_format == 'json':
            result = {
                'success': True,
                'dry_run': True,
                'employee_name': redacted_name,
                'actions': [
                    'Check for duplicate PAM User',
                    'Generate secure password (complexity requirements applied)',
                    f'Create PAM User: {redacted_username}',
                    f'Link PAM User to PAM Config: {account.get("pam_config_uid")}',
                    f'Configure rotation: {pam.get("rotation", {}).get("schedule")}',
                    'Submit immediate rotation',
                    f'Generate share URL for PAM User (expiry: {email_config.get("share_url_expiry", "7d")})',
                    f'Send email to: {redacted_email}'
                ],
                'configuration': {
                    'employee': redacted_name,
                    'username': redacted_username,
                    'folder': vault_config.get('folder', 'Shared Folders/PAM/{}'.format(user.get('department', 'Unknown'))),
                    'rotation_schedule': pam.get('rotation', {}).get('schedule'),
                    'email_recipient': redacted_email
                }
            }
            print(json.dumps(result, indent=2))
        else:
            print('\n' + '='*60)
            print('DRY RUN MODE - NO CHANGES WILL BE MADE')
            print('='*60)
            print(f'\nEmployee: {redacted_name}')
            print(f'Username: {redacted_username}')
            print(f'Email: {redacted_email}')
            print('\nPlanned Actions:')
            print('  1. Check for duplicate PAM User in folder')
            print(f'  2. Generate secure password')
            print(f'     Complexity: requirements applied')
            print(f'  3. Create PAM User record')
            default_folder = '/Employees/{}'.format(user.get('department', 'Unknown'))
            print(f'     Folder: {vault_config.get("folder", default_folder)}')
            print(f'  4. Link to PAM Config: {account.get("pam_config_uid")[:20]}...')
            print(f'  5. Configure rotation')
            print(f'     Schedule: {pam.get("rotation", {}).get("schedule")}')
            print(f'  6. Submit immediate rotation')
            print(f'  7. Generate one-time share URL for PAM User')
            print(f'     Expiry: {email_config.get("share_url_expiry", "7d")}')
            print(f'  8. Send welcome email')
            print(f'     To: {redacted_email}')
            print(f'     Config: {email_config.get("config_name")}')
            print('\n' + '='*60)
            print('✓ Validation passed - ready for actual provisioning')
            print('  Run without --dry-run to execute')
            print('='*60 + '\n')

    # =========================================================================
    # PAM User Creation & Rotation
    # =========================================================================

    def _check_duplicate(self, config: Dict[str, Any], params: KeeperParams) -> bool:
        """
        Check for duplicate PAM Users using dual-check approach.

        Checks:
        1. If DN provided: Check entire vault for same DN (prevents rotation conflicts)
        2. Always: Check target folder for same username (prevents folder duplicates)

        Args:
            config: Validated configuration
            params: KeeperParams session

        Returns:
            True if duplicate found, False otherwise
        """
        distinguished_name = config['account'].get('distinguished_name')

        # Check 1: Global DN check (if DN provided)
        if distinguished_name:
            if self._check_duplicate_by_dn(distinguished_name, params):
                return True

        # Check 2: Folder-scoped username check (always)
        if self._check_duplicate_by_username_in_folder(config, params):
            return True

        return False

    def _check_duplicate_by_dn(self, distinguished_name: str, params: KeeperParams) -> bool:
        """
        Check for duplicate PAM Users by Distinguished Name (global vault search).

        Active Directory DNs are unique across the entire AD forest. If a PAM User
        already exists with this DN, it's managing the same AD account, which would
        cause rotation conflicts.

        Args:
            distinguished_name: The Distinguished Name to check
            params: KeeperParams session

        Returns:
            True if duplicate DN found, False otherwise
        """
        # Search all PAM User records in vault
        for record_uid in params.record_cache:
            try:
                record = vault.KeeperRecord.load(params, record_uid)

                # Check if it's a PAM User
                if not isinstance(record, vault.TypedRecord):
                    continue
                if record.record_type != 'pamUser':
                    continue

                # Check DN match
                facade = PamUserRecordFacade()
                facade.record = record

                if facade.distinguishedName == distinguished_name:
                    logging.error(f'❌ Duplicate PAM User found (by Distinguished Name):')
                    logging.error(f'   Distinguished Name: {distinguished_name}')
                    logging.error(f'   Existing UID: {record_uid}')
                    logging.error(f'   Title: {record.title}')
                    logging.error(f'   Username: {facade.login}')
                    logging.error(f'')
                    logging.error(f'   This DN is already being managed by another PAM User.')
                    logging.error(f'   Creating a duplicate would cause rotation conflicts.')
                    return True

            except Exception as e:
                continue

        return False

    def _check_duplicate_by_username_in_folder(self, config: Dict[str, Any], params: KeeperParams) -> bool:
        """
        Check for duplicate PAM Users by username in the target folder.

        Prevents creating the same username multiple times in the same folder location.
        This is important for all PAM types (Azure AD, AWS IAM, Active Directory).

        Args:
            config: Validated configuration
            params: KeeperParams session

        Returns:
            True if duplicate username found in folder, False otherwise
        """
        username = config['account']['username']
        pam_config_uid = config['account']['pam_config_uid']

        # Get the same folder path that will be used for PAM User creation
        try:
            gateway_folder_uid, gateway_folder_path = self._get_gateway_application_folder(pam_config_uid, params)
        except Exception as e:
            return False

        # Determine target folder (same logic as _create_pam_user)
        user_specified_folder = config.get('vault', {}).get('folder')

        if user_specified_folder:
            target_folder_path = f"{gateway_folder_path}/{user_specified_folder.strip('/')}"
        else:
            department = config['user'].get('department', 'Default')
            target_folder_path = f"{gateway_folder_path}/PAM Users/{department}"

        # Get folder UID
        folder_uid = self._get_folder_uid(target_folder_path, params)

        if not folder_uid:
            return False

        # Get all records in this folder
        records_in_folder = params.subfolder_record_cache.get(folder_uid, set())

        if not records_in_folder:
            return False

        # Search for PAM Users in folder with matching username
        for record_uid in records_in_folder:
            try:
                record = vault.KeeperRecord.load(params, record_uid)

                # Check if it's a PAM User
                if not isinstance(record, vault.TypedRecord):
                    continue
                if record.record_type != 'pamUser':
                    continue

                # Check username match
                facade = PamUserRecordFacade()
                facade.record = record

                if facade.login == username:
                    logging.error(f'❌ Duplicate PAM User found (by username in folder):')
                    logging.error(f'   Username: {username}')
                    logging.error(f'   Folder: {target_folder_path}')
                    logging.error(f'   Existing UID: {record_uid}')
                    logging.error(f'   Title: {record.title}')
                    return True

            except Exception as e:
                continue

        return False

    def _get_folder_uid(self, folder_path: str, params: KeeperParams) -> Optional[str]:
        """
        Get folder UID by path.

        Args:
            folder_path: Folder path (e.g., "Shared Folders/PAM/Engineering")
            params: KeeperParams session

        Returns:
            Folder UID if found, None otherwise
        """

        try:
            result = try_resolve_path(params, folder_path)
            if result:
                folder_node, remaining_path = result
                if folder_node and not remaining_path:
                    return folder_node.uid
        except Exception:
            pass

        return None

    def _generate_password(self, password_complexity: str) -> str:
        """
        Generate secure random password using Commander's built-in generator.

        This is a critical security feature. Commander generates passwords
        using cryptographic RNG instead of receiving them from external systems.

        NOTE: Password will be set on target account via immediate rotation
        after PAM User creation (using existing rotation infrastructure).

        Args:
            password_complexity: Complexity string (e.g., "32,5,5,5,5")
                Format: "length,upper,lower,digits,special"

        Returns:
            Generated password (will be stored encrypted in vault)

        Raises:
            ValueError: If complexity string is invalid
        """
        # Use Commander's built-in password generator
        kpg = generator.KeeperPasswordGenerator.create_from_rules(password_complexity)
        if not kpg:
            raise ValueError(f'Invalid password complexity format: {password_complexity}')

        return kpg.generate()

    def _create_pam_user(
        self,
        config: Dict[str, Any],
        password: str,
        params: KeeperParams
    ) -> str:
        """
        Create PAM User record.

        Args:
            config: Validated configuration
            password: Generated password
            params: KeeperParams session

        Returns:
            Created PAM User record UID

        Raises:
            CommandError: If PAM User creation fails
        """

        username = config['account']['username']
        pam_config_uid = config['account']['pam_config_uid']

        # Get gateway application folder from PAM Config
        gateway_folder_uid, gateway_folder_path = self._get_gateway_application_folder(pam_config_uid, params)

        # Determine target folder
        user_specified_folder = config.get('vault', {}).get('folder')

        # Validate user-specified folder path
        if user_specified_folder:

            self._validate_folder_path(user_specified_folder)

            # User specified a subfolder (relative to gateway folder)
            # Example: "PAM Users/Engineering"
            target_folder_path = f"{gateway_folder_path}/{user_specified_folder.strip('/')}"
        else:
            # Auto-generate subfolder based on department
            department = config['user'].get('department', 'Default')
            target_folder_path = f"{gateway_folder_path}/PAM Users/{department}"

        # Ensure target folder exists
        folder_uid = self._ensure_folder_exists(target_folder_path, params)

        # Create PAM User typed record
        pam_user = vault.TypedRecord()

        # Use facade to set fields
        facade = PamUserRecordFacade()
        facade.record = pam_user
        facade.login = username
        facade.password = password
        facade.managed = True

        # Set title (custom or auto-generated)
        pam_title = config.get('pam', {}).get('pam_user_title')
        if pam_title:
            pam_user.title = pam_title
        else:
            first = config['user']['first_name']
            last = config['user']['last_name']
            pam_user.title = f"PAM: {first} {last} - {username}"

        # Add custom fields for metadata
        custom_fields = []

        # Employee ID
        if config['user'].get('employee_id'):
            custom_fields.append(vault.TypedField.new_field(
                'text',
                config['user']['employee_id'],
                'Employee ID'
            ))

        # Department
        if config['user'].get('department'):
            custom_fields.append(vault.TypedField.new_field(
                'text',
                config['user']['department'],
                'Department'
            ))

        # Distinguished Name (Active Directory)
        if config['account'].get('distinguished_name'):
            dn = config['account']['distinguished_name']
            custom_fields.append(vault.TypedField.new_field(
                'text',
                dn,
                'Distinguished Name'
            ))

        if custom_fields:
            pam_user.custom = custom_fields

        # Add to vault
        try:

            # Create record in vault and add to folder
            add_record_to_folder(params, pam_user, folder_uid)

            # Sync to get the record UID
            api.sync_down(params)

            return pam_user.record_uid

        except Exception as e:
            logging.error(f'Failed to create PAM User: {e}')
            raise CommandError('credential-provision', f'PAM User creation failed: {e}')

    def _validate_folder_path(self, folder_path: str) -> None:
        """
        Validate folder path to prevent path traversal attacks.

        Args:
            folder_path: User-specified folder path

        Raises:
            ValueError: If path contains path traversal patterns
        """
        if not folder_path:
            return

        # Check for path traversal patterns
        if '..' in folder_path:
            raise ValueError(
                f"Invalid folder path: '{folder_path}' contains path traversal pattern '..'.\n"
                f"Folder paths must be relative to the gateway application folder.\n"
                f"Example: 'PAM Users/Engineering' (not '../../../evil/path')"
            )

        # Normalize path separators and check for suspicious patterns
        normalized = folder_path.replace('\\', '/')

        # Check for absolute paths (should be relative)
        if normalized.startswith('/'):
            raise ValueError(
                f"Invalid folder path: '{folder_path}' appears to be an absolute path.\n"
                f"Folder paths must be relative to the gateway application folder.\n"
                f"Example: 'PAM Users/Engineering' (not '/Shared Folders/...')"
            )

    def _get_gateway_application_folder(self, pam_config_uid: str, params: KeeperParams) -> Tuple[str, str]:
        """
        Get gateway application folder from PAM Configuration.

        Uses PamConfigurationRecordFacade to access the folder_uid property
        that is stored in the PAM Config's pamResources field.

        Args:
            pam_config_uid: PAM Configuration record UID
            params: KeeperParams

        Returns:
            Tuple of (folder_uid, folder_path)

        Raises:
            ValueError: If PAM Config not found or folder not accessible
        """

        # Load PAM Config record
        pam_config_record = vault.KeeperRecord.load(params, pam_config_uid)
        if not pam_config_record:
            raise ValueError(f"PAM Configuration not found: {pam_config_uid}")

        # Use facade to access folder_uid
        facade = PamConfigurationRecordFacade()
        facade.record = pam_config_record
        facade.load_typed_fields()

        folder_uid = facade.folder_uid

        if not folder_uid:
            raise ValueError(
                f"PAM Configuration '{pam_config_record.title}' has no application folder configured.\n"
                f"Please configure the application folder in the PAM Configuration record."
            )

        # Get folder path from folder_uid using existing utility
        if folder_uid not in params.folder_cache:
            raise ValueError(
                f"Application folder (UID: {folder_uid}) not found in vault.\n"
                f"Ensure the folder is shared with you."
            )

        folder_path = get_folder_path(params, folder_uid)

        return folder_uid, folder_path

    def _ensure_folder_exists(self, folder_path: str, params: KeeperParams) -> Optional[str]:
        """
        Ensure folder exists, create if needed (creating nested folders level by level).

        Args:
            folder_path: Folder path (e.g., "Shared Folders/PAM/Engineering")
            params: KeeperParams session

        Returns:
            Folder UID

        Raises:
            CommandError: If folder creation fails
        """

        # Check if full path already exists
        folder_uid = self._get_folder_uid(folder_path, params)
        if folder_uid:
            return folder_uid

        try:
            # Split path into components
            # Handle both "/" and "\" as path separators
            components = folder_path.replace('\\', '/').split('/')

            # Build path incrementally, creating each level as needed
            current_path = ""
            for i, component in enumerate(components):
                if not component:
                    continue

                # Build path up to this level
                if current_path:
                    current_path = f"{current_path}/{component}"
                else:
                    current_path = component

                # Check if this level exists
                level_uid = self._get_folder_uid(current_path, params)
                if level_uid:
                    continue

                # Determine if this should be a shared folder or subfolder
                # First level should be shared_folder=True, subsequent levels don't need the flag
                is_first_level = (i == 0)

                folder_cmd = FolderMakeCommand()
                folder_cmd.execute(
                    params,
                    folder=current_path,
                    shared_folder=is_first_level,
                    user_folder=not is_first_level
                )

                # Refresh cache after each folder creation
                api.sync_down(params)

                # Verify creation
                level_uid = self._get_folder_uid(current_path, params)
                if not level_uid:
                    raise Exception(f'Folder creation succeeded but UID not found: {current_path}')

            # Get final folder UID
            folder_uid = self._get_folder_uid(folder_path, params)
            if not folder_uid:
                raise Exception(f'Folder path creation succeeded but final UID not found: {folder_path}')

            return folder_uid

        except Exception as e:
            logging.error(f'Failed to create folder path {folder_path}: {e}')
            raise CommandError('credential-provision', f'Folder creation failed: {e}')

    def _create_dag_link(
        self,
        pam_user_uid: str,
        pam_config_uid: str,
        params: KeeperParams
    ) -> None:
        """
        Create DAG relationship linking PAM User to PAM Config.

        This establishes the 'belongs_to' relationship that tells the
        rotation system which PAM Config to use for this user.

        Args:
            pam_user_uid: PAM User record UID
            pam_config_uid: PAM Configuration record UID
            params: KeeperParams session

        Raises:
            CommandError: If DAG linking fails
        """

        # Check if RecordLink is available (requires Python 3.8+)
        if RecordLink is None:
            logging.error('RecordLink unavailable (requires Python 3.8+ for pydantic)')
            raise CommandError(
                'credential-provision',
                'DAG linking requires Python 3.8+ (pydantic dependency)'
            )

        try:
            # Load the PAM Config record to use for record linking
            pam_config_record = vault.KeeperRecord.load(params, pam_config_uid)

            # Create RecordLink instance
            record_link = RecordLink(record=pam_config_record, params=params, fail_on_corrupt=False)

            # Create belongs_to relationship: PAM User belongs_to PAM Configuration
            record_link.belongs_to(
                record_uid=pam_user_uid,
                parent_record_uid=pam_config_uid
            )

            # Save the DAG changes
            record_link.save()

        except Exception as e:
            logging.error(f'Failed to create DAG link: {e}')
            raise CommandError('credential-provision', f'DAG linking failed: {e}')

    def _configure_rotation(
        self,
        pam_user_uid: str,
        config: Dict[str, Any],
        params: KeeperParams
    ) -> None:
        """
        Configure automatic password rotation using PAM rotation command.

        Uses the existing PAMCreateRecordRotationCommand to set up rotation,
        ensuring we use the same logic as the CLI command.

        Args:
            pam_user_uid: PAM User record UID
            config: Configuration dict
            params: KeeperParams session

        Raises:
            CommandError: If rotation configuration fails
        """

        rotation_config = config['pam']['rotation']
        pam_config_uid = config['account']['pam_config_uid']

        # Check if rotation commands are available (Python 3.8+)
        if PAMCreateRecordRotationCommand is None:
            logging.error('PAM rotation unavailable (requires Python 3.8+)')
            raise CommandError('credential-provision', 'Rotation requires Python 3.8+ (pydantic dependency)')

        try:
            schedule = rotation_config['schedule']
            complexity = rotation_config['password_complexity']

            rotation_cmd = PAMCreateRecordRotationCommand()
            kwargs = {
                'record_name': pam_user_uid,
                'iam_aad_config_uid': pam_config_uid,
                'schedule_cron_data': [schedule],
                'pwd_complexity': complexity,
                'enable': True,
                'force': True,
            }

            try:
                # Suppress verbose output from rotation command
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    rotation_cmd.execute(params, **kwargs)
            except Exception as rotation_error:
                error_msg = str(rotation_error)
                if '500' in error_msg or 'gateway' in error_msg.lower():
                    logging.warning('Gateway unavailable - rotation configuration deferred')
                    logging.warning('Configure rotation manually when gateway is available')
                else:
                    raise

        except CommandError:
            raise
        except Exception as e:
            logging.error(f'Failed to configure rotation: {e}')
            raise CommandError('credential-provision', f'Rotation configuration failed: {e}')

    def _rotate_immediately(
        self,
        pam_user_uid: str,
        config: Dict[str, Any],
        params: KeeperParams
    ) -> bool:
        """
        Submit immediate rotation request to sync password to target system.

        This submits a rotation job to sync the generated password stored in
        the PAM User record to the actual account (AD, Azure AD, AWS IAM, etc.).
        The rotation is asynchronous and may complete after this method returns.

        NOTE: Immediate rotation is REQUIRED for provisioning. Without it, the
        PAM User would have a password that doesn't match the target account.

        Args:
            pam_user_uid: PAM User record UID
            config: Configuration dict (unused, kept for consistency)
            params: KeeperParams session

        Returns:
            True if rotation was submitted successfully
            False if rotation submission failed (non-critical)
        """
        # Check if rotation commands are available (Python 3.8+)
        if PAMGatewayActionRotateCommand is None:
            logging.warning('PAM rotation unavailable (requires Python 3.8+) - skipping immediate rotation')
            return False

        try:
            rotate_cmd = PAMGatewayActionRotateCommand()

            # Execute rotation for this specific PAM User
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                rotate_cmd.execute(params, record_uid=pam_user_uid)

            return True

        except Exception as e:
            # Non-critical failure: PAM User is created and rotation scheduled
            # The scheduled rotation will eventually sync the password
            logging.warning(f'⚠️  Immediate rotation failed: {e}')
            logging.warning(f'   Password will sync on next scheduled rotation')
            return False  # Graceful degradation

    def _generate_share_url(
        self,
        pam_user_uid: str,
        config: Dict[str, Any],
        params: KeeperParams
    ) -> str:
        """
        Generate one-time share URL for PAM User.

        Shares the PAM User directly (not a copy) so the user always sees
        the current password, even after future rotations.

        Args:
            pam_user_uid: UID of PAM User to share
            config: Configuration dict (contains expiry settings)
            params: KeeperParams session

        Returns:
            Share URL string

        Raises:
            CommandError: If share URL generation fails
        """
        # Parse expiry (e.g., "7d" = 7 days)
        expiry_str = config.get('email', {}).get('share_url_expiry', '7d')
        expiration_delta = parse_timeout(expiry_str)
        expiry_seconds = int(expiration_delta.total_seconds())

        try:
            # Generate share URL using internal helper
            # NOTE: Extracts logic from OneTimeShareCreateCommand (commands/register.py)
            share_url = self._generate_share_url_internal(
                record_uid=pam_user_uid,
                expiry_seconds=expiry_seconds,
                params=params
            )

            return share_url

        except Exception as e:
            logging.error(f'Failed to generate share URL: {e}')
            raise CommandError('credential-provision', f'Share URL generation failed: {e}')

    def _generate_share_url_internal(
        self,
        record_uid: str,
        expiry_seconds: int,
        params: KeeperParams
    ) -> str:
        """
        Generate one-time share URL for a record (PAM User).

        This extracts the core logic from OneTimeShareCreateCommand
        (keepercommander/commands/register.py lines 2365-2430).

        Resolution: BLOCKER_KC-1007-5_Share-URL-API-Missing_2025-11-17
        Decided to extract logic rather than create shared api.create_share_url()
        to stay within scope of KC-1007. Can be refactored later if needed.

        Args:
            record_uid: UID of record to share (PAM User)
            expiry_seconds: Seconds until share expires
            params: KeeperParams session

        Returns:
            Share URL string

        Raises:
            ValueError: If record not found
            Exception: If share creation fails
        """
        # Get record key
        if record_uid not in params.record_cache:
            raise ValueError(f'Record not found: {record_uid}')

        record_key = params.record_cache[record_uid]['record_key_unencrypted']

        # Generate client keys (from OneTimeShareCreateCommand)
        client_key = utils.generate_aes_key()
        client_id = crypto.hmac_sha512(client_key, 'KEEPER_SECRETS_MANAGER_CLIENT_ID'.encode())

        # Create share request
        rq = APIRequest_pb2.AddExternalShareRequest()
        rq.recordUid = utils.base64_url_decode(record_uid)
        rq.encryptedRecordKey = crypto.encrypt_aes_v2(record_key, client_key)
        rq.clientId = client_id
        rq.accessExpireOn = utils.current_milli_time() + int(expiry_seconds * 1000)

        # Send request
        api.communicate_rest(params, rq, 'vault/external_share_add', rs_type=APIRequest_pb2.Device)

        # Build URL
        parsed = urlparse(params.server)
        server_netloc = parsed.netloc if parsed.netloc else parsed.path
        url = urlunparse(('https', server_netloc, '/vault/share/', None, None, utils.base64_url_encode(client_key)))

        return str(url)

    def _load_email_config(
        self,
        config_name: str,
        params: KeeperParams
    ):
        """
        Load email configuration from vault.

        Args:
            config_name: Email config name
            params: KeeperParams session

        Returns:
            EmailConfig object

        Raises:
            CommandError: If email config not found
        """
        # Find email config by name
        record_uid = email_commands.find_email_config_record(params, config_name)

        if not record_uid:
            raise CommandError('credential-provision', f'Email config not found: {config_name}')

        # Load email config from record
        try:
            email_config = email_commands.load_email_config_from_record(params, record_uid)
            return email_config
        except Exception as e:
            raise CommandError('credential-provision', f'Failed to load email config: {e}')

    def _send_email(
        self,
        config: Dict[str, Any],
        share_url: str,
        params: KeeperParams
    ) -> bool:
        """
        Send welcome email with credentials using existing onboarding template.

        Args:
            config: Configuration dict
            share_url: One-time share URL
            params: KeeperParams session

        Returns:
            True if email sent successfully, False if failed (non-critical)
        """
        email_config_name = config['email']['config_name']
        send_to = config['email']['send_to']
        subject = config['email'].get('subject', 'Welcome - Your Account Credentials')

        # Load email configuration
        try:
            email_config = self._load_email_config(email_config_name, params)
        except Exception as e:
            logging.warning(f'⚠️  Failed to load email config: {e}')
            return False

        # Build email body using existing template
        user = config['user']
        custom_message = config['email'].get(
            'custom_message',
            f"Welcome to the team, {user['first_name']}! Your corporate account credentials are ready."
        )
        record_title = f"Corporate Account - {user['first_name']} {user['last_name']}"

        # Convert expiry format from short notation (7d, 24h, 60mi) to human-readable (7 days, 24 hours, 60 minutes)
        expiry_str = config['email'].get('share_url_expiry', '7d')
        expiration_delta = parse_timeout(expiry_str)
        expiration = format_timeout(expiration_delta)

        body = build_onboarding_email(
            share_url=share_url,
            custom_message=custom_message,
            record_title=record_title,
            expiration=expiration
        )

        # Send email (suppress verbose email service output)
        try:
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                sender = EmailSender(email_config)
                sender.send(send_to, subject, body, html=True)
            return True

        except Exception as e:
            logging.warning(f'⚠️  Email sending failed: {e}')
            logging.info(f'Manual delivery required - share URL: {share_url}')
            return False

    # =========================================================================
    # Rollback Logic
    # =========================================================================

    def _rollback(self, state: ProvisioningState, params: KeeperParams) -> None:
        """
        Rollback created records on critical failure.

        Cleans up partially-created resources when provisioning fails at a
        critical step (PAM User creation, DAG linking, rotation config, etc.).

        Non-critical failures (email, share URL) do not trigger rollback.

        Args:
            state: ProvisioningState tracking created resources
            params: KeeperParams session

        Implementation Notes:
            - DAG links are likely auto-removed when child record is deleted
            - Rollback attempts are defensive (don't fail if already cleaned up)
            - Partial rollback success is acceptable (logs errors for manual cleanup)
        """

        rollback_errors = []

        logging.warning('Rolling back provisioning changes')

        if state.pam_user_uid:
            try:
                api.delete_record(params, state.pam_user_uid)
            except Exception as e:
                rollback_errors.append(f'PAM User: {e}')
                logging.error(f'Rollback failed for PAM User: {e}')

        if rollback_errors:
            logging.error('Rollback completed with errors - manual cleanup may be required')
            for error in rollback_errors:
                logging.error(f'  {error}')

    # =========================================================================
    # System-Specific Field Validation
    # =========================================================================

    def _search_pam_users_by_login(self, params: KeeperParams, username: str) -> List[Dict[str, str]]:
        """
        Search for existing PAM User records by login username.

        This is critical for Azure AD which only allows ONE PAM User per Azure AD user.
        Creating duplicate PAM Users causes rotation conflicts.

        Args:
            params: KeeperParams session
            username: Login username to search for

        Returns:
            List of matching PAM User records with 'uid' and 'title' keys

        Example:
            existing = self._search_pam_users_by_login(params, 'john.doe@company.com')
            if existing:
                raise ValueError(f"User already exists: {existing[0]['uid']}")
        """
        matching_users = []

        for record_uid, record in params.record_cache.items():
            if record.get('record_type') == 'pamUser':
                record_data = record.get('data_unencrypted')
                if record_data:
                    # Check login field in PAM User record
                    for field in record_data.get('fields', []):
                        if field.get('type') == 'login':
                            field_values = field.get('value', [])
                            if field_values and isinstance(field_values, list):
                                login_value = field_values[0].get('text', '') if field_values[0] else ''
                                if login_value == username:
                                    matching_users.append({
                                        'uid': record_uid,
                                        'title': record.get('title', 'Untitled')
                                    })

        return matching_users

    def _validate_system_specific_fields(
        self,
        config: Dict[str, Any],
        pam_config_record: Dict[str, Any],
        params: KeeperParams
    ) -> List[str]:
        """
        Validate YAML fields based on PAM system type (Active Directory, Azure AD, AWS IAM).

        This validation runs AFTER basic YAML validation and AFTER loading the PAM Config
        from the vault, so we can determine the target system type and apply system-specific rules.

        Args:
            config: Parsed YAML configuration
            pam_config_record: PAM Configuration record from vault
            params: KeeperParams session

        Returns:
            List of validation error messages (empty if valid)

        System-Specific Rules:
            - Active Directory: Optional distinguished_name for precise targeting
            - Azure AD: Required domain\\username or username@domain format, duplicate check
            - AWS IAM: No additional validation needed

        """
        errors = []
        warnings = []

        # Extract PAM system type from KeeperRecord object
        # The record is now a TypedRecord, so we access record_type directly
        pam_type = ''

        if hasattr(pam_config_record, 'record_type'):
            # TypedRecord - get the record type
            record_type = pam_config_record.record_type

            # Map record types to PAM system types
            if ('ad' in record_type.lower() or
                'active' in record_type.lower() or
                'domain' in record_type.lower()):
                pam_type = 'activedirectory'
            elif 'azure' in record_type.lower():
                pam_type = 'azuread'
            elif 'aws' in record_type.lower() or 'iam' in record_type.lower():
                pam_type = 'awsiam'
            else:
                pam_type = record_type.lower()

        # Normalize type string (handle various formats)
        pam_type = str(pam_type).lower().replace('_', '').replace('-', '')

        username = config['account']['username']

        # ===================================================================
        # Active Directory Validation
        # ===================================================================
        if pam_type in ['ad', 'activedirectory', 'active directory']:
            distinguished_name = config['account'].get('distinguished_name')

            if not distinguished_name:
                logging.warning('')
                logging.warning('⚠️  No "distinguished_name" provided for Active Directory')
                logging.warning('    The system will search by username in the PAM Config search base')
                logging.warning('    This may fail or target the wrong user in multi-OU environments')
                logging.warning('')
                logging.warning('    Recommendation: Add distinguished_name to your YAML:')
                logging.warning('    account:')
                logging.warning('      username: john.doe-admin')
                logging.warning('      distinguished_name: "CN=john.doe-admin,OU=IT Admins,DC=company,DC=com"')
                logging.warning('')
            else:
                if not distinguished_name.startswith('CN=') or 'DC=' not in distinguished_name:
                    errors.append(
                        f'account.distinguished_name has invalid format: {distinguished_name}'
                    )
                    errors.append(
                        '    Expected format: CN=username,OU=organizational_unit,DC=domain,DC=com'
                    )
                    errors.append(
                        '    Example: CN=john.doe-admin,OU=IT Admins,DC=company,DC=com'
                    )

        # ===================================================================
        # Azure AD Validation
        # ===================================================================
        elif pam_type in ['azuread', 'azure ad', 'azure', 'aad']:
            # Validate username format (must contain \ or @)
            if '\\' not in username and '@' not in username:
                errors.append(
                    'Azure AD requires username in format: "domain\\username" or "username@domain"'
                )
                errors.append(f'    Current username: {username}')
                errors.append(f'    Examples: "COMPANY\\john.doe" or "john.doe@company.com"')

            # Check for existing PAM User (Azure AD constraint: only one PAM User per Azure AD user)
            existing_pam_users = self._search_pam_users_by_login(params, username)
            if existing_pam_users:
                errors.append('')
                errors.append(f'❌ Azure AD user "{username}" already exists in vault')
                errors.append(f'   Existing PAM User UID: {existing_pam_users[0]["uid"]}')
                errors.append(f'   Existing PAM User Title: {existing_pam_users[0]["title"]}')
                errors.append('')
                errors.append('   Azure AD Constraint: Only ONE PAM User record per Azure AD user')
                errors.append('   Having multiple PAM User records causes rotation conflicts')
                errors.append('')
                errors.append('   Solutions:')
                errors.append('   1. Use the existing PAM User record instead')
                errors.append('   2. Delete the existing PAM User if it\'s incorrect')
                errors.append('   3. Use a different Azure AD username')
                errors.append('')

        # ===================================================================
        # AWS IAM Validation
        # ===================================================================
        elif pam_type in ['awsiam', 'aws iam', 'iam', 'aws']:
            # AWS IAM works with just username - no additional validation needed
            pass

        # ===================================================================
        # Unknown PAM Type
        # ===================================================================
        else:
            logging.warning('')
            logging.warning(f'⚠️  Unknown or unsupported PAM system type: "{pam_type}"')
            logging.warning('    Using generic validation only')
            logging.warning('    Supported types: Active Directory, Azure AD, AWS IAM')
            logging.warning('')

        return errors
