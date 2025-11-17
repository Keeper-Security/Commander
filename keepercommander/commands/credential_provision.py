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
"""

import argparse
import json
import logging
import os
import re
import secrets
import string
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta

try:
    import yaml
except ImportError:
    yaml = None

from .base import Command, suppress_exit, raise_parse_exception
from .. import api, vault, vault_extensions, crypto, utils
from ..error import CommandError
from ..params import KeeperParams


# =============================================================================
# Argument Parser
# =============================================================================

credential_provision_parser = argparse.ArgumentParser(
    prog='credential-provision',
    description='Automate employee credential provisioning with PAM User creation, '
                'password rotation, and email delivery'
)

credential_provision_parser.add_argument(
    '--config',
    dest='config',
    required=True,
    help='Path to YAML configuration file'
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
    command_info['credential-provision'] = 'Automate employee credential provisioning'


# =============================================================================
# Main Command Class
# =============================================================================

class CredentialProvisionCommand(Command):
    """
    Automated Credential Provisioning Command

    This command orchestrates the following operations:
    1. Parse and validate YAML configuration
    2. Check for duplicate PAM Users
    3. Generate secure password
    4. Create PAM User record with rotation configured
    5. Trigger immediate password rotation (if gateway available)
    6. Create Login record for sharing
    7. Generate one-time share URL
    8. Send welcome email with credentials
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
        dry_run = kwargs.get('dry_run', False)
        output_format = kwargs.get('output', 'text')

        try:
            # Phase 1: Load and validate YAML configuration
            if output_format == 'text':
                logging.info(f'Loading configuration from: {config_path}')

            config = self._load_yaml(config_path)

            if output_format == 'text':
                logging.info('Validating configuration...')

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

            if output_format == 'text':
                logging.info('✓ Configuration validated successfully')

            # Phase 2: Dry-run mode (validation only)
            if dry_run:
                self._dry_run_report(params, config, output_format)
                return

            # Phase 3: Execute provisioning (NOT IMPLEMENTED YET)
            if output_format == 'text':
                logging.info('\n' + '='*60)
                logging.info('PROVISIONING NOT YET IMPLEMENTED')
                logging.info('='*60)
                logging.info('Story KC-1007-2 (Foundation) focuses on:')
                logging.info('  ✓ Command structure')
                logging.info('  ✓ YAML parsing')
                logging.info('  ✓ Validation framework')
                logging.info('  ✓ Dry-run mode')
                logging.info('\nProvisioning logic will be implemented in:')
                logging.info('  • KC-1007-3: PAM User Creation')
                logging.info('  • KC-1007-4: Rotation & Login Records')
                logging.info('  • KC-1007-5: Sharing & Email')
                logging.info('='*60 + '\n')
            else:
                result = {
                    'success': False,
                    'error': 'Provisioning not yet implemented',
                    'message': 'KC-1007-2 focuses on foundation and validation only'
                }
                print(json.dumps(result, indent=2))

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
        if personal_email and not self._is_valid_email(personal_email):
            errors.append(f'user.personal_email is invalid: {personal_email}')

        # Validate corporate email if provided
        corporate_email = user.get('corporate_email', '')
        if corporate_email and not self._is_valid_email(corporate_email):
            errors.append(f'user.corporate_email is invalid: {corporate_email}')

        # Validate manager_email if provided
        manager_email = user.get('manager_email', '')
        if manager_email and not self._is_valid_email(manager_email):
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
            return errors  # Can't validate further

        # Required rotation fields
        if not rotation.get('schedule'):
            errors.append('pam.rotation.schedule is required (CRON format)')
        else:
            # Validate CRON format (6-field for rotation)
            schedule = rotation['schedule']
            if not self._is_valid_cron(schedule):
                errors.append(
                    f'pam.rotation.schedule has invalid CRON format: {schedule}\n'
                    f'    Expected 6 fields: seconds minute hour day month day-of-week\n'
                    f'    Example: "0 0 3 * * ?" (Daily at 3:00:00 AM)'
                )

        if not rotation.get('password_complexity'):
            errors.append('pam.rotation.password_complexity is required')
        else:
            # Validate complexity format
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

        # Check if email config exists in vault
        # TODO: Implement in next phase when we have email config lookup
        # For now, just validate the field is present

        # Validate send_to if provided
        send_to = email.get('send_to', 'personal')
        if send_to not in ['personal', 'corporate', 'both']:
            errors.append(
                f'email.send_to must be "personal", "corporate", or "both": {send_to}'
            )

        # Validate share_url_expiry if provided
        expiry = email.get('share_url_expiry', '7d')
        if expiry and not self._is_valid_expiry(expiry):
            errors.append(
                f'email.share_url_expiry has invalid format: {expiry}\n'
                f'    Expected: <number>d (days), <number>h (hours), or <number>m (minutes)\n'
                f'    Examples: "7d", "24h", "60m"'
            )

        return errors

    def _validate_vault_section(self, params: KeeperParams, vault_config: Dict[str, Any]) -> List[str]:
        """Validate vault section (folder paths)."""
        errors = []

        folder = vault_config.get('folder')
        if folder:
            # TODO: Check if folder exists (implement in next phase)
            # For now, just validate it's a non-empty string
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

    def _is_valid_email(self, email: str) -> bool:
        """Basic email format validation."""
        # Simple regex for email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _is_valid_cron(self, cron: str) -> bool:
        """
        Validate CRON format (6-field for rotation schedules).

        Note: This is basic validation. Detailed validation happens in
        discoveryrotation.validate_cron_expression() when rotation is configured.
        """
        parts = cron.strip().split()

        # Rotation schedules require 6 fields (including seconds)
        if len(parts) != 6:
            return False

        # Validate each field with appropriate ranges
        # Format: seconds minute hour day month day-of-week
        field_ranges = [
            (0, 59),  # seconds
            (0, 59),  # minutes
            (0, 23),  # hours
            (1, 31),  # day of month
            (1, 12),  # month
            (0, 7),   # day of week (0 and 7 both = Sunday)
        ]

        for i, part in enumerate(parts):
            # Allow special characters
            if part in ['*', '?']:
                continue

            # Check for steps (*/n)
            if '/' in part:
                base, step = part.split('/', 1)
                if base == '*' and step.isdigit():
                    continue
                # Complex step patterns - let discoveryrotation validate
                if '-' in base:
                    continue

            # Check for ranges (n-m)
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    if start.isdigit() and end.isdigit():
                        min_val, max_val = field_ranges[i]
                        if min_val <= int(start) <= max_val and min_val <= int(end) <= max_val:
                            continue
                except:
                    return False
                return False

            # Check for lists (n,m,o)
            if ',' in part:
                try:
                    values = [int(v) for v in part.split(',')]
                    min_val, max_val = field_ranges[i]
                    if all(min_val <= v <= max_val for v in values):
                        continue
                except:
                    return False
                return False

            # Check single number
            if part.isdigit():
                min_val, max_val = field_ranges[i]
                if not (min_val <= int(part) <= max_val):
                    return False
            else:
                return False

        return True

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
        """Validate share URL expiry format: 7d, 24h, 60m"""
        pattern = r'^\d+[dhm]$'
        return bool(re.match(pattern, expiry))

    # =========================================================================
    # Dry-Run Mode
    # =========================================================================

    def _dry_run_report(self, params: KeeperParams, config: Dict[str, Any], output_format: str):
        """
        Generate dry-run report showing what would be created.

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

        if output_format == 'json':
            result = {
                'success': True,
                'dry_run': True,
                'employee_name': employee_name,
                'actions': [
                    'Check for duplicate PAM User',
                    f'Generate secure password (complexity: {pam.get("rotation", {}).get("password_complexity")})',
                    f'Create PAM User: {username}',
                    f'Link PAM User to PAM Config: {account.get("pam_config_uid")}',
                    f'Configure rotation: {pam.get("rotation", {}).get("schedule")}',
                    'Trigger immediate rotation (if gateway available)',
                    'Create Login record',
                    f'Generate share URL (expiry: {email_config.get("share_url_expiry", "7d")})',
                    f'Send email to: {user.get("personal_email")}'
                ],
                'configuration': {
                    'employee': employee_name,
                    'username': username,
                    'folder': vault_config.get('folder', f'/Employees/{user.get("department", "Unknown")}'),
                    'rotation_schedule': pam.get('rotation', {}).get('schedule'),
                    'email_recipient': user.get('personal_email')
                }
            }
            print(json.dumps(result, indent=2))
        else:
            print('\n' + '='*60)
            print('DRY RUN MODE - NO CHANGES WILL BE MADE')
            print('='*60)
            print(f'\nEmployee: {employee_name}')
            print(f'Username: {username}')
            print(f'Email: {user.get("personal_email")}')
            print('\nPlanned Actions:')
            print('  1. Check for duplicate PAM User in folder')
            print(f'  2. Generate secure password')
            print(f'     Complexity: {pam.get("rotation", {}).get("password_complexity")}')
            print(f'  3. Create PAM User record')
            print(f'     Folder: {vault_config.get("folder", f"/Employees/{user.get("department", "Unknown")}")}')
            print(f'  4. Link to PAM Config: {account.get("pam_config_uid")[:20]}...')
            print(f'  5. Configure rotation')
            print(f'     Schedule: {pam.get("rotation", {}).get("schedule")}')
            print(f'  6. Trigger immediate rotation (if gateway available)')
            print(f'  7. Create Login record in admin vault')
            print(f'  8. Generate one-time share URL')
            print(f'     Expiry: {email_config.get("share_url_expiry", "7d")}')
            print(f'  9. Send welcome email')
            print(f'     To: {user.get("personal_email")}')
            print(f'     Config: {email_config.get("config_name")}')
            print('\n' + '='*60)
            print('✓ Validation passed - ready for actual provisioning')
            print('  Run without --dry-run to execute')
            print('='*60 + '\n')
