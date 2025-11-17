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

class ProvisioningState:
    """Track provisioning state for rollback on critical failure."""

    def __init__(self):
        self.pam_user_uid = None
        self.login_record_uid = None
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

            # Phase 3: Execute provisioning (KC-1007-3)
            if output_format == 'text':
                logging.info('\n' + '='*60)
                logging.info('STARTING CREDENTIAL PROVISIONING')
                logging.info('='*60 + '\n')

            # Initialize provisioning state for rollback tracking (KC-1007-6)
            state = ProvisioningState()

            try:
                # Check for duplicate PAM Users
                if output_format == 'text':
                    logging.info('Step 1: Checking for duplicate PAM Users...')

                if self._check_duplicate(config, params):
                    error_msg = f'Duplicate PAM User already exists for username: {config["account"]["username"]}'
                    if output_format == 'json':
                        result = {'success': False, 'error': error_msg}
                        print(json.dumps(result, indent=2))
                    else:
                        logging.error(error_msg)
                    raise CommandError('credential-provision', error_msg)

                if output_format == 'text':
                    logging.info('✓ No duplicates found\n')

                # Generate secure password
                if output_format == 'text':
                    logging.info('Step 2: Generating secure password...')

                password = self._generate_password(config['pam']['rotation']['password_complexity'])

                if output_format == 'text':
                    logging.info('✓ Password generated\n')

                # Create PAM User
                if output_format == 'text':
                    logging.info('Step 3: Creating PAM User record...')

                pam_user_uid = self._create_pam_user(config, password, params)
                state.pam_user_uid = pam_user_uid  # Track for rollback

                if output_format == 'text':
                    logging.info('✓ PAM User created\n')

                # Link to PAM Configuration
                if output_format == 'text':
                    logging.info('Step 4: Linking to PAM Configuration...')

                self._create_dag_link(pam_user_uid, config['account']['pam_config_uid'], params)
                state.dag_link_created = True  # Track for rollback

                if output_format == 'text':
                    logging.info('✓ DAG link created\n')

                # Configure rotation
                if output_format == 'text':
                    logging.info('Step 5: Configuring password rotation...')

                self._configure_rotation(pam_user_uid, config, params)

                if output_format == 'text':
                    logging.info('✓ Rotation configured\n')

                # Check gateway status (KC-1007-4)
                if output_format == 'text':
                    logging.info('Step 6: Checking gateway status...')

                gateway_available = self._check_gateway_status(
                    config['account']['pam_config_uid'],
                    params
                )

                if output_format == 'text':
                    if gateway_available:
                        logging.info('✓ Gateway available\n')
                    else:
                        logging.info('⚠️  Gateway status uncertain (will attempt rotation)\n')

                # Perform immediate rotation (KC-1007-4)
                if output_format == 'text':
                    logging.info('Step 7: Performing immediate rotation...')

                rotation_success = self._rotate_immediately(pam_user_uid, config, params)

                if output_format == 'text':
                    if rotation_success:
                        logging.info('✓ Immediate rotation complete\n')
                    else:
                        logging.info('⚠️  Rotation deferred to next schedule\n')

                # Create Login record (KC-1007-4)
                if output_format == 'text':
                    logging.info('Step 8: Creating Login record...')

                login_record_uid = self._create_login_record(config, password, params)
                state.login_record_uid = login_record_uid  # Track for rollback

                if output_format == 'text':
                    logging.info('✓ Login record created\n')

                # Generate share URL (KC-1007-5)
                if output_format == 'text':
                    logging.info('Step 9: Generating share URL...')

                share_url = self._generate_share_url(login_record_uid, config, params)

                if output_format == 'text':
                    logging.info('✓ Share URL generated\n')

                # Send email (KC-1007-5)
                if output_format == 'text':
                    logging.info('Step 10: Sending welcome email...')

                email_success = self._send_email(config, share_url, params)

                if output_format == 'text':
                    if email_success:
                        logging.info('✓ Email sent successfully\n')
                    else:
                        logging.info('⚠️  Email sending failed (non-critical)\n')

                # Success!
                if output_format == 'text':
                    logging.info('\n' + '='*60)
                    logging.info('✅ PROVISIONING COMPLETE')
                    logging.info('='*60)
                    logging.info(f'PAM User UID: {pam_user_uid}')
                    logging.info(f'Login Record UID: {login_record_uid}')
                    logging.info(f'Share URL: {share_url}')
                    logging.info(f'Username: {config["account"]["username"]}')
                    logging.info(f'Employee: {config["user"]["first_name"]} {config["user"]["last_name"]}')
                    logging.info(f'Rotation: {"Synced" if rotation_success else "Scheduled"}')
                    logging.info(f'Email: {"Sent" if email_success else "Failed (manual delivery required)"}')
                    logging.info('='*60 + '\n')
                else:
                    result = {
                        'success': True,
                        'pam_user_uid': pam_user_uid,
                        'login_record_uid': login_record_uid,
                        'share_url': share_url,
                        'username': config['account']['username'],
                        'employee_name': f"{config['user']['first_name']} {config['user']['last_name']}",
                        'rotation_status': 'synced' if rotation_success else 'scheduled',
                        'email_status': 'sent' if email_success else 'failed',
                        'message': 'Credential provisioning complete'
                    }
                    print(json.dumps(result, indent=2))

            except CommandError as e:
                # Critical failure during provisioning - rollback changes
                logging.error(f'\n❌ CRITICAL FAILURE: {str(e)}')
                self._rollback(state, params)
                raise
            except Exception as e:
                # Unexpected failure during provisioning - rollback changes
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

    # =========================================================================
    # KC-1007-3: PAM User Creation & Rotation
    # =========================================================================

    def _check_duplicate(self, config: Dict[str, Any], params: KeeperParams) -> bool:
        """
        Check for duplicate PAM Users.

        A duplicate is defined as a PAM User with the same username
        in the same folder.

        Args:
            config: Validated configuration
            params: KeeperParams session

        Returns:
            True if duplicate found, False otherwise
        """
        username = config['account']['username']
        folder_path = config.get('vault', {}).get('folder', f"/Employees/{config['user'].get('department', 'Unknown')}")

        # Get folder UID
        folder_uid = self._get_folder_uid(folder_path, params)

        if not folder_uid:
            # Folder doesn't exist yet, so no duplicates possible
            return False

        # Search for PAM Users in folder with matching username
        for record_uid in params.record_cache:
            record = vault.KeeperRecord.load(params, record_uid)

            # Check if it's a PAM User
            if not isinstance(record, vault.TypedRecord):
                continue
            if record.record_type != 'pamUser':
                continue

            # Check if in same folder
            record_folder_uid = record.folder_uid if hasattr(record, 'folder_uid') else None
            if record_folder_uid != folder_uid:
                continue

            # Check username match
            # Use record facade to get login field
            try:
                from keepercommander.commands.pam.user_facade import PamUserRecordFacade
                facade = PamUserRecordFacade()
                facade.assign_record(record)

                if facade.login == username:
                    logging.error(f'❌ Duplicate PAM User found:')
                    logging.error(f'   Username: {username}')
                    logging.error(f'   Folder: {folder_path}')
                    logging.error(f'   Existing UID: {record_uid}')
                    logging.error(f'   Title: {record.title}')
                    return True
            except Exception as e:
                logging.debug(f'Error checking record {record_uid}: {e}')
                continue

        return False

    def _get_folder_uid(self, folder_path: str, params: KeeperParams) -> Optional[str]:
        """
        Get folder UID by path.

        Args:
            folder_path: Folder path (e.g., "/Employees/Engineering")
            params: KeeperParams session

        Returns:
            Folder UID if found, None otherwise
        """
        from ..subfolder import try_resolve_path

        try:
            folder_node = try_resolve_path(params, folder_path)
            if folder_node:
                return folder_node.uid
        except:
            pass

        return None

    def _generate_password(self, password_complexity: str) -> str:
        """
        Generate secure random password.

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
        # Parse complexity: "length,upper,lower,digits,special"
        try:
            parts = password_complexity.split(',')
            if len(parts) != 5:
                raise ValueError(f'Invalid complexity format: {password_complexity}')

            length = int(parts[0])
            min_upper = int(parts[1])
            min_lower = int(parts[2])
            min_digits = int(parts[3])
            min_special = int(parts[4])

            # Validate that minimums don't exceed length
            total_min = min_upper + min_lower + min_digits + min_special
            if total_min > length:
                raise ValueError(
                    f'Password complexity requirements ({total_min}) exceed length ({length})'
                )

        except (ValueError, IndexError) as e:
            raise ValueError(f'Invalid password complexity: {password_complexity}. {str(e)}')

        # Generate secure random password
        password = self._generate_random_password(length, min_upper, min_lower, min_digits, min_special)

        logging.info(f'✓ Generated secure password (length: {length})')
        logging.debug(f'  Complexity: {min_upper} upper, {min_lower} lower, {min_digits} digits, {min_special} special')

        return password

    def _generate_random_password(
        self,
        length: int,
        min_upper: int,
        min_lower: int,
        min_digits: int,
        min_special: int
    ) -> str:
        """
        Generate cryptographically secure random password.

        Uses secrets module (cryptographic RNG) to generate password
        meeting complexity requirements.

        Args:
            length: Total password length
            min_upper: Minimum uppercase letters
            min_lower: Minimum lowercase letters
            min_digits: Minimum digits
            min_special: Minimum special characters

        Returns:
            Random password meeting all requirements
        """
        # Character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = '''!@#$%^?();',.=+[]<>{}-_/\\*&:"`~|'''

        # Ensure minimum requirements
        password_chars = []
        password_chars.extend(secrets.choice(uppercase) for _ in range(min_upper))
        password_chars.extend(secrets.choice(lowercase) for _ in range(min_lower))
        password_chars.extend(secrets.choice(digits) for _ in range(min_digits))
        password_chars.extend(secrets.choice(special) for _ in range(min_special))

        # Fill remaining length with random mix
        remaining = length - len(password_chars)
        if remaining > 0:
            all_chars = uppercase + lowercase + digits + special
            password_chars.extend(secrets.choice(all_chars) for _ in range(remaining))

        # Shuffle to avoid predictable pattern (first chars always uppercase, etc.)
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

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
        from keepercommander.commands.pam.user_facade import PamUserRecordFacade

        username = config['account']['username']
        folder_path = config.get('vault', {}).get('folder', f"/Employees/{config['user'].get('department', 'Unknown')}")

        # Ensure folder exists
        folder_uid = self._ensure_folder_exists(folder_path, params)

        # Create PAM User typed record
        pam_user = vault.TypedRecord()
        pam_user.record_type = 'pamUser'

        # Use facade to set fields
        facade = PamUserRecordFacade()
        facade.assign_record(pam_user)
        facade.login = username
        facade.password = password
        facade.managed = True

        # Set title (custom or auto-generated)
        pam_title = config.get('pam', {}).get('pam_user_title')
        if pam_title:
            pam_user.title = pam_title
        else:
            # Auto-generate: "PAM: FirstName LastName - Username"
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

        if custom_fields:
            pam_user.custom = custom_fields

        # Add to vault
        try:
            record_uid = vault.KeeperRecord.create(params, pam_user)

            # Set folder
            if folder_uid:
                api.sync_down(params)  # Refresh cache
                vault_extensions.move_record(params, record_uid, folder_uid)

            logging.info(f'✅ Created PAM User: {pam_user.title}')
            logging.info(f'   UID: {record_uid}')
            logging.info(f'   Folder: {folder_path}')

            return record_uid

        except Exception as e:
            logging.error(f'Failed to create PAM User: {e}')
            raise CommandError('credential-provision', f'PAM User creation failed: {e}')

    def _ensure_folder_exists(self, folder_path: str, params: KeeperParams) -> Optional[str]:
        """
        Ensure folder exists, create if needed.

        Args:
            folder_path: Folder path (e.g., "/Employees/Engineering")
            params: KeeperParams session

        Returns:
            Folder UID

        Raises:
            CommandError: If folder creation fails
        """
        from ..commands.folder import FolderMakeCommand

        # Check if exists
        folder_uid = self._get_folder_uid(folder_path, params)
        if folder_uid:
            return folder_uid

        # Create folder
        logging.info(f'Creating folder: {folder_path}')

        try:
            # Use existing folder command to create
            folder_cmd = FolderMakeCommand()
            folder_cmd.execute(params, folder=folder_path, shared_folder=True)

            # Refresh cache
            api.sync_down(params)

            # Get UID after creation
            folder_uid = self._get_folder_uid(folder_path, params)
            if not folder_uid:
                raise Exception(f'Folder creation succeeded but UID not found: {folder_path}')

            logging.info(f'✓ Created shared folder: {folder_path}')
            return folder_uid

        except Exception as e:
            logging.error(f'Failed to create folder {folder_path}: {e}')
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
        from ..discovery_common import record_link

        try:
            # Create belongs_to relationship
            # PAM User belongs_to PAM Configuration
            record_link.link_records(
                params=params,
                child_uid=pam_user_uid,
                parent_uid=pam_config_uid
            )

            logging.info(f'✅ Linked PAM User to PAM Configuration')
            logging.debug(f'   PAM User: {pam_user_uid}')
            logging.debug(f'   PAM Config: {pam_config_uid}')

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
        Configure automatic password rotation.

        Creates rotation schedule with complexity requirements
        and enables rotation for the PAM User.

        Args:
            pam_user_uid: PAM User record UID
            config: Configuration dict
            params: KeeperParams session

        Raises:
            CommandError: If rotation configuration fails
        """
        from ..commands.pam import router_helper
        from ..proto import router_pb2

        rotation_config = config['pam']['rotation']

        try:
            # Build rotation request
            schedule = rotation_config['schedule']
            complexity = rotation_config['password_complexity']

            # Use router helper to set rotation information
            router_helper.router_set_record_rotation_information(
                params=params,
                record_uid=pam_user_uid,
                resource_ref=None,  # Will use default from PAM Config
                pwd_complexity=complexity,
                schedule_data=[{"type": "CRON", "cron": schedule, "tz": "Etc/UTC"}]
            )

            logging.info(f'✅ Configured rotation for PAM User')
            logging.debug(f'   Schedule: {schedule}')
            logging.debug(f'   Complexity: {complexity}')

        except Exception as e:
            logging.error(f'Failed to configure rotation: {e}')
            raise CommandError('credential-provision', f'Rotation configuration failed: {e}')

    def _check_gateway_status(
        self,
        pam_config_uid: str,
        params: KeeperParams
    ) -> bool:
        """
        Check if PAM Gateway is available for immediate rotation.

        Uses simplified approach: Assume gateway is available if rotation
        is configured. Actual connectivity is verified during rotation attempt.

        Args:
            pam_config_uid: PAM Configuration record UID
            params: KeeperParams session

        Returns:
            True if gateway appears available, False otherwise
        """
        # Simplified approach per design review:
        # We assume the gateway is available if the PAM Configuration exists
        # The actual rotation command will handle gateway connectivity gracefully

        try:
            # Verify PAM Config exists in vault
            if pam_config_uid in params.record_cache:
                logging.debug(f'PAM Configuration found: {pam_config_uid}')
                return True
            else:
                logging.warning(f'PAM Configuration not found in vault: {pam_config_uid}')
                return False
        except Exception as e:
            logging.warning(f'Gateway status check failed: {e}')
            return False  # Graceful degradation

    def _rotate_immediately(
        self,
        pam_user_uid: str,
        config: Dict[str, Any],
        params: KeeperParams
    ) -> bool:
        """
        Perform immediate rotation to sync password to target system.

        This overwrites the HR-set initial password with the generated
        password stored in the PAM User record.

        Args:
            pam_user_uid: PAM User record UID
            config: Configuration dict
            params: KeeperParams session

        Returns:
            True if rotation succeeded or was not requested
            False if rotation was requested but failed (non-critical)
        """
        # Check if immediate rotation was requested
        rotation_config = config['pam']['rotation']
        rotate_immediately = rotation_config.get('rotate_immediately', False)

        if not rotate_immediately:
            logging.debug('Immediate rotation not requested (rotate_immediately: false)')
            return True

        logging.info('Attempting immediate rotation...')

        try:
            # Import rotation command
            from ..commands.discoveryrotation import PAMGatewayActionRotateCommand

            # Create and execute rotation command
            rotate_cmd = PAMGatewayActionRotateCommand()

            # Execute rotation for this specific PAM User
            rotate_cmd.execute(params, record_uid=pam_user_uid)

            logging.info('✅ Immediate rotation completed successfully')
            logging.debug(f'   Password synced to target system')
            return True

        except Exception as e:
            # Non-critical failure: PAM User is created and rotation scheduled
            # The scheduled rotation will eventually sync the password
            logging.warning(f'⚠️  Immediate rotation failed: {e}')
            logging.warning(f'   Password will sync on next scheduled rotation')
            return False  # Graceful degradation

    def _create_login_record(
        self,
        config: Dict[str, Any],
        password: str,
        params: KeeperParams
    ) -> str:
        """
        Create Login record for sharing employee credentials.

        This record is created in the admin's personal vault and can be
        shared with appropriate parties (manager, IT admin, etc.).

        Args:
            config: Configuration dict
            password: Generated password
            params: KeeperParams session

        Returns:
            Login record UID

        Raises:
            CommandError: If Login record creation fails
        """
        try:
            # Build employee name
            first_name = config['user']['first_name']
            last_name = config['user']['last_name']
            full_name = f'{first_name} {last_name}'
            username = config['account']['username']

            # Create Login typed record
            login_record = vault.TypedRecord()
            login_record.record_type = 'login'

            # Set fields
            login_record.title = f'Corporate Account - {full_name}'
            login_record.login = username
            login_record.password = password

            # Build notes with employee info
            notes_lines = [
                'Employee Credential Information',
                '=' * 40,
                f'Employee: {full_name}',
                f'Username: {username}',
                f'Email: {config["user"]["email"]}',
                '',
                '⚠️  NOTE: This password is PAM-managed.',
                '   It will rotate automatically per schedule.',
                '   Always use the current password from vault.',
                '',
                f'Rotation Schedule: {config["pam"]["rotation"]["schedule"]}',
                f'Password Complexity: {config["pam"]["rotation"]["password_complexity"]}',
            ]
            login_record.notes = '\n'.join(notes_lines)

            # Create record in vault
            record_uid = vault.KeeperRecord.create(params, login_record)

            logging.info(f'✅ Login record created')
            logging.debug(f'   Record UID: {record_uid}')
            logging.debug(f'   Title: {login_record.title}')

            return record_uid

        except Exception as e:
            logging.error(f'Failed to create Login record: {e}')
            raise CommandError('credential-provision', f'Login record creation failed: {e}')

    def _generate_share_url(
        self,
        login_record_uid: str,
        config: Dict[str, Any],
        params: KeeperParams
    ) -> str:
        """
        Generate one-time share URL for Login record.

        Args:
            login_record_uid: UID of Login record to share
            config: Configuration dict (contains expiry settings)
            params: KeeperParams session

        Returns:
            Share URL string

        Raises:
            CommandError: If share URL generation fails
        """
        # Parse expiry (e.g., "7d" = 7 days)
        expiry_str = config.get('email', {}).get('share_url_expiry', '7d')
        expiry_seconds = self._parse_expiry(expiry_str)

        try:
            # Generate share URL using internal helper
            # NOTE: Extracts logic from OneTimeShareCreateCommand (commands/register.py)
            share_url = self._generate_share_url_internal(
                login_record_uid=login_record_uid,
                expiry_seconds=expiry_seconds,
                params=params
            )

            logging.info('✅ Generated one-time share URL')
            logging.info(f'   Expires: {expiry_str}')
            logging.info(f'   Max uses: 1 (single-use)')

            return share_url

        except Exception as e:
            logging.error(f'Failed to generate share URL: {e}')
            raise CommandError('credential-provision', f'Share URL generation failed: {e}')

    def _generate_share_url_internal(
        self,
        login_record_uid: str,
        expiry_seconds: int,
        params: KeeperParams
    ) -> str:
        """
        Generate one-time share URL for Login record.

        This extracts the core logic from OneTimeShareCreateCommand
        (keepercommander/commands/register.py lines 2365-2430).

        Resolution: BLOCKER_KC-1007-5_Share-URL-API-Missing_2025-11-17
        Decided to extract logic rather than create shared api.create_share_url()
        to stay within scope of KC-1007. Can be refactored later if needed.

        Args:
            login_record_uid: UID of Login record to share
            expiry_seconds: Seconds until share expires
            params: KeeperParams session

        Returns:
            Share URL string

        Raises:
            ValueError: If record not found
            Exception: If share creation fails
        """
        from keepercommander import api, utils, crypto
        from keepercommander.proto import APIRequest_pb2
        from urllib.parse import urlunparse, urlparse

        # Get record key
        if login_record_uid not in params.record_cache:
            raise ValueError(f'Login record not found: {login_record_uid}')

        record_key = params.record_cache[login_record_uid]['record_key_unencrypted']

        # Generate client keys (from OneTimeShareCreateCommand)
        client_key = utils.generate_aes_key()
        client_id = crypto.hmac_sha512(client_key, 'KEEPER_SECRETS_MANAGER_CLIENT_ID'.encode())

        # Create share request
        rq = APIRequest_pb2.AddExternalShareRequest()
        rq.recordUid = utils.base64_url_decode(login_record_uid)
        rq.encryptedRecordKey = crypto.encrypt_aes_v2(record_key, client_key)
        rq.clientId = client_id
        rq.accessExpireOn = utils.current_milli_time() + int(expiry_seconds * 1000)

        # Send request
        api.communicate_rest(params, rq, 'vault/external_share_add', rs_type=APIRequest_pb2.Device)

        # Build URL
        parsed = urlparse(params.server)
        server_netloc = parsed.netloc if parsed.netloc else parsed.path
        url = urlunparse(('https', server_netloc, '/vault/share/', None, None, utils.base64_url_encode(client_key)))

        logging.debug(f'Generated share URL: {url[:50]}... (expires in {expiry_seconds}s)')

        return str(url)

    def _parse_expiry(self, expiry_str: str) -> int:
        """
        Parse expiry string to seconds.

        Supported formats:
        - "7d" = 7 days
        - "24h" = 24 hours
        - "60m" = 60 minutes

        Args:
            expiry_str: Expiry string (e.g., "7d")

        Returns:
            Seconds

        Raises:
            ValueError: If format invalid
        """
        import re

        match = re.match(r'^(\d+)([dhm])$', expiry_str)
        if not match:
            # Default to 7 days
            logging.warning(f'Invalid expiry format: {expiry_str}, using 7d')
            return 7 * 24 * 60 * 60

        value = int(match.group(1))
        unit = match.group(2)

        if unit == 'd':
            return value * 24 * 60 * 60
        elif unit == 'h':
            return value * 60 * 60
        elif unit == 'm':
            return value * 60

        return 7 * 24 * 60 * 60  # Default 7 days

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
        from keepercommander.commands import email_commands

        # Find email config by name
        record_uid = email_commands.find_email_config_by_name(params, config_name)

        if not record_uid:
            raise CommandError('credential-provision', f'Email config not found: {config_name}')

        # Load email config from record
        try:
            email_config = email_commands.load_email_config_from_record(params, record_uid)
            logging.debug(f'Loaded email config: {config_name}')
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
        from keepercommander.email_service import EmailSender, build_onboarding_email

        email_config_name = config['email']['config_name']
        send_to = config['email'].get('send_to', 'personal')
        subject = config['email'].get('subject', 'Welcome - Your Account Credentials')

        # Load email configuration
        try:
            email_config = self._load_email_config(email_config_name, params)
        except Exception as e:
            logging.warning(f'⚠️  Failed to load email config: {e}')
            return False

        # Determine recipient(s)
        recipients = []
        if send_to == 'personal':
            recipients.append(config['user']['personal_email'])
        elif send_to == 'corporate':
            corporate_email = config['user'].get('corporate_email')
            if not corporate_email:
                logging.error('corporate_email not specified in config')
                return False
            recipients.append(corporate_email)
        elif send_to == 'both':
            recipients.append(config['user']['personal_email'])
            corporate_email = config['user'].get('corporate_email')
            if corporate_email:
                recipients.append(corporate_email)
        else:
            logging.error(f'Invalid send_to value: {send_to}')
            return False

        # Build email body using existing template
        user = config['user']
        custom_message = config['email'].get(
            'custom_message',
            f"Welcome to the team, {user['first_name']}! Your corporate account credentials are ready."
        )
        record_title = f"Corporate Account - {user['first_name']} {user['last_name']}"
        expiration = config['email'].get('share_url_expiry', '7 days')

        body = build_onboarding_email(
            share_url=share_url,
            custom_message=custom_message,
            record_title=record_title,
            expiration=expiration
        )

        # Send email to each recipient
        try:
            sender = EmailSender(email_config)

            for recipient in recipients:
                sender.send(recipient, subject, body, html=True)
                logging.info(f'✅ Email sent to: {recipient}')

            return True

        except Exception as e:
            logging.warning(f'⚠️  Email sending failed: {e}')
            logging.info(f'Manual delivery required - share URL: {share_url}')
            return False

    # =========================================================================
    # KC-1007-6: Rollback Logic
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
        from keepercommander import api

        rollback_errors = []

        logging.info('Rolling back provisioning changes...')

        # Delete Login record (if created)
        if state.login_record_uid:
            try:
                api.delete_record(params, state.login_record_uid)
                logging.info('✅ Rollback: Deleted Login record')
            except Exception as e:
                rollback_errors.append(f'Login record: {e}')
                logging.error(f'⚠️  Rollback failed for Login record: {e}')

        # Delete PAM User (also should remove DAG links automatically)
        if state.pam_user_uid:
            try:
                api.delete_record(params, state.pam_user_uid)
                logging.info('✅ Rollback: Deleted PAM User')
            except Exception as e:
                rollback_errors.append(f'PAM User: {e}')
                logging.error(f'⚠️  Rollback failed for PAM User: {e}')

        # Log rollback summary
        if rollback_errors:
            logging.error('\n' + '='*60)
            logging.error('⚠️  ROLLBACK COMPLETED WITH ERRORS')
            logging.error('='*60)
            logging.error('Some resources could not be automatically cleaned up:')
            for error in rollback_errors:
                logging.error(f'   • {error}')
            logging.error('\nManual cleanup may be required.')
            logging.error('Check your vault for orphaned records.')
            logging.error('='*60 + '\n')
        else:
            logging.info('\n' + '='*60)
            logging.info('✅ ROLLBACK COMPLETED SUCCESSFULLY')
            logging.info('='*60)
            logging.info('All created resources have been cleaned up.')
            logging.info('='*60 + '\n')
