#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""
Core setup logic for Docker-based integrations.

This module provides the reusable base class for setting up
Commander Service Mode with Docker and KSM.
"""

import io
import json
import logging
import os
import sys
import tempfile
import uuid
from typing import Any, Dict, Optional, Tuple

from ...commands.ksm import KSMCommand
from ... import api, vault, utils, crypto, attachment, record_management, loginv3
from ...display import bcolors
from ...error import CommandError, KeeperApiError

from .models import DockerLoginMode, DockerSetupConstants, SetupResult, SetupStep
from .printer import DockerSetupPrinter
from .federated_setup import (
    FederatedSetupOptions,
    create_federated_config,
    keeper_token_audience,
    remove_managed_login_artifacts,
    remove_managed_federated_clients,
    remove_managed_federated_client,
    read_jwt_claims,
    upload_federated_artifacts,
)
from ..config.record_handler import RecordHandler


class DockerSetupBase:
    """Base class for Docker setup with reusable core logic"""

    @staticmethod
    def add_login_flow_arguments(parser) -> None:
        """Add the common login-flow arguments to a Docker setup parser."""
        parser.add_argument(
            '--login-flow',
            choices=[mode.value for mode in DockerLoginMode],
            help=(
                'Service Mode login: ksm (Commander config.json) or oidc (federated OIDC); '
                'if omitted, prompt interactively'
            ),
        )
        parser.add_argument(
            '--oidc-token-file',
            dest='oidc_token_file',
            help='Path to an OIDC JWT file (required for --login-flow oidc)',
        )
        parser.add_argument(
            '--oidc-issuer',
            dest='oidc_issuer',
            help='Expected OIDC issuer (defaults to the JWT iss claim)',
        )
        parser.add_argument(
            '--oidc-subject',
            dest='oidc_subject',
            help='Expected OIDC subject (defaults to the JWT sub claim)',
        )
        parser.add_argument(
            '--oidc-jwks-uri',
            dest='oidc_jwks_uri',
            help='Optional issuer JWKS URI (blank uses OIDC discovery)',
        )

    @staticmethod
    def _select_login_mode(login_flow: Optional[str], command_name: str) -> DockerLoginMode:
        if login_flow:
            try:
                return DockerLoginMode(login_flow)
            except ValueError:
                raise CommandError(command_name, f'Unsupported login flow: {login_flow}')

        DockerSetupPrinter.print_header('Config Setup')
        print(f'{bcolors.BOLD}1. Commander config.json{bcolors.ENDC}')
        print(
            '  Downloads config.json from the Keeper record and uses it to log in to Service Mode.'
        )
        print(f'\n{bcolors.BOLD}2. Federated OIDC{bcolors.ENDC}')
        print(
            '  Uses a provider JWT and federated config to create the Keeper session.'
        )
        while True:
            prompt = (
                f'{bcolors.OKBLUE}Select Service Mode login? '
                f'[Press Enter for 1] (1/2):{bcolors.ENDC} '
            )
            choice = input(prompt).strip().lower()
            if not choice or choice == '1':
                return DockerLoginMode.KSM
            if choice == '2':
                return DockerLoginMode.OIDC
            print('Please enter 1 or 2.')

    @staticmethod
    def collect_login_options(
        login_flow: Optional[str] = None,
        oidc_token_file: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
        oidc_subject: Optional[str] = None,
        oidc_jwks_uri: Optional[str] = None,
        command_name: str = 'docker-setup',
        default_oidc_token_file: Optional[str] = None,
        keeper_server: Optional[str] = None,
    ) -> Tuple[DockerLoginMode, Optional[FederatedSetupOptions]]:
        """Resolve login mode and validate OIDC input before provisioning resources."""
        login_mode = DockerSetupBase._select_login_mode(login_flow, command_name)
        if login_mode is DockerLoginMode.KSM:
            if any((oidc_token_file, oidc_issuer, oidc_subject, oidc_jwks_uri)):
                raise CommandError(
                    command_name,
                    'OIDC-specific options require --login-flow oidc',
                )
            return login_mode, None

        print(f'\n{bcolors.BOLD}OIDC JWT{bcolors.ENDC}')
        print('  Provide a provider-issued JWT; Keeper uses it to validate federated login.')
        token_input = oidc_token_file
        if not token_input:
            default_token = default_oidc_token_file or os.path.join(
                str(utils.get_default_path()), DockerSetupConstants.OIDC_TOKEN_FILENAME
            )
            default_token = os.path.abspath(os.path.expanduser(default_token))
            prompt = (
                f'{bcolors.OKBLUE}JWT file path? [Press Enter for {default_token}]:'
                f'{bcolors.ENDC} '
            )
            token_input = input(prompt).strip() or default_token
        token_path = os.path.abspath(os.path.expanduser(token_input))
        expected_audience = None
        if keeper_server:
            try:
                expected_audience = keeper_token_audience(keeper_server)
            except (TypeError, ValueError) as e:
                raise CommandError(command_name, f'Unable to determine Keeper token audience: {e}')
        claims = read_jwt_claims(token_path, command_name, expected_audience)

        issuer_default = claims.get('iss')
        subject_default = claims.get('sub')
        oidc_issuer = (oidc_issuer or '').strip()
        oidc_subject = (oidc_subject or '').strip()
        if not oidc_issuer and not issuer_default:
            print(f'\n{bcolors.BOLD}OIDC Issuer{bcolors.ENDC}')
            print('  The JWT issuer URL.')
            oidc_issuer = input(f'{bcolors.OKBLUE}Issuer?{bcolors.ENDC} ').strip()
        issuer = oidc_issuer or issuer_default or ''
        if not oidc_subject and not subject_default:
            print(f'\n{bcolors.BOLD}OIDC Subject{bcolors.ENDC}')
            print('  The identity represented by the JWT.')
            oidc_subject = input(f'{bcolors.OKBLUE}Subject?{bcolors.ENDC} ').strip()
        subject = oidc_subject or subject_default or ''
        if not issuer:
            raise CommandError(command_name, 'OIDC issuer is required')
        if not subject:
            raise CommandError(command_name, 'OIDC subject is required')
        if issuer_default and issuer != issuer_default:
            raise CommandError(
                command_name,
                'The configured OIDC issuer must exactly match the JWT iss claim',
            )
        if subject_default and subject != subject_default:
            raise CommandError(
                command_name,
                'The configured OIDC subject must exactly match the JWT sub claim',
            )

        if oidc_jwks_uri is None:
            print(f'\n{bcolors.BOLD}OIDC JWKS URI (optional){bcolors.ENDC}')
            print(
                '  Optional signing-key URL; Keeper registers it when supplied.'
            )
            oidc_jwks_uri = input(
                f'{bcolors.OKBLUE}JWKS URI? [Press Enter for issuer discovery]:'
                f'{bcolors.ENDC} '
            ).strip()
        else:
            oidc_jwks_uri = oidc_jwks_uri.strip()

        return login_mode, FederatedSetupOptions(
            token_path=token_path,
            issuer=issuer,
            subject=subject,
            jwks_uri=oidc_jwks_uri or None,
        )

    @staticmethod
    def _is_owned_record(params, record_uid: str) -> bool:
        """True when record_owner_cache marks the record as owned by this account."""
        if not record_uid:
            return False
        owner_cache = getattr(params, 'record_owner_cache', None) or {}
        owner = owner_cache.get(record_uid)
        return bool(owner and owner.owner)

    @staticmethod
    def _is_owned_shared_folder(params, folder_uid: str) -> bool:
        """True when the shared folder is owned by the current account."""
        if not folder_uid:
            return False
        shared_folder = (getattr(params, 'shared_folder_cache', None) or {}).get(folder_uid)
        if not shared_folder:
            return False

        owner_uid = shared_folder.get('owner_account_uid')
        account_uid_bytes = getattr(params, 'account_uid_bytes', None)
        if owner_uid and account_uid_bytes:
            return owner_uid == utils.base64_url_encode(account_uid_bytes)

        owner_username = shared_folder.get('owner_username')
        if owner_username and getattr(params, 'user', None):
            return owner_username.lower() == params.user.lower()
        return False

    @staticmethod
    def _find_owned_ksm_app_by_title(params, app_name: str):
        """Return an owned KSM app with this title, or None (ignores non-owned squats)."""
        if not app_name:
            return None
        for rec_cache_val in (getattr(params, 'record_cache', None) or {}).values():
            rec = KSMCommand._app_record_from_cache_entry(rec_cache_val)
            if not rec:
                continue
            try:
                title = json.loads(rec['data_unencrypted'].decode('utf-8')).get('title')
            except Exception:
                continue
            if title == app_name and DockerSetupBase._is_owned_record(params, rec.get('record_uid')):
                return rec
        return None

    @staticmethod
    def resolve_commander_config_path(config_path: str = None, params=None) -> str:
        """Resolve config.json using the same rules as login/shell startup."""
        if config_path:
            resolved = os.path.expanduser(config_path)
        elif params and getattr(params, 'config_filename', None):
            resolved = os.path.expanduser(params.config_filename)
        else:
            resolved = str(utils.get_default_path() / 'config.json')
        return os.path.abspath(resolved)

    @staticmethod
    def _require_commander_config_file(command_name: str, config_path: str = None, params=None) -> str:
        resolved = DockerSetupBase.resolve_commander_config_path(config_path, params)
        if not os.path.isfile(resolved):
            raise CommandError(command_name, f'Config file not found: {resolved}')
        return resolved

    @staticmethod
    def _require_file_based_config(params, command_name: str) -> None:
        """Raise CommandError if credentials are in the OS keychain rather than config.json."""
        from ...config_storage.loader import CONFIG_STORAGE_URL, _is_os_keychain_url
        config_storage = params.config.get(CONFIG_STORAGE_URL, '') if isinstance(params.config, dict) else ''
        if _is_os_keychain_url(config_storage):
            raise CommandError(
                command_name,
                f'{bcolors.FAIL}{bcolors.BOLD}Error:{bcolors.ENDC} '
                f'{bcolors.FAIL}This command requires credentials to be stored in config.json, '
                f'but they are currently stored in the OS keychain.{bcolors.ENDC}\n\n'
                f'{bcolors.OKBLUE}Please re-login with the --config-file flag first:{bcolors.ENDC}\n\n'
                f'    {bcolors.OKGREEN}login --config-file{bcolors.ENDC}    '
                f'{bcolors.OKGREEN}(or: keeper shell --config-file){bcolors.ENDC}\n\n'
                f'Then re-run this command.'
            )

    def run_setup_steps(self, params, folder_name: str, app_name: str, record_name: str,
                       config_path: str, timeout: str, skip_device_setup: bool = False,
                       login_mode: DockerLoginMode = DockerLoginMode.KSM,
                       federated_options: Optional[FederatedSetupOptions] = None,
                       command_name: str = 'docker-setup') -> SetupResult:
        """
        Core setup steps that can be reused by integration commands.
        Returns a SetupResult object containing all the created resources.
        """
        if login_mode is DockerLoginMode.OIDC and not RecordHandler.has_file_storage(params):
            raise CommandError(
                command_name,
                'Federated OIDC setup requires Keeper file storage to upload federated-config.json '
                'and the OIDC JWT as record attachments.',
            )
        if login_mode is DockerLoginMode.OIDC and not federated_options:
            raise CommandError(command_name, 'OIDC login options were not supplied')
        if login_mode is DockerLoginMode.OIDC:
            try:
                token_is_commander_config = os.path.samefile(
                    federated_options.token_path, config_path
                )
            except OSError:
                token_is_commander_config = (
                    os.path.realpath(federated_options.token_path)
                    == os.path.realpath(config_path)
                )
            if token_is_commander_config:
                raise CommandError(
                    command_name,
                    'The OIDC JWT file must be separate from your local Commander config.json',
                )

        # Total number of steps
        total_steps = len(SetupStep)
        
        # OIDC containers authenticate with a federated client and do not use
        # the local Commander device token or persistent-login settings.
        if login_mode is DockerLoginMode.OIDC:
            DockerSetupPrinter.print_step(
                SetupStep.DEVICE_SETUP.value,
                total_steps,
                'Skipping device setup (not used by federated login)...',
            )
        elif not skip_device_setup:
            DockerSetupPrinter.print_step(SetupStep.DEVICE_SETUP.value, total_steps, "Checking device settings...")
            self._setup_device(params, timeout)
        else:
            DockerSetupPrinter.print_step(SetupStep.DEVICE_SETUP.value, total_steps, "Skipping device setup (--skip-device-setup)")

        # Step 2: Create shared folder
        DockerSetupPrinter.print_step(SetupStep.CREATE_FOLDER.value, total_steps, f"Creating shared folder '{folder_name}'...")
        folder_uid = self._create_shared_folder(params, folder_name)

        # Step 3: Create config record
        DockerSetupPrinter.print_step(SetupStep.CREATE_RECORD.value, total_steps, f"Creating record '{record_name}'...")
        record_uid = self._create_config_record(params, record_name, folder_uid)

        # Step 4: Create KSM app
        DockerSetupPrinter.print_step(SetupStep.CREATE_KSM_APP.value, total_steps, f"Creating Secrets Manager app '{app_name}'...")
        app_uid = self._create_ksm_app(params, app_name)

        # Step 5: Share folder with app
        DockerSetupPrinter.print_step(SetupStep.SHARE_FOLDER.value, total_steps, "Sharing folder with app...")
        self._share_folder_with_app(params, app_uid, folder_uid)

        # Step 6: Create KSM client device used to bootstrap record access.
        DockerSetupPrinter.print_step(SetupStep.CREATE_CLIENT.value, total_steps, "Creating client device and generating config...")
        b64_config = self._create_client_device(params, app_uid, app_name)

        # Step 7: Store only the selected runtime login artifacts.
        if login_mode is DockerLoginMode.OIDC:
            DockerSetupPrinter.print_step(
                SetupStep.STORE_LOGIN_ARTIFACTS.value,
                total_steps,
                'Registering federated login and uploading OIDC artifacts...',
            )
            federated_config_path = None
            client_name = None
            try:
                federated_config_path, client_name = create_federated_config(
                    params,
                    app_uid,
                    federated_options,
                    command_name,
                    output_dir=os.path.dirname(config_path),
                )
                upload_federated_artifacts(
                    params,
                    record_uid,
                    federated_config_path,
                    federated_options.token_path,
                    command_name,
                )
                try:
                    remove_managed_federated_clients(
                        params, app_uid, keep_client_name=client_name
                    )
                except Exception as cleanup_error:
                    DockerSetupPrinter.print_warning(
                        f'Could not revoke previous setup-managed federated client(s): {cleanup_error}'
                    )
            except Exception:
                if client_name:
                    try:
                        remove_managed_federated_client(params, app_uid, client_name)
                    except Exception as cleanup_error:
                        logging.warning(
                            'Could not revoke federated client %s after setup failure: %s',
                            client_name,
                            cleanup_error,
                        )
                raise
            finally:
                if federated_config_path and os.path.exists(federated_config_path):
                    try:
                        os.unlink(federated_config_path)
                    except OSError as cleanup_error:
                        logging.warning(
                            'Could not remove generated federated config at %s: %s',
                            federated_config_path,
                            cleanup_error,
                        )
            cleanup_paths = [federated_options.token_path]
        else:
            DockerSetupPrinter.print_step(
                SetupStep.STORE_LOGIN_ARTIFACTS.value, total_steps, 'Storing config.json...'
            )
            self._upload_config_file(params, record_uid, config_path)
            try:
                remove_managed_federated_clients(params, app_uid)
            except Exception as cleanup_error:
                DockerSetupPrinter.print_warning(
                    f'Could not revoke previous setup-managed federated client(s): {cleanup_error}'
                )
            cleanup_paths = []

        return SetupResult(
            folder_uid=folder_uid,
            folder_name=folder_name,
            app_uid=app_uid,
            app_name=app_name,
            record_uid=record_uid,
            b64_config=b64_config,
            login_mode=login_mode,
            cleanup_paths=cleanup_paths,
        )

    # ========================
    # Core Setup Methods
    # ========================

    def _setup_device(self, params, timeout: str) -> None:
        """Check and setup device registration, persistent login, and timeout"""
        from ...commands.utils import ThisDeviceCommand
        
        try:
            device_info = ThisDeviceCommand.get_device_info(params)
            
            # Device registration
            if not device_info.get('data_key_present', False):
                DockerSetupPrinter.print_warning("Device not registered")
                loginv3.LoginV3API.register_encrypted_data_key_for_device(params)
                DockerSetupPrinter.print_success("Device registered successfully")
            else:
                DockerSetupPrinter.print_success("Device already registered")

            # Persistent login
            if not device_info.get('persistent_login', False):
                DockerSetupPrinter.print_warning("Persistent login disabled")
                loginv3.LoginV3API.set_user_setting(params, 'persistent_login', '1')
                DockerSetupPrinter.print_success("Persistent login enabled")
            else:
                DockerSetupPrinter.print_success("Persistent login already enabled")

            # Timeout
            DockerSetupPrinter.print_success(f"Setting logout timeout to {timeout}...")
            # Suppress command output
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                ThisDeviceCommand().execute(params, ops=['timeout', timeout])
            finally:
                sys.stdout = old_stdout

        except Exception as e:
            raise CommandError('docker-setup', f'Device setup failed: {str(e)}')

    @staticmethod
    def _add_owned_shared_folder(params, folder_name: str) -> str:
        """Create a root-level shared folder via folder_add (allows duplicate display names).

        Bypasses FolderMakeCommand/mkdir, which refuses to create when any visible
        folder already has the same name — including a non-owned squat.
        """
        name = (folder_name or '').strip()
        if not name:
            raise CommandError('docker-setup', 'Shared folder name is required')
        if not getattr(params, 'data_key', None):
            raise CommandError('docker-setup', 'Not logged in (missing data key)')

        folder_uid = api.generate_record_uid()
        folder_key = utils.generate_aes_key()
        request = {
            'command': 'folder_add',
            'folder_type': 'shared_folder',
            'folder_uid': folder_uid,
            'key': utils.base64_url_encode(crypto.encrypt_aes_v1(folder_key, params.data_key)),
            'name': utils.base64_url_encode(crypto.encrypt_aes_v1(name.encode('utf-8'), folder_key)),
            'data': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'name': name}).encode('utf-8'), folder_key)
            ),
            'manage_users': True,
            'manage_records': True,
            'can_share': True,
            'can_edit': True,
        }
        api.communicate(params, request)
        params.sync_data = True
        return folder_uid

    def _create_shared_folder(self, params, folder_name: str) -> str:
        """Create a shared folder, or reuse one owned by this account with the same name."""
        saw_non_owned = False
        for folder_uid, folder in (params.folder_cache or {}).items():
            if folder.name != folder_name or folder_uid not in (params.shared_folder_cache or {}):
                continue
            if self._is_owned_shared_folder(params, folder_uid):
                DockerSetupPrinter.print_success(f"Using existing shared folder (UID: {folder_uid})")
                return folder_uid
            saw_non_owned = True

        if saw_non_owned:
            DockerSetupPrinter.print_warning(
                f"Ignoring shared folder(s) named '{folder_name}' owned by another account; "
                f"creating a new owned folder"
            )

        try:
            folder_uid = self._add_owned_shared_folder(params, folder_name)
            api.sync_down(params)
            DockerSetupPrinter.print_success(f"Shared folder created successfully (UID: {folder_uid})")
            return folder_uid
        except CommandError:
            raise
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to create shared folder: {str(e)}')

    def _create_config_record(self, params, record_name: str, folder_uid: str) -> str:
        """Create a config record, or reuse an owned one with the same title in the folder."""
        saw_non_owned = False
        for rec_uid in (params.subfolder_record_cache or {}).get(folder_uid, []):
            rec = api.get_record(params, rec_uid)
            if rec.title != record_name:
                continue
            if self._is_owned_record(params, rec_uid):
                DockerSetupPrinter.print_success("Using existing record")
                return rec_uid
            saw_non_owned = True

        if saw_non_owned:
            DockerSetupPrinter.print_warning(
                f"Ignoring record(s) titled '{record_name}' owned by another account; "
                f"creating a new owned record"
            )

        try:
            record = vault.KeeperRecord.create(params, 'login')
            record.record_uid = utils.generate_uid()
            record.record_key = utils.generate_aes_key()
            record.title = record_name
            record.type_name = 'login'

            record_management.add_record_to_folder(params, record, folder_uid)
            api.sync_down(params)

            DockerSetupPrinter.print_success(f"Record created successfully (UID: {record.record_uid})")
            return record.record_uid
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to create record: {str(e)}')

    def _upload_config_file(self, params, record_uid: str, config_path: str) -> None:
        """Upload config.json as attachment, or store as custom field if no file storage plan.
        
        """
        temp_config_path = None
        try:
            cleaned_config_path = self._clean_config_json(config_path)
            if cleaned_config_path != config_path:
                temp_config_path = cleaned_config_path

            if RecordHandler.has_file_storage(params):
                self._upload_config_as_attachment(params, record_uid, cleaned_config_path)
            else:
                self._store_config_as_custom_field(params, record_uid, cleaned_config_path)
        except CommandError:
            raise
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to store config file: {str(e)}')
        finally:
            if temp_config_path and os.path.exists(temp_config_path):
                try:
                    os.unlink(temp_config_path)
                except OSError:
                    pass

    def _upload_config_as_attachment(self, params, record_uid: str, config_path: str) -> None:
        """Upload config.json as a file attachment (requires file storage plan)."""
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('docker-setup', 'Invalid record type for attachments')
        remove_managed_login_artifacts(record, params)

        upload_task = attachment.FileUploadTask(config_path)
        upload_task.name = 'config.json'
        upload_task.title = 'config.json'

        attachment.upload_attachments(params, record, [upload_task])
        record_management.update_record(params, record)
        params.sync_data = True
        api.sync_down(params)

        DockerSetupPrinter.print_success("Config file uploaded as attachment")

    def _store_config_as_custom_field(self, params, record_uid: str, config_path: str) -> None:
        """Store config.json content as a custom field (fallback when no file storage plan)."""
        with open(config_path, 'r') as f:
            config_content = f.read()

        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('docker-setup', 'Invalid record type')

        remove_managed_login_artifacts(record, params)
        if record.custom is None:
            record.custom = []
        record.custom.append(vault.TypedField.new_field('secret', config_content, 'config_json'))

        record_management.update_record(params, record)
        params.sync_data = True
        api.sync_down(params)

        DockerSetupPrinter.print_success("Config stored as custom field (no file storage plan)")

    def _clean_config_json(self, config_path: str) -> str:
        """Clean config.json by keeping only essential authentication keys"""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            # Essential keys for authentication
            essential_keys = {
                'server', 'user', 'device_token', 'private_key',
                'device_id', 'clone_code', 'session_token', 'data_key'
            }
            
            cleaned_config = {k: v for k, v in config_data.items() if k in essential_keys}
            removed_count = len(config_data) - len(cleaned_config)
            
            if removed_count > 0:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                    json.dump(cleaned_config, tmp_file, indent=2)
                    temp_path = tmp_file.name
                
                DockerSetupPrinter.print_success(
                    f"Config cleaned (kept {len(cleaned_config)} essential keys, removed {removed_count} non-essential)"
                )
                return temp_path
            else:
                DockerSetupPrinter.print_success("Config is already minimal")
                return config_path
                
        except Exception as e:
            DockerSetupPrinter.print_warning(f"Could not clean config: {str(e)}")
            return config_path

    def _create_ksm_app(self, params, app_name: str) -> str:
        """Create a KSM app, or reuse an owned app with the same title."""
        existing_app = self._find_owned_ksm_app_by_title(params, app_name)
        if existing_app:
            DockerSetupPrinter.print_success("Using existing app")
            return existing_app.get('record_uid')

        existing_any = KSMCommand.get_app_record(params, app_name)
        force_to_add = False
        if existing_any:
            existing_uid = existing_any.get('record_uid')
            if self._is_owned_record(params, existing_uid):
                DockerSetupPrinter.print_success("Using existing app")
                return existing_uid
            force_to_add = True
            DockerSetupPrinter.print_warning(
                f"Ignoring Secrets Manager app '{app_name}' owned by another account; "
                f"creating a new owned app"
            )

        try:
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                KSMCommand.add_new_v5_app(
                    params, app_name, force_to_add=force_to_add, format_type='table'
                )
            finally:
                sys.stdout = old_stdout

            api.sync_down(params)

            app_rec = self._find_owned_ksm_app_by_title(params, app_name)
            if not app_rec:
                raise CommandError('docker-setup', 'Failed to retrieve created app')

            app_uid = app_rec.get('record_uid')
            DockerSetupPrinter.print_success(f"App created successfully (UID: {app_uid})")
            return app_uid
        except CommandError:
            raise
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to create KSM app: {str(e)}')

    def _share_folder_with_app(self, params, app_uid: str, folder_uid: str) -> None:
        """Share the folder with the KSM app"""
        try:
            app_rec = KSMCommand.get_app_record(params, app_uid)
            if not app_rec:
                raise CommandError('docker-setup', 'App not found')

            # Suppress all output (stdout and logging)
            old_stdout = sys.stdout
            old_log_level = logging.root.level
            
            sys.stdout = io.StringIO()
            logging.root.setLevel(logging.CRITICAL + 1)  # Disable all logging
            try:
                KSMCommand.add_app_share(
                    params,
                    secret_uids=[folder_uid],
                    app_name_or_uid=app_uid,
                    is_editable=True
                )
            finally:
                sys.stdout = old_stdout
                logging.root.setLevel(old_log_level)     
            DockerSetupPrinter.print_success("Folder shared with app")
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to share folder with app: {str(e)}')

    def _create_client_device(self, params, app_uid: str, app_name: str) -> str:
        """Create client device and return b64 config"""
        try:
            default_client_name = DockerSetupConstants.DEFAULT_CLIENT_NAME

            def get_client_names():
                app_info = KSMCommand.get_app_info(params, app_uid)
                return {
                    client.id
                    for info in app_info
                    for client in info.clients
                    if getattr(client, 'id', '')
                }

            def get_unique_client_name(existing_names):
                for _ in range(5):
                    candidate = f'{default_client_name} {uuid.uuid4().hex[:8]}'
                    if candidate not in existing_names:
                        return candidate
                raise CommandError(
                    'docker-setup',
                    'Could not find an unused KSM client name after multiple attempts',
                )

            def add_client(name):
                return KSMCommand.add_client(
                    params=params,
                    app_name_or_uid=app_uid,
                    count=1,
                    unlock_ip=True,
                    first_access_expire_on=60,
                    access_expire_in_min=None,
                    client_name=name,
                    config_init='b64',
                    silent=True
                )

            existing_names = get_client_names()
            client_name = default_client_name
            if client_name in existing_names:
                client_name = get_unique_client_name(existing_names)
                DockerSetupPrinter.print_warning(
                    'A client with the default name already exists; using a unique name'
                )

            try:
                tokens_and_devices = add_client(client_name)
            except KeeperApiError as e:
                if e.result_code != 'duplicate_app_client_name':
                    raise

                # The request may have succeeded despite the duplicate response, or
                # another setup may have created this name concurrently. Refresh the
                # app state before retrying so we never blindly create another device.
                current_names = get_client_names()
                if client_name in current_names:
                    raise CommandError(
                        'docker-setup',
                        f'KSM reports a duplicate client name and "{client_name}" now '
                        'exists. Skipping retry to avoid creating a duplicate client device.',
                    )

                # Also reserve the attempted name in case the API state has not
                # reflected a successfully created client yet.
                client_name = get_unique_client_name(current_names | {client_name})
                DockerSetupPrinter.print_warning(
                    'KSM reported a duplicate client name; retrying with a verified unique name'
                )
                try:
                    tokens_and_devices = add_client(client_name)
                except KeeperApiError as retry_error:
                    if retry_error.result_code == 'duplicate_app_client_name':
                        retry_names = get_client_names()
                        if client_name in retry_names:
                            raise CommandError(
                                'docker-setup',
                                f'KSM reports that "{client_name}" exists after the retry. '
                                'Skipping further retries to avoid duplicate client devices.',
                            )
                    raise
            
            if not tokens_and_devices or len(tokens_and_devices) == 0:
                raise CommandError('docker-setup', 'Failed to generate client device')

            b64_config = tokens_and_devices[0]['config']
            DockerSetupPrinter.print_success("Client device created successfully")
            
            return b64_config
        except CommandError:
            raise
        except Exception as e:
            raise CommandError('docker-setup', f'Failed to create client device: {str(e)}')

    # ========================
    # Shared Configuration Methods
    # ========================

    def _get_ngrok_config(self) -> Dict[str, Any]:
        """Get ngrok configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}Ngrok Tunneling (optional):{bcolors.ENDC}")
        print(f"  Generate a public URL for your service using ngrok")
        use_ngrok = input(f"{bcolors.OKBLUE}Enable ngrok? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'ngrok_enabled': use_ngrok, 'ngrok_auth_token': '', 'ngrok_custom_domain': '', 'ngrok_public_url': ''}
        
        if use_ngrok:
            while True:
                token = input(f"{bcolors.OKBLUE}Ngrok auth token:{bcolors.ENDC} ").strip()
                try:
                    config['ngrok_auth_token'] = ConfigValidator.validate_ngrok_token(token)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            
            # Validate custom domain if provided (ngrok allows subdomain prefixes)
            domain = input(f"{bcolors.OKBLUE}Ngrok custom domain [Press Enter to skip]:{bcolors.ENDC} ").strip()
            if domain:
                while True:
                    try:
                        config['ngrok_custom_domain'] = ConfigValidator.validate_domain(domain, require_tld=False)
                        # Construct ngrok public URL
                        if '.' not in config['ngrok_custom_domain']:
                            config['ngrok_public_url'] = f"https://{config['ngrok_custom_domain']}.ngrok.io"
                        else:
                            config['ngrok_public_url'] = f"https://{config['ngrok_custom_domain']}"
                        break
                    except ValidationError as e:
                        print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                        domain = input(f"{bcolors.OKBLUE}Ngrok custom domain [Press Enter to skip]:{bcolors.ENDC} ").strip()
                        if not domain:
                            break
        
        return config

    def _get_cloudflare_config(self) -> Dict[str, Any]:
        """Get Cloudflare configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}Cloudflare Tunneling (optional):{bcolors.ENDC}")
        print(f"  Generate a public URL for your service using Cloudflare")
        use_cloudflare = input(f"{bcolors.OKBLUE}Enable Cloudflare? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'
        
        config = {'cloudflare_enabled': use_cloudflare, 'cloudflare_tunnel_token': '', 
                  'cloudflare_custom_domain': '', 'cloudflare_public_url': ''}
        
        if use_cloudflare:
            while True:
                token = input(f"{bcolors.OKBLUE}Cloudflare tunnel token:{bcolors.ENDC} ").strip()
                try:
                    config['cloudflare_tunnel_token'] = ConfigValidator.validate_cloudflare_token(token)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
            
            while True:
                domain = input(f"{bcolors.OKBLUE}Cloudflare custom domain:{bcolors.ENDC} ").strip()
                try:
                    config['cloudflare_custom_domain'] = ConfigValidator.validate_domain(domain)
                    # Construct cloudflare public URL
                    config['cloudflare_public_url'] = f"https://{config['cloudflare_custom_domain']}"
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
        
        return config

    def _get_tailscale_config(self) -> Dict[str, Any]:
        """Get Tailscale Funnel configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}Tailscale Funnel (optional):{bcolors.ENDC}")
        print(f"  Generate a public URL for your service using Tailscale Funnel")
        use_tailscale = input(f"{bcolors.OKBLUE}Enable Tailscale? [Press Enter for No] (y/n):{bcolors.ENDC} ").strip().lower() == 'y'

        config = {'tailscale_enabled': use_tailscale, 'tailscale_auth_key': '',
                  'tailscale_advertise_tags': '', 'tailscale_public_url': ''}

        if use_tailscale:
            while True:
                key = input(f"{bcolors.OKBLUE}Tailscale auth key:{bcolors.ENDC} ").strip()
                try:
                    config['tailscale_auth_key'] = ConfigValidator.validate_tailscale_auth_key(key)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")

            config['tailscale_advertise_tags'] = input(
                f"{bcolors.OKBLUE}Tailscale ACL tags to advertise, comma-separated "
                f"[Press Enter to skip; required for OAuth-derived keys]:{bcolors.ENDC} "
            ).strip()

        return config

    @staticmethod
    def _disabled_tailscale_config() -> Dict[str, Any]:
        return {'tailscale_enabled': False, 'tailscale_auth_key': '',
                'tailscale_advertise_tags': '', 'tailscale_public_url': ''}

    def _get_advanced_security_config(self) -> Dict[str, Any]:
        """Get advanced security configuration (IP filter, rate limit, encryption, token expiry)."""
        print(f"\n{bcolors.BOLD}Advanced Security (optional):{bcolors.ENDC}")
        print(f"  Configure IP filtering, rate limiting, and response encryption")
        enable_advanced = input(
            f"{bcolors.OKBLUE}Enable advanced security? [Press Enter for No] (y/n):{bcolors.ENDC} "
        ).strip().lower() == 'y'

        config = {
            'allowed_ip': '0.0.0.0/0,::/0',
            'denied_ip': '',
            'rate_limit': '',
            'encryption_enabled': False,
            'encryption_key': '',
            'token_expiration': ''
        }

        if enable_advanced:
            config.update(self._get_ip_allowed_config())
            config.update(self._get_ip_denied_config())
            config.update(self._get_rate_limit_config())
            config.update(self._get_encryption_config())
            config.update(self._get_token_expiration_config())

        return config

    def _get_ip_allowed_config(self) -> Dict[str, str]:
        """Get allowed IP configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}IP Allowed List:{bcolors.ENDC}")
        print(f"  Comma-separated IPs or CIDR ranges (e.g., 192.168.1.0/24,10.0.0.1)")

        ip_list = input(f"{bcolors.OKBLUE}Allowed IPs [Press Enter for all]:{bcolors.ENDC} ").strip()

        if ip_list:
            while True:
                try:
                    return {'allowed_ip': ConfigValidator.validate_ip_list(ip_list)}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    ip_list = input(
                        f"{bcolors.OKBLUE}Allowed IPs [Press Enter for all]:{bcolors.ENDC} "
                    ).strip()
                    if not ip_list:
                        break

        return {'allowed_ip': '0.0.0.0/0,::/0'}

    def _get_ip_denied_config(self) -> Dict[str, str]:
        """Get denied IP configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}IP Denied List:{bcolors.ENDC}")
        print(f"  Comma-separated IPs or CIDR ranges to block")

        ip_list = input(f"{bcolors.OKBLUE}Denied IPs [Press Enter to skip]:{bcolors.ENDC} ").strip()

        if ip_list:
            while True:
                try:
                    return {'denied_ip': ConfigValidator.validate_ip_list(ip_list)}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    ip_list = input(
                        f"{bcolors.OKBLUE}Denied IPs [Press Enter to skip]:{bcolors.ENDC} "
                    ).strip()
                    if not ip_list:
                        break

        return {'denied_ip': ''}

    def _get_rate_limit_config(self) -> Dict[str, str]:
        """Get rate limiting configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}Rate Limiting:{bcolors.ENDC}")
        print(f"  Format: <number>/<period> (e.g., 10/minute, 100/hour, 1000/day)")

        rate_limit = input(f"{bcolors.OKBLUE}Rate limit [Press Enter to skip]:{bcolors.ENDC} ").strip()

        if rate_limit:
            while True:
                try:
                    return {'rate_limit': ConfigValidator.validate_rate_limit(rate_limit)}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    rate_limit = input(
                        f"{bcolors.OKBLUE}Rate limit [Press Enter to skip]:{bcolors.ENDC} "
                    ).strip()
                    if not rate_limit:
                        break

        return {'rate_limit': ''}

    def _get_encryption_config(self) -> Dict[str, Any]:
        """Get encryption configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}Response Encryption:{bcolors.ENDC}")
        print(f"  Enable AES-256 encryption for API responses")
        enable_encryption = input(
            f"{bcolors.OKBLUE}Enable encryption? [Press Enter for No] (y/n):{bcolors.ENDC} "
        ).strip().lower() == 'y'

        config = {'encryption_enabled': enable_encryption, 'encryption_key': ''}

        if enable_encryption:
            print(f"  Encryption key must be exactly 32 alphanumeric characters")
            while True:
                key = input(f"{bcolors.OKBLUE}Encryption key (32 chars):{bcolors.ENDC} ").strip()
                try:
                    config['encryption_key'] = ConfigValidator.validate_encryption_key(key)
                    break
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")

        return config

    def _get_token_expiration_config(self) -> Dict[str, str]:
        """Get token expiration configuration"""
        from ..config.config_validation import ConfigValidator, ValidationError

        print(f"\n{bcolors.BOLD}API Token Expiration:{bcolors.ENDC}")
        print(f"  Format: Xm (minutes), Xh (hours), Xd (days) - e.g., 30m, 24h, 7d")

        expiration = input(
            f"{bcolors.OKBLUE}Token expiration [Press Enter for never]:{bcolors.ENDC} "
        ).strip()

        if expiration:
            while True:
                try:
                    ConfigValidator.parse_expiration_time(expiration)
                    return {'token_expiration': expiration}
                except ValidationError as e:
                    print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")
                    expiration = input(
                        f"{bcolors.OKBLUE}Token expiration [Press Enter for never]:{bcolors.ENDC} "
                    ).strip()
                    if not expiration:
                        break

        return {'token_expiration': ''}
