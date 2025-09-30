#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import logging
import getpass
from datetime import datetime, timedelta
from typing import Tuple

from . import api, utils, crypto
from .proto import APIRequest_pb2
from .display import bcolors
from .params import KeeperParams
from .error import KeeperApiError


class MasterPasswordReentryEnforcer:
    """Handler for MASTER_PASSWORD_REENTRY enforcement with multi-factor authentication support."""
    
    # Class variable to store the last successful validation time per user
    _last_validation_time = {}
    
    @classmethod
    def requires_master_password_reentry(cls, params: KeeperParams, operation: str = "record_level") -> bool:
        """
        Check if master password reentry is required for the given operation.
        
        Args:
            params: KeeperParams instance
            operation: The operation being performed (default: "record_level")
            
        Returns:
            bool: True if master password reentry is required
        """
        # Bypass enforcement when running in service mode
        if hasattr(params, 'service_mode') and params.service_mode:
            logging.info(f"Bypassing master password enforcement for operation '{operation}' - running in service mode")
            return False

        if not params.enforcements:
            return False
            
        # Look for MASTER_PASSWORD_REENTRY enforcement
        json_enforcements = params.enforcements.get('jsons', [])
        
        for enforcement in json_enforcements:
            if enforcement.get('key') == 'master_password_reentry':
                try:
                    enforcement_value = json.loads(enforcement.get('value', '{}'))
                    operations = enforcement_value.get('operations', [])
                    timeout_minutes = enforcement_value.get('timeout', 5)
                    
                    # Check if the current operation requires master password reentry
                    if operation in operations:
                        # Check if we're still within the timeout period
                        user_key = params.user
                        if user_key in cls._last_validation_time:
                            last_validation = cls._last_validation_time[user_key]
                            if datetime.now() - last_validation < timedelta(minutes=timeout_minutes):
                                return False  # Still within timeout, no need to reenter
                        
                        return True  # Enforcement required
                        
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logging.warning(f"Failed to parse MASTER_PASSWORD_REENTRY enforcement: {e}")
                    
        return False

    @classmethod
    def _is_biometric_available(cls, params: KeeperParams) -> bool:
        """
        Check if biometric authentication is available for the user.
        
        Args:
            params: KeeperParams instance
            
        Returns:
            bool: True if biometric authentication is available
        """
        try:
            from .biometric import check_biometric_previously_used, BiometricClient
            from .biometric.platforms.detector import BiometricDetector
            
            # Check if biometric was previously used
            if not check_biometric_previously_used(params.user):
                return False
                
            # Check if platform supports biometric
            detector = BiometricDetector()
            supported, _ = detector.detect_platform_capabilities()
            if not supported:
                return False
                
            # Check if user has registered biometric credentials
            client = BiometricClient()
            credentials = client.get_available_credentials(params)
            return len(credentials) > 0
            
        except (ImportError, Exception) as e:
            logging.debug(f"Biometric not available: {e}")
            return False
    
    @classmethod 
    def _validate_biometric(cls, params: KeeperParams) -> bool:
        """
        Perform biometric authentication for vault re-authentication.
        
        Args:
            params: KeeperParams instance
            
        Returns:
            bool: True if biometric validation successful, False otherwise
        """
        try:
            from .biometric import BiometricClient
            
            print(f'{bcolors.WARNING}Biometric authentication required for this operation.{bcolors.ENDC}')
            print('Please complete biometric authentication...')
            
            client = BiometricClient()
            
            # Generate authentication options for vault re-authentication
            auth_options = client.generate_authentication_options(params, purpose='vault')
            
            # Perform biometric authentication
            auth_response = client.perform_authentication(auth_options)
            
            if auth_response:
                # Store successful validation time
                cls._last_validation_time[params.user] = datetime.now()
                print(f'{bcolors.OKGREEN}Biometric authentication successful.{bcolors.ENDC}')
                return True
            else:
                logging.warning("Biometric authentication failed")
                return False
                
        except KeyboardInterrupt:
            logging.info("Biometric authentication cancelled by user")
            return False
        except Exception as e:
            logging.debug(f"Biometric authentication failed: {e}")
            return False
    
    @classmethod
    def _has_master_password_or_alternate(cls, params: KeeperParams) -> Tuple[bool, bool]:
        """
        Check if user has master password or alternate SSO master password.
        
        Args:
            params: KeeperParams instance
            
        Returns:
            Tuple[bool, bool]: (has_regular_master_password, has_alternate_sso_password)
        """
        is_sso_user = params.settings.get('sso_user', False) if params.settings else False
        logging.debug(f"Checking authentication methods - is_sso_user: {is_sso_user}")
        
        # For regular users, check if they can use master password authentication
        has_salt = hasattr(params, 'salt') and params.salt
        has_iterations = hasattr(params, 'iterations') and params.iterations
        
        # If user is logged in (has session token) but doesn't have salt/iterations in params,
        # assume they can still do master password auth (persistent login scenario)
        # We'll fetch salt/iterations when needed during validation
        if not is_sso_user:
            if has_salt and has_iterations:
                has_regular = True
                logging.debug(f"Regular user - salt/iterations available in params")
            elif params.session_token and params.user:
                has_regular = True
                logging.debug(f"Regular user - persistent login detected, will fetch salt/iterations when needed")
            else:
                has_regular = False
                logging.debug(f"Regular user - no session or authentication data available")
        else:
            has_regular = False
        
        logging.debug(f"Regular user auth check - has_salt: {has_salt}, has_iterations: {has_iterations}, has_regular: {has_regular}")
        
        # Check if SSO user has alternate password
        has_alternate = False
        if is_sso_user:
            try:
                current_salt = api.communicate_rest(params, None, 'authentication/get_salt_and_iterations',
                                                  rs_type=APIRequest_pb2.Salt)
                has_alternate = current_salt is not None
                logging.debug(f"SSO user - API call successful, has_alternate: {has_alternate}")
            except KeeperApiError as kae:
                has_alternate = kae.result_code != 'doesnt_exist'
                logging.debug(f"SSO user - API error: {kae.result_code}, has_alternate: {has_alternate}")
            except Exception as e:
                logging.debug(f"SSO user - Exception checking alternate password: {e}")
                pass
                
        return has_regular, has_alternate
    
    @classmethod
    def _validate_master_or_alternate_password(cls, params: KeeperParams) -> bool:
        """
        Validate master password or alternate SSO master password.
        
        Args:
            params: KeeperParams instance
            
        Returns:
            bool: True if validation successful, False otherwise
        """
        is_sso_user = params.settings.get('sso_user', False)
        has_regular, has_alternate = cls._has_master_password_or_alternate(params)
        
        if not has_regular and not has_alternate:
            return False
            
        try:
            if is_sso_user and has_alternate:
                # Get salt and iterations for alternate password
                try:
                    current_salt = api.communicate_rest(params, None, 'authentication/get_salt_and_iterations',
                                                      rs_type=APIRequest_pb2.Salt)
                    salt = current_salt.salt
                    iterations = current_salt.iterations
                except Exception:
                    logging.warning("Cannot validate alternate SSO master password: no salt information available")
                    return False
                    
                prompt_text = f'{bcolors.WARNING}Alternate SSO master password reentry required for this operation.{bcolors.ENDC}\nEnter alternate SSO master password: '
            else:
                # Use regular master password
                # Check if salt/iterations are in params, if not fetch them (persistent login scenario)
                if hasattr(params, 'salt') and params.salt and hasattr(params, 'iterations') and params.iterations:
                    salt = params.salt
                    iterations = params.iterations
                    logging.debug("Using salt/iterations from params")
                else:
                    # Fetch salt/iterations from server (persistent login case)
                    try:
                        logging.debug("Fetching salt/iterations from server for persistent login user")
                        current_salt = api.communicate_rest(params, None, 'authentication/get_salt_and_iterations',
                                                          rs_type=APIRequest_pb2.Salt)
                        salt = current_salt.salt
                        iterations = current_salt.iterations
                        logging.debug("Successfully fetched salt/iterations from server")
                    except Exception as e:
                        logging.warning(f"Cannot validate master password: failed to get salt information from server: {e}")
                        return False
                    
                prompt_text = f'{bcolors.WARNING}Master password reentry required for this operation.{bcolors.ENDC}\nEnter master password: '
            
            # Prompt for password
            master_password = getpass.getpass(prompt=prompt_text).strip()
            
            if not master_password:
                logging.warning("Password is required")
                return False
            
            # Create authentication hash
            auth_hash = crypto.derive_keyhash_v1(master_password, salt, iterations)
            
            # Create master password reentry request
            rq = APIRequest_pb2.MasterPasswordReentryRequest()
            rq.pbkdf2Password = utils.base64_url_encode(auth_hash)
            rq.action = APIRequest_pb2.UNMASK
            
            # Validate with server
            rs = api.communicate_rest(params, rq, 'authentication/validate_master_password',
                                    rs_type=APIRequest_pb2.MasterPasswordReentryResponse, payload_version=1)
            
            if rs.status == APIRequest_pb2.MP_SUCCESS:
                # Store successful validation time
                cls._last_validation_time[params.user] = datetime.now()
                return True
            else:
                logging.error("Password validation failed")
                return False
                
        except Exception as e:
            logging.error(f"Password validation failed: {e}")
            return False
    
    @classmethod
    def check_and_enforce(cls, params: KeeperParams, operation: str = "record_level") -> bool:
        """
        Check if enforcement is required and handle multi-factor authentication if needed.
        
        Uses priority-based authentication:
        1. First check biometric (if enabled)
        2. Then check master password/alternate SSO master password (if available)
        3. If none available, policy does not apply
        
        Args:
            params: KeeperParams instance
            operation: The operation being performed
            
        Returns:
            bool: True if operation can proceed, False if validation failed
        """
        if not cls.requires_master_password_reentry(params, operation):
            return True
            
        # Priority 1: Biometric authentication
        if cls._is_biometric_available(params):
            logging.info("Using biometric authentication for re-authentication")
            return cls._validate_biometric(params)
        
        # Priority 2: Master password or alternate SSO master password
        has_regular, has_alternate = cls._has_master_password_or_alternate(params)
        if has_regular or has_alternate:
            if has_alternate:
                logging.info("Using alternate SSO master password for re-authentication")
            else:
                logging.info("Using master password for re-authentication")
            return cls._validate_master_or_alternate_password(params)
        
        # If no authentication methods are available, policy does not apply
        logging.info("Master Password Re-authentication skipped: Master Password or alternate SSO Master Password not available - policy does not apply")
        return True
