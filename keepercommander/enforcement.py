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

import itertools
import json
import logging
import getpass
import re
import threading
from datetime import datetime, timedelta
from typing import Tuple, Optional, List, Dict, Any, Set

from . import api, utils, crypto
from .proto import APIRequest_pb2, record_pb2
from .display import bcolors
from .params import KeeperParams
from .error import KeeperApiError, CommandError
from .generator import (
    DEFAULT_PASSPHRASE_WORD_COUNT, DEFAULT_PASSPHRASE_CAPITALIZE, DEFAULT_PASSPHRASE_NUMBER,
    MAX_PASSPHRASE_WORD_COUNT,
    PP_SEPARATOR_CHARACTERS, _passphrase_separators_from_policy,
    format_passphrase_separators_for_display,
)


def _find_enforcement_value(enforcements, key):
    # type: (Any, str) -> Any
    """Return raw enforcement value for `key` across known layouts, or None."""
    if not isinstance(enforcements, dict):
        return None
    for bucket in ('jsons', 'strings'):
        items = enforcements.get(bucket)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get('key') == key:
                    return item.get('value')
    return enforcements.get(key) if key in enforcements else None


def _coerce_int(value):
    # type: (Any) -> Optional[int]
    """Coerce enforcement values to int.

    Server-side enforcement payloads sometimes serialize numeric fields as
    strings. Returns None if the value cannot be safely interpreted as int.
    `bool` is intentionally rejected (it's a subclass of int).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.lstrip('-').isdigit():
            try:
                return int(s)
            except ValueError:
                return None
    return None


class MasterPasswordReentryEnforcer:
    """Handler for MASTER_PASSWORD_REENTRY enforcement with multi-factor authentication support."""
    
    # Class variable to store the last successful validation time per user (thread-safe)
    _last_validation_time = {}
    _validation_lock = threading.RLock()
    
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
        # Input validation for operation parameter
        if not operation or not isinstance(operation, str) or len(operation.strip()) == 0:
            logging.error("Invalid operation parameter provided")
            return False
            
        # Sanitize operation string to prevent injection attacks
        operation = operation.strip()[:100]  # Limit length and strip whitespace
        # Bypass enforcement when running in service mode
        if params and hasattr(params, 'service_mode') and params.service_mode:
            logging.debug(f"Bypassing master password enforcement for operation '{operation}' - running in service mode")
            return False

        if not params or not params.enforcements:
            return False
            
        # Look for MASTER_PASSWORD_REENTRY enforcement
        json_enforcements = params.enforcements.get('jsons', [])
        
        for enforcement in json_enforcements:
            if enforcement.get('key') == 'master_password_reentry':
                try:
                    enforcement_value = json.loads(enforcement.get('value', '{}'))
                    operations = enforcement_value.get('operations', [])
                    timeout_minutes = enforcement_value.get('timeout', 5)
                    
                    # Validate timeout to prevent integer overflow and ensure reasonable bounds
                    if not isinstance(timeout_minutes, (int, float)) or timeout_minutes < 0 or timeout_minutes > 999:  # Max 999 minutes
                        logging.error("Invalid timeout value in enforcement policy, timeout value must be more than or equal to 0 and less than or equal to 999 minutes, timeout value will be set to 5 minutes")
                        timeout_minutes = 5  # Default fallback
                    
                    # Check if the current operation requires master password reentry
                    if operation in operations:
                        # Check if we're still within the timeout period (thread-safe)
                        user_key = params.user if params.user else None
                        if not user_key:
                            logging.error("User key not available")
                            return True  # Enforcement required if user key is missing
                            
                        with cls._validation_lock:
                            if user_key in cls._last_validation_time:
                                last_validation = cls._last_validation_time[user_key]
                                if datetime.now() - last_validation < timedelta(minutes=timeout_minutes):
                                    return False  # Still within timeout, no need to reenter
                        
                        return True  # Enforcement required
                        
                except (json.JSONDecodeError, KeyError, TypeError):
                    logging.error("Failed to parse MASTER_PASSWORD_REENTRY enforcement")
                    
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
            
        except (ImportError, Exception):
            logging.debug("Biometric not available")
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
                # Store successful validation time (thread-safe)
                user_key = params.user if params and params.user else None
                if user_key:
                    with cls._validation_lock:
                        cls._last_validation_time[user_key] = datetime.now()
                print(f'{bcolors.OKGREEN}Biometric authentication successful.{bcolors.ENDC}')
                return True
            else:
                logging.warning("Biometric authentication failed")
                return False
                
        except KeyboardInterrupt:
            logging.info("Biometric authentication cancelled by user")
            return False
        except Exception:
            logging.debug("Biometric authentication failed")
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
        
        # Check if SSO user has alternate password
        has_alternate = False
        if is_sso_user:
            try:
                current_salt = api.communicate_rest(params, None, 'authentication/get_salt_and_iterations',
                                                  rs_type=APIRequest_pb2.Salt)
                has_alternate = current_salt is not None
                logging.debug(f"SSO user - API call successful")
            except KeeperApiError as kae:
                has_alternate = kae.result_code != 'doesnt_exist'
                logging.debug(f"SSO user - API error: {kae.result_code}")
            except Exception:
                logging.debug("SSO user - Exception checking alternate password")
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
                    logging.error("Cannot validate alternate SSO master password: no salt information available")
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
                    except Exception:
                        logging.error("Cannot validate master password: failed to get salt information from server")
                        return False
                    
                prompt_text = f'{bcolors.WARNING}Master password reentry required for this operation.{bcolors.ENDC}\nEnter master password: '
            
            # Prompt for password
            master_password = getpass.getpass(prompt=prompt_text).strip()
            
            if not master_password:
                logging.error("Password is required")
                return False
            
            try:
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
                    # Store successful validation time (thread-safe)
                    user_key = params.user if params and params.user else None
                    if user_key:
                        with cls._validation_lock:
                            cls._last_validation_time[user_key] = datetime.now()
                    return True
                else:
                    logging.error("Password validation failed")
                    return False
                    
            finally:
                # Clear sensitive data from memory
                master_password = 'x' * len(master_password)
                del master_password
                if 'auth_hash' in locals():
                    auth_hash = b'x' * len(auth_hash)
                    del auth_hash
                
        except Exception:
            logging.error("Password validation failed")
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


class PasswordComplexityEnforcer:
    """Enforces GENERATED_PASSWORD_COMPLEXITY policy on record passwords."""

    _POLICY_KEY = 'generated_password_complexity'

    _CHAR_CLASSES = (
        ('lower-use', 'lower-min', 'lowercase', str.islower),
        ('upper-use', 'upper-min', 'uppercase', str.isupper),
        ('digit-use', 'digit-min', 'digit',     str.isdigit),
    )

    @classmethod
    def get_policy(cls, params):   # type: (KeeperParams) -> Optional[Dict[str, Any]]
        if not params or not params.enforcements:
            return None
        raw = _find_enforcement_value(params.enforcements, cls._POLICY_KEY)
        if raw is None:
            return None
        try:
            rules = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            logging.debug('Failed to parse %s enforcement', cls._POLICY_KEY)
            return None
        if isinstance(rules, list) and rules and isinstance(rules[0], dict):
            return rules[0]
        if isinstance(rules, dict):
            return rules
        return None

    @classmethod
    def _normalize_passphrase_separators(cls, policy):   # type: (Dict[str, Any]) -> Optional[str]
        raw = policy.get('passphrase-separator')
        if isinstance(raw, str) and raw.strip():
            allowed = _passphrase_separators_from_policy(raw.strip())
            return allowed or None
        return PP_SEPARATOR_CHARACTERS

    @classmethod
    def validate_passphrase(cls, password, policy):   # type: (str, Dict[str, Any]) -> List[str]
        """Validate password as a vault-style passphrase per policy passphrase-* fields."""
        failures = []   # type: List[str]
        if policy.get('passphrase-allow') is False:
            return failures

        allowed_seps = cls._normalize_passphrase_separators(policy)
        if not allowed_seps:
            failures.append(
                'Passphrase cannot meet separator criteria set by policy. '
                f'Allowed: {format_passphrase_separators_for_display(PP_SEPARATOR_CHARACTERS)}.')
            return failures

        separator = next((ch for ch in allowed_seps if ch in password), None)
        if separator is None:
            # Allow CLI-selected separators even when not listed in policy.
            separator = next((ch for ch in PP_SEPARATOR_CHARACTERS if ch in password), None)
        if separator is None:
            failures.append(
                'Passphrase must contain an allowed separator character. '
                f'Allowed: {format_passphrase_separators_for_display(PP_SEPARATOR_CHARACTERS)}.')
            return failures

        words = password.split(separator)
        if not words or any(not word for word in words):
            failures.append('Passphrase contains an empty word.')
            return failures

        min_words = _coerce_int(policy.get('passphrase-length')) or DEFAULT_PASSPHRASE_WORD_COUNT
        if len(words) < min_words:
            failures.append(
                f'Passphrase must contain at least {min_words} words (got {len(words)}).')
        if len(words) > MAX_PASSPHRASE_WORD_COUNT:
            failures.append(
                f'Passphrase must contain at most {MAX_PASSPHRASE_WORD_COUNT} words (got {len(words)}).')

        capitalize = bool(policy.get('passphrase-capitalize', DEFAULT_PASSPHRASE_CAPITALIZE))
        append_number = bool(policy.get('passphrase-number', DEFAULT_PASSPHRASE_NUMBER))

        if capitalize:
            word_re = re.compile(r'^[A-Z][a-z]{2,}$')
            if append_number:
                first_re = re.compile(r'^[A-Z][a-z]{2,}[0-9]$')
            else:
                first_re = re.compile(r'^[A-Z][a-z]{2,}[0-9]?$')
        else:
            word_re = re.compile(r'^[A-Za-z]{3,}$')
            if append_number:
                first_re = re.compile(r'^[A-Za-z]{3,}[0-9]$')
            else:
                first_re = re.compile(r'^[A-Za-z]{3,}[0-9]?$')

        for index, word in enumerate(words):
            pattern = first_re if index == 0 else word_re
            if not pattern.match(word):
                if index == 0 and append_number:
                    failures.append('First passphrase word must end with a digit (0-9).')
                elif capitalize:
                    failures.append(
                        'Each passphrase word must start with a capital letter and contain at least 3 letters.')
                else:
                    failures.append('Each passphrase word must contain at least 3 letters.')
                break

        return failures

    @classmethod
    def validate_password(cls, password, policy):   # type: (str, Dict[str, Any]) -> List[str]
        failures = []   # type: List[str]
        if not policy or not isinstance(password, str) or not password:
            return failures

        min_length = _coerce_int(policy.get('length'))
        if min_length is not None and min_length > 0 and len(password) < min_length:
            failures.append(
                f'Password must be at least {min_length} characters (got {len(password)}).')

        for use_key, min_key, label, predicate in cls._CHAR_CLASSES:
            if not policy.get(use_key):
                continue
            required = _coerce_int(policy.get(min_key, 1))
            if required is None or required <= 0:
                continue
            count = sum(1 for c in password if predicate(c))
            if count < required:
                failures.append(
                    f'Password must contain at least {required} {label} character(s) (got {count}).')

        if policy.get('special-use'):
            required = _coerce_int(policy.get('special-min', 1))
            if required is not None and required > 0:
                allowed = policy.get('special') or ''
                count = (sum(1 for c in password if c in allowed) if allowed
                         else sum(1 for c in password if not c.isalnum()))
                if count < required:
                    failures.append(
                        f'Password must contain at least {required} special character(s) (got {count}).')

        if not failures:
            return []

        # Vault re-validates as a passphrase when random password rules fail.
        if policy.get('passphrase-allow') is False:
            return failures

        passphrase_failures = cls.validate_passphrase(password, policy)
        if not passphrase_failures:
            return []

        return passphrase_failures

    @classmethod
    def validate_record(cls, params, source):   # type: (KeeperParams, Any) -> List[str]
        """Return policy violations across all password fields in `source`.

        `source` may be a vault.TypedRecord, a v3 record-data dict, or a JSON
        string of that dict. Returns [] when no policy applies or no password
        fields are present.
        """
        policy = cls.get_policy(params)
        if not policy:
            return []
        failures = []   # type: List[str]
        for pw in cls._extract_passwords(source):
            failures.extend(cls.validate_password(pw, policy))
        return failures

    @staticmethod
    def _extract_passwords(source):   # type: (Any) -> List[str]
        if source is None:
            return []
        passwords = []   # type: List[str]
        if hasattr(source, 'fields') and hasattr(source, 'custom'):
            for fld in itertools.chain(source.fields or [], source.custom or []):
                if getattr(fld, 'type', None) == 'password':
                    val = getattr(fld, 'value', None)
                    if isinstance(val, list):
                        passwords.extend(v for v in val if isinstance(v, str) and v)
            return passwords

        data = source
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                return []
        if not isinstance(data, dict):
            return []
        for fld in data.get('fields') or []:
            if isinstance(fld, dict) and fld.get('type') == 'password':
                val = fld.get('value')
                if isinstance(val, list):
                    passwords.extend(v for v in val if isinstance(v, str) and v)
        return passwords


class RecordTypeEnforcer:
    """Enforces RESTRICT_RECORD_TYPES policy on record creation/update.

    Stored value is a JSON object {"std": [<id>, ...], "ent": [<id>, ...]} of
    record-type IDs the user is *blocked* from creating. IDs are resolved to
    type names via `params.record_type_cache`.
    """

    _POLICY_KEY = 'restrict_record_types'

    @classmethod
    def get_restricted_record_types(cls, params):   # type: (KeeperParams) -> Optional[Set[str]]
        if not params or not params.enforcements:
            return None
        raw = _find_enforcement_value(params.enforcements, cls._POLICY_KEY)
        if raw is None:
            return None
        try:
            policy = raw if isinstance(raw, dict) else json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logging.debug('Failed to parse %s enforcement', cls._POLICY_KEY)
            return None
        if not isinstance(policy, dict):
            return None

        cache = getattr(params, 'record_type_cache', None) or {}
        restricted = set()   # type: Set[str]
        scope_buckets = (
            ('std', record_pb2.RT_STANDARD),
            ('ent', record_pb2.RT_ENTERPRISE),
        )
        for bucket, scope in scope_buckets:
            for rt_id in policy.get(bucket) or []:
                try:
                    rt_id = int(rt_id)
                except (TypeError, ValueError):
                    continue
                # Role policy stores bare recordTypeId; sync_down keys cache by
                # recordTypeId + scope * 1_000_000.
                scoped_id = rt_id + scope * 1_000_000
                entry = cache.get(scoped_id) or cache.get(rt_id)
                if not entry:
                    continue
                try:
                    schema = json.loads(entry) if isinstance(entry, str) else entry
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(schema, dict):
                    name = schema.get('$id')
                    if name:
                        restricted.add(name)
        return restricted

    @classmethod
    def enforce(cls, params, record_type, command):
        # type: (KeeperParams, Optional[str], str) -> None
        """Raise CommandError when `record_type` is blocked by policy."""
        if not record_type:
            return
        restricted = cls.get_restricted_record_types(params)
        if not restricted or record_type not in restricted:
            return
        raise CommandError(
            command,
            f'Record type "{record_type}" is restricted by your enterprise role policy '
            f'and cannot be created.')
