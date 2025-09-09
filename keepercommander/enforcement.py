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

from . import api, utils, crypto
from .proto import APIRequest_pb2
from .display import bcolors
from .params import KeeperParams


class MasterPasswordReentryEnforcer:
    """Handler for MASTER_PASSWORD_REENTRY enforcement."""
    
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
    def validate_master_password(cls, params: KeeperParams) -> bool:
        """
        Prompt user for master password and validate it.
        
        Args:
            params: KeeperParams instance
            
        Returns:
            bool: True if validation successful, False otherwise
        """
        try:
            # Check if salt and iterations are available in params
            if not hasattr(params, 'salt') or not params.salt:
                logging.warning("Cannot validate master password: no salt information available")
                return False
                
            if not hasattr(params, 'iterations') or not params.iterations:
                logging.warning("Cannot validate master password: no iterations information available")
                return False
            
            # Prompt for master password
            master_password = getpass.getpass(
                prompt=f'{bcolors.WARNING}Master password reentry required for this operation.{bcolors.ENDC}\n'
                       f'Enter master password: '
            ).strip()
            
            if not master_password:
                logging.warning("Master password is required")
                return False
            
            # Create authentication hash using params.salt and params.iterations directly
            auth_hash = crypto.derive_keyhash_v1(master_password, params.salt, params.iterations)
            
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
                logging.error("Master password validation failed")
                return False
                
        except Exception as e:
            logging.error(f"Master password validation failed")
            return False
    
    @classmethod
    def check_and_enforce(cls, params: KeeperParams, operation: str = "record_level") -> bool:
        """
        Check if enforcement is required and handle master password reentry if needed.
        
        Args:
            params: KeeperParams instance
            operation: The operation being performed
            
        Returns:
            bool: True if operation can proceed, False if validation failed
        """
        if cls.requires_master_password_reentry(params, operation):
            return cls.validate_master_password(params)
        return True
