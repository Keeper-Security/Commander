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

import argparse
import logging

from .base import BiometricCommand
from ..utils.constants import DEFAULT_REGISTRATION_TIMEOUT, SUCCESS_MESSAGES, ERROR_MESSAGES
from ...error import CommandError


class BiometricRegisterCommand(BiometricCommand):
    """Register biometric authentication"""

    parser = argparse.ArgumentParser(prog='biometric register', description='Add biometric authentication method')
    parser.add_argument('--name', dest='name', action='store', 
                       help='Friendly name for the biometric method')
    parser.add_argument('--timeout', dest='timeout', type=int, default=DEFAULT_REGISTRATION_TIMEOUT,
                       help=f'Authentication timeout in seconds (default: {DEFAULT_REGISTRATION_TIMEOUT})')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Execute registration"""
        def _register():
            self._check_platform_support(kwargs.get('force', False))

            if self.client.platform_handler and hasattr(self.client.platform_handler, 'storage_handler'):
                storage_handler = getattr(self.client.platform_handler, 'storage_handler')
                if storage_handler and hasattr(storage_handler, 'get_credential_id'):
                    existing_credential_id = storage_handler.get_credential_id(params.user)
                    if existing_credential_id:
                        raise CommandError(self.__class__.__name__, ERROR_MESSAGES['credential_already_registered'])


            friendly_name = kwargs.get('name') or self._get_default_credential_name()
            timeout = kwargs.get('timeout', DEFAULT_REGISTRATION_TIMEOUT)

            logging.info(f'Adding biometric authentication method: {friendly_name}')

            try:
                # Generate registration options
                registration_options = self.client.generate_registration_options(params, **kwargs)

                credential_response = self.client.create_credential(registration_options, timeout)

                # Verify registration
                self.client.verify_registration(params, registration_options, credential_response, friendly_name)

                self._report_success(friendly_name, params.user)
                
            except Exception as e:
                error_str = str(e).lower()
                if ("object already exists" in error_str or 
                    "biometric credential for this account already exists" in error_str):
                    
                    if self.client.platform_handler and hasattr(self.client.platform_handler, 'storage_handler'):
                        storage_handler = getattr(self.client.platform_handler, 'storage_handler')
                        if storage_handler and hasattr(storage_handler, 'store_credential_id'):
                            existing_credential_id = storage_handler.get_credential_id(params.user)
                            if not existing_credential_id:
                                placeholder_id = f"{params.user}"
                                storage_handler.store_credential_id(params.user, placeholder_id)
                                logging.debug(f'Stored placeholder credential ID for user: {params.user}')
                            else:
                                logging.debug(f'Credential ID already exists for user: {params.user}')
                    
                    self._report_success(friendly_name, params.user)
                else:
                    raise e
        return self._execute_with_error_handling('register biometric authentication', _register)

    def _report_success(self, friendly_name: str, username: str):
        """Report successful registration"""
        flag_status = ("Biometric registration successful" 
                      if self._check_biometric_flag(username)
                      else "Biometric registration failed, please try again")

        logging.info(SUCCESS_MESSAGES['registration_complete'])
        print(f'\nSuccess! Biometric authentication "{friendly_name}" has been configured.')
        print(f'{flag_status}') 
        print(f'\nPlease register your device using the \033[31m"this-device register"\033[0m command to set biometric authentication as your default login method.')        