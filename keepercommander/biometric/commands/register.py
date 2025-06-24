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
from ..utils.constants import SUCCESS_MESSAGES, ERROR_MESSAGES
from ...error import CommandError


class BiometricRegisterCommand(BiometricCommand):
    """Register biometric authentication"""

    parser = argparse.ArgumentParser(prog='biometric register', description='Add biometric authentication method')
    parser.add_argument('--name', dest='name', action='store', 
                       help='Friendly name for the biometric method')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Execute registration with improved error handling and method breakdown"""
        def _register():
            self._validate_prerequisites(params, kwargs)
            registration_data = self._prepare_registration(params, kwargs)
            credential = self._perform_registration(params, registration_data)
            self._finalize_registration(params, credential)
        
        return self._execute_with_error_handling('register biometric authentication', _register)

    def _validate_prerequisites(self, params, kwargs):
        """Validate platform support and check for existing credentials"""
        self._check_platform_support(kwargs.get('force', False))
        self._check_existing_credentials(params)

    def _check_existing_credentials(self, params):
        """Check if credential already exists for this user"""
        if self.client.platform_handler and hasattr(self.client.platform_handler, 'storage_handler'):
            storage_handler = getattr(self.client.platform_handler, 'storage_handler')
            if storage_handler and hasattr(storage_handler, 'get_credential_id'):
                existing_credential_id = storage_handler.get_credential_id(params.user)
                if existing_credential_id:
                    raise CommandError(None, ERROR_MESSAGES['credential_already_registered'])

    def _prepare_registration(self, params, kwargs):
        """Prepare registration data and options"""
        friendly_name = kwargs.get('name') or self._get_default_credential_name()
        
        if len(friendly_name) > 32:
            raise ValueError("Friendly name must be 32 characters or less")
        
        logging.info("Adding biometric authentication method: %s", friendly_name)
        
        return {
            'friendly_name': friendly_name
        }

    def _perform_registration(self, params, registration_data):
        """Perform the actual biometric registration"""
        try:
            # Generate registration options
            registration_options = self.client.generate_registration_options(params)
            
            # Create credential
            credential_response = self.client.create_credential(registration_options)
            
            # Verify registration
            self.client.verify_registration(params, registration_options, credential_response, registration_data['friendly_name'])
            
            return {
                'response': credential_response,
                'friendly_name': registration_data['friendly_name']
            }
            
        except Exception as e:
            return self._handle_registration_error(e, params, registration_data['friendly_name'])

    def _handle_registration_error(self, error, params, friendly_name):
        """Handle registration errors, including existing credential scenarios"""
        error_str = str(error).lower()
        if ("object already exists" in error_str or 
            "biometric credential for this account already exists" in error_str):
            
            self._store_placeholder_credential(params)
            return {'friendly_name': friendly_name, 'existing_credential': True}
        else:
            raise error

    def _store_placeholder_credential(self, params):
        """Store placeholder credential ID if storage is available"""
        if self.client.platform_handler and hasattr(self.client.platform_handler, 'storage_handler'):
            storage_handler = getattr(self.client.platform_handler, 'storage_handler')
            if storage_handler and hasattr(storage_handler, 'store_credential_id'):
                existing_credential_id = storage_handler.get_credential_id(params.user)
                if not existing_credential_id:
                    placeholder_id = f"{params.user}"
                    storage_handler.store_credential_id(params.user, placeholder_id)
                    logging.debug("Stored placeholder credential ID for user: %s", params.user)
                else:
                    logging.debug("Credential ID already exists for user: %s", params.user)

    def _finalize_registration(self, params, credential):
        """Finalize registration and report success"""
        friendly_name = credential['friendly_name']
        self._report_success(friendly_name, params.user)

    def _report_success(self, friendly_name: str, username: str):
        """Report successful registration"""
        if self._check_biometric_flag(username):
            logging.info(SUCCESS_MESSAGES['registration_complete'])
            print(f'\nSuccess! Biometric authentication "{friendly_name}" has been registered.')
            print(f'\nPlease register your device using the \033[31m"this-device register"\033[0m command to set biometric authentication as your default login method.')
        else:
            print(f'\nBiometric authentication setup incomplete. Please try again.')        