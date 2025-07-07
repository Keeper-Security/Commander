import argparse
import logging

from .base import BiometricCommand
from ...error import CommandError


class BiometricRegisterCommand(BiometricCommand):
    """Register biometric authentication"""

    parser = argparse.ArgumentParser(prog='biometric register', description='Add biometric authentication method')
    parser.add_argument('--name', dest='name', action='store', 
                       help='Friendly name for the biometric method')
    parser.add_argument('--force', dest='force', action='store_true', 
                       help='Force registration even if platform support is uncertain')
    parser.add_argument('--timeout', dest='timeout', type=int, default=30,
                       help='Authentication timeout in seconds (default: 30)')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Execute registration"""
        try:
            self._check_platform_support(kwargs.get('force', False))

            friendly_name = kwargs.get('name') or self._get_default_credential_name()
            timeout = kwargs.get('timeout', 30)

            logging.info(f'Adding biometric authentication method: {friendly_name}')

            # Generate registration options
            registration_options = self.client.generate_registration_options(params, **kwargs)

            # Create credential
            credential_response = self.client.create_credential(registration_options, timeout)

            # Verify registration
            self.client.verify_registration(params, registration_options, credential_response, friendly_name)

            # Set biometric flag
            self._set_biometric_flag(params.user, True)

            # Check if flag was set successfully
            if self._check_biometric_flag(params.user):
                flag_status = "Biometric registration successful"
            else:
                flag_status = "Biometric registration failed, please try again"

            logging.info(f'Biometric authentication method "{friendly_name}" added successfully!')
            print(f'\nSuccess! Biometric authentication "{friendly_name}" has been configured.')
            print('Biometric authentication will now be your default login method.')
            print(f'{flag_status}')

        except KeyboardInterrupt:
            logging.info('Biometric registration cancelled by user')
            raise CommandError('biometric register', 'Registration cancelled by user')
        except Exception as e:
            logging.error(f'Failed to add biometric authentication: {str(e)}')
            raise CommandError('biometric register', str(e)) 