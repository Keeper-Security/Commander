#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import base64
import json
import logging
import os
import platform
import sys
import threading
import time
from typing import Optional, Dict, Any

from .. import api, utils, rest_api
from ..commands.base import GroupCommand, Command, report_output_parser, dump_report_data, field_to_title, user_choice
from ..error import CommandError, KeeperApiError
from ..proto import APIRequest_pb2

# FIDO2 imports for biometric authentication
try:
    from fido2.client import ClientError, DefaultClientDataCollector, UserInteraction, WebAuthnClient
    from fido2.ctap import CtapError
    from fido2.webauthn import (
        PublicKeyCredentialRequestOptions, 
        AuthenticationResponse,
        PublicKeyCredentialCreationOptions, 
        RegistrationResponse,
        UserVerificationRequirement
    )
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False

# Platform-specific imports
PLATFORM_SUPPORT = {
    'windows': False,
    'macos': False,
    'linux': False
}

# Windows-specific imports
if os.name == 'nt':
    try:
        from fido2.client.windows import WindowsClient
        import winreg
        PLATFORM_SUPPORT['windows'] = True
    except ImportError:
        pass

# macOS-specific imports
elif platform.system() == 'Darwin':
    try:
        import ctypes
        import ctypes.util
        PLATFORM_SUPPORT['macos'] = True
    except ImportError:
        pass

# Linux-specific imports
elif platform.system() == 'Linux':
    try:
        from fido2.hid import CtapHidDevice
        PLATFORM_SUPPORT['linux'] = True
    except ImportError:
        pass


def verify_rp_id_none(rp_id, origin):
    return True



def check_biometric_previously_used(username):
    """Check if biometric authentication was previously used for this user - Windows only"""
    if os.name == 'nt':
        from .biometric_win import get_windows_registry_biometric_flag
        return get_windows_registry_biometric_flag(username)
    else:
        return False


class BiometricInteraction(UserInteraction):
    """Custom interaction handler for biometric authentication"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._cancelled = False
    
    def prompt_up(self):
        """Prompt user for biometric authentication"""
        system = platform.system()
        if system == 'Windows':
            print("\nPlease authenticate using Windows Hello...")
        else:
            print("\nBiometric authentication is not implemented for this platform...")
    
    def request_pin(self, permissions, rp_id):
        """Request PIN if required"""
        if self._cancelled:
            raise Exception("Authentication cancelled by user")
        
        try:
            import getpass
            pin = getpass.getpass("Enter your security key PIN: ")
            return pin
        except KeyboardInterrupt:
            self._cancelled = True
            raise Exception("Authentication cancelled by user")
    
    def request_uv(self, permissions, rp_id):
        """Request user verification"""
        return True
    
    def cancel(self):
        """Cancel the authentication process"""
        self._cancelled = True


class PlatformBiometricDetector:
    """Detect and validate biometric capabilities across platforms"""
    
    @staticmethod
    def detect_platform_biometric():
        """Detect biometric capabilities for the current platform"""
        system = platform.system()
        
        if system == 'Windows':
            from .biometric_win import detect_windows_hello
            return detect_windows_hello()
        elif system == 'Darwin':
            return False, "macOS biometric authentication is not implemented"
        else:
            return False, f"Biometric authentication is only supported on Windows. Current platform: {system}"


class BiometricCommand(GroupCommand):
    """Main biometric command group"""
    
    def __init__(self):
        super().__init__()
        self.register_command('register', BiometricRegisterCommand(), 'Add biometric authentication method')
        self.register_command('list', BiometricListCommand(), 'List biometric authentication methods')
        self.register_command('unregister', BiometricUnregisterCommand(), 'Disable biometric authentication for this user')
        self.register_command('verify', BiometricVerifyCommand(), 'Verify biometric authentication with existing credentials')


class BiometricRegisterCommand(Command):
    """Command to add biometric authentication method"""
    
    parser = argparse.ArgumentParser(prog='biometric register', description='Add biometric authentication method')
    parser.add_argument('--name', dest='name', action='store', 
                       help='Friendly name for the biometric method')
    parser.add_argument('--force', dest='force', action='store_true', 
                       help='Force registration even if platform support is uncertain')
    parser.add_argument('--timeout', dest='timeout', type=int, default=30,
                       help='Authentication timeout in seconds (default: 30)')

    def get_parser(self):
        return BiometricRegisterCommand.parser

    def execute(self, params, **kwargs):
        """Execute biometric add command"""
        if not FIDO2_AVAILABLE:
            raise CommandError('biometric add', 
                             'FIDO2 library is not available. Please install: pip install fido2')

        supported, message = PlatformBiometricDetector.detect_platform_biometric()
        if not supported and not kwargs.get('force', False):
            raise CommandError('biometric add', 
                             f'Biometric authentication is not supported: {message}\n'
                             f'Use --force to attempt registration anyway.')
        
        if not supported:
            logging.warning(f'Platform support uncertain: {message}')

        try:
            friendly_name = kwargs.get('name') or self._get_default_name()
            timeout = kwargs.get('timeout', 30)
            
            logging.info(f'Adding biometric authentication method: {friendly_name}')
            
            registration_options = self._generate_registration_options(params, kwargs)
            credential_response = self._create_biometric_credential(registration_options, timeout)
            self._verify_registration(params, registration_options, credential_response, friendly_name)
            
            self._set_biometric_enabled_for_user(params.user, True)
            
            if check_biometric_previously_used(params.user):
                flag_status = "Biometric Registration successfully"
            else:
                flag_status = "Biometric Registration failed, please try again"
            
            logging.info(f'Biometric authentication method "{friendly_name}" added successfully!')
            print(f'\nSuccess! Biometric authentication "{friendly_name}" has been configured.')
            print('Biometric authentication will now be your default login method.')
            print(f'{flag_status}')
            
        except KeyboardInterrupt:
            logging.info('Biometric registration cancelled by user')
            raise CommandError('biometric add', 'Registration cancelled by user')
        except Exception as e:
            logging.error(f'Failed to add biometric authentication: {str(e)}')
            raise CommandError('biometric add', str(e))

    def _get_default_name(self):
        """Generate a default name for the biometric method"""
        system = platform.system()
        hostname = platform.node() or 'Unknown'
        
        if system == 'Windows':
            return f"Windows Hello - {hostname}"
        else:
            raise CommandError('biometric add', f'Biometric authentication is only supported on Windows. Current platform: {system}')

    def _generate_registration_options(self, params, kwargs):
        """Call Keeper's generate_registration API"""
        try:
            rq = APIRequest_pb2.PasskeyRegistrationRequest()
            rq.authenticatorAttachment = APIRequest_pb2.AuthenticatorAttachment.PLATFORM
            
            rs = api.communicate_rest(
                params, 
                rq, 
                'authentication/passkey/generate_registration',
                rs_type=APIRequest_pb2.PasskeyRegistrationResponse
            )
            
            challenge_token = rs.challengeToken
            pk_creation_options = json.loads(rs.pkCreationOptions)
            
            return {
                'challenge_token': challenge_token,
                'creation_options': pk_creation_options
            }
            
        except Exception as e:
            raise CommandError('biometric add', f'Failed to generate registration options: {str(e)}')

    def _create_biometric_credential(self, registration_options, timeout=30):
        """Create biometric credential using FIDO2"""
        try:
            creation_options = registration_options['creation_options']
            
            # Convert base64url encoded values to bytes
            if isinstance(creation_options.get('challenge'), str):
                creation_options['challenge'] = utils.base64_url_decode(creation_options['challenge'])
            
            # Platform-specific handling - Windows only
            system = platform.system()
            if system == 'Windows':
                from .biometric_win import handle_windows_credential_creation
                creation_options = handle_windows_credential_creation(creation_options, timeout)
            else:
                raise Exception(f'Biometric authentication is only supported on Windows. Current platform: {system}')
            
            options = PublicKeyCredentialCreationOptions.from_dict(creation_options)
            
            rp_id = options.rp.id or 'keepersecurity.com'
            origin = f'https://{rp_id}'
            
            client = self._create_webauthn_client(origin, timeout)
            
            if not client:
                raise Exception('Failed to create WebAuthn client for biometric authentication')
            
            print("Please complete biometric authentication...")
            
            if system == 'Windows':
                from .biometric_win import perform_windows_credential_creation
                return perform_windows_credential_creation(client, options)
            else:
                raise Exception(f'Biometric authentication is only supported on Windows. Current platform: {system}')
                
        except ClientError as err:
            if isinstance(err.cause, CtapError):
                error_messages = {
                    CtapError.ERR.UNSUPPORTED_ALGORITHM: 'Biometric authenticator does not support the required algorithm',
                    CtapError.ERR.CREDENTIAL_EXCLUDED: 'A credential for this account already exists',
                    CtapError.ERR.OPERATION_DENIED: 'Biometric authentication was cancelled or denied',
                    CtapError.ERR.USER_ACTION_TIMEOUT: 'Biometric authentication timed out',
                    CtapError.ERR.UP_REQUIRED: 'User presence required - please touch your authenticator'
                }
                
                error_code = err.cause.code if err.cause else None
                error_msg = error_messages.get(error_code, f'CTAP error: {error_code}')
                raise Exception(error_msg)
            
            raise Exception(f'Biometric credential creation failed: {str(err)}')
        except Exception as e:
            raise Exception(f'Failed to create biometric credential: {str(e)}')

    def _create_webauthn_client(self, origin, timeout=30):
        """Create appropriate WebAuthn client for the platform - Windows only"""
        data_collector = DefaultClientDataCollector(origin, verify=verify_rp_id_none)
        
        system = platform.system()
        
        if system == 'Windows':
            from .biometric_win import create_windows_webauthn_client
            return create_windows_webauthn_client(data_collector, timeout)
        else:
            raise Exception(f'Biometric authentication is only supported on Windows. Current platform: {system}')

    def _verify_registration(self, params, registration_options, credential_response, friendly_name):
        """Verify the registration with Keeper"""
        try:
            # Format the response correctly for Keeper's API
            client_data_bytes = credential_response.response.client_data
            if hasattr(client_data_bytes, 'b64'):
                client_data_b64 = client_data_bytes.b64
            else:
                client_data_b64 = utils.base64_url_encode(client_data_bytes)
            
            attestation_object = {
                'id': credential_response.id,
                'rawId': utils.base64_url_encode(credential_response.raw_id),
                'response': {
                    'attestationObject': utils.base64_url_encode(credential_response.response.attestation_object),
                    'clientDataJSON': client_data_b64
                },
                'type': 'public-key',
                'clientExtensionResults': credential_response.client_extension_results or {}
            }
            
            rq = APIRequest_pb2.PasskeyRegistrationFinalization()
            rq.challengeToken = registration_options['challenge_token']
            rq.authenticatorResponse = json.dumps(attestation_object)
            rq.friendlyName = friendly_name
            
            api.communicate_rest(
                params, 
                rq, 
                'authentication/passkey/verify_registration'
            )
             
        except Exception as e:
            raise Exception(f'Failed to verify biometric registration: {str(e)}')

    def _set_biometric_enabled_for_user(self, username, enabled):
        """Set biometric authentication enabled flag for a user on this device - Windows only"""
        if os.name == 'nt':
            # Use Windows registry on Windows
            from .biometric_win import set_windows_registry_biometric_flag
            set_windows_registry_biometric_flag(username, enabled)
        else:
            raise Exception(f'Biometric authentication is only supported on Windows. Current platform: {platform.system()}')


class BiometricListCommand(Command):
    """Command to list biometric authentication methods"""
    
    parser = argparse.ArgumentParser(prog='biometric list', description='List biometric authentication methods')
    parser.add_argument('--format', dest='format', choices=['table', 'json'], default='table',
                       help='Output format (default: table)')

    def get_parser(self):
        return BiometricListCommand.parser

    def execute(self, params, **kwargs):
        """List registered biometric methods"""
        try:
            rq = APIRequest_pb2.PasskeyListRequest()
            rs = api.communicate_rest(
                params,
                rq,
                'authentication/passkey/get_available_keys',
                rs_type=APIRequest_pb2.PasskeyListResponse
            )
            
            passkeys = []
            for passkey in rs.passkeyInfo:
                passkeys.append({
                    'id': passkey.userId,
                    'name': passkey.friendlyName,
                    'created': passkey.createdAtMillis,
                    'last_used': passkey.lastUsedMillis,
                    'aaguid': passkey.AAGUID if hasattr(passkey, 'AAGUID') else 'N/A'
                })
            
            if kwargs.get('format') == 'json':
                print(json.dumps(passkeys, indent=2))
            else:
                if not passkeys:
                    print("No biometric authentication methods found.")
                else:
                    print("\n📱 Registered Biometric Authentication Methods:")
                    print("-" * 70)
                    for passkey in passkeys:
                        print(f"Name: {passkey['name']}")
                        print(f"ID: {passkey['id']}")
                        print(f"AAGUID: {passkey['aaguid']}")
                        print(f"Created: {passkey['created']}")
                        print(f"Last Used: {passkey['last_used']}")
                        print("-" * 70)
            
        except Exception as e:
            raise CommandError('biometric list', f'Failed to list biometric methods: {str(e)}')


class BiometricUnregisterCommand(Command):
    """Command to disable biometric authentication for the current user"""
    
    parser = argparse.ArgumentParser(prog='biometric unregister', description='Disable biometric authentication for this user')
    parser.add_argument('--confirm', dest='confirm', action='store_true',
                       help='Skip confirmation prompt')

    def get_parser(self):
        return BiometricUnregisterCommand.parser

    def execute(self, params, **kwargs):
        """Disable biometric authentication for the current user"""
        
        if not check_biometric_previously_used(params.user):
            print(f"💡 Biometric authentication is already disabled for user '{params.user}'.")
            return
        
        if not kwargs.get('confirm'):
            confirm = input(f"Are you sure you want to disable biometric authentication for user '{params.user}'? (y/N): ")
            if confirm.lower() != 'y':
                print("Operation cancelled.")
                return
        
        try:
            if os.name == 'nt':
                from .biometric_win import set_windows_registry_biometric_flag
                success = set_windows_registry_biometric_flag(params.user, False)
                flag_status = "successfully Unregister Biometric Authentication" if success else "Failed to Unregister Biometric Authentication"
            else:
                raise CommandError('biometric disable', f'Biometric authentication is only supported on Windows. Current platform: {platform.system()}')
            
            # Verify the flag was set correctly
            if not check_biometric_previously_used(params.user):
                print(f"Biometric authentication has been disabled for user '{params.user}'.")
                print("Password authentication will be used for future logins.")
                print(f"{flag_status}")
            else:
                print(f"Failed to disable biometric authentication. Please try again.")
                print(f"{flag_status}")
            
        except Exception as e:
            raise CommandError('biometric disable', f'Failed to disable biometric authentication: {str(e)}')


class BiometricVerifyCommand(Command):
    """Command to verify biometric authentication with existing credentials"""
    
    parser = argparse.ArgumentParser(prog='biometric verify', description='Verify biometric authentication with existing credentials')
    parser.add_argument('--timeout', dest='timeout', type=int, default=10, help='Authentication timeout in seconds (default: 10)')
    parser.add_argument('--credential-id', dest='credential_id', help='Specific credential ID to test (optional)')
    parser.add_argument('--purpose', dest='purpose', choices=['login', 'vault'], default='login', help='Authentication purpose (default: login)')

    def get_parser(self):
        return BiometricVerifyCommand.parser

    def execute(self, params, **kwargs):
        """Execute biometric verify command"""
        if not FIDO2_AVAILABLE:
            raise CommandError('biometric verify', 'FIDO2 library is not available. Please install: pip install fido2')

        try:
            timeout = kwargs.get('timeout', 10)
            credential_id = kwargs.get('credential_id')
            purpose = kwargs.get('purpose', 'login')
            
            available_credentials = self._get_available_credentials(params)
            if not available_credentials:
                raise CommandError('biometric verify', 'No biometric credentials found. Please add a credential first using "biometric add"')
            
            print(f"Found {len(available_credentials)} biometric credential(s)")
            
            auth_options = self._generate_authentication_options(params, purpose, credential_id)
            
            assertion_response = self._perform_biometric_authentication(auth_options, timeout)
            
            verification_result = self._verify_authentication_response(params, auth_options, assertion_response, purpose)
            
            self._report_verification_results(verification_result, purpose)
            
        except KeyboardInterrupt:
            raise CommandError('biometric verify', 'Verification cancelled by user')
        except Exception as e:
            raise CommandError('biometric verify', str(e))

    def _get_available_credentials(self, params):
        """Get list of available biometric credentials"""
        try:
            rq = APIRequest_pb2.PasskeyListRequest()
            rs = api.communicate_rest(params, rq, 'authentication/passkey/get_available_keys', rs_type=APIRequest_pb2.PasskeyListResponse)
            
            return [{
                'id': passkey.userId,
                'name': passkey.friendlyName,
                'created': passkey.createdAtMillis,
                'last_used': passkey.lastUsedMillis
            } for passkey in rs.passkeyInfo]
            
        except Exception as e:
            raise Exception(f'Failed to retrieve available credentials: {str(e)}')

    def _generate_authentication_options(self, params, purpose='vault', credential_id=None):
        """Generate authentication options for verification"""
        try:
            rq = APIRequest_pb2.PasskeyAuthenticationRequest()
            rq.authenticatorAttachment = APIRequest_pb2.AuthenticatorAttachment.PLATFORM
            rq.clientVersion = rest_api.CLIENT_VERSION
            rq.username = params.user
            rq.passkeyPurpose = APIRequest_pb2.PasskeyPurpose.PK_REAUTH if purpose == 'vault' else APIRequest_pb2.PasskeyPurpose.PK_LOGIN
            
            if hasattr(params, 'device_token') and params.device_token:
                rq.encryptedDeviceToken = utils.base64_url_decode(params.device_token)
            
            rs = api.communicate_rest(params, rq, 'authentication/passkey/generate_authentication', rs_type=APIRequest_pb2.PasskeyAuthenticationResponse)
            
            return {
                'challenge_token': rs.challengeToken,
                'request_options': json.loads(rs.pkRequestOptions),
                'login_token': rs.encryptedLoginToken,
                'purpose': purpose
            }
            
        except Exception as e:
            raise Exception(f'Failed to generate authentication options: {str(e)}')

    def _perform_biometric_authentication(self, auth_options, timeout=10):
        """Perform the actual biometric authentication"""
        try:
            request_options = auth_options['request_options']
            pk_options = request_options.get('publicKeyCredentialRequestOptions', request_options)

            if 'challenge' not in pk_options or not pk_options['challenge']:
                raise Exception("Missing 'challenge' in PublicKeyCredentialRequestOptions")

            if not isinstance(pk_options['challenge'], (bytes, bytearray)):
                pk_options['challenge'] = utils.base64_url_decode(pk_options['challenge'])

            if 'allowCredentials' in pk_options:
                for cred in pk_options['allowCredentials']:
                    if isinstance(cred.get('id'), str):
                        cred['id'] = utils.base64_url_decode(cred['id'])

            system = platform.system()
            if system == 'Windows':
                from .biometric_win import handle_windows_authentication_options
                pk_options = handle_windows_authentication_options(pk_options, timeout)
            else:
                raise Exception(f'Biometric authentication is only supported on Windows. Current platform: {system}')

            options = PublicKeyCredentialRequestOptions.from_dict(pk_options)
            rp_id = options.rp_id or 'keepersecurity.com'
            origin = f'https://{rp_id}'
            
            data_collector = DefaultClientDataCollector(origin, verify=verify_rp_id_none)
            
            # Windows-only authentication
            from .biometric_win import create_windows_webauthn_client, perform_windows_authentication
            client = create_windows_webauthn_client(data_collector, timeout)
            return perform_windows_authentication(client, options)

        except ClientError as err:
            if isinstance(err.cause, CtapError):
                error_messages = {
                    CtapError.ERR.NO_CREDENTIALS: 'No matching credentials found on the authenticator',
                    CtapError.ERR.OPERATION_DENIED: 'Biometric authentication was cancelled or denied',
                    CtapError.ERR.USER_ACTION_TIMEOUT: 'Biometric authentication timed out',
                    CtapError.ERR.UP_REQUIRED: 'User presence required - please touch your authenticator',
                    CtapError.ERR.UV_INVALID: 'User verification failed - biometric authentication rejected'
                }
                error_msg = error_messages.get(err.cause.code, f'CTAP error: {err.cause.code}')
                raise Exception(error_msg)
            raise Exception(f'Biometric authentication failed: {str(err)}')
        except Exception as e:
            raise Exception(f'Failed to perform biometric authentication: {str(e)}')

    def _extract_assertion_response(self, assertion_result):
        """Extract assertion response from various result types"""
        try:
            if hasattr(assertion_result, 'get_response'):
                return assertion_result.get_response(0)
            elif hasattr(assertion_result, 'get_assertions'):
                assertions = assertion_result.get_assertions()
                if assertions and len(assertions) > 0:
                    return assertions[0]
                else:
                    raise Exception("AssertionSelection has no assertions")
            elif hasattr(assertion_result, 'response'):
                return assertion_result
            elif hasattr(assertion_result, 'assertions') and assertion_result.assertions:
                return assertion_result.assertions[0]
            else:
                raise Exception(f"Unknown assertion result format: {type(assertion_result)}")
        except Exception as e:
            raise Exception(f"Failed to extract assertion response: {str(e)}")

    def _verify_authentication_response(self, params, auth_options, assertion_response, purpose):
        """Verify the authentication response with Keeper"""
        try:
            actual_response = self._extract_assertion_response(assertion_response)
            
            if not hasattr(actual_response, 'response'):
                raise Exception(f"Invalid assertion response object after extraction: {type(actual_response)}")
            
            client_data_bytes = actual_response.response.client_data
            if hasattr(client_data_bytes, 'b64'):
                client_data_b64 = client_data_bytes.b64
            elif isinstance(client_data_bytes, bytes):
                client_data_b64 = utils.base64_url_encode(client_data_bytes)
            else:
                client_data_b64 = str(client_data_bytes)
            
            credential_id = actual_response.id
            credential_raw_id = actual_response.raw_id
            if not credential_id or not credential_raw_id:
                raise Exception("Could not extract credential ID from assertion response")
            
            assertion_object = {
                'id': credential_id,
                'rawId': utils.base64_url_encode(credential_raw_id),
                'response': {
                    'authenticatorData': utils.base64_url_encode(actual_response.response.authenticator_data),
                    'clientDataJSON': client_data_b64,
                    'signature': utils.base64_url_encode(actual_response.response.signature),
                },
                'type': 'public-key',
                'clientExtensionResults': getattr(actual_response, 'client_extension_results', {}) or {}
            }
            
            rq = APIRequest_pb2.PasskeyValidationRequest()
            rq.challengeToken = auth_options['challenge_token']
            rq.assertionResponse = json.dumps(assertion_object).encode('utf-8')
            rq.passkeyPurpose = APIRequest_pb2.PasskeyPurpose.PK_REAUTH if purpose == 'vault' else APIRequest_pb2.PasskeyPurpose.PK_LOGIN
            
            # Include login token if available
            if auth_options.get('login_token'):
                login_token = auth_options['login_token']
                rq.encryptedLoginToken = utils.base64_url_decode(login_token) if isinstance(login_token, str) else login_token
            
            rs = api.communicate_rest(params, rq, 'authentication/passkey/verify_authentication', rs_type=APIRequest_pb2.PasskeyValidationResponse)
            
            return {
                'is_valid': rs.isValid,
                'login_token': rs.encryptedLoginToken,
                'credential_id': actual_response.id.encode(),
                'user_handle': actual_response.response.user_handle
            }
            
        except Exception as e:
            raise Exception(f'Failed to verify authentication response: {str(e)}')

    def _report_verification_results(self, verification_result, purpose):
        """Report the verification results to the user"""
        print(f"\nBiometric Authentication Verification Results:")
        print("=" * 50)
        
        if verification_result['is_valid']:
            print("Status: SUCCESSFUL")
            print(f"Purpose: {purpose.upper()}")
            print(f"Credential ID: {utils.base64_url_encode(verification_result['credential_id'])}")
            
            if verification_result.get('user_handle'):
                print(f"User Handle: {utils.base64_url_encode(verification_result['user_handle'])}")
            if verification_result.get('login_token'):
                print("Login Token: Received")
            
            print("\nYour biometric authentication is working correctly!")
        else:
            print("Status: FAILED")
            print(f"Purpose: {purpose.upper()}")
            print("\nAuthentication verification failed. Please check your biometric setup.")
            
        print("=" * 50)

    def biometric_authenticate(self, params, username=None, **kwargs):
        """Perform biometric authentication for login"""
        if not FIDO2_AVAILABLE:
            raise Exception('FIDO2 library is not available')
        
        try:
            credential_id = kwargs.get('credential_id')
            purpose = kwargs.get('purpose', 'login')
            
            auth_options = self._generate_authentication_options(params, purpose, credential_id)
            assertion_response = self._perform_biometric_authentication(auth_options, timeout=10)
            login_token = self._verify_authentication_response(params, auth_options, assertion_response, purpose)
            
            return login_token
            
        except Exception as e:
            raise Exception(f'Biometric authentication failed: {str(e)}') 