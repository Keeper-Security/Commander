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
from typing import Dict, Any, Optional

from fido2.client import DefaultClientDataCollector
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from .. import api, utils, rest_api
from ..proto import APIRequest_pb2
from .platforms.detector import BiometricDetector
from .utils.constants import (
    STATUS_SUCCESS, STATUS_NOT_FOUND, STATUS_BAD_REQUEST, STATUS_SERVER_ERROR,
    API_ENDPOINTS, API_RESPONSE_MESSAGES
)

# WebAuthn protocol constants
WEBAUTHN_ORIGIN_SCHEME = 'https'

class BiometricClient:
    """Main client for biometric authentication operations"""

    def __init__(self):
        self.detector = BiometricDetector()
        self.platform_handler = None
        self._initialize_platform_handler()

    def _initialize_platform_handler(self):
        """Initialize platform-specific handler"""
        try:
            self.platform_handler = self.detector.get_platform_handler()
        except Exception as e:
            logging.warning(f"Failed to initialize platform handler: {e}")

    def generate_registration_options(self, params, **kwargs) -> Dict[str, Any]:
        """Generate registration options from Keeper API"""
        try:
            rq = APIRequest_pb2.PasskeyRegistrationRequest()
            rq.authenticatorAttachment = APIRequest_pb2.AuthenticatorAttachment.PLATFORM

            rs = api.communicate_rest(
                params,
                rq,
                API_ENDPOINTS['generate_registration'],
                rs_type=APIRequest_pb2.PasskeyRegistrationResponse
            )

            return {
                'challenge_token': rs.challengeToken,
                'creation_options': json.loads(rs.pkCreationOptions)
            }
        except Exception as e:
            raise Exception(str(e))

    def create_credential(self, registration_options: Dict[str, Any], timeout: int = 30):
        """Create biometric credential"""
        if not self.platform_handler:
            raise Exception("Platform handler not available")

        try:
            creation_options = registration_options['creation_options']

            # Convert base64url encoded values to bytes
            if isinstance(creation_options.get('challenge'), str):
                creation_options['challenge'] = utils.base64_url_decode(creation_options['challenge'])

            # Handle platform-specific options
            creation_options = self.platform_handler.handle_credential_creation(creation_options, timeout)

            # Create WebAuthn client
            options = PublicKeyCredentialCreationOptions.from_dict(creation_options)
            # Extract RP ID from the API response
            rp_id = options.rp.id
            if not rp_id:
                # If no RP ID in response, try to extract from creation_options directly
                rp_id = creation_options.get('rp', {}).get('id')
            if not rp_id:
                raise Exception("No RP ID found in API response - server configuration error")
            origin = f'{WEBAUTHN_ORIGIN_SCHEME}://{rp_id}'

            data_collector = DefaultClientDataCollector(origin)
            client = self.platform_handler.create_webauthn_client(data_collector, timeout)

            print("Please complete biometric authentication...")
            return self.platform_handler.perform_credential_creation(client, options)

        except Exception as e:
            raise Exception(str(e))

    def verify_registration(self, params, registration_options: Dict[str, Any],
                          credential_response, friendly_name: str):
        """Verify registration with Keeper API"""
        try:
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

            api.communicate_rest(params, rq, API_ENDPOINTS['verify_registration'])

            # Store credential ID in platform storage (this also serves as the biometric flag)
            if self.platform_handler and hasattr(self.platform_handler, 'storage_handler'):
                storage_handler = getattr(self.platform_handler, 'storage_handler')
                if storage_handler and hasattr(storage_handler, 'store_credential_id'):
                    try:
                        credential_id = credential_response.id
                        success = storage_handler.store_credential_id(params.user, credential_id)
                        if success:
                            logging.debug(f'Stored credential ID for user {params.user}')
                        else:
                            logging.warning(f'Failed to store credential ID for user {params.user}')
                    except Exception as e:
                        logging.warning(f'Error storing credential ID: {str(e)}')

        except Exception as e:
            raise Exception(str(e))

    def generate_authentication_options(self, params, purpose: str = 'login') -> Dict[str, Any]:
        """Generate authentication options"""
        try:
            rq = APIRequest_pb2.PasskeyAuthenticationRequest()
            rq.authenticatorAttachment = APIRequest_pb2.AuthenticatorAttachment.PLATFORM
            rq.clientVersion = rest_api.CLIENT_VERSION
            rq.username = params.user
            rq.passkeyPurpose = (APIRequest_pb2.PasskeyPurpose.PK_REAUTH
                               if purpose == 'vault' else APIRequest_pb2.PasskeyPurpose.PK_LOGIN)

            if hasattr(params, 'device_token') and params.device_token:
                rq.encryptedDeviceToken = utils.base64_url_decode(params.device_token)

            rs = api.communicate_rest(
                params, rq, API_ENDPOINTS['generate_authentication'],
                rs_type=APIRequest_pb2.PasskeyAuthenticationResponse
            )

            return {
                'challenge_token': rs.challengeToken,
                'request_options': json.loads(rs.pkRequestOptions),
                'login_token': rs.encryptedLoginToken,
                'purpose': purpose
            }
        except Exception as e:
            raise Exception(str(e))

    def perform_authentication(self, auth_options: Dict[str, Any], timeout: int = 10):
        """Perform biometric authentication"""
        if not self.platform_handler:
            raise Exception("Platform handler not available")

        try:
            request_options = auth_options['request_options']
            pk_options = request_options.get('publicKeyCredentialRequestOptions', request_options)

            if not isinstance(pk_options['challenge'], (bytes, bytearray)):
                pk_options['challenge'] = utils.base64_url_decode(pk_options['challenge'])

            if 'allowCredentials' in pk_options:
                for cred in pk_options['allowCredentials']:
                    if isinstance(cred.get('id'), str):
                        cred['id'] = utils.base64_url_decode(cred['id'])

            pk_options = self.platform_handler.handle_authentication_options(pk_options, timeout)

            options = PublicKeyCredentialRequestOptions.from_dict(pk_options)
            # Extract RP ID from the API response
            rp_id = options.rp_id
            if not rp_id:
                # If no RP ID in response, try to extract from pk_options directly
                rp_id = pk_options.get('rpId')
            if not rp_id:
                raise Exception("No RP ID found in API response - server configuration error")
            origin = f'{WEBAUTHN_ORIGIN_SCHEME}://{rp_id}'

            data_collector = DefaultClientDataCollector(origin)
            client = self.platform_handler.create_webauthn_client(data_collector, timeout)

            return self.platform_handler.perform_authentication(client, options)

        except Exception as e:
            raise Exception(str(e))

    def get_available_credentials(self, params):
        """Get list of available biometric credentials"""
        try:
            rq = APIRequest_pb2.PasskeyListRequest()
            rs = api.communicate_rest(params, rq, API_ENDPOINTS['get_available_keys'], 
                                    rs_type=APIRequest_pb2.PasskeyListResponse)

            return [{
                'id': passkey.userId,
                'name': passkey.friendlyName,
                'created': passkey.createdAtMillis,
                'last_used': passkey.lastUsedMillis,
                'credential_id': passkey.credentialId
            } for passkey in rs.passkeyInfo]

        except Exception as e:
            raise Exception(str(e))

    def disable_passkey(self, params, user_id: int, credential_id: bytes):
        """Disable a passkey using the UpdatePasskeyRequest endpoint"""
        try:
            rq = APIRequest_pb2.UpdatePasskeyRequest()
            rq.userId = user_id
            rq.credentialId = credential_id
            # Don't set friendlyName since we're only disabling, not updating name

            # Use the same pattern as other API methods
            api.communicate_rest(params, rq, API_ENDPOINTS['disable_passkey'])
            
            # If we get here, the API call was successful
            return {'status': STATUS_SUCCESS, 'message': API_RESPONSE_MESSAGES['passkey_disabled_success']}

        except Exception as e:
            # Parse the error message for specific error types
            error_msg = str(e).lower()
            if 'bad_request' in error_msg or 'credential id' in error_msg or 'userid' in error_msg:
                return {'status': STATUS_BAD_REQUEST, 'message': API_RESPONSE_MESSAGES['disable_bad_request']}
            elif 'server_error' in error_msg or 'unexpected' in error_msg:
                return {'status': STATUS_SERVER_ERROR, 'message': API_RESPONSE_MESSAGES['server_exception']}
            else:
                raise Exception(str(e))

    def update_passkey_name(self, params, user_id: int, credential_id: bytes, friendly_name: str):
        """Update the friendly name of a passkey using the UpdatePasskeyRequest endpoint"""
        try:
            rq = APIRequest_pb2.UpdatePasskeyRequest()
            rq.userId = user_id
            rq.credentialId = credential_id
            rq.friendlyName = friendly_name

            # Use the update_friendly_name endpoint
            api.communicate_rest(params, rq, API_ENDPOINTS['update_passkey_name'])
            
            # If we get here, the API call was successful
            return {'status': STATUS_SUCCESS, 'message': API_RESPONSE_MESSAGES['passkey_name_updated_success']}

        except Exception as e:
            # Parse the error message for specific error types
            error_msg = str(e).lower()
            if 'bad_request' in error_msg or 'credential id' in error_msg or 'userid' in error_msg:
                return {'status': STATUS_BAD_REQUEST, 'message': API_RESPONSE_MESSAGES['update_bad_request']}
            elif 'server_error' in error_msg or 'unexpected' in error_msg:
                return {'status': STATUS_SERVER_ERROR, 'message': API_RESPONSE_MESSAGES['server_exception']}
            else:
                raise Exception(str(e)) 