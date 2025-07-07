import json
import logging
from typing import Dict, Any, Optional

from fido2.client import DefaultClientDataCollector
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from ... import api, utils, rest_api
from ...proto import APIRequest_pb2
from .detector import BiometricDetector


def verify_rp_id_none(rp_id, origin):
    """Verification function for RP ID"""
    return True


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
                'authentication/passkey/generate_registration',
                rs_type=APIRequest_pb2.PasskeyRegistrationResponse
            )

            return {
                'challenge_token': rs.challengeToken,
                'creation_options': json.loads(rs.pkCreationOptions)
            }
        except Exception as e:
            raise Exception(f'Failed to generate registration options: {str(e)}')

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
            rp_id = options.rp.id or 'keepersecurity.com'
            origin = f'https://{rp_id}'

            data_collector = DefaultClientDataCollector(origin, verify=verify_rp_id_none)
            client = self.platform_handler.create_webauthn_client(data_collector, timeout)

            print("Please complete biometric authentication...")
            return self.platform_handler.perform_credential_creation(client, options)

        except Exception as e:
            raise Exception(f'Failed to create biometric credential: {str(e)}')

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

            api.communicate_rest(params, rq, 'authentication/passkey/verify_registration')

        except Exception as e:
            raise Exception(f'Failed to verify biometric registration: {str(e)}')

    def generate_authentication_options(self, params, purpose: str = 'login',
                                      credential_id: Optional[str] = None) -> Dict[str, Any]:
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
                params, rq, 'authentication/passkey/generate_authentication',
                rs_type=APIRequest_pb2.PasskeyAuthenticationResponse
            )

            return {
                'challenge_token': rs.challengeToken,
                'request_options': json.loads(rs.pkRequestOptions),
                'login_token': rs.encryptedLoginToken,
                'purpose': purpose
            }
        except Exception as e:
            raise Exception(f'Failed to generate authentication options: {str(e)}')

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
            rp_id = options.rp_id or 'keepersecurity.com'
            origin = f'https://{rp_id}'

            data_collector = DefaultClientDataCollector(origin, verify=verify_rp_id_none)
            client = self.platform_handler.create_webauthn_client(data_collector, timeout)

            return self.platform_handler.perform_authentication(client, options)

        except Exception as e:
            raise Exception(f'Failed to perform biometric authentication: {str(e)}')

    def get_available_credentials(self, params):
        """Get list of available biometric credentials"""
        try:
            rq = APIRequest_pb2.PasskeyListRequest()
            rs = api.communicate_rest(params, rq, 'authentication/passkey/get_available_keys', 
                                    rs_type=APIRequest_pb2.PasskeyListResponse)

            return [{
                'id': passkey.userId,
                'name': passkey.friendlyName,
                'created': passkey.createdAtMillis,
                'last_used': passkey.lastUsedMillis
            } for passkey in rs.passkeyInfo]

        except Exception as e:
            raise Exception(f'Failed to retrieve available credentials: {str(e)}') 