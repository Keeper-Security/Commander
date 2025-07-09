import argparse
import json

from .base import BiometricCommand
from ..utils.constants import DEFAULT_AUTHENTICATION_TIMEOUT
from ... import utils


class BiometricVerifyCommand(BiometricCommand):
    """Verify biometric authentication"""

    parser = argparse.ArgumentParser(prog='biometric verify', description='Verify biometric authentication with existing credentials')
    parser.add_argument('--timeout', dest='timeout', type=int, default=DEFAULT_AUTHENTICATION_TIMEOUT, 
                       help=f'Authentication timeout in seconds (default: {DEFAULT_AUTHENTICATION_TIMEOUT})')
    parser.add_argument('--credential-id', dest='credential_id', 
                       help='Specific credential ID to test (optional)')
    parser.add_argument('--purpose', dest='purpose', choices=['login', 'vault'], default='login', 
                       help='Authentication purpose (default: login)')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Execute biometric verify command"""
        def _verify():
            timeout = kwargs.get('timeout', DEFAULT_AUTHENTICATION_TIMEOUT)
            credential_id = kwargs.get('credential_id')
            purpose = kwargs.get('purpose', 'login')

            # Get available credentials
            available_credentials = self._get_available_credentials_or_error(params)
            print(f"Found {len(available_credentials)} biometric credential(s)")

            # Generate authentication options
            auth_options = self.client.generate_authentication_options(params, purpose, credential_id)

            # Perform authentication
            assertion_response = self.client.perform_authentication(auth_options, timeout)

            # Verify authentication
            verification_result = self._verify_authentication_response(params, auth_options, assertion_response, purpose)

            # Report results
            self._report_verification_results(verification_result, purpose)

        return self._execute_with_error_handling('verify biometric authentication', _verify)

    def _verify_authentication_response(self, params, auth_options, assertion_response, purpose):
        """Verify the authentication response with Keeper"""
        try:
            actual_response = self._extract_assertion_response(assertion_response)

            if not hasattr(actual_response, 'response'):
                raise Exception(f"Invalid assertion response object: {type(actual_response)}")

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

            # Import here to avoid circular imports
            from ...proto import APIRequest_pb2
            from ... import api

            rq = APIRequest_pb2.PasskeyValidationRequest()
            rq.challengeToken = auth_options['challenge_token']
            rq.assertionResponse = json.dumps(assertion_object).encode('utf-8')
            rq.passkeyPurpose = (APIRequest_pb2.PasskeyPurpose.PK_REAUTH 
                               if purpose == 'vault' else APIRequest_pb2.PasskeyPurpose.PK_LOGIN)

            # Include login token if available
            if auth_options.get('login_token'):
                login_token = auth_options['login_token']
                rq.encryptedLoginToken = utils.base64_url_decode(login_token) if isinstance(login_token, str) else login_token

            rs = api.communicate_rest(params, rq, 'authentication/passkey/verify_authentication', 
                                    rs_type=APIRequest_pb2.PasskeyValidationResponse)

            return {
                'is_valid': rs.isValid,
                'login_token': rs.encryptedLoginToken,
                'credential_id': actual_response.id.encode() if isinstance(actual_response.id, str) else actual_response.id,
                'user_handle': actual_response.response.user_handle
            }

        except Exception as e:
            raise Exception(f'Failed to verify authentication response: {str(e)}')

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

            print("\n Your biometric authentication is working correctly!")
        else:
            print("Status: FAILED")
            print(f"Purpose: {purpose.upper()}")
            print("\n  Authentication verification failed. Please check your biometric setup.")

        print("=" * 50)

    def biometric_authenticate(self, params, username=None, **kwargs):
        """Perform biometric authentication for login"""
        try:
            credential_id = kwargs.get('credential_id')
            purpose = kwargs.get('purpose', 'login')

            auth_options = self.client.generate_authentication_options(params, purpose, credential_id)
            assertion_response = self.client.perform_authentication(auth_options, timeout=10)
            verification_result = self._verify_authentication_response(params, auth_options, assertion_response, purpose)

            return verification_result

        except Exception as e:
            raise Exception(f'Biometric authentication failed: {str(e)}') 