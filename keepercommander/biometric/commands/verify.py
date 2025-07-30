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
import json

from .base import BiometricCommand
from ..utils.constants import SUCCESS_MESSAGES, API_ENDPOINTS
from ... import utils


class BiometricVerifyCommand(BiometricCommand):
    """Verify biometric authentication"""

    parser = argparse.ArgumentParser(prog='biometric verify', description='Verify biometric authentication with existing credentials')
    parser.add_argument('--purpose', dest='purpose', choices=['login', 'vault'], default='login', 
                       help='Authentication purpose (default: login)')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Execute biometric verify command"""
        def _verify():
            self._check_platform_support()
            purpose = kwargs.get('purpose', 'login')

            available_credentials = self._get_available_credentials_or_error(params)

            # Generate authentication options
            auth_options = self.client.generate_authentication_options(params, purpose)

            # Perform authentication
            assertion_response = self.client.perform_authentication(auth_options)

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
            client_data_b64 = self._extract_client_data_b64(client_data_bytes)

            credential_id = actual_response.id
            credential_raw_id = actual_response.raw_id
            if not credential_id or not credential_raw_id:
                raise Exception("Could not extract credential ID from assertion response")

            assertion_object = self._create_assertion_object(actual_response, client_data_b64)

            return self._send_verification_request(params, auth_options, assertion_object, purpose)

        except Exception as e:
            raise Exception(str(e))

    def _extract_client_data_b64(self, client_data_bytes):
        """Extract base64-encoded client data"""
        if hasattr(client_data_bytes, 'b64'):
            return client_data_bytes.b64
        elif isinstance(client_data_bytes, bytes):
            return utils.base64_url_encode(client_data_bytes)
        else:
            return str(client_data_bytes)

    def _create_assertion_object(self, actual_response, client_data_b64):
        """Create assertion object for verification"""
        return {
            'id': actual_response.id,
            'rawId': utils.base64_url_encode(actual_response.raw_id),
            'response': {
                'authenticatorData': utils.base64_url_encode(actual_response.response.authenticator_data),
                'clientDataJSON': client_data_b64,
                'signature': utils.base64_url_encode(actual_response.response.signature),
            },
            'type': 'public-key',
            'clientExtensionResults': getattr(actual_response, 'client_extension_results', {}) or {}
        }

    def _send_verification_request(self, params, auth_options, assertion_object, purpose):
        """Send verification request to Keeper API"""
        from ...proto import APIRequest_pb2
        from ... import api

        rq = APIRequest_pb2.PasskeyValidationRequest()
        rq.challengeToken = auth_options['challenge_token']
        rq.assertionResponse = json.dumps(assertion_object).encode('utf-8')
        rq.passkeyPurpose = (APIRequest_pb2.PasskeyPurpose.PK_REAUTH 
                           if purpose == 'vault' else APIRequest_pb2.PasskeyPurpose.PK_LOGIN)

        if auth_options.get('login_token'):
            login_token = auth_options['login_token']
            rq.encryptedLoginToken = utils.base64_url_decode(login_token) if isinstance(login_token, str) else login_token

        rs = api.communicate_rest(params, rq, API_ENDPOINTS['verify_authentication'], 
                                rs_type=APIRequest_pb2.PasskeyValidationResponse)

        return {
            'is_valid': rs.isValid,
            'login_token': rs.encryptedLoginToken,
            'credential_id': assertion_object['id'].encode() if isinstance(assertion_object['id'], str) else assertion_object['id'],
            'user_handle': getattr(getattr(getattr(assertion_object, 'response', None), 'response', None), 'user_handle', None)
        }

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
            raise Exception(str(e))

    def _report_verification_results(self, verification_result, purpose):
        """Report the verification results to the user"""
        print(f"\nBiometric Authentication Verification Results:")
        print("=" * 50)

        if verification_result['is_valid']:
            print("Status: SUCCESSFUL")
            print(f"Purpose: {purpose.upper()}")

            if verification_result.get('user_handle'):
                print(f"User Handle: {utils.base64_url_encode(verification_result['user_handle'])}")
            if verification_result.get('login_token'):
                print("Login Token: Received")

            print(f"\n{SUCCESS_MESSAGES['verification_success']}")
        else:
            print("Status: FAILED")
            print(f"Purpose: {purpose.upper()}")
            print("\n  Authentication verification failed. Please check your biometric setup.")

        print("=" * 50)

    def biometric_authenticate(self, params, username=None, **kwargs):
        """Perform biometric authentication for login"""
        try:
            purpose = kwargs.get('purpose', 'login')

            auth_options = self.client.generate_authentication_options(params, purpose)
            assertion_response = self.client.perform_authentication(auth_options)
            verification_result = self._verify_authentication_response(params, auth_options, assertion_response, purpose)

            return verification_result

        except Exception as e:
            raise Exception(str(e)) 