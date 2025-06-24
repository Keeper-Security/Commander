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
from typing import Dict, Any, Tuple

from .... import utils, crypto
from ...utils.constants import (
    AUTH_REASONS,
    ERROR_MESSAGES,
    DEFAULT_BIOMETRIC_TIMEOUT
)
from ...utils.error_handler import BiometricErrorHandler

# WebAuthn constants
WEBAUTHN_CHALLENGE_TYPE_CREATE = 'webauthn.create'
WEBAUTHN_CHALLENGE_TYPE_GET = 'webauthn.get'
WEBAUTHN_CREDENTIAL_TYPE = 'public-key'

# Cryptographic constants
EC_CURVE_P256 = 1
EC_ALG_ES256 = -7
EC_KTY_EC2 = 2
EC_PUBLIC_KEY_UNCOMPRESSED_PREFIX = 0x04
EC_COORDINATE_LENGTH = 32

# Authentication flags
AUTH_FLAG_UP = 0b00000001  # User Present
AUTH_FLAG_UV = 0b00000100  # User Verified
AUTH_FLAG_AT = 0b01000000  # Attested credential data included
AUTH_FLAG_CREATION = AUTH_FLAG_UP | AUTH_FLAG_UV | AUTH_FLAG_AT  # 0b01000101
AUTH_FLAG_ASSERTION = AUTH_FLAG_UP | AUTH_FLAG_UV  # 0b00000101


class BaseWebAuthnClient:
    """Base WebAuthn client with common functionality"""
    
    def __init__(self, client_data_collector, keychain_manager):
        self.client_data_collector = client_data_collector
        self.keychain_manager = keychain_manager

    def _validate_dependencies(self, required_modules: list) -> None:
        """Validate that required modules are available"""
        BiometricErrorHandler.validate_dependencies(required_modules)

    def _create_client_data(self, data_type: str, challenge: bytes, rp_id: str) -> Tuple[Dict[str, Any], bytes]:
        """Create WebAuthn client data"""
        origin = getattr(self.client_data_collector, 'origin', f'https://{rp_id}')
        client_data = {
            'type': data_type,
            'challenge': utils.base64_url_encode(challenge),
            'origin': origin,
            'crossOrigin': False
        }
        client_data_json = json.dumps(client_data, separators=(',', ':')).encode()
        return client_data, client_data_json

    def _create_authenticator_data(self, rp_id: str, flags: int, counter: int = 0, 
                                 additional_data: bytes = b'') -> bytes:
        """Create WebAuthn authenticator data"""
        import hashlib
        import struct
        
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        counter_bytes = struct.pack('>I', counter)
        return rp_id_hash + struct.pack('B', flags) + counter_bytes + additional_data

    def _create_signed_data(self, authenticator_data: bytes, client_data_json: bytes) -> bytes:
        """Create data to be signed for WebAuthn"""
        import hashlib
        client_data_hash = hashlib.sha256(client_data_json).digest()
        return authenticator_data + client_data_hash


class MacOSTouchIDWebAuthnClient(BaseWebAuthnClient):
    """macOS Touch ID WebAuthn client with DRY principles"""
    
    def __init__(self, client_data_collector, keychain_manager):
        super().__init__(client_data_collector, keychain_manager)

    def make_credential(self, options):
        """Create WebAuthn credential using Touch ID"""
        try:
            self._validate_dependencies(['LocalAuthentication', 'cbor2'])
            
            timeout_ms = getattr(options, 'timeout', None)
            timeout_seconds = (timeout_ms / 1000.0) if timeout_ms else DEFAULT_BIOMETRIC_TIMEOUT
            
            if hasattr(options, 'exclude_credentials') and options.exclude_credentials:
                for excluded_cred in options.exclude_credentials:
                    cred_id = excluded_cred.id
                    if isinstance(cred_id, str):
                        cred_id_b64 = cred_id
                    else:
                        cred_id_b64 = utils.base64_url_encode(cred_id)
                    
                    if self.keychain_manager.credential_exists(cred_id_b64, options.rp.id, timeout_seconds):
                        raise OSError("The object already exists")
            
            credential_id = utils.base64_url_encode(crypto.get_random_bytes(32))
            private_key, public_key = crypto.generate_ec_key()
            public_key_data = crypto.unload_ec_public_key(public_key)
            private_key_data = crypto.unload_ec_private_key(private_key)

            rp_id = options.rp.id
            if not rp_id:
                raise Exception("No RP ID found in options - server configuration error")
            context = self._create_auth_context()
            self._check_biometric_availability(context)
            
            if not self.keychain_manager.store_credential(credential_id, private_key_data, rp_id, timeout_seconds):
                raise Exception(ERROR_MESSAGES['keychain_store_failed'])
            
            reason = AUTH_REASONS['register'].format(rp_id=rp_id)
            success = self._authenticate_with_touchid(context, reason, timeout_seconds)
            
            if not success:
                self.keychain_manager.delete_credential(credential_id, rp_id, timeout_seconds)
                raise Exception(ERROR_MESSAGES['authentication_failed'])

            return self._create_credential_response(
                options, credential_id, public_key_data, rp_id
            )

        except Exception as e:
            raise Exception(str(e))

    def get_assertion(self, options):
        """Get WebAuthn assertion using Touch ID"""
        try:
            self._validate_dependencies(['LocalAuthentication'])
            
            timeout_ms = getattr(options, 'timeout', None)
            timeout_seconds = (timeout_ms / 1000.0) if timeout_ms else DEFAULT_BIOMETRIC_TIMEOUT
            
            challenge = options.challenge
            rp_id = options.rp_id
            if not rp_id:
                raise Exception("No RP ID found in options - server configuration error")
            private_key, credential_id_b64, credential_id_bytes = self._find_credential(options, rp_id, timeout_seconds)
            
            context = self._create_auth_context()
            self._check_biometric_availability(context)
            
            reason = AUTH_REASONS['login'].format(rp_id=rp_id)
            success = self._authenticate_with_touchid(context, reason, timeout_seconds)
            
            if not success:
                raise Exception(ERROR_MESSAGES['authentication_failed'])

            return self._create_assertion_response(
                challenge, rp_id, credential_id_b64, credential_id_bytes, private_key
            )

        except Exception as e:
            raise Exception(str(e))

    def _create_auth_context(self):
        """Create LocalAuthentication context"""
        import LocalAuthentication  # pylint: disable=import-error
        return LocalAuthentication.LAContext.alloc().init()  # pylint: disable=no-member

    def _check_biometric_availability(self, context):
        """Check if biometric authentication is available"""
        import LocalAuthentication  # pylint: disable=import-error
        
        error = None
        can_evaluate = context.canEvaluatePolicy_error_(
            LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
            error
        )
        
        if not can_evaluate:
            raise Exception(ERROR_MESSAGES['touchid_not_available'])

    def _authenticate_with_touchid(self, context, reason: str, timeout_seconds: float = 30) -> bool:
        """Perform Touch ID authentication with proper synchronization"""
        import LocalAuthentication  # pylint: disable=import-error
        import threading
                
        event = threading.Event()
        result = {'success': False, 'error': None}
        
        def auth_callback(success, error):
            result['success'] = bool(success)
            result['error'] = error
            event.set()
        
        context.evaluatePolicy_localizedReason_reply_(
            LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
            reason,
            auth_callback
        )
        
        # Wait for result with synchronization
        if event.wait(timeout=timeout_seconds):
            if result['error']:
                from ...utils.error_handler import BiometricErrorHandler
                raise BiometricErrorHandler.handle_authentication_error(
                    Exception(str(result['error'])), "Touch ID"
                )
            return result['success']
        else:
            raise TimeoutError("Touch ID authentication timed out")

    def _find_credential(self, options, rp_id: str, timeout_seconds: float) -> Tuple[Any, str, bytes]:
        """Find credential using keychain manager"""
        allowed_credentials = options.allow_credentials or []
        if not allowed_credentials:
            raise Exception("No allowed credentials found")

        for cred in allowed_credentials:
            cred_id = cred.id
            if isinstance(cred_id, str):
                test_id_b64 = cred_id
                test_id_bytes = utils.base64_url_decode(cred_id)
            else:
                test_id_bytes = cred_id
                test_id_b64 = utils.base64_url_encode(cred_id)

            test_key = self.keychain_manager.load_credential(test_id_b64, rp_id, timeout_seconds)
            if test_key:
                return test_key, test_id_b64, test_id_bytes

        from ...utils.error_handler import BiometricErrorHandler
        raise BiometricErrorHandler.handle_authentication_error(
            Exception("no matching credential found"), "Touch ID"
        )

    def _create_credential_response(self, options, credential_id: str, 
                                  public_key_data: bytes, rp_id: str):
        """Create WebAuthn credential response"""
        import cbor2
        import struct
        
        challenge = options.challenge
        client_data, client_data_json = self._create_client_data(
            WEBAUTHN_CHALLENGE_TYPE_CREATE, challenge, rp_id
        )

        # Create COSE key
        x_coord, y_coord = self._extract_key_coordinates(public_key_data)
        cose_key = {
            1: EC_KTY_EC2,      # kty: EC2
            3: EC_ALG_ES256,    # alg: ES256
            -1: EC_CURVE_P256,  # crv: P-256
            -2: x_coord,
            -3: y_coord
        }

        # Create attested credential data
        attested_credential_data = (
            b'\x00' * 16 +  # AAGUID
            struct.pack('>H', len(utils.base64_url_decode(credential_id))) +
            utils.base64_url_decode(credential_id) +
            cbor2.dumps(cose_key)
        )

        # Create authenticator data
        authenticator_data = self._create_authenticator_data(
            rp_id, AUTH_FLAG_CREATION, 0, attested_credential_data
        )

        # Create attestation object
        attestation_object = {
            'fmt': 'none',
            'attStmt': {},
            'authData': authenticator_data
        }

        return self._create_registration_response(
            credential_id,
            client_data_json,
            cbor2.dumps(attestation_object)
        )

    def _create_assertion_response(self, challenge: bytes, rp_id: str, 
                                 credential_id_b64: str, credential_id_bytes: bytes, 
                                 private_key):
        """Create WebAuthn assertion response"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        
        client_data, client_data_json = self._create_client_data(
            WEBAUTHN_CHALLENGE_TYPE_GET, challenge, rp_id
        )

        # Create authenticator data
        authenticator_data = self._create_authenticator_data(rp_id, AUTH_FLAG_ASSERTION)

        # Sign the data
        signed_data = self._create_signed_data(authenticator_data, client_data_json)
        der_signature = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

        return self._create_authentication_response(
            credential_id_b64,
            credential_id_bytes,
            client_data_json,
            authenticator_data,
            der_signature
        )

    def _extract_key_coordinates(self, public_key_data: bytes) -> Tuple[bytes, bytes]:
        """Extract x and y coordinates from EC key"""
        expected_length = 1 + (2 * EC_COORDINATE_LENGTH)  # 1 + (2 * 32) = 65
        if len(public_key_data) != expected_length or public_key_data[0] != EC_PUBLIC_KEY_UNCOMPRESSED_PREFIX:
            raise Exception("Invalid P-256 public key format")
        
        return (public_key_data[1:1 + EC_COORDINATE_LENGTH], 
                public_key_data[1 + EC_COORDINATE_LENGTH:])

    def _create_registration_response(self, credential_id: str, client_data_json: bytes, 
                                    attestation_object_cbor: bytes):
        """Create registration response"""
        class RegistrationResponse:
            def __init__(self, cred_id, cred_raw_id, client_data, attestation_obj):
                self.id = cred_id
                self.raw_id = cred_raw_id
                self.response = AttestationResponse(client_data, attestation_obj)
                self.client_extension_results = {}
                self.type = WEBAUTHN_CREDENTIAL_TYPE
                
        class AttestationResponse:
            def __init__(self, client_data, attestation_obj):
                self.client_data = client_data
                self.attestation_object = attestation_obj
        
        return RegistrationResponse(
            credential_id,
            utils.base64_url_decode(credential_id),
            client_data_json,
            attestation_object_cbor
        )

    def _create_authentication_response(self, credential_id_b64: str, credential_id_bytes: bytes, 
                                      client_data_json: bytes, authenticator_data: bytes, 
                                      signature: bytes):
        """Create authentication response"""
        class AuthenticationResponse:
            def __init__(self, cred_id, cred_raw_id, client_data, auth_data, sig):
                self.id = cred_id
                self.raw_id = cred_raw_id
                self.response = AssertionResponse(client_data, auth_data, sig)
                self.client_extension_results = {}
                self.type = WEBAUTHN_CREDENTIAL_TYPE
                
        class AssertionResponse:
            def __init__(self, client_data, auth_data, sig):
                self.client_data = client_data
                self.authenticator_data = auth_data
                self.signature = sig
                self.user_handle = None
        
        return AuthenticationResponse(
            credential_id_b64,
            credential_id_bytes,
            client_data_json,
            authenticator_data,
            signature
        ) 