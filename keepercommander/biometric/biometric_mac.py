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

import json
import logging
import os
import platform
import subprocess
import threading
import time
from typing import Tuple

from keepercommander import utils

# Try to import cbor2 for proper WebAuthn CBOR encoding
try:
    import cbor2
    CBOR2_AVAILABLE = True
except ImportError:
    CBOR2_AVAILABLE = False

# FIDO2 imports for biometric authentication
try:
    from fido2.client import DefaultClientDataCollector
    from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False


# macOS Preferences Helper Functions (equivalent to Windows registry)
def get_macos_biometric_preferences_path():
    """Get the macOS preferences path for storing biometric flags"""
    home_dir = os.path.expanduser("~")
    return os.path.join(home_dir, "Library", "Preferences", "com.keepersecurity.commander.biometric.plist")


def set_macos_biometric_flag(username: str, enabled: bool) -> bool:
    """Set biometric flag in macOS preferences (equivalent to Windows registry)"""
    try:
        import plistlib
        prefs_path = get_macos_biometric_preferences_path()
        
        # Load existing preferences or create new dict
        prefs = {}
        if os.path.exists(prefs_path):
            try:
                with open(prefs_path, 'rb') as f:
                    prefs = plistlib.load(f)
            except Exception:
                prefs = {}
        
        # Update the preference
        prefs[username] = enabled
        
        # Save preferences
        os.makedirs(os.path.dirname(prefs_path), exist_ok=True)
        with open(prefs_path, 'wb') as f:
            plistlib.dump(prefs, f)
        
        return True
    except Exception as e:
        logging.debug(f'Failed to set macOS biometric flag: {e}')
        return False


def get_macos_biometric_flag(username: str) -> bool:
    """Get biometric flag from macOS preferences (equivalent to Windows registry)"""
    try:
        import plistlib
        prefs_path = get_macos_biometric_preferences_path()
        
        if not os.path.exists(prefs_path):
            return False
        
        with open(prefs_path, 'rb') as f:
            prefs = plistlib.load(f)
        
        return prefs.get(username, False)
    except Exception as e:
        logging.debug(f'Failed to get macOS biometric flag: {e}')
        return False


def detect_touch_id() -> Tuple[bool, str]:
    """Detect Touch ID availability on macOS"""
    if platform.system() != 'Darwin':
        return False, "Not running on macOS"
    
    try:
        # First, try bioutil command
        result = subprocess.run([
            'bioutil', '-r', '-s'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            # Check for Touch ID configuration indicators
            if ('touch id' in output or 
                'biometrics functionality: 1' in output or
                'biometric' in output):
                return True, "Touch ID is available and configured"
        
        # Fallback: try to check with LocalAuthentication directly
        try:
            import LocalAuthentication  # pylint: disable=import-error
            
            context = LocalAuthentication.LAContext.alloc().init()
            error = None
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                error
            )
            
            if can_evaluate:
                return True, "Touch ID is available (verified via LocalAuthentication)"
            else:
                return False, "Touch ID is not available or configured"
                
        except ImportError:
            # If LocalAuthentication is not available, try system_profiler as last resort
            result = subprocess.run([
                'system_profiler', 'SPiBridgeDataType'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'touch id' in output or 'biometric' in output:
                    return True, "Touch ID hardware detected"
            
            return False, "Touch ID detection inconclusive - LocalAuthentication not available"
        
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
        # If command-line tools fail, try LocalAuthentication as fallback
        try:
            import LocalAuthentication  # pylint: disable=import-error
            
            context = LocalAuthentication.LAContext.alloc().init()
            error = None
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                error
            )
            
            if can_evaluate:
                return True, "Touch ID is available (fallback detection)"
            else:
                return False, "Touch ID is not available or configured"
                
        except ImportError:
            return False, f"Error checking Touch ID: {str(e)}"


def create_macos_webauthn_client(data_collector, timeout=30):
    """Create macOS-specific WebAuthn client"""
    try:
        # Import the Touch ID interaction class
        from .biometric import BiometricInteraction
        interaction = BiometricInteraction(timeout)
        
        # Create custom Touch ID WebAuthn client
        return MacOSTouchIDWebAuthnClient(data_collector, interaction, timeout)
    except ImportError:
        raise Exception('macOS Touch ID client dependencies are not available')


def handle_macos_credential_creation(creation_options, timeout=30):
    """Handle macOS-specific credential creation modifications"""
    # Convert base64url encoded user ID to bytes
    if isinstance(creation_options['user'].get('id'), str):
        user_id = utils.base64_url_decode(creation_options['user']['id'])
        creation_options['user']['id'] = user_id
    
    # Remove incompatible options
    creation_options.pop('hints', None)
    creation_options.pop('extensions', None)
    
    # Check for existing credentials to prevent duplicates (like Windows FIDO2 does)
    if 'excludeCredentials' in creation_options and creation_options['excludeCredentials']:
        # Check if any excluded credentials exist in our keychain
        for excluded_cred in creation_options['excludeCredentials']:
            cred_id = excluded_cred.get('id')
            if isinstance(cred_id, str):
                cred_id_b64 = cred_id
            else:
                cred_id_b64 = utils.base64_url_encode(cred_id)
            
            # Check if this credential exists in keychain
            if load_private_key_from_keychain(cred_id_b64):
                raise Exception("A biometric credential for this account already exists on this device. Please use 'biometric unregister' first if you want to replace it.")
    
    if 'excludeCredentials' in creation_options and not creation_options['excludeCredentials']:
        creation_options.pop('excludeCredentials')
    
    # Ensure proper algorithm support
    if 'pubKeyCredParams' in creation_options:
        if not any(p.get('alg') == -7 for p in creation_options['pubKeyCredParams']):
            creation_options['pubKeyCredParams'].append({'alg': -7, 'type': 'public-key'})
    
    # Set up biometric-specific options
    if 'authenticatorSelection' not in creation_options:
        creation_options['authenticatorSelection'] = {}

    creation_options['authenticatorSelection'].update({
        'authenticatorAttachment': 'platform',
        'userVerification': 'required',
        'residentKey': 'discouraged'  # Use discouraged for macOS
    })

    creation_options['attestation'] = 'none'
    
    if 'timeout' not in creation_options:
        creation_options['timeout'] = timeout * 1000
    
    return creation_options


def handle_macos_authentication_options(pk_options, timeout=30):
    """Handle macOS-specific authentication options modifications"""
    # Remove incompatible options
    pk_options.pop('hints', None)
    pk_options.pop('extensions', None)
    
    # Set user verification requirement
    pk_options['userVerification'] = 'required'
    
    # Set timeout
    if 'timeout' not in pk_options:
        pk_options['timeout'] = timeout * 1000
    
    return pk_options


def perform_macos_authentication(client, options):
    """Perform macOS-specific biometric authentication"""
    try:
        assertion_result = client.get_assertion(options)
        return assertion_result
    except Exception as e:
        error_msg = str(e).lower()
        if "cancelled" in error_msg or "denied" in error_msg:
            raise Exception("Touch ID authentication was cancelled or denied")
        elif "timeout" in error_msg:
            raise Exception("Touch ID authentication timed out")
        elif "not available" in error_msg:
            raise Exception("Touch ID is not available or not set up")
        else:
            raise Exception(f"Touch ID authentication failed: {str(e)}")


def perform_macos_credential_creation(client, options):
    """Perform macOS-specific credential creation"""
    try:
        credential_response = client.make_credential(options)
        return credential_response
    except Exception as e:
        error_msg = str(e).lower()
        if "cancelled" in error_msg or "denied" in error_msg:
            raise Exception("Touch ID authentication was cancelled or denied")
        elif "timeout" in error_msg:
            raise Exception("Touch ID authentication timed out")
        elif "not available" in error_msg:
            raise Exception("Touch ID is not available or not set up")
        else:
            raise Exception(f"Touch ID authentication failed: {str(e)}")


def store_private_key_in_keychain(credential_id, private_key_data, rp_id):
    """Store private key data in macOS keychain"""
    try:
        import subprocess
        import base64
        
        # Encode the private key data as base64 for storage
        encoded_key = base64.b64encode(private_key_data).decode('ascii')
        
        # Create a unique service name for Keeper WebAuthn credentials
        service_name = f"Keeper WebAuthn - {rp_id}"
        account_name = f"webauthn-{credential_id}"
        
        # Use security command to add to keychain
        security_cmd = [
            'security', 'add-internet-password',
            '-s', service_name,  # service
            '-a', account_name,  # account
            '-w', encoded_key,   # password (our encoded key data)
            '-D', 'WebAuthn Credential',  # description
            '-j', f'Keeper biometric credential for {rp_id}',  # comment
            '-T', '',  # trusted applications (empty for all)
            '-U',  # update if exists

        ]
        
        # Run the security command
        result = subprocess.run(security_cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=30)
        
        if result.returncode == 0:
            print(f"🔐 Stored credential in keychain: {credential_id}")
            return True
        else:
            print(f"⚠️  Warning: Could not store in keychain: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"⚠️  Error storing in keychain: {str(e)}")
        return False


def load_private_key_from_keychain(credential_id):
    """Load private key data from macOS keychain"""
    try:
        import subprocess
        import base64
        
        # Try to find the credential in keychain
        possible_services = [
            "Keeper WebAuthn - keepersecurity.com",
        ]
        
        account_name = f"webauthn-{credential_id}"
        
        for service_name in possible_services:
            try:
                # Use security command to find the password
                security_cmd = [
                    'security', 'find-internet-password',
                    '-s', service_name,
                    '-a', account_name,
                    '-w'  # output password only
                ]
                
                result = subprocess.run(security_cmd, 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                
                if result.returncode == 0:
                    encoded_key = result.stdout.strip()
                    if encoded_key:
                        # Decode the base64 encoded key data
                        key_data = base64.b64decode(encoded_key)
                        print(f"🔐 Retrieved private key from keychain: {credential_id}")
                        return key_data
                        
            except Exception:
                continue
                
        return None
        
    except Exception as e:
        print(f"⚠️  Error loading from keychain: {str(e)}")
        return None


def delete_keychain_item(credential_id):
    """Delete a credential from macOS keychain"""
    try:
        import subprocess
        
        # Try to delete from keychain using all possible service names
        possible_services = [
            "Keeper WebAuthn - keepersecurity.com",
        ]
        
        account_name = f"webauthn-{credential_id}"
        deleted = False
        
        for service_name in possible_services:
            try:
                # Use security command to delete the password
                security_cmd = [
                    'security', 'delete-internet-password',
                    '-s', service_name,
                    '-a', account_name
                ]
                
                result = subprocess.run(security_cmd, 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                
                if result.returncode == 0:
                    print(f"🗑️  Removed credential from keychain: {credential_id}")
                    deleted = True
                    break
                    
            except Exception:
                continue
        
        return deleted
            
    except Exception as e:
        print(f"⚠️  Error deleting from keychain: {str(e)}")
        return False


class MacOSTouchIDWebAuthnClient:
    """
    Custom macOS WebAuthn client that implements FIDO2 interface but uses Touch ID internally.
    """
    
    def __init__(self, client_data_collector, user_interaction, timeout=30):
        self.client_data_collector = client_data_collector
        self.user_interaction = user_interaction
        self.timeout = timeout
        
        # Verify Touch ID availability
        supported, message = detect_touch_id()
        if not supported:
            print(f"⚠️  Touch ID detection: {message}")
        else:
            print(f"✅ Touch ID available: {message}")
    
    def make_credential(self, options):
        """Create WebAuthn credential using Touch ID + keychain storage"""
        print("🍎 Creating Touch ID credential using FIDO2-compatible format...")
        
        try:
            # Import macOS-specific modules
            try:
                import LocalAuthentication  # pylint: disable=import-error
            except ImportError:
                raise Exception("LocalAuthentication framework not available. Please install PyObjC.")
            
            # Generate a credential ID
            credential_id = utils.base64_url_encode(os.urandom(32))
            print(f"🔑 Generated credential ID: {credential_id}")
            
            # Create LocalAuthentication context
            context = LocalAuthentication.LAContext.alloc().init()
            
            # Check if biometrics are available
            error = None
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                error
            )
            
            if not can_evaluate:
                raise Exception("Touch ID is not available or configured on this device")
            
            # Create real EC P-256 key pair using cryptography library
            print("🔑 Generating EC P-256 key pair...")
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
            
            # Generate EC P-256 private key
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            
            # Export public key in uncompressed format
            public_key_data = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Store the private key in keychain
            private_key_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            rp_id = options.rp.id or 'keepersecurity.com'
            store_private_key_in_keychain(credential_id, private_key_data, rp_id)
            
            # Perform Touch ID authentication
            print("🔐 Please authenticate with Touch ID to register credential...")
            success = self._authenticate_with_touchid_sync(context, 
                f"Register biometric authentication for {rp_id}", 
                self.timeout)
            
            if not success:
                # Clean up the key if authentication failed
                delete_keychain_item(credential_id)
                raise Exception("Touch ID authentication failed or was cancelled")
            
            print("✅ Touch ID authentication successful!")
            
            # Create WebAuthn attestation object
            challenge = options.challenge
            
            # Create client data
            origin = getattr(self.client_data_collector, 'origin', f'https://{rp_id}') if self.client_data_collector else f'https://{rp_id}'
            client_data = {
                'type': 'webauthn.create',
                'challenge': utils.base64_url_encode(challenge),
                'origin': origin,
                'crossOrigin': False
            }
            client_data_json = json.dumps(client_data, separators=(',', ':')).encode()
            
            # Create proper CBOR-encoded attestation object
            import hashlib
            import struct
            
            # RP ID hash
            rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
            
            # Flags byte (UP=1, UV=1, AT=1)
            flags = 0b01000101
            
            # Counter (4 bytes)
            counter = struct.pack('>I', 0)
            
            # Create COSE Key format for ES256
            if not CBOR2_AVAILABLE:
                raise Exception("cbor2 library is required. Please install: pip install cbor2")
            
            x_coord, y_coord = self._extract_public_key_coordinates(public_key_data)
            
            cose_key = {
                1: 2,      # kty: EC2
                3: -7,     # alg: ES256  
                -1: 1,     # crv: P-256
                -2: x_coord,  # x coordinate
                -3: y_coord   # y coordinate
            }
            
            cose_key_cbor = cbor2.dumps(cose_key)
            
            # Create attested credential data
            attested_credential_data = (
                b'\x00' * 16 +  # AAGUID (16 bytes)
                struct.pack('>H', len(utils.base64_url_decode(credential_id))) +  # Credential ID length
                utils.base64_url_decode(credential_id) +  # Credential ID
                cose_key_cbor  # CBOR-encoded public key
            )
            
            # Create complete authenticator data
            authenticator_data = rp_id_hash + struct.pack('B', flags) + counter + attested_credential_data
            
            # Create attestation object
            attestation_object_dict = {
                'fmt': 'none',  # Format identifier
                'attStmt': {},  # Attestation statement (empty for 'none' format)
                'authData': authenticator_data  # Raw bytes
            }
            
            attestation_object_cbor = cbor2.dumps(attestation_object_dict)
            
            # Create FIDO2-compatible registration response
            class MacOSRegistrationResponse:
                def __init__(self, cred_id, cred_raw_id, client_data, attestation_obj):
                    self.id = cred_id
                    self.raw_id = cred_raw_id
                    self.response = MacOSAuthenticatorAttestationResponse(client_data, attestation_obj)
                    self.client_extension_results = {}
                    self.type = 'public-key'
                    
            class MacOSAuthenticatorAttestationResponse:
                def __init__(self, client_data, attestation_obj):
                    self.client_data = client_data
                    self.attestation_object = attestation_obj
            
            credential_response = MacOSRegistrationResponse(
                credential_id,
                utils.base64_url_decode(credential_id),
                client_data_json,
                attestation_object_cbor
            )
            
            print("✅ FIDO2-compatible Touch ID credential created successfully!")
            return credential_response
            
        except Exception as e:
            raise Exception(f"Failed to create Touch ID credential: {str(e)}")
    
    def get_assertion(self, options):
        """Get WebAuthn assertion using Touch ID + keychain stored keys"""
        print("🍎 Authenticating with Touch ID using FIDO2-compatible format...")
        
        try:
            # Import macOS-specific modules
            try:
                import LocalAuthentication  # pylint: disable=import-error
            except ImportError:
                raise Exception("LocalAuthentication framework not available. Please install PyObjC.")
            
            # Get challenge and other parameters
            challenge = options.challenge
            rp_id = options.rp_id or 'keepersecurity.com'
            
            # Get allowed credentials
            allowed_credentials = options.allow_credentials or []
            if not allowed_credentials:
                raise Exception("No allowed credentials found in authentication request")
            
            # Find a credential that exists in our keychain
            private_key = None
            credential_id_b64 = None
            credential_id_bytes = None
            
            for credential_info in allowed_credentials:
                cred_id = credential_info.id
                if isinstance(cred_id, str):
                    test_cred_id_b64 = cred_id
                    test_cred_id_bytes = utils.base64_url_decode(cred_id)
                else:
                    test_cred_id_bytes = cred_id
                    test_cred_id_b64 = utils.base64_url_encode(cred_id)
                
                # Try to retrieve the private key from keychain
                test_private_key = self._retrieve_private_key_from_keychain(test_cred_id_b64)
                if test_private_key:
                    private_key = test_private_key
                    credential_id_b64 = test_cred_id_b64
                    credential_id_bytes = test_cred_id_bytes
                    print(f"🔑 Found credential in keychain: {credential_id_b64}")
                    break
            
            if not private_key:
                raise Exception("No matching credential found in keychain. Please run 'biometric register' first.")
            
            # Create LocalAuthentication context
            context = LocalAuthentication.LAContext.alloc().init()
            
            # Check if biometrics are available
            error = None
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                error
            )
            
            if not can_evaluate:
                raise Exception("Touch ID is not available or configured on this device")
            
            # Perform Touch ID authentication
            print(f"🔐 Please authenticate with Touch ID for {rp_id}...")
            
            # Create client data JSON
            origin = getattr(self.client_data_collector, 'origin', f'https://{rp_id}') if self.client_data_collector else f'https://{rp_id}'
            client_data = {
                'type': 'webauthn.get',
                'challenge': utils.base64_url_encode(challenge),
                'origin': origin,
                'crossOrigin': False
            }
            client_data_json = json.dumps(client_data, separators=(',', ':')).encode('utf-8')
            
            # Create authenticator data
            import hashlib
            import struct
            
            rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
            flags = 0b00000101  # UP=1, UV=1 (user present, user verified)
            counter = struct.pack('>I', 0)  # Counter = 0
            
            authenticator_data = rp_id_hash + struct.pack('B', flags) + counter
            
            # Create the data to be signed
            client_data_hash = hashlib.sha256(client_data_json).digest()
            signed_data = authenticator_data + client_data_hash
            
            # Perform Touch ID authentication before signing
            success = self._authenticate_with_touchid_sync(context, 
                f"Authenticate with Keeper for {rp_id}", 
                self.timeout)
            
            if not success:
                raise Exception("Touch ID authentication failed or was cancelled")
            
            print("✅ Touch ID authentication successful!")
            
            # Sign the data using the private key
            print("🔏 Signing authentication challenge...")
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            
            # Create DER signature
            der_signature = private_key.sign(
                signed_data,
                ec.ECDSA(hashes.SHA256())
            )
            
            print("✅ Signature created successfully!")
            
            # Create FIDO2-compatible assertion response
            class MacOSAuthenticationResponse:
                def __init__(self, cred_id, cred_raw_id, client_data, auth_data, sig, user_handle):
                    self.id = cred_id
                    self.raw_id = cred_raw_id
                    self.response = MacOSAuthenticatorAssertionResponse(client_data, auth_data, sig, user_handle)
                    self.client_extension_results = {}
                    self.type = 'public-key'
                    
            class MacOSAuthenticatorAssertionResponse:
                def __init__(self, client_data, auth_data, sig, user_handle):
                    self.client_data = client_data
                    self.authenticator_data = auth_data
                    self.signature = sig  # Use DER signature directly
                    self.user_handle = user_handle
            
            assertion_response = MacOSAuthenticationResponse(
                credential_id_b64,
                credential_id_bytes,
                client_data_json,
                authenticator_data,
                der_signature,
                None
            )
            
            print("✅ FIDO2-compatible Touch ID assertion created successfully!")
            return assertion_response
            
        except Exception as e:
            raise Exception(f"Failed to perform Touch ID authentication: {str(e)}")
    
    def _authenticate_with_touchid_sync(self, context, reason, timeout=30):
        """Perform synchronous Touch ID authentication"""
        import threading
        import time
        
        try:
            import LocalAuthentication  # pylint: disable=import-error
        except ImportError:
            raise Exception("LocalAuthentication framework not available")
        
        result = {'success': False}
        error_holder = {'error': None}
        
        def auth_callback(success, error):
            result['success'] = bool(success)
            error_holder['error'] = error
        
        # Start authentication
        try:
            context.evaluatePolicy_localizedReason_reply_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                reason,
                auth_callback
            )
        except Exception as e:
            raise Exception(f"Failed to start Touch ID prompt: {str(e)}")
        
        # Wait for result with timeout
        start_time = time.time()
        while time.time() - start_time < timeout:
            if result['success'] or error_holder['error']:
                break
            time.sleep(0.1)
        
        if error_holder['error']:
            raise Exception(f"Touch ID authentication failed: {error_holder['error']}")
        
        return result['success']
    
    def _retrieve_private_key_from_keychain(self, credential_id):
        """Retrieve private key from keychain by credential ID"""
        try:
            # Load the private key data from keychain
            private_key_data = load_private_key_from_keychain(credential_id)
            if not private_key_data:
                return None
            
            # Deserialize the private key using cryptography library
            from cryptography.hazmat.primitives import serialization
            
            private_key = serialization.load_der_private_key(
                private_key_data,
                password=None
            )
            
            return private_key
                
        except Exception as e:
            print(f"⚠️  Error retrieving key from keychain: {str(e)}")
            return None
    
    def _extract_public_key_coordinates(self, public_key_data):
        """Extract x and y coordinates from EC P-256 public key data"""
        try:
            # P-256 public key in uncompressed format:
            # 1 byte: 0x04 (uncompressed point indicator)
            # 32 bytes: x coordinate
            # 32 bytes: y coordinate
            
            if len(public_key_data) != 65:
                raise Exception(f"Invalid P-256 public key length: {len(public_key_data)}, expected 65")
            
            if public_key_data[0] != 0x04:
                raise Exception(f"Invalid P-256 public key format: expected 0x04, got 0x{public_key_data[0]:02x}")
            
            x_coord = public_key_data[1:33]   # bytes 1-32
            y_coord = public_key_data[33:65]  # bytes 33-64
            
            return x_coord, y_coord
            
        except Exception as e:
            raise Exception(f"Failed to extract public key coordinates: {str(e)}") 