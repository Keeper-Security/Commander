import json
import logging
import os
import platform
import subprocess
import threading
import time
from typing import Dict, Any, Tuple

from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from ... import utils
from ..core.base import StorageHandler
from .base import BasePlatformHandler


class MacOSStorageHandler(StorageHandler):
    """macOS plist storage handler"""

    def __init__(self):
        self.prefs_path = self._get_prefs_path()

    def _get_prefs_path(self):
        """Get macOS preferences path"""
        home_dir = os.path.expanduser("~")
        return os.path.join(home_dir, "Library", "Preferences", "com.keepersecurity.commander.biometric.plist")

    def get_biometric_flag(self, username: str) -> bool:
        """Get biometric flag from macOS preferences"""
        try:
            import plistlib
            if not os.path.exists(self.prefs_path):
                return False
            
            with open(self.prefs_path, 'rb') as f:
                prefs = plistlib.load(f)
            
            return prefs.get(username, False)
        except Exception as e:
            logging.debug(f'Failed to get macOS biometric flag: {e}')
            return False

    def set_biometric_flag(self, username: str, enabled: bool) -> bool:
        """Set biometric flag in macOS preferences"""
        try:
            import plistlib
            prefs = {}
            
            if os.path.exists(self.prefs_path):
                try:
                    with open(self.prefs_path, 'rb') as f:
                        prefs = plistlib.load(f)
                except Exception:
                    prefs = {}
            
            prefs[username] = enabled
            
            os.makedirs(os.path.dirname(self.prefs_path), exist_ok=True)
            with open(self.prefs_path, 'wb') as f:
                plistlib.dump(prefs, f)
            
            return True
        except Exception as e:
            logging.debug(f'Failed to set macOS biometric flag: {e}')
            return False

    def delete_biometric_flag(self, username: str) -> bool:
        """Delete biometric flag from macOS preferences"""
        try:
            import plistlib
            if not os.path.exists(self.prefs_path):
                return True  # Already deleted/doesn't exist
            
            with open(self.prefs_path, 'rb') as f:
                prefs = plistlib.load(f)
            
            if username in prefs:
                del prefs[username]
                
                # Save the updated plist
                with open(self.prefs_path, 'wb') as f:
                    plistlib.dump(prefs, f)
            
            return True
        except Exception as e:
            logging.debug(f'Failed to delete macOS biometric flag: {e}')
            return False


class MacOSHandler(BasePlatformHandler):
    """macOS-specific biometric handler"""

    def __init__(self):
        super().__init__()

    def _create_storage_handler(self) -> StorageHandler:
        return MacOSStorageHandler()

    def _ensure_pam_configured(self):
        """Ensure Touch ID is configured for sudo if not already present"""
        try:
            with open('/etc/pam.d/sudo', 'r') as f:
                content = f.read()
            if 'pam_tid.so' not in content:
                print("\n" + "="*60)
                print("TOUCH ID CONFIGURATION REQUIRED")
                print("="*60)
                print("To enable Touch ID for sudo commands, Keeper needs to modify")
                print("the system configuration file (/etc/pam.d/sudo).")
                print("\nThis will allow you to use Touch ID instead of typing your")
                print("password when running sudo commands in the terminal.")
                print("\nYou will be prompted for your macOS account password to")
                print("authorize this system configuration change.")
                print("="*60)
                
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.strip() and not line.strip().startswith('#'):
                        lines.insert(i, 'auth       sufficient     pam_tid.so')
                        break
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                    tmp.write('\n'.join(lines))
                    tmp.flush()
                    subprocess.run(['sudo', 'cp', tmp.name, '/etc/pam.d/sudo'], check=True)
                    os.unlink(tmp.name)
                    print("✓ Touch ID for sudo has been successfully configured!")
        except Exception:
            pass  # Silently fail if cannot configure PAM

    def detect_capabilities(self) -> Tuple[bool, str]:
        """Detect Touch ID availability on macOS"""
        if platform.system() != 'Darwin':
            return False, "Not running on macOS"

        error_messages = []

        try:
            # Try bioutil command first
            try:
                result = subprocess.run([
                    'bioutil', '-r', '-s'
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    output = result.stdout.lower()
                    if ('touch id' in output or 
                        'biometrics functionality: 1' in output or
                        'biometric' in output):
                        self._ensure_pam_configured()
                        return True, "Touch ID is available and configured"
                    else:
                        error_messages.append(f"bioutil: ran successfully but no Touch ID detected")
                else:
                    error_messages.append(f"bioutil: command failed (return code {result.returncode})")
            except FileNotFoundError:
                error_messages.append("bioutil: command not found")
            except Exception as e:
                error_messages.append(f"bioutil: {str(e)}")

            # Fallback: LocalAuthentication check
            try:
                import LocalAuthentication  # pylint: disable=import-error
                context = LocalAuthentication.LAContext.alloc().init()  # pylint: disable=no-member
                error = None
                can_evaluate = context.canEvaluatePolicy_error_(
                    LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                    error
                )
                
                if can_evaluate:
                    self._ensure_pam_configured()
                    return True, "Touch ID is available"
                else:
                    la_error = f"LocalAuthentication: policy evaluation failed"
                    if error:
                        la_error += f" (error: {error})"
                    error_messages.append(la_error)
                    
            except ImportError as e:
                error_messages.append(f"LocalAuthentication: import failed - {str(e)}")
                error_messages.append("LocalAuthentication: try 'pip install pyobjc-framework-LocalAuthentication'")
            except Exception as e:
                error_messages.append(f"LocalAuthentication: {str(e)}")

            # System profiler as last resort
            try:
                result = subprocess.run([
                    'system_profiler', 'SPiBridgeDataType'
                ], capture_output=True, text=True, timeout=15)

                if result.returncode == 0:
                    output = result.stdout.lower()
                    if 'touch id' in output or 'biometric' in output:
                        self._ensure_pam_configured()
                        return True, "Touch ID hardware detected"
                    else:
                        error_messages.append("system_profiler: no Touch ID hardware found")
                else:
                    error_messages.append(f"system_profiler: failed (return code {result.returncode})")
            except Exception as e:
                error_messages.append(f"system_profiler: {str(e)}")

            # If we get here, all detection methods failed
            detailed_error = "Touch ID detection failed. " + "; ".join(error_messages)
            detailed_error += ". Please verify Touch ID is set up in System Preferences > Touch ID & Password"
            return False, detailed_error

        except Exception as e:
            return False, f"Error checking Touch ID: {str(e)}"

    def create_webauthn_client(self, data_collector, timeout: int = 30):
        """Create macOS Touch ID WebAuthn client"""
        try:
            from ..core.base import BiometricInteraction
            interaction = BiometricInteraction(timeout)
            return MacOSTouchIDWebAuthnClient(data_collector, interaction, timeout)
        except ImportError:
            raise Exception('macOS Touch ID client dependencies not available')

    def handle_credential_creation(self, creation_options: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        """Handle macOS-specific credential creation"""
        # Convert user ID to bytes
        if isinstance(creation_options['user'].get('id'), str):
            user_id = utils.base64_url_decode(creation_options['user']['id'])
            creation_options['user']['id'] = user_id

        # Remove unsupported options
        creation_options.pop('hints', None)
        creation_options.pop('extensions', None)

        # Check for existing credentials
        if 'excludeCredentials' in creation_options and creation_options['excludeCredentials']:
            for excluded_cred in creation_options['excludeCredentials']:
                cred_id = excluded_cred.get('id')
                if isinstance(cred_id, str):
                    cred_id_b64 = cred_id
                else:
                    cred_id_b64 = utils.base64_url_encode(cred_id)
                
                if self._credential_exists_in_keychain(cred_id_b64):
                    raise Exception("A biometric credential for this account already exists. Use 'biometric unregister' first.")

        if 'excludeCredentials' in creation_options and not creation_options['excludeCredentials']:
            creation_options.pop('excludeCredentials')

        # Set authenticator selection
        if 'authenticatorSelection' not in creation_options:
            creation_options['authenticatorSelection'] = {}

        creation_options['authenticatorSelection'].update({
            'authenticatorAttachment': 'platform',
            'userVerification': 'required',
            'residentKey': 'discouraged'
        })

        creation_options['attestation'] = 'none'
        
        if 'timeout' not in creation_options:
            creation_options['timeout'] = timeout * 1000

        return creation_options

    def handle_authentication_options(self, pk_options: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
        """Handle macOS-specific authentication options"""
        pk_options.pop('hints', None)
        pk_options.pop('extensions', None)
        pk_options['userVerification'] = 'required'
        
        if 'timeout' not in pk_options:
            pk_options['timeout'] = timeout * 1000

        return pk_options

    def perform_authentication(self, client, options: PublicKeyCredentialRequestOptions):
        """Perform macOS Touch ID authentication"""
        try:
            return client.get_assertion(options)
        except Exception as e:
            error_msg = str(e).lower()
            if "cancelled" in error_msg or "denied" in error_msg:
                raise Exception("Touch ID authentication cancelled")
            elif "timeout" in error_msg:
                raise Exception("Touch ID authentication timed out")
            elif "not available" in error_msg:
                raise Exception("Touch ID is not available or not set up")
            else:
                raise Exception(f"Touch ID authentication failed: {str(e)}")

    def perform_credential_creation(self, client, options: PublicKeyCredentialCreationOptions):
        """Perform macOS Touch ID credential creation"""
        try:
            return client.make_credential(options)
        except Exception as e:
            error_msg = str(e).lower()
            if "cancelled" in error_msg or "denied" in error_msg:
                raise Exception("Touch ID authentication cancelled")
            elif "timeout" in error_msg:
                raise Exception("Touch ID authentication timed out")
            elif "not available" in error_msg:
                raise Exception("Touch ID is not available or not set up")
            else:
                raise Exception(f"Touch ID authentication failed: {str(e)}")

    def _credential_exists_in_keychain(self, credential_id: str) -> bool:
        """Check if credential exists in keychain"""
        try:
            import subprocess
            account_name = f"webauthn-{credential_id}"
            
            possible_services = [
                "Keeper WebAuthn - keepersecurity.com",
            ]
            
            for service_name in possible_services:
                try:
                    result = subprocess.run([
                        'security', 'find-internet-password',
                        '-s', service_name,
                        '-a', account_name,
                        '-w'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        return True
                except Exception:
                    continue
            
            return False
        except Exception:
            return False


class MacOSTouchIDWebAuthnClient:
    """Custom macOS WebAuthn client using Touch ID"""
    
    def __init__(self, client_data_collector, user_interaction, timeout=30):
        self.client_data_collector = client_data_collector
        self.user_interaction = user_interaction
        self.timeout = timeout

    def make_credential(self, options):
        """Create WebAuthn credential using Touch ID"""
        try:
            # Import required modules
            try:
                import LocalAuthentication  # pylint: disable=import-error
                import cbor2
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives import serialization
                import hashlib
                import struct
            except ImportError as e:
                raise Exception(f"Required dependencies not available: {e}")

            # Generate credential ID
            credential_id = utils.base64_url_encode(os.urandom(32))
            
            # Create LocalAuthentication context
            context = LocalAuthentication.LAContext.alloc().init()  # pylint: disable=no-member
            
            # Check biometric availability
            error = None
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                error
            )
            
            if not can_evaluate:
                raise Exception("Touch ID is not available or configured")

            # Generate EC P-256 key pair
            private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            
            # Export public key
            public_key_data = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

            # Store private key in keychain
            private_key_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            rp_id = options.rp.id or 'keepersecurity.com'
            self._store_key_in_keychain(credential_id, private_key_data, rp_id)

            # Perform Touch ID authentication
            success = self._authenticate_with_touchid(context, 
                f"Register biometric authentication for {rp_id}")

            if not success:
                self._delete_key_from_keychain(credential_id)
                raise Exception("Touch ID authentication failed")

            # Create WebAuthn response
            challenge = options.challenge
            origin = getattr(self.client_data_collector, 'origin', f'https://{rp_id}')
            
            client_data = {
                'type': 'webauthn.create',
                'challenge': utils.base64_url_encode(challenge),
                'origin': origin,
                'crossOrigin': False
            }
            client_data_json = json.dumps(client_data, separators=(',', ':')).encode()

            # Create authenticator data
            rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
            flags = 0b01000101  # UP=1, UV=1, AT=1
            counter = struct.pack('>I', 0)

            # Create COSE key
            x_coord, y_coord = self._extract_key_coordinates(public_key_data)
            cose_key = {
                1: 2,      # kty: EC2
                3: -7,     # alg: ES256
                -1: 1,     # crv: P-256
                -2: x_coord,
                -3: y_coord
            }

            cose_key_cbor = cbor2.dumps(cose_key)

            # Create attested credential data
            attested_credential_data = (
                b'\x00' * 16 +  # AAGUID
                struct.pack('>H', len(utils.base64_url_decode(credential_id))) +
                utils.base64_url_decode(credential_id) +
                cose_key_cbor
            )

            authenticator_data = rp_id_hash + struct.pack('B', flags) + counter + attested_credential_data

            # Create attestation object
            attestation_object = {
                'fmt': 'none',
                'attStmt': {},
                'authData': authenticator_data
            }

            attestation_object_cbor = cbor2.dumps(attestation_object)

            # Create response
            return self._create_registration_response(
                credential_id,
                client_data_json,
                attestation_object_cbor
            )

        except Exception as e:
            raise Exception(f"Failed to create Touch ID credential: {str(e)}")

    def get_assertion(self, options):
        """Get WebAuthn assertion using Touch ID"""
        try:
            # Import required modules
            try:
                import LocalAuthentication  # pylint: disable=import-error
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives import serialization
                import hashlib
                import struct
            except ImportError as e:
                raise Exception(f"Required dependencies not available: {e}")

            # Find credential in keychain
            challenge = options.challenge
            rp_id = options.rp_id or 'keepersecurity.com'
            
            allowed_credentials = options.allow_credentials or []
            if not allowed_credentials:
                raise Exception("No allowed credentials found")

            private_key = None
            credential_id_b64 = None
            credential_id_bytes = None

            for cred in allowed_credentials:
                cred_id = cred.id
                if isinstance(cred_id, str):
                    test_id_b64 = cred_id
                    test_id_bytes = utils.base64_url_decode(cred_id)
                else:
                    test_id_bytes = cred_id
                    test_id_b64 = utils.base64_url_encode(cred_id)

                test_key = self._load_key_from_keychain(test_id_b64)
                if test_key:
                    private_key = test_key
                    credential_id_b64 = test_id_b64
                    credential_id_bytes = test_id_bytes
                    break

            if not private_key:
                raise Exception("No matching credential found in keychain")

            # Create LocalAuthentication context
            context = LocalAuthentication.LAContext.alloc().init()  # pylint: disable=no-member

            # Check biometric availability
            error = None
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                error
            )

            if not can_evaluate:
                raise Exception("Touch ID is not available or configured")

            # Create client data
            origin = getattr(self.client_data_collector, 'origin', f'https://{rp_id}')
            client_data = {
                'type': 'webauthn.get',
                'challenge': utils.base64_url_encode(challenge),
                'origin': origin,
                'crossOrigin': False
            }
            client_data_json = json.dumps(client_data, separators=(',', ':')).encode()

            # Create authenticator data
            rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
            flags = 0b00000101  # UP=1, UV=1
            counter = struct.pack('>I', 0)
            authenticator_data = rp_id_hash + struct.pack('B', flags) + counter

            # Create signed data
            client_data_hash = hashlib.sha256(client_data_json).digest()
            signed_data = authenticator_data + client_data_hash

            # Perform Touch ID authentication
            success = self._authenticate_with_touchid(context, 
                f"Authenticate with Keeper for {rp_id}")

            if not success:
                raise Exception("Touch ID authentication failed")

            # Sign the data
            der_signature = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))  # type: ignore

            # Create response
            return self._create_assertion_response(
                credential_id_b64,
                credential_id_bytes,
                client_data_json,
                authenticator_data,
                der_signature
            )

        except Exception as e:
            raise Exception(f"Failed to perform Touch ID authentication: {str(e)}")

    def _authenticate_with_touchid(self, context, reason):
        """Perform Touch ID authentication"""
        try:
            import LocalAuthentication  # pylint: disable=import-error
            import threading
            import time
            
            result = {'success': False}
            error_holder = {'error': None}
            
            def auth_callback(success, error):
                result['success'] = bool(success)
                error_holder['error'] = error
            
            context.evaluatePolicy_localizedReason_reply_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,  # pylint: disable=no-member
                reason,
                auth_callback
            )
            
            # Wait for result
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                if result['success'] or error_holder['error']:
                    break
                time.sleep(0.1)
            
            if error_holder['error']:
                raise Exception(f"Touch ID authentication failed: {error_holder['error']}")
            
            return result['success']
            
        except Exception as e:
            raise Exception(f"Touch ID authentication error: {str(e)}")

    def _store_key_in_keychain(self, credential_id, private_key_data, rp_id):
        """Store private key in keychain"""
        try:
            import subprocess
            import base64
            
            encoded_key = base64.b64encode(private_key_data).decode('ascii')
            service_name = f"Keeper WebAuthn - {rp_id}"
            account_name = f"webauthn-{credential_id}"
            
            result = subprocess.run([
                'security', 'add-internet-password',
                '-s', service_name,
                '-a', account_name,
                '-w', encoded_key,
                '-D', 'WebAuthn Credential',
                '-j', f'Keeper biometric credential for {rp_id}',
                '-T', '',
                '-U'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logging.warning(f"Could not store in keychain: {result.stderr}")
                
        except Exception as e:
            logging.warning(f"Error storing in keychain: {str(e)}")

    def _load_key_from_keychain(self, credential_id):
        """Load private key from keychain"""
        try:
            import subprocess
            import base64
            from cryptography.hazmat.primitives import serialization
            
            account_name = f"webauthn-{credential_id}"
            possible_services = ["Keeper WebAuthn - keepersecurity.com"]
            
            for service_name in possible_services:
                try:
                    result = subprocess.run([
                        'security', 'find-internet-password',
                        '-s', service_name,
                        '-a', account_name,
                        '-w'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        encoded_key = result.stdout.strip()
                        if encoded_key:
                            key_data = base64.b64decode(encoded_key)
                            return serialization.load_der_private_key(key_data, password=None)
                            
                except Exception:
                    continue
            
            return None
            
        except Exception as e:
            logging.warning(f"Error loading from keychain: {str(e)}")
            return None

    def _delete_key_from_keychain(self, credential_id):
        """Delete key from keychain"""
        try:
            import subprocess
            
            account_name = f"webauthn-{credential_id}"
            possible_services = ["Keeper WebAuthn - keepersecurity.com"]
            
            for service_name in possible_services:
                try:
                    subprocess.run([
                        'security', 'delete-internet-password',
                        '-s', service_name,
                        '-a', account_name
                    ], capture_output=True, text=True, timeout=10)
                except Exception:
                    continue
                    
        except Exception as e:
            logging.warning(f"Error deleting from keychain: {str(e)}")

    def _extract_key_coordinates(self, public_key_data):
        """Extract x and y coordinates from EC key"""
        if len(public_key_data) != 65 or public_key_data[0] != 0x04:
            raise Exception("Invalid P-256 public key format")
        
        return public_key_data[1:33], public_key_data[33:65]

    def _create_registration_response(self, credential_id, client_data_json, attestation_object_cbor):
        """Create registration response"""
        class RegistrationResponse:
            def __init__(self, cred_id, cred_raw_id, client_data, attestation_obj):
                self.id = cred_id
                self.raw_id = cred_raw_id
                self.response = AttestationResponse(client_data, attestation_obj)
                self.client_extension_results = {}
                self.type = 'public-key'
                
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

    def _create_assertion_response(self, credential_id_b64, credential_id_bytes, 
                                 client_data_json, authenticator_data, signature):
        """Create assertion response"""
        class AuthenticationResponse:
            def __init__(self, cred_id, cred_raw_id, client_data, auth_data, sig):
                self.id = cred_id
                self.raw_id = cred_raw_id
                self.response = AssertionResponse(client_data, auth_data, sig)
                self.client_extension_results = {}
                self.type = 'public-key'
                
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