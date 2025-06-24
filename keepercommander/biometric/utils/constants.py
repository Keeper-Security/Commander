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

# Default timeout value for all biometric operations
DEFAULT_BIOMETRIC_TIMEOUT = 60

# Platform/System constants
PLATFORM_WINDOWS = 'Windows'
PLATFORM_DARWIN = 'Darwin'

# HTTP Status codes
STATUS_SUCCESS = 200  # OK
STATUS_NOT_FOUND = 404  # Not Found
STATUS_BAD_REQUEST = 400  # Bad Request
STATUS_ERROR = 500  # Internal Server Error

# Status code to readable message mapping
STATUS_MESSAGES = {
    STATUS_SUCCESS: 'Success',
    STATUS_NOT_FOUND: 'Not Found',
    STATUS_BAD_REQUEST: 'Bad Request',
    STATUS_ERROR: 'Error'
}

def get_status_message(status_code: int) -> str:
    """Get readable message for HTTP status code"""
    return STATUS_MESSAGES.get(status_code, f"Unknown Status ({status_code})")

def is_success_status(status_code: int) -> bool:
    """Check if status code indicates success (2xx range)"""
    return 200 <= status_code < 300

# API Endpoints
API_ENDPOINTS = {
    'generate_registration': 'authentication/passkey/generate_registration',
    'verify_registration': 'authentication/passkey/verify_registration',
    'generate_authentication': 'authentication/passkey/generate_authentication',
    'verify_authentication': 'authentication/passkey/verify_authentication',
    'get_available_keys': 'authentication/passkey/get_available_keys',
    'disable_passkey': 'authentication/passkey/disable',
    'update_passkey_name': 'authentication/passkey/update_friendly_name'
}

# API Response Messages
API_RESPONSE_MESSAGES = {
    'passkey_disabled_success': 'Passkey was successfully disabled and no longer available for login',
    'passkey_name_updated_success': 'Passkey friendly name was successfully updated',
    'disable_bad_request': 'Unable to disable. Data error. Credential ID or UserID mismatch',
    'update_bad_request': 'Unable to update. Data error. Credential ID or UserID mismatch',
    'server_exception': 'Unexpected server exception'
}

AUTHENTICATOR_SELECTION = {
    'authenticatorAttachment': 'platform',
    'userVerification': 'required'
}

# Storage paths and service names
WINDOWS_REGISTRY_PATH = r"SOFTWARE\Keeper Security\Commander\Biometric"
MACOS_PREFS_PATH = "com.keepersecurity.commander.biometric.plist"
MACOS_KEYCHAIN_SERVICE_PREFIX = "Keeper WebAuthn"

# FIDO2 availability check
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


# Error messages
ERROR_MESSAGES = {
    'no_fido2': 'FIDO2 library not available. Please install: pip install fido2',
    'platform_not_supported': 'Biometric authentication not supported on this platform',
    'no_credentials': 'No biometric credentials found. Please register first using "biometric register"',
    'authentication_cancelled': 'Biometric authentication was cancelled',
    'authentication_timeout': 'Biometric authentication timed out',
    'authentication_failed': 'Biometric authentication failed',
    'registration_failed': 'Biometric registration failed',
    'verification_failed': 'Biometric verification failed',
    'credential_exists': 'A biometric credential for this account already exists. Use "biometric unregister" first.',
    'credential_already_registered': 'A biometric credential for this account already exists. Use "biometric unregister" first.',
    'keychain_store_failed': 'Failed to store credential in keychain',
    'touchid_not_available': 'Touch ID is not available or configured',
    'windows_hello_not_setup': 'Windows Hello is available but not yet set up. Please complete the setup in Windows Settings > Accounts > Sign-In options, then try running this command again.',
    'no_matching_credential': 'No matching credential found in keychain'
}

# Success messages
SUCCESS_MESSAGES = {
    'registration_complete': 'Biometric authentication completed successfully!',
    'unregistration_complete': 'Biometric authentication has been completely removed',
    'verification_success': 'Your biometric authentication is working correctly!',
    'credential_disabled': 'Passkey was successfully disabled and no longer available for login'
}

# Default credential name template
CREDENTIAL_NAME_TEMPLATE = "Commander CLI ({hostname})"

# Common authentication reasons
AUTH_REASONS = {
    'register': "Register biometric authentication for {rp_id}",
    'login': "Authenticate with Keeper for {rp_id}",
    'verification': "Verify biometric authentication for {rp_id}"
} 