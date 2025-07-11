# Default timeout values
DEFAULT_REGISTRATION_TIMEOUT = 30
DEFAULT_AUTHENTICATION_TIMEOUT = 10

# RP ID for Keeper
KEEPER_RP_ID = 'keepersecurity.com'

# Authenticator selection preferences
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

# Warning messages
FIDO2_WARNING_MESSAGE = """
    You can use Security Key with Commander:
    Upgrade your Python interpreter to 3.10 or newer
    and make sure fido2 package is 2.0.0 or newer
"""

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
    'keychain_store_failed': 'Failed to store credential in keychain',
    'touchid_not_available': 'Touch ID is not available or configured',
    'windows_hello_not_available': 'Windows Hello not available'
}

# Success messages
SUCCESS_MESSAGES = {
    'registration_complete': 'Biometric authentication method added successfully!',
    'unregistration_complete': 'Biometric authentication has been completely removed',
    'verification_success': 'Your biometric authentication is working correctly!',
    'credential_disabled': 'Passkey was successfully disabled and no longer available for login'
}

# Default credential name templates
CREDENTIAL_NAME_TEMPLATES = {
    'Windows': "Windows Hello - {hostname}",
    'Darwin': "Touch ID - {hostname}",
    'default': "Biometric - {hostname}"
}

# Common authentication reasons
AUTH_REASONS = {
    'register': "Register biometric authentication for {rp_id}",
    'login': "Authenticate with Keeper for {rp_id}",
    'verification': "Verify biometric authentication for {rp_id}"
} 