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

# Platform-specific settings
WINDOWS_SETTINGS = {
    'residentKey': 'required',
    'attestation': 'none'
}

MACOS_SETTINGS = {
    'residentKey': 'discouraged',
    'attestation': 'none'
}

# Storage paths
WINDOWS_REGISTRY_PATH = r"SOFTWARE\Keeper Security\Commander\Biometric"
MACOS_PREFS_PATH = "com.keepersecurity.commander.biometric.plist"

# Error messages
ERROR_MESSAGES = {
    'no_fido2': 'FIDO2 library not available. Please install: pip install fido2',
    'platform_not_supported': 'Biometric authentication not supported on this platform',
    'no_credentials': 'No biometric credentials found. Please register first using "biometric register"',
    'authentication_cancelled': 'Biometric authentication was cancelled',
    'authentication_timeout': 'Biometric authentication timed out',
    'authentication_failed': 'Biometric authentication failed',
    'registration_failed': 'Biometric registration failed',
    'verification_failed': 'Biometric verification failed'
} 