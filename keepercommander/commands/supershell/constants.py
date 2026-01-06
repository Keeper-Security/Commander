"""
SuperShell constants

Thresholds, limits, and other constant values.
"""

# Auto-expand folders with fewer records than this
AUTO_EXPAND_THRESHOLD = 20

# Maximum devices to show in device status dropdown
DEVICE_DISPLAY_LIMIT = 10

# Sensitive field names that should be masked
SENSITIVE_FIELD_NAMES = frozenset({
    'password', 'secret', 'pin', 'token', 'key', 'apikey', 'api_key',
    'privatekey', 'private_key', 'secret2', 'pincode', 'passphrase',
    'onetimecode', 'totp', 'passkey'
})

# Field type prefixes to strip from display names
FIELD_TYPE_PREFIXES = (
    'text:', 'multiline:', 'url:', 'phone:', 'email:',
    'secret:', 'date:', 'name:', 'host:', 'address:'
)

# Friendly names for field types
FIELD_TYPE_FRIENDLY_NAMES = {
    'text:': 'Text',
    'multiline:': 'Note',
    'url:': 'URL',
    'phone:': 'Phone',
    'email:': 'Email',
    'secret:': 'Secret',
    'date:': 'Date',
    'name:': 'Name',
    'host:': 'Host',
    'address:': 'Address',
}

# Reference field types to skip in display (shown elsewhere)
REFERENCE_FIELD_TYPES = frozenset({'fileRef', 'addressRef', 'cardRef'})
