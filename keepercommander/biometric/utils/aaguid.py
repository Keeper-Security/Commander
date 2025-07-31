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

"""
AAGUID (Authenticator Attestation GUID) related constants and utilities.
These constants help identify the specific authenticator/provider used for WebAuthn credentials.
"""

# AAGUID to provider name mapping
# Based on community-sourced data from https://github.com/passkeydeveloper/passkey-authenticator-aaguids
AAGUID_PROVIDER_MAPPING = {
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
    'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
    '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
    '00000000-0000-0000-0000-000000000000': 'Platform Authenticator'
}


def get_provider_name_from_aaguid(aaguid: str) -> str:
    """Get friendly provider name from AAGUID"""
    if not aaguid:
        return None
    
    # Normalize AAGUID format (ensure lowercase, with dashes)
    normalized_aaguid = aaguid.lower()
    if len(normalized_aaguid) == 32:  # No dashes
        normalized_aaguid = f"{normalized_aaguid[:8]}-{normalized_aaguid[8:12]}-{normalized_aaguid[12:16]}-{normalized_aaguid[16:20]}-{normalized_aaguid[20:]}"
    
    return AAGUID_PROVIDER_MAPPING.get(normalized_aaguid)
