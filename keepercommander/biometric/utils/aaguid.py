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

import json
import pkgutil
from functools import lru_cache


@lru_cache(maxsize=1)
def _get_provider_mapping():
    """Load the bundled, names-only snapshot of the Web Vault's combined registry.

    Source: passkeydeveloper/passkey-authenticator-aaguids/combined_aaguid.json.
    Keep resources/passkey_aaguid_names.json in sync with that registry; icons
    are omitted because Commander only displays authenticator names.
    """
    data = pkgutil.get_data('keepercommander', 'resources/passkey_aaguid_names.json')
    return json.loads(data) if data else {}


def get_provider_name_from_aaguid(aaguid: str) -> str:
    """Resolve the authenticator name using the same normalization as Web Vault."""
    if not aaguid:
        return 'Unknown Authenticator'
    
    # Normalize AAGUID format (ensure lowercase, with dashes)
    normalized_aaguid = aaguid.lower().strip()
    hex_aaguid = normalized_aaguid.replace('-', '')
    if len(hex_aaguid) == 32:
        normalized_aaguid = f"{hex_aaguid[:8]}-{hex_aaguid[8:12]}-{hex_aaguid[12:16]}-{hex_aaguid[16:20]}-{hex_aaguid[20:]}"
    
    return _get_provider_mapping().get(normalized_aaguid, 'Unknown Authenticator')
