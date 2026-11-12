#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from typing import Dict, Optional, Tuple

# (folder role is Owner, secret role) -> NSF role. Never grants more than Delinea did:
# folder Edit / Add Secret / View have no NSF equivalent beyond the secret dimension.
FOLDER_ROLE_MAP: Dict[Tuple[bool, str], str] = {
    (True, 'owner'): 'full-manager',
    (True, 'edit'): 'full-manager',
    (True, 'view'): 'share-manager',
    (True, 'list'): 'requestor',
    (False, 'owner'): 'content-share-manager',
    (False, 'edit'): 'content-manager',
    (False, 'view'): 'viewer',
    (False, 'list'): 'requestor',
}

SECRET_ROLE_MAP: Dict[str, str] = {
    'owner': 'content-share-manager',
    'edit': 'content-manager',
    'view': 'viewer',
    'list': 'requestor',
}

# NSF role -> classic (manage_users, manage_records); None = no classic equivalent.
CLASSIC_FOLDER_FLAGS: Dict[str, Optional[Tuple[bool, bool]]] = {
    'full-manager': (True, True),
    'content-share-manager': (False, True),
    'content-manager': (False, True),
    'share-manager': (True, False),
    'viewer': (False, False),
    'requestor': None,
}

# NSF role -> classic record share (can_edit, can_share); None = no classic equivalent.
CLASSIC_RECORD_FLAGS: Dict[str, Optional[Tuple[bool, bool]]] = {
    'full-manager': (True, True),
    'content-share-manager': (True, True),
    'content-manager': (True, False),
    'share-manager': (False, True),
    'viewer': (False, False),
    'requestor': None,
}


class RoleResolver:
    """Single source of truth for all role mapping logic."""

    @staticmethod
    def delinea_folder_to_nsf(folder_role: str, secret_role: str) -> Optional[str]:
        """Map Delinea folder + secret roles to NSF role."""
        key = ((folder_role or '').strip().lower() == 'owner',
               (secret_role or '').strip().lower())
        return FOLDER_ROLE_MAP.get(key)

    @staticmethod
    def delinea_secret_to_nsf(secret_role: str) -> Optional[str]:
        """Map Delinea secret role to NSF role."""
        return SECRET_ROLE_MAP.get((secret_role or '').strip().lower())

    @staticmethod
    def nsf_to_classic_record_flags(nsf_role: str) -> Optional[Tuple[bool, bool]]:
        """Convert NSF role to classic record permission flags."""
        return CLASSIC_RECORD_FLAGS.get(nsf_role)

    @staticmethod
    def nsf_to_classic_folder_flags(nsf_role: str) -> Optional[Tuple[bool, bool]]:
        """Convert NSF role to classic folder permission flags."""
        return CLASSIC_FOLDER_FLAGS.get(nsf_role)
