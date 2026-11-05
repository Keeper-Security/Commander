#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from typing import Dict, Iterable, List, Optional, Tuple

from ....nested_share_folder.permissions import resolve_role_name
from .models import AccessGrant, FindingLog, Principal

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


def folder_role(folder_access_role: str, secret_access_role: str) -> Optional[str]:
    key = ((folder_access_role or '').strip().lower() ==
           'owner', (secret_access_role or '').strip().lower())
    return FOLDER_ROLE_MAP.get(key)


def secret_role(secret_access_role: str) -> Optional[str]:
    return SECRET_ROLE_MAP.get((secret_access_role or '').strip().lower())


def permission_boundaries(folders: Dict[int, dict]) -> Dict[int, int]:
    """Map each folder id to the nearest ancestor-or-self that owns its permissions.

    A boundary is a top-level folder or one with ``inheritPermissions`` false.
    Each boundary becomes one shared folder; descendants are routed into it.
    """
    raise NotImplementedError


class PermissionMapper:
    """Converts Delinea folder / secret permission rows to ``AccessGrant`` lists."""

    def __init__(self, users: Dict[int, dict], groups: Dict[int, dict], findings: FindingLog):
        self.users = users
        self.groups = groups
        self.findings = findings

    def principal(self, row: dict) -> Optional[Principal]:
        """Principal for a permission row (``userId`` > 0 is a user, else ``groupId``)."""
        raise NotImplementedError

    def folder_grants(self, rows: Iterable[dict]) -> List[AccessGrant]:
        """One grant per principal, keeping the highest role (``rank``).

        Rows whose role pair is not in ``FOLDER_ROLE_MAP`` produce a Finding.
        """
        raise NotImplementedError

    def secret_grants(self, rows: Iterable[dict]) -> List[AccessGrant]:
        """Same as ``folder_grants`` using ``SECRET_ROLE_MAP``; teams are expanded to users
        (``share_record_v3`` / ``ShareRecordCommand`` accept users only)."""
        raise NotImplementedError

    @staticmethod
    def is_override(secret: dict, secret_rows: List[dict], folder_rows: List[dict]) -> bool:
        """True when the secret's grants differ from its folder's.

        ``inheritPermissions`` is unreliable on some Secret Server versions, so
        compare the (principal, secretAccessRoleName) sets as well.
        """
        raise NotImplementedError

    @staticmethod
    def to_permission_entry(grant: AccessGrant, keeper_name: str, use_nsf: bool) -> Optional[dict]:
        """``safe_folders[].permissions[]`` entry consumed by ``pam project import``.

        Returns ``None`` in classic mode when the role has no classic equivalent.
        """
        flags = CLASSIC_FOLDER_FLAGS.get(grant.role)
        if flags is None and not use_nsf:
            return None
        manage_users, manage_records = flags or (False, False)
        return {'name': keeper_name, 'role': grant.role,
                'manage_users': manage_users, 'manage_records': manage_records}

    def classic_folder_defaults(self, folder_name: str, grants: List[AccessGrant]) -> dict:
        """``safe_folders[]`` defaults (``manage_users``, ``manage_records``, ``can_edit``, ``can_share``).

        Classic record permissions apply to every member, so ``can_edit`` /
        ``can_share`` are true only when every grant's ``CLASSIC_RECORD_FLAGS``
        allows it; a Finding names folders where members were downgraded.
        ``manage_*`` defaults are false (explicit entries carry them).
        """
        raise NotImplementedError

    @staticmethod
    def rank(role: str) -> int:
        return resolve_role_name(role)
