#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from typing import Dict, Iterable, List, Optional, Tuple

from ....nested_share_folder.permissions import resolve_role_name
from .models import AccessGrant, FindingLog, Principal, PrincipalKind, _positive

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
    cache: Dict[int, int] = {}

    def boundary_of(folder_id: int, trail: Tuple[int, ...]) -> int:
        if folder_id in cache:
            return cache[folder_id]
        folder = folders.get(folder_id) or {}
        parent = folder.get('parentFolderId')
        parent_id = parent if isinstance(parent, int) and parent > 0 and parent in folders and parent != folder_id else None
        is_boundary = parent_id is None or folder.get('inheritPermissions') is False or folder_id in trail
        if is_boundary or parent_id is None:
            cache[folder_id] = folder_id
            return folder_id
        result = boundary_of(parent_id, trail + (folder_id,))
        cache[folder_id] = result
        return result

    for folder_id in folders:
        boundary_of(folder_id, ())
    return cache


class PermissionMapper:
    """Converts Delinea folder / secret permission rows to ``AccessGrant`` lists."""

    def __init__(self, users: Optional[Dict[int, dict]], groups: Optional[Dict[int, dict]],
                 findings: FindingLog):
        # Normalise None so principal() lookups never hit NoneType.get.
        self.users = users or {}
        self.groups = groups or {}
        self.findings = findings

    def principal(self, row: dict) -> Optional[Principal]:
        """Principal for a permission row (``userId`` > 0 is a user, else ``groupId``)."""
        user_id = _positive(row.get('userId'))
        if user_id:
            user = self.users.get(user_id) or {}
            email = str(user.get('emailAddress') or '')
            name = str(user.get('userName') or email or user_id)
            return Principal(PrincipalKind.USER, user_id, name, email)
        group_id = _positive(row.get('groupId'))
        if group_id:
            group = self.groups.get(group_id) or {}
            name = str(group.get('name') or group_id)
            return Principal(PrincipalKind.TEAM, group_id, name)
        return None

    def folder_grants(self, rows: Iterable[dict]) -> List[AccessGrant]:
        """One grant per principal, keeping the highest role (``rank``).

        Rows whose role pair is not in ``FOLDER_ROLE_MAP`` produce a Finding.
        """
        best: Dict[Tuple[PrincipalKind, int], AccessGrant] = {}
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            principal = self.principal(row)
            if principal is None:
                continue
            role = folder_role(row.get('folderAccessRoleName'), row.get('secretAccessRoleName'))
            if not role:
                self.findings.add(
                    'Folder permission',
                    f"{row.get('folderAccessRoleName') or ''}/{row.get('secretAccessRoleName') or ''}",
                    'No Keeper role for this Delinea folder permission')
                continue
            self._keep_highest(best, AccessGrant(principal, role))
        return list(best.values())

    def secret_grants(self, rows: Iterable[dict]) -> List[AccessGrant]:
        """Same as ``folder_grants`` using ``SECRET_ROLE_MAP``; teams are expanded to users
        (``share_record_v3`` / ``ShareRecordCommand`` accept users only)."""
        best: Dict[Tuple[PrincipalKind, int], AccessGrant] = {}
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            principal = self.principal(row)
            if principal is None:
                continue
            role = secret_role(row.get('secretAccessRoleName'))
            if not role:
                self.findings.add(
                    'Secret permission',
                    f"{principal.name}/{row.get('secretAccessRoleName') or ''}",
                    'No Keeper role for this Delinea secret permission')
                continue
            principals = self._expand(principal)
            for person in principals:
                self._keep_highest(best, AccessGrant(person, role))
        return list(best.values())

    @staticmethod
    def is_override(secret: dict, secret_rows: List[dict], folder_rows: List[dict]) -> bool:
        """True when the secret's grants differ from its folder's.

        ``inheritPermissions`` is unreliable on some Secret Server versions, so
        compare the (principal, secretAccessRoleName) sets as well.
        """
        if isinstance(secret, dict) and secret.get('inheritPermissions') is False:
            return True
        return _role_pairs(secret_rows) != _role_pairs(folder_rows)

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
        edit_votes = []
        share_votes = []
        downgraded = False
        for grant in grants:
            flags = CLASSIC_RECORD_FLAGS.get(grant.role)
            if flags is None:
                downgraded = True
                continue
            edit_votes.append(flags[0])
            share_votes.append(flags[1])
        can_edit = bool(edit_votes) and all(edit_votes)
        can_share = bool(share_votes) and all(share_votes)
        if downgraded or any(vote and not can_edit for vote in edit_votes) or any(
                vote and not can_share for vote in share_votes):
            self.findings.add(
                'Folder permissions', folder_name,
                'Classic shared folders apply one record permission to every member; some members were downgraded')
        return {'manage_users': False, 'manage_records': False,
                'can_edit': can_edit, 'can_share': can_share}

    def _keep_highest(self, best: Dict[Tuple[PrincipalKind, int], AccessGrant], grant: AccessGrant) -> None:
        key = (grant.principal.kind, grant.principal.source_id)
        current = best.get(key)
        if current is None or self.rank(grant.role) > self.rank(current.role):
            best[key] = grant

    def _expand(self, principal: Principal) -> List[Principal]:
        if principal.kind is not PrincipalKind.TEAM:
            return [principal]
        people = []
        seen = set()
        for user_id in self._group_user_ids(principal.source_id, seen):
            user = self.users.get(user_id) or {}
            email = str(user.get('emailAddress') or '')
            name = str(user.get('userName') or email or user_id)
            people.append(Principal(PrincipalKind.USER, user_id, name, email))
        return people

    def _group_user_ids(self, group_id: int, seen: set) -> List[int]:
        if group_id in seen:
            return []
        seen.add(group_id)
        group = self.groups.get(group_id) or {}
        ids = [user_id for user_id in (_positive(x) for x in (group.get('users') or [])) if user_id]
        for child in group.get('groups') or []:
            child_id = _positive(child)
            if child_id:
                ids.extend(self._group_user_ids(child_id, seen))
        return ids

    @staticmethod
    def rank(role: str) -> int:
        return resolve_role_name(role)




def _role_pairs(rows: List[dict]) -> set:
    pairs = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        pairs.add((
            _positive(row.get('userId')) or 0,
            _positive(row.get('groupId')) or 0,
            str(row.get('secretAccessRoleName') or '').strip().lower(),
        ))
    return pairs