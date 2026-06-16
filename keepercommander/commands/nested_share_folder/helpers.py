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
Nested Share Folder — shared utilities, constants, and design-pattern helpers.

Principles applied:
  - DRY: All repeated logic (expiration parsing, folder resolution,
    role inference, error handling) is centralised here.
  - Single Responsibility: Each function does exactly one thing.
  - Open/Closed: New role mappings or permission labels can be added
    without modifying consumers.
"""

import re
import datetime
import logging
from contextlib import contextmanager
from datetime import timezone, timedelta
from typing import Optional

from ...error import CommandError

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

ROOT_FOLDER_UID = 'AAAAAAAAAAAAAAAAAPmtNA'
"""Sentinel UID the server uses for the Nested Share Folder root folder."""

RECORD_PERM_LABELS = [
    ('can_view_title',       'View Title'),
    ('can_view',             'View Content'),
    ('can_edit',             'Edit'),
    ('can_list_access',      'List Access'),
    ('can_update_access',    'Update Access'),
    ('can_delete',           'Delete'),
    ('can_change_ownership', 'Change Ownership'),
    ('can_request_access',   'Request Access'),
    ('can_approve_access',   'Approve Access'),
]
"""Record-level permission flags and their display labels."""

FOLDER_PERM_LABELS = [
    ('can_list_folders',     'List Folders'),
    ('can_list_records',     'List Records'),
    ('can_view_records',     'View Records'),
    ('can_edit_records',     'Edit Records'),
    ('can_add',              'Add (folders/records)'),
    ('can_remove',           'Remove (folders/records)'),
    ('can_delete',           'Delete'),
    ('can_list_access',      'List Access'),
    ('can_update_access',    'Update Access'),
    ('can_approve_access',   'Approve Access'),
    ('can_request_access',   'Request Access'),
    ('can_update_setting',   'Update Setting'),
    ('can_change_ownership', 'Change Ownership'),
]
"""Folder-level permission flags and their display labels."""

_EXPIRATION_RE = re.compile(
    r'(\d+)\s*(mi(?:nutes?)?|h(?:ours?)?|d(?:ays?)?|mo(?:nths?)?|y(?:ears?)?)',
    re.IGNORECASE,
)

MIN_SHARE_EXPIRATION_MS = 60_000
"""Minimum share expiration is one minute (milliseconds)."""


# ═══════════════════════════════════════════════════════════════════════════
# Error-handling patterns  (eliminates repetitive try/except boilerplate)
# ═══════════════════════════════════════════════════════════════════════════

@contextmanager
def command_error_handler(cmd_name):
    """Context manager that standardises exception handling for commands.

    CommandError passes through unchanged; every other exception is wrapped
    in a new CommandError so callers never need the 5-line try/except block.

    Usage::

        with command_error_handler('nsf-mkdir'):
            result = api_call(...)
            check_result(result, 'nsf-mkdir')
    """
    try:
        yield
    except CommandError:
        raise
    except Exception as exc:
        raise CommandError(cmd_name, str(exc))


def check_result(result, cmd_name):
    """Raise ``CommandError`` when *result['success']* is falsy.

    Standardises the ``if not result['success']: raise ...`` pattern that
    appears in almost every command.
    """
    if not result.get('success'):
        raise CommandError(cmd_name, result.get('message', 'Unknown error'))


# ═══════════════════════════════════════════════════════════════════════════
# Parser helpers
# ═══════════════════════════════════════════════════════════════════════════

def raise_parse_exception(self, status=0, message=None):
    """Override parser error to raise exception instead of ``sys.exit``."""
    from ..base import ParseError
    raise ParseError(message)


def suppress_exit(self, status=0, message=None):
    """Suppress parser exit."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# UID helpers
# ═══════════════════════════════════════════════════════════════════════════

def normalize_parent_uid(uid):
    """Normalize root folder UIDs to a consistent ``'root'`` or empty string."""
    if uid == ROOT_FOLDER_UID or uid == 'root':
        return 'root'
    return uid or ''


# ═══════════════════════════════════════════════════════════════════════════
# Resolution helpers
# ═══════════════════════════════════════════════════════════════════════════

def resolve_folder_uid(params, identifier):
    """Resolve a folder name, path, or UID to a Nested Share Folder UID.

    Delegates to the service layer's ``resolve_folder_identifier``
    to avoid duplicating resolution logic.
    """
    if not identifier:
        return None
    from ... import nested_share_folder as _nsf
    return _nsf.resolve_folder_identifier(params, identifier)



_LEGACY_TO_KD_RECORD_MSG = (
    "Cannot use legacy record '{ident}' with a Nested Share Folder command. "
)
_LEGACY_TO_KD_FOLDER_MSG = (
    "Folder '{ident}' is a legacy folder. Nested Share Folder commands operate "
    "only on Nested Share Folders."
)


def is_nested_share_record(params, record_uid):
    """Return True when *record_uid* is a Nested Share Folder (v3) record."""
    return bool(record_uid) and record_uid in getattr(
        params, 'nested_share_records', {})


def is_nested_share_folder(params, folder_uid):
    """Return True when *folder_uid* is a Nested Share Folder.
    """
    if not folder_uid:
        return False
    if folder_uid == ROOT_FOLDER_UID:
        return True
    return folder_uid in getattr(params, 'nested_share_folders', {})


def ensure_nested_share_record(params, record_uid, cmd_name, identifier=None):
    """Raise ``CommandError`` if *record_uid* is not a Nested Share Record."""
    if not is_nested_share_record(params, record_uid):
        ident = identifier or record_uid
        raise CommandError(cmd_name, _LEGACY_TO_KD_RECORD_MSG.format(ident=ident))


def ensure_nested_share_folder(params, folder_uid, cmd_name, identifier=None):
    """Raise ``CommandError`` if *folder_uid* is not a Nested Share Folder."""
    if not is_nested_share_folder(params, folder_uid):
        ident = identifier or folder_uid
        raise CommandError(cmd_name, _LEGACY_TO_KD_FOLDER_MSG.format(ident=ident))


def classify_share_recipient(params, recipient):
    """Classify a single ``-e/--email`` value as a user or a team.

    Mirrors the legacy ``share-folder`` resolution exactly:
      1. If *recipient* matches ``EMAIL_PATTERN`` → ``('user', email_lower)``.
      2. Otherwise look it up in ``api.get_share_objects(params)['teams']``
         (cap of 500 entries) and, if needed, ``params.available_team_cache``.
         A match by team name *or* team UID returns ``('team', team_uid_b64)``.
      3. No match → logs the same warning as legacy and returns ``None``.
      4. Multiple matches → logs the same warning and returns ``None``.

    Returns ``(kind, identifier)`` or ``None``.
    """
    from ... import constants, api

    if re.match(constants.EMAIL_PATTERN, recipient):
        return 'user', recipient.lower()

    try:
        teams = api.get_share_objects(params).get('teams', {}) or {}
    except Exception:
        teams = {}
    teams_map = {uid: t.get('name') for uid, t in teams.items()}

    if len(teams_map) >= 500:
        try:
            api.load_available_teams(params)
            teams_map.update({t.get('team_uid'): t.get('team_name')
                              for t in (params.available_team_cache or [])})
        except Exception:
            pass

    matches = [uid for uid, name in teams_map.items()
               if recipient in (name, uid)]

    if len(matches) == 1:
        return 'team', matches[0]

    if not matches:
        logger.warning('User "%s" could not be resolved as email or team',
                       recipient)
    else:
        logger.warning(
            'Multiple matches were found for team "%s". Try using its UID -- '
            'which can be found via `list-team` -- instead', recipient)
    return None


def find_folder_location(params, record_uid):
    """Return a {uid, path} dict for the first NSF folder containing *record_uid*."""
    nsf_folder_records = getattr(params, 'nested_share_folder_records', {})
    nsf_folders = getattr(params, 'nested_share_folders', {})

    def _build_path(fuid):
        parts = []
        cur = fuid
        while cur and cur in nsf_folders and cur != ROOT_FOLDER_UID:
            obj = nsf_folders[cur]
            parts.append(obj.get('name', cur))
            p = obj.get('parent_uid') or ''
            cur = None if (not p or p not in nsf_folders) else p
        return '/'.join(reversed(parts))

    for fuid, rec_set in nsf_folder_records.items():
        if record_uid in rec_set:
            if fuid == ROOT_FOLDER_UID or fuid not in nsf_folders:
                return {'uid': None, 'path': '/'}
            return {'uid': fuid, 'path': _build_path(fuid)}
    return None


def collect_records_in_folder(params, folder_uid, recursive=False):
    """Walk Nested Share Folder membership tables to collect record UIDs in *folder_uid*.

    Nested Share Folder does not store ``record_uids`` / ``children`` on folder objects;
    record membership lives in ``params.nested_share_folder_records`` and the
    folder hierarchy in ``params.nested_share_folders[*]['parent_uid']``. This
    helper walks both, optionally recursing into sub-folders.

    Returns an ordered list of unique record UIDs (preserves first-seen order).
    """
    nsf_folders = getattr(params, 'nested_share_folders', {})
    nsf_folder_records = getattr(params, 'nested_share_folder_records', {})

    seen = set()
    record_uids = []

    def add_records(fuid):
        for rec_uid in nsf_folder_records.get(fuid, set()) or ():
            if rec_uid not in seen:
                seen.add(rec_uid)
                record_uids.append(rec_uid)

    visited = set()

    def walk(fuid):
        if fuid in visited:
            return
        visited.add(fuid)
        add_records(fuid)
        if not recursive:
            return
        for child_uid, child_obj in nsf_folders.items():
            if child_obj.get('parent_uid') == fuid and child_uid not in visited:
                walk(child_uid)

    walk(folder_uid)
    return record_uids


# ═══════════════════════════════════════════════════════════════════════════
# Expiration parsing
# ═══════════════════════════════════════════════════════════════════════════

def validate_share_expiration_timestamp(expiration_ms, cmd_name):
    """Reject finite expirations that are less than one minute."""
    if expiration_ms is None or expiration_ms == -1:
        return
    min_allowed = int(datetime.datetime.now(timezone.utc).timestamp() * 1000) + MIN_SHARE_EXPIRATION_MS
    if expiration_ms < min_allowed:
        raise CommandError(
            cmd_name,
            'Share expiration must be at least 1 minute.',
        )


def parse_expiration(expire_at, expire_in, cmd_name):
    """Parse ``--expire-at`` / ``--expire-in`` into a millisecond timestamp.

    Returns *None* if neither argument is provided, or ``-1`` for ``'never'``.
    """
    raw = expire_at or expire_in
    if not raw:
        return None
    if raw.lower() == 'never':
        return -1

    if expire_at:
        try:
            dt = datetime.datetime.fromisoformat(raw.replace('Z', '+00:00'))
            expiration_ms = int(dt.timestamp() * 1000)
        except ValueError:
            raise CommandError(
                cmd_name,
                f'Invalid --expire-at format: {raw!r}. '
                f'Use ISO datetime, e.g. 2027-01-01T00:00:00Z or "never"',
            )
        validate_share_expiration_timestamp(expiration_ms, cmd_name)
        return expiration_ms

    m = _EXPIRATION_RE.fullmatch(raw)
    if not m:
        raise CommandError(
            cmd_name,
            f'Invalid --expire-in format: {raw!r}. Examples: 30d, 6mo, 1y, 24h, 30mi',
        )
    amount = int(m.group(1))
    unit = m.group(2).lower()
    if unit.startswith('mi') and amount < 1:
        raise CommandError(
            cmd_name,
            'Share expiration must be at least 1 minute.',
        )
    now = datetime.datetime.now(timezone.utc)
    delta_map = {
        'mi': timedelta(minutes=amount),
        'h':  timedelta(hours=amount),
        'd':  timedelta(days=amount),
        'mo': timedelta(days=amount * 30),
        'y':  timedelta(days=amount * 365),
    }
    delta = next(v for k, v in delta_map.items() if unit.startswith(k))
    expiration_ms = int((now + delta).timestamp() * 1000)
    validate_share_expiration_timestamp(expiration_ms, cmd_name)
    return expiration_ms


# ═══════════════════════════════════════════════════════════════════════════
# Role helpers
# ═══════════════════════════════════════════════════════════════════════════

def infer_role(access):
    """Derive a display role name from permission flags (most permissive wins).

    Follows the official permission matrix::

        full-manager > content-share-manager > share-manager >
        content-manager > viewer > contributor > requestor > navigator

    The distinguishing trait between ``share-manager`` and
    ``content-share-manager`` is the ability to *edit* records: both roles
    grant ``can_update_access`` + ``can_approve_access``, but only
    ``content-share-manager`` also grants ``can_edit``. Without that check
    every share-manager would be reported as content-share-manager.
    """
    get = access.get
    if get('can_change_ownership') or get('can_delete'):
        return 'full-manager'
    if get('can_update_access') and get('can_approve_access') and get('can_edit'):
        return 'content-share-manager'
    if get('can_update_access') and get('can_approve_access'):
        return 'share-manager'
    if get('can_update_access'):
        return 'share-manager'
    if get('can_edit'):
        return 'content-manager'
    if get('can_view') and get('can_list_access'):
        return 'viewer'
    if get('can_view'):
        return 'contributor'
    if get('can_view_title'):
        return 'requestor'
    return 'navigator'


def role_label(access_role_type):
    """Convert a numeric ``access_role_type`` to a readable uppercase label."""
    from ... import nested_share_folder as _nsf
    if access_role_type is not None:
        return next(
            (k.upper() for k, v in _nsf.ROLE_NAME_MAP.items()
             if v == access_role_type and '_' not in k),
            str(access_role_type),
        )
    return ''


# Map backend AccessRoleType enum names to Nested Share Folder display labels.
# Source of truth: folder_pb2.AccessRoleType (NAVIGATOR=0 ... MANAGER=6).
_ACCESS_ROLE_DISPLAY_LABELS = {
    'NAVIGATOR':             'contributor',
    'REQUESTOR':             'contributor',
    'VIEWER':                'viewer',
    'SHARED_MANAGER':        'share-manager',
    'CONTENT_MANAGER':       'content-manager',
    'CONTENT_SHARE_MANAGER': 'content-share-manager',
    'MANAGER':               'full-manager',
    'UNRESOLVED':            'unresolved',
}


def format_role_display(role):
    """Convert an ``AccessRoleType`` to a Nested Share Folder display role label.

    Accepts either the proto enum name (``'SHARED_MANAGER'``) or its integer
    value, and returns the canonical hyphenated lowercase label used across
    Nested Share Folder (``'share-manager'``, ``'full-manager'``, ``'viewer'`` …).
    Falls back to a best-effort lowercase form when the role is unknown.
    """
    if role is None or role == '':
        return ''
    if isinstance(role, int):
        from ...proto import folder_pb2
        try:
            role = folder_pb2.AccessRoleType.Name(role)
        except Exception:
            return str(role)
    if isinstance(role, str):
        key = role.upper().replace('-', '_')
        return _ACCESS_ROLE_DISPLAY_LABELS.get(key, role.lower().replace('_', '-'))
    return str(role)


def get_access_role_label(access):
    """Get the Nested Share Folder role label for an access entry.

    Prefers the stored ``access_role_type`` (proto enum int) when available;
    otherwise falls back to inferring the role from permission flags. The
    returned label uses the canonical hyphenated lowercase Nested Share Folder form
    (e.g. ``'full-manager'``, ``'share-manager'``, ``'viewer'``).
    """
    role_int = access.get('access_role_type')
    if role_int is not None:
        return format_role_display(role_int)
    return infer_role(access)


# ═══════════════════════════════════════════════════════════════════════════
# Formatting helpers
# ═══════════════════════════════════════════════════════════════════════════

def format_timestamp(ms):
    """Format a millisecond epoch timestamp as ``'YYYY-MM-DD HH:MM:SS'``."""
    if ms:
        return datetime.datetime.fromtimestamp(ms / 1000).strftime('%Y-%m-%d %H:%M:%S')
    return ''


# ═══════════════════════════════════════════════════════════════════════════
# Permission checks
# ═══════════════════════════════════════════════════════════════════════════

def check_folder_edit_permission(params, folder_uid, cmd_name):
    """Raise if the current user cannot edit (rename/recolor) the folder."""
    _check_folder_permission(params, folder_uid, 'can_update_setting',
                             'You do not have permission to edit this folder.', cmd_name)


def check_folder_share_permission(params, folder_uid, cmd_name):
    """Raise if the current user cannot share the folder."""
    _check_folder_permission(params, folder_uid, 'can_update_access',
                             'You do not have permission to share this folder.', cmd_name)


def check_folder_delete_permission(params, folder_uid, cmd_name):
    """Raise if the current user cannot delete the folder."""
    _check_folder_permission(params, folder_uid, 'can_delete',
                             'You do not have permission to delete this folder.', cmd_name)


def check_record_edit_permission(params, record_uid, cmd_name):
    """Raise if the current user cannot edit the record."""
    _check_record_permission(params, record_uid, 'can_edit',
                             'You do not have edit permissions on this record.', cmd_name)


def check_record_share_permission(params, record_uid, cmd_name):
    """Raise if the current user cannot share the record."""
    _check_record_permission(params, record_uid, 'can_update_access',
                             'You do not have permission to share this record.', cmd_name)


def check_record_delete_permission(params, record_uid, cmd_name):
    """Raise if the current user cannot delete the record."""
    _check_record_permission(params, record_uid, 'can_delete',
                             'You do not have permission to delete this record.', cmd_name)


def _current_user_account_uid(params):
    """Return the base64url-encoded account UID for the current session, or ''."""
    from ... import utils
    raw = getattr(params, 'account_uid_bytes', None)
    if not raw:
        return ''
    try:
        return utils.base64_url_encode(raw)
    except Exception:
        return ''


def _is_current_user_access(access, params, current_account_uid):
    """Return True if *access* belongs to the currently logged-in user.

    Matches by ``username`` first (the populated case after a successful
    user-cache resolution) then falls back to ``access_type_uid`` /
    ``access_uid`` against the current account UID for sync windows where
    the username has not yet been filled in from ``params.user_cache``.
    """
    username = access.get('username')
    if username and username == params.user:
        return True
    if not current_account_uid:
        return False
    accessor_uid = access.get('access_type_uid') or access.get('access_uid')
    return bool(accessor_uid) and accessor_uid == current_account_uid


def _check_folder_permission(params, folder_uid, permission_key, error_message, cmd_name):
    """Enforce a folder permission for the current user.

    Behaviour:
      * If the cache has no access entries for *folder_uid* at all, skip the
        check (the server is the source of truth and will reject if needed).
        This avoids false-positives during a partial / first sync.
      * If access entries exist but **none** matches the current user, deny
        (treat the user as having no row, not as having implicit access).
      * If the matching entry is OWNER, allow.
      * Otherwise, allow only when ``permissions[permission_key]`` is truthy.
    """
    from ...proto import folder_pb2
    accesses = getattr(params, 'nested_share_folder_accesses', {}).get(folder_uid, [])
    if not accesses:
        return

    current_account_uid = _current_user_account_uid(params)
    for fa in accesses:
        if not _is_current_user_access(fa, params, current_account_uid):
            continue
        if fa.get('access_type') == int(folder_pb2.AT_OWNER):
            return
        perms = fa.get('permissions', {}) or {}
        if perms.get(permission_key):
            return
        raise CommandError(cmd_name, error_message)

    # Access list is non-empty but the current user is not in it.
    raise CommandError(cmd_name, error_message)


def _check_record_permission(params, record_uid, permission_key, error_message, cmd_name):
    """Enforce a record permission for the current user.

    Same fail-closed semantics as :func:`_check_folder_permission`.
    """
    accesses = getattr(params, 'nested_share_record_accesses', {}).get(record_uid, [])
    if not accesses:
        return

    current_account_uid = _current_user_account_uid(params)
    for ra in accesses:
        if not _is_current_user_access(ra, params, current_account_uid):
            continue
        if ra.get('owner'):
            return
        if ra.get(permission_key):
            return
        raise CommandError(cmd_name, error_message)

    raise CommandError(cmd_name, error_message)


# ═══════════════════════════════════════════════════════════════════════════
# Record metadata loading
# ═══════════════════════════════════════════════════════════════════════════

def load_record_metadata(params, record_uid):
    """Load record metadata from cache, falling back to the v3 details API.

    Returns a dict with keys:
        ``title``, ``type``, ``fields``, ``notes``,
        ``revision``, ``version``, ``folder_location``
    """
    from ... import nested_share_folder as _nsf

    title = record_uid
    rec_type = ''
    fields = []
    notes = ''
    revision = 0
    version = 0

    nsf_record_data = getattr(params, 'nested_share_record_data', {})
    if record_uid in nsf_record_data:
        data_obj = nsf_record_data[record_uid]
        if 'data_json' in data_obj:
            dj = data_obj['data_json']
            title    = dj.get('title', record_uid)
            rec_type = dj.get('type', '')
            fields   = dj.get('fields', [])
            notes    = dj.get('notes', '') or ''

    nsf_records = getattr(params, 'nested_share_records', {})
    if record_uid in nsf_records:
        rec_obj = nsf_records[record_uid]
        revision = rec_obj.get('revision', 0)
        version  = rec_obj.get('version', 0)

    if title == record_uid:
        try:
            det = _nsf.get_record_details_v3(params, [record_uid])
            if det['data']:
                d = det['data'][0]
                title    = d.get('title', record_uid)
                rec_type = d.get('type', '')
                revision = d.get('revision', 0)
                version  = d.get('version', 0)
        except Exception:
            pass

    return {
        'title': title,
        'type': rec_type,
        'fields': fields,
        'notes': notes,
        'revision': revision,
        'version': version,
        'folder_location': find_folder_location(params, record_uid),
    }
