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
KeeperDrive — shared utilities, constants, and design-pattern helpers.

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
"""Sentinel UID the server uses for the KeeperDrive root folder."""

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


# ═══════════════════════════════════════════════════════════════════════════
# Error-handling patterns  (eliminates repetitive try/except boilerplate)
# ═══════════════════════════════════════════════════════════════════════════

@contextmanager
def command_error_handler(cmd_name):
    """Context manager that standardises exception handling for commands.

    CommandError passes through unchanged; every other exception is wrapped
    in a new CommandError so callers never need the 5-line try/except block.

    Usage::

        with command_error_handler('kd-mkdir'):
            result = api_call(...)
            check_result(result, 'kd-mkdir')
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
    """Resolve a folder name, path, or UID to a KeeperDrive folder UID.

    Delegates to the service layer's ``resolve_folder_identifier``
    to avoid duplicating resolution logic.
    """
    if not identifier:
        return None
    from ... import keeper_drive as _kd
    return _kd.resolve_folder_identifier(params, identifier)


def find_folder_location(params, record_uid):
    """Return the display name of the first folder containing *record_uid*."""
    kd_folder_records = getattr(params, 'keeper_drive_folder_records', {})
    kd_folders = getattr(params, 'keeper_drive_folders', {})
    for fuid, rec_set in kd_folder_records.items():
        if record_uid in rec_set:
            if fuid == ROOT_FOLDER_UID:
                return 'root'
            if fuid in kd_folders:
                return kd_folders[fuid].get('name', fuid)
            return fuid
    return ''


# ═══════════════════════════════════════════════════════════════════════════
# Expiration parsing
# ═══════════════════════════════════════════════════════════════════════════

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
            return int(dt.timestamp() * 1000)
        except ValueError:
            raise CommandError(
                cmd_name,
                f'Invalid --expire-at format: {raw!r}. '
                f'Use ISO datetime, e.g. 2027-01-01T00:00:00Z or "never"',
            )

    m = _EXPIRATION_RE.fullmatch(raw)
    if not m:
        raise CommandError(
            cmd_name,
            f'Invalid --expire-in format: {raw!r}. Examples: 30d, 6mo, 1y, 24h, 30mi',
        )
    amount = int(m.group(1))
    unit = m.group(2).lower()
    now = datetime.datetime.now(timezone.utc)
    delta_map = {
        'mi': timedelta(minutes=amount),
        'h':  timedelta(hours=amount),
        'd':  timedelta(days=amount),
        'mo': timedelta(days=amount * 30),
        'y':  timedelta(days=amount * 365),
    }
    delta = next(v for k, v in delta_map.items() if unit.startswith(k))
    return int((now + delta).timestamp() * 1000)


# ═══════════════════════════════════════════════════════════════════════════
# Role helpers
# ═══════════════════════════════════════════════════════════════════════════

def infer_role(access):
    """Derive a display role name from permission flags (most permissive wins).

    Follows the official permission matrix::

        manager > content-share-manager > shared-manager >
        content-manager > viewer > contributor
    """
    get = access.get
    if get('can_change_ownership') or get('can_delete'):
        return 'manager'
    if get('can_update_access') and get('can_approve_access'):
        return 'content-share-manager'
    if get('can_update_access'):
        return 'shared-manager'
    if get('can_edit'):
        return 'content-manager'
    if get('can_view') and get('can_list_access'):
        return 'viewer'
    return 'contributor'


def role_label(access_role_type):
    """Convert a numeric ``access_role_type`` to a readable uppercase label."""
    from ... import keeper_drive as _kd
    if access_role_type is not None:
        return next(
            (k.upper() for k, v in _kd.ROLE_NAME_MAP.items()
             if v == access_role_type and '-' not in k and '_' not in k),
            str(access_role_type),
        )
    return ''


def get_access_role_label(access):
    """Get the role label for an access entry — stored role type or inferred."""
    role_int = access.get('access_role_type')
    if role_int is not None:
        raw = role_label(role_int)
        # Map backend roles 0 (NAVIGATOR) and 1 (REQUESTOR) to display label CONTRIBUTOR
        if raw in ('NAVIGATOR', 'REQUESTOR', '0', '1'):
            return 'CONTRIBUTOR'
        return raw
    inferred = infer_role(access).upper().replace('-', '_')
    return inferred


# ═══════════════════════════════════════════════════════════════════════════
# Formatting helpers
# ═══════════════════════════════════════════════════════════════════════════

def format_timestamp(ms):
    """Format a millisecond epoch timestamp as ``'YYYY-MM-DD HH:MM:SS'``."""
    if ms:
        return datetime.datetime.fromtimestamp(ms / 1000).strftime('%Y-%m-%d %H:%M:%S')
    return ''


# ═══════════════════════════════════════════════════════════════════════════
# Record metadata loading
# ═══════════════════════════════════════════════════════════════════════════

def load_record_metadata(params, record_uid):
    """Load record metadata from cache, falling back to the v3 details API.

    Returns a dict with keys:
        ``title``, ``type``, ``fields``, ``notes``,
        ``revision``, ``version``, ``folder_location``
    """
    from ... import keeper_drive as _kd

    title = record_uid
    rec_type = ''
    fields = []
    notes = ''
    revision = 0
    version = 0

    kd_record_data = getattr(params, 'keeper_drive_record_data', {})
    if record_uid in kd_record_data:
        data_obj = kd_record_data[record_uid]
        if 'data_json' in data_obj:
            dj = data_obj['data_json']
            title    = dj.get('title', record_uid)
            rec_type = dj.get('type', '')
            fields   = dj.get('fields', [])
            notes    = dj.get('notes', '') or ''

    kd_records = getattr(params, 'keeper_drive_records', {})
    if record_uid in kd_records:
        rec_obj = kd_records[record_uid]
        revision = rec_obj.get('revision', 0)
        version  = rec_obj.get('version', 0)

    if title == record_uid:
        try:
            det = _kd.get_record_details_v3(params, [record_uid])
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
