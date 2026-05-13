"""Pre-flight environment checks — port of 00_pre_flight_checks.sh.

Eleven read-only checks covering roster integrity, Commander version,
auth, disk space, and export-directory writability. Each yields a
PreflightCheck with status PASS | FAIL | WARN and a one-line message.

Separate from `selftest.py` which focuses on SDK-integration. Pre-flight
is higher-level: "can this machine actually run a migration?"
"""

import csv
import logging
import os
import re
import shutil


MIN_KEEPER_VERSION = (17, 0, 0)
MIN_DISK_GB = 20
# Bug 38 — pre-fix this list was the full bash-reference roster header
# (5 columns) and pre-flight FAILed on the minimal 2-column roster the
# `users` subcommand actually accepts. Now: only `email` + `full_name`
# are required (REQUIRED_*); the rest are optional and surface as a
# WARN if missing in `check_roster_empty_fields`. Operators can still
# pass the bash-reference 5-column shape — extras are accepted.
REQUIRED_ROSTER_HEADER = ['email', 'full_name']
OPTIONAL_ROSTER_HEADER = ['department', 'record_count', 'migration_folder_name']
# Kept for back-compat with anything that imported the old name.
EXPECTED_ROSTER_HEADER = REQUIRED_ROSTER_HEADER + OPTIONAL_ROSTER_HEADER
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
FOLDER_RE = re.compile(r'^MIGRATION-[A-Za-z0-9_-]+$')


class PreflightCheck:
    __slots__ = ('name', 'status', 'message')

    def __init__(self, name, status, message=''):
        self.name = name
        self.status = status
        self.message = message

    def as_row(self):
        return [self.name, self.status, self.message]

    def __repr__(self):
        # Readable one-liner — rehearsal .out artifacts dump list-of-
        # PreflightCheck and the default <obj at 0x...> repr hid the
        # actual diagnostic signal.
        msg = f' — {self.message}' if self.message else ''
        return f'PreflightCheck({self.status} {self.name}{msg})'


# ─── Keeper version ──────────────────────────────────────────────────────────


def _parse_version(v):
    """Parse 'X.Y.Z' (+ optional trailing suffix) into (X, Y, Z)."""
    m = re.match(r'(\d+)\.(\d+)\.(\d+)', v or '')
    if not m:
        return None
    return tuple(int(m.group(i)) for i in (1, 2, 3))


def check_keeper_version(min_version=MIN_KEEPER_VERSION):
    try:
        import keepercommander
    except ImportError:
        return PreflightCheck('keeper.installed', 'FAIL',
                              'keepercommander package not importable')
    version = getattr(keepercommander, '__version__', '')
    parsed = _parse_version(version)
    if parsed is None:
        return PreflightCheck('keeper.version', 'WARN',
                              f'Could not parse version: {version!r}')
    if parsed >= min_version:
        return PreflightCheck(
            'keeper.version', 'PASS',
            f'{version} ≥ {".".join(map(str, min_version))}',
        )
    return PreflightCheck(
        'keeper.version', 'FAIL',
        f'{version} < minimum {".".join(map(str, min_version))}',
    )


# ─── Roster sanity ───────────────────────────────────────────────────────────


def check_roster_exists(roster_path):
    if not os.path.exists(roster_path):
        return PreflightCheck('roster.file', 'FAIL', f'not found: {roster_path}')
    return PreflightCheck('roster.file', 'PASS', roster_path)


def check_roster_header(roster_path):
    """PASS if the roster contains all REQUIRED columns. Extras are
    fine. Bug 38 — pre-fix this required the full 5-column bash-
    reference header and FAILed on the 2-column shape `users`
    actually accepts.
    """
    try:
        with open(roster_path, newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None)
    except OSError:
        return PreflightCheck('roster.header', 'FAIL', 'cannot read file')
    if not header:
        return PreflightCheck('roster.header', 'FAIL', 'empty file')
    cols = {c.strip() for c in header}
    missing = [c for c in REQUIRED_ROSTER_HEADER if c not in cols]
    if missing:
        return PreflightCheck(
            'roster.header', 'FAIL',
            f'missing required column(s): {missing}; got {list(cols)}',
        )
    return PreflightCheck('roster.header', 'PASS', ','.join(sorted(cols)))


def _read_roster_rows(roster_path):
    with open(roster_path, newline='') as f:
        reader = csv.DictReader(f)
        return list(reader)


def check_roster_row_count(roster_path):
    rows = _read_roster_rows(roster_path)
    n = len([r for r in rows if (r.get('email') or '').strip()])
    if n == 0:
        return PreflightCheck('roster.rows', 'WARN',
                              'no users — structure-only migration')
    return PreflightCheck('roster.rows', 'PASS', f'{n} user(s)')


def check_roster_duplicates(roster_path):
    rows = _read_roster_rows(roster_path)
    emails = [(r.get('email') or '').strip().lower()
              for r in rows if (r.get('email') or '').strip()]
    seen = set()
    dupes = set()
    for e in emails:
        if e in seen:
            dupes.add(e)
        seen.add(e)
    if dupes:
        return PreflightCheck('roster.dupes', 'FAIL',
                              f'duplicate emails: {sorted(dupes)}')
    return PreflightCheck('roster.dupes', 'PASS', 'no duplicate emails')


def check_roster_email_format(roster_path):
    rows = _read_roster_rows(roster_path)
    bad = []
    for r in rows:
        email = (r.get('email') or '').strip()
        if email and not EMAIL_RE.match(email):
            bad.append(email)
    if bad:
        return PreflightCheck('roster.email_format', 'WARN',
                              f'possibly-invalid emails: {bad[:5]}')
    return PreflightCheck('roster.email_format', 'PASS',
                          'all email addresses well-formed')


def check_roster_folder_convention(roster_path):
    rows = _read_roster_rows(roster_path)
    bad = []
    for r in rows:
        folder = (r.get('migration_folder_name') or '').strip()
        if folder and not FOLDER_RE.match(folder):
            bad.append(folder)
    if bad:
        return PreflightCheck('roster.folder_convention', 'FAIL',
                              f'not matching MIGRATION-* pattern: {bad[:5]}')
    return PreflightCheck('roster.folder_convention', 'PASS',
                          'all folder names match MIGRATION-*')


def check_roster_empty_fields(roster_path):
    """Warn on empty cells. Required-column emptiness is a strong
    signal (FAIL); optional-column emptiness is only worth a WARN.
    Bug 38 — pre-fix any optional column being empty failed the
    check, even though those columns are unused by `users`.
    """
    rows = _read_roster_rows(roster_path)
    cols_present = set()
    if rows:
        cols_present = set(rows[0].keys())
    required_empty = 0
    optional_empty = 0
    for r in rows:
        for key in REQUIRED_ROSTER_HEADER:
            if not (r.get(key) or '').strip():
                required_empty += 1
        for key in OPTIONAL_ROSTER_HEADER:
            if key not in cols_present:
                continue   # column absent — not "empty", just unused
            if not (r.get(key) or '').strip():
                optional_empty += 1
    if required_empty:
        return PreflightCheck(
            'roster.empty_fields', 'FAIL',
            f'{required_empty} empty required-field cell(s)',
        )
    if optional_empty:
        return PreflightCheck(
            'roster.empty_fields', 'WARN',
            f'{optional_empty} empty optional-field cell(s)',
        )
    return PreflightCheck('roster.empty_fields', 'PASS',
                          'all fields populated')


# ─── Auth / session ──────────────────────────────────────────────────────────


def check_session(params):
    user = getattr(params, 'user', '') or ''
    if user:
        return PreflightCheck('session', 'PASS', user)
    return PreflightCheck('session', 'FAIL', 'not authenticated')


def check_enterprise_admin(params):
    """Heuristic — param.enterprise present implies enterprise-admin role."""
    ent = getattr(params, 'enterprise', None) or {}
    if ent:
        return PreflightCheck('enterprise.admin', 'PASS',
                              ent.get('enterprise_name', '?'))
    return PreflightCheck(
        'enterprise.admin', 'WARN',
        'cannot confirm enterprise admin — params.enterprise empty',
    )


# ─── Environment ─────────────────────────────────────────────────────────────


def check_disk_space(output_dir='.', min_gb=MIN_DISK_GB):
    try:
        total, used, free = shutil.disk_usage(output_dir)
    except OSError as e:
        return PreflightCheck('disk', 'FAIL', f'disk_usage failed: {e}')
    free_gb = free // (1024 ** 3)
    if free_gb >= min_gb:
        return PreflightCheck('disk', 'PASS', f'{free_gb}GB free ≥ {min_gb}GB')
    return PreflightCheck('disk', 'FAIL',
                          f'{free_gb}GB free < {min_gb}GB required')


def check_output_dir_writable(output_dir):
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        return PreflightCheck('output_dir.mkdir', 'FAIL', str(e))
    if not os.access(output_dir, os.W_OK):
        return PreflightCheck('output_dir.writable', 'FAIL',
                              f'{output_dir} not writable')
    return PreflightCheck('output_dir.writable', 'PASS', output_dir)


# ─── Driver ──────────────────────────────────────────────────────────────────


def run(params, roster_path, output_dir='.', min_disk_gb=MIN_DISK_GB):
    """Execute every check. Returns (results, fail_count, warn_count)."""
    results = []

    results.append(check_keeper_version())
    results.append(check_session(params))
    results.append(check_enterprise_admin(params))
    results.append(check_disk_space(output_dir, min_gb=min_disk_gb))
    results.append(check_output_dir_writable(output_dir))

    results.append(check_roster_exists(roster_path))
    if results[-1].status == 'PASS':
        results.append(check_roster_header(roster_path))
        results.append(check_roster_row_count(roster_path))
        results.append(check_roster_duplicates(roster_path))
        results.append(check_roster_email_format(roster_path))
        results.append(check_roster_folder_convention(roster_path))
        results.append(check_roster_empty_fields(roster_path))

    fails = sum(1 for r in results if r.status == 'FAIL')
    warns = sum(1 for r in results if r.status == 'WARN')

    for r in results:
        emoji = {'PASS': '✓', 'FAIL': '✗', 'WARN': '⚠'}.get(r.status, '?')
        logging.info('  %s %-26s %s', emoji, r.name, r.message)

    return results, fails, warns
