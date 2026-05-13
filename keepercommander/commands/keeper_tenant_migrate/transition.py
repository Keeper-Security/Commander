import csv
import datetime
import json
import logging

from .inventory import _is_header_row


CATEGORY_A = 'A'   # NEW — not on target, safe to invite
CATEGORY_D = 'D'   # ALREADY_IN_TARGET — skip invite, still assign memberships
CATEGORY_E = 'E'   # PENDING_INVITE — extend/resend
CATEGORY_UNKNOWN = 'UNKNOWN'


_STATUS_TO_CATEGORY = {
    'active':   (CATEGORY_D, 'skip_invite_assign_memberships', '-',
                 'Already active on target — skip invite, still assign teams/roles/SFs'),
    'invited':  (CATEGORY_E, 'resend_or_extend', 'admin',
                 "Invite sent but not accepted — run 'enterprise-user --extend EMAIL'"),
    'pending':  (CATEGORY_E, 'resend_or_extend', 'admin',
                 "Invite sent but not accepted — run 'enterprise-user --extend EMAIL'"),
    'locked':   (CATEGORY_UNKNOWN, 'unlock_first', 'admin',
                 'User Locked on target — unlock before migration'),
    'disabled': (CATEGORY_UNKNOWN, 'unlock_first', 'admin',
                 'User Disabled on target — unlock before migration'),
}


def classify_user(email, target_status):
    """Return (category, action, actor, notes) for one email given its target status.

    target_status='' or None → Category A (NEW — safe to invite).
    """
    if not target_status:
        return (CATEGORY_A, 'auto_invite', 'admin',
                'No conflict detected — proceed with enterprise-user --invite')
    key = target_status.strip().lower()
    if key in _STATUS_TO_CATEGORY:
        return _STATUS_TO_CATEGORY[key]
    return (CATEGORY_UNKNOWN, 'investigate', 'admin',
            f'Unexpected target status: {target_status}')


def load_source_users_from_inventory(inventory_path):
    with open(inventory_path) as f:
        inv = json.load(f)
    out = []
    for u in inv.get('entities', {}).get('users', []):
        email = (u.get('email') or '').strip().lower()
        if not email:
            continue
        out.append({
            'email': email,
            'node': u.get('node', ''),
            'teams': list(u.get('teams', [])),
            'roles': list(u.get('roles', [])),
        })
    return out


def load_source_users_from_roster(roster_path):
    out = []
    with open(roster_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            email = (row.get('email') or row.get('Email') or
                     next(iter(row.values()), '')).strip().lower()
            if email and email != 'email':
                out.append({'email': email, 'node': '', 'teams': [], 'roles': []})
    return out


_HEADER_EMAIL_NAMES = {'email', 'e-mail', 'username', 'user'}
_HEADER_STATUS_NAMES = {'status', 'account status', 'user status'}


def _detect_column_indices(header_row):
    """Return (email_idx, status_idx) or (None, None) if no header detected."""
    if not header_row:
        return None, None
    first = header_row[0].strip().lower()
    # Conservative header heuristic: first cell looks like an ID column header.
    if first not in ('id', 'uid', 'user id', 'user_id', 'node id', 'node_id',
                     'email', 'e-mail'):
        return None, None
    email_idx = None
    status_idx = None
    for i, cell in enumerate(header_row):
        lower = cell.strip().lower()
        if email_idx is None and lower in _HEADER_EMAIL_NAMES:
            email_idx = i
        if status_idx is None and lower in _HEADER_STATUS_NAMES:
            status_idx = i
    return email_idx, status_idx


def load_target_user_map(target_users_csv):
    """Parse `enterprise-info --users --format csv` output into {email_lower: status}.

    Resolves columns by header name when the CSV has a header row. Falls back
    to the positional layout `id, email, status, ...` if no header is present
    (matches what `enterprise-info --columns status,... --format csv` emits).
    """
    mapping = {}
    with open(target_users_csv, newline='') as f:
        rows = list(csv.reader(f))

    if not rows:
        return mapping

    email_idx, status_idx = _detect_column_indices(rows[0])
    header_present = email_idx is not None and status_idx is not None

    for idx, row in enumerate(rows):
        if not row:
            continue
        if header_present and idx == 0:
            continue
        if not header_present and _is_header_row(row[0].strip()):
            continue

        if header_present:
            if len(row) <= max(email_idx, status_idx):
                continue
            email = row[email_idx].strip().lower()
            status = row[status_idx].strip()
        else:
            if len(row) < 3:
                continue
            email = row[1].strip().lower()
            status = row[2].strip()

        if email:
            mapping[email] = status
    return mapping


def categorize(source_users, target_user_map):
    """Apply classify_user() to every source user + tally categories."""
    rows = []
    tally = {CATEGORY_A: 0, CATEGORY_D: 0, CATEGORY_E: 0, CATEGORY_UNKNOWN: 0}
    for u in source_users:
        status = target_user_map.get(u['email'], '')
        category, action, actor, notes = classify_user(u['email'], status)
        tally[category] += 1
        rows.append({
            'source_email': u['email'],
            'source_node': u.get('node', ''),
            'source_teams': u.get('teams', []),
            'source_roles': u.get('roles', []),
            'target_status': status or 'not_found',
            'category': category,
            'action_required': action,
            'actor': actor,
            'notes': notes,
        })
    return rows, tally


FIELDNAMES = [
    'source_email', 'source_node', 'source_teams', 'source_roles',
    'target_status', 'category', 'action_required', 'actor', 'notes',
]


def write_plan_csv(rows, output_path):
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                **row,
                'source_teams': '|'.join(row.get('source_teams', [])),
                'source_roles': '|'.join(row.get('source_roles', [])),
            })


def render_summary_markdown(rows, tally, source_label, target_label,
                            source_user_count, target_user_count, csv_path):
    unknown_rows = [r for r in rows if r['category'] == CATEGORY_UNKNOWN]
    pending_rows = [r for r in rows if r['category'] == CATEGORY_E]

    lines = []
    lines.append('# User Transition Plan')
    lines.append('')
    lines.append(f"**Generated**: {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f'**Source**: {source_label}')
    lines.append(f'**Target**: {target_label}')
    lines.append(f'**Source users**: {source_user_count}')
    lines.append(f'**Target users**: {target_user_count}')
    lines.append('')
    lines.append('## Category Breakdown')
    lines.append('')
    lines.append('| Category | Count | Action | Gate? |')
    lines.append('|----------|------:|--------|-------|')
    lines.append(f'| **A — NEW** | {tally[CATEGORY_A]} | Auto-invite | No |')
    lines.append('| **B — PERSONAL_ACCOUNT** | 0* | User action required | **YES** |')
    lines.append('| **C — OTHER_ENTERPRISE** | 0* | MSP escalation | **YES** |')
    lines.append(f'| **D — ALREADY_IN_TARGET** | {tally[CATEGORY_D]} | Skip invite, assign memberships | No |')
    lines.append(f'| **E — PENDING_INVITE** | {tally[CATEGORY_E]} | Resend/extend | No |')
    lines.append(f'| **UNKNOWN** | {tally[CATEGORY_UNKNOWN]} | Manual investigation | **YES** |')
    lines.append('')
    lines.append('*Categories B and C can only be distinguished by attempting invite and parsing '
                 'the error response — this script categorizes optimistically as A. The actual '
                 '`tenant-migrate users` invocation will report real failures.*')
    lines.append('')
    lines.append('## Detailed Plan')
    lines.append('')
    lines.append(f'`{csv_path}` — see this CSV for per-user details.')
    lines.append('')
    lines.append('## Pre-Invite Gates')
    lines.append('')
    lines.append('Before running the users phase, resolve these blockers:')
    lines.append('')

    if unknown_rows:
        lines.append(f'### UNKNOWN ({len(unknown_rows)} users)')
        lines.append('Users with unexpected target statuses (Locked/Disabled/unknown). '
                     'Investigate each manually.')
        lines.append('')
        lines.append('```')
        for r in unknown_rows[:20]:
            lines.append(f'{r["source_email"]}  status={r["target_status"]}  notes={r["notes"]}')
        lines.append('```')
        lines.append('')

    if pending_rows:
        lines.append(f'### PENDING_INVITE ({len(pending_rows)} users)')
        lines.append('Run `keeper enterprise-user EMAIL --extend` to extend consent, '
                     'or `--unlock` if locked.')
        lines.append('')

    lines.append('## Next Steps')
    lines.append('')
    lines.append(f'1. Review `{csv_path}` — check every email\'s category')
    lines.append('2. Resolve any UNKNOWN-category users manually')
    lines.append('3. Extend consent for PENDING users if near expiry')
    lines.append('4. Run `tenant-migrate users` — Category A users get invited automatically')
    lines.append('5. After invites, rerun to detect any B/C users revealed by invite failures')
    lines.append('')
    return '\n'.join(lines) + '\n'


class UserTransitionChecker:
    def __init__(self, source_users, target_user_map,
                 source_label='', target_label='', target_user_count=None):
        self.source_users = source_users
        self.target_user_map = target_user_map
        self.source_label = source_label
        self.target_label = target_label
        self.target_user_count = (target_user_count if target_user_count is not None
                                  else len(target_user_map))

    @classmethod
    def from_inventory(cls, inventory_path, target_users_csv, target_label=''):
        return cls(
            source_users=load_source_users_from_inventory(inventory_path),
            target_user_map=load_target_user_map(target_users_csv),
            source_label=inventory_path,
            target_label=target_label,
        )

    @classmethod
    def from_roster(cls, roster_path, target_users_csv, target_label=''):
        return cls(
            source_users=load_source_users_from_roster(roster_path),
            target_user_map=load_target_user_map(target_users_csv),
            source_label=roster_path,
            target_label=target_label,
        )

    def run(self, csv_output, md_output):
        rows, tally = categorize(self.source_users, self.target_user_map)
        write_plan_csv(rows, csv_output)
        md = render_summary_markdown(
            rows, tally, self.source_label, self.target_label,
            source_user_count=len(self.source_users),
            target_user_count=self.target_user_count,
            csv_path=csv_output,
        )
        with open(md_output, 'w') as f:
            f.write(md)
        blockers = tally[CATEGORY_UNKNOWN]
        logging.info('Transition plan: A=%d D=%d E=%d UNKNOWN=%d',
                     tally[CATEGORY_A], tally[CATEGORY_D],
                     tally[CATEGORY_E], tally[CATEGORY_UNKNOWN])
        return {'rows': rows, 'tally': tally, 'blockers': blockers,
                'csv_path': csv_output, 'md_path': md_output}
