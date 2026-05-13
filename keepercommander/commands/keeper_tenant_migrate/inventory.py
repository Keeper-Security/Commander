import csv
import datetime
import glob
import hashlib
import json
import logging
import os
import re


def _keeps(prefix):
    if not prefix:
        return lambda _name: True
    return lambda name: isinstance(name, str) and name.startswith(prefix)


def _split_lines(cell):
    """Split a Commander CSV cell that packs multiple values separated by a newline.

    `enterprise-info --format csv` emits list-valued columns (teams, roles, alias)
    as a single quoted cell where entries are separated by a real newline. We
    also tolerate the literal two-char sequence `\\n` in case upstream escapes it.
    """
    if not cell:
        return []
    raw = cell.replace('\\n', '\n')
    return [p.strip() for p in raw.split('\n') if p.strip()]


def _is_header_row(first_cell):
    return first_cell.lower() in ('id', 'uid', 'user id', 'user_id', 'node id', 'node_id')


def _read_csv_rows(path):
    with open(path, newline='') as f:
        for row in csv.reader(f):
            if row and not _is_header_row(row[0].strip()):
                yield [c.strip() for c in row]


def parse_nodes_csv(path, keep):
    out = []
    for parts in _read_csv_rows(path):
        if len(parts) < 7:
            continue
        nid, name, parent, isolated, ucount, tcount, rcount = parts[:7]
        if not keep(name):
            continue
        out.append({
            'id': nid,
            'name': name,
            'parent': parent,
            'isolated': isolated.lower() == 'true',
            'user_count': int(ucount) if ucount.isdigit() else 0,
            'team_count': int(tcount) if tcount.isdigit() else 0,
            'role_count': int(rcount) if rcount.isdigit() else 0,
        })
    return out


def parse_teams_csv(path, keep):
    out = []
    for parts in _read_csv_rows(path):
        if len(parts) < 6:
            continue
        uid, name, restricts, node, ucount, rcount = parts[:6]
        if not keep(name):
            continue
        out.append({
            'uid': uid,
            'name': name,
            'restricts': restricts,
            'node': node,
            'user_count': int(ucount) if ucount.isdigit() else 0,
            'role_count': int(rcount) if rcount.isdigit() else 0,
        })
    return out


def parse_roles_dir(roles_dir, keep):
    out = []
    if not roles_dir or not os.path.isdir(roles_dir):
        return out
    for role_file in sorted(glob.glob(os.path.join(roles_dir, '*.json'))):
        try:
            with open(role_file) as f:
                role = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if not keep(role.get('name', '')):
            continue
        out.append({
            'id': role.get('id'),
            'name': role.get('name'),
            'node': role.get('node'),
            'default_role': role.get('default_role', False),
            'managed_nodes': role.get('managed_nodes', []),
            'enforcements': role.get('enforcements', {}),
            'users': role.get('users', []),
            'teams': role.get('teams', []),
        })
    return out


def load_hsf_map(hsf_map_path):
    mapping = {}
    if not hsf_map_path or not os.path.exists(hsf_map_path):
        return mapping
    with open(hsf_map_path) as f:
        for line in f:
            line = line.rstrip()
            if '|' not in line:
                continue
            t_name, u_email = line.split('|', 1)
            mapping.setdefault(u_email.strip().lower(), set()).add(t_name.strip())
    return mapping


def parse_users_csv(path, prefix, hsf_map):
    out = []
    for parts in _read_csv_rows(path):
        # job_title may be missing; accept 11 or more columns
        if len(parts) < 11:
            continue
        uid, email, status, transfer_status, node, tcount, teams, rcount, roles, alias, tfa = parts[:11]
        job_title = parts[11] if len(parts) >= 12 else ''
        team_list = _split_lines(teams)
        role_list = _split_lines(roles)
        if prefix:
            in_scoped_team = any(prefix in t for t in team_list)
            in_scoped_role = any(prefix in r for r in role_list)
            in_scoped_node = prefix in node
            if not (in_scoped_team or in_scoped_role or in_scoped_node):
                continue
        alias_list = [a for a in _split_lines(alias) if a.lower() != email.lower()]
        out.append({
            'id': uid,
            'email': email,
            'status': status,
            'transfer_status': transfer_status,
            'node': node,
            'teams': team_list,
            'roles': role_list,
            'alias': alias,
            'aliases': alias_list,
            '2fa_enabled': tfa.lower() == 'true',
            'job_title': job_title,
            'hide_shared_folders_teams': sorted(hsf_map.get(email.strip().lower(), [])),
        })
    return out


def parse_shared_folders_json(path, keep):
    out = []
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path) as f:
            sf_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out
    sfs = sf_data if isinstance(sf_data, list) else list(sf_data.values())
    for sf in sfs:
        name = sf.get('name', '')
        if not keep(name):
            continue
        out.append({
            'uid': sf.get('shared_folder_uid', sf.get('uid', '')),
            'name': name,
            'default_manage_users': sf.get('default_manage_users', sf.get('manage_users')),
            'default_manage_records': sf.get('default_manage_records', sf.get('manage_records')),
            'default_can_edit': sf.get('default_can_edit', sf.get('can_edit')),
            'default_can_share': sf.get('default_can_share', sf.get('can_share')),
            'users': sf.get('users', []),
            'teams': sf.get('teams', []),
            'records': sf.get('records', []),
        })
    return out


_RECORD_JSON_RE = re.compile(r'\{[^{}]*"title".*?\n\}(?=\s|\Z)', re.DOTALL)


def parse_record_file(path):
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return None
    m = _RECORD_JSON_RE.search(content)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
        return None


def _field_first_value(fields, field_type):
    for f in fields or []:
        if isinstance(f, dict) and f.get('type') == field_type:
            vals = f.get('value', []) or []
            if isinstance(vals, list):
                return vals[0] if vals else ''
            return vals
    return ''


def _custom_fields_by_label(custom):
    """Normalize v3 custom[] into {label: value}.

    Multi-value fields are joined with '\\n' (same shape convert_v3_record
    preserves). Empty values skipped. Label collisions get numeric suffix.
    """
    out = {}
    for cf in custom or []:
        if not isinstance(cf, dict):
            continue
        label = cf.get('label') or cf.get('type') or ''
        values = cf.get('value', []) or []
        if not values or (isinstance(values, list) and not any(values)):
            continue
        if isinstance(values, list):
            v = '\n'.join(str(x) for x in values) if len(values) > 1 else str(values[0])
        else:
            v = str(values)
        key = label
        i = 1
        while key in out:
            i += 1
            key = f'{label}#{i}'
        out[key] = v
    return out


def _non_empty_field_count(fields):
    """Count typed fields with at least one non-empty value.

    Mirrors what Keeper's import/export pipeline considers a 'populated'
    field — drives the field-count-parity check in phase_records.
    """
    n = 0
    for f in fields or []:
        if not isinstance(f, dict):
            continue
        values = f.get('value', []) or []
        if isinstance(values, list):
            if any(v for v in values):
                n += 1
        elif values:
            n += 1
    return n


def _non_empty_custom_field_count(custom):
    n = 0
    for cf in custom or []:
        if not isinstance(cf, dict):
            continue
        values = cf.get('value', []) or []
        if isinstance(values, list):
            if any(v for v in values):
                n += 1
        elif values:
            n += 1
    return n


def summarize_record(rec, include_fields=False):
    """Return the record's validator shape.

    With `include_fields=True`, also captures login/password/login_url/notes/
    custom_fields so phase_records can do field-by-field comparison. Without
    the flag, only counts + flags are emitted (safer default for large
    tenants — keeps passwords out of the inventory JSON).

    Always-captured counts (for source↔target count-drift detection):
      - `standard_field_count` — non-empty typed fields (login / password /
        url / notes / oneTimeCode / passkey / ...)
      - `custom_field_count` — non-empty entries in the custom[] array
      - `total_field_count` — sum of the above
      - `attachment_count` — fileRef value total
      - `direct_shares` — list of non-owner share grants
      - `has_totp` — convenience flag
    """
    fields = rec.get('fields', []) or []
    file_refs = [f for f in fields if isinstance(f, dict) and f.get('type') == 'fileRef']
    attach_count = sum(len(f.get('value', []) or []) for f in file_refs)
    non_owner_shares = [up for up in rec.get('user_permissions', []) or []
                        if isinstance(up, dict) and not up.get('owner')]

    standard_fc = _non_empty_field_count(fields)
    custom_fc = _non_empty_custom_field_count(rec.get('custom', []))
    summary = {
        'uid': rec.get('record_uid'),
        'title': rec.get('title'),
        'type': rec.get('type'),
        'attachment_count': attach_count,
        'standard_field_count': standard_fc,
        'custom_field_count': custom_fc,
        'total_field_count': standard_fc + custom_fc,
        'has_totp': any(f.get('type') == 'oneTimeCode' and f.get('value')
                        for f in fields if isinstance(f, dict)),
        'direct_shares': [{
            'username': s.get('username'),
            'editable': s.get('editable', False),
            'shareable': s.get('shareable', False),
            'share_admin': s.get('share_admin', False),
        } for s in non_owner_shares],
    }

    if include_fields:
        summary['login'] = _field_first_value(fields, 'login')
        summary['password'] = _field_first_value(fields, 'password')
        summary['login_url'] = _field_first_value(fields, 'url')
        summary['notes'] = rec.get('notes', '') or ''
        summary['totp_secret'] = _field_first_value(fields, 'oneTimeCode')
        summary['custom_fields'] = _custom_fields_by_label(rec.get('custom', []))

    return summary


def parse_records_dir(records_dir, keep, include_fields=False):
    out = []
    if not records_dir or not os.path.isdir(records_dir):
        return out
    for rec_file in sorted(glob.glob(os.path.join(records_dir, '*.json'))):
        rec = parse_record_file(rec_file)
        if rec is None:
            continue
        if not keep(rec.get('title', '')):
            continue
        out.append(summarize_record(rec, include_fields=include_fields))
    return out


def compute_counts(entities):
    records = entities['records']
    roles = entities['roles']
    return {
        'nodes': len(entities['nodes']),
        'teams': len(entities['teams']),
        'roles': len(roles),
        'users': len(entities['users']),
        'shared_folders': len(entities['shared_folders']),
        'records': len(records),
        'attachments': sum(r.get('attachment_count', 0) for r in records),
        'direct_shares': sum(len(r.get('direct_shares', [])) for r in records),
        'total_enforcements': sum(len(r.get('enforcements', {})) for r in roles),
        'total_privileges': sum(
            sum(len(mn.get('privileges', [])) for mn in r.get('managed_nodes', []))
            for r in roles
        ),
    }


class InventoryAssembler:
    """Assemble an inventory dict from pre-captured source files.

    The bash reference (00d_migration_inventory.sh) fetches raw CSV/JSON via the
    Commander CLI and stages them in a tmp dir. This class takes that tmp dir
    (or any dir with the same layout) and produces the merged inventory JSON.
    """

    FILES = {
        'nodes_csv': 'nodes.csv',
        'teams_csv': 'teams.csv',
        'users_csv': 'users.csv',
        'roles_dir': 'roles',
        'shared_folders_json': 'shared_folders.json',
        'records_dir': 'records',
        'hsf_map': 'user_hsf_teams.txt',
    }

    def __init__(self, tmp_dir, prefix='', scope_node='',
                 source_user='', source_server='', source_root='',
                 target_user='', target_root='', include_fields=False):
        self.tmp_dir = tmp_dir
        self.prefix = prefix
        self.scope_node = scope_node
        self.source_user = source_user
        self.source_server = source_server
        self.source_root = source_root
        self.target_user = target_user
        self.target_root = target_root
        self.include_fields = include_fields

    def _path(self, key):
        rel = self.FILES[key]
        return os.path.join(self.tmp_dir, rel)

    def build(self):
        keep = _keeps(self.prefix)
        hsf_map = load_hsf_map(self._path('hsf_map'))

        entities = {
            'nodes': parse_nodes_csv(self._path('nodes_csv'), keep) if os.path.exists(self._path('nodes_csv')) else [],
            'teams': parse_teams_csv(self._path('teams_csv'), keep) if os.path.exists(self._path('teams_csv')) else [],
            'roles': parse_roles_dir(self._path('roles_dir'), keep),
            'users': parse_users_csv(self._path('users_csv'), self.prefix, hsf_map)
                      if os.path.exists(self._path('users_csv')) else [],
            'shared_folders': parse_shared_folders_json(self._path('shared_folders_json'), keep),
            'records': parse_records_dir(self._path('records_dir'), keep,
                                         include_fields=self.include_fields),
        }

        inventory = {
            'captured_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'source_user': self.source_user,
            'source_server': self.source_server,
            'source_root': self.source_root,
            'target_user': self.target_user,
            'target_root': self.target_root,
            'scope_node': self.scope_node,
            'prefix_filter': self.prefix,
            'counts': compute_counts(entities),
            'entities': entities,
        }
        return inventory

    def write(self, output_path):
        inventory = self.build()
        with open(output_path, 'w') as f:
            json.dump(inventory, f, indent=2)
        os.chmod(output_path, 0o600)
        with open(output_path, 'rb') as f:
            checksum = hashlib.sha256(f.read()).hexdigest()
        sidecar = f'{output_path}.sha256'
        with open(sidecar, 'w') as f:
            f.write(checksum + '\n')
        os.chmod(sidecar, 0o600)
        logging.info('Inventory: %s (sha256: %s)', output_path, checksum)
        return inventory, checksum
