"""Source-vs-target reconciliation report (port of 06c_reconciliation_report.sh).

Compares a frozen source inventory (from the plan phase) to live target-tenant
state and emits a human-readable Markdown report with per-entity delta
tables and actionable next-steps.

Pure functions where possible; Markdown generation is a single render_report()
call driven by a `ReconcileInput` dict.
"""

import datetime
import hashlib
import json
import logging
import os


def verify_inventory_checksum(inventory_path):
    """Return (ok: bool, actual: str, expected: str). ok=True if sidecar matches
    or the sidecar file doesn't exist (no tampering detected)."""
    sidecar = inventory_path + '.sha256'
    with open(inventory_path, 'rb') as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if not os.path.exists(sidecar):
        return True, actual, ''
    with open(sidecar) as f:
        expected = f.read().strip()
    return (expected == actual), actual, expected


def compare_by_key(src_items, target_names, key='name'):
    """Return (found, missing) lists of src names, split by target membership."""
    found = []
    missing = []
    for item in src_items:
        name = item.get(key, '')
        (found if name in target_names else missing).append(name)
    return found, missing


def build_target_index(target_state):
    """Build name/email lookup sets from a target_state dict.

    target_state shape: {
        'nodes': list[dict{name,...}],
        'teams': list[dict{name,...}],
        'roles': list[dict{name,...}],
        'users': list[dict{email,...}],
        'shared_folders': list[dict{name,...}],
    }
    """
    return {
        'nodes': {n.get('name', '') for n in target_state.get('nodes', [])},
        'teams': {t.get('name', '') for t in target_state.get('teams', [])},
        'roles': {r.get('name', '') for r in target_state.get('roles', [])},
        'users': {u.get('email', '').lower()
                  for u in target_state.get('users', []) if u.get('email')},
        'shared_folders': {s.get('name', '')
                           for s in target_state.get('shared_folders', [])},
    }


def compute_deltas(inventory, target_state):
    """Return a dict of deltas per entity type + aggregate metrics."""
    target = build_target_index(target_state)
    src = inventory.get('entities', {})

    node_found, node_missing = compare_by_key(src.get('nodes', []), target['nodes'])
    team_found, team_missing = compare_by_key(src.get('teams', []), target['teams'])
    role_found, role_missing = compare_by_key(src.get('roles', []), target['roles'])
    sf_found, sf_missing = compare_by_key(src.get('shared_folders', []),
                                           target['shared_folders'])

    user_found = []
    user_missing = []
    for u in src.get('users', []):
        email = (u.get('email', '') or '').lower()
        (user_found if email in target['users'] else user_missing).append(email)

    deltas = {
        'nodes': {'found': node_found, 'missing': node_missing},
        'teams': {'found': team_found, 'missing': team_missing},
        'roles': {'found': role_found, 'missing': role_missing},
        'users': {'found': user_found, 'missing': user_missing},
        'shared_folders': {'found': sf_found, 'missing': sf_missing},
    }

    total_expected = sum(inventory['counts'].get(k, 0) for k in
                         ('nodes', 'teams', 'roles', 'users', 'shared_folders'))
    total_found = sum(len(d['found']) for d in deltas.values())
    total_missing = sum(len(d['missing']) for d in deltas.values())

    return {
        'deltas': deltas,
        'total_expected': total_expected,
        'total_found': total_found,
        'total_missing': total_missing,
        'success_pct': (total_found / total_expected * 100.0) if total_expected else 100.0,
    }


def _status_emoji(total_missing, pct):
    if total_missing == 0:
        return '✅'
    if pct >= 90:
        return '⚠️'
    return '❌'


def _render_entity_section(title, src_items, delta, label_key='name'):
    lines = [f'## {title}', '']
    total = len(src_items)
    pass_count = len(delta['found'])
    fail_count = len(delta['missing'])
    status = '✅' if fail_count == 0 else '❌'
    lines.append('| Expected | Found | Missing | Status |')
    lines.append('|----------|-------|---------|--------|')
    lines.append(f'| {total} | {pass_count} | {fail_count} | {status} |')
    lines.append('')
    if fail_count:
        lines.append('### Missing from target')
        lines.append('')
        missing_set = set(delta['missing'])
        for item in src_items:
            name = item.get(label_key, '')
            if name in missing_set:
                lines.append(f'- `{name}`')
        lines.append('')
    return lines


def render_report(inventory, target_state, inventory_path=''):
    """Return the full Markdown report string."""
    reconcile = compute_deltas(inventory, target_state)
    deltas = reconcile['deltas']
    total_missing = reconcile['total_missing']
    pct = reconcile['success_pct']
    emoji = _status_emoji(total_missing, pct)

    src = inventory.get('entities', {})
    counts = inventory.get('counts', {})

    lines = ['# Migration Reconciliation Report', '']
    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    lines.append(f'**Generated**: {ts}')
    if inventory_path:
        lines.append(f'**Inventory**: `{os.path.basename(inventory_path)}` '
                     f'(captured {inventory.get("captured_at", "unknown")})')
    lines.append(f'**Source**: {inventory.get("source_user", "")} '
                 f'({inventory.get("source_root", "")})')
    # inventory is captured against source only, so target_user / target_root
    # are almost always empty. Fall back to target_state's captured_user +
    # root-node name so the report has real identities instead of blanks.
    target_nodes = target_state.get('nodes') or []
    target_root_fallback = (target_nodes[0].get('name', '')
                             if target_nodes else '')
    target_user = (inventory.get('target_user', '')
                   or target_state.get('captured_user', ''))
    target_root = (inventory.get('target_root', '')
                   or target_root_fallback)
    lines.append(f'**Target**: {target_user} ({target_root})')
    lines.append('')
    lines.append(f'## {emoji} Executive Summary')
    lines.append('')
    lines.append(f'- **Entities expected**: {reconcile["total_expected"]}')
    lines.append(f'- **Found on target**: {reconcile["total_found"]}')
    lines.append(f'- **Missing**: {total_missing}')
    lines.append(f'- **Success rate**: {pct:.1f}%')
    lines.append('')
    if total_missing == 0:
        lines.append(f'{emoji} All entities from source inventory are present on target.')
    else:
        lines.append(f'{emoji} {total_missing} entities need attention (see sections below).')
    lines.append('')

    lines.extend(_render_entity_section('Nodes', src.get('nodes', []),
                                        deltas['nodes']))
    lines.extend(_render_entity_section('Teams', src.get('teams', []),
                                        deltas['teams']))
    lines.extend(_render_entity_section('Roles', src.get('roles', []),
                                        deltas['roles']))
    lines.extend(_render_entity_section('Users', src.get('users', []),
                                        deltas['users'], label_key='email'))
    lines.extend(_render_entity_section('Shared Folders', src.get('shared_folders', []),
                                        deltas['shared_folders']))

    # Records summary (full field-level comparison is the validator's job)
    lines.append('## Records')
    lines.append('')
    lines.append('| Source Records | Attachments | Direct Shares | TOTP Fields |')
    lines.append('|----------------|-------------|---------------|-------------|')
    has_totp = sum(1 for r in src.get('records', []) if r.get('has_totp'))
    lines.append(f'| {counts.get("records", 0)} | {counts.get("attachments", 0)} | '
                 f'{counts.get("direct_shares", 0)} | {has_totp} |')
    lines.append('')
    lines.append('*Per-record field validation requires `tenant-migrate verify`.*')
    lines.append('')

    if src.get('roles'):
        target_role_set = build_target_index(target_state)['roles']
        lines.append('## Role Detail')
        lines.append('')
        lines.append('| Role | Managed Nodes | Privileges | Enforcements | Teams | Users |')
        lines.append('|------|--------------:|-----------:|-------------:|------:|------:|')
        for role in src['roles']:
            priv_count = sum(len(mn.get('privileges', []) or [])
                             for mn in role.get('managed_nodes', []) or [])
            marker = '✅' if role.get('name', '') in target_role_set else '❌'
            lines.append(
                f'| {marker} {role.get("name", "")} '
                f'| {len(role.get("managed_nodes", []) or [])} '
                f'| {priv_count} '
                f'| {len(role.get("enforcements", {}) or {})} '
                f'| {len(role.get("teams", []) or [])} '
                f'| {len(role.get("users", []) or [])} |'
            )
        lines.append('')

    lines.append('## Action Items')
    lines.append('')
    if total_missing == 0:
        lines.append('No action items — migration is reconciled.')
    else:
        for kind, section_title, action in (
            ('nodes', 'Nodes', 'Run `tenant-migrate structure` to restore node hierarchy.'),
            ('teams', 'Teams', 'Run `tenant-migrate structure` — check team restrictions and node assignments.'),
            ('roles', 'Roles', 'Run `tenant-migrate structure` — verify roles_complete.json is provided.'),
            ('users', 'Users', 'Run `tenant-migrate transition-check` to categorize user statuses.'),
            ('shared_folders', 'Shared Folders', 'Re-run `tenant-migrate structure` — check for dedup conflicts.'),
        ):
            missing = deltas[kind]['missing']
            if not missing:
                continue
            lines.append(f'### Missing {section_title} ({len(missing)})')
            lines.append(action)
            lines.append('')

    lines.append('## Next Steps')
    lines.append('')
    lines.append('1. Address each section under **Action Items** above')
    lines.append('2. Re-run `tenant-migrate verify` for field-level validation')
    lines.append('3. Once 100% reconciled, proceed to point-of-no-return gate')
    lines.append('4. Archive this report in `migration_logs/` for audit trail')
    lines.append('')

    return '\n'.join(lines)


class Reconciler:
    """Loads inventory + target state, emits Markdown + returns summary."""

    def __init__(self, inventory_path, target_state_provider):
        """
        target_state_provider: callable() -> target_state dict. Abstracts the
        enterprise-info fetch so tests don't need a live tenant.
        """
        self.inventory_path = inventory_path
        self.target_state_provider = target_state_provider

    def run(self, output_path):
        ok, actual, expected = verify_inventory_checksum(self.inventory_path)
        if not ok:
            logging.warning('Inventory checksum mismatch! actual=%s expected=%s',
                            actual, expected)
        with open(self.inventory_path) as f:
            inventory = json.load(f)
        target_state = self.target_state_provider()
        report = render_report(inventory, target_state, self.inventory_path)
        with open(output_path, 'w') as f:
            f.write(report)
        summary = compute_deltas(inventory, target_state)
        return {
            'report_path': output_path,
            'checksum_ok': ok,
            'summary': summary,
        }
