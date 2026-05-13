"""Source data-quality scanner — pre-flight inventory analysis.

User ask 2026-05-03: "we need a way to test what was skipped so we know
it works". The skip_audit module classifies SKIPs *after* a migration
runs. This module catches the same patterns *before* a migration runs,
so the operator can fix source data quality issues before the migration
SKIPs them.

Findings categories (matched against the inventory shape produced by
`live_inventory.build_inventory_from_params`):

  source-data-quality   — invalid source config that target rejects
                          (Bug 64-class: require_account_share on
                          non-admin roles, role + TRANSFER_ACCOUNT
                          mismatch, etc.)
  deprecated-alias      — legacy enforcement keys that get rewritten
                          at capture (Bug 63 deprecation map). Not
                          a problem at write time, but operators
                          should know their source is using
                          deprecated naming.
  whitespace-padding    — SF/team/role names with leading/trailing
                          whitespace that get stripped at create.
                          Cosmetic, but breaks naive verify.
  schema-violation      — roles carrying both managed_nodes (admin)
                          and teams. Keeper schema rule violation.
  lockout-risk          — v1.7: lockout-risk enforcements present on
                          builtin-admin roles. Surfaces pre-flight
                          even when the operator plans to opt in via
                          `--apply-admin-lockout-risk-enforcements`.

The output is a list of findings, each a dict:
    {category, entity_kind, entity_name, issue, suggested_action}

Read-only over the inventory dict. No live session needed.
"""

from .live_inventory import _DEPRECATED_ENFORCEMENT_KEYS
from .structure import (BUILTIN_ROLE_NAMES, BUILTIN_ROLE_SUFFIX,
                        LOCKOUT_RISK_ENFORCEMENTS)


CATEGORIES = (
    'source-data-quality',
    'deprecated-alias',
    'whitespace-padding',
    'schema-violation',
    'lockout-risk',
)


def _has_transfer_account(role):
    """True when the role carries TRANSFER_ACCOUNT in any managed_node
    privilege list. Mirrors the runtime check in
    `structure.build_source_role_meta`."""
    for mn in role.get('managed_nodes', []) or []:
        for priv in mn.get('privileges', []) or []:
            if (priv or '').lower() == 'transfer_account':
                return True
    return False


def scan_roles(inventory):
    """Yield findings about role-level data-quality issues."""
    roles = (inventory.get('entities') or {}).get('roles') or []
    for role in roles:
        name = (role.get('name') or '').strip()
        if not name:
            continue
        # Bug 64 — require_account_share on non-admin role.
        enfs = role.get('enforcements') or {}
        if 'require_account_share' in enfs and not _has_transfer_account(role):
            yield {
                'category': 'source-data-quality',
                'entity_kind': 'role',
                'entity_name': role.get('name', ''),
                'issue': ('require_account_share enforcement set on '
                          'role without TRANSFER_ACCOUNT privilege '
                          '(Bug 64). Target server will reject this '
                          'with bad_inputs_enforcement.'),
                'suggested_action': ('On source: either grant '
                                      'TRANSFER_ACCOUNT to this role '
                                      'OR remove the '
                                      'require_account_share '
                                      'enforcement.'),
            }
        # Bug 63a — deprecated enforcement aliases.
        for key in enfs:
            if (key or '').lower() in _DEPRECATED_ENFORCEMENT_KEYS:
                canonical, _xform = _DEPRECATED_ENFORCEMENT_KEYS[
                    (key or '').lower()]
                yield {
                    'category': 'deprecated-alias',
                    'entity_kind': 'role',
                    'entity_name': role.get('name', ''),
                    'issue': (f'Enforcement key {key!r} is a deprecated '
                              f'alias of {canonical!r}. Plugin will '
                              'rewrite at capture time, but the source '
                              'is using outdated naming.'),
                    'suggested_action': ('No action required — plugin '
                                          'auto-rewrites. To clean up '
                                          'source, set the canonical key '
                                          'manually.'),
                }
        # Schema violation: managed_nodes + teams together.
        if role.get('managed_nodes') and role.get('teams'):
            yield {
                'category': 'schema-violation',
                'entity_kind': 'role',
                'entity_name': role.get('name', ''),
                'issue': ('Role carries both managed_nodes (admin) '
                          'AND teams. Keeper schema rule prohibits '
                          'this combination.'),
                'suggested_action': ('On source: either remove '
                                      'managed_nodes (make role '
                                      'non-admin) or remove team '
                                      'assignments. Target migration '
                                      'will fail otherwise.'),
            }
        # v1.7 — lockout-risk enforcements on builtin-admin roles.
        # These will SKIP at structure-time by default (the safe
        # behavior); operator may opt in via
        # `--apply-admin-lockout-risk-enforcements` after auditing.
        # Either way, surface pre-flight so the operator sees the
        # decision they're making.
        bare_name = name.replace(BUILTIN_ROLE_SUFFIX, '')
        if bare_name in BUILTIN_ROLE_NAMES:
            present_lockout_keys = sorted(
                k for k in enfs if k in LOCKOUT_RISK_ENFORCEMENTS)
            for key in present_lockout_keys:
                yield {
                    'category': 'lockout-risk',
                    'entity_kind': 'role',
                    'entity_name': role.get('name', ''),
                    'issue': (f'Lockout-risk enforcement {key!r} on '
                              f'builtin-admin role {bare_name!r}. '
                              'Cross-tenant value drift on this key '
                              'class can lock the operator out of the '
                              'target tenant (worked example: '
                              '2026-04-26 jlima+demo2 incident via '
                              'restrict_ip_addresses).'),
                    'suggested_action': (
                        'Default v1.7 behavior is SKIP at structure-'
                        'time (safe). To apply, audit the source '
                        'value for target-tenant compatibility, '
                        'ensure an out-of-band recovery path, then '
                        'pass --apply-admin-lockout-risk-enforcements '
                        'to the structure subcommand. Run audit-'
                        'lockout-risk before AND after migration to '
                        'confirm intended state.'),
                }


def scan_whitespace(inventory):
    """Yield findings about leading/trailing whitespace in SF/team/role
    names. Plugin strips at create-time (Bug 55) but the source data
    is non-canonical."""
    entities = inventory.get('entities') or {}
    for kind in ('shared_folders', 'teams', 'roles'):
        for ent in entities.get(kind) or []:
            name = ent.get('name', '')
            if not name:
                continue
            if name != name.strip():
                yield {
                    'category': 'whitespace-padding',
                    'entity_kind': kind.rstrip('s'),
                    'entity_name': name,
                    'issue': (f'Name {name!r} has leading/trailing '
                              'whitespace. Plugin will strip on '
                              'create (Bug 55).'),
                    'suggested_action': ('No action required — plugin '
                                          'auto-strips. Verify uses '
                                          'whitespace-aware lookup '
                                          '(Bug 65).'),
                }


def scan(inventory):
    """Run every scanner and aggregate findings.

    Returns list[finding-dict]. Empty list when the inventory is clean.
    """
    findings = []
    findings.extend(scan_roles(inventory))
    findings.extend(scan_whitespace(inventory))
    return findings


def summarize(findings):
    """Return {category: count} across findings."""
    counts = {c: 0 for c in CATEGORIES}
    for f in findings:
        c = f.get('category', '')
        if c:
            counts[c] = counts.get(c, 0) + 1
    counts['total'] = sum(v for k, v in counts.items() if k != 'total')
    return counts
