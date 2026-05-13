"""SKIP audit framework — categorize SKIPPED entries from a structure
results CSV so operators can tell at a glance which gaps are by-design
(no action), source data-quality (fix on source), target capability
(unfixable), or stale-pending-rehearsal (will resolve on next run).

Driven by user ask 2026-05-03: "we need a way to test what was skipped
so we know it works". The framework reads `structure_results.csv` (the
per-step CSV emitted by `structure` and `auto-migrate` since v1.5.5)
and categorizes every SKIPPED row.

Categories:
  by-design       — self-reference, intentional `users` stage SKIP, etc.
                    Operator action: none.
  bug-pending     — pattern matches a now-fixed plugin bug (Bug 58
                    duplicate-name dedupe, Bug 62 colon path, Bug 63
                    legacy alias, Bug 64 TRANSFER_ACCOUNT pre-flight).
                    Will resolve on next rehearsal.
                    Operator action: re-run.
  source-quality  — source carries invalid configuration (e.g. Bug 64
                    require_account_share on non-admin role). Target
                    rejects on stricter validation.
                    Operator action: fix source, re-export.
  target-capability — target tenant genuinely lacks a privilege or
                    feature (e.g. `privilege_access`, `manage_billing`
                    not enabled on the plan). Plugin can't substitute.
                    Operator action: enable feature on target plan, or
                    accept the gap.
  cascade         — parent operation failed/skipped, all dependents
                    couldn't proceed. Resolves when parent resolves.
                    Operator action: investigate the parent SKIP.
  unknown         — pattern not matched. Likely a new bug.
                    Operator action: file an issue.

The framework is read-only over the CSV; it doesn't talk to a live
session. Dynamic verification (probing target tenant capabilities) is
a separate phase planned for v1.7.
"""

import csv
import os


CATEGORIES = (
    'by-design',
    'bug-pending',
    'source-quality',
    'target-capability',
    'cascade',
    'unknown',
)


_BUG_PATTERNS = (
    # (substring matched against `notes` column lowercased, category, bug_ref)
    ('self-reference', 'by-design', 'Bug 47 self-ref guard'),
    ('users invite is high-risk', 'by-design',
     'intentional users-stage SKIP — run `tenant-migrate users` separately'),
    ('role never created on target', 'cascade',
     'parent role missing — investigate parent SKIP first'),
    ('target role never created', 'cascade',
     'parent role missing on target — investigate parent SKIP. With '
     'Bug 58 fix the duplicate-name case resolves automatically'),
    ('target team never created', 'cascade',
     'parent team missing on target — investigate parent team SKIP'),
    ('renamed from', 'bug-pending', 'Bug 61 verify rename-aware lookup '
     '(structure stage already renames; verify now resolves through map)'),
    ('lacks transfer_account', 'source-quality',
     'Bug 64 — fix source role to grant TRANSFER_ACCOUNT or remove '
     'require_account_share enforcement'),
    ('cross-tenant require_account_share rejection', 'source-quality',
     'Bug 64 (formerly Upstream-3) — pre-flight gate added in v1.6'),
    ('environment-restricted boolean', 'bug-pending',
     'Bug 63 / Upstream-4 reclassified — deprecated alias rewrite '
     'added in v1.6, will resolve next rehearsal'),
    ('invalid privilege', 'target-capability',
     'target tenant plan does not enable this privilege; enable on '
     'target plan or accept the gap'),
    ('shape not accepted by commander cli', 'bug-pending',
     'Bug 62 colon-path sanitization (FILE phase) added in v1.6'),
    ('dependency missing on target', 'cascade',
     'usually resolves after `users` stage completes; re-run after '
     'users migration'),
    ('already present (resume)', 'by-design',
     'idempotent re-run — entity was created in a prior run'),
    ('default for new users', 'by-design',
     'role created with new-user-default flag set'),
    ('keeper schema rule', 'source-quality',
     'source role carries both managed_nodes (admin) and teams; split '
     'on source before retry'),
)


def classify_skip(notes):
    """Return (category, suggested_action) for a SKIP `notes` string.

    Falls back to ('unknown', '') when no pattern matches — caller
    should treat unknowns as potential bugs and surface them.
    """
    low = (notes or '').lower()
    for marker, category, action in _BUG_PATTERNS:
        if marker in low:
            return category, action
    return 'unknown', ''


def audit_structure_results(csv_path):
    """Read `structure_results.csv` and return a list of dicts:

        {'category', 'name', 'action', 'status', 'notes',
         'audit_category', 'audit_action'}

    Only SKIPPED rows are classified; PASS/FAILED rows pass through
    with audit_category='' (they aren't SKIPs by definition).
    """
    out = []
    if not csv_path or not os.path.isfile(csv_path):
        return out
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            entry = dict(row)
            if (row.get('status') or '').upper() == 'SKIPPED':
                category, action = classify_skip(row.get('notes', ''))
                entry['audit_category'] = category
                entry['audit_action'] = action
            else:
                entry['audit_category'] = ''
                entry['audit_action'] = ''
            out.append(entry)
    return out


def summarize_audit(rows):
    """Return {category: count} across SKIP rows in `rows`."""
    counts = {c: 0 for c in CATEGORIES}
    for r in rows:
        c = r.get('audit_category')
        if not c:
            continue
        counts[c] = counts.get(c, 0) + 1
    counts['total_skipped'] = sum(v for k, v in counts.items()
                                   if k != 'total_skipped')
    return counts


def write_audit_csv(rows, out_path):
    """Persist the audited rows to `out_path` as CSV with the original
    columns plus `audit_category` + `audit_action`. Returns the
    summary counts dict."""
    fieldnames = ['category', 'name', 'action', 'status', 'notes',
                  'audit_category', 'audit_action']
    with open(out_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, '') for k in fieldnames})
    os.chmod(out_path, 0o600)
    return summarize_audit(rows)
