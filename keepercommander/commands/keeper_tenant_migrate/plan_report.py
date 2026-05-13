"""Customer-friendly migration plan report (markdown + JSON mirror).

Combines the operator's recommendations from `plan` (inventory),
`nested-sf-plan` (subfolder decisions), and `estimate` (sizing /
throttle tier) into a single mid-technical-admin report. The audience
is an enterprise admin who can read tables and YAML but is NOT a CLI
power user — they need to email this to a CISO, paper-print it, and
edit a small overrides.yaml file before authorising the migration.

Output contract (T1.7):

    migration-plan.md    — human-readable, 0644 (no secrets)
    migration-plan.json  — machine-readable mirror, 0644

The JSON mirror is consumed by `overrides.py` (T2) for override-key
validation. Both files are pure functions of the three input JSONs.
This module performs NO live tenant access — it is strictly read-only
against on-disk artifacts produced by earlier subcommands.
"""

import datetime
import json
import os


# ── Section headings (kept short — enterprise admin scans the TOC) ─────

H_TITLE = '# Migration plan'
H_SUMMARY = '## Summary'
H_DECISIONS = '## Decisions awaiting your review'
H_DEFAULTS = '## Defaults applied (no action needed)'
H_PHASES = '## What this migration will do'
H_NOT_TOUCH = '## What this migration will NOT touch'
H_SIGNOFF = '## Sign-off'
H_OVERRIDES = '## Override syntax cheat sheet'


# ── Action / policy → plain-language label ────────────────────────────

_ACTION_LABEL = {
    'preserve-subfolder':
        'keep as subfolder under parent (inherit parent permissions)',
    'promote-to-sibling':
        'create a new top-level shared folder named "Parent - Child"',
    'promote-to-true-nested':
        'create a true nested shared folder (NOT supported by current Commander)',
    'flatten-with-prefix':
        'create a flat top-level shared folder named "Parent__Child"',
    'needs-review':
        'parent folder data missing — operator must edit plan JSON',
}

_CONFLICT_LABEL = {
    'error':       'fail and surface the collision (operator resolves)',
    'suffix':      'append " (2)", " (3)" until the name is unique',
    'merge':       'reuse the existing target folder (membership unioned)',
}


# ── Bucketing thresholds ──────────────────────────────────────────────

_DIVERGENT_ACTIONS = {
    'promote-to-sibling',
    'promote-to-true-nested',
    'flatten-with-prefix',
    'needs-review',
}


# ── Utilities ─────────────────────────────────────────────────────────


def _load_json(path):
    """Return parsed JSON or None on missing/invalid file."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _utc_now_str():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')


def _safe_get(d, *keys, default=None):
    """Walk nested keys, return default if any link is missing."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _alternatives_for_action(chosen, supports_true_nested):
    """Return the override-friendly alternatives (chosen excluded)."""
    base = ['preserve-subfolder', 'promote-to-sibling',
            'flatten-with-prefix', 'needs-review']
    if supports_true_nested:
        base.append('promote-to-true-nested')
    return [a for a in base if a != chosen]


def _row_for_decision(idx, decision, supports_true_nested):
    """Render one decision as a markdown table row."""
    sub_path = decision.get('subfolder_path') or decision.get('subfolder_name', '?')
    reason = decision.get('reason', '') or ''
    action = decision.get('proposed_target_action', 'needs-review')
    label = _ACTION_LABEL.get(action, action)
    alternatives = ', '.join(_alternatives_for_action(action, supports_true_nested))
    uid = decision.get('subfolder_uid', '')
    override_key = f'`subfolders.{uid}`' if uid else '_(no UID)_'
    what = f'`{sub_path}` — {reason}' if reason else f'`{sub_path}`'
    return f'| {idx} | {what} | {label} | {alternatives} | {override_key} |'


def _conflict_row(idx, decision):
    """Render one conflict-policy row for the decisions table."""
    sub_path = decision.get('subfolder_path') or decision.get('subfolder_name', '?')
    proposed = decision.get('proposed_promoted_name', '') or sub_path
    policy = decision.get('conflict_resolution', 'error')
    label = _CONFLICT_LABEL.get(policy, policy)
    alternatives = ', '.join(p for p in ('error', 'suffix', 'merge') if p != policy)
    uid = decision.get('subfolder_uid', '')
    override_key = f'`conflicts.{uid}`' if uid else '_(no UID)_'
    return (f'| {idx} | name `{proposed}` collides with an existing '
            f'top-level SF | {label} | {alternatives} | {override_key} |')


# ── Section renderers ─────────────────────────────────────────────────


def _render_header(inventory, estimate, plan_meta):
    """Top-of-report identity block."""
    src_user = _safe_get(inventory, 'source_user', default='') or ''
    src_root = _safe_get(inventory, 'source_root', default='') or ''
    scope_node = _safe_get(inventory, 'scope_node', default='') or ''
    prefix = _safe_get(inventory, 'prefix_filter', default='') or ''
    tier_label = _safe_get(estimate, 'throttle', 'tier', default='unknown')
    delay = _safe_get(estimate, 'throttle', 'delay', default=0)
    batch = _safe_get(estimate, 'throttle', 'batch_size', default=0)
    duration = _safe_get(estimate, 'totals', 'duration_human', default='unknown')
    total_calls = _safe_get(estimate, 'totals', 'calls', default=0)

    src_id = f'{src_user} ({src_root})' if src_root else src_user or '_unknown_'
    scope_part = f'{scope_node} / prefix `{prefix}`' if prefix \
        else (scope_node or '_full tenant_')

    lines = [H_TITLE, '']
    lines.append(f'**Generated**: {_utc_now_str()}')
    lines.append(f'**Source tenant**: {src_id}')
    lines.append(f'**Scope**: {scope_part}')
    lines.append(f'**Throttle tier**: {tier_label} '
                 f'(`--delay={delay} --batch-size={batch}`)')
    lines.append(f'**Estimated runtime**: {duration} '
                 f'({total_calls:,} API calls)')
    if plan_meta.get('commander_supports_true_nested_sf') is False:
        lines.append('**Commander capability**: true-nested SFs '
                     '**NOT supported** in this Commander version '
                     '(`promote-to-true-nested` is greyed out)')
    elif plan_meta.get('commander_supports_true_nested_sf') is True:
        lines.append('**Commander capability**: true-nested SFs supported')
    lines.append('')
    return lines


def _render_summary(inventory, plan_meta, decisions, conflicts):
    """Summary section — one-paragraph TL;DR + bullet counts."""
    counts = _safe_get(inventory, 'counts', default={}) or {}

    lines = [H_SUMMARY, '']
    if counts:
        bits = [
            f'{counts.get("nodes", 0):,} nodes',
            f'{counts.get("teams", 0):,} teams',
            f'{counts.get("roles", 0):,} roles',
            f'{counts.get("users", 0):,} users',
            f'{counts.get("shared_folders", 0):,} shared folders',
            f'{counts.get("records", 0):,} records',
        ]
        lines.append('You are about to recreate ' + ' / '.join(bits)
                     + ' on the target tenant.')
    else:
        lines.append('Inventory data missing — counts unavailable.')
    lines.append('')

    total_subs = len(plan_meta.get('decisions') or [])
    inherit_count = sum(1 for d in plan_meta.get('decisions') or []
                         if d.get('proposed_target_action') == 'preserve-subfolder')
    review_count = len(decisions)
    conflict_count = len(conflicts)

    lines.append(f'- **{inherit_count}** of **{total_subs}** subfolders '
                 f'inherit from their parent (safe default — no decision '
                 f'needed)')
    lines.append(f'- **{review_count}** subfolder decisions need your '
                 f'review')
    lines.append(f'- **{conflict_count}** name conflicts need a resolution '
                 f'policy')
    lines.append('')
    return lines


def _render_decisions(decisions, conflicts, supports_true_nested):
    """The headline 'fix me first' section."""
    lines = [H_DECISIONS, '']
    if not decisions and not conflicts:
        lines.append('_No decisions need review — every subfolder uses the '
                     'safe default and no name conflicts were detected._')
        lines.append('')
        return lines
    lines.append('Each row below is the operator\'s recommendation. To '
                 'override, edit the `overrides.yaml` file and use the key '
                 'in the rightmost column.')
    lines.append('')
    lines.append('| # | What | Operator recommends | Alternatives | Override key |')
    lines.append('|---|------|---------------------|--------------|--------------|')
    idx = 1
    for d in decisions:
        lines.append(_row_for_decision(idx, d, supports_true_nested))
        idx += 1
    for d in conflicts:
        lines.append(_conflict_row(idx, d))
        idx += 1
    lines.append('')
    return lines


def _render_defaults(plan_meta):
    """Collapsible bucket of the safe-default rows — count only."""
    lines = [H_DEFAULTS, '']
    decisions = plan_meta.get('decisions') or []
    inherit = [d for d in decisions
               if d.get('proposed_target_action') == 'preserve-subfolder']
    if not decisions:
        lines.append('_No subfolders to bucket — tenant has no nested '
                     'shared folders._')
        lines.append('')
        return lines
    if not inherit:
        lines.append('_No defaults applied — every subfolder needs a '
                     'decision (see section above)._')
        lines.append('')
        return lines

    lines.append('<details><summary>'
                 f'{len(inherit)} subfolder(s) using the safe default '
                 '(`preserve-subfolder`) — click to expand'
                 '</summary>')
    lines.append('')
    lines.append('| Subfolder | Parent SF | Reason |')
    lines.append('|-----------|-----------|--------|')
    for d in inherit:
        path = d.get('subfolder_path') or d.get('subfolder_name', '?')
        parent = d.get('parent_sf_name', '') or '_(unresolved)_'
        reason = d.get('reason', '') or 'inherits parent'
        lines.append(f'| `{path}` | `{parent}` | {reason} |')
    lines.append('')
    lines.append('</details>')
    lines.append('')
    return lines


def _render_phases(inventory, estimate):
    """Per-phase plain-language summary."""
    lines = [H_PHASES, '']
    counts = _safe_get(inventory, 'counts', default={}) or {}
    if not counts:
        lines.append('_Counts unavailable — re-run `plan` to populate '
                     'the inventory._')
        lines.append('')
        return lines

    phases = [
        ('Step 1 — `pre-flight` (after roster prep)',
         'verify roster CSV, Commander version, disk, auth — '
         'requires `--roster <path-to-csv>` so this step is run '
         'AFTER the customer has prepared the user roster, not before'),
        ('Step 2 — `plan` (already done)',
         'capture source inventory'),
        ('Step 3 — `estimate` (already done)',
         f'size the run at the {_safe_get(estimate, "throttle", "tier", default="unknown")} tier'),
        ('Step 4 — `point-of-no-return`',
         'sign the checkpoint authorising destructive next steps'),
        ('Step 5 — `structure`',
         f'recreate {counts.get("nodes", 0):,} node(s), '
         f'{counts.get("teams", 0):,} team(s), '
         f'{counts.get("roles", 0):,} role(s) on target'),
        ('Step 6 — `users`',
         f'invite / place {counts.get("users", 0):,} user(s) on target'),
        ('Step 7 — `records-export` (source)',
         f'export {counts.get("records", 0):,} record(s) as JSON'),
        ('Step 8 — `convert`',
         'translate v3 export to Commander import format'),
        ('Step 9 — `records-import` (target)',
         f'import {counts.get("records", 0):,} record(s)'),
        # Bug 20/29 split records-shares into the cross-tenant two-
        # phase form. Bug 37 — plan-report still listed the old
        # single-session `records-shares` step which silently SKIPS
        # everything cross-tenant. Updated to match the actual
        # auto-migrate stage list and customer-facing CLI surface.
        ('Step 10 — `records-shares-extract` (source)',
         f'extract {counts.get("direct_shares", 0):,} direct record '
         'share(s) to a JSON manifest'),
        ('Step 11 — `records-shares-apply` (target)',
         f'replay {counts.get("direct_shares", 0):,} direct record '
         'share(s) from the manifest'),
        ('Step 12 — `records-attachments-download` (source)',
         f'pull {counts.get("attachments", 0):,} attachment(s) into staging'),
        ('Step 13 — `records-attachments-upload` (target)',
         f'push {counts.get("attachments", 0):,} attachment(s) onto target'),
        ('Step 14 — `verify`',
         'field-level diff against the frozen inventory'),
        ('Step 15 — `reconcile`',
         'source-vs-target delta report'),
    ]
    for label, desc in phases:
        lines.append(f'- **{label}**: {desc}')
    lines.append('')
    return lines


def _render_not_touch():
    """Rule 0 reminder — what stays untouched."""
    lines = [H_NOT_TOUCH, '']
    lines.append('- **Source tenant is read-only forever.** '
                 'No record, user, role, or folder is ever modified or '
                 'deleted on the source by this migration. The migration '
                 'tool enforces this in code (Rule 0).')
    lines.append('- **No data leaves your tenant boundary.** All transfer '
                 'happens between the two Commander sessions you have '
                 'authenticated. Nothing is uploaded to a third party.')
    lines.append('- **No source destruction without a separate command.** '
                 'Locking or deleting source users requires running '
                 '`tenant-migrate decommission` explicitly — never part '
                 'of the forward migration.')
    lines.append('')
    return lines


def _render_signoff(decisions, conflicts):
    """Checkbox list of what the user is approving."""
    lines = [H_SIGNOFF, '']
    lines.append('By running the migration after this report, you are '
                 'approving the following:')
    lines.append('')
    if decisions:
        lines.append('- [ ] I have reviewed the **'
                     f'{len(decisions)}** subfolder decision(s) listed '
                     'above and accept the operator\'s recommendation '
                     '(or have entered overrides in `overrides.yaml`).')
    if conflicts:
        lines.append('- [ ] I have reviewed the **'
                     f'{len(conflicts)}** name-conflict policy choice(s) '
                     'listed above.')
    lines.append('- [ ] I accept the estimated runtime and throttle tier '
                 'shown in the Summary.')
    lines.append('- [ ] I confirm the source tenant is read-only and no '
                 'live data will be modified on the source side.')
    lines.append('- [ ] I have a current backup or am running this against '
                 'a disposable target tenant.')
    lines.append('')
    return lines


def _render_overrides_cheatsheet():
    """Short YAML examples — covers the 3 kinds of override."""
    lines = [H_OVERRIDES, '']
    lines.append('Create `overrides.yaml` next to this report to change '
                 'any of the operator\'s recommendations:')
    lines.append('')
    lines.append('```yaml')
    lines.append('# Override per-subfolder action — keys come from the')
    lines.append('# "Override key" column in the Decisions table above.')
    lines.append('subfolders:')
    lines.append('  AbCdEf123: preserve-subfolder    # keep as subfolder')
    lines.append('  GhIjKl456: flatten-with-prefix   # legacy target')
    lines.append('')
    lines.append('# Override conflict resolution policy.')
    lines.append('conflicts:')
    lines.append('  AbCdEf123: suffix                # auto-suffix on collision')
    lines.append('')
    lines.append('# (Tier override requires the explicit --accept-risk flag')
    lines.append('# on the consuming subcommand. Operators rarely need this.)')
    lines.append('# tier:')
    lines.append('#   delay: 1.5')
    lines.append('#   batch_size: 25')
    lines.append('')
    lines.append('# Free-text note attached to every override (audit trail).')
    lines.append('notes:')
    lines.append('  AbCdEf123: "CISO requested per-folder isolation"')
    lines.append('```')
    lines.append('')
    lines.append('Then run the next step with `--overrides overrides.yaml`. '
                 'Validation errors are reported with the exact line + key '
                 'before any tenant operation runs.')
    lines.append('')
    return lines


# ── Decision extraction (the meat of the report) ──────────────────────


def _split_decisions(plan_meta):
    """Return (review, conflicts) lists ready for the table renderers.

    `review` carries every subfolder whose recommended action diverges
    from the safe default (preserve-subfolder). `conflicts` are the
    rows whose conflict_resolution is anything other than the default
    'error' policy — surfaced separately because they're a different
    kind of decision (not 'what shape', but 'how to react to a clash').
    """
    decisions = plan_meta.get('decisions') or []
    review = [d for d in decisions
              if d.get('proposed_target_action') in _DIVERGENT_ACTIONS]
    conflicts = [d for d in decisions
                 if d.get('conflict_resolution')
                 and d.get('conflict_resolution') != 'error']
    return review, conflicts


# ── Public renderer + writer ──────────────────────────────────────────


def render_migration_plan(inventory_path='', nested_sf_plan_path='',
                           estimate_path=''):
    """Return the full markdown report string.

    All three paths are optional individually — the report degrades
    gracefully when any input is missing (with a one-line note in the
    affected section). At least one input path must be provided; the
    caller is expected to enforce that, but this function still returns
    a coherent (mostly-empty) report when none are given.
    """
    inventory = _load_json(inventory_path) or {}
    plan_meta = _load_json(nested_sf_plan_path) or {}
    estimate = _load_json(estimate_path) or {}

    decisions, conflicts = _split_decisions(plan_meta)
    supports_true_nested = bool(
        plan_meta.get('commander_supports_true_nested_sf'))

    parts = []
    parts.extend(_render_header(inventory, estimate, plan_meta))
    parts.append('---')
    parts.append('')
    parts.extend(_render_summary(inventory, plan_meta, decisions, conflicts))
    parts.extend(_render_decisions(decisions, conflicts, supports_true_nested))
    parts.extend(_render_defaults(plan_meta))
    parts.extend(_render_phases(inventory, estimate))
    parts.extend(_render_not_touch())
    parts.extend(_render_signoff(decisions, conflicts))
    parts.extend(_render_overrides_cheatsheet())

    return '\n'.join(parts)


def build_machine_mirror(inventory_path='', nested_sf_plan_path='',
                          estimate_path=''):
    """Return a JSON-serialisable dict mirroring the markdown report.

    Consumed by `overrides.py` (T2) to validate override keys against
    the universe of actually-decidable rows. Schema is intentionally
    flat:

        {
          "generated_at": "2026-04-26T14:23:00Z",
          "inputs": {
            "inventory":      <path or "">,
            "nested_sf_plan": <path or "">,
            "estimate":       <path or "">
          },
          "summary": {
            "counts":   {...inventory counts...},
            "throttle": {...estimate throttle...},
            "totals":   {...estimate totals...}
          },
          "commander_supports_true_nested_sf": bool,
          "decisions": [           # divergent subfolders only
            {"override_key": "subfolders.<uid>",
             "subfolder_uid": "...", "subfolder_path": "...",
             "operator_recommends": "<action>",
             "alternatives": [...],
             "reason": "..."},
            ...
          ],
          "conflicts": [           # non-'error' conflict policies
            {"override_key": "conflicts.<uid>",
             "subfolder_uid": "...", "subfolder_path": "...",
             "operator_recommends": "<policy>",
             "alternatives": [...]},
            ...
          ],
          "defaults_bucket": {     # the 90% no-decision items
            "preserve-subfolder": <count>
          }
        }
    """
    inventory = _load_json(inventory_path) or {}
    plan_meta = _load_json(nested_sf_plan_path) or {}
    estimate = _load_json(estimate_path) or {}

    decisions, conflicts = _split_decisions(plan_meta)
    supports_true_nested = bool(
        plan_meta.get('commander_supports_true_nested_sf'))

    decision_rows = []
    for d in decisions:
        action = d.get('proposed_target_action', 'needs-review')
        decision_rows.append({
            'override_key': f'subfolders.{d.get("subfolder_uid", "")}',
            'subfolder_uid': d.get('subfolder_uid', ''),
            'subfolder_path': d.get('subfolder_path')
                              or d.get('subfolder_name', ''),
            'parent_sf_name': d.get('parent_sf_name', ''),
            'proposed_target_action': action,
            'operator_recommends': action,
            'alternatives': _alternatives_for_action(action,
                                                      supports_true_nested),
            'reason': d.get('reason', ''),
        })

    conflict_rows = []
    for d in conflicts:
        policy = d.get('conflict_resolution', 'error')
        conflict_rows.append({
            'override_key': f'conflicts.{d.get("subfolder_uid", "")}',
            'subfolder_uid': d.get('subfolder_uid', ''),
            'subfolder_path': d.get('subfolder_path')
                              or d.get('subfolder_name', ''),
            'proposed_promoted_name': d.get('proposed_promoted_name', ''),
            'conflict_resolution': policy,
            'operator_recommends': policy,
            'alternatives': [p for p in ('error', 'suffix', 'merge')
                             if p != policy],
        })

    inherit_count = sum(1 for d in plan_meta.get('decisions') or []
                         if d.get('proposed_target_action') == 'preserve-subfolder')

    return {
        'generated_at': datetime.datetime.utcnow().strftime(
            '%Y-%m-%dT%H:%M:%SZ'),
        'inputs': {
            'inventory': inventory_path or '',
            'nested_sf_plan': nested_sf_plan_path or '',
            'estimate': estimate_path or '',
        },
        'summary': {
            'source_user': inventory.get('source_user', ''),
            'source_root': inventory.get('source_root', ''),
            'scope_node': inventory.get('scope_node', ''),
            'prefix_filter': inventory.get('prefix_filter', ''),
            'counts': dict(inventory.get('counts') or {}),
            'throttle': dict(estimate.get('throttle') or {}),
            'totals': dict(estimate.get('totals') or {}),
        },
        'commander_supports_true_nested_sf': supports_true_nested,
        'tier': dict(estimate.get('throttle') or {}),
        'decisions': decision_rows,
        'conflicts': conflict_rows,
        'defaults_bucket': {
            'preserve-subfolder': inherit_count,
        },
    }


def write_report(output_path, *, inventory_path='', nested_sf_plan_path='',
                  estimate_path=''):
    """Write `migration-plan.md` + companion `migration-plan.json`.

    `output_path` is the markdown path. The JSON sits next to it with
    the suffix swapped (foo.md → foo.json). Both are 0644 by design —
    the report is intentionally world-readable so admins can email it
    or share it with a CISO. No secrets land in either file.

    Returns (md_path, json_path).
    """
    if not (inventory_path or nested_sf_plan_path or estimate_path):
        raise ValueError(
            'plan-report needs at least one of --inventory, '
            '--nested-sf-plan, or --estimate.'
        )

    md = render_migration_plan(
        inventory_path=inventory_path,
        nested_sf_plan_path=nested_sf_plan_path,
        estimate_path=estimate_path,
    )
    mirror = build_machine_mirror(
        inventory_path=inventory_path,
        nested_sf_plan_path=nested_sf_plan_path,
        estimate_path=estimate_path,
    )

    with open(output_path, 'w') as f:
        f.write(md)
    os.chmod(output_path, 0o644)

    json_path = _companion_json_path(output_path)
    with open(json_path, 'w') as f:
        json.dump(mirror, f, indent=2)
    os.chmod(json_path, 0o644)
    return output_path, json_path


def _companion_json_path(md_path):
    """Foo/bar.md → Foo/bar.json. Anything else → <path>.json."""
    base, ext = os.path.splitext(md_path)
    if ext.lower() == '.md':
        return base + '.json'
    return md_path + '.json'
