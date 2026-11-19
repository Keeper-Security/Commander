#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Text and JSON output of `pam project update` (plan, "Output format").

Pure functions of an ``UpdatePlan``. A secret or a note is NEVER printed: ``Change.shown()`` already gives
``<hidden>`` for them, and everything below prints only what it returns.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .update_diff import KIND_GRAPH, KIND_RECORD, OP_REMOVE
from .update_plan import ItemResult, UpdatePlan

BRIEF_ROW_LIMIT = 50
TIP = 'Tip: add -v / --verbose for the field-by-field report (identical records included).'


def _short(value: Any, limit: int = 60) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return text if len(text) <= limit else text[:limit - 3] + '...'


def _change_line(change) -> str:
    old, new = change.shown()
    label = 'record' if change.kind == KIND_RECORD else 'graph '
    if change.op == '+':
        body = f'{change.path}: {_short(new)}'
    elif change.op == OP_REMOVE:
        body = f'{change.path}: {_short(old)} (removed)'
    else:
        body = f'{change.path}: {_short(old)} -> {_short(new)}'
    note = f'  [{change.note}]' if change.note else ''
    return f'    {label}  {change.op} {body}{note}'


def password_summary(plan: UpdatePlan) -> List[str]:
    """The password lines of the plan, confirmation and summary (see "--include-passwords")."""
    if plan.include_passwords:
        rotating = plan.passwords_on_rotating
        return [f'WARNING: --include-passwords IS ON - {plan.passwords_to_write} PASSWORD(S) WILL BE REPLACED WITH '
                f'THE VALUES FROM THE JSON ({rotating} OF THEM ON USERS WITH ROTATION ENABLED)']
    if plan.passwords_skipped:
        return [f'{plan.passwords_skipped} password(s) in the JSON differ from the vault and were skipped '
                '(rotation may have changed them); use --include-passwords to replace them.']
    return []


def summary_line(plan: UpdatePlan) -> str:
    total = len(plan.compared)
    changed = len(plan.changed)
    return (f'{changed} of {total} records would change (record {plan.record_changes}, graph {plan.graph_changes}); '
            f'{total - changed} identical.')


def estimate_line(plan: UpdatePlan) -> str:
    total = len(plan.compared)
    changed = len(plan.changed)
    return (f'{changed} of {total} records differ and need updating; {total - changed} identical; '
            f'Not in the JSON: {len(plan.not_in_json)}.')


def _table(rows: List[ItemResult]) -> List[str]:
    width = max([len(r.title) for r in rows] + [len('Record')]) + 2
    type_width = max([len(r.record_type) for r in rows] + [len('Type')]) + 2
    lines = [f'{"Record":<{width + 2}}{"Type":<{type_width}}{"Record":>7}{"Graph":>7}']
    for r in rows:
        lines.append(f'~ {r.title:<{width}}{r.record_type:<{type_width}}{r.record_changes:>7}{r.graph_changes:>7}')
    return lines


def format_text(plan: UpdatePlan, *, verbose: bool = False, brief_tip: bool = True) -> str:
    """The report of a plan (errors, warnings and the diff). Used for ``-d`` and for the plan before the prompt."""
    lines: List[str] = []
    if plan.errors:
        lines.append(f'{len(plan.errors)} error(s) - nothing would be written:')
        lines.extend(f'  ERROR: {e}' for e in plan.errors)
    if verbose:
        for r in plan.results:
            if r.differs:
                lines.append(f'~ {r.title}  ({r.record_type}, uid {r.uid})')
                lines.extend(_change_line(c) for c in r.changes)
            elif not r.compared:
                lines.append(f'! {r.title}  (not compared)')
            else:
                lines.append(f'= {r.title}  (identical)')
            lines.extend(f'    ! {w}' for w in r.warnings)
    else:
        changed = plan.changed
        if changed:
            lines.extend(_table(changed[:BRIEF_ROW_LIMIT]))
            if len(changed) > BRIEF_ROW_LIMIT:
                lines.append(f'... and {len(changed) - BRIEF_ROW_LIMIT} more (use --format json for all)')
        lines.extend(f'WARNING: {w}' for w in plan.warnings)
    if verbose:
        per_record = {w for r in plan.results for w in r.warnings}
        lines.extend(f'WARNING: {w}' for w in plan.warnings if w not in per_record)
    if plan.results:
        lines.append(summary_line(plan))
    if plan.not_in_json:
        lines.append(f'Not in the JSON (kept as is): {len(plan.not_in_json)}.')
        if verbose:
            lines.extend(f'  {uid}  {title}  ({rtype})' for uid, title, rtype in plan.not_in_json)
    lines.extend(password_summary(plan))
    if not verbose and brief_tip and plan.results:
        lines.append(TIP)
    return '\n'.join(lines)


def to_dict(plan: UpdatePlan, *, verbose: bool = False, estimate: bool = False) -> Dict[str, Any]:
    """The ``--format json`` result: ``{summary, changes[], skipped[], errors[], warnings[]}``."""
    total = len(plan.compared)
    summary = {
        'mode': plan.mode,
        'records': total,
        'changed': len(plan.changed),
        'identical': total - len(plan.changed),
        'record_changes': plan.record_changes,
        'graph_changes': plan.graph_changes,
        'not_in_json': len(plan.not_in_json),
        'passwords_skipped': plan.passwords_skipped,
        'passwords_to_write': plan.passwords_to_write,
        'passwords_to_write_on_rotating_users': plan.passwords_on_rotating,
        'include_passwords': plan.include_passwords,
        'errors': len(plan.errors),
    }
    out: Dict[str, Any] = {'summary': summary, 'errors': list(plan.errors), 'warnings': list(plan.warnings)}
    if estimate:
        return out
    changes = []
    for r in plan.results:
        if not r.differs and not verbose:
            continue
        entry: Dict[str, Any] = {'record_title': r.title, 'uid': r.uid, 'type': r.record_type,
                                 'record_changes': r.record_changes, 'graph_changes': r.graph_changes}
        if verbose:
            details = []
            for c in r.changes:
                old, new = c.shown()
                details.append({'kind': c.kind, 'op': c.op, 'path': c.path, 'old': old, 'new': new,
                                **({'note': c.note} if c.note else {})})
            entry['details'] = details
        changes.append(entry)
    out['changes'] = changes
    out['skipped'] = [{'uid': uid, 'title': title, 'type': rtype, 'reason': 'not in the JSON'}
                      for uid, title, rtype in plan.not_in_json]
    return out
