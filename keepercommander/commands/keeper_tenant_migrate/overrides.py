"""User-supplied overrides on the operator's migration plan.

Squad-3 round 1 / T2: closes the operator-vs-customer UX gap. The
operator runs `nested-sf-plan` (and round 1's T1 `plan-report`)
producing a JSON plan + a markdown report. The customer reviews the
markdown report, drafts a small YAML overrides file, then runs
`tenant-migrate structure --overrides <path>` to apply their choices
on top of the operator's defaults.

Schema doc: `.context/overrides-schema.md`. Keep that file in sync
with the validation rules in this module.

Invariants
----------
- `apply_overrides(plan, overrides)` returns a NEW dict; the input
  plan is never mutated. The audit trail depends on knowing the
  original (Rule 0 spirit applies even to in-memory plans).
- Validation FAILS LOUDLY: every typo / unknown UID / invalid enum
  raises `OverridesValidationError` with a friendly, actionable
  message. No silent skipping.
- The module is read-only against the source tenant: it manipulates
  in-memory plan dicts only, never calls Commander.

T1 contract (round 1)
---------------------
T2 reads any plan dict exposing:

    plan = {
        'decisions': [{'subfolder_uid': ..., 'proposed_target_action':
                       ..., 'conflict_resolution': ...}, ...],
        'commander_supports_true_nested_sf': bool,
        'tier': str,
    }

T1's `migration-plan.json` is expected to mirror that shape. Any
schema drift between T1 and T2 is resolved at the integration step
(per squad-3-plan §3.3 Step 4). `validate_overrides` is written
defensively against missing keys so T1's merge is straight-line.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .nested_sf_plan import (
    ACTION_PRESERVE,
    ALL_ACTIONS,
    ALL_CONFLICT_POLICIES,
    ACTION_FLATTEN,
    ACTION_PROMOTE,
    ACTION_TRUE_NESTED,
    CONFLICT_MERGE,
    _normalize_action,
)


# ─── Tier enum (mirrors estimate.SCALE_TIERS labels in flat form) ───────────

TIER_SMALL = 'small'
TIER_MEDIUM = 'medium'
TIER_LARGE = 'large'
TIER_XLARGE = 'xlarge'
TIER_AUTO = 'auto'

ALL_TIERS = (TIER_SMALL, TIER_MEDIUM, TIER_LARGE, TIER_XLARGE, TIER_AUTO)


# Conflict policies that imply an existing target SF the user might want
# to merge with. `preserve-subfolder` lives inside the parent SF, so
# `merge` is meaningless.
ACTIONS_THAT_ALLOW_MERGE = (
    ACTION_PROMOTE,
    ACTION_TRUE_NESTED,
    ACTION_FLATTEN,
)


class OverridesValidationError(Exception):
    """Raised when the overrides file is structurally or semantically wrong.

    Carries a list of friendly, actionable error strings (NOT python
    tracebacks). Callers print them line-by-line.
    """

    def __init__(self, errors: List[str]):
        self.errors = list(errors)
        super().__init__('\n'.join(self.errors) or 'overrides validation failed')


# ─── Loading ───────────────────────────────────────────────────────────────

def _safe_load_yaml_or_json(text: str):
    """Best-effort parse: prefer YAML when PyYAML is present, fall back to JSON.

    Returns the parsed object (typically a dict), `None` for explicit
    `null` / empty input, or raises `ValueError` (incl. yaml.YAMLError /
    json.JSONDecodeError) on malformed input. Caller decides what to do
    with non-dict shapes.
    """
    if not text or not text.strip():
        return None
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


def load_overrides(path: str) -> Dict[str, Any]:
    """Read an overrides file (YAML or JSON) and return the raw mapping.

    Returns `{}` for an empty / missing file (caller decides whether
    that's an error). Raises `OverridesValidationError` on malformed
    YAML/JSON or on a non-mapping top-level value, with a friendly
    message that points at the file path.
    """
    if not path:
        raise OverridesValidationError(['no overrides path supplied'])
    if not os.path.isfile(path):
        raise OverridesValidationError(
            [f'overrides file not found: {path}'])
    try:
        with open(path) as f:
            text = f.read()
    except OSError as e:
        raise OverridesValidationError(
            [f'overrides file unreadable: {path} ({e})']) from e
    try:
        data = _safe_load_yaml_or_json(text)
    except Exception as e:
        # PyYAML raises yaml.YAMLError (NOT a ValueError subclass);
        # JSON fallback raises json.JSONDecodeError (subclass of
        # ValueError). Cover both with a friendly wrapper so the user
        # sees an actionable line, not a parser traceback.
        raise OverridesValidationError(
            [f'overrides file is not valid YAML/JSON: {path} ({e})']) from e

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise OverridesValidationError(
            [f'overrides file top-level must be a mapping (got '
             f'{type(data).__name__}): {path}'])
    return data


# ─── Validation ────────────────────────────────────────────────────────────

def _plan_subfolder_uids(plan: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """{subfolder_uid: decision_dict} from a plan; resilient to missing keys."""
    out: Dict[str, Dict[str, Any]] = {}
    for d in (plan or {}).get('decisions') or []:
        uid = d.get('subfolder_uid', '') if isinstance(d, dict) else ''
        if uid:
            out[uid] = d
    return out


def _close_match(uid: str, candidates: Iterable[str]) -> Optional[str]:
    """Return the closest UID in `candidates` (prefix-or-suffix match).

    Cheap heuristic — Commander UIDs are 22-char base64; difflib would
    work but is overkill. Callers guarantee `uid` is a non-empty string;
    returns None when no candidate is a sensible near-miss.
    """
    for c in candidates:
        if c.startswith(uid) or uid.startswith(c):
            return c
        if c.endswith(uid) or uid.endswith(c):
            return c
    return None


def _format_valid(values: Iterable[str]) -> str:
    return ', '.join(sorted(values))


def _block(value: Any, *, key: str, errors: List[str]) -> Dict[str, Any]:
    """Coerce a top-level block into a dict; record an error on type mismatch."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        errors.append(
            f'overrides.{key} must be a mapping (got '
            f'{type(value).__name__})')
        return {}
    return value


def _validate_subfolders(overrides: Dict[str, Any], plan: Dict[str, Any],
                          errors: List[str]) -> None:
    block = _block(overrides.get('subfolders'), key='subfolders',
                    errors=errors)
    if not block:
        return
    plan_uids = _plan_subfolder_uids(plan)
    supports_true_nested = bool(plan.get('commander_supports_true_nested_sf'))
    valid_actions = set(ALL_ACTIONS)

    for uid, raw_action in block.items():
        if not isinstance(uid, str) or not uid:
            errors.append(
                f'overrides.subfolders has a non-string key: {uid!r}')
            continue
        if not isinstance(raw_action, str):
            errors.append(
                f'override `subfolders.{uid}: {raw_action!r}` is not a '
                f'string; valid: {_format_valid(valid_actions)}')
            continue
        action = _normalize_action(raw_action)
        if action not in valid_actions:
            errors.append(
                f'override `subfolders.{uid}: {raw_action}` is invalid; '
                f'valid: {_format_valid(valid_actions)}')
            continue
        if uid not in plan_uids:
            hint = _close_match(uid, plan_uids.keys())
            tip = (f' did you mean {hint!r}?' if hint
                    else ' (no subfolder with this UID in the plan)')
            errors.append(
                f'override `subfolders.{uid}` references an unknown UID;'
                f'{tip}')
            continue
        if (action == ACTION_TRUE_NESTED and not supports_true_nested):
            errors.append(
                f'override `subfolders.{uid}: promote-to-true-nested` '
                f'requires Commander true-nested SF support, but the '
                f'plan was generated with `commander_supports_true_'
                f'nested_sf=False`. Use `promote-to-sibling` instead, '
                f'or regenerate the plan against a Commander version '
                f'that supports true-nested SFs.')


def _effective_action(plan_decision: Dict[str, Any],
                      override_action: Optional[str]) -> str:
    """Action that will actually run: override wins over plan default."""
    if override_action:
        return _normalize_action(override_action)
    return _normalize_action(
        (plan_decision or {}).get('proposed_target_action')
        or ACTION_PRESERVE)


def _validate_conflicts(overrides: Dict[str, Any], plan: Dict[str, Any],
                         errors: List[str]) -> None:
    block = _block(overrides.get('conflicts'), key='conflicts',
                    errors=errors)
    if not block:
        return
    plan_uids = _plan_subfolder_uids(plan)
    sub_block = overrides.get('subfolders') or {}
    if not isinstance(sub_block, dict):
        sub_block = {}
    valid_policies = set(ALL_CONFLICT_POLICIES)

    for uid, raw_policy in block.items():
        if not isinstance(uid, str) or not uid:
            errors.append(
                f'overrides.conflicts has a non-string key: {uid!r}')
            continue
        if not isinstance(raw_policy, str):
            errors.append(
                f'override `conflicts.{uid}: {raw_policy!r}` is not a '
                f'string; valid: {_format_valid(valid_policies)}')
            continue
        if raw_policy not in valid_policies:
            errors.append(
                f'override `conflicts.{uid}: {raw_policy}` is invalid; '
                f'valid: {_format_valid(valid_policies)}')
            continue
        if uid not in plan_uids:
            hint = _close_match(uid, plan_uids.keys())
            tip = (f' did you mean {hint!r}?' if hint
                    else ' (no subfolder with this UID in the plan)')
            errors.append(
                f'override `conflicts.{uid}` references an unknown UID;'
                f'{tip}')
            continue
        if raw_policy == CONFLICT_MERGE:
            action = _effective_action(plan_uids.get(uid),
                                        sub_block.get(uid))
            if action not in ACTIONS_THAT_ALLOW_MERGE:
                errors.append(
                    f'override `conflicts.{uid}: merge` is invalid '
                    f'when the effective action is `{action}`; '
                    f'`merge` is only valid for: '
                    f'{_format_valid(ACTIONS_THAT_ALLOW_MERGE)}. '
                    f'Either change the conflict policy to `error` '
                    f'or `suffix`, or override the subfolder action '
                    f'to one that creates a top-level SF.')


def _validate_tier(overrides: Dict[str, Any], *, accept_risk: bool,
                    plan: Dict[str, Any], errors: List[str]) -> None:
    raw = overrides.get('tier')
    if raw is None or raw == '':
        return
    if not isinstance(raw, str):
        errors.append(
            f'override `tier: {raw!r}` is not a string; valid: '
            f'{_format_valid(ALL_TIERS)}')
        return
    if raw not in ALL_TIERS:
        errors.append(
            f'override `tier: {raw}` is invalid; valid: '
            f'{_format_valid(ALL_TIERS)}')
        return
    if raw == TIER_AUTO:
        # `auto` is equivalent to omitting the key — no risk gate.
        return
    if not accept_risk:
        recommended = (plan or {}).get('tier') or '(unknown — plan does ' \
                                                  'not surface tier)'
        errors.append(
            f'override `tier: {raw}` is advisory + audit-only in this '
            f'release; the actual throttle is driven by --delay / '
            f'--batch-size at the CLI. It still requires the '
            f'`--accept-risk` flag on the structure invocation. The '
            f'operator recommended `{recommended}` based on tenant size; '
            f'tier under-sizing is the #1 cause of mid-migration throttle '
            f'failures. Pass `--accept-risk` if you understand the '
            f'trade-off.')


def _validate_notes(overrides: Dict[str, Any], errors: List[str]) -> None:
    block = _block(overrides.get('notes'), key='notes', errors=errors)
    if not block:
        return
    for uid, note in block.items():
        if not isinstance(uid, str) or not uid:
            errors.append(
                f'overrides.notes has a non-string key: {uid!r}')
            continue
        if not isinstance(note, str):
            errors.append(
                f'overrides.notes.{uid} must be a string '
                f'(got {type(note).__name__})')


_RECOGNISED_TOP_KEYS = ('subfolders', 'conflicts', 'tier', 'notes')


def _validate_top_level(overrides: Dict[str, Any],
                         errors: List[str]) -> None:
    for key in overrides.keys():
        if key not in _RECOGNISED_TOP_KEYS:
            errors.append(
                f'overrides.{key} is not a recognised top-level key; '
                f'valid: {_format_valid(_RECOGNISED_TOP_KEYS)}')


def validate_overrides(overrides: Dict[str, Any], plan: Dict[str, Any], *,
                        accept_risk: bool = False) -> List[str]:
    """Return a (possibly empty) list of friendly error strings.

    Empty list = the overrides are valid against `plan`. Each entry is
    one error; the caller prints them line-by-line. The function never
    raises — it's pure analysis. Use `OverridesValidationError(errors)`
    to escalate to an exception when the caller wants fail-fast.
    """
    errors: List[str] = []
    if not isinstance(overrides, dict):
        errors.append(
            f'overrides must be a mapping (got '
            f'{type(overrides).__name__})')
        return errors
    _validate_top_level(overrides, errors)
    _validate_subfolders(overrides, plan or {}, errors)
    _validate_conflicts(overrides, plan or {}, errors)
    _validate_tier(overrides, accept_risk=accept_risk,
                    plan=plan or {}, errors=errors)
    _validate_notes(overrides, errors)
    return errors


# ─── Application ───────────────────────────────────────────────────────────


def _deepcopy_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """JSON round-trip = cheap, complete decoupling from the input."""
    return json.loads(json.dumps(plan or {}))


def apply_overrides(plan: Dict[str, Any],
                    overrides: Dict[str, Any]) -> Tuple[Dict[str, Any],
                                                          List[Dict[str, Any]]]:
    """Return (new_plan, audit_entries) — never mutates `plan`.

    `audit_entries` is the list of every applied override in the
    order they were applied, suitable for feeding into
    `audit.append_audit_event`. Each entry shape:

        {
          'kind': 'subfolder' | 'conflict' | 'tier',
          'uid':  '<uid-or-_global>',
          'before': '<original value>',
          'after':  '<new value>',
          'note':   '<user-supplied or empty>',
        }

    Skipped overrides (e.g., a `subfolders.<uid>` that already
    matches the plan's recommendation) are NOT audit entries — only
    the actual deltas land in the chain.
    """
    new_plan = _deepcopy_plan(plan)
    audit: List[Dict[str, Any]] = []
    if not overrides:
        return new_plan, audit

    notes_block = overrides.get('notes') or {}
    if not isinstance(notes_block, dict):
        notes_block = {}

    sub_block = overrides.get('subfolders') or {}
    if not isinstance(sub_block, dict):
        sub_block = {}
    conflict_block = overrides.get('conflicts') or {}
    if not isinstance(conflict_block, dict):
        conflict_block = {}

    decisions = new_plan.get('decisions') or []
    if isinstance(decisions, list):
        for decision in decisions:
            if not isinstance(decision, dict):
                continue
            uid = decision.get('subfolder_uid', '')
            if not uid:
                continue
            if uid in sub_block:
                new_action = _normalize_action(sub_block[uid])
                old_action = _normalize_action(
                    decision.get('proposed_target_action')
                    or ACTION_PRESERVE)
                if new_action != old_action:
                    decision['proposed_target_action'] = new_action
                    audit.append({
                        'kind': 'subfolder',
                        'uid': uid,
                        'before': old_action,
                        'after': new_action,
                        'note': str(notes_block.get(uid, '') or ''),
                    })
            if uid in conflict_block:
                new_pol = conflict_block[uid]
                old_pol = decision.get('conflict_resolution') or ''
                if new_pol != old_pol:
                    decision['conflict_resolution'] = new_pol
                    audit.append({
                        'kind': 'conflict',
                        'uid': uid,
                        'before': old_pol,
                        'after': new_pol,
                        'note': str(notes_block.get(uid, '') or ''),
                    })

    tier_value = overrides.get('tier')
    if isinstance(tier_value, str) and tier_value and tier_value != TIER_AUTO:
        old_tier = new_plan.get('tier') or ''
        if tier_value != old_tier:
            new_plan['tier'] = tier_value
            audit.append({
                'kind': 'tier',
                'uid': '_global',
                'before': old_tier,
                'after': tier_value,
                'note': str(notes_block.get('_tier', '') or ''),
            })

    # Surface user-flagged orphan notes (notes with no override) so
    # the audit chain captures the commentary even without a concrete
    # delta.
    plan_uids = _plan_subfolder_uids(plan)
    overridden_uids = set(sub_block.keys()) | set(conflict_block.keys())
    for uid, note in notes_block.items():
        if not isinstance(note, str) or not note:
            continue
        if uid in overridden_uids or uid == '_tier':
            continue
        # An orphan note — captured for the audit chain.
        audit.append({
            'kind': 'note',
            'uid': uid,
            'before': '',
            'after': '',
            'note': note,
            'in_plan': uid in plan_uids,
        })

    return new_plan, audit


# ─── Friendly reporter ─────────────────────────────────────────────────────

def format_validation_errors(errors: List[str], *, path: str = '') -> str:
    """Single multi-line block suitable for `logging.error` / stderr.

    Customer-facing — never embed a python traceback. Each error gets
    its own line, prefixed with a bullet. The header tells the user
    which file the errors came from.
    """
    if not errors:
        return ''
    header_path = path or '<overrides>'
    lines = [
        f'{len(errors)} error(s) in {header_path}:',
    ]
    for e in errors:
        lines.append(f'  - {e}')
    lines.append('')
    lines.append('Fix the file and re-run. No changes were applied to '
                  'the plan.')
    return '\n'.join(lines)


# ─── Convenience: load + validate + apply in one go ────────────────────────

def load_validate_apply(path: str, plan: Dict[str, Any], *,
                         accept_risk: bool = False) -> Tuple[Dict[str, Any],
                                                              List[Dict[str, Any]]]:
    """Load `path`, validate against `plan`, return (new_plan, audit).

    Raises `OverridesValidationError` (with a populated `.errors`
    list) when validation fails. Callers should catch that and print
    `format_validation_errors(e.errors, path=path)` to stderr.
    """
    overrides = load_overrides(path)
    errors = validate_overrides(overrides, plan, accept_risk=accept_risk)
    if errors:
        raise OverridesValidationError(errors)
    return apply_overrides(plan, overrides)
