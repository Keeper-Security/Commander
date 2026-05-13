"""Tenant-size pre-estimation.

Consumes a `plan`-produced inventory.json and returns:
  - entity counts (pass-through from inventory['counts'])
  - per-stage API call budget
  - throttle tier recommendation (delay, batch_size)
  - runtime estimate at recommended throttle

Designed as a read-only pre-flight — no network, no tenant mutations.

The single source of truth for scale tiers lives here; `wizard.py`
imports SCALE_TIERS from this module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping, Sequence


# ── Tuning constants ────────────────────────────────────────────────

# Average Commander API round-trip seen in v1.1/v1.2 rehearsals.
# Add the active `--delay` on top to get per-call wall time.
AVG_CALL_LATENCY_SEC = 0.3

# Attachments dominate wall time — file I/O + two calls per file.
# Per-file overhead on top of AVG_CALL_LATENCY_SEC (download + upload).
ATTACHMENT_EXTRA_SEC = 1.5

# Commander's rate limiter injects 60-second pauses when it detects
# burst activity. Calibrated from Tier 6 rehearsal 2026-04-19:
#   - 9-entity structure restore: 4–6 throttles (240–360 s wait)
#   - 3-record records-shares: 1 throttle (60 s)
#   - 9-entity cleanup (target): 1 throttle (60 s)
# The probability is roughly 1 throttle per ~3 calls on the write
# paths once a session is warm. We model it as a linear penalty
# proportional to call count above a small-tier floor.
THROTTLE_PAUSE_SEC = 60.0
# Calls-per-throttle ratio. Ignored for tier='empty' / 'small' where
# in practice throttles are rare (observed 0 on small runs).
CALLS_PER_THROTTLE_MEDIUM_PLUS = 3

# Per-operation API call budgets. Calibrated from rehearsal 1+2 logs.
PER_OP_CALLS = {
    'node_create':     1,
    'team_create':     2,    # create + member bind
    'role_create':     2,    # create + enforcement apply
    'role_managed':    1,    # per managed-node privilege
    'user_invite':     2,    # invite + place in node
    'record_import':   1,    # one native batch per record-type
    'attachment_xfer': 2,    # download + upload
    'share_record':    1,
}

# (upper_bound_count, delay_sec, batch_size, label)
#
# Shared with wizard._SCALE_TIERS — wizard re-exports from here.
SCALE_TIERS: Sequence[tuple[int, float, int, str]] = (
    (50,      0.5, 0,   'small (≤50)'),
    (500,     1.0, 25,  'medium (51–500)'),
    (5000,    2.0, 50,  'large (501–5k)'),
    (10**9,   3.0, 100, 'xlarge (5k+)'),
)


def tier_for(count: int) -> tuple[float, int, str]:
    """Return (delay, batch_size, label) for a record/user count."""
    if count <= 0:
        return (0.0, 0, 'empty')
    for upper, delay, batch, label in SCALE_TIERS:
        if count <= upper:
            return (delay, batch, label)
    return (0.0, 0, 'unknown')


@dataclass
class StageEstimate:
    name: str
    calls: int
    seconds_at_throttle: float

    def duration_str(self) -> str:
        return _fmt_duration(self.seconds_at_throttle)


@dataclass
class Estimate:
    counts: Mapping[str, int]
    stages: Sequence[StageEstimate]
    delay: float
    batch_size: int
    tier_label: str
    total_calls: int
    total_seconds: float

    def as_json(self) -> dict:
        return {
            'counts': dict(self.counts),
            'stages': [
                {'name': s.name,
                 'calls': s.calls,
                 'seconds': round(s.seconds_at_throttle, 1)}
                for s in self.stages
            ],
            'throttle': {
                'delay': self.delay,
                'batch_size': self.batch_size,
                'tier': self.tier_label,
            },
            'totals': {
                'calls': self.total_calls,
                'seconds': round(self.total_seconds, 1),
                'duration_human': _fmt_duration(self.total_seconds),
            },
        }


# ── Estimation ──────────────────────────────────────────────────────

def _budget_structure(counts) -> int:
    return (
        counts.get('nodes', 0)                         * PER_OP_CALLS['node_create']
        + counts.get('teams', 0)                       * PER_OP_CALLS['team_create']
        + counts.get('roles', 0)                       * PER_OP_CALLS['role_create']
        + counts.get('total_privileges', 0)            * PER_OP_CALLS['role_managed']
    )


def _budget_users(counts) -> int:
    return counts.get('users', 0) * PER_OP_CALLS['user_invite']


def _budget_records_import(counts) -> int:
    # Commander imports by batch per record-type. Without a type breakdown
    # in the inventory we approximate at 5 batches (covers login, password,
    # note, fileRef, generic typed).
    if counts.get('records', 0) <= 0:
        return 0
    return 5 * PER_OP_CALLS['record_import']


def _budget_attachments(counts) -> int:
    return counts.get('attachments', 0) * PER_OP_CALLS['attachment_xfer']


def _budget_shares(counts) -> int:
    return counts.get('direct_shares', 0) * PER_OP_CALLS['share_record']


def _stage_seconds(calls: int, delay: float, *,
                   attachment_calls: int = 0,
                   include_throttle: bool = False) -> float:
    """Wall-clock estimate for a stage.

    `include_throttle`: when True, adds a throttle-penalty term
    proportional to call count. Commander's rate limiter injects
    THROTTLE_PAUSE_SEC seconds per ~CALLS_PER_THROTTLE_MEDIUM_PLUS
    calls on write-heavy paths after a session is warm. Off for
    small-tier or pure-read stages.
    """
    if calls <= 0:
        return 0.0
    base = calls * (AVG_CALL_LATENCY_SEC + delay)
    attach_extra = (attachment_calls / 2) * ATTACHMENT_EXTRA_SEC
    throttle_extra = 0.0
    if include_throttle and calls >= CALLS_PER_THROTTLE_MEDIUM_PLUS:
        expected_throttles = calls / CALLS_PER_THROTTLE_MEDIUM_PLUS
        throttle_extra = expected_throttles * THROTTLE_PAUSE_SEC
    return base + attach_extra + throttle_extra


def estimate_from_counts(counts: Mapping[str, int], *,
                         tier_driver: str = 'auto',
                         include_throttle: bool = True,
                         calls_per_minute: float = 0.0) -> Estimate:
    """Compute the estimate from an inventory's `counts` dict.

    tier_driver: 'auto' uses max(users, records); 'users' or 'records'
    forces one axis (useful when the scope is deliberately narrow).
    include_throttle: when True (default), adds a throttle-penalty
    term for medium+ tiers so the wall-clock estimate reflects
    Commander's 60 s rate-limit pauses observed in live rehearsals.
    Pass False to get a pure per-call-latency estimate (useful for
    comparing against idealized benchmarks).
    calls_per_minute: when > 0, overrides the tier-derived `delay`
    with `60/cpm - AVG_CALL_LATENCY_SEC` (floored at 0). Also disables
    the throttle penalty term because the cpm cap IS the throttle
    model — double-counting would inflate the estimate.
    """
    if tier_driver == 'users':
        driver = counts.get('users', 0)
    elif tier_driver == 'records':
        driver = counts.get('records', 0)
    else:
        driver = max(counts.get('users', 0), counts.get('records', 0))

    delay, batch_size, tier_label = tier_for(driver)

    # Operator-supplied cpm overrides the tier delay. We subtract the
    # observed round-trip latency because per-call wall time in
    # _stage_seconds is computed as (latency + delay), so the effective
    # rate stays honest. Also switch the label to reflect the override.
    if calls_per_minute and calls_per_minute > 0:
        per_call = 60.0 / float(calls_per_minute)
        delay = max(0.0, per_call - AVG_CALL_LATENCY_SEC)
        tier_label = f'{tier_label} [cpm={calls_per_minute:g}]'
        include_throttle = False  # cpm cap already models the throttle

    # Enable throttle penalty on medium+ tiers — small runs don't
    # hit Commander's rate limiter often enough for the penalty to
    # be meaningful and would inflate the estimate inappropriately.
    # Caller can force-disable via include_throttle=False.
    throttle_active = include_throttle and tier_label not in (
        'empty', 'small (≤50)',
    )

    stages = []
    for name, calls, is_attach in (
        ('structure',          _budget_structure(counts), False),
        ('users',              _budget_users(counts), False),
        ('records-import',     _budget_records_import(counts), False),
        ('records-attachments', _budget_attachments(counts), True),
        ('records-shares',     _budget_shares(counts), False),
    ):
        seconds = _stage_seconds(
            calls, delay,
            attachment_calls=calls if is_attach else 0,
            include_throttle=throttle_active,
        )
        stages.append(StageEstimate(name=name, calls=calls,
                                    seconds_at_throttle=seconds))

    total_calls = sum(s.calls for s in stages)
    total_seconds = sum(s.seconds_at_throttle for s in stages)

    return Estimate(
        counts=dict(counts),
        stages=stages,
        delay=delay,
        batch_size=batch_size,
        tier_label=tier_label,
        total_calls=total_calls,
        total_seconds=total_seconds,
    )


def load_inventory_counts(inventory_path: str) -> dict:
    with open(inventory_path) as f:
        inv = json.load(f)
    counts = inv.get('counts') or {}
    if not counts:
        raise ValueError(
            f'inventory at {inventory_path} has no "counts" — '
            f'was it produced by `plan`?'
        )
    return counts


# ── Formatting ──────────────────────────────────────────────────────

def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f'{seconds}s'
    if seconds < 3600:
        return f'{seconds // 60}m {seconds % 60}s'
    h, rem = divmod(seconds, 3600)
    return f'{h}h {rem // 60}m'


def render_markdown(est: Estimate, enterprise_name: str = '') -> str:
    lines = []
    title = f'Tenant size estimate — {enterprise_name}' if enterprise_name \
            else 'Tenant size estimate'
    lines.append(f'## {title}\n')

    lines.append('### Counts')
    lines.append('| Entity | Count |')
    lines.append('|--------|------:|')
    for key in ('nodes', 'teams', 'roles', 'users', 'shared_folders',
                'records', 'attachments', 'direct_shares',
                'total_enforcements', 'total_privileges'):
        v = est.counts.get(key, 0)
        lines.append(f'| {key} | {v:,} |')
    lines.append('')

    lines.append('### API call budget (approximate)')
    lines.append('| Stage | Calls | Est. duration |')
    lines.append('|-------|------:|---------------|')
    for s in est.stages:
        lines.append(f'| {s.name} | {s.calls:,} | {s.duration_str()} |')
    lines.append(f'| **Total** | **{est.total_calls:,}** | '
                 f'**{_fmt_duration(est.total_seconds)}** |')
    lines.append('')

    lines.append('### Throttle recommendation')
    lines.append(f'- Detected tier: **{est.tier_label}**')
    lines.append(f'- Recommended flags: `--delay={est.delay} '
                 f'--batch-size={est.batch_size}`')
    lines.append(f'- Est. runtime at recommended throttle: '
                 f'**{_fmt_duration(est.total_seconds)}**')
    lines.append('')

    warnings = _warnings(est)
    if warnings:
        lines.append('### Warnings')
        for w in warnings:
            lines.append(f'- {w}')
        lines.append('')

    lines.append('### Notes')
    lines.append('- API call counts are estimates, not guarantees. '
                 'Commander batches some calls; backoff inserts retries.')
    lines.append('- Latency baseline: 300 ms per call, +1.5 s per '
                 'attachment (empirical from rehearsal 1+2).')
    lines.append('- **Throttle penalty**: Commander\'s rate limiter '
                 'injects 60 s pauses on burst writes. Medium+ tiers '
                 'add ~1 pause per 3 calls to the estimate. Observed '
                 '4–6 throttles on a 9-entity structure-live run.')
    lines.append('- Tier selection uses `max(users, records)` in scope.')
    lines.append('')
    return '\n'.join(lines)


# ── Scale-tier verification (Phase C) ──────────────────────────────
#
# When a scale rehearsal completes, callers can ask: did the actual
# runtime / API-call count / throttle incidents fall within the
# tier's predicted envelope? `predict_for_count` and `compare_actual`
# answer that.


def predict_for_count(count: int, *,
                      driver: str = 'records',
                      include_throttle: bool = True
                      ) -> dict:
    """Predict runtime / call count / throttle incidents for `count`
    records (or users — set `driver`).

    Used by the scale_seeder / harness Tier 8 to compute a target
    envelope before the run starts. Returns a plain dict so the harness
    can serialize it next to the seed log without a dataclass dance.
    """
    counts = {driver: count}
    est = estimate_from_counts(counts, tier_driver=driver,
                                include_throttle=include_throttle)
    # Throttles modeled in _stage_seconds (see THROTTLE_PAUSE_SEC).
    # Re-derive the prediction here so callers can quote it.
    if include_throttle and est.tier_label not in ('empty', 'small (≤50)'):
        predicted_throttles = est.total_calls // CALLS_PER_THROTTLE_MEDIUM_PLUS
    else:
        predicted_throttles = 0
    return {
        'count': count,
        'driver': driver,
        'tier': est.tier_label,
        'delay': est.delay,
        'batch_size': est.batch_size,
        'predicted_calls': est.total_calls,
        'predicted_throttles': predicted_throttles,
        'predicted_seconds': round(est.total_seconds, 1),
        'predicted_duration': _fmt_duration(est.total_seconds),
    }


def compare_actual(prediction: dict, *,
                   actual_seconds: float,
                   actual_calls: int = 0,
                   actual_throttles: int = 0,
                   tolerance: float = 0.25
                   ) -> dict:
    """Compare an actual run against the prediction envelope.

    `tolerance` is fractional (0.25 = ±25%). Returns a verdict dict the
    harness writes to the run dir alongside the rehearsal matrix.
    """
    predicted_seconds = float(prediction.get('predicted_seconds') or 0.0)
    lower = predicted_seconds * (1 - tolerance)
    upper = predicted_seconds * (1 + tolerance)
    runtime_within = (lower <= actual_seconds <= upper) if predicted_seconds \
        else (actual_seconds >= 0)

    predicted_calls = int(prediction.get('predicted_calls') or 0)
    calls_within = True
    if predicted_calls > 0 and actual_calls > 0:
        calls_within = (abs(actual_calls - predicted_calls)
                        <= predicted_calls * tolerance)

    predicted_throttles = int(prediction.get('predicted_throttles') or 0)
    # Throttles are noisy — accept ±50% on the throttle count
    # (calibration drift is real, the only useful signal is "did the
    # backoff machinery fire roughly N times" not the exact count).
    throttle_tolerance = max(tolerance * 2, 0.5)
    throttles_within = True
    if predicted_throttles > 0:
        throttles_within = (abs(actual_throttles - predicted_throttles)
                            <= max(1, predicted_throttles * throttle_tolerance))
    elif actual_throttles > 0:
        # We expected zero throttles; firing more than 2 is a regression.
        throttles_within = actual_throttles <= 2

    pass_overall = runtime_within and calls_within and throttles_within
    return {
        'prediction': dict(prediction),
        'actual': {
            'seconds': round(actual_seconds, 1),
            'calls': actual_calls,
            'throttles': actual_throttles,
        },
        'tolerance': tolerance,
        'verdict': {
            'runtime_within_envelope': runtime_within,
            'calls_within_envelope': calls_within,
            'throttles_within_envelope': throttles_within,
            'pass': pass_overall,
        },
    }


def render_tier_validation_report(comparison: dict) -> str:
    """Markdown summary of compare_actual output. Used by the harness'
    Tier 8 step to drop a human-readable report in the run dir."""
    p = comparison.get('prediction') or {}
    a = comparison.get('actual') or {}
    v = comparison.get('verdict') or {}
    tol = comparison.get('tolerance', 0.25)
    lines = [
        '## Scale-tier validation\n',
        f'- Tier: **{p.get("tier", "?")}**',
        f'- Records driven: {p.get("count", 0):,}',
        f'- Tolerance band: ±{int(tol * 100)}%\n',
        '| Metric | Predicted | Actual | Within band |',
        '|--------|----------:|-------:|:-----------:|',
        (f'| Runtime  | {p.get("predicted_duration", "?")} '
         f'| {_fmt_duration(a.get("seconds", 0))} '
         f'| {"PASS" if v.get("runtime_within_envelope") else "FAIL"} |'),
        (f'| API calls| {p.get("predicted_calls", 0):,} '
         f'| {a.get("calls", 0):,} '
         f'| {"PASS" if v.get("calls_within_envelope") else "FAIL"} |'),
        (f'| Throttles| {p.get("predicted_throttles", 0)} '
         f'| {a.get("throttles", 0)} '
         f'| {"PASS" if v.get("throttles_within_envelope") else "FAIL"} |'),
        '',
        f'**Overall**: {"PASS" if v.get("pass") else "FAIL"}',
        '',
    ]
    return '\n'.join(lines)


def _warnings(est: Estimate) -> list[str]:
    out = []
    attachments = est.counts.get('attachments', 0)
    direct_shares = est.counts.get('direct_shares', 0)
    if attachments:
        out.append(
            f'{attachments} attachment(s) require the two-shell pattern — '
            f'schedule both source and target sessions.'
        )
    if direct_shares:
        out.append(
            f'{direct_shares} direct share(s) rely on target users '
            f'existing first — run `users` before `records-shares`.'
        )
    if est.total_seconds > 3600:
        out.append(
            f'Est. runtime exceeds 1 h ({_fmt_duration(est.total_seconds)}) — '
            f'plan around rate-limit windows and Commander session lifetime.'
        )
    if est.total_calls > 10_000:
        out.append(
            f'Est. {est.total_calls:,} calls crosses Commander\'s typical '
            f'rate-limit thresholds — consider tighter `--delay` or '
            f'splitting the scope.'
        )
    return out
