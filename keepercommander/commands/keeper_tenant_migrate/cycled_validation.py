"""Cycled round-trip migration validation harness.

A *cycle* is one complete forward+reverse migration:

    plan -> structure -> users -> records-export -> records-import
        -> records-shares -> records-attachments -> verify
        -> undo -> verify-clean

The cycled harness runs N cycles back-to-back and asserts:

  - **Source-read-only (Rule 0)**: source bytes are captured once
    BEFORE cycle 1 and re-checked after every cycle. Any mutation =
    immediate abort + audit-log entry. This rule supersedes everything
    else in this module.
  - **Target idempotency**: post-create state on cycle N is byte-equal
    to post-create state on cycle 1.
  - **Undo cleanliness**: after each cycle's undo + verify-clean, the
    target carries zero MIGTEST-* entities.
  - **No metric drift**: per-cycle deltas (API calls, runtime,
    throttle events, verify pass rate, undo completion rate) stay
    within ±5% of cycle 1.

The module is fakes-only — every dependency (StructureClient,
UserClient, ShareClient, AttachmentClient, CleanupClient,
UndoClient) is the in-package Fake* implementation. **No subprocess
is spawned. No network call is made. No real Commander session is
opened.** That's what makes the harness runnable in unit tests.

Live-mode wiring (the ``--cycles N`` flag in
``migration_scripts/ci/comprehensive_rehearsal.py``) re-uses the
contracts defined here (CycleResult, CycleMetrics, drift threshold)
but drives real subprocess invocations instead of fakes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


__all__ = [
    'DRIFT_THRESHOLD',
    'CycleMetrics',
    'CycleResult',
    'CycledHarness',
    'SourceMutationError',
    'compute_drift',
    'snapshot_bytes',
    'verify_source_read_only',
]


# ── Constants ───────────────────────────────────────────────────────

#: Maximum allowed drift between cycle 1 and cycle N for any metric
#: before the harness flags a FAIL. 5 % matches the squad-2 brief (T6.4).
DRIFT_THRESHOLD = 0.05

#: How many cycles a default ``run()`` invocation executes when no
#: explicit count is passed. The squad-2 brief locks this to 3.
DEFAULT_CYCLES = 3


# ── Errors ──────────────────────────────────────────────────────────


class SourceMutationError(RuntimeError):
    """Raised the instant a source-side byte mutation is detected.

    Rule 0 of the squad-2 cycled tests: source is read-only forever.
    Detection happens via byte-level snapshot comparison after every
    cycle. Raising this error aborts the harness immediately, before
    any further cycles can compound the breach.
    """


# ── Source-read-only rail ───────────────────────────────────────────


def snapshot_bytes(obj) -> bytes:
    """Deterministic byte representation of any JSON-serialisable object.

    Uses ``json.dumps`` with ``sort_keys=True`` so the snapshot is
    invariant under dict-key ordering and structure-equivalent across
    Python versions.
    """
    return json.dumps(obj, sort_keys=True, default=str).encode('utf-8')


def verify_source_read_only(baseline: bytes, current_obj,
                             *, cycle: int = 0,
                             audit_log: Optional[List[str]] = None) -> None:
    """Assert source bytes still match ``baseline``.

    Raises ``SourceMutationError`` on any divergence. When an
    ``audit_log`` list is given, an entry is appended describing the
    breach BEFORE the exception is raised (so post-mortem inspection
    of the audit list shows the failure even if the caller doesn't
    handle the exception).
    """
    current = snapshot_bytes(current_obj)
    if current == baseline:
        return
    baseline_h = hashlib.sha256(baseline).hexdigest()[:16]
    current_h = hashlib.sha256(current).hexdigest()[:16]
    msg = (
        f'SOURCE MUTATION DETECTED at cycle {cycle}: '
        f'baseline sha256={baseline_h} != current sha256={current_h}. '
        f'Source MUST be read-only (Rule 0). Aborting harness.'
    )
    if audit_log is not None:
        audit_log.append(msg)
    logging.error(msg)
    raise SourceMutationError(msg)


# ── Cycle data shapes ───────────────────────────────────────────────


@dataclass
class CycleMetrics:
    """Per-cycle observability summary.

    Numbers are intentionally narrow — five small ints/floats — so a
    drift comparison is straightforward and the JSON dump for live-mode
    rehearsals stays human-skimmable.
    """
    api_calls: int = 0
    runtime_seconds: float = 0.0
    throttle_events: int = 0
    verify_pass_rate: float = 1.0    # 0.0 .. 1.0
    undo_completion_rate: float = 1.0    # 0.0 .. 1.0

    def as_dict(self) -> dict:
        return {
            'api_calls': self.api_calls,
            'runtime_seconds': round(self.runtime_seconds, 4),
            'throttle_events': self.throttle_events,
            'verify_pass_rate': round(self.verify_pass_rate, 4),
            'undo_completion_rate': round(self.undo_completion_rate, 4),
        }


@dataclass
class CycleResult:
    """Outcome of one cycle iteration."""
    cycle: int
    status: str    # PASS | FAIL
    metrics: CycleMetrics
    target_post_create_hash: str = ''
    target_post_undo_clean: bool = True
    notes: str = ''

    def as_dict(self) -> dict:
        return {
            'cycle': self.cycle,
            'status': self.status,
            'metrics': self.metrics.as_dict(),
            'target_post_create_hash': self.target_post_create_hash,
            'target_post_undo_clean': self.target_post_undo_clean,
            'notes': self.notes,
        }


def compute_drift(cycle1: CycleMetrics, cycleN: CycleMetrics) -> dict:
    """Return the relative drift of every metric vs cycle 1.

    ``api_calls``, ``runtime_seconds`` and ``throttle_events`` use a
    symmetric ``abs(a - b) / max(a, 1)`` so a "0 vs 0" baseline reports
    0 drift instead of NaN.

    ``verify_pass_rate`` and ``undo_completion_rate`` are already
    fractions; we use absolute difference (so e.g. a regression from
    1.0 to 0.96 reports 0.04, not 4 %).
    """
    def rel(base, now):
        return abs(now - base) / max(abs(base), 1.0)

    def absdiff(base, now):
        return abs(now - base)

    return {
        'api_calls': rel(cycle1.api_calls, cycleN.api_calls),
        'runtime_seconds': rel(cycle1.runtime_seconds,
                                cycleN.runtime_seconds),
        'throttle_events': rel(cycle1.throttle_events,
                                cycleN.throttle_events),
        'verify_pass_rate': absdiff(cycle1.verify_pass_rate,
                                     cycleN.verify_pass_rate),
        'undo_completion_rate': absdiff(cycle1.undo_completion_rate,
                                         cycleN.undo_completion_rate),
    }


# ── Fakes-mode round-trip core ──────────────────────────────────────
#
# This is a *minimal* but realistic round-trip: we don't drive every
# subcommand's full code path here (the unit suite already does), we
# drive enough to exercise the cycle invariants:
#
#   - structure: create a fixed set of MIGTEST-* nodes/teams/roles/SFs
#   - users: invite a fixed roster
#   - records: import N records and capture their UIDs
#   - shares: grant a fixed set of share pairs
#   - attachments: upload a fixed set of attachment pairs
#   - verify: count target entities; expected==created
#   - undo: replay inverse ops via FakeUndoClient
#   - verify-clean: target inventory is empty of MIGTEST-* again


def _build_synthetic_inventory(*, prefix: str = 'MIGTEST-',
                                 scope_node: str = 'MIGRATION-TEST-NODE',
                                 ) -> dict:
    """Return a deterministic source inventory used by every cycle.

    The shape mirrors what ``plan`` emits (the keys ``entities``,
    ``counts``, ``source_user``) but trimmed to just enough to exercise
    one round-trip end-to-end.
    """
    return {
        'source_user': 'admin@source.example.com',
        'scope_node': scope_node,
        'prefix': prefix,
        'entities': {
            'nodes': [
                {'name': f'{prefix}NodeAlpha', 'parent': scope_node},
                {'name': f'{prefix}NodeBeta', 'parent': scope_node},
            ],
            'teams': [
                {'name': f'{prefix}TeamOne', 'node': f'{prefix}NodeAlpha'},
            ],
            'roles': [
                {'name': f'{prefix}RoleAdmin', 'node': f'{prefix}NodeAlpha'},
            ],
            'shared_folders': [
                {'name': f'{prefix}SF-Engineering', 'uid': 'sf-eng-001'},
            ],
            'users': [
                {'email': 'alice+migtest@migtest.local',
                 'node': f'{prefix}NodeAlpha'},
                {'email': 'bob+migtest@migtest.local',
                 'node': f'{prefix}NodeBeta'},
            ],
            'records': [
                {'uid': 'rec-001', 'title': f'{prefix}Login-001'},
                {'uid': 'rec-002', 'title': f'{prefix}DBCred-002'},
                {'uid': 'rec-003', 'title': f'{prefix}SSH-003'},
            ],
            'shares': [
                {'target_uid': 'rec-001',
                 'email': 'alice+migtest@migtest.local'},
                {'target_uid': 'rec-002',
                 'email': 'bob+migtest@migtest.local'},
            ],
            'attachments': [
                {'target_uid': 'rec-001', 'file_name': 'config.txt'},
                {'target_uid': 'rec-003', 'file_name': 'key.pem'},
            ],
        },
        'counts': {
            'nodes': 2, 'teams': 1, 'roles': 1,
            'shared_folders': 1, 'users': 2, 'records': 3,
            'shares': 2, 'attachments': 2,
        },
    }


@dataclass
class _TargetState:
    """In-memory snapshot of the target tenant during one cycle.

    Mutated by ``_step_*`` helpers, queried by ``_count_migtest`` for
    verify-clean assertions. Each cycle starts with an empty target.
    """
    nodes: dict = field(default_factory=dict)
    teams: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    shared_folders: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    records: dict = field(default_factory=dict)
    shares: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    api_calls: int = 0

    def snapshot(self) -> dict:
        return {
            'nodes': sorted(self.nodes.keys()),
            'teams': sorted(self.teams.keys()),
            'roles': sorted(self.roles.keys()),
            'shared_folders': sorted(self.shared_folders.keys()),
            'users': sorted(self.users.keys()),
            'records': sorted(self.records.keys()),
            'shares': sorted([(s['target_uid'], s['email'])
                              for s in self.shares]),
            'attachments': sorted([(a['target_uid'], a['file_name'])
                                    for a in self.attachments]),
        }

    def count_migtest(self, prefix: str) -> int:
        n = 0
        for collection in (self.nodes, self.teams, self.roles,
                            self.shared_folders, self.users,
                            self.records):
            for k in collection:
                if k.startswith(prefix) or k.startswith('rec-') \
                        or '+migtest@' in k or k.startswith('sf-'):
                    n += 1
        # Shares + attachments are reference-only — counted via their
        # parent record. We add them separately so the undo-clean
        # assertion is exact.
        n += len(self.shares) + len(self.attachments)
        return n


def _step_structure(target: _TargetState, inv: dict) -> List[dict]:
    """Create nodes/teams/roles/SFs on target. Returns audit-event for undo."""
    created = {'nodes': [], 'teams': [], 'roles': [], 'shared_folders': []}
    for n in inv['entities']['nodes']:
        target.nodes[n['name']] = dict(n)
        target.api_calls += 1
        created['nodes'].append(n['name'])
    for t in inv['entities']['teams']:
        target.teams[t['name']] = dict(t)
        target.api_calls += 1
        created['teams'].append(t['name'])
    for r in inv['entities']['roles']:
        target.roles[r['name']] = dict(r)
        target.api_calls += 1
        created['roles'].append(r['name'])
    for sf in inv['entities']['shared_folders']:
        target.shared_folders[sf['name']] = dict(sf)
        target.api_calls += 1
        created['shared_folders'].append(sf['uid'])
    return [{'subcommand': 'structure',
             'summary': {'created_entities': created},
             'signature': 'structure-1'}]


def _step_users(target: _TargetState, inv: dict) -> List[dict]:
    invited = []
    for u in inv['entities']['users']:
        target.users[u['email']] = dict(u)
        target.api_calls += 1
        invited.append(u['email'])
    return [{'subcommand': 'users',
             'summary': {'invited_emails': invited},
             'signature': 'users-1'}]


def _step_records(target: _TargetState, inv: dict) -> List[dict]:
    imported = []
    for r in inv['entities']['records']:
        target.records[r['uid']] = dict(r)
        target.api_calls += 1
        imported.append(r['uid'])
    return [{'subcommand': 'records-import',
             'summary': {'imported_uids': imported},
             'signature': 'records-import-1'}]


def _step_shares(target: _TargetState, inv: dict) -> List[dict]:
    grants = []
    for s in inv['entities']['shares']:
        target.shares.append(dict(s))
        target.api_calls += 1
        grants.append({'target_uid': s['target_uid'],
                        'email': s['email']})
    return [{'subcommand': 'records-shares',
             'summary': {'share_grants': grants},
             'signature': 'records-shares-1'}]


def _step_attachments(target: _TargetState, inv: dict) -> List[dict]:
    uploaded = []
    for a in inv['entities']['attachments']:
        target.attachments.append(dict(a))
        target.api_calls += 1
        uploaded.append({'target_uid': a['target_uid'],
                          'file_name': a['file_name']})
    return [{'subcommand': 'records-attachments',
             'summary': {'uploaded': uploaded},
             'signature': 'records-attachments-1'}]


def _step_verify(target: _TargetState, inv: dict) -> Tuple[int, int]:
    """Return (passed, total) where each created entity counts once."""
    expected = inv['counts']
    passed = 0
    total = 0
    for kind, expected_count in expected.items():
        total += expected_count
        if kind == 'nodes':
            passed += sum(1 for n in inv['entities']['nodes']
                           if n['name'] in target.nodes)
        elif kind == 'teams':
            passed += sum(1 for t in inv['entities']['teams']
                           if t['name'] in target.teams)
        elif kind == 'roles':
            passed += sum(1 for r in inv['entities']['roles']
                           if r['name'] in target.roles)
        elif kind == 'shared_folders':
            passed += sum(1 for s in inv['entities']['shared_folders']
                           if s['name'] in target.shared_folders)
        elif kind == 'users':
            passed += sum(1 for u in inv['entities']['users']
                           if u['email'] in target.users)
        elif kind == 'records':
            passed += sum(1 for r in inv['entities']['records']
                           if r['uid'] in target.records)
        elif kind == 'shares':
            passed += sum(1 for s in inv['entities']['shares']
                           if any(ts['target_uid'] == s['target_uid']
                                   and ts['email'] == s['email']
                                   for ts in target.shares))
        elif kind == 'attachments':
            passed += sum(1 for a in inv['entities']['attachments']
                           if any(ta['target_uid'] == a['target_uid']
                                   and ta['file_name'] == a['file_name']
                                   for ta in target.attachments))
    return passed, total


def _step_undo(target: _TargetState, audit_events: List[dict],
                prefix: str) -> Tuple[int, int]:
    """Return (reversed, attempted). Walks LIFO over audit_events."""
    attempted = 0
    reversed_count = 0
    for ev in reversed(audit_events):
        sub = ev.get('subcommand', '')
        summary = ev.get('summary', {})
        if sub == 'records-attachments':
            for u in summary.get('uploaded', []):
                attempted += 1
                target.attachments = [
                    a for a in target.attachments
                    if not (a['target_uid'] == u['target_uid']
                             and a['file_name'] == u['file_name'])
                ]
                target.api_calls += 1
                reversed_count += 1
        elif sub == 'records-shares':
            for g in summary.get('share_grants', []):
                attempted += 1
                target.shares = [
                    s for s in target.shares
                    if not (s['target_uid'] == g['target_uid']
                             and s['email'] == g['email'])
                ]
                target.api_calls += 1
                reversed_count += 1
        elif sub == 'records-import':
            # Records-import undo IS reversible in the cycled harness:
            # the cycle owns the target tenant entirely, so we can
            # delete the imported UIDs unambiguously. (In live mode this
            # remains MANUAL — the live-mode harness simulates an
            # operator running the manual delete via the audit trail.)
            for uid in summary.get('imported_uids', []):
                attempted += 1
                target.records.pop(uid, None)
                target.api_calls += 1
                reversed_count += 1
        elif sub == 'users':
            for e in summary.get('invited_emails', []):
                attempted += 1
                target.users.pop(e, None)
                target.api_calls += 1
                reversed_count += 1
        elif sub == 'structure':
            created = summary.get('created_entities', {})
            for uid in created.get('shared_folders', []):
                attempted += 1
                # SFs are stored by name — find the one with this uid.
                victim = None
                for name, sf in target.shared_folders.items():
                    if sf.get('uid') == uid:
                        victim = name
                        break
                if victim is not None:
                    target.shared_folders.pop(victim, None)
                    reversed_count += 1
                target.api_calls += 1
            for name in created.get('roles', []):
                attempted += 1
                target.roles.pop(name, None)
                target.api_calls += 1
                reversed_count += 1
            for name in created.get('teams', []):
                attempted += 1
                target.teams.pop(name, None)
                target.api_calls += 1
                reversed_count += 1
            for name in created.get('nodes', []):
                attempted += 1
                target.nodes.pop(name, None)
                target.api_calls += 1
                reversed_count += 1
    return reversed_count, attempted


# ── Harness ─────────────────────────────────────────────────────────


@dataclass
class CycledHarness:
    """N-iteration round-trip validator (fakes-mode).

    Construct with a synthetic inventory + scope/prefix, then call
    ``run(cycles=N)``. Returns a list[CycleResult]. Always re-checks
    the source-read-only invariant after every cycle.

    The harness is intentionally stateless across instances — every
    call to ``run`` builds fresh ``_TargetState`` and audit objects so
    cycles share no Python-level state that could mask bugs.
    """
    prefix: str = 'MIGTEST-'
    scope_node: str = 'MIGRATION-TEST-NODE'
    inventory: dict = field(default_factory=dict)
    drift_threshold: float = DRIFT_THRESHOLD
    audit_log: List[str] = field(default_factory=list)
    _baseline_source_bytes: bytes = b''

    def __post_init__(self):
        if not self.inventory:
            self.inventory = _build_synthetic_inventory(
                prefix=self.prefix, scope_node=self.scope_node,
            )
        # Capture the baseline source snapshot ONCE. Every subsequent
        # cycle will re-check against this exact byte sequence.
        self._baseline_source_bytes = snapshot_bytes(self.inventory)

    # — Rule 0 hard rail ————————————————————————————————————————

    def assert_source_unchanged(self, *, cycle: int) -> None:
        """Re-verify the source inventory is byte-identical to baseline.

        Called after every cycle. Raises ``SourceMutationError`` on
        any breach. **Do not catch this exception inside the harness**
        — it is meant to abort the entire run so a regression cannot
        silently compound across cycles.
        """
        verify_source_read_only(
            self._baseline_source_bytes,
            self.inventory,
            cycle=cycle,
            audit_log=self.audit_log,
        )

    # — Per-cycle —————————————————————————————————————————————————

    def run_one_cycle(self, *, cycle: int,
                       hammer: bool = False) -> CycleResult:
        """Execute one cycle. ``hammer`` skips the wait between
        forward and undo, deliberately stress-testing the orchestrator
        for races/data-loss."""
        # The forward stages clone the source inventory locally and
        # only ever read from the clone — the clone is the API of the
        # forward path, so even a buggy step that *tries* to mutate
        # the source can only mutate this clone. The
        # ``assert_source_unchanged`` post-check guarantees the
        # original was never touched at the byte level.
        local_inv = copy.deepcopy(self.inventory)

        target = _TargetState()
        audit_events: List[dict] = []

        t0 = time.perf_counter()
        try:
            audit_events += _step_structure(target, local_inv)
            audit_events += _step_users(target, local_inv)
            audit_events += _step_records(target, local_inv)
            audit_events += _step_shares(target, local_inv)
            audit_events += _step_attachments(target, local_inv)

            post_create_hash = hashlib.sha256(
                snapshot_bytes(target.snapshot())
            ).hexdigest()

            verify_passed, verify_total = _step_verify(target, local_inv)
            verify_rate = ((verify_passed / verify_total)
                            if verify_total else 1.0)

            if not hammer:
                # No wait in fakes-mode (would just slow the suite).
                # Hammer mode makes no functional difference here but
                # the flag is propagated so live-mode can branch on it.
                pass

            undo_reversed, undo_attempted = _step_undo(
                target, audit_events, prefix=self.prefix,
            )
            undo_rate = ((undo_reversed / undo_attempted)
                          if undo_attempted else 1.0)

            post_undo_clean = (target.count_migtest(self.prefix) == 0)

        finally:
            runtime = time.perf_counter() - t0

        # Rule 0 — post-cycle source byte assertion.
        # Done AFTER the cycle so a buggy step that mutated source can
        # be detected even if the step itself returned PASS. If the
        # bytes diverged, this raises SourceMutationError unconditionally.
        self.assert_source_unchanged(cycle=cycle)

        metrics = CycleMetrics(
            api_calls=target.api_calls,
            runtime_seconds=runtime,
            throttle_events=0,
            verify_pass_rate=verify_rate,
            undo_completion_rate=undo_rate,
        )
        notes_parts = []
        if verify_rate < 1.0:
            notes_parts.append(
                f'verify {verify_passed}/{verify_total}',
            )
        if not post_undo_clean:
            notes_parts.append(
                f'undo residue {target.count_migtest(self.prefix)}',
            )
        status = ('PASS'
                   if verify_rate == 1.0 and post_undo_clean
                   else 'FAIL')
        return CycleResult(
            cycle=cycle, status=status, metrics=metrics,
            target_post_create_hash=post_create_hash,
            target_post_undo_clean=post_undo_clean,
            notes='; '.join(notes_parts),
        )

    # — Multi-cycle ————————————————————————————————————————————————

    def run(self, *, cycles: int = DEFAULT_CYCLES,
            hammer: bool = False) -> List[CycleResult]:
        """Run ``cycles`` cycles. Returns the list of per-cycle results.

        On the first SourceMutationError the run aborts; the list at
        that point has the up-to-the-breach results plus the audit_log
        attribute carries the mutation message.
        """
        if cycles < 1:
            raise ValueError(f'cycles must be >= 1, got {cycles}')
        results: List[CycleResult] = []
        for i in range(1, cycles + 1):
            try:
                r = self.run_one_cycle(cycle=i, hammer=hammer)
            except SourceMutationError:
                # Already audit-logged inside verify_source_read_only.
                # Re-raise so the caller knows the run was aborted.
                raise
            results.append(r)
        return results

    # — Aggregate analysis —————————————————————————————————————————

    def assert_no_drift(self, results: List[CycleResult]) -> List[str]:
        """Compare cycle 1 vs cycle N for every metric. Returns a list
        of FAIL messages (empty list = no drift)."""
        if len(results) < 2:
            return []
        c1 = results[0].metrics
        failures: List[str] = []
        for r in results[1:]:
            drift = compute_drift(c1, r.metrics)
            for metric, value in drift.items():
                if value > self.drift_threshold:
                    failures.append(
                        f'cycle {r.cycle}: {metric} drift '
                        f'{value:.4f} > {self.drift_threshold:.4f} '
                        f'(c1={getattr(c1, metric)}, '
                        f'cN={getattr(r.metrics, metric)})'
                    )
        return failures

    def assert_idempotency(self, results: List[CycleResult]) -> List[str]:
        """Every cycle's ``target_post_create_hash`` must equal cycle 1's.
        Returns a list of FAIL messages (empty = idempotent)."""
        if len(results) < 2:
            return []
        h1 = results[0].target_post_create_hash
        failures = []
        for r in results[1:]:
            if r.target_post_create_hash != h1:
                failures.append(
                    f'cycle {r.cycle}: target post-create hash '
                    f'{r.target_post_create_hash[:16]} != '
                    f'cycle-1 {h1[:16]}'
                )
        return failures

    def assert_undo_clean(self, results: List[CycleResult]) -> List[str]:
        """Every cycle must end with target_post_undo_clean == True."""
        return [
            f'cycle {r.cycle}: undo did not clean target ({r.notes})'
            for r in results if not r.target_post_undo_clean
        ]


# ── Cross-cycle audit emission ──────────────────────────────────────


def write_per_cycle_audit(run_dir: str, cycle: int,
                            result: CycleResult) -> str:
    """Persist one cycle's audit summary under ``run_dir/cycle-N/``.

    Returns the path written. Used by the live-mode harness so each
    cycle's audit trail is preserved separately (T6.8).
    """
    cycle_dir = os.path.join(run_dir, f'cycle-{cycle}')
    os.makedirs(cycle_dir, exist_ok=True)
    audit_path = os.path.join(cycle_dir, 'audit.log')
    with open(audit_path, 'w') as f:
        f.write(json.dumps(result.as_dict(), indent=2))
        f.write('\n')
    return audit_path


def write_unified_audit(run_dir: str,
                          results: List[CycleResult]) -> str:
    """Emit ``cycled_audit_summary.md`` across every cycle.

    Returns the markdown path. Includes the cycle-vs-cycle drift
    analysis so an operator can spot a regression at a glance.
    """
    md_path = os.path.join(run_dir, 'cycled_audit_summary.md')
    json_path = os.path.join(run_dir, 'cycled_validation.json')
    lines = [
        '# Cycled validation — audit summary',
        '',
        f'Cycles run: {len(results)}',
        '',
        '| # | Status | API calls | Runtime (s) | Throttles | '
        'Verify% | Undo% | Notes |',
        '|---|---|---:|---:|---:|---:|---:|---|',
    ]
    for r in results:
        m = r.metrics
        lines.append(
            f'| {r.cycle} | **{r.status}** | {m.api_calls} | '
            f'{m.runtime_seconds:.4f} | {m.throttle_events} | '
            f'{m.verify_pass_rate * 100:.1f}% | '
            f'{m.undo_completion_rate * 100:.1f}% | {r.notes} |'
        )
    if len(results) >= 2:
        lines += ['', '## Drift vs cycle 1',
                   '',
                   '| Cycle | api_calls | runtime | throttles | '
                   'verify | undo |',
                   '|---|---:|---:|---:|---:|---:|']
        c1 = results[0].metrics
        for r in results[1:]:
            d = compute_drift(c1, r.metrics)
            lines.append(
                f"| {r.cycle} | {d['api_calls']:.4f} | "
                f"{d['runtime_seconds']:.4f} | "
                f"{d['throttle_events']:.4f} | "
                f"{d['verify_pass_rate']:.4f} | "
                f"{d['undo_completion_rate']:.4f} |"
            )
    with open(md_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    with open(json_path, 'w') as f:
        json.dump([r.as_dict() for r in results], f, indent=2)
    return md_path


# ── Live-mode hook (no subprocess invoked here) ─────────────────────
#
# The live harness in ``migration_scripts/ci/comprehensive_rehearsal.py``
# imports the helpers below to drive the per-cycle invariant checks
# against real subprocess outputs. This module never opens a subprocess
# itself — the live harness owns that responsibility.


def hash_source_config_file(path: str) -> str:
    """Return the SHA-256 of the source config file's bytes.

    The live harness computes this once before cycle 1 and re-computes
    it after every cycle. Any change in the digest aborts the run with
    a SourceMutationError. Mtime is intentionally NOT used — it would
    catch ``touch`` but miss a write that preserves mtime; bytes is the
    only safe oracle.
    """
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(1 << 16)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def assert_source_file_unchanged(path: str, baseline_hash: str,
                                   *, cycle: int,
                                   audit_log: Optional[List[str]] = None,
                                   ) -> None:
    """Live-mode counterpart to ``verify_source_read_only``.

    Raises ``SourceMutationError`` if the source-config bytes diverged
    since baseline. ``baseline_hash`` is whatever
    ``hash_source_config_file`` returned at run start.
    """
    current = hash_source_config_file(path)
    if current == baseline_hash:
        return
    msg = (
        f'SOURCE CONFIG FILE MUTATED at cycle {cycle}: '
        f'baseline sha256={baseline_hash[:16]} != '
        f'current sha256={current[:16]} (path={path!r}). '
        f'Aborting harness — Rule 0.'
    )
    if audit_log is not None:
        audit_log.append(msg)
    logging.error(msg)
    raise SourceMutationError(msg)
