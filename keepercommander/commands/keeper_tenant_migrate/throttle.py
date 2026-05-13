"""Adaptive inter-call throttle for Commander SDK invocations.

Why
---
Commander's `rest_api.communicate_rest` detects a 403/throttled response
and sleeps internally (`rest_api.py:273` — "Throttled (attempt N/M),
retrying in X seconds"). That handles the immediate request but does
nothing about the NEXT call: if our inter-call cadence is above the
tenant's budget we keep hitting the wall. The fixed per-stage delays in
`auto_migrate.RunConfig` are a guess, not a measurement — a slow run or
a sudden lock on MSP quota leaves the admin's browser starved.

This module ports the bash pipeline's `kc_call` pattern
(`migration_scripts/_throttle_helpers.sh`) into Python:

  - BASE delay (default 2.0s)
  - +1s per observed throttle event, capped at MAX (default 30s)
  - decay back to BASE after SUCCESS_RESET clean calls (default 20)

One `AdaptiveThrottle` per `(server, user)` pair so source-side and
target-side budgets never contaminate each other. All Commander calls
chain through `commander_clients._call`, so wrapping that one site
covers every SDK op — structure, users, records, attachments, shares,
cleanup, decommission, transfer, ownership, undo, sf-reconcile.

Signals
-------
Two distinct signals count as a throttle hit, both handled:

  1. **Log record** — Commander logs
     `logging.warning('Throttled (attempt %d/%d), retrying in %d seconds',
                       retries, max_retries, backoff)` at
     `rest_api.py:273`. We install a scoped `logging.Handler` while the
     SDK call runs and count matching records. This covers the case
     where rest_api's internal retry budget succeeds on attempt 2 or 3
     — the caller sees no exception but we learned we're near the wall.

  2. **Transient exception** — when rest_api's retry budget is
     exhausted it raises `KeeperApiError(result_code='throttled')`.
     The caller either bubbles this up (non-idempotent ops) or hands
     it to `backoff.Retry` for one more try. Either way we bump the
     adaptive delay.

Thread safety
-------------
Commander plugin usage is single-threaded in practice, but the state is
guarded with a lock anyway — rehearsal harness runs stages in
sub-processes sharing no process state, and the lock is cheap.

Resetting
---------
`AdaptiveThrottle.reset_registry()` clears the per-tenant singletons.
Tests use this to avoid carry-over between unit tests.
"""

from __future__ import annotations

import logging
import math
import random
import threading
import time
from typing import Callable, Dict, Optional, Tuple


# Default knobs — match the bash pipeline's empirically-tuned values
# except for max_delay (bash cap was 10s; we lift to 30s because
# Commander's own backoff floor is 30s — a lower ceiling buys nothing).
DEFAULT_BASE_DELAY = 2.0
DEFAULT_MAX_DELAY = 30.0
DEFAULT_SUCCESS_RESET = 20
DEFAULT_JITTER = 0.5
DEFAULT_STEP = 1.0
# Clustering: when a throttle hit lands within CLUSTER_WINDOW seconds
# of the previous hit, switch from linear +step to exponential growth.
# Commander's own rest_api backoff is 60s per hit, so throttle events
# observed by our handler are always ≥60s apart. 120s covers "still
# hitting trouble across 1-2 backoff cycles" which is the genuine
# clustering signal. 30s (initial default) was dead code in practice.
DEFAULT_CLUSTER_WINDOW = 120.0

# Cooldown after last throttle before ANY decay fires. Prevents the
# delay-decay / re-throttle oscillation observed 2026-04-22:
#   20 clean calls → delay decays → throttle → +step → 20 clean →
#   decay → throttle → … forever.
# 60s matches Commander's internal backoff cycle: we require a full
# backoff-window of clean calls before we start believing the tenant
# is actually OK with our current rate.
DEFAULT_DECAY_COOLDOWN = 60.0

# Bucket refill decays more conservatively than current_delay. The
# delay is a post-call pace (easily relaxed); the bucket is a burst
# cap that needs to stay at the proven-safe rate until we're sure
# the tenant has eased. Decay only every Nth success_reset window.
DEFAULT_BUCKET_DECAY_EVERY_N_WINDOWS = 3

# Token bucket defaults — capacity bounds the worst-case burst; refill
# rate in tokens/sec governs sustained throughput. `capacity=3` is
# calibrated from 2026-04-22 observations: 3 consecutive calls fit in
# Commander's burst budget, the 4th usually triggers throttle.
DEFAULT_BUCKET_CAPACITY = 3
DEFAULT_BUCKET_REFILL_PER_SEC = 0.5    # 30 cpm
DEFAULT_BUCKET_MIN_REFILL_PER_SEC = 0.1  # floor when clustering pushes us down

# Default marker substring matched in WARNING log records to detect
# throttle events emitted by the SDK's own retry path (Commander's
# `rest_api.communicate_rest` at `rest_api.py:273`). Configurable
# per-`ThrottleLogCapture` instance for embedding contexts where the
# upstream SDK logs a different phrase.
THROTTLE_LOG_MARKER = 'Throttled (attempt'
# Backwards-compat alias — kept in case downstream tooling reads the
# private name. Not used in this module beyond the alias itself.
_THROTTLE_LOG_MARKER = THROTTLE_LOG_MARKER


class AdaptiveThrottle:
    """Per-tenant adaptive inter-call pacing.

    Call contract (see `commander_clients._call`):

        throttle.begin_call()
        try:
            cmd.execute(params, **kwargs)
            throttle.end_call(hit=<handler-detected>)
        except Transient:
            throttle.end_call(hit=True)
            raise
        finally:
            throttle.sleep()   # paces the NEXT call

    `hit` is True when either (a) the scoped logging handler caught a
    "Throttled (attempt" record or (b) the caller detected a transient
    exception and is about to raise. Either bumps `current_delay`.
    """

    def __init__(self, *, tenant_label: str = '',
                  base_delay: float = DEFAULT_BASE_DELAY,
                  max_delay: float = DEFAULT_MAX_DELAY,
                  success_reset: int = DEFAULT_SUCCESS_RESET,
                  jitter: float = DEFAULT_JITTER,
                  step: float = DEFAULT_STEP,
                  cluster_window: float = DEFAULT_CLUSTER_WINDOW,
                  decay_cooldown: float = DEFAULT_DECAY_COOLDOWN,
                  bucket_decay_every_n_windows: int = DEFAULT_BUCKET_DECAY_EVERY_N_WINDOWS,
                  bucket_capacity: int = DEFAULT_BUCKET_CAPACITY,
                  bucket_refill_per_sec: float = DEFAULT_BUCKET_REFILL_PER_SEC,
                  bucket_min_refill_per_sec: float = DEFAULT_BUCKET_MIN_REFILL_PER_SEC,
                  enabled: bool = True):
        if base_delay < 0:
            raise ValueError('base_delay must be >= 0')
        if max_delay < base_delay:
            raise ValueError('max_delay must be >= base_delay')
        if success_reset < 1:
            raise ValueError('success_reset must be >= 1')
        if bucket_decay_every_n_windows < 1:
            raise ValueError('bucket_decay_every_n_windows must be >= 1')
        self.tenant_label = tenant_label or 'unknown'
        self.base_delay = float(base_delay)
        self.max_delay = float(max_delay)
        self.success_reset = int(success_reset)
        self.jitter = max(float(jitter), 0.0)
        self.step = max(float(step), 0.0)
        self.cluster_window = max(float(cluster_window), 0.0)
        self.decay_cooldown = max(float(decay_cooldown), 0.0)
        self.bucket_decay_every_n_windows = int(bucket_decay_every_n_windows)
        self.enabled = bool(enabled)

        self.current_delay = self.base_delay
        self.consecutive_ok = 0
        self.throttle_events = 0
        self.clustered_events = 0
        self.total_sleep = 0.0
        self._in_call_events = 0
        # Windows of success_reset clean calls completed since the
        # last throttle. Used to gate bucket decay asymmetrically
        # relative to delay decay.
        self._clean_windows_since_hit = 0
        # None = no hit yet. We can't use 0.0 because tests (and real
        # monotonic on cold boot) can genuinely be at t=0.
        self._last_hit_time: Optional[float] = None
        self._lock = threading.Lock()

        # Burst-bound gate. acquire() runs BEFORE each SDK call fires,
        # so the token bucket's refill rate governs sustained
        # throughput and its capacity governs how many back-to-back
        # calls can land before we start throttling ourselves.
        self.bucket = TokenBucket(
            capacity=int(bucket_capacity),
            refill_per_sec=float(bucket_refill_per_sec),
            min_refill_per_sec=float(bucket_min_refill_per_sec),
            label=self.tenant_label,
        )

    # ─── Signal ingress ────────────────────────────────────────────

    def begin_call(self) -> None:
        with self._lock:
            self._in_call_events = 0

    def record_log_event(self, message: str = '') -> None:
        """Called by the logging handler when a 'Throttled (attempt' log
        record is observed during an SDK call."""
        with self._lock:
            self._in_call_events += 1

    def end_call(self, *, hit: bool = False,
                  now: Optional[float] = None) -> None:
        """Finalize accounting for one SDK call.

        `hit=True` when the caller saw a transient exception; OR'd with
        any log-record events ingested during the call. `now` is
        injectable for tests — defaults to time.monotonic().

        Clustering: when a hit lands within `cluster_window` seconds of
        the previous hit, apply exponential growth (double current_delay
        or +step, whichever is larger) instead of linear +step. A
        sustained burst converges in O(log N) instead of O(N) — much
        faster than Commander's internal 30s backoff ladder.
        """
        from time import monotonic
        now = monotonic() if now is None else float(now)
        with self._lock:
            effective_hit = hit or self._in_call_events > 0
            if effective_hit:
                self.throttle_events += max(self._in_call_events, 1)
                self.consecutive_ok = 0
                is_cluster = (self._last_hit_time is not None
                               and (now - self._last_hit_time)
                                   <= self.cluster_window)
                self._last_hit_time = now
                if is_cluster:
                    self.clustered_events += 1
                if self.current_delay < self.max_delay:
                    if is_cluster:
                        # Exponential: double current, floor at +step
                        proposed = max(self.current_delay * 2,
                                       self.current_delay + self.step)
                    else:
                        proposed = self.current_delay + self.step
                    new_delay = min(self.max_delay, proposed)
                    if new_delay != self.current_delay:
                        logging.warning(
                            'adaptive-throttle[%s]: +%.1fs → %.1fs '
                            '(throttle hit%s)',
                            self.tenant_label,
                            new_delay - self.current_delay,
                            new_delay,
                            ', clustered' if is_cluster else '',
                        )
                    self.current_delay = new_delay
                # Tell the bucket to slow down too. Clustered hits
                # halve refill; isolated hits cut 10 %.
                self.bucket.on_hit(clustered=is_cluster)
                # Reset the clean-window counter so bucket decay
                # restarts its wait after this fresh hit.
                self._clean_windows_since_hit = 0
            else:
                self.consecutive_ok += 1
                # Cooldown gate: even when we hit success_reset clean
                # calls, don't decay the delay if we're still within
                # decay_cooldown seconds of the last throttle. This
                # prevents the 2026-04-22 oscillation where "20 clean
                # calls → decay → throttle → +step" formed a steady
                # cycle without forward progress.
                cooldown_ok = (self._last_hit_time is None
                                or (now - self._last_hit_time)
                                    >= self.decay_cooldown)
                # Window crossed: decide on delay decay + bucket decay
                # independently. Delay-decay is gated on cooldown AND
                # (current > base). Bucket-decay is gated only on
                # cooldown — so bucket can keep ticking up toward its
                # initial refill even after the delay has already
                # reached base_delay and stops changing.
                if (self.consecutive_ok >= self.success_reset
                        and cooldown_ok):
                    self.consecutive_ok = 0
                    self._clean_windows_since_hit += 1
                    if self.current_delay > self.base_delay:
                        # Decay one step back toward base. Grow fast,
                        # shrink slow. Matches kc_call.
                        new_delay = max(self.base_delay,
                                         self.current_delay - self.step)
                        logging.warning(
                            'adaptive-throttle[%s]: -%.1fs → %.1fs (%d '
                            'clean calls)',
                            self.tenant_label,
                            self.current_delay - new_delay, new_delay,
                            self.success_reset * self._clean_windows_since_hit,
                        )
                        self.current_delay = new_delay
                    # Bucket decays asymmetrically — only every Nth
                    # clean window. The delay is a post-call pace
                    # (easily relaxed); the bucket is a burst cap
                    # that stays sticky until we're really sure.
                    if (self._clean_windows_since_hit
                            % self.bucket_decay_every_n_windows == 0):
                        self.bucket.on_clean_window()
            self._in_call_events = 0

    # ─── Pacing ────────────────────────────────────────────────────

    def acquire(self, sleeper: Callable[[float], None] = time.sleep,
                 now_fn: Callable[[], float] = time.monotonic) -> float:
        """Block until a token is available for the next SDK call.

        Called BEFORE cmd.execute() fires. This is the burst-bound
        half of the throttle — it prevents the SDK's internal N-call
        bursts from blowing the tenant's burst budget. The
        post-call sleep() is the other half, reacting to throttle
        events that still slip through.

        Returns the wait duration. No-op (returns 0) when disabled.
        """
        if not self.enabled:
            return 0.0
        waited = self.bucket.acquire(sleeper=sleeper, now_fn=now_fn)
        with self._lock:
            self.total_sleep += waited
        return waited

    def sleep(self, sleeper: Callable[[float], None] = time.sleep) -> float:
        """Sleep the paced amount and return the wait duration.

        No-op (returns 0.0) when the throttle is disabled.
        """
        if not self.enabled:
            return 0.0
        with self._lock:
            wait = self.current_delay
            if self.jitter:
                wait += random.uniform(0.0, self.jitter)
        if wait <= 0:
            return 0.0
        sleeper(wait)
        with self._lock:
            self.total_sleep += wait
        return wait

    # ─── Observability ─────────────────────────────────────────────

    def state(self) -> dict:
        with self._lock:
            return {
                'tenant': self.tenant_label,
                'enabled': self.enabled,
                'current_delay': round(self.current_delay, 3),
                'base_delay': self.base_delay,
                'max_delay': self.max_delay,
                'consecutive_ok': self.consecutive_ok,
                'throttle_events': self.throttle_events,
                'clustered_events': self.clustered_events,
                'total_sleep_seconds': round(self.total_sleep, 3),
                'bucket': self.bucket.state(),
            }

    # ─── Registry plumbing ─────────────────────────────────────────

    _registry: Dict[Tuple[str, str], 'AdaptiveThrottle'] = {}
    _registry_lock = threading.Lock()
    _default_config: dict = {
        'base_delay': DEFAULT_BASE_DELAY,
        'max_delay': DEFAULT_MAX_DELAY,
        'success_reset': DEFAULT_SUCCESS_RESET,
        'jitter': DEFAULT_JITTER,
        'step': DEFAULT_STEP,
        'cluster_window': DEFAULT_CLUSTER_WINDOW,
        'decay_cooldown': DEFAULT_DECAY_COOLDOWN,
        'bucket_decay_every_n_windows': DEFAULT_BUCKET_DECAY_EVERY_N_WINDOWS,
        'bucket_capacity': DEFAULT_BUCKET_CAPACITY,
        'bucket_refill_per_sec': DEFAULT_BUCKET_REFILL_PER_SEC,
        'bucket_min_refill_per_sec': DEFAULT_BUCKET_MIN_REFILL_PER_SEC,
        'enabled': True,
    }

    @classmethod
    def configure_defaults(cls, **kwargs) -> None:
        """Set the config applied to newly-created throttles.

        Existing throttles keep their original config — call
        `reset_registry()` first if you want every tenant to pick up
        new defaults.
        """
        for k, v in kwargs.items():
            if k not in cls._default_config:
                raise KeyError(f'unknown throttle config key: {k}')
            cls._default_config[k] = v

    @classmethod
    def get_defaults(cls) -> dict:
        return dict(cls._default_config)

    @classmethod
    def for_params(cls, params) -> 'AdaptiveThrottle':
        """Return the singleton throttle for the tenant `params` points
        at. `params.server` + `params.user` is the identity key.
        """
        key = cls._key_for(params)
        with cls._registry_lock:
            inst = cls._registry.get(key)
            if inst is None:
                server, user = key
                label = f'{user}@{server}' if user else server or 'unknown'
                inst = cls(tenant_label=label, **cls._default_config)
                cls._registry[key] = inst
            return inst

    @staticmethod
    def _key_for(params) -> Tuple[str, str]:
        server = getattr(params, 'server', '') or ''
        user = getattr(params, 'user', '') or ''
        return (server, user)

    @classmethod
    def reset_registry(cls) -> None:
        with cls._registry_lock:
            cls._registry.clear()

    @classmethod
    def registry_snapshot(cls) -> dict:
        with cls._registry_lock:
            return {f'{u}@{s}' if u else s: t.state()
                    for (s, u), t in cls._registry.items()}


# ─── Token bucket ──────────────────────────────────────────────────


class TokenBucket:
    """Classic token-bucket rate limiter with adaptive refill.

    Why
    ---
    `AdaptiveThrottle.sleep()` paces the AVERAGE inter-call interval
    but doesn't bound bursts. Structure's step_enforcements loop (and
    step_managed_nodes + step_role_users + step_role_teams) fires
    dozens of `_call`s per role in tight sequence — the per-role work
    is domain-level, not plugin-level: each Keeper role carries ~40
    enforcements, each managed node has ~3 privileges, each priv is
    an API call. `_call` rate-limits individually, but without a
    per-tenant gate those N calls still hit the API within seconds of
    each other and drain the tenant's burst budget.

    Mechanism
    ---------
    - `capacity` tokens fit in the bucket. A fresh run starts full.
    - `refill_per_sec` tokens are added continuously (fractional
      refill is tracked by delta-time multiplication).
    - `acquire()` waits until at least one token is available, then
      decrements.
    - `on_hit(clustered)` lowers refill when the outer throttle
      detects a throttle event — clustered hits halve it, isolated
      ones cut 10%, never below `min_refill_per_sec`.
    - `on_clean_window()` restores 10% of the starting refill after
      each clean window signal, capped at the starting rate.

    Thread safety
    -------------
    Lock-guarded. Commander plugin usage is single-threaded but the
    lock is cheap.
    """

    def __init__(self, *, capacity: int, refill_per_sec: float,
                  min_refill_per_sec: float, label: str = ''):
        if capacity < 1:
            raise ValueError('capacity must be >= 1')
        if refill_per_sec <= 0:
            raise ValueError('refill_per_sec must be > 0')
        if min_refill_per_sec <= 0 or min_refill_per_sec > refill_per_sec:
            raise ValueError(
                'min_refill_per_sec must be > 0 and <= refill_per_sec')
        self.capacity = int(capacity)
        self.initial_refill = float(refill_per_sec)
        self.refill_per_sec = float(refill_per_sec)
        self.min_refill_per_sec = float(min_refill_per_sec)
        self.label = label
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()
        # Diagnostics
        self.waits = 0
        self.total_wait = 0.0

    def _refill(self, now: float) -> None:
        # Caller holds self._lock
        elapsed = max(0.0, now - self.last_refill)
        self.tokens = min(float(self.capacity),
                           self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now

    def acquire(self, sleeper: Callable[[float], None] = time.sleep,
                 now_fn: Callable[[], float] = time.monotonic) -> float:
        """Block until a token is available, then consume one.

        Returns the total time spent waiting. When a token is already
        available, returns 0 immediately.
        """
        waited = 0.0
        while True:
            with self._lock:
                now = now_fn()
                self._refill(now)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    if waited > 0:
                        self.waits += 1
                        self.total_wait += waited
                    return waited
                # Compute sleep for exactly one-token deficit
                deficit = 1.0 - self.tokens
                sleep_for = deficit / self.refill_per_sec
            # Release lock during sleep
            sleeper(sleep_for)
            waited += sleep_for

    def on_hit(self, *, clustered: bool) -> None:
        with self._lock:
            before = self.refill_per_sec
            if clustered:
                new_rate = max(self.min_refill_per_sec,
                                self.refill_per_sec / 2.0)
            else:
                new_rate = max(self.min_refill_per_sec,
                                self.refill_per_sec * 0.9)
            if new_rate != before:
                logging.warning(
                    'token-bucket[%s]: refill %.3f → %.3f tok/s '
                    '(%s throttle)',
                    self.label, before, new_rate,
                    'clustered' if clustered else 'isolated',
                )
            self.refill_per_sec = new_rate

    def on_clean_window(self) -> None:
        with self._lock:
            if self.refill_per_sec >= self.initial_refill:
                return
            new_rate = min(self.initial_refill,
                            self.refill_per_sec * 1.1)
            self.refill_per_sec = new_rate

    def state(self) -> dict:
        with self._lock:
            return {
                'capacity': self.capacity,
                'tokens': round(self.tokens, 3),
                'refill_per_sec': round(self.refill_per_sec, 4),
                'initial_refill': round(self.initial_refill, 4),
                'waits': self.waits,
                'total_wait': round(self.total_wait, 3),
            }


# ─── Scoped logging handler ────────────────────────────────────────


class ThrottleLogCapture:
    """Context manager that routes `logging.warning('Throttled (attempt'
    …)` records into an AdaptiveThrottle for the duration of a call.

    Installed on the ROOT logger because Commander uses
    `logging.warning(...)` directly rather than a named logger at
    `rest_api.py:273`. The handler forwards nothing else — records pass
    through unmodified because we don't set `propagate=False` anywhere.

    `log_marker` overrides the substring matched against WARNING records
    for embedding contexts where the upstream SDK uses a different
    phrase. Defaults to `THROTTLE_LOG_MARKER` (Commander's current
    phrasing). See `THROTTLE_EMBEDDING.md` for usage outside the plugin.
    """

    def __init__(self, throttle: AdaptiveThrottle,
                 log_marker: str = THROTTLE_LOG_MARKER):
        self.throttle = throttle
        self.log_marker = log_marker
        self._handler: Optional[logging.Handler] = None

    def __enter__(self):
        self._handler = _Handler(self.throttle, self.log_marker)
        logging.getLogger().addHandler(self._handler)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._handler is not None:
            logging.getLogger().removeHandler(self._handler)
            self._handler = None
        return False


class _Handler(logging.Handler):
    def __init__(self, throttle: AdaptiveThrottle,
                 log_marker: str = THROTTLE_LOG_MARKER):
        super().__init__(level=logging.WARNING)
        self._throttle = throttle
        self._log_marker = log_marker

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:                                 # noqa: BLE001
            return
        if self._log_marker in msg:
            self._throttle.record_log_event(msg)


# ─── Silent-failure capture ────────────────────────────────────────


# Default markers Commander emits via `logging.warning()` when it
# decides NOT to perform the requested operation but returns success
# anyway. Without capturing these, the plugin treats the call as
# SUCCESS even though nothing changed on the tenant. See 2026-04-22
# full-tenant run: `Add/Remove managed node privilege: invalid
# privilege: privilege_access` logged + normal return → _call returned
# True → priv counted as SUCCESS. Classifier never ran because ok=True.
#
# With `SilentFailureCapture` active, any matching warning during
# cmd.execute() converts the call result to False (failed) + populates
# `_LAST_CALL_ERROR` with the message so the classifier can route it
# to SKIPPED/FAILED appropriately.
#
# These markers are migration-flow specific. Embedding contexts
# (Commander team adopting the AdaptiveThrottle, downstream tooling)
# pass their own list to `SilentFailureCapture(markers=...)` — the
# substring-match mechanism is generic; the vocabulary is consumer-
# owned. See `THROTTLE_EMBEDDING.md` for the embedding contract.
SILENT_FAILURE_MARKERS = (
    'invalid privilege',
    'invalid enforcement',
    'is not found: skipping',
    'does not manage node',
    'is skipped. expected format',   # enforcement value in wrong
                                      # shape (e.g. dict-valued
                                      # restrict_record_types rejected
                                      # by the KEY:[VALUE] parser).
                                      # Fix pending in v1.4.1 — route
                                      # dict-valued enforcements
                                      # through enforcement_direct.
                                      # Until then mark as SKIPPED.
    'expects "login"',                # two_factor_duration_*
                                      # enforcements: server expects
                                      # CLI keywords ("login",
                                      # "12_hours", "24_hours",
                                      # "30_days", "forever") but
                                      # source data emits the internal
                                      # storage format ("0,12,24").
                                      # Documented in Gap 2 of
                                      # commander-docs-gaps.md.
    'failed to grant admin privileges',  # operator lacks the
                                          # privilege to assign
                                          # managed_node to a role.
                                          # Without this catch the
                                          # operator's privileges
                                          # silently disappear in
                                          # migration. Surfaced
                                          # 2026-04-26 by golden-role
                                          # walkthrough on EU demo.
    'is not an admin role',           # `require_account_share`
                                       # enforcement applied to a
                                       # role lacking managed_nodes.
                                       # Server logs warning, plugin
                                       # silently records SUCCESS.
                                       # Surfaced same walkthrough.
    'not a valid site',               # server-side URL validation
                                       # rejection (warn_/restrict_
                                       # _business_sites enforcements).
    'not a valid domain',             # server-side domain validation
                                       # rejection (warn_/restrict_
                                       # _business_domains enforcements).
    'cannot update enforcement',     # generic Commander rejection
                                      # phrasing for enforcement set
                                      # operations that the API
                                      # ultimately rejects.
    'teams cannot be assigned to roles with administrative permissions',
                                      # Bug 13 — admin/team mutual
                                      # exclusion. Server logs this
                                      # when add_team_to_role hits a
                                      # role that already carries
                                      # managed_nodes; without the
                                      # capture the plugin returns ok
                                      # and the link silently never
                                      # lands.
    'no objects provided',            # Same Bug-13 surface — alternate
                                      # phrasing Commander uses for
                                      # the same admin/team rejection.
                                      # Generic enough that we keep
                                      # the marker scoped via the
                                      # classifier downstream.
)
# Backwards-compat alias — kept for any downstream importer that
# referenced the private name. New code uses `SILENT_FAILURE_MARKERS`.
_SILENT_FAILURE_MARKERS = SILENT_FAILURE_MARKERS


class SilentFailureCapture:
    """Context manager that installs a logging handler to detect the
    "logged a warning, gave up silently" patterns produced by an SDK
    or service the consumer is calling through.

    Usage:
        cap = SilentFailureCapture()                 # default markers
        with cap:
            cmd.execute(params, **kwargs)
        if cap.message:
            return False, cap.message

        # Or with consumer-owned markers (embedding contexts, e.g. the
        # Commander team adopting the throttle without inheriting the
        # plugin's migration-flow vocabulary):
        cap = SilentFailureCapture(markers=('your-app: skipped',
                                            'permission denied: skipping'))
    """

    def __init__(self, markers=None):
        # Normalize once, lowercased, so the per-record loop is hot-path
        # cheap. None = default plugin/migration vocabulary.
        self.markers = (
            tuple(m.lower() for m in markers)
            if markers is not None
            else SILENT_FAILURE_MARKERS
        )
        self.message: str = ''
        self._handler: Optional[logging.Handler] = None

    def __enter__(self):
        self._handler = _SilentHandler(self)
        logging.getLogger().addHandler(self._handler)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._handler is not None:
            logging.getLogger().removeHandler(self._handler)
            self._handler = None
        return False


class _SilentHandler(logging.Handler):
    def __init__(self, capture: SilentFailureCapture):
        super().__init__(level=logging.WARNING)
        self._cap = capture

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:                                 # noqa: BLE001
            return
        low = msg.lower()
        for marker in self._cap.markers:
            if marker in low:
                # Only capture the FIRST one — if the same _call
                # triggers multiple silent skips, one diagnostic is
                # enough to route the classifier.
                if not self._cap.message:
                    self._cap.message = msg
                return


# ─── Convenience helpers ───────────────────────────────────────────


def is_throttle_exception(exc: BaseException) -> bool:
    """True when `exc` is a KeeperApiError with throttled result_code,
    OR a generic exception whose message contains a throttle marker.

    Kept loose because the SDK isn't fully typed — a string-sniffing
    fallback catches cases where a library layer re-raises as a plain
    Exception."""
    if exc is None:
        return False
    rc = getattr(exc, 'result_code', '') or ''
    if isinstance(rc, str) and rc.lower() in (
            'throttled', 'too_many_requests'):
        return True
    msg = (str(exc) or '').lower()
    return 'throttled' in msg or 'too many requests' in msg or '429' in msg
