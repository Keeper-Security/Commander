"""Exponential backoff for transient Keeper API errors.

Wraps the per-call operations in `UserRunner` / `ShareRestorer` /
`AttachmentMigrator` so that a single HTTP 429 / session-expired hit
waits `delay * 2` seconds and retries once. A second consecutive hit
on the same call escalates to `SafeguardBlocked` — at that point the
tenant is clearly overwhelmed and the operator needs to pick a larger
`--delay` before retrying.

Design constraints:
  - Pure function + class — no network; tests inject a `sleeper`.
  - Classification is string-based on top of whatever exception the
    SDK raises. Keeper Commander throws `KeeperApiError(result_code,
    message)` for API-layer failures and plain Python exceptions for
    everything else. We look at the message body for known markers.
  - Non-retryable errors propagate immediately. We never retry a
    CommandError (user-visible rejection) or a ValueError (programmer
    bug).

Usage
-----

    from .backoff import Retry, is_transient

    retry = Retry(delay=2.0, sleeper=time.sleep)
    result = retry.call(lambda: client.invite_user(email, name, node))

The wrapper returns the callable's result on success. On a transient
error it sleeps, retries once, and re-raises on the second hit.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Iterable, Tuple


# Known transient-error markers. Matched case-insensitively against
# str(exc). Add entries as we discover new SDK signatures in the field —
# false-positive retries are harmless, false-negatives hurt throughput.
TRANSIENT_MARKERS: Tuple[str, ...] = (
    'throttled',
    'rate limit',
    'rate-limit',
    'rate_limit',
    'too many requests',
    '429',
    'session expired',
    'session_expired',
    'session is expired',
    'auth_failed',
    'connection reset',
    'timed out',
    'timeout',
    'temporarily unavailable',
)

# Non-transient markers — always fail fast.
FATAL_MARKERS: Tuple[str, ...] = (
    'permission denied',
    'not authorized',
    'forbidden',
    'invalid input',
    'bad request',
)


def _is_allowed_transient_type(exc: BaseException) -> bool:
    """Only these exception classes are eligible for string-based
    transient classification. A programmer bug that happens to have
    '429' or 'timeout' in its message (e.g., `ValueError("waited 429
    ms")`) is NOT a transient — retrying it would hide the bug and
    the second failure would surface as SafeguardBlocked with the
    original type lost. Gate on type first."""
    # Keeper's own API error class — import lazily so this module
    # stays import-free for tests that stub the SDK.
    try:
        from keepercommander.error import KeeperApiError
        if isinstance(exc, KeeperApiError):
            return True
    except ImportError:                               # pragma: no cover
        pass
    # Network / IO layer
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return True
    # http.client.HTTPException covers urllib-level transient issues
    try:
        import http.client
        if isinstance(exc, http.client.HTTPException):
            return True
    except ImportError:                               # pragma: no cover
        pass
    return False


def is_transient(exc: BaseException,
                  transient_markers: Iterable[str] = TRANSIENT_MARKERS,
                  fatal_markers: Iterable[str] = FATAL_MARKERS) -> bool:
    """Return True when the error looks retry-worthy.

    Gate: the exception must be an ALLOWED transient type. A generic
    RuntimeError / ValueError / KeyError is always False — those are
    programmer bugs or unexpected SDK behavior, and retrying them
    converts a helpful stack trace into a confusing SafeguardBlocked.

    Prefers explicit non-transient signal (FATAL_MARKERS) over explicit
    transient signal within the allowed classes, so 'forbidden' always
    fails fast even if the message also mentions 'timeout' for some
    reason. This keeps us safe when an auth error accidentally renders
    a misleading body.
    """
    if exc is None:
        return False
    if not _is_allowed_transient_type(exc):
        return False
    msg = (str(exc) or '').lower()
    for marker in fatal_markers:
        if marker in msg:
            return False
    # Inspect Keeper's structured result_code if present (more precise
    # than string matching).
    rc = getattr(exc, 'result_code', '') or ''
    if isinstance(rc, str):
        rc_l = rc.lower()
        if rc_l in ('throttled', 'too_many_requests', 'session_expired',
                    'auth_failed'):
            return True
    for marker in transient_markers:
        if marker in msg:
            return True
    return False


class Retry:
    """Per-runner helper — owns the retry budget for one logical op.

    A fresh instance per call keeps the "one retry" budget from leaking
    across unrelated ops.

    Idempotency
    -----------
    Retry is safe for operations that are idempotent at the Keeper API
    level — e.g. `share-record -a owner`, `enterprise-team -au EMAIL`,
    `upload-attachment`. Re-running a throttled-then-succeeded call
    produces the same end state.

    It is NOT safe for operations with observable side-effects that
    would duplicate on retry. Examples:
      - `enterprise-user --invite` — sends an email each time Commander
        reaches the invite endpoint.
      - `transfer-user EMAIL` — moves vault records; second call after
        a partial-success first call could re-transfer or error.

    Call sites that wrap non-idempotent ops MUST pass `idempotent=False`
    on the per-call `.call(..., idempotent=False)` invocation OR construct
    the Retry with `max_retries=0` to disable retries entirely. The
    default is `idempotent=True` (callers opt OUT of retry).
    """

    def __init__(self, *, delay: float = 0.0, sleeper: Callable[[float], None] = time.sleep,
                 max_retries: int = 1, backoff_multiplier: float = 2.0):
        self.delay = max(float(delay or 0.0), 0.0)
        self.sleeper = sleeper
        self.max_retries = max_retries
        self.backoff_multiplier = backoff_multiplier

    def call(self, func: Callable[[], Any], *,
              op_label: str = '',
              idempotent: bool = True) -> Any:
        """Invoke `func()` with up to `max_retries` extra attempts on
        transient errors. Raises `SafeguardBlocked` on budget exhaustion
        so the caller's existing safeguard machinery handles the bail.

        `op_label` is an optional human-readable tag used in log lines.
        `idempotent` — pass False for ops with side-effects that would
        duplicate on retry (invite emails, user transfers). When False,
        a transient failure is re-raised immediately without retry so
        the caller records the error without double-firing the side
        effect on the next attempt.
        """
        from .safeguards import SafeguardBlocked

        effective_retries = self.max_retries if idempotent else 0

        last_exc = None
        for attempt in range(effective_retries + 1):
            try:
                return func()
            except BaseException as exc:         # noqa: BLE001
                if not is_transient(exc):
                    raise
                last_exc = exc
                if attempt >= effective_retries:
                    break
                wait = max(self.delay * (self.backoff_multiplier ** attempt),
                            1.0)
                logging.warning(
                    'transient error%s on attempt %d — waiting %.1fs: %s',
                    f' [{op_label}]' if op_label else '',
                    attempt + 1, wait, exc,
                )
                self.sleeper(wait)

        # Budget exhausted (or non-idempotent fast-fail) — escalate.
        raise SafeguardBlocked(
            f'repeated transient error after {effective_retries + 1} '
            f'attempt(s){" [" + op_label + "]" if op_label else ""}: '
            f'{last_exc}. Increase --delay and retry, or wait for '
            'tenant to cool down before re-running.'
        )
