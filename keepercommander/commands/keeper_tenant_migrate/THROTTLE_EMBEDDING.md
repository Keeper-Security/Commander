# Embedding `throttle.py` outside the plugin

`keepercommander.commands.keeper_tenant_migrate.throttle` is the plugin's adaptive inter-call
pacer + token bucket + log-handler integration. The module has no
internal dependencies on the rest of the plugin (zero
`from keepercommander.commands.keeper_tenant_migrate.*` imports) and uses only the Python
stdlib plus duck-typed access to a session-like object's `server` /
`user` attributes.

This document is the contract for embedding it into:

- The Keeper Commander team's own tooling, if they want a turnkey
  per-tenant adaptive throttle.
- Migration-adjacent tooling (bulk record import benchmark, tenant-
  cleanup CLIs, third-party Commander wrappers).
- Tests that need a deterministic seam without monkeypatching.

---

## Public API surface

```python
from keepercommander.commands.keeper_tenant_migrate.throttle import (
    AdaptiveThrottle,            # core pacer
    TokenBucket,                  # burst rate limiter (composed in AdaptiveThrottle)
    ThrottleLogCapture,           # context manager: forwards SDK throttle warnings
    SilentFailureCapture,         # context manager: detects logged-but-silent failures
    is_throttle_exception,        # bool helper for transient SDK exceptions
    THROTTLE_LOG_MARKER,          # default substring matched in WARNING records
    SILENT_FAILURE_MARKERS,       # default tuple of silent-skip phrases
)
```

`AdaptiveThrottle.for_params(params)` requires `params.server` and
`params.user`. Anything that walks like a Commander session works.
For non-session contexts, construct directly:

```python
throttle = AdaptiveThrottle(tenant_label='ci-bench', enabled=True)
```

---

## Call lifecycle

```python
throttle = AdaptiveThrottle.for_params(params)

throttle.acquire()          # bucket gate before the call fires
throttle.begin_call()
hit = False
try:
    with ThrottleLogCapture(throttle):
        result = your_sdk_call(...)
except Exception as e:
    if is_throttle_exception(e):
        hit = True
    raise
finally:
    throttle.end_call(hit=hit)
    throttle.sleep()        # paces the NEXT call
```

`ThrottleLogCapture` installs a scoped `logging.Handler` on the root
logger. It detects the SDK's own retry path (Commander logs
`'Throttled (attempt %d/%d), retrying in %d seconds'` from
`rest_api.py:273`) and feeds those signals back into the throttle so
adaptive backoff sees BOTH bubbled-up exceptions AND in-SDK retries
that succeed silently.

---

## Configuring the markers

The marker substrings are CONSUMER-OWNED. Defaults track Commander's
current vocabulary; embedding contexts pass their own.

### Throttle log marker

```python
ThrottleLogCapture(throttle, log_marker='RateLimited(')   # custom phrase
```

When the upstream SDK changes its log format, override at the call
site without modifying the throttle module.

### Silent-failure markers

```python
cap = SilentFailureCapture(markers=(
    'your-svc: permission denied',
    'requested entity not found',
))
with cap:
    sdk_call(...)
if cap.message:
    # SDK silently skipped — treat as failure.
    raise YourFailure(cap.message)
```

The default `SILENT_FAILURE_MARKERS` tuple is migration-flow specific
(e.g. `'is not found: skipping'`, `'cannot update enforcement'`).
Embedding contexts that don't want to inherit the migration
vocabulary pass their own list.

The substring match is case-insensitive (markers are lowercased once
at construction). First match wins; subsequent matches in the same
scope are ignored.

---

## Registry

`AdaptiveThrottle._registry` is a process-wide `Dict[(server, user),
AdaptiveThrottle]`. `for_params(params)` is the canonical entry; it
returns the existing instance for the tenant or creates a new one
using `configure_defaults(...)` knobs.

```python
AdaptiveThrottle.configure_defaults(
    base_delay=2.5,
    max_delay=45.0,
    bucket_capacity=5,
)
# Subsequent for_params() calls pick up the new defaults.
# Existing instances keep their original config — call
# reset_registry() to force re-creation.

AdaptiveThrottle.reset_registry()
```

The registry is intentionally process-global — multiple subprocesses
each have their own. Tests that need isolation call `reset_registry()`
in their setUp.

---

## Stdlib-only

`throttle.py` imports: `logging`, `math`, `random`, `threading`,
`time`, `typing`. Nothing else. It can be vendored into any project
without dragging in `keepercommander` or `keeper_tenant_migrate`
itself.

If you only need the burst gate (no adaptive decay), import
`TokenBucket` directly. If you only need the log capture
(without the throttle), `ThrottleLogCapture` accepts any object with
a `record_log_event(message)` method — duck-typed, not a hard
`AdaptiveThrottle` dependency.

---

## What's NOT in scope for this module

- `keepercommander.api` calls — this module never makes network calls;
  it paces the consumer's calls.
- Server-side throttle headers (X-RateLimit-*) — Keeper's API doesn't
  emit them; the throttle infers from log records and exception
  result_codes.
- Fairness across requesters — single-process single-throttle-per-
  tenant. If you need cross-process coordination, layer a Redis-
  backed token bucket above the in-memory one.

---

## Testing seams

- `AdaptiveThrottle._sleep` defaults to `time.sleep` and is monkey-
  patchable per-instance for tests (`throttle._sleep = lambda s: None`).
- `time.monotonic` is used for hit-clustering; tests inject `now=` into
  `end_call(hit=True, now=42.0)`.
- `ThrottleLogCapture` and `SilentFailureCapture` install handlers on
  the root logger; `tests/test_throttle.py` shows the standard
  `logging.disable(logging.CRITICAL)` pattern in setUp/tearDown.
