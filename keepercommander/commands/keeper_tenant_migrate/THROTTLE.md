# Throttle behavior — adaptive rate limiting

`tenant-migrate auto-migrate` makes thousands of API calls against
Keeper Commander during a typical migration. Some Keeper tenants
have aggressive per-tenant rate limits (MSP / EU / disposable test
tenants in particular). This document explains how the plugin
auto-tunes its outbound rate to stay below the server's throttle
threshold without operator intervention.

---

## TL;DR

The plugin runs two layered mechanisms in parallel:

1. **Token bucket** — hard cap on burst rate. Set via
   `--calls-per-minute` + `--burst-capacity`. Like a leaky-bucket
   filter on outbound calls.
2. **Adaptive delay** — closed-loop control on per-call sleep time.
   Grows on `result_code='throttled'` responses, decays after N
   clean calls. Set via `--adaptive-base-delay`,
   `--adaptive-max-delay`, `--adaptive-success-reset`.

Default behavior auto-discovers the steady-state rate that keeps the
server happy. For a 1000-ops/hour tenant, the loop converges to ~3.6
seconds per call within ~5 minutes of warm-up.

---

## Token bucket

**Purpose:** prevents bursts above a known sustained ceiling.

```
              ┌─────────────────┐
   API call ──┤ remove 1 token  ├── send to server
              │ wait if empty   │
              └─────────────────┘
                     ▲
              refill rate (tokens/sec)
```

Configurable via:

| Flag | Default | Meaning |
|---|---|---|
| `--calls-per-minute N` | 0 (disabled) | Sustained ceiling. 16/min = 960/hour. |
| `--burst-capacity N` | 3 | Max consecutive calls before bucket empties. |

When `--calls-per-minute` is unset, the bucket uses an "initial-refill"
default of 0.5 tokens/sec (≈ 30/min) — generous, suitable for most
production tenants. Lower it explicitly when working against a hard
per-tenant ceiling.

### Math

```
calls_per_minute = N
refill_rate      = N / 60       (tokens/sec)
burst_window_sec = capacity / refill_rate
```

Example: `--calls-per-minute 16 --burst-capacity 3`
- Refill: 0.267 tokens/sec
- Burst window: 11.25s (drain bucket → wait this long for next burst)
- Sustained: 960/hour

---

## Adaptive delay (closed-loop control)

**Purpose:** discovers and tracks the server's actual throttle
threshold without operator pre-knowledge of the limit.

```
        Send call
            ↓
    ┌─── server response ───┐
    ↓                       ↓
 ok / clean             throttled
    ↓                       ↓
 inc clean_count       grow delay
    ↓                       ↓
 if clean_count >= N   delay += step
   shrink delay        clamp to max_delay
   reset clean_count   reset clean_count
    ↓                       ↓
    └────── sleep ─────────┘
            ↓
        Next call
```

Configurable via:

| Flag | Default | Meaning |
|---|---|---|
| `--adaptive-base-delay S` | 2.0 | Starting per-call delay. |
| `--adaptive-max-delay S` | 30.0 | Cap on grown delay. |
| `--adaptive-success-reset N` | 20 | Clean calls before decay step. |
| `--cluster-window S` | 120.0 | Window for clustered-throttle detection. |
| `--decay-cooldown S` | 60.0 | Min seconds between decay events. |
| `--bucket-decay-every-n-windows N` | 3 | Token-bucket refill decay frequency. |
| `--no-adaptive-throttle` | (off) | Disable adaptive delay (keep token bucket only). |

### How growth works

Each `KeeperApiError` with `result_code='throttled'`:
- Wait the existing `current_delay`
- Increment `current_delay` by `step` (default 1.0s)
- Cap at `max_delay`
- Reset clean-call counter to 0

Multiple throttle events within `--cluster-window` are treated as a
single cluster — only the first contributes a step (avoids
overshoot during a server-side backoff cluster).

### How decay works

Every `--adaptive-success-reset` clean calls (no throttle):
- Decrement `current_delay` by `step`
- Reset clean-call counter

Every `--bucket-decay-every-n-windows` clean windows (no throttle):
- Slightly reduce token-bucket refill rate (defaults to 0.5 tok/sec
  initial → can decay down to base-delay-derived rate)

### Steady-state convergence

For a server limit of `R` ops/hour, the loop converges to:
```
steady_delay ≈ 3600 / R
```

Convergence path against an unknown ceiling:
1. Start at `base_delay` (default 2.0s)
2. Hit throttle → grow → grow → ... until calls succeed
3. Clean calls accumulate → decay → settle at threshold

Typical warm-up: 1-3 minutes of throttle hits, then 5-30 minutes of
steady-state oscillation around the limit.

---

## Reading throttle logs

The plugin emits these lines:

```
adaptive-throttle: on — base=2.00s max=30.0s reset@20 clean calls
                          step=1.0s jitter=0.5s cluster_window=120s
                          decay_cooldown=60s bucket_decay=3 windows
token-bucket: capacity=3 refill=0.500 tok/s (30.0 cpm) min_refill=0.083 tok/s

# After throttle hits:
adaptive-throttle[user@tenant]: +1.0s → 3.0s (throttle hit)
adaptive-throttle[user@tenant]: +1.0s → 4.0s (throttle hit)

# After 20 clean calls:
adaptive-throttle[user@tenant]: -1.0s → 3.0s (20 clean calls)
```

Final stage summary:
```
adaptive-throttle[user@tenant] summary: N events,
    peak Xs (current Ys), total sleep Zs
```

Look for:
- **Throttle events count**: 0-3 = clean tenant; 10+ = aggressive limit
- **Peak vs current**: large gap = oscillation; close = steady-state found
- **Total sleep**: indicator of how much wall-clock the throttle cost

---

## Tuning guide

### Known per-hour limit

If you know the target tenant's ceiling (e.g. 1000 ops/hour from
support docs):

```bash
# 14/min = 840/hour (15% headroom under 1000)
--calls-per-minute 14
--burst-capacity 5

# Pre-tune adaptive starting point near steady-state
--adaptive-base-delay 4.0     # 3600/14/60 = ~4.3s
--adaptive-max-delay 60       # tolerate hard backoffs
--adaptive-success-reset 30   # decay slower (less overshoot)
```

### Unknown limit, MSP/EU target

Conservative defaults work; the loop discovers the right pace:
```bash
# (defaults — no flags needed)
```

### High-throughput, generous tenant

For dev/test tenants with ample quota:
```bash
--no-adaptive-throttle        # token bucket only
--calls-per-minute 60         # 1/sec sustained
--burst-capacity 10           # allow bigger bursts
```

### Hard lockout recovery

Some Keeper backends impose 5-10 min cooldowns after sustained
throttle. Increase max_delay to ride them out:
```bash
--adaptive-max-delay 300      # 5-min ceiling on per-call delay
--cluster-window 600          # treat throttle clusters more conservatively
```

---

## Adjacent: chunked records-import (Bug 68 / v1.6.2)

The records-import phase was historically one big batched call →
no inter-call gap → MSP target rate-limit accumulated. Bug 68
splits the bundle into chunks with explicit `time.sleep()` between:

```bash
--import-chunk-size 100        # records per chunk
--import-chunk-delay 2.0       # seconds between chunks
```

This mirrors the pacing pattern observed in upstream `pam-import`
(every mutation followed by `api.sync_down()`), but with explicit
`time.sleep()` instead of full vault re-syncs (latter would cost
megabytes of read bandwidth per call).

---

## Limitations

- **Reactive, not predictive** — the loop only sees `throttled`
  responses. There's no "remaining quota" telemetry from Keeper, so
  calibration takes some throttle hits to find the floor.
- **Hard lockouts** — adaptive delay can't shorten a server-side
  cooldown, only wait it out. Set `--adaptive-max-delay` high enough
  to ride them.
- **No per-call payload weighting** — a `vault/records_add` for
  1000 records is treated the same as a single `node/get`. Server
  may rate-limit the heavy call disproportionately.
- **Not reusable from upstream** — pam-import's `sync_down`-between-
  mutations pattern was the inspiration but not the implementation;
  this is purely keeperCMD's own code (`keeper_tenant_migrate/
  throttle.py` + `backoff.py`).

---

## Related files

- `keeper_tenant_migrate/throttle.py` — `AdaptiveThrottle` class +
  token bucket
- `keeper_tenant_migrate/backoff.py` — `Retry` helper used by
  attachments-download/upload + records-shares
- `keeper_tenant_migrate/commands.py` — auto-migrate parser flags
  (search `adaptive-` and `calls-per-minute`)
- `keeper_tenant_migrate/auto_migrate.py` — `RunConfig.adaptive_*`
  fields + per-stage delay overrides
- `keeper_tenant_migrate/AUTOMATED_ADJUSTMENT.md` — wizard
  Phase-5 static pacing (older doc; this file supersedes for the
  adaptive layer)
