# 04 — Concurrent `declare overlay` runs against the same base inventory

## Attack

Two `keeper-migrate ... declare overlay` invocations run **concurrently** against the same `inventory.json` base file, e.g. two operators running the same workflow on the same shared host, or a CI job racing with an interactive operator. The overlay engine's read-then-write of `inventory.edited.json` is non-atomic — depending on timing, one operator's edits silently overwrite the other's, or the output file ends up with mixed-write content if both processes write simultaneously.

If an attacker can force the race (e.g. by knowing operator schedules + holding a malicious `edits.yaml` ready to fire at the same moment), they can make their overlay land while the legitimate one disappears.

## Pre-condition

- Two `declare overlay` processes running concurrently on the same base inventory
- Output path is the same (or in the same dir with predictable naming)
- No file-lock around the read-edit-write cycle

## Defense

1. **File-lock around the engine** — the overlay engine should acquire an exclusive lock on the output path before writing (and on the base inventory's parent dir during read, if same-dir output is in play). Implementation pattern: `fcntl.flock` on a sidecar `.lock` file.
2. **Deterministic timestamped output naming** — even with locking, recommending operators use timestamped output paths (`inventory.edited.<YYYY-MM-DDTHH-MM-SS>.json`) reduces the collision surface entirely; the `OPERATOR_PLAYBOOK.md` Workflow D guidance can pre-suggest this.
3. **Engine timing** is already negligible (validate 3.39 ms, overlay 121.49 ms on a 925 KB / 1161-record inventory per Scope A) — race window is small but not zero.
4. **`SHA256SUMS.txt` post-write** — if implemented to cover `inventory.edited.json`, mismatch detection picks up partial-write artifacts.

## Pinning test

**TODO** — write a test that:
1. Spawns two `declare overlay` subprocesses targeting the same base + same output path with different `edits.yaml` files.
2. Asserts: either the second one fails with a clear lock-busy error, or the output file contains a fully-applied edit-set from one of the two (not a mix).
3. Should live in `keeper_tenant_migrate/declare/tests/test_declare_concurrency.py` (new file on the spike branch when Phase 1.2 ships).

## Status

🟡 **needs file-lock test** — defense is partially structural (deterministic output paths) but the lock itself is a TODO.

## Affected phase / opportunity

Phase 1 — declare-overlay wedge red-team review. Pinning test fits naturally as part of Phase 1.2 expansion (D11 -> Phase 3 in execution plan).

## Owner

Bob (keeperCMD-side) — overlay engine is in keeperCMD's `declare/` package.
