# 05 — Operator-host shell access between `plan` and `apply`

## Attack

Attacker has temporary shell access on the operator's host (e.g. via a stolen SSH key, malicious cron, or a poisoned ops-tooling supply chain) for a brief window **between** `keeper-migrate ... declare overlay` (which produces `inventory.edited.json`) and `keeper-migrate ... structure --inventory inventory.edited.json` (which applies the overlay'd inventory to the target tenant). The attacker swaps `inventory.edited.json` with a malicious version — adds a role, changes role bindings, redirects shared-folder permissions — and the apply step lands the attacker's changes on the target.

This is the classic TOCTOU (time-of-check vs time-of-use) attack against operator-host pipelines.

## Pre-condition

- Attacker has shell-level write access to the operator's working directory during the gap between `declare overlay` and `tenant-migrate structure`
- The operator does not re-verify integrity between the two steps

## Defense

1. **`SHA256SUMS.txt` invariant from D2 / `OUTPUT_CONTRACT.md` § Artifact 5** — `declare overlay` should write a SHA-256 sidecar for `inventory.edited.json` at output time. The subsequent `tenant-migrate structure` step should re-verify before applying. **This is the primary defense for this scenario.** Status: SHA-256 covers `records-export/` today; extending to cover `inventory.edited.json` is a v1.x increment.
2. **Workflow D's prerequisite chain** in `OPERATOR_PLAYBOOK.md` covers the `keeper-migrate → dsk` boundary; the same pattern (`audit.log` chain check + sha256sum verify) applies to the `declare overlay → tenant-migrate structure` boundary inside Workflow A/B.
3. **Operator discipline** — the `declare overlay` engine prints the SHA-256 of the output file at exit; the operator pastes it into the next-step invocation as `--expected-inventory-hash`. Manual but cheap.
4. **Air-gap host** — for high-trust migrations, the operator can run the entire pipeline on a host with no inbound network access and locked-down ssh; closes the attack window entirely. Already standard practice per `SECURITY_MODEL.md`.
5. **Short window** — engine timing is negligible (overlay 121.49 ms; structure-apply is the bigger fraction); the gap between overlay output and structure consumption is whatever the operator inserts, so the operator can keep it sub-second in practice.

## Pinning test

- Tier 1 (existing): `test_adversarial.py::SideloadingTests` — covers malformed/malicious inventory injection. Defense is at consume-time validation.
- **TODO** — explicit test for the SHA-256 sidecar invariant on `inventory.edited.json`: write a test that hashes the output, mutates the file out-of-band, and asserts the next-step consumer detects the mismatch.

## Status

🔵 **seeded** — primary defense (SHA-256 sidecar + chain verification) is structural; specific pinning test for `inventory.edited.json` hash is a TODO for Phase 1.2 hardening.

## Affected phase / opportunity

Phase 1 — declare-overlay wedge red-team review. Same defense pattern reused at Phase 4-A boundary (`keeper-migrate → dsk import`).

## Owner

Bob (keeperCMD-side) — SHA-256 sidecar emission is keeperCMD's responsibility; consumers (both `tenant-migrate structure` and `dsk import`) verify on read.
