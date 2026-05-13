# 02 — Tamper with `manifest.csv` between `keeper-migrate` and `dsk import`

## Attack

Attacker has temporary write access to the migration run-dir (e.g. shell access on the operator's host, or write permission on the shared storage) **after `keeper-migrate` finishes** but **before `dsk import` starts**. Attacker swaps `target_uid` values in `manifest.csv` rows so that records are adopted under the wrong target UID — DSK now claims ownership of an attacker-controlled record, while a legitimately migrated record is left orphan.

## Pre-condition

- Run-dir is on shared storage between `keeper-migrate` and `dsk import` runs (typical operator workflow)
- Attacker has write access during the gap (or via stolen credentials, or via a malicious script in cron, or a poisoned operator host)
- DSK consumes `manifest.csv` without verifying integrity against a sidecar

## Defense

1. **`manifest.csv.sha256` sidecar** (per [`OUTPUT_CONTRACT.md`](../../OUTPUT_CONTRACT.md) v1.1+ § Artifact 2). **STRUCTURAL MITIGATION shipped 2026-05-09 at `keeperCMD:master@674322c`**. Sidecar is emitted at the same moment manifest.csv is written, before any external consumer can act. Closes the previously-open gap "should be extended to cover manifest.csv in a future v1.x increment".
2. **`SHA256SUMS.txt`** (run-dir top-level, per § Artifact 5) covers manifest.csv too — but only after `verify` runs. Sidecar from #1 covers the pre-verify window.
3. **`audit.log`** chain (per `OUTPUT_CONTRACT.md` § Artifact 4, source `audit.py`) records the hash of `manifest.csv` at write-time; tampering invalidates the chain when `verify_audit_log()` runs.
4. **Operator discipline**: `OPERATOR_PLAYBOOK.md` Workflow D Step D.1 prerequisites include `verify_audit_log` + `sha256sum -c` checks before `dsk import` runs — these are explicit checkpoints.
5. **DSK-side defense (Phase 4-A scope)**: `dsk import-from-keepercmd` re-verifies the audit chain + the new sidecar before consuming `manifest.csv`. **SHIPPED at `dsk@61223ee` (B1)** — Midas's converter checks `verify_audit_log()` + `sha256sum -c` per `OUTPUT_CONTRACT.md` consumption pattern. Sidecar verification is recommended for v1.1+ consumers (the converter can adopt this in a small follow-up if not already covered).

## Pinning test

- Tier 1 (existing): `test_adversarial.py::AuditTamperingTests` — pins the chain-verification side.
- Tier 1 (NEW 2026-05-09): `test_manifest.py::WriteManifestCsvTests::test_sha256_sidecar_emitted_for_scenario_02` + `test_sha256_sidecar_detects_tamper` — pins the sidecar emission + tamper-detection.
- Tier 3 (DSK-side): `tests/test_red_team_r23.py::TestScenario02ManifestCsvTamper` — 5 pinning tests. **SHIPPED 2026-05-09 at `dsk@61223ee` (Midas).**

## Status

🟢 **pinned, both sides + structural mitigation shipped.** The original gap ("manifest.csv has no integrity sidecar at write-time") is now structurally closed via the v1.1 sidecar.

## Affected phase / opportunity

Phase 4-A (DSK adopts post-migration records). Cross-product boundary.

## Owner

Midas (DSK) — owns the `dsk import` adoption-gate logic. Bob can provide a tampered-fixture scenario as part of D1 fixture prep if useful.
