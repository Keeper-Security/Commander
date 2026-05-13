# 03 — Ownership marker forgery — pre-emptive `keeper_declarative_manager` write

## Attack

Attacker writes a `keeper_declarative_manager` custom field to a target-tenant record **before `dsk import` runs** (e.g. via the Web UI, or via Commander API with stolen creds). When `dsk import` then reads the target tenant, it finds records that already carry DSK's ownership marker for an attacker-controlled identifier — DSK skips them as "already managed" and leaves them under the attacker's effective ownership claim. Subsequent `dsk plan` shows no drift on those records (because they're "owned"), masking the rogue state.

## Pre-condition

- Attacker has write access to one or more records on the target tenant before `dsk import`
- DSK accepts `keeper_declarative_manager` fields without cross-validating against `manifest.csv`'s "came from keeperCMD" signal

## Defense

1. **DSK-side cross-validation**: when `manifest.csv` is present in the run-dir (the [D7 marker convention](../../../DSK_INTEGRATION_ANALYSIS.md) signal), DSK should expect target-tenant records that are listed in the UID-map to have **NO pre-existing** `keeper_declarative_manager` field. A pre-existing marker on a row that's also in the manifest UID-map is suspicious — log it, refuse to silently adopt, require operator override (`--accept-pre-existing-marker`).
2. **Operator discipline**: `OPERATOR_PLAYBOOK.md` Workflow D prerequisites include verifying `dsk plan` returns no drift after `dsk import`. If pre-emptive markers are present, the post-import `plan` will show records that DSK thinks are managed but the operator never expected to see — caught at the human-review checkpoint.
3. **Audit-log from migration day**: `keeper-migrate records-import`'s `audit.log` lists exactly which target_uids it created. Cross-referencing with marker presence catches forgeries — markers on uids not created by `records-import` are by definition pre-existing or attacker-injected.

## Pinning test

- Tier 3 (new, DSK-side): **TODO** — `dsk import` integration test where a target-tenant fixture has one record with a pre-existing `keeper_declarative_manager` field that conflicts with a `manifest.csv` UID-map row. Assert: `dsk import` refuses without `--accept-pre-existing-marker`, and the error message names the offending UID.

## Status

🟡 **needs DSK-side test** — Tier 3 cross-product defense; lives DSK-side per the (b) marker convention from D7.

## Affected phase / opportunity

Phase 4-A (DSK adopts post-migration records).

## Owner

Midas (DSK) — owns `dsk import` adoption logic + marker semantics.
