# 01 — Malicious overlay role-rename for privilege escalation

## Attack

Attacker submits a `edits.yaml` to the ops repo that **renames a low-privilege role to the same name as an existing high-privilege role**, attempting to merge bindings under the high-privilege name during overlay application. If undetected, the attacker's user (bound to the low-privilege role) inherits the high-privilege role's enforcements + admin-node assignments on the target tenant.

## Pre-condition

- Attacker has write access to the ops-repo branch where `edits.yaml` lives
- A maintainer reviews + merges the PR without catching the rename collision
- Operator runs `keeper-migrate ... declare overlay --edits edits.yaml` against a real source inventory + applies via `tenant-migrate structure`

## Defense

1. **Pydantic schema** rejects `roles.rename` collisions where the new name matches another existing role in the inventory. Source: `keeper_tenant_migrate/declare/schema.py` (`OverlayManifest` validators).
2. **`ref_graph`** detects when a renamed role would collapse into another role's binding scope and surfaces it as a dangling-ref-class error with `exit: 3`.
3. **`secret_guard`** would catch any field-value injection if the attacker also tried to embed a credential as a role-name (defense-in-depth, not the primary defense for this attack).
4. **PR review on ops repo** is the primary human gate — rename collisions show up as a clear diff (`role:old_name → high_privilege_name`) that any reviewer can flag.
5. **`tenant-migrate structure --dry-run`** before apply shows the resulting binding graph; reviewer can spot the inherited admin-node grants.

## Pinning test

`keeper_tenant_migrate/declare/tests/test_declare_overlay.py::EditOrderTests` and `test_dangling_ref_role_rename` — the spike branch's existing tests. Specifically the dangling-ref + edit-order pinning. **TODO** when D11 corpus is fully populated: add `test_role_rename_collision_with_existing_high_privilege_role` for the explicit collision case.

## Status

🔵 **seeded** — primary defenses (schema + ref_graph + dry-run) all exist; explicit collision test is a TODO for hardening.

## Affected phase / opportunity

Phase 1 — declare-overlay wedge red-team review.

## Owner

Bob (keeperCMD-side) — declare engine + schema lives in keeperCMD.
