# Live-tenant runbook

First-time verification of the Python port against a real Commander
session. Start every block with a read-only check so a misconfigured
session is caught before any entity is written.

Tested environments:
- Source: EU demo tenant (`~/.keeper/source-tenant.json`)
- Target: MSP disposable tenant (`~/.keeper/target-tenant.json`)

Replace paths + prefix values to match your setup.

---

## 0. Install

`tenant-migrate` is built into Keeper Commander. Make sure
`keepercommander` is current and start a shell:

```bash
pip install --upgrade keepercommander
keeper
```

Confirm:

```
My Vault> tenant-migrate
# → help table listing 16 subcommands
```

---

## 1. Smoke-test source session (read-only)

```
$ keeper --config ~/.keeper/source-tenant.json
My Vault> tenant-migrate self-test
```

**Expected output** (empty tenant still passes structural checks):
```
  ✓ session.user               <your source admin email>
  ✓ commander_clients.import   all 4 clients import
  ✓ parser.dests               10 commands verified
  ✓ enterprise.loaded          enterprise=<name>, nodes=<N>
  ✓ live_inventory             nodes=.. teams=.. roles=.. users=..
  ✓ target_state               nodes=.. teams=.. roles=.. sfs=..
  ✓ record.read                read uid=.. title=..
```

Any `✗` → stop. Fix the underlying issue before continuing (most likely
session not authenticated or Commander version drift).

---

## 2. Capture source inventory

```
My Vault> tenant-migrate plan \
    --output /tmp/source_inv.json \
    --node MIGRATION-TEST-NODE \
    --prefix MIGTEST-
```

Creates:
- `/tmp/source_inv.json` — frozen snapshot
- `/tmp/source_inv.json.sha256` — tamper sidecar

Confirm:
```bash
cat /tmp/source_inv.json | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['counts'])"
# expected: {'nodes': 4, 'teams': 3, 'roles': 3, 'users': 0, 'shared_folders': 3, 'records': 0, ...}
```

### 2a. (Pre-flight, optional) Classify shared_folder_folder subfolders

Run `nested-sf-plan` whenever the source inventory contains
`shared_folder_folder` entries and you want to choose how they get
shaped on the target tenant. Read-only; safe to run repeatedly.

```
My Vault> tenant-migrate nested-sf-plan \
    --inventory /tmp/source_inv.json \
    --output /tmp/nested_sf_plan.json \
    [--default-action {preserve-subfolder,promote-to-sibling, \
                        promote-to-true-nested,flatten-with-prefix}] \
    [--per-folder-rules /tmp/rules.json] \
    [--default-conflict-resolution {error,suffix,merge}]
```

Output classifies every `shared_folder_folder` against the **5-option
migration matrix** (full reference: `.context/sf-option-matrix.md`):

- `preserve-subfolder` — keep child as a `shared_folder_folder`,
  inheriting parent's members + perms.
- `promote-to-sibling` (default for divergent subfolders) — create a
  top-level SF named `Parent - Child`; child gets its own ACL.
- `promote-to-true-nested` — placeholder for future Commander
  versions; falls back to `promote-to-sibling` until
  `commander_supports_true_nested_sf()` returns `True` (audit confirmed
  unavailable through v17.2.15).
- `flatten-with-prefix` — top-level SF named `Parent__Child`; for
  legacy targets without `shared_folder_folder` support.
- `hybrid-per-folder` — different option per subfolder UID. Driven by
  `--per-folder-rules` JSON or by hand-editing the plan JSON between
  scan and apply.

Pass the resulting plan to `structure --nested-sf-plan PATH` later
(Step 6). Skipping this step preserves existing behavior — every
subfolder is recreated as a subfolder. The full Commander-surface
audit lives in `.context/sf-commander-surface.md`.

#### Worked examples

**A. Single source SF with one divergent subfolder (sibling promotion)**

```
My Vault> tenant-migrate nested-sf-plan \
    --inventory /tmp/source_inv.json \
    --output /tmp/plan.json \
    --default-action promote-to-sibling
```

Plan emits one row with `proposed_target_action=promote-to-sibling`
and `proposed_promoted_name='Parent - Child'`. Apply:

```
$ keeper --config ~/.keeper/target-tenant.json
My Vault> tenant-migrate structure \
    --inventory /tmp/source_inv.json \
    --nested-sf-plan /tmp/plan.json \
    --steps 12-12
```

**B. Three subfolders, mixed strategy (hybrid-per-folder)**

Operator wants subfolder `Sensitive` promoted, subfolder `Archive`
flattened, subfolder `Internal` left as a subfolder (preserve). Write
the rules:

```
$ cat > /tmp/rules.json <<'EOF'
{
  "sff-uid-sensitive": "promote-to-sibling",
  "sff-uid-archive":   "flatten-with-prefix",
  "sff-uid-internal":  "preserve-subfolder"
}
EOF
```

Then:

```
My Vault> tenant-migrate nested-sf-plan \
    --inventory /tmp/source_inv.json \
    --output /tmp/plan.json \
    --per-folder-rules /tmp/rules.json
```

Each row in the plan JSON gets the action you specified. Edit the
`proposed_promoted_name` field manually if the auto-generated name
collides with an existing SF on target.

**C. Sibling promotion with collision policy (suffix)**

If the target tenant already contains a top-level SF named
`Parent - Child`, the apply step would fail by default
(`conflict_resolution=error`). To auto-suffix:

```
My Vault> tenant-migrate nested-sf-plan \
    --inventory /tmp/source_inv.json \
    --output /tmp/plan.json \
    --default-conflict-resolution suffix
```

The materializer creates `Parent - Child (2)`. The audit log records
the suffix.

**D. Flatten for a legacy target**

Some legacy targets reject `shared_folder_folder`. Force flat naming:

```
My Vault> tenant-migrate nested-sf-plan \
    --inventory /tmp/source_inv.json \
    --output /tmp/plan.json \
    --default-action flatten-with-prefix
```

Each divergent subfolder becomes `Parent__Child`.

**E. Future-ready (true-nested) — placeholder**

When Keeper releases nested-SF support, run:

```
My Vault> tenant-migrate nested-sf-plan \
    --inventory /tmp/source_inv.json \
    --output /tmp/plan.json \
    --default-action promote-to-true-nested
```

Today the runtime probe falls back to `promote-to-sibling`
automatically. When the probe returns `True`, the materializer
activates and creates true nested SFs.

#### Reading the plan JSON before applying

The plan JSON has these top-level fields:

```json
{
  "scanned_at": "2026-04-26T...",
  "source_tenant": "My company",
  "default_action": "promote-to-sibling",
  "default_conflict_resolution": "error",
  "commander_supports_true_nested_sf": false,
  "decisions": [...],
  "summary": {"inherit": N, "promotion-candidate": N, "cannot-classify": N},
  "action_summary": {"preserve-subfolder": N, "promote-to-sibling": N, ...}
}
```

Each `decisions` row has `proposed_target_action`,
`proposed_promoted_name`, `conflict_resolution`, and (when divergent)
`membership_diff`. Operators routinely edit the JSON between scan and
apply — change the action on a specific row, change the conflict
policy, or override the auto-generated promoted name.

---

## 2b. (Optional) Apply overlay edits before applying structure

Use the `declare` subcommand group to rewrite the captured inventory
before it lands on target. Common operator edits at this stage:

- Rename a role to match target conventions (`Source-Admin` → `Target-Admin`)
- Drop test/legacy roles you don't want migrated
- Strip lockout-risk enforcements from a role (e.g. `require_account_share`,
  `restrict_ip_addresses`) when the target's own admin needs to administer
  the role first; the v1.7 default-skip already protects *builtin* admin
  roles, but custom roles need explicit removal here.
- Rename shared folders and propagate the rewrite to record `folder_path`

Workflow:

```bash
# 1. Author the overlay manifest
cat > /tmp/run/edits.yaml <<'EOF'
schema: tenant-overlay.v1
name: acme-target-prep
base: /tmp/run/inventory.json
edits:
  roles:
    rename:
      Source-Admin: Target-Admin
    drop:
      - Legacy-Test-Role
    strip_enforcements:
      Target-Admin:
        - require_account_share
  shared_folders:
    rename:
      Engineering: Eng
EOF

# 2. Schema-check the manifest before doing anything
keeper-migrate --config "$TGT" tenant-migrate declare validate /tmp/run/edits.yaml
# expected: PASS — exit 0

# 3. Apply the overlay; output is written 0o600
keeper-migrate --config "$TGT" tenant-migrate declare overlay \
    --base /tmp/run/inventory.json \
    --edits /tmp/run/edits.yaml \
    --output /tmp/run/inventory.edited.json

# 4. (Equivalent) dry-run: validate manifest + apply in memory only
keeper-migrate --config "$TGT" tenant-migrate declare overlay \
    --base /tmp/run/inventory.json \
    --edits /tmp/run/edits.yaml \
    --output /tmp/run/inventory.edited.json \
    --dry-run

# 5. Feed the overlay'd inventory into every downstream stage:
#    structure / users / records-import etc all take --inventory.
```

Schema constraints (Pydantic strict):

- `schema: tenant-overlay.v1` — mandatory and pinned; unknown versions exit 2
- Extra fields rejected at every nesting level
- Type-checked: `roles.rename` is `dict[str, str]`, `roles.drop` is
  `list[str]`, `roles.strip_enforcements` is `dict[str, list[str]]`

Edit application order inside `apply_overlay`: drops → strip → renames.
The base inventory is never mutated (deepcopy invariant); the output
file is a fresh JSON.

What's covered today:

- `roles.rename` with cross-reference propagation to `require_account_share`
- `roles.drop` (decrements `counts.roles`)
- `roles.strip_enforcements` (per-role list of keys to remove)
- `shared_folders.rename` with `records[].folder_path` propagation
  anchored on `folder_uid`

What's NOT covered yet — queued for the next overlay-engine cycle:

- `nodes.remap` — node path rewrites cross-reference `roles.node` and
  `teams.node`; full propagation audit pending
- `teams.rename` / `teams.drop` — team name vs UID references in
  shared folders need verification before shipping
- `users.drop` / `users.domain_remap` — rehearsal fixture coverage gap
- `scope.include_nodes` / `scope.exclude_nodes` — glob-based subtree filter

Until those land, hand-edit the captured `inventory.json` directly for
those cases — it is plain JSON and editable with any tool, and the
downstream stages don't care which path produced the inventory.

## 3. Switch to target + self-test

```
My Vault> quit
$ keeper --config ~/.keeper/target-tenant.json
My Vault> tenant-migrate self-test
```

Same output pattern. Must be `✓` on `session.user` before continuing.

---

## 4. Target-side transition check (dry-run user plan)

```bash
$ keeper --config ~/.keeper/target-tenant.json \
    enterprise-info --users --format csv \
    --columns status,transfer_status,node,team_count,teams,role_count,roles,alias,2fa_enabled \
    > /tmp/target_users.csv

My Vault> tenant-migrate transition-check \
    --inventory /tmp/source_inv.json \
    --target-users-csv /tmp/target_users.csv \
    --csv-output /tmp/plan.csv \
    --md-output /tmp/plan.md
```

Review `/tmp/plan.md` — any UNKNOWN users must be resolved before users
phase.

---

## 5. Capture pre-state of target

```
My Vault> tenant-migrate capture-target-state --output /tmp/target_before.json
```

Later steps will diff against this to prove they worked.

---

## 6. Restore structure (start with Step 0-3 only to validate)

```
My Vault> tenant-migrate structure \
    --inventory /tmp/source_inv.json \
    --source-root "My company" \
    --target-root Keeperdemo \
    --scope-node MIGRATION-TEST-NODE \
    --steps 0-3
```

Logged output per entity. Common first-run issues:
- `record_types.json` missing — harmless, Step 0 skips.
- Node creation FAIL `may already exist` — fine on re-runs; run steps 4-12 next.

Verify:
```
My Vault> tenant-migrate capture-target-state --output /tmp/target_mid.json
My Vault> tenant-migrate reconcile \
    --inventory /tmp/source_inv.json \
    --target-state /tmp/target_mid.json \
    --output /tmp/recon_mid.md
```

Nodes/teams section of `recon_mid.md` should show no missing items.

---

## 7. Continue to steps 4-6 (roles + enforcements)

```
My Vault> tenant-migrate structure --inventory /tmp/source_inv.json \
    --source-root "My company" --target-root Keeperdemo \
    --scope-node MIGRATION-TEST-NODE --steps 4-6
```

After run:
```
My Vault> tenant-migrate capture-target-state --output /tmp/target_mid2.json
My Vault> tenant-migrate verify \
    --inventory /tmp/source_inv.json \
    --target-state /tmp/target_mid2.json \
    --output /tmp/checks.csv
```

`/tmp/checks.csv` is the 8-phase field-by-field diff (pre-flight, nodes,
teams, roles, SFs, records, record types, counts). Zero FAILs is the goal.

---

## 8. Run remaining steps (7-12)

```
My Vault> tenant-migrate structure --inventory /tmp/source_inv.json \
    --source-root "My company" --target-root Keeperdemo \
    --scope-node MIGRATION-TEST-NODE --steps 7-12
```

---

## 9. Records migration (when roster has users)

### 9a. Export source records (source session)

```
$ keeper --config ~/.keeper/source-tenant.json
My Vault> tenant-migrate records-export \
    --output-dir /tmp/src_records \
    --prefix MIGTEST-
```

### 9b. Convert offline

```bash
$ keeper --config ~/.keeper/target-tenant.json \
    shell -c "tenant-migrate convert --input-dir /tmp/src_records --output /tmp/import.json --split-by-type"
```

### 9c. Import on target

```
My Vault> tenant-migrate records-import --input /tmp/import.json --dry-run
# review output
My Vault> tenant-migrate records-import --input /tmp/import.json
```

### 9d. Attachments + shares (need a manifest of source_uid→target_uid)

Build the manifest by correlating source export filenames with target
record UIDs post-import:

```
source_uid,target_uid
<src-uid-1>,<tgt-uid-1>
...
```

Then:
```
My Vault> tenant-migrate records-attachments \
    --manifest /tmp/manifest.csv \
    --staging-dir /tmp/att_stage

My Vault> tenant-migrate records-shares \
    --manifest /tmp/manifest.csv \
    --skip-missing-users
```

---

## 10. Final reconciliation

```
My Vault> tenant-migrate capture-target-state --output /tmp/target_final.json
My Vault> tenant-migrate reconcile \
    --inventory /tmp/source_inv.json \
    --target-state /tmp/target_final.json \
    --output /tmp/reconciliation.md
```

Review — if success_pct == 100 and total_missing == 0, migration is
verified complete. Archive `/tmp/source_inv.json`, `/tmp/checks.csv`,
`/tmp/reconciliation.md` for audit.

---

## Resuming after a crash

The `structure` stage iterates over thousands of entities at ~5 cpm
under throttle. A process death mid-run (SSH drop, terminal close,
parent session disconnect) historically left the target tenant in a
half-built state with no smart way to pick up — the operator had to
either wipe target and start over (hours of lost work) or hand-walk
the audit log.

`structure --resume` solves this with state-reconciliation: every
sub-step queries the target tenant for its current state at entry,
pre-filters source rows to the delta, and only writes what's missing.
Runs are idempotent: a re-run after a successful migration is a
clean no-op.

### Standard recovery sequence

When a `structure` run dies partway through:

```bash
# 1. Reconnect to the target tenant.
keeper --config ~/.keeper/target-tenant.json shell
# (verify: `whoami` reports the target admin)
exit

# 2. Re-issue the SAME structure command with --resume appended.
keeper-migrate --config ~/.keeper/target-tenant.json \
    tenant-migrate structure \
    --inventory /tmp/run/inventory.json \
    --scope-node MIGRATION-TEST-NODE \
    --target-root Keeperdemo \
    --resume

# 3. Inspect the audit log. Every row is one of:
#    - SKIPPED  "already present (resume)"      — landed pre-crash
#    - SUCCESS  "created — was missing on resume" — landed this run
#    - SKIPPED  "N enforcement(s) already applied (resume)" — partial role
grep -E "resume|missing on resume|already applied" \
    /tmp/run/audit.log

# 4. Re-run --resume one more time. The audit summary should report
#    `skipped_already_present == total ops` and `created` == 0 — the
#    second run is a no-op confirming the structure stage is whole.
keeper-migrate --config ~/.keeper/target-tenant.json \
    tenant-migrate structure \
    --inventory /tmp/run/inventory.json \
    --scope-node MIGRATION-TEST-NODE \
    --target-root Keeperdemo \
    --resume
```

### Behavior matrix

| Source row state on target | Audit entry on `--resume` |
|---|---|
| Identical to source | `SKIPPED — already present (resume)` |
| Absent | `SUCCESS — created — was missing on resume` |
| Partially applied (some enforcements missing) | `SKIPPED — N enforcement(s) already applied (resume)` for the matched keys + `SUCCESS` for the missing keys |
| Entity exists with a different value (user on a different node) | Re-issued — Commander's idempotent layer accepts, audit tallies as SUCCESS |

### When to use `--resume`

- After a process death mid-`structure` (SSH drop, kernel kill, etc.).
- After `structure` exited with FAILED entities you've manually
  fixed on target (e.g. created a missing parent node).
- After re-running structure to verify nothing drifted.

### When NOT to use `--resume`

- The first time you run `structure` against a fresh target — it's
  unnecessary and adds one read API call per sub-step (3 to 11 extra
  calls total, depending on which steps run).
- After a `cleanup --prefix` run on the same scope — the target IS
  empty by design, and `--resume` would correctly recreate everything
  but tag every row as "created — was missing on resume" rather than
  the cleaner unflagged SUCCESS line.

### Defense in depth: nohup invocation

`--resume` is the recovery; nohup is the prevention. For
multi-hour migrations, launch under nohup so the process survives
session death in the first place:

```bash
nohup keeper-migrate --config ~/.keeper/target-tenant.json \
    tenant-migrate auto-migrate \
    --run-dir "$RUN" --scope-node MIGRATION-TEST-NODE \
    --prefix MIGTEST- --target-root Keeperdemo \
    --expected-source-tenant "Acme Source" \
    --expected-target-tenant "Keeperdemo" \
    < /dev/null > "$RUN/run.stdout" 2> "$RUN/run.stderr" &
disown
echo $! > "$RUN/run.pid"
```

The run survives Claude-session death, terminal close, SSH drop. Use
`--resume` only as a fallback when nohup wasn't in place.

**Phase 2 #3 fix**: `--expected-source-tenant` and
`--expected-target-tenant` now **fail-CLOSED** (raise `ValueError`
before any stage dispatches) when the supplied name does not match
the verified session tenant name. Pre-Phase-2 they were parsed but
never enforced. Always pass both for nohup runs — they are the
last line of defense against `--config` / `--target-config` swap
mistakes.

---

## Troubleshooting quickrefs

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `self-test` ✗ on `session.user` | Not logged in | `keeper --config CFG login` first |
| `enterprise.loaded` ✗ | sync-down didn't run | Invoke `sync-down` manually before rerun |
| `parser.dests` ✗ | Commander version drift | Rerun tests; diff commander_clients.py vs parser |
| Structure: every entity FAILED "may already exist" | Re-running after partial success | Re-run with `--resume` (see "Resuming after a crash" above) |
| Records-import: `Unknown record type` | Custom type not loaded | Run `--steps 0` of structure first |
| Attachments: `0 files` | Source record cache stale | `sync-down` on source before `records-export` |

---

## Known irreversibles

`tenant-migrate undo` can roll back users / structure / records-shares /
records-attachments, but three subcommands produce state that the undo
planner can't fully reverse. Know what you're signing up for before you
run them.

| Subcommand | Reversible via `undo`? | Recovery path |
|------------|------------------------|---------------|
| `cleanup` | NO — entities already deleted | Restore from the pre-delete SHA256SUMS backup directory, OR accept loss. Always take a backup before running. |
| `decommission` | NO — source users are locked + removed | Same as `cleanup`. Keep the checkpoint CSV + audit log; there is no "un-decommission". |
| `records-import` | PARTIAL — undo emits a manual-action entry, not an automatic rollback | Commander's native `import` can write partial batches on failure. To revert, `undo` gives you the list of imported UIDs — delete them individually via `keeper rm UID` or wipe the whole target node. |
| `records-attachments` | PARTIAL — undo records file-name pairs but Keeper fileRef UIDs change per upload | Admin must manually identify the fileRef for each uploaded attachment on target and delete via Commander. The audit event captures `[{target_uid, file_name}]` for the lookup. |
| `take-ownership` | YES via `take-ownership-restore` | Pass the take-ownership report CSV to `take-ownership-restore` to move the captured records back from the admin to each original owner. Both verbs append chain entries; `audit-verify` correlates them. |
| `take-ownership-restore` | NO — it IS the reversal of take-ownership | Restoration is itself audit-chain-tracked (Phase 2 #1). To "undo a restore", re-run `take-ownership` against the same admin/users — but consider if you actually need to. |
| `transfer-user` | NO — source users are auto-locked and their vaults are MOVED into the admin account | Manually unlock each source user via `enterprise-user --unlock`, then either accept the data loss (vaults are now under the admin) or use `take-ownership-restore` against the original take-ownership backup if one exists. |

### What this means for a real run
1. Always do a **dry-run first** for any step that touches target data.
2. Always take a **take-ownership backup** (per-user JSON with SHA256SUMS
   manifest) before `cleanup` or `decommission`.
3. If `records-import` errors mid-batch, run `tenant-migrate reconcile`
   before retrying — the report will tell you which UIDs landed.
4. The full audit chain lives at `<run_dir>/audit.log`; `audit-verify`
   confirms integrity and lets you replay the history.

---

## Lockout-risk enforcements (v1.7+)

Four enforcements can lock the tenant administrator out of the target
tenant if cross-tenant value drift mis-applies them. The structure
stage **default-skips** them on `BUILTIN_ROLE_NAMES` roles
(Administrator / Keeper Administrator / Admin / Enterprise Admin /
Executive); the verify stage reports them as `SKIP` instead of `FAIL`.
The 2026-04-26 `jlima+demo2` incident — `restrict_ip_addresses`
mis-applied with no defense-in-depth — is the worked example.

| Key | Lockout vector |
|---|---|
| `require_account_share` | Binds login to a target role NAME that may not be migratable. Already covered by Bug 47/64/51 + verify SKIP. |
| `restrict_ip_addresses` | IP allowlist drift → admin's IP not on target list → permanent lockout. |
| `master_password_reentry` | Vault-open re-prompt cadence; if mis-set, admin can't open the vault to fix it. |
| `two_factor_by_ip` | 2FA-bypass list per CIDR; misalignment leaves admin always 2FA-blocked. |

### Default behavior (recommended)
```bash
keeper-migrate structure --inventory inventory.json
# lockout-risk keys SKIP'd on builtin-admin roles → operator applies
# manually post-migration after auditing the value
```

### Opt-in (only after auditing values for target compatibility)
```bash
keeper-migrate structure --inventory inventory.json \
    --apply-admin-lockout-risk-enforcements
```
Use this only when:
1. You've reviewed each lockout-risk value on source AND confirmed it's
   correct for the target tenant's network/2FA/role topology.
2. You have a recovery plan if the value locks the operator out
   (out-of-band Commander session that can clear the enforcement).

### Audit subcommand
```bash
# Pre-migration baseline
keeper-migrate audit-lockout-risk --output target-baseline.md

# Post-migration verification + cross-compare to source
keeper-migrate audit-lockout-risk \
    --source-inventory inventory.json \
    --output target-post-migration.md
```
Read-only; reports which builtin-admin roles on target carry which
lockout-risk enforcements, plus optional source-vs-target drift.
