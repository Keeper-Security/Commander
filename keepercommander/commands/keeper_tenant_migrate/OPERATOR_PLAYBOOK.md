# Operator Playbook — `keeper-migrate tenant-migrate`

The canonical command sequence for migrating one Keeper tenant onto
another via the `tenant-migrate` plugin. Three workflows are codified:

- **Workflow A** — Standard forward migration (no nested SFs, no
  resume needed, single pass).
- **Workflow B** — Forward migration with nested-SF planning step
  (recommended whenever the source has `shared_folder_folder` rows).
- **Workflow C** — Resume after a mid-stage crash (G7, T1-squad-2).

Source tenant is **read-only forever** (Rule 0 of `.context/squad-2-plan.md`).
Every step here either reads source, writes target, or processes
local files. Three subcommands write back to source — `cleanup`,
`take-ownership`, `transfer-user`, `decommission` — and they appear
ONLY in the post-migration cleanup workflow (Workflow A step 14).
That workflow gates on the source-mode interlock + tenant-name
assertion + `--confirm-source-destructive` ALL three layered.

> **Truth source for flag/argument detail**: `.context/command-surface.md`
> (matches argparse). This playbook ties the subcommands together; it
> does NOT re-document every flag.

---

## Glossary

- `$RUN` — A single shared run-directory. Both source and target
  shells point at the same path. Holds `inventory.json`, audit log,
  manifest, staging dir, checkpoint, reports.
- `$SOURCE` — `keeper-migrate --config ~/.keeper/source-tenant.json` (EU
  demo source tenant in our reference setup).
- `$TARGET` — `keeper-migrate --config ~/.keeper/target-tenant.json`
  (MSP disposable target).
- `MIGTEST-` — the canonical entity prefix for rehearsals; substitute
  your own when running production. Constraints in `CLAUDE.md` rule 2.

---

## Workflow A — Standard forward migration

Use this when:
- Source has only top-level shared folders (no
  `shared_folder_folder` subfolders) OR you accept the default
  `promote-to-sibling` strategy for any subfolders found.
- Single forward pass — no mid-stage interruption expected.

### Step 1 — `pre-flight`

```bash
$TARGET tenant-migrate pre-flight \
  --roster $RUN/roster.csv \
  --output-dir $RUN \
  --csv-output $RUN/preflight.csv
```

Validates roster shape, Commander version, disk + writability, target
session auth.

- Expected duration: < 5s.
- Audit log shape: none (no writes).
- Roll back: nothing to undo.

### Step 2 — `plan` (source-side)

```bash
$SOURCE tenant-migrate plan \
  --output $RUN/inventory.json \
  --node MIGRATION-TEST-NODE \
  --prefix MIGTEST-
```

Captures source inventory. SHA-256 sidecar is written automatically.

- Expected duration: 5-60s for a small tenant; minutes-to-hours on a
  large EU enterprise (driven by HSF scrape).
- Audit log shape: read-only — no audit event.
- Roll back: delete `$RUN/inventory.json`. No live state to undo.

### Step 3 — `estimate`

```bash
tenant-migrate estimate \
  --inventory $RUN/inventory.json \
  --output $RUN/estimate.md \
  --output-json $RUN/estimate.json
```

Reads only the inventory. Produces an API-call budget + ETA banner
the operator reads BEFORE deciding whether to proceed.

- Expected duration: < 1s.
- Audit log shape: none (offline).
- Roll back: delete the report files.

### Step 3a — `nested-sf-plan` (only if source has nested shared folders)

```bash
tenant-migrate nested-sf-plan \
  --inventory $RUN/inventory.json \
  --output $RUN/nested-sf-plan.json \
  --default-action promote-to-sibling \
  --default-conflict-resolution error
```

Emits a per-subfolder migration plan for every `shared_folder_folder`
in scope. See Workflow B for the full deep-dive.

### Step 3b — `plan-report` (customer-facing review)

```bash
tenant-migrate plan-report \
  --inventory $RUN/inventory.json \
  --nested-sf-plan $RUN/nested-sf-plan.json \
  --estimate $RUN/estimate.json \
  --output $RUN/migration-plan.md
```

Renders a single customer-friendly markdown document from the three
inputs above. The audience is a mid-technical enterprise admin who
needs to review the operator's recommendations before authorising the
run. The report:

- Surfaces ONLY the decisions that need attention (divergent
  subfolders, name conflicts, tier outliers).
- Buckets the 90% safe-default rows in a collapsible block.
- Shows the operator's recommendation alongside the alternatives plus
  the override key for direct YAML editing.
- Prints a sign-off checklist of what the user is approving by
  proceeding.
- Writes a companion `migration-plan.json` (machine-readable mirror)
  used by `--overrides overrides.yaml` validation in later steps.

Both files are 0644 — intentionally world-readable so admins can email
or paper-print the report. No secrets land in either file.

- Expected duration: < 1s.
- Audit log shape: none (read-only, offline).
- Roll back: delete `migration-plan.md` + `migration-plan.json`.

All three input flags are individually optional — at least one is
required. When an input is missing the affected section degrades
gracefully (a one-line note explains what's missing).

### Step 4 — `point-of-no-return`

```bash
$TARGET tenant-migrate point-of-no-return \
  --checks $RUN/preflight.csv \
  --reconciliation '' \
  --checkpoint $RUN/checkpoint.json \
  --confirm "YES"
```

Refuses if `preflight.csv` has any `severity=FAIL` rows. Writes a
signed checkpoint. The checkpoint is required input for `decommission`
later.

- Expected duration: < 1s.
- Audit log shape: writes a `point-of-no-return` audit event when
  `$RUN/audit.log` already exists.
- Roll back: delete `$RUN/checkpoint.json` (no destructive ops yet).

### Step 4.5 — `nested-sf-plan` (recommended for any source with SFFs)

```bash
$SOURCE tenant-migrate nested-sf-plan \
  --inventory $RUN/inventory.json \
  --output $RUN/nested-sf-plan.json \
  --default-action promote-to-sibling
```

Walks every `shared_folder_folder` and classifies it against the
5-option matrix. Read-only (no source-side writes). Produces both the
machine-readable plan JSON consumed by `structure --nested-sf-plan`
AND, since squad-3 round 1, a markdown report mirror via the new
`plan-report` subcommand (see step 4.6).

- Expected duration: <5s for small tenants; up to a minute for
  enterprise.
- Audit log shape: read-only — no audit event.
- Roll back: delete the plan JSON.

### Step 4.6 — `plan-report` + `overrides.yaml` (squad-3 round 1)

The customer (tenant admin) reads the markdown plan report, then
optionally drafts an `overrides.yaml` to disagree with the operator's
recommendations on specific rows. Schema lives in
`.context/overrides-schema.md`. Minimal example:

```yaml
# $RUN/overrides.yaml — drafted by tenant admin after reviewing plan
subfolders:
  abc123XYZsubfolder1: promote-to-sibling
  def456XYZsubfolder2: flatten-with-prefix

conflicts:
  abc123XYZsubfolder1: merge

notes:
  abc123XYZsubfolder1: "Eng owns this on target — merge instead of error"
```

The customer hands this back to the operator (email / git PR / shared
drive) for application in step 5.

### Step 5 — `structure`

```bash
$TARGET tenant-migrate structure \
  --inventory $RUN/inventory.json \
  --nested-sf-plan $RUN/nested-sf-plan.json \
  --overrides $RUN/overrides.yaml \
  --source-root "My company" \
  --target-root "Keeperdemo" \
  --scope-node MIGRATION-TEST-NODE \
  --steps 0-12
```

Restores nodes/teams/roles/enforcements/SF membership/vault folders
on target. The forward path's heaviest write stage. 13 sub-steps;
`StructureRestore.run()` executes each in order.

**v1.7 — lockout-risk default-skip on builtin-admin roles**: four
enforcements (`require_account_share`, `restrict_ip_addresses`,
`master_password_reentry`, `two_factor_by_ip`) SKIP by default on
`Administrator` / `Keeper Administrator` / `Admin` / `Enterprise Admin`
/ `Executive` roles. Cross-tenant value drift on these can lock the
operator out of target before they have a chance to fix it (worked
example: 2026-04-26 `jlima+demo2` incident). Pass
`--apply-admin-lockout-risk-enforcements` ONLY after auditing each
value for target compatibility AND ensuring you have an out-of-band
recovery path. See RUNBOOK.md → "Lockout-risk enforcements".

`--overrides` (squad-3 round 1) loads the customer's YAML, validates
it against the nested-SF plan, and applies the deltas to a NEW plan
in memory — the original plan JSON on disk is never mutated. Every
applied override (subfolder action, conflict policy, tier) lands in
the audit chain with before/after values + the customer's note, so
support can later reconstruct what the customer changed from the
operator's defaults.

If the YAML sets `tier:` to anything other than `auto`, the run
ALSO requires `--accept-risk` because tier under-sizing is the #1
cause of mid-migration throttle failures.

- Expected duration: 5-30 min for small/medium tenants;
  hours for enterprise scale (Commander throttle dominates).
- Audit log shape: one `structure` event per call with
  `summary.created_entities = {nodes, teams, roles, shared_folders}`,
  PLUS `summary.overrides = {source, count, entries}` when
  `--overrides` was supplied with a non-empty file.
- Roll back: `tenant-migrate undo --audit-log $RUN/audit.log --execute`
  — undoes the structure event by deleting created entities in reverse.

### Step 6 — `users`

```bash
$TARGET tenant-migrate users \
  --inventory $RUN/inventory.json \
  --roster $RUN/roster.csv \
  --source-root "My company" \
  --target-root "Keeperdemo" \
  --sso-policy warn \
  --run-dir $RUN
```

Sends real invite emails to each roster row. Pre-existing target
users are classified `EXTENDED` (placement updates only).

- Expected duration: 1s/user + delay; 10-30 min for 100 users.
- Audit log shape: `users` event with `summary.invited_emails`.
- Roll back: `undo --hard --execute` to delete; `undo --execute` to
  lock instead of delete.

### Step 7 — `records-export` (source-side)

```bash
$SOURCE tenant-migrate records-export \
  --output-dir $RUN/records_export \
  --prefix MIGTEST-
```

Walks every record matching `--prefix` (or `--folder-uid` scope) and
emits one v3 JSON file per record (chmod 0600). Writes `staging.json`
that the cross-tenant attachment pipeline consumes.

- Expected duration: 1-5s/record + delay.
- Audit log shape: per-record `records-export` event when
  `$RUN/records_export/audit.log` is set.
- Roll back: delete `$RUN/records_export/`. No source mutation.

### Step 8 — `convert` (offline)

```bash
tenant-migrate convert \
  --input-dir $RUN/records_export \
  --output $RUN/records_import.json \
  --include-sf
```

Pure offline conversion. v3 records → v2 import bundle.

- Expected duration: < 5s.
- Audit log shape: none (offline).
- Roll back: delete `$RUN/records_import.json`.

### Step 9 — `records-import` (target-side)

```bash
$TARGET tenant-migrate records-import \
  --input $RUN/records_import.json \
  --permissions N
```

Imports records via Commander's native import flow.

- Expected duration: 1-3s/record + delay.
- Audit log shape: `records-import` event with
  `summary.imported_uids`.
- Roll back: NOT automatic — `undo` plans this as MANUAL with the
  list of UIDs the operator must delete by hand. (Cycled validation
  in fakes-mode CAN reverse it because the cycle owns the target
  entirely; live operators must run the manual deletes.)

### Step 9a — `records-manifest`

```bash
$TARGET tenant-migrate records-manifest \
  --source-dir $RUN/records_export \
  --output $RUN/manifest.csv
```

Builds the `source_uid,target_uid` manifest by matching record titles
across the source export dir and the target session. Required input
for shares + attachments.

- Expected duration: < 5s.
- Audit log shape: none.
- Roll back: delete `$RUN/manifest.csv`.

### Step 10 — `records-shares` (target-side, sees both)

```bash
$TARGET tenant-migrate records-shares \
  --manifest $RUN/manifest.csv \
  --skip-missing-users \
  --run-dir $RUN
```

Replays per-record `user_permissions[]` onto target.

- Expected duration: 1s/share + delay.
- Audit log shape: `records-shares` event with
  `summary.share_grants`.
- Roll back: `undo --execute` revokes via `revoke_record_share`.

### Step 11 — `records-attachments-download` (source-side)

```bash
$SOURCE tenant-migrate records-attachments-download \
  --source-uids $RUN/manifest.csv \
  --staging-dir $RUN/staging
```

Downloads attachments to `$RUN/staging/<source_uid>/`. Writes
`staging.json` so phase 2 can run later without source session.

- Expected duration: 1-3s/attachment.
- Audit log shape: per-attachment event.
- Roll back: delete `$RUN/staging/`.

### Step 12 — `records-attachments-upload` (target-side)

```bash
$TARGET tenant-migrate records-attachments-upload \
  --manifest $RUN/manifest.csv \
  --staging-dir $RUN/staging \
  --run-dir $RUN
```

Uploads from staging to target.

- Expected duration: 1-3s/attachment.
- Audit log shape: `records-attachments` event with
  `summary.uploaded`.
- Roll back: `undo --execute` calls `delete_attachment`.

### Step 13 — `capture-target-state`

```bash
$TARGET tenant-migrate capture-target-state \
  --output $RUN/target-state.json \
  --prefix MIGTEST-
```

Dumps target enterprise data as JSON for `verify` and `reconcile`.

- Expected duration: 5-60s.
- Audit log shape: read-only.
- Roll back: delete `$RUN/target-state.json`.

### Step 14 — `verify`

```bash
tenant-migrate verify \
  --inventory $RUN/inventory.json \
  --target-state $RUN/target-state.json \
  --output $RUN/checks.csv
```

Field-level comparison. Emits `checks.csv` with severities
PASS/FAIL/SKIP/WARN.

- Expected duration: < 5s.
- Audit log shape: none (offline).
- Roll back: delete `$RUN/checks.csv`.

### Step 15 — `reconcile`

```bash
tenant-migrate reconcile \
  --inventory $RUN/inventory.json \
  --target-state $RUN/target-state.json \
  --output $RUN/reconcile.md
```

Markdown source/target/delta report.

- Expected duration: < 5s.
- Audit log shape: none.
- Roll back: delete `$RUN/reconcile.md`.

### Step 15a — `audit-lockout-risk` (v1.7+, recommended)

```bash
$TARGET tenant-migrate audit-lockout-risk \
  --source-inventory $RUN/inventory.json \
  --output $RUN/lockout-risk-audit.md
```

Read-only safety check. Lists which builtin-admin roles on target
carry which lockout-risk enforcements; flags drift vs. source baseline.
Run **before** handing the tenant off to the customer — any value here
that doesn't match an audited source value warrants manual review.

- Expected duration: < 5s.
- Audit log shape: none (read-only).
- Roll back: delete `$RUN/lockout-risk-audit.md`.

### Step 16 — `shared-folders-reconcile` (cron-able, post-activation)

```bash
$TARGET tenant-migrate shared-folders-reconcile \
  --inventory $RUN/inventory.json \
  --report $RUN/sf-reconcile.md \
  --run-dir $RUN
```

Drip-feeds SF memberships as users activate. Idempotent — safe to run
on cron daily until the still-pending list empties.

- Expected duration: 1-5 min per pass.
- Audit log shape: `shared-folders-reconcile` event with
  `summary.applied`.
- Roll back: `--prune --dry-run` to preview removals.

### Step 17 — (optional) `decommission --plan-only`

```bash
$SOURCE tenant-migrate decommission \
  --roster $RUN/roster.csv \
  --plan-only \
  --plan-output $RUN/decommission.plan.md
```

PLAN-ONLY emits a Markdown checklist of `keeper enterprise-user
--lock/--delete` commands the operator runs by hand. Source-side
destructive — requires the source-mode interlock + `--confirm-source-destructive`
+ `--expected-tenant-name` to actually execute.

- Expected duration: < 5s for plan-only.
- Audit log shape: `decommission` MANUAL audit event when
  `--confirm-manual-completion` is run AFTER the operator runs the
  plan by hand.
- Roll back: source-side deletion is irreversible. The plan-only
  output is the operator's audit trail of what they ran by hand.

---

## Worked example — Workflow A

Run dir + roster prepared:

```bash
mkdir -p /tmp/mig
cat > /tmp/mig/roster.csv <<'EOF'
email,full_name
alice@example.com,Alice Test
bob@example.com,Bob Test
EOF
RUN=/tmp/mig
```

Forward path (target session is the EU demo target / MSP disposable):

```bash
keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate pre-flight \
  --roster $RUN/roster.csv --output-dir $RUN --csv-output $RUN/preflight.csv

keeper-migrate --config ~/.keeper/source-tenant.json tenant-migrate plan \
  --output $RUN/inventory.json --node MIGRATION-TEST-NODE --prefix MIGTEST-

keeper-migrate tenant-migrate estimate \
  --inventory $RUN/inventory.json \
  --output $RUN/estimate.md --output-json $RUN/estimate.json

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate point-of-no-return \
  --checks $RUN/preflight.csv --checkpoint $RUN/checkpoint.json --confirm YES

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate structure \
  --inventory $RUN/inventory.json --scope-node MIGRATION-TEST-NODE --steps 0-12

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate users \
  --inventory $RUN/inventory.json --roster $RUN/roster.csv --run-dir $RUN

keeper-migrate --config ~/.keeper/source-tenant.json tenant-migrate records-export \
  --output-dir $RUN/records_export --prefix MIGTEST-

keeper-migrate tenant-migrate convert \
  --input-dir $RUN/records_export --output $RUN/records_import.json --include-sf

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate records-import \
  --input $RUN/records_import.json --permissions N

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate records-manifest \
  --source-dir $RUN/records_export --output $RUN/manifest.csv

keeper-migrate --config ~/.keeper/source-tenant.json tenant-migrate records-attachments-download \
  --source-uids $RUN/manifest.csv --staging-dir $RUN/staging

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate records-attachments-upload \
  --manifest $RUN/manifest.csv --staging-dir $RUN/staging --run-dir $RUN

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate records-shares \
  --manifest $RUN/manifest.csv --skip-missing-users --run-dir $RUN

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate capture-target-state \
  --output $RUN/target-state.json --prefix MIGTEST-

keeper-migrate tenant-migrate verify \
  --inventory $RUN/inventory.json --target-state $RUN/target-state.json --output $RUN/checks.csv

keeper-migrate tenant-migrate reconcile \
  --inventory $RUN/inventory.json --target-state $RUN/target-state.json --output $RUN/reconcile.md

keeper-migrate --config ~/.keeper/target-tenant.json tenant-migrate shared-folders-reconcile \
  --inventory $RUN/inventory.json --report $RUN/sf-reconcile.md --run-dir $RUN
```

Pure offline subcommands (`estimate`, `convert`, `verify`, `reconcile`)
don't need a `--config` flag — they don't open a Commander session.

---

## Workflow B — With nested-SF planning

Trigger when:
- `inventory.json` from step 2 has a non-empty
  `entities.shared_folder_folders` list, OR
- The operator wants to mix per-folder strategies (e.g.
  preserve-subfolder for some SFs, flatten-with-prefix for legacy
  ones).

Insert these steps between step 2 and step 3 of Workflow A:

### Step 2a — `nested-sf-plan`

```bash
tenant-migrate nested-sf-plan \
  --inventory $RUN/inventory.json \
  --output $RUN/nested_sf_plan.json \
  --default-action promote-to-sibling \
  --default-conflict-resolution error
```

Classifies every `shared_folder_folder` against the 5-option matrix.
Output JSON has one row per subfolder with action + conflict policy.
File is chmod 0600 (it can leak SF structure if leaked).

- Expected duration: < 5s for typical inventories.
- Audit log shape: none (offline).
- Roll back: delete `$RUN/nested_sf_plan.json`.

### Step 2b — operator review

The operator opens `$RUN/nested_sf_plan.json`, scans for
`needs-review` rows (parent SF data missing or ambiguous), and edits
each row's `action` field if the default doesn't fit. Save the file.

This is a HUMAN STEP. There is no subcommand for it. The chmod 0600
matters: only the operator should read this.

### Step 5 (with nested-SF plan)

Replace step 5 of Workflow A with:

```bash
$TARGET tenant-migrate structure \
  --inventory $RUN/inventory.json \
  --nested-sf-plan $RUN/nested_sf_plan.json \
  --scope-node MIGRATION-TEST-NODE \
  --steps 0-12
```

The `--nested-sf-plan` flag is consumed only inside `step_vault_folders`
(step 11 of the 13-step structure restore). The 5-option dispatch
tree picks one branch per subfolder:

```
nested-sf-plan row → action key
   preserve-subfolder       → create as shared_folder_folder under parent
   promote-to-sibling       → create as top-level shared_folder, qualified name
   promote-to-true-nested   → ERROR — Commander does not support yet
   flatten-with-prefix      → create as top-level shared_folder, "Parent__Child"
   needs-review             → SKIP with audit-log warning
```

All other steps in Workflow B are identical to Workflow A.

---

## Workflow C — Resume after mid-stage crash

Trigger when `structure` (step 5 of Workflow A) was interrupted
(network drop, OOM, operator Ctrl-C, Commander throttle that
cascaded). The target tenant has SOME of the entities created and
some missing.

### Step 1 — figure out what crashed

```bash
tenant-migrate audit-verify --directory $RUN
```

If chain breaks at a `structure` event with no closing summary, you
crashed mid-stage.

### Step 2 — resume `structure` with `--resume`

```bash
$TARGET tenant-migrate structure \
  --inventory $RUN/inventory.json \
  --scope-node MIGRATION-TEST-NODE \
  --steps 0-12 \
  --resume
```

The `--resume` flag is **opt-in** (`StructureRestore.resume=False` by
default — every existing call site stays unchanged). When set:

- Each step queries target state via the L4 projection methods on
  `StructureClient` (`list_node_names`, `list_team_names`,
  `list_role_names`, `list_isolated_node_names`,
  `list_role_managed_nodes`, `list_role_privileges`,
  `list_role_enforcements`, `list_user_node_assignments`,
  `list_user_team_memberships`, `list_role_user_memberships`,
  `list_role_team_memberships`, `list_shared_folder_names`,
  `find_folder_uid`).
- Source rows that already match target state get classified
  `SKIPPED (already present)`.
- Rows whose target slot was missing get classified
  `SUCCESS (created — was missing on resume)`.
- Partial enforcements get reconciled (only the missing keys are
  applied).

Idempotency invariant: running `structure --resume` twice in a row
makes the second run a no-op. (Verified by
`test_resume_after_crash.py`.)

### Step 3 — continue from the post-structure step

Resume the playbook at step 6 (`users`). The downstream stages are
already idempotent (each has `--resume` of its own when applicable).

### Audit log behavior under `--resume`

A `structure` event still gets emitted, but `summary.created_entities`
contains only the delta (entities that were newly created on this
resume run). Entities skipped because they were already present do
NOT appear in `created_entities` — they would otherwise inflate the
undo plan.

A `--resume` warning is emitted into the audit event so undo can
later distinguish a fresh-structure event from a resume-structure
event.

### Roll back

`undo --execute` against an audit log produced by `--resume` will
correctly delete only the entities listed in `created_entities` — i.e.
the delta this resume actually created. Entities that pre-existed
target before the resume (and were skipped) are NOT in the audit
event and so are NOT touched by undo. This is the right behavior:
they weren't created by this run; we shouldn't unmake what we didn't
make.

### MSP runs: `undo --mc` keeps reversal in scope

If the original migration ran under a Managed Company scope (any
verb invoked with `--mc <MC-Name>`), the matching `undo` MUST also
pass `--mc <MC-Name>` so the inverse ops land on the same MC, not
the MSP root. Without `--mc`, `undo` defaults to the MSP root and
the inverse calls hit the wrong tenant. Phase 2 #3 added the flag
and threads it through `MCContext`; the chain entry records the MC
name so `audit-verify` can correlate the reversal with the original.

```bash
# Original run under an MC:
keeper-migrate --config ~/.keeper/target-tenant.json \
    cleanup --mc "Acme Corp" --prefix MIGTEST- --confirm

# Reversal MUST stay scoped to the same MC:
keeper-migrate --config ~/.keeper/target-tenant.json \
    undo --audit-log $RUN/audit.log --mc "Acme Corp" --execute
```

---

## Workflow B + C — Resume with nested-SF plan

Both flags compose:

```bash
$TARGET tenant-migrate structure \
  --inventory $RUN/inventory.json \
  --nested-sf-plan $RUN/nested_sf_plan.json \
  --scope-node MIGRATION-TEST-NODE \
  --steps 0-12 \
  --resume
```

The 5-option dispatch tree is consulted per row exactly as in
Workflow B. The `--resume` projection (`list_shared_folder_names` +
`find_folder_uid`) skips any SF whose qualified/flattened name is
already present on target. The first-pass-crash-mid-promote case is
covered by `step_vault_folders`'s state-reconciliation: SFs created
before the crash get their UIDs recovered via `find_folder_uid` so
later steps that depend on SF UID (membership, sub-record placement)
see the right value.

---

## Cycle harness — `--cycles N --hammer` (squad-2 T6)

Not a user-facing subcommand. Lives in:

- `keeper_tenant_migrate/cycled_validation.py` — fakes-only harness
  (`CycledHarness.run(cycles=N)`).
- `migration_scripts/ci/comprehensive_rehearsal.py` — live-mode
  wiring (`--cycles N` and `--hammer` flags).

What it asserts after every cycle:

1. **Source-read-only (Rule 0)** — source bytes captured once before
   cycle 1; re-checked after every cycle. `SourceMutationError` on
   divergence. Audit log records the breach BEFORE the exception so
   post-mortem inspection works.
2. **Target idempotency** — post-create state on cycle N is byte-equal
   to cycle 1.
3. **Undo cleanliness** — after each cycle's undo + verify-clean, the
   target carries zero MIGTEST-* entities.
4. **No metric drift** — per-cycle deltas (API calls, runtime,
   throttle events, verify pass rate, undo completion rate) within
   ±5% of cycle 1.

Default cycles = 3 (squad-2 brief T6.4 lock).

Use this to validate a cleanup pass — if 3 cycles pass clean, your
config + roster + inventory are migration-stable.

---

## Decision tree — which workflow do I run?

```
            Did source `plan` emit
            shared_folder_folder rows?
                    │
        ┌───────────┴───────────┐
        │                       │
        no                      yes
        │                       │
        ▼                       ▼
   Workflow A            Operator wants to
                         mix per-folder
                         strategies?
                                │
                    ┌───────────┴───────────┐
                    │                       │
                    no, default OK          yes
                    │                       │
                    ▼                       ▼
               Workflow A          Workflow B
              (default action       (--per-folder-rules)
              promote-to-sibling
              already handles it)


            Mid-stage crash on structure?
                    │
        ┌───────────┴───────────┐
        │                       │
        no                      yes
        │                       │
        ▼                       ▼
   continue              Workflow C
   playbook              (--resume)
```

---

## Failure-recovery quick reference

| Stage | If it fails... | Action |
|---|---|---|
| `pre-flight` | abort the run, fix the underlying issue (roster shape, disk, auth). |
| `plan` | usually a transient throttle; rerun. If repeats, drop scope (`--node`, `--prefix`). |
| `estimate` | offline only — never fails on a healthy inventory. |
| `point-of-no-return` | refuses on FAIL severities — fix the offenders, rerun pre-flight, rerun gate. |
| `structure` | `--resume` (Workflow C). |
| `users` | per-row checkpointed; `--resume` picks up after the last successful invite. |
| `records-export` | `--resume` not yet on this stage — restart with the same `--prefix`/`--folder-uid` (idempotent: target dir is overwritten). |
| `records-import` | `--dry-run` first to validate; on failure, edit the bundle or re-run. |
| `records-attachments-{download,upload}` | upload has `--resume`; download is restart-safe (file overwrite). |
| `records-shares` | `--resume`. |
| `shared-folders-reconcile` | idempotent — just rerun. |
| `verify` | offline; rerun. |
| `reconcile` | offline; rerun. |
| `decommission --plan-only` | rerun; if execution path failed mid-roster, the `--report-output` CSV records who was processed. |

---

## Workflow D — Post-migration handoff to downstream consumers (Python API)

**When to run:** after Workflow A (or B) completes and `verify` has reported all-green. The target tenant now has the migrated records but the run-dir state (inventory + manifest + audit chain) is useful to downstream tooling — declarative SDKs that want to adopt the new tenant for ongoing management, SIEM ingestors that want the audit-chain evidence stream, compliance tools that want to record the cutover, drift watchers that want a baseline.

**Time budget:** ~10 minutes operator wall-clock for the API setup; ongoing consumer-side polling/scheduling is separate.

**Mental model.** The tenant migration tool did the **migration day** — one-shot transfer source → target. From this point forward, the target tenant's state can drift unless something owns the lifecycle. The Python API exposed by `integrations/dsk_hooks.py` is the stable surface any consumer reads from — declarative SDK, SIEM ingestor, drift watcher, compliance dashboard, anything else. Schema details are in [`OUTPUT_CONTRACT.md`](OUTPUT_CONTRACT.md).

### Prerequisites

| Requirement | Verify with |
|---|---|
| Workflow A `verify` (Step 14) reported all-green | inspect `verify-reports/` in `$RUN`; expect zero `FAIL` rows across all phases |
| Run-dir intact | `ls $RUN` shows `inventory.json`, `manifest.csv`, `records-export/`, `audit.log`, `SHA256SUMS.txt` |
| `audit.log` chain unbroken | `keeper tenant-migrate audit-verify --run-dir "$RUN"` reports no breakage |
| Records integrity | `cd $RUN && sha256sum -c SHA256SUMS.txt` returns all `OK` |
| Downstream consumer ready | the consumer has `keeper_tenant_migrate` importable in its Python environment (installs via the package's distribution channel) |

If any prerequisite fails: **fix it before starting**.

### Operator side — audit + export

```bash
export RUN_DIR=$RUN                                # the run-dir from Workflow A

# 1. Confirm the run-dir's audit chain is intact (HMAC-chained)
keeper tenant-migrate audit-verify --run-dir "$RUN_DIR"

# 2. Emit SIEM-ready evidence (CEF / syslog / JSONL)
keeper tenant-migrate audit-export --run-dir "$RUN_DIR" --format cef \
    > /var/log/migrations/$(basename $RUN_DIR).cef

# 3. Confirm the integrity manifest
sha256sum -c "$RUN_DIR/SHA256SUMS.txt"
```

The run-dir is now consumer-ready.

### Consumer side — Python API

A downstream consumer imports from `keepercommander.commands.keeper_tenant_migrate.integrations.dsk_hooks` and reads the canonical artifacts:

```python
from keepercommander.commands.keeper_tenant_migrate.integrations.dsk_hooks import (
    discover_run_dir,
    verify_run_dir_integrity,
    get_audit_chain_tail,
    get_users_transition_table,
    get_enterprise_state,
    get_vault_sharing_state,
    get_compliance_evidence,
    stream_compliance_evidence_for_siem,
)

artifacts = discover_run_dir("/path/to/run-dir")
report = verify_run_dir_integrity(artifacts, require_minisig=False)
assert report.audit_chain_ok and report.sha256_manifest_ok

# Typed access to the canonical state:
users = get_users_transition_table(artifacts)        # per-user migration row
ent = get_enterprise_state(artifacts)                # nodes / roles / teams
sharing = get_vault_sharing_state(artifacts)         # SF + record shares

# SIEM streaming (compliance evidence event stream)
for event in stream_compliance_evidence_for_siem(artifacts):
    siem_client.ingest(event)
```

Full API surface: **13 callable hooks + 8 type symbols**. Signatures versioned by `keeper_tenant_migrate`'s own SemVer; breaking changes require deprecation aliases. See `integrations/dsk_hooks.py` for the complete docstring inventory.

### What this enables

- **Declarative-SDK adoption** — a downstream SDK adopts the migrated records under its own ownership marker; subsequent edits go through the SDK's plan/apply cycle
- **Drift detection** — the consumer caches the baseline state and compares periodically; alerts on unauthorised changes
- **Compliance evidence** — the `stream_compliance_evidence_for_siem` hook produces CEF/syslog/JSONL events for ingestion into SIEM platforms
- **GitOps flow** — the consumer commits the canonical state to a git ops repo; subsequent changes land via PR + apply
- **Cross-product reporting** — typed access to user-transition tables and vault-sharing state for dashboards / billing / capacity-planning

### Pitfalls

#### `manifest.csv` rows with `status=ambiguous` or `status=unpaired`

If `records-attachments` ran with `--allow-ambiguous`, ambiguous rows got first-match. Downstream consumers adopt the picked target_uid — fine if intended. If not, fix on target tenant directly, then re-run the consumer's adopt step (idempotent for well-designed consumers).

`unpaired` rows mean the source record didn't pair on target side (title collision, import failure, scope exclusion). Either re-run the affected migration step (`records-import`) and regenerate `manifest.csv`, or ignore if the row was intentionally out of scope.

#### Don't commit the run-dir to a shared ops repo

The run-dir contains `records-export/<uid>.json` files with **plaintext field values** (passwords, SSH keys) when `--include-fields` was used. Per [`SECURITY_MODEL.md`](SECURITY_MODEL.md), the run-dir is a transient artifact — once the consumer has adopted state, the operator should `rm -rf "$RUN_DIR"` or move it to ephemeral encrypted storage. The consumer's derived manifest carries no plaintext (the API never returns secret values); that derived manifest is safe to commit; the run-dir is not.

#### Trust-boundary discipline on the consumer side

`integrations/dsk_hooks.py:_safe_open` enforces `O_NOFOLLOW` + regular-file + size checks. Consumers should adopt the same discipline at any other I/O boundary they introduce — symlinks and non-regular files are refused by the API helpers; replicating the pattern elsewhere keeps the trust boundary symmetric.

### Quick decision: do I run Workflow D?

| Situation | Run Workflow D? |
|---|---|
| Customer wants ongoing declarative management, GitOps flow, drift detection | **Yes.** Standard handoff. |
| Customer wants compliance / SIEM evidence stream | **Yes.** Run the audit-export step + the consumer's SIEM ingest hook. |
| Customer wants one-shot migration only, target tenant managed elsewhere (e.g. Terraform) | **No.** Skip D — Workflow A's output is complete on its own. |
| Customer not sure | Default to **No** — Workflow D can be retro-applied any time, as long as the run-dir is preserved. |

---

## Workflow E — Absorption (S2: source company B merges into A's existing tenant)

**When to run:** acquisition / M&A close. Source tenant B is full; **target tenant A is non-empty** (A has its own users, structure, records, shared folders already).

**Time budget:** highly dependent on B's scale. Plan for several hours wall-clock for a ~50-user / ~1000-record absorption; full day or more for larger.

**Mental model.** Standard forward migration assumes an empty target. Absorption is what you actually do during M&A: B's content merges into A's existing tree. Collisions are the operator's problem; the tool surfaces them and applies rename-with-suffix by default.

### Prerequisites

| Requirement | Verify with |
|---|---|
| Both tenants accessible | separate Commander shells, separate `keeper login` per shell, shared `--run-dir` |
| A's seat count has headroom | manual: A's seat count must accommodate B's user count after collisions resolved |
| Node-remap strategy decided | typically a new sub-node under A: `B Company (acquired YYYY-Q#)` |
| SSO/IdP plan for B's users | decide: keep B's email domains (no IdP changes needed) OR rewrite via `users.domain_remap` overlay verb |
| B's source users granted SHARE_FOLDER prerequisites | surfaced in `manual-actions` after `pre-flight`; each user grants the migrating admin access to records shared between B users |
| A's admin notified of license/seat impact | out of scope for tool; admin handles |

### Operator sequence

```bash
# === On source shell (B) ===
keeper login                              # interactive

keeper tenant-migrate pre-flight --config <source-config> --run-dir $RUN
keeper tenant-migrate audit-lockout-risk --config <source-config> --run-dir $RUN
keeper tenant-migrate plan --config <source-config> --run-dir $RUN
keeper tenant-migrate assemble-inventory --config <source-config> --run-dir $RUN
keeper tenant-migrate estimate --config <source-config> --run-dir $RUN

# === On target shell (A) ===
keeper login                              # separate session, separate shell

keeper tenant-migrate capture-target-state --config <target-config> --run-dir $RUN
# Records A's pre-absorption state; defines what NOT to touch.

# === Author the overlay (any shell, writes to run-dir) ===
$EDITOR $RUN/migration.yaml
```

A minimal absorption overlay:

```yaml
scope:
  include_nodes: ["My Company/*"]                  # everything under B's root
nodes:
  remap:
    "My Company": "B Company (acquired 2026-Q2)"   # land B's tree under a new sub-node of A
teams:
  rename:                                          # if A already has same-named teams
    "Administrator": "B-Administrator"
users:
  domain_remap: { "@b-company.com": "@a-company.com" }
  drop:                                            # users that don't transfer
    - "specific.c-suite@b-company.com"
```

Then validate, apply, verify:

```bash
keeper tenant-migrate declare validate --run-dir $RUN
keeper tenant-migrate declare overlay --run-dir $RUN
keeper tenant-migrate transition-check --run-dir $RUN

# Customer review
keeper tenant-migrate plan-report --run-dir $RUN > b-absorption-preview.md

# Point of no return (locks the plan)
keeper tenant-migrate point-of-no-return --run-dir $RUN

# Apply (on target shell A) — standard sequence
keeper tenant-migrate structure --config <target-config> --run-dir $RUN
keeper tenant-migrate users --config <target-config> --run-dir $RUN

# Records pipeline
keeper tenant-migrate records-export --config <source-config> --run-dir $RUN
keeper tenant-migrate convert --run-dir $RUN
keeper tenant-migrate records-import --config <target-config> --run-dir $RUN
keeper tenant-migrate records-shares extract --config <source-config> --run-dir $RUN
keeper tenant-migrate records-shares apply --config <target-config> --run-dir $RUN
keeper tenant-migrate records-attachments download --config <source-config> --run-dir $RUN
keeper tenant-migrate records-attachments upload --config <target-config> --run-dir $RUN
keeper tenant-migrate records-references-rewrite --run-dir $RUN

# Take ownership / user transfers
keeper tenant-migrate take-ownership --config <target-config> --run-dir $RUN
keeper tenant-migrate transfer-user --config <source-config> --target-config <target-config> --run-dir $RUN

# Reconcile + verify
keeper tenant-migrate shared-folders-reconcile --config <target-config> --run-dir $RUN
keeper tenant-migrate verify --config <target-config> --run-dir $RUN
keeper tenant-migrate audit-verify --run-dir $RUN

# After A's admin confirms B's data is intact in A
keeper tenant-migrate cleanup --config <source-config> --run-dir $RUN
keeper tenant-migrate decommission --config <source-config> --run-dir $RUN
```

### What's automated vs manual

| Automated | Manual (out of scope per [`LIMITATIONS.md`](LIMITATIONS.md)) |
|---|---|
| Data move, audit chain, collision rename-with-suffix (Layer-1 default), verify pass, cleanup/decommission on source | Seat-count delta estimate at A; collision merge policy (rename-with-suffix is default; merging equivalent roles/SFs is post-absorption admin work); IdP repointing for B's users; PAM re-setup on A; Personal-Keeper user acceptances (Category B); cross-enterprise conflict resolution (Category C); SSO/SCIM bridge during transition; source-tenant decommission timing |

---

## Workflow F — Divestiture (S3: subset of A moves to new tenant A')

**When to run:** spin-off, business-unit separation, divestiture. Source A is full; **target A' is a new empty tenant**; selection is a **subset** of A's tree.

**Time budget:** like absorption, scale-dependent. Add overhead for dual-ownership review.

**Mental model.** Divestiture is selective extraction. declare-overlay's scope filter does the heavy lifting; the operator's hardest work is deciding what stays at A vs. what moves to A'. Source-side cleanup happens last and is gated on A' verification.

### Prerequisites

| Requirement | Verify with |
|---|---|
| Both tenants accessible | A's existing session + A' (newly provisioned) session |
| Scope decided | which nodes/teams/users transfer to A'; which stay at A |
| A' has seat-count for divested users | out of scope; admin handles |
| Dual-ownership policy | for records shared by BOTH the divested subtree AND the residual A tree, admin's per-record decision (typically: copy to A', keep at A, mark for manual ownership review) |
| IdP/SSO plan for A''s users | usually a new tenant binding on the IdP |

### Operator sequence

```bash
# === On source shell (A) ===
keeper login

keeper tenant-migrate pre-flight --config <source-config> --run-dir $RUN
keeper tenant-migrate audit-lockout-risk --config <source-config> --run-dir $RUN

# === On target shell (A', greenfield) ===
keeper login

keeper tenant-migrate capture-target-state --config <target-config> --run-dir $RUN
# Records the empty A' state for the verify pass to compare against.

# === Author the divestiture overlay ===
$EDITOR $RUN/migration.yaml
```

A divestiture overlay (subset scope):

```yaml
scope:
  include_nodes: ["My Company/Spin-Off Division/*"]
  exclude_nodes: ["My Company/Spin-Off Division/Confidential-Stays-At-Parent"]
users:
  drop:
    - "specific.parent-only.users@a-company.com"
teams:
  drop:
    - "A-internal team that isn't transferring"
```

Then plan against the filtered scope, validate, apply, verify:

```bash
keeper tenant-migrate plan --config <source-config> --run-dir $RUN
keeper tenant-migrate assemble-inventory --config <source-config> --run-dir $RUN
keeper tenant-migrate estimate --config <source-config> --run-dir $RUN

keeper tenant-migrate declare validate --run-dir $RUN
keeper tenant-migrate declare overlay --run-dir $RUN
keeper tenant-migrate transition-check --run-dir $RUN

# Dual-ownership review (admin manual step)
# Inspect $RUN/manual-actions.json — look for DUAL_OWNERSHIP_REVIEW
# entries. Each is a record shared with both the divested subtree
# AND the residual A tree. Admin decides per-record.

# Customer review
keeper tenant-migrate plan-report --run-dir $RUN > divestiture-preview.md

# Point of no return
keeper tenant-migrate point-of-no-return --run-dir $RUN

# Apply (on A' shell) — same standard sequence as Workflow A
keeper tenant-migrate structure --config <target-config> --run-dir $RUN
keeper tenant-migrate users --config <target-config> --run-dir $RUN
keeper tenant-migrate records-export --config <source-config> --run-dir $RUN
keeper tenant-migrate convert --run-dir $RUN
keeper tenant-migrate records-import --config <target-config> --run-dir $RUN
keeper tenant-migrate records-shares extract --config <source-config> --run-dir $RUN
keeper tenant-migrate records-shares apply --config <target-config> --run-dir $RUN
keeper tenant-migrate records-attachments download --config <source-config> --run-dir $RUN
keeper tenant-migrate records-attachments upload --config <target-config> --run-dir $RUN
keeper tenant-migrate records-references-rewrite --run-dir $RUN

# Take ownership in A'
keeper tenant-migrate take-ownership --config <target-config> --run-dir $RUN

# Verify A'
keeper tenant-migrate shared-folders-reconcile --config <target-config> --run-dir $RUN
keeper tenant-migrate verify --config <target-config> --run-dir $RUN
keeper tenant-migrate audit-verify --run-dir $RUN

# Source-side cleanup (DESTRUCTIVE on A — only after A' fully verified)
keeper tenant-migrate cleanup --config <source-config> --run-dir $RUN
keeper tenant-migrate decommission --config <source-config> --run-dir $RUN
```

### What's automated vs manual

| Automated | Manual (out of scope per [`LIMITATIONS.md`](LIMITATIONS.md) + `PRODUCT_OVERVIEW.md` M&A row) |
|---|---|
| Scope filtering via declare-overlay; data move; audit chain; rename-with-suffix for any incidental collisions (rare in greenfield A'); verify pass | Scope-include / scope-exclude decisions (admin's organisational knowledge); dual-ownership per-record decisions; source-side cleanup TIMING (must happen only after A' is fully verified); seat-count reduction at A after cleanup; IdP repointing for A''s new users; new IdP binding for A'; SSO bridge during transition; PAM re-setup at A' |

---

## Subcommand sequence diagram

```
  pre-flight ──▶ plan ──▶ estimate ──▶ point-of-no-return ──▶ structure
                                                                  │
                                              (Workflow C)   ◀────┤  --resume
                                                                  ▼
                                                                users
                                                                  │
                                                                  ▼
  records-export ──▶ convert ──▶ records-import ──▶ records-manifest
                                        │
                                        ▼
            ┌───── records-shares ──────┴────── records-attachments-{dl,up}
            │
            ▼
   capture-target-state ──▶ verify ──▶ reconcile ──▶ shared-folders-reconcile
                                                              │
                                                              ▼
                                              decommission --plan-only
                                              ◀───── (operator runs by hand)
```

---

## See also

- `.context/command-surface.md` — argparse-truth flag reference for
  every subcommand.
- `keeper_tenant_migrate/RUNBOOK.md` — narrative end-to-end walkthrough.
- `keeper_tenant_migrate/SECURITY_MODEL.md` — interlock chain detail.
- `keeper_tenant_migrate/DEPENDENCY_SCHEMATIC.md` — 5-diagram
  architecture organigram (squad-2 update appended).
- `.context/squad-2-plan.md` — the round 2 brief that produced
  `--resume`, `--nested-sf-plan`, and the cycled harness.
- `.context/sf-option-matrix.md` — the 5-option SF migration matrix.
- `.context/sf-commander-surface.md` — Commander's nested-SF surface
  audit (T2).
