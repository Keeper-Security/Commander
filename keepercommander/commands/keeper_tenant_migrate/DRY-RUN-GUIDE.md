# Dry-run guide — one step at a time

Every mutating subcommand accepts `--dry-run`. In dry-run mode:

- No write reaches the tenant — the Commander client is wrapped so each
  would-be write is intercepted and recorded.
- The driver still walks its full code path, populating counters and
  result rows as if the run had succeeded.
- An optional `--dry-run-report REPORT.md` emits a Markdown plan
  classifying each op as **CREATE** (target lacks it), **SKIP**
  (already present), **CONFLICT** (present with different attrs),
  **DELETE** (teardown), or **UNCHECKED**.

Read-only subcommands (`plan`, `verify`, `reconcile`, `self-test`,
`pre-flight`, `capture-target-state`, `assemble-inventory`,
`transition-check`, `convert`, `records-manifest`, `manual-actions`,
`records-export`) never touch target state, so they have no dry-run.

## Help

Commander's group-dispatch handles `--help` at every level:

```
tenant-migrate                # lists all 24 subcommands with one-line descriptions
tenant-migrate structure --help   # flags + defaults for structure
tenant-migrate take-ownership --help
# …one per subcommand
```

Help output is produced by the underlying argparse parsers and tested
end-to-end in `tests/test_dispatch.py`.

## Step-by-step — dry-run every phase before touching anything

The customer's typical order when they want *every* step pre-flighted
separately:

### 1. Validate the environment (read-only, cheap)

```
tenant-migrate pre-flight --roster roster.csv \
  --output-dir /tmp/run --csv-output /tmp/preflight.csv

tenant-migrate self-test
```

Pre-flight reads the roster for sanity and confirms Commander version /
disk / output-dir writability. Self-test probes every SDK integration
point without writing.

### 2. Capture plan + classify users (read-only)

```
tenant-migrate plan --output /tmp/inv.json \
  --node MIGRATION-TEST-NODE --prefix MIGTEST-
```

(Switch to target session, then:)

```
keeper --config target-config.json enterprise-info --users --format csv \
  --columns status,transfer_status,node > /tmp/target_users.csv

tenant-migrate transition-check \
  --inventory /tmp/inv.json \
  --target-users-csv /tmp/target_users.csv \
  --csv-output /tmp/plan.csv --md-output /tmp/plan.md

tenant-migrate manual-actions \
  --inventory /tmp/inv.json \
  --transition-plan /tmp/plan.csv \
  --output /tmp/manual-actions.md
```

`manual-actions.md` is the customer's checklist — items users must do
(create MIGRATION-* folders, accept invites, unlock accounts, …).

### 3. Dry-run each mutating phase individually

All seven mutating subcommands now accept `--dry-run --dry-run-report`:

```
# Path A ownership transfer — preview on source session
tenant-migrate take-ownership \
  --verification-report verify.csv \
  --backup-dir /tmp/backups \
  --report-output /tmp/ownership.csv \
  --dry-run --dry-run-report /tmp/ownership-plan.md

# Path B vault transfer
tenant-migrate transfer-user \
  --readiness-report readiness.csv \
  --report-output /tmp/transfer.csv \
  --dry-run --dry-run-report /tmp/transfer-plan.md

# Structure — entire 13-step restore, or slice via --steps
tenant-migrate structure --inventory /tmp/inv.json \
  --source-root "My company" --target-root Keeperdemo \
  --scope-node MIGRATION-TEST-NODE \
  --steps 0-6 \
  --dry-run --dry-run-report /tmp/structure-plan.md

# Structure — slice a single phase
tenant-migrate structure --inventory /tmp/inv.json \
  --steps 4-4 \
  --dry-run --dry-run-report /tmp/structure-roles.md

# Users — invite + placement
tenant-migrate users --inventory /tmp/inv.json \
  --roster /tmp/roster.csv \
  --transition-plan /tmp/plan.csv \
  --dry-run --dry-run-report /tmp/users-plan.md

# Records pipeline
tenant-migrate records-import --input /tmp/import.json --dry-run
tenant-migrate records-attachments \
  --manifest /tmp/manifest.csv --staging-dir /tmp/att \
  --dry-run --dry-run-report /tmp/attachments-plan.md
tenant-migrate records-shares \
  --manifest /tmp/manifest.csv \
  --skip-missing-users \
  --dry-run --dry-run-report /tmp/shares-plan.md

# Cleanup + decommission
tenant-migrate cleanup --prefix MIGTEST- \
  --dry-run --dry-run-report /tmp/cleanup-plan.md
# NOTE: cleanup without --dry-run requires --confirm

tenant-migrate decommission \
  --roster /tmp/roster.csv \
  --checkpoint /tmp/.checkpoint.json \
  --report-output /tmp/decom.csv \
  --dry-run --dry-run-report /tmp/decom-plan.md
# NOTE: decommission still requires a valid point-of-no-return
# checkpoint even in dry-run — safety rail.
```

### 4. Read the per-phase reports

Every `.md` file follows the same layout:

```
# Dry-run plan

| Outcome    | Count |
|------------|------:|
| CREATE     |   10  |
| SKIP       |    3  |
| CONFLICT   |    1  |
| DELETE     |    0  |
| UNCHECKED  |    0  |
| **Total**  |   14  |

## CONFLICT (1)

- `create_team` — team 'Shared' exists but on a different node …

## CREATE (10)

- `create_node` — node 'MIGRATION-TEST-NODE'
- `create_team` — team 'MIGTEST-Team-AllRestrictions'
- …
```

Workflow:

1. If **CONFLICT > 0** — read the detail for each; either rename the
   source entity, delete the target conflict, or accept drift.
2. If **CREATE > 0** — those are the ops the live run will add. Good.
3. **SKIP** entries are no-ops; safe to leave.
4. **UNCHECKED** entries couldn't be probed from target state alone
   (usually because they depend on another op's output). Re-run the
   dry-run after the earlier phase has landed to recheck.

### 5. Flip to live

Drop `--dry-run --dry-run-report …` and rerun the same command. The
driver executes the same plan with no other flag changes.

```
tenant-migrate structure --inventory /tmp/inv.json \
  --source-root "My company" --target-root Keeperdemo \
  --scope-node MIGRATION-TEST-NODE --steps 0-6
```

### 6. MSP admins — target a specific Managed Company

Add `--mc` to route any stage at a MC child tenant:

```
tenant-migrate run --inventory /tmp/inv.json --output-dir /tmp/run \
  --mc "Customer Inc."     # switches to MC, runs, switches back to MSP
```

Works on `run`, `structure`, `users` today; extendable to the other
subcommands (same one-line wrap pattern).

## Recovering from an aborted live run

Every stage writes a checkpoint. To resume:

```
tenant-migrate run --inventory /tmp/inv.json --output-dir /tmp/run --resume
```

The orchestrator reads `/tmp/run/.run_state`, skips already-completed
stages, and re-runs whichever one failed. Pairs with `--end-stage` to
stop at a specific phase.
