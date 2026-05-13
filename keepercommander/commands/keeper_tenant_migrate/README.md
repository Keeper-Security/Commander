# `keeper-tenant-migrate`

Keeper tenant-lifecycle tool. Moves users, roles, teams, nodes,
records, shared folders, attachments, and audit trail between
Keeper enterprise/MSP tenants. Handles five distinct lifecycle
scenarios (see matrix below); six workflows compose existing
primitives.

**Status**: v1.7.7 — 41 subcommands, **2491 plugin tests** (1
pre-existing skip), 88% line coverage, live-proven end-to-end on
real tenants (rehearsal-15 against Commander v17.2.13, rehearsal-16
against v18.0.0).

Ships as a Commander plugin (registered via Commander's plugin
discovery) and as a standalone `keeper-migrate` console script for
one-shot invocation.

## Tenant-lifecycle scenarios

A "migration" can mean any of five events. The same primitives
handle all five; the operator workflow differs.

| # | Scenario | Source state | Target state | Selection | Workflow |
|---|---|---|---|---|---|
| **S1** | Same-customer rename / rehome (e.g. EU→US data residency, MSP rebrand) | full | empty | 100% goes | Workflow A — Standard forward |
| **S2** | Absorption / acquisition (Company B folds into A's existing tenant) | full | **non-empty** | 100% of B; merge into A | Workflow E — Absorption |
| **S3** | Divestiture / spin-off (subset of A splits to new tenant A') | full | empty new | **subset** by scope filter | Workflow F — Divestiture |
| **S4** | MSP customer transfer (MSP-X → MSP-Y, or MSP → standalone enterprise) | full MC subset | empty or non-empty MC subset | full MC scope | Workflow A with `--mc <name>` |
| **S5** | Carve-out + merger (subset of A spins off, then absorbed into B) | partial | non-empty | subset | F → E composed, two separate run-dirs |

Run-machinery workflows orthogonal to the lifecycle scenarios:

- **Workflow B** — Nested shared folder; preserves multi-level SF
  hierarchies. Applies to S1, S2, S3 when SFs are deep.
- **Workflow C** — Resume after mid-stage crash; signed
  checkpoints. Applies to all scenarios.
- **Workflow D** — Post-migration handoff to downstream consumers
  via the stable Python API (`integrations/dsk_hooks.py`). Applies
  to all scenarios.

Full workflow narratives in `OPERATOR_PLAYBOOK.md`.

> **Reading path**: `RUNBOOK.md` (canonical run-through) →
> `OPERATOR_PLAYBOOK.md` (six workflows step-by-step) →
> `SECURITY_MODEL.md` (4-layer interlock, audit chain integrity,
> 0o600 plaintext handling) → `OUTPUT_CONTRACT.md` (run-dir schema
> for downstream consumers) → `DEPENDENCY_SCHEMATIC.md` (5-diagram
> architecture organigram) → `migration_scripts/ci/REHEARSAL_GUIDE.md`
> (live-test harness, Tiers 1-7 + scale Tier 8 + cycled Tier 9).

## What the tool does

A complete tenant-to-tenant migration with:

- **Read-only source enforcement** — source tenant is never written
  to during a migration; destructive operations layered behind
  source-mode interlock + tenant-name assertion + explicit
  `--confirm-source-destructive`.
- **Dry-run + plan-report** — preview the full migration before
  authorizing it; produce customer-facing review reports.
- **Tamper-evident audit chain** — every destructive op appends an
  HMAC-chained event to `<run_dir>/audit.log`; `audit-verify` walks
  the chain and detects post-hoc tampering; safe for SIEM
  forwarding (CEF / syslog / json-lines).
- **Resume + checkpoint** — multi-hour migrations survive mid-run
  interruption via signed checkpoints.
- **MC scoping** — `--mc <name>` routes destructive operations to a
  specific Managed Company; `mc-leak-check` in the rehearsal harness
  verifies no writes leak to the MSP root.
- **Undo** — `undo --execute` rewinds operations using the audit log
  as source of truth; `--mc` threading keeps reversals scoped.
- **Stable Python API for declarative-SDK consumers** —
  `keepercommander.commands.keeper_tenant_migrate.integrations.dsk_hooks` ships 14 callable
  hooks + 8 type symbols, R6.1 SemVer-versioned.

## Two-shell model

Each Commander shell authenticates to ONE tenant. The tool runs in
whichever shell you launched; cross-tenant coordination happens
through a **shared run directory** — both shells point at the same
`--run-dir PATH`, and hand off state via files (`inventory.json`,
`target_state.json`, `manifest.csv`, `checks.csv`,
`reconciliation.md`, `audit.log`, `SHA256SUMS.txt`).

The **wizard** (`tenant-migrate wizard --run-dir PATH`) is the
menu-driven front door: it detects whether your shell is the source
or target by matching `params` against the `migration.yaml` run-spec,
inspects what artifacts already exist in the run-dir, and proposes
the next appropriate step for THIS shell's role. See `WIZARD_GUIDE.md`
for the 10-minute walkthrough.

Individual subcommands work standalone — wizard is optional. Power
users chain them with `--config SRC` and `--config TGT` invocations.

## Subcommand surface

41 subcommands grouped by phase. Full surface + flag detail at
`.context/subcommand-surface-catalogue-2026-05-10.md`.

| Phase | Subcommands |
|---|---|
| **Pre-flight** | `self-test`, `session`, `pre-flight`, `audit-lockout-risk` |
| **Plan** | `plan`, `assemble-inventory`, `estimate`, `transition-check`, `nested-sf-plan`, `plan-report`, `capture-target-state` |
| **Declare overlay** | `declare overlay`, `declare validate` |
| **Restore on target** | `structure`, `users`, `shared-folders-reconcile` |
| **Records pipeline** | `records-export`, `convert`, `records-import`, `records-manifest`, `records-shares` (extract / apply), `records-attachments` (download / upload), `records-references-rewrite` |
| **Take ownership** | `take-ownership`, `take-ownership-restore`, `transfer-user` |
| **Verify + reconcile** | `verify`, `reconcile`, `manual-actions` |
| **Audit + replay** | `audit-verify`, `audit-export`, `undo` |
| **Decommission** | `point-of-no-return`, `decommission`, `cleanup` |
| **Orchestrator** | `auto-migrate`, `run`, `wizard` |

## Supported migration topologies

Tenant-agnostic — wherever two Commander sessions can reach, you can
migrate. Verified topologies:

| Source | Target | How |
|---|---|---|
| Enterprise tenant → another enterprise tenant | Plain two-session chain. `RUNBOOK.md` is this case. |
| Enterprise → Managed Company (MC under an MSP) | `--mc "Customer Inc."` on the target-side subcommands routes through `switch-to-mc` before any write. |
| MSP → MSP (transfer one MC between two MSPs) | Run twice: once with `--mc SOURCE_MC` on the origin MSP session (source side), once with `--mc TARGET_MC` on the destination MSP session. The inventory + records artifacts carry between the two MSPs unchanged. |
| Enterprise → Enterprise + node filter | `--node` / `--scope-node` flag on `plan` + `structure` + `users`. |
| Test/MIGTEST subtree → disposable target | `--prefix MIGTEST-` on `plan`; `cleanup --prefix MIGTEST-` on teardown. |

Subcommands don't care about source/target *type* — only what
`params.enterprise` looks like. A Commander session scoped at an MC
via `switch-to-mc` is indistinguishable from a direct enterprise
login.

## Install

`keeper tenant-migrate` ships built-in with Keeper Commander (the
upstream Commander tree contains this subpackage under
`keepercommander/commands/keeper_tenant_migrate/`). No separate
install step is needed.

```bash
pip install --upgrade keepercommander
keeper                                          # interactive shell
```

`tenant-migrate` appears at the Commander prompt automatically.

### One-shot non-interactive invocation

For scripting or CI, use Commander's standard one-shot syntax:

```bash
keeper --config ~/.keeper/source-tenant.json tenant-migrate session
keeper --config ~/.keeper/source-tenant.json tenant-migrate plan \
    --output /tmp/inventory.json
```

### Optional PyYAML for declare-overlay verbs

`declare overlay` reads `migration.yaml`; without `PyYAML` installed
it falls back to a JSON parser (so `migration.json` also works). To
use YAML overlay files:

```bash
pip install pyyaml
```

### `tenant-migrate` at the Commander prompt

```
My Vault> tenant-migrate
tenant-migrate command [--options]

   plan                  Build inventory JSON from live params.enterprise.
   structure             Restore nodes, teams, roles, enforcements, SFs.
   users                 Invite/place users per inventory.
   records-export        Export source records as v3 JSON per file.
   ...
```

## Typical flow

```bash
# 1. On SOURCE tenant: capture inventory
tenant-migrate plan \
    --output $RUN/inventory.json \
    --scope-node MIGRATION-TEST-NODE --prefix MIGTEST-

# 2. On TARGET tenant: capture pre-existing state for verify/reconcile
tenant-migrate capture-target-state --output $RUN/target_state.json

# 3. On TARGET tenant: restore structure (nodes/teams/roles/SFs)
tenant-migrate structure \
    --inventory $RUN/inventory.json \
    --source-root "My company" --target-root "Keeperdemo" \
    --scope-node MIGRATION-TEST-NODE

# 4. On TARGET tenant: invite users
tenant-migrate users \
    --inventory $RUN/inventory.json \
    --roster $RUN/roster.csv

# 5. Records pipeline (source → convert → target → manifest → shares)
tenant-migrate records-export --output-dir $RUN/records_export --prefix MIGTEST-
tenant-migrate convert \
    --input-dir $RUN/records_export --output $RUN/records_import.json
tenant-migrate records-import --input $RUN/records_import.json
tenant-migrate records-manifest \
    --source-dir $RUN/records_export --output $RUN/manifest.csv
tenant-migrate records-shares extract \
    --manifest $RUN/manifest.csv --output $RUN/shares.json
tenant-migrate records-shares apply --input $RUN/shares.json

# 6. Verify + reconcile
tenant-migrate capture-target-state --output $RUN/target_state.json
tenant-migrate verify \
    --inventory $RUN/inventory.json \
    --target-state $RUN/target_state.json \
    --output $RUN/checks.csv
tenant-migrate reconcile \
    --inventory $RUN/inventory.json \
    --target-state $RUN/target_state.json \
    --output $RUN/reconciliation.md
```

Or run the orchestrator end-to-end:

```bash
tenant-migrate auto-migrate \
    --run-dir $RUN \
    --target-config ~/.keeper/target-tenant.json \
    --scope-node MIGRATION-TEST-NODE --prefix MIGTEST- \
    --target-root "Keeperdemo" \
    --expected-source-tenant "My company" \
    --expected-target-tenant "Keeperdemo"
```

## Architecture

Module-per-domain with driver + protocol pattern. The driver holds
logic; the protocol (`StructureClient`, `UserClient`,
`AttachmentClient`, `ShareClient`, …) abstracts every target-side
write so a `FakeClient` can exercise the full path in unit tests
without a live tenant. `commander_clients.py` is the sole SDK
boundary.

```
commands.py             ← subcommand dispatch + argparse (41 parsers)
commander_clients.py    ← SOLE SDK boundary (L1 in DEPENDENCY_SCHEMATIC)
__init__.py             ← exports register_commands / register_command_info
structure.py            ← StructureRestore (13 steps) + StructureClient
users.py                ← UserRunner + UserClient
shares.py               ← ShareRestorer + ShareClient
attachments.py          ← AttachmentMigrator + AttachmentClient
converter.py            ← v3→v2 record format conversion
inventory.py            ← InventoryAssembler (offline)
live_inventory.py       ← Inventory builder from live params.enterprise
transition.py           ← UserTransitionChecker
validate.py             ← 8-phase field-level Validator framework
reconcile.py            ← Reconciler (emits Markdown)
orchestrator.py         ← Stage sequencing with checkpoints/resume
auto_migrate.py         ← End-to-end pipeline orchestrator
checkpoint.py           ← Resumable-loop protocol (signed checkpoints)
mc_context.py           ← --mc Managed Company scoping
estimate.py             ← Throttle-aware pre-flight sizing
audit.py                ← HMAC-chained audit log + SHA256SUMS
audit_export.py         ← CEF / syslog / json-lines for SIEM
declare/                ← Declarative overlay verbs (overlay, validate)
integrations/dsk_hooks.py ← stable Python API for downstream consumers (13 hooks + 8 type symbols)
helpers/node_paths.py   ← remap_root / remap_node / leaf_of
smoke/                  ← CI smoke layer (kwarg-strict)
```

Full architecture: `DEPENDENCY_SCHEMATIC.md` (5-diagram organigram).

## Tests

```bash
python3 -m pytest keeper_tenant_migrate/tests/
# → 2432 passed, 1 skipped, ~85s on a Mac M-series venv
```

Everything under `keeper_tenant_migrate/tests/` runs without a
network connection or authenticated Commander session.

### Live rehearsal harness

The CI harness at `migration_scripts/ci/comprehensive_rehearsal.py`
exercises every automatable subcommand against live tenants in
tiered order (read-only → dry-run → live writes → MC-scoped writes
→ scale → cycled). See `migration_scripts/ci/REHEARSAL_GUIDE.md`
for full usage.

Quick smoke (read-only + dry-runs only — zero target writes):

```bash
python3 migration_scripts/ci/comprehensive_rehearsal.py \
    --source-config ~/.keeper/source-tenant.json \
    --target-config ~/.keeper/target-tenant.json \
    --run-dir /tmp/rehearsal
```

Full pipeline (opt-in live writes, with source-read-only hard-rail):

```bash
python3 migration_scripts/ci/comprehensive_rehearsal.py \
    --source-config ~/.keeper/source-tenant.json \
    --target-config ~/.keeper/target-tenant.json \
    --run-dir /tmp/rehearsal \
    --scope-node MIGRATION-TEST-NODE --prefix MIGTEST- \
    --live-writes
```

MC-scoped path (mc-leak-check verifies no writes leak to MSP root):

```bash
python3 migration_scripts/ci/comprehensive_rehearsal.py \
    --source-config ~/.keeper/source-tenant.json \
    --target-config ~/.keeper/target-tenant.json \
    --run-dir /tmp/rehearsal \
    --scope-node MIGRATION-TEST-NODE --prefix MIGTEST- \
    --live-writes --target-mc "Test Company"
```

### Adversarial suite

`tests/test_adversarial.py` + `tests/test_undo_adversarial.py` +
`tests/test_declare_adversarial.py` enumerate known attack vectors
(safeguard bypass, sideloading, silent failures, manifest daisy-
chain, audit tampering, source-read-only bypass, MC-context lateral
movement, declare-overlay symlink attacks). Each test locks down a
specific defense — any failure flags a regression.

## Security

Three subcommands write plaintext secrets (mode 0600); all defaults
are safe:

| Output | Contains | When |
|---|---|---|
| `records-export /<uid>.json` | login / password / TOTP / notes / custom fields | Always |
| `plan --include-fields` inventory JSON | Same, inside `entities.records[]` | Opt-in only |
| `capture-target-state --include-fields` state JSON | Same | Opt-in only |

Operational guidance:

- Default `plan` / `capture-target-state` exclude record field data
  — only entity metadata. Stick to the default unless field-level
  verify is needed.
- Clean up record exports + field-level inventories after each run.
  The `.sha256` sidecars are 0600 but don't contain secrets.
- The validator never emits raw field values to logs or `checks.csv`
  — FAIL messages say "password mismatch", never the values.
- The reconcile report only reports presence + counts.

Never written anywhere:

- Keeper master passwords (Commander never exposes them).
- Session tokens (`params.session_token` is never serialized).
- Shared-folder encryption keys (handled entirely inside Commander).

Full security model: `SECURITY_MODEL.md`.

## References

- `RUNBOOK.md` — canonical run-through
- `OPERATOR_PLAYBOOK.md` — workflow-A/B/C step-by-step
- `SECURITY_MODEL.md` — 4-layer interlock + audit chain integrity
- `OUTPUT_CONTRACT.md` — run-dir schema for downstream consumers
- `DEPENDENCY_SCHEMATIC.md` — 5-diagram architecture organigram
- `CHANGELOG.md` — release history
- `THROTTLE.md` — rate-limit behavior + tuning
- `DRY-RUN-GUIDE.md` — dry-run mechanics
- `WIZARD_GUIDE.md` — menu-driven front door
- `LIMITATIONS.md` — known limitations + workarounds
- `LIVE_BUGS.md` / `LIVE_BUGS_PLAN.md` — bug-pattern catalogue
- `NEXT_STEPS.md` — open work
- `PUBLISHING.md` — PyPI release recipe (publish PARKED)
- `migration_scripts/` — bash reference implementation (proven, kept
  for lookup)
- `migration_scripts/ci/REHEARSAL_GUIDE.md` — live-test harness
