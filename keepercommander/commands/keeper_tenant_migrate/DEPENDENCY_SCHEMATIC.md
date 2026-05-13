# Dependency schematic — electronic-style organigram

Systems view of the plugin for review, onboarding, and impact analysis.

Notation follows electronic-schematic conventions:
  - `═══` power rail / always-on (session, audit)
  - `───` wire / data flow
  - `▶`   direction of data movement
  - `◊`   interlock / safeguard (interrupts the signal on failure)
  - `[N]` node/block; protocol clients are `[PROT]` with concrete `<CLASS>`
  - `╳`   broken / rejected path

48 modules, 34 subcommands. This doc shows the 6 diagrams that
matter for reasoning about change impact:

  1. Runtime topology (session → subcommand → Commander)
  2. Module dependency layers
  3. Subcommand data flow (inventory.json → …)
  4. Protocol / implementation axis
  5. Safeguard interlock chain
  6. SF migration option dispatch (squad-2 T2)

Squad-2 deltas (merged 2026-04-26):
  - **NEW** `nested_sf_plan.py` (L4 driver, sits next to `structure`)
  - **NEW** `cycled_validation.py` (L4 harness, **not** in the
    migration hot path — CI/test-only orchestrator that drives the
    same L4 drivers across N cycles)
  - **NEW** `smoke/` package (orthogonal to the L1-L5 stack — kwarg-
    strict CI layer that swaps Commander's argparse parsers in for
    `commander_clients` validation)
  - **EXTENDED** `structure.py` — state-reconciliation under
    `--resume`, 5-option dispatch under `--nested-sf-plan`
  - **EXTENDED** `commander_clients.py` — 12 new projection methods
    (`list_*` / `find_folder_uid`) used only by `--resume`

---

## 1. Runtime topology — where writes actually go

```
  operator machine                          keeper cloud
  ┌────────────────────┐                   ┌──────────────┐
  │ keeper-migrate     │                   │ SOURCE tenant │
  │  ├ plugin_loader   │──── session A ───▶│ (EU demo)     │
  │  ├ __main__        │    [READ ONLY]    └──────────────┘
  │  └ commands.py     │
  │      │             │                   ┌──────────────┐
  │      │  MCContext  │──── session B ───▶│ TARGET tenant│
  │      │  ─────◊───  │     [MSP root]    │ (MSP/MC)     │
  │      │   │         │                   │  │           │
  │      │   └─ --mc ──┼──── switch ──────▶│  └─ MC-A     │
  │      ▼             │                   │  └─ MC-B     │
  │   commander_       │                   │  └─ MC-C     │
  │   clients.py       │                   └──────────────┘
  └────────────────────┘

Two sessions NEVER share process state. The plugin holds one at a time
(Commander limitation). Cross-tenant coordination via files in $RUN.

Interlocks (◊) at the boundary:
  ◊ --source-read-only   (harness) — refuses destructive subcmd against
                          source-config before subprocess starts
  ◊ source_mode:read_only (migration.yaml) — 4-layer interlock in
                          subcommands refuses source writes
  ◊ MCContext            — returns MC-scoped params; callers use
                          ctx.params for subsequent ops
```

---

## 2. Module dependency layers

Layered bottom-up. Lower layers have zero upward deps. Circular imports
would break this — the tree is acyclic by construction.

```
  ┌─────────────────────────────────────────────────────────────┐
  │  L5  —  entrypoints + orchestration                         │
  │   __main__ · plugin_loader · commands · wizard · menu       │
  │                         │                                    │
  └────────────────────────┬┴────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  L4  —  subcommand drivers (protocol + logic)               │
  │   structure · users · shares · attachments · reconcile      │
  │   sf_reconcile · cleanup · decommission · transfer_user     │
  │   take_ownership · take_ownership_restore · inventory       │
  │   live_inventory · validate · verify(in commands) · run     │
  │   nested_sf_plan ★squad-2                                   │
  │                         │                                    │
  └────────────────────────┬┴────────────────────────────────────┘
                           │
       (orthogonal:                                              │
        cycled_validation ★squad-2 — drives L4 drivers across   │
        N cycles for round-trip validation; NOT in the migration │
        hot path. Uses ONLY Fake* clients. No L1 imports.)       │
                           │
       (orthogonal: smoke/ ★squad-2 — kwarg-strict L1            │
        substitute that swaps Commander argparse parsers in to   │
        validate commander_clients dispatches the right kwargs.) │
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  L3  —  cross-cutting services                              │
  │   mc_context · dry_run · checkpoint · backoff · safeguards  │
  │   gate · email_remap · orchestrator · estimate              │
  │                         │                                    │
  └────────────────────────┬┴────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  L2  —  shared data + I/O helpers                           │
  │   audit · csv_utils · converter · manifest · helpers/        │
  │   compliance · compat_checks · preflight · selftest         │
  │   session · transition · tenant_profile                     │
  │                         │                                    │
  └────────────────────────┬┴────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  L1  —  Commander SDK wrappers                              │
  │   commander_clients       (SDK → protocols)                  │
  │   audit_export            (SIEM formats)                     │
  │                                                              │
  └─────────────────────────────────────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  L0  —  Commander SDK (external, pinned v17.2.13)           │
  └─────────────────────────────────────────────────────────────┘
```

Promotion rule: adding an L1 import to an L3 module drives that L3 down
to L1 abstractly (implementation detail leak). Keep L3 clean of SDK
imports — go through a protocol.

---

## 3. Subcommand data flow — the pipeline

```
                     ┌──────────────┐
  [SOURCE session]   │   plan       │  reads: params.enterprise,
                     │              │         folder_cache,
                     │              │         subfolder_record_cache
                     └──────┬───────┘  writes: $RUN/inventory.json
                            │                  (0600 if --include-fields)
                            ▼
                     ╔══════════════════════════════════════╗
                     ║      $RUN/inventory.json (hand-off)   ║
                     ╚══════════════════════════════════════╝
                            │
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
  │  estimate    │  │  structure   │  │  shared-folders- │
  │              │  │              │  │  reconcile       │
  │  pre-flight  │  │              │  │                  │
  │  sizing      │  │              │  │                  │
  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
         │                 │                    │
         ▼                 ▼                    ▼
    estimate.md       target tenant        (add/prune SF
    estimate.json     gets nodes/          memberships as
                      teams/roles          users activate)

                     ┌──────────────┐
                     │ records-     │   [SOURCE session]
                     │ export       │
                     │              │
                     └──────┬───────┘
                            │   per-record JSON (0600)
                            ▼   + staging.json (for attachments)
                     ╔══════════════════════════════════════╗
                     ║   $RUN/records_export/*.json         ║
                     ║   (+ staging for attachments)        ║
                     ╚══════════════════════════════════════╝
                            │
                            ▼
                     ┌──────────────┐
                     │  convert     │   [local, no network]
                     │              │   v3 → v2 import bundle
                     └──────┬───────┘
                            ▼
                     ╔══════════════════════════════════════╗
                     ║   $RUN/records_import.json           ║
                     ╚══════════════════════════════════════╝
                            │
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
  │ records-     │  │ records-     │  │ records-         │
  │ import       │  │ attachments- │  │ attachments-     │
  │              │  │ download     │  │ upload           │
  │ [TARGET]     │  │ [SOURCE]     │  │ [TARGET]         │
  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
         │                 │                    ▲
         ▼                 ▼                    │
    target vault     $RUN/staging_dir/ ─────────┘
    + manifest.csv
         │
         ▼
  ┌──────────────┐
  │ records-     │
  │ manifest     │   source_uid ↔ target_uid pairing (title-match)
  │              │   + ambiguity detection
  └──────┬───────┘
         ▼
     manifest.csv
         │
         ▼
  ┌──────────────┐
  │ records-     │   share grants from source user_permissions
  │ shares       │   (replayed on target via share-record)
  └──────┬───────┘
         ▼
  target SFs have
  the drip-fed
  grants

  ════════════════════════════════════════════════════════════
       audit.log (append-only, hash-chained, EVERY write)
  ════════════════════════════════════════════════════════════
                            │
                            ▼
                     ┌──────────────┐
                     │ audit-verify │  SHA256 sidecars + chain hash
                     │              │
                     └──────┬───────┘
                            ▼
                    ok: true / false

                     ┌──────────────┐
                     │ undo         │  walks audit.log in reverse,
                     │ --execute    │  dispatches inverse ops
                     └──────────────┘
```

---

## 4. Protocol / implementation axis

Each driver module defines a protocol; tests pass a Fake; production
passes Commander-backed real. This is the "hot-swap" axis — the
entire test suite runs without a live tenant by only swapping L1.

```
  DRIVER (L4)          PROTOCOL (L4)         FAKE (L4)            REAL (L1)
  ═══════════          ══════════════         ═══════════════      ══════════════════

  StructureRestore  ─▶ StructureClient   ─▶ FakeClient         ─▶ CommanderStructureClient
  UserRunner        ─▶ UserClient        ─▶ FakeUserClient     ─▶ CommanderUserClient
  AttachmentDownloader
    + Uploader      ─▶ AttachmentClient  ─▶ FakeAttachmentClient ─▶ CommanderAttachmentClient
  ShareRestorer     ─▶ ShareClient       ─▶ FakeShareClient    ─▶ CommanderShareClient
  SFReconciler      ─▶ SFReconcileClient ─▶ FakeSFReconcile*   ─▶ CommanderSFReconcileClient
  cleanup()         ─▶ CleanupClient     ─▶ FakeCleanupClient  ─▶ CommanderCleanupClient
  process_users()
    (decommission)  ─▶ DecommissionClient ─▶ FakeDecommission* ─▶ CommanderDecommissionClient
  process_users()
    (take_ownership) ─▶ OwnershipClient  ─▶ FakeOwnershipClient ─▶ CommanderOwnershipClient
  process_users()
    (transfer_user)  ─▶ TransferUserClient ─▶ FakeTransferUser* ─▶ CommanderTransferUserClient
  UndoRunner        ─▶ UndoClient        ─▶ FakeUndoClient     ─▶ CommanderUndoClient
```

One swap point. All destructive ops go through this axis.
`commander_clients.py` is the ONLY module where L1 (Commander SDK)
is imported — the protocol boundary enforces it.

### Squad-2 extension — `StructureClient` projection methods

T1 added 12 read-only methods to the `StructureClient` protocol,
all defaulting to empty so non-Commander backends see a cold-start:

```
  list_node_names(scope_node='')           → set[str]
  list_team_names(scope_node='')           → set[str]
  list_role_names(scope_node='')           → set[str]
  list_isolated_node_names(scope_node='')  → set[str]
  list_role_managed_nodes(role_name)       → set[(node, cascade)]
  list_role_privileges(role_name)          → set[(privilege, node)]
  list_role_enforcements(role_name)        → dict[key, value]
  list_user_node_assignments()             → dict[email, node]
  list_user_team_memberships()             → dict[email, set[team]]
  list_role_user_memberships()             → dict[role, set[email]]
  list_role_team_memberships()             → dict[role, set[team]]
  list_shared_folder_names()               → set[str]
  find_folder_uid(name, parent_uid)        → str (uid or '')
```

`StructureRestore(resume=True)` calls these once per step at entry
to pre-filter source rows. `FakeClient` exposes mirror `existing_*`
attributes tests pre-seed to simulate a partially-migrated target.
`CommanderStructureClient` overrides each by walking
`params.enterprise` (no extra round-trips — uses already-cached
state).

---

## 5. Safeguard interlock chain

Every destructive subcommand passes through multiple interlocks BEFORE
hitting Commander. Failure on ANY one blocks the call. Depicted as a
series of ◊ gates on the signal line.

```
  kwargs in
      │
      ▼
  ┌───────────────┐
  │ argparse      │   typed args (force=True defaults, --confirm
  │               │   required on decommission + cleanup, etc.)
  └───────┬───────┘
          │
          ▼  ◊ --source-read-only
  ┌───────────────┐   harness-level pre-subprocess check:
  │ comprehensive │   subcommand NOT in SOURCE_SAFE_SUBCOMMANDS
  │ _rehearsal.py │   → refuse, returncode=-2
  └───────┬───────┘
          │
          ▼  ◊ MCContext.__enter__
  ┌───────────────┐   switch-to-mc or no-op for empty --mc;
  │ MCContext     │   FAILED switch exposes MSP params so caller
  │ (mc_context)  │   sees the failure, not wrong MC silently
  └───────┬───────┘
          │
          ▼  ◊ _enforce_source_mode_from_kwargs (migration.yaml)
  ┌───────────────┐   4-layer interlock:
  │ safeguards    │   1. source_mode == 'destructive' in yaml
  │ (SafeguardBl.)│   2. --confirm-source-destructive passed
  │               │   3. expected_tenant_name matches session
  └───────┬───────┘   4. expected_tenant_name matches spec.source
          │
          ▼  ◊ expect_tenant
  ┌───────────────┐   session.enterprise_name must match
  │ (continued    │   an operator-typed sentinel. Catches
  │  safeguards)  │   typo'd session/spec.
  └───────┬───────┘
          │
          ▼  ◊ enforce_batch_cap
  ┌───────────────┐   count <= cap (default 50) OR
  │               │   --override-batch-cap explicitly set
  └───────┬───────┘
          │
          ▼  ◊ confirm_interactive (if not --yes / --confirm)
  ┌───────────────┐   TTY prompt; yes/y → proceed
  │               │   anything else → abort
  └───────┬───────┘
          │
          ▼  ◊ production_tenant_warning
  ┌───────────────┐   heuristic — tenant name lacks any of
  │               │   {test, demo, sandbox, migtest, …} →
  │               │   banner warning (not a block)
  └───────┬───────┘
          │
          ▼  [ACTUAL WRITE via Commander]
  ┌───────────────┐   _call(cmd, params, force=True, **kwargs)
  │ commander_    │
  │ _clients._call│
  └───────┬───────┘
          │
          ▼  ◊ verify-after-delete (cleanup, decommission)
  ┌───────────────┐   client.list_entities() / is_user_present()
  │ _still_present│   re-check: entity still there → ERROR
  │ is_user_present   not silent success
  └───────┬───────┘
          │
          ▼
  ┌───────────────┐   chained, signed, appended on every write
  │ audit.log     │   — verify via audit-verify; tamper → refuse
  │               │   to undo
  └───────────────┘
```

---

## 6. SF migration option dispatch (squad-2 T2)

`structure --nested-sf-plan` consumes a JSON plan emitted by
`tenant-migrate nested-sf-plan`. Each `shared_folder_folder` row
carries an `action` field; `step_vault_folders` dispatches per row.

```
   inventory.json
       │
       ▼
   ┌────────────────────┐
   │ nested-sf-plan     │   classify each shared_folder_folder
   │  (read-only)       │   against the 5-option matrix.
   └─────────┬──────────┘
             ▼
   ╔══════════════════════════════════════════════════════════╗
   ║   $RUN/nested_sf_plan.json    (chmod 0600)               ║
   ║                                                          ║
   ║   per-row: { sf_uid, action, conflict_resolution, ... }  ║
   ╚══════════════════════════════════════════════════════════╝
             │
             ▼
   ┌────────────────────┐
   │ structure          │   --nested-sf-plan <path>
   │ step_vault_folders │
   └─────────┬──────────┘
             │  for each row:
             ▼
       ┌─────────────────────────────────────────────────┐
       │   action ∈ {                                    │
       │      preserve-subfolder,                        │
       │      promote-to-sibling,                        │
       │      promote-to-true-nested,                    │
       │      flatten-with-prefix,                       │
       │      needs-review                               │
       │   }                                             │
       └─────────────────────────────────────────────────┘
                │
       ┌────────┼─────────┬────────────┬──────────────┐
       │        │         │            │              │
       ▼        ▼         ▼            ▼              ▼
   preserve  promote   promote     flatten         needs-
   -subfolder -to-     -to-true-   -with-prefix    review
       │     sibling   nested          │              │
       │        │         │            │              ▼
       │        │         │            │           SKIP +
       │        │         │            │           audit-log
       │        │         │            │           warning
       │        │         │            │
       │        │         │            ▼
       │        │         │       client.add_shared_folder(
       │        │         │          "Parent__Child",
       │        │         │          parent_uid='')   ← root
       │        │         ▼
       │        │    ◊ commander_supports_true_nested_sf()
       │        │    │     │
       │        │    no    yes
       │        │    │     │
       │        │    ▼     ▼
       │        │  ERROR   client.add_subfolder(name,
       │        │   (no     parent_sf_folder_uid=parent_sf)
       │        │    Commander  ← but as a real nested SF
       │        │    version
       │        │    yet)
       │        │
       │        ▼
       │   client.add_shared_folder(
       │      "Parent - Child",
       │      parent_uid='')        ← root, qualified name
       │
       ▼
   client.add_subfolder(
      name,
      parent_sf_folder_uid=parent_sf_uid)
                                   ← inside parent SF (legacy)
```

Conflict resolution (per row, `conflict_resolution` field):

```
   target name already exists?
        │
   ┌────┴────┬──────────────┐
   │         │              │
   error    suffix          merge
   │         │              │
   ▼         ▼              ▼
   FAILED   create with     attach to existing SF
   abort    "  (2)"         (membership union)
   row      tail
```

Resume composition: when both `--resume` and `--nested-sf-plan` are
on, the `step_vault_folders` resume path consults
`list_shared_folder_names()` first; SFs already on target are skipped
(audit logged as `SKIPPED — already present`) and `find_folder_uid`
recovers their UID for downstream membership steps.

---

## Change-impact quick reference

When editing in these modules, expect to re-test:

| Touching... | Re-run these tests |
|---|---|
| `mc_context.py` | `test_mc_context` + `test_adversarial::MCContextLateralMovementTests` + live Tier 7 |
| `cleanup.py` | `test_cleanup` + `test_adversarial::SilentFailureTests` + `test_full_pipeline` |
| `sf_reconcile.py` | `test_sf_reconcile` + `test_full_pipeline` + `test_fuzz_input::SFReconcileInventoryFuzzTests` |
| `commander_clients.py` | **everything** (L1 → every driver depends on this axis) |
| `safeguards.py` | `test_safeguards` + `test_adversarial::SafeguardBypassTests` + any command test |
| `audit.py` | `test_adversarial::AuditTamperingTests` + `test_e2e_integration::PipelineAuditContinuity` + `test_e2e_integration::AuditChainTrimmingTests` |
| `checkpoint.py` | `test_checkpoint` + every wiring test in `test_checkpoint_wiring` |
| `commands.py` argparse | lint with `python -m unittest discover` — argparse shape is asserted in `test_rehearsal_harness` SOURCE_SAFE_SUBCOMMANDS snapshot |
| `nested_sf_plan.py` | `test_nested_sf_plan` + `test_sf_option_matrix` + `smoke/test_smoke_nested_sf_plan` |
| `cycled_validation.py` | `test_cycled_round_trip` + the 5 % drift-threshold assertions |
| `structure.py` resume path | `test_resume_after_crash` + `test_e2e_operator_playbook` |
| `structure.py` SF dispatch | `test_structure` + `test_sf_option_matrix` + `smoke/test_smoke_structure` |

If a test below the diagonal fails after a change above it, the
abstraction leaked — fix the boundary, not the test.
