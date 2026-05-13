# Changelog

All notable changes to `keeper_tenant_migrate`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

*(empty)*

## [1.7.7] — 2026-05-13

Release-engineering cut. Captures three code changes landed on master
after the `v1.7.6` tag plus the documentation cleanup that restored
joao-authoritative voice across cmd-side docs. The tenant migration
tool is in a coherent, taggable release-point. PyPI publish remains
parked (see `.context/pypi-publish-resume-point.md`); this release
exists so the tool is PR-ready for upstream Commander independently
of PyPI.

### Fixed

- **Audit-log path resolution** (`8f45ebc`): subcommands now prefer
  the top-level `run_dir` when resolving the audit-log destination,
  eliminating a class of audit-chain holes where stage-local
  directories silently absorbed entries.
- **`records-export` + `take-ownership` audit emission** (`f4d2116`):
  both subcommands now emit audit events to the top-level `run_dir`
  rather than the stage-local directory.

### Changed

- **DSK-integration streaming hook signature** (`c94fa88`): added
  `Iterator[str]` return type on the SIEM compliance-evidence stream
  in `integrations/dsk_hooks.py` — typing refinement; no behaviour
  change for callers.

### Docs

- Coverage-gap audit, per-subcommand audit, documentation audit,
  live-validation gap matrix (35/41 verbs live-anchored), and a
  PR-readiness master checklist landed under `.context/` — the
  pre-merge gate for an upstream PR now has a single navigable
  trail.
- Doc cleanup pass restored joao-authored voice across cmd-side
  docs and removed outside-collaborator authority framings. Two
  outside-author commits on master were neutralised: `9a14218`
  (OPERATOR_PLAYBOOK edit) reverted at `8f385b3`; `df1133d`
  (auto-coupling GitHub Actions workflow) disarmed at `c7a78e8`
  (file kept for the template-injection hardening from `258344e`).

Test suite: 2492 collected; 2491 passed + 1 pre-existing skip.

## [1.7.6] — 2026-05-11

Packaging fix tagged at `34b7951`.

### Fixed

- **Wheel now ships the `integrations` subpackage** (`34b7951`):
  setuptools `packages` list was missing the subpackage, so 1.7.5
  wheel installs left `keeper_tenant_migrate.integrations` absent
  at runtime. 1.7.6 wheel restores it. Smoke-install verified.

## [1.7.5] — 2026-05-10

Release-engineered cut of the Phase 1.2 declare-overlay wedge.
`keeper-tenant-migrate` is set up as a separately-versioned library
so `keepercommander[migrate]` extras can pull it in alongside `dsk`
when the publish path is eventually opened. **Not published to PyPI**
— production upload deferred (task #73 PARKED pending Keeper-eng
blessing on the publish path; see
`.context/pypi-publish-resume-point.md`).

### Added — Phase 1.2 declare-overlay verbs (2026-05-10)

- **`scope.include_nodes / exclude_nodes`** (`2ccdc6b`): fnmatch-glob
  filter on `entities.nodes`; cascades drop to roles/teams whose
  `node` references a filtered-out node. Tenant-level entities (no
  `node` field) survive unconditionally. +16 unit tests.
- **`nodes.remap`** (`79e5723`): `{old_name: new_name}` exact-match
  rewrite of `entities.nodes[*].name`; cross-ref propagation to
  `roles[*].node` and `teams[*].node`. Atomic — captured map fixed
  at function entry; swap patterns like `{A: B, B: A}` work
  correctly. Collision is operator's responsibility (downstream
  pipeline's `--preserve-duplicate-node-names` is the safety net).
  +17 unit tests.
- **`teams.rename / teams.drop`** (`7be1b68`): exact-name rewrites
  + cascade to `roles[*].teams[*]`, `shared_folders[*].teams[*]`,
  `users[*].teams[*]`. Heterogeneous entries handled per
  `structure.py:770-775` shape detection (live_inventory emits
  strings; assemble-inventory emits dicts with `team_name`/`name`
  keys). Drop runs before rename. +21 unit tests.
- **`users.drop / users.domain_remap`** (`7e525de`): fnmatch-glob
  drop against `users[*].email` + cascade to
  `shared_folders[*].users[*].username` and
  `records[*].direct_shares[*].username`. Domain-remap rewrites
  `users[*].email/aliases/alias` plus the same SF/records username
  refs; reuses the existing `email_remap.remap_email` helper that
  the runtime migration already calls. Drop runs before
  domain_remap. +26 unit tests.
- **ref_graph extension** (`0448606`): `find_dangling_refs` now
  validates exact-name targets for `nodes.remap`, `teams.rename`,
  `teams.drop`. Fnmatch-glob verbs (`scope.*`, `users.drop`) and
  domain-keyed `users.domain_remap` are intentionally NOT validated
  — globs may legitimately match zero entities, and domain keys
  have no inventory referent. +9 unit tests.
- **Adversarial pins for Phase 1.2 verbs** (`45657af`): one
  TestCase per verb, covering glob-injection, swap cycles
  (2-cycle + 3-cycle), heterogeneous entry mixing, dict-extra-field
  preservation, atomic-swap, drop-runs-before-{rename,remap},
  empty-string survives glob sweep. +16 tests.

Declare-overlay test suite: 117 → 168 green. Plugin overall: 2347
passed, 1 skipped (no regressions; pre-existing
test_destructive_command failure is unaffected, verified on clean
master baseline).

### Added — earlier in cycle (rolled into this release)
- **Customer-friendly `plan-report` subcommand** (squad-3 round 1 / T1 ✅)
  (`keeper_tenant_migrate/plan_report.py`). New read-only subcommand
  combines `plan` + `nested-sf-plan` + `estimate` outputs into a
  single mid-technical-admin markdown report (`migration-plan.md`)
  plus a machine-readable mirror (`migration-plan.json`). Surfaces
  only the decisions that need operator attention (divergent
  subfolders, name conflicts, tier outliers) and buckets the 90 %
  safe-default rows in a collapsible block. Each decision row carries
  the operator's recommendation, the alternatives, and the override
  key for direct YAML editing in `overrides.yaml`. The sign-off block
  is a checkbox list of what the user approves by running the
  migration. Both output files are 0644 by design — the report is
  intentionally email-able / paper-print-friendly and contains no
  secrets. All three input paths are individually optional (at least
  one required); the report degrades gracefully when an input is
  missing. Embeds the `commander_supports_true_nested_sf()` probe
  result so the user sees why `promote-to-true-nested` is greyed out
  today (Commander v17.2.13 doesn't support it). 58 new unit tests,
  100 % line coverage on the new module. OPERATOR_PLAYBOOK gains
  step 3b with the worked invocation.
- **User-decidable migration plan via `overrides.yaml`** (squad-3
  round 1 / T2 ✅). New `keeper_tenant_migrate/overrides.py` module
  loads, validates, and applies a small flat YAML the customer
  (tenant admin) drafts after reviewing the operator's nested-SF
  plan. Top-level keys: `subfolders` (uid → action enum from the
  5-option matrix), `conflicts` (uid → name-collision policy),
  `tier` (throttle-tier override, advisory + audit-only this release,
  gated behind `--accept-risk`), `notes` (free-text per-row
  commentary). Schema doc: `.context/overrides-schema.md`. Wired
  into `tenant-migrate structure` via new `--overrides <path>` and
  `--accept-risk` flags. `apply_overrides` returns a NEW plan dict
  — the input is never mutated, so the audit trail of "what the
  customer changed from the operator's defaults" is reconstructible
  from the before/after values landed in the audit chain. Validation
  failures emit a friendly multi-line error (no Python tracebacks)
  with actionable hints (close-match suggestions for typo'd UIDs,
  full valid-value sets for invalid enums, "requires --accept-risk"
  reminders for tier overrides). 82 new unit tests at 100% coverage
  on `overrides.py`. End-to-end round-trip test
  (`test_overrides_wiring.py`) verifies the customer's choices drive
  `step_vault_folders` dispatch, that the source plan JSON is
  byte-identical after a run with overrides, and that validation
  errors abort before any structure step runs.
- **Resume after mid-stage crash** (G7 ✅). `tenant-migrate structure
  --resume` opt-in flag implements the state-reconciliation approach
  from the 2026-04-22 design doc: every `step_*` queries the target
  tenant for current state at entry, pre-filters source rows to the
  delta, and only writes what's missing. Audit-log entries
  distinguish `SKIPPED — already present (resume)`, `SUCCESS —
  created (was missing on resume)`, and `SKIPPED — N enforcement(s)
  already applied (resume)`. Idempotent: a second `--resume` run
  back-to-back is a clean no-op (every row SKIPPED). Default off —
  current operators see no behavior change without the flag.
  RUNBOOK section "Resuming after a crash" walks the recovery
  sequence including the nohup invocation that prevents the death in
  the first place. New projection methods on `StructureClient` +
  `CommanderStructureClient` (read `params.enterprise` after
  sync-down, no extra API calls beyond what structure already pays).
  35 new unit tests plus 12 new Commander client projection tests.
- **Cycled validation harness (Tier 9, ROADMAP F4).** New
  `keeper_tenant_migrate/cycled_validation.py` runs N back-to-back
  forward+undo migration cycles against in-memory fakes and asserts
  byte-equal idempotency, undo cleanliness, and metric drift <= 5 %
  vs cycle 1. Source-read-only is enforced **in code** (Rule 0):
  source bytes are captured once before cycle 1 and re-asserted
  after every cycle; any divergence raises `SourceMutationError`
  and aborts the run before further cycles execute. The live-mode
  counterpart in `migration_scripts/ci/comprehensive_rehearsal.py`
  adds `--cycles N` and `--hammer` flags that wrap the existing
  Tier 1-8 sequence in the same loop, emit per-cycle audit trails
  under `<run-dir>/cycle-N/`, and write a unified
  `cycled_audit_summary.md` + `cycled_validation.json`. New unit
  test file `tests/test_cycled_round_trip.py` ships 68 tests with
  Rule 0 enforcement tests running first (regression-priority).
  100 % line coverage on the new module. Live execution stays
  gated on `keeper login` (Phase B/C/E blocker). REHEARSAL_GUIDE
  has a new "Cycled validation (Tier 9 / `--cycles N`)" section.
- **5-option SF migration matrix** (`nested_sf_plan.py`): the
  `proposed_target_action` enum extends from 3 → 5 values
  (`preserve-subfolder`, `promote-to-sibling`,
  `promote-to-true-nested`, `flatten-with-prefix`, `needs-review`).
  `nested-sf-plan` gains `--default-action`, `--per-folder-rules`, and
  `--default-conflict-resolution` flags. `step_vault_folders`
  dispatches per-row to one of four materializers
  (`_apply_preserve_subfolder`, `_apply_promote_sibling`,
  `_apply_flatten_prefix`, `_apply_promote_true_nested`).
  `commander_supports_true_nested_sf()` is the runtime probe gating
  option 3 (today returns False for every released Commander; flips to
  True automatically when Keeper ships nested-SF support). Conflict
  handling per row: `error` (default) / `suffix` / `merge`. Backwards
  compatible with v1.3.0-rc2 plan JSON via `action_lookup` legacy-name
  translation. `.context/sf-commander-surface.md` documents the full
  Commander surface audit (v17.2.13 pin, verified against origin
  v17.2.15 — no nested-SF support landed). `.context/sf-option-matrix.md`
  is the operator's option-picking reference. RUNBOOK Step 2a
  expanded with worked examples for each option. 89 new unit tests
  including round-trip integrity for all 5 options against a synthetic
  source vault (verifies source-read-only and target-shape correctness).
- Comprehensive-node verification fixtures (`tests/fixtures/comprehensive_node.py`) plus per-category and end-to-end tests (`tests/test_comprehensive_node.py`, `tests/test_comprehensive_node_e2e.py`) addressing every item under VERIFICATION_GAPS.md "What's Needed: Comprehensive Test Node"; fakes-only — live rehearsal still required (Phase B/C in ROADMAP).
- **Phase C scale-tier verification.** `estimate.predict_for_count`
  + `compare_actual` + `render_tier_validation_report` — given a
  record count, predict runtime / API calls / throttle incidents,
  then compare to actual at the end of a scale rehearsal. Powers
  the `comprehensive_rehearsal.py --seed-scale N` Tier 8.
  Companion seeder lives outside the package at
  `migration_scripts/ci/scale_seeder.py`.
- `nested-sf-plan` subcommand: read-only classifier for `shared_folder_folder` subfolders (inherit / promotion-candidate / cannot-classify) plus optional `structure --nested-sf-plan` consumption hook for promoting divergent subfolders to top-level SFs on target.
- **CI smoke layer (Phase D).** New `keeper_tenant_migrate/smoke/`
  package + `.github/workflows/smoke.yml` runs on every PR and push to
  `master`. A structurally-faithful Commander stub
  (`smoke/_stub/runtime.py`) introspects each Commander Command class's
  argparse parser at install time and rejects any kwarg the plugin
  sends that is not a real parser dest — same rejection the live SDK
  would emit, but caught in CI before merge. 8 end-to-end smoke tests
  cover `plan`, `structure --dry-run`, `users --dry-run`,
  `records-export`, `cleanup --dry-run`, `decommission --plan-only`,
  `verify`, `undo --plan-only`. A harness self-test
  (`test_harness_self_test.py`) injects synthetic SDK kwarg drift,
  asserts the suite fails, then restores and asserts it passes —
  documenting that the harness can catch what it is designed to
  catch. 100 % statement coverage on the stub framework module.
  Workflow runs on Python 3.9 + 3.11 with pip cache.
  See `migration_scripts/ci/REHEARSAL_GUIDE.md` "CI smoke layer
  (Phase D)" for the full operator runbook including the
  break-it-and-detect demo and the "I bumped the Commander pin and
  CI broke" workflow.

### Tests
- **Coverage uplift 81 % → 99 %** on the six modules flagged as sub-90 %
  by the squad-1 audit. Per-module deltas (production-only lines):
  `menu.py` 77 % → 100 %, `selftest.py` 78 % → 100 %, `wizard.py`
  84 % → 100 %, `take_ownership_restore.py` 85 % → 100 %,
  `sf_reconcile.py` 89 % → 99 %, `structure.py` 89 % → 99 %.
  Test count 1356 → 1454 (98 new tests). Three residual lines
  (`structure.py:153`, `:161`, `:595` and `sf_reconcile.py:176`) are
  Python `else: continue` peephole-optimised jumps that
  `coverage.py 7.10` instruments at 0 hits even when execution
  demonstrably passes through them — covered by tracer-level proof
  in `TopologicalNodeOrderEdgeCases` /
  `MalformedInventoryTests` docstrings, flagged for future coverage
  tooling once the upstream issue resolves.
- New `[tool.coverage.run]` + `[tool.coverage.report]` config in
  `pyproject.toml` makes `coverage report` filter to production code
  (`omit = tests/*, smoke/*`) and exclude `raise NotImplementedError`
  protocol stubs from totals — gives an honest production-only
  number instead of mixing test files into the denominator.

### Security
- **Mandatory tenant assertion on destructive subcommands.** A
  2026-04-20 red-team test proved that a polluted `config.json` (correct
  filename, wrong credentials inside) silently aimed destructive
  `cleanup` writes at the WRONG tenant. Filename is not a safe proxy
  for tenant identity. New `require_tenant_assertion` guard at
  `safeguards.py:154` is wired into `cleanup`, `decommission`,
  `take-ownership`, `transfer-user`. Each now requires either
  `--expected-tenant-name <NAME>` (session-name check) OR
  `--skip-tenant-check` (explicit opt-out with WARNING log) on every
  live run. Dry-run paths are unchanged. Harness
  (`comprehensive_rehearsal.py`) passes `--skip-tenant-check` since
  it pre-validates via explicit `target_config` selection.
  `RequireTenantAssertionTests` adds 9 new unit tests.

## [1.3.0-rc2] — 2026-04-19

### Fixed
- **`--mc` flag was a silent no-op** (discovered live during Phase E
  smoke against Test Company MC). Commander's `SwitchToMcCommand`
  doesn't mutate the caller's `params` — it stashes the MC-scoped
  params in `msp.mc_params_dict[id]` expecting the interactive shell
  to swap references before each command. Plugin subcommands bypass
  that loop, so every operation after `switch-to-mc` still ran
  against the MSP root. Fix: `MCContext` now exposes the MC-scoped
  params via `ctx.params`; callers pass `ctx.params` (not the
  original) to subcommand `execute()`. Affects `RunCommand`,
  `StructureCommand`, `UsersCommand`. Live-validated against
  Keeperdemo MSP + Test Company MC (0 users, distinct enterprise).
- `test_mc_context.py` rewritten for new `(ok, params)` return tuple
  from `switch_to_mc` / `switch_to_msp`.

## [1.3.0-rc1] — 2026-04-19

Post-migration ergonomics + pre-flight sizing + safer destructive paths.
Full notes: [`RELEASE_NOTES_v1.3.0.md`](../_archive/release_notes/v1.3/RELEASE_NOTES_v1.3.0.md).

### Added
- `tenant-migrate estimate` subcommand — pre-flight tenant size, API
  call budget, runtime estimate, throttle tier recommendation.
  `estimate.SCALE_TIERS` is the single source of truth for tier
  selection; wizard imports from it.
- `tenant-migrate shared-folders-reconcile` — idempotent, cron-able
  drip-feed to apply SF memberships as target users activate.
  Add-only (`--prune` is a deliberate future opt-in), supports email
  remap, checkpoint-aware.
- `decommission --plan-only` — emits a Markdown plan with copy-pasteable
  `keeper enterprise-user --lock/--delete` commands for operators to
  run manually. Includes prerequisites checklist + per-user verification
  grep + pointer to `--confirm-manual-completion`.
- `decommission --confirm-manual-completion` — appends a chained audit
  event noting "operator manually deleted N users" after running the
  plan by hand.
- Checkpoint protocol (`checkpoint.py`) — generic per-stage resume for
  loop-over-N subcommands. SHA-256 of input manifest pinned to
  checkpoint; atomic write + 0600; clear-on-success.
- `keeper-migrate` console script + `python -m keeper_tenant_migrate`
  equivalent — fixes one-shot invocation (`keeper <cmd>` silently fell
  back to core-command help because plugin wasn't registered on that
  code path).
- Live smoke tests exercised: `cleanup --dry-run`, `estimate`,
  `shared-folders-reconcile --dry-run`, `decommission --plan-only`,
  `keeper-migrate` wrapper — all against MSP target.

### Changed
- `records-shares` now supports `--resume` / `--force-restart` for
  mid-run recovery via the checkpoint protocol. Summary separates
  `skip` (empty user_permissions) from `resumed` (skipped-over by
  checkpoint).
- `decommission` automated path now logs a warning recommending
  `--plan-only` instead. `--checkpoint` and `--report-output` remain
  required on the automated path but are optional for the new
  plan-only / manual-completion paths.
- `PHASE_B_RUNBOOK.md` updated to use `keeper-migrate` for plugin
  subcommands (plain `keeper` continues to work for core Commander
  commands).
- Top-level `NEXT_STEPS.md` collapsed to a pointer — source of truth
  is `keeper_tenant_migrate/NEXT_STEPS.md`.

### Fixed
- Plugin dispatch in one-shot `keeper <cmd>` invocations (see
  `keeper-migrate` above). Previous behavior: `keeper … tenant-migrate X`
  silently rendered the core-command help screen instead of running X.

### Testing
- Full suite: 857 tests green (was 797 at the start of the v1.3.0 work
  cycle). 60 new tests covering estimate, reconcile, checkpoint,
  records-shares resumability, decommission plan-only.

## [1.2.0] — Unreleased

Post-review hardening + the four gaps the adversarial/silent-failure/
test-coverage agents called out as unfixed in v1.1.0.

### User folder hierarchy mirroring (gap closed)

- `records-export` now captures each record's folder path via a new
  `_build_folder_path_index` helper (walks `params.folder_cache` +
  `params.subfolder_record_cache`) — previously only shared-folder
  placement was captured.
- `converter` emits the folder info as `folders: [{folder: path}]`
  for user-folder hierarchy AND `folders: [{shared_folder: path}]`
  for SF placement. Commander's native import rebuilds the tree on
  target.
- 5 new tests cover the pivot, nested user folders, multi-folder
  records, and emission shape.

### Cross-tenant attachments (dual-session workaround)

- Split `AttachmentMigrator` into `AttachmentDownloader` (source
  shell) + `AttachmentUploader` (target shell). Downloader writes a
  `staging.json` index; uploader reads it without needing source
  session access. Removes the "current session must see both sides"
  limitation.
- Two new subcommands: `records-attachments-download`,
  `records-attachments-upload`. Existing `records-attachments`
  remains for single-session flows.
- 4 new tests cover staging manifest, cross-phase handoff, missing
  staging directory, and legacy dir-listing fallback.

### SSO/SCIM/Bridge tenant-config capture

- `build_sso_config` extended to capture `scims` (tenant-scoped SCIM
  connectors) and `bridges` (on-prem AD/LDAP appliances) from
  `params.enterprise` top-level tables — NOT just `sso_services`.
- `manual_actions.enumerate_actions` emits per-connector prerequisite
  entries: SCIM bearer-token rotation, bridge re-registration.
- No credentials are carried: SCIM tokens and bridge private keys
  are never exposed by Commander's enterprise sync and must be
  regenerated on target.
- 5 new tests including "no-sso-config emits no SSO actions."

### Tighter integrity checks on SHA256SUMS

- `write_sha256sums` exclude now supports relative-path patterns +
  fnmatch globs. Basename-only excludes still work (legacy) but log
  a DEBUG line when they silently skip a nested file.
- Symlinks are never hashed AND now emit a WARNING so the operator
  knows an on-disk entry was excluded.
- 4 new tests: nested-file hashing, basename-legacy behavior,
  strict-path excludes, symlink-skipped-and-logged.

### RecordsImport: imported_uids hardening

- Parses the input bundle to learn expected record titles.
- Post-import cache diff is narrowed to UIDs whose title is in the
  bundle — a concurrent sync-down between before/after snapshots no
  longer pollutes `imported_uids`.
- Warns when raw diff is 2×+ the title-matched subset so the
  operator knows cache pollution occurred.

### CI smoke documentation

- `CI_SMOKE.md` — GitHub Actions workflow skeleton + secret rotation
  plan + local pre-push hook alternative. Not yet wired (needs
  disposable tenants provisioned) but every scaffold needed is here.

### Tests

- 797 unit tests (up from 779 in v1.1.0). Zero network / tenant
  dependencies.

## [1.1.0] — Unreleased

Phase 3–7 of the tenant-migration toolkit. Full-spectrum cross-tenant
coverage: menu-driven wizard, pre-flight compat checks, middle-severity
gaps (email-remap / SSO / rate-limits), v1.1 deferred items (queued team
users, PAM detection, SF per-user perms, arbitrary rollback, SIEM export).

### New subcommands

- `wizard` — menu-driven flow; reads/writes `<run_dir>/migration.yaml`,
  detects per-shell source/target role, proposes the next step, runs
  pre-flight compat checks before destructive phases.
- `audit-export` — format audit.log as json-lines, syslog (RFC 5424),
  or ArcSight CEF for SIEM ingestion.
- `undo` — arbitrary-point rollback using audit.log as source of truth;
  chain-verifies before running; dry-run by default; per-event
  inverse ops (lock/delete users, delete structure entities, revoke
  shares, manual-action refs for take-ownership and records-import).

### Two-shell model

- `session` subcommand prints the current shell's user/region/tenant.
- `detect_session_role(params, spec)` matches the session against the
  run-spec's source/target entries so the wizard adapts per-shell.
- Shared `run_dir` with hand-off artifacts: `inventory.json`,
  `target_state.json`, `manifest.csv`, `checks.csv`,
  `reconciliation.md`, `audit.log` — each shell writes what it
  produces; the other shell reads.

### Pre-flight compatibility checks

- `compat_checks.node_depth_compat` — source max depth vs target limit.
- `compat_checks.record_type_compat` — source types missing on target.
- `compat_checks.attachment_size_survey` — attachments ≥ 100 MB flagged.
- Wizard runs all three on role=target + inventory present; FAIL
  verdicts prompt "continue anyway?".

### Email-domain remap

- `--old-domain` / `--new-domain` on `users`, `records-shares`,
  `take-ownership`. Aliases, share grantees, admin email all remapped.
- `email_remap.infer_domains_from_spec(spec)` auto-derives pair from
  `spec.source.email_domain` / `target.email_domain` when set.

### SSO/SCIM awareness

- `live_inventory` captures `is_sso` per user + `sso_config.providers`
  at the tenant level (entity_id, ACS URL, SCIM URL, token-present).
- `--sso-policy allow|warn|skip` on `users`; `skip` blocks SSO users
  from being invited manually — they must be re-provisioned via IdP.
- `manual-actions` now emits a prerequisite IdP reconfiguration
  checklist per SSO provider on source.

### Rate-limit knobs

- `--delay SECONDS` + `--batch-size N` on `users`, `records-shares`,
  `records-attachments`, `take-ownership`. Batch checkpoints let
  Commander sync-down catch up on long runs.

### Queued team users

- `live_inventory` captures each team's `queued_users` (users invited
  to teams before the tenant-level invite was accepted).
- `UserRunner` approves queued memberships after invite succeeds.

### PAM config reference detection

- `pam_detection.detect_pam_records` flags any record typed `pam*`,
  carrying a `pam*` field, or with a `pam_`/`rotation` custom-field label.
- `manual-actions` surfaces counts per type + instruction to
  re-register gateways / re-issue agent tokens / re-enable rotation
  on target.

### SF record-level per-user perms

- `live_inventory.build_shared_folder_entities` normalizes per-user
  `manage_users` / `manage_records` / `can_edit` / `can_share`.
- Validator `phase_shared_folders` diffs per-user and per-team perms
  across tenants; MISSING / EXTRA / drift flagged as WARN.

### Undo-feeding audit events

- Every destructive subcommand now stamps the data `undo` needs to
  unwind the run:
  - `users` → `summary.invited_emails`
  - `structure` → `summary.created_entities` (nodes/teams/roles)
  - `records-import` → `summary.imported_uids` (diffed from
    `params.record_cache` before/after the native import)
  - `records-shares` → `summary.share_grants` `[{target_uid, email}]`
  - `records-attachments` → `summary.uploaded` `[{target_uid, file_name}]`
- All events chain into `<run_dir>/audit.log` via `append_audit_event`.

### Exponential backoff on transient errors

- New `backoff.py` module: `Retry.call(fn)` wraps per-unit operations
  in `UserRunner` / `ShareRestorer` / `AttachmentMigrator`. One retry
  on transient (`429`, `throttled`, `session_expired`, `connection
  reset`, `timeout`); second hit raises `SafeguardBlocked`.
- `commander_clients._call` re-raises transient errors; non-transient
  still swallowed + logged (preserves existing per-item status).

### Records umbrella subcommand

- New `tenant-migrate records --run-dir PATH` — auto-detects shell
  role and chains either source stages (export + convert) or target
  stages (manifest + import + attachments + shares). `--stages`
  override runs an explicit list. Halt-on-fail in non-dry-run mode.

### `run` orchestrator extended with records stage

- `tenant-migrate run` now includes a `records` stage that chains
  records-import → attachments → shares when the run-dir has the
  bundle + manifest present; SKIPPED when absent.

### Wizard `.run_state` persistence

- `load_run_state` / `save_run_state` / `update_run_state` helpers
  at `<run_dir>/.run_state` (JSON, 0600).
- `Wizard.confirm_once(key, title)` prompts once per run-dir and
  replays the prior answer on re-entry — used for IdP re-point
  confirmation, batch-cap override, etc.

### `approve_team_queue_user` on the real SDK client

- `CommanderUserClient.approve_team_queue_user` wired via
  `enterprise-team TEAM_NAME -au EMAIL`. Idempotent: Commander emits
  `team_enterprise_user_add` when the user is now active or re-queues
  otherwise.

### Source-tenant write interlock

- Four-layer opt-in required before any `cleanup` / `decommission` /
  `take-ownership` / `transfer-user` is allowed to write to the
  SOURCE tenant:
  1. `source_mode: destructive` in `migration.yaml` (default `read_only`)
  2. `--confirm-source-destructive` CLI flag at invocation
  3. `--expected-tenant-name "X"` that matches the current session
  4. spec.source.enterprise_name matches the typed name
- New `safeguards.enforce_source_mode(params, run_spec, ...)` runs
  the check at the top of every source-writeable execute().
- Wizard writes `source_mode: read_only` into every new spec and
  shows the current mode in its banner.
- 10 new unit tests + SECURITY_MODEL.md section.

### Tests

- 768 unit tests (up from 307 at 1.0.0). Zero network / tenant
  dependencies — every Commander call is behind a `FakeClient` or
  `DryRun` wrapper.

### Docs

- `AUTOMATED_ADJUSTMENT.md` — wizard policy for auto-deriving remap
  domains, auto-tuning rate limits by scale, auto-prompting for IdP
  reconfirmation before `users` runs.
- `LIMITATIONS.md` (new) — intentional out-of-scope areas.
- `WIZARD_GUIDE.md` (new) — first-run walkthrough of the two-shell
  model + wizard flow.
- README updated for the two-shell model.
- README install section shows `pip install ./keeper_tenant_migrate[yaml]`
  alongside the bootstrap import and one-liner approaches.
- `RUNBOOK.md` documents the three undo-irreversibles (`cleanup`,
  `decommission`, partial `records-import`, attachment fileRef lookup).

## [1.0.0] — Unreleased

First release — native Commander plugin port of the `migration_scripts/`
bash pipeline. All six coverage-audit gaps closed; every bash behavior
has a Python equivalent with unit tests.

### Subcommands (25)

- **Capture / plan**: `plan`, `assemble-inventory`, `transition-check`,
  `capture-target-state`, `records-export`
- **Convert / import**: `convert`, `records-import`, `records-manifest`,
  `records-attachments`, `records-shares`
- **Restore / place**: `structure`, `users`, `take-ownership`,
  `transfer-user`
- **Validate / report**: `verify`, `reconcile`, `self-test`,
  `pre-flight`, `manual-actions`
- **Destructive (gated)**: `point-of-no-return`, `decommission`,
  `cleanup`
- **Orchestration**: `run`
- **Audit**: `audit-verify`

### Features

- 13-step structure-restore (nodes → teams → roles → enforcements →
  SF membership → user assignments → team/role wiring) with topological
  sort + duplicate-name dedup + built-in role collision resolver.
- 4-phase enforcement application (SIMPLE / ACCOUNT_SHARE / FILE /
  direct-API fallback for `json`/`jsonarray` types the CLI rejects).
- 9-phase field-level validator (pre-flight + nodes + teams + roles +
  SFs + records + record-types + vault-health + entity-count parity).
- Hash-chained audit log (`audit.py`) with SHA-256 per-file sidecars
  + signed verify receipts — `audit-verify` flags any tampering.
- Dry-run (`--dry-run`) on every mutating subcommand with a target-
  state-diff Markdown report classifying each op as CREATE / SKIP /
  CONFLICT / DELETE / UNCHECKED.
- Manual-actions enumerator — Markdown checklist grouped by phase
  and actor (source_user / target_user / admin) describing every
  human step the tool cannot automate (folder sharing, invite
  acceptance, etc.).
- MSP → Managed-Company scoping (`--mc`) via `switch-to-mc` +
  `switch-to-msp` context manager with revert on exception.
- Safeguards: `--expected-tenant-name`, `--batch-cap`, production-name
  warning, framed ⚠ DESTRUCTIVE / ℹ MODIFYING banners, interactive
  yes/no confirmation with TTY detection, signed checkpoint with
  72h TTL before `decommission`.
- BOM-safe / header-validated CSV loaders (Excel-saved rosters parse
  correctly; wrong-header CSVs raise instead of silently yielding 0).
- Zero-knowledge posture: plaintext outputs chmod 0600; validator
  messages never interpolate field values; audit chain is
  tamper-evident.

### Documentation

- `README.md` — install, supported topologies, typical flow, security.
- `RUNBOOK.md` — 10-step live-tenant walkthrough.
- `DRY-RUN-GUIDE.md` — per-subcommand dry-run recipe + help usage.
- `SECURITY_MODEL.md` — zero-knowledge guarantees + failure recovery.
- `COVERAGE_AUDIT.md` — bash-script-to-Python-module traceability.
- `PLAN.md` — release-readiness checklist.

### Tests

- 517 unit tests, no network or authenticated session required.
- Adversarial reviews (code-reviewer + silent-failure-hunter +
  test-analyzer) ran across modules; all critical + important findings
  closed with regression tests.

### Known gaps (tracked for v1.1 / v1.2)

- SF record-level per-user `can_share` / `can_edit` (source of truth
  is `apply-membership` behavior, not this tool's).
- PAM config references.
- Queued team users/state.
- Specific enforcement value types (`ip_whitelist`, `two_factor_duration`,
  `record_types-FILE`, `password_complexity-FILE`) exercised live —
  direct-API path covers them in code, but they need a round-trip
  against a tenant carrying one of these values.

### Live verification

Blocked on an authenticated MSP session — see `RUNBOOK.md` for the
exact commands. Code paths exercised via unit tests; live run is
the remaining acceptance step.
