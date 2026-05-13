# Security model, zero-knowledge posture, and failure recovery

Honest statement of what this plugin *does* and *does not* guarantee.
Written so compliance can cite specific file/line pairs; no marketing.

## Zero-knowledge — what it means here

Keeper's cloud is zero-knowledge: the server stores only ciphertext; the
record-encryption key lives in the client's memory for the duration of
a session. This plugin inherits that posture **unchanged**:

- **Commander is the only component that talks to Keeper.** We never
  re-implement crypto; every write is a wrapper over a Commander
  `Command.execute()`. Session tokens, record keys, and data keys never
  leave Commander's `params` object — see `commander_clients.py`.
- **No record body crosses the network in plaintext** — Commander's
  `import` / `upload-attachment` / `share-record` commands encrypt at
  the client before posting to the API. We route to those commands
  verbatim.

### Where plaintext lands on the admin's disk

The admin machine necessarily decrypts to transfer records to another
tenant. Commander cannot move a record from tenant A to tenant B
without reading its plaintext first — no server-side rewrap path
exists. Three files can contain plaintext:

| File | Contains | Default |
|------|----------|---------|
| `records-export/<uid>.json` | login / password / TOTP seed / notes / custom fields | Always written |
| `plan --include-fields` inventory | Same fields embedded in `entities.records[]` | Opt-in |
| `capture-target-state --include-fields` | Same, for the target | Opt-in |

Mitigations already shipped:

- All three are chmod **0600** (owner read/write only) immediately after
  write — enforced in `inventory.InventoryAssembler.write`,
  `live_inventory.write_inventory`, and
  `commands.RecordsExportCommand.execute`.
- A SHA-256 sidecar (`.sha256` or `SHA256SUMS.txt`) is written alongside
  every sensitive artifact — see `audit.py`.
- The validator's `_compare_field` + `_compare_custom_fields` never
  interpolate source/target field values in check messages; FAIL
  messages say `"password mismatch"`, never the values themselves.
  Regression tests in `tests/test_security.py::ValidatorNeverEmitsFieldValuesTests`.
- The reconcile Markdown report operates purely on name-and-count
  metadata; records never appear with their bodies there.

### What is never persisted

- **Keeper master password**: Commander never exposes it to this plugin.
  No code path in `keeper_tenant_migrate/*.py` reads or prints it.
- **Session tokens**: `params.session_token` is never serialized to JSON,
  CSV, or log output. Grep the module: no reference to `session_token`.
- **Shared-folder encryption keys**: handled entirely inside Commander;
  this plugin addresses SFs by name, not by key material.
- **Device private keys**: same — Commander-only.

### Zero-knowledge operational guidance

1. Run on a dedicated migration host. Blow it away when done.
2. Keep the `records-export` / `plan --include-fields` dirs on
   short-lived encrypted storage (e.g., `tmpfs`, ephemeral LUKS).
3. Do not commit migration artifacts to version control (the repo
   `.gitignore` should exclude `migration_logs/`, `/tmp/...` paths).
4. Run `tenant-migrate audit-verify --directory DIR` after every mover
   step to detect tampering-in-transit (USB, S3, shared drives).
5. Delete plaintext dirs as soon as `verify` + `reconcile` pass.

## Source-tenant write protection (4-layer interlock)

Four destructive subcommands can write to the SOURCE tenant —
`cleanup`, `decommission`, `take-ownership`, `transfer-user`. A typo
or stale config run against the wrong session could destroy customer
data. The plugin refuses to run those subcommands against a source
session unless **every one of four deliberate signals** is present:

| Layer | Signal | Where it lives |
|-------|--------|----------------|
| 1 | `source_mode: destructive` | `migration.yaml` — file edit |
| 2 | `--confirm-source-destructive` | CLI flag at invocation |
| 3 | `--expected-tenant-name "Acme Source"` | CLI flag, must match the current session |
| 4 | spec.source.enterprise_name == the typed name | cross-check against the spec |

Default `source_mode` is `read_only`. Every newly-created `migration.yaml`
the wizard writes starts with `read_only`. Flipping to `destructive`
requires a deliberate text-editor change — not a CLI toggle.

### Enforcement path

`safeguards.enforce_source_mode(params, run_spec, confirm_flag,
expected_tenant_name, subcommand)` is called at the top of every
source-writeable execute(). It checks the four layers in order and
raises `SafeguardBlocked` on the first failure. The error message
names the missing signal so the operator can see *why* the op was
refused without trial-and-error.

### What this protects against

- **Wrong-session typo** — admin runs the command against a source
  shell expecting it was a target shell. Layer 3 catches.
- **Wrong-spec point** — admin edited the spec to allow destructive
  mode against Tenant A, but invoked the command while logged into
  Tenant B. Layer 4 catches.
- **Stale CI script** — a shell script that was fine against a
  sandbox is pointed at production. Layers 1+3 catch (migration.yaml
  isn't in the script; tenant name hasn't been updated either).
- **First-time user** — the defaults block writes; the admin has to
  read the docs and flip multiple switches to enable them.

### When the interlock does NOT fire

- Target-side sessions (the interlock is a no-op against target).
- `detect_session_role` can't classify the session as source (empty
  spec, unknown enterprise, etc.) — also a no-op, since the plugin
  can't be sure.
- Dry-runs — each destructive subcommand skips all safeguards in
  dry-run because no API calls land.

## Mandatory tenant assertion (target-destructive hardening)

The 4-layer interlock above only fires on SOURCE sessions. Target-side
destructive ops (`cleanup`, `decommission`, `take-ownership`,
`transfer-user`) historically trusted the caller — if the operator
`--config`'d the right file, the plugin assumed the session landed on
the intended tenant.

A 2026-04-20 red-team test invalidated that assumption. A
`config-msp.json` file that was supposed to hold TARGET credentials was
polluted with SOURCE credentials (same filename, wrong bytes inside).
The caller ran `cleanup --config config-msp.json --prefix MIGTEST-` and
wiped entities from the SOURCE tenant. Filename is not a safe proxy for
tenant identity.

### The fix

Every live invocation of the four destructive subcommands now requires
ONE of:

- `--expected-tenant-name "<NAME>"` — exact case-insensitive match
  against `params.enterprise['enterprise_name']`. Raises
  `SafeguardBlocked` on mismatch, also raises if `<NAME>` is empty
  without the opt-out flag.
- `--skip-tenant-check` — explicit opt-out that logs a WARNING
  naming the current session tenant. Used by programmatic callers
  that have pre-validated the session (e.g. `auto-migrate`
  `SessionPair.verify_distinct`, the CI rehearsal harness).

Enforced by `safeguards.require_tenant_assertion(params, expected_name,
skip_check, subcommand)` at the top of each destructive execute() —
BEFORE any Commander call. Dry-runs bypass as before.

### Difference from the source interlock

The 4-layer source interlock is multi-signal defense against typos
WITHIN a known-source session. This new assertion is single-signal
defense against MISCLASSIFYING the session itself — it fires on target
sessions too, because target-misaim was the exact red-team outcome.

## Source-tenant read-only hard-rail (harness layer)

The 4-layer interlock above is the primary defense — it fires in the
subcommand itself. But the CI rehearsal harness
(`migration_scripts/ci/comprehensive_rehearsal.py`) adds a coarser
**second line** that refuses the call without ever reaching Commander.

### What it does

When `--source-read-only` is passed to the harness, every invocation
against `--source-config` is checked against the
`SOURCE_SAFE_SUBCOMMANDS` allowlist. Anything not on the allowlist
short-circuits to FAIL with a `SAFEGUARD (source-read-only)` log line
— no subprocess, no Commander call, no API hit.

### The allowlist (known-read-only)

```
session, self-test, pre-flight,
plan, estimate, reconcile, verify, audit-verify, audit-export,
manual-actions, transition-check,
convert, records-manifest,
records-export, records-attachments-download,
capture-target-state, decommission (plan-only), assemble-inventory
```

Any destructive subcommand (`structure`, `users`, `records-import`,
`cleanup`, `records-attachments-upload`, `records-shares`,
`shared-folders-reconcile`, `take-ownership`, `transfer-user`) is
not on the list and therefore cannot be invoked against the source
config while `--source-read-only` is active.

### When to use

- Real customer data as source. Zero tolerance for accidental
  writes.
- Sharing the rehearsal script with ops who may not have vetted
  every flag — the hard-rail protects against operator error.
- CI runs where a misconfigured `CONFIG_SRC` vs `CONFIG_TGT`
  environment variable could route a destructive call the wrong way.

### Folder-UID-scoped records migration (`Tier 6c`)

`records-export --folder-uid <uid>` (new) restricts the export to
records reachable from a specific folder subtree on the source. No
structure, no users, no shares outside that subtree are touched on
the export side. Pair with `--source-read-only` for the strongest
guarantee against any source mutation.

Typical usage:
```bash
python3 migration_scripts/ci/comprehensive_rehearsal.py \
    --source-config ~/.keeper/source-tenant.json \
    --target-config ~/.keeper/target-tenant.json \
    --run-dir /tmp/rehearsal-folder \
    --prefix MIGTEST- \
    --source-folder-uid <UID-1> \
    --source-folder-uid <UID-2> \
    --source-read-only
```

## Silent-failure defense (verify-after-delete)

Commander's enterprise-\* commands log **warnings without raising**
on certain failures. The plugin used to trust the command's
success-ish return value and count silent no-ops as successful.
Three bugs of this class were found live during v1.3 rehearsals and
fixed:

| Bug | Discovered | Fix |
|---|---|---|
| `--mc` context silently routed writes to MSP root instead of MC | 2026-04-19 Phase E smoke | `MCContext` returns MC-scoped `params`; callers use `ctx.params` (rc2) |
| `cleanup` counted `enterprise-node --delete` as success when Commander warned 'node has children' | 2026-04-19 Tier 6 live rehearsal | `_still_present()` re-queries after each delete; leftover → error |
| `decommission` counted `enterprise-user --delete` as success when user had owned records / queued teams blocking deletion | 2026-04-19 decommission hardening | `DecommissionClient.is_user_present()` post-delete check |

### Pattern — "trust but verify"

Every destructive subcommand that can hit Commander's
warning-without-exception pattern now runs a verify step after each
mutation:

```python
call_ok = client.delete_node(name)     # may return True even on silent fail
leftover = _still_present(client, 'nodes', 'name', name)
if call_ok and not leftover:
    # actually deleted
else:
    # silent no-op or hard fail — count as error
```

For `decommission` the hook is `DecommissionClient.is_user_present()`.
Default implementation returns False (opt-out of verification),
so legacy clients don't accidentally permit a failure but do
preserve the old behavior when explicitly desired.

This is the same bug class as the `--mc` silent no-op, and the same
defensive pattern. If a future subcommand adds a destructive loop
over Commander calls, it should add a `is_X_absent` / `_still_present`
verification step on the matching protocol.

## Failure recovery capabilities

### Per-subcommand idempotency

Every mutating subcommand is re-run safe with the same inputs:

| Subcommand | Re-run behavior |
|------------|-----------------|
| `structure` | Commander's `enterprise-node/team/role --add` return non-zero on "already exists"; the driver records FAILED with "may already exist" note, so partial runs converge. |
| `users` | Transition-check Category D (ALREADY_IN_TARGET) path short-circuits — no duplicate invite. |
| `records-import` | Commander's native import dedupes by record key before creating. |
| `records-attachments` | Each manifest row independent; skips source records with no attachments. |
| `records-shares` | `share-record -a grant` is idempotent on Commander's side. |
| `take-ownership` | Per-user report records YES/NO; re-run the CSV with the same verification_report to retry only the NO rows. |
| `transfer-user` | Commander auto-locks; re-running on an already-locked user returns "user already locked" — driver counts as FAILED but no state corruption. |
| `cleanup` | `enterprise-* --delete -f` safe to re-run — entities already gone return non-zero, counted as error. |
| `decommission` | Same as cleanup; `enterprise-user --lock` is idempotent, `--delete` only removes what's still present. |

### Orchestrator-level resume

`orchestrator.py` writes `.run_state` after every stage:

```
PHASE=users
STATUS=PASSED
TIMESTAMP=2026-04-18T18:03:00Z
```

On `tenant-migrate run ... --resume`, the driver reads the file:
- `PASSED` / `SKIPPED` / `AUTHORIZED` → advance to the next stage.
- `FAILED` / `PAUSED` / `BLOCKED` → replay the same stage.
- Unknown → start from `STAGE_ORDER[0]` (conservative).

### Checkpointed point-of-no-return

Before any destructive source-side operation (`decommission`), admins
must run `tenant-migrate point-of-no-return` which:
1. Reads the validator's `checks.csv` — refuses if any FAIL row present.
2. Requires `--confirm YES` — no default bypass.
3. Writes a JSON checkpoint with SHA-256 self-signature + UTC timestamp.
4. `decommission` refuses to run without a valid non-expired (72h
   default) checkpoint. Signature drift is detected and rejected.

### Hash-chained audit log

Every `records-export` and `take-ownership` appends a JSON event to a
per-run `audit.log` (see `audit.py::append_audit_event`). Each event
carries a `prev_hash` field chained to the prior line; tampering with
ANY earlier line invalidates every downstream hash.

`tenant-migrate audit-verify --directory DIR`:
- Walks `SHA256SUMS.txt` — reports `ok` / `missing` / `mismatch` per file.
- Walks `audit.log` — reports first broken line number (or `PASS`).
- Returns a single `ok: bool` for CI gating.

### Recovery from partial failures

| Failure mode | Recovery |
|--------------|----------|
| Ctrl+C mid-stage | Re-run same stage; idempotency handles the replay. |
| Network drop mid-user invite | Transition-check Category E (PENDING_INVITE) path handles retries. |
| Plan-dir files corrupted | Re-run `plan` or `assemble-inventory` from the same source. |
| Target tenant drift between dry-run and live | Rerun `--dry-run` — classifier will show the new CONFLICT / SKIP deltas. |
| Admin machine failure | Inventory JSON is the canonical hand-off; any fresh admin machine can resume from `.run_state` + the inventory + the checkpoint. |
| Checkpoint expired mid-decom | Re-run `point-of-no-return` to re-issue; decommission will then proceed. |
| Tampered audit log | `audit-verify` flags the broken line; compliance team has cryptographic evidence of the tampering. |

### What recovery does NOT protect against

- **Simultaneous write from outside this plugin** — if another admin
  edits the target during a run, idempotency can't sort out the drift.
  Mitigation: run with exclusive target-admin access.
- **Source-side deletion during migration** — `transfer-user`
  auto-locks but if a source user deletes a record between plan and
  export, the migration misses it silently. Mitigation: put source
  under change-freeze during the migration window.
- **API throttling losing a partial batch** — Commander's own retry
  logic handles per-call throttling; at higher volume, wrap
  `records-attachments` / `records-shares` in a batching script.

## Threat model (brief)

Attacker class | Can do? | Mitigation
---|---|---
Untrusted network between admin + Keeper | No — Commander sends only ciphertext | N/A
Compromised admin machine | Yes — plaintext in memory during the run | Dedicated host, short-lived dirs, 0600 on disk
Malicious insider admin | Yes — full access by design | Audit log + checkpoint + 0600 leave forensic trail
Tampered USB / S3 bucket | Detected — SHA256SUMS.txt + audit.log chain | `audit-verify`
Stolen inventory file | Yes, reveals entity structure; plaintext only if `--include-fields` was used | Exclude from default; chmod 0600; cleanup after
Stolen checkpoint file | No destructive op — signature is self-certifying + 72h TTL | `gate.py::read_checkpoint`
