# Wizard guide — first migration in 10 minutes

`tenant-migrate wizard` is the menu-driven front door. It coordinates
two Commander shells (source + target) via a shared run directory,
and calls the right subcommand for you based on:

- which tenant the current shell is authenticated to,
- what artifacts already exist in the run-dir, and
- what the run-spec says you're trying to migrate.

---

## Prerequisites

- Python 3.9+, Commander 17.2.11+, plugin installed (`install.py`).
- Two separate Commander sessions ready:
  - **Source shell**: logged into the tenant you're migrating FROM.
  - **Target shell**: logged into the tenant you're migrating TO.
- One empty run directory both shells can read/write (e.g.
  `/tmp/migrate-2026-04-18/` or a shared NFS mount).

---

## Step 1 — Launch in both shells

```bash
# Source shell (EU demo):
keeper --config ~/.keeper/source-tenant.json
Commander> tenant-migrate wizard --run-dir /tmp/migrate-2026-04-18

# Target shell (MSP disposable):
keeper --config ~/.keeper/target-tenant.json
Commander> tenant-migrate wizard --run-dir /tmp/migrate-2026-04-18
```

The wizard prints a banner showing which tenant each shell is on. If
a shell shows `No active session`, run `keeper login` first.

---

## Step 2 — Create the run-spec (source shell, one-time)

First invocation creates `<run_dir>/migration.yaml`. The wizard walks
through:

1. Source tenant region / type
2. Target tenant region / type / MC name (when type=mc)
3. What to migrate (multi-toggle: structure / users / records /
   attachments / shares / decommission)
4. Scope (full / node / prefix)
5. Data residency pin (blocks cross-region moves)

All values go into `migration.yaml` with mode 0600. The target shell
reads the same file on its next invocation.

---

## Step 3 — Source shell proposes `plan`

Once the spec exists, the wizard detects role=source and artifact
state and offers:

```
  Next step
  1) plan
  2) records-export
   q) cancel
```

Pick `plan`. The wizard asks `Dry-run first? [Y/n]` (choose Yes the
first time). The dry-run writes `<run_dir>/plan.dry-run.md` you can
review before running for real.

Running `plan` for real writes `<run_dir>/inventory.json` (chmod 0600;
plaintext only if you passed `--include-fields` somewhere).

---

## Step 4 — Target shell sees the inventory, proposes `structure`

Switch to the target shell, run the wizard again. It detects:

- role=target (by matching spec.target against the current session)
- `inventory.json` present in run-dir

It runs the **pre-flight compat checks** automatically:

```
  ── Pre-flight compatibility checks ──
    ✓ node_depth: source max node depth: 4
    ✓ record_types: all 7 source record types present on target
    ✓ attachment_size: all 12 attachments under 100MB cap
```

Any FAIL prompts "continue anyway?". Then offers:

```
  Next step
  1) structure
  2) users
  3) records-import
  ...
```

Pick `structure` first. Dry-run → real run → inspect `reconciliation.md`.

---

## Step 5 — Rinse and repeat

The wizard remembers what's done via artifacts in `<run_dir>`. Each
invocation re-detects state and proposes the next uncompleted step
for the current shell's role. Artifacts:

| File | Written by | Role |
|------|-----------|------|
| `migration.yaml` | wizard | both |
| `inventory.json` | `plan` (source) | source |
| `target_state.json` | `capture-target-state` | target |
| `manifest.csv` | `records-manifest` | target |
| `checks.csv` | `verify` | target |
| `reconciliation.md` | `reconcile` | target |
| `audit.log` | every mutating subcommand | both |

---

## Step 6 — Verify & sign off

Target shell, once users + records are in:
```
  1) verify
  2) reconcile
```

`verify` writes `checks.csv` + a receipt with per-user SF permission
diffs + record field matches. `reconcile` writes
`reconciliation.md` with source/target/delta + any manual-action
reminders.

If both are clean, you can run `manual-actions --inventory ... --output
actions.md` to emit a customer-facing checklist (SSO IdP reconfig,
PAM gateway re-registration, post-migration user sign-off).

---

## Step 7 — Destructive phases are gated

`cleanup`, `decommission`, `take-ownership`, `transfer-user` all:

1. Print a safeguard banner with `⚠ DESTRUCTIVE` framing
2. Require `confirm_interactive` (yes / y / no / n / empty)
3. Refuse if `--expected-tenant-name` mismatches the current session
4. Refuse bulk ops over `--batch-cap` without `--override-batch-cap`
5. Refuse `decommission` without a signed `point-of-no-return`
   checkpoint from `gate.py`

---

## Step 8 — Rollback if needed

Every mutating subcommand appends to `<run_dir>/audit.log`. Each line
chains to the previous (prev_hash + signature) — tamper-evident.

To unwind:
```bash
tenant-migrate undo --audit-log /tmp/migrate-2026-04-18/audit.log
# dry-run by default, shows the inverse plan

# When you're sure:
tenant-migrate undo --audit-log /tmp/...audit.log --execute
```

`undo` verifies the chain first. If broken, it refuses to proceed.
Irreversible events (`cleanup`, `decommission`) are listed but not
acted on — the manual-action text tells you which SHA256SUMS backup
dir to restore from.

---

## Troubleshooting

- **"Role: unknown"** → the current shell doesn't match either
  `spec.source` or `spec.target`. Check `tenant-migrate session`;
  fix the enterprise_name / region field in `migration.yaml`.
- **Pre-flight FAIL on node_depth** → your source tree is deeper
  than the target plan allows. Flatten `source_root` first or
  re-parent the deepest nodes.
- **Pre-flight FAIL on record_types** → load the custom types on
  target first: `tenant-migrate structure --inventory ...
  --steps 0`.
- **Throttling** → add `--delay 2.0 --batch-size 50` to `users` /
  `records-shares` calls (or let the wizard's auto-adjustment tier
  do it once the auto-adjustment policy lands).

---

## What the wizard does NOT do

It doesn't authenticate for you. It doesn't decide for you whether
to use Path A (take-ownership) or Path B (transfer-user) — you pick
in the spec. And it never mutates anything without a dry-run preview
+ explicit confirmation.

## See also

- [`AUTOMATED_ADJUSTMENT.md`](AUTOMATED_ADJUSTMENT.md) — the wizard's
  automatic-decision policy: email-domain remap, SSO/SCIM handling,
  rate-limit auto-tuning. Each automatic behaviour has a manual
  override flag if you'd rather drive it explicitly.

