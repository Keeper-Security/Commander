# Pre-migration requirements — customer admin guide

**Audience:** the customer-side admin commissioning a Keeper tenant
migration. Read this BEFORE the migration day; the steps below are
prerequisites that must be completed by the customer-side admin (or
delegated to a designated migrating-admin user).

**Why this exists:** the migration tool moves data the migrating
admin can see. Records that live only in individual users' vaults
(not shared with the admin) are invisible to the tool until the
user explicitly grants access. This guide walks through the
ownership / sharing prep that makes those records reachable, plus
the surrounding manual steps that fall outside the tool's scope.

**Where the tool ships:** `keeper tenant-migrate <subcommand>` is a
built-in Keeper Commander command. Once `keepercommander` is
installed and the migrating admin is logged in to the source tenant,
the tool is ready to run.

---

## 1. Before migration day — preparation (allow 1-2 weeks)

### 1.1. Identify the migrating admin

Pick **one user** who will run the migration on the customer's
behalf. This user becomes the **migrating admin**. The migrating
admin needs:

- Enterprise-admin role on **both** the source tenant and the target
  tenant (the migration runs in two Commander shells, one per
  tenant)
- Direct in-browser access to the source tenant's Keeper Web Vault
  (for verification of share grants in § 1.2)
- A clean workstation with `keepercommander` installed and `keeper
  login` ready against each tenant

The migrating admin is the **owner of record** for the migration
audit chain — every operation is signed by their session.

### 1.2. Records and shared folders → migrating admin's vault

This is the heart of pre-migration prep. Records the migrating
admin cannot see do not migrate.

#### Why this matters

Keeper's zero-knowledge posture means each user's vault records are
encrypted under that user's keys. The migrating admin can only
read records that are:

- Owned by the migrating admin directly, OR
- Shared with the migrating admin (via shared folder membership or
  direct record share), OR
- In a shared folder where the migrating admin has at least Read
  permission

If a source user has records ONLY in their personal vault (not in
any shared folder), those records stay invisible until the user
explicitly shares them with the migrating admin.

#### Step-by-step: bringing records into the admin's view

**Step 1 — Inventory by shared-folder ownership.** Have each
source-tenant user run a quick check in the Web Vault:

> Web Vault → Shared Folders → for each folder I own:
> click *Share* → confirm migrating-admin email is listed with
> "Can Edit" + "Can Share" (or higher). If not, *Add User* and grant
> "Can Edit" + "Can Share".

This makes the folder's records visible to the migrating admin.

**Step 2 — Inventory personal-vault records.** For records that
live ONLY in the user's personal vault (not in any shared folder),
the user has two options:

- **Option A (recommended): move into a shared folder.** Web Vault
  → drag the record into an existing shared folder that the
  migrating admin can see. The record is now reachable.
- **Option B (direct record share).** Web Vault → record → *Share*
  → enter migrating-admin email → "Can Edit". Per-record sharing
  works but is tedious for large vaults; prefer Option A when
  feasible.

**Step 3 — Bulk take-ownership (migrating admin, after Step 1 + 2
are complete).** Once shares are in place, the migrating admin
runs:

```bash
keeper login                                     # source tenant
keeper tenant-migrate pre-flight \
    --source-config <source-config> \
    --run-dir ~/migration-prep
```

The `pre-flight` subcommand surfaces a `manual-actions.json`
report. Look for:

- **`PREREQUISITE_GRANT_NEEDED`** entries — users who haven't
  completed Step 1 yet. Send them a reminder.
- **`RECORD_NOT_VISIBLE`** entries — records that exist in the
  source tenant but are not reachable from the migrating admin's
  session. These are still locked in personal vaults.

When `manual-actions.json` shows zero `PREREQUISITE_GRANT_NEEDED`
and zero `RECORD_NOT_VISIBLE`, the records are ready for migration.

**Step 4 — (Optional) bulk take-ownership of accessible records.**
For records the admin can see but doesn't own, the migrating admin
can claim ownership in advance:

```bash
keeper tenant-migrate take-ownership \
    --source-config <source-config> \
    --run-dir ~/migration-prep \
    --dry-run                                    # preview first
```

After reviewing the dry-run report, drop `--dry-run` to apply. The
admin now owns those records; the original owners retain `Can Edit`
access via the shared folder.

> **What about `transfer-user`?** `transfer-user` is the
> alternative path: source users opt in to share their **entire
> account** with the migrating admin via Keeper's
> `REQUIRE_ACCOUNT_SHARE` mechanism. Use it when source users
> consent to a full-account transfer rather than per-folder
> sharing. Subject to per-user CATEGORY_E (pending-invite) and
> CATEGORY_B (personal-Keeper) edge cases — `transition-check`
> classifies each user before the migration runs. Details in
> `LIMITATIONS.md § 5`.

### 1.3. License-seat headroom

Confirm the target tenant has seat-count headroom for the
incoming users. The tool does NOT enforce seat limits; Keeper's
own user-creation step will reject over-quota invites at runtime,
leaving the migration partially complete.

Action: ask your Keeper account manager to confirm the target
tenant's licensed seat count exceeds (source user count − overlap
between source/target users).

### 1.4. SSO / IdP plan

If the source tenant uses SSO (SAML / SCIM), prepare the IdP
admin actions BEFORE the migration:

- **SAML**: stage the new ACS URL for the target tenant; do NOT
  cut over until the migration's `users` phase has run on the
  target side. Once users are created on target, repoint the IdP
  app to the target tenant's ACS URL. The migration tool does NOT
  touch the IdP — every IdP (Azure AD, Okta, Ping, etc.) has a
  different admin API and customers stay in the loop.
- **SCIM**: regenerate the SCIM bearer token on the target tenant
  before updating the IdP's SCIM endpoint configuration.

### 1.5. PAM infrastructure (if applicable)

If the source tenant has PAM resources, list:

- Each PAM gateway and its host
- Each rotation schedule
- Each PAM agent and its target system

These are tenant-bound; the migration tool flags them in
`manual-actions` but does NOT re-create them on target. Plan a
post-migration re-setup window:

1. Install a fresh gateway binary on the target tenant
2. Generate a new gateway token; install on the host
3. Re-pair agents to the new gateway
4. Re-create rotation schedules (rotation engine is tenant-scoped)

### 1.6. SIEM / audit forwarding

If the source tenant pipes audit events to a SIEM:

- Identify the SIEM webhook / log forwarder endpoint
- Update the target tenant's enterprise-audit-export configuration
  with the same endpoint (or a new endpoint, depending on your
  retention policy)
- After cutover, source-tenant audit retention follows your
  policy; if you need historical audit log on the new tenant,
  export the source's audit history BEFORE migration day (the
  migration tool's `audit-export` is for the migration's OWN
  audit chain, not the tenant's historical events)

### 1.7. Backup directory

Reserve a directory on the migrating admin's workstation for the
migration run-dir. Suggested location: `~/migration-2026-Q2/`
(replace with your own naming). All migration artifacts land here:

- `inventory.json` — full source-tenant snapshot
- `manifest.csv` — source UID → target UID pairing
- `audit.log` — HMAC-chained operation log
- `records_export/` — per-record JSON files (sensitive; 0o600)
- `SHA256SUMS.txt` — integrity manifest

The run-dir contains **plaintext** field values for any record the
migrating admin can see (so they can be re-encrypted under target
keys via Commander's import). **Treat the run-dir as you would the
admin's personal vault export.** Do NOT commit it to a shared
repository; delete or move to encrypted storage after the migration
completes.

---

## 2. Migration day — what the admin does

The migration is operator-driven. The migrating admin runs a
sequence of subcommands documented in `OPERATOR_PLAYBOOK.md` and
`RUNBOOK.md`. The high-level flow:

1. `pre-flight` — re-confirm readiness
2. `plan` + `plan-report` — generate the customer-facing preview
3. **Customer review of the preview** — sign-off before any writes
4. `point-of-no-return` — locks the plan
5. Apply phase — `structure`, `users`, records pipeline,
   `take-ownership`, `verify`
6. Source-side cleanup (if applicable) — `cleanup`, `decommission`

Estimated wall-clock: **~15-30 minutes per 1,000 records, +
overhead for large nested shared folders**. Plan a maintenance
window or run during low-traffic hours.

### What customers MUST NOT do during migration

- **Do not edit either tenant via Web Vault while migration is in
  flight** — concurrent writes invalidate the manifest pairing and
  trigger drift in the post-migration verify report
- **Do not change SSO / IdP settings mid-migration** — wait for
  the `users` phase to complete before repointing the IdP
- **Do not run other Commander automation** against either tenant
  during the migration window — concurrent SDK calls compete for
  the same persistent-login session

---

## 3. After migration — verification + manual cleanup

### 3.1. Tool-side verification

The migrating admin runs:

```bash
keeper tenant-migrate verify --target-config <target-config> --run-dir <run_dir>
keeper tenant-migrate audit-verify --run-dir <run_dir>
sha256sum -c <run_dir>/SHA256SUMS.txt
```

All three should return clean. If any fail, see
`RUNBOOK.md § Verification failures` and the
`manual-actions.json` report for residual items.

### 3.2. Customer-side manual cleanup

These are **deliberately out of the tool's scope** — the customer
admin must complete them:

- [ ] **PAM gateway / agent / rotation re-setup** on the target
      tenant (per § 1.5 inventory)
- [ ] **SSO / IdP repointing** — flip the SAML ACS URL or SCIM
      endpoint from source to target (per § 1.4 plan)
- [ ] **Source-tenant decommission decision** — keep dormant for a
      retention window, or run `keeper tenant-migrate decommission`
      to lifecycle-end source users
- [ ] **Personal-Keeper user transfers (Category B)** — each
      affected user accepts the transfer in-browser; the tool can
      only invite, not accept
- [ ] **Cross-enterprise conflict resolution (Category C)** — if
      any source user is already a member of a different Keeper
      enterprise, contact Keeper Support
- [ ] **Restore individual ownership (if you want it back)** — by
      default the migrating admin owns all migrated records. To
      return ownership to the original users:
      ```bash
      keeper tenant-migrate take-ownership-restore \
          --target-config <target-config> \
          --run-dir <run_dir> \
          --backup-dir <pre-take-ownership-backup>
      ```
- [ ] **Archive the run-dir** to encrypted storage if regulatory
      retention requires it — then delete from the admin's
      workstation

### 3.3. License-seat reduction (if applicable)

For absorptions: confirm the combined seat count matches the
post-migration billable count. For divestitures: reduce the
source tenant's seat count after `decommission` completes.

### 3.4. SIEM continuity

Confirm the target tenant's audit-export endpoint is receiving
events. If your SIEM correlates by tenant ID, update the
correlation rules for the new tenant ID.

---

## 4. Communication template for source users

Use the following template (or adapt) to communicate with source
users BEFORE migration day:

> Subject: Action needed — Keeper vault migration to new tenant on
> [DATE]
>
> Hi [user name],
>
> Our organisation is migrating its Keeper vault to a new tenant on
> [DATE]. Your records and shared folders will be moved
> automatically by the migrating admin ([ADMIN NAME / EMAIL]) — but
> we need a small action from you BEFORE [DATE - 1 week] so that
> the migrating admin can see your data:
>
> **Action 1 — Share your owned shared folders with the migrating
> admin.** Open the Keeper Web Vault, go to Shared Folders, and for
> each folder you own:
> - Click *Share*
> - Add `[ADMIN EMAIL]` with "Can Edit" + "Can Share" permission
> - Save
>
> **Action 2 — Move personal records into a shared folder (or skip
> this if you don't have personal-only records that need
> migrating).** Records that live only in your personal vault are
> invisible to the migration unless you share them. For each
> personal record that should be migrated:
> - Either drag it into one of your shared folders, OR
> - Click *Share* → add `[ADMIN EMAIL]` → "Can Edit"
>
> After the migration completes, the migrating admin will return
> ownership of your records to you (or to the configured target
> owner). You will be invited to the new Keeper tenant; accept the
> invite when it arrives.
>
> If you have **Personal-Keeper plan records** (your own personal
> Keeper account, not enterprise), those require an additional
> in-browser acceptance — you'll receive a separate invite for
> those after migration day.
>
> Questions? Reach out to [ADMIN NAME] or open a ticket at
> [INTERNAL SUPPORT].
>
> Thanks,
> [INTERNAL IT TEAM]

---

## 5. Quick prerequisites checklist (one-page summary)

Print this and hang it on the migrating admin's monitor.

### Two weeks before migration day

- [ ] Migrating admin identified; has enterprise-admin on both tenants
- [ ] Communication template sent to all source-tenant users
- [ ] Target tenant provisioned and licensed for projected seat count
- [ ] SSO / IdP plan documented; new endpoints staged but not active
- [ ] PAM inventory exported; re-setup runbook prepared

### One week before migration day

- [ ] All source users have completed Action 1 + Action 2 (per § 4)
- [ ] `keeper tenant-migrate pre-flight` reports zero
      `PREREQUISITE_GRANT_NEEDED`
- [ ] `keeper tenant-migrate pre-flight` reports zero
      `RECORD_NOT_VISIBLE`
- [ ] Customer review of `plan-report` complete; sign-off obtained
- [ ] Maintenance window scheduled with stakeholders

### Migration day

- [ ] Run-dir reserved on admin workstation (with at least
      [estimated size + 50% buffer] free)
- [ ] Both tenant shells authenticated (interactive `keeper login`)
- [ ] Stakeholders notified that no Web-Vault edits should happen
      during migration window
- [ ] Run the migration per `OPERATOR_PLAYBOOK.md` Workflow A / B
      / E / F (whichever fits your scenario)

### Day after migration

- [ ] `verify` + `audit-verify` + `sha256sum -c` all clean
- [ ] PAM infrastructure re-set up on target
- [ ] SSO / IdP repointed; first user logged in successfully
- [ ] Migrating admin has returned record ownership to users (if
      Step 4 was used)
- [ ] Source-tenant decommission decision executed
- [ ] Run-dir archived or deleted per retention policy

---

---

## 6. Absorption (S2) — special considerations

Use this section if the migration is an **acquisition / absorption**:
your tenant A is acquiring Company B and B's full tenant data is
folding into A's already-populated tenant.

This is more nuanced than a standard rename because A already has
its own users, roles, teams, and shared folders. Conflicts will
happen. Plan for them.

### 6.1. Dual-admin coordination

Both tenants' admins must be in the loop:

- **B's admin (source-side)** ensures B's source users complete the
  PREREQUISITE_GRANT actions in § 1.2 (records → migrating admin
  visibility) before migration day
- **A's admin (target-side)** runs `capture-target-state` on A
  BEFORE the migration applies — this snapshots A's pre-absorption
  state so the post-absorption `verify` knows what to leave alone
- **The migrating admin** can be a designated user with
  enterprise-admin on both — or two distinct people in two shells
  coordinating via the shared `--run-dir`

If A and B's admins are different people, agree on a comms channel
(Slack DM, shared doc, dedicated email thread) for live coordination
on migration day.

### 6.2. Sub-node strategy for B's tree

Default approach: B's enterprise tree lands under a new sub-node of
A, named something like `"B Company (acquired 2026-Q2)"`. This
keeps B's structure intact, recognisable, and reversible.

Decide **before migration day**:

- The exact name of the absorption sub-node
- Whether to keep B's internal node hierarchy as-is, or flatten
- Which A-admins get manage-permissions on the new sub-node

The `declare overlay` configuration in the run-dir (`migration.yaml`)
encodes this:

```yaml
nodes:
  remap:
    "My Company": "B Company (acquired 2026-Q2)"
```

### 6.3. Naming-collision policy

When B has a role / team / shared folder with the same name as one
already in A (e.g. both have an "Administrator" role), the tool
applies **Layer-1 default: rename-with-suffix**. B's "Administrator"
role becomes "Administrator_B" on target.

Customer decision (BEFORE migration day):

- **Accept rename-with-suffix.** Simple, automatic, reversible.
  Post-absorption, A's admin can manually consolidate via the Web
  Vault if desired ("Administrator" + "Administrator_B" → review
  members, merge by hand).
- **Pre-rename in the overlay.** If B's name is itself ambiguous
  (e.g. "Finance" collides with "Finance" but B's is actually
  procurement), pre-rename via `teams.rename` overlay verb to
  something distinctive ("Finance_BProcurement"). Cleaner than
  post-hoc cleanup.
- **Manual merge BEFORE migration.** If two equivalent roles/SFs
  should become ONE on target, the simplest path is to manually
  consolidate on B's side first (Web Vault → reassign members /
  records), then re-snapshot. The tool does NOT do automatic
  merging.

### 6.4. User email collision

If B has a user `alice@b-company.com` AND A already has
`alice@b-company.com` (same email, different person — rare but
possible across two enterprises that share a contractor), Keeper's
user-creation rejects the duplicate. Options:

- **Email domain rewrite.** Use `users.domain_remap` in the overlay
  to give B's users an A-domain email
  (`alice@b-company.com → alice@a-company.com`). Coordinated with A's
  IdP cutover.
- **Drop the colliding user from B's transfer.** Use `users.drop`
  to skip; manually invite A's existing user to B's content
  post-migration.

Settle BEFORE migration day; collisions discovered mid-run pause
the migration on a per-user manual-action gate.

### 6.5. IdP harmonisation

Decide whether B's users keep their original email domain or get
A's domain post-absorption:

- **Keep B's domain.** No IdP rewrite needed; A's IdP gains a
  second SAML domain configuration if SSO bridges both.
- **Rewrite to A's domain.** Use `users.domain_remap` in the
  overlay; A's IdP handles authentication for the rewritten
  addresses; B's IdP is deprecated post-cutover.

The decision affects: SSO flow, user-side email change
communication, SCIM provisioning lifecycle.

### 6.6. Audit-trail bifurcation

A's existing audit history STAYS at A. B's pre-migration audit
history stays at B (re-keying side effect per `LIMITATIONS.md § 2`).
The migration's OWN `audit.log` records the absorption itself.

If regulatory retention requires preserving B's pre-migration audit
history at the new tenant, export it BEFORE migration day via
Keeper's enterprise audit-export and store alongside the
post-migration archive.

### 6.7. Pre-absorption license-seat estimate

A's seat count after absorption ≈ (A's pre-absorption seat count) +
(B's transferred user count) − (any cross-tenant duplicates
resolved by user-collision policy in § 6.4).

Confirm with your Keeper account manager BEFORE migration day that
A's licence accommodates the projected total.

---

## 7. Divestiture (S3) — special considerations

Use this section if the migration is a **divestiture / spin-off**:
a subset of your existing tenant A is being carved out to a new
empty tenant A'.

This is selective extraction — the hardest decisions are about
**what stays** vs. **what goes**, and **who owns what** during the
transition.

### 7.1. Scope decision (what transfers)

Decide which nodes / teams / users / shared folders go to A':

- **Include scope.** Typically a top-level node and everything
  under it, e.g. `"My Company/Spin-Off Division/*"`. Encoded in
  the overlay as:
  ```yaml
  scope:
    include_nodes: ["My Company/Spin-Off Division/*"]
  ```
- **Exclude scope.** Anything under the divested subtree that
  must STAY at A (e.g. confidential records the parent retains):
  ```yaml
  scope:
    exclude_nodes:
      - "My Company/Spin-Off Division/Confidential-Parent-Only"
  ```
- **User drops.** Users under the divested subtree who don't go
  with the spin-off (typically parent-company executives who
  maintain oversight):
  ```yaml
  users:
    drop:
      - "ceo.parent@a-company.com"
      - "cfo.parent@a-company.com"
  ```
- **Team drops.** A-internal teams that aren't part of the
  divestiture:
  ```yaml
  teams:
    drop:
      - "A-Wide Steering Committee"
  ```

Customer responsibility: produce the inclusion/exclusion lists in
writing, signed off by both A's leadership and A''s incoming
leadership, BEFORE migration day. The migrating admin encodes the
agreed scope into `migration.yaml`.

### 7.2. Dual-ownership records

A record shared by BOTH the divested subtree AND the residual A
tree (e.g. a vendor contract used by both the spin-off and the
parent) requires a per-record ownership decision. The tool surfaces
these as `DUAL_OWNERSHIP_REVIEW` entries in `manual-actions.json`
after the `plan` phase runs.

Typical disposition options (customer admin decides per record):

- **Copy to both.** Duplicate in A' (under spin-off ownership) AND
  keep in A. Both tenants have an independent record going forward.
- **Move to A', keep a reference in A.** A's record is replaced
  with a placeholder noting "moved to spin-off tenant" with a
  contact for the new owner.
- **Keep at A, grant cross-tenant share.** Record stays at A;
  spin-off users get external-share access (Keeper's cross-enterprise
  share path — subject to policy and `LIMITATIONS.md § 9`).
- **Drop from migration.** Record stays at A; spin-off users
  re-create as needed.

The migrating admin walks the `DUAL_OWNERSHIP_REVIEW` list with
A's data-governance owner and records each decision in the run-dir
BEFORE proceeding to the apply phase.

### 7.3. Source-side cleanup timing

`cleanup` and `decommission` on the source tenant (A) are
DESTRUCTIVE. They remove the divested entities from A and lifecycle-end
the divested users on A's side.

**Sequence (non-negotiable):**

1. Apply the migration (data → A')
2. Run `verify` on A' — confirm zero `FAIL` rows
3. Run `audit-verify` on the run-dir — confirm chain integrity
4. A' admin confirms in writing that A' is operationally complete
   and the spin-off team can work from A'
5. A's admin signs off on the cleanup readiness
6. THEN run `cleanup` and `decommission` on A

If you cleanup BEFORE A' is verified, recovery is via the
pre-delete SHA256SUMS backup — possible but slow and partial.
Don't.

### 7.4. License-seat reduction at A

After `cleanup` and `decommission` complete on A, contact your
Keeper account manager to reduce A's licensed seat count to reflect
the departed users. The tool does NOT trigger billing changes; this
is a manual administrative step with Keeper.

### 7.5. SSO / IdP setup for A'

A' typically gets:

- A new IdP application registration (SAML SP / SCIM SP)
- Either: a sub-tenant binding on A's existing IdP, OR a separate
  IdP tenant for the spin-off
- A bridge period during cutover where both IdPs accept the
  divested users' SSO logins

Coordinate IdP cutover with A''s admin: typically the bridge
window is 1-2 weeks post-migration; the divested users' "old"
A-IdP login is disabled at the end of the window.

### 7.6. PAM in a divestiture

PAM resources transferred to A' require fresh gateway / agent /
rotation re-setup on A' (same as absorption — `LIMITATIONS.md § 3`).
Plan a post-migration window of 1-2 working days for PAM re-setup
on A' before the spin-off team can use PAM functionality on the
new tenant.

### 7.7. Post-divestiture handoff to spin-off ownership

After cleanup completes on A and A' is fully operational, the
migrating admin's role on A' typically transfers:

- A' admin (incoming spin-off leadership) gets enterprise-admin
- The original migrating admin steps down from A''s
  enterprise-admin role (use Keeper Web Vault: Admin → Users →
  Remove from role)

Document the handoff in writing for audit / compliance.

---

## See also

- `OPERATOR_PLAYBOOK.md` — six workflow narratives (A standard
  forward / B nested shared folder / C resume after crash / D
  downstream-consumer handoff / E absorption / F divestiture)
- `RUNBOOK.md` — canonical first-run walkthrough
- `LIMITATIONS.md` — explicit out-of-scope items + edge cases
- `SECURITY_MODEL.md` — zero-knowledge posture, 4-layer interlock,
  audit chain integrity, 0o600 handling
- `OUTPUT_CONTRACT.md` — run-dir schema (for downstream-consumer
  integrators only — most customer admins won't need this)
