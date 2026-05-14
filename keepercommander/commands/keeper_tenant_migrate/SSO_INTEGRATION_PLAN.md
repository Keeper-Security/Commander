# SSO integration plan — migration tool ↔ Keeper SSO Cloud Connect

**Audience:** customer admin or migrating-admin planning the SSO /
IdP repointing portion of a Keeper tenant migration.

**Status:** forward-looking plan that covers two paths:

1. **Path A — `sso-cloud` CLI available** (depends on
   `Keeper-Security/Commander#2046` merging). At this writing the
   PR is OPEN, NOT MERGED. When/if it merges, Commander grows a new
   `sso-cloud` (alias `sso`) command group with 12 subcommands for
   Cloud Connect configuration management.
2. **Path B — `sso-cloud` CLI NOT yet available** (current state).
   SSO repointing stays a manual Web Vault / IdP-admin operation
   exactly as `CUSTOMER_REQUIREMENTS.md § 1.4` currently describes.

This plan ensures the migration tool's customer-facing materials
work in both worlds and can be tightened to Path A once #2046 lands.

---

## 1. What the migration tool does + does not do for SSO

The migration tool's existing behaviour (any version up to v1.7.7):

- ✅ **Detects SSO usage on source** during `pre-flight` — surfaces
  in `manual-actions.json` as `PREREQUISITE_SSO_CONFIG_REVIEW`
- ✅ **Captures SSO-related enforcement keys** (e.g.,
  `require_sso_login`, `restrict_sharing` for SSO-managed nodes)
  during `plan` / `assemble-inventory`
- ✅ **Re-applies enforcement keys** to the target tenant during
  the `structure` phase
- ❌ **Does NOT configure SSO Cloud Connect** on either tenant
  (IdP admin API differs per provider; customers stay in the loop)
- ❌ **Does NOT generate or rotate SAML / SCIM tokens** (each IdP
  has its own admin surface)
- ❌ **Does NOT push IdP metadata** to the target tenant

The cutover steps that the customer admin handles manually:

1. Pre-migration: register a new SAML SP / SCIM SP in the target
   IdP tenant (staged but inactive)
2. After `users` phase completes: activate the SAML ACS URL on the
   target tenant; update IdP to push to target's ACS
3. After cutover validated: deactivate / remove the source-tenant
   SAML SP from the IdP

---

## 2. Path A — when `sso-cloud` CLI is available

### 2.1. Upstream reference

`Keeper-Security/Commander#2046` adds the `sso-cloud` command group.
Per its PR description, it provides 12 subcommands for configuring
**Keeper SSO Cloud Connect** (Keeper's hosted SAML SP service —
distinct from on-prem SSO Connect):

| Subcommand | Purpose |
|---|---|
| `sso-cloud create` | Create a new SSO Cloud configuration on the tenant |
| `sso-cloud get` | Inspect an existing SSO Cloud configuration |
| `sso-cloud list` | List all SSO Cloud configurations on the tenant |
| `sso-cloud config-list` | List configuration fields and current values |
| `sso-cloud set` | Update one or more fields of an existing configuration |
| `sso-cloud upload` | Upload IdP metadata XML (with built-in validation) |
| `sso-cloud download` | Download Keeper's SP metadata XML for IdP-side configuration |
| `sso-cloud validate` | Validate the configuration end-to-end (metadata sanity, ACS reachability, etc.) |
| `sso-cloud delete` | Remove an SSO Cloud configuration |
| `sso-cloud log` | View recent SSO login attempts on this configuration |
| `sso-cloud log-clear` | Clear the SSO log |
| `sso-cloud guide` | Print an interactive setup guide |

**Important flag noted in #2046**: `--force-authn` — forces
re-authentication on the IdP side (useful for testing).

### 2.2. Scenario integration — when `sso-cloud` is available

The migration's existing `users` phase doesn't need to change.
What changes is the **operator's runbook around the migration**.
The customer admin now has CLI tooling for the SSO-side prep +
cutover.

**Pre-migration (target-tenant SSO bootstrap):**

```bash
# Operator at the target tenant Commander shell
keeper login --config <target-config>

# Step 1 — download Keeper's SP metadata for the IdP-admin to wire up
keeper sso-cloud download \
    --config-name "production-sso" \
    --output /tmp/target-sp-metadata.xml

# Step 2 — the IdP admin imports target-sp-metadata.xml into the IdP
# (e.g., Azure AD: "Enterprise Application" → "Single sign-on" →
# "Upload metadata file"). This creates the SAML application on the
# IdP side, pointing at the target Keeper tenant's ACS URL.

# Step 3 — the IdP admin exports the IdP's metadata
# (idp-metadata.xml) and gives it to the migrating admin.

# Step 4 — upload IdP metadata to the target tenant
keeper sso-cloud upload \
    --config-name "production-sso" \
    --metadata-file /tmp/idp-metadata.xml \
    --force-authn          # require re-auth on every login (recommended)

# Step 5 — validate end-to-end before cutover
keeper sso-cloud validate --config-name "production-sso"
# Expected: "All checks passed"
```

**During migration (no SSO change yet):**

The migration tool's `users` phase creates user accounts on the
target tenant in INVITED state. Users are not yet SSO-bound. The
SSO configuration from § 2.2 step 1-5 is in place but not enforced.

**Cutover (after `users` phase + verify):**

```bash
# Step 6 — enforce SSO on the target tenant's enterprise
keeper enterprise-role-edit --role "All Users" \
    --enforcement "require_sso_login=true"

# Step 7 — list SSO logs to confirm the first user can log in via IdP
keeper sso-cloud log --config-name "production-sso" --since 1h

# Step 8 — IdP admin decommissions the source-tenant SAML SP
# (UI-driven; varies per IdP)

# Step 9 — clean up source-tenant SSO Cloud (optional)
keeper login --config <source-config>
keeper sso-cloud delete --config-name "production-sso" --confirm
```

### 2.3. What this changes in `CUSTOMER_REQUIREMENTS.md` § 1.4

When Path A is available, replace the current § 1.4 prose:

> "**SAML**: stage the new ACS URL for the target tenant; do NOT
> cut over until the migration's `users` phase has run on the
> target side."

With:

> "**SAML via Keeper SSO Cloud Connect**: run
> `keeper sso-cloud download` on target to get the SP metadata;
> have the IdP admin register the SAML app on the IdP side; then
> run `keeper sso-cloud upload` on target with the IdP metadata.
> Validate with `keeper sso-cloud validate` before the cutover.
> See `SSO_INTEGRATION_PLAN.md` § 2.2 for the full sequence."

The `CUSTOMER_REQUIREMENTS.md § 3.2 manual cleanup` checklist gets
a matching update — the "SSO / IdP repointing" item becomes
"run `keeper sso-cloud delete` on source after cutover verification".

---

## 3. Path B — current state, `sso-cloud` CLI NOT available

This is the scenario as `CUSTOMER_REQUIREMENTS.md § 1.4` already
describes. No changes needed today.

The customer admin handles SSO entirely via:

- The target tenant's Web Vault → Admin → SSO Cloud Configuration UI
- The IdP admin console (Azure AD, Okta, Ping, etc.)
- Manual metadata file exchange

The migration tool stays out of the SSO mechanics; it only
surfaces SSO-related items in `manual-actions.json`.

---

## 4. Decision points — when to flip from Path B to Path A

`sso-cloud` becomes the recommended path when ALL of:

- [ ] `Keeper-Security/Commander#2046` is MERGED
- [ ] The merged version is on a Commander release the customer is running (currently v18.x)
- [ ] The customer is using **Keeper SSO Cloud Connect** (hosted)
      rather than **on-prem Keeper SSO Connect** (self-hosted; uses
      a different command surface that `sso-cloud` doesn't manage)

If the customer is on on-prem SSO Connect, Path B remains the
recommendation regardless of whether #2046 merges.

---

## 5. Cross-product compatibility

`sso-cloud` is a Commander command, not a `keeper-tenant-migrate`
command. It does NOT depend on the migration tool, and the migration
tool does NOT depend on it. They compose in the operator's runbook;
the operator chooses when to run which.

Specifically, the migration tool's `users` phase and the
`sso-cloud` commands are **independent**:

- Users can be created on the target before SSO is configured
  (they land in invited state, log in via password until SSO is
  cut over)
- SSO can be configured on the target before any users exist
  (the configuration is dormant until the enforcement is set)

The ordering is the customer admin's call. Recommendation:
configure SSO first (steps 1-5 of § 2.2), let users phase create
the accounts, validate per-user login, then flip the enforcement
(step 6).

---

## 6. Action items for the migration tool when #2046 merges

These are NOT to be done now — they're a forward-looking checklist:

1. Update `CUSTOMER_REQUIREMENTS.md § 1.4` per § 2.3 above
2. Update `OPERATOR_PLAYBOOK.md` Workflow A's pre-flight section
   to mention `sso-cloud validate` as an optional "before cutover"
   check
3. Add a note in `LIMITATIONS.md § 4 "SSO / SCIM IdP reconfiguration"`
   that for Keeper SSO Cloud Connect customers, Commander now
   provides the CLI surface — IdP-side admin work is still
   customer-owned but Keeper-side is automatable
4. Consider whether `manual-actions.json` should be enriched with
   `RECOMMENDED_SSO_CLOUD_CMDS` entries that print the exact
   `keeper sso-cloud ...` commands to run for each detected SSO
   configuration on the source tenant

No code changes are needed to the migration tool's core for any
of this — only documentation. `sso-cloud` is a separate command
group with its own lifecycle.

---

## See also

- `CUSTOMER_REQUIREMENTS.md § 1.4` — current SSO/IdP plan
  (Path B)
- `CUSTOMER_REQUIREMENTS.md § 3.2` — post-migration SSO cleanup
- `LIMITATIONS.md § 4` — explicit SSO/SCIM out-of-scope statement
- `Keeper-Security/Commander#2046` — upstream PR for `sso-cloud`
  (track for merge status)
