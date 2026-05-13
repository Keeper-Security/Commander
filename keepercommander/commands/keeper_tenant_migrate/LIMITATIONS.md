# Limitations

What the plugin intentionally does NOT do — and how to work around each.

---

## 1. No dual-session authentication

Commander holds one session at a time. The plugin runs in whichever
shell you launched; each shell authenticates separately via `keeper
login`. Cross-tenant coordination happens through the shared run-dir,
not a single in-process dual session.

**Workaround**: use two shells + a shared `--run-dir PATH`, or script
the chain with `keeper --config SRC` and `keeper --config TGT`
invocations.

---

## 2. Secret re-keying at the tenant level

A migrated record is re-encrypted under the destination tenant's
keys when Commander imports it. The plugin doesn't touch this — it
relies on Commander's `import`. Side effects:

- **Audit logs on source can't be decrypted on target.**
- **Enterprise-level log streaming (SIEM)** is tenant-scoped; rotate
  target endpoints before migration so events land in the right
  bucket. Use `audit-export` to replay the plugin's own audit.log if
  needed.

---

## 3. PAM rotation, gateways, agents

Rotation schedules, gateway registrations, and PAM agent tokens are
tenant-scoped and don't transfer. The plugin's `pam_detection`
module flags every PAM-related record so the admin gets a manual
re-configuration checklist in `manual-actions`, but the re-setup
itself (gateway install, agent token, bastion pairing) is
out of scope.

---

## 4. SSO / SCIM IdP reconfiguration

SAML ACS URLs and SCIM bearer tokens are tenant-scoped. The plugin
emits a prerequisite checklist per SSO provider telling the admin to
repoint their IdP (Azure AD / Okta / Ping) at the new tenant BEFORE
the `users` phase runs. We don't attempt to call the IdP's admin API —
every IdP is different and customers need to stay in the loop.

---

## 5. transfer-user Path B is partial

`transfer-user` relies on `REQUIRE_ACCOUNT_SHARE` being accepted by
each source user. Users who haven't accepted land in CATEGORY_E
(pending invite) and transfers for them silently skip. The
`readiness-report` column `migration_path` classifies each user; the
plugin refuses to transfer non-READY rows unless `--force` is set
(which isn't currently implemented — intentionally).

---

## 6. Arbitrary-point rollback can't unwind delete-class events

`undo` reverses:
- user invites (lock / delete)
- structure creates (nodes / teams / roles / SFs by name or UID)
- record-shares grants (revoke)
- record-attachments uploads (by file name — with caveat below)

It CANNOT reverse:
- `cleanup` / `decommission` (entities already gone; restore from
  the pre-delete SHA256SUMS backup dir instead)
- `records-import` (deleting imported records can't be distinguished
  from deleting target-native records — emits a MANUAL plan)
- attachment uploads by file name alone (Commander needs the
  fileRef UID; undo emits a warning and skips — delete manually)

---

## 7. Cross-region compliance is informational

`compliance.evaluate(source, target, override=False)` returns
ALLOW / WARN / BLOCKED / OVERRIDE based on the run-spec's
`data_residency` pin and `compliance_tags` union. It flags violations;
it does NOT enforce them at the infrastructure level. A BLOCKED
verdict requires an explicit `--override` to proceed, and that
override is recorded in the audit log — but the plugin assumes the
admin has independent authority to make that call.

---

## 8. Scale ceilings (not hard limits, just untested)

- Tested with up to ~1,400 records + ~20 users.
- `plan` / `records-export` are bulk-API calls subject to Commander's
  native throttling — runs beyond ~50,000 records may need manual
  splitting by `--prefix` or `--node`.
- `--batch-size` knob is static; exponential backoff on HTTP 429 is
  deferred to v1.1.1.

---

## 9. Not supported end-to-end

- **Folder-level shares BETWEEN source users** that don't include the
  admin — the admin has no way to see those records unless the source
  user grants access. Takes a `SHARE_FOLDER` prerequisite from each
  user. Surfaced as a PREREQUISITE item in `manual-actions`.
- **Personal-Keeper → Enterprise transfers** (Category B) — user
  accepts in-browser.
- **Cross-enterprise conflict release** (Category C) — contact Keeper
  Support.

---

## 10. Audit chain can be broken by manual editing

`audit.log` is append-only and signed per-line. Editing it invalidates
the chain; `audit-verify` reports the first broken line. We don't
seal the log against motivated tampering with admin access —
the chain is a tamper-evident mechanism, not a tamper-proof one.
