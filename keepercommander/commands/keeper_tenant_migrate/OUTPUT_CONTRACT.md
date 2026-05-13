# `keeper-tenant-migrate` output contract — v1.0

**Status:** v1.1 stable as of 2026-05-09 (additive: `manifest.csv.sha256`
sidecar added — see § Artifact 2 + Artifact 5; v1.0 consumers continue
to work without changes). **Authoritative for downstream consumers.**
**Audience:** anyone reading `keeper-tenant-migrate`-produced run-dirs.

This document is the **stable contract** between the migration tool's
output artifacts and any downstream tool that consumes them. The
output shapes documented here are settled and won't change within
v1.x.

> **Why this exists:** downstream consumers (declarative SDKs,
> SIEM ingestors, compliance dashboards, drift watchers) need a
> formal spec of what the migration tool writes so they can read it
> without coupling to internal implementation details. This doc is
> that spec.

---

## Versioning rules

| Rule | Detail |
|---|---|
| **Stable contract** | Every artifact below is **v1.x stable**. New optional fields may be added (additive); existing fields keep their names + types. |
| **Breaking changes** | Renaming a field, removing a field, changing a type, or changing the file format → **v2.0** of this document. Such a change is announced to downstream consumers **before** it ships. |
| **Detecting the version** | An optional `_contract_version` key may appear in `inventory.json` / `audit.log` event payloads; consumers should default to v1.0 if absent. |

---

## Run-dir layout

A `keeper-migrate` invocation produces a run-dir with this shape:

```
<run-dir>/
├── inventory.json                       # tenant structure snapshot
├── manifest.csv                         # source_uid → target_uid pairs (after records-import)
├── records_export/                      # one JSON per source record (underscore — see § naming below)
│   ├── <source_uid>.json
│   ├── <source_uid>.json
│   └── ...
├── audit.log                            # JSON-lines, hash-chained
├── SHA256SUMS.txt                       # sha256sum -c format, covers records_export/
├── verify-reports/                      # per-phase verify output (optional)
│   └── ...
├── reconcile-reports/                   # post-migration reconcile output (optional)
│   └── ...
└── checkpoints/                         # resumable-loop state (optional, internal)
    └── ...
```

All files written by keeperCMD use **mode 0600** for sensitive content (records_export/, audit.log when it carries hashes of plaintext) and **0644** for purely structural files (inventory.json, manifest.csv, SHA256SUMS.txt).

Not every run produces every file — the table below states which subcommand emits each artifact.

### Naming reconciliation (added 2026-05-10)

The records-export DIRECTORY is named **`records_export/` (underscore)** on disk, NOT `records-export/` (hyphen). Earlier versions of this doc consistently used the hyphen form (matching the SUBCOMMAND name `tenant-migrate records-export`). The underscore form is what `auto_migrate.py:866` actually writes — confirmed against rehearsal-16 fixture (1081 records).

Consumers (declarative SDKs, anonymize tooling, third-party readers) MUST accept the underscore form. They MAY accept the hyphen form for backwards compatibility with anyone who renamed via symlink. The OUTPUT_CONTRACT v1.x guarantee from this point forward is: **`records_export/` is canonical**; the hyphen form should be treated as a deprecated synonym.

Discovery shipped: 2026-05-09 D1 anonymization run on real rehearsal-16 fixture. Cross-product impact: all `records-export` references in this doc (now updated to `records_export`) and any hardcoded `records-export` paths in downstream consumers should be updated. Fix is additive — no breaking change to v1.x; consumers that already accept `records_export` continue working.

---

## Artifact 1 — `inventory.json`

**Emitted by:** `tenant-migrate plan`, `tenant-migrate live-inventory`
**Purpose:** structured snapshot of a tenant's nodes / teams / roles / shared folders / records / users at capture time.
**Format:** UTF-8 JSON, single object, `0644` perms.

### Schema (v1.0)

```json
{
  "schema_version": "1.0",
  "captured_at": "2026-05-08T18:30:00Z",
  "source_tenant": {
    "name": "<tenant display name>",
    "region": "EU|US|GOV|CA|AU|JP",
    "captured_by_user": "<email>"
  },
  "scope": {
    "node_path": "MIGRATION-TEST-NODE",
    "prefix": "MIGTEST-",
    "include_pam": true,
    "include_attachments": true
  },
  "entities": {
    "nodes": [
      {
        "uid": "<22-char base64url>",
        "name": "<node name>",
        "parent_uid": "<22-char base64url | null>",
        "isolated": false
      }
    ],
    "teams": [
      {
        "uid": "<22-char base64url>",
        "name": "<team name>",
        "node_uid": "<22-char base64url>",
        "users": ["<email>", ...],
        "shared_folders": ["<sf_uid>", ...]
      }
    ],
    "roles": [
      {
        "uid": "<22-char base64url>",
        "name": "<role name>",
        "node_uid": "<22-char base64url>",
        "users": ["<email>", ...],
        "teams": ["<team_uid>", ...],
        "enforcements": [
          {"key": "<enforcement-key>", "value": "<string|bool|long|file-ref>"}
        ],
        "managed_nodes": ["<node_uid>", ...],
        "privileges": ["MANAGE_USER", ...]
      }
    ],
    "shared_folders": [
      {
        "uid": "<22-char base64url>",
        "name": "<sf name>",
        "node_uid": "<22-char base64url>",
        "users": ["<email>", ...],
        "teams": ["<team_uid>", ...],
        "records": ["<record_uid>", ...],
        "default_manage_records": true,
        "default_manage_users": true,
        "default_can_edit": true,
        "default_can_share": true
      }
    ],
    "records": [
      {
        "uid": "<22-char base64url>",
        "title": "<record title>",
        "type": "login|encryptedNotes|pamMachine|pamDatabase|pamDirectory|pamUser|pamRemoteBrowser|...",
        "owner_email": "<email>",
        "shared_folder_uids": ["<sf_uid>", ...],
        "folder_path": "/<path>/<to>/<record>"
      }
    ],
    "users": [
      {
        "email": "<email>",
        "node_uid": "<22-char base64url>",
        "status": "active|locked|invited|disabled",
        "name": "<display name>"
      }
    ]
  },
  "counts": {
    "nodes": 4,
    "teams": 3,
    "roles": 5,
    "shared_folders": 47,
    "records": 1161,
    "users": 12
  }
}
```

### Stability notes (v1.0)

- **`uid` fields** are 22-char base64url-encoded — Commander's standard UID shape.
- **`folder_path`** uses `/` as separator. A literal `/` in a folder name is escaped as `//` (per [pitfall §12.5](../../projects-index/tests/commander-vault-cookbook/volumes/pitfalls.md#125--in-shared-folder-names--)).
- **`enforcements[].value`** is a string in JSON regardless of the enforcement-key's actual type (`bool`/`long`/`string`/`file-ref`); consumers cast based on the key.
- **PAM-typed records** carry their `pam_settings` envelope under `records[].pam_settings` when full record bodies are loaded; in `inventory.json` the bodies are summary-only (UID + title + type + ownership + folder).
- **Field absence vs `null`:** v1.0 omits keys whose value is null; consumers should treat a missing key as null. Future versions may emit explicit `null` — both forms are equivalent.

---

## Artifact 2 — `manifest.csv`

**Emitted by:** `tenant-migrate records-attachments` (after `records-import`); `tenant-migrate records-shares-extract` writes a sibling form.
**Purpose:** the **source-uid → target-uid map** keeperCMD builds by pairing record titles between the source export-dir and the target post-import session.
**Format:** RFC 4180 CSV, UTF-8, `0644`, header row required.

### Schema (v1.0)

```csv
source_uid,target_uid,title,type,status,timestamp
<22-char>,<22-char>,"<title>",<type>,paired,2026-05-08T18:30:00Z
<22-char>,<22-char>,"<title with, comma>",login,paired,2026-05-08T18:30:00Z
<22-char>,,"<title>",encryptedNotes,unpaired,2026-05-08T18:30:00Z
```

### Column reference

| Column | Type | Required | Notes |
|---|---|---|---|
| `source_uid` | str (22 char base64url) | yes | The source-tenant record UID. |
| `target_uid` | str (22 char base64url) | conditional | Empty when `status=unpaired`. |
| `title` | str | yes | Record title. CSV-quoted per RFC 4180 if it contains comma / quote / newline. |
| `type` | str | yes | Same enumeration as `inventory.json:records[].type`. |
| `status` | enum | yes | `paired` / `unpaired` / `ambiguous` / `skipped`. |
| `timestamp` | ISO8601 UTC | yes | When the row was pair-resolved. |

### Stability notes (v1.0)

- **Header row presence is the v1.0 marker.** A header-only file (no data rows) means "no records paired"; a file without the header row is malformed and should fail the consumer.
- **Empty `target_uid`** means the source record didn't pair on the target side (title collision, ambiguous match, or import failure). Downstream consumers should ignore unpaired rows for adoption.
- **`status=ambiguous`** rows occur when the same title appears multiple times on either side. keeperCMD does not silently resolve — the operator decides via `--allow-ambiguous` or manual disambiguation. Consumers should treat ambiguous rows as advisory.
- **CSV quoting** follows RFC 4180: fields containing comma / quote / newline are wrapped in `"..."` and embedded `"` is escaped as `""`.

### "Came from keeperCMD" detection (S1 / D7)

**The presence of `manifest.csv` in a run-dir is the authoritative signal that the records were migrated by keeperCMD.** Downstream consumers (declarative SDKs, audit ingestors, drift watchers, compliance tools) should check for `manifest.csv` in the run-dir; if present, apply the migrated-record adoption path (no pre-existing `keeper_declarative_manager` field expected). If absent, normal native-record adoption.

Edge cases for consumer-side handling: see § "How to consume safely (consumer-side patterns)" below.

### Integrity sidecar `manifest.csv.sha256` (v1.1+)

**Emitted by:** the same subcommand that writes `manifest.csv` (`records-attachments` / `records-shares-extract`), at write-time.
**Purpose:** detect manifest.csv tamper between keeperCMD finishing and a downstream consumer (declarative SDK import path, operator running `sha256sum -c`) starting. **Closes red-team Scenario 02** ("manifest.csv tamper between keeper-migrate and downstream import") structurally — the sidecar exists from the moment manifest.csv exists, not just after `verify` runs later.

**Format:** single line, `sha256sum -c` format, `0600` perms, basename relative:

```
<64-char hex digest>  manifest.csv
```

**Verification:**

```bash
cd <run-dir> && sha256sum -c manifest.csv.sha256
# OR equivalently in Python:
python3 -c "
import hashlib
with open('<run-dir>/manifest.csv','rb') as f: live=hashlib.sha256(f.read()).hexdigest()
with open('<run-dir>/manifest.csv.sha256') as f: stored=f.read().split()[0]
assert live == stored, 'manifest.csv tampered'
"
```

**Stability notes:**

- **v1.0 consumers continue to work** — the sidecar is purely additive. Consumers that don't check it remain correct (just less paranoid).
- **Recommended for v1.1+ consumers** — Downstream consumers should verify this sidecar before adopting any rows from `manifest.csv` (treat sidecar mismatch as hard fail, same as `AuditChainCorrupt`).
- **No collision with `<run-dir>/SHA256SUMS.txt`** generated later by `verify` — that's a multi-file manifest covering the whole run-dir; this is a single-file sidecar specific to manifest.csv.

---

## Artifact 3 — `records_export/<source_uid>.json`

**Emitted by:** `tenant-migrate records-export`
**Purpose:** full record body (title + fields + custom + notes + attachments-meta) for cross-tenant transfer.
**Format:** UTF-8 JSON per file, **`0600`** perms, one file per source record.
**Filename:** `<source_uid>.json` — the 22-char base64url UID followed by `.json`.

### Schema (v1.0)

```json
{
  "uid": "<22-char>",
  "title": "<title>",
  "type": "login|encryptedNotes|...",
  "version": <int>,
  "fields": [
    {"type": "login", "value": ["<email-or-username>"]},
    {"type": "password", "value": ["<password>"]},
    {"type": "url", "value": ["https://..."]}
  ],
  "custom": [
    {"type": "text", "label": "<label>", "value": ["..."]}
  ],
  "notes": "<plaintext notes>",
  "files": [
    {"name": "<filename>", "size": <bytes>, "type": "<mime>"}
  ]
}
```

### Stability notes (v1.0)

- **`fields[].value`** is always a list (Commander's record-v3 shape), even when only one value exists. Empty fields use `[]` not `[null]`.
- **`custom[]`** is the user-defined-field list. Order matches Commander's record-v3 ordering.
- **`files[]`** is metadata only; binary content lives alongside as `<source_uid>.<filename>` in the same dir.
- **PAM-record types** carry `pam_settings` (object) and may carry `connection` / `users` / `rotation_settings` sub-objects — the shape is the [`pam project import` JSON template](https://docs.keeper.io/en/keeperpam/commander-cli/command-reference/keeperpam-commands), inherited as-is from upstream Commander.
- **Plaintext on disk** — these files contain cleartext field values (passwords, SSH private keys, etc.) by necessity for cross-tenant migration. See [`SECURITY_MODEL.md`](SECURITY_MODEL.md) for the full rationale + 4-layer interlock.

---

## Artifact 4 — `audit.log`

**Emitted by:** every mutating subcommand (`structure`, `records-import`, `records-attachments`, `records-shares-apply`, `cleanup`, `decommission`, `transfer-user`, etc.)
**Purpose:** tamper-evident JSON-lines log of every operation; chained via `prev_hash`.
**Format:** JSON-lines (one JSON object per line), UTF-8, **`0600`** perms.
**Source-of-truth:** `keeper_tenant_migrate/audit.py` (`append_audit_event`, `verify_audit_log`).

### Per-line schema (v1.0)

```json
{
  "subcommand": "records-import",
  "inputs": {"source_dir": "<path>", "input_hash": "<sha256>"},
  "outputs": {"output_dir": "<path>", "output_hash": "<sha256>"},
  "summary": {"created": 1161, "skipped": 0, "errors": 0},
  "tenant": "<source-or-target-tenant-name>",
  "operator_email": "<email>",
  "timestamp": "2026-05-08T18:30:00Z",
  "prev_hash": "<sha256-of-previous-line | empty-for-first-line>",
  "signature": "<sha256 of the full event minus signature field>"
}
```

### Stability notes (v1.0)

- **One JSON object per line.** No multi-line JSON. Trailing newline mandatory.
- **`prev_hash` chain** — empty string on the first line; subsequent lines hash the entire prior line. Tampering with line N invalidates lines N..end. Verify with `verify_audit_log(path)` from `audit.py`.
- **`signature`** — sha256 of the event dict (sorted keys, signature field removed). Allows per-line integrity verification.
- **No plaintext field values** appear in audit.log — only hashes, counts, and structural identifiers. Safe for SIEM forwarding.
- **Idempotent re-runs** — re-running a subcommand produces a new event (different timestamp + signature), not an in-place edit. Append-only.

### Forensic reconstruction guarantee

Given a complete `audit.log`, you can reconstruct: which subcommand ran, when, by whom, against which inputs (by hash), with what result counts, in what order. This is what compliance teams typically need.

---

## Artifact 5 — `SHA256SUMS.txt`

**Emitted by:** `tenant-migrate records-export` (covering the `records_export/` dir).
**Purpose:** verify export integrity offline with standard `sha256sum -c`.
**Format:** standard `sha256sum` output — one line per file, UTF-8, `0644`.

```
<64-char hex>  records_export/<source_uid>.json
<64-char hex>  records_export/<source_uid>.json
...
```

### Verification

```bash
cd <run-dir>
sha256sum -c SHA256SUMS.txt
```

### Stability notes (v1.0)

- **Two-space separator** between hash and filename (the `sha256sum --check` standard).
- **Filenames are relative** to the run-dir — verification must be done from the run-dir as cwd.
- **Coverage scope** — v1.0 covers `records_export/` only. Future versions may add `inventory.json` and `manifest.csv` to the manifest; consumers should accept additional lines without erroring.

---

## How to consume safely (consumer-side patterns)

Recommended consumer pattern for `<consumer> import-from-run-dir <run-dir>`:

1. **Detect contract version** — read `inventory.json:schema_version`; default to `1.0` if absent. Reject contracts > known major.
2. **Verify integrity before reading** — run `sha256sum -c SHA256SUMS.txt` if records bodies will be parsed; run `verify_audit_log(audit.log)` for compliance handover.
3. **Consume `manifest.csv` first** — its presence is the migrated-record signal (S1 / D7). Build the source→target UID map in memory.
4. **Cross-reference `inventory.json`** — for each row in `manifest.csv`, look up the target_uid in `inventory.json:entities.records[]` to recover folder path + type + sharing context.
5. **Adopt records under the consumer's ownership marker** — apply `keeper_declarative_manager` marker to target-tenant records that match a paired manifest.csv row; skip ambiguous/unpaired rows with a warning.
6. **Optional record-body parse** — if the consumer is configured to absorb full record bodies (rather than just claim ownership), read `records_export/<source_uid>.json` for paired rows. Treat the contents as 0600-sensitive throughout.

### Anti-patterns (don't)

- **Don't parse `inventory.json` and `manifest.csv` independently and reconcile by title.** Title is not unique across roles; UID-pairing via `manifest.csv` is the only reliable bridge.
- **Don't cache the run-dir** between keeperCMD invocations. Each `keeper-migrate` run produces a fresh run-dir; consumers should re-read on every adoption.
- **Don't write back into the run-dir.** It's a frozen artifact of one operation; modification breaks the audit chain.

---

## Change-management protocol

When this contract needs to change:

1. joao proposes the change with rationale + impact analysis.
2. Downstream consumers are notified (via R6.1 cross-product change
   notification) and given a window to confirm whether they can
   absorb the change.
3. If the change is **additive**, it ships in the next migration-tool
   bugfix tag and this doc is bumped to v1.x+1 (no major bump).
4. If the change is **breaking**, this doc bumps to v2.0; consumers
   get a v1→v2 migration window before the migration tool ships the
   change.
5. Either way, the change lands with a `_contract_version` bump in
   the affected artifact.

> **Today's status:** v1.0 is the first formalised version. Earlier
> migration-tool releases shipped these formats too; v1.0 is where
> they were first written down. v1.1 added `manifest.csv.sha256`
> (additive).

---

## Proposed v1.2 — strict signed-output mode (design draft)

**Status**: design draft 2026-05-10. Signature backend choice pending
joao's decision (Ed25519 vs minisign vs ssh-keygen → see open Q1).

**Why proposed**: the 2026-05-09 red-team pentest flagged P0-8 — no external trust anchor for `SHA256SUMS.txt`. An attacker who replaces both `audit.log` and `SHA256SUMS.txt` consistently (with the new audit chain genesis-rooted) passes both internal-chain verify and SHA256SUMS verify. Without an external signature, there's no trust anchor.

**Why additive (v1.x not v2.0)**: per the v2 forward-compat policy below, additive bumps stay v1.x. The signed-output sidecar adds a new optional file; v1.0/v1.1 consumers continue to work unchanged (they don't read the sidecar). Strict mode is opt-in via a consumer-side `--require-output-signature` flag.

### Sidecar artifact

| File | When | Format | Mode |
|---|---|---|---|
| `SHA256SUMS.txt.minisig` | always emitted by keeperCMD v1.2+ when signing key configured; absent if no key | minisign signature output (binary or base64-armoured per minisign defaults) | 0o644 |

**Filename rationale**: `.minisig` (NOT generic `.sig`) — minisign's standard sidecar suffix per its docs. `.sig` is ambiguous (could be PGP, OpenSSL, etc.). `.minisig` is unambiguous: any operator running `file *.minisig` or `minisign -V` immediately knows the format.

### Backend

**v1.2 = minisign only.** Reasoning:
- Single binary, zero runtime deps, offline-friendly. Matches keeperCMD's no-network-during-migration constraint.
- Verification fits in ~50 LOC of Python. Small surface = easier to audit + smaller blast radius if backend itself has a CVE.
- sigstore brings transparency log + Fulcio identity binding, but requires network at verify time + adds OIDC dependency. Wrong shape for the air-gapped customer-migration scenario.

**v1.3 (future)**: sigstore as a SECOND backend, operator-selectable via `--signature-backend=sigstore`. Don't multi-backend at v1.2 — keep the surface small until v1.2 is operationally proven.

### What gets signed

`SHA256SUMS.txt` is the canonical signed payload. The minisig signs `SHA256SUMS.txt`'s bytes verbatim.

`SHA256SUMS.txt` MUST cover `inventory.json` in its manifest entries (in addition to the records-export contents it already covers). This is required because OUTPUT_CONTRACT spec §2 says consumers MUST inspect `_contract_version` (in `inventory.json`) before parsing artifact bodies — and that inspection must be cryptographically anchored. Without `inventory.json` in the signed manifest, `_contract_version` is forge-able (M3/M4 finding from pentest).

Coverage scope for v1.2 SHA256SUMS:
```
<hash>  inventory.json
<hash>  manifest.csv
<hash>  manifest.csv.sha256
<hash>  records_export/<source_uid>.json
<hash>  records_export/<source_uid>.json
...
```

### Public-key distribution

**Two-tier model**:

| Tier | Source | Use case |
|---|---|---|
| Primary | KSM record (e.g., `keeper-cmd-fixture-signing-pubkey`) | Operators with active Keeper session — uses existing auth, no new infra |
| Fallback | `--signature-pubkey FILE` flag | Air-gapped / offline contexts where Keeper isn't reachable |

**Public-key identifier**: minisign's native `untrusted comment` field carries a human-readable key ID (e.g., `keeperCMD-fixture-signer-2026-Q2`). Consumers should display this in verify output: `"Verified by: keeperCMD-fixture-signer-2026-Q2"`.

**Rotation**: each rotation = new key + new identifier + KSM record updated atomically. Existing fixtures signed by old key remain verifiable until purged (`--signature-pubkey-history FILE` flag for accepting historical keys). Rotation procedure in OPERATOR_PLAYBOOK.

### Verification ordering for `--require-output-signature` mode (consumer side)

```
1. Read SHA256SUMS.txt.minisig + SHA256SUMS.txt
2. minisign verify (using key from KSM or --signature-pubkey FILE)
   → fail-closed if signature invalid OR key not present in strict mode
3. Verify SHA256SUMS.txt covers inventory.json (must be in manifest)
   → fail-closed if not present (defends against partial-coverage attacks)
4. Compute fresh SHA256 of inventory.json → matches manifest entry
5. NOW parse inventory.json → check _contract_version
6. Continue with manifest.csv sidecar / records body / etc per v1.1
```

This makes `_contract_version` cryptographically anchored. Without inventory.json in the signed manifest, version is forge-able.

### Migration plan for existing v1.0/v1.1 fixtures

| Fixture status | v1.2 keeperCMD reads it? | Consumer strict-mode reads it? |
|---|---|---|
| v1.0 (no sidecar, no .minisig) | Yes — backwards compatible | NO (strict mode requires sig); operator must pass `--no-require-output-signature` to consume |
| v1.1 (manifest.csv.sha256 only, no .minisig) | Yes | Same as v1.0 |
| v1.2 (full signing) | Yes | Yes — strict-mode happy path |
| v1.2 with .minisig MISSING when backend says it should be present | Fail to verify; refuse to consume per fail-closed default | Fail-closed |
| v1.2 with .minisig invalid | Fail-closed | Fail-closed |

**Retroactive signing**: keeperCMD v1.2+ provides `keeper-migrate sign-existing-fixture <run-dir>` to regenerate `SHA256SUMS.txt.minisig` for an older fixture. Documents the historical key used + timestamp.

### keeperCMD-side implementation outline

| Phase | What | Where |
|---|---|---|
| Phase A | Add minisign-verify primitive to `audit.py` (matches `verify_audit_log`'s shape — `(ok, reason)` tuple) | `audit.py` |
| Phase B | Add `--signing-key` flag to `auto-migrate` and other write subcommands; sign at the end of `write_sha256sums` | `commands.py`, `audit.py:write_sha256sums` |
| Phase C | Add `keeper-migrate verify-signature <run-dir>` subcommand | `commands.py` |
| Phase D | Add `keeper-migrate sign-existing-fixture <run-dir>` subcommand for retroactive signing | `commands.py` |
| Phase E | Document in OPERATOR_PLAYBOOK + RUNBOOK; KSM record schema | docs |

**Ship gate**: Phase A + Phase B before v1.2 tag. C/D/E can land incrementally.

### Test gates before v1.2 ships

Per the v2 forward-compat policy §4 (which v1.2 also follows since
strict-mode introduces a new fail-closed path):

- [ ] All 4 cross-product invariants documented in `RUNBOOK.md`
      remain green under both strict-mode-on and strict-mode-off
- [ ] Downstream consumers have shipped v1.2-aware readers
- [ ] Round-trip integration test (migration tool writes signed
      run-dir → consumer reads strict-mode → 0 drift on plan) passes
      against synthetic AND real fixtures
- [ ] Pentest re-run against v1.2 runtime — confirm P0-8 closed
      structurally

### Rollback

If v1.2 ships and consumers break:
- Migration tool reverts default `--signing-key` to None (unsigned,
  falls back to v1.1 behaviour)
- v1.2 writer code stays in the migration tool (no code revert
  needed) — only the default changes
- Consumer-side strict-mode flag remains opt-in until v1.3

### Open design items (joao's call)

- [ ] Q1 signature backend — current proposal: minisign for v1.2;
      sigstore for v1.3
- [ ] Q2 sidecar filename — current proposal: `SHA256SUMS.txt.minisig`
- [ ] Q3 public-key channel — current proposal: KSM record +
      `--signature-pubkey FILE` fallback
- [ ] Q4 `inventory.json` in signed manifest — current proposal:
      YES (cryptographically anchor `_contract_version`)

When joao decides on the 4 open items, this section is promoted from
"design draft" to "v1.2 stable" + the doc header status line is
bumped + implementation PRs open.

---

## Forward-compat policy for v2 (when/if a breaking change is needed)

A breaking change to this contract is a high-blast-radius event for downstream consumers. The policy below codifies what keeperCMD commits to when shipping a v2.

### 1. Dual-publish window

When v2 ships, keeperCMD writes **both** v1.x and v2 artifacts for at least **two minor releases** (≈3 months at current cadence). Concretely:

| Phase | What keeperCMD writes | Consumer-side action |
|---|---|---|
| v2 + 0 (introduction) | v1.x (default) + v2 (opt-in via `--output-contract-version=2`) | Consumer adds v2 reader path; v1 reader stays primary |
| v2 + 1 (transition) | v1.x + v2 (both unconditionally) | Consumer switches primary path to v2; v1 reader becomes fallback |
| v2 + 2 (cutover) | v2 (default) + v1.x (opt-in via `--output-contract-version=1`) | Consumer drops v1 reader |
| v2 + 3 (sunset) | v2 only | v1 readers fail with clear error message |

Minimum 6 months elapse between introduction and sunset.

### 2. Consumer migration guarantees

While v1.x and v2 are both supported:

- A consumer reading a v1.x run-dir on v2-shipped keeperCMD MUST work unchanged (no silent drift).
- A consumer reading a v2 run-dir on v1-only consumer MUST fail loudly (with a clear "unsupported contract version" error), not silently mis-parse.
- The `_contract_version` field in `inventory.json` and audit.log events is the canonical version signal — consumers MUST inspect it before parsing artifact bodies.

### 3. Deprecation signaling in v1.x before v2 ships

For at least **one minor release** before v2:

- Affected v1.x fields get a `_deprecated: true` companion key (additive, doesn't break v1.0 readers).
- A `DEPRECATIONS.md` companion doc lists every soon-to-break field + replacement v2 field.
- Downstream-consumer notification fires per the existing Change-management protocol step 4.
- Optional: a `_deprecation_warning` event lands in audit.log on every run.

### 4. Test gates before v2 ships

A v2 ships only when:

- Cross-product invariants documented in `RUNBOOK.md` remain green
  under both v1.x and v2 readers.
- Downstream consumers have shipped v2-aware readers and confirmed.
- A round-trip integration test (migration tool writes v2 → consumer
  reads v2 → 0 drift on plan) passes against both the synthetic
  fixture and a real (anonymized) fixture.

### 5. Rollback path

If v2 ships and consumers surface a regression:

- Migration tool reverts the `--output-contract-version=2` default
  back to v1.x (one-line config flip).
- The v2 writer code stays in the migration tool (no code revert
  needed) — only the default changes.
- Notification fires within 1 hour of regression confirmation.
- v2 sunset clock is reset.

### 6. Schema versioning at field level

Each artifact carries its own `schema_version`. These are
**independent**:

- A change to `inventory.json` schema bumps
  `inventory.json::schema_version` only.
- An OUTPUT_CONTRACT v2 may include a mix of bumped + unchanged
  artifact schemas.
- Consumers should inspect both `_contract_version` (top-level) and
  `schema_version` (per-artifact) and refuse to parse if either
  exceeds their supported max.

### 7. Versioning discipline

A v2 transition is **owned cmd-side** by joao (writer side, this
doc, DEPRECATIONS.md). Downstream consumers own their reader side
on their own schedule, with notification per the change-management
protocol above. The matrix routing
(`MERGE_AND_CONTRIBUTION_DECISIONS.md`) classifies a v2 transition
as **behavior-breaking** → full SEC pattern applies.

---

## References

- [`SECURITY_MODEL.md`](SECURITY_MODEL.md) — why plaintext on disk is intrinsic to cross-tenant migration + the 4-layer interlock
- [`audit.py`](audit.py) — source of truth for `audit.log` format + `SHA256SUMS.txt` generation
- [`manifest.py`](manifest.py) — source of truth for `manifest.csv` schema
- [`inventory.py`](inventory.py) — source of truth for `inventory.json` schema
