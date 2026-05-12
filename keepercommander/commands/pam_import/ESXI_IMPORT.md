# `pam project esxi-import` — Operator Guide

Discover a VMware ESXi host and import its inventory (host + VMs + local users) as Keeper PAM records: pamMachine for the host & each VM, pamUser per local non-system user, and pamRemoteBrowser records for WebUI access. Mirrors the `pam project kcm-import` design (one command does discover + plan + apply).

## Prerequisites

| | |
|---|---|
| Keeper PAM Configuration (record_type `pamNetworkConfiguration`) | Required. Pass UID as `--pam-config-uid`. Has a working gateway. |
| Gateway online | The pamConfig's `controllerUid` must be set + gateway container running. |
| `pyvmomi` Python library | Required for SOAP discovery. `pip install pyvmomi` (or `pip install keepercommander[esxi]`). |
| ESXi credentials | Need read access to host inventory + permissions. SSH not required for import (only for later rotation). |
| Network reach | Operator workstation can reach ESXi on TCP 443. |

## Quick start

```
# Show what would happen, no vault changes
pam project esxi-import \
  --host esxi-01.example.com --user root --password-env ESXI_PWD \
  --pam-config-uid <pamConfig-UID> \
  --dry-run

# Apply
ESXI_PWD='...' pam project esxi-import \
  --host esxi-01.example.com --user root --password-env ESXI_PWD \
  --pam-config-uid <pamConfig-UID> \
  --auto-folder "ESXi - esxi-01" \
  --target "ops:esxi-01" \
  --yes
```

## What the command does, in order

1. **Discover** the ESXi host via pyvmomi (SOAP/443). Reads host info, local users, roles, per-VM permissions, VM inventory.
2. **Plan**: emits one row per record we'll create (host pamMachine + N VM pamMachines + M pamUsers + per-user pamRemoteBrowsers).
3. **Apply** (with `--yes` and without `--dry-run`):
   - Create records via `record-add`
   - Populate trafficEncryptionSeed via in-process update (Launch-button gate)
   - Wire DAG: `link_resource_to_config` + `set_resource_allowed` to the pamConfig
   - Link primary pamUser per resource (DAG edge controls Launch-default credential)
   - Move records into per-user folders (if `--folder-from user`)
   - Share records with the right Keeper recipients (per ESXi roles)
   - Post-create: write labeled custom fields (Service Tag, Hardware, CPU, RAM, Guest OS, etc.) so Web Vault shows each piece with a human-readable label
4. **Report**: PROJECT ASSETS / IMPORT RESULTS / RECORD BREAKDOWN / WARNINGS / WHAT-TO-DO-NEXT.

## Operator option matrix

| Flag | Values | Default | Controls |
|---|---|---|---|
| `--host` | `<fqdn or ip>` | required | ESXi management interface |
| `--user` | `<esxi user>` | required | Read-capable user (root works; non-admin may miss some metadata) |
| `--password-env` | `<env var>` | required | Env var holding the password (never accept password on argv) |
| `--pam-config-uid` | `<UID>` | required | Linked pamNetworkConfiguration with working gateway |
| `--host-record-type` | `pamMachine` / `pamRemoteBrowser` / `both` | `pamMachine` | Whether host gets SSH pamMachine, a generic WebUI RBI, or both |
| `--vm-record-type` | `vm1=pamDatabase,vm2=pamDirectory` | (auto) | Per-VM override (default routes via `PROTOCOL_TYPE_MAP`) |
| `--share-scope` | `permissions` / `all` | `permissions` | Who can SEE each VM — permission-based or broadcast |
| `--minimum-role` | `admin` / `vm-user` / `readonly` | `vm-user` | ESXi role threshold to appear in shares |
| `--include-host-share` | `always` / `by-permissions` / `never` | `by-permissions` | Host-record share scope |
| `--vm-primary-user` | `dominant-permission` / `broadcast` / `none` | `dominant-permission` | Whose creds AUTOFILL at Launch |
| `--folder-from` | `none` / `user` / `role` | `none` | Folder organisation (per-user / per-role) |
| `--rbi-mode` | `none` / `per-host` / `per-user` | `none` | Whether to emit per-user pamRemoteBrowser records |
| `--user-map` | `alice=alice@example.com,...` | none | Explicit ESXi-principal → Keeper-email mapping |
| `--user-domain` | `example.com` | none | Global email suffix when --user-map doesn't cover a principal |
| `--target` | `<audit-tag>` | none | Stamps record notes for rollback verification |
| `--auto-folder` | `<name>` | none | Create + use a fresh folder hierarchy for this run |
| `--dry-run` | flag | false | Show the plan, no vault changes |
| `--yes` | flag | false | Skip interactive confirmation |

## Rollback

```
# Roll back a previous run
pam project esxi-import --rollback \
  --state-file ~/.cache/commander/pam_import/esxi-01.example.com.state.json \
  --audit-tag "ops:esxi-01" \
  --yes
```

`--audit-tag` is REQUIRED (operator-typed, defends against tampered state.json nuking arbitrary records). If you didn't pass `--target` on the original run, pass `--rollback-skip-audit-check` to accept the risk.

Rollback removes:
- Records via `keeper rm`
- Operator-side per-user folders (if `--folder-from user` was used)

Rollback does NOT unwind DAG edges (Commander has no `unlink_resource_from_config`); orphaned edges are harmless but persist.

## WHAT TO DO NEXT (printed at end of every run)

1. **Verify the gateway is online** in Web Vault: PAM Configurations → click the linked pamConfig. Badge must be green.
2. **Resolve placeholder hostnames** — VMs with no IP at discovery (powered-off / no tools) got `<UPDATE-IP-FOR-name>` placeholders. Update manually OR power on + re-import.
3. **Add credentials for pamUsers** — passwords are EMPTY by design (ESXi doesn't expose stored hashes). Either add manually or run rotation to generate fresh.
4. **Wire unresolved principals** — re-run with `--user-map principal=email` if any ESXi principals had no Keeper email mapping.
5. **Enable SSH for rotation** — ESXi SSH should be DISABLED in production; enable on-demand for rotation only.
6. **Test a Launch** — click any VM record's Launch button. Should autofill with the dominant-permission pamUser's credentials.
7. **Clean up** — `pam project esxi-import --rollback --state-file ... --audit-tag ...`.

## Notes

- **Empty pamUser passwords are intentional**. ESXi doesn't expose stored hashes; rotation generates fresh ones at first run.
- **Powered-off VMs** get a `<UPDATE-IP-FOR-...>` placeholder. The record is still created with full metadata; operator updates `pamHostname.hostName` post-import or re-runs after power-on.
- **`--share-scope all` is opt-in**. Default is `permissions` (each user sees only the VMs they have ESXi roles on).
- **`--vm-primary-user dominant-permission`** picks the highest-role user per VM as the Launch-default credential. Other users sharing the VM still have access via record-share; they just have to switch credential at Launch time.
- **Custom labeled fields** (Service Tag, Hardware, etc.) are written via in-process `record_management.update_record` AFTER record creation — they don't go through `record-add` argv (where they'd be ps-visible system-wide for the lifetime of the subprocess).
