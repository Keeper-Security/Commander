# PAM Workflow Command Documentation

This document describes **PAM Workflow** support in Keeper Commander: access approval, optional check-in/check-out, multi-factor authentication, justification fields, time-bounded leases, and integration with `pam launch`, `pam tunnel start`, and `pam action rotate`.

> **Note**: Keeper Commander supports line continuation using backslash (`\`) at the end of lines. Do not put spaces after the backslash.

## Examples and placeholders

Throughout this document, replace placeholders with values from your vault:

| Placeholder | Meaning |
|-------------|---------|
| `<RECORD_UID>` | Base64-url record UID for the PAM resource |
| `<FLOW_UID>` | Workflow flow UID (from `pam workflow pending` or `pam workflow state`) |
| `<user@example.com>` | Keeper account email |

---

## 1. Overview — PAM Workflow (Access Approval + Time-Bounded Lease)

**What it is**

PAM Workflow is a **per-record policy** that can gate privileged access behind:

- One or more **approvals** (with optional escalation approvers)
- **Time windows** (allowed days, time-of-day ranges, timezone)
- **Multi-factor authentication** (2FA through the router workflow gate)
- **Reason** and/or **ticket** requirements
- **Check-in/check-out** when configured
- A **time-bounded lease** (`accessLength`) that limits how long an approved session remains valid

**Where it runs**

- Commander **17.2.16** and newer expects a **workflow-aware Keeper Router** so workflow configuration and state endpoints respond normally.
- Older routers **without** workflow REST endpoints are handled via **transport fallback** (see Section 3 and Section 11): the client does not hard-block `pam launch` / `pam tunnel start` solely because workflow reads failed.

**Scope**

Workflow applies to **PAM resources** managed through Commander (`pamMachine`, `pamDirectory`, `pamDatabase`, and Remote Browser Isolation flows where workflow is configured on the underlying PAM record types your tenant uses). Commander’s CLI surfaces workflow on commands that touch those records.

---

## 2. Prerequisites

### Enterprise enforcement booleans

Enterprise admins configure enforcement keys that Commander evaluates **before** workflow-specific logic on supported paths:

| Concept | Enforcement key (exact string) | Used by |
|---------|-------------------------------|---------|
| Launch / cloud connections | `allow_launch_pam_on_cloud_connection` | `pam launch` |
| Tunnels / port forwarding | `allow_launch_pam_tunnels` | `pam tunnel start` |
| Credential rotation | `allow_rotate_credentials` | `pam action rotate` |
| Workflow administration exemption | `allow_configure_workflow_settings` | Clients use this with record ACL to determine users who **manage** workflow settings (see `is_workflow_exempt` — users with edit access **and** this permission may bypass workflow for that record). |

**Strict-deny semantics when the key is missing**

When an **enterprise enforcement context** exists (non-empty `booleans` list on `params.enforcements`), keys such as `allow_launch_pam_on_cloud_connection`, `allow_launch_pam_tunnels`, and workflow-related checks follow web-vault parity: if the relevant boolean **is absent** from the list, access is treated as **denied** (missing key behaves like false). See `is_pam_action_allowed_by_enforcement` in `keepercommander/commands/workflow/helpers.py`.

Rotation uses dedicated logic in `_is_rotation_allowed_by_enforcement`: absent `allow_rotate_credentials` in an enterprise context → deny.

### PAM Configuration `allowedSettings`

Each PAM resource links to a **PAM Configuration** record whose DAG exposes `allowedSettings`. Commander maps DAG fields to JSON keys including:

| JSON key | Meaning |
|----------|---------|
| `connections` | Launch / connect allowed |
| `tunneling` | Tunnel / port-forward allowed (DAG may expose `portForwards`; CLI helper maps to `tunneling`) |
| `rotation` | Manual rotation allowed |
| Remote browser isolation | Where exposed on your configuration |

If `allowedSettings.<key>` is **explicitly false**, Commander blocks the matching action **before** workflow auto-checkout.

### Operational readiness

- **Gateway online** and reachable through the router for the resource’s configuration.
- Valid **session** (`keeper login` or equivalent).

---

## 3. Two-Gate Enforcement Model

**Gate 1 — Per-user enterprise enforcement**

Evaluated first on launch and tunnel paths via `is_pam_action_allowed_by_enforcement`:

- Launch: key `allow_launch_pam_on_cloud_connection`
- Tunnel: key `allow_launch_pam_tunnels`

If this gate denies, Commander prints an error and returns without contacting workflow services.

**Gate 2 — PAM Configuration `allowedSettings`**

Evaluated via `is_pam_config_action_allowed_for_record`:

- Launch: action key `'connections'`
- Tunnel: action key `'tunneling'`
- Rotation: `'rotation'` checked inside `record_rotate` using `PAMConfigurationListCommand._pam_config_allowed_settings_json`

Explicit `False` on the configuration denies the operation before workflow checkout.

**Transport fallback (workflow router compatibility)**

`WorkflowAccessValidator._read_workflow_config` (and related workflow state reads) catches transport failures and returns an internal sentinel so **`check_workflow_for_launch`** treats “workflow API unavailable” as **allow legacy path** — gateway remains authoritative. This avoids blocking production launches on routers that do not yet expose workflow endpoints.

**Rotation**

`pam action rotate` applies:

1. `_is_rotation_allowed_by_enforcement` → must find `allow_rotate_credentials: true`; missing key in enterprise context → deny.
2. PAM config → `allowed.get('rotation') is False` → deny with configuration-scoped message.

The legacy umbrella **`allow_pam_rotation` is not consulted** for the client gate; disabling rotation via `allow_rotate_credentials: false` is honored even if older umbrella defaults exist elsewhere.

---

## 4. Command Reference — `pam workflow *`

### 4.1 `pam workflow create`

**Purpose**: Create workflow configuration for a PAM record.

#### Command Syntax

```bash
pam workflow create <record> [OPTIONS]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `record` | Yes | — | Record UID or name to configure workflow for |
| `-n`, `--approvals-needed` | No | `1` | Number of approvals required |
| `-co`, `--checkout` | No | off | Enable single-user check-in/check-out mode |
| `-sa`, `--start-on-approval` | No | off | Start access timer when approved (vs when checked out) |
| `-rr`, `--require-reason` | No | off | Require user to provide reason for access |
| `-rt`, `--require-ticket` | No | off | Require user to provide ticket number |
| `-rm`, `--require-mfa` | No | off | Require MFA verification for access |
| `-d`, `--duration` | No | `1d` | Access duration (e.g., `"2h"`, `"30m"`, `"1d"`). Default: 1d |
| `--allowed-days` | No | — | Comma-separated allowed days (e.g., `"mon,tue,wed,thu,fri"`) |
| `--time-range` | No | — | Allowed time range in HH:MM-HH:MM format (e.g., `"09:00-17:00"`) |
| `--timezone` | No | — | Timezone for allowed times (e.g., `"America/New_York"`) |
| `-u`, `--approver` | Conditional | — | User email to add as an approver. Pass multiple times to add several. Required when `--approvals-needed > 0`. Duplicates are removed automatically. |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
# Two approvers, business hours only (replace placeholders)
pam workflow create <RECORD_UID> \
  --approvals-needed 2 \
  --approver alice.admin@example.com \
  --approver bob.manager@example.com \
  --require-reason \
  --duration 4h \
  --allowed-days mon,tue,wed,thu,fri \
  --time-range 09:00-17:00 \
  --timezone America/New_York
```

```bash
# Approvals disabled — checkout-only workflow
pam workflow create <RECORD_UID> --approvals-needed 0 --checkout --duration 2h
```

```bash
# JSON output for automation
pam workflow create <RECORD_UID> -n 1 -u approver@example.com --format json
```

#### Notes

- If workflow already exists, Commander raises **`Workflow already configured for "<title>" (<uid>).`** with hints to `pam workflow update`, `pam workflow read`, or delete-and-recreate.
- **`At least one --approver is required when --approvals-needed > 0.`** — the creator is **not** auto-added as an approver.
- If `--approvals-needed 0` but approvers are supplied, a **warning** is logged that approvers will never be required.
- Server failures after `create_workflow_config` may leave configuration without approvers; the command prints recovery **`pam workflow add-approver`** guidance.

---

### 4.2 `pam workflow read`

**Purpose**: Read and display workflow configuration.

#### Command Syntax

```bash
pam workflow read <record> [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `record` | Yes | — | Record UID or name |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow read <RECORD_UID>
pam workflow read <RECORD_UID> --format json
```

#### Notes

- When no workflow exists, table mode prints **`No workflow configured for this record`** and suggests **`pam workflow create <record>`**.
- JSON mode emits `{"status": "no_workflow", "message": "No workflow configured"}`.

---

### 4.3 `pam workflow update`

**Purpose**: Update existing workflow configuration. Only specified fields change.

#### Command Syntax

```bash
pam workflow update <record> [OPTIONS]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `record` | Yes | — | Record UID or name with workflow to update |
| `-n`, `--approvals-needed` | No | — | Number of approvals required |
| `-co`, `--checkout` | No | — | Enable/disable check-in/check-out (`true`/`false`) |
| `-sa`, `--start-on-approval` | No | — | Start timer on approval vs check-out (`true`/`false`) |
| `-rr`, `--require-reason` | No | — | Require reason (`true`/`false`) |
| `-rt`, `--require-ticket` | No | — | Require ticket (`true`/`false`) |
| `-rm`, `--require-mfa` | No | — | Require MFA (`true`/`false`) |
| `-d`, `--duration` | No | — | Access duration (e.g., `"2h"`, `"30m"`, `"1d"`) |
| `--allowed-days` | No | — | Comma-separated allowed days |
| `--time-range` | No | — | Allowed time range HH:MM-HH:MM |
| `--timezone` | No | — | Timezone for allowed times |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow update <RECORD_UID> --duration 8h --require-mfa true
pam workflow update <RECORD_UID> -n 2 --checkout false --format json
```

#### Notes

- **`No workflow found for record. Create one first with "pam workflow create"`** when nothing exists.
- **`No updates provided. Specify at least one option to update (e.g., --approvals-needed, --duration)`** if no updatable flags were passed.
- **`Approvals needed must be 0 or greater`** if `-n` is negative.

---

### 4.4 `pam workflow delete`

**Purpose**: Delete workflow configuration from a record.

#### Command Syntax

```bash
pam workflow delete <record> [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `record` | Yes | — | Record UID or name to remove workflow from |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow delete <RECORD_UID>
pam workflow delete <RECORD_UID> --format json
```

#### Notes

- Pre-check prevents confusing repeat deletes: **`No workflow configured for "<title>" (<uid>). Nothing to delete.`**

---

### 4.5 `pam workflow add-approver`

**Purpose**: Add approvers to a workflow.

#### Command Syntax

```bash
pam workflow add-approver <record> [OPTIONS]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `record` | Yes | — | Record UID or name |
| `-u`, `--user` | Conditional | — | User email to add as approver (can specify multiple times) |
| `-t`, `--team` | Conditional | — | Team name or UID to add as approver (can specify multiple times) |
| `-e`, `--escalation` | No | off | Mark as escalation approver |
| `-ea`, `--escalation-after` | No | — | Time before escalating (e.g., `"30m"`, `"1h"`). Only meaningful with `--escalation` |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow add-approver <RECORD_UID> --user alice.admin@example.com --user bob.manager@example.com
pam workflow add-approver <RECORD_UID> --team "Platform Ops" --escalation --escalation-after 1h
```

#### Notes

- **`Must specify at least one --user or --team`**
- **`--escalation-after requires --escalation flag`**
- Users and teams are **de-duplicated** (first-seen order preserved).

---

### 4.6 `pam workflow remove-approver`

**Purpose**: Remove approvers from a workflow.

#### Command Syntax

```bash
pam workflow remove-approver <record> [OPTIONS]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `record` | Yes | — | Record UID or name |
| `-u`, `--user` | Conditional | — | User email to remove as approver |
| `-t`, `--team` | Conditional | — | Team name or UID to remove as approver |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow remove-approver <RECORD_UID> --user former.approver@example.com
pam workflow remove-approver <RECORD_UID> --team abcTeamUidExample00001
```

#### Notes

- **`Must specify at least one --user or --team`**

---

### 4.7 `pam workflow request`

**Purpose**: Request access to a PAM resource, escalate, or cancel a pending request.

#### Command Syntax

```bash
pam workflow request <record> [OPTIONS]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `record` | Yes | — | Record UID or name |
| `-r`, `--reason` | No | — | Reason for access request |
| `-t`, `--ticket` | No | — | External ticket/reference number |
| `-e`, `--escalate` | No | off | Escalate a pending request to escalation approvers |
| `-c`, `--cancel` | No | off | Cancel a pending or active workflow request |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow request <RECORD_UID> --reason "INC123 investigation" --ticket INC123
pam workflow request <RECORD_UID> --escalate
pam workflow request <RECORD_UID> --cancel
```

#### Notes

- **`--cancel and --escalate cannot be used together`**
- **`--cancel cannot be used with --reason or --ticket`**
- **`No active workflow request found for this record.`** on cancel when nothing active.

---

### 4.8 `pam workflow start`

**Purpose**: Start a workflow (**check-out**). Accepts record UID/name or Flow UID.

#### Command Syntax

```bash
pam workflow start <uid> [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `uid` | Yes | — | Record UID, record name, or Flow UID |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow start <RECORD_UID>
pam workflow start <FLOW_UID>
```

#### Notes

- Invalid UID: **`"<uid>" is not a valid record UID/name or flow UID`**

---

### 4.9 `pam workflow end`

**Purpose**: End a workflow (**check-in**).

#### Command Syntax

```bash
pam workflow end <uid> [OPTIONS]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `uid` | Yes | — | Record UID, record name, or Flow UID |
| `-f`, `--force` | No | off | Force check-in: approvers can terminate another user’s active session when single-user checkout is enabled |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow end <RECORD_UID>
pam workflow end <FLOW_UID> --force
```

#### Notes

- Normal path without `--force`: **`No active workflow found for this record. The workflow may have already ended or never started.`**

---

### 4.10 `pam workflow state`

**Purpose**: Get workflow state for a record or flow.

#### Command Syntax

```bash
pam workflow state (--record <record> | --flow-uid <flow_uid>) [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `-r`, `--record` | One of group | — | Record UID or name |
| `-f`, `--flow-uid` | One of group | — | Flow UID of active workflow |
| `--format` | No | `table` | Output format: `table` or `json` |

Exactly one of `--record` or `--flow-uid` is required (mutually exclusive group).

#### Examples

```bash
pam workflow state --record <RECORD_UID>
pam workflow state --flow-uid <FLOW_UID> --format json
```

#### Notes

- **`Invalid flow UID: "<flow_uid>"`** when `--flow-uid` is malformed.

---

### 4.11 `pam workflow my-access`

**Purpose**: List all workflow states for the **current user**.

#### Command Syntax

```bash
pam workflow my-access [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow my-access
pam workflow my-access --format json
```

---

### 4.12 `pam workflow pending`

**Purpose**: List pending approval requests for the current approver session.

#### Command Syntax

```bash
pam workflow pending [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow pending
pam workflow pending --format json
```

#### Notes

- Duplicate flows from the router response are collapsed; flows already approved by the current user are filtered out.

---

### 4.13 `pam workflow approve`

**Purpose**: Approve a workflow access request.

#### Command Syntax

```bash
pam workflow approve <flow_uid> [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `flow_uid` | Yes | — | Flow UID of the workflow to approve |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow approve <FLOW_UID>
pam workflow approve <FLOW_UID> --format json
```

#### Notes

- **`Invalid flow UID: "<flow_uid>"`** when decoding fails.

---

### 4.14 `pam workflow deny`

**Purpose**: Deny a workflow access request.

#### Command Syntax

```bash
pam workflow deny <flow_uid> [-r REASON] [--format table|json]
```

#### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `flow_uid` | Yes | — | Flow UID of the workflow to deny |
| `-r`, `--reason` | No | — | Reason for denial |
| `--format` | No | `table` | Output format: `table` or `json` |

#### Examples

```bash
pam workflow deny <FLOW_UID> --reason "Does not meet change-window policy"
pam workflow deny <FLOW_UID>
```

#### Notes

- **`Invalid flow UID: "<flow_uid>"`** when decoding fails.

---

## 5. Time and Duration Encoding

### `--duration`

`WorkflowFormatter.parse_duration` accepts:

- Suffix forms: **`Nd`**, **`Nh`**, **`Nm`** where `N` is a positive integer (e.g., `"1d"`, `"2h"`, `"30m"`).
- A bare positive integer string → interpreted as **minutes**.

Invalid input raises:

```text
Invalid duration format: <value>. Use a positive value like "2h", "30m", or "1d"
```

### `--time-range`

Format **`HH:MM-HH:MM`**. Parsed into protobuf **`TimeOfDayRange`** with **`startTime` / `endTime` stored as HHMM integers** (for example `09:00` → `900`, `17:30` → `1730`), matching server validation (hours 0–23, minutes 0–59).

**Known formatting caveat (`pam workflow read`, table mode)**

The table renderer still uses **`divmod(value, 60)`** on `startTime`/`endTime` in `WorkflowReadCommand._print_table`. That arithmetic assumes **minutes-since-midnight**, not HHMM. Values remain correct on the wire and in JSON (`WorkflowFormatter.format_temporal_filter` uses HHMM-aware formatting). Operators should prefer **`--format json`** or interpret ranges via JSON export until the table path is aligned.

### `--allowed-days`

Comma-separated tokens; accepted aliases include short (`mon`) and long (`monday`) forms per `WorkflowFormatter.DAY_PARSE_MAP`. Unknown tokens raise **`Invalid day: "<token>". Valid: ...`**.

### `--timezone`

IANA name (for example **`America/New_York`**). Unknown zones fall back to local wall-clock for enforcement with debug logging.

### Enforcement at launch

`WorkflowAccessValidator._check_allowed_times` enforces configured **`allowedTimes`** during **`check_workflow_for_launch`** before approving interactive access.

---

## 6. `pam launch` Integration

**Program name**: `pam launch`

### Workflow-related flags

| Flag | Short | Default | Help text (summary) |
|------|-------|---------|---------------------|
| `--reason` | `-r` | — | Justification for workflow access when required |
| `--ticket` | `-tk` | — | External ticket/reference when required |
| `--auto-checkout` | `-aco` | off | Auto-confirm checkout when approved but not checked out |
| `--wait` | `-w` | off | Poll until approval or timeout |
| `--wait-timeout` | `-wt` | `600` | Max seconds to poll when `--wait` is set |

### Behavior

1. **Enterprise gate**: `allow_launch_pam_on_cloud_connection`.
2. **PAM config gate**: `connections` in `allowedSettings`.
3. **`check_workflow_for_launch`** orchestrates workflow states:
   - **`no_workflow` / `needs_start`**: inline **`prompt_for_reason_ticket`** when required; submits **`request_workflow_access`** via **`submit_access_request`** (matches web vault first-launch flow).
   - **`needs_action`**: same prompting when **`AC_REASON` / `AC_TICKET`** pending.
   - **`ready_to_start`**: interactive **`Workflow approved. Check out '<record_uid>' now? [Y/n]:`** unless **`--auto-checkout`**.
   - **`waiting`**: with **`--wait`**, polls every **8 seconds** until state changes or **`--wait-timeout`**; timeout prints **`Approval not received within <n>s.`**
4. **MFA**: When **`requireMFA`** and gateway online probe **`is_gateway_online_for_record` is `False`**, the MFA prompt is **skipped** (debug log); launch proceeds to gateway errors if applicable.
5. **Gateway resolution fallback**: If **`get_all_gateways`** misses the controller, Commander calls **`pam/get_configuration_controller`** (`configuration_controller_get`) so non-owner KSM visibility cases still resolve the gateway (matches web vault).
6. **Lease expiry**: A threading timer fires at **`expires_on_ms`** → **`shutdown_requested`**, ending the CLI session; after terminal reset the user sees **`Access expired — session terminated by workflow lease.`**
7. **Auto check-in**: On normal exit, if **`workflow_started_by_launch`** and lease did not expire, **`end_workflow`** is posted with **`ProtobufRefBuilder.workflow_ref`** — failures **`logging.debug("Auto check-in failed: ...")`** only (see Troubleshooting).
8. After **`WorkflowGate`** denies, **`pam launch`** returns **silently** (no redundant catch-all error), mirroring **`pam tunnel start`**.

---

## 7. `pam tunnel start` Integration

**Program name**: `pam tunnel start`

### Workflow-related flags

Same set as **`pam launch`**: **`--reason` / `-r`**, **`--ticket` / `-tk`**, **`--auto-checkout` / `-aco`**, **`--wait` / `-w`**, **`--wait-timeout` / `-wt`** (default **600**).

### Behavior

- Gates: **`allow_launch_pam_tunnels`** then **`tunneling`** in PAM config **`allowedSettings`**.
- **`check_workflow_for_launch`** identical orchestration path as launch (shared implementation).
- **Lease-expiry timer dedup**: **`_LEASE_EXPIRY_TIMERS_BY_RECORD`** — starting a tunnel cancels any prior timer for the same **`record_uid`** so duplicate **`Tunnel access lease expired`** messages do not stack.
- At expiry, Commander prints **`Tunnel access lease expired for <record_uid>. Server will refuse new auth requests; any in-flight SSH session will continue until you disconnect it.`** — reflects **soft-close** limits (Python cannot hard-kill existing forwarded channels).

### Known limitation — `pam tunnel stop` does not release workflow lease

Stopping the tunnel **does not** call **`end_workflow`**. The lease remains until server **`expiresOn`** or explicit:

```bash
pam workflow end <RECORD_UID>
```

---

## 8. `pam action rotate` Integration

**Program name**: `pam action rotate`

### Enforcement

1. **`_is_rotation_allowed_by_enforcement`** — requires explicit **`allow_rotate_credentials: true`** in enterprise **`booleans`**; absent → deny with **`Rotation is not allowed for this account by enterprise enforcement (allow_rotate_credentials).`**
2. **`PAMConfigurationListCommand._pam_config_allowed_settings_json`** → **`rotation`** must not be **`False`**; otherwise **`Rotation is disabled by the PAM Configuration [<config_uid>] for record [<record_uid>].`**

Legacy **`allow_pam_rotation`** fallback is **not** used in this client gate.

---

## 9. Approver Workflow (End-to-End Example)

Replace placeholders before running.

**1. Administrator creates workflow with two approvers**

```bash
pam workflow create <RECORD_UID> \
  --approvals-needed 2 \
  --approver alice.admin@example.com \
  --approver bob.manager@example.com \
  --require-reason \
  --require-ticket \
  --checkout \
  --duration 2h \
  --timezone UTC
```

Expected (table):

```text
Workflow created successfully

Record: Prod SSH Bastion (<RECORD_UID>)
Approvals needed: 2
Check-in/out: Yes
Duration: 2 hours
Requires reason: Yes
Requires ticket: Yes
Approvers: alice.admin@example.com, bob.manager@example.com
```

**2. Requester launches — prompted inline, blocked pending approval**

```bash
pam launch <RECORD_UID>
```

Typical intermediate messages:

```text
Workflow requires a justification.
...
Access request submitted.

Workflow access is pending: waiting for Approval Required.
Your request is being processed. Please wait for approval.
```

**3. Each approver reviews and approves**

Approver Alice:

```bash
pam workflow pending
pam workflow approve <FLOW_UID_FROM_PENDING_TABLE>
```

Approver Bob repeats **`pam workflow approve`** with the same **`FLOW_UID`** (until approvals satisfied).

**4. Requester retries with wait**

```bash
pam launch <RECORD_UID> --wait --wait-timeout 900 --auto-checkout
```

Typical:

```text
Waiting for approval... (timeout: 900s; press Ctrl+C to cancel)
Checked out.
Launching connection to Prod SSH Bastion...
```

**5. Session ends — auto check-in**

Exit the terminal session normally (Ctrl+C double-tap per CLI guidance). When **`pam launch`** performed checkout, **`end_workflow`** runs automatically unless lease expired first.

If checkout must be released manually:

```bash
pam workflow end <RECORD_UID>
```

---

## 10. Troubleshooting

| Symptom | Explanation / Next step |
|---------|-------------------------|
| **`Workflow already configured for "<title>" (<uid>).`** | Use **`pam workflow update`** or **`pam workflow delete`** then recreate. |
| **`At least one --approver is required when --approvals-needed > 0.`** | Pass **`-u`** for each approver or set **`--approvals-needed 0`**. |
| **`This record is protected by a workflow.`** / must **`pam workflow request`** | No active flow yet — **`pam launch`** may submit automatically when prompted; or run **`pam workflow request`** explicitly. |
| Launch succeeds but workflow reads previously failed | Transport fallback — router may lack workflow REST endpoints; verify router/gateway deployment supports workflow APIs if policy requires client-side enforcement. |
| **`Auto check-in failed`** | Only **`logging.debug`** today — check **`DEBUG`** logs or run **`pam workflow end <RECORD_UID>`**. |
| Tunnel stopped but lease active | Expected — run **`pam workflow end <RECORD_UID>`**. |
| **`Access expired — session terminated by workflow lease.`** | Lease **`expiresOn`** reached — **`pam launch`** hard-disconnect from CLI perspective. |
| **`Tunnel access lease expired...`** | Timer fired — server rejects new tunnel auth; disconnect existing SSH clients manually if needed. |
| **`Workflow access is outside the allowed time window.`** | Outside **`allowedTimes`** — retry inside policy window or update configuration. |
| **`PAM tunnels are not allowed... (allow_launch_pam_tunnels)`** | Enterprise enforcement — admin must grant tunnel entitlement. |
| **`pam launch aborted: ... allow_launch_pam_on_cloud_connection`** | Enterprise enforcement denies launch. |
| **`Rotation is not allowed... (allow_rotate_credentials)`** | Enterprise enforcement denies rotation. |

---

## 11. Backward Compatibility

| Commander version | Behavior |
|-------------------|----------|
| **17.2.15 and earlier** | No **`pam workflow *`** commands; **`pam launch`**, **`pam tunnel start`**, **`pam action rotate`** use legacy gates only where implemented. |
| Router **without** workflow REST API | Transport fallback → **`WorkflowAccessValidator`** allows legacy launch/tunnel path; gateway/server policy still applies. |
| **17.2.16** | Full workflow CLI surface shipped (merge **`2d911529`** — PR **#1997** squash — plus related release commits). |

---

## 12. Changelog — Commits in This Shipment

The **first 23** commits below were delivered as **PR #1997** (“Workflow pam launch compat”), squashed into upstream Commander at **`2d911529`** and released as **Commander 17.2.16**.

The **final two** rows (**`a19d6e88`**, **`79a709a5`**) were independent upstream fixes bundled into the same release for completeness.

| Commit | Area | Summary |
|--------|------|---------|
| `8f4aaa37` | Workflow gate | Allow on transport error so prod routers without workflow API don't hard-block legacy launch/tunnel |
| `b8dd42ea` | PAM launch | Drop redundant catch-all error after workflow gate, mirror tunnel |
| `3711e014` | Rotation enforcement | Drop legacy allow_pam_rotation fallback to honor allow_rotate_credentials:false |
| `43c2d83b` | Enforcement helpers | Strict-deny PAM enforcement helpers when key absent in enterprise context |
| `03e30176` | PAM workflow | Handle no_workflow / needs_start with inline prompt + initial request submission |
| `790eef62` | PAM workflow delete | Pre-check existing config and bail with clear message |
| `e3b17dc2` | PAM tunnel | Dedup lease-expiry timer per record, document soft-close limitation |
| `828a2257` | PAM launch | Fall back to pam/get_configuration_controller when get_controllers misses |
| `c0a7638e` | PAM workflow create | Pre-check existing config and fail with an actionable message |
| `f8d51dba` | PAM workflow create | Drop creator auto-add; require --approver when approvalsNeeded > 0 |
| `7a18ac69` | PAM workflow create | Skip auto-add of creator as approver when approvalsNeeded=0 |
| `3d238705` | PAM workflow | Encode TimeOfDayRange as HHMM (server format), not minutes-since-midnight |
| `44d2e3fd` | PAM launch / tunnel | Per-user enforcement gate before PAM-config gate |
| `9bacc795` | PAM launch / tunnel | Gate on PAM config allowedSettings before lease auto-checkout |
| `38c9d182` | PAM tunnel | Document that stop does not release the workflow lease |
| `1f408ed2` | PAM action rotate | Enforce the same two gates as the web vault |
| `98a68cca` | PAM workflow | Skip MFA prompt when gateway is offline |
| `7b0ca7d4` | PAM workflow | --wait polls for approval before launching |
| `fb9f08be` | PAM workflow | Auto check-in pam launch session when launch owns the checkout |
| `a72b6093` | PAM workflow | Prompt to check out when launch hits WS_READY_TO_START |
| `a3c859a8` | PAM workflow | Prompt for reason/ticket inline at launch instead of bailing |
| `5e484793` | PAM workflow | Hard-disconnect pam launch and pam tunnel at lease expiry |
| `6d21c6ae` | PAM workflow | Enforce allowedTimes window in launch gate |
| `a19d6e88` | pam project import / extend | Fix --sample-data + load enterprise data lazily (PR #1996) |
| `79a709a5` | Share folder | Fix ShareFolderCommand |

---

## 13. See Also

- [Keeper Documentation — PAM Overview](https://docs.keeper.io/privileged-access-manager)
- [Keeper Documentation — PAM Configuration](https://docs.keeper.io/privileged-access-manager)
- Commander **`--syntax-help`** on record commands — cross-reference **`RECORD_ADD_DOCUMENTATION.md`** for typed field syntax when editing PAM records.

---

## Appendix — Implementation references (for maintainers)

| Component | Module |
|-----------|--------|
| Workflow CLI — create/read/update/delete/approvers | `keepercommander/commands/workflow/config_commands.py` |
| Workflow CLI — request/start/end | `keepercommander/commands/workflow/requester_commands.py` |
| Workflow CLI — pending/approve/deny | `keepercommander/commands/workflow/approver_commands.py` |
| Workflow CLI — state/my-access | `keepercommander/commands/workflow/state_commands.py` |
| Formatters, resolver, enforcement helpers | `keepercommander/commands/workflow/helpers.py` |
| **`WorkflowAccessValidator`**, **`check_workflow_for_launch`**, MFA | `keepercommander/commands/workflow/mfa.py` |
| **`pam launch`** | `keepercommander/commands/pam_launch/launch.py` |
| **`pam tunnel start`** | `keepercommander/commands/tunnel_and_connections.py` |
| **`pam action rotate`** gates | `keepercommander/commands/discoveryrotation.py` |
