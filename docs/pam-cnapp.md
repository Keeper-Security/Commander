# `pam cnapp` — Manage CNAPP Integrations

The `pam cnapp` command group connects Keeper PAM to a Cloud-Native Application Protection Platform (CNAPP) provider. It lets you configure the provider connection, pull the queue of security issues the provider has flagged, associate vault records with those issues, and dispatch remediation actions to a PAM Gateway.

All commands run against a **network** (identified by a network record UID) and talk to the Keeper Router (krouter), which brokers the request to the provider and, where relevant, to the Gateway.

- **Command root:** `pam cnapp`
- **Aliases:** `pam cnapp config` → `c`, `pam cnapp queue` → `q`
- **Default sub-command:** running `pam cnapp` with no verb defaults to `pam cnapp queue`, which in turn defaults to `pam cnapp queue list`.
- **Supported providers:** `wiz`

---

## Table of Contents

1. [Concepts](#concepts)
2. [Command Tree](#command-tree)
3. [Configuration Commands](#configuration-commands)
   - [`config set`](#config-set)
   - [`config test`](#config-test)
   - [`config test-encrypter`](#config-test-encrypter)
   - [`config read`](#config-read)
   - [`config delete`](#config-delete)
4. [Queue Commands](#queue-commands)
   - [`queue list`](#queue-list)
   - [`queue associate`](#queue-associate)
   - [`queue remediate`](#queue-remediate)
   - [`queue set-status`](#queue-set-status)
   - [`queue delete`](#queue-delete)
5. [Issue Status Values](#issue-status-values)
6. [Payload Decryption](#payload-decryption)
7. [Examples](#examples)

---

## Concepts

**Network** — A PAM network record. Every `pam cnapp` command targets a single network via its UID (base64url). The network holds the CNAPP configuration and owns the queue of issues.

**Provider** — The CNAPP vendor Keeper integrates with. The provider keyword is case-insensitive (`wiz` or `WIZ`). Currently only **Wiz** is supported.

**Configuration** — The stored connection details for a provider on a network: client ID, client secret, API endpoint, OAuth2 auth endpoint, and a reference to an *Encrypter* record. Configuration is validated against the provider before being persisted.

**Encrypter** — A customer-deployed service that encrypts issue payloads before they are stored in Keeper. Its base URL and AES-256 key live in a vault record referenced by the configuration (`--config-record`). Commander uses that key locally to decrypt payloads when listing the queue.

**Queue** — The list of security issues the provider has pushed for a network. Each item carries a status, timestamps, an (encrypted) payload describing the issue, and optionally an associated vault record.

**Gateway** — The PAM Gateway (controller) that executes remediation actions such as credential rotation.

---

## Command Tree

```
pam cnapp
├── config (c)
│   ├── set              Create or update the provider configuration
│   ├── test             Validate credentials without saving
│   ├── test-encrypter   Health-check the customer Encrypter
│   ├── read             Read the persisted configuration
│   └── delete           Delete the configuration
└── queue (q)
    ├── list (l)         List queued issues
    ├── associate (a)    Attach a vault record to a queue item
    ├── remediate (r)    Trigger a remediation action via the Gateway
    ├── set-status (s)   Update an issue's status
    └── delete (d)       Delete a queue item
```

---

## Configuration Commands

Configuration commands live under `pam cnapp config` (alias `c`).

### `config set`

Create or update the CNAPP provider configuration on a network. The credentials are validated against the provider before being persisted.

```
pam cnapp config set --network-uid <UID> --provider wiz --client-id <ID> \
  --api-endpoint <URL> --auth-endpoint <URL> --config-record <UID> \
  [--client-secret <SECRET>]
```

| Flag | Required | Description |
|---|---|---|
| `--network-uid`, `-n` | Yes | Network record UID (base64url). |
| `--provider`, `-p` | Yes | Provider keyword: `wiz` (case-insensitive). |
| `--client-id` | Yes | Provider API client ID / app ID. |
| `--client-secret` | No | Provider API client secret. **Omit to keep the existing stored secret** when editing an existing configuration. |
| `--api-endpoint` | Yes | Provider API endpoint URL (e.g. `https://api.us1.app.wiz.io/graphql`). |
| `--auth-endpoint` | Yes | Provider OAuth2 token endpoint URL (e.g. `https://auth.app.wiz.io/oauth/token`). Lets you point at your own tenant/region. |
| `--config-record` | Yes | UID of the vault record holding the Encrypter URL and encryption key. |

On success the saved configuration is printed. The `--auth-endpoint` allows customers to target their own tenant or region (for example, an EU vs. US Wiz auth host) without a code change.

### `config test`

Validate provider credentials by probing the provider **without persisting anything**. Useful for verifying credentials before running `config set`.

```
pam cnapp config test --network-uid <UID> --provider wiz --client-id <ID> \
  --client-secret <SECRET> --api-endpoint <URL> --auth-endpoint <URL>
```

| Flag | Required | Description |
|---|---|---|
| `--network-uid`, `-n` | Yes | Network record UID (base64url). |
| `--provider`, `-p` | Yes | Provider keyword: `wiz`. |
| `--client-id` | Yes | Provider API client ID. |
| `--client-secret` | Yes | Provider API client secret. |
| `--api-endpoint` | Yes | Provider API endpoint URL. |
| `--auth-endpoint` | Yes | Provider OAuth2 token endpoint URL. |

Prints `CNAPP credentials validated successfully.` on success; fails with the provider's reason when credentials are rejected.

### `config test-encrypter`

Health-check the customer-deployed Encrypter. Keeper Router probes `<url>/health`.

```
pam cnapp config test-encrypter --url <BASE_URL>
```

| Flag | Required | Description |
|---|---|---|
| `--url`, `-u` | Yes | Base URL of the Encrypter. `/health` is appended automatically. |

Use this before `config set` to confirm the Encrypter referenced by your configuration is reachable. Prints `Encrypter is reachable.` on success.

### `config read`

Read the persisted CNAPP configuration for a network. Note: the client secret is **never** returned by the server — only the endpoints, client ID, and Encrypter record UID.

```
pam cnapp config read --network-uid <UID> --provider wiz [--format table|json]
```

| Flag | Required | Description |
|---|---|---|
| `--network-uid`, `-n` | Yes | Network record UID (base64url). |
| `--provider`, `-p` | Yes | Provider keyword: `wiz`. |
| `--format` | No | Output format: `table` (default) or `json`. |

### `config delete`

Remove the CNAPP configuration from a network.

```
pam cnapp config delete --network-uid <UID>
```

| Flag | Required | Description |
|---|---|---|
| `--network-uid`, `-n` | Yes | Network record UID (base64url). |

Fails if no configuration currently exists on the network.

---

## Queue Commands

Queue commands live under `pam cnapp queue` (alias `q`).

### `queue list`

List queued CNAPP issues for a network. By default Commander attempts to decrypt each item's payload locally using the Encrypter key so it can show a human-readable issue summary (see [Payload Decryption](#payload-decryption)).

```
pam cnapp queue list --network-uid <UID> [--status <STATUS>] [--provider wiz] \
  [--config-record <UID>] [--no-decrypt] [--format table|json]
```

| Flag | Required | Description |
|---|---|---|
| `--network-uid`, `-n` | Yes | Network record UID (base64url). |
| `--status`, `-s` | No | Filter by status name or id. Default: all statuses. See [Issue Status Values](#issue-status-values). |
| `--provider`, `-p` | No | Provider keyword used for the config lookup. Default: `wiz`. |
| `--config-record` | No | Explicit Encrypter vault record UID. Overrides the automatic lookup done via `config read`. |
| `--no-decrypt` | No | Skip payload decryption and show only the encrypted envelope's metadata. |
| `--format` | No | Output format: `table` (default) or `json`. |

The table output includes: Queue ID, Provider, Status, Received (UTC), Resolved (UTC), associated Record UID, Control Hash, and an Issue summary (severity · control/issue · resource). The control hash identifies the provider control that flagged the issue and is what auto-remediation rules are keyed on (see `queue remediate --auto-remediate`); it is also exposed as `controlHash` in `--format json` output.

**Notes:**
- If no Encrypter key can be resolved, payloads are shown as `<encrypted>` and a warning is printed. Pass `--config-record <UID>` or ensure `config read` succeeds.
- CLI paging is not yet available. If more items exist than were returned (`hasMore`), resolve or delete returned items to surface the rest.

### `queue associate`

Attach a vault record to a queue item. Association is **required before remediation** so the Gateway knows which credential to act on.

```
pam cnapp queue associate --queue-id <ID> --record-uid <UID>
```

| Flag | Required | Description |
|---|---|---|
| `--queue-id`, `-q` | Yes | Queue item ID (from `queue list`). |
| `--record-uid`, `-r` | Yes | Vault record UID to associate (base64url). |

### `queue remediate`

Dispatch a remediation action to the Gateway for a queued issue.

```
pam cnapp queue remediate --queue-id <ID> --action <ACTION> [options]
```

| Flag | Required | Description |
|---|---|---|
| `--queue-id`, `-q` | Yes | Queue item ID. |
| `--action`, `-a` | Yes | Remediation action. See table below. |
| `--resource-ref` | No | Resource reference UID for the action. |
| `--pwd-complexity` | No | Password complexity JSON (for `rotate_credentials`). |
| `--controller-uid` | No | Override the Gateway UID. |
| `--message-uid` | No | Client-generated conversation UID for streaming responses. |
| `--group` | No | Group to remove the user from (`remove_standing_privilege` only). Repeatable. |
| `--role` | No | Role to remove the user from (`remove_standing_privilege` only). Repeatable. |
| `--network-uid`, `-n` | No | PAM configuration (network) record UID whose record key encrypts the `--group`/`--role` values. Required when `--group`/`--role` is given. |
| `--auto-remediate` | No | Register an auto-remediation rule for this item's control hash before rotating (`rotate_credentials` only; the queue item must carry a control hash — see the Control Hash column in `queue list`). |

**Action types:**

| Action | Description |
|---|---|
| `rotate_credentials` | Rotate the credential associated with the issue. Supports `--auto-remediate` to also register an auto-remediation rule so future issues with the same control hash rotate automatically. |
| `manage_access` | Manage access to the flagged resource. Frontend-only — rejected by Keeper Router. |
| `jit_access` | Grant just-in-time access. Frontend-only — rejected by Keeper Router. |
| `remove_standing_privilege` | Remove the user's standing privilege. Target groups/roles are supplied with `--group`/`--role` and encrypted client-side with the PAM configuration record key — Keeper Router never sees them in the clear. When omitted, the Gateway resolves the targets from the resource record's JIT settings. |

> **Note:** Keeper Router dispatches `rotate_credentials` and `remove_standing_privilege`; `manage_access` and `jit_access` return an error. On success the command prints the dispatched action, resulting status, and any result message.

### `queue set-status`

Update the local status of a queue item. Keeper Router notifies the provider on a best-effort basis.

```
pam cnapp queue set-status --queue-id <ID> --status <STATUS> [--reason <TEXT>]
```

| Flag | Required | Description |
|---|---|---|
| `--queue-id`, `-q` | Yes | Queue item ID. |
| `--status`, `-s` | Yes | New status name or numeric id. `0`/`all` is not allowed here — a specific status is required. |
| `--reason` | No | Free-form reason, forwarded to the provider notification. |

### `queue delete`

Delete a queue item entirely.

```
pam cnapp queue delete --queue-id <ID>
```

| Flag | Required | Description |
|---|---|---|
| `--queue-id`, `-q` | Yes | Queue item ID to delete. |

Fails if the queue ID is unknown.

---

## Issue Status Values

Status flags (`--status`) accept either the case-insensitive name or the numeric id:

| Name | ID |
|---|---|
| `pending` | 1 |
| `in_progress` | 2 |
| `resolved` | 3 |
| `failed` | 4 |
| `cancelled` | 5 |

For `queue list`, a status of `0` (or an empty value) means **all statuses** — this is the default. For `queue set-status`, `0`/all is rejected; you must supply a specific status.

---

## Payload Decryption

Each queue item's payload (the issue detail) is stored encrypted. Commander decrypts it locally so it can show a readable summary, using this flow:

1. The AES-256-GCM key is taken from the **Encrypter record** — either the one you pass via `--config-record`, or the `cnappConfigRecordUid` resolved automatically from `config read`.
2. The key is read from the Encrypter vault record's `Encryption Key` field (a `secret` or `note` typed field). Keys are expected to be 32 bytes, base64 or base64url-encoded (e.g. the output of `openssl rand -base64 32`).
3. The encrypted payload is unwrapped (`AES-256-GCM`, nonce + ciphertext + tag) and parsed as JSON.

If the key can't be resolved or a payload fails to decrypt, the item is still listed but its Issue column shows `<encrypted>` (with a warning). Use `--no-decrypt` to skip decryption entirely and show only metadata.

---

## Examples

### Validate credentials, then save the configuration

```bash
# 1. Confirm the Encrypter is reachable
pam cnapp config test-encrypter --url https://encrypter.internal.example.com

# 2. Validate provider credentials without saving
pam cnapp config test \
  --network-uid nB2c3D4e5F6g7H8i9J0kLm \
  --provider wiz \
  --client-id my-wiz-client-id \
  --client-secret "MyWizClientSecret" \
  --api-endpoint https://api.us1.app.wiz.io/graphql \
  --auth-endpoint https://auth.app.wiz.io/oauth/token

# 3. Persist the configuration
pam cnapp config set \
  --network-uid nB2c3D4e5F6g7H8i9J0kLm \
  --provider wiz \
  --client-id my-wiz-client-id \
  --client-secret "MyWizClientSecret" \
  --api-endpoint https://api.us1.app.wiz.io/graphql \
  --auth-endpoint https://auth.app.wiz.io/oauth/token \
  --config-record eNc2Rypt3rReCoRdUiD01
```

### Update an endpoint without changing the stored secret

```bash
pam cnapp config set \
  --network-uid nB2c3D4e5F6g7H8i9J0kLm \
  --provider wiz \
  --client-id my-wiz-client-id \
  --api-endpoint https://api.eu1.app.wiz.io/graphql \
  --auth-endpoint https://auth.app.wiz.io/oauth/token \
  --config-record eNc2Rypt3rReCoRdUiD01
```

### Read the current configuration as JSON

```bash
pam cnapp config read --network-uid nB2c3D4e5F6g7H8i9J0kLm --provider wiz --format json
```

### List all queued issues

```bash
pam cnapp queue list --network-uid nB2c3D4e5F6g7H8i9J0kLm
```

### List only pending issues without decrypting payloads

```bash
pam cnapp queue list --network-uid nB2c3D4e5F6g7H8i9J0kLm --status pending --no-decrypt
```

### List issues, decrypting with an explicit Encrypter record

```bash
pam cnapp queue list \
  --network-uid nB2c3D4e5F6g7H8i9J0kLm \
  --config-record eNc2Rypt3rReCoRdUiD01 \
  --format json
```

### Remediate an issue by rotating credentials

```bash
# 1. Associate the vault record that holds the credential to rotate
pam cnapp queue associate --queue-id 42 --record-uid rEcOrDuIdToRoTaTe123

# 2. Dispatch the rotation to the Gateway
pam cnapp queue remediate --queue-id 42 --action rotate_credentials

# Or also register an auto-remediation rule so future issues with the same
# control hash rotate automatically (item must carry a control hash):
pam cnapp queue remediate --queue-id 42 --action rotate_credentials --auto-remediate
```

### Remove standing privilege from specific groups and roles

```bash
# Group/role names are encrypted client-side with the network record key.
pam cnapp queue remediate --queue-id 42 --action remove_standing_privilege \
  --network-uid nB2c3D4e5F6g7H8i9J0kLm \
  --group Admins --group DBAs --role db-owner

# Without --group/--role the Gateway uses the resource record's JIT settings:
pam cnapp queue remediate --queue-id 42 --action remove_standing_privilege
```

### Mark an issue resolved with a reason

```bash
pam cnapp queue set-status --queue-id 42 --status resolved --reason "Rotated and verified"
```

### Delete a queue item

```bash
pam cnapp queue delete --queue-id 42
```

### Delete the configuration

```bash
pam cnapp config delete --network-uid nB2c3D4e5F6g7H8i9J0kLm
```
