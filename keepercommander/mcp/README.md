# Keeper Commander — MCP Server

The MCP server lets approved AI assistants (Claude Desktop, Cursor, VS Code, etc.)
securely operate on your Keeper vault, Secrets Manager, and KeeperPAM over the
[Model Context Protocol](https://modelcontextprotocol.io). **You** decide which
capabilities are exposed and which client agents may connect — and you can revoke a
client at any time.

- **Transport:** local stdio. The AI client launches `keeper mcp start` as a subprocess.
- **You control access** through the `mcp` command in an authenticated Commander session.
- **The agent cannot escalate itself:** all approval/capability settings live in a
  dedicated vault record (`Keeper Commander MCP Access`) that the running server is
  forbidden to read or modify.

---

## How it works

```
AI client (Claude Desktop) ──launches──▶  keeper mcp start --client-token <TOKEN>
                                                     │  stdio / JSON-RPC
                                                     ▼
                                          MCP server (this module)
   1. loads approval + capability config FROM the dedicated vault record
   2. validates <TOKEN> against approved, non-revoked, non-expired clients
   3. exposes ONLY tools this client is granted ∩ globally enabled
   4. enforces folder/record scope + guardrails on every call
   5. refuses any operation that touches its own config record
   6. audits every tool call to ~/.keeper/mcp_audit.log
                                                     │
                                                     ▼
                              Commander API / commands (reused as-is)
```

Two execution contexts share one config record with **asymmetric** access:

| Context | Runs as | May write the config record? |
|---|---|---|
| `mcp enable/disable/capability/scope/client …` | you, interactively | **yes** |
| `mcp start` (the server the agent launches) | the agent | **no** (hard-blocked) |

Revocation and capability changes are re-read on a refresh interval
(`--refresh-ttl`, default **60s**), so they take effect without restarting the agent.

---

## Requirements

- The `mcp` Python package: `pip install mcp` (already in `requirements.txt`).
- A usable Commander login. Because the agent launches `mcp start` non-interactively,
  set up **persistent login / a device token** so the server can open the vault without
  prompting.

---

## Quick start

Run these in an authenticated Commander shell (`keeper shell`) or as `keeper <command>`.

```text
# 1. Turn on AI access
My Vault> mcp enable

# 2. See what can be exposed
My Vault> mcp capability list

# 3. Allow specific capabilities
My Vault> mcp capability enable search_records
My Vault> mcp capability enable read_secret

# 4. (Recommended) Scope sensitive capabilities to specific folders
My Vault> mcp scope read_secret --add-folder <FOLDER_UID>

# 5. Approve a client agent — prints a one-time token + a config block to paste
My Vault> mcp client approve --name "Claude Desktop" --expire 7d \
              --capabilities search_records,read_secret

# 6. Review anytime; revoke when done
My Vault> mcp status
My Vault> mcp client list
My Vault> mcp client revoke "Claude Desktop"
```

`mcp --help` prints this workflow inline as well.

### Wiring into the AI client

`mcp client approve` prints a ready-to-paste block. Drop it into your client's MCP
configuration (for Claude Desktop, `claude_desktop_config.json`) and restart the client:

```json
{
  "mcpServers": {
    "keeper": {
      "command": "keeper",
      "args": ["mcp", "start", "--client-token", "<TOKEN>"]
    }
  }
}
```

You can also supply the token via the `KEEPER_MCP_CLIENT_TOKEN` environment variable
instead of `--client-token`.

---

## The `mcp` command reference

| Command | Description |
|---|---|
| `mcp status` | Master toggle, enabled capabilities + scopes, connected agents |
| `mcp enable` / `mcp disable` | Master AI-access toggle |
| `mcp capability list` | List all capabilities and whether each is allowed |
| `mcp capability enable <name>` / `disable <name>` | Toggle one capability |
| `mcp scope <name> --add-folder/--add-record/--clear` | Scope a capability |
| `mcp client approve --name <n> [--expire 7d] [--capabilities a,b]` | Approve an agent, mint a token |
| `mcp client list` | List connected agents (id, status, expiry, grants) |
| `mcp client revoke <id-or-name>` | Revoke an agent |
| `mcp start [--client-token <t>] [--refresh-ttl 60]` | Run the stdio server (launched by the client) |

`--expire` accepts `Xm` / `Xh` / `Xd` (e.g. `30m`, `24h`, `7d`); default is never.
`--capabilities` restricts a client to a subset; omit it to inherit all enabled
capabilities.

---

## Capabilities (tools exposed to the agent)

Each capability is a toggle. When enabled (and granted to the client), it registers one
MCP tool. High-risk PAM capabilities default to **off** and support guardrails.

### Vault
| Capability | Tool arguments | Maps to |
|---|---|---|
| `search_records` | `query?`, `limit?` | in-memory search |
| `read_secret` | `record` (UID/title), `field?` | record field read |
| `create_record` | `title`, `record_type?`, `folder?`, `notes?`, `fields[]` | `record-add` |
| `update_record` | `record`, `title?`, `notes?`, `fields[]` | `record-update` |
| `share_record` | `record`, `email?`, `action?`, `can_edit?`, `can_share?`, `one_time?`, `name?`, `expire?` | `share-record` / `one-time-share` |
| `share_folder` | `folder`, `email?`, `action?`, `can_edit?` | `share-folder` |

### Secrets Manager
| Capability | Tool arguments | Maps to |
|---|---|---|
| `ksm_manage_app` | `action` (`app-create`\|`client-add`\|`share`), `name?`, `app?`, `secret?` | `secrets-manager …` |

### KeeperPAM (high-risk, default off)
| Capability | Tool arguments | Maps to |
|---|---|---|
| `pam_rotate` | `record_uid`, `dry_run?` | `pam action rotate` |
| `pam_launch_session` | `record_uid`, `host?`, `reason?`, `ticket?` | `pam tunnel start` |
| `pam_exec_command` | `record_uid`, `command`, `host?` | `pam action exec` |
| `pam_db_query` | `record_uid`, `query` | `pam action query` |

> **Note:** `pam action exec` and `pam action query` are currently **stub commands that
> return synthetic data**, so you can exercise the full agent → MCP → gateway path
> before the gateway-side implementation lands. The MCP tools activate automatically once
> the real commands ship.

### Guardrails
Guardrails are per-capability constraints stored in the config record:

- `dry_run_only: true` — forces `--dry-run` on `pam_rotate` regardless of the agent's args.
- `host_allowlist: [ ... ]` — restricts `pam_launch_session` / `pam_exec_command` to the
  listed hosts.

### Scope
`search_records`, `read_secret`, `create_record`, `update_record`, `share_record`, and
`share_folder` honor scope. An empty scope means "whole vault"; add folders (subfolders
included) or records to restrict. Out-of-scope requests are denied.

---

## Security model

- **Self-protection:** the config record's UID is added to a deny-set at startup. Every
  secret tool refuses that UID, and `search_records` omits it. The agent can neither read
  nor change its own permissions.
- **Tokens:** only a SHA-256 hash of each client token is stored; the plaintext token is
  shown **once** at approval. Validation is constant-time.
- **Revocation/expiry:** enforced on the refresh interval (default 60s) — no agent
  restart needed.
- **Audit:** every tool call (allowed / denied / error) is appended to
  `~/.keeper/mcp_audit.log` with metadata only (never argument values).

---

## Concrete examples you can test

### A. Try tools with the MCP Inspector (no AI client needed)

```bash
# In an authenticated Commander session:
keeper mcp enable
keeper mcp capability enable search_records
keeper mcp capability enable read_secret
keeper mcp client approve --name "Inspector" --capabilities search_records,read_secret
#   -> copy the printed <TOKEN>

# Drive the server directly with the official inspector:
npx @modelcontextprotocol/inspector keeper mcp start --client-token <TOKEN>
```

In the Inspector you should see exactly two tools (`search_records`, `read_secret`).
Call `search_records` with `{"limit": 5}`, then `read_secret` with
`{"record": "<one of the returned UIDs>"}`.

### B. Exercise the PAM stubs from the CLI

The stub commands return synthetic data, so they are safe to run anywhere:

```text
My Vault> pam action query --record-uid ANY --query "select 1" --format json
{"status": "success", "record_uid": "ANY", "query": "select 1",
 "columns": ["id", "name"], "rows": [[1, "alpha"], [2, "beta"]], "row_count": 2, ...}

My Vault> pam action exec --record-uid ANY --command "hostname" --format json
{"status": "success", "command": "hostname", "exit_code": 0,
 "stdout": "[stub] executed: hostname", ...}
```

Enable them for an agent with:

```text
My Vault> mcp capability enable pam_db_query
My Vault> mcp capability enable pam_exec_command
```

### C. Verify revocation

```text
My Vault> mcp client approve --name "Temp" --capabilities read_secret
My Vault> mcp client list            # "Temp" shows as active
My Vault> mcp client revoke "Temp"
My Vault> mcp client list            # "Temp" shows as revoked
```

A running agent using that token starts getting "not authorized" on its next call within
the refresh interval (default 60s).

---

## Automated tests

Three suites live under `unit-tests/`:

| File | Scope | Needs a real account? |
|---|---|---|
| `test_mcp.py` | config, guardrails, server internals (unit) | no |
| `test_mcp_tools.py` | every tool/capability: registry, read handlers vs. an in-memory vault, command construction, server dispatch, config persistence | no |
| `test_mcp_live.py` | live read + create/update/delete lifecycle + PAM stubs against a real session | **opt-in** |

Run the offline suites (default):

```bash
python -m pytest unit-tests/test_mcp.py unit-tests/test_mcp_tools.py -v
```

Run the live suite against your **persistent Commander session** (skipped unless the env
var is set; it creates a uniquely named throwaway record and deletes it, and never runs
outward-facing operations):

```bash
KEEPER_MCP_LIVE=1 python -m pytest unit-tests/test_mcp_live.py -v -s
```

---

## Troubleshooting

- **`The "mcp" package is required for "mcp start"`** — `pip install mcp`.
- **`AI agent access is disabled`** — run `mcp enable`.
- **`Invalid or revoked client token`** — the token is unknown, revoked, or expired;
  approve a new client with `mcp client approve`.
- **Agent starts but no tools appear** — no capabilities are enabled, or the client's
  `--capabilities` subset excludes the enabled ones. Check `mcp status`.
- **A tool returns an empty or error result** — the underlying Commander command may have
  been blocked (e.g. the password-policy check on `record-add`). The reason is surfaced in
  the tool result and in `~/.keeper/mcp_audit.log`.
- **`pam action exec/query … not available`** — the running Commander build does not
  register those verbs; upgrade to a build that includes them (the stubs ship with this
  module).
