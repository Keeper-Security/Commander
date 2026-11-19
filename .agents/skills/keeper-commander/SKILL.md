---
name: keeper-commander
description: >-
  Operate and automate Keeper Security and KeeperPAM using the Keeper Commander CLI (`keeper`).
  Use when querying or managing enterprise users, roles, teams, nodes, PAM/KSM permissions,
  gateways, credential rotations, tunnels, audit/compliance reports, or vault records.
---

# Keeper Commander CLI Skill (`keeper`)

Use this skill to answer questions, generate reports, and automate administrative or vault workflows in **Keeper Commander** (`keeper`).

---

## Quick Setup for Sysadmins (Copilot, Claude, Cursor & Codex)

You can export this skill file directly from Keeper Commander into your AI assistant with a single command:

```bash
# Export for GitHub / VS Code Copilot (.github/copilot-instructions.md)
keeper ai-setup --target copilot

# Export a standalone file to upload into Microsoft 365 Copilot / Copilot Studio Knowledge
keeper ai-setup --output ~/Desktop/KEEPER_COMMANDER_SKILL.md

# Export for Claude Code (~/.claude/skills/keeper-commander/SKILL.md)
keeper ai-setup --target claude

# Export for Cursor (.cursor/rules/keeper-commander.mdc)
keeper ai-setup --target cursor

# Export for Codex / Antigravity / Gemini CLI (.agents/skills/keeper-commander/SKILL.md)
keeper ai-setup --target agents
```

---

## 1. Core Execution Pattern for AI Agents

Always invoke Keeper Commander non-interactively via `keeper shell -c "<command>"` and request `--format json` whenever the command supports it so you can parse structured output reliably:

```bash
keeper shell -c "<command> --format json"
```

### Multi-Step Chaining in One Turn
When a user's request spans multiple data sources or actions, chain commands inside a single turn rather than asking the user to run multiple steps manually:
- **Multiple commands in one session:** Pass semicolon-separated commands or a batch file (`run-batch`), or run sequential `keeper shell -c` calls and join the JSON results in Python/`jq`.
- **Note on stdout parsing:** `keeper shell -c "... --format json"` may print informational banner lines before the JSON payload; parse from the first `[` or `{` character in stdout.

### Safety Guardrails (Read-Only vs. Mutating)
- **Read-Only Commands (Execute Immediately):** `enterprise-info` (`ei`), `user-report`, `audit-report`, `audit-log`, `action-report` (without `--apply-action`), `security-audit-report`, `compliance`, `external-shares-report`, `pam gateway list`, `pam config list`, `pam rotation list`, `pam tunnel list`, `secrets-manager app list`, `search`, `ls`, `get`, `find-duplicate`, `password-report`, `file-report`, `breachwatch list`, `whoami`.
- **Mutating / Destructive Commands (Confirm with User First):** Any command that modifies enterprise or vault state (`--add`, `--delete`, `--lock`, `--unlock`, `--disable`, `--wipe-out`, `--enforcement`, `--add-user`, `--remove-user`, `--apply-action`, `rm`, `rmdir`, `delete-all`, `transfer-user`, `pam action rotate`, `pam gateway remove`, `pam config remove`). Show the exact command(s) and ask for confirmation before executing.

---

## 2. Enterprise Reporting & Auditing

### Enterprise Hierarchy: Users, Roles, Teams, and Nodes (`enterprise-info` / `ei`)
- **List all users with custom columns:**
  ```bash
  keeper shell -c "enterprise-info --users --columns name,status,transfer_status,node,roles,teams,2fa_enabled,job_title --format json"
  ```
- **List all roles with enforcement policies, direct users, and assigned teams:**
  ```bash
  keeper shell -c "enterprise-info --roles --columns node,admin,user_count,users,team_count,teams,enforcements --format json"
  ```
- **List all teams and their members:**
  ```bash
  keeper shell -c "enterprise-info --teams --columns node,restricts,user_count,users,roles --format json"
  ```
- **List all enterprise nodes:**
  ```bash
  keeper shell -c "enterprise-info --nodes --columns parent_node,user_count,team_count,role_count,provisioning --format json"
  ```
- **Scope any `enterprise-info` query to a specific sub-node:** Append `--node "<Node Name or ID>"`.

### Auditing Users with KeeperPAM or Secrets Manager (KSM) Permissions
KeeperPAM and KSM capabilities are granted via Role Enforcement Policies (`role_enforcements`) assigned either directly to users (`roles.users`) or inherited through teams (`roles.teams` -> `teams.users`).
- **All 14 KeeperPAM Enforcement Keys:**
  `allow_pam_rotation`, `allow_pam_discovery`, `allow_pam_gateway`, `allow_configure_rotation_settings`, `allow_rotate_credentials`, `allow_configure_pam_cloud_connection_settings`, `allow_launch_pam_on_cloud_connection`, `allow_configure_pam_tunneling_settings`, `allow_launch_pam_tunnels`, `allow_launch_rbi`, `allow_configure_rbi`, `allow_view_kcm_recordings`, `allow_view_rbi_recordings`, `allow_configure_workflow_settings`
- **Keeper Secrets Manager (KSM) Enforcement Key:**
  `allow_secrets_manager`
- **How to resolve all PAM/KSM users in one turn:**
  Query `ei --roles --columns node,enforcements,users,teams --format json` and `ei --teams --columns users --format json` (or run `pam-users` / `ksm-users` if available), expand team memberships into users, and filter roles whose `enforcements` contain any of the keys above.

### User Activity, Inactivity & Login Reports
- **Last login report across enterprise users:**
  ```bash
  keeper shell -c "user-report --last-login --days 365 --format json"
  ```
- **Find inactive users (no login for $N$ days) or invited/locked users (`action-report`):**
  ```bash
  # Dry-run report of users who haven't logged in for 90 days:
  keeper shell -c "action-report --target user --days-since 90 --format json"

  # Invited users who haven't accepted for 30 days:
  keeper shell -c "action-report --target invited --days-since 30 --format json"
  ```
- **Audit event logs (`audit-report`):**
  ```bash
  # Raw audit events:
  keeper shell -c "audit-report --report-type raw --created recent --limit 100 --format json"

  # Summary counts by event type and user:
  keeper shell -c "audit-report --report-type dim --columns audit_event_type,username --format json"
  ```
- **Security Audit & Compliance Reports:**
  ```bash
  keeper shell -c "security-audit-report --format json"
  keeper shell -c "compliance summary-report --format json"
  keeper shell -c "compliance report --format json"
  keeper shell -c "external-shares-report --format json"
  ```

---

## 3. Enterprise User, Role & Team Administration

- **Manage Enterprise Users (`enterprise-user` / `eu`):**
  ```bash
  # Invite user to a node:
  keeper shell -c "enterprise-user --add user@company.com --name 'Full Name' --node 'Engineering'"

  # Lock / unlock / disable 2FA / delete user:
  keeper shell -c "enterprise-user --lock user@company.com"
  keeper shell -c "enterprise-user --unlock user@company.com"
  keeper shell -c "enterprise-user --disable user@company.com"
  ```
- **Manage Enterprise Roles & Enforcements (`enterprise-role` / `er`):**
  ```bash
  # Create a role, enable PAM enforcements, and assign users/teams:
  keeper shell -c "enterprise-role --add 'DBA PAM Role' --node 'Engineering'"
  keeper shell -c "enterprise-role 'DBA PAM Role' --enforcement ALLOW_PAM_ROTATION:true --enforcement ALLOW_LAUNCH_PAM_TUNNELS:true"
  keeper shell -c "enterprise-role 'DBA PAM Role' --add-user alice@company.com --add-team 'DB Team'"
  ```
- **Approve Pending Devices & Queued Teams:**
  ```bash
  keeper shell -c "device-approve"
  keeper shell -c "team-approve"
  ```

---

## 4. KeeperPAM & Secrets Manager Operations

- **Gateways (`pam gateway`):**
  ```bash
  keeper shell -c "pam gateway list --format json"
  keeper shell -c "pam gateway new --name 'Prod Gateway' --application 'My KSM App' --config-init b64"
  ```
- **PAM Configurations (`pam config`):**
  ```bash
  keeper shell -c "pam config list --format json"
  ```
- **Credential Rotation (`pam rotation` & `pam action rotate`):**
  ```bash
  keeper shell -c "pam rotation list --format json"
  keeper shell -c "pam action rotate --record-uid <RECORD_UID>"
  ```
- **Tunnels, Connections & RBI (`pam tunnel`, `pam connection`, `pam rbi`, `pam launch`):**
  ```bash
  keeper shell -c "pam tunnel list --format json"
  keeper shell -c "pam tunnel start <RECORD_UID> --host 127.0.0.1 --port 5432"
  keeper shell -c "pam tunnel stop <RECORD_UID>"
  keeper shell -c "pam launch <RECORD_UID>"
  ```
- **Keeper Secrets Manager (`secrets-manager` / `ksm`):**
  ```bash
  keeper shell -c "secrets-manager app list"
  keeper shell -c "secrets-manager app get <APP_UID_OR_NAME>"
  ```

---

## 5. Vault & Record Operations

- **Search & Inspect Vault Records:**
  ```bash
  keeper shell -c "list --format json"
  keeper shell -c "search '<pattern>' --format json"
  keeper shell -c "get <RECORD_UID> --format json"
  keeper shell -c "list-sf --format json"
  ```
- **Vault Health & Attachment Audits:**
  ```bash
  keeper shell -c "whoami --json"
  keeper shell -c "file-report --format json"
  keeper shell -c "password-report --format json"
  keeper shell -c "find-duplicate --full --format json"
  keeper shell -c "breachwatch list --all --format json"
  ```
