# KCM Database Import — Quick Start Guide

Migrate connections from a KCM (Keeper Connection Manager) / Apache Guacamole database directly into Keeper PAM. The `pam project kcm-import` command connects to the KCM database, extracts connections, users, and groups, maps 150+ Guacamole parameters to Keeper record fields, and imports everything into your vault.

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Keeper Commander** | Installed and logged in (`keeper shell`) |
| **KCM instance** | Running KCM with MySQL or PostgreSQL backend |
| **Database access** | Credentials for the KCM/Guacamole database |
| **Python DB driver** | `pip3 install pymysql` (MySQL) or `pip3 install psycopg2-binary` (PostgreSQL) |
| **Gateway** | An existing Keeper gateway, or the command will create one |
| **Docker** *(optional)* | Only needed if using `--docker-detect` for auto-discovery |

## Quick Start — Docker Auto-Detect (Simplest)

If Commander is running on the same host as KCM's Docker stack:

```bash
# 1. Preview what would be imported (no vault changes)
My Vault> pam project kcm-import --docker-detect --dry-run

# 2. Run the actual import
My Vault> pam project kcm-import --docker-detect --name "KCM Migration"
```

That's it. The command will:
1. Discover the KCM database container automatically
2. Detect the database type (MySQL or PostgreSQL)
3. Resolve the container's IP address
4. Extract credentials from the container's environment
5. Connect, extract all connections/users/groups, and import them

## Quick Start — Manual Database Connection

When the database is on a remote host or you need explicit control:

```bash
# Store your DB password in a Keeper vault record first, then:
My Vault> pam project kcm-import \
    --db-host 10.0.0.5 \
    --db-type postgresql \
    --db-password-record "KCM DB Password" \
    --db-ssl \
    --name "Production KCM"
```

> **Security note:** Database passwords are never accepted as CLI arguments.
> Use `--db-password-record` to reference a vault record, or the command will prompt interactively.

## Common Workflows

### 1. Explore Before You Import

List all connection groups in the KCM database to understand what's there:

```bash
My Vault> pam project kcm-import --docker-detect --list-groups
```

Output shows each group with its resource and user counts, helping you decide what to import.

### 2. Import Specific Groups Only

Use `--groups` with wildcard patterns to import a subset:

```bash
# Import only Production and Staging groups
My Vault> pam project kcm-import --docker-detect \
    --groups "Production*,Staging*" \
    --name "Prod Migration"
```

Or exclude groups you don't want:

```bash
# Import everything except test and incomplete groups
My Vault> pam project kcm-import --docker-detect \
    --exclude-groups "Test*,Incomplete*,Sandbox*"
```

Patterns support `*` and `?` wildcards and match against group name, full path, or any path segment.

### 3. Dry Run + JSON Review

For maximum control, preview the import and save the extracted data:

```bash
# Save JSON for review without modifying the vault
My Vault> pam project kcm-import --docker-detect \
    --dry-run \
    --output ~/kcm-review.json

# Include credentials in the JSON (redacted by default)
My Vault> pam project kcm-import --docker-detect \
    --output ~/kcm-full.json \
    --include-credentials
```

### 4. Extend an Existing PAM Configuration

Add KCM connections to an existing PAM project instead of creating a new one:

```bash
My Vault> pam project kcm-import --docker-detect \
    --config "Existing PAM Config" \
    --groups "NewDepartment*"
```

### 5. Non-Interactive / Batch Mode

For scripting or automation, skip all prompts:

```bash
My Vault> pam project kcm-import --docker-detect \
    --name "Automated Import" \
    --gateway "My Gateway" \
    --yes
```

### 6. Get a Size Estimate

Check how many records would be created without connecting to the vault:

```bash
My Vault> pam project kcm-import --docker-detect --estimate
```

## Folder Modes

The `--folder-mode` flag controls how KCM connection groups map to Keeper shared folders:

| Mode | Behavior |
|------|----------|
| `ksm` *(default)* | Preserves group nesting, but groups with a KSM config become root-level shared folders |
| `exact` | Preserves the exact KCM group hierarchy as nested folders |
| `flat` | Every group becomes a root-level shared folder (no nesting) |

```bash
# Use exact hierarchy
My Vault> pam project kcm-import --docker-detect --folder-mode exact
```

## What Gets Imported

| KCM Object | Keeper Record Type |
|------------|-------------------|
| SSH connections | `pamMachine` |
| RDP connections | `pamMachine` |
| VNC connections | `pamMachine` |
| Telnet connections | `pamMachine` |
| HTTP/HTTPS connections | `pamRemoteBrowser` |
| MySQL connections | `pamDatabase` |
| PostgreSQL connections | `pamDatabase` |
| SQL Server connections | `pamDatabase` |
| Oracle connections | `pamDatabase` |
| Kubernetes connections | `pamMachine` |
| LDAP connections | `pamMachine` |
| Connection users | `pamUser` |

150+ Guacamole parameters are mapped, including: hostname, port, credentials, SSH keys, RDP display settings, VNC encodings, database schemas, TOTP/MFA, jump hosts, recording paths, and more.

## Import Report

After a successful import, the command:

1. **Prints a summary** to the console with pass/fail/skip counts per record type
2. **Creates a vault record** in the project folder containing:
   - Copyable custom fields: gateway deploy command, Gateway Token, Config UID, Gateway UID, KSM App UID
   - `KCM-Import-Report.md` file attachment with the full report
   - Per-record breakdown with reasons for any failures or skips
   - Throttle statistics and the redacted CLI command for reproducibility

## Cleaning Up an Import

To reverse an import and remove all created records, folders, gateway, and KSM app:

```bash
# Preview what would be deleted
My Vault> pam project kcm-cleanup --name "KCM Migration" --dry-run

# Delete everything from the import
My Vault> pam project kcm-cleanup --name "KCM Migration" --yes

# Or reference by PAM config UID
My Vault> pam project kcm-cleanup --config VxANFEPLi8E9gdtlDmfBvw --yes
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `MySQL driver not found` | `pip3 install pymysql` |
| `PostgreSQL driver not found` | `pip3 install psycopg2-binary` |
| `Refusing to connect without SSL/TLS` | Add `--db-ssl` for encrypted connections, or `--allow-cleartext` if SSL is unavailable (not recommended) |
| `No Docker containers found` | Ensure Docker is running and the KCM database container is up. Use `--docker-container NAME` if auto-discovery fails |
| `KCM schema not found` | The database exists but doesn't have Guacamole tables. Verify `--db-name` points to the correct database (default: `guacamole_db`) |
| `No connections match the group filter` | Run `--list-groups` to see available groups and adjust your `--groups` pattern |
| HTTP 403 throttling | The adaptive throttler handles this automatically. For manual tuning, use `--batch-size` and `--batch-delay` |
| Import is slow | Reduce `--batch-size` if hitting throttles, or increase it if the server handles load well. `--no-auto-throttle` disables adaptive tuning |

## Full Flag Reference

See the [PAM Import README](README.md) for the complete list of all flags and their defaults, JSON format details, and PAM configuration options.
